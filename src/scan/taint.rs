// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Statement-level taint scanner for `type = "taint"` rules.

use crate::rules::CompiledRule;
use crate::scan::FileHit;
use std::collections::HashSet;

/// `name` appears in `s` as a whole identifier, not a substring: `x` must
/// not match `x1` or `foo_x`.
fn word_present(s: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$';
    for (i, _) in s.match_indices(name) {
        let ok_before = i == 0 || !ident(s.as_bytes()[i - 1]);
        let end = i + name.len();
        let ok_after = end >= s.len() || !ident(s.as_bytes()[end]);
        if ok_before && ok_after {
            return true;
        }
    }
    false
}

/// Function-boundary heads: taint in one function body must not silently
/// flow into another's same-named local. Covers the common declaration
/// spellings across js/py/rs/go/rb/php/sh/java.
fn is_fn_head(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("def ")
        || t.starts_with("function ")
        || t.starts_with("fn ")
        || t.starts_with("pub fn ")
        || t.starts_with("func ")
        || t.starts_with("sub ")
        || t.starts_with("async def ")
        || t.starts_with("async function ")
        || (t.starts_with("const ") && t.contains("=>")) // arrow fns
        || (t.contains('(') && t.ends_with('{') && {
            // c/java style `type name(args) {`
            let head = t.split('(').next().unwrap_or("");
            let mut it = head.split_whitespace();
            it.next().is_some() && it.next().is_some()
        })
}

/// Sequential intra-file taint with scope tracking: a variable is tainted
/// when its assignment RHS matches `source` or references an already-tainted
/// var in the same scope. Reassignment to a clean RHS untaints the name.
/// A `sanitizers` regex match on the RHS clears taint instead of spreading
/// it (`x = encodeURIComponent(x)`).
///
/// Scope model: unindented assignments are module globals that survive
/// function boundaries; lines more indented than the current `def`-like
/// head are locals that die when indentation returns to the head's level.
/// This is still an approximation - return values and parameters are not
/// tracked - but it kills the common false link between same-named locals
/// in different functions.
pub(crate) fn taint_scan(
    text: &str,
    source: &regex::Regex,
    sink: &regex::Regex,
    sanitizers: &[regex::Regex],
    rule: &CompiledRule,
    max_hits: usize,
) -> Vec<FileHit> {
    // let|const|var|local|<name> = <rhs>   also bare `x = y`
    static ASSIGN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = ASSIGN.get_or_init(|| {
        regex::Regex::new(
            r"(?m)^\s*(?:let|const|var|local|dim)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=(.*)$",
        )
        .unwrap()
    });
    let mut globals: HashSet<String> = HashSet::new();
    let mut locals: HashSet<String> = HashSet::new();
    let mut fn_indent: Option<usize> = None;
    let mut hits = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let indent = line.len() - line.trim_start().len();
        let is_local = match fn_indent {
            Some(fi) if line.trim().is_empty() => true, // blanks stay in-fn
            Some(fi) if indent > fi => true,
            Some(_) => {
                fn_indent = None; // dedent ended the function
                locals.clear();
                false
            }
            None => false,
        };
        if is_fn_head(line) {
            fn_indent = Some(indent);
            locals.clear(); // params/declarations are not carried in
        }
        let mut assigned_clean: Option<String> = None;
        if let Some(c) = re.captures(line) {
            let (lhs, rhs) = (c[1].to_string(), c[2].to_string());
            if !rhs.starts_with('=') {
                let rhs_dirty = source.is_match(&rhs)
                    || (is_local && locals.iter().any(|v| word_present(&rhs, v))
                        || globals.iter().any(|v| word_present(&rhs, v)));
                let sanitized = sanitizers.iter().any(|s| s.is_match(&rhs));
                if rhs_dirty && (!sanitized || source.is_match(&rhs)) {
                    if is_local {
                        locals.insert(lhs);
                    } else {
                        globals.insert(lhs);
                    }
                } else {
                    assigned_clean = Some(lhs);
                }
            }
        }
        // clean reassignment or a sanitizer call clears the name in scope
        if let Some(lhs) = assigned_clean {
            locals.remove(&lhs);
            globals.remove(&lhs);
        }
        // sink line mentioning a tainted var (word-boundary, not substring)
        if sink.is_match(line) {
            let cand: Vec<&String> = if is_local {
                locals.iter().chain(globals.iter()).collect()
            } else {
                globals.iter().collect()
            };
            for v in cand {
                if word_present(line, v) {
                    hits.push(FileHit {
                        line: Some(i + 1),
                        excerpt: Some(line.trim().chars().take(120).collect()),
                        message: format!("{}: tainted var `{v}` reaches sink", rule.description),
                        severity_override: None,
                    });
                    break;
                }
            }
        }
        if hits.len() >= max_hits {
            break;
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(sanitizers: &[&str]) -> CompiledRule {
        CompiledRule {
            set: "t".into(),
            id: "T".into(),
            severity: crate::finding::Severity::High,
            description: "t".into(),
            remediation: None,
            reference: None,
            window: None,
            kind: crate::rules::CompiledKind::Taint {
                source: regex::Regex::new(r"process\.env|getenv").unwrap(),
                sink: regex::Regex::new(r"fetch\(|exec\(").unwrap(),
                sanitizers: sanitizers
                    .iter()
                    .map(|s| regex::Regex::new(s).unwrap())
                    .collect(),
                path: None,
            },
        }
    }

    fn scan(text: &str, sanitizers: &[&str]) -> Vec<FileHit> {
        let r = rule(sanitizers);
        taint_scan(
            text,
            &regex::Regex::new(r"process\.env|getenv").unwrap(),
            &regex::Regex::new(r"fetch\(|exec\(").unwrap(),
            &r.sanitizers_of(),
            &r,
            5,
        )
    }

    impl CompiledRule {
        fn sanitizers_of(&self) -> Vec<regex::Regex> {
            match &self.kind {
                crate::rules::CompiledKind::Taint { sanitizers, .. } => sanitizers.clone(),
                _ => vec![],
            }
        }
    }

    #[test]
    fn basic_flow() {
        let hits = scan("x = process.env.SECRET\nfetch(url + x)\n", &[]);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn substring_names_do_not_taint() {
        // x1 contains x as a prefix but is a different identifier
        let hits = scan("x = process.env.S\nfetch(x1)\n", &[]);
        assert!(hits.is_empty());
    }

    #[test]
    fn clean_reassignment_untaints() {
        let hits = scan("x = process.env.S\nx = \"static\"\nfetch(x)\n", &[]);
        assert!(hits.is_empty());
    }

    #[test]
    fn sanitizer_clears() {
        let hits = scan(
            "x = process.env.S\ny = escape(x)\nfetch(y)\n",
            &["escape\\("],
        );
        assert!(hits.is_empty());
        // source matching the rhs still wins over the sanitizer
        let hits = scan("y = escape(process.env.S)\nfetch(y)\n", &["escape\\("]);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn locals_do_not_cross_functions() {
        let t = "def a():\n    x = process.env.S\n\ndef b():\n    fetch(x)\n";
        assert!(scan(t, &[]).is_empty());
        // but a module-level global does flow into the function
        let t = "x = process.env.S\n\ndef b():\n    fetch(x)\n";
        assert_eq!(scan(t, &[]).len(), 1);
    }
}
