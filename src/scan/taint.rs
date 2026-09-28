//! Statement-level taint scanner for `type = "taint"` rules.

use crate::rules::CompiledRule;
use crate::scan::FileHit;
use std::collections::HashSet;

/// Sequential intra-file taint: a variable is tainted when its assignment
/// RHS matches `source` or references an already-tainted var. A line
/// matches `sink` while naming a tainted var -> hit at the sink line.
/// Language-agnostic via assignment-shape regexes (js/py/rs/go/sh).
pub(crate) fn taint_scan(
    text: &str,
    source: &regex::Regex,
    sink: &regex::Regex,
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
    let mut tainted: HashSet<String> = HashSet::new();
    let mut hits = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if let Some(c) = re.captures(line) {
            let (lhs, rhs) = (c[1].to_string(), c[2].to_string());
            if rhs.starts_with('=') {
                continue; // == / === comparisons, not assignment
            }
            let dirty = source.is_match(&rhs) || tainted.iter().any(|v| rhs.contains(v.as_str()));
            if dirty {
                tainted.insert(lhs);
            }
        }
        // sink line mentioning a tainted var
        if sink.is_match(line) {
            for v in &tainted {
                if line.contains(v.as_str()) {
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
