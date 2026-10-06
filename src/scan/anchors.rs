// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Regex anchor extraction: pull the literal(s) every match of a pattern
//! must contain so the shared Aho-Corasick pass can gate the regex.

use super::engine::{LitRef, Slot};

/// Literals guaranteed to appear in any match of `pat` (an OR set: at least
/// one must be present). Used to gate a rule's regex behind the shared
/// Aho-Corasick scan instead of a per-file regex pass. `None` when no
/// literal is provably required - case-insensitive patterns, pure classes,
/// or alternations whose branches lack literals.
pub(super) fn regex_anchors(pat: &str) -> Option<Vec<String>> {
    if pat.contains("(?i") {
        return None; // case-insensitive literals can't anchor a caseful AC
    }
    let hir = regex_syntax::ParserBuilder::new()
        .utf8(false)
        .build()
        .parse(pat)
        .ok()?;
    // walk returns the node's literal OR-set: Some(set) means every match of
    // the node contains at least one set member; None means nothing provable
    // (a match may contain no literal at all). For concatenations any single
    // required anchor gates the whole pattern, so keep the single longest
    // candidate - one rare literal beats a union of common ones.
    fn walk(h: &regex_syntax::hir::Hir) -> Option<Vec<Vec<u8>>> {
        use regex_syntax::hir::HirKind;
        match h.kind() {
            HirKind::Literal(b) => Some(vec![b.0.to_vec()]),
            HirKind::Concat(subs) => {
                let mut best: Option<Vec<Vec<u8>>> = None;
                for s in subs {
                    let Some(set) = walk(s) else { continue };
                    let better = match (&best, set.iter().map(|l| l.len()).max()) {
                        (None, _) => true,
                        (Some(b), Some(m)) => m > b.iter().map(|l| l.len()).max().unwrap_or(0),
                        _ => false,
                    };
                    if better {
                        best = Some(set);
                    }
                }
                best.or(Some(Vec::new()))
            }
            HirKind::Alternation(subs) => {
                let mut all: Vec<Vec<u8>> = Vec::new();
                for s in subs {
                    let set = walk(s)?; // a branch with no literal kills it
                    if set.is_empty() {
                        return None; // a branch can match with no literal at all
                    }
                    all.extend(set);
                }
                Some(all)
            }
            HirKind::Repetition(r) => {
                if r.min >= 1 {
                    walk(&r.sub)
                } else {
                    Some(Vec::new()) // optional part needs no literal
                }
            }
            _ => Some(Vec::new()), // classes, looks, etc: no required literal
        }
    }
    let bag = walk(&hir)?;
    let out: Vec<String> = bag
        .into_iter()
        .filter_map(|b| String::from_utf8(b).ok())
        .filter(|s| s.len() >= 3 && s.len() <= 128)
        .collect();
    if out.is_empty() { None } else { Some(out) }
}

/// Register a regex: provable literal anchors go into the AC automaton so
/// Literal pool: patterns, per-pattern emit refs, and a name index
/// shared by contains literals and extracted regex anchors.
#[derive(Default)]
pub(super) struct LitPool {
    pub lits: Vec<String>,
    pub lit_of: Vec<Vec<(usize, LitRef)>>,
    lit_idx: std::collections::HashMap<String, usize>,
}

impl LitPool {
    pub(super) fn push_lit(&mut self, s: &str, ri: usize, r: LitRef) {
        if let Some(&i) = self.lit_idx.get(s) {
            self.lit_of[i].push((ri, r));
            return;
        }
        self.lits.push(s.to_string());
        self.lit_of.push(vec![(ri, r)]);
        self.lit_idx.insert(s.to_string(), self.lits.len() - 1);
    }
}

/// the rule's regex only runs on files containing an anchor; unanchorable
/// patterns fall back to the shared RegexSet.
pub(super) fn push_re(
    unanchored: &mut Vec<(usize, Slot, regex::Regex)>,
    pool: &mut LitPool,
    re: &regex::Regex,
    ri: usize,
    slot: Slot,
) {
    if let Some(anchors) = regex_anchors(re.as_str()) {
        for a in anchors {
            pool.push_lit(&a, ri, LitRef::Anchor(slot));
        }
    } else {
        unanchored.push((ri, slot, re.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::regex_anchors;

    #[test]
    fn anchors() {
        for (pat, want) in [
            (
                r#"api\.telegram\.org/bot[0-9]{6,}:[A-Za-z0-9_-]{30,}|t\.me/[A-Za-z0-9_]{3,}(bot)?"#,
                true,
            ),
            (
                r#""(pre|post)?install"\s*:\s*"[^"]*(node|curl|wget|sh|bash|eval|base64|powershell)[^"]*""#,
                true,
            ),
            (r#"exec\.Command\s*\(\s*"(?:sh|bash|cmd)""#, true),
            (r#"[a-z]{3,8}"#, false),
            (r#"(?i)secret"#, false),
            // a bare-class branch means a match need not contain a literal
            (r#"foo|\d+"#, false),
            // all branches with literals stay anchorable
            (r#"api\.x\.com/req|cdn\.x\.com/f"#, true),
        ] {
            let a = regex_anchors(pat);
            assert_eq!(a.is_some(), want, "{pat}");
        }
    }
}
