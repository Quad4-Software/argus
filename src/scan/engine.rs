// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Per-file rule matching: one Aho-Corasick pass collects every `contains`
//! literal, keyword-gate hit, and regex-anchor hit per file, and per-regex
//! `is_match` prefilters cover patterns with no provable literal. Only rules
//! flagged by one of those gates run their expensive per-match extraction.
//! RegexSet was measured slower here: reporting which patterns matched
//! forces a PikeVM NFA simulation over every byte, while per-regex
//! is_match skips non-matching files through SIMD prefilters.

use super::walk::dep_name_candidates;
use super::{FileHit, hex_sha256, line_excerpt, line_of};
use crate::finding::Severity;
use crate::rules::{CompiledKind, CompiledRule, UnsafeRefs};
use std::collections::HashSet;

fn is_full_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// docker://...@sha256:<64hex> style digest pin - immutable like a commit SHA.
fn is_digest_pin(s: &str) -> bool {
    s.len() == 71 && s.starts_with("sha256:") && s[7..].bytes().all(|b| b.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// Single-pass matcher: every rule's content regexes live in one RegexSet and
// every `contains` literal in one Aho-Corasick automaton. A file then costs
// two passes over its bytes instead of one pass per rule; only rules the
// automata actually fired on get their expensive per-hit extraction.
// ---------------------------------------------------------------------------

/// Which pattern slot of a rule a combined-automaton index belongs to.
#[derive(Clone, Copy, Debug)]
pub(super) enum Slot {
    /// The rule's main matching regex (content/secret/package/sourceurl/actionref).
    Main,
    /// Taint/Dataflow source regex.
    Source,
    /// Taint/Dataflow sink regex.
    Sink,
}

/// What an AC literal means to a rule: an emitting `contains` needle, or a
/// regex anchor. Gate keywords live in the separate `ac_gate` automaton.
#[derive(Clone, Copy, Debug)]
pub(super) enum LitRef {
    Emit(usize),
    /// Required literal inside the rule's regex for the given slot; the
    /// regex runs only when an anchor literal lands in the file.
    Anchor(Slot),
}

/// Bytes around a hit where a keyword must appear for gated rules.
const GATE_RADIUS: usize = 250;

pub(crate) struct Matcher {
    /// Regexes with no provable literal anchor: gated per file by is_match,
    /// whose inner literal prefilter keeps misses cheap. The RegexSet
    /// alternative turns into a PikeVM simulation of every pattern on every
    /// byte - measured far slower than per-regex prefilters on real trees.
    /// Regex clones share the compiled program, so this is cheap.
    unanchored: Vec<(usize, Slot, regex::Regex)>,
    ac: Option<aho_corasick::AhoCorasick>,
    /// Case-insensitive automaton over gate keywords only; gitleaks keyword
    /// lists are lowercase while real tokens are often AWS/TOKEN shaped.
    ac_gate: Option<aho_corasick::AhoCorasick>,
    /// Rules carrying at least one keyword: when none of their keywords
    /// appears in a file the rule cannot fire, so its regex is skipped too.
    has_gate: HashSet<usize>,
    /// gate keyword index -> rules gated on it
    gate_of: Vec<Vec<usize>>,
    /// ac pattern index -> all (rule, lit) pairs sharing that literal;
    /// distinct rules legitimately reuse the same needle.
    lit_of: Vec<Vec<(usize, LitRef)>>,
    /// Languages needed by ast rules in this matcher (parse gate per file).
    #[cfg(feature = "ast")]
    ast_langs: HashSet<crate::astscan::AstLang>,
}

impl Matcher {
    pub fn build<'a>(rules: impl Iterator<Item = &'a CompiledRule>) -> Self {
        let mut unanchored: Vec<(usize, Slot, regex::Regex)> = Vec::new();
        let mut pool = super::anchors::LitPool::default();
        // gate keywords live in a second, case-insensitive automaton
        let mut glits: Vec<String> = Vec::new();
        let mut gate_of: Vec<Vec<usize>> = Vec::new();
        let mut gidx: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut has_gate: HashSet<usize> = HashSet::new();
        let push_gate = |glits: &mut Vec<String>,
                         gate_of: &mut Vec<Vec<usize>>,
                         gidx: &mut std::collections::HashMap<String, usize>,
                         has_gate: &mut HashSet<usize>,
                         s: &str,
                         ri: usize| {
            let pat = *gidx.entry(s.to_string()).or_insert_with(|| {
                glits.push(s.to_string());
                gate_of.push(Vec::new());
                glits.len() - 1
            });
            gate_of[pat].push(ri);
            has_gate.insert(ri);
        };
        #[cfg(feature = "ast")]
        let mut ast_langs = HashSet::new();
        for (i, r) in rules.enumerate() {
            match &r.kind {
                CompiledKind::Content {
                    regex,
                    contains,
                    gate,
                    ..
                } => {
                    if let Some(re) = regex {
                        super::anchors::push_re(&mut unanchored, &mut pool, re, i, Slot::Main);
                    }
                    for (li, l) in contains.iter().enumerate() {
                        if !l.is_empty() {
                            pool.push_lit(l, i, LitRef::Emit(li));
                        }
                    }
                    for kw in gate.iter().flatten() {
                        let k = kw.to_lowercase();
                        if !k.is_empty() {
                            push_gate(&mut glits, &mut gate_of, &mut gidx, &mut has_gate, &k, i);
                        }
                    }
                }
                CompiledKind::Secret { re, gate, .. } => {
                    super::anchors::push_re(&mut unanchored, &mut pool, re, i, Slot::Main);
                    for kw in gate.iter().flatten() {
                        let k = kw.to_lowercase();
                        if !k.is_empty() {
                            push_gate(&mut glits, &mut gate_of, &mut gidx, &mut has_gate, &k, i);
                        }
                    }
                }
                CompiledKind::SourceUrl { line_re, .. } => {
                    super::anchors::push_re(&mut unanchored, &mut pool, line_re, i, Slot::Main);
                }
                CompiledKind::Package { names_re, .. } => {
                    super::anchors::push_re(&mut unanchored, &mut pool, names_re, i, Slot::Main);
                }
                CompiledKind::ActionRef { uses_re, .. } => {
                    super::anchors::push_re(&mut unanchored, &mut pool, uses_re, i, Slot::Main);
                }
                CompiledKind::Taint { source, sink, .. }
                | CompiledKind::Dataflow { source, sink, .. } => {
                    super::anchors::push_re(&mut unanchored, &mut pool, source, i, Slot::Source);
                    super::anchors::push_re(&mut unanchored, &mut pool, sink, i, Slot::Sink);
                }
                #[cfg(feature = "ast")]
                CompiledKind::Ast { lang, .. } => {
                    ast_langs.insert(*lang);
                    // typescript rules also gate tsx files
                    if *lang == crate::astscan::AstLang::TypeScript {
                        ast_langs.insert(crate::astscan::AstLang::Tsx);
                    }
                }
                _ => {}
            }
        }

        let ac = if pool.lits.is_empty() {
            None
        } else {
            aho_corasick::AhoCorasick::builder()
                .match_kind(aho_corasick::MatchKind::Standard)
                .build(&pool.lits)
                .ok()
        };
        let ac_gate = if glits.is_empty() {
            None
        } else {
            aho_corasick::AhoCorasick::builder()
                .match_kind(aho_corasick::MatchKind::Standard)
                .ascii_case_insensitive(true)
                .build(&glits)
                .ok()
        };
        if std::env::var_os("ARGUS_PROF").is_some() {
            let anchored = pool
                .lit_of
                .iter()
                .flatten()
                .filter(|(_, r)| matches!(r, LitRef::Anchor(_)))
                .count();
            eprintln!(
                "matcher: {} anchored lits, {} unanchored regexes",
                anchored,
                unanchored.len()
            );
        }
        Matcher {
            unanchored,
            ac,
            ac_gate,
            gate_of,
            has_gate,
            lit_of: pool.lit_of,
            #[cfg(feature = "ast")]
            ast_langs,
        }
    }
}

impl FileMatch {
    /// May the rule's main regex possibly match this file?
    fn can_main(&self, i: usize) -> bool {
        self.main.contains(&i) || self.anchors.contains(&(i, 0))
    }
    fn can_src(&self, i: usize) -> bool {
        self.src.contains(&i) || self.anchors.contains(&(i, 1))
    }
    fn can_sink(&self, i: usize) -> bool {
        self.sink.contains(&i) || self.anchors.contains(&(i, 2))
    }
}

/// Keyword proximity gate (gitleaks semantics): a hit at byte `off` counts
/// only when a keyword hit lands within GATE_RADIUS bytes. Rules without
/// keywords are never gated.
fn gate_ok(gate: &Option<Vec<String>>, fm: &FileMatch, rule_idx: usize, off: usize) -> bool {
    match gate {
        None => true,
        Some(_) => fm
            .gates
            .get(&rule_idx)
            .is_some_and(|v| v.iter().any(|&k| k.abs_diff(off) <= GATE_RADIUS)),
    }
}

/// Per-file result of running the shared automata once.
#[derive(Default)]
pub(crate) struct FileMatch {
    /// Rules whose main regex matched somewhere.
    main: HashSet<usize>,
    src: HashSet<usize>,
    sink: HashSet<usize>,
    /// Rules whose regex anchors hit (slot encoded: 0 main, 1 src, 2 sink).
    anchors: HashSet<(usize, u8)>,
    /// rule index -> (literal index, byte offset) for every AC hit.
    lits: std::collections::HashMap<usize, Vec<(usize, usize)>>,
    /// rule index -> keyword hit offsets (gitleaks proximity gate).
    gates: std::collections::HashMap<usize, Vec<usize>>,
    /// Parse tree when the file's language has ast rules loaded.
    #[cfg(feature = "ast")]
    tree: Option<tree_sitter::Tree>,
}

impl FileMatch {
    pub(crate) fn compute(m: &Matcher, text: &str, rel: &str) -> Self {
        #[cfg(not(feature = "ast"))]
        let _ = rel;
        let mut fm = FileMatch::default();
        // case-insensitive keyword pass first: unanchored regexes of gated
        // rules can then be skipped outright when no keyword is present
        if let Some(ag) = &m.ac_gate {
            for mt in ag.find_overlapping_iter(text) {
                for &ri in &m.gate_of[mt.pattern().as_usize()] {
                    let e = fm.gates.entry(ri).or_default();
                    if e.len() < 512 {
                        e.push(mt.start());
                    }
                }
            }
        }
        for &(ri, slot, ref re) in &m.unanchored {
            if m.has_gate.contains(&ri) && !fm.gates.contains_key(&ri) {
                continue; // gated rule with no keyword in file can never fire
            }
            if re.is_match(text) {
                match slot {
                    Slot::Main => fm.main.insert(ri),
                    Slot::Source => fm.src.insert(ri),
                    Slot::Sink => fm.sink.insert(ri),
                };
            }
        }
        if let Some(ac) = &m.ac {
            for mt in ac.find_overlapping_iter(text) {
                let pat = mt.pattern().as_usize();
                let emit = |p: usize, off: usize, fm: &mut FileMatch| {
                    for &(ri, r) in &m.lit_of[p] {
                        match r {
                            LitRef::Emit(li) => {
                                let e = fm.lits.entry(ri).or_default();
                                // bounded: gates need existence, emitters
                                // cap at max_hits anyway
                                if e.len() < 512 {
                                    e.push((li, off));
                                }
                            }
                            LitRef::Anchor(s) => {
                                fm.anchors.insert((
                                    ri,
                                    match s {
                                        Slot::Main => 0,
                                        Slot::Source => 1,
                                        Slot::Sink => 2,
                                    },
                                ));
                            }
                        }
                    }
                };
                emit(pat, mt.start(), &mut fm);
            }
        }
        #[cfg(feature = "ast")]
        if let Some(lang) = crate::astscan::lang_for_path(rel)
            && m.ast_langs.contains(&lang)
        {
            fm.tree = crate::astscan::parse(lang, text);
        }
        fm
    }
}

pub(crate) fn check_file(
    rel: &str,
    text: Option<&str>,
    bytes: Option<&[u8]>,
    rule_idx: usize,
    rule: &CompiledRule,
    max_hits: usize,
    fm: &FileMatch,
) -> Vec<FileHit> {
    let mut hits = Vec::new();
    match &rule.kind {
        CompiledKind::Hash { sha256 } => {
            let b = match bytes {
                Some(b) => b,
                None => return hits,
            };
            let digest = hex_sha256(b);
            if sha256.contains(&digest) {
                hits.push(FileHit {
                    line: None,
                    excerpt: Some(format!("sha256={digest}")),
                    message: format!("{}: file hash {digest}", rule.description),
                    severity_override: None,
                });
            }
        }
        CompiledKind::SourceUrl { line_re, allowed } => {
            let text = match text {
                Some(t) => t,
                None => return hits,
            };
            if !fm.can_main(rule_idx) {
                return hits;
            }
            let mut last_off = 0usize;
            for cap in line_re.captures_iter(text) {
                if hits.len() >= max_hits {
                    return hits;
                }
                let url = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                let host = url
                    .trim_start_matches("http://")
                    .trim_start_matches("https://")
                    .split(['/', ':', '?'])
                    .next()
                    .unwrap_or("")
                    .to_lowercase();
                if host.is_empty()
                    || allowed
                        .iter()
                        .any(|a| host == *a || host.ends_with(&format!(".{a}")))
                {
                    continue;
                }
                let off = cap.get(0).map(|m| m.start()).unwrap_or(0);
                if off == last_off {
                    continue;
                }
                last_off = off;
                hits.push(FileHit {
                    line: Some(line_of(text, off)),
                    excerpt: Some(line_excerpt(text, off)),
                    message: format!("{}: dependency source `{host}`", rule.description),
                    severity_override: None,
                });
            }
        }
        CompiledKind::Path { regex } => {
            if regex.is_match(rel) {
                hits.push(FileHit {
                    line: None,
                    excerpt: None,
                    message: rule.description.clone(),
                    severity_override: None,
                });
            }
        }
        CompiledKind::Content {
            contains,
            contains_all,
            regex,
            unless,
            exclude,
            gate,
            ..
        } => {
            let text = match text {
                Some(t) => t,
                None => return hits,
            };
            if gate.is_some() && !fm.gates.contains_key(&rule_idx) {
                return hits;
            }
            if let Some(u) = unless
                && u.is_match(text)
            {
                return hits;
            }
            let lit_hits = fm.lits.get(&rule_idx).map(|v| v.as_slice()).unwrap_or(&[]);
            let lit_present =
                |li: usize| contains[li].is_empty() || lit_hits.iter().any(|&(i, _)| i == li);
            if *contains_all && !contains.is_empty() && !(0..contains.len()).all(lit_present) {
                return hits;
            }
            if !contains.is_empty() && !contains_all {
                for &(li, off) in lit_hits {
                    if hits.len() >= max_hits {
                        break;
                    }
                    if !gate_ok(gate, fm, rule_idx, off) {
                        continue;
                    }
                    hits.push(FileHit {
                        line: Some(line_of(text, off)),
                        excerpt: Some(line_excerpt(text, off)),
                        message: format!("{}: matched {:?}", rule.description, contains[li]),
                        severity_override: None,
                    });
                }
                // An empty literal matched everywhere in the old engine;
                // preserve that as a single hit at the top of the file.
                if contains.iter().any(|l| l.is_empty()) && hits.len() < max_hits {
                    hits.push(FileHit {
                        line: Some(1),
                        excerpt: Some(line_excerpt(text, 0)),
                        message: format!("{}: matched {:?}", rule.description, ""),
                        severity_override: None,
                    });
                }
            } else if *contains_all && !contains.is_empty() {
                // All present: report position of the first literal's hit.
                let off = lit_hits
                    .iter()
                    .find(|(i, _)| *i == 0)
                    .map(|&(_, p)| p)
                    .unwrap_or(0);
                if !gate_ok(gate, fm, rule_idx, off) {
                    return hits;
                }
                hits.push(FileHit {
                    line: Some(line_of(text, off)),
                    excerpt: Some(line_excerpt(text, off)),
                    message: format!(
                        "{}: all {} markers present",
                        rule.description,
                        contains.len()
                    ),
                    severity_override: None,
                });
            }
            if let Some(re) = regex
                && fm.can_main(rule_idx)
            {
                for m in re.find_iter(text) {
                    if hits.len() >= max_hits {
                        return hits;
                    }
                    if exclude.as_ref().is_some_and(|x| x.is_match(m.as_str())) {
                        continue;
                    }
                    if !gate_ok(gate, fm, rule_idx, m.start()) {
                        continue;
                    }
                    hits.push(FileHit {
                        line: Some(line_of(text, m.start())),
                        excerpt: Some(line_excerpt(text, m.start())),
                        message: format!("{}: matched /{}/", rule.description, m.as_str()),
                        severity_override: None,
                    });
                }
            }
        }
        CompiledKind::Taint {
            source,
            sink,
            sanitizers,
            ..
        } => {
            let text = match text {
                Some(t) => t,
                None => return hits,
            };
            if !(fm.can_src(rule_idx) && fm.can_sink(rule_idx)) {
                return hits; // both sides must be possible for taint to fire
            }
            hits.extend(super::taint::taint_scan(
                text, source, sink, sanitizers, rule, max_hits,
            ));
        }
        CompiledKind::Dataflow { source, sink, .. } => {
            let text = match text {
                Some(t) => t,
                None => return hits,
            };
            if !(fm.can_src(rule_idx) && fm.can_sink(rule_idx)) {
                return hits;
            }
            let s_hit = source.find(text);
            let k_hit = sink.find(text);
            if let (Some(sm), Some(km)) = (s_hit, k_hit) {
                hits.push(FileHit {
                    line: Some(line_of(text, sm.start())),
                    excerpt: Some(line_excerpt(text, km.start())),
                    message: format!(
                        "{}: source /{}/ reaches sink /{}/",
                        rule.description,
                        sm.as_str(),
                        km.as_str()
                    ),
                    severity_override: None,
                });
            }
        }
        CompiledKind::Package { names_re, versions } => {
            let text = match text {
                Some(t) => t,
                None => return hits,
            };
            if !fm.can_main(rule_idx) {
                return hits;
            }
            for cap in names_re.captures_iter(text) {
                if hits.len() >= max_hits {
                    return hits;
                }
                let Some(m) = cap.get(1) else { continue };
                let name = m.as_str();
                let window_end = (m.end() + 256).min(text.len());
                let window = &text[m.end()..window_end];
                let hit_ver = if versions.is_empty() {
                    None
                } else {
                    versions
                        .iter()
                        .find(|v| version_bounded(window, v))
                        .cloned()
                };
                if !versions.is_empty() && hit_ver.is_none() {
                    continue; // name present but no known-bad version nearby
                }
                let msg = match hit_ver {
                    Some(v) => format!("{}: `{name}` at known-bad version {v}", rule.description),
                    None => format!("{}: `{name}`", rule.description),
                };
                hits.push(FileHit {
                    line: Some(line_of(text, m.start())),
                    excerpt: Some(line_excerpt(text, m.start())),
                    message: msg,
                    severity_override: None,
                });
            }
        }
        CompiledKind::Secret {
            re,
            group,
            entropy,
            min_len,
            gate,
        } => {
            let text = match text {
                Some(t) => t,
                None => return hits,
            };
            if gate.is_some() && !fm.gates.contains_key(&rule_idx) {
                return hits;
            }
            if !fm.can_main(rule_idx) {
                return hits;
            }
            static PLACEHOLDER: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
            let ph = PLACEHOLDER.get_or_init(|| {
                regex::Regex::new(r"(?i)(x{3,}|\*+|placeholder|example|sample|dummy|changeme|your[-_ ]|<[^>]+>|\$\{|%\w+%|test[_-]?|fake|none|redact|\b0{4,}|\b1{6,}|\babc|lorem)").unwrap()
            });
            for cap in re.captures_iter(text) {
                if hits.len() >= max_hits {
                    return hits;
                }
                let gi = group.unwrap_or(1);
                let cand = cap.get(gi).map(|m| m.as_str()).unwrap_or("");
                if cand.len() < *min_len || is_placeholder(cand, ph) {
                    continue;
                }
                if shannon_entropy(cand) < *entropy {
                    continue;
                }
                if !gate_ok(
                    gate,
                    fm,
                    rule_idx,
                    cap.get(0).map(|m| m.start()).unwrap_or(0),
                ) {
                    continue;
                }
                let off = cap.get(gi).map(|m| m.start()).unwrap_or(0);
                hits.push(FileHit {
                    line: Some(line_of(text, off)),
                    excerpt: Some(mask_secret(&line_excerpt(text, off), cand)),
                    message: rule.description.clone(),
                    severity_override: None,
                });
            }
        }
        CompiledKind::Typosquat { top, .. } => {
            let text = match text {
                Some(t) => t,
                None => return hits,
            };
            for (name, off) in dep_name_candidates(rel, text) {
                if hits.len() >= max_hits {
                    return hits;
                }
                let has_nonascii = !name.is_ascii();
                let norm = crate::rules::norm_name(&name);
                let norm = norm.trim_start_matches('/').to_string();
                if norm.is_empty() || top.contains(&norm) {
                    continue;
                }
                let suspect = if has_nonascii {
                    let stripped: String = norm.chars().filter(|c| c.is_ascii()).collect();
                    !stripped.is_empty()
                        && !top.contains(&stripped)
                        && top.iter().any(|t| lev_at_most(&stripped, t, 1))
                } else {
                    top.iter().any(|t| lev_at_most(&norm, t, 1))
                };
                if suspect {
                    hits.push(FileHit {
                        line: Some(line_of(text, off)),
                        excerpt: Some(line_excerpt(text, off)),
                        message: format!(
                            "{}: `{}` is within edit distance 1 of a popular package name",
                            rule.description, name
                        ),
                        severity_override: None,
                    });
                }
            }
        }
        CompiledKind::ActionRef {
            uses_re,
            wildcard,
            malicious,
            unsafe_refs,
        } => {
            let text = match text {
                Some(t) => t,
                None => return hits,
            };
            if !fm.can_main(rule_idx) {
                return hits;
            }
            for cap in uses_re.captures_iter(text) {
                if hits.len() >= max_hits {
                    return hits;
                }
                let (reff, off) = if *wildcard {
                    (
                        cap.get(3).map(|m| m.as_str()).unwrap_or("").to_string(),
                        cap.get(0).map(|m| m.start()).unwrap_or(0),
                    )
                } else {
                    (
                        cap.get(1).map(|m| m.as_str()).unwrap_or("").to_string(),
                        cap.get(0).map(|m| m.start()).unwrap_or(0),
                    )
                };
                let matched = cap.get(0).map(|m| m.as_str()).unwrap_or("");
                let mk = |msg: String, sev| FileHit {
                    line: Some(line_of(text, off)),
                    excerpt: Some(line_excerpt(text, off)),
                    message: format!("{}: {} -> {matched}", rule.description, msg),
                    severity_override: sev,
                };
                let pinned = is_full_sha(&reff) || is_digest_pin(&reff);
                if pinned && malicious.contains(&reff.to_lowercase()) {
                    hits.push(mk(
                        format!("pinned to KNOWN-MALICIOUS ref {reff}"),
                        Some(Severity::Critical),
                    ));
                } else if pinned {
                    if matches!(unsafe_refs, UnsafeRefs::All) {
                        hits.push(mk(format!("unverifiable pin {reff}"), None));
                    }
                } else {
                    hits.push(mk(format!("mutable ref {reff}"), None));
                }
            }
        }
        #[cfg(feature = "ast")]
        CompiledKind::Ast {
            query,
            tsx_query,
            capture,
            lang,
        } => {
            let (Some(text), Some(tree)) = (text, fm.tree.as_ref()) else {
                return hits;
            };
            // a ts rule's query runs on a tsx tree via its second compiled
            // query; other language mismatches emit nothing
            let file_lang = crate::astscan::lang_for_path(rel);
            if file_lang.is_none_or(|fl| !crate::astscan::covers(*lang, fl)) {
                return hits;
            }
            let query = if file_lang == Some(crate::astscan::AstLang::Tsx) {
                tsx_query.as_deref().unwrap_or(query.as_ref())
            } else {
                query.as_ref()
            };
            let names = query.capture_names();
            // `capture` picks the named capture; default = first capture in
            // the query. A match without the wanted capture emits nothing.
            let want: Option<u32> = capture
                .as_ref()
                .and_then(|c| names.iter().position(|n| n == c).map(|i| i as u32));
            use streaming_iterator::StreamingIterator;
            let mut cursor = tree_sitter::QueryCursor::new();
            let mut iter = cursor.matches(query, tree.root_node(), text.as_bytes());
            while let Some(m) = iter.next() {
                if hits.len() >= max_hits {
                    return hits;
                }
                for cap in m.captures {
                    if let Some(w) = want
                        && cap.index != w
                    {
                        continue;
                    }
                    let node = cap.node;
                    hits.push(FileHit {
                        line: Some(node.start_position().row + 1),
                        excerpt: Some(line_excerpt(text, node.start_byte())),
                        message: format!("{}: ast `{}`", rule.description, node.kind()),
                        severity_override: None,
                    });
                    break; // one hit per query match
                }
            }
        }
    }
    hits
}

/// True if levenshtein(a, b) <= k (early-exit banded check).
/// Counts adjacent transpositions as one edit (damerau variant).
pub(crate) fn lev_at_most(a: &str, b: &str, k: usize) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len().abs_diff(b.len()) > k {
        return false;
    }
    let (m, n) = (a.len(), b.len());
    let mut prev2 = vec![0usize; n + 1];
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut cur = vec![0usize; n + 1];
    for i in 1..=m {
        cur[0] = i;
        let mut row_min = cur[0];
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
            // adjacent transposition (classic typosquat shape)
            if i >= 2 && j >= 2 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                cur[j] = cur[j].min(prev2[j - 2] + 1);
            }
            row_min = row_min.min(cur[j]);
        }
        if row_min > k {
            return false;
        }
        std::mem::swap(&mut prev2, &mut prev);
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[n] <= k
}

pub(crate) fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    for b in s.as_bytes() {
        counts[*b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn is_placeholder(s: &str, ph: &regex::Regex) -> bool {
    if ph.is_match(s) {
        return true;
    }
    // low-variety strings: <=4 distinct chars
    s.as_bytes()
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len()
        <= 4
}

/// Redact the secret inside the excerpt before reporting.
fn mask_secret(line: &str, secret: &str) -> String {
    if secret.len() < 8 {
        return line.to_string();
    }
    // char-aware slicing: a token with multibyte chars must not panic
    // mid-scan
    let head: String = secret.chars().take(4).collect();
    let tail: String = secret
        .chars()
        .rev()
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let masked = format!("{head}...{tail}");
    line.replace(secret, &masked)
}

/// True when `version` appears in `window` as its own token.
/// A longer version that merely contains the bad string does not count:
/// 6.0.0 is not 16.0.0, and 5.6.1 is not 5.6.10.
fn version_bounded(window: &str, version: &str) -> bool {
    if version.is_empty() {
        return false;
    }
    let bytes = window.as_bytes();
    let needle = version.as_bytes();
    let mut from = 0;
    while from + needle.len() <= bytes.len() {
        let Some(rel) = window[from..].find(version) else {
            break;
        };
        let at = from + rel;
        let before_ok = at == 0 || !bytes[at - 1].is_ascii_alphanumeric();
        let after = at + needle.len();
        let after_ok = after >= bytes.len() || !bytes[after].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        from = at + 1;
    }
    false
}

#[cfg(test)]
mod version_bounds {
    use super::version_bounded;

    #[test]
    fn longer_versions_do_not_match() {
        assert!(version_bounded(r#""6.0.0""#, "6.0.0"));
        assert!(!version_bounded(r#""16.0.0""#, "6.0.0"));
        assert!(!version_bounded(r#""5.6.10""#, "5.6.1"));
        assert!(version_bounded("axios@1.14.1", "1.14.1"));
        assert!(!version_bounded("axios@1.14.10", "1.14.1"));
        assert!(!version_bounded("axios@11.14.1", "1.14.1"));
    }
}

#[cfg(test)]
mod matcher_tests {
    use super::*;

    fn content_rule(id: &str, contains: &[&str]) -> CompiledRule {
        CompiledRule {
            set: "t".into(),
            id: id.into(),
            severity: crate::finding::Severity::High,
            description: "t".into(),
            remediation: None,
            reference: None,
            window: None,
            kind: CompiledKind::Content {
                path: None,
                contains: contains.iter().map(|s| s.to_string()).collect(),
                contains_all: false,
                regex: None,
                unless: None,
                exclude: None,
                gate: None,
            },
        }
    }

    #[test]
    fn contains_literal_emits() {
        let rules = [content_rule("R1", &["skyleen.fr"])];
        let m = Matcher::build(rules.iter());
        let fm = FileMatch::compute(&m, "beacon skyleen.fr\n", "x.txt");
        assert!(
            fm.lits.get(&0).is_some_and(|v| !v.is_empty()),
            "no lit hit recorded for skyleen.fr: {:?}",
            fm.lits
        );
    }

    #[test]
    fn nested_literals_all_report() {
        // "m-kosche.com" inside "t.m-kosche.com": overlapping iteration
        // must credit both rules
        let rules = [
            content_rule("R-long", &["t.m-kosche.com"]),
            content_rule("R-short", &["m-kosche.com"]),
        ];
        let m = Matcher::build(rules.iter());
        let fm = FileMatch::compute(&m, "x t.m-kosche.com y", "x.txt");
        assert!(fm.lits.get(&0).is_some_and(|v| !v.is_empty()));
        assert!(fm.lits.get(&1).is_some_and(|v| !v.is_empty()));
    }

    #[test]
    fn short_literal_does_not_eat_longer() {
        // a 2-byte keyword ("sk") starting at the same position must not
        // suppress the longer contains literal under it
        let rules = [
            content_rule("R-emit", &["skyleen.fr"]),
            CompiledRule {
                set: "t".into(),
                id: "R-gate".into(),
                severity: crate::finding::Severity::Low,
                description: "t".into(),
                remediation: None,
                reference: None,
                window: None,
                kind: CompiledKind::Content {
                    path: None,
                    contains: vec![],
                    contains_all: false,
                    regex: None,
                    unless: None,
                    exclude: None,
                    gate: Some(vec!["sk".to_string()]),
                },
            },
        ];
        let m = Matcher::build(rules.iter());
        let fm = FileMatch::compute(&m, "# beacon skyleen.fr\n", "x.txt");
        assert!(fm.lits.get(&0).is_some_and(|v| !v.is_empty()));
        assert!(fm.gates.contains_key(&1));
    }

    #[test]
    fn anchor_gates_and_unanchors() {
        let rules = [CompiledRule {
            set: "t".into(),
            id: "R-anchor".into(),
            severity: crate::finding::Severity::High,
            description: "t".into(),
            remediation: None,
            reference: None,
            window: None,
            kind: CompiledKind::Content {
                path: None,
                contains: vec![],
                contains_all: false,
                regex: Some(regex::Regex::new("skyleen\\.fr/[a-z0-9]+").unwrap()),
                unless: None,
                exclude: None,
                gate: None,
            },
        }];
        let m = Matcher::build(rules.iter());
        let fm = FileMatch::compute(&m, "skyleen.fr/x", "x.txt");
        assert!(fm.can_main(0));
        let fm2 = FileMatch::compute(&m, "nothing here", "x.txt");
        assert!(!fm2.can_main(0));
    }

    #[test]
    fn builtin_set_finds_sck003_and_telegram() {
        // the full builtin table once swallowed "skyleen.fr" under a
        // shorter keyword - overlapping iteration is load-bearing
        let rules = crate::rules::load(&[], false).unwrap().0;
        let m = Matcher::build(rules.iter());
        let idx = rules.iter().position(|r| r.id == "SCK-003").unwrap();
        let fm = FileMatch::compute(&m, "# beacon skyleen.fr\n", "requirements.txt");
        assert!(fm.lits.get(&idx).is_some_and(|v| !v.is_empty()));
        let idx2 = rules.iter().position(|r| r.id == "MAL-011").unwrap();
        let fm2 = FileMatch::compute(
            &m,
            "u='https://api.telegram.org/bot123456789:AAFHnqXzCm0g9h7KvLpJmWsYdErTuIoPbN2/x'",
            "c2.py",
        );
        assert!(fm2.can_main(idx2));
    }
}
