// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Per-commit secrets scan over git history. Secrets that were committed
//! and later removed still leak - they must be rotated, not deleted.
//!
//! On top of emitting one finding per (commit, file) hit, this module keeps
//! a per-token provenance timeline: which commits added the secret and
//! which removed it, keyed by a non-reversible fingerprint of the matched
//! text (findings only ever carry masked excerpts, so the fingerprint is
//! derived before masking). Combined with a fingerprint set for the
//! checked-out tree, each finding can then say whether the credential is
//! still at HEAD, was deleted at some commit, or vanished and reappeared.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use sha2::Digest;

use crate::finding::Finding;
use crate::rules::{CompiledKind, CompiledRule};
use crate::scan::{ScanOptions, collect_files, rel_path, scan_file};

const MAX_COMMITS: usize = 500;

/// Keyword proximity radius for gated rules; mirrors engine::GATE_RADIUS,
/// which is private to the scan module.
const GATE_RADIUS: usize = 250;

/// Whether the token entered or left the tree at a commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvKind {
    Added,
    Removed,
}

/// One provenance event: (committer unix ts, commit sha, kind).
pub type HistEvent = (i64, String, EvKind);

/// Rotation verdict for one token fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RotState {
    /// Token is at HEAD, or was never seen removed on a scanned ref.
    Live,
    /// Token left the tree; last_seen is the commit that removed it.
    Removed { last_seen: String },
    /// Token was added, removed, then added again later - the classic
    /// revert-or-reintroduce pattern that makes "deleted" keys live again.
    Reappeared { gap_at: String },
    /// No events recorded for the fingerprint.
    Unknown,
}

/// Raw candidate extracted from text before masking. history.rs needs the
/// real bytes to fingerprint; Finding only exposes a masked excerpt.
struct Cand {
    rule_id: String,
    token: String,
    line: usize,
}

/// sha256(rule_id:first4:last4:len) - stable for the same token under the
/// same rule, intentionally not reversible, and safe to put in reports.
/// Never feed the raw secret anywhere else.
pub fn secret_fingerprint(rule_id: &str, token: &str) -> String {
    // char-aware ends: a multibyte token must not slice mid-codepoint
    let head: String = token.chars().take(4).collect();
    let tail: String = token
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let mut h = sha2::Sha256::new();
    h.update(format!("{rule_id}:{head}:{tail}:{}", token.len()).as_bytes());
    h.finalize().iter().map(|x| format!("{x:02x}")).collect()
}

/// Pure state machine over one token's event timeline. in_head is ground
/// truth for "in the checked-out tree right now"; without it a token whose
/// last event is an add is still treated as live because --all covers every
/// ref, not just the checkout.
pub fn rotation_state(events: &[HistEvent], in_head: bool) -> RotState {
    if in_head {
        return RotState::Live;
    }
    if events.is_empty() {
        return RotState::Unknown;
    }
    let mut evs = events.to_vec();
    // Chronological order across branches.
    evs.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut present = false;
    let mut seen_add = false;
    let mut readd: Option<String> = None;
    let mut last_remove: Option<String> = None;
    // Process one commit at a time: a rewrite shows the token on both - and
    // + lines, meaning it never left the tree. Per commit, "still there
    // afterwards" (any add) wins over "left" (only removals).
    let mut i = 0;
    while i < evs.len() {
        let (ts, ref sha, _) = evs[i];
        let mut j = i;
        let (mut has_add, mut has_rem) = (false, false);
        while j < evs.len() && evs[j].0 == ts && evs[j].1 == *sha {
            match evs[j].2 {
                EvKind::Added => has_add = true,
                EvKind::Removed => has_rem = true,
            }
            j += 1;
        }
        if has_add {
            if seen_add && !present {
                // re-added after an absence; keep the latest one. Same-commit
                // -/+ pairs (has_rem) only reach this branch when the token
                // was believed absent, i.e. a genuine reintroduction.
                readd = Some(sha.clone());
            }
            present = true;
            seen_add = true;
        }
        if has_rem && !has_add {
            present = false;
            last_remove = Some(sha.clone());
        }
        i = j;
    }
    // the anomaly outranks the calm "removed" verdict: a token that came
    // back once can come back again, so it always deserves the flag
    if let Some(sha) = readd {
        return RotState::Reappeared { gap_at: sha };
    }
    if !present {
        return RotState::Removed {
            last_seen: last_remove.unwrap_or_else(|| evs.last().unwrap().1.clone()),
        };
    }
    RotState::Live
}

/// Human-facing evidence line for a rotation verdict. head_scanned marks
/// whether a HEAD fingerprint set was supplied; without it we cannot claim
/// anything about the current tree, only about history.
fn rotation_evidence(state: &RotState, in_head: bool, head_scanned: bool) -> Option<String> {
    let short = |s: &str| s[..12.min(s.len())].to_string();
    match state {
        RotState::Live if in_head => {
            Some("still present at HEAD - rotate and purge history".into())
        }
        RotState::Live => Some("still present on a scanned ref - rotate and purge history".into()),
        RotState::Removed { last_seen } if head_scanned => Some(format!(
            "not present in current tree since {} - confirm rotation, history still leaks it",
            short(last_seen)
        )),
        RotState::Removed { last_seen } => Some(format!(
            "removed in {} - confirm rotation, history still leaks it",
            short(last_seen)
        )),
        RotState::Reappeared { gap_at } => Some(format!(
            "reappeared in {} after absence - likely reverted or reintroduced",
            short(gap_at)
        )),
        RotState::Unknown => None,
    }
}

/// Same placeholder heuristics the engine applies to secret candidates.
/// Duplicated because engine::is_placeholder is private; keep in sync.
fn is_placeholder(s: &str) -> bool {
    static PH: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let ph = PH.get_or_init(|| {
        regex::Regex::new(r"(?i)(x{3,}|\*+|placeholder|example|sample|dummy|changeme|your[-_ ]|<[^>]+>|\$\{|%\w+%|test[_-]?|fake|none|redact|\b0{4,}|\b1{6,}|\babc|lorem)").unwrap()
    });
    if ph.is_match(s) {
        return true;
    }
    s.as_bytes().iter().collect::<HashSet<_>>().len() <= 4
}

fn line_of(text: &str, byte_off: usize) -> usize {
    text[..byte_off].bytes().filter(|&b| b == b'\n').count() + 1
}

/// Lowercased gate-keyword hit offsets per rule index, capped at the
/// engine's 512-entry bound so pathological files stay cheap.
fn gate_offsets(rules: &[&CompiledRule], text: &str) -> HashMap<usize, Vec<usize>> {
    let lower = text.to_lowercase();
    let mut out = HashMap::new();
    for (i, r) in rules.iter().enumerate() {
        let kws = match &r.kind {
            CompiledKind::Secret { gate: Some(g), .. }
            | CompiledKind::Content { gate: Some(g), .. } => g,
            _ => continue,
        };
        let mut v = Vec::new();
        for kw in kws {
            let kl = kw.to_lowercase();
            if kl.is_empty() {
                continue;
            }
            for (off, _) in lower.match_indices(&kl) {
                if v.len() >= 512 {
                    break;
                }
                v.push(off);
            }
        }
        if !v.is_empty() {
            out.insert(i, v);
        }
    }
    out
}

/// Replica of engine::gate_ok: a gated hit needs a keyword within
/// GATE_RADIUS bytes of the match start.
fn gate_ok(
    gate: &Option<Vec<String>>,
    kpos: &HashMap<usize, Vec<usize>>,
    ri: usize,
    off: usize,
) -> bool {
    match gate {
        None => true,
        Some(_) => kpos
            .get(&ri)
            .is_some_and(|v| v.iter().any(|&k| k.abs_diff(off) <= GATE_RADIUS)),
    }
}

/// Extract the raw secret-shaped tokens rules would report on text.
/// The engine's FileHit keeps the candidate private, so the Secret and
/// Content branches are re-run here with the same filters (capture group,
/// min_len, entropy, placeholder, gate, per-rule hit cap) - the fingerprint
/// must come from the unmasked match.
fn candidates_in_text(
    rel: &str,
    text: &str,
    rules: &[&CompiledRule],
    max_hits: usize,
) -> Vec<Cand> {
    let kpos = gate_offsets(rules, text);
    let mut out: Vec<Cand> = Vec::new();
    for (i, rule) in rules.iter().enumerate() {
        let base = out.len();
        let room = |out: &Vec<Cand>| out.len() - base < max_hits;
        match &rule.kind {
            CompiledKind::Secret {
                re,
                group,
                entropy,
                min_len,
                gate,
            } => {
                for cap in re.captures_iter(text) {
                    if !room(&out) {
                        break;
                    }
                    let gi = group.unwrap_or(1);
                    let cand = cap.get(gi).map(|m| m.as_str()).unwrap_or("");
                    if cand.len() < *min_len
                        || is_placeholder(cand)
                        || crate::scan::engine::shannon_entropy(cand) < *entropy
                    {
                        continue;
                    }
                    let m0 = cap.get(0).map(|m| m.start()).unwrap_or(0);
                    if !gate_ok(gate, &kpos, i, m0) {
                        continue;
                    }
                    let off = cap.get(gi).map(|m| m.start()).unwrap_or(0);
                    out.push(Cand {
                        rule_id: rule.id.clone(),
                        token: cand.to_string(),
                        line: line_of(text, off),
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
                if gate.is_some() && !kpos.contains_key(&i) {
                    continue;
                }
                if let Some(u) = unless
                    && u.is_match(text)
                {
                    continue;
                }
                if *contains_all && !contains.is_empty() {
                    // the rule needs every needle; partial presence cannot fire
                    if contains
                        .iter()
                        .all(|l| l.is_empty() || text.contains(l.as_str()))
                        && room(&out)
                    {
                        let off = contains
                            .iter()
                            .find(|l| !l.is_empty())
                            .and_then(|l| text.find(l.as_str()))
                            .unwrap_or(0);
                        out.push(Cand {
                            rule_id: rule.id.clone(),
                            token: contains[0].clone(),
                            line: line_of(text, off),
                        });
                    }
                } else {
                    for l in contains {
                        if l.is_empty() {
                            continue;
                        }
                        for (off, _) in text.match_indices(l.as_str()) {
                            if !room(&out) {
                                break;
                            }
                            if !gate_ok(gate, &kpos, i, off) {
                                continue;
                            }
                            out.push(Cand {
                                rule_id: rule.id.clone(),
                                token: l.clone(),
                                line: line_of(text, off),
                            });
                        }
                    }
                }
                if let Some(re) = regex {
                    for m in re.find_iter(text) {
                        if !room(&out) {
                            break;
                        }
                        if exclude.as_ref().is_some_and(|x| x.is_match(m.as_str())) {
                            continue;
                        }
                        if !gate_ok(gate, &kpos, i, m.start()) {
                            continue;
                        }
                        out.push(Cand {
                            rule_id: rule.id.clone(),
                            token: m.as_str().to_string(),
                            line: line_of(text, m.start()),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    // SEC-090 entropy pass, under the same guards scan.rs applies
    if !rules.is_empty()
        && !crate::entropy::is_lockfile_name(rel)
        && !crate::entropy::is_generated(text)
    {
        for (ln, line) in text.lines().enumerate() {
            for tok in crate::entropy::tokens(line) {
                out.push(Cand {
                    rule_id: "SEC-090".into(),
                    token: tok,
                    line: ln + 1,
                });
            }
        }
    }
    out
}

/// head4...tail3 shapes produced by the engine's masking.
fn masked_shapes(excerpt: &str) -> Vec<(String, String)> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new("[A-Za-z0-9+/=_-]{4}\\.\\.\\.[A-Za-z0-9+/=_-]{3}").unwrap()
    });
    re.find_iter(excerpt)
        .map(|m| {
            let s = m.as_str();
            (s[..4].to_string(), s[s.len() - 3..].to_string())
        })
        .collect()
}

fn tokenish(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 512
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "+/=_-.".contains(c))
}

/// Tie a finding back to the exact raw token it reported, so the right
/// fingerprint gets the timeline. Order: the raw match content rules echo
/// into the message, a verbatim token in the excerpt, the masked
/// head...tail shape, then a unique-candidate fallback on (rule, line).
fn resolve_fp(f: &Finding, cands: &[Cand]) -> Option<String> {
    let pool: Vec<&Cand> = cands.iter().filter(|c| c.rule_id == f.rule_id).collect();
    if pool.is_empty() {
        return None;
    }
    let by_line: Vec<&Cand> = pool
        .iter()
        .copied()
        .filter(|c| f.line == Some(c.line))
        .collect();
    let pool = if by_line.is_empty() { pool } else { by_line };
    // content rules report the raw match as desc: matched /tok/; the
    // history scanner appends  (committed in ..) afterwards
    if let Some(pos) = f.message.rfind("matched /") {
        let tail = &f.message[pos + "matched /".len()..];
        let tail = tail.split(" (committed in").next().unwrap_or(tail);
        let tail = tail.strip_suffix('/').unwrap_or(tail);
        if tokenish(tail) {
            if let Some(c) = pool.iter().find(|c| c.token == tail) {
                return Some(secret_fingerprint(&f.rule_id, &c.token));
            }
            // not in the candidate pool (deduped or capped there), but the
            // message token is authoritative
            return Some(secret_fingerprint(&f.rule_id, tail));
        }
    }
    if let Some(ex) = &f.excerpt {
        // short or low-entropy matches are left unmasked in the excerpt
        for c in &pool {
            if c.token.len() >= 4 && ex.contains(&c.token) {
                return Some(secret_fingerprint(&f.rule_id, &c.token));
            }
        }
        let shapes = masked_shapes(ex);
        let mut hits: Vec<&Cand> = pool
            .iter()
            .copied()
            .filter(|c| {
                shapes
                    .iter()
                    .any(|(h, t)| c.token.starts_with(h.as_str()) && c.token.ends_with(t.as_str()))
            })
            .collect();
        // deterministic pick when several tokens share a mask shape
        hits.sort_by(|a, b| a.token.cmp(&b.token));
        hits.dedup_by(|a, b| a.token == b.token);
        if let Some(c) = hits.first() {
            return Some(secret_fingerprint(&f.rule_id, &c.token));
        }
    }
    if pool.len() == 1 {
        return Some(secret_fingerprint(&f.rule_id, &pool[0].token));
    }
    None
}

/// Accumulates findings, per-finding fingerprints, and the fp -> event
/// timeline while the git log stream is parsed.
struct Ctx<'a> {
    secrets: &'a [&'a CompiledRule],
    opts: &'a ScanOptions,
    target: &'a str,
    findings: Vec<Finding>,
    finding_fps: Vec<Option<String>>,
    events: HashMap<String, Vec<HistEvent>>,
}

impl Ctx<'_> {
    fn record(&mut self, fp: String, sha: &str, ts: i64, kind: EvKind) {
        let e = self.events.entry(fp).or_default();
        if !e.iter().any(|x| x.1 == sha && x.2 == kind) {
            e.push((ts, sha.to_string(), kind));
        }
    }

    /// Process one (commit, file) diff chunk: added lines produce findings
    /// and Added events, removed lines produce Removed events. Without the
    /// removal side a deleted secret looks identical to a live one.
    /// dfile is the --- a/ name, which for deletions is the only real
    /// path (+++ /dev/null carries none).
    fn flush(
        &mut self,
        sha: &str,
        ts: i64,
        file: &str,
        dfile: &str,
        adds: &mut Vec<String>,
        dels: &mut Vec<String>,
    ) {
        if !sha.is_empty() && !file.is_empty() && !adds.is_empty() {
            let rel = format!("{file}@{sha_short}", sha_short = &sha[..8.min(sha.len())]);
            let body = adds.join("\n");
            let cands =
                candidates_in_text(&rel, &body, self.secrets, self.opts.max_per_rule_per_file);
            for mut f in scan_file(
                &rel,
                Some(&body),
                None,
                self.secrets,
                self.opts,
                self.target,
            ) {
                f.message = format!("{} (committed in {})", f.message, &sha[..12.min(sha.len())]);
                self.finding_fps.push(resolve_fp(&f, &cands));
                self.findings.push(f);
            }
            for c in &cands {
                self.record(
                    secret_fingerprint(&c.rule_id, &c.token),
                    sha,
                    ts,
                    EvKind::Added,
                );
            }
        }
        adds.clear();
        if !sha.is_empty() && !dels.is_empty() {
            let dfile = if dfile.is_empty() { file } else { dfile };
            let rel = format!("{dfile}@{sha_short}", sha_short = &sha[..8.min(sha.len())]);
            let body = dels.join("\n");
            for c in candidates_in_text(&rel, &body, self.secrets, self.opts.max_per_rule_per_file)
            {
                self.record(
                    secret_fingerprint(&c.rule_id, &c.token),
                    sha,
                    ts,
                    EvKind::Removed,
                );
            }
        }
        dels.clear();
    }
}

/// Scan added lines of git log --all -p for each commit. Returns one
/// finding group per (commit, file) that carries a secret rule hit.
/// Provenance that requires knowing the checked-out tree is annotated in a
/// weaker form: use scan_history_provenance when a HEAD fingerprint set is
/// available.
#[allow(dead_code)] // compat shim: misc.rs uses scan_history_provenance
pub fn scan_history(
    root: &Path,
    rules: &[CompiledRule],
    opts: &ScanOptions,
    target: &str,
    verbose: u8,
) -> Vec<Finding> {
    scan_history_inner(root, rules, opts, target, verbose, None)
}

/// Same scan, plus rotation provenance. head is the fingerprint set for
/// secrets in the checked-out tree (see head_secret_fps); each finding gets
/// an evidence line saying whether the token is still at HEAD, when it left
/// the tree, or whether it reappeared after an absence.
pub fn scan_history_provenance(
    root: &Path,
    rules: &[CompiledRule],
    opts: &ScanOptions,
    target: &str,
    verbose: u8,
    head: &HashSet<String>,
) -> Vec<Finding> {
    scan_history_inner(root, rules, opts, target, verbose, Some(head))
}

fn scan_history_inner(
    root: &Path,
    rules: &[CompiledRule],
    opts: &ScanOptions,
    target: &str,
    verbose: u8,
    head: Option<&HashSet<String>>,
) -> Vec<Finding> {
    let secrets: Vec<&CompiledRule> = rules.iter().filter(|r| r.set == "secrets").collect();
    if secrets.is_empty() {
        return Vec::new();
    }
    // %ct (committer time) lets events sort chronologically even though
    // --all interleaves branch order.
    let out = std::process::Command::new("git")
        .args([
            "-C",
            &root.display().to_string(),
            "log",
            "--all",
            "--format=commit %H %ct",
            "-p",
            "-U0",
            "--no-color",
            &format!("-n{MAX_COMMITS}"),
        ])
        .output();
    let Ok(o) = out else {
        return Vec::new();
    };
    if !o.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&o.stdout);
    let mut ctx = Ctx {
        secrets: &secrets,
        opts,
        target,
        findings: Vec::new(),
        finding_fps: Vec::new(),
        events: HashMap::new(),
    };
    let mut sha = String::new();
    let mut ts: i64 = 0;
    let mut file = String::new();
    let mut dfile = String::new();
    let mut adds: Vec<String> = Vec::new();
    let mut dels: Vec<String> = Vec::new();
    let mut count = 0;
    for line in text.lines() {
        if let Some(s) = line.strip_prefix("commit ") {
            ctx.flush(&sha, ts, &file, &dfile, &mut adds, &mut dels);
            let mut it = s.split_whitespace();
            sha = it.next().unwrap_or("").to_string();
            ts = it.next().and_then(|t| t.parse().ok()).unwrap_or(0);
            file.clear();
            dfile.clear();
            count += 1;
            if count > MAX_COMMITS {
                break;
            }
        } else if let Some(f) = line.strip_prefix("+++ b/") {
            ctx.flush(&sha, ts, &file, &dfile, &mut adds, &mut dels);
            file = f.to_string();
            dfile.clear();
        } else if let Some(f) = line.strip_prefix("--- a/") {
            dfile = f.to_string();
        } else if line.starts_with("+++") || line.starts_with("---") {
            // /dev/null or old-name headers, not content
        } else if let Some(l) = line.strip_prefix('+') {
            adds.push(l.to_string());
        } else if let Some(l) = line.strip_prefix('-') {
            dels.push(l.to_string());
        }
    }
    ctx.flush(&sha, ts, &file, &dfile, &mut adds, &mut dels);
    let head_scanned = head.is_some();
    let empty = HashSet::new();
    let head = head.unwrap_or(&empty);
    for (f, fpo) in ctx.findings.iter_mut().zip(ctx.finding_fps.iter()) {
        let Some(fp) = fpo else { continue };
        let evs = ctx.events.get(fp).map(|v| v.as_slice()).unwrap_or(&[]);
        let in_head = head.contains(fp);
        let state = rotation_state(evs, in_head);
        let mut ev = f.evidence.take().unwrap_or_default();
        if let Some(msg) = rotation_evidence(&state, in_head, head_scanned) {
            ev.push(msg);
        }
        // a stable short fp lets identical tokens be correlated across
        // findings and commits without ever storing the secret
        ev.push(format!("secret fp {}", &fp[..16.min(fp.len())]));
        f.evidence = Some(ev);
    }
    if verbose > 0 {
        eprintln!(
            "history: scanned {} commits, {} secret findings, {} token fingerprints",
            count.min(MAX_COMMITS),
            ctx.findings.len(),
            ctx.events.len()
        );
    }
    ctx.findings
}

/// Fingerprint every secret-shaped token in one working-tree file. path
/// doubles as the relative name for path-scoped rules, so callers should
/// pass a repo-relative path for correct scoping.
#[allow(dead_code)] // library entry point: callers use head_secret_fps
pub fn fingerprint_file_secrets(
    path: &Path,
    rules: &[CompiledRule],
    opts: &ScanOptions,
) -> HashSet<String> {
    let rel = path.to_string_lossy().into_owned();
    fingerprint_path(&rel, path, rules, opts)
}

fn fingerprint_path(
    rel: &str,
    path: &Path,
    rules: &[CompiledRule],
    opts: &ScanOptions,
) -> HashSet<String> {
    let mut out = HashSet::new();
    let Ok(meta) = path.metadata() else {
        return out;
    };
    if meta.len() > opts.max_file_size {
        return out;
    }
    let Ok(bytes) = std::fs::read(path) else {
        return out;
    };
    // binary blobs only ever carry test-vector-shaped literals; the real
    // scanner drops secrets findings on binaries too
    if crate::scan::looks_binary(&bytes) {
        return out;
    }
    let text = String::from_utf8_lossy(&bytes);
    let scope: Vec<&CompiledRule> = rules
        .iter()
        .filter(|r| r.set == "secrets" && r.path_in_scope(rel))
        .collect();
    for c in candidates_in_text(rel, &text, &scope, opts.max_per_rule_per_file) {
        out.insert(secret_fingerprint(&c.rule_id, &c.token));
    }
    out
}

/// Fingerprint every secret-shaped token in the checked-out tree at root.
/// Same matching rules as a real scan minus reporting, so a token that only
/// survives in history can be told apart from one still present at HEAD.
/// Sequential walk: fine for history scans, but it reads every file a
/// second time - fold into the main scan walk if that ever hurts.
pub fn head_secret_fps(root: &Path, rules: &[CompiledRule], opts: &ScanOptions) -> HashSet<String> {
    let mut out = HashSet::new();
    for f in collect_files(root, opts.include_git, opts.prune) {
        let rel = rel_path(root, &f);
        if opts.exclude.iter().any(|re| re.is_match(&rel)) {
            continue;
        }
        out.extend(fingerprint_path(&rel, &f, rules, opts));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;

    fn ev(ts: i64, sha: &str, k: EvKind) -> HistEvent {
        (ts, sha.to_string(), k)
    }

    #[test]
    fn rotation_state_transitions() {
        // no information at all
        assert_eq!(rotation_state(&[], false), RotState::Unknown);
        // head membership always wins
        assert_eq!(rotation_state(&[], true), RotState::Live);
        assert_eq!(
            rotation_state(
                &[ev(1, "a", EvKind::Added), ev(2, "b", EvKind::Removed)],
                true
            ),
            RotState::Live
        );
        // added and never removed: still on a scanned ref even if not at HEAD
        assert_eq!(
            rotation_state(&[ev(1, "a", EvKind::Added)], false),
            RotState::Live
        );
        // added then removed: the removing commit is the "since" marker
        assert_eq!(
            rotation_state(
                &[ev(1, "a", EvKind::Added), ev(2, "b", EvKind::Removed)],
                false
            ),
            RotState::Removed {
                last_seen: "b".into()
            }
        );
        // removed without a scanned add (history truncated): still removed
        assert_eq!(
            rotation_state(&[ev(2, "b", EvKind::Removed)], false),
            RotState::Removed {
                last_seen: "b".into()
            }
        );
        // add, remove, re-add: the gap is what matters even if removed again
        assert_eq!(
            rotation_state(
                &[
                    ev(1, "a", EvKind::Added),
                    ev(2, "b", EvKind::Removed),
                    ev(3, "c", EvKind::Added),
                    ev(4, "d", EvKind::Removed),
                ],
                false
            ),
            RotState::Reappeared { gap_at: "c".into() }
        );
        // events arrive newest-first from git log; sorting must fix order
        assert_eq!(
            rotation_state(
                &[
                    ev(3, "c", EvKind::Added),
                    ev(1, "a", EvKind::Added),
                    ev(2, "b", EvKind::Removed),
                ],
                false
            ),
            RotState::Reappeared { gap_at: "c".into() }
        );
        // same-commit rewrite (-old/+new) nets to still present
        assert_eq!(
            rotation_state(
                &[
                    ev(1, "a", EvKind::Added),
                    ev(2, "b", EvKind::Removed),
                    ev(2, "b", EvKind::Added)
                ],
                false
            ),
            RotState::Live
        );
    }

    #[test]
    fn fingerprint_is_stable_and_masked() {
        let fp = secret_fingerprint("SEC-001", "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(fp.len(), 64);
        assert_eq!(fp, secret_fingerprint("SEC-001", "AKIAIOSFODNN7EXAMPLE"));
        // same token under another rule fingerprints differently
        assert_ne!(fp, secret_fingerprint("SEC-999", "AKIAIOSFODNN7EXAMPLE"));
        assert!(!fp.contains("AKIA"));
    }

    fn git(dir: &Path, args: &[&str], date: &str) {
        let st = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.email=t@example.com",
                "-c",
                "user.name=T",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .env("GIT_AUTHOR_DATE", date)
            .env("GIT_COMMITTER_DATE", date)
            .status()
            .unwrap();
        assert!(st.success());
    }

    fn head_sha(dir: &Path) -> String {
        let o = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }

    fn repo(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "argus-hist-{}-{tag}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-q"], "2026-01-01T00:00:00Z");
        dir
    }

    fn commit_file(dir: &Path, body: Option<&str>, msg: &str, date: &str) {
        let f = dir.join("keys.txt");
        match body {
            Some(b) => std::fs::write(&f, b).unwrap(),
            None => std::fs::remove_file(&f).unwrap(),
        }
        git(dir, &["add", "-A"], date);
        git(dir, &["commit", "-q", "-m", msg], date);
    }

    fn evidence_of(f: &Finding) -> String {
        f.evidence.clone().unwrap_or_default().join(" | ")
    }

    const KEY: &str = "AKIAIOSFODNN7EXAMPLE";

    #[test]
    fn removed_secret_is_flagged_not_at_head() {
        let dir = repo("removed");
        commit_file(
            &dir,
            Some(&format!("aws_key = {KEY}\n")),
            "add key",
            "2026-01-02T00:00:00Z",
        );
        commit_file(&dir, None, "remove key", "2026-01-03T00:00:00Z");
        let (rules, _) = crate::rules::load(&[], false).unwrap();
        let opts = ScanOptions::default();
        let head = head_secret_fps(&dir, &rules, &opts);
        assert!(!head.contains(&secret_fingerprint("SEC-001", KEY)));
        let fs = scan_history_provenance(&dir, &rules, &opts, "t", 0, &head);
        let f = fs
            .iter()
            .find(|f| f.rule_id == "SEC-001")
            .expect("SEC-001 hit");
        let ev = evidence_of(f);
        assert!(
            ev.contains("not present in current tree since"),
            "evidence: {ev}"
        );
        assert!(ev.contains("secret fp "), "evidence: {ev}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn live_secret_is_flagged_at_head() {
        let dir = repo("live");
        commit_file(
            &dir,
            Some(&format!("aws_key = {KEY}\n")),
            "add key",
            "2026-01-02T00:00:00Z",
        );
        let (rules, _) = crate::rules::load(&[], false).unwrap();
        let opts = ScanOptions::default();
        let head = head_secret_fps(&dir, &rules, &opts);
        assert!(head.contains(&secret_fingerprint("SEC-001", KEY)));
        let fs = scan_history_provenance(&dir, &rules, &opts, "t", 0, &head);
        let f = fs
            .iter()
            .find(|f| f.rule_id == "SEC-001")
            .expect("SEC-001 hit");
        assert!(
            evidence_of(f).contains("still present at HEAD"),
            "evidence: {}",
            evidence_of(f)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reappeared_secret_is_flagged() {
        let dir = repo("reappeared");
        let body = format!("aws_key = {KEY}\n");
        commit_file(&dir, Some(&body), "add key", "2026-01-02T00:00:00Z");
        commit_file(&dir, None, "remove key", "2026-01-03T00:00:00Z");
        commit_file(
            &dir,
            Some(&body),
            "revert reintroduces key",
            "2026-01-04T00:00:00Z",
        );
        let readd_sha = head_sha(&dir);
        commit_file(&dir, None, "remove key again", "2026-01-05T00:00:00Z");
        let (rules, _) = crate::rules::load(&[], false).unwrap();
        let opts = ScanOptions::default();
        let head = head_secret_fps(&dir, &rules, &opts);
        let fs = scan_history_provenance(&dir, &rules, &opts, "t", 0, &head);
        let f = fs
            .iter()
            .find(|f| f.rule_id == "SEC-001")
            .expect("SEC-001 hit");
        let ev = evidence_of(f);
        assert!(ev.contains("reappeared in"), "evidence: {ev}");
        assert!(
            ev.contains(&readd_sha[..12]),
            "evidence {ev} should name re-add commit {readd_sha}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn plain_scan_history_still_works() {
        // the head-less wrapper must not claim anything about the live tree
        let dir = repo("plain");
        commit_file(
            &dir,
            Some(&format!("aws_key = {KEY}\n")),
            "add key",
            "2026-01-02T00:00:00Z",
        );
        commit_file(&dir, None, "remove key", "2026-01-03T00:00:00Z");
        let (rules, _) = crate::rules::load(&[], false).unwrap();
        let opts = ScanOptions::default();
        let fs = scan_history(&dir, &rules, &opts, "t", 0);
        let f = fs
            .iter()
            .find(|f| f.rule_id == "SEC-001")
            .expect("SEC-001 hit");
        let ev = evidence_of(f);
        assert!(ev.contains("removed in"), "evidence: {ev}");
        assert!(
            !ev.contains("not present in current tree"),
            "evidence: {ev}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
