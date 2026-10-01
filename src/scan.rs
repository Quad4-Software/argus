// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Scan engine: directory walk plus rule matching, parallel via std threads.

use crate::color::Styles;
use crate::finding::{Finding, Severity};
use crate::progress::Progress;
use crate::rules::{CompiledKind, CompiledRule, UnsafeRefs};
use sha2::Digest;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct ScanOptions {
    /// Skip files larger than this (bytes).
    pub max_file_size: u64,
    pub jobs: usize,
    /// Max findings emitted per rule per file.
    pub max_per_rule_per_file: usize,
    /// Repo-relative path exclusions.
    pub exclude: Vec<regex::Regex>,
    /// Also walk .git internals (refs, hooks, config) instead of skipping.
    pub include_git: bool,
    #[cfg(feature = "yara")]
    pub yara: Option<std::sync::Arc<yara_x::Rules>>,
    /// Rule ids to skip (argus --disable-rule).
    pub disabled: std::collections::HashSet<String>,
    /// If non-empty, only rules/findings from these rulesets run.
    pub only_sets: std::collections::HashSet<String>,
    /// Reuse findings for unchanged files via .arguscache.json.
    pub incremental: bool,
    /// Live progress line on stderr while a scan runs.
    pub progress: bool,
    /// Style table for the progress line (color-less when disabled).
    pub styles: Styles,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            max_file_size: 8 * 1024 * 1024,
            jobs: 8,
            max_per_rule_per_file: 3,
            exclude: Vec::new(),
            include_git: false,
            #[cfg(feature = "yara")]
            yara: None,
            disabled: std::collections::HashSet::new(),
            only_sets: std::collections::HashSet::new(),
            incremental: false,
            progress: false,
            styles: Styles::new(crate::color::ColorMode::Never),
        }
    }
}

pub(crate) fn looks_binary(bytes: &[u8]) -> bool {
    bytes[..bytes.len().min(8192)].contains(&0)
}

fn is_full_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// docker://...@sha256:<64hex> style digest pin - immutable like a commit SHA.
fn is_digest_pin(s: &str) -> bool {
    s.len() == 71 && s.starts_with("sha256:") && s[7..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn line_of(text: &str, byte_off: usize) -> usize {
    text[..byte_off].bytes().filter(|&b| b == b'\n').count() + 1
}

fn line_excerpt(text: &str, byte_off: usize) -> String {
    let start = text[..byte_off].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let end = text[byte_off..]
        .find('\n')
        .map(|i| byte_off + i)
        .unwrap_or(text.len());
    text[start..end].trim().chars().take(200).collect()
}

pub(crate) struct FileHit {
    line: Option<usize>,
    excerpt: Option<String>,
    message: String,
    severity_override: Option<Severity>,
}

fn check_file(
    rel: &str,
    text: Option<&str>,
    bytes: Option<&[u8]>,
    rule: &CompiledRule,
    max_hits: usize,
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
            ..
        } => {
            let text = match text {
                Some(t) => t,
                None => return hits,
            };
            if let Some(u) = unless
                && u.is_match(text)
            {
                return hits;
            }
            if *contains_all
                && !contains.is_empty()
                && !contains.iter().all(|c| text.contains(c.as_str()))
            {
                return hits;
            }
            if !contains.is_empty() && !contains_all {
                'outer: for c in contains {
                    let mut start = 0;
                    while let Some(off) = text[start..].find(c.as_str()) {
                        let off = start + off;
                        hits.push(FileHit {
                            line: Some(line_of(text, off)),
                            excerpt: Some(line_excerpt(text, off)),
                            message: format!("{}: matched {:?}", rule.description, c),
                            severity_override: None,
                        });
                        if hits.len() >= max_hits {
                            break 'outer;
                        }
                        start = off + c.len().max(1);
                    }
                }
            } else if *contains_all {
                // All present: report position of the first one.
                if let Some(first) = contains.first()
                    && let Some(off) = text.find(first.as_str())
                {
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
            }
            if let Some(re) = regex {
                for m in re.find_iter(text) {
                    if hits.len() >= max_hits {
                        return hits;
                    }
                    if exclude.as_ref().is_some_and(|x| x.is_match(m.as_str())) {
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
        CompiledKind::Taint { source, sink, .. } => {
            let text = match text {
                Some(t) => t,
                None => return hits,
            };
            hits.extend(crate::scan::taint::taint_scan(
                text, source, sink, rule, max_hits,
            ));
        }
        CompiledKind::Dataflow { source, sink, .. } => {
            let text = match text {
                Some(t) => t,
                None => return hits,
            };
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
            entropy,
            min_len,
        } => {
            let text = match text {
                Some(t) => t,
                None => return hits,
            };
            static PLACEHOLDER: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
            let ph = PLACEHOLDER.get_or_init(|| {
                regex::Regex::new(r"(?i)(x{3,}|\*+|placeholder|example|sample|dummy|changeme|your[-_ ]|<[^>]+>|\$\{|%\w+%|test[_-]?|fake|none|redact|\b0{4,}|\b1{6,}|\babc|lorem)").unwrap()
            });
            for cap in re.captures_iter(text) {
                if hits.len() >= max_hits {
                    return hits;
                }
                let cand = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                if cand.len() < *min_len || is_placeholder(cand, ph) {
                    continue;
                }
                if shannon_entropy(cand) < *entropy {
                    continue;
                }
                let off = cap.get(1).map(|m| m.start()).unwrap_or(0);
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
    }
    hits
}

/// Scan one file; returns findings. text is None for skipped/oversize/binary files.
/// True when a suppression marker covers this finding.
/// Markers: argus:ignore <ID> on the same line, argus:ignore-next-line <ID>
/// on the previous line, argus:ignore-file anywhere near the top (first 20 lines).
/// <ID> optional = suppress everything; comma lists allowed.
fn suppressed(text: Option<&str>, line: Option<usize>, rule_id: &str) -> bool {
    let Some(t) = text else { return false };
    let lines: Vec<&str> = t.lines().take(line.unwrap_or(20)).collect();
    // file-level marker
    for l in lines.iter().take(20) {
        if l.contains("argus:ignore-file") {
            return true;
        }
    }
    let Some(ln) = line else { return false };
    let idx = ln - 1;
    let covers = |l: &str, prefix: &str| -> bool {
        let Some(pos) = l.find(prefix) else {
            return false;
        };
        let rest = l[pos + prefix.len()..].trim();
        rest.is_empty()
            || rest
                .split([',', ' ', ';'])
                .any(|w| w == rule_id || w == "*")
    };
    if idx < lines.len() && covers(lines[idx], "argus:ignore") {
        return true;
    }
    if idx > 0 && covers(lines[idx - 1], "argus:ignore-next-line") {
        return true;
    }
    false
}

pub fn scan_file(
    rel: &str,
    text: Option<&str>,
    bytes: Option<&[u8]>,
    rules: &[&CompiledRule],
    opts: &ScanOptions,
    target: &str,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut seen: HashSet<(String, Option<usize>, String)> = HashSet::new();
    for rule in rules {
        if !rule.path_in_scope(rel) {
            continue;
        }
        for mut hit in check_file(rel, text, bytes, rule, opts.max_per_rule_per_file) {
            if suppressed(text, hit.line, &rule.id) {
                continue;
            }
            if rule.set == "secrets"
                && let Some(ex) = &hit.excerpt
            {
                hit.excerpt = Some(mask_tokens(ex));
            }
            let key = (
                rule.id.clone(),
                hit.line,
                hit.excerpt.clone().unwrap_or_default(),
            );
            if !seen.insert(key) {
                continue;
            }
            out.push(Finding {
                ruleset: rule.set.clone(),
                rule_id: rule.id.clone(),
                severity: hit.severity_override.unwrap_or(rule.severity),
                target: target.into(),
                path: rel.into(),
                line: hit.line,
                excerpt: hit.excerpt,
                message: hit.message,
                remediation: rule.remediation.clone(),
                reference: rule.reference.clone(),
                window: rule.window.clone(),
            });
        }
    }
    // entropy pass: secrets no shape rule knows - high-entropy tokens on
    // code-ish files only, with guards for hashes/paths/known-safe files
    if rules.iter().any(|r| r.set == "secrets")
        && let Some(t) = text
        && !crate::entropy::is_lockfile_name(rel)
    {
        for (ln, line) in t.lines().enumerate() {
            for tok in crate::entropy::tokens(line) {
                if suppressed(text, Some(ln + 1), "SEC-090") {
                    continue;
                }
                if !seen.insert(("SEC-090".into(), Some(ln + 1), tok.clone())) {
                    continue;
                }
                out.push(Finding {
                    ruleset: "secrets".into(),
                    rule_id: "SEC-090".into(),
                    severity: Severity::Medium,
                    target: target.into(),
                    path: rel.into(),
                    line: Some(ln + 1),
                    excerpt: Some(mask_tokens(&tok)),
                    message: "high-entropy token - possible unrecognized credential".into(),
                    remediation: Some(
                        "Check whether this is a live secret; rotate and move to a manager if so."
                            .into(),
                    ),
                    reference: None,
                    window: None,
                });
            }
        }
    }
    out
}

/// Scan all files under root in parallel. target labels findings.
/// Returns (findings, files_scanned).
pub fn scan_root(
    root: &Path,
    target: &str,
    rules: &[CompiledRule],
    opts: &ScanOptions,
) -> (Vec<Finding>, usize) {
    let files = collect_files(root, opts.include_git);
    run_pool(files, root, target, rules, opts)
}

/// Scan an explicit repo-relative file list under root (used by --diff mode).
pub fn scan_selected(
    root: &Path,
    rels: &[String],
    label: &str,
    rules: &[CompiledRule],
    opts: &ScanOptions,
) -> (Vec<Finding>, usize) {
    let files: Vec<PathBuf> = rels
        .iter()
        .map(|r| root.join(r))
        .filter(|p| p.is_file())
        .collect();
    run_pool(files, root, label, rules, opts)
}

fn run_pool(
    files: Vec<PathBuf>,
    root: &Path,
    target: &str,
    rules: &[CompiledRule],
    opts: &ScanOptions,
) -> (Vec<Finding>, usize) {
    let count = files.len();
    // incremental cache: read-through on (mtime,size) hit, write-back of
    // freshly scanned results. Shared cache = mutexed map.
    let cache = if opts.incremental {
        let fp = crate::cache::ruleset_fp(&rules.iter().collect::<Vec<_>>());
        Some((
            crate::cache::load(root, &fp),
            Mutex::new(std::collections::HashMap::<String, crate::cache::Entry>::new()),
            fp,
        ))
    } else {
        None
    };
    let queue = Arc::new(Mutex::new(files.into_iter()));
    let results = Arc::new(Mutex::new(Vec::new()));
    let jobs = opts.jobs.max(1).min(count.max(1));
    let prog = Arc::new(Progress::new(target, count, opts.progress, opts.styles));
    // Windows gives default threads about 1 MiB. The regex crate recurses
    // and that overflows while matching short files. Workers get 8 MiB.
    let rules = Arc::new(rules.to_vec());
    let opts = Arc::new(opts.clone());
    let root = Arc::new(root.to_path_buf());
    let target = Arc::new(target.to_string());
    let cache = Arc::new(cache);

    let mut workers = Vec::with_capacity(jobs);
    for _ in 0..jobs {
        let (queue, results, prog, rules, opts, root, target, cache) = (
            Arc::clone(&queue),
            Arc::clone(&results),
            Arc::clone(&prog),
            Arc::clone(&rules),
            Arc::clone(&opts),
            Arc::clone(&root),
            Arc::clone(&target),
            Arc::clone(&cache),
        );
        workers.push(
            std::thread::Builder::new()
                .name("argus-scan".into())
                .stack_size(8 * 1024 * 1024)
                .spawn(move || {
                    loop {
                        let file = {
                            let mut q = queue.lock().unwrap();
                            q.next()
                        };
                        let Some(file) = file else { break };
                        prog.tick();
                        let rel = rel_path(&root, &file);
                        if opts.exclude.iter().any(|re| re.is_match(&rel)) {
                            continue;
                        }
                        let applicable: Vec<&CompiledRule> =
                            rules.iter().filter(|r| r.path_in_scope(&rel)).collect();
                        if applicable.is_empty() {
                            continue;
                        }
                        // cache hit: same mtime+size -> replay stored findings
                        let sig = crate::cache::stat_sig(&file);
                        if let Some((cache, _, _)) = cache.as_ref()
                            && let Some((mt, sz)) = sig
                            && let Some(e) = cache.files.get(&rel)
                            && e.mtime_ns == mt
                            && e.size == sz
                        {
                            prog.add_findings(e.findings.len());
                            results.lock().unwrap().extend(e.findings.iter().cloned());
                            continue;
                        }
                        let needs_text = applicable
                            .iter()
                            .any(|r| r.needs_content() && !r.needs_bytes());
                        #[cfg(feature = "yara")]
                        let has_yara = opts.yara.is_some();
                        #[cfg(not(feature = "yara"))]
                        let has_yara = false;
                        let needs_bytes = applicable.iter().any(|r| r.needs_bytes()) || has_yara;
                        let (text, bytes) = if needs_text || needs_bytes {
                            match std::fs::metadata(&file) {
                                Ok(m) if m.len() <= opts.max_file_size => {
                                    match std::fs::read(&file) {
                                        Ok(b) => {
                                            let t = if needs_text {
                                                Some(if looks_binary(&b) {
                                                    extract_strings(&b)
                                                } else {
                                                    String::from_utf8_lossy(&b).into_owned()
                                                })
                                            } else {
                                                None
                                            };
                                            (t, Some(b))
                                        }
                                        Err(_) => (None, None),
                                    }
                                }
                                _ => (None, None),
                            }
                        } else {
                            (None, None)
                        };
                        let binary = bytes.as_deref().is_some_and(looks_binary);
                        let mut found = scan_file(
                            &rel,
                            text.as_deref(),
                            bytes.as_deref(),
                            &applicable,
                            &opts,
                            &target,
                        );
                        if binary {
                            // literal secret patterns inside binaries are test
                            // vectors (every distro lib carries them); real
                            // embedded credentials are encoded and string rules
                            // would FP constantly
                            found.retain(|f| f.ruleset != "secrets");
                        }
                        if let Some(t) = text.as_deref() {
                            if audit_enabled(&opts, &rel) {
                                found.extend(crate::workflow_audit::audit(
                                    &rel,
                                    t,
                                    &target,
                                    &opts.disabled,
                                ));
                            }
                            if container_enabled(&opts, &rel) {
                                found.extend(crate::container_audit::audit(
                                    &rel,
                                    t,
                                    &target,
                                    &opts.disabled,
                                ));
                            }
                        }
                        #[cfg(feature = "yara")]
                        if let (Some(ruleset), Some(b)) = (opts.yara.as_ref(), bytes.as_deref()) {
                            found.extend(crate::yarascan::scan_bytes(&rel, b, ruleset, &target));
                        }
                        let found = found;
                        if let Some((_, new, _)) = cache.as_ref()
                            && let Some((mt, sz)) = sig
                        {
                            new.lock().unwrap().insert(
                                rel.clone(),
                                crate::cache::Entry {
                                    mtime_ns: mt,
                                    size: sz,
                                    findings: found.clone(),
                                },
                            );
                        }
                        if !found.is_empty() {
                            prog.add_findings(found.len());
                            results.lock().unwrap().extend(found);
                        }
                    }
                })
                .expect("spawn scan worker"),
        );
    }
    for worker in workers {
        worker.join().expect("scan worker");
    }

    let cache = Arc::try_unwrap(cache).ok().unwrap();
    if let Some((old, new, fp)) = cache {
        let mut merged = old;
        merged.ruleset_fp = fp;
        merged.files.extend(new.into_inner().unwrap());
        crate::cache::store(&root, &merged);
    }
    let findings = Arc::try_unwrap(results)
        .expect("scan results")
        .into_inner()
        .unwrap();
    (findings, count)
}

fn hex_sha256(b: &[u8]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(b);
    h.finalize().iter().map(|x| format!("{x:02x}")).collect()
}

/// Run all rules against in-memory text as a pseudo-file rel under target.
/// Used by system scans for synthesized inputs (e.g. pacman -Qqm output).
pub fn scan_text(rel: &str, text: &str, rules: &[CompiledRule], target: &str) -> Vec<Finding> {
    let opts = ScanOptions::default();
    let applicable: Vec<&CompiledRule> = rules.iter().filter(|r| r.path_in_scope(rel)).collect();
    scan_file(rel, Some(text), None, &applicable, &opts, target)
}

/// Printable-ASCII string extraction (min run 6) for binary files.
fn extract_strings(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len().min(1 << 20));
    let mut run = Vec::new();
    for &c in b {
        if (0x20..=0x7e).contains(&c) || c == b'\t' {
            run.push(c);
        } else {
            if run.len() >= 6 {
                out.push_str(std::str::from_utf8(&run).unwrap_or(""));
                out.push('\n');
            }
            run.clear();
        }
    }
    if run.len() >= 6 {
        out.push_str(std::str::from_utf8(&run).unwrap_or(""));
    }
    out
}

/// True if levenshtein(a, b) <= k (early-exit banded check).
fn lev_at_most(a: &str, b: &str, k: usize) -> bool {
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

fn container_enabled(opts: &ScanOptions, rel: &str) -> bool {
    let set_ok = opts.only_sets.is_empty() || opts.only_sets.contains("container-audit");
    set_ok
        && !matches!(
            crate::container_audit::kind_of(rel),
            crate::container_audit::Kind::None
        )
}

static WF_PATHS: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
fn audit_enabled(opts: &ScanOptions, rel: &str) -> bool {
    let set_ok = opts.only_sets.is_empty() || opts.only_sets.contains("workflow-audit");
    if !set_ok {
        return false;
    }
    WF_PATHS
        .get_or_init(|| {
            regex::Regex::new(r"(^|/)\.(github|gitea|forgejo)/workflows/[^/]+\.ya?ml$").unwrap()
        })
        .is_match(rel)
}

fn shannon_entropy(s: &str) -> f64 {
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
    let masked = format!("{}...{}", &secret[..4], &secret[secret.len() - 3..]);
    line.replace(secret, &masked)
}

/// Mask any high-entropy token inside an excerpt (secrets never report raw).
fn mask_tokens(line: &str) -> String {
    static TOK: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = TOK.get_or_init(|| regex::Regex::new("[A-Za-z0-9+/=_-]{16,}").unwrap());
    re.replace_all(line, |c: &regex::Captures| {
        let s = &c[0];
        if shannon_entropy(s) >= 3.4 {
            format!("{}...{}", &s[..4], &s[s.len() - 3..])
        } else {
            s.to_string()
        }
    })
    .into_owned()
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

pub(crate) mod taint;
pub(crate) mod walk;
pub(crate) use walk::{collect_files, dep_name_candidates, rel_path};
