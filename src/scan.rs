// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Scan engine: directory walk plus rule matching, parallel via std threads.

use crate::color::Styles;
use crate::finding::{Finding, Severity};
use crate::progress::Progress;
use crate::rules::CompiledRule;
use engine::{FileMatch, Matcher, check_file, shannon_entropy};
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
    /// Prune dependency/build dirs and honor .gitignore/.ignore while
    /// walking (--no-prune disables).
    pub prune: bool,
    /// Live-verify provider-shaped tokens against their issuer APIs
    /// (--verify-secrets, network required).
    pub verify_secrets: bool,
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
            prune: true,
            verify_secrets: false,
            styles: Styles::new(crate::color::ColorMode::Never),
        }
    }
}

pub(crate) fn looks_binary(bytes: &[u8]) -> bool {
    bytes[..bytes.len().min(8192)].contains(&0)
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
    let m = Matcher::build(rules.iter().copied());
    let idxs: Vec<usize> = (0..rules.len()).collect();
    scan_file_matched(rel, text, bytes, rules, &idxs, &m, opts, target)
}

/// Scan one file with a shared, prebuilt matcher. `idxs` are indices into
/// `rules` (the same slice the matcher was built over) selected by
/// `path_in_scope`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn scan_file_matched(
    rel: &str,
    text: Option<&str>,
    bytes: Option<&[u8]>,
    rules: &[&CompiledRule],
    idxs: &[usize],
    m: &Matcher,
    opts: &ScanOptions,
    target: &str,
) -> Vec<Finding> {
    let fm_own = text.map(|t| FileMatch::compute(m, t, rel));
    let fm_def = FileMatch::default();
    let fm = fm_own.as_ref().unwrap_or(&fm_def);
    let mut out = Vec::new();
    let mut seen: HashSet<(String, Option<usize>, String)> = HashSet::new();
    for &i in idxs {
        let rule = rules[i];
        for mut hit in check_file(rel, text, bytes, i, rule, opts.max_per_rule_per_file, fm) {
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
                evidence: None,
            });
        }
    }
    // entropy pass: secrets no shape rule knows - high-entropy tokens on
    // code-ish files only, with guards for hashes/paths/known-safe files
    // and machine-generated sources
    if idxs.iter().any(|&i| rules[i].set == "secrets")
        && let Some(t) = text
        && !crate::entropy::is_lockfile_name(rel)
        && !crate::entropy::is_generated(t)
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
                    evidence: None,
                });
            }
        }
    }
    // --verify-secrets: live-check provider-shaped tokens against their
    // own issuer API, capped per file. Only exact provider shapes are
    // ever sent (never arbitrary strings) and findings mask the token.
    // Binary files are skipped - extracted strings trip on test vectors.
    if opts.verify_secrets
        && let Some(t) = text
        && !bytes.as_deref().is_some_and(looks_binary)
    {
        out.extend(crate::verify::verify_file_text(t, rel, target, 5));
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
    let files = collect_files(root, opts.include_git, opts.prune);
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
    mut files: Vec<PathBuf>,
    root: &Path,
    target: &str,
    rules: &[CompiledRule],
    opts: &ScanOptions,
) -> (Vec<Finding>, usize) {
    // Largest-first scheduling: the biggest files start on workers early
    // instead of straggling at the tail of the walk order.
    files.sort_by_key(|p| std::cmp::Reverse(p.metadata().map(|m| m.len()).unwrap_or(0)));
    let count = files.len();
    // incremental cache: read-through on (mtime,size) hit, write-back of
    // freshly scanned results. Shared cache = mutexed map.
    let cache = if opts.incremental {
        // verify-secrets findings come from live provider calls; without
        // the flag in the fingerprint a cached non-verify run replays
        // stale verdicts (and vice versa)
        let mut fp = crate::cache::ruleset_fp(&rules.iter().collect::<Vec<_>>());
        fp.push_str(if opts.verify_secrets {
            "+verify"
        } else {
            "-verify"
        });
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
    // One RegexSet + one Aho-Corasick automaton across all rules, shared
    // read-only by every worker.
    let matcher = Arc::new(Matcher::build(rules.iter()));
    // Windows gives default threads about 1 MiB. The regex crate recurses
    // and that overflows while matching short files. Workers get 8 MiB.
    let rules = Arc::new(rules.to_vec());
    let opts = Arc::new(opts.clone());
    let root = Arc::new(root.to_path_buf());
    let target = Arc::new(target.to_string());
    let cache = Arc::new(cache);

    let mut workers = Vec::with_capacity(jobs);
    for _ in 0..jobs {
        let (queue, results, prog, rules, opts, root, target, cache, matcher) = (
            Arc::clone(&queue),
            Arc::clone(&results),
            Arc::clone(&prog),
            Arc::clone(&rules),
            Arc::clone(&opts),
            Arc::clone(&root),
            Arc::clone(&target),
            Arc::clone(&cache),
            Arc::clone(&matcher),
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
                        let rule_refs: Vec<&CompiledRule> = rules.iter().collect();
                        let applicable: Vec<usize> = (0..rule_refs.len())
                            .filter(|&i| rule_refs[i].path_in_scope(&rel))
                            .collect();
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
                            .any(|&i| rules[i].needs_content() && !rules[i].needs_bytes());
                        #[cfg(feature = "yara")]
                        let has_yara = opts.yara.is_some();
                        #[cfg(not(feature = "yara"))]
                        let has_yara = false;
                        let needs_bytes =
                            applicable.iter().any(|&i| rules[i].needs_bytes()) || has_yara;
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
                        let mut found = scan_file_matched(
                            &rel,
                            text.as_deref(),
                            bytes.as_deref(),
                            &rule_refs,
                            &applicable,
                            &matcher,
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

mod anchors;
pub(crate) mod engine;
pub(crate) mod taint;
pub(crate) mod walk;
pub(crate) use walk::{collect_files, rel_path};
