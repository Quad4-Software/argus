// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! argus similar + scan --similar: vendored-copy and near-dup detection.

use std::path::PathBuf;

use crate::finding::{Finding, Report, Severity};
use crate::scan::ScanOptions;
use crate::similar;

/// Flags for the downloadable signed similarity corpus. Grouped so the
/// Similar dispatch arm stays readable as the corpus surface grows.
/// Default = no corpus activity.
#[derive(Default)]
pub(crate) struct CorpusArgs<'a> {
    /// Corpus db path (--corpus-db). Doubles as the fetch destination and
    /// the --corpus-build output; default: ~/.local/share/argus/corpus.db.
    pub db: Option<&'a std::path::Path>,
    /// Download and verify a signed corpus (--fetch-corpus URL).
    pub fetch: Option<&'a str>,
    /// ed25519 pubkey override for corpus verification (--corpus-pubkey);
    /// defaults to the embedded release key.
    pub pubkey: Option<&'a std::path::Path>,
    /// Also search the corpus db during index lookup
    /// (--index-lookup-corpus).
    pub lookup: bool,
    /// Maintainer build: fingerprint `a` (and `b`) into a fresh corpus db
    /// (--corpus-build NAME).
    pub build: Option<&'a str>,
}

/// Full `argus similar` surface: pair/dedup scoring, index build/query,
/// plus the signed-corpus actions (fetch, build, lookup). Mirrors the
/// clap fields on Cmd::Similar.
pub(crate) struct SimilarArgs<'a> {
    /// Left side (file or directory).
    pub a: &'a std::path::Path,
    /// Right side; omit for internal dedup of `a`.
    pub b: Option<&'a std::path::Path>,
    /// Fingerprint index db override (--index).
    pub index: Option<&'a std::path::Path>,
    /// --index-build.
    pub index_build: bool,
    /// --index-query.
    pub index_query: bool,
    /// Corpus flags (--fetch-corpus/--corpus-db/--corpus-pubkey/
    /// --index-lookup-corpus/--corpus-build).
    pub corpus: CorpusArgs<'a>,
}

pub(crate) fn similar_dispatch(args: &SimilarArgs<'_>, opts: &ScanOptions, report: &mut Report) {
    let (a, b, index) = (args.a, args.b, args.index);
    let corpus = &args.corpus;
    // fetch first so --fetch-corpus chains into a same-invocation lookup
    if let Some(url) = corpus.fetch {
        let dest = corpus
            .db
            .map(PathBuf::from)
            .unwrap_or_else(similar::corpus_path);
        match similar::fetch_corpus(url, &dest, corpus.pubkey) {
            Ok(msg) => eprintln!("similar: {msg}"),
            Err(e) => {
                report.errors.push(format!("similar --fetch-corpus: {e}"));
                return;
            }
        }
        // a bare fetch is a maintenance action, not a scan of `a`
        if !(args.index_build || args.index_query || corpus.lookup || corpus.build.is_some()) {
            return;
        }
    }
    if let Some(name) = corpus.build {
        let mut dirs = vec![a.to_path_buf()];
        if let Some(b) = b {
            dirs.push(b.to_path_buf());
        }
        let out = corpus
            .db
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("corpus.db"));
        match similar::build_corpus(&dirs, &out, name) {
            Ok(msg) => eprintln!("similar: {msg}"),
            Err(e) => report.errors.push(format!("similar --corpus-build: {e}")),
        }
        return;
    }
    if args.index_build {
        if let Err(e) = similar::index_build(a, index, opts.max_file_size, report) {
            report.errors.push(format!("similar --index-build: {e}"));
        }
        return;
    }
    if args.index_query || corpus.lookup {
        if args.index_query
            && let Err(e) = similar::index_query(a, index, opts.max_file_size, report)
        {
            report.errors.push(format!("similar --index-query: {e}"));
        }
        if corpus.lookup
            && let Err(e) = similar::corpus_lookup(a, corpus.db, opts.max_file_size, report)
        {
            report
                .errors
                .push(format!("similar --index-lookup-corpus: {e}"));
        }
        return;
    }
    let ai = similar::index(a, opts.max_file_size);
    let bi = match b {
        Some(b) => similar::index(b, opts.max_file_size),
        None => Vec::new(),
    };
    if b.is_some() {
        if ai.len() * bi.len() > 4_000_000 {
            report.errors.push(format!(
                "similar: {}x{} files - too many to compare, narrow the paths",
                ai.len(),
                bi.len()
            ));
            return;
        }
        for fa in &ai {
            for fb in &bi {
                push_similar(report, fa, fb);
            }
        }
    } else {
        for i in 0..ai.len() {
            for j in (i + 1)..ai.len() {
                push_similar(report, &ai[i], &ai[j]);
            }
        }
    }
}

fn push_similar(report: &mut Report, fa: &similar::Fingerprint, fb: &similar::Fingerprint) {
    // shared thresholds with the index-query path (SIM-003/004): classify()
    // owns the jaccard/containment/shingle-floor rules for both
    let Some(hit) = similar::classify(fa, fb) else {
        return;
    };
    let (id, sev, msg) = if hit.jaccard {
        (
            "SIM-001",
            Severity::High,
            format!(
                "{} shares {:.0}% of its code fingerprint with {} - likely vendored/copied",
                fa.path.display(),
                hit.score * 100.0,
                fb.path.display()
            ),
        )
    } else {
        (
            "SIM-002",
            Severity::Medium,
            format!(
                "{} embeds {:.0}% of {}'s fingerprint - possible copied region inside a larger file",
                fb.path.display(),
                hit.score * 100.0,
                fa.path.display()
            ),
        )
    };
    report.findings.push(Finding {
        ruleset: "similarity".into(),
        rule_id: id.into(),
        severity: sev,
        target: fa.path.display().to_string(),
        path: fb.path.display().to_string(),
        line: None,
        excerpt: None,
        message: msg,
        remediation: Some(
            "Check provenance: if this is a vendored copy, track upstream for CVEs and license obligations."
                .into(),
        ),
        reference: None,
        window: None,
        evidence: None,
});
}

/// `--similar PATH` on a scan: flag scanned files copied from the reference
/// tree (vendored deps, license-evasion copies, provenance laundering).
pub(crate) fn vendored_check(
    paths: &[PathBuf],
    refpath: &std::path::Path,
    opts: &ScanOptions,
    report: &mut Report,
    verbose: u8,
) {
    let refs = similar::index(refpath, opts.max_file_size);
    if refs.is_empty() {
        report.errors.push(format!(
            "similar: no fingerprintable sources under {}",
            refpath.display()
        ));
        return;
    }
    let mut ours = Vec::new();
    for p in paths {
        ours.extend(similar::index(p, opts.max_file_size));
    }
    if verbose > 0 {
        eprintln!(
            "similar: comparing {} scanned files x {} reference files",
            ours.len(),
            refs.len()
        );
    }
    if ours.len() * refs.len() > 4_000_000 {
        report.errors.push(format!(
            "similar: {}x{} files - too many to compare, narrow the paths",
            ours.len(),
            refs.len()
        ));
        return;
    }
    for fo in &ours {
        for fr in &refs {
            push_similar(report, fo, fr);
        }
    }
}
