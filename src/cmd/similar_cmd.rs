// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! argus similar + scan --similar: vendored-copy and near-dup detection.

use std::path::PathBuf;

use crate::finding::{Finding, Report, Severity};
use crate::scan::ScanOptions;
use crate::similar;

/// `argus similar`: score two files/trees, or find near-duplicate pairs
/// inside one tree when b is None.
pub(crate) fn similar_cmd(
    a: &std::path::Path,
    b: Option<&std::path::Path>,
    index: Option<&std::path::Path>,
    index_build: bool,
    index_query: bool,
    opts: &ScanOptions,
    report: &mut Report,
) {
    if index_build {
        if let Err(e) = similar::index_build(a, index, opts.max_file_size, report) {
            report.errors.push(format!("similar --index-build: {e}"));
        }
        return;
    }
    if index_query {
        if let Err(e) = similar::index_query(a, index, opts.max_file_size, report) {
            report.errors.push(format!("similar --index-query: {e}"));
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
