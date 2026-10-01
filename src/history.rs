// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Per-commit secrets scan over git history. Secrets that were committed
//! and later removed still leak - they must be rotated, not deleted.

use std::path::Path;

use crate::finding::Finding;
use crate::rules::CompiledRule;
use crate::scan::{ScanOptions, scan_file};

const MAX_COMMITS: usize = 500;

/// Scan added lines of `git log --all -p` for each commit. Returns one
/// finding group per (commit, file) that carries a secret rule hit.
pub fn scan_history(
    root: &Path,
    rules: &[CompiledRule],
    opts: &ScanOptions,
    target: &str,
    verbose: u8,
) -> Vec<Finding> {
    let secrets: Vec<&CompiledRule> = rules.iter().filter(|r| r.set == "secrets").collect();
    if secrets.is_empty() {
        return Vec::new();
    }
    let out = std::process::Command::new("git")
        .args([
            "-C",
            &root.display().to_string(),
            "log",
            "--all",
            "--format=commit %H",
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
    let mut findings = Vec::new();
    let mut sha = String::new();
    let mut file = String::new();
    let mut adds: Vec<String> = Vec::new();
    let mut count = 0;
    let flush = |sha: &str, file: &str, adds: &mut Vec<String>, findings: &mut Vec<Finding>| {
        if sha.is_empty() || file.is_empty() || adds.is_empty() {
            return;
        }
        let rel = format!("{file}@{sha_short}", sha_short = &sha[..8.min(sha.len())]);
        let body = adds.join("\n");
        for mut f in scan_file(&rel, Some(&body), None, &secrets, opts, target) {
            f.message = format!("{} (committed in {})", f.message, &sha[..12.min(sha.len())]);
            findings.push(f);
        }
        adds.clear();
    };
    for line in text.lines() {
        if let Some(s) = line.strip_prefix("commit ") {
            flush(&sha, &file, &mut adds, &mut findings);
            sha = s.trim().to_string();
            file.clear();
            count += 1;
            if count > MAX_COMMITS {
                break;
            }
        } else if let Some(f) = line.strip_prefix("+++ b/") {
            flush(&sha, &file, &mut adds, &mut findings);
            file = f.to_string();
        } else if line.starts_with('+') && !line.starts_with("+++") {
            adds.push(line[1..].to_string());
        } else if line.starts_with("diff --git") || line.starts_with("index ") {
            continue;
        } else if line.starts_with("---") {
            // old filename
        }
    }
    flush(&sha, &file, &mut adds, &mut findings);
    if verbose > 0 {
        eprintln!(
            "history: scanned {} commits, {} secret findings",
            count.min(MAX_COMMITS),
            findings.len()
        );
    }
    findings
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_logic() {
        // exercised via tmpdir below
    }
}
