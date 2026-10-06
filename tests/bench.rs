// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Secrets benchmark gate on the labeled seed corpus: every file under
//! tests/bench/seed/true must produce at least one secrets finding
//! (ruleset "secrets"/"verify" or SEC-*/VER-*/GL-* rule id), and nothing
//! under false/ may produce one. Hermetic: plain `scan` does no network.

use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_argus"))
}

fn seed() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/bench/seed")
}

fn is_secret_finding(f: &Value) -> bool {
    let rid = f["rule_id"].as_str().unwrap_or("");
    matches!(f["ruleset"].as_str(), Some("secrets") | Some("verify"))
        || rid.starts_with("SEC-")
        || rid.starts_with("VER-")
        || rid.starts_with("GL-")
}

/// Repo-relative paths (forward slashes) of every file under dir.
fn files_under(dir: &Path, root: &Path, out: &mut Vec<String>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            files_under(&p, root, out);
        } else {
            out.push(
                p.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

#[test]
fn secrets_seed_full_recall_zero_fp() {
    let seed = seed();
    let out = bin()
        .arg("scan")
        .arg(&seed)
        .args(["--format", "json", "--color", "never"])
        .env("ARGUS_OFFLINE", "1") // hermetic: no provider verification
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "scan json ({}): {e}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let mut hits: BTreeMap<String, usize> = BTreeMap::new();
    for f in report["findings"].as_array().unwrap() {
        if is_secret_finding(f) {
            *hits
                .entry(f["path"].as_str().unwrap_or("").to_string())
                .or_default() += 1;
        }
    }

    let mut failures = Vec::new();
    let mut positives = Vec::new();
    files_under(&seed.join("true"), &seed, &mut positives);
    for rel in &positives {
        if hits.get(rel).copied().unwrap_or(0) == 0 {
            failures.push(format!("{rel}: labeled secret but no secrets finding"));
        }
    }
    let mut negatives = Vec::new();
    files_under(&seed.join("false"), &seed, &mut negatives);
    for rel in &negatives {
        if let Some(n) = hits.get(rel) {
            failures.push(format!("{rel}: labeled clean but {n} secrets finding(s)"));
        }
    }
    assert!(
        positives.len() >= 5,
        "seed corpus vanished: {} positives",
        positives.len()
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
