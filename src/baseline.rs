// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Baseline mode: record accepted findings, fail only on new ones.

use crate::finding::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct Baseline {
    pub tool: String,
    pub created_at: String,
    pub fingerprints: Vec<String>,
}

/// Stable identity of a finding: rule + path + normalized excerpt.
/// Line numbers intentionally excluded (they drift on unrelated edits).
pub fn fingerprint(f: &Finding) -> String {
    let excerpt = f.excerpt.as_deref().unwrap_or("").trim();
    let mut h: u64 = 0xcbf29ce484222325;
    for b in format!("{}|{}|{}", f.rule_id, f.path, excerpt).as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", h)
}

pub fn load(path: &Path) -> Result<HashSet<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let b: Baseline =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(b.fingerprints.into_iter().collect())
}

pub fn write(path: &Path, findings: &[Finding]) -> Result<(), String> {
    let mut fps: Vec<String> = findings.iter().map(fingerprint).collect();
    fps.sort();
    fps.dedup();
    let b = Baseline {
        tool: "argus".into(),
        created_at: crate::finding::iso8601(crate::finding::unix_now()),
        fingerprints: fps,
    };
    let text = serde_json::to_string_pretty(&b).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Split findings into (known, new) given a loaded baseline.
pub fn partition(findings: Vec<Finding>, base: &HashSet<String>) -> (Vec<Finding>, Vec<Finding>) {
    findings
        .into_iter()
        .partition(|f| base.contains(&fingerprint(f)))
}

/// Worst severity among new findings (what --fail-on-new gates on).
pub fn worst_of(new: &[Finding]) -> Option<Severity> {
    new.iter().map(|f| f.severity).max()
}
