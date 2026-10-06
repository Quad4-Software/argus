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
/// Critical findings are never suppressed: a baselined file that now
/// hides a live credential (the classic "baseline swallowed a prod
/// secret" failure) must still surface. `unsuppressed` counts them.
pub fn partition(
    findings: Vec<Finding>,
    base: &HashSet<String>,
    unsuppressed: &mut usize,
) -> (Vec<Finding>, Vec<Finding>) {
    let mut known = Vec::new();
    let mut new = Vec::new();
    for mut f in findings {
        if base.contains(&fingerprint(&f)) {
            if f.severity == Severity::Critical {
                *unsuppressed += 1;
                f.evidence.get_or_insert_with(Vec::new).push(
                    "matches baseline fingerprint but kept visible: Critical findings are never suppressed".into(),
                );
                new.push(f);
            } else {
                known.push(f);
            }
        } else {
            new.push(f);
        }
    }
    (known, new)
}

/// Worst severity among new findings (what --fail-on-new gates on).
pub fn worst_of(new: &[Finding]) -> Option<Severity> {
    new.iter().map(|f| f.severity).max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;

    fn mk(sev: Severity, id: &str, path: &str) -> Finding {
        Finding {
            ruleset: "test".into(),
            rule_id: id.into(),
            severity: sev,
            target: "t".into(),
            path: path.into(),
            line: None,
            excerpt: None,
            message: "m".into(),
            remediation: None,
            reference: None,
            window: None,
            evidence: None,
        }
    }

    #[test]
    fn critical_never_suppressed() {
        let live = mk(Severity::Critical, "VER-001", "a.env");
        let low = mk(Severity::Low, "X-1", "b.txt");
        let base: HashSet<String> = [fingerprint(&live), fingerprint(&low)]
            .into_iter()
            .collect();
        let mut unsup = 0usize;
        let (known, new) = partition(vec![live, low], &base, &mut unsup);
        assert_eq!(known.len(), 1);
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].severity, Severity::Critical);
        assert_eq!(unsup, 1);
        assert!(
            new[0]
                .evidence
                .as_ref()
                .unwrap()
                .iter()
                .any(|e| e.contains("never suppressed"))
        );
    }
}
