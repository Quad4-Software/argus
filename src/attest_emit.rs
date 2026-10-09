// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! in-toto attestation export for scan reports. The report JSON becomes
//! the statement subject (sha256 of its canonical serialization); the
//! predicate carries a severity summary and a digest over the finding
//! fingerprints so a consumer can gate a release on scan results without
//! re-implementing argus rules. Signing is detached: \<out\>.sig holds a
//! base64 ed25519 signature over the exact bytes written, verifiable
//! with verify_attestation and the public key.

// public API pending wiring into the scan CLI path

use crate::finding::{Finding, Severity};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
const PREDICATE_TYPE: &str = "https://quad4.io/argus/scan/v1";
const SUBJECT_NAME: &str = "argus-scan";

#[derive(Serialize)]
struct Statement {
    #[serde(rename = "_type")]
    stmt_type: &'static str,
    subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    predicate_type: &'static str,
    predicate: Predicate,
}

#[derive(Serialize)]
struct Subject {
    name: &'static str,
    digest: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct Predicate {
    tool: &'static str,
    version: String,
    /// Severity counts, so policy checks do not need to walk findings.
    counts: Counts,
    /// Caller-supplied fingerprint of the ruleset that produced the
    /// report; skipped when the report JSON does not carry one.
    #[serde(skip_serializing_if = "Option::is_none")]
    ruleset_fingerprint: Option<String>,
    /// RFC3339 emission time.
    timestamp: String,
    /// sha256 over the sorted baseline::fingerprint list. One digest
    /// identifies the exact finding set; sorting makes it independent
    /// of report ordering.
    #[serde(skip_serializing_if = "Option::is_none")]
    finding_fingerprints: Option<String>,
}

#[derive(Serialize, Default)]
struct Counts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    total: usize,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// \<path\>.sig, appending rather than replacing the extension so
/// report.intoto.json -> report.intoto.json.sig.
fn sig_path(p: &Path) -> PathBuf {
    let mut os = p.as_os_str().to_os_string();
    os.push(".sig");
    PathBuf::from(os)
}

/// Write an in-toto statement for a scan report at `out`. With `key`,
/// also writes a detached ed25519 signature to `<out>.sig`.
/// Returns the statement path.
pub fn emit_attestation(
    report_json: &serde_json::Value,
    out: &Path,
    key: Option<&Path>,
) -> Result<PathBuf, String> {
    // serde_json::Value maps are BTreeMap-backed, so this compact
    // serialization is canonical for any parse-equal document.
    let canon = serde_json::to_string(report_json).map_err(|e| e.to_string())?;
    let report_sha = hex(&Sha256::digest(canon.as_bytes()));

    let findings: Vec<Finding> = report_json
        .get("findings")
        .and_then(|f| f.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect()
        })
        .unwrap_or_default();

    let mut counts = Counts::default();
    for f in &findings {
        counts.total += 1;
        match f.severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
            Severity::Info => counts.info += 1,
        }
    }

    let finding_fingerprints = if findings.is_empty() {
        None
    } else {
        let mut fps: Vec<String> = findings.iter().map(crate::baseline::fingerprint).collect();
        fps.sort();
        fps.dedup();
        Some(hex(&Sha256::digest(fps.join("\n").as_bytes())))
    };

    let stmt = Statement {
        stmt_type: STATEMENT_TYPE,
        subject: vec![Subject {
            name: SUBJECT_NAME,
            digest: BTreeMap::from([("sha256".into(), report_sha)]),
        }],
        predicate_type: PREDICATE_TYPE,
        predicate: Predicate {
            tool: "argus-scanner",
            version: report_json
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or(env!("CARGO_PKG_VERSION"))
                .to_string(),
            counts,
            ruleset_fingerprint: report_json
                .get("ruleset_fingerprint")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            timestamp: crate::finding::iso8601_pub(),
            finding_fingerprints,
        },
    };

    // serialize the typed struct, not a Value: field order is fixed at
    // compile time, keeping the signed bytes deterministic
    let bytes = serde_json::to_vec_pretty(&stmt).map_err(|e| e.to_string())?;
    std::fs::write(out, &bytes).map_err(|e| format!("{}: {e}", out.display()))?;
    if let Some(k) = key {
        let sig = crate::rulesign::sign_bytes(&bytes, k)?;
        let sp = sig_path(out);
        std::fs::write(&sp, format!("{sig}\n")).map_err(|e| format!("{}: {e}", sp.display()))?;
    }
    Ok(out.to_path_buf())
}

/// Verify the detached signature `<attestation>.sig` over the exact
/// attestation file bytes against an ed25519 public key file.
pub fn verify_attestation(attestation: &Path, pubkey: &Path) -> Result<(), String> {
    let sp = sig_path(attestation);
    let sig = std::fs::read_to_string(&sp).map_err(|_| {
        format!(
            "{}: missing signature file {}",
            attestation.display(),
            sp.display()
        )
    })?;
    let bytes =
        std::fs::read(attestation).map_err(|e| format!("{}: {e}", attestation.display()))?;
    crate::rulesign::verify_bytes(&bytes, &sig, pubkey)
        .map_err(|e| format!("{}: {e}", attestation.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Report, Severity};

    fn tmpdir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("argus-attest-emit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn sample_report() -> serde_json::Value {
        let mut r = Report::new();
        r.findings.push(Finding {
            ruleset: "test".into(),
            rule_id: "T-1".into(),
            severity: Severity::High,
            target: "t".into(),
            path: "a.txt".into(),
            line: None,
            excerpt: None,
            message: "m".into(),
            remediation: None,
            reference: None,
            window: None,
            evidence: None,
        });
        serde_json::to_value(&r).unwrap()
    }

    #[test]
    fn statement_digest_covers_canonical_report() {
        let dir = tmpdir("digest");
        let report = sample_report();
        let out = emit_attestation(&report, &dir.join("scan.intoto.json"), None).unwrap();
        let stmt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
        assert_eq!(stmt["_type"], STATEMENT_TYPE);
        assert_eq!(stmt["predicateType"], PREDICATE_TYPE);
        assert_eq!(stmt["subject"][0]["name"], SUBJECT_NAME);
        let canon = serde_json::to_string(&report).unwrap();
        let want = hex(&Sha256::digest(canon.as_bytes()));
        assert_eq!(stmt["subject"][0]["digest"]["sha256"], want);
        assert_eq!(stmt["predicate"]["counts"]["high"], 1);
        assert_eq!(stmt["predicate"]["counts"]["total"], 1);
        assert!(stmt["predicate"]["finding_fingerprints"].is_string());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn signed_attestation_verifies_and_tamper_fails() {
        let dir = tmpdir("signed");
        let privk = dir.join("k.priv");
        let pubk = dir.join("k.pub");
        crate::rulesign::keygen(&privk, &pubk).unwrap();
        let out = dir.join("scan.intoto.json");
        emit_attestation(&sample_report(), &out, Some(&privk)).unwrap();
        verify_attestation(&out, &pubk).unwrap();

        // flipping one byte in the statement must fail verification
        let mut bytes = std::fs::read(&out).unwrap();
        let i = bytes.len() / 2;
        bytes[i] ^= 0x01;
        let tampered = dir.join("tampered.intoto.json");
        std::fs::write(&tampered, &bytes).unwrap();
        std::fs::copy(sig_path(&out), sig_path(&tampered)).unwrap();
        assert!(verify_attestation(&tampered, &pubk).is_err());

        // a missing .sig is an error, not a pass
        let unsigned = dir.join("unsigned.intoto.json");
        emit_attestation(&sample_report(), &unsigned, None).unwrap();
        assert!(verify_attestation(&unsigned, &pubk).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
