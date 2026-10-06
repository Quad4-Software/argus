// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! `argus attest` driver: verify sigstore bundles, npm attestations and
//! cosign .sig/.cert pairs, printing verdicts and pushing findings.

use crate::attest::AttestReport;
use crate::finding::{Finding, Report, Severity};
use std::path::PathBuf;

/// First PEM CERTIFICATE block -> DER.
fn pem_cert_der(pem: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let mut in_blk = false;
    let mut b = String::new();
    for l in pem.lines() {
        if l.contains("BEGIN CERTIFICATE") {
            in_blk = true;
        } else if l.contains("END CERTIFICATE") {
            break;
        } else if in_blk {
            b.push_str(l.trim());
        }
    }
    base64::engine::general_purpose::STANDARD.decode(b).ok()
}

fn finding(rep: &AttestReport, name: &str) -> Finding {
    let (sev, id, msg) = match rep.verdict() {
        "VERIFIED" if rep.chain_ok => (
            Severity::Info,
            "AT-001",
            format!(
                "attestation verified for {name}: signature, Fulcio chain and Rekor tlog all check out"
            ),
        ),
        "VERIFIED" => (
            Severity::Info,
            "AT-001",
            format!(
                "attestation verified for {name}: key signature and Rekor tlog check out (registry-key attestation)"
            ),
        ),
        v if v.starts_with("PARTIAL") => (
            Severity::Low,
            "AT-002",
            format!(
                "attestation for {name} has a valid signature and Fulcio chain but the Rekor log entry is unverified or absent"
            ),
        ),
        v if v.starts_with("FAIL") => (
            Severity::High,
            "AT-003",
            format!("attestation for {name} FAILED: {}", rep.errors.join("; ")),
        ),
        _ => (
            Severity::Medium,
            "AT-004",
            format!(
                "attestation for {name} could not be verified: {}",
                rep.errors.join("; ")
            ),
        ),
    };
    let mut evidence = Vec::new();
    for i in &rep.identities {
        evidence.push(format!("identity: {i}"));
    }
    if let Some(iss) = &rep.issuer {
        evidence.push(format!("issuer: {iss}"));
    }
    if let Some(r) = &rep.source_repo {
        evidence.push(format!("source: {r}"));
    }
    if let Some(m) = rep.artifact_match {
        evidence.push(format!("artifact digest match: {m}"));
    }
    Finding {
        ruleset: "attest".into(),
        rule_id: id.into(),
        severity: sev,
        target: "attest".into(),
        path: name.into(),
        line: None,
        excerpt: rep.identities.first().cloned(),
        message: msg,
        remediation: None,
        reference: None,
        window: None,
        evidence: Some(evidence),
    }
}

fn print_report(name: &str, rep: &AttestReport) {
    eprintln!("{name}: {}", rep.verdict());
    for i in &rep.identities {
        eprintln!("  identity: {i}");
    }
    if let Some(iss) = &rep.issuer {
        eprintln!("  issuer: {iss}");
    }
    if let Some(r) = &rep.source_repo {
        eprintln!("  source: {r}");
    }
    if let Some(m) = rep.artifact_match {
        eprintln!("  artifact digest match: {m}");
    }
    for e in &rep.errors {
        eprintln!("  error: {e}");
    }
}

pub(crate) struct AttestArgs<'a> {
    pub bundle: &'a Option<PathBuf>,
    pub artifact: &'a Option<PathBuf>,
    pub npm: &'a Option<String>,
    pub sig: &'a Option<PathBuf>,
    pub cert: &'a Option<PathBuf>,
    pub rekor_pub: &'a Option<PathBuf>,
    pub offline: bool,
}

pub(crate) fn attest_cmd(a: &AttestArgs, report: &mut Report) -> Result<(), String> {
    let (bundle, artifact, npm, sig, cert, rekor_pub, offline) = (
        a.bundle,
        a.artifact,
        a.npm,
        a.sig,
        a.cert,
        a.rekor_pub,
        a.offline,
    );
    let log_key = rekor_pub
        .as_ref()
        .map(|p| {
            let pem = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            crate::attest::load_log_key(&pem)
        })
        .transpose()?;
    let mut reps: Vec<(String, AttestReport)> = Vec::new();

    if let Some(b) = bundle {
        let bytes = std::fs::read(b).map_err(|e| format!("{}: {e}", b.display()))?;
        let rep = crate::attest::verify_bundle_key(&bytes, artifact.as_deref(), log_key.as_ref());
        reps.push((b.display().to_string(), rep));
    }
    if let Some(pkg) = npm {
        if offline {
            return Err("--npm attestation needs network (offline mode set)".into());
        }
        let http = crate::http::HttpClient::new(vec![]);
        let rs = crate::attest::verify_npm(&http, pkg)?;
        for (i, r) in rs.into_iter().enumerate() {
            reps.push((format!("npm:{pkg}[{i}]"), r));
        }
    }
    if sig.is_some() || cert.is_some() {
        let (sig, cert) = (
            sig.as_ref().ok_or("--sig and --cert go together")?,
            cert.as_ref().ok_or("--sig and --cert go together")?,
        );
        let sig_raw = std::fs::read(sig).map_err(|e| format!("{}: {e}", sig.display()))?;
        use base64::Engine as _;
        let sig_b = base64::engine::general_purpose::STANDARD
            .decode(String::from_utf8_lossy(&sig_raw).trim())
            .unwrap_or_else(|_| sig_raw.clone());
        let cert_pem =
            std::fs::read_to_string(cert).map_err(|e| format!("{}: {e}", cert.display()))?;
        let der = pem_cert_der(&cert_pem)
            .ok_or_else(|| format!("{}: no PEM certificate found", cert.display()))?;
        let artifact_b = artifact
            .as_ref()
            .map(|p| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display())))
            .transpose()?
            .ok_or("--sig/--cert mode requires --artifact")?;
        let rep = crate::attest::verify_sig_cert(&sig_b, &der, &artifact_b);
        reps.push((sig.display().to_string(), rep));
    }
    if reps.is_empty() {
        return Err("nothing to verify: pass a bundle, --npm PKG, or --sig+--cert".into());
    }
    for (name, rep) in &reps {
        print_report(name, rep);
        report.findings.push(finding(rep, name));
    }
    Ok(())
}
