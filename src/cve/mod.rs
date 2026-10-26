// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! argus cve: match installed or advertised versions of nginx, PHP,
//! Apache httpd, Brotli, Traefik and Caddy against a bundled advisory
//! database. External mode is passive fingerprinting only; no exploit
//! payloads are sent. Local mode reads binaries, configs and package
//! metadata; --root inspects a mounted tree without executing anything.

mod db;
mod distro;
mod external;
mod local;
mod probe;
mod version;

use crate::cli::CveArgs;
use crate::finding::{Finding, Report, Severity};
use std::io::Read as _;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

pub const DEFAULT_PORTS: &[u16] = &[80, 443, 8080, 8443, 8000, 8081, 8888, 9443, 2019, 3000];

pub fn print_db(a: &CveArgs) -> Result<ExitCode, String> {
    let db = db::load(&a.db)?;
    print!("{}", db::list(&db, &a.product));
    Ok(ExitCode::SUCCESS)
}

pub fn run(a: &CveArgs, report: &mut Report) -> Result<(), String> {
    let mut db = db::load(&a.db)?;
    if !a.product.is_empty() {
        db.retain(|x| a.product.iter().any(|p| p == &x.product));
    }
    let mut findings = if a.local || a.root.is_some() {
        let root = a.root.clone().unwrap_or_else(|| "/".into());
        local::scan(&db, &root, a.root.is_none(), a)
    } else {
        let mut targets = a.targets.clone();
        if let Some(f) = &a.file {
            let text =
                std::fs::read_to_string(f).map_err(|e| format!("read {}: {e}", f.display()))?;
            targets.extend(
                text.lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty()),
            );
        }
        if targets.is_empty() {
            local::scan(&db, Path::new("/"), true, a)
        } else {
            external::scan(&db, &targets, a)?
        }
    };
    findings.sort_by(|x, y| {
        (x.target.clone(), x.path.clone(), x.rule_id.clone()).cmp(&(
            y.target.clone(),
            y.path.clone(),
            y.rule_id.clone(),
        ))
    });
    report.findings.extend(findings);
    Ok(())
}

pub(crate) fn mk(
    adv_id: &str,
    sev: Severity,
    target: &str,
    path: &str,
    msg: impl Into<String>,
) -> Finding {
    Finding {
        ruleset: "cve".into(),
        rule_id: adv_id.into(),
        severity: sev,
        target: target.into(),
        path: path.into(),
        line: None,
        excerpt: None,
        message: msg.into(),
        remediation: None,
        reference: None,
        window: None,
        evidence: None,
    }
}

/// Build a finding for one matched advisory.
pub(crate) fn adv_finding(
    adv: &db::Advisory,
    sev: Severity,
    target: &str,
    path: &str,
    mut evidence: Vec<String>,
) -> Finding {
    let mut msg = String::new();
    if adv.exploited || adv.kev {
        msg.push_str("[exploited in the wild] ");
    }
    msg.push_str(&format!("{}: {}", adv.id, adv.title));
    if adv.exploited {
        evidence.push("exploited in the wild".into());
    }
    if adv.kev {
        evidence.push("CISA KEV".into());
    }
    if adv.rce {
        evidence.push("unauthenticated RCE class".into());
    }
    evidence.push(format!("fixed in {}", adv.fixed));
    let mut remediation = format!("Upgrade {} to {}", adv.product, adv.fixed);
    if let Some(n) = &adv.note {
        remediation.push_str(&format!(". {n}"));
    }
    let mut f = mk(&adv.id, sev, target, path, msg);
    f.remediation = Some(remediation);
    f.reference = adv.reference.clone();
    f.evidence = (!evidence.is_empty()).then_some(evidence);
    f
}

/// Reachability from probe results for one advisory.
pub(crate) enum Reach {
    Yes(Vec<String>),
    No,
    Unknown(&'static str),
}

pub(crate) fn reach(adv: &db::Advisory, evals: &[(String, probe::Eval)]) -> Reach {
    if adv.needs.is_empty() {
        return Reach::Yes(Vec::new());
    }
    let mut unknown = false;
    let mut yes = Vec::new();
    let mut no = 0;
    for (n, e) in evals {
        match e {
            probe::Eval::Yes => yes.push(format!("config enables {n}")),
            probe::Eval::No => no += 1,
            probe::Eval::Unknown => unknown = true,
        }
    }
    if !yes.is_empty() {
        Reach::Yes(yes)
    } else if no == adv.needs.len() {
        Reach::No
    } else if unknown {
        Reach::Unknown("configuration not inspected")
    } else {
        Reach::No
    }
}

/// Run a helper binary with a hard timeout; returns (stdout+stderr).
/// Never runs in --root mode (callers gate on that).
pub(crate) fn run_cmd(prog: &str, args: &[&str], timeout: Duration) -> Option<(String, bool)> {
    run_cmd_path(Path::new(prog), args, timeout)
}

pub(crate) fn run_cmd_path(
    prog: &Path,
    args: &[&str],
    timeout: Duration,
) -> Option<(String, bool)> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => {
                let mut out = String::new();
                if let Some(mut so) = child.stdout.take() {
                    let mut b = Vec::new();
                    let _ = so.read_to_end(&mut b);
                    out.push_str(&String::from_utf8_lossy(&b));
                }
                if let Some(mut se) = child.stderr.take() {
                    let mut b = Vec::new();
                    let _ = se.read_to_end(&mut b);
                    out.push_str(&String::from_utf8_lossy(&b));
                }
                return Some((out, st.success()));
            }
            Ok(None) => {
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    }
}

/// Read file bytes capped at a size limit, in chunks.
pub(crate) fn read_capped(p: &Path, cap: u64) -> Option<Vec<u8>> {
    let mut f = std::fs::File::open(p).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1 << 20];
    loop {
        let n = f.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() as u64 >= cap {
            buf.truncate(cap as usize);
            break;
        }
    }
    Some(buf)
}
