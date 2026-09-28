//! System hardening audit - a Lynis-class check set for the host.
//! Reads /etc, /proc, /sys and a handful of read-only command outputs
//! (ss, systemctl, ip) and reports hardening gaps by category.
//!
//! Categories follow Lynis' own grouping so users cross-reference easily:
//! BOOT kernel/auth/ssh network filesystem services logging scheduler
//! integrity home mal (malware quick-checks)

mod checks;
mod net;
mod ops;
use crate::finding::{Finding, Severity};
use checks::*;
use net::*;
use ops::*;
use std::collections::HashSet;
use std::path::Path;

const LYNIS: &str = "https://cisofy.com/lynis/";

fn mk(id: &str, sev: Severity, path: &str, msg: impl Into<String>, fix: &str) -> Finding {
    Finding {
        ruleset: "system-audit".into(),
        rule_id: id.into(),
        severity: sev,
        target: "system".into(),
        path: path.into(),
        line: None,
        excerpt: None,
        message: msg.into(),
        remediation: Some(fix.into()),
        reference: Some(LYNIS.into()),
        window: None,
    }
}

fn read(p: &str) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

fn read_trim(p: &str) -> Option<String> {
    read(p).map(|s| s.trim().to_string())
}

fn cmd(prog: &str, args: &[&str]) -> Option<String> {
    std::process::Command::new(prog)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
}

/// sysctl from /proc/sys (no subprocess needed).
fn sysctl(key: &str) -> Option<String> {
    read_trim(&format!("/proc/sys/{}", key.replace('.', "/")))
}

fn sysctl_is(key: &str, want: &str) -> Option<bool> {
    sysctl(key).map(|v| v == want)
}

pub fn audit() -> Vec<Finding> {
    let mut out = Vec::new();
    kernel(&mut out);
    auth(&mut out);
    ssh(&mut out);
    network(&mut out);
    filesystem(&mut out);
    services(&mut out);
    logging(&mut out);
    scheduler(&mut out);
    integrity(&mut out);
    homes(&mut out);
    malware(&mut out);
    out
}

// ---------- kernel ----------
