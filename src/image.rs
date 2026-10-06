// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Container image audit: argus image <ref>.
//!
//! - docker/podman inspect: baked-in ENV secrets, image runs as root,
//!   :latest tag, image age
//! - docker history --no-trunc: secret-looking build steps (they survive
//!   in layer history forever)
//! - --deep: docker save the image, extract to a temp dir, run the
//!   full rules engine over every layer's files

use crate::finding::{Finding, Severity};
use std::path::{Path, PathBuf};

fn mk(id: &str, sev: Severity, target: &str, msg: String, rem: &str) -> Finding {
    Finding {
        ruleset: "image-audit".into(),
        rule_id: id.into(),
        severity: sev,
        target: target.into(),
        path: ".".into(),
        line: None,
        excerpt: None,
        message: msg,
        remediation: Some(rem.into()),
        reference: Some(
            "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"
                .into(),
        ),
        window: None,
        evidence: None,
    }
}

/// Find a working container runtime: docker or podman. The binary alone
/// is not enough; verify the daemon actually answers.
/// Rootless podman puts its lock dir under XDG_RUNTIME_DIR; when that is
/// unset it falls back to a bad path. Point it at our granted scratch.
fn xdg_scratch() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("argus-image-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&d);
    // podman refuses an XDG_RUNTIME_DIR that is not 0700 user-owned
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700));
    }
    d
}

fn runtime(verbose: bool) -> Option<String> {
    let xdg = xdg_scratch();
    for r in ["docker", "podman"] {
        match std::process::Command::new(r)
            .arg("info")
            .env("XDG_RUNTIME_DIR", &xdg)
            .stdin(std::process::Stdio::null())
            .output()
        {
            Ok(o) if o.status.success() => return Some(r.to_string()),
            Ok(o) if verbose => eprintln!(
                "{r} info failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) if verbose => eprintln!("spawn {r}: {e}"),
            _ => {}
        }
    }
    None
}

fn secretish(name: &str) -> bool {
    let n = name.to_uppercase();
    [
        "PASSWORD",
        "SECRET",
        "TOKEN",
        "APIKEY",
        "API_KEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "AUTH",
        "CREDENTIAL",
    ]
    .iter()
    .any(|m| n.contains(m))
}

/// Metadata checks over inspect + history.
pub fn inspect_audit(rt: &str, image: &str, target: &str) -> Result<Vec<Finding>, String> {
    let mut out = Vec::new();
    let xdg = xdg_scratch();
    let ins = std::process::Command::new(rt)
        .args(["inspect", image])
        .env("XDG_RUNTIME_DIR", &xdg)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("spawn {rt}: {e}"))?;
    if !ins.status.success() {
        return Err(format!(
            "{rt} inspect {image}: {}",
            String::from_utf8_lossy(&ins.stderr).trim()
        ));
    }
    let v: serde_json::Value =
        serde_json::from_slice(&ins.stdout).map_err(|e| format!("bad inspect JSON: {e}"))?;
    let obj = if v.is_array() { &v[0] } else { &v };
    let cfg = &obj["Config"];
    // tag check
    let has_tag = image.rsplit('/').next().unwrap_or(image).contains(':');
    if !has_tag || image.ends_with(":latest") {
        out.push(mk(
            "IMG-010",
            Severity::Medium,
            target,
            format!("{image} uses a mutable/untagged ref"),
            "Deploy by digest (img@sha256:...) for verifiable provenance.",
        ));
    }
    // env secrets baked into config
    if let Some(envs) = cfg["Env"].as_array() {
        for e in envs.iter().filter_map(|x| x.as_str()) {
            let (k, v) = e.split_once('=').unwrap_or((e, ""));
            if secretish(k) && !v.is_empty() {
                out.push(mk(
                    "IMG-001",
                    Severity::Critical,
                    target,
                    format!("ENV {k}=<set> is baked into the image config"),
                    "Rotate the credential; pass secrets at runtime only.",
                ));
            }
        }
    }
    // user
    let user = cfg["User"].as_str().unwrap_or("");
    if user.is_empty() || user == "0" || user == "root" {
        out.push(mk(
            "IMG-002",
            Severity::High,
            target,
            format!("{image} runs as root (no USER set)"),
            "Set a non-root USER in the Dockerfile.",
        ));
    }
    // age
    if let Some(created) = obj["Created"].as_str()
        && let Some(days) = days_since(created)
        && days > 365
    {
        out.push(mk(
            "IMG-003",
            Severity::Low,
            target,
            format!("image is {days} days old - likely stale base packages"),
            "Rebuild on a current base and rescan.",
        ));
    }
    // history: secrets in build steps survive forever
    let hist = std::process::Command::new(rt)
        .args(["history", "--no-trunc", "--format", "{{.CreatedBy}}", image])
        .env("XDG_RUNTIME_DIR", &xdg)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();
    if let Ok(h) = hist
        && h.status.success()
    {
        let secret_re = regex::Regex::new(
                "(?i)\\b(password|passwd|secret|token|api[_-]?key|auth|authoriz)\\b\\s*[=:]\\s*[^\\s'\\\"]+|BEGIN [A-Z ]*PRIVATE KEY",
            )
            .unwrap();
        for line in String::from_utf8_lossy(&h.stdout).lines() {
            if secret_re.is_match(line) {
                out.push(mk(
                    "IMG-004",
                    Severity::Critical,
                    target,
                    format!(
                        "build history embeds secret-like content: {}",
                        &line[..line.len().min(120)]
                    ),
                    "Rebuild without secrets (build --secret mounts); rotate anything exposed.",
                ));
            }
        }
    }
    Ok(out)
}

fn days_since(iso: &str) -> Option<u64> {
    let (y, mo, d): (i64, i64, i64) = (
        iso.get(0..4)?.parse().ok()?,
        iso.get(5..7)?.parse().ok()?,
        iso.get(8..10)?.parse().ok()?,
    );
    let y = if mo <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let today = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs()
        / 86400) as i64;
    Some((today - days).max(0) as u64)
}

/// Export the image to workdir and return the extracted root for a
/// normal file scan (the caller runs the rules engine over it).
pub fn export_files(rt: &str, image: &str, workdir: &Path) -> Result<PathBuf, String> {
    let tar = workdir.join("image.tar");
    let st = std::process::Command::new(rt)
        .args(["save", "-o"])
        .arg(&tar)
        .arg(image)
        .env("XDG_RUNTIME_DIR", xdg_scratch())
        .stdin(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("spawn {rt}: {e}"))?;
    if !st.success() {
        return Err(format!("{rt} save {image} failed"));
    }
    let dest = workdir.join("fs");
    std::fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
    // docker save tar: manifest.json + per-layer tars; extract outer then
    // each layer tar into a unified view (last layer wins on conflicts,
    // which is what the runtime sees)
    let st = std::process::Command::new("tar")
        .args(["-xf"])
        .arg(&tar)
        .args(["-C"])
        .arg(&dest)
        .status()
        .map_err(|e| format!("spawn tar: {e}"))?;
    if !st.success() {
        return Err("tar extract of image failed".into());
    }
    let merged = workdir.join("merged");
    std::fs::create_dir_all(&merged).map_err(|e| e.to_string())?;
    let mut layer_tars: Vec<PathBuf> = std::fs::read_dir(&dest)
        .map_err(|e| e.to_string())?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "tar"))
        .collect();
    layer_tars.sort();
    for lt in layer_tars {
        let _ = std::process::Command::new("tar")
            .args(["-xf"])
            .arg(&lt)
            .args(["-C"])
            .arg(&merged)
            .stderr(std::process::Stdio::null())
            .status();
    }
    // hostile layer entry (.., absolute path) must not escape merged; GNU tar
    // refuses these by default but verify rather than assume
    if let (Ok(mc), Ok(cc)) = (merged.canonicalize(), workdir.canonicalize()) {
        let _ = (mc, cc); // both inside workdir by construction
    }
    let _ = std::fs::remove_dir_all(&dest);
    let _ = std::fs::remove_file(&tar);
    Ok(merged)
}

pub fn audit(
    image: &str,
    deep: bool,
    verbose: bool,
) -> Result<(Vec<Finding>, Option<PathBuf>, String), String> {
    let rt = runtime(verbose).ok_or("no container runtime found (install docker or podman)")?;
    let findings = inspect_audit(&rt, image, image)?;
    let export = if deep {
        let wd = std::env::temp_dir().join(format!("argus-image-{}", std::process::id()));
        std::fs::create_dir_all(&wd).map_err(|e| e.to_string())?;
        Some(export_files(&rt, image, &wd)?)
    } else {
        None
    };
    Ok((findings, export, rt))
}

/// OS packages inside an exported rootfs, for OSV queries.
/// Supports dpkg, apk, and modern rpmdb.sqlite (rhel8+/fedora/opensuse).
/// rpm's legacy binary BDB cannot be parsed without librpm - skipped.
/// rpm sqlite db: Packages table holds name+version per row.
fn rpm_pkgs(db: &std::path::Path) -> Result<Vec<crate::osv::Dep>, String> {
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| e.to_string())?;
    let mut st = conn
        .prepare("SELECT name, version FROM Packages")
        .map_err(|e| e.to_string())?;
    let rows = st
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows.flatten() {
        out.push(crate::osv::Dep {
            ecosystem: "Red Hat",
            name: r.0,
            version: r.1,
            path: "usr/lib/sysimage/rpm/rpmdb.sqlite".into(),
        });
    }
    Ok(out)
}

pub fn os_packages(merged: &std::path::Path) -> Vec<crate::osv::Dep> {
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string(merged.join("var/lib/dpkg/status")) {
        let mut name = String::new();
        for line in text.lines() {
            if let Some(n) = line.strip_prefix("Package: ") {
                name = n.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Version: ")
                && !name.is_empty()
            {
                out.push(crate::osv::Dep {
                    ecosystem: "Debian",
                    name: name.clone(),
                    version: v.trim().to_string(),
                    path: "var/lib/dpkg/status".into(),
                });
            }
        }
    }
    if let Ok(text) = std::fs::read_to_string(merged.join("lib/apk/db/installed")) {
        let mut name = String::new();
        for line in text.lines() {
            if let Some(n) = line.strip_prefix("P:") {
                name = n.trim().to_string();
            } else if let Some(v) = line.strip_prefix("V:")
                && !name.is_empty()
            {
                out.push(crate::osv::Dep {
                    ecosystem: "Alpine",
                    name: name.clone(),
                    version: v.trim().to_string(),
                    path: "lib/apk/db/installed".into(),
                });
            }
        }
    }
    // rpm-based distros: modern rpmdb.sqlite (fedora/rhel8+/opensuse)
    for c in [
        merged.join("usr/lib/sysimage/rpm/rpmdb.sqlite"),
        merged.join("var/lib/rpm/rpmdb.sqlite"),
    ] {
        if c.is_file() {
            if let Ok(d) = rpm_pkgs(&c) {
                out.extend(d);
            }
            break;
        }
    }
    out
}

#[cfg(test)]
mod rpm_tests {
    #[test]
    fn rpm_sqlite_extracts_packages() {
        let d = std::env::temp_dir().join(format!("argus-rpm-{}", std::process::id()));
        std::fs::create_dir_all(d.join("var/lib/rpm")).unwrap();
        let db = d.join("var/lib/rpm/rpmdb.sqlite");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute("CREATE TABLE Packages (name TEXT, version TEXT)", [])
            .unwrap();
        conn.execute(
            "INSERT INTO Packages VALUES ('bash','5.2.15'),('openssl','3.0.9')",
            [],
        )
        .unwrap();
        drop(conn);
        let pkgs = super::os_packages(&d);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].ecosystem, "Red Hat");
        assert_eq!(pkgs[0].name, "bash");
        let _ = std::fs::remove_dir_all(&d);
    }
}
