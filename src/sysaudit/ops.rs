// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

use super::*;
pub(crate) fn logging(out: &mut Vec<Finding>) {
    let journal = read("/etc/systemd/journald.conf").unwrap_or_default();
    let persistent = journal.lines().any(|l| {
        l.trim_start().starts_with("Storage=persistent")
            || l.trim_start().starts_with("Storage=auto")
    });
    if !persistent {
        out.push(mk(
            "SYS-LOG-01",
            Severity::Low,
            "/etc/systemd/journald.conf",
            "journald Storage not persistent - logs die on reboot",
            "Set Storage=persistent and mkdir /var/log/journal.",
        ));
    }
    if cmd("systemctl", &["is-active", "auditd"]).map(|s| s.trim() == "active") != Some(true)
        && !Path::new("/usr/sbin/auditd").exists()
        && !Path::new("/sbin/auditd").exists()
    {
        out.push(mk(
            "SYS-LOG-02",
            Severity::Low,
            "auditd",
            "no auditd - no syscall/file-integrity audit trail",
            "Install auditd and load a baseline ruleset for security events.",
        ));
    }
    let has_syslog = Path::new("/var/log/syslog").exists()
        || Path::new("/var/log/messages").exists()
        || cmd("systemctl", &["is-active", "rsyslog"]).map(|s| s.trim() == "active") == Some(true);
    if !has_syslog {
        out.push(mk(
            "SYS-LOG-03",
            Severity::Info,
            "syslog",
            "no syslog daemon visible - journald only (fine if log shipping is configured)",
            "Consider remote log shipping (syslog/vector/journald upload).",
        ));
    }
}

// ---------- scheduler ----------

pub(crate) fn scheduler(out: &mut Vec<Finding>) {
    if !Path::new("/etc/cron.allow").exists() && !Path::new("/etc/cron.deny").exists() {
        out.push(mk(
            "SYS-CRON-01",
            Severity::Low,
            "/etc/cron.allow",
            "no cron.allow/deny - any account can schedule jobs",
            "Create /etc/cron.allow with only the accounts that need cron.",
        ));
    }
    if !Path::new("/etc/at.allow").exists() && !Path::new("/etc/at.deny").exists() {
        out.push(mk(
            "SYS-CRON-02",
            Severity::Low,
            "/etc/at.allow",
            "no at.allow/deny - any account can schedule at-jobs",
            "Create /etc/at.allow or disable atd.",
        ));
    }
    for d in [
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ] {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                if let Some(m) = mode_of(&e.path().to_string_lossy())
                    && m & 0o022 != 0
                {
                    out.push(mk(
                            "SYS-CRON-03",
                            Severity::High,
                            &e.path().to_string_lossy(),
                            format!("cron file {} is writable by non-owner ({m:04o}) - privilege escalation", e.file_name().to_string_lossy()),
                            "chmod 644 root:root at minimum; cron jobs run as their owner (often root).",
                        ));
                }
            }
        }
    }
}

// ---------- integrity / frameworks ----------

pub(crate) fn integrity(out: &mut Vec<Finding>) {
    let has_aide = Path::new("/usr/bin/aide").exists() || Path::new("/usr/sbin/aide").exists();
    let has_rkhunter = Path::new("/usr/bin/rkhunter").exists();
    let has_f2b = Path::new("/usr/bin/fail2ban-client").exists();
    if !has_aide && !has_rkhunter {
        out.push(mk(
            "SYS-INT-01",
            Severity::Info,
            "tools",
            "no file-integrity tooling (aide/rkhunter) - rootkits and tampering go unnoticed",
            "Install aide or rkhunter and baseline the system.",
        ));
    }
    if !has_f2b {
        out.push(mk(
            "SYS-INT-02",
            Severity::Info,
            "tools",
            "no fail2ban - repeated auth failures are not throttled",
            "Install fail2ban or sshguard for exposed services.",
        ));
    }
    let aa = Path::new("/sys/kernel/security/apparmor").exists();
    let se = Path::new("/sys/fs/selinux").exists();
    if !aa && !se {
        out.push(mk(
            "SYS-INT-03",
            Severity::Medium,
            "mandatory access control",
            "no AppArmor or SELinux - no MAC layer between a compromised daemon and the box",
            "Enable AppArmor (easier) or SELinux and apply profiles to exposed services.",
        ));
    } else if aa && let Some(s) = cmd("aa-status", &["--enabled"]) {
        let _ = s;
    }
    // time sync
    if cmd("systemctl", &["is-active", "systemd-timesyncd"]).map(|s| s.trim() == "active")
        != Some(true)
        && cmd("systemctl", &["is-active", "chronyd"]).map(|s| s.trim() == "active") != Some(true)
        && cmd("systemctl", &["is-active", "ntpd"]).map(|s| s.trim() == "active") != Some(true)
    {
        out.push(mk(
            "SYS-INT-04",
            Severity::Low,
            "ntp",
            "no time-sync service - clock drift breaks TLS, logs and audit correlation",
            "Enable systemd-timesyncd or chrony.",
        ));
    }
}

// ---------- home dirs ----------

pub(crate) fn homes(out: &mut Vec<Finding>) {
    for base in ["/home", "/root"] {
        let b = Path::new(base);
        if !b.is_dir() {
            continue;
        }
        let entries: Vec<_> = if base == "/root" {
            vec![b.to_path_buf()]
        } else {
            std::fs::read_dir(b)
                .map(|d| d.flatten().map(|e| e.path()).collect())
                .unwrap_or_default()
        };
        for home in entries {
            let Some(m) = mode_of(&home.to_string_lossy()) else {
                continue;
            };
            if m & 0o022 != 0 {
                out.push(mk(
                    "SYS-HOME-01",
                    Severity::Medium,
                    &home.to_string_lossy(),
                    format!(
                        "home dir {} is group/world-writable ({m:04o})",
                        home.file_name().unwrap_or_default().to_string_lossy()
                    ),
                    "chmod 750 or stricter.",
                ));
            }
            let ssh = home.join(".ssh");
            if ssh.is_dir() {
                if let Some(sm) = mode_of(&ssh.to_string_lossy())
                    && sm & 0o077 != 0
                {
                    out.push(mk(
                        "SYS-HOME-02",
                        Severity::High,
                        &ssh.to_string_lossy(),
                        format!("~/.ssh mode {sm:04o} readable by others"),
                        "chmod 700 ~/.ssh.",
                    ));
                }
                for f in [
                    "id_rsa",
                    "id_ed25519",
                    "id_ecdsa",
                    "id_dsa",
                    "authorized_keys",
                    "known_hosts",
                    "config",
                ] {
                    let fp = ssh.join(f);
                    if let Some(fm) = mode_of(&fp.to_string_lossy()) {
                        let private = f.starts_with("id_") && !f.ends_with(".pub");
                        if (private && fm & 0o177 != 0) || (!private && fm & 0o022 != 0) {
                            out.push(mk(
                                "SYS-HOME-03",
                                if private { Severity::High } else { Severity::Low },
                                &fp.to_string_lossy(),
                                format!("{} mode {fm:04o} too permissive", fp.to_string_lossy()),
                                "ssh refuses loose key perms; chmod 600 private keys, 644 the rest.",
                            ));
                        }
                    }
                }
            }
        }
    }
}

// ---------- malware quick checks (lynis MALW section) ----------

pub(crate) fn malware(out: &mut Vec<Finding>) {
    // ld.so.preload is THE classic userland-rootkit primitive
    if let Some(pl) = read("/etc/ld.so.preload") {
        let t = pl.trim();
        if !t.is_empty() {
            out.push(mk(
                "SYS-MAL-01",
                Severity::Critical,
                "/etc/ld.so.preload",
                format!("ld.so.preload is non-empty ({t}) - every process loads this library"),
                "This is a signature of userland rootkits (Azazel, Jynx). Investigate before deleting.",
            ));
        }
    }
    // processes running from temp dirs
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            let name = e.file_name();
            if name.to_string_lossy().chars().all(|c| c.is_ascii_digit())
                && let Ok(exe) = std::fs::read_link(e.path().join("exe"))
            {
                let ex = exe.to_string_lossy();
                if ex.starts_with("/tmp")
                    || ex.starts_with("/dev/shm")
                    || ex.starts_with("/var/tmp")
                {
                    let comm =
                        read_trim(&e.path().join("comm").to_string_lossy()).unwrap_or_default();
                    out.push(mk(
                            "SYS-MAL-02",
                            Severity::High,
                            &e.path().to_string_lossy(),
                            format!("process {comm} (pid {}) executes from {ex} - classic dropper location", name.to_string_lossy()),
                            "Inspect the binary and its parent; /tmp execution is near-always malicious or ad-hoc.",
                        ));
                }
            }
        }
    }
    // deleted-but-running binaries (self-cleaning malware)
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            let name = e.file_name();
            if name.to_string_lossy().chars().all(|c| c.is_ascii_digit())
                && let Ok(exe) = std::fs::read_link(e.path().join("exe"))
                && exe.to_string_lossy().ends_with(" (deleted)")
            {
                out.push(mk(
                            "SYS-MAL-03",
                            Severity::Medium,
                            &e.path().to_string_lossy(),
                            format!("pid {} runs a deleted binary ({}) - self-cleaning payload or crashed update", name.to_string_lossy(), exe.to_string_lossy()),
                            "Check the process tree; deleted executables are a common malware trick.",
                        ));
            }
        }
    }
    // hidden dirs/files in system temp roots (cheap anomaly signal)
    for d in ["/tmp", "/dev/shm", "/var/tmp"] {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                let known = [
                    ".X11-unix",
                    ".ICE-unix",
                    ".font-unix",
                    ".XIM-unix",
                    ".Test-unix",
                    ".X0-lock",
                    ".X1-lock",
                    ".X2-lock",
                    ".mount",
                    ".tmp",
                ];
                let normal = known.iter().any(|k| n == *k)
                    || n.starts_with(".X") && n.ends_with("-lock")
                    || n.starts_with("systemd-private-");
                if n.starts_with('.') && n != "." && n != ".." && !normal {
                    out.push(mk(
                        "SYS-MAL-04",
                        Severity::Low,
                        &e.path().to_string_lossy(),
                        format!("hidden entry {n} in {d}"),
                        "Verify it belongs to a known tool (X11-unix, systemd-private are normal).",
                    ));
                }
            }
        }
    }
}

/// Service config audits: nginx, apache, mysql, postgres, redis.
/// Only reads files that exist; absent services produce no findings.
pub(crate) fn services_cfg(out: &mut Vec<Finding>) {
    // nginx: autoindex, missing ssl on 443 vhosts, allow all on server
    for p in ["/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/default"] {
        let Some(t) = read(p) else { continue };
        if t.contains("autoindex on") {
            out.push(mk(
                "SYS-SVC-01",
                Severity::Medium,
                p,
                "nginx autoindex enabled - directory contents enumerable",
                "Set autoindex off unless indexing is intentional.",
            ));
        }
        if t.contains("listen 443") && !t.contains("ssl_certificate") && !t.contains("ssl on") {
            out.push(mk(
                "SYS-SVC-02",
                Severity::High,
                p,
                "nginx listens on 443 without ssl_certificate",
                "Point ssl_certificate/ssl_certificate_key at real certs.",
            ));
        }
        if t.contains("allow all") || t.contains("allow 0.0.0.0/0") {
            out.push(mk(
                "SYS-SVC-03",
                Severity::Low,
                p,
                "nginx allow all without location scoping",
                "Scope allow/deny to specific locations or IP ranges.",
            ));
        }
    }
    // apache
    for p in [
        "/etc/apache2/apache2.conf",
        "/etc/httpd/conf/httpd.conf",
        "/etc/httpd/conf.d/*.conf",
    ] {
        if p.contains('*') {
            continue; // glob expansion skipped; main files cover the signal
        }
        let Some(t) = read(p) else { continue };
        if t.contains("Options") && t.contains("Indexes") {
            out.push(mk(
                "SYS-SVC-11",
                Severity::Medium,
                p,
                "apache Options Indexes - directory listing enabled",
                "Remove Indexes from Options in production vhosts.",
            ));
        }
        if t.contains("AllowOverride All") {
            out.push(mk(
                "SYS-SVC-12",
                Severity::Low,
                p,
                "apache AllowOverride All - .htaccess can reconfigure",
                "Set AllowOverride None where .htaccess is not needed.",
            ));
        }
    }
    // mysql/mariadb
    for p in [
        "/etc/mysql/my.cnf",
        "/etc/my.cnf",
        "/etc/mysql/mariadb.conf.d/50-server.cnf",
    ] {
        let Some(t) = read(p) else { continue };
        let t = t.to_lowercase();
        if t.contains("bind-address") && t.contains("0.0.0.0") {
            out.push(mk(
                "SYS-SVC-21",
                Severity::High,
                p,
                "mysql binds to 0.0.0.0 - reachable on all interfaces",
                "Bind to 127.0.0.1 or the specific app interface.",
            ));
        }
        if t.contains("skip-grant-tables") {
            out.push(mk(
                "SYS-SVC-22",
                Severity::Critical,
                p,
                "mysql skip-grant-tables - authentication bypassed entirely",
                "Remove it; this disables all account checks.",
            ));
        }
    }
    // postgres
    for p in ["/etc/postgresql"] {
        if let Ok(rd) = std::fs::read_dir(p) {
            for ent in rd.flatten() {
                let cf = ent.path().join("main/postgresql.conf");
                let Some(t) = read(&cf.to_string_lossy()) else {
                    continue;
                };
                for line in t.lines() {
                    let l = line.trim();
                    if l.starts_with("listen_addresses") && l.contains('*') {
                        out.push(mk(
                            "SYS-SVC-31",
                            Severity::Medium,
                            &cf.to_string_lossy(),
                            "postgres listen_addresses '*' - reachable on all interfaces",
                            "Restrict to needed interfaces; pair with pg_hba rules.",
                        ));
                    }
                }
            }
        }
    }
    // redis
    for p in ["/etc/redis/redis.conf", "/etc/redis.conf"] {
        let Some(t) = read(p) else { continue };
        let active = |k: &str| t.lines().any(|l| l.trim().starts_with(k));
        if active("bind 0.0.0.0") || (active("bind *") && !t.contains("requirepass")) {
            out.push(mk(
                "SYS-SVC-41",
                Severity::High,
                p,
                "redis bound to all interfaces without requirepass",
                "Bind loopback or set requirepass + protected-mode.",
            ));
        }
    }
}
