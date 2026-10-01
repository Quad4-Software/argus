// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

use super::*;
pub(crate) fn kernel(out: &mut Vec<Finding>) {
    // (sysctl key, secure value, id, severity, what)
    let checks: &[(&str, &str, &str, Severity, &str)] = &[
        (
            "kernel.randomize_va_space",
            "2",
            "SYS-KERN-01",
            Severity::High,
            "ASLR fully enabled (2)",
        ),
        (
            "kernel.kptr_restrict",
            "2",
            "SYS-KERN-02",
            Severity::Low,
            "kernel pointers hidden (kptr_restrict=2)",
        ),
        (
            "kernel.yama.ptrace_scope",
            "2",
            "SYS-KERN-03",
            Severity::Medium,
            "ptrace restricted to admin (ptrace_scope=2)",
        ),
        (
            "kernel.kexec_load_disabled",
            "1",
            "SYS-KERN-04",
            Severity::Low,
            "kexec disabled",
        ),
        (
            "fs.suid_dumpable",
            "0",
            "SYS-KERN-05",
            Severity::Medium,
            "suid core dumps disabled",
        ),
        (
            "kernel.unprivileged_userns_clone",
            "0",
            "SYS-KERN-06",
            Severity::Medium,
            "unprivileged user namespaces disabled",
        ),
        (
            "kernel.dmesg_restrict",
            "1",
            "SYS-KERN-07",
            Severity::Low,
            "dmesg restricted",
        ),
        (
            "net.ipv4.ip_forward",
            "0",
            "SYS-NET-01",
            Severity::Medium,
            "IPv4 forwarding off on a non-router",
        ),
        (
            "net.ipv4.conf.all.rp_filter",
            "1",
            "SYS-NET-02",
            Severity::Low,
            "reverse-path filtering on",
        ),
        (
            "net.ipv4.conf.all.accept_source_route",
            "0",
            "SYS-NET-03",
            Severity::Medium,
            "source-routed packets dropped",
        ),
        (
            "net.ipv4.conf.all.accept_redirects",
            "0",
            "SYS-NET-04",
            Severity::Medium,
            "ICMP redirects not accepted",
        ),
        (
            "net.ipv4.tcp_syncookies",
            "1",
            "SYS-NET-05",
            Severity::Low,
            "SYN cookies on",
        ),
        (
            "net.ipv4.conf.all.send_redirects",
            "0",
            "SYS-NET-06",
            Severity::Low,
            "host does not send ICMP redirects",
        ),
        (
            "net.ipv4.icmp_echo_ignore_broadcasts",
            "1",
            "SYS-NET-07",
            Severity::Low,
            "ICMP broadcast pings ignored",
        ),
    ];
    for (key, want, id, sev, what) in checks {
        if let Some(false) = sysctl_is(key, want) {
            let cur = sysctl(key).unwrap_or_default();
            out.push(mk(
                id,
                *sev,
                "/etc/sysctl.d",
                format!("sysctl {key}={cur} - want {want} ({what})"),
                &format!("Set {key}={want} in /etc/sysctl.d/*.conf and sysctl --system."),
            ));
        }
        // missing keys mean the module/knob is not loaded - skip
    }
    // core_pattern piped to a helper is a data-exfil + persistence primitive
    if let Some(cp) = sysctl("kernel.core_pattern")
        && cp.starts_with('|')
    {
        out.push(mk(
                "SYS-KERN-08",
                Severity::Medium,
                "/proc/sys/kernel/core_pattern",
                format!("core_pattern pipes to a helper ({cp}) - crash data leaves the box and the pipe runs as root"),
                "Use a plain file pattern or disable cores for suid/PII workloads.",
            ));
    }
    // unprivileged userns on Ubuntu-style knob too
    if let Some(v) = sysctl("user.max_user_namespaces")
        && v.parse::<u64>().unwrap_or(0) > 1000
        && sysctl("kernel.unprivileged_userns_clone").is_none()
    {
        // high cap with no clone knob visible: common default, report low
        out.push(mk(
                "SYS-KERN-06",
                Severity::Low,
                "/proc/sys/user/max_user_namespaces",
                format!("user.max_user_namespaces={v} - unprivileged userns is wide open (container-escape primitive)"),
                "Restrict with kernel.unprivileged_userns_clone=0 or a small max_user_namespaces.",
            ));
    }
    // secure boot
    if Path::new("/sys/firmware/efi").exists() {
        match cmd("mokutil", &["--sb-state"]) {
            Some(s) if s.contains("SecureBoot enabled") => {}
            _ => out.push(mk(
                "SYS-BOOT-01",
                Severity::Low,
                "/sys/firmware/efi",
                "UEFI present but Secure Boot is off or undetermined",
                "Enable Secure Boot in firmware (mokutil --sb-state to verify).",
            )),
        }
    }
}

// ---------- auth / accounts ----------

pub(crate) fn parse_passwd(text: &str) -> Vec<(String, u32, String, String)> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() >= 7 {
                Some((
                    f[0].to_string(),
                    f[2].parse().unwrap_or(u32::MAX),
                    f[5].to_string(),
                    f[6].to_string(),
                ))
            } else {
                None
            }
        })
        .collect()
}

pub(crate) fn parse_shadow(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() >= 2 {
                Some((f[0].to_string(), f[1].to_string()))
            } else {
                None
            }
        })
        .collect()
}

pub(crate) fn mode_of(p: &str) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(p).ok().map(|m| m.mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = p;
        None
    }
}

pub(crate) fn auth(out: &mut Vec<Finding>) {
    let Some(pw) = read("/etc/passwd") else {
        return;
    };
    let accounts = parse_passwd(&pw);
    let shadow = read("/etc/shadow")
        .map(|s| parse_shadow(&s))
        .unwrap_or_default();
    let empty_pw: HashSet<&str> = shadow
        .iter()
        .filter(|(_, h)| h.is_empty())
        .map(|(u, _)| u.as_str())
        .collect();
    let locked_pw: HashSet<&str> = shadow
        .iter()
        .filter(|(_, h)| h.starts_with('!') || h.starts_with('*'))
        .map(|(u, _)| u.as_str())
        .collect();

    for (user, uid, home, shell) in &accounts {
        if *uid == 0 && user != "root" {
            out.push(mk(
                "SYS-AUTH-01",
                Severity::High,
                "/etc/passwd",
                format!("account {user} has UID 0 (second root)"),
                "Remove or reassign; extra UID-0 accounts bypass single-root assumptions.",
            ));
        }
        if empty_pw.contains(user.as_str()) {
            out.push(mk(
                "SYS-AUTH-02",
                Severity::Critical,
                "/etc/shadow",
                format!("account {user} has an EMPTY password"),
                "Lock it (passwd -l) or set a password immediately.",
            ));
        }
        let login_shell =
            !(shell.contains("nologin") || shell.contains("false") || shell.is_empty());
        if login_shell
            && !locked_pw.contains(user.as_str())
            && user != "root"
            && (*uid == 0 || home.is_empty() || !Path::new(home).exists())
        {
            out.push(mk(
                "SYS-AUTH-03",
                Severity::Low,
                "/etc/passwd",
                format!("login-capable account {user} has a missing/unusual home ({home})"),
                "Verify the account is still needed and its home is correct.",
            ));
        }
    }

    for (path, max, id) in [
        ("/etc/passwd", 0o644, "SYS-AUTH-10"),
        ("/etc/group", 0o644, "SYS-AUTH-11"),
    ] {
        if let Some(m) = mode_of(path)
            && (m & 0o022 != 0 || m > max)
        {
            out.push(mk(
                id,
                Severity::High,
                path,
                format!("{path} mode {m:04o} is writable beyond root"),
                "chmod 644.",
            ));
        }
    }
    for (path, max, id) in [
        ("/etc/shadow", 0o640, "SYS-AUTH-12"),
        ("/etc/gshadow", 0o640, "SYS-AUTH-13"),
    ] {
        if let Some(m) = mode_of(path)
            && (m & 0o027 != 0 || m > max)
        {
            out.push(mk(
                id,
                Severity::High,
                path,
                format!("{path} mode {m:04o} exposes password hashes"),
                "chmod 640 root:shadow.",
            ));
        }
    }

    // password aging policy
    if let Some(ld) = read("/etc/login.defs") {
        for line in ld.lines() {
            let t = line.trim();
            if t.starts_with("PASS_MAX_DAYS") {
                let days: i64 = t
                    .split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                if days > 365 || days == 99999 {
                    out.push(mk(
                        "SYS-AUTH-20",
                        Severity::Low,
                        "/etc/login.defs",
                        format!("PASS_MAX_DAYS={days} - passwords effectively never expire"),
                        "Set a real rotation window (90-365) for local accounts.",
                    ));
                }
            }
        }
    }

    // sudoers: NOPASSWD / !authenticate are quiet privilege grants
    for p in ["/etc/sudoers", "/etc/sudoers.d"] {
        collect_sudo_rules(p, out);
    }
}

pub(crate) fn collect_sudo_rules(p: &str, out: &mut Vec<Finding>) {
    let path = Path::new(p);
    let files: Vec<std::path::PathBuf> = if path.is_dir() {
        std::fs::read_dir(path)
            .map(|d| d.flatten().map(|e| e.path()).collect())
            .unwrap_or_default()
    } else if path.is_file() {
        vec![path.to_path_buf()]
    } else {
        Vec::new()
    };
    for f in files {
        let Some(text) = read(&f.to_string_lossy()) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            if t.contains("NOPASSWD") {
                out.push(mk(
                    "SYS-AUTH-30",
                    Severity::Medium,
                    &f.to_string_lossy(),
                    format!("sudo rule line {} grants NOPASSWD: {}", n + 1, &t[..t.len().min(80)]),
                    "Prefer password-authenticated sudo; NOPASSWD turns account compromise into instant root.",
                ));
            }
            if t.starts_with("Defaults") && t.contains("env_keep") {
                out.push(mk(
                    "SYS-AUTH-31",
                    Severity::Low,
                    &f.to_string_lossy(),
                    "sudoers keeps environment variables (env_keep) - PATH/lib tricks survive sudo",
                    "Minimize env_keep entries.",
                ));
            }
        }
    }
    // sudoers.d perms must be 440/750-ish, not world-readable
    if let Some(m) = mode_of("/etc/sudoers")
        && m & 0o077 != 0
    {
        out.push(mk(
            "SYS-AUTH-32",
            Severity::Medium,
            "/etc/sudoers",
            format!("sudoers mode {m:04o} readable by others"),
            "chmod 440 /etc/sudoers.",
        ));
    }
}

// ---------- ssh ----------

pub(crate) fn sshd_conf(paths: &[&str]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for p in paths {
        let path = Path::new(p);
        let files: Vec<_> = if path.is_dir() {
            std::fs::read_dir(path)
                .map(|d| d.flatten().map(|e| e.path()).collect())
                .unwrap_or_default()
        } else {
            vec![path.to_path_buf()]
        };
        for f in files {
            if let Some(t) = read(&f.to_string_lossy()) {
                for line in t.lines() {
                    let l = line.trim();
                    if l.is_empty() || l.starts_with('#') {
                        continue;
                    }
                    let mut it = l.split_whitespace();
                    if let (Some(k), Some(v)) = (it.next(), it.next()) {
                        out.push((k.to_lowercase(), v.to_string()));
                    }
                }
            }
        }
    }
    out
}

pub(crate) fn conf_get<'a>(conf: &'a [(String, String)], key: &str) -> Option<&'a str> {
    conf.iter()
        .rev()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

pub(crate) fn ssh(out: &mut Vec<Finding>) {
    let conf = sshd_conf(&["/etc/ssh/sshd_config.d", "/etc/ssh/sshd_config"]);
    if conf.is_empty() {
        return;
    }
    let checks: &[(&str, &[&str], &str, Severity, &str)] = &[
        (
            "permitrootlogin",
            &["no", "prohibit-password"],
            "SYS-SSH-01",
            Severity::High,
            "remote root login allowed",
        ),
        (
            "passwordauthentication",
            &["no"],
            "SYS-SSH-02",
            Severity::Medium,
            "password auth on (brute-force surface)",
        ),
        (
            "permitemptypasswords",
            &["no"],
            "SYS-SSH-03",
            Severity::High,
            "empty passwords permitted",
        ),
        (
            "x11forwarding",
            &["no"],
            "SYS-SSH-04",
            Severity::Low,
            "X11 forwarding on",
        ),
        (
            "permituserenvironment",
            &["no"],
            "SYS-SSH-05",
            Severity::Medium,
            "user env injection allowed",
        ),
        (
            "ignorerhosts",
            &["yes"],
            "SYS-SSH-06",
            Severity::Low,
            "rhosts honored",
        ),
        (
            "allowtcpforwarding",
            &["no"],
            "SYS-SSH-07",
            Severity::Low,
            "TCP forwarding on (pivot surface)",
        ),
        (
            "permittunnel",
            &["no"],
            "SYS-SSH-08",
            Severity::Low,
            "SSH tunneling allowed",
        ),
    ];
    for (key, ok, id, sev, what) in checks {
        match conf_get(&conf, key) {
            Some(v) if !ok.contains(&v.to_lowercase().as_str()) => out.push(mk(
                id,
                *sev,
                "/etc/ssh/sshd_config",
                format!("sshd {key}={v} - {what}"),
                &format!("Set {key} to one of {}.", ok.join("/")),
            )),
            None if *key != "permitrootlogin" && *key != "passwordauthentication" => out.push(mk(
                id,
                *sev,
                "/etc/ssh/sshd_config",
                format!("sshd {key} unset - {what} (default may allow)"),
                &format!("Set {key} explicitly to {}.", ok[0]),
            )),
            _ => {}
        }
    }
    if conf_get(&conf, "maxauthtries").is_none_or(|v| v.parse::<u32>().unwrap_or(10) > 4) {
        out.push(mk(
            "SYS-SSH-09",
            Severity::Low,
            "/etc/ssh/sshd_config",
            format!(
                "MaxAuthTries={} - too many auth attempts per connection",
                conf_get(&conf, "maxauthtries").unwrap_or("6")
            ),
            "Set MaxAuthTries 3 or 4.",
        ));
    }
    if conf_get(&conf, "logingracetime").is_none_or(|v| {
        let n: u32 = v.trim_end_matches('s').parse().unwrap_or(120);
        n > 60
    }) {
        out.push(mk(
            "SYS-SSH-10",
            Severity::Low,
            "/etc/ssh/sshd_config",
            "LoginGraceTime long - holds auth slots open",
            "Set LoginGraceTime 30.",
        ));
    }
    if conf.is_empty()
        || (conf_get(&conf, "allowusers").is_none() && conf_get(&conf, "allowgroups").is_none())
    {
        out.push(mk(
            "SYS-SSH-11",
            Severity::Low,
            "/etc/ssh/sshd_config",
            "no AllowUsers/AllowGroups - every account with a password can try ssh",
            "Restrict with AllowGroups ssh-users or AllowUsers.",
        ));
    }
    let weak = conf_get(&conf, "ciphers")
        .map(|c| {
            c.split(',')
                .filter(|x| {
                    let x = x.trim();
                    x.contains("cbc") || x.contains("arcfour") || x.contains("3des")
                })
                .count()
        })
        .unwrap_or(0);
    if weak > 0 {
        out.push(mk(
            "SYS-SSH-12",
            Severity::Medium,
            "/etc/ssh/sshd_config",
            format!("{weak} weak ciphers configured (CBC/3DES/arcfour)"),
            "Keep chacha20-poly1305/aes-gcm; drop CBC-era ciphers.",
        ));
    }
    if conf_get(&conf, "banner").is_none() {
        out.push(mk(
            "SYS-SSH-13",
            Severity::Info,
            "/etc/ssh/sshd_config",
            "no login Banner (optional legal/monitoring notice)",
            "Set Banner /etc/issue.net if policy requires it.",
        ));
    }
}

// ---------- network ----------
