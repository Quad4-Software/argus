// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Host posture that the original Lynis set does not cover.
//! Kernel version checks use the upstream stable versions from the kernel CNA.
//! A distribution build can carry the same fix under a different package
//! revision, so a hit is a lead until the package changelog says otherwise.

use super::*;
use std::path::Path;

const KEV: &str = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";
const CPU: &str = "https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/index.html";
const LOCK: &str = "https://www.kernel.org/doc/html/latest/admin-guide/LSM/lockdown.html";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ker {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

struct KevCve {
    id: &'static str,
    what: &'static str,
    introduced: Ker,
    fixes: &'static [(u32, u32, u32)],
    mainline: Ker,
    module_hint: &'static [&'static str],
}

const KEVS: &[KevCve] = &[
    KevCve {
        id: "CVE-2025-39682",
        what: "kTLS zero-length receive record",
        introduced: Ker {
            major: 6,
            minor: 0,
            patch: 0,
        },
        fixes: &[(6, 1, 149), (6, 6, 103), (6, 12, 44), (6, 16, 4)],
        mainline: Ker {
            major: 6,
            minor: 17,
            patch: 0,
        },
        module_hint: &["tls"],
    },
    KevCve {
        id: "CVE-2025-39964",
        what: "AF_ALG concurrent sendmsg",
        introduced: Ker {
            major: 2,
            minor: 6,
            patch: 38,
        },
        fixes: &[
            (5, 10, 245),
            (5, 15, 194),
            (6, 1, 154),
            (6, 6, 108),
            (6, 12, 49),
            (6, 16, 9),
        ],
        mainline: Ker {
            major: 6,
            minor: 17,
            patch: 0,
        },
        module_hint: &["af_alg", "algif_skcipher", "algif_aead", "algif_hash"],
    },
    KevCve {
        id: "CVE-2026-53266",
        what: "ebtables SNAT ARP rewrite",
        introduced: Ker {
            major: 5,
            minor: 10,
            patch: 0,
        },
        fixes: &[
            (5, 10, 259),
            (5, 15, 210),
            (6, 1, 176),
            (6, 6, 143),
            (6, 12, 94),
            (6, 18, 36),
            (7, 0, 13),
        ],
        mainline: Ker {
            major: 7,
            minor: 1,
            patch: 0,
        },
        module_hint: &["ebt_snat", "ebtable_nat", "ebtable_filter"],
    },
];

pub fn parse_ker(raw: &str) -> Option<Ker> {
    let head = raw.split(['-', '+']).next()?.trim();
    let mut parts = head.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().unwrap_or(0);
    Some(Ker {
        major,
        minor,
        patch,
    })
}

pub fn kev_behind(ver: Ker, id: &str) -> bool {
    let Some(cve) = KEVS.iter().find(|c| c.id == id) else {
        return false;
    };
    if id == "CVE-2026-53266" && ebt_short_branch(ver) {
        return true;
    }
    if ver < cve.introduced || ver >= cve.mainline {
        return false;
    }
    if let Some((_, _, fixed)) = cve
        .fixes
        .iter()
        .find(|(maj, min, _)| *maj == ver.major && *min == ver.minor)
    {
        return ver.patch < *fixed;
    }
    true
}

fn ebt_short_branch(ver: Ker) -> bool {
    (ver.major == 5 && ver.minor == 4 && ver.patch >= 73)
        || (ver.major == 5 && ver.minor == 8 && ver.patch >= 17)
        || (ver.major == 5 && ver.minor == 9 && ver.patch >= 2)
}

pub fn newer_kernel<'a>(
    running: &str,
    installed: impl IntoIterator<Item = &'a str>,
) -> Option<&'a str> {
    let run = parse_ker(running)?;
    installed
        .into_iter()
        .filter(|name| parse_ker(name).is_some_and(|v| v > run))
        .max_by_key(|name| parse_ker(name).unwrap())
}

pub fn nft_input_accept(text: &str) -> bool {
    text.lines().any(|line| {
        let low = line.to_ascii_lowercase();
        low.contains("hook input") && low.contains("policy accept")
    })
}

pub fn ipt_input_accept(text: &str) -> bool {
    text.lines()
        .any(|line| line.trim().eq_ignore_ascii_case("-P INPUT ACCEPT"))
}

pub fn resolved_weak(text: &str) -> Vec<&'static str> {
    let mut dnssec = String::new();
    let mut dot = String::new();
    let mut llmnr = String::new();
    let mut mdns = String::new();
    let mut dns_set = false;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches('"').to_ascii_lowercase();
        match k.trim().to_ascii_lowercase().as_str() {
            "dnssec" => dnssec = v,
            "dnsovertls" => dot = v,
            "llmnr" => llmnr = v,
            "multicastdns" => mdns = v,
            "dns" if !v.is_empty() => dns_set = true,
            _ => {}
        }
    }
    let mut out = Vec::new();
    if dnssec == "no" {
        out.push("dnssec");
    }
    if dns_set && (dot.is_empty() || dot == "no") {
        out.push("dot");
    }
    if llmnr == "yes" || mdns == "yes" {
        out.push("multicast");
    }
    out
}

pub fn chrony_wide(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.split('#').next().unwrap_or("").trim();
        line == "allow"
            || line.starts_with("allow 0.0.0.0")
            || line.starts_with("allow ::")
            || line.starts_with("allow 0/0")
    })
}

pub fn grub_unlocked(cfg: &str) -> bool {
    let low = cfg.to_ascii_lowercase();
    !low.contains("password_pbkdf2") && !low.contains("set superusers")
}

pub fn grub_cmdline_risks(text: &str) -> Vec<&'static str> {
    let mut joined = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("GRUB_CMDLINE_LINUX") {
            joined.push(' ');
            joined.push_str(line);
        }
    }
    let low = joined.to_ascii_lowercase();
    let mut out = Vec::new();
    for token in [
        "mitigations=off",
        "nosmep",
        "nosmap",
        "nopti",
        "nokaslr",
        "init=/bin/sh",
        "init=/bin/bash",
    ] {
        if low.contains(token) {
            out.push(token);
        }
    }
    out
}

pub fn unit_risks(text: &str) -> Vec<&'static str> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();
        let low = val.to_ascii_lowercase();
        if key == "killmode" && low == "none" {
            out.push("killmode");
        }
        if key == "umask" && matches!(low.as_str(), "0000" | "000" | "0") {
            out.push("umask");
        }
        if key == "execstart"
            && (low.contains("/tmp/") || low.contains("/dev/shm/") || low.contains("/var/tmp/"))
        {
            out.push("execstart");
        }
        if key == "ambientcapabilities"
            && (low.contains("cap_sys_admin")
                || low.contains("cap_sys_module")
                || low.contains("cap_sys_rawio")
                || low.contains("cap_bpf"))
        {
            out.push("ambient");
        }
    }
    out.sort();
    out.dedup();
    out
}

pub fn secure_boot_on(bytes: &[u8]) -> Option<bool> {
    bytes.get(4).map(|b| *b == 1)
}

pub fn cpu_vulnerable(text: &str) -> bool {
    text.trim().starts_with("Vulnerable")
}

pub fn input_comm_ok(comm: &str) -> bool {
    const OK: &[&str] = &[
        "systemd-logind",
        "systemd-udevd",
        "Xorg",
        "X",
        "Xwayland",
        "gnome-shell",
        "mutter",
        "kwin_wayland",
        "kwin_x11",
        "plasmashell",
        "sway",
        "hyprland",
        "labwc",
        "weston",
        "cage",
        "cosmic-comp",
        "niri",
        "wayfire",
        "river",
        "seatd",
        "sddm",
        "gdm",
        "gdm-wayland-ses",
        "lightdm",
        "greetd",
        "inputplumber",
    ];
    OK.contains(&comm)
}

pub fn remote_sessions(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(start) = line.rfind(" (") else {
            continue;
        };
        let host = line[start + 2..].trim().trim_end_matches(')');
        if host.is_empty() || host == ":0" {
            continue;
        }
        let user = line.split_whitespace().next().unwrap_or("");
        if !user.is_empty() {
            out.push((user.to_string(), host.to_string()));
        }
    }
    out
}

pub fn unattended_off(text: &str) -> bool {
    text.lines().any(|line| {
        let low = line.to_ascii_lowercase();
        low.contains("unattended-upgrade") && (low.contains("\"0\"") || low.contains("'0'"))
    })
}

pub(crate) fn posture(out: &mut Vec<Finding>) {
    kernel_kevs(out);
    packages(out);
    firewall(out);
    dns(out);
    time_sync(out);
    firmware(out);
    cpu(out);
    grub(out);
    units(out);
    input_devs(out);
    sessions(out);
    consoles(out);
}

fn kernel_kevs(out: &mut Vec<Finding>) {
    let Some(raw) = read_trim("/proc/sys/kernel/osrelease") else {
        return;
    };
    let Some(ver) = parse_ker(&raw) else {
        return;
    };
    let modules = read("/proc/modules").unwrap_or_default();
    let distro = raw.contains('-');
    for cve in KEVS {
        let short = cve.id == "CVE-2026-53266" && ebt_short_branch(ver);
        if !short && !kev_behind(ver, cve.id) {
            continue;
        }
        let loaded = cve
            .module_hint
            .iter()
            .any(|name| module_loaded(&modules, name));
        let sev = if loaded {
            Severity::High
        } else {
            Severity::Medium
        };
        let mut msg = format!(
            "{} {} is older than the upstream fix for {} ({})",
            raw,
            ver_label(ver),
            cve.id,
            cve.what
        );
        if distro {
            msg.push_str(". A distribution kernel may already carry the backport");
        }
        if loaded {
            msg.push_str(". A related module is loaded");
        }
        out.push(note(
            "SYS-KERN-20",
            sev,
            "/proc/sys/kernel/osrelease",
            msg,
            "Boot a kernel at or past the upstream stable fix, or confirm the backport in the package changelog.",
            KEV,
        ));
    }
}

fn module_loaded(text: &str, name: &str) -> bool {
    text.lines()
        .any(|line| line.split_whitespace().next() == Some(name))
}

fn ver_label(ver: Ker) -> String {
    format!("{}.{}.{}", ver.major, ver.minor, ver.patch)
}

fn packages(out: &mut Vec<Finding>) {
    if Path::new("/var/run/reboot-required").exists() || Path::new("/run/reboot-required").exists()
    {
        out.push(note(
            "SYS-PKG-01",
            Severity::Medium,
            "/run/reboot-required",
            "a package update is installed and the system still needs a reboot",
            "Reboot onto the installed kernel.",
            "https://wiki.debian.org/UnattendedUpgrades",
        ));
    }
    let running = read_trim("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mut installed = Vec::new();
    for dir in ["/lib/modules", "/usr/lib/modules"] {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for ent in rd.flatten() {
                if let Some(name) = ent.file_name().to_str() {
                    installed.push(name.to_string());
                }
            }
        }
    }
    let refs: Vec<&str> = installed.iter().map(String::as_str).collect();
    if let Some(newer) = newer_kernel(&running, refs) {
        out.push(note(
            "SYS-PKG-02",
            Severity::Medium,
            "/lib/modules",
            format!("installed kernel {newer} is newer than the running {running}"),
            "Reboot onto the installed kernel.",
            "https://www.kernel.org/",
        ));
    }
    for p in [
        "/etc/apt/apt.conf.d/20auto-upgrades",
        "/etc/apt/apt.conf.d/50unattended-upgrades",
    ] {
        if let Some(text) = read(p)
            && unattended_off(&text)
        {
            out.push(note(
                "SYS-PKG-03",
                Severity::Low,
                p,
                "unattended upgrades are turned off",
                "Set APT::Periodic::Unattended-Upgrade \"1\" if this host should patch itself.",
                "https://wiki.debian.org/UnattendedUpgrades",
            ));
            break;
        }
    }
}

fn firewall(out: &mut Vec<Finding>) {
    let nft = cmd("nft", &["list", "ruleset"]).unwrap_or_default();
    let v4 = cmd("iptables", &["-S"]).unwrap_or_default();
    let v6 = cmd("ip6tables", &["-S"]).unwrap_or_default();
    if nft_input_accept(&nft) {
        out.push(note(
            "SYS-FW-01",
            Severity::Medium,
            "nft",
            "an nftables input hook uses policy accept",
            "Set the input policy to drop and allow the services you mean to expose.",
            "https://wiki.nftables.org/",
        ));
    }
    if ipt_input_accept(&v4) {
        out.push(note(
            "SYS-FW-02",
            Severity::Medium,
            "iptables",
            "IPv4 INPUT policy is ACCEPT",
            "Set the INPUT policy to DROP after the allow rules.",
            "https://www.netfilter.org/",
        ));
    }
    if ipt_input_accept(&v6) && !ipt_input_accept(&v4) && !v4.is_empty() {
        out.push(note(
            "SYS-FW-03",
            Severity::Medium,
            "ip6tables",
            "IPv6 INPUT policy is ACCEPT while IPv4 is not",
            "Give IPv6 the same default-deny policy as IPv4.",
            "https://www.netfilter.org/",
        ));
    }
}

fn dns(out: &mut Vec<Finding>) {
    let mut text = read("/etc/systemd/resolved.conf").unwrap_or_default();
    if let Ok(rd) = std::fs::read_dir("/etc/systemd/resolved.conf.d") {
        for ent in rd.flatten() {
            if let Some(extra) = read(&ent.path().to_string_lossy()) {
                text.push('\n');
                text.push_str(&extra);
            }
        }
    }
    for flag in resolved_weak(&text) {
        let (id, msg, fix) = match flag {
            "dnssec" => (
                "SYS-DNS-01",
                "systemd-resolved DNSSEC is off",
                "Set DNSSEC=allow-downgrade or yes.",
            ),
            "dot" => (
                "SYS-DNS-02",
                "systemd-resolved has upstream DNS servers and DNSOverTLS is off",
                "Set DNSOverTLS=yes or opportunistic for those servers.",
            ),
            _ => (
                "SYS-DNS-03",
                "systemd-resolved answers multicast DNS or LLMNR",
                "Set LLMNR=no and MulticastDNS=no on networks you do not trust.",
            ),
        };
        out.push(note(
            id,
            Severity::Low,
            "/etc/systemd/resolved.conf",
            msg,
            fix,
            "https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html",
        ));
    }
}

fn time_sync(out: &mut Vec<Finding>) {
    for p in ["/etc/chrony.conf", "/etc/chrony/chrony.conf"] {
        if let Some(text) = read(p)
            && chrony_wide(&text)
        {
            out.push(note(
                "SYS-TIME-01",
                Severity::Medium,
                p,
                "chrony allows NTP clients from an unrestricted network",
                "Remove the open allow line or limit it to an admin network.",
                "https://chrony-project.org/documentation.html",
            ));
        }
    }
    let synced = read_trim("/run/systemd/timesync/synchronized").unwrap_or_default();
    let has_client = Path::new("/etc/chrony.conf").exists()
        || Path::new("/etc/chrony/chrony.conf").exists()
        || Path::new("/etc/ntp.conf").exists()
        || Path::new("/etc/systemd/timesyncd.conf").exists()
        || synced == "1";
    if Path::new("/proc/sys/kernel/osrelease").exists() && !has_client && synced != "1" {
        out.push(note(
            "SYS-TIME-02",
            Severity::Low,
            "/etc/systemd/timesyncd.conf",
            "no chrony, ntp, or timesyncd client is configured, and the clock is not marked synchronized",
            "Run systemd-timesyncd or chronyd against the NTP servers you trust.",
            "https://www.freedesktop.org/software/systemd/man/latest/systemd-timesyncd.service.html",
        ));
    }
}

fn firmware(out: &mut Vec<Finding>) {
    if let Some(text) = read("/sys/kernel/security/lockdown")
        && text.contains("[none]")
    {
        out.push(note(
            "SYS-FW-10",
            Severity::Low,
            "/sys/kernel/security/lockdown",
            "kernel lockdown is none",
            "Enable lockdown integrity or confidentiality when Secure Boot is on.",
            LOCK,
        ));
    }
    let Some(rd) = std::fs::read_dir("/sys/firmware/efi/efivars").ok() else {
        return;
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("SecureBoot-") && !name.starts_with("SetupMode-") {
            continue;
        }
        let Ok(bytes) = std::fs::read(ent.path()) else {
            continue;
        };
        if name.starts_with("SecureBoot-") && secure_boot_on(&bytes) == Some(false) {
            out.push(note(
                "SYS-FW-11",
                Severity::Medium,
                "/sys/firmware/efi/efivars",
                "UEFI Secure Boot is off",
                "Turn Secure Boot on and keep the firmware dbx current. This does not scan firmware images.",
                "https://www.kernel.org/doc/html/latest/admin-guide/LSM/lockdown.html",
            ));
        }
        if name.starts_with("SetupMode-") && secure_boot_on(&bytes) == Some(true) {
            out.push(note(
                "SYS-FW-12",
                Severity::High,
                "/sys/firmware/efi/efivars",
                "UEFI is in setup mode, so firmware keys can be replaced",
                "Leave setup mode after the platform keys are enrolled.",
                "https://www.kernel.org/doc/html/latest/admin-guide/LSM/lockdown.html",
            ));
        }
    }
}

fn cpu(out: &mut Vec<Finding>) {
    let dir = "/sys/devices/system/cpu/vulnerabilities";
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().to_string();
        let Ok(text) = std::fs::read_to_string(ent.path()) else {
            continue;
        };
        if cpu_vulnerable(&text) {
            out.push(note(
                "SYS-CPU-01",
                Severity::High,
                dir,
                format!("{name} reports {}", text.trim()),
                "Apply the kernel and microcode update the CPU vendor published for this issue.",
                CPU,
            ));
        }
    }
}

fn grub(out: &mut Vec<Finding>) {
    for p in ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"] {
        if let Some(text) = read(p)
            && grub_unlocked(&text)
        {
            out.push(note(
                "SYS-GRUB-01",
                Severity::Low,
                p,
                "GRUB has no superuser password, so the console can edit the kernel command line",
                "Set a GRUB superuser and a pbkdf2 password.",
                "https://www.gnu.org/software/grub/manual/grub/html_node/Security.html",
            ));
        }
    }
    if let Some(text) = read("/etc/default/grub") {
        let risks = grub_cmdline_risks(&text);
        if !risks.is_empty() {
            out.push(note(
                "SYS-GRUB-02",
                Severity::High,
                "/etc/default/grub",
                format!("kernel command line sets {}", risks.join(", ")),
                "Drop mitigations=off, nosmep, nosmap, nopti, nokaslr, and init=/bin/sh unless this boot is a recovery.",
                "https://www.gnu.org/software/grub/manual/grub/html_node/Security.html",
            ));
        }
    }
}

fn units(out: &mut Vec<Finding>) {
    let root = Path::new("/etc/systemd/system");
    let mut files = Vec::new();
    collect_units(root, 0, &mut files);
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let risks = unit_risks(&text);
        if risks.is_empty() {
            continue;
        }
        out.push(note(
            "SYS-UNIT-01",
            Severity::Medium,
            &path.to_string_lossy(),
            format!("systemd unit has {}", risks.join(", ")),
            "Avoid KillMode=none, UMask=0000, AmbientCapabilities such as CAP_SYS_ADMIN, and ExecStart under /tmp.",
            "https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html",
        ));
    }
}

fn collect_units(dir: &Path, depth: u8, out: &mut Vec<std::path::PathBuf>) {
    if depth > 3 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for ent in rd.flatten() {
        let path = ent.path();
        if path.is_dir() {
            collect_units(&path, depth + 1, out);
            continue;
        }
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if name.ends_with(".service") && !points_at_null(&path) {
            out.push(path);
        }
    }
}

fn points_at_null(path: &Path) -> bool {
    std::fs::read_link(path)
        .ok()
        .is_some_and(|t| t == Path::new("/dev/null"))
}

fn input_devs(out: &mut Vec<Finding>) {
    if let Ok(rd) = std::fs::read_dir("/dev/input") {
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            if !name.starts_with("event") {
                continue;
            }
            if let Some(mode) = super::checks::mode_of(&ent.path().to_string_lossy())
                && mode & 0o004 != 0
            {
                out.push(note(
                    "SYS-IN-01",
                    Severity::High,
                    &ent.path().to_string_lossy(),
                    format!("/dev/input/{name} is world-readable"),
                    "Keep event devices owned by root and the input group, mode 660 or tighter.",
                    "https://www.kernel.org/doc/html/latest/input/input.html",
                ));
            }
        }
    }
    if let Some(group) = read("/etc/group") {
        for line in group.lines() {
            let mut cols = line.split(':');
            if cols.next() != Some("input") {
                continue;
            }
            let members = cols.nth(2).unwrap_or("");
            if !members.is_empty() {
                out.push(note(
                    "SYS-IN-02",
                    Severity::Low,
                    "/etc/group",
                    format!("input group members can read key and pointer events: {members}"),
                    "Keep the input group empty unless a seat manager needs those accounts.",
                    "https://www.kernel.org/doc/html/latest/input/input.html",
                ));
            }
        }
    }
    let mut hits = 0u32;
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return;
    };
    for ent in rd.flatten() {
        if hits >= 12 {
            break;
        }
        let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let comm = std::fs::read_to_string(ent.path().join("comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        if comm.is_empty() || input_comm_ok(&comm) {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(ent.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let text = target.to_string_lossy();
            if text.contains("/dev/input/event") {
                out.push(note(
                    "SYS-IN-03",
                    Severity::Medium,
                    &text,
                    format!("pid {pid} ({comm}) holds an input event device"),
                    "Compositors and login managers are expected. Anything else can be a keylogger lead.",
                    "https://www.kernel.org/doc/html/latest/input/input.html",
                ));
                hits += 1;
                break;
            }
        }
    }
}

fn sessions(out: &mut Vec<Finding>) {
    let Some(text) = cmd("who", &[]) else {
        return;
    };
    let rows = remote_sessions(&text);
    if rows.is_empty() {
        return;
    }
    let shown: Vec<String> = rows
        .iter()
        .take(8)
        .map(|(u, h)| format!("{u} from {h}"))
        .collect();
    out.push(note(
        "SYS-SSH-20",
        Severity::Info,
        "who",
        format!("remote logins: {}", shown.join(", ")),
        "Confirm each session. A console or SSH login you do not recognize is a lead.",
        "https://man.archlinux.org/man/who.1.en",
    ));
}

fn consoles(out: &mut Vec<Finding>) {
    let Some(text) = cmd(
        "systemctl",
        &[
            "list-unit-files",
            "--state=enabled",
            "--no-legend",
            "--no-pager",
        ],
    ) else {
        return;
    };
    let mut names = Vec::new();
    for line in text.lines() {
        let unit = line.split_whitespace().next().unwrap_or("");
        if unit.starts_with("serial-getty@")
            || unit.starts_with("container-getty@")
            || unit.contains("hvc")
            || unit.contains("ttyS")
        {
            names.push(unit.to_string());
        }
    }
    if !names.is_empty() {
        names.truncate(6);
        out.push(note(
            "SYS-CON-01",
            Severity::Low,
            "systemd",
            format!("serial or hypervisor console login is enabled: {}", names.join(", ")),
            "Disable the getty on consoles the hypervisor or a serial cable can reach, if you do not use them.",
            "https://www.freedesktop.org/software/systemd/man/latest/systemd-getty-generator.html",
        ));
    }
}

fn note(
    id: &str,
    sev: Severity,
    path: &str,
    msg: impl Into<String>,
    fix: &str,
    reference: &str,
) -> Finding {
    let mut finding = mk(id, sev, path, msg, fix);
    finding.reference = Some(reference.to_string());
    finding
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kev_versions_follow_the_kernel_cna() {
        let old = parse_ker("6.12.40-1-cachyos").unwrap();
        assert!(kev_behind(old, "CVE-2025-39682"));
        assert!(kev_behind(old, "CVE-2025-39964"));
        assert!(kev_behind(old, "CVE-2026-53266"));
        let mid = parse_ker("6.12.90").unwrap();
        assert!(!kev_behind(mid, "CVE-2025-39682"));
        assert!(!kev_behind(mid, "CVE-2025-39964"));
        assert!(kev_behind(mid, "CVE-2026-53266"));
        let cur = parse_ker("7.2.8-1-cachyos").unwrap();
        assert!(!kev_behind(cur, "CVE-2025-39682"));
        assert!(!kev_behind(cur, "CVE-2025-39964"));
        assert!(!kev_behind(cur, "CVE-2026-53266"));
        assert!(kev_behind(parse_ker("5.4.80").unwrap(), "CVE-2026-53266"));
        assert_eq!(
            newer_kernel("6.18.52-1", ["7.2.8-1-cachyos", "6.18.52-1"]),
            Some("7.2.8-1-cachyos")
        );
    }

    #[test]
    fn posture_parsers_flag_open_policy_and_leads() {
        assert!(nft_input_accept(
            "chain input { type filter hook input priority 0; policy accept; }"
        ));
        assert!(ipt_input_accept("-P INPUT ACCEPT\n-A INPUT -j DROP\n"));
        assert!(resolved_weak("DNSSEC=no\nDNS=1.1.1.1\nLLMNR=yes\n").contains(&"dnssec"));
        assert!(chrony_wide("# allow\nallow 0.0.0.0/0\n"));
        assert!(grub_unlocked("set timeout=5\n"));
        assert!(!grub_unlocked(
            "set superusers=\"root\"\npassword_pbkdf2 root grub.pbkdf2.sha512.1\n"
        ));
        assert!(grub_cmdline_risks("GRUB_CMDLINE_LINUX=\"mitigations=off nokaslr\"").len() == 2);
        let risks = unit_risks(
            "KillMode=none\nUMask=0000\nExecStart=/tmp/agent\nAmbientCapabilities=CAP_SYS_ADMIN\n",
        );
        assert_eq!(risks.len(), 4);
        assert_eq!(secure_boot_on(&[0, 0, 0, 0, 0]), Some(false));
        assert!(cpu_vulnerable("Vulnerable: Clear CPU buffers\n"));
        assert!(!cpu_vulnerable("Mitigation: Safe RET\n"));
        assert!(!input_comm_ok("evtest"));
        assert!(input_comm_ok("sway"));
        let sessions = remote_sessions("root     pts/1        2026-09-30 09:00 (203.0.113.10)\n");
        assert_eq!(sessions[0].1, "203.0.113.10");
        assert!(unattended_off("APT::Periodic::Unattended-Upgrade \"0\";\n"));
    }

    #[test]
    fn posture_on_this_host_returns_ids() {
        let mut out = Vec::new();
        posture(&mut out);
        for finding in &out {
            assert!(finding.rule_id.starts_with("SYS-"), "{}", finding.rule_id);
        }
    }
}
