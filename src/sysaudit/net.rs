use super::*;
pub(crate) fn network(out: &mut Vec<Finding>) {
    // dangerous-listener check via ss
    if let Some(ss) = cmd("ss", &["-tulpnH"]) {
        for line in ss.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            let _proto = cols.first().copied().unwrap_or("");
            let local = cols.get(4).copied().unwrap_or("");
            let port = local.rsplit(':').next().unwrap_or("");
            let proc = line
                .rsplit("users:((")
                .nth(1)
                .map(|s| s.trim_end_matches("))").to_string());
            let danger = match port {
                "23" => Some(("telnet", Severity::Critical)),
                "21" => Some(("ftp", Severity::High)),
                "111" => Some(("rpcbind", Severity::Medium)),
                "445" | "139" => Some(("smb", Severity::Medium)),
                "3389" => Some(("rdp", Severity::Medium)),
                "5900" | "5901" => Some(("vnc", Severity::High)),
                "6379" => Some(("redis", Severity::High)),
                "9200" | "9300" => Some(("elasticsearch", Severity::High)),
                "27017" => Some(("mongodb", Severity::High)),
                "3306" => Some(("mysql", Severity::Medium)),
                "5432" => Some(("postgres", Severity::Medium)),
                "2375" => Some(("docker API unencrypted - remote root", Severity::Critical)),
                "11211" => Some(("memcached", Severity::Medium)),
                _ => None,
            };
            if let Some((name, sev)) = danger {
                if local.starts_with("127.") || local.starts_with("[::1") {
                    continue; // bound to loopback only - fine
                }
                let proc = proc.unwrap_or_default();
                let _ = &proc;
                out.push(mk(
                    "SYS-NET-10",
                    sev,
                    "ss -tulpn",
                    format!("service {name} listens on a non-loopback address ({local})"),
                    "Bind to localhost or firewall it; these services should not be network-exposed.",
                ));
            }
        }
    }
    // promiscuous interface = sniffing or bridge; worth noting
    if let Some(links) = cmd("ip", &["-o", "link"]) {
        for line in links.lines() {
            if line.contains("PROMISC") && !line.contains("NO-CARRIER") {
                let name = line.split(':').nth(1).map(|s| s.trim()).unwrap_or("?");
                out.push(mk(
                    "SYS-NET-20",
                    Severity::Medium,
                    "ip link",
                    format!("interface {name} is in promiscuous mode (sniffing or bridge)"),
                    "Verify a legitimate capture/bridge owns this.",
                ));
            }
        }
    }
    // firewall posture: count rules
    let nft = cmd("nft", &["list", "ruleset"])
        .map(|s| s.lines().filter(|l| l.contains("chain ")).count());
    let ipt = cmd("iptables", &["-S"]).map(|s| s.lines().filter(|l| l.starts_with("-A")).count());
    match (nft, ipt) {
        (Some(n), _) if n > 0 => {}
        (_, Some(n)) if n > 0 => {}
        _ => out.push(mk(
            "SYS-NET-30",
            Severity::Medium,
            "firewall",
            "no nft/iptables ruleset found - every listening service is wide open",
            "Configure a default-deny inbound policy (nftables, ufw, or firewalld).",
        )),
    }
}

// ---------- filesystem ----------

pub(crate) fn filesystem(out: &mut Vec<Finding>) {
    let mounts = read("/proc/mounts").unwrap_or_default();
    for (mp, want_opts, id) in [
        ("/tmp", &["nosuid", "nodev", "noexec"][..], "SYS-FS-01"),
        ("/var/tmp", &["nosuid", "nodev", "noexec"][..], "SYS-FS-02"),
        ("/dev/shm", &["nosuid", "nodev", "noexec"][..], "SYS-FS-03"),
        ("/home", &["nodev"][..], "SYS-FS-04"),
    ] {
        if let Some(line) = mounts
            .lines()
            .find(|l| l.split_whitespace().nth(1) == Some(mp))
        {
            let opts = line.split_whitespace().nth(3).unwrap_or("");
            let missing: Vec<&str> = want_opts
                .iter()
                .filter(|o| !opts.contains(**o))
                .cloned()
                .collect();
            if !missing.is_empty() {
                out.push(mk(
                    id,
                    Severity::Medium,
                    "/etc/fstab",
                    format!("{mp} mounted without {}", missing.join(",")),
                    "Add the flags in fstab or a .mount unit and remount.",
                ));
            }
        }
    }
    // world-writable dirs without sticky bit
    for d in ["/tmp", "/var/tmp", "/dev/shm"] {
        if let Some(m) = mode_of(d)
            && m & 0o1000 == 0
        {
            out.push(mk(
                "SYS-FS-10",
                Severity::Medium,
                d,
                format!("{d} lacks the sticky bit - users can delete each other's files"),
                "chmod +t.",
            ));
        }
    }
}

// ---------- services ----------

pub(crate) fn services(out: &mut Vec<Finding>) {
    let Some(units) = cmd(
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
    let risky: &[(&str, Severity, &str)] = &[
        ("telnet", Severity::High, "cleartext remote shell"),
        ("rsh", Severity::High, "cleartext remote shell"),
        ("rlogin", Severity::High, "cleartext remote shell"),
        ("vsftpd", Severity::Medium, "FTP server enabled"),
        ("proftpd", Severity::Medium, "FTP server enabled"),
        ("tftp", Severity::High, "unauthenticated file transfer"),
        (
            "rpcbind",
            Severity::Medium,
            "RPC portmapper (amplification + weak auth)",
        ),
        ("nfs-server", Severity::Low, "NFS server - check exports"),
        (
            "avahi-daemon",
            Severity::Low,
            "mDNS responder - spoofable announcements",
        ),
        (
            "cups",
            Severity::Low,
            "print service enabled - historic RCE surface",
        ),
        ("saned", Severity::Low, "scanner daemon"),
        (
            "smbd",
            Severity::Medium,
            "SMB enabled - check shares and signing",
        ),
        ("snmpd", Severity::Medium, "SNMP - check community strings"),
        (
            "docker",
            Severity::Info,
            "docker daemon enabled - its socket is root-equivalent",
        ),
        (
            "sshd",
            Severity::Info,
            "sshd enabled - hardening audited separately",
        ),
    ];
    for line in units.lines() {
        let name = line.split_whitespace().next().unwrap_or("");
        let base = name
            .trim_end_matches(".service")
            .trim_end_matches(".socket");
        for (r, sev, what) in risky {
            if base == *r {
                out.push(mk(
                    &format!(
                        "SYS-SVC-{}",
                        r.chars().take(4).collect::<String>().to_uppercase()
                    ),
                    *sev,
                    name,
                    format!("{name} enabled: {what}"),
                    "Disable unless needed (systemctl disable --now).",
                ));
            }
        }
    }
    // systemd-analyze security on the worst offenders, cheap top-5
    if let Some(sec) = cmd("systemd-analyze", &["security"]) {
        for line in sec.lines().skip(1).take(5) {
            let mut c = line.split_whitespace();
            if let (Some(unit), Some(score)) = (c.next(), c.next())
                && let Ok(s) = score.parse::<f32>()
                && s >= 8.0
            {
                out.push(mk(
                    "SYS-SVC-SEC",
                    Severity::Low,
                    unit,
                    format!("{unit} runs UNSAFE (exposure {s}/10) - no sandboxing"),
                    "Harden with ProtectSystem/PrivateTmp/NoNewPrivileges in the unit.",
                ));
            }
        }
    }
}

// ---------- logging ----------
