// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

use crate::cli::{Cli, Cmd, Format};
use crate::host::{self, Cmd as HostCmd};
use crate::osint::{self, Hit, Status};
use std::process::ExitCode;

pub(crate) fn run(cli: &Cli, offline: bool, format: Format) -> Result<ExitCode, String> {
    let Cmd::Host(cmd) = &cli.cmd else {
        return Err("not a host command".into());
    };
    let (report, child) = match cmd {
        HostCmd::Chat { domain } => (osint::scan_chat(domain)?, None),
        HostCmd::Threats { root } => {
            let root = root
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("/"));
            (host::scan_threats(&root), None)
        }
        HostCmd::Signatures {
            path,
            no_update,
            db,
            max_age_hours,
        } => (
            host::scan_signatures(path, db.as_deref(), *no_update, *max_age_hours, offline)?,
            None,
        ),
        HostCmd::Conns {
            allow,
            watch,
            proc,
            command,
        } => {
            let root = host::proc_root(proc.as_ref());
            let observed = host::observe(&root, command, *watch)?;
            let mut flows = observed.flows;
            let mut allow_list = match allow {
                Some(path) => {
                    let text = std::fs::read_to_string(path)
                        .map_err(|e| format!("allow {}: {e}", path.display()))?;
                    Some(host::parse_allow(&text))
                }
                None => None,
            };
            if !offline {
                if let Some(list) = allow_list.as_mut() {
                    resolve_names(list);
                }
                label_ptr(&mut flows);
            }
            let fail = allow_list
                .as_ref()
                .is_some_and(|list| !host::unexpected(&flows, list).is_empty());
            let report = conns_report(&root, &flows, allow_list.as_ref());
            if fail {
                finish(cli, format, &report)?;
                return Ok(ExitCode::from(1));
            }
            (report, observed.child_code)
        }
    };
    finish(cli, format, &report)?;
    if let Some(code) = child {
        if code == 0 {
            return Ok(ExitCode::SUCCESS);
        }
        return Ok(ExitCode::from(code.clamp(1, 125) as u8));
    }
    Ok(ExitCode::SUCCESS)
}

fn conns_report(
    root: &std::path::Path,
    flows: &[host::Flow],
    allow: Option<&host::Allow>,
) -> osint::Report {
    let mut findings = Vec::new();
    if flows.is_empty() && !root.join("net/tcp").exists() {
        findings.push(Hit::new(
            "conns",
            Status::Inconclusive,
            "no tcp table under the proc root",
            None,
        ));
    }
    let mut shown = 0usize;
    for flow in flows {
        if shown >= 80 {
            break;
        }
        let who = if flow.comm.is_empty() {
            flow.pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".into())
        } else if let Some(pid) = flow.pid {
            format!("{pid}/{}", flow.comm)
        } else {
            flow.comm.clone()
        };
        let remote = if flow.name.is_empty() {
            format!("{}:{}", flow.remote_ip, flow.remote_port)
        } else {
            format!("{} ({}):{}", flow.name, flow.remote_ip, flow.remote_port)
        };
        findings.push(Hit::new(
            flow.dir,
            Status::Confirmed,
            format!(
                "{} {} {who} {}:{} -> {remote}",
                flow.proto, flow.state, flow.local_ip, flow.local_port
            ),
            None,
        ));
        shown += 1;
    }
    if flows.len() > shown {
        findings.push(Hit::new(
            "conns",
            Status::Confirmed,
            format!("{} more sockets omitted", flows.len() - shown),
            None,
        ));
    }
    if let Some(allow) = allow {
        for flow in host::unexpected(flows, allow) {
            let remote = format!("{}:{}", flow.remote_ip, flow.remote_port);
            let why = if host::is_metadata(&flow.remote_ip) {
                "cloud metadata address"
            } else {
                "not on the allow list"
            };
            findings.push(Hit::new(
                "egress",
                Status::Confirmed,
                format!("{remote} {why}"),
                None,
            ));
        }
        if !findings.iter().any(|h| h.module == "egress") {
            findings.push(Hit::new(
                "egress",
                Status::Absent,
                "outbound sockets match the allow list",
                None,
            ));
        }
    }
    osint::Report {
        target: root.display().to_string(),
        kind: "conns",
        elapsed_ms: 0,
        findings,
    }
}

fn resolve_names(allow: &mut host::Allow) {
    let net = osint::net::Net::new();
    let pending = host::pending_names(allow);
    for (name, port) in pending {
        let mut ips = Vec::new();
        for kind in ["A", "AAAA"] {
            let Ok(resp) = net.lookup(&name, kind) else {
                continue;
            };
            for ans in resp.answers {
                if ans.typ == 1 || ans.typ == 28 {
                    ips.push(ans.data.trim_end_matches('.').to_string());
                }
            }
        }
        host::remember_name(allow, &name, port, &ips);
    }
}

fn label_ptr(flows: &mut [host::Flow]) {
    let mut ips = Vec::new();
    for flow in flows.iter() {
        if flow.dir == "listen" || !public_v4(&flow.remote_ip) {
            continue;
        }
        if ips.iter().any(|ip| ip == &flow.remote_ip) {
            continue;
        }
        if ips.len() >= 16 {
            break;
        }
        ips.push(flow.remote_ip.clone());
    }
    if ips.is_empty() {
        return;
    }
    let net = osint::net::Net::new();
    for ip in ips {
        let Some(q) = ptr_name(&ip) else {
            continue;
        };
        let Ok(resp) = net.lookup(&q, "PTR") else {
            continue;
        };
        let Some(name) = resp
            .answers
            .iter()
            .find(|a| a.typ == 12)
            .map(|a| a.data.trim_end_matches('.').to_string())
        else {
            continue;
        };
        for flow in flows.iter_mut() {
            if flow.remote_ip == ip {
                flow.name = name.clone();
            }
        }
    }
}

fn public_v4(ip: &str) -> bool {
    let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let o = v4.octets();
    !(o[0] == 10
        || o[0] == 127
        || (o[0] == 172 && (o[1] & 0xf0) == 16)
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 169 && o[1] == 254)
        || o[0] >= 224)
}

fn ptr_name(ip: &str) -> Option<String> {
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        let o = v4.octets();
        return Some(format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]));
    }
    None
}

fn finish(cli: &Cli, format: Format, report: &osint::Report) -> Result<(), String> {
    if cli.store {
        let body = osint::render(report, Format::Json);
        if let Err(e) = crate::db::put_report(report.kind, &report.target, &body) {
            eprintln!("store: {e}");
        }
    }
    let text = osint::render(report, format);
    match &cli.output {
        Some(p) => std::fs::write(p, text).map_err(|e| format!("write {}: {e}", p.display()))?,
        None => print!("{text}"),
    }
    Ok(())
}
