// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! XMPP and IRC service records for one domain.
//! This reads DNS SRV only. It does not connect, join a room, or send a message.

use super::name::safe_dns_name;
use super::net::Net;
use super::{Hit, Report, Status};
use serde_json::json;
use std::time::Instant;

const SERVICES: &[(&str, &str)] = &[
    ("_xmpp-client._tcp", "xmpp-starttls"),
    ("_xmpps-client._tcp", "xmpp-tls"),
    ("_xmpp-server._tcp", "xmpp-server"),
    ("_xmpps-server._tcp", "xmpp-server-tls"),
    ("_irc._tcp", "irc"),
    ("_ircs._tcp", "ircs"),
];

pub struct Srv {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

pub fn parse_srv(data: &str) -> Option<Srv> {
    let mut parts = data.split_whitespace();
    let priority = parts.next()?.parse().ok()?;
    let weight = parts.next()?.parse().ok()?;
    let port = parts.next()?.parse().ok()?;
    let target = parts.next()?.trim_end_matches('.').to_ascii_lowercase();
    if target.is_empty() || target == "." {
        return None;
    }
    Some(Srv {
        priority,
        weight,
        port,
        target,
    })
}

pub fn scan(raw: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    let domain = raw
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .split('/')
        .next()
        .unwrap_or("")
        .trim_end_matches('.');
    if !safe_dns_name(domain) {
        return Err("chat checks need a dotted ASCII domain".into());
    }
    let net = Net::new();
    let mut findings = Vec::new();
    let mut saw_xmpp_tls = false;
    let mut saw_xmpp_starttls = false;
    let mut saw_irc = false;
    let mut saw_ircs = false;
    for &(name, module) in SERVICES {
        let q = format!("{name}.{domain}");
        let resp = match net.lookup(&q, "SRV") {
            Ok(r) => r,
            Err(e) => {
                findings.push(Hit::new(module, Status::Error, e, None));
                continue;
            }
        };
        if resp.status == 3 || (resp.status == 0 && resp.answers.iter().all(|a| a.typ != 33)) {
            findings.push(Hit::new(
                module,
                Status::Absent,
                format!("no {name} SRV"),
                None,
            ));
            continue;
        }
        if resp.status != 0 {
            findings.push(Hit::new(
                module,
                Status::Error,
                format!("dns status {}", resp.status),
                None,
            ));
            continue;
        }
        let rows: Vec<_> = resp
            .answers
            .iter()
            .filter(|a| a.typ == 33)
            .filter_map(|a| parse_srv(&a.data))
            .collect();
        if rows.is_empty() {
            findings.push(Hit::new(
                module,
                Status::Absent,
                format!("no usable {name} SRV"),
                None,
            ));
            continue;
        }
        match module {
            "xmpp-tls" | "xmpp-server-tls" => saw_xmpp_tls = true,
            "xmpp-starttls" | "xmpp-server" => saw_xmpp_starttls = true,
            "irc" => saw_irc = true,
            "ircs" => saw_ircs = true,
            _ => {}
        }
        let summary = rows
            .iter()
            .map(|s| format!("{}:{} {}", s.priority, s.port, s.target))
            .collect::<Vec<_>>()
            .join(", ");
        let evidence = rows
            .iter()
            .map(|s| {
                json!({
                    "priority": s.priority,
                    "weight": s.weight,
                    "port": s.port,
                    "target": s.target,
                })
            })
            .collect::<Vec<_>>();
        findings.push(Hit::new(
            module,
            Status::Confirmed,
            summary,
            Some(json!({"records": evidence})),
        ));
    }
    if saw_xmpp_starttls && !saw_xmpp_tls {
        findings.push(Hit::new(
            "xmpp-direct-tls",
            Status::Inconclusive,
            "STARTTLS XMPP SRV is published and the direct TLS SRV is absent",
            None,
        ));
    }
    if saw_irc && !saw_ircs {
        findings.push(Hit::new(
            "irc-tls",
            Status::Confirmed,
            "cleartext IRC SRV is published and the IRC-over-TLS SRV is absent",
            None,
        ));
    }
    Ok(Report {
        target: domain.to_string(),
        kind: "chat",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srv_parse_reads_priority_port_and_target() {
        let s = parse_srv("10 5 5222 xmpp.example.com.").unwrap();
        assert_eq!(s.priority, 10);
        assert_eq!(s.port, 5222);
        assert_eq!(s.target, "xmpp.example.com");
        assert!(parse_srv("0 0 6697 .").is_none());
    }
}
