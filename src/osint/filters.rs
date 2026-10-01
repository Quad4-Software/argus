// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Whether public filter resolvers refuse a name that Cloudflare still answers.
//! A block is a lead about reputation feeds. It is not a verdict on the site.

use super::net::{DnsResp, Net};
use super::{Hit, Status};
use serde_json::json;

const RESOLVERS: &[(&str, &str)] = &[
    ("Quad9", "https://dns.quad9.net/dns-query"),
    ("AdGuard", "https://dns.adguard-dns.com/resolve"),
];

pub fn scan(net: &Net, domain: &str) -> Hit {
    let reference = match net.lookup_via("https://cloudflare-dns.com/dns-query", domain, "A") {
        Ok(resp) => resp,
        Err(e) => {
            return Hit::new(
                "filters",
                Status::Inconclusive,
                format!("reference resolver failed: {e}"),
                None,
            );
        }
    };
    if !answered(&reference) {
        return Hit::new(
            "filters",
            Status::Inconclusive,
            "reference resolver has no address to compare",
            None,
        );
    }
    let mut blocked = Vec::new();
    let mut clear = Vec::new();
    let mut missed = Vec::new();
    for (name, base) in RESOLVERS {
        match net.lookup_via(base, domain, "A") {
            Ok(resp) if is_blocked(&resp) => blocked.push(*name),
            Ok(_) => clear.push(*name),
            Err(_) => missed.push(*name),
        }
    }
    let evidence = json!({"blocked": blocked, "clear": clear, "missed": missed});
    if !blocked.is_empty() {
        Hit::new(
            "filters",
            Status::Confirmed,
            format!("blocked by {}", blocked.join(", ")),
            Some(evidence),
        )
    } else if clear.is_empty() {
        Hit::new(
            "filters",
            Status::Inconclusive,
            "filter resolvers did not answer",
            Some(evidence),
        )
    } else {
        Hit::new(
            "filters",
            Status::Absent,
            format!("not blocked by {}", clear.join(", ")),
            Some(evidence),
        )
    }
}

fn answered(resp: &DnsResp) -> bool {
    resp.status == 0 && resp.answers.iter().any(|a| a.typ == 1 && !sink(&a.data))
}

pub(crate) fn is_blocked(resp: &DnsResp) -> bool {
    if resp.status == 2 || resp.status == 3 {
        return true;
    }
    if resp.status != 0 {
        return false;
    }
    let addrs: Vec<&str> = resp
        .answers
        .iter()
        .filter(|a| a.typ == 1 || a.typ == 28)
        .map(|a| a.data.as_str())
        .collect();
    !addrs.is_empty() && addrs.iter().all(|ip| sink(ip))
}

fn sink(ip: &str) -> bool {
    matches!(
        ip,
        "0.0.0.0" | "127.0.0.1" | "::" | "::1" | "0:0:0:0:0:0:0:0"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osint::net::Rr;

    #[test]
    fn sink_and_nxdomain_count_as_blocks() {
        let nx = DnsResp {
            status: 3,
            ad: false,
            answers: Vec::new(),
        };
        assert!(is_blocked(&nx));
        let sink = DnsResp {
            status: 0,
            ad: false,
            answers: vec![Rr {
                typ: 1,
                data: "0.0.0.0".into(),
            }],
        };
        assert!(is_blocked(&sink));
        let live = DnsResp {
            status: 0,
            ad: false,
            answers: vec![Rr {
                typ: 1,
                data: "203.0.113.10".into(),
            }],
        };
        assert!(!is_blocked(&live));
    }
}
