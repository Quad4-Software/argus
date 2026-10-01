// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Public records for one domain.

use super::intel::{hudson_domain, urlscan};
use super::name::{normalize_domain, public_ip};
use super::net::{Net, clip};
use super::surface::{
    certs, homepage, passive_names, rdap_domain, rdap_ip, robots, security_txt, site_files, wayback,
};
use super::{Hit, Report, Status};
use serde_json::json;
use std::time::Instant;

pub fn scan(raw: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    let domain = normalize_domain(raw)?;
    let net = Net::new();
    let (dns, page, robots_hit, sec, rdap, cert, archive, names, files, rock, scans, filters) =
        std::thread::scope(|s| {
            let dns = s.spawn(|| dns_bundle(&net, &domain));
            let page = s.spawn(|| homepage(&net, &domain));
            let robots_hit = s.spawn(|| robots(&net, &domain));
            let sec = s.spawn(|| security_txt(&net, &domain));
            let rdap = s.spawn(|| rdap_domain(&net, &domain));
            let cert = s.spawn(|| certs(&net, &domain));
            let archive = s.spawn(|| wayback(&net, &domain));
            let names = s.spawn(|| passive_names(&net, &domain));
            let files = s.spawn(|| site_files(&net, &domain));
            let rock = s.spawn(|| hudson_domain(&net, &domain));
            let scans = s.spawn(|| urlscan(&net, &domain));
            let filters = s.spawn(|| super::filters::scan(&net, &domain));
            (
                join(dns),
                join(page),
                join_one(robots_hit, "robots"),
                join_one(sec, "securitytxt"),
                join_one(rdap, "rdap"),
                join_one(cert, "certs"),
                join_one(archive, "wayback"),
                join_one(names, "names"),
                join(files),
                join_one(rock, "hudsonrock"),
                join_one(scans, "urlscan"),
                join_one(filters, "filters"),
            )
        });
    let mut findings = dns;
    findings.extend(page);
    findings.push(robots_hit);
    findings.push(sec);
    findings.push(rdap);
    findings.push(cert);
    findings.push(archive);
    findings.push(names);
    findings.extend(files);
    findings.push(rock);
    findings.push(scans);
    findings.push(filters);
    let ips = public_addrs(&findings);
    if ips.is_empty() {
        findings.push(Hit::new(
            "ptr",
            Status::Absent,
            "no public address to reverse",
            None,
        ));
    } else {
        let extra = std::thread::scope(|s| {
            let handles: Vec<_> = ips
                .iter()
                .flat_map(|ip| {
                    [
                        s.spawn(|| rdap_ip(&net, ip)),
                        s.spawn(|| ptr_lookup(&net, ip)),
                    ]
                })
                .collect();
            handles
                .into_iter()
                .map(|h| join_one(h, "rdap-ip"))
                .collect::<Vec<_>>()
        });
        findings.extend(extra);
    }
    sort_domain(&mut findings);
    Ok(Report {
        target: domain,
        kind: "domain",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

fn dns_bundle(net: &Net, domain: &str) -> Vec<Hit> {
    let types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "DS"];
    let got = std::thread::scope(|s| {
        let handles: Vec<_> = types
            .iter()
            .map(|t| s.spawn(|| (*t, net.lookup(domain, t))))
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| ("", Err("lookup panicked".into())))
            })
            .collect::<Vec<_>>()
    });
    if got
        .iter()
        .all(|(_, r)| r.as_ref().is_ok_and(|d| d.status == 3))
    {
        return vec![Hit::new("dns", Status::Absent, "name does not exist", None)];
    }
    let mut hits = Vec::new();
    for (q, res) in got {
        let module = match q {
            "A" => "a",
            "AAAA" => "aaaa",
            "CNAME" => "cname",
            "MX" => "mx",
            "NS" => "ns",
            "TXT" => "txt",
            "SOA" => "soa",
            "CAA" => "caa",
            "DS" => "dnssec",
            _ => continue,
        };
        let resp = match res {
            Ok(r) => r,
            Err(e) => {
                hits.push(Hit::new(module, Status::Error, e, None));
                continue;
            }
        };
        if resp.status != 0 && resp.status != 3 {
            hits.push(Hit::new(
                module,
                Status::Error,
                format!("dns status {}", resp.status),
                None,
            ));
            continue;
        }
        match q {
            "A" | "AAAA" => {
                let typ = if q == "A" { 1 } else { 28 };
                let ips: Vec<String> = resp
                    .answers
                    .iter()
                    .filter(|a| a.typ == typ)
                    .map(|a| a.data.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if ips.is_empty() {
                    hits.push(Hit::new(
                        module,
                        Status::Absent,
                        format!("no {q} record"),
                        None,
                    ));
                } else {
                    let private = ips.iter().any(|ip| !public_ip(ip));
                    hits.push(Hit::new(
                        module,
                        Status::Confirmed,
                        ips.join(", "),
                        Some(json!({"ips": ips, "private": private})),
                    ));
                }
            }
            "CNAME" => {
                let names: Vec<String> = resp
                    .answers
                    .iter()
                    .filter(|a| a.typ == 5)
                    .map(|a| a.data.trim_end_matches('.').to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !names.is_empty() {
                    hits.push(Hit::new(
                        "cname",
                        Status::Confirmed,
                        names.join(", "),
                        Some(json!({"targets": names})),
                    ));
                }
            }
            "MX" => hits.push(mx_from_answers(&resp.answers)),
            "NS" => {
                let ns: Vec<String> = resp
                    .answers
                    .iter()
                    .filter(|a| a.typ == 2)
                    .map(|a| a.data.trim_end_matches('.').to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect();
                if ns.is_empty() {
                    hits.push(Hit::new("ns", Status::Absent, "no NS record", None));
                } else {
                    hits.push(Hit::new(
                        "ns",
                        Status::Confirmed,
                        ns.join(", "),
                        Some(json!({"nameservers": ns})),
                    ));
                }
            }
            "TXT" => {
                let txts = super::net::txt_values(&resp.answers);
                if txts.is_empty() {
                    hits.push(Hit::new("txt", Status::Absent, "no TXT record", None));
                } else {
                    let shown: Vec<String> = txts.iter().take(8).map(|t| clip(t)).collect();
                    hits.push(Hit::new(
                        "txt",
                        Status::Confirmed,
                        format!("{} TXT record(s)", txts.len()),
                        Some(json!({"records": shown, "count": txts.len()})),
                    ));
                }
            }
            "SOA" => {
                let soa = resp
                    .answers
                    .iter()
                    .find(|a| a.typ == 6)
                    .map(|a| clip(&a.data));
                match soa {
                    Some(s) => hits.push(Hit::new(
                        "soa",
                        Status::Confirmed,
                        s,
                        Some(json!({"authenticated": resp.ad})),
                    )),
                    None => hits.push(Hit::new("soa", Status::Absent, "no SOA record", None)),
                }
            }
            "CAA" => {
                let rows: Vec<String> = resp
                    .answers
                    .iter()
                    .filter(|a| a.typ == 257)
                    .map(|a| clip(&a.data))
                    .collect();
                if rows.is_empty() {
                    hits.push(Hit::new("caa", Status::Absent, "no CAA record", None));
                } else {
                    hits.push(Hit::new(
                        "caa",
                        Status::Confirmed,
                        rows.join(" | "),
                        Some(json!({"records": rows})),
                    ));
                }
            }
            "DS" => {
                let published = resp.answers.iter().any(|a| a.typ == 43);
                if published {
                    hits.push(Hit::new(
                        "dnssec",
                        Status::Confirmed,
                        "DS is published",
                        Some(json!({"authenticated": resp.ad})),
                    ));
                } else {
                    hits.push(Hit::new(
                        "dnssec",
                        Status::Absent,
                        "no DS record",
                        Some(json!({"authenticated": resp.ad})),
                    ));
                }
            }
            _ => {}
        }
    }
    hits
}

fn mx_from_answers(answers: &[super::net::Rr]) -> Hit {
    let mut recs = Vec::new();
    for a in answers.iter().filter(|a| a.typ == 15) {
        if let Some(rec) = parse_mx(&a.data) {
            recs.push(rec);
        }
    }
    recs.sort_by_key(|r| r.0);
    if recs.len() == 1 && recs[0].0 == 0 && (recs[0].1.is_empty() || recs[0].1 == ".") {
        return Hit::new(
            "mx",
            Status::Absent,
            "null MX, the domain does not accept mail",
            Some(json!({"null_mx": true})),
        );
    }
    if recs.is_empty() {
        return Hit::new(
            "mx",
            Status::Absent,
            "no MX record",
            Some(json!({"null_mx": false})),
        );
    }
    let hosts: Vec<&str> = recs.iter().map(|(_, h)| h.as_str()).collect();
    let summary = recs
        .iter()
        .map(|(p, h)| format!("{p} {h}"))
        .collect::<Vec<_>>()
        .join(", ");
    Hit::new(
        "mx",
        Status::Confirmed,
        summary,
        Some(json!({
            "null_mx": false,
            "hosts": hosts,
            "records": recs.iter().map(|(p, h)| json!({"pref": p, "host": h})).collect::<Vec<_>>(),
        })),
    )
}

pub(crate) fn parse_mx(data: &str) -> Option<(u16, String)> {
    let mut parts = data.split_whitespace();
    let pref: u16 = parts.next()?.parse().ok()?;
    let host = parts
        .next()
        .unwrap_or(".")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let host = if host.is_empty() {
        ".".to_string()
    } else {
        host
    };
    Some((pref, host))
}

pub(crate) fn ptr_lookup(net: &Net, ip: &str) -> Hit {
    let Some(name) = reverse_name(ip) else {
        return Hit::new(
            "ptr",
            Status::Error,
            format!("{ip} is not an address"),
            None,
        );
    };
    match net.lookup(&name, "PTR") {
        Err(e) => Hit::new("ptr", Status::Error, e, Some(json!({"ip": ip}))),
        Ok(r) => {
            let names: Vec<String> = r
                .answers
                .iter()
                .filter(|a| a.typ == 12)
                .map(|a| a.data.trim_end_matches('.').to_ascii_lowercase())
                .filter(|n| !n.is_empty())
                .take(4)
                .collect();
            if names.is_empty() {
                Hit::new(
                    "ptr",
                    Status::Absent,
                    format!("no PTR for {ip}"),
                    Some(json!({"ip": ip, "name": name})),
                )
            } else {
                Hit::new(
                    "ptr",
                    Status::Confirmed,
                    format!("{ip} -> {}", names.join(", ")),
                    Some(json!({"ip": ip, "names": names})),
                )
            }
        }
    }
}

pub(crate) fn reverse_name(ip: &str) -> Option<String> {
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        let o = v4.octets();
        return Some(format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]));
    }
    let v6 = ip.parse::<std::net::Ipv6Addr>().ok()?;
    let mut nibbles = Vec::with_capacity(32);
    for b in v6.octets() {
        nibbles.push(format!("{:x}", b >> 4));
        nibbles.push(format!("{:x}", b & 0x0f));
    }
    nibbles.reverse();
    Some(format!("{}.ip6.arpa", nibbles.join(".")))
}

fn public_addrs(findings: &[Hit]) -> Vec<String> {
    let mut out = Vec::new();
    for h in findings {
        if h.module != "a" && h.module != "aaaa" {
            continue;
        }
        let Some(v) = &h.evidence else { continue };
        let Some(arr) = v.get("ips").and_then(|x| x.as_array()) else {
            continue;
        };
        for ip in arr {
            let Some(s) = ip.as_str() else { continue };
            if public_ip(s) && !out.contains(&s.to_string()) {
                out.push(s.to_string());
            }
        }
    }
    out.truncate(2);
    out
}

fn join(h: std::thread::ScopedJoinHandle<Vec<Hit>>) -> Vec<Hit> {
    h.join()
        .unwrap_or_else(|_| vec![Hit::new("dns", Status::Error, "lookup panicked", None)])
}

fn join_one(h: std::thread::ScopedJoinHandle<Hit>, module: &str) -> Hit {
    h.join()
        .unwrap_or_else(|_| Hit::new(module, Status::Error, "lookup panicked", None))
}

fn sort_domain(findings: &mut [Hit]) {
    fn rank(m: &str) -> u8 {
        match m {
            "a" => 0,
            "aaaa" => 1,
            "cname" => 2,
            "mx" => 3,
            "ns" => 4,
            "txt" => 5,
            "soa" => 6,
            "caa" => 7,
            "dnssec" => 8,
            "dns" => 9,
            "rdap" => 10,
            "rdap-ip" => 11,
            "ptr" => 12,
            "certs" => 13,
            "names" => 14,
            "wayback" => 15,
            "http" => 16,
            "headers" => 17,
            "waf" => 18,
            "trackers" => 19,
            "title" => 20,
            "mailboxes" => 21,
            "robots" => 22,
            "llms" => 23,
            "llms-full" => 24,
            "tdmrep" => 25,
            "securitytxt" => 26,
            "hudsonrock" => 27,
            "urlscan" => 28,
            "ads" => 29,
            "humans" => 30,
            "seo" => 31,
            "filters" => 32,
            _ => 40,
        }
    }
    findings.sort_by(|a, b| {
        rank(&a.module)
            .cmp(&rank(&b.module))
            .then(a.summary.cmp(&b.summary))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mx_and_null() {
        assert_eq!(
            parse_mx("10 in1-smtp.messagingengine.com.").unwrap(),
            (10, "in1-smtp.messagingengine.com".into())
        );
        let hit = mx_from_answers(&[super::super::net::Rr {
            typ: 15,
            data: "0 .".into(),
        }]);
        assert_eq!(hit.status, Status::Absent);
        assert!(hit.summary.contains("null MX"));
    }

    #[test]
    fn reverses_public_addresses() {
        assert_eq!(
            reverse_name("203.0.113.10").as_deref(),
            Some("10.113.0.203.in-addr.arpa")
        );
        assert_eq!(
            reverse_name("2001:db8::1").as_deref(),
            Some("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa")
        );
    }
}
