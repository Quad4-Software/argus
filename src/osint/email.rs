// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Public records for one mailbox.

use super::domain::parse_mx;
use super::intel::hudson_email;
use super::name::{
    is_disposable, is_role, mail_service, parse_mailbox, provider, public_ip, safe_dns_name,
};
use super::net::Net;
use super::policy::{
    dkim_key_state, eval_dmarc, eval_spf, mx_matches_policy, parse_mta_sts, record_tags,
};
use super::smtp;
use super::surface::{
    autoconfig, certs, github, gravatar, hibp, hkp, openpgpkey, pastes, rdap_domain, rdap_ip,
    security_txt, vks, wkd,
};
use super::{Hit, Report, Status};
use serde_json::json;
use std::time::Instant;

const DKIM_SELECTORS: &[&str] = &[
    "selector1",
    "selector2",
    "google",
    "s1",
    "s2",
    "k1",
    "k2",
    "k3",
    "default",
    "dkim",
    "mail",
    "protonmail",
    "fm1",
    "fm2",
    "fm3",
];

const SRV_NAMES: &[&str] = &[
    "_submission._tcp",
    "_submissions._tcp",
    "_imaps._tcp",
    "_imap._tcp",
    "_pop3s._tcp",
    "_autodiscover._tcp",
];

pub fn scan(raw: &str, smtp_probe: bool) -> Result<Report, String> {
    let t0 = Instant::now();
    let mailbox = parse_mailbox(raw)?;
    let address = mailbox.address();
    let mut findings = vec![
        Hit::new(
            "syntax",
            Status::Confirmed,
            address.clone(),
            Some(json!({"local": mailbox.local, "domain": mailbox.domain})),
        ),
        if is_role(&mailbox.local) {
            Hit::new(
                "role",
                Status::Confirmed,
                "local part matches a role name",
                Some(json!({"local": super::name::local_base(&mailbox.local)})),
            )
        } else {
            Hit::new(
                "role",
                Status::Absent,
                "local part is not in the role list",
                None,
            )
        },
        match provider(&mailbox.domain) {
            Some(name) => Hit::new(
                "provider",
                Status::Confirmed,
                name,
                Some(json!({"domain": mailbox.domain})),
            ),
            None => Hit::new(
                "provider",
                Status::Absent,
                "not in the bundled provider list",
                None,
            ),
        },
        if is_disposable(&mailbox.domain) {
            Hit::new(
                "disposable",
                Status::Confirmed,
                "known disposable domain",
                Some(json!({"domain": mailbox.domain})),
            )
        } else {
            Hit::new(
                "disposable",
                Status::Absent,
                "not in the bundled disposable list",
                None,
            )
        },
    ];
    if !safe_dns_name(&mailbox.domain) {
        findings.push(Hit::new(
            "mx",
            Status::Inconclusive,
            "network checks run on dotted ASCII domains only",
            None,
        ));
        return Ok(finish(address, t0, findings));
    }
    let net = Net::new();
    let domain = mailbox.domain.clone();
    let local = mailbox.local.clone();
    let email = address.clone();
    let (
        mx,
        spf,
        dmarc,
        bimi,
        tlsrpt,
        mtasts,
        dkim,
        dnssec,
        srv,
        rdap,
        cert,
        auto,
        sec,
        grav,
        key_wkd,
        key_vks,
        key_hkp,
        key_dns,
        gh,
        breach,
        paste,
        rock,
    ) = std::thread::scope(|s| {
        let mx = s.spawn(|| mx_lookup(&net, &domain));
        let spf = s.spawn(|| eval_spf(&domain, |name| net.txt(name)));
        let dmarc = s.spawn(|| eval_dmarc(&domain, |name| net.txt(name)));
        let bimi = s.spawn(|| bimi_lookup(&net, &domain));
        let tlsrpt = s.spawn(|| tlsrpt_lookup(&net, &domain));
        let mtasts = s.spawn(|| mtasts_lookup(&net, &domain));
        let dkim = s.spawn(|| dkim_lookup(&net, &domain));
        let dnssec = s.spawn(|| dnssec_lookup(&net, &domain));
        let srv = s.spawn(|| srv_lookup(&net, &domain));
        let rdap = s.spawn(|| rdap_domain(&net, &domain));
        let cert = s.spawn(|| certs(&net, &domain));
        let auto = s.spawn(|| autoconfig(&net, &domain));
        let sec = s.spawn(|| security_txt(&net, &domain));
        let grav = s.spawn(|| gravatar(&net, &email));
        let key_wkd = s.spawn(|| wkd(&net, &local, &domain));
        let key_vks = s.spawn(|| vks(&net, &email));
        let key_hkp = s.spawn(|| hkp(&net, &email));
        let key_dns = s.spawn(|| openpgpkey(&net, &local, &domain));
        let gh = s.spawn(|| github(&net, &email));
        let breach = s.spawn(|| hibp(&net, &email));
        let paste = s.spawn(|| pastes(&net, &email));
        let rock = s.spawn(|| hudson_email(&net, &email));
        (
            join(mx, "mx"),
            join(spf, "spf"),
            join(dmarc, "dmarc"),
            join(bimi, "bimi"),
            join(tlsrpt, "tlsrpt"),
            join(mtasts, "mtasts"),
            join(dkim, "dkim"),
            join(dnssec, "dnssec"),
            join(srv, "srv"),
            join(rdap, "rdap"),
            join(cert, "certs"),
            join(auto, "autoconfig"),
            join(sec, "securitytxt"),
            join(grav, "gravatar"),
            join(key_wkd, "wkd"),
            join(key_vks, "vks"),
            join(key_hkp, "hkp"),
            join(key_dns, "openpgpkey"),
            join(gh, "github"),
            join(breach, "hibp"),
            join(paste, "pastes"),
            join(rock, "hudsonrock"),
        )
    });
    let host = mailhost_from(&mx);
    let (dane, net_rdap, smtp_hit) = std::thread::scope(|s| {
        let dane = s.spawn(|| dane_lookup(&net, &mx));
        let net_rdap = s.spawn(|| rdap_network(&net, &mx));
        let smtp_hit = s.spawn(|| smtp_for(&mx, &email, smtp_probe));
        (
            join(dane, "dane"),
            join(net_rdap, "rdap-network"),
            join(smtp_hit, "smtp"),
        )
    });
    findings.extend([
        mx, host, spf, dmarc, bimi, tlsrpt, mtasts, dkim, dnssec, srv, dane, net_rdap, smtp_hit,
        rdap, cert, auto, sec, grav, key_wkd, key_vks, key_hkp, key_dns, gh, breach, paste, rock,
    ]);
    sort_email(&mut findings);
    Ok(finish(address, t0, findings))
}

fn finish(address: String, t0: Instant, findings: Vec<Hit>) -> Report {
    Report {
        target: address,
        kind: "email",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    }
}

fn mx_lookup(net: &Net, domain: &str) -> Hit {
    let resp = match net.lookup(domain, "MX") {
        Ok(r) => r,
        Err(e) => return Hit::new("mx", Status::Error, e, None),
    };
    if resp.status == 3 {
        return Hit::new("mx", Status::Absent, "domain name does not exist", None);
    }
    if resp.status != 0 {
        return Hit::new(
            "mx",
            Status::Error,
            format!("dns status {}", resp.status),
            None,
        );
    }
    let mut recs = Vec::new();
    for a in resp.answers.iter().filter(|a| a.typ == 15) {
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
            Some(json!({"null_mx": true, "hosts": []})),
        );
    }
    if recs.is_empty() {
        let a = net.lookup(domain, "A").ok();
        let aaaa = net.lookup(domain, "AAAA").ok();
        let has = a.is_some_and(|r| r.answers.iter().any(|x| x.typ == 1))
            || aaaa.is_some_and(|r| r.answers.iter().any(|x| x.typ == 28));
        if has {
            return Hit::new(
                "mx",
                Status::Confirmed,
                "implicit MX, the domain itself accepts mail",
                Some(json!({"hosts": [domain], "implicit": true, "null_mx": false})),
            );
        }
        return Hit::new(
            "mx",
            Status::Absent,
            "no MX record and no address",
            Some(json!({"null_mx": false, "hosts": []})),
        );
    }
    let hosts: Vec<String> = recs.iter().map(|(_, h)| h.clone()).collect();
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

fn hosts_of(mx: &Hit) -> Vec<String> {
    mx.evidence
        .as_ref()
        .and_then(|v| v.get("hosts"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn null_mx(mx: &Hit) -> bool {
    mx.evidence
        .as_ref()
        .and_then(|v| v.get("null_mx"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn mailhost_from(mx: &Hit) -> Hit {
    if mx.status == Status::Error {
        return Hit::new("mailhost", Status::Error, "MX lookup failed", None);
    }
    if null_mx(mx) {
        return Hit::new("mailhost", Status::Absent, "null MX, no mail host", None);
    }
    let hosts = hosts_of(mx);
    let mut names: Vec<&str> = Vec::new();
    for h in &hosts {
        if let Some(n) = mail_service(h)
            && !names.contains(&n)
        {
            names.push(n);
        }
    }
    if names.is_empty() {
        Hit::new(
            "mailhost",
            Status::Inconclusive,
            "MX host is not in the bundled mail service list",
            Some(json!({"hosts": hosts})),
        )
    } else {
        Hit::new(
            "mailhost",
            Status::Confirmed,
            names.join(", "),
            Some(json!({"hosts": hosts, "services": names})),
        )
    }
}

fn bimi_lookup(net: &Net, domain: &str) -> Hit {
    let texts = match net.txt(&format!("default._bimi.{domain}")) {
        Ok(t) => t,
        Err(e) => return Hit::new("bimi", Status::Error, e, None),
    };
    let recs: Vec<_> = texts
        .iter()
        .map(|t| record_tags(t))
        .filter(|t| t.get("v").is_some_and(|v| v.eq_ignore_ascii_case("BIMI1")))
        .collect();
    if recs.is_empty() {
        return Hit::new("bimi", Status::Absent, "no default BIMI record", None);
    }
    if recs.len() > 1 {
        return Hit::new("bimi", Status::Error, "more than one BIMI record", None);
    }
    let l = recs[0].get("l").cloned().unwrap_or_default();
    let a = recs[0].get("a").cloned().unwrap_or_default();
    if a.is_empty() {
        let summary = if l.is_empty() {
            "BIMI record has no logo or authority certificate"
        } else {
            "BIMI logo published, no authority certificate"
        };
        return Hit::new(
            "bimi",
            Status::Inconclusive,
            summary,
            Some(json!({"l": l, "a": a})),
        );
    }
    if !a.to_ascii_lowercase().starts_with("https://") {
        return Hit::new(
            "bimi",
            Status::Error,
            "BIMI certificate URL is not https",
            Some(json!({"l": l, "a": a})),
        );
    }
    match net.get(&a, &[]) {
        Err(e) => Hit::new(
            "bimi",
            Status::Inconclusive,
            e,
            Some(json!({"l": l, "a": a})),
        ),
        Ok(r) if r.status == 200 && looks_like_cert(&r.body) => Hit::new(
            "bimi",
            Status::Confirmed,
            "BIMI authority certificate fetched",
            Some(json!({"l": l, "a": a})),
        ),
        Ok(r) => Hit::new(
            "bimi",
            Status::Inconclusive,
            format!("BIMI authority URL HTTP {}", r.status),
            Some(json!({"l": l, "a": a})),
        ),
    }
}

fn looks_like_cert(body: &str) -> bool {
    let t = body.trim_start();
    t.contains("BEGIN CERTIFICATE") || t.as_bytes().first() == Some(&0x30)
}

fn tlsrpt_lookup(net: &Net, domain: &str) -> Hit {
    let name = format!("_smtp._tls.{domain}");
    let texts = match net.txt(&name) {
        Ok(t) => t,
        Err(e) => return Hit::new("tlsrpt", Status::Error, e, None),
    };
    let recs: Vec<_> = texts
        .iter()
        .filter(|t| t.to_ascii_lowercase().starts_with("v=tlsrptv1"))
        .cloned()
        .collect();
    if recs.is_empty() {
        Hit::new("tlsrpt", Status::Absent, "no TLS reporting record", None)
    } else {
        Hit::new(
            "tlsrpt",
            Status::Confirmed,
            "TLS reporting record published",
            Some(json!({"records": recs})),
        )
    }
}

fn mtasts_lookup(net: &Net, domain: &str) -> Hit {
    let texts = match net.txt(&format!("_mta-sts.{domain}")) {
        Ok(t) => t,
        Err(e) => return Hit::new("mtasts", Status::Error, e, None),
    };
    if !texts
        .iter()
        .any(|t| t.to_ascii_lowercase().contains("v=stsv1"))
    {
        return Hit::new("mtasts", Status::Absent, "no MTA-STS TXT record", None);
    }
    let url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
    let resp = match net.get(&url, &[]) {
        Ok(r) => r,
        Err(e) => {
            return Hit::new(
                "mtasts",
                Status::Inconclusive,
                format!("TXT is published but the policy did not load: {e}"),
                None,
            );
        }
    };
    if resp.status != 200 {
        return Hit::new(
            "mtasts",
            Status::Inconclusive,
            format!("TXT is published but policy HTTP {}", resp.status),
            None,
        );
    }
    let Some(pol) = parse_mta_sts(&resp.body) else {
        return Hit::new(
            "mtasts",
            Status::Inconclusive,
            "policy file is not a usable STSv1 document",
            None,
        );
    };
    let mx = match net.lookup(domain, "MX") {
        Ok(r) => r
            .answers
            .iter()
            .filter(|a| a.typ == 15)
            .filter_map(|a| parse_mx(&a.data))
            .map(|(_, h)| h)
            .filter(|h| h != ".")
            .collect::<Vec<_>>(),
        Err(_) => Vec::new(),
    };
    let outside: Vec<&str> = mx
        .iter()
        .map(String::as_str)
        .filter(|h| !pol.mx.iter().any(|p| mx_matches_policy(h, p)))
        .collect();
    if mx.is_empty() || outside.is_empty() {
        Hit::new(
            "mtasts",
            Status::Confirmed,
            format!("mode={}, live MX matches the policy", pol.mode),
            Some(json!({"mode": pol.mode, "mx": pol.mx})),
        )
    } else {
        Hit::new(
            "mtasts",
            Status::Inconclusive,
            format!(
                "mode={}, MX outside the policy: {}",
                pol.mode,
                outside.join(", ")
            ),
            Some(json!({"mode": pol.mode, "outside": outside})),
        )
    }
}

fn dkim_lookup(net: &Net, domain: &str) -> Hit {
    let rows = std::thread::scope(|s| {
        let handles: Vec<_> = DKIM_SELECTORS
            .iter()
            .map(|sel| s.spawn(move || (*sel, net.txt(&format!("{sel}._domainkey.{domain}")))))
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| ("", Err("lookup panicked".into())))
            })
            .collect::<Vec<_>>()
    });
    let mut present = Vec::new();
    let mut revoked = 0;
    let mut failed = 0;
    for (sel, res) in rows {
        match res {
            Err(_) => failed += 1,
            Ok(texts) => {
                let mut saw = false;
                for t in &texts {
                    match dkim_key_state(t) {
                        Some("present") => {
                            present.push(sel.to_string());
                            saw = true;
                            break;
                        }
                        Some("revoked") => {
                            revoked += 1;
                            saw = true;
                            break;
                        }
                        _ => {}
                    }
                }
                let _ = saw;
            }
        }
    }
    if !present.is_empty() {
        return Hit::new(
            "dkim",
            Status::Confirmed,
            format!("published selectors {}", present.join(", ")),
            Some(
                json!({"selectors": present, "checked": DKIM_SELECTORS.len(), "revoked": revoked}),
            ),
        );
    }
    if failed == DKIM_SELECTORS.len() {
        return Hit::new("dkim", Status::Error, "selector lookups failed", None);
    }
    Hit::new(
        "dkim",
        Status::Inconclusive,
        "none of the checked selectors published a usable key",
        Some(json!({"checked": DKIM_SELECTORS.len(), "revoked": revoked})),
    )
}

fn dnssec_lookup(net: &Net, domain: &str) -> Hit {
    match net.lookup(domain, "DS") {
        Err(e) => Hit::new("dnssec", Status::Error, e, None),
        Ok(r) if r.status != 0 && r.status != 3 => Hit::new(
            "dnssec",
            Status::Error,
            format!("dns status {}", r.status),
            None,
        ),
        Ok(r) if r.answers.iter().any(|a| a.typ == 43) => Hit::new(
            "dnssec",
            Status::Confirmed,
            "DS is published",
            Some(json!({"authenticated": r.ad})),
        ),
        Ok(r) => Hit::new(
            "dnssec",
            Status::Absent,
            "no DS record",
            Some(json!({"authenticated": r.ad})),
        ),
    }
}

fn srv_lookup(net: &Net, domain: &str) -> Hit {
    let rows = std::thread::scope(|s| {
        let handles: Vec<_> = SRV_NAMES
            .iter()
            .map(|n| s.spawn(move || (*n, net.lookup(&format!("{n}.{domain}"), "SRV"))))
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| ("", Err("lookup panicked".into())))
            })
            .collect::<Vec<_>>()
    });
    let mut found = Vec::new();
    let mut failed = 0;
    for (name, res) in rows {
        match res {
            Err(_) => failed += 1,
            Ok(r) => {
                for a in r.answers.iter().filter(|a| a.typ == 33) {
                    found.push(format!("{name} {}", a.data.trim()));
                }
            }
        }
    }
    if !found.is_empty() {
        Hit::new(
            "srv",
            Status::Confirmed,
            format!("{} mail SRV record(s)", found.len()),
            Some(json!({"records": found})),
        )
    } else if failed == SRV_NAMES.len() {
        Hit::new("srv", Status::Error, "SRV lookups failed", None)
    } else {
        Hit::new("srv", Status::Absent, "no mail SRV records", None)
    }
}

fn rdap_network(net: &Net, mx: &Hit) -> Hit {
    if mx.status == Status::Error {
        return Hit::new("rdap-network", Status::Error, "MX lookup failed", None);
    }
    if null_mx(mx) {
        return Hit::new(
            "rdap-network",
            Status::Absent,
            "null MX, no mail host address",
            None,
        );
    }
    let Some(host) = hosts_of(mx).into_iter().next() else {
        return Hit::new(
            "rdap-network",
            Status::Absent,
            "no mail host to look up",
            None,
        );
    };
    let resp = match net.lookup(&host, "A") {
        Ok(r) => r,
        Err(e) => return Hit::new("rdap-network", Status::Error, e, None),
    };
    let Some(ip) = resp
        .answers
        .iter()
        .find(|a| a.typ == 1 && public_ip(&a.data))
    else {
        return Hit::new(
            "rdap-network",
            Status::Inconclusive,
            format!("{host} has no public A record"),
            None,
        );
    };
    let mut hit = rdap_ip(net, &ip.data);
    hit.module = "rdap-network".into();
    hit
}

fn smtp_for(mx: &Hit, email: &str, enabled: bool) -> Hit {
    if !enabled {
        return smtp::skipped();
    }
    if mx.status == Status::Error {
        return Hit::new("smtp", Status::Error, "MX lookup failed", None);
    }
    if null_mx(mx) {
        return Hit::new("smtp", Status::Absent, "null MX, nothing to ask", None);
    }
    let Some(host) = hosts_of(mx).into_iter().next() else {
        return Hit::new("smtp", Status::Absent, "no mail host to ask", None);
    };
    smtp::probe(&host, email)
}

fn dane_lookup(net: &Net, mx: &Hit) -> Hit {
    if mx.status == Status::Error {
        return Hit::new("dane", Status::Error, "MX lookup failed", None);
    }
    if null_mx(mx) {
        return Hit::new(
            "dane",
            Status::Absent,
            "null MX, no TLSA name to query",
            None,
        );
    }
    let hosts = hosts_of(mx);
    let Some(host) = hosts.first() else {
        return Hit::new(
            "dane",
            Status::Absent,
            "no mail host to check for TLSA",
            None,
        );
    };
    let name = format!("_25._tcp.{host}");
    match net.lookup(&name, "TLSA") {
        Err(e) => Hit::new("dane", Status::Error, e, None),
        Ok(r) if r.answers.iter().any(|a| a.typ == 52) => Hit::new(
            "dane",
            Status::Confirmed,
            format!("TLSA published at {name}"),
            Some(json!({"name": name})),
        ),
        Ok(_) => Hit::new("dane", Status::Absent, format!("no TLSA at {name}"), None),
    }
}

fn join(h: std::thread::ScopedJoinHandle<Hit>, module: &str) -> Hit {
    h.join()
        .unwrap_or_else(|_| Hit::new(module, Status::Error, "lookup panicked", None))
}

fn sort_email(findings: &mut [Hit]) {
    fn rank(m: &str) -> u8 {
        match m {
            "syntax" => 0,
            "role" => 1,
            "provider" => 2,
            "disposable" => 3,
            "mx" => 4,
            "mailhost" => 5,
            "spf" => 6,
            "dmarc" => 7,
            "bimi" => 8,
            "tlsrpt" => 9,
            "mtasts" => 10,
            "dkim" => 11,
            "dnssec" => 12,
            "srv" => 13,
            "dane" => 14,
            "rdap-network" => 15,
            "smtp" => 16,
            "rdap" => 17,
            "certs" => 18,
            "autoconfig" => 19,
            "securitytxt" => 20,
            "gravatar" => 21,
            "wkd" => 22,
            "openpgpkey" => 23,
            "vks" => 24,
            "hkp" => 25,
            "github" => 26,
            "hibp" => 27,
            "pastes" => 28,
            "hudsonrock" => 29,
            _ => 40,
        }
    }
    findings.sort_by_key(|h| rank(&h.module));
}
