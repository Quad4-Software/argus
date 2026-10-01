// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! SPF, DMARC, DKIM, BIMI, and MTA-STS parsing.
//! Lookup functions are injected so the rules can be tested without DNS.

use super::name::{org_chain, safe_dns_name};
use super::{Hit, Status};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};

pub fn record_tags(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for part in text.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        out.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
    }
    out
}

#[derive(Debug)]
struct SpfRec {
    raw: String,
    all: String,
    redirect: String,
    includes: Vec<String>,
    charged: u32,
}

fn parse_spf(text: &str) -> Option<SpfRec> {
    let text = text.trim();
    let mut words = text.split_whitespace();
    let ver = words.next()?.to_ascii_lowercase();
    if ver != "v=spf1" {
        return None;
    }
    let mut rec = SpfRec {
        raw: text.to_string(),
        all: String::new(),
        redirect: String::new(),
        includes: Vec::new(),
        charged: 0,
    };
    for term in words {
        let low = term.to_ascii_lowercase();
        let stripped = low.trim_start_matches(['+', '-', '~', '?']);
        if let Some(rest) = stripped.strip_prefix("include:") {
            if !rest.is_empty() {
                rec.includes.push(rest.to_string());
            }
        } else if let Some(rest) = stripped.strip_prefix("redirect=") {
            rec.redirect = rest.to_string();
        } else if stripped == "all" {
            let q = if low.starts_with(['+', '-', '~', '?']) {
                &low[..1]
            } else {
                "+"
            };
            rec.all = format!("{q}all");
        } else {
            let name = stripped.split([':', '/', '=']).next().unwrap_or("");
            if matches!(name, "a" | "mx" | "ptr" | "exists") {
                rec.charged += 1;
            }
        }
    }
    Some(rec)
}

/// SPF published at `domain`. `lookup` returns TXT strings for a name.
/// The 10-lookup cap counts include, a, mx, ptr, exists, and redirect.
pub fn eval_spf(domain: &str, mut lookup: impl FnMut(&str) -> Result<Vec<String>, String>) -> Hit {
    let mut seen = HashSet::new();
    let mut lookups = 0u32;
    let mut hops: Vec<Value> = Vec::new();
    match walk(domain, &mut lookup, &mut seen, &mut lookups, &mut hops) {
        Ok(all) => {
            let policy = if all.is_empty() {
                "neutral".to_string()
            } else {
                all
            };
            let noun = if lookups == 1 { "lookup" } else { "lookups" };
            Hit::new(
                "spf",
                Status::Confirmed,
                format!("SPF {policy}. {lookups} DNS {noun}"),
                Some(json!({"records": hops, "lookups": lookups, "limit": 10})),
            )
        }
        Err(problem) => {
            if problem.contains("has no SPF record") && hops.is_empty() {
                return Hit::new("spf", Status::Absent, "no SPF record", None);
            }
            let status = if problem.starts_with("temperror") {
                Status::Inconclusive
            } else {
                Status::Error
            };
            Hit::new(
                "spf",
                status,
                problem,
                Some(json!({"records": hops, "lookups": lookups, "limit": 10})),
            )
        }
    }
}

fn walk(
    domain: &str,
    lookup: &mut impl FnMut(&str) -> Result<Vec<String>, String>,
    seen: &mut HashSet<String>,
    lookups: &mut u32,
    hops: &mut Vec<Value>,
) -> Result<String, String> {
    if !seen.insert(domain.to_string()) {
        return Err(format!("permerror, SPF loop at {domain}"));
    }
    if !safe_dns_name(domain) {
        return Err(format!("permerror, refusing {domain}"));
    }
    let texts = lookup(domain).map_err(|e| format!("temperror, {e}"))?;
    let mut recs: Vec<SpfRec> = texts.iter().filter_map(|t| parse_spf(t)).collect();
    if recs.is_empty() {
        return Err(format!("permerror, {domain} has no SPF record"));
    }
    if recs.len() > 1 {
        return Err(format!("permerror, more than one SPF record at {domain}"));
    }
    let rec = recs.remove(0);
    hops.push(json!({
        "domain": domain,
        "raw": rec.raw,
        "all": rec.all,
        "redirect": rec.redirect,
        "includes": rec.includes,
    }));
    for _ in 0..rec.charged {
        *lookups += 1;
        if *lookups > 10 {
            return Err("permerror, more than 10 DNS lookups".into());
        }
    }
    for inc in &rec.includes {
        *lookups += 1;
        if *lookups > 10 {
            return Err("permerror, more than 10 DNS lookups".into());
        }
        walk(inc, lookup, seen, lookups, hops)?;
    }
    if !rec.all.is_empty() {
        return Ok(rec.all);
    }
    if !rec.redirect.is_empty() {
        *lookups += 1;
        if *lookups > 10 {
            return Err("permerror, more than 10 DNS lookups".into());
        }
        return walk(&rec.redirect, lookup, seen, lookups, hops);
    }
    Ok(String::new())
}

pub fn eval_dmarc(
    domain: &str,
    mut lookup: impl FnMut(&str) -> Result<Vec<String>, String>,
) -> Hit {
    let chain = org_chain(domain);
    for name in &chain {
        let q = format!("_dmarc.{name}");
        let texts = match lookup(&q) {
            Ok(t) => t,
            Err(e) => return Hit::new("dmarc", Status::Error, e, None),
        };
        let recs: Vec<BTreeMap<String, String>> = texts
            .iter()
            .map(|t| record_tags(t))
            .filter(|t| t.get("v").is_some_and(|v| v.eq_ignore_ascii_case("DMARC1")))
            .collect();
        if recs.is_empty() {
            continue;
        }
        if recs.len() > 1 {
            return Hit::new(
                "dmarc",
                Status::Error,
                format!("permerror, more than one DMARC record at {name}"),
                None,
            );
        }
        let p = recs[0]
            .get("p")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        if !matches!(p.as_str(), "none" | "quarantine" | "reject") {
            return Hit::new(
                "dmarc",
                Status::Inconclusive,
                format!("DMARC record at {name} has no usable p tag"),
                Some(json!({"name": name, "tags": recs[0]})),
            );
        }
        let mut summary = format!("p={p}");
        if let Some(sp) = recs[0].get("sp") {
            summary.push_str(&format!(" sp={}", sp.to_ascii_lowercase()));
        }
        if name != domain {
            summary.push_str(&format!(" inherited from {name}"));
        }
        return Hit::new(
            "dmarc",
            Status::Confirmed,
            summary,
            Some(json!({
                "name": name,
                "tags": recs[0],
                "organizational_domain": chain.last(),
            })),
        );
    }
    Hit::new(
        "dmarc",
        Status::Absent,
        "no DMARC record at this host or its organizational domain",
        Some(json!({"queried": chain.iter().map(|n| format!("_dmarc.{n}")).collect::<Vec<_>>()})),
    )
}

pub fn dkim_key_state(text: &str) -> Option<&'static str> {
    let low = text.to_ascii_lowercase();
    if !low.contains("v=dkim1") && !low.contains("p=") {
        return None;
    }
    let Some(i) = low.find("p=") else {
        return Some("present");
    };
    let mut rest = &low[i + 2..];
    if let Some(cut) = rest.find(';') {
        rest = &rest[..cut];
    }
    if rest.trim().is_empty() {
        Some("revoked")
    } else {
        Some("present")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct StsPolicy {
    pub mode: String,
    pub mx: Vec<String>,
}

pub fn parse_mta_sts(body: &str) -> Option<StsPolicy> {
    let mut version = String::new();
    let mut mode = String::new();
    let mut mx = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim().to_ascii_lowercase();
        match k.as_str() {
            "version" => version = v,
            "mode" => mode = v,
            "mx" if !v.is_empty() => mx.push(v),
            _ => {}
        }
    }
    if version != "stsv1" || !matches!(mode.as_str(), "enforce" | "testing" | "none") {
        return None;
    }
    Some(StsPolicy { mode, mx })
}

pub fn mx_matches_policy(host: &str, pattern: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suf) = pattern.strip_prefix("*.") {
        host == suf
            || (host.len() > suf.len() + 1
                && host.ends_with(suf)
                && host.as_bytes()[host.len() - suf.len() - 1] == b'.')
    } else {
        host == pattern
    }
}

/// Extra mail findings derived from records that were already collected.
/// `+all` and `?all` accept mail the domain did not list. `p=none` and an
/// MTA-STS testing mode publish a policy that does not enforce. BIMI without
/// a quarantine or reject DMARC policy will not display at large providers.
pub fn mail_gaps(spf: &Hit, dmarc: &Hit, mtasts: &Hit, bimi: &Hit) -> Vec<Hit> {
    let mut out = Vec::new();
    if spf.status == Status::Confirmed {
        let open = spf.summary.contains("+all") || spf.summary.contains("?all");
        if open {
            out.push(Hit::new(
                "spf-open",
                Status::Confirmed,
                "SPF ends in +all or ?all, so unlisted senders are not rejected",
                None,
            ));
        }
    }
    if dmarc.status == Status::Confirmed && dmarc.summary.contains("p=none") {
        out.push(Hit::new(
            "dmarc-none",
            Status::Confirmed,
            "DMARC p=none monitors mail and does not quarantine or reject",
            None,
        ));
    }
    let mode = mtasts
        .evidence
        .as_ref()
        .and_then(|v| v.get("mode"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if matches!(mode, "testing" | "none") {
        out.push(Hit::new(
            "mtasts-mode",
            Status::Confirmed,
            format!("MTA-STS mode is {mode}, so senders are not required to fail closed"),
            None,
        ));
    }
    let enforced = dmarc.summary.contains("p=reject") || dmarc.summary.contains("p=quarantine");
    if bimi.status == Status::Confirmed && !enforced {
        out.push(Hit::new(
            "bimi-dmarc",
            Status::Confirmed,
            "BIMI is published without a DMARC quarantine or reject policy",
            None,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txt_map(rows: &[(&str, &str)]) -> impl FnMut(&str) -> Result<Vec<String>, String> {
        let rows: Vec<(String, String)> = rows
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        move |name: &str| {
            Ok(rows
                .iter()
                .filter(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
                .collect())
        }
    }

    #[test]
    fn spf_fail_closed_and_lookup_cap() {
        let hit = eval_spf(
            "quad4.io",
            txt_map(&[("quad4.io", "v=spf1 include:_spf.example.com -all")]),
        );
        // include target has no record, so this is a permerror after one lookup
        assert_eq!(hit.status, Status::Error);
        assert!(hit.summary.contains("no SPF record"));

        let hit = eval_spf(
            "quad4.io",
            txt_map(&[
                ("quad4.io", "v=spf1 include:_spf.example.com -all"),
                ("_spf.example.com", "v=spf1 ip4:192.0.2.1 -all"),
            ]),
        );
        assert_eq!(hit.status, Status::Confirmed);
        assert!(hit.summary.starts_with("SPF -all"));
        assert!(hit.summary.contains("1 DNS lookup"));

        let mut includes = String::from("v=spf1");
        let mut rows = vec![("root.test".to_string(), String::new())];
        for i in 0..11 {
            let name = format!("i{i}.test");
            includes.push_str(&format!(" include:{name}"));
            rows.push((name, "v=spf1 -all".into()));
        }
        rows[0].1 = includes;
        let pairs: Vec<(String, String)> = rows.clone();
        let hit = eval_spf("root.test", move |name: &str| {
            Ok(pairs
                .iter()
                .filter(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
                .collect())
        });
        assert_eq!(hit.status, Status::Error);
        assert!(hit.summary.contains("more than 10"));
    }

    #[test]
    fn spf_absent_and_two_records() {
        let hit = eval_spf(
            "quad4.io",
            txt_map(&[("quad4.io", "google-site-verification=abc")]),
        );
        assert_eq!(hit.status, Status::Absent);
        let hit = eval_spf(
            "quad4.io",
            txt_map(&[("quad4.io", "v=spf1 -all"), ("quad4.io", "v=spf1 ~all")]),
        );
        assert!(hit.summary.contains("more than one"));
    }

    #[test]
    fn dmarc_inherits_organizational_domain() {
        let hit = eval_dmarc(
            "mail.example.co.uk",
            txt_map(&[("_dmarc.example.co.uk", "v=DMARC1; p=reject; sp=quarantine")]),
        );
        assert_eq!(hit.status, Status::Confirmed);
        assert!(hit.summary.contains("p=reject"));
        assert!(hit.summary.contains("inherited from example.co.uk"));

        let hit = eval_dmarc(
            "quad4.io",
            txt_map(&[("_dmarc.quad4.io", "v=DMARC1; p=none")]),
        );
        assert_eq!(hit.summary, "p=none");

        let hit = eval_dmarc("quad4.io", txt_map(&[]));
        assert_eq!(hit.status, Status::Absent);
    }

    #[test]
    fn dkim_and_sts() {
        assert_eq!(dkim_key_state("v=DKIM1; p=Zm9v"), Some("present"));
        assert_eq!(dkim_key_state("v=DKIM1; p="), Some("revoked"));
        assert_eq!(dkim_key_state("v=spf1 -all"), None);
        let p =
            parse_mta_sts("version: STSv1\nmode: enforce\nmx: *.messagingengine.com\n").unwrap();
        assert_eq!(p.mode, "enforce");
        assert!(mx_matches_policy(
            "in1-smtp.messagingengine.com",
            "*.messagingengine.com"
        ));
        assert!(!mx_matches_policy(
            "messagingengine.com.evil",
            "*.messagingengine.com"
        ));
        assert!(parse_mta_sts("version: STSv1\nmode: nope\n").is_none());
    }

    #[test]
    fn mail_gaps_flag_open_spf_and_monitor_only_dmarc() {
        let spf = Hit::new("spf", Status::Confirmed, "SPF +all. 1 DNS lookup", None);
        let dmarc = Hit::new("dmarc", Status::Confirmed, "p=none", None);
        let mtasts = Hit::new(
            "mtasts",
            Status::Confirmed,
            "mode=testing",
            Some(json!({"mode": "testing"})),
        );
        let bimi = Hit::new("bimi", Status::Confirmed, "BIMI logo published", None);
        let gaps = mail_gaps(&spf, &dmarc, &mtasts, &bimi);
        let mods: Vec<_> = gaps.iter().map(|h| h.module.as_str()).collect();
        assert!(mods.contains(&"spf-open"));
        assert!(mods.contains(&"dmarc-none"));
        assert!(mods.contains(&"mtasts-mode"));
        assert!(mods.contains(&"bimi-dmarc"));
        let tight = Hit::new("spf", Status::Confirmed, "SPF -all. 1 DNS lookup", None);
        let reject = Hit::new("dmarc", Status::Confirmed, "p=reject", None);
        let enforce = Hit::new(
            "mtasts",
            Status::Confirmed,
            "mode=enforce",
            Some(json!({"mode": "enforce"})),
        );
        assert!(mail_gaps(&tight, &reject, &enforce, &bimi).is_empty());
    }
}
