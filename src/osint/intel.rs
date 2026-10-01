// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Free public intel feeds.
//! Hudson Rock's complimentary index, urlscan, Shodan InternetDB, and ipwho.is.
//! Passwords, cookies, and infected machine names are not kept.

use super::name::percent_encode;
use super::net::Net;
use super::{Hit, Status};
use serde_json::{Value, json};

const ROCK: &str = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools";

pub fn hudson_domain(net: &Net, domain: &str) -> Hit {
    let url = format!("{ROCK}/search-by-domain?domain={}", percent_encode(domain));
    fetch("hudsonrock", net, &url, hudson_domain_body)
}

pub fn hudson_email(net: &Net, email: &str) -> Hit {
    let url = format!("{ROCK}/search-by-email?email={}", percent_encode(email));
    fetch("hudsonrock", net, &url, hudson_account_body)
}

pub fn hudson_ip(net: &Net, ip: &str) -> Hit {
    let url = format!("{ROCK}/search-by-ip?ip={}", percent_encode(ip));
    fetch("hudsonrock", net, &url, hudson_account_body)
}

pub fn urlscan(net: &Net, domain: &str) -> Hit {
    let q = percent_encode(&format!("domain:{domain}"));
    let url = format!("https://urlscan.io/api/v1/search/?q={q}&size=5");
    fetch("urlscan", net, &url, urlscan_body)
}

pub fn internetdb(net: &Net, ip: &str) -> Hit {
    let url = format!("https://internetdb.shodan.io/{}", percent_encode(ip));
    match net.get(&url, &[("Accept", "application/json")]) {
        Err(e) => Hit::new("internetdb", Status::Error, e, None),
        Ok(r) if r.status == 404 => Hit::new(
            "internetdb",
            Status::Absent,
            "not in Shodan InternetDB",
            None,
        ),
        Ok(r) if r.status != 200 => Hit::new(
            "internetdb",
            Status::Error,
            format!("internetdb HTTP {}", r.status),
            None,
        ),
        Ok(r) => internetdb_body(&r.body),
    }
}

pub fn geo_online(net: &Net, ip: &str) -> Hit {
    let url = format!("https://ipwho.is/{}", percent_encode(ip));
    fetch("geo", net, &url, ipwho_body)
}

fn fetch(module: &str, net: &Net, url: &str, parse: fn(&str) -> Hit) -> Hit {
    match net.get(url, &[("Accept", "application/json")]) {
        Err(e) => Hit::new(module, Status::Error, e, None),
        Ok(r) if r.status != 200 => Hit::new(
            module,
            Status::Error,
            format!("{module} HTTP {}", r.status),
            None,
        ),
        Ok(r) => parse(&r.body),
    }
}

pub(crate) fn hudson_domain_body(body: &str) -> Hit {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) if body.len() >= 512 * 1024 => {
            return counts_only(body);
        }
        Err(_) => {
            return Hit::new(
                "hudsonrock",
                Status::Error,
                "Hudson Rock response was not JSON",
                None,
            );
        }
    };
    let employees = num(&v, "employees");
    let users = num(&v, "users");
    let third = num(&v, "third_parties");
    let urls = num(&v, "totalUrls");
    let samples = url_samples(&v);
    domain_hit(employees, users, third, urls, samples)
}

fn counts_only(body: &str) -> Hit {
    let employees = loose_num(body, "employees").unwrap_or(0);
    let users = loose_num(body, "users").unwrap_or(0);
    let third = loose_num(body, "third_parties").unwrap_or(0);
    let urls = loose_num(body, "totalUrls").unwrap_or(0);
    let mut hit = domain_hit(employees, users, third, urls, Vec::new());
    if let Some(ev) = hit.evidence.as_mut() {
        ev["truncated"] = json!(true);
    }
    hit
}

fn domain_hit(employees: i64, users: i64, third: i64, urls: i64, samples: Vec<String>) -> Hit {
    let evidence = json!({
        "employees": employees,
        "users": users,
        "third_parties": third,
        "urls": urls,
        "samples": samples,
    });
    if employees == 0 && users == 0 && third == 0 && urls == 0 {
        Hit::new(
            "hudsonrock",
            Status::Absent,
            "no infostealer exposure in the Hudson Rock free index",
            Some(evidence),
        )
    } else {
        Hit::new(
            "hudsonrock",
            Status::Confirmed,
            format!(
                "{employees} employee exposure(s), {users} user exposure(s), {third} third parties"
            ),
            Some(evidence),
        )
    }
}

pub(crate) fn hudson_account_body(body: &str) -> Hit {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return Hit::new(
                "hudsonrock",
                Status::Error,
                "Hudson Rock response was not JSON",
                None,
            );
        }
    };
    let rows = v.get("stealers").and_then(|s| s.as_array());
    let n = rows.map(|a| a.len()).unwrap_or(0);
    let corporate = num(&v, "total_corporate_services");
    let user_services = num(&v, "total_user_services");
    let kept: Vec<Value> = rows
        .map(|arr| {
            arr.iter()
                .take(5)
                .map(|row| {
                    json!({
                        "date_compromised": row.get("date_compromised").and_then(|d| d.as_str()).unwrap_or(""),
                        "operating_system": row.get("operating_system").and_then(|d| d.as_str()).unwrap_or(""),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let evidence = json!({
        "stealers": n,
        "corporate_services": corporate,
        "user_services": user_services,
        "records": kept,
    });
    if n == 0 && corporate == 0 && user_services == 0 {
        Hit::new(
            "hudsonrock",
            Status::Absent,
            "no infostealer exposure in the Hudson Rock free index",
            Some(evidence),
        )
    } else {
        Hit::new(
            "hudsonrock",
            Status::Confirmed,
            format!("{n} infostealer record(s), {corporate} corporate service(s)"),
            Some(evidence),
        )
    }
}

pub(crate) fn urlscan_body(body: &str) -> Hit {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return Hit::new(
                "urlscan",
                Status::Error,
                "urlscan response was not JSON",
                None,
            );
        }
    };
    let total = num(&v, "total");
    let rows: Vec<Value> = v
        .get("results")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .take(5)
                .map(|row| {
                    json!({
                        "url": row.get("task").and_then(|t| t.get("url")).and_then(|u| u.as_str()).unwrap_or(""),
                        "time": row.get("task").and_then(|t| t.get("time")).and_then(|u| u.as_str()).unwrap_or(""),
                        "title": row.get("page").and_then(|t| t.get("title")).and_then(|u| u.as_str()).unwrap_or(""),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    if total == 0 {
        Hit::new(
            "urlscan",
            Status::Absent,
            "no public urlscan results",
            Some(json!({"total": 0})),
        )
    } else {
        Hit::new(
            "urlscan",
            Status::Confirmed,
            format!("{total} public urlscan result(s)"),
            Some(json!({"total": total, "results": rows})),
        )
    }
}

pub(crate) fn internetdb_body(body: &str) -> Hit {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return Hit::new(
                "internetdb",
                Status::Error,
                "InternetDB response was not JSON",
                None,
            );
        }
    };
    let ports = i64_list(v.get("ports"), 20);
    let vulns = str_list(v.get("vulns"), 20);
    let tags = str_list(v.get("tags"), 8);
    let hostnames = str_list(v.get("hostnames"), 8);
    let cpes = str_list(v.get("cpes"), 8);
    let summary = if ports.is_empty() {
        "listed, no open ports".to_string()
    } else {
        format!("{} open port(s) in Shodan InternetDB", ports.len())
    };
    Hit::new(
        "internetdb",
        Status::Confirmed,
        summary,
        Some(json!({
            "ports": ports,
            "vulns": vulns,
            "tags": tags,
            "hostnames": hostnames,
            "cpes": cpes,
        })),
    )
}

pub(crate) fn ipwho_body(body: &str) -> Hit {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return Hit::new("geo", Status::Error, "ipwho.is response was not JSON", None),
    };
    if v.get("success").and_then(|s| s.as_bool()) == Some(false) {
        let msg = v
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("ipwho.is refused this address");
        return Hit::new("geo", Status::Error, msg, None);
    }
    geo_hit("geo", "ipwho.is", &v, false)
}

pub(crate) fn geo_hit(module: &str, source: &str, v: &Value, nested: bool) -> Hit {
    let country = text(v, "country");
    let region = text(v, "region");
    let city = text(v, "city");
    let code = text(v, "country_code");
    let mut parts = Vec::new();
    for p in [&city, &region, &country] {
        if !p.is_empty() && !parts.iter().any(|have: &String| have == p) {
            parts.push(p.clone());
        }
    }
    let label = if source.starts_with("DB-IP") {
        "DB-IP.com City Lite"
    } else {
        source
    };
    let summary = if parts.is_empty() {
        format!("geolocation from {label}")
    } else {
        format!("{} ({label})", parts.join(", "))
    };
    let tz = if nested {
        text(v, "timezone")
    } else {
        v.get("timezone")
            .and_then(|t| t.get("id"))
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string()
    };
    let (asn, org) = if nested {
        (None, String::new())
    } else {
        (
            v.get("connection")
                .and_then(|c| c.get("asn"))
                .and_then(|n| n.as_i64()),
            v.get("connection")
                .and_then(|c| c.get("org"))
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string(),
        )
    };
    Hit::new(
        module,
        Status::Confirmed,
        summary,
        Some(json!({
            "source": source,
            "country": country,
            "country_code": code,
            "region": region,
            "city": city,
            "latitude": v.get("latitude").cloned().unwrap_or(Value::Null),
            "longitude": v.get("longitude").cloned().unwrap_or(Value::Null),
            "timezone": tz,
            "asn": asn,
            "org": org,
        })),
    )
}

fn num(v: &Value, key: &str) -> i64 {
    v.get(key).and_then(|n| n.as_i64()).unwrap_or(0)
}

fn loose_num(body: &str, key: &str) -> Option<i64> {
    let pat = format!("\"{key}\":");
    let i = body.find(&pat)?;
    let rest = body[i + pat.len()..].trim_start();
    let digits: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    digits.parse().ok()
}

fn text(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .trim()
        .to_string()
}

fn url_samples(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_urls(v.get("data"), &mut out);
    out
}

fn collect_urls(v: Option<&Value>, out: &mut Vec<String>) {
    let Some(v) = v else { return };
    match v {
        Value::String(s) => {
            let bare = s.split(['?', '#']).next().unwrap_or(s).trim();
            if bare.contains("://") && !out.iter().any(|have| have == bare) {
                out.push(bare.chars().take(180).collect());
            }
        }
        Value::Array(items) => {
            for item in items {
                if out.len() == 8 {
                    return;
                }
                collect_urls(Some(item), out);
            }
        }
        Value::Object(map) => {
            for val in map.values() {
                if out.len() == 8 {
                    return;
                }
                collect_urls(Some(val), out);
            }
        }
        _ => {}
    }
}

fn str_list(v: Option<&Value>, cap: usize) -> Vec<String> {
    v.and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .take(cap)
                .collect()
        })
        .unwrap_or_default()
}

fn i64_list(v: Option<&Value>, cap: usize) -> Vec<i64> {
    v.and_then(|x| x.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_i64()).take(cap).collect())
        .unwrap_or_default()
}

pub fn asn(net: &Net, ip: &str) -> Hit {
    let url = format!(
        "https://stat.ripe.net/data/prefix-overview/data.json?resource={}",
        percent_encode(ip)
    );
    fetch("asn", net, &url, asn_body)
}

pub fn vpn(net: &Net, ip: &str) -> Hit {
    let url = format!(
        "https://proxycheck.io/v2/{}?vpn=1&asn=1",
        percent_encode(ip)
    );
    fetch("vpn", net, &url, vpn_body)
}

pub(crate) fn asn_body(body: &str) -> Hit {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return Hit::new("asn", Status::Error, "RIPEstat response was not JSON", None),
    };
    let data = v.get("data");
    let prefix = data
        .and_then(|d| d.get("resource"))
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    let asn = data
        .and_then(|d| d.get("asns"))
        .and_then(|a| a.as_array())
        .and_then(|a| a.first());
    let number = asn.and_then(|a| a.get("asn")).and_then(|n| n.as_i64());
    let holder = asn
        .and_then(|a| a.get("holder"))
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    let Some(number) = number else {
        return Hit::new(
            "asn",
            Status::Inconclusive,
            "RIPEstat returned no origin AS",
            Some(json!({"prefix": prefix})),
        );
    };
    let summary = if holder.is_empty() {
        format!("AS{number} {prefix}")
    } else {
        format!("AS{number} {holder}, {prefix}")
    };
    Hit::new(
        "asn",
        Status::Confirmed,
        summary,
        Some(json!({"asn": number, "holder": holder, "prefix": prefix})),
    )
}

pub(crate) fn vpn_body(body: &str) -> Hit {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return Hit::new(
                "vpn",
                Status::Error,
                "proxycheck response was not JSON",
                None,
            );
        }
    };
    let row = v.as_object().and_then(|m| {
        m.iter()
            .find(|(k, _)| k.as_str() != "status")
            .map(|(_, val)| val)
    });
    let Some(row) = row else {
        return Hit::new("vpn", Status::Error, "proxycheck returned no address", None);
    };
    let proxy = row.get("proxy").and_then(|p| p.as_str()).unwrap_or("");
    let kind = row.get("type").and_then(|p| p.as_str()).unwrap_or("");
    let provider = row.get("provider").and_then(|p| p.as_str()).unwrap_or("");
    let evidence =
        json!({"proxy": proxy, "type": kind, "provider": provider, "source": "proxycheck.io"});
    if proxy.eq_ignore_ascii_case("yes") {
        let label = if kind.is_empty() { "proxy" } else { kind };
        Hit::new(
            "vpn",
            Status::Confirmed,
            format!("proxycheck.io classifies this address as {label}"),
            Some(evidence),
        )
    } else if proxy.eq_ignore_ascii_case("no") {
        Hit::new(
            "vpn",
            Status::Absent,
            "proxycheck.io does not classify this address as a proxy or VPN",
            Some(evidence),
        )
    } else {
        Hit::new(
            "vpn",
            Status::Inconclusive,
            "proxycheck.io did not say whether this address is a proxy",
            Some(evidence),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hudson_domain_miss_ignores_the_global_corpus() {
        let body = r#"{"total":0,"totalStealers":36631606,"employees":0,"users":0,"third_parties":0,"logo":"https://cdn.example/x","data":{"employees_urls":[]},"totalUrls":0}"#;
        let hit = hudson_domain_body(body);
        assert_eq!(hit.status, Status::Absent);
        assert!(!hit.summary.contains("36631606"));
        assert!(!hit.summary.contains("logo"));
    }

    #[test]
    fn hudson_account_drops_secrets() {
        let body = r#"{"stealers":[{"date_compromised":"2024-01-02","operating_system":"Windows 10","password":"nope","computer_name":"DESKTOP"}],"total_corporate_services":1,"total_user_services":2}"#;
        let hit = hudson_account_body(body);
        assert_eq!(hit.status, Status::Confirmed);
        let raw = serde_json::to_string(&hit).unwrap();
        assert!(raw.contains("2024-01-02"));
        assert!(!raw.contains("nope"));
        assert!(!raw.contains("DESKTOP"));
        assert!(!raw.contains("password"));
    }

    #[test]
    fn url_samples_drop_query_strings() {
        let body = r#"{"employees":1,"users":0,"third_parties":0,"totalUrls":1,"data":{"employees_urls":["https://quad4.io/login?token=secret"]}}"#;
        let hit = hudson_domain_body(body);
        let raw = serde_json::to_string(&hit).unwrap();
        assert!(raw.contains("https://quad4.io/login"));
        assert!(!raw.contains("secret"));
    }

    #[test]
    fn urlscan_and_internetdb_and_ipwho() {
        assert_eq!(
            urlscan_body(r#"{"results":[],"total":0}"#).status,
            Status::Absent
        );
        let scan = urlscan_body(
            r#"{"total":2,"results":[{"task":{"url":"https://quad4.io/","time":"2026-01-01"},"page":{"title":"Quad4"}}]}"#,
        );
        assert_eq!(scan.status, Status::Confirmed);
        let db = internetdb_body(
            r#"{"ports":[80,443],"hostnames":["a.example"],"tags":[],"vulns":[],"cpes":[]}"#,
        );
        assert!(db.summary.contains("2 open port"));
        let geo = ipwho_body(
            r#"{"success":true,"country":"United States","country_code":"US","region":"New York","city":"New York City","latitude":1.0,"longitude":2.0,"timezone":{"id":"America/New_York"},"connection":{"asn":64496,"org":"Example Host"}}"#,
        );
        assert_eq!(geo.status, Status::Confirmed);
        assert!(geo.summary.contains("United States"));
    }

    #[test]
    fn asn_and_vpn_read_the_public_fields() {
        let asn = asn_body(
            r#"{"data":{"resource":"203.0.113.0/24","asns":[{"asn":64496,"holder":"EXAMPLE-AS"}]}}"#,
        );
        assert_eq!(asn.status, Status::Confirmed);
        assert!(asn.summary.contains("AS64496"));
        assert!(asn.summary.contains("203.0.113.0/24"));
        let yes = vpn_body(
            r#"{"status":"ok","203.0.113.10":{"proxy":"yes","type":"VPN","provider":"Example Host"}}"#,
        );
        assert_eq!(yes.status, Status::Confirmed);
        assert!(yes.summary.contains("VPN"));
        let no = vpn_body(
            r#"{"status":"ok","1.1.1.1":{"proxy":"no","type":"Business","provider":"Cloudflare, Inc."}}"#,
        );
        assert_eq!(no.status, Status::Absent);
    }
}
