// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Open threat-intel lookups.
//! AlienVault OTX needs OTX_API_KEY. ThreatFox needs ABUSECH_AUTH_KEY.
//! Feodo Tracker is a public IP blocklist and needs no key.
//! Sample hashes and reporter notes are not kept.

use super::filehash::circl_body;
use super::name::{percent_encode, public_ip, validate_domain};
use super::net::Net;
use super::{Hit, Report, Status};
use serde_json::{Value, json};
use std::time::Instant;

pub fn scan(raw: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    let indicator = raw.trim().to_string();
    if indicator.is_empty() || indicator.len() > 512 {
        return Err("pass an IP, domain, URL, or file hash".into());
    }
    let kind = classify(&indicator)?;
    let net = Net::new();
    let (otx, fox, feodo, circl) = std::thread::scope(|s| {
        let otx = s.spawn(|| otx_lookup(&net, kind, &indicator));
        let fox = s.spawn(|| threatfox(&indicator));
        let feodo = s.spawn(|| {
            if kind == "ip" {
                feodo_lookup(&net, &indicator)
            } else {
                Hit::new(
                    "feodo",
                    Status::Absent,
                    "Feodo Tracker is an IP blocklist",
                    None,
                )
            }
        });
        let circl = s.spawn(|| {
            if kind == "hash" {
                hash_lookup(&net, &indicator)
            } else {
                Hit::new(
                    "circl",
                    Status::Absent,
                    "CIRCL hashlookup takes a file hash",
                    None,
                )
            }
        });
        (
            join(otx, "otx"),
            join(fox, "threatfox"),
            join(feodo, "feodo"),
            join(circl, "circl"),
        )
    });
    Ok(Report {
        target: indicator,
        kind: "intel",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings: vec![
            Hit::new("kind", Status::Confirmed, kind.to_string(), None),
            otx,
            fox,
            feodo,
            circl,
        ],
    })
}

fn join(h: std::thread::ScopedJoinHandle<Hit>, module: &str) -> Hit {
    h.join()
        .unwrap_or_else(|_| Hit::new(module, Status::Error, "lookup panicked", None))
}

fn classify(raw: &str) -> Result<&'static str, String> {
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Ok("url");
    }
    if public_ip(raw) || raw.parse::<std::net::IpAddr>().is_ok() {
        if !public_ip(raw) {
            return Err("refusing a local or private address".into());
        }
        return Ok("ip");
    }
    if matches!(lower.len(), 32 | 40 | 64) && lower.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok("hash");
    }
    validate_domain(&lower)?;
    Ok("domain")
}

fn otx_lookup(net: &Net, kind: &str, indicator: &str) -> Hit {
    let key = std::env::var("OTX_API_KEY").unwrap_or_default();
    if key.is_empty() {
        return Hit::new("otx", Status::Inconclusive, "OTX_API_KEY is not set", None);
    }
    let (section, value) = match kind {
        "ip" => ("IPv4", indicator.to_string()),
        "domain" => ("hostname", indicator.to_string()),
        "url" => ("url", percent_encode(indicator)),
        "hash" => {
            let algo = match indicator.len() {
                32 => "MD5",
                40 => "SHA1",
                _ => "SHA256",
            };
            (algo, indicator.to_ascii_lowercase())
        }
        _ => ("hostname", indicator.to_string()),
    };
    let url = format!("https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general");
    match net.get(&url, &[("X-OTX-API-KEY", &key)]) {
        Err(e) => Hit::new("otx", Status::Error, e, None),
        Ok(r) => otx_body(r.status, &r.body),
    }
}

pub(crate) fn otx_body(status: u16, body: &str) -> Hit {
    if status == 401 || status == 403 {
        return Hit::new("otx", Status::Error, "OTX rejected the API key", None);
    }
    if status != 200 {
        return Hit::new("otx", Status::Error, format!("OTX HTTP {status}"), None);
    }
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return Hit::new("otx", Status::Error, "OTX response was not JSON", None),
    };
    let pulses = v
        .get("pulse_info")
        .and_then(|p| p.get("count"))
        .and_then(|n| n.as_i64())
        .unwrap_or(0);
    if pulses <= 0 {
        return Hit::new("otx", Status::Absent, "no OTX pulses", None);
    }
    Hit::new(
        "otx",
        Status::Confirmed,
        format!("{pulses} OTX pulse(s)"),
        Some(json!({"pulses": pulses})),
    )
}

fn threatfox(indicator: &str) -> Hit {
    let key = std::env::var("ABUSECH_AUTH_KEY").unwrap_or_default();
    if key.is_empty() {
        return Hit::new(
            "threatfox",
            Status::Inconclusive,
            "ABUSECH_AUTH_KEY is not set",
            None,
        );
    }
    let config = ureq::config::Config::builder()
        .timeout_global(Some(std::time::Duration::from_secs(6)))
        .http_status_as_error(false)
        .user_agent(concat!("argus/", env!("CARGO_PKG_VERSION")))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let body = json!({
        "query": "search_ioc",
        "search_term": indicator,
        "exact_match": true
    })
    .to_string();
    let mut resp = match agent
        .post("https://threatfox-api.abuse.ch/api/v1/")
        .header("Auth-Key", &key)
        .header("Content-Type", "application/json")
        .send(&body)
    {
        Ok(r) => r,
        Err(e) => return Hit::new("threatfox", Status::Error, e.to_string(), None),
    };
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    threatfox_body(status, &text)
}

pub(crate) fn threatfox_body(status: u16, body: &str) -> Hit {
    if status == 401 || status == 403 {
        return Hit::new(
            "threatfox",
            Status::Error,
            "abuse.ch rejected the API key",
            None,
        );
    }
    if status != 200 {
        return Hit::new(
            "threatfox",
            Status::Error,
            format!("threatfox HTTP {status}"),
            None,
        );
    }
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return Hit::new(
                "threatfox",
                Status::Error,
                "threatfox response was not JSON",
                None,
            );
        }
    };
    let query = v.get("query_status").and_then(|s| s.as_str()).unwrap_or("");
    if query != "ok" {
        return Hit::new("threatfox", Status::Absent, "not in ThreatFox", None);
    }
    let rows = v.get("data").and_then(|d| d.as_array());
    let Some(rows) = rows else {
        return Hit::new("threatfox", Status::Absent, "not in ThreatFox", None);
    };
    let names: Vec<String> = rows
        .iter()
        .take(5)
        .map(|row| {
            row.get("malware_printable")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_string()
        })
        .collect();
    if names.is_empty() {
        return Hit::new("threatfox", Status::Absent, "not in ThreatFox", None);
    }
    Hit::new(
        "threatfox",
        Status::Confirmed,
        format!("ThreatFox: {}", names.join(", ")),
        Some(json!({"malware": names})),
    )
}

fn feodo_lookup(net: &Net, ip: &str) -> Hit {
    let url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";
    match net.get(url, &[("Accept", "application/json")]) {
        Err(e) => Hit::new("feodo", Status::Error, e, None),
        Ok(r) => feodo_body(ip, r.status, &r.body),
    }
}

pub(crate) fn feodo_body(ip: &str, status: u16, body: &str) -> Hit {
    if status != 200 {
        return Hit::new("feodo", Status::Error, format!("feodo HTTP {status}"), None);
    }
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return Hit::new("feodo", Status::Error, "feodo response was not JSON", None),
    };
    let rows = v
        .as_array()
        .or_else(|| v.get("data").and_then(|d| d.as_array()));
    let Some(rows) = rows else {
        return Hit::new(
            "feodo",
            Status::Inconclusive,
            "feodo list had no rows",
            None,
        );
    };
    for row in rows {
        let addr = row.get("ip_address").and_then(|s| s.as_str()).unwrap_or("");
        if addr == ip {
            let malware = row.get("malware").and_then(|s| s.as_str()).unwrap_or("");
            let summary = if malware.is_empty() {
                "listed on the Feodo Tracker blocklist".into()
            } else {
                format!("Feodo Tracker lists {malware}")
            };
            return Hit::new(
                "feodo",
                Status::Confirmed,
                summary,
                Some(json!({"malware": malware})),
            );
        }
    }
    Hit::new(
        "feodo",
        Status::Absent,
        "not on the Feodo Tracker blocklist",
        None,
    )
}

fn hash_lookup(net: &Net, hash: &str) -> Hit {
    let algo = match hash.len() {
        32 => "md5",
        40 => "sha1",
        _ => "sha256",
    };
    let url = format!(
        "https://hashlookup.circl.lu/lookup/{algo}/{}",
        hash.to_ascii_lowercase()
    );
    match net.get(&url, &[("Accept", "application/json")]) {
        Err(e) => Hit::new("circl", Status::Error, e, None),
        Ok(r) => circl_body(r.status, &r.body),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otx_and_threatfox_and_feodo_read_the_public_fields() {
        let otx = otx_body(200, r#"{"pulse_info":{"count":2}}"#);
        assert_eq!(otx.status, Status::Confirmed);
        assert!(otx.summary.contains("2"));
        assert_eq!(
            otx_body(200, r#"{"pulse_info":{"count":0}}"#).status,
            Status::Absent
        );
        let fox = threatfox_body(
            200,
            r#"{"query_status":"ok","data":[{"malware_printable":"Cobalt Strike","malware_samples":[{"sha256_hash":"abcd"}]}]}"#,
        );
        let raw = serde_json::to_string(&fox).unwrap();
        assert!(raw.contains("Cobalt Strike"));
        assert!(!raw.contains("abcd"));
        let list = r#"[{"ip_address":"203.0.113.10","malware":"Dridex"}]"#;
        assert_eq!(
            feodo_body("203.0.113.10", 200, list).status,
            Status::Confirmed
        );
        assert_eq!(feodo_body("203.0.113.11", 200, list).status, Status::Absent);
    }
}
