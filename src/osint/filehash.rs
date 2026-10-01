// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Public file-hash lookup.
//! CIRCL hashlookup needs no key. MalwareBazaar runs when ABUSECH_AUTH_KEY is set.
//! The hash is not sent anywhere else, and no sample is downloaded.

use super::net::Net;
use super::{Hit, Report, Status};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

pub fn scan(raw: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    let hash = raw.trim().to_ascii_lowercase();
    let algo = match hash.len() {
        32 => "md5",
        40 => "sha1",
        64 => "sha256",
        _ => return Err("pass an MD5, SHA-1, or SHA-256 hex digest".into()),
    };
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("digest is not hex".into());
    }
    let net = Net::new();
    let (known, bazaar) = std::thread::scope(|s| {
        let known = s.spawn(|| circl(&net, algo, &hash));
        let bazaar = s.spawn(|| malwarebazaar(&hash));
        (
            known
                .join()
                .unwrap_or_else(|_| Hit::new("circl", Status::Error, "lookup panicked", None)),
            bazaar.join().unwrap_or_else(|_| {
                Hit::new("malwarebazaar", Status::Error, "lookup panicked", None)
            }),
        )
    });
    Ok(Report {
        target: hash,
        kind: "hash",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings: vec![
            Hit::new("syntax", Status::Confirmed, algo.to_string(), None),
            known,
            bazaar,
        ],
    })
}

fn circl(net: &Net, algo: &str, hash: &str) -> Hit {
    let url = format!("https://hashlookup.circl.lu/lookup/{algo}/{hash}");
    match net.get(&url, &[("Accept", "application/json")]) {
        Err(e) => Hit::new("circl", Status::Error, e, None),
        Ok(r) => circl_body(r.status, &r.body),
    }
}

pub(crate) fn circl_body(status: u16, body: &str) -> Hit {
    if status == 404 {
        return Hit::new(
            "circl",
            Status::Absent,
            "not in the CIRCL hashlookup index",
            None,
        );
    }
    if status != 200 {
        return Hit::new(
            "circl",
            Status::Error,
            format!("hashlookup HTTP {status}"),
            None,
        );
    }
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return Hit::new(
                "circl",
                Status::Error,
                "hashlookup response was not JSON",
                None,
            );
        }
    };
    let name = v
        .get("FileName")
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    let malicious = match v.get("KnownMalicious") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|i| i.as_str())
            .take(4)
            .collect::<Vec<_>>()
            .join(", "),
        _ => String::new(),
    };
    let summary = if name.is_empty() && malicious.is_empty() {
        "known file in CIRCL hashlookup".to_string()
    } else if malicious.is_empty() {
        format!("known file {name}")
    } else if name.is_empty() {
        format!("listed by {malicious}")
    } else {
        format!("known file {name}, also listed by {malicious}")
    };
    Hit::new(
        "circl",
        Status::Confirmed,
        summary,
        Some(json!({"file": name, "known_malicious": malicious})),
    )
}

fn malwarebazaar(hash: &str) -> Hit {
    let key = std::env::var("ABUSECH_AUTH_KEY").unwrap_or_default();
    if key.is_empty() {
        return Hit::new(
            "malwarebazaar",
            Status::Inconclusive,
            "ABUSECH_AUTH_KEY is not set",
            None,
        );
    }
    let config = ureq::config::Config::builder()
        .timeout_global(Some(Duration::from_secs(6)))
        .http_status_as_error(false)
        .user_agent(concat!("argus/", env!("CARGO_PKG_VERSION")))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let body = format!("query=get_info&hash={hash}");
    let mut resp = match agent
        .post("https://mb-api.abuse.ch/api/v1/")
        .header("Auth-Key", &key)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(&body)
    {
        Ok(r) => r,
        Err(e) => return Hit::new("malwarebazaar", Status::Error, e.to_string(), None),
    };
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    bazaar_body(status, &text)
}

pub(crate) fn bazaar_body(status: u16, body: &str) -> Hit {
    if status == 401 || status == 403 {
        return Hit::new(
            "malwarebazaar",
            Status::Error,
            "abuse.ch rejected the API key",
            None,
        );
    }
    if status != 200 {
        return Hit::new(
            "malwarebazaar",
            Status::Error,
            format!("malwarebazaar HTTP {status}"),
            None,
        );
    }
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            return Hit::new(
                "malwarebazaar",
                Status::Error,
                "malwarebazaar response was not JSON",
                None,
            );
        }
    };
    let query = v.get("query_status").and_then(|s| s.as_str()).unwrap_or("");
    if query == "hash_not_found" {
        return Hit::new(
            "malwarebazaar",
            Status::Absent,
            "not in MalwareBazaar",
            None,
        );
    }
    if query != "ok" {
        return Hit::new(
            "malwarebazaar",
            Status::Inconclusive,
            if query.is_empty() {
                "malwarebazaar returned no status".into()
            } else {
                format!("malwarebazaar status {query}")
            },
            None,
        );
    }
    let row = v
        .get("data")
        .and_then(|d| d.as_array())
        .and_then(|a| a.first());
    let signature = row
        .and_then(|r| r.get("signature"))
        .and_then(|s| s.as_str())
        .unwrap_or("");
    let file_type = row
        .and_then(|r| r.get("file_type"))
        .and_then(|s| s.as_str())
        .unwrap_or("");
    let summary = if signature.is_empty() {
        "listed in MalwareBazaar".to_string()
    } else {
        format!("MalwareBazaar signature {signature}")
    };
    Hit::new(
        "malwarebazaar",
        Status::Confirmed,
        summary,
        Some(json!({"signature": signature, "file_type": file_type})),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circl_names_the_file_and_a_miss_is_absent() {
        let hit = circl_body(
            200,
            r#"{"FileName":"eicar.com","KnownMalicious":"malshare.com","SHA-256":"abc"}"#,
        );
        assert_eq!(hit.status, Status::Confirmed);
        assert!(hit.summary.contains("eicar.com"));
        assert!(hit.summary.contains("malshare.com"));
        assert_eq!(circl_body(404, "{}").status, Status::Absent);
    }

    #[test]
    fn bazaar_does_not_keep_a_sample() {
        let hit = bazaar_body(
            200,
            r#"{"query_status":"ok","data":[{"signature":"EICAR","file_type":"txt","file_content":"nope"}]}"#,
        );
        let raw = serde_json::to_string(&hit).unwrap();
        assert!(raw.contains("EICAR"));
        assert!(!raw.contains("nope"));
        assert_eq!(
            bazaar_body(200, r#"{"query_status":"hash_not_found"}"#).status,
            Status::Absent
        );
    }
}
