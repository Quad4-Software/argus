// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Keybase profile, identity proofs, and the public device list.
//! The lookup API needs no key. Device records come from the account
//! sigchain, so old machines, phones, and paper keys show up next to
//! the current ones. A username hit is a lead, not proof of identity.

use super::siteurl::fetch_public;
use super::{Hit, Report, Status};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::Instant;

pub fn scan(name: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    let name = name.trim();
    if !valid_name(name) {
        return Err("keybase username must be 2-32 letters, digits, or underscore".into());
    }
    let url = format!(
        "https://keybase.io/_/api/1.0/user/lookup.json?username={name}&fields=basics,profile,pictures,proofs_summary,devices"
    );
    let (status, _, _, body) = fetch_public(&url)?;
    if status != 200 {
        return Err(format!("keybase lookup HTTP {status}"));
    }
    let doc: Value = serde_json::from_str(&body).map_err(|e| format!("keybase json: {e}"))?;
    let code = doc["status"]["code"].as_i64().unwrap_or(-1);
    let them = &doc["them"];
    let findings = if code == 205 || them.is_null() {
        vec![Hit::new(
            "profile",
            Status::Absent,
            format!("no keybase account named {name}"),
            None,
        )]
    } else if code != 0 {
        let desc = doc["status"]["desc"].as_str().unwrap_or("unknown");
        return Err(format!("keybase lookup status {code}: {desc}"));
    } else {
        findings(them)
    };
    Ok(Report {
        target: name.to_string(),
        kind: "keybase",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

fn valid_name(name: &str) -> bool {
    (2..=32).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn findings(them: &Value) -> Vec<Hit> {
    let mut out = vec![profile_hit(them)];
    out.extend(proof_hits(them));
    out.extend(device_hits(them));
    out
}

fn profile_hit(them: &Value) -> Hit {
    let basics = &them["basics"];
    let profile = &them["profile"];
    let username = text(&basics["username"]);
    let full_name = text(&profile["full_name"]);
    let summary = if full_name.is_empty() {
        username.clone()
    } else {
        format!("{username} ({full_name})")
    };
    Hit::new(
        "profile",
        Status::Confirmed,
        summary,
        Some(json!({
            "uid": text(&them["id"]),
            "username": username,
            "full_name": full_name,
            "location": text(&profile["location"]),
            "bio": text(&profile["bio"]),
            "created": iso(basics["ctime"].as_u64()),
            "updated": iso(basics["mtime"].as_u64()),
            "avatar": text(&them["pictures"]["primary"]["url"]),
        })),
    )
}

fn proof_hits(them: &Value) -> Vec<Hit> {
    let mut proofs = Vec::new();
    if let Some(groups) = them["proofs_summary"]["by_presentation_group"].as_object() {
        for (platform, list) in groups {
            for p in list.as_array().into_iter().flatten() {
                proofs.push(json!({
                    "platform": platform,
                    "nametag": text(&p["nametag"]),
                    "state": proof_state(p["state"].as_i64().unwrap_or(0)),
                    "url": text(&p["service_url"]),
                    "proof": text(&p["human_url"]),
                }));
            }
        }
    }
    let valid = proofs
        .iter()
        .filter(|p| p["state"].as_str() == Some("ok"))
        .count();
    let mut out = Vec::new();
    if proofs.is_empty() {
        out.push(Hit::new(
            "proofs",
            Status::Absent,
            "no public identity proofs",
            None,
        ));
        return out;
    }
    out.push(Hit::new(
        "proofs",
        Status::Confirmed,
        format!("{valid}/{} proof(s) valid", proofs.len()),
        Some(json!({"links": proofs})),
    ));
    for p in &proofs {
        let platform = p["platform"].as_str().unwrap_or("proof");
        let nametag = p["nametag"].as_str().unwrap_or("");
        let state = p["state"].as_str().unwrap_or("");
        out.push(Hit::new(
            platform,
            Status::Confirmed,
            format!("{nametag} ({state})"),
            Some(p.clone()),
        ));
    }
    out
}

fn device_hits(them: &Value) -> Vec<Hit> {
    let mut devices: Vec<(u64, Value)> = Vec::new();
    if let Some(map) = them["devices"].as_object() {
        for (id, d) in map {
            let ctime = d["ctime"].as_u64().unwrap_or(0);
            devices.push((
                ctime,
                json!({
                    "id": id,
                    "name": text(&d["name"]),
                    "type": text(&d["type"]),
                    "status": device_status(d["status"].as_i64().unwrap_or(0)),
                    "created": iso(Some(ctime)),
                    "updated": iso(d["mtime"].as_u64()),
                    "keys": d["keys"].as_array().map_or(0, |k| k.len()),
                }),
            ));
        }
    }
    devices.sort_by_key(|a| std::cmp::Reverse(a.0));
    let list: Vec<Value> = devices.into_iter().map(|(_, v)| v).collect();
    let mut out = Vec::new();
    if list.is_empty() {
        out.push(Hit::new(
            "devices",
            Status::Absent,
            "no devices on the public record",
            None,
        ));
        return out;
    }
    let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
    for d in &list {
        *kinds
            .entry(d["type"].as_str().unwrap_or("unknown"))
            .or_default() += 1;
    }
    let mix = kinds
        .iter()
        .map(|(k, n)| format!("{n} {k}"))
        .collect::<Vec<_>>()
        .join(", ");
    let active = list
        .iter()
        .filter(|d| d["status"].as_str() == Some("active"))
        .count();
    out.push(Hit::new(
        "devices",
        Status::Confirmed,
        format!("{} device(s), {active} active: {mix}", list.len()),
        Some(json!({"devices": list})),
    ));
    let revoked = list.len() - active;
    if revoked > 0 {
        out.push(Hit::new(
            "revoked",
            Status::Confirmed,
            format!("{revoked} revoked device(s)"),
            None,
        ));
    }
    for d in &list {
        let typ = d["type"].as_str().unwrap_or("device");
        let name = d["name"].as_str().unwrap_or("");
        let status = d["status"].as_str().unwrap_or("unknown");
        let created = d["created"].as_str().unwrap_or("");
        let day = created.get(..10).unwrap_or(created);
        out.push(Hit::new(
            "device",
            Status::Confirmed,
            format!("{typ} {name} created {day} ({status})"),
            Some(d.clone()),
        ));
    }
    out
}

fn text(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn iso(secs: Option<u64>) -> String {
    secs.filter(|s| *s > 0)
        .map(crate::finding::iso8601)
        .unwrap_or_default()
}

fn proof_state(code: i64) -> &'static str {
    match code {
        1 => "ok",
        2 => "temp failure",
        3 => "perm failure",
        5 => "superseded",
        7 => "revoked",
        8 => "deleted",
        _ => "unchecked",
    }
}

fn device_status(code: i64) -> &'static str {
    match code {
        1 => "active",
        2 => "revoked",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        serde_json::from_str(
            r#"{
            "id": "9a2c8a8ac48162723c7992570c87da00",
            "basics": {
                "username": "maxtaco",
                "ctime": 1399919269,
                "mtime": 1399919269
            },
            "profile": {
                "full_name": "Max Krohn",
                "location": "New York",
                "bio": "keybase"
            },
            "pictures": {"primary": {"url": "https://keybase.io/maxtaco/avatar"}},
            "proofs_summary": {
                "by_presentation_group": {
                    "twitter": [{"proof_type": "twitter", "nametag": "maxtaco", "state": 1,
                        "service_url": "https://twitter.com/maxtaco", "human_url": "https://twitter.com/maxtaco/status/1"}],
                    "github": [{"proof_type": "github", "nametag": "maxtaco", "state": 7,
                        "service_url": "https://github.com/maxtaco", "human_url": "https://gist.github.com/x"}]
                }
            },
            "devices": {
                "0c0c1393f8dd8a6ff19e710333533718": {"type": "desktop", "ctime": 1745315510,
                    "mtime": 1745315510, "name": "cc-linux-vm", "status": 1, "keys": [{}, {}]},
                "594bf7611bb6ef8f65a6e3cfbd1bfd18": {"type": "mobile", "ctime": 1581366712,
                    "mtime": 1581366713, "name": "ipad", "status": 2, "keys": [{}]}
            }
        }"#,
        )
        .unwrap()
    }

    #[test]
    fn parses_profile_proofs_and_devices() {
        let them = fixture();
        let hits = findings(&them);
        let profile = hits.iter().find(|h| h.module == "profile").unwrap();
        assert_eq!(profile.status, Status::Confirmed);
        assert!(profile.summary.contains("maxtaco"));
        assert!(profile.summary.contains("Max Krohn"));

        let proofs = hits.iter().find(|h| h.module == "proofs").unwrap();
        assert!(proofs.summary.contains("1/2"));
        assert!(hits.iter().any(|h| h.module == "twitter"));
        assert!(hits.iter().any(|h| h.module == "github"));

        let devices = hits.iter().find(|h| h.module == "devices").unwrap();
        assert!(devices.summary.contains("2 device(s)"));
        assert!(devices.summary.contains("1 active"));
        assert!(devices.summary.contains("1 desktop"));
        assert!(hits.iter().any(|h| h.module == "revoked"));
        let rows: Vec<_> = hits.iter().filter(|h| h.module == "device").collect();
        assert_eq!(rows.len(), 2);
        assert!(
            rows[0].summary.contains("cc-linux-vm"),
            "{}",
            rows[0].summary
        );
        assert!(rows[1].summary.contains("(revoked)"), "{}", rows[1].summary);
    }

    #[test]
    fn proof_state_and_device_status_labels() {
        assert_eq!(proof_state(1), "ok");
        assert_eq!(proof_state(7), "revoked");
        assert_eq!(device_status(1), "active");
        assert_eq!(device_status(2), "revoked");
        assert_eq!(device_status(0), "unknown");
    }

    #[test]
    fn iso_skips_empty_timestamps() {
        assert_eq!(iso(None), "");
        assert_eq!(iso(Some(0)), "");
        assert_eq!(iso(Some(1399919269)), "2014-05-12T18:27:49Z");
    }

    #[test]
    fn rejects_bad_names() {
        assert!(valid_name("maxtaco"));
        assert!(valid_name("a_b1"));
        assert!(!valid_name("a"));
        assert!(!valid_name("has space"));
        assert!(!valid_name("has-dash"));
        assert!(!valid_name(&"x".repeat(33)));
    }
}
