// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Public Mastodon account.
//! The account lookup endpoint is public on most instances. Profile
//! fields, links, and flags come from the same view the web UI shows.
//! A handle match is a lead, not proof of identity.

use super::name::normalize_domain;
use super::siteurl::fetch_public;
use super::surface::html_text;
use super::{Hit, Report, Status};
use serde_json::{Value, json};
use std::time::Instant;

pub fn scan(target: &str, instance: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    let (handle, host) = resolve(target, instance)?;
    let acct = format!("{handle}@{host}");
    let url = format!(
        "https://{host}/api/v1/accounts/lookup?acct={}",
        super::name::percent_encode(&acct)
    );
    let (status, _, _, body) = fetch_public(&url)?;
    let mut findings = Vec::new();
    if status == 404 {
        findings.push(Hit::new(
            "profile",
            Status::Absent,
            format!("no mastodon account {acct}"),
            None,
        ));
    } else if status != 200 {
        return Err(format!("mastodon lookup HTTP {status}"));
    } else {
        let doc: Value = serde_json::from_str(&body).map_err(|e| format!("mastodon json: {e}"))?;
        if doc["id"].as_str().is_none() && doc["id"].as_i64().is_none() {
            findings.push(Hit::new(
                "profile",
                Status::Inconclusive,
                "lookup returned no account id",
                None,
            ));
        } else {
            findings = report_hits(&doc, &acct);
        }
    }
    Ok(Report {
        target: target.trim().to_string(),
        kind: "mastodon",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

fn resolve(target: &str, instance: &str) -> Result<(String, String), String> {
    let t = target.trim();
    if let Some(rest) = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
    {
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        let host = normalize_domain(host)?;
        let mut parts = path.split('/').filter(|p| !p.is_empty());
        let first = parts.next().unwrap_or("");
        let handle = if let Some(h) = first.strip_prefix('@') {
            h.split('@').next().unwrap_or("")
        } else if matches!(first, "users" | "web" | "deck") {
            let next = parts.next().unwrap_or("");
            next.strip_prefix('@').unwrap_or(next)
        } else {
            first
        };
        return Ok((valid_handle(handle)?, host));
    }
    let t = t.trim_start_matches('@');
    if let Some((handle, host)) = t.split_once('@') {
        return Ok((valid_handle(handle)?, normalize_domain(host)?));
    }
    Ok((valid_handle(t)?, normalize_domain(instance)?))
}

fn valid_handle(handle: &str) -> Result<String, String> {
    if handle.is_empty() || handle.len() > 64 {
        return Err("pass a mastodon handle, user@instance, or profile url".into());
    }
    if !handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return Err("mastodon usernames use letters, digits, dot, underscore, or hyphen".into());
    }
    Ok(handle.to_string())
}

fn report_hits(doc: &Value, acct: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    let display = doc["display_name"].as_str().unwrap_or("");
    let handle = doc["acct"].as_str().unwrap_or(acct);
    let summary = if display.is_empty() {
        format!("@{handle}")
    } else {
        format!("{display} (@{handle})")
    };
    out.push(Hit::new(
        "profile",
        Status::Confirmed,
        summary,
        Some(json!({
            "id": doc["id"],
            "acct": handle,
            "username": doc["username"].as_str().unwrap_or(""),
            "display_name": display,
            "url": doc["url"].as_str().unwrap_or(""),
            "note": html_text(doc["note"].as_str().unwrap_or("")),
            "avatar": doc["avatar"].as_str().unwrap_or(""),
            "header": doc["header"].as_str().unwrap_or(""),
        })),
    ));
    out.push(Hit::new(
        "counts",
        Status::Confirmed,
        format!(
            "{} followers, {} following, {} posts",
            count(doc, "followers_count"),
            count(doc, "following_count"),
            count(doc, "statuses_count")
        ),
        Some(json!({
            "followers": doc["followers_count"],
            "following": doc["following_count"],
            "statuses": doc["statuses_count"],
        })),
    ));
    let created = doc["created_at"].as_str().unwrap_or("");
    out.push(if created.is_empty() {
        Hit::new(
            "created",
            Status::Absent,
            "no account date in the view",
            None,
        )
    } else {
        Hit::new("created", Status::Confirmed, created.to_string(), None)
    });
    let last = doc["last_status_at"].as_str().unwrap_or("");
    out.push(if last.is_empty() {
        Hit::new("last_status", Status::Absent, "no public posts", None)
    } else {
        Hit::new("last_status", Status::Confirmed, last.to_string(), None)
    });
    let mut flags = Vec::new();
    for (key, label) in [
        ("locked", "locked"),
        ("bot", "bot"),
        ("group", "group"),
        ("noindex", "noindex"),
    ] {
        if doc[key].as_bool() == Some(true) {
            flags.push(label);
        }
    }
    out.push(if flags.is_empty() {
        Hit::new("flags", Status::Absent, "no account flags set", None)
    } else {
        Hit::new("flags", Status::Confirmed, flags.join(", "), None)
    });
    let fields: Vec<Value> = doc["fields"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|f| {
            let name = html_text(f["name"].as_str().unwrap_or(""));
            let value = html_text(f["value"].as_str().unwrap_or(""));
            if name.is_empty() && value.is_empty() {
                return None;
            }
            Some(json!({
                "name": name,
                "value": value,
                "verified_at": f["verified_at"],
            }))
        })
        .collect();
    out.push(if fields.is_empty() {
        Hit::new("fields", Status::Absent, "no profile fields", None)
    } else {
        let summary = fields
            .iter()
            .map(|f| {
                let name = f["name"].as_str().unwrap_or("");
                let value = f["value"].as_str().unwrap_or("");
                format!("{name}: {value}")
            })
            .collect::<Vec<_>>()
            .join(", ");
        Hit::new(
            "fields",
            Status::Confirmed,
            summary,
            Some(json!({"fields": fields})),
        )
    });
    out
}

fn count(doc: &Value, key: &str) -> i64 {
    doc[key].as_i64().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        serde_json::from_str(
            r#"{
            "id": "1",
            "username": "Gargron",
            "acct": "Gargron",
            "display_name": "Eugen Rochko",
            "note": "<p>Founder of <a href=\"https://joinmastodon.org\">Mastodon</a></p>",
            "url": "https://mastodon.social/@Gargron",
            "avatar": "https://files.example/avatar.png",
            "header": "https://files.example/header.jpg",
            "followers_count": 383064,
            "following_count": 746,
            "statuses_count": 82422,
            "created_at": "2016-03-16T00:00:00.000Z",
            "last_status_at": "2026-10-08",
            "locked": false,
            "bot": false,
            "group": false,
            "noindex": false,
            "fields": [
                {"name": "Website", "value": "<a href=\"https://example.org\">example.org</a>", "verified_at": "2024-01-01T00:00:00.000Z"}
            ]
        }"#,
        )
        .unwrap()
    }

    #[test]
    fn resolves_handles_urls_and_bare_names() {
        assert_eq!(
            resolve("Gargron@mastodon.social", "mastodon.social").unwrap(),
            ("Gargron".to_string(), "mastodon.social".to_string())
        );
        assert_eq!(
            resolve("@Gargron@mastodon.social", "mastodon.social").unwrap(),
            ("Gargron".to_string(), "mastodon.social".to_string())
        );
        assert_eq!(
            resolve("https://mastodon.social/@Gargron", "mastodon.social").unwrap(),
            ("Gargron".to_string(), "mastodon.social".to_string())
        );
        assert_eq!(
            resolve("https://mastodon.social/users/Gargron", "mastodon.social").unwrap(),
            ("Gargron".to_string(), "mastodon.social".to_string())
        );
        assert_eq!(
            resolve("https://mastodon.social/web/@Gargron", "mastodon.social").unwrap(),
            ("Gargron".to_string(), "mastodon.social".to_string())
        );
        assert_eq!(
            resolve("Gargron", "fosstodon.org").unwrap(),
            ("Gargron".to_string(), "fosstodon.org".to_string())
        );
        assert!(resolve("bad user!", "mastodon.social").is_err());
        assert!(resolve("Gargron", "not a host").is_err());
    }

    #[test]
    fn parses_an_account_view() {
        let hits = report_hits(&fixture(), "Gargron@mastodon.social");
        let profile = hits.iter().find(|h| h.module == "profile").unwrap();
        assert_eq!(profile.status, Status::Confirmed);
        assert!(profile.summary.contains("Eugen Rochko (@Gargron)"));
        let evidence = profile.evidence.as_ref().unwrap();
        assert_eq!(evidence["note"], "Founder of Mastodon");
        let counts = hits.iter().find(|h| h.module == "counts").unwrap();
        assert!(counts.summary.contains("383064 followers"));
        assert_eq!(
            hits.iter().find(|h| h.module == "flags").unwrap().status,
            Status::Absent
        );
        let fields = hits.iter().find(|h| h.module == "fields").unwrap();
        assert_eq!(fields.summary, "Website: example.org");
    }

    #[test]
    fn flags_and_empty_fields_read_cleanly() {
        let doc = json!({
            "id": 7,
            "acct": "x@example.social",
            "locked": true,
            "bot": true,
            "fields": [],
            "last_status_at": null,
        });
        let hits = report_hits(&doc, "x@example.social");
        assert_eq!(
            hits.iter().find(|h| h.module == "flags").unwrap().summary,
            "locked, bot"
        );
        assert_eq!(
            hits.iter().find(|h| h.module == "fields").unwrap().status,
            Status::Absent
        );
        assert_eq!(
            hits.iter()
                .find(|h| h.module == "last_status")
                .unwrap()
                .status,
            Status::Absent
        );
    }
}
