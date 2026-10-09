// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Public Bluesky profile.
//! The public appview answers without a token. A handle resolves to a
//! DID, and the actor view carries counts, self-labels, and any
//! verification. A handle match is a lead, not proof of identity.

use super::siteurl::fetch_public;
use super::{Hit, Report, Status};
use serde_json::{Value, json};
use std::time::Instant;

pub fn scan(raw: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    let actor = resolve(raw)?;
    let url = format!(
        "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={}",
        super::name::percent_encode(&actor)
    );
    let (status, _, _, body) = fetch_public(&url)?;
    let mut findings = Vec::new();
    if status == 404 || (status == 400 && body.contains("not found")) {
        findings.push(Hit::new(
            "profile",
            Status::Absent,
            format!("no bluesky profile for {actor}"),
            None,
        ));
    } else if status != 200 {
        return Err(format!("bluesky appview HTTP {status}"));
    } else {
        let doc: Value = serde_json::from_str(&body).map_err(|e| format!("bluesky json: {e}"))?;
        if doc["did"].as_str().is_none() {
            findings.push(Hit::new(
                "profile",
                Status::Inconclusive,
                "appview returned no did for this actor",
                None,
            ));
        } else {
            findings = report_hits(&doc);
        }
    }
    Ok(Report {
        target: raw.trim().to_string(),
        kind: "bluesky",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

fn resolve(raw: &str) -> Result<String, String> {
    let mut t = raw.trim().trim_start_matches('@');
    if let Some(rest) = t.strip_prefix("at://") {
        t = rest.split('/').next().unwrap_or("");
    } else if let Some(rest) = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
    {
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        let host = host.trim_start_matches("www.");
        if host != "bsky.app" {
            return Err("bluesky profile urls use bsky.app".into());
        }
        let mut parts = path.split('/');
        match (parts.next(), parts.next()) {
            (Some("profile"), Some(actor)) => t = actor,
            _ => return Err("bluesky url must look like bsky.app/profile/<handle>".into()),
        }
    }
    if t.is_empty() || t.len() > 253 {
        return Err("pass a bluesky handle, did, or bsky.app profile url".into());
    }
    if t.starts_with("did:") {
        if !t
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '-' | '_'))
        {
            return Err("bluesky did has unexpected characters".into());
        }
        return Ok(t.to_string());
    }
    if !t
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        || t.contains("..")
    {
        return Err("bluesky handle has unexpected characters".into());
    }
    Ok(t.to_string())
}

fn report_hits(doc: &Value) -> Vec<Hit> {
    let mut out = Vec::new();
    let handle = doc["handle"].as_str().unwrap_or("");
    let display = doc["displayName"].as_str().unwrap_or("");
    let summary = if display.is_empty() {
        handle.to_string()
    } else {
        format!("{display} (@{handle})")
    };
    out.push(Hit::new(
        "profile",
        Status::Confirmed,
        summary,
        Some(json!({
            "did": doc["did"],
            "handle": handle,
            "display_name": display,
            "description": doc["description"].as_str().unwrap_or(""),
            "avatar": doc["avatar"].as_str().unwrap_or(""),
            "banner": doc["banner"].as_str().unwrap_or(""),
        })),
    ));
    out.push(Hit::new(
        "counts",
        Status::Confirmed,
        format!(
            "{} followers, {} following, {} posts",
            count(doc, "followersCount"),
            count(doc, "followsCount"),
            count(doc, "postsCount")
        ),
        Some(json!({
            "followers": doc["followersCount"],
            "following": doc["followsCount"],
            "posts": doc["postsCount"],
        })),
    ));
    let created = doc["createdAt"].as_str().unwrap_or("");
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
    let labels: Vec<&str> = doc["labels"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|l| l["val"].as_str())
        .collect();
    out.push(if labels.is_empty() {
        Hit::new("labels", Status::Absent, "no self-labels", None)
    } else {
        Hit::new(
            "labels",
            Status::Confirmed,
            labels.join(", "),
            Some(json!({"labels": labels})),
        )
    });
    let verified = doc["verification"]["verifiedStatus"].as_str().unwrap_or("");
    out.push(if verified == "valid" {
        let issuers: Vec<&str> = doc["verification"]["verifications"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v["issuerHandle"].as_str())
            .collect();
        Hit::new(
            "verified",
            Status::Confirmed,
            format!("verified by {}", issuers.join(", ")),
            Some(json!({"issuers": issuers})),
        )
    } else {
        Hit::new("verified", Status::Absent, "no valid verification", None)
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
            "did": "did:plc:oky5czdrnfjpqslsw2a5iclo",
            "handle": "jay.bsky.team",
            "displayName": "Jay",
            "description": "Founder",
            "avatar": "https://cdn.example/avatar.jpg",
            "banner": "https://cdn.example/banner.jpg",
            "followersCount": 594645,
            "followsCount": 3986,
            "postsCount": 4172,
            "createdAt": "2022-11-17T06:31:40.296Z",
            "labels": [{"val": "porn"}],
            "verification": {
                "verifiedStatus": "valid",
                "verifications": [{"issuerHandle": "bsky.app"}]
            }
        }"#,
        )
        .unwrap()
    }

    #[test]
    fn resolves_handles_dids_and_urls() {
        assert_eq!(resolve("@jay.bsky.team").unwrap(), "jay.bsky.team");
        assert_eq!(resolve("did:plc:abc123").unwrap(), "did:plc:abc123");
        assert_eq!(
            resolve("https://bsky.app/profile/jay.bsky.team/post/3k").unwrap(),
            "jay.bsky.team"
        );
        assert_eq!(
            resolve("at://did:plc:abc123/app.bsky.actor.profile/self").unwrap(),
            "did:plc:abc123"
        );
        assert!(resolve("https://example.com/profile/x").is_err());
        assert!(resolve("bad handle!").is_err());
        assert!(resolve("").is_err());
    }

    #[test]
    fn parses_a_profile_view() {
        let hits = report_hits(&fixture());
        let profile = hits.iter().find(|h| h.module == "profile").unwrap();
        assert_eq!(profile.status, Status::Confirmed);
        assert!(profile.summary.contains("Jay (@jay.bsky.team)"));
        let counts = hits.iter().find(|h| h.module == "counts").unwrap();
        assert!(counts.summary.contains("594645 followers"));
        assert!(hits.iter().any(|h| h.module == "created"));
        let labels = hits.iter().find(|h| h.module == "labels").unwrap();
        assert_eq!(labels.summary, "porn");
        let verified = hits.iter().find(|h| h.module == "verified").unwrap();
        assert_eq!(verified.status, Status::Confirmed);
        assert!(verified.summary.contains("bsky.app"));
    }

    #[test]
    fn empty_labels_and_verification_read_as_absent() {
        let doc = json!({
            "did": "did:plc:x",
            "handle": "x.test",
            "labels": [],
            "verification": {"verifiedStatus": "none", "verifications": []},
        });
        let hits = report_hits(&doc);
        assert_eq!(
            hits.iter().find(|h| h.module == "labels").unwrap().status,
            Status::Absent
        );
        assert_eq!(
            hits.iter().find(|h| h.module == "verified").unwrap().status,
            Status::Absent
        );
        assert_eq!(
            hits.iter().find(|h| h.module == "created").unwrap().status,
            Status::Absent
        );
    }
}
