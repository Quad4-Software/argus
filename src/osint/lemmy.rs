// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Public Lemmy account from the instance API.
//! The v3 user endpoint is public on most instances and returns the
//! person view with counts, moderated communities, and recent posts
//! and comments. A hit is a lead, not proof of identity.

use super::name::normalize_domain;
use super::siteurl::fetch_public;
use super::{Hit, Report, Status};
use serde_json::{Value, json};
use std::time::Instant;

const RECENT: usize = 10;

pub fn scan(target: &str, instance: Option<&str>) -> Result<Report, String> {
    let t0 = Instant::now();
    let (name, host) = resolve(target, instance)?;
    let url = format!(
        "https://{host}/api/v3/user?username={}&limit={RECENT}&sort=New",
        super::name::percent_encode(&name)
    );
    let (status, _, _, body) = fetch_public(&url)?;
    let mut findings = Vec::new();
    if status == 404 {
        findings.push(Hit::new(
            "profile",
            Status::Absent,
            format!("no lemmy account {name}@{host}"),
            None,
        ));
    } else if status != 200 {
        return Err(format!("lemmy lookup HTTP {status}"));
    } else {
        let doc: Value = serde_json::from_str(&body).map_err(|e| format!("lemmy json: {e}"))?;
        if doc["person_view"]["person"]["name"]
            .as_str()
            .unwrap_or("")
            .is_empty()
        {
            findings.push(Hit::new(
                "profile",
                Status::Absent,
                format!("no lemmy account {name}@{host}"),
                None,
            ));
        } else {
            findings = report_hits(&doc, &name, &host);
        }
    }
    Ok(Report {
        target: target.trim().to_string(),
        kind: "lemmy",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

fn resolve(target: &str, instance: Option<&str>) -> Result<(String, String), String> {
    let t = target.trim();
    if let Some(rest) = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
    {
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        let host = normalize_domain(host)?;
        let mut parts = path.split('/').filter(|p| !p.is_empty());
        let first = parts.next().unwrap_or("");
        let name = if matches!(first, "u" | "user" | "users") {
            parts.next().unwrap_or("")
        } else {
            first
        };
        return Ok((valid_name(name)?, host));
    }
    let t = t.trim_start_matches('@');
    if let Some((name, host)) = t.split_once('@') {
        return Ok((valid_name(name)?, normalize_domain(host)?));
    }
    let host = instance
        .map(normalize_domain)
        .transpose()?
        .ok_or("pass name@instance or --instance")?;
    Ok((valid_name(t)?, host))
}

fn valid_name(name: &str) -> Result<String, String> {
    if (1..=50).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        Ok(name.to_string())
    } else {
        Err("lemmy usernames use 1-50 letters, digits, or underscore".into())
    }
}

fn report_hits(doc: &Value, name: &str, host: &str) -> Vec<Hit> {
    let view = &doc["person_view"];
    let person = &view["person"];
    let display = person["display_name"].as_str().unwrap_or("");
    let actor = person["actor_id"].as_str().unwrap_or("");
    let summary = if display.is_empty() {
        format!("{name}@{host}")
    } else {
        format!("{display} ({name}@{host})")
    };
    let mut out = vec![Hit::new(
        "profile",
        Status::Confirmed,
        summary,
        Some(json!({
            "name": person["name"],
            "display_name": display,
            "id": person["id"],
            "actor_id": actor,
            "home": host_of(actor),
            "instance": host,
            "bio": person["bio"].as_str().unwrap_or(""),
            "avatar": person["avatar"].as_str().unwrap_or(""),
            "banner": person["banner"].as_str().unwrap_or(""),
            "matrix_user_id": person["matrix_user_id"].as_str().unwrap_or(""),
            "published": person["published"].as_str().unwrap_or(""),
            "updated": person["updated"].as_str().unwrap_or(""),
        })),
    )];
    out.push(Hit::new(
        "counts",
        Status::Confirmed,
        format!(
            "{} posts, {} comments",
            view["counts"]["post_count"].as_i64().unwrap_or(0),
            view["counts"]["comment_count"].as_i64().unwrap_or(0)
        ),
        Some(json!({
            "posts": view["counts"]["post_count"],
            "comments": view["counts"]["comment_count"],
        })),
    ));
    let mut flags = Vec::new();
    for (key, label) in [
        ("is_admin", "admin"),
        ("bot_account", "bot"),
        ("banned", "banned"),
        ("deleted", "deleted"),
        ("local", "local"),
    ] {
        let on = if key == "is_admin" {
            view[key].as_bool()
        } else {
            person[key].as_bool()
        };
        if on == Some(true) {
            flags.push(label);
        }
    }
    out.push(if flags.is_empty() {
        Hit::new("flags", Status::Absent, "no account flags set", None)
    } else {
        Hit::new("flags", Status::Confirmed, flags.join(", "), None)
    });
    let moderates: Vec<Value> = doc["moderates"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| {
            json!({
                "name": m["community"]["name"],
                "title": m["community"]["title"],
                "url": m["community"]["actor_id"],
            })
        })
        .collect();
    out.push(if moderates.is_empty() {
        Hit::new(
            "moderates",
            Status::Absent,
            "moderates no communities",
            None,
        )
    } else {
        let list: Vec<&str> = moderates
            .iter()
            .filter_map(|m| m["name"].as_str())
            .collect();
        Hit::new(
            "moderates",
            Status::Confirmed,
            list.join(", "),
            Some(json!({"communities": moderates})),
        )
    });
    let posts: Vec<Value> = doc["posts"]
        .as_array()
        .into_iter()
        .flatten()
        .take(5)
        .map(|p| {
            json!({
                "title": p["post"]["name"],
                "community": p["community"]["name"],
                "score": p["counts"]["score"],
                "comments": p["counts"]["comments"],
                "published": p["counts"]["published"],
                "url": p["post"]["ap_id"],
            })
        })
        .collect();
    out.push(if posts.is_empty() {
        Hit::new("posts", Status::Absent, "no recent posts", None)
    } else {
        let newest = posts[0]["title"].as_str().unwrap_or("");
        Hit::new(
            "posts",
            Status::Confirmed,
            format!("{} recent post(s), newest: {newest}", posts.len()),
            Some(json!({"posts": posts})),
        )
    });
    let comments: Vec<Value> = doc["comments"]
        .as_array()
        .into_iter()
        .flatten()
        .take(5)
        .map(|c| {
            json!({
                "body": clip(c["comment"]["content"].as_str().unwrap_or(""), 200),
                "community": c["community"]["name"],
                "score": c["counts"]["score"],
                "published": c["counts"]["published"],
                "url": c["comment"]["ap_id"],
            })
        })
        .collect();
    out.push(if comments.is_empty() {
        Hit::new("comments", Status::Absent, "no recent comments", None)
    } else {
        let newest = comments[0]["body"].as_str().unwrap_or("");
        Hit::new(
            "comments",
            Status::Confirmed,
            format!("{} recent comment(s), newest: {newest}", comments.len()),
            Some(json!({"comments": comments})),
        )
    });
    out
}

fn host_of(url: &str) -> String {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    rest.split(['/', '?', '#']).next().unwrap_or("").to_string()
}

fn clip(s: &str, n: usize) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.chars().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_names_urls_and_instances() {
        assert_eq!(
            resolve("dessalines@lemmy.ml", None).unwrap(),
            ("dessalines".to_string(), "lemmy.ml".to_string())
        );
        assert_eq!(
            resolve("https://lemmy.ml/u/dessalines", None).unwrap(),
            ("dessalines".to_string(), "lemmy.ml".to_string())
        );
        assert_eq!(
            resolve("dessalines", Some("lemmy.ml")).unwrap(),
            ("dessalines".to_string(), "lemmy.ml".to_string())
        );
        assert!(resolve("dessalines", None).is_err());
        assert!(resolve("bad name!", Some("lemmy.ml")).is_err());
        assert!(resolve("dessalines", Some("not a host")).is_err());
    }

    #[test]
    fn builds_findings_from_the_person_view() {
        let doc: Value = serde_json::from_str(
            r#"{
            "person_view": {
                "person": {
                    "id": 34, "name": "dessalines", "display_name": "Dessalines",
                    "actor_id": "https://lemmy.ml/u/dessalines", "local": true,
                    "banned": false, "deleted": false, "bot_account": false,
                    "matrix_user_id": "@happydooby:matrix.org",
                    "published": "2019-04-17T23:34:40.912940Z",
                    "updated": "2022-09-15T13:41:47.087316Z",
                    "avatar": "https://lemmy.ml/pictrs/a.webp", "banner": ""
                },
                "counts": {"post_count": 1118, "comment_count": 8986},
                "is_admin": true
            },
            "posts": [{
                "post": {"name": "Lemmy Development Update", "ap_id": "https://lemmy.ml/post/1"},
                "community": {"name": "announcements", "actor_id": "https://lemmy.ml/c/announcements"},
                "counts": {"score": 51, "comments": 6, "published": "2026-10-08T16:05:34Z"}
            }],
            "comments": [{
                "comment": {"content": "This is completely incorrect.", "ap_id": "https://lemmy.ml/comment/2"},
                "community": {"name": "announcements"},
                "counts": {"score": 5, "published": "2026-10-08T22:28:12Z"}
            }],
            "moderates": [{"community": {"name": "announcements", "title": "Announcements", "actor_id": "https://lemmy.ml/c/announcements"}}]
        }"#,
        )
        .unwrap();
        let hits = report_hits(&doc, "dessalines", "lemmy.ml");
        let profile = hits.iter().find(|h| h.module == "profile").unwrap();
        assert!(profile.summary.contains("Dessalines (dessalines@lemmy.ml)"));
        assert_eq!(
            hits.iter().find(|h| h.module == "counts").unwrap().summary,
            "1118 posts, 8986 comments"
        );
        assert_eq!(
            hits.iter().find(|h| h.module == "flags").unwrap().summary,
            "admin, local"
        );
        assert_eq!(
            hits.iter()
                .find(|h| h.module == "moderates")
                .unwrap()
                .summary,
            "announcements"
        );
        assert!(
            hits.iter()
                .find(|h| h.module == "posts")
                .unwrap()
                .summary
                .contains("Lemmy Development Update")
        );
        assert!(
            hits.iter()
                .find(|h| h.module == "comments")
                .unwrap()
                .summary
                .contains("completely incorrect")
        );
    }
}
