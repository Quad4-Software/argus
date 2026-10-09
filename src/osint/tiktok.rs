// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Public TikTok video and profile metadata.
//! Videos resolve through the public oembed endpoint. Profiles are
//! parsed best effort from the page rehydration blob. A challenge page
//! reports inconclusive instead of a hard failure. No login is used.

use super::siteurl::fetch_public;
use super::{Hit, Report, Status};
use regex::Regex;
use serde_json::{Value, json};
use std::time::Instant;

const OEMBED: &str = "https://www.tiktok.com/oembed";

pub fn scan(target: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    match resolve(target)? {
        Mode::Video(id) => video(&id, target, t0),
        Mode::User(name) => user(&name, target, t0),
    }
}

enum Mode {
    Video(String),
    User(String),
}

fn resolve(raw: &str) -> Result<Mode, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("pass a video id, video url, @user, or profile url".into());
    }
    let mut rest = t;
    for prefix in ["https://", "http://"] {
        rest = rest.strip_prefix(prefix).unwrap_or(rest);
    }
    rest = rest.strip_prefix("www.").unwrap_or(rest);
    rest = rest.strip_prefix("m.").unwrap_or(rest);
    if let Some(path) = rest.strip_prefix("tiktok.com/") {
        let path = path
            .split(['?', '#'])
            .next()
            .unwrap_or(path)
            .trim_matches('/');
        if let Some(id) = path.strip_prefix("video/") {
            return video_id(id);
        }
        if let Some(after) = path.strip_prefix('@') {
            let mut parts = after.split('/');
            let name = parts.next().unwrap_or("");
            if parts.next() == Some("video") {
                return video_id(parts.next().unwrap_or(""));
            }
            return Ok(Mode::User(valid_user(name)?));
        }
        return Err(
            "tiktok url must look like tiktok.com/@user or tiktok.com/@user/video/<id>".into(),
        );
    }
    if let Some(name) = t.strip_prefix('@') {
        return Ok(Mode::User(valid_user(name)?));
    }
    if t.chars().all(|c| c.is_ascii_digit()) && (15..=25).contains(&t.len()) {
        return Ok(Mode::Video(t.to_string()));
    }
    Ok(Mode::User(valid_user(t)?))
}

fn video_id(id: &str) -> Result<Mode, String> {
    if id.chars().all(|c| c.is_ascii_digit()) && (15..=25).contains(&id.len()) {
        Ok(Mode::Video(id.to_string()))
    } else {
        Err("tiktok video ids are digits".into())
    }
}

fn valid_user(name: &str) -> Result<String, String> {
    let name = name.trim_matches('/');
    if (2..=24).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_'))
    {
        Ok(name.to_string())
    } else {
        Err("tiktok usernames use 2-24 letters, digits, dot, or underscore".into())
    }
}

fn video(id: &str, target: &str, t0: Instant) -> Result<Report, String> {
    let watch = format!("https://www.tiktok.com/@x/video/{id}");
    let url = format!("{OEMBED}?url={}", super::name::percent_encode(&watch));
    let (status, _, _, body) = fetch_public(&url)?;
    let mut findings = Vec::new();
    if status != 200 {
        findings.push(Hit::new(
            "video",
            Status::Absent,
            format!("no public oembed metadata for video {id}"),
            None,
        ));
    } else {
        let doc: Value = serde_json::from_str(&body).map_err(|e| format!("tiktok json: {e}"))?;
        let title = doc["title"].as_str().unwrap_or("");
        findings.push(Hit::new(
            "video",
            Status::Confirmed,
            if title.is_empty() {
                id.to_string()
            } else {
                clip(title, 120)
            },
            Some(json!({
                "id": id,
                "title": title,
                "thumbnail": doc["thumbnail_url"].as_str().unwrap_or(""),
            })),
        ));
        let author = doc["author_name"].as_str().unwrap_or("");
        if author.is_empty() {
            findings.push(Hit::new(
                "author",
                Status::Absent,
                "no author in the oembed view",
                None,
            ));
        } else {
            findings.push(Hit::new(
                "author",
                Status::Confirmed,
                format!("{author} ({})", doc["author_url"].as_str().unwrap_or("")),
                Some(json!({"url": doc["author_url"].as_str().unwrap_or("")})),
            ));
        }
    }
    Ok(Report {
        target: target.trim().to_string(),
        kind: "tiktok",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

fn user(name: &str, target: &str, t0: Instant) -> Result<Report, String> {
    let page_url = format!("https://www.tiktok.com/@{name}");
    let (status, _, _, body) = fetch_public(&page_url)?;
    let mut findings = Vec::new();
    if status == 404 {
        findings.push(Hit::new(
            "profile",
            Status::Absent,
            format!("no tiktok account @{name}"),
            None,
        ));
    } else if status != 200 {
        return Err(format!("tiktok profile HTTP {status}"));
    } else {
        match account(&body) {
            Account::Found(info) => findings = account_hits(&info, name),
            Account::Missing => findings.push(Hit::new(
                "profile",
                Status::Absent,
                format!("no tiktok account @{name}"),
                None,
            )),
            Account::Unknown => findings.push(Hit::new(
                "profile",
                Status::Inconclusive,
                "profile page did not include account data (challenge or removed)",
                None,
            )),
        }
    }
    Ok(Report {
        target: target.trim().to_string(),
        kind: "tiktok",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

enum Account {
    Found(Value),
    Missing,
    Unknown,
}

/// The page embeds a rehydration blob. A removed account carries a
/// statusCode and no userInfo, a challenge page carries neither.
fn account(body: &str) -> Account {
    let Some(doc) = rehydration(body) else {
        return Account::Unknown;
    };
    let detail = &doc["__DEFAULT_SCOPE__"]["webapp.user-detail"];
    if !detail["userInfo"].is_null() {
        Account::Found(detail["userInfo"].clone())
    } else if !detail["statusCode"].is_null() {
        Account::Missing
    } else {
        Account::Unknown
    }
}

fn rehydration(body: &str) -> Option<Value> {
    let marker = "__UNIVERSAL_DATA_FOR_REHYDRATION__";
    let start = body.find(marker)?;
    let rest = &body[start..];
    let gt = rest.find('>')?;
    let content_at = start + gt + 1;
    let end = body[content_at..].find("</script>")?;
    serde_json::from_str(&body[content_at..content_at + end]).ok()
}

fn account_hits(info: &Value, name: &str) -> Vec<Hit> {
    let user = &info["user"];
    let unique = user["uniqueId"].as_str().unwrap_or(name);
    let nickname = user["nickname"].as_str().unwrap_or("");
    let bio = user["signature"].as_str().unwrap_or("");
    let summary = if nickname.is_empty() {
        format!("@{unique}")
    } else {
        format!("{nickname} (@{unique})")
    };
    let mut out = vec![Hit::new(
        "profile",
        Status::Confirmed,
        summary,
        Some(json!({
            "id": user["id"].as_str().unwrap_or(""),
            "unique_id": unique,
            "nickname": nickname,
            "bio": bio,
            "region": user["region"].as_str().unwrap_or(""),
            "avatar": user["avatarLarger"].as_str().unwrap_or(""),
            "created": created(user["createTime"].as_u64()),
            "url": format!("https://www.tiktok.com/@{unique}"),
        })),
    )];
    let stats = &info["statsV2"];
    let followers = stat(stats, "followerCount").or_else(|| stat(&info["stats"], "followerCount"));
    let following =
        stat(stats, "followingCount").or_else(|| stat(&info["stats"], "followingCount"));
    let likes = stat(stats, "heartCount").or_else(|| stat(&info["stats"], "heartCount"));
    let videos = stat(stats, "videoCount").or_else(|| stat(&info["stats"], "videoCount"));
    out.push(Hit::new(
        "stats",
        Status::Confirmed,
        format!(
            "{} followers, {} following, {} likes, {} videos",
            show(&followers),
            show(&following),
            show(&likes),
            show(&videos)
        ),
        Some(json!({
            "followers": followers,
            "following": following,
            "likes": likes,
            "videos": videos,
        })),
    ));
    let mut flags = Vec::new();
    if user["verified"].as_bool() == Some(true) {
        flags.push("verified");
    }
    if user["privateAccount"].as_bool() == Some(true) {
        flags.push("private");
    }
    if user["ttSeller"].as_bool() == Some(true) {
        flags.push("seller");
    }
    out.push(if flags.is_empty() {
        Hit::new("flags", Status::Absent, "no account flags set", None)
    } else {
        Hit::new("flags", Status::Confirmed, flags.join(", "), None)
    });
    let links: Vec<String> = Regex::new(r"https?://[^\s]+")
        .unwrap()
        .find_iter(bio)
        .map(|m| m.as_str().trim_end_matches(['.', ',']).to_string())
        .collect();
    out.push(if links.is_empty() {
        Hit::new("links", Status::Absent, "no links in the bio", None)
    } else {
        Hit::new(
            "links",
            Status::Confirmed,
            links.join(", "),
            Some(json!({"links": links})),
        )
    });
    out
}

fn stat(stats: &Value, key: &str) -> Option<i64> {
    stats[key]
        .as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| stats[key].as_i64())
}

fn show(v: &Option<i64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "?".into())
}

fn created(secs: Option<u64>) -> String {
    secs.filter(|s| *s > 0)
        .map(crate::finding::iso8601)
        .unwrap_or_default()
}

fn clip(s: &str, n: usize) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.chars().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode_of(raw: &str) -> String {
        match resolve(raw).unwrap() {
            Mode::Video(id) => format!("video:{id}"),
            Mode::User(name) => format!("user:{name}"),
        }
    }

    #[test]
    fn resolves_videos_and_users() {
        assert_eq!(mode_of("@scout2015"), "user:scout2015");
        assert_eq!(mode_of("scout2015"), "user:scout2015");
        assert_eq!(
            mode_of("https://www.tiktok.com/@scout2015"),
            "user:scout2015"
        );
        assert_eq!(
            mode_of("https://www.tiktok.com/@scout2015/video/6718335390845095173"),
            "video:6718335390845095173"
        );
        assert_eq!(
            mode_of("https://www.tiktok.com/video/6718335390845095173"),
            "video:6718335390845095173"
        );
        assert!(resolve("bad user!").is_err());
        assert!(resolve("https://www.tiktok.com/tag/cats").is_err());
    }

    #[test]
    fn parses_the_rehydration_blob() {
        let body = r#"<html><script id="__UNIVERSAL_DATA_FOR_REHYDRATION__" type="application/json">
        {"__DEFAULT_SCOPE__":{"webapp.user-detail":{"userInfo":{
            "user":{"id":"53279706535428096","uniqueId":"scout2015","nickname":"Scout, Suki & Stella",
                "signature":"Follow us\nhttps://example.com/links","avatarLarger":"https://cdn.example/a.jpg",
                "verified":true,"privateAccount":false,"ttSeller":false,"createTime":1453074387},
            "stats":{"followerCount":9000000,"followingCount":1173,"heartCount":108300000,"videoCount":3073},
            "statsV2":{"followerCount":"9022701","followingCount":"1173","heartCount":"108329314","videoCount":"3073"}
        }}}}</script></html>"#;
        let info = match account(body) {
            Account::Found(info) => info,
            _ => panic!("want a found account"),
        };
        let hits = account_hits(&info, "scout2015");
        let profile = hits.iter().find(|h| h.module == "profile").unwrap();
        assert!(
            profile
                .summary
                .contains("Scout, Suki & Stella (@scout2015)")
        );
        let stats = hits.iter().find(|h| h.module == "stats").unwrap();
        assert!(
            stats.summary.contains("9022701 followers"),
            "{}",
            stats.summary
        );
        assert!(stats.summary.contains("108329314 likes"));
        let flags = hits.iter().find(|h| h.module == "flags").unwrap();
        assert_eq!(flags.summary, "verified");
        let links = hits.iter().find(|h| h.module == "links").unwrap();
        assert_eq!(links.summary, "https://example.com/links");
    }

    #[test]
    fn missing_and_challenge_pages() {
        let missing = r#"<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__" type="application/json">
            {"__DEFAULT_SCOPE__":{"webapp.user-detail":{"statusCode":10221,"statusMsg":""}}}</script>"#;
        assert!(matches!(account(missing), Account::Missing));
        assert!(matches!(account("<html>no blob</html>"), Account::Unknown));
        let empty: Value = json!({});
        assert!(matches!(
            account(&format!(
                "<script id=\"__UNIVERSAL_DATA_FOR_REHYDRATION__\" type=\"application/json\">{empty}</script>"
            )),
            Account::Unknown
        ));
    }
}
