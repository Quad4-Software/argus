// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Public Reddit account history from the Arctic Shift archive.
//! Reddit's own JSON refuses datacenter clients, so this reads the
//! community-run archive: karma, archive counts, and recent posts and
//! comments. Deleted and edited items reflect the archive snapshot.
//! A hit is a lead, not proof of identity.

use super::siteurl::fetch_public_slow;
use super::{Hit, Report, Status};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::Instant;

const BASE: &str = "https://arctic-shift.photon-reddit.com";
const RECENT: usize = 10;

pub fn scan(name: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    let name = resolve(name)?;
    let mut findings = Vec::new();
    let profile = archive(&format!("/api/users/search?author={name}&limit=1"));
    let rows = match profile {
        Ok(doc) => doc["data"].as_array().cloned().unwrap_or_default(),
        Err(e) => {
            findings.push(Hit::new(
                "profile",
                Status::Inconclusive,
                format!("archive unavailable: {e}"),
                None,
            ));
            return Ok(report(name, t0, findings));
        }
    };
    let row = rows
        .first()
        .filter(|r| text(&r["author"]).eq_ignore_ascii_case(&name));
    let Some(row) = row else {
        findings.push(Hit::new(
            "profile",
            Status::Absent,
            format!("no archive records for u/{name}"),
            None,
        ));
        return Ok(report(name, t0, findings));
    };
    let meta = &row["_meta"];
    let posts = recent(&name, "posts");
    let comments = recent(&name, "comments");
    let author = text(&row["author"]);
    findings.push(Hit::new(
        "profile",
        Status::Confirmed,
        format!("u/{author}"),
        Some(json!({
            "author": author,
            "id": text(&row["id"]),
            "url": format!("https://www.reddit.com/user/{author}"),
            "created": iso(earliest(meta)),
            "last_active": iso(latest(meta)),
        })),
    ));
    findings.push(Hit::new(
        "karma",
        Status::Confirmed,
        format!(
            "{} post, {} comment, {} total",
            num(meta, "post_karma"),
            num(meta, "comment_karma"),
            num(meta, "total_karma")
        ),
        Some(json!({
            "post_karma": meta["post_karma"],
            "comment_karma": meta["comment_karma"],
            "total_karma": meta["total_karma"],
        })),
    ));
    findings.push(Hit::new(
        "activity",
        Status::Confirmed,
        format!(
            "{} posts, {} comments in the archive",
            num(meta, "num_posts"),
            num(meta, "num_comments")
        ),
        None,
    ));
    findings.push(posts_hit(&posts));
    findings.push(comments_hit(&comments));
    findings.push(subreddits_hit(&posts, &comments));
    Ok(report(name, t0, findings))
}

/// One archive query. The public archive answers a busy moment with
/// HTTP 422 and a data:null error body, so that retries once and then
/// surfaces the message instead of a false miss.
fn archive(path: &str) -> Result<Value, String> {
    let url = format!("{BASE}{path}");
    let mut last = String::from("no response");
    for attempt in 0..2 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        match fetch_public_slow(&url) {
            Ok((200, _, _, body)) => match serde_json::from_str::<Value>(&body) {
                Ok(doc) if !doc["data"].is_null() => return Ok(doc),
                Ok(doc) => {
                    last = doc["error"]
                        .as_str()
                        .unwrap_or("archive returned no data")
                        .to_string()
                }
                Err(e) => last = format!("archive json: {e}"),
            },
            Ok((status, _, _, body)) => {
                last = format!("archive HTTP {status}: {}", clip(&body, 100))
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn report(name: String, t0: Instant, findings: Vec<Hit>) -> Report {
    Report {
        target: name,
        kind: "reddit",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    }
}

fn resolve(raw: &str) -> Result<String, String> {
    let mut t = raw.trim();
    for prefix in ["https://", "http://"] {
        t = t.strip_prefix(prefix).unwrap_or(t);
    }
    t = t.strip_prefix("www.").unwrap_or(t);
    t = t.strip_prefix("old.").unwrap_or(t);
    if let Some(rest) = t.strip_prefix("reddit.com") {
        let mut parts = rest.split('/').filter(|p| !p.is_empty());
        match (parts.next(), parts.next()) {
            (Some("user" | "u"), Some(name)) => t = name,
            _ => return Err("reddit url must look like reddit.com/user/<name>".into()),
        }
    }
    let name = t.trim_start_matches("u/").trim_end_matches('/');
    if !(3..=20).contains(&name.len())
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        return Err("reddit username must be 3-20 letters, digits, dash, or underscore".into());
    }
    Ok(name.to_string())
}

fn recent(name: &str, kind: &str) -> Result<Vec<Value>, String> {
    let doc = archive(&format!(
        "/api/{kind}/search?author={name}&limit={RECENT}&sort=desc"
    ))?;
    Ok(doc["data"].as_array().cloned().unwrap_or_default())
}

fn posts_hit(posts: &Result<Vec<Value>, String>) -> Hit {
    let posts = match posts {
        Ok(posts) => posts,
        Err(e) => {
            return Hit::new(
                "posts",
                Status::Inconclusive,
                format!("archive unavailable: {e}"),
                None,
            );
        }
    };
    if posts.is_empty() {
        return Hit::new("posts", Status::Absent, "no archived posts", None);
    }
    let rows: Vec<Value> = posts
        .iter()
        .take(5)
        .map(|p| {
            json!({
                "id": text(&p["id"]),
                "subreddit": text(&p["subreddit"]),
                "title": text(&p["title"]),
                "score": p["score"],
                "comments": p["num_comments"],
                "nsfw": p["over_18"].as_bool().unwrap_or(false),
                "created": iso(p["created"].as_u64()),
                "permalink": reddit_url(&text(&p["permalink"])),
            })
        })
        .collect();
    let newest = posts
        .first()
        .and_then(|p| p["title"].as_str())
        .unwrap_or("");
    Hit::new(
        "posts",
        Status::Confirmed,
        format!("{} archived post(s), newest: {newest}", posts.len()),
        Some(json!({"posts": rows})),
    )
}

fn comments_hit(comments: &Result<Vec<Value>, String>) -> Hit {
    let comments = match comments {
        Ok(comments) => comments,
        Err(e) => {
            return Hit::new(
                "comments",
                Status::Inconclusive,
                format!("archive unavailable: {e}"),
                None,
            );
        }
    };
    if comments.is_empty() {
        return Hit::new("comments", Status::Absent, "no archived comments", None);
    }
    let rows: Vec<Value> = comments
        .iter()
        .take(5)
        .map(|c| {
            json!({
                "id": text(&c["id"]),
                "subreddit": text(&c["subreddit"]),
                "body": clip(&text(&c["body"]), 200),
                "score": c["score"],
                "created": iso(c["created"].as_u64()),
                "permalink": reddit_url(&text(&c["permalink"])),
            })
        })
        .collect();
    let newest = comments
        .first()
        .and_then(|c| c["body"].as_str())
        .unwrap_or("");
    Hit::new(
        "comments",
        Status::Confirmed,
        format!(
            "{} archived comment(s), newest: {}",
            comments.len(),
            clip(newest, 80)
        ),
        Some(json!({"comments": rows})),
    )
}

fn subreddits_hit(
    posts: &Result<Vec<Value>, String>,
    comments: &Result<Vec<Value>, String>,
) -> Hit {
    let empty = Vec::new();
    let posts = posts.as_ref().unwrap_or(&empty);
    let comments = comments.as_ref().unwrap_or(&empty);
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for row in posts.iter().chain(comments.iter()) {
        if let Some(sub) = row["subreddit"].as_str()
            && !sub.is_empty()
            && !sub.starts_with("u_")
        {
            *counts.entry(sub.to_string()).or_default() += 1;
        }
    }
    if counts.is_empty() {
        return Hit::new(
            "subreddits",
            Status::Absent,
            "no subreddit activity in the recent window",
            None,
        );
    }
    let mut ranked: Vec<(String, usize)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let list: Vec<String> = ranked.iter().map(|(s, _)| format!("r/{s}")).collect();
    Hit::new(
        "subreddits",
        Status::Confirmed,
        list.join(", "),
        Some(
            json!({"subreddits": ranked.iter().map(|(s, n)| json!({"name": s, "hits": n})).collect::<Vec<_>>()}),
        ),
    )
}

fn earliest(meta: &Value) -> Option<u64> {
    let a = meta["earliest_post_at"].as_u64().unwrap_or(0);
    let b = meta["earliest_comment_at"].as_u64().unwrap_or(0);
    match (a, b) {
        (0, 0) => None,
        (0, b) => Some(b),
        (a, 0) => Some(a),
        (a, b) => Some(a.min(b)),
    }
}

fn latest(meta: &Value) -> Option<u64> {
    let a = meta["last_post_at"].as_u64().unwrap_or(0);
    let b = meta["last_comment_at"].as_u64().unwrap_or(0);
    match (a, b) {
        (0, 0) => None,
        (0, b) => Some(b),
        (a, 0) => Some(a),
        (a, b) => Some(a.max(b)),
    }
}

fn reddit_url(permalink: &str) -> String {
    if permalink.is_empty() {
        String::new()
    } else {
        format!("https://www.reddit.com{permalink}")
    }
}

fn num(meta: &Value, key: &str) -> i64 {
    meta[key].as_i64().unwrap_or(0)
}

fn text(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn clip(s: &str, n: usize) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.chars().take(n).collect()
}

fn iso(secs: Option<u64>) -> String {
    secs.filter(|s| *s > 0)
        .map(crate::finding::iso8601)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_names_and_urls() {
        assert_eq!(resolve("spez").unwrap(), "spez");
        assert_eq!(resolve("u/spez").unwrap(), "spez");
        assert_eq!(resolve("https://www.reddit.com/user/spez").unwrap(), "spez");
        assert_eq!(resolve("reddit.com/u/spez/").unwrap(), "spez");
        assert!(resolve("https://example.com/user/spez").is_err());
        assert!(resolve("ab").is_err());
        assert!(resolve("bad name!").is_err());
    }

    #[test]
    fn builds_findings_from_archive_rows() {
        let user = json!({
            "author": "spez",
            "id": "1w72",
            "_meta": {
                "earliest_post_at": 1119552314,
                "earliest_comment_at": 1134392748,
                "last_post_at": 1751475161,
                "last_comment_at": 1729645028,
                "num_posts": 549,
                "num_comments": 2568,
                "post_karma": 832984,
                "comment_karma": 666948,
                "total_karma": 1499932
            }
        });
        let posts = vec![json!({
            "id": "1vgbkge", "subreddit": "u_spez", "title": "Modernizing Reddit",
            "score": 280, "num_comments": 262, "over_18": false,
            "created": 1785945836, "permalink": "/user/spez/comments/1vgbkge/modernizing/"
        })];
        let comments = vec![json!({
            "id": "p1wosm9", "subreddit": "announcements", "body": "That was the thinking.",
            "score": 5, "created": 1785954710, "permalink": "/r/announcements/comments/1vgbkge/x/p1wosm9/"
        })];
        let meta = &user["_meta"];
        assert_eq!(iso(earliest(meta)), "2005-06-23T18:45:14Z");
        assert_eq!(iso(latest(meta)), "2025-07-02T16:52:41Z");
        assert_eq!(num(meta, "total_karma"), 1499932);

        let profile = Hit::new("profile", Status::Confirmed, "u/spez", None);
        assert_eq!(profile.summary, "u/spez");
        let ph = posts_hit(&Ok(posts));
        assert!(ph.summary.contains("1 archived post(s)"));
        assert!(ph.summary.contains("Modernizing Reddit"));
        let ch = comments_hit(&Ok(comments));
        assert!(ch.summary.contains("1 archived comment(s)"));
        let sh = subreddits_hit(
            &Ok(vec![json!({"subreddit": "announcements"})]),
            &Ok(vec![]),
        );
        assert_eq!(sh.summary, "r/announcements");
        assert!(posts_hit(&Ok(vec![])).status == Status::Absent);
        let err = posts_hit(&Err("Timeout. Maybe slow down a bit".into()));
        assert_eq!(err.status, Status::Inconclusive);
        assert!(err.summary.contains("Timeout"));
    }

    #[test]
    fn missing_user_reads_as_absent() {
        let doc: Value = serde_json::from_str(r#"{"data":[]}"#).unwrap();
        assert!(doc["data"].as_array().unwrap().is_empty());
    }
}
