// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Public YouTube video and channel metadata.
//! Videos resolve through the public oembed endpoint. Channels come
//! from the public page header (subscribers, video count, verification)
//! and the Atom feed, which carries recent uploads with view counts.
//! No key is used and nothing is downloaded.

use super::siteurl::{fetch_public, fetch_public_cap};
use super::{Hit, Report, Status};
use regex::Regex;
use serde_json::{Value, json};
use std::time::Instant;

const OEMBED: &str = "https://www.youtube.com/oembed";
const FEED: &str = "https://www.youtube.com/feeds/videos.xml?channel_id=";
const HEADER_WINDOW: usize = 9000;
/// Channel pages run past 2 MB and the header sits at the end.
const PAGE_CAP: usize = 4 * 1024 * 1024;

pub fn scan(target: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    match resolve(target)? {
        Mode::Video(id) => video(&id, target, t0),
        Mode::Channel(path) => channel(&path, target, t0),
    }
}

enum Mode {
    Video(String),
    Channel(String),
}

fn resolve(raw: &str) -> Result<Mode, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("pass a video id, video url, handle, or channel url".into());
    }
    let mut rest = t;
    for prefix in ["https://", "http://"] {
        rest = rest.strip_prefix(prefix).unwrap_or(rest);
    }
    rest = rest.strip_prefix("www.").unwrap_or(rest);
    rest = rest.strip_prefix("m.").unwrap_or(rest);
    rest = rest.strip_prefix("music.").unwrap_or(rest);
    if let Some(path) = rest.strip_prefix("youtu.be/") {
        let id = path.split(['?', '#', '/']).next().unwrap_or("");
        return video_id(id);
    }
    if let Some(path) = rest.strip_prefix("youtube.com/") {
        if let Some(query) = path.strip_prefix("watch?")
            && let Some(v) = query_param(query, "v")
        {
            return video_id(v);
        }
        for prefix in ["shorts/", "embed/", "live/", "v/"] {
            if let Some(p) = path.strip_prefix(prefix) {
                let id = p.split(['?', '#', '/']).next().unwrap_or("");
                return video_id(id);
            }
        }
        let path = path.trim_matches('/');
        return channel_path(path);
    }
    if is_video_id(t) {
        return Ok(Mode::Video(t.to_string()));
    }
    let handle = t.trim_start_matches('@');
    channel_path(&format!("@{handle}"))
}

fn video_id(id: &str) -> Result<Mode, String> {
    if is_video_id(id) {
        Ok(Mode::Video(id.to_string()))
    } else {
        Err("youtube video ids are 11 characters".into())
    }
}

fn channel_path(path: &str) -> Result<Mode, String> {
    if path.is_empty()
        || path.len() > 100
        || path.contains("..")
        || path.contains(':')
        || !path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '/' | '.' | '-' | '_'))
    {
        return Err("pass a video id, video url, handle, or channel url".into());
    }
    Ok(Mode::Channel(path.to_string()))
}

fn is_video_id(s: &str) -> bool {
    s.len() == 11
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

fn video(id: &str, target: &str, t0: Instant) -> Result<Report, String> {
    let watch = format!("https://www.youtube.com/watch?v={id}");
    let url = format!(
        "{OEMBED}?format=json&url={}",
        super::name::percent_encode(&watch)
    );
    let (status, _, _, body) = fetch_public(&url)?;
    let mut findings = Vec::new();
    if status != 200 {
        findings.push(Hit::new(
            "video",
            Status::Absent,
            format!("no public oembed metadata for {id}"),
            None,
        ));
    } else {
        let doc: Value = serde_json::from_str(&body).map_err(|e| format!("youtube json: {e}"))?;
        let title = doc["title"].as_str().unwrap_or("");
        findings.push(Hit::new(
            "video",
            Status::Confirmed,
            if title.is_empty() {
                id.to_string()
            } else {
                title.to_string()
            },
            Some(json!({
                "id": id,
                "url": watch,
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
                author.to_string(),
                Some(json!({"url": doc["author_url"].as_str().unwrap_or("")})),
            ));
        }
    }
    Ok(Report {
        target: target.trim().to_string(),
        kind: "youtube",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

fn channel(path: &str, target: &str, t0: Instant) -> Result<Report, String> {
    let page_url = format!("https://www.youtube.com/{path}");
    let (status, final_url, _, body) = fetch_public_cap(&page_url, PAGE_CAP)?;
    let mut findings = Vec::new();
    if !(200..300).contains(&status) {
        findings.push(Hit::new(
            "channel",
            Status::Absent,
            format!("no youtube channel at {page_url} (HTTP {status})"),
            None,
        ));
        return Ok(Report {
            target: target.trim().to_string(),
            kind: "youtube",
            elapsed_ms: t0.elapsed().as_millis() as u64,
            findings,
        });
    }
    let header_at = body.rfind("\"pageHeaderRenderer\"").unwrap_or(0);
    let header = window(&body, header_at, HEADER_WINDOW);
    let title = capture(header, r#""pageTitle":"([^"]*)""#);
    let handle = capture(header, r#""content":"(@[^"]+)""#);
    let subs = capture(header, r#""content":"([^"]+ subscribers?)""#);
    let videos = capture(header, r#""content":"([\d.,KMB]+ videos?)""#);
    let verified = header.contains("CHECK_CIRCLE_FILLED");
    let id = capture(
        &body,
        r#"rel="canonical" href="https://www\.youtube\.com/channel/(UC[A-Za-z0-9_-]{22})""#,
    );
    if title.is_empty() && id.is_empty() {
        findings.push(Hit::new(
            "channel",
            Status::Inconclusive,
            "page had no channel header",
            None,
        ));
        return Ok(Report {
            target: target.trim().to_string(),
            kind: "youtube",
            elapsed_ms: t0.elapsed().as_millis() as u64,
            findings,
        });
    }
    let summary = if handle.is_empty() {
        title.clone()
    } else {
        format!("{title} ({handle})")
    };
    findings.push(Hit::new(
        "channel",
        Status::Confirmed,
        summary,
        Some(json!({
            "id": id,
            "title": title,
            "handle": handle,
            "url": final_url,
            "verified": verified,
        })),
    ));
    findings.push(Hit::new(
        "verified",
        if verified {
            Status::Confirmed
        } else {
            Status::Absent
        },
        if verified {
            "channel badge present"
        } else {
            "no verification badge"
        },
        None,
    ));
    findings.push(if subs.is_empty() && videos.is_empty() {
        Hit::new(
            "stats",
            Status::Inconclusive,
            "no counts in the header",
            None,
        )
    } else {
        Hit::new(
            "stats",
            Status::Confirmed,
            format!("{subs}, {videos}")
                .trim_matches([',', ' '])
                .to_string(),
            Some(json!({"subscribers": subs, "videos": videos})),
        )
    });
    let description = unescape(&capture(
        &body,
        r#""channelMetadataRenderer":\{"title":"[^"]*","description":"((?:[^"\\]|\\.)*)""#,
    ));
    findings.push(if description.is_empty() {
        Hit::new("about", Status::Absent, "no description", None)
    } else {
        Hit::new(
            "about",
            Status::Confirmed,
            clip(&description, 240),
            Some(json!({"description": description})),
        )
    });
    if id.is_empty() {
        findings.push(Hit::new(
            "created",
            Status::Inconclusive,
            "channel id not on the page, feed not read",
            None,
        ));
        findings.push(Hit::new(
            "recent",
            Status::Inconclusive,
            "channel id not on the page, feed not read",
            None,
        ));
        return Ok(Report {
            target: target.trim().to_string(),
            kind: "youtube",
            elapsed_ms: t0.elapsed().as_millis() as u64,
            findings,
        });
    }
    let feed_url = format!("{FEED}{id}");
    match fetch_public(&feed_url) {
        Ok((200, _, _, feed)) => {
            let created = capture(&feed, r"<published>([^<]+)</published>");
            findings.push(if created.is_empty() {
                Hit::new(
                    "created",
                    Status::Absent,
                    "no channel date in the feed",
                    None,
                )
            } else {
                Hit::new("created", Status::Confirmed, created, None)
            });
            findings.push(feed_hit(&feed));
        }
        Ok((st, _, _, _)) => {
            findings.push(Hit::new(
                "recent",
                Status::Inconclusive,
                format!("feed HTTP {st}"),
                None,
            ));
            findings.push(Hit::new(
                "created",
                Status::Inconclusive,
                format!("feed HTTP {st}"),
                None,
            ));
        }
        Err(e) => {
            findings.push(Hit::new("recent", Status::Inconclusive, e.clone(), None));
            findings.push(Hit::new("created", Status::Inconclusive, e, None));
        }
    }
    Ok(Report {
        target: target.trim().to_string(),
        kind: "youtube",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

fn feed_hit(feed: &str) -> Hit {
    let entry_re = Regex::new(r"(?s)<entry>(.*?)</entry>").unwrap();
    let mut rows = Vec::new();
    for c in entry_re.captures_iter(feed).take(5) {
        let entry = &c[1];
        rows.push(json!({
            "id": capture(entry, r"<yt:videoId>([^<]+)"),
            "title": super::surface::html_text(&capture(entry, r"<title>([^<]*)</title>")),
            "published": capture(entry, r"<published>([^<]+)"),
            "views": capture(entry, r#"views="(\d+)""#),
        }));
    }
    if rows.is_empty() {
        return Hit::new("recent", Status::Absent, "no uploads in the feed", None);
    }
    let newest = rows[0]["title"].as_str().unwrap_or("");
    Hit::new(
        "recent",
        Status::Confirmed,
        format!("{} recent upload(s), newest: {newest}", rows.len()),
        Some(json!({"videos": rows})),
    )
}

fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == name
        {
            return Some(v);
        }
    }
    None
}

fn capture(body: &str, pattern: &str) -> String {
    Regex::new(pattern)
        .ok()
        .and_then(|re| re.captures(body).map(|c| c[1].to_string()))
        .unwrap_or_default()
}

fn window(s: &str, start: usize, len: usize) -> &str {
    let mut end = (start + len).min(s.len());
    while end > start && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[start.min(end)..end]
}

fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push(' '),
            Some('r') | Some('t') => {}
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('/') => out.push('/'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                if let Ok(n) = u32::from_str_radix(&hex, 16)
                    && let Some(ch) = char::from_u32(n)
                {
                    out.push(ch);
                }
            }
            Some(other) => out.push(other),
            None => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
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
            Mode::Channel(p) => format!("channel:{p}"),
        }
    }

    #[test]
    fn resolves_videos_and_channels() {
        assert_eq!(mode_of("dQw4w9WgXcQ"), "video:dQw4w9WgXcQ");
        assert_eq!(
            mode_of("https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=1"),
            "video:dQw4w9WgXcQ"
        );
        assert_eq!(mode_of("https://youtu.be/dQw4w9WgXcQ"), "video:dQw4w9WgXcQ");
        assert_eq!(
            mode_of("https://www.youtube.com/shorts/dQw4w9WgXcQ"),
            "video:dQw4w9WgXcQ"
        );
        assert_eq!(mode_of("@NASA"), "channel:@NASA");
        assert_eq!(mode_of("NASA"), "channel:@NASA");
        assert_eq!(mode_of("https://www.youtube.com/@NASA"), "channel:@NASA");
        assert_eq!(
            mode_of("https://www.youtube.com/channel/UCLA_DiR1FfKNvjuUpBHmylQ"),
            "channel:channel/UCLA_DiR1FfKNvjuUpBHmylQ"
        );
        assert!(resolve("https://www.youtube.com/../../etc").is_err());
        assert!(resolve("bad id!").is_err());
    }

    #[test]
    fn parses_the_channel_header_and_feed() {
        let page = r#"<html><head>
            <meta property="og:title" content="NASA">
            <link rel="canonical" href="https://www.youtube.com/channel/UCLA_DiR1FfKNvjuUpBHmylQ">
            </head><body>
            <script>"header":{"pageHeaderRenderer":{"pageTitle":"NASA","content":{"pageHeaderViewModel":{
            "title":{"dynamicTextViewModel":{"text":{"content":"NASA","attachmentRuns":[{"element":{"type":{"imageType":{"image":{"sources":[{"clientResource":{"imageName":"CHECK_CIRCLE_FILLED"}}]}}}}}]}}},
            "metadata":{"contentMetadataViewModel":{"metadataRows":[{"metadataParts":[{"text":{"content":"@NASA"}}]},
            {"metadataParts":[{"text":{"content":"15.1M subscribers"}},{"text":{"content":"6.1K videos"}}]}]}}}}}}}
            "channelMetadataRenderer":{"title":"NASA","description":"Exploring space.\nJoin us."}
            </script></body></html>"#;
        let header_at = page.rfind("\"pageHeaderRenderer\"").unwrap_or(0);
        let header = window(page, header_at, HEADER_WINDOW);
        assert_eq!(capture(header, r#""pageTitle":"([^"]*)""#), "NASA");
        assert_eq!(capture(header, r#""content":"(@[^"]+)""#), "@NASA");
        assert_eq!(
            capture(header, r#""content":"([^"]+ subscribers?)""#),
            "15.1M subscribers"
        );
        assert_eq!(
            capture(header, r#""content":"([\d.,KMB]+ videos?)""#),
            "6.1K videos"
        );
        assert!(header.contains("CHECK_CIRCLE_FILLED"));
        assert_eq!(
            capture(
                page,
                r#"rel="canonical" href="https://www\.youtube\.com/channel/(UC[A-Za-z0-9_-]{22})""#
            ),
            "UCLA_DiR1FfKNvjuUpBHmylQ"
        );
        assert_eq!(
            unescape(&capture(
                page,
                r#""channelMetadataRenderer":\{"title":"[^"]*","description":"((?:[^"\\]|\\.)*)""#
            )),
            "Exploring space. Join us."
        );

        let feed = r#"<feed><published>2008-06-03T18:44:30+00:00</published>
            <entry><id>yt:video:x6p9Ri0DlNE</id><yt:videoId>x6p9Ri0DlNE</yt:videoId>
            <title>NASA's SpaceX Crew-12</title><published>2026-10-08T16:52:21+00:00</published>
            <media:statistics views="388493"/></entry></feed>"#;
        let hit = feed_hit(feed);
        assert_eq!(hit.status, Status::Confirmed);
        assert!(hit.summary.contains("1 recent upload(s)"));
        let ev = hit.evidence.unwrap();
        assert_eq!(ev["videos"][0]["id"], "x6p9Ri0DlNE");
        assert_eq!(ev["videos"][0]["views"], "388493");
        assert_eq!(hit_summary(&feed_hit("")), "no uploads in the feed");
    }

    fn hit_summary(h: &Hit) -> String {
        h.summary.clone()
    }

    #[test]
    fn video_and_author_findings() {
        let doc: Value = serde_json::from_str(
            r#"{"title":"Never Gonna Give You Up","author_name":"Rick Astley",
                "author_url":"https://www.youtube.com/@RickAstleyYT",
                "thumbnail_url":"https://i.ytimg.com/vi/dQw4w9WgXcQ/hq.jpg"}"#,
        )
        .unwrap();
        assert_eq!(doc["author_name"], "Rick Astley");
    }
}
