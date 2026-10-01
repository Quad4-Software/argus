// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! RSS 2.0, Atom, and JSON Feed fetch and search.
//! Saving the report with --store keeps items for a later records search.

use super::siteurl::fetch_public;
use super::{Hit, Report, Status};
use serde_json::{Value, json};
use std::time::Instant;

struct Item {
    title: String,
    link: String,
    date: String,
    summary: String,
}

pub fn scan(raw: &str, query: Option<&str>) -> Result<Report, String> {
    let t0 = Instant::now();
    let (status, final_url, _, body) = fetch_public(raw)?;
    if !(200..400).contains(&status) {
        return Err(format!("feed HTTP {status}"));
    }
    let items = parse_feed(&body)?;
    let q = query.unwrap_or("").trim().to_ascii_lowercase();
    let matched: Vec<&Item> = if q.is_empty() {
        items.iter().collect()
    } else {
        items
            .iter()
            .filter(|it| {
                it.title.to_ascii_lowercase().contains(&q)
                    || it.summary.to_ascii_lowercase().contains(&q)
            })
            .collect()
    };
    let shown: Vec<&Item> = matched.iter().copied().take(40).collect();
    let summary = if q.is_empty() {
        format!("{} item(s) from {final_url}", items.len())
    } else {
        format!("{} match(es) of {} item(s)", matched.len(), items.len())
    };
    let status = if shown.is_empty() {
        Status::Absent
    } else {
        Status::Confirmed
    };
    Ok(Report {
        target: raw.trim().to_string(),
        kind: "feed",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings: vec![Hit::new(
            "feed",
            status,
            summary,
            Some(json!({
                "count": items.len(),
                "matched": matched.len(),
                "items": shown.iter().map(|it| json!({
                    "title": it.title,
                    "link": it.link,
                    "date": it.date,
                    "summary": clip(&it.summary),
                })).collect::<Vec<_>>(),
            })),
        )],
    })
}

fn parse_feed(body: &str) -> Result<Vec<Item>, String> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') {
        return parse_json(trimmed);
    }
    let lower = body.to_ascii_lowercase();
    if lower.contains("<feed") && lower.contains("<entry") {
        return Ok(parse_blocks(body, "entry", true));
    }
    if lower.contains("<rss") || lower.contains("<item") {
        return Ok(parse_blocks(body, "item", false));
    }
    Err("not an RSS, Atom, or JSON feed".into())
}

fn parse_json(body: &str) -> Result<Vec<Item>, String> {
    let v: Value = serde_json::from_str(body).map_err(|e| format!("JSON feed: {e}"))?;
    let version = v.get("version").and_then(|x| x.as_str()).unwrap_or("");
    if !version.contains("jsonfeed.org") && v.get("items").is_none() {
        return Err("not a JSON feed".into());
    }
    let Some(items) = v.get("items").and_then(|x| x.as_array()) else {
        return Ok(Vec::new());
    };
    Ok(items
        .iter()
        .map(|it| Item {
            title: it
                .get("title")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim()
                .to_string(),
            link: it
                .get("url")
                .or_else(|| it.get("external_url"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            date: it
                .get("date_published")
                .or_else(|| it.get("date_modified"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            summary: it
                .get("content_text")
                .or_else(|| it.get("summary"))
                .or_else(|| it.get("content_html"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        })
        .filter(|it| !it.title.is_empty() || !it.link.is_empty())
        .collect())
}

fn parse_blocks(body: &str, tag: &str, atom: bool) -> Vec<Item> {
    let mut out = Vec::new();
    let lower = body.to_ascii_lowercase();
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find(&open) {
        let start = from + rel;
        let Some(rel_end) = lower[start..].find(&close) else {
            break;
        };
        let end = start + rel_end + close.len();
        let block = &body[start..end];
        let title = strip_tags(&tag_text(block, "title"));
        let link = if atom {
            attr_link(block).unwrap_or_else(|| tag_text(block, "link"))
        } else {
            let raw = tag_text(block, "link");
            if raw.is_empty() {
                attr_link(block).unwrap_or_default()
            } else {
                raw
            }
        };
        let date = {
            let d = if atom {
                tag_text(block, "updated")
            } else {
                String::new()
            };
            if d.is_empty() {
                tag_text(block, "published")
            } else {
                d
            }
        };
        let date = if date.is_empty() {
            tag_text(block, "pubdate")
        } else {
            date
        };
        let summary = strip_tags(&{
            let s = tag_text(block, if atom { "summary" } else { "description" });
            if s.is_empty() {
                tag_text(block, "content")
            } else {
                s
            }
        });
        if !title.is_empty() || !link.is_empty() {
            out.push(Item {
                title,
                link: link.trim().to_string(),
                date,
                summary,
            });
        }
        from = end;
        if out.len() >= 200 {
            break;
        }
    }
    out
}

fn tag_text(block: &str, tag: &str) -> String {
    let lower = block.to_ascii_lowercase();
    let open = format!("<{tag}");
    let Some(rel) = lower.find(&open) else {
        return String::new();
    };
    let start = rel;
    let Some(gt) = lower[start..].find('>') else {
        return String::new();
    };
    if lower.as_bytes().get(start + gt - 1) == Some(&b'/') {
        return String::new();
    }
    let inner_at = start + gt + 1;
    let close = format!("</{tag}>");
    let Some(rel_end) = lower[inner_at..].find(&close) else {
        return String::new();
    };
    unwrap_cdata(block[inner_at..inner_at + rel_end].trim())
}

fn attr_link(block: &str) -> Option<String> {
    let lower = block.to_ascii_lowercase();
    let mut from = 0;
    while let Some(rel) = lower[from..].find("<link") {
        let start = from + rel;
        let rest = &block[start..];
        let lower_rest = &lower[start..];
        let end = lower_rest.find('>').unwrap_or(0);
        let tag = &rest[..end];
        let rel_attr = attr(tag, "rel").unwrap_or_default();
        if rel_attr.is_empty() || rel_attr == "alternate" {
            if let Some(href) = attr(tag, "href") {
                return Some(href);
            }
        }
        from = start + 5;
    }
    None
}

fn attr(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let key = format!("{name}=");
    let rel = lower.find(&key)?;
    let bytes = tag.as_bytes();
    let mut i = rel + key.len();
    if i >= bytes.len() {
        return None;
    }
    let quote = bytes[i];
    if quote == b'"' || quote == b'\'' {
        i += 1;
        let start = i;
        while i < bytes.len() && bytes[i] != quote {
            i += 1;
        }
        Some(tag[start..i].to_string())
    } else {
        None
    }
}

fn unwrap_cdata(text: &str) -> String {
    let t = text.trim();
    if let Some(inner) = t
        .strip_prefix("<![CDATA[")
        .and_then(|s| s.strip_suffix("]]>"))
    {
        inner.trim().to_string()
    } else {
        t.to_string()
    }
}

fn strip_tags(text: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in text.chars() {
        if c == '<' {
            in_tag = true;
        } else if c == '>' {
            in_tag = false;
        } else if !in_tag {
            out.push(c);
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn clip(s: &str) -> String {
    let mut t = s.to_string();
    if t.len() > 240 {
        t.truncate(240);
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rss_atom_and_json_and_a_query() {
        let rss = r#"<rss><channel><item><title><![CDATA[Rust 1.2]]></title><link>https://example.com/a</link><pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate><description>compiler</description></item><item><title>Other</title><link>https://example.com/b</link></item></channel></rss>"#;
        let items = parse_feed(rss).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "Rust 1.2");
        assert_eq!(items[0].link, "https://example.com/a");
        let atom = r#"<feed><entry><title>Hello</title><link href="https://example.com/c"/><updated>2024-01-01T00:00:00Z</updated><summary>note</summary></entry></feed>"#;
        let atom_items = parse_feed(atom).unwrap();
        assert_eq!(atom_items[0].link, "https://example.com/c");
        let json = r#"{"version":"https://jsonfeed.org/version/1.1","items":[{"title":"Rust notes","url":"https://example.com/d","content_text":"feed"}]}"#;
        assert_eq!(parse_feed(json).unwrap()[0].title, "Rust notes");
        let matched: Vec<_> = items
            .iter()
            .filter(|it| it.title.to_ascii_lowercase().contains("rust"))
            .collect();
        assert_eq!(matched.len(), 1);
    }
}
