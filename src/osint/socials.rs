// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Social and resume links from a public page.
//! Link-in-bio hubs are fetched once and their outbound links are extracted
//! with the same parser. A challenge page is reported. It is not solved.

use super::siteurl::fetch_public;
use super::waf;
use super::{Hit, Report, Status};
use serde_json::json;
use std::collections::BTreeSet;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Social {
    pub platform: String,
    pub url: String,
}

pub fn scan(raw: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    let (status, final_url, headers, body) = fetch_public(raw)?;
    let host = host_of(&final_url);
    let challenge = waf::detect(&headers, &body);
    let mut socials = extract(&body);
    let mut resumes = resume_links(&body);
    if is_link_hub(&host) || socials.iter().any(|s| is_link_hub_platform(&s.platform)) {
        let hubs: Vec<String> = socials
            .iter()
            .filter(|s| is_link_hub_platform(&s.platform))
            .map(|s| s.url.clone())
            .take(2)
            .collect();
        let extra = if is_link_hub(&host) && hubs.is_empty() {
            Vec::new()
        } else {
            hubs
        };
        for hub in extra {
            if let Ok((st, _, _, page)) = fetch_public(&hub)
                && (200..400).contains(&st)
            {
                socials.extend(extract(&page));
                resumes.extend(resume_links(&page));
            }
        }
        if is_link_hub(&host) {
            socials.extend(hub_outbounds(&body));
        }
    }
    socials.retain(|s| s.platform != "linktree" || !is_link_hub(&host));
    dedup(&mut socials, &mut resumes);
    let mut findings = vec![challenge];
    if socials.is_empty() {
        let blocked = findings
            .first()
            .is_some_and(|h| h.status == Status::Confirmed && h.module == "waf");
        findings.push(Hit::new(
            "socials",
            if blocked {
                Status::Inconclusive
            } else {
                Status::Absent
            },
            if blocked {
                "challenge page, profile links not read"
            } else {
                "no social profile links"
            },
            None,
        ));
    } else {
        findings.push(Hit::new(
            "socials",
            Status::Confirmed,
            format!("{} profile link(s)", socials.len()),
            Some(json!({
                "links": socials.iter().map(|s| json!({"platform": s.platform, "url": s.url})).collect::<Vec<_>>()
            })),
        ));
        for s in &socials {
            findings.push(Hit::new(
                &s.platform,
                Status::Confirmed,
                s.url.clone(),
                None,
            ));
        }
    }
    if resumes.is_empty() {
        findings.push(Hit::new(
            "resume",
            Status::Absent,
            "no resume or cv link on the page",
            None,
        ));
    } else {
        findings.push(Hit::new(
            "resume",
            Status::Confirmed,
            format!("{} resume link(s)", resumes.len()),
            Some(json!({ "links": resumes })),
        ));
    }
    let _ = status;
    Ok(Report {
        target: raw.trim().to_string(),
        kind: "socials",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

pub(crate) fn extract(body: &str) -> Vec<Social> {
    let mut out = Vec::new();
    for url in urls_in(body) {
        if let Some(platform) = platform_of(&url) {
            out.push(Social {
                platform: platform.to_string(),
                url: trim_query(&url),
            });
        }
    }
    out
}

pub(crate) fn resume_links(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for url in urls_in(body) {
        let lower = url.to_ascii_lowercase();
        let path = lower.split('?').next().unwrap_or(&lower);
        let doc = path.ends_with(".pdf")
            || path.ends_with(".doc")
            || path.ends_with(".docx")
            || path.ends_with(".odt")
            || path.ends_with(".rtf");
        let named = path.contains("resume") || path.contains("curriculum") || path_has_cv(path);
        if doc && named {
            out.push(trim_query(&url));
        }
    }
    out
}

fn hub_outbounds(body: &str) -> Vec<Social> {
    urls_in(body)
        .into_iter()
        .filter(|u| {
            let lower = u.to_ascii_lowercase();
            lower.starts_with("https://")
                && !is_asset(&lower)
                && !skip_outbound(&lower)
                && platform_of(u).is_none()
                && !is_link_hub(&host_of(u))
        })
        .map(|u| Social {
            platform: "link".into(),
            url: trim_query(&u),
        })
        .collect()
}

fn urls_in(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i + 8 < bytes.len() {
        if bytes[i] >= 128 {
            i += 1;
            while i < bytes.len() && bytes[i] & 0b1100_0000 == 0b1000_0000 {
                i += 1;
            }
            continue;
        }
        let window = &body[i..];
        let lower = window.as_bytes();
        let https = lower.len() >= 8 && lower[..8].eq_ignore_ascii_case(b"https://");
        let http = lower.len() >= 7 && lower[..7].eq_ignore_ascii_case(b"http://");
        if https || http {
            let start = i;
            let mut j = if https { i + 8 } else { i + 7 };
            while j < bytes.len() {
                let c = bytes[j];
                if c.is_ascii_whitespace()
                    || matches!(
                        c,
                        b'"' | b'\'' | b'<' | b'>' | b')' | b']' | b'{' | b'}' | b'\\'
                    )
                {
                    break;
                }
                j += 1;
            }
            let mut url = body[start..j].trim_end_matches(['.', ',', ';']).to_string();
            if url.len() < 300 && !url.to_ascii_lowercase().starts_with("http://localhost") {
                out.push(std::mem::take(&mut url));
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

fn platform_of(url: &str) -> Option<&'static str> {
    let host = host_of(url);
    let host = host.strip_prefix("www.").unwrap_or(&host);
    let host = host.strip_prefix("m.").unwrap_or(host);
    if host == "github.com" || host == "gist.github.com" {
        return Some("github");
    }
    if host == "gitlab.com" {
        return Some("gitlab");
    }
    if host == "codeberg.org" {
        return Some("codeberg");
    }
    if host == "twitter.com" || host == "x.com" || host == "mobile.twitter.com" {
        return Some("x");
    }
    if host == "bsky.app" {
        return Some("bluesky");
    }
    if host == "linkedin.com" {
        return Some("linkedin");
    }
    if host == "youtube.com" || host == "youtu.be" {
        return Some("youtube");
    }
    if host == "twitch.tv" {
        return Some("twitch");
    }
    if host == "tiktok.com" {
        return Some("tiktok");
    }
    if host == "medium.com" || host.ends_with(".medium.com") {
        return Some("medium");
    }
    if host == "pinterest.com" {
        return Some("pinterest");
    }
    if host == "instagram.com" {
        return Some("instagram");
    }
    if host == "facebook.com" || host == "fb.com" {
        return Some("facebook");
    }
    if host == "t.me" || host == "telegram.me" {
        return Some("telegram");
    }
    if host == "discord.gg" || host == "discord.com" {
        return Some("discord");
    }
    if host == "reddit.com" {
        return Some("reddit");
    }
    if host == "keybase.io" {
        return Some("keybase");
    }
    if matches!(
        host,
        "mastodon.social" | "fosstodon.org" | "hachyderm.io" | "infosec.exchange"
    ) {
        return Some("mastodon");
    }
    if host == "linktr.ee" || host == "linktree.com" {
        return Some("linktree");
    }
    if host == "bio.link" {
        return Some("biolink");
    }
    if host == "beacons.ai" {
        return Some("beacons");
    }
    if host == "solo.to" {
        return Some("solo");
    }
    if host == "lnk.bio" {
        return Some("lnkbio");
    }
    if host == "campsite.bio" || host == "allmylinks.com" || host == "bento.me" || host == "hoo.be"
    {
        return Some("linkhub");
    }
    if host == "about.me" || host.ends_with(".carrd.co") {
        return Some("linkhub");
    }
    None
}

fn is_link_hub(host: &str) -> bool {
    let host = host.strip_prefix("www.").unwrap_or(host);
    matches!(
        host,
        "linktr.ee"
            | "linktree.com"
            | "bio.link"
            | "beacons.ai"
            | "solo.to"
            | "lnk.bio"
            | "campsite.bio"
            | "allmylinks.com"
            | "bento.me"
            | "hoo.be"
            | "about.me"
    ) || host.ends_with(".carrd.co")
}

fn is_link_hub_platform(platform: &str) -> bool {
    matches!(
        platform,
        "linktree" | "biolink" | "beacons" | "solo" | "lnkbio" | "linkhub"
    )
}

fn is_asset(url: &str) -> bool {
    let path = url.split('?').next().unwrap_or(url);
    path.ends_with(".css")
        || path.ends_with(".js")
        || path.ends_with(".png")
        || path.ends_with(".jpg")
        || path.ends_with(".jpeg")
        || path.ends_with(".svg")
        || path.ends_with(".woff")
        || path.ends_with(".woff2")
        || path.ends_with(".webp")
        || path.ends_with(".avif")
        || path.ends_with(".gif")
        || path.ends_with(".ico")
        || path.ends_with(".json")
        || path.ends_with(".webmanifest")
        || path.ends_with(".map")
}

fn skip_outbound(url: &str) -> bool {
    let host = host_of(url);
    let host = host.strip_prefix("www.").unwrap_or(&host).to_string();
    host == "schema.org"
        || host.ends_with(".schema.org")
        || host.ends_with("googleapis.com")
        || host.ends_with("gstatic.com")
        || host == "w3.org"
        || host.ends_with(".w3.org")
        || (host.ends_with("linktr.ee") && host != "linktr.ee")
        || host.ends_with("gmpg.org")
}

fn path_has_cv(path: &str) -> bool {
    path.split(['/', '-', '_', '.']).any(|p| p == "cv")
}

fn trim_query(url: &str) -> String {
    url.split('?')
        .next()
        .unwrap_or(url)
        .trim_end_matches('/')
        .to_string()
}

fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    host.split('@')
        .next_back()
        .unwrap_or(host)
        .to_ascii_lowercase()
}

fn dedup(socials: &mut Vec<Social>, resumes: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    socials.retain(|s| seen.insert(format!("{} {}", s.platform, s.url)));
    let mut seen_r = BTreeSet::new();
    resumes.retain(|r| seen_r.insert(r.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_fixture_finds_profiles_and_a_resume() {
        let html = r#"
            <p>hello…</p>
            <a href="https://github.com/octocat">gh</a>
            <a href="https://linktr.ee/octocat">links</a>
            <a href="https://example.com/files/Ada-Resume.pdf">cv</a>
            <a href="https://cdn.example.com/app.js">js</a>
            <script>{"url":"https://mastodon.social/@octocat"}</script>
        "#;
        let socials = extract(html);
        assert!(
            socials
                .iter()
                .any(|s| s.platform == "github" && s.url.ends_with("/octocat"))
        );
        assert!(socials.iter().any(|s| s.platform == "linktree"));
        assert!(socials.iter().any(|s| s.platform == "mastodon"));
        assert!(!socials.iter().any(|s| s.url.ends_with(".js")));
        let resumes = resume_links(html);
        assert_eq!(resumes.len(), 1);
        assert!(resumes[0].contains("Ada-Resume.pdf"));
        assert!(skip_outbound(
            "https://assets.production.linktr.ee/fonts/v1/LinkSansProduct.woff2"
        ));
        assert!(skip_outbound("https://schema.org/ProfilePage"));
        assert!(!skip_outbound("https://armra.com"));
    }
}
