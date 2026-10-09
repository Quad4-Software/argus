// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Public Steam community profile.
//! One page fetch and, unless the profile is private, the alias
//! endpoint for previous persona names. Counts come from the sidebar
//! and reflect what Steam shows a logged-out visitor. A persona is a
//! lead, not proof of identity.

use super::siteurl::fetch_public_no_gzip;
use super::surface::html_text;
use super::{Hit, Report, Status};
use regex::Regex;
use serde_json::{Map, Value, json};
use std::time::Instant;

pub fn scan(target: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    let path = resolve(target)?;
    let url = format!("https://steamcommunity.com/{path}");
    let (status, final_url, _, body) = fetch_public_no_gzip(&url)?;
    let mut findings = Vec::new();
    if status == 404 || body.contains("The specified profile could not be found") {
        findings.push(Hit::new(
            "profile",
            Status::Absent,
            format!("no steam profile at {url}"),
            None,
        ));
    } else if !(200..300).contains(&status) {
        return Err(format!("steam profile HTTP {status}"));
    } else {
        let mut p = parse(&body);
        if p.persona.is_empty() {
            findings.push(Hit::new(
                "profile",
                Status::Inconclusive,
                "profile page had no persona block",
                None,
            ));
        } else {
            if !p.private {
                p.aliases = aliases(&path);
            }
            findings = report_hits(&p, &final_url);
        }
    }
    Ok(Report {
        target: target.trim().to_string(),
        kind: "steam",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

fn resolve(raw: &str) -> Result<String, String> {
    let mut t = raw.trim();
    for prefix in ["https://", "http://"] {
        t = t.strip_prefix(prefix).unwrap_or(t);
    }
    t = t.strip_prefix("www.").unwrap_or(t);
    t = t.strip_prefix("steamcommunity.com/").unwrap_or(t);
    let t = t.split(['?', '#']).next().unwrap_or(t).trim_matches('/');
    if let Some(id) = t.strip_prefix("profiles/") {
        if !id.is_empty() && id.chars().all(|c| c.is_ascii_digit()) {
            return Ok(format!("profiles/{id}"));
        }
        return Err("steam profile id must be digits".into());
    }
    let vanity = t.strip_prefix("id/").unwrap_or(t);
    if vanity.is_empty() {
        return Err("pass a steam vanity name, id64, or profile url".into());
    }
    if vanity.chars().all(|c| c.is_ascii_digit()) {
        return Ok(format!("profiles/{vanity}"));
    }
    if vanity.len() > 64
        || !vanity
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err("steam vanity names use letters, digits, dot, underscore, or hyphen".into());
    }
    Ok(format!("id/{vanity}"))
}

#[derive(Debug, Default)]
struct Profile {
    persona: String,
    steam_id: String,
    custom_url: String,
    real_name: String,
    location: String,
    bio: String,
    level: String,
    xp: String,
    badge: String,
    avatar: String,
    frame: String,
    flag: String,
    status: String,
    private: bool,
    counts: Vec<(String, String)>,
    recent: Vec<RecentGame>,
    aliases: Vec<(String, String)>,
}

#[derive(Debug)]
struct RecentGame {
    app_id: String,
    name: String,
    hours: String,
    last_played: String,
}

fn parse(body: &str) -> Profile {
    let mut p = Profile {
        persona: text_capture(body, r#"actual_persona_name">([^<]+)</span>"#),
        custom_url: capture(body, r#"steamcommunity\.com/id/([^/"?]+)"#),
        real_name: text_capture(body, r#"header_real_name[^>]*>\s*<bdi>([^<]+)</bdi>"#),
        location: text_capture(body, r#"(?s)header_location">(.*?)</div>"#),
        bio: text_capture(body, r#"(?s)class="profile_summary[^"]*">(.*?)</div>"#),
        level: capture(body, r#"friendPlayerLevelNum">(\d+)</span>"#),
        xp: capture(body, r#"class="xp">([\d,]+)\s*XP</div>"#),
        badge: text_capture(
            body,
            r#"data-tooltip-html="([^"]+)"[^>]*>\s*<img[^>]*class="badge_icon"#,
        ),
        avatar: capture(body, r#"property="og:image" content="([^"]+)""#),
        frame: capture(
            body,
            r#"(?s)profile_avatar_frame">.*?(?:srcset|src)="([^"]+)""#,
        ),
        flag: capture(body, r#"class="profile_flag" src="([^"]+)""#),
        ..Profile::default()
    };
    for re in [
        r#""steamid":"(\d+)""#,
        r#"steamcommunity\.com/profiles/(\d+)"#,
    ] {
        if let Some(id) = capture_opt(body, re) {
            p.steam_id = id;
            break;
        }
    }
    p.status = if body.contains("playerAvatar profile_header_size in-game")
        || body.contains(r#"class="playerAvatar profile_header_size" in-game"#)
    {
        "in-game".to_string()
    } else if body.contains("playerAvatar profile_header_size online") {
        "online".to_string()
    } else if body.contains("playerAvatar profile_header_size offline") {
        "offline".to_string()
    } else {
        String::new()
    };
    p.private = body.contains("This profile is private") || body.contains("profile_private_info");
    let count_re = Regex::new(
        r#"count_link_label">([^<]+)</span>&nbsp;\s*<span class="profile_count_link_total">\s*([0-9,]+)"#,
    )
    .unwrap();
    for c in count_re.captures_iter(body) {
        p.counts.push((c[1].to_string(), c[2].to_string()));
    }
    let recent_re = Regex::new(
        r#"(?s)<div class="game_info">.{0,300}?href="https://steamcommunity\.com/app/(\d+)".{0,600}?<div class="game_info_details">(.*?)</div>.{0,300}?<div class="game_name">\s*<a[^>]*>([^<]+)</a>"#,
    )
    .unwrap();
    for c in recent_re.captures_iter(body) {
        let details = html_text(&c[2]);
        p.recent.push(RecentGame {
            app_id: c[1].to_string(),
            name: html_text(&c[3]),
            hours: capture(&details, r#"([\d,]+)\s*hrs on record"#),
            last_played: capture(&details, r#"last played on (.+)$"#),
        });
    }
    p
}

fn aliases(path: &str) -> Vec<(String, String)> {
    let url = format!("https://steamcommunity.com/{path}/ajaxaliases");
    let Ok((status, _, _, body)) = fetch_public_no_gzip(&url) else {
        return Vec::new();
    };
    if status != 200 {
        return Vec::new();
    }
    let rows: Vec<Value> = serde_json::from_str(&body).unwrap_or_default();
    rows.iter()
        .filter_map(|r| {
            let name = r.get("newname").and_then(|v| v.as_str())?;
            let when = r.get("timechanged").and_then(|v| v.as_str()).unwrap_or("");
            Some((name.to_string(), when.to_string()))
        })
        .collect()
}

fn report_hits(p: &Profile, url: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    let mut summary = p.persona.clone();
    if !p.real_name.is_empty() {
        summary.push_str(&format!(" ({})", p.real_name));
    }
    if !p.level.is_empty() {
        summary.push_str(&format!(", level {}", p.level));
    }
    out.push(Hit::new(
        "profile",
        Status::Confirmed,
        summary,
        Some(json!({
            "persona": p.persona,
            "steam_id": p.steam_id,
            "custom_url": p.custom_url,
            "level": p.level,
            "badge_xp": p.xp,
            "favorite_badge": p.badge,
            "avatar": p.avatar,
            "avatar_frame": p.frame,
            "country_flag": p.flag,
            "url": url,
        })),
    ));
    if p.real_name.is_empty() && p.location.is_empty() && p.bio.is_empty() {
        out.push(Hit::new(
            "identity",
            Status::Absent,
            "no name, location, or bio on the profile",
            None,
        ));
    } else {
        let mut bits = Vec::new();
        if !p.real_name.is_empty() {
            bits.push(p.real_name.clone());
        }
        if !p.location.is_empty() {
            bits.push(p.location.clone());
        }
        out.push(Hit::new(
            "identity",
            Status::Confirmed,
            if bits.is_empty() {
                "bio text".to_string()
            } else {
                bits.join(", ")
            },
            Some(json!({
                "real_name": p.real_name,
                "location": p.location,
                "bio": p.bio,
            })),
        ));
    }
    out.push(if p.status.is_empty() {
        Hit::new("status", Status::Inconclusive, "status not shown", None)
    } else {
        Hit::new("status", Status::Confirmed, p.status.clone(), None)
    });
    out.push(if p.private {
        Hit::new(
            "private",
            Status::Confirmed,
            "profile is private, counts are hidden",
            None,
        )
    } else {
        Hit::new("private", Status::Absent, "profile is public", None)
    });
    if p.counts.is_empty() {
        out.push(Hit::new(
            "counts",
            if p.private {
                Status::Inconclusive
            } else {
                Status::Absent
            },
            "no counts on the page",
            None,
        ));
    } else {
        let summary = p
            .counts
            .iter()
            .map(|(k, v)| format!("{k} {v}"))
            .collect::<Vec<_>>()
            .join(", ");
        let mut map = Map::new();
        for (k, v) in &p.counts {
            map.insert(k.clone(), json!(v));
        }
        out.push(Hit::new(
            "counts",
            Status::Confirmed,
            summary,
            Some(json!({"counts": map})),
        ));
    }
    if p.aliases.is_empty() {
        out.push(Hit::new(
            "names",
            Status::Absent,
            "no recorded name changes",
            None,
        ));
    } else {
        out.push(Hit::new(
            "names",
            Status::Confirmed,
            format!("{} name change(s)", p.aliases.len()),
            Some(json!({
                "names": p.aliases.iter().map(|(n, t)| json!({"name": n, "changed": t})).collect::<Vec<_>>()
            })),
        ));
    }
    if p.recent.is_empty() {
        out.push(Hit::new(
            "recent",
            Status::Absent,
            "no recent games shown",
            None,
        ));
    } else {
        out.push(Hit::new(
            "recent",
            Status::Confirmed,
            format!("{} recent game(s)", p.recent.len()),
            Some(json!({
                "games": p.recent.iter().map(|g| json!({
                    "app_id": g.app_id,
                    "name": g.name,
                    "hours": g.hours,
                    "last_played": g.last_played,
                })).collect::<Vec<_>>()
            })),
        ));
    }
    out
}

fn capture(body: &str, pattern: &str) -> String {
    capture_opt(body, pattern).unwrap_or_default()
}

fn capture_opt(body: &str, pattern: &str) -> Option<String> {
    Regex::new(pattern)
        .ok()?
        .captures(body)
        .map(|c| c[1].to_string())
}

fn text_capture(body: &str, pattern: &str) -> String {
    capture_opt(body, pattern)
        .map(|raw| html_text(&raw))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"<html><head>
        <meta property="og:image" content="https://avatars.example/zed_full.jpg">
        </head><body>
        <div class="playerAvatar profile_header_size online" data-miniprofile="55384244">
        <div class="playerAvatarAutoSizeInner">
        <div class="profile_avatar_frame"><picture><source srcset="https://shared.example/frame.png"></source>
        <img src="https://shared.example/frame.png"></picture></div>
        <picture><source srcset="https://avatars.example/zed_full.jpg"></source>
        <img srcset="https://avatars.example/zed_full.jpg"></picture></div></div>
        <span class="actual_persona_name">Zed</span>
        <div class="header_real_name ellipsis"><bdi>Ken Wolfe</bdi>
        <div class="header_location"><img class="profile_flag" src="https://flags.example/us.gif">
        Florida, United States</div></div>
        <div class="profile_summary noexpand">shipping software<br>and games</div>
        <script>"steamid":"76561198015649972"</script>
        <span class="friendPlayerLevelNum">126</span>
        <div class="xp">100 XP</div>
        <a data-tooltip-html="Steam Grand Prix 2019 &lt;br&gt;Team Corgi" href="/badges"><img class="badge_icon small" src="x.png"></a>
        <a href="https://steamcommunity.com/profiles/76561198015649972/games/?tab=all"><span class="count_link_label">Games</span>&nbsp;<span class="profile_count_link_total">827</span></a>
        <a href="https://steamcommunity.com/profiles/76561198015649972/friends/"><span class="count_link_label">Friends</span>&nbsp;<span class="profile_count_link_total">34</span></a>
        <div class="game_info"><div class="game_info_cap"><a href="https://steamcommunity.com/app/960090"><img class="game_capsule" src="c.jpg"></a></div>
        <div class="game_info_details">894 hrs on record<br>last played on Oct 7</div>
        <div class="game_name"><a class="whiteLink" href="https://steamcommunity.com/app/960090">Bloons TD 6</a></div></div>
        </body></html>"#;

    #[test]
    fn resolves_vanity_ids_and_urls() {
        assert_eq!(resolve("zed").unwrap(), "id/zed");
        assert_eq!(
            resolve("76561198015649972").unwrap(),
            "profiles/76561198015649972"
        );
        assert_eq!(
            resolve("https://steamcommunity.com/id/zed").unwrap(),
            "id/zed"
        );
        assert_eq!(
            resolve("steamcommunity.com/profiles/76561198015649972").unwrap(),
            "profiles/76561198015649972"
        );
        assert_eq!(resolve("id/zed?x=1").unwrap(), "id/zed");
        assert!(resolve("").is_err());
        assert!(resolve("profiles/notdigits").is_err());
        assert!(resolve("bad name!").is_err());
    }

    #[test]
    fn parses_a_public_profile() {
        let p = parse(PAGE);
        assert_eq!(p.persona, "Zed");
        assert_eq!(p.steam_id, "76561198015649972");
        assert_eq!(p.real_name, "Ken Wolfe");
        assert_eq!(p.location, "Florida, United States");
        assert_eq!(p.bio, "shipping software and games");
        assert_eq!(p.level, "126");
        assert_eq!(p.xp, "100");
        assert_eq!(p.avatar, "https://avatars.example/zed_full.jpg");
        assert_eq!(p.frame, "https://shared.example/frame.png");
        assert_eq!(p.flag, "https://flags.example/us.gif");
        assert_eq!(p.status, "online");
        assert!(!p.private);
        assert_eq!(
            p.counts,
            vec![
                ("Games".to_string(), "827".to_string()),
                ("Friends".to_string(), "34".to_string())
            ]
        );
        assert_eq!(p.recent.len(), 1);
        assert_eq!(p.recent[0].name, "Bloons TD 6");
        assert_eq!(p.recent[0].hours, "894");
        assert_eq!(p.recent[0].last_played, "Oct 7");
        assert!(p.badge.contains("Team Corgi"));

        let hits = report_hits(&p, "https://steamcommunity.com/id/zed");
        let profile = hits.iter().find(|h| h.module == "profile").unwrap();
        assert!(profile.summary.contains("Zed (Ken Wolfe), level 126"));
        assert!(
            hits.iter()
                .any(|h| h.module == "counts" && h.summary.contains("Games 827"))
        );
        assert!(
            hits.iter()
                .any(|h| h.module == "recent" && h.summary.contains("1 recent"))
        );
        assert!(
            hits.iter()
                .any(|h| h.module == "private" && h.status == Status::Absent)
        );
        assert!(
            hits.iter()
                .any(|h| h.module == "names" && h.status == Status::Absent)
        );
    }

    #[test]
    fn parses_a_private_profile() {
        let body = "<div class=\"profile_private_info\">This profile is private</div>";
        let p = parse(body);
        assert!(p.private);
        assert!(p.persona.is_empty());
        let hits = report_hits(
            &Profile {
                persona: "Ghost".into(),
                private: true,
                ..Profile::default()
            },
            "u",
        );
        assert!(
            hits.iter()
                .any(|h| h.module == "private" && h.status == Status::Confirmed)
        );
        let counts = hits.iter().find(|h| h.module == "counts").unwrap();
        assert_eq!(counts.status, Status::Inconclusive);
    }
}
