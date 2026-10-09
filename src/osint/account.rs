// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Public forge account metadata.
//! GitHub answers without a token. GitLab's full profile often needs
//! GITLAB_TOKEN. Missing fields stay inconclusive. Tokens are not printed.

use super::net::Net;
use super::siteurl::{Fetched, Headers, fetch_public};
use super::socials::{self, Social};
use super::{Hit, Report, Status};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn scan(forge: &str, login: &str, host: Option<&str>) -> Result<Report, String> {
    let t0 = std::time::Instant::now();
    let login = login.trim();
    if !valid_login(login) {
        return Err("login must be letters, digits, dot, underscore, or hyphen".into());
    }
    let forge = forge.trim().to_ascii_lowercase();
    let report = match forge.as_str() {
        "github" | "gh" => github(login)?,
        "gitlab" | "gl" => gitlab(login, host)?,
        _ => return Err("forge must be github or gitlab".into()),
    };
    Ok(Report {
        target: format!("{forge}:{login}"),
        kind: "account",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings: report,
    })
}

fn github(login: &str) -> Result<Vec<Hit>, String> {
    let token = std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("GH_TOKEN"))
        .ok();
    let auth = token.as_deref().map(|t| format!("Bearer {t}"));
    let mut extra = vec![("Accept", "application/vnd.github+json")];
    if let Some(t) = auth.as_deref() {
        extra.push(("Authorization", t));
    }
    let user_url = format!("https://api.github.com/users/{login}");
    let (status, _, body) = api_get(&user_url, &extra)?;
    if status == 404 {
        return Err(format!("no such GitHub account: {login}"));
    }
    if !(200..300).contains(&status) {
        return Err(format!("GitHub user API HTTP {status}"));
    }
    let user: Value = serde_json::from_str(&body).map_err(|e| format!("GitHub user JSON: {e}"))?;
    let mut findings = vec![profile_hit("github", &user, true)];
    let repos_url =
        format!("https://api.github.com/users/{login}/repos?per_page=100&sort=updated&type=owner");
    match api_get(&repos_url, &extra) {
        Ok((st, hdrs, raw)) if (200..300).contains(&st) => {
            let repos: Vec<Value> = serde_json::from_str(&raw).unwrap_or_default();
            findings.push(repo_hit(
                &repos,
                "stargazers_count",
                "fork",
                "html_url",
                "name",
                link_next(&hdrs),
            ));
            findings.extend(resume_repos(&repos, "name", "html_url"));
        }
        _ => findings.push(Hit::new(
            "repos",
            Status::Inconclusive,
            "repo list was not readable",
            None,
        )),
    }
    let is_org = user.get("type").and_then(|t| t.as_str()) == Some("Organization");
    let events_url = if is_org {
        format!("https://api.github.com/orgs/{login}/events?per_page=30")
    } else {
        format!("https://api.github.com/users/{login}/events/public?per_page=30")
    };
    match api_get(&events_url, &extra) {
        Ok((st, _, raw)) if (200..300).contains(&st) => {
            let arr: Vec<Value> = serde_json::from_str(&raw).unwrap_or_default();
            let evs = super::gharchive::events_from_values(&arr);
            findings.push(super::gharchive::events_hit(&evs, "events"));
        }
        Ok((st, _, _)) => findings.push(Hit::new(
            "events",
            Status::Inconclusive,
            format!("GitHub events API HTTP {st}"),
            None,
        )),
        Err(e) => findings.push(Hit::new("events", Status::Inconclusive, e, None)),
    }
    findings.extend(page_socials(
        user.get("blog").and_then(|v| v.as_str()).unwrap_or(""),
        user.get("bio").and_then(|v| v.as_str()).unwrap_or(""),
        user.get("twitter_username").and_then(|v| v.as_str()),
    ));
    Ok(findings)
}

fn gitlab(login: &str, host: Option<&str>) -> Result<Vec<Hit>, String> {
    let origin = gitlab_origin(host)?;
    let search = format!("{origin}/api/v4/users?username={login}");
    let (status, _, _, body) = fetch_public(&search)?;
    if !(200..300).contains(&status) {
        return Err(format!("GitLab user search HTTP {status}"));
    }
    let rows: Vec<Value> = serde_json::from_str(&body).map_err(|e| format!("GitLab JSON: {e}"))?;
    let Some(row) = rows.into_iter().next() else {
        return Err(format!("no such GitLab account: {login}"));
    };
    let id = row.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    let token = std::env::var("GITLAB_TOKEN")
        .or_else(|_| std::env::var("GL_TOKEN"))
        .ok();
    let mut user = row;
    let mut detail_note = None;
    if id > 0 {
        let url = format!("{origin}/api/v4/users/{id}");
        if let Ok((st, _, _, raw)) = fetch_token(&url, token.as_deref(), "PRIVATE-TOKEN") {
            if (200..300).contains(&st) {
                if let Ok(full) = serde_json::from_str::<Value>(&raw) {
                    user = full;
                }
            } else if st == 401 || st == 403 {
                detail_note = Some(
                    "GitLab hid profile fields. Set GITLAB_TOKEN for created date, followers, and bio",
                );
            }
        }
    }
    let mut findings = vec![profile_hit(
        "gitlab",
        &user,
        user.get("created_at").is_some(),
    )];
    if let Some(note) = detail_note {
        findings.push(Hit::new("profile-extra", Status::Inconclusive, note, None));
    }
    if id > 0 {
        let repos_url = format!(
            "{origin}/api/v4/users/{id}/projects?per_page=100&order_by=updated_at&simple=true"
        );
        match fetch_public(&repos_url) {
            Ok((st, _, hdrs, raw)) if (200..300).contains(&st) => {
                let repos: Vec<Value> = serde_json::from_str(&raw).unwrap_or_default();
                findings.push(repo_hit(
                    &repos,
                    "star_count",
                    "forked_from_project",
                    "web_url",
                    "path",
                    link_next(&hdrs),
                ));
                findings.extend(resume_repos(&repos, "path", "web_url"));
            }
            _ => findings.push(Hit::new(
                "repos",
                Status::Inconclusive,
                "project list was not readable",
                None,
            )),
        }
    }
    let website = user
        .get("website_url")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let bio = user.get("bio").and_then(|v| v.as_str()).unwrap_or("");
    findings.extend(page_socials(
        website,
        bio,
        user.get("twitter").and_then(|v| v.as_str()),
    ));
    Ok(findings)
}

fn api_get(url: &str, extra: &[(&str, &str)]) -> Result<(u16, Headers, String), String> {
    if url.starts_with("https://api.github.com/") || url.starts_with("https://gitlab.com/") {
        let net = Net::new();
        let resp = net.get(url, extra)?;
        return Ok((resp.status, resp.headers, resp.body));
    }
    let (st, _, hdrs, body) = fetch_public(url)?;
    Ok((st, hdrs, body))
}

fn fetch_token(url: &str, token: Option<&str>, header: &str) -> Result<Fetched, String> {
    if token.is_none() {
        return fetch_public(url);
    }
    let net = Net::new();
    let resp = net.get(url, &[(header, token.unwrap_or(""))])?;
    Ok((resp.status, url.to_string(), resp.headers, resp.body))
}

fn profile_hit(forge: &str, user: &Value, have_created: bool) -> Hit {
    let created = user
        .get("created_at")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let age = age_days(created);
    let followers = user.get("followers").and_then(|v| v.as_i64());
    let following = user.get("following").and_then(|v| v.as_i64());
    let repos = user
        .get("public_repos")
        .or_else(|| user.get("projects_limit"))
        .and_then(|v| v.as_i64());
    let name = text(user, "name");
    let login = text(user, "login").or_else(|| text(user, "username"));
    let mut summary = format!(
        "{} {}",
        login.as_deref().unwrap_or("?"),
        name.as_deref().unwrap_or("")
    );
    if let Some(days) = age {
        summary.push_str(&format!(", {days} days old"));
    } else if !have_created {
        summary.push_str(", age not in the public record");
    }
    if let Some(n) = followers {
        summary.push_str(&format!(", {n} followers"));
    }
    if let Some(n) = following {
        summary.push_str(&format!(", {n} following"));
    }
    Hit::new(
        "profile",
        Status::Confirmed,
        summary.trim().to_string(),
        Some(json!({
            "forge": forge,
            "login": login,
            "name": name,
            "id": user.get("id"),
            "created_at": if created.is_empty() { Value::Null } else { json!(created) },
            "age_days": age,
            "public_repos": repos,
            "followers": followers,
            "following": following,
            "company": user.get("company").or_else(|| user.get("organization")),
            "location": user.get("location"),
            "blog": user.get("blog").or_else(|| user.get("website_url")),
            "email": user.get("email").or_else(|| user.get("public_email")),
            "bio": user.get("bio"),
            "twitter": user.get("twitter_username").or_else(|| user.get("twitter")),
        })),
    )
}

fn repo_hit(
    repos: &[Value],
    star_key: &str,
    fork_key: &str,
    url_key: &str,
    name_key: &str,
    truncated: bool,
) -> Hit {
    let mut stars = 0i64;
    let mut forks = 0i64;
    let mut top = Vec::new();
    for repo in repos {
        stars += repo.get(star_key).and_then(|v| v.as_i64()).unwrap_or(0);
        let is_fork = match repo.get(fork_key) {
            Some(Value::Bool(b)) => *b,
            Some(Value::Null) | None => false,
            Some(_) => true,
        };
        if is_fork {
            forks += 1;
        }
        if top.len() < 8 {
            top.push(json!({
                "name": repo.get(name_key),
                "stars": repo.get(star_key),
                "fork": is_fork,
                "url": repo.get(url_key),
            }));
        }
    }
    let mut summary = format!(
        "{} repo(s), {} fork(s), {} star(s)",
        repos.len(),
        forks,
        stars
    );
    if truncated {
        summary.push_str(", first page only");
    }
    Hit::new(
        "repos",
        if repos.is_empty() {
            Status::Absent
        } else {
            Status::Confirmed
        },
        summary,
        Some(json!({ "truncated": truncated, "top": top })),
    )
}

fn resume_repos(repos: &[Value], name_key: &str, url_key: &str) -> Vec<Hit> {
    let mut links = Vec::new();
    for repo in repos {
        let name = repo.get(name_key).and_then(|v| v.as_str()).unwrap_or("");
        let lower = name.to_ascii_lowercase();
        if (lower.contains("resume") || lower == "cv" || lower.contains("curriculum"))
            && let Some(url) = repo.get(url_key).and_then(|v| v.as_str())
        {
            links.push(url.to_string());
        }
    }
    if links.is_empty() {
        vec![Hit::new(
            "resume",
            Status::Absent,
            "no public repo named like a resume",
            None,
        )]
    } else {
        vec![Hit::new(
            "resume",
            Status::Confirmed,
            format!("{} repo(s) named like a resume", links.len()),
            Some(json!({ "links": links })),
        )]
    }
}

fn page_socials(blog: &str, bio: &str, twitter: Option<&str>) -> Vec<Hit> {
    let mut found: Vec<Social> = socials::extract(bio);
    if let Some(handle) = twitter.map(str::trim).filter(|s| !s.is_empty()) {
        found.push(Social {
            platform: "x".into(),
            url: format!("https://x.com/{handle}"),
        });
    }
    let blog = normalize_http(blog);
    if let Some(url) = blog {
        match fetch_public(&url) {
            Ok((st, _, _, body)) if (200..400).contains(&st) => {
                found.extend(socials::extract(&body));
                let resumes = socials::resume_links(&body);
                if !resumes.is_empty() {
                    return with_socials(
                        found,
                        Some(Hit::new(
                            "resume-page",
                            Status::Confirmed,
                            format!("{} resume link(s) on the profile site", resumes.len()),
                            Some(json!({ "links": resumes })),
                        )),
                    );
                }
            }
            _ => {}
        }
    }
    with_socials(found, None)
}

fn with_socials(found: Vec<Social>, extra: Option<Hit>) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for s in found {
        if seen.insert(format!("{} {}", s.platform, s.url)) {
            hits.push(Hit::new(&s.platform, Status::Confirmed, s.url, None));
        }
    }
    if hits.is_empty() {
        hits.push(Hit::new(
            "socials",
            Status::Absent,
            "no social links on the public profile",
            None,
        ));
    }
    if let Some(hit) = extra {
        hits.push(hit);
    }
    hits
}

fn link_next(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("link") && v.to_ascii_lowercase().contains("rel=\"next\"")
    })
}

fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn valid_login(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= 80
        && login
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn gitlab_origin(host: Option<&str>) -> Result<String, String> {
    let Some(host) = host.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok("https://gitlab.com".into());
    };
    let url = if host.starts_with("http://") || host.starts_with("https://") {
        host.trim_end_matches('/').to_string()
    } else {
        format!("https://{}", host.trim_end_matches('/'))
    };
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("bad GitLab host".into());
    }
    fetch_public(&format!("{url}/"))?;
    Ok(url)
}

fn normalize_http(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.starts_with("https://") || raw.starts_with("http://") {
        Some(raw.to_string())
    } else if raw.contains('.') && !raw.contains(' ') {
        Some(format!("https://{raw}"))
    } else {
        None
    }
}

fn age_days(iso: &str) -> Option<i64> {
    if iso.len() < 10 {
        return None;
    }
    let y: i32 = iso[0..4].parse().ok()?;
    let m: i32 = iso[5..7].parse().ok()?;
    let d: i32 = iso[8..10].parse().ok()?;
    let then = civil_days(y, m, d)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64 / 86400;
    Some(now.saturating_sub(then))
}

fn civil_days(y: i32, m: i32, d: i32) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u64;
    Some(era as i64 * 146097 + doe as i64 - 719468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_login_checks() {
        assert_eq!(civil_days(1970, 1, 1), Some(0));
        assert!(valid_login("octocat"));
        assert!(valid_login("nick.thomas"));
        assert!(!valid_login("a/b"));
        assert!(age_days("1970-01-01T00:00:00Z").unwrap() > 20_000);
    }
}
