//! Roam mode: search-forge discovery then clone+scan.
//! GitHub /search/repositories (+/search/code with auth), GitLab
//! /projects?search=, Gitea /repos/search.

use crate::http::HttpClient;
use crate::provider::RepoSpec;

pub struct RoamQuery {
    pub query: Option<String>,
    pub topic: Option<String>,
    pub language: Option<String>,
    pub min_stars: Option<u64>,
    /// GitHub code search term (requires token).
    pub code_search: Option<String>,
    pub limit: usize,
}

/// Search the given forge; returns candidate repos.
pub fn search(
    api_base: &str,
    forge: &str,
    token: Option<&str>,
    q: &RoamQuery,
) -> Result<Vec<RepoSpec>, String> {
    let headers = match token {
        Some(t) if forge == "github" => vec![
            ("Authorization".into(), format!("Bearer {t}")),
            ("Accept".into(), "application/vnd.github+json".into()),
        ],
        Some(t) if forge == "gitlab" => vec![("PRIVATE-TOKEN".into(), t.into())],
        Some(t) => vec![("Authorization".into(), format!("token {t}"))],
        None => vec![],
    };
    let http = HttpClient::new(headers);

    match forge {
        "github" => github_search(&http, api_base, q),
        "gitlab" => gitlab_search(&http, api_base, q),
        "gitea" => gitea_search(&http, api_base, q),
        other => Err(format!("unknown forge {other:?} (github|gitlab|gitea)")),
    }
}

fn github_q(q: &RoamQuery) -> String {
    let mut parts = Vec::new();
    if let Some(s) = &q.query {
        parts.push(s.clone());
    }
    if let Some(t) = &q.topic {
        parts.push(format!("topic:{t}"));
    }
    if let Some(l) = &q.language {
        parts.push(format!("language:{l}"));
    }
    if let Some(s) = &q.min_stars {
        parts.push(format!("stars:>={s}"));
    }
    if parts.is_empty() {
        parts.push("stars:>10".into());
    }
    parts.join("+")
}

fn github_search(http: &HttpClient, api: &str, q: &RoamQuery) -> Result<Vec<RepoSpec>, String> {
    let mut out = Vec::new();
    let mut urls: Vec<String> = Vec::new();
    urls.push(format!(
        "{api}/search/repositories?q={}&per_page={}&sort=updated",
        urlenc(&github_q(q)),
        q.limit.min(100)
    ));
    if let Some(cs) = &q.code_search {
        // code search returns file matches; dedupe to repos
        urls.push(format!("{api}/search/code?q={}&per_page=100", urlenc(cs)));
    }
    for url in urls {
        let v = http.get_json(&url)?;
        let items = v["items"].as_array().cloned().unwrap_or_default();
        for it in items {
            // code search items wrap repo in repository
            let r = it.get("repository").unwrap_or(&it);
            let full = r["full_name"]
                .as_str()
                .or_else(|| r["name"].as_str())
                .unwrap_or("");
            let clone = r["clone_url"]
                .as_str()
                .map(String::from)
                .unwrap_or_else(|| format!("https://github.com/{full}.git"));
            if full.is_empty() {
                continue;
            }
            if out.iter().any(|x: &RepoSpec| x.full_name == full) {
                continue;
            }
            out.push(RepoSpec {
                full_name: full.into(),
                clone_url: clone,
                private: r["private"].as_bool().unwrap_or(false),
                archived: r["archived"].as_bool().unwrap_or(false),
                fork: r["fork"].as_bool().unwrap_or(false),
                updated_at: r["updated_at"].as_str().map(str::to_string),
                created_at: r["created_at"].as_str().map(str::to_string),
            });
            if out.len() >= q.limit {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

fn gitlab_search(http: &HttpClient, api: &str, q: &RoamQuery) -> Result<Vec<RepoSpec>, String> {
    let term = q
        .query
        .clone()
        .or(q.topic.clone())
        .unwrap_or_else(|| "*".into());
    let url = format!(
        "{api}/projects?search={}&per_page={}&order_by=last_activity_at&simple=true",
        urlenc(&term),
        q.limit.min(100)
    );
    let arr = http.get_paged(&url, 100)?;
    let mut out = Vec::new();
    for r in arr {
        let full = r["path_with_namespace"].as_str().unwrap_or("");
        let clone = r["http_url_to_repo"]
            .as_str()
            .map(String::from)
            .unwrap_or_else(|| format!("https://gitlab.com/{full}.git"));
        out.push(RepoSpec {
            full_name: full.into(),
            clone_url: clone,
            private: r["visibility"].as_str() == Some("private"),
            archived: r["archived"].as_bool().unwrap_or(false),
            fork: false,
            updated_at: r["last_activity_at"].as_str().map(str::to_string),
            created_at: r["created_at"].as_str().map(str::to_string),
        });
        if out.len() >= q.limit {
            break;
        }
    }
    Ok(out)
}

fn gitea_search(http: &HttpClient, api: &str, q: &RoamQuery) -> Result<Vec<RepoSpec>, String> {
    let mut url = format!("{api}/repos/search?limit={}", q.limit.min(50));
    if let Some(t) = &q.topic {
        url += &format!("&topic={}", urlenc(t));
    }
    if let Some(s) = &q.query {
        url += &format!("&q={}", urlenc(s));
    }
    let v = http.get_json(&url)?;
    let mut out = Vec::new();
    for r in v["data"].as_array().cloned().unwrap_or_default() {
        let full = r["full_name"].as_str().unwrap_or("");
        out.push(RepoSpec {
            full_name: full.into(),
            clone_url: r["clone_url"]
                .as_str()
                .map(String::from)
                .unwrap_or_else(|| full.to_string()),
            private: r["private"].as_bool().unwrap_or(false),
            archived: r["archived"].as_bool().unwrap_or(false),
            fork: r["fork"].as_bool().unwrap_or(false),
            updated_at: r["updated_at"].as_str().map(str::to_string),
            created_at: r["created_at"].as_str().map(str::to_string),
        });
    }
    Ok(out)
}

fn urlenc(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}
