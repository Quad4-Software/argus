//! Gitea / Forgejo repo enumeration.

use super::{RepoSpec, Selector};
use crate::http::HttpClient;

pub fn api_base(host: &str) -> String {
    let h = host.trim_end_matches('/');
    if h.starts_with("http://") {
        return format!("{h}/api/v1");
    }
    let h = h.strip_prefix("https://").unwrap_or(h);
    format!("https://{h}/api/v1")
}

fn endpoint(api: &str, sel: &Selector) -> String {
    match sel {
        Selector::Me => format!("{api}/user/repos"),
        Selector::User(u) => format!("{api}/users/{u}/repos"),
        Selector::Org(o) => format!("{api}/orgs/{o}/repos"),
    }
}

pub fn list_repos(api: &str, token: Option<&str>, sel: &Selector) -> Result<Vec<RepoSpec>, String> {
    let mut headers = Vec::new();
    if let Some(t) = token {
        headers.push(("Authorization".to_string(), format!("token {t}")));
    }
    let http = HttpClient::new(headers);
    let items = http.get_paged(&endpoint(api, sel), 50)?;
    Ok(items
        .iter()
        .filter_map(|r| {
            Some(RepoSpec {
                full_name: r["full_name"].as_str()?.to_string(),
                clone_url: r["clone_url"]
                    .as_str()
                    .or_else(|| r["html_url"].as_str())?
                    .to_string(),
                private: r["private"].as_bool().unwrap_or(false),
                archived: r["archived"].as_bool().unwrap_or(false),
                fork: r["fork"].as_bool().unwrap_or(false),
                updated_at: r["updated_at"].as_str().map(str::to_string),
                created_at: r["created_at"].as_str().map(str::to_string),
            })
        })
        .collect())
}
