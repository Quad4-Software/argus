//! GitLab (gitlab.com and self-hosted) repo enumeration.

use super::{RepoSpec, Selector};
use crate::http::HttpClient;

pub fn api_base(host: Option<&str>) -> String {
    let h = host.unwrap_or("gitlab.com").trim_end_matches('/');
    if h.starts_with("http://") {
        return format!("{h}/api/v4");
    }
    let h = h.strip_prefix("https://").unwrap_or(h);
    format!("https://{h}/api/v4")
}

fn endpoint(api: &str, sel: &Selector) -> String {
    match sel {
        Selector::Me => format!("{api}/projects?membership=true&simple=true"),
        Selector::User(u) => format!("{api}/users/{u}/projects?simple=true"),
        Selector::Org(g) => format!("{api}/groups/{g}/projects?include_subgroups=true&simple=true"),
    }
}

pub fn list_repos(api: &str, token: Option<&str>, sel: &Selector) -> Result<Vec<RepoSpec>, String> {
    let mut headers = Vec::new();
    if let Some(t) = token {
        headers.push(("PRIVATE-TOKEN".to_string(), t.to_string()));
    }
    let http = HttpClient::new(headers);
    let items = http.get_paged(&endpoint(api, sel), 100)?;
    Ok(items
        .iter()
        .filter_map(|r| {
            Some(RepoSpec {
                full_name: r["path_with_namespace"].as_str()?.to_string(),
                clone_url: r["http_url_to_repo"].as_str()?.to_string(),
                private: r["visibility"].as_str() != Some("public"),
                archived: r["archived"].as_bool().unwrap_or(false),
                fork: r["forked_from_project"].is_object(),
                updated_at: r["last_activity_at"].as_str().map(str::to_string),
                created_at: r["created_at"].as_str().map(str::to_string),
            })
        })
        .collect())
}
