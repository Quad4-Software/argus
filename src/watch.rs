//! Watch mode: continuously monitor repos (and RSS/Atom feeds) for pushes,
//! rescanning on change. Push detection via git ls-remote (forge-agnostic);
//! optional atom/rss feed targets for notification-style updates.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Default, Serialize, Deserialize)]
pub struct WatchState {
    /// repo key -> last seen HEAD sha
    pub heads: HashMap<String, String>,
    /// feed url -> last seen entry id
    pub feeds: HashMap<String, String>,
    /// repo key -> known finding fingerprints (baseline per repo)
    pub known_findings: HashMap<String, Vec<String>>,
    /// repo key -> dep identities "eco:name@version" seen at last scan
    #[serde(default)]
    pub deps: HashMap<String, Vec<String>>,
    /// "eco:name" -> sorted maintainer list at last check
    #[serde(default)]
    pub maintainers: HashMap<String, Vec<String>>,
}

/// Diff a repo's dep set against the stored baseline. Returns
/// (added, removed, version-changed) as display strings.
pub fn dep_delta(old: &[String], new: &[String]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let name_of = |s: &str| s.rsplit('@').next_back().unwrap_or(s).to_string();
    let oldm: HashMap<String, &str> = old.iter().map(|s| (name_of(s), s.as_str())).collect();
    let newm: HashMap<String, &str> = new.iter().map(|s| (name_of(s), s.as_str())).collect();
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    for (n, v) in &newm {
        match oldm.get(n) {
            None => added.push(v.to_string()),
            Some(o) if o != v => changed.push(format!("{o} -> {v}")),
            _ => {}
        }
    }
    for (n, v) in &oldm {
        if !newm.contains_key(n) {
            removed.push(v.to_string());
        }
    }
    (added, removed, changed)
}

/// Added/removed names between two sorted maintainer lists.
pub fn maintainer_delta(old: &[String], new: &[String]) -> (Vec<String>, Vec<String>) {
    let added: Vec<String> = new.iter().filter(|m| !old.contains(m)).cloned().collect();
    let removed: Vec<String> = old.iter().filter(|m| !new.contains(m)).cloned().collect();
    (added, removed)
}

fn state_path() -> PathBuf {
    std::env::home_dir()
        .unwrap_or_else(|| "/tmp".into())
        .join(".local/share/argus/watch-state.json")
}

pub fn load_state() -> WatchState {
    std::fs::read_to_string(state_path())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn save_state(s: &WatchState) -> Result<(), String> {
    let p = state_path();
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    std::fs::write(
        &p,
        serde_json::to_string_pretty(s).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("{}: {e}", p.display()))
}

/// git ls-remote <url> HEAD -> sha (forge-agnostic push detection).
pub fn remote_head(url: &str) -> Result<String, String> {
    let out = std::process::Command::new("git")
        .args(["ls-remote", url, "HEAD"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("spawn git: {e}"))?;
    if !out.status.success() {
        return Err(format!("ls-remote {url} failed"));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.split_whitespace()
        .next()
        .map(str::to_string)
        .ok_or_else(|| format!("ls-remote {url}: empty"))
}

/// Fetch an RSS/Atom feed and return the newest entry id/guid/title tuple.
/// Minimal parser: <entry><id>/<guid>, <item><guid>, fallback <updated>/<pubDate>.
pub fn latest_feed_entry(url: &str) -> Result<String, String> {
    let mut resp = ureq::get(url)
        .header("User-Agent", "argus")
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;
    let body = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("read {url}: {e}"))?;
    parse_feed_latest(&body).ok_or_else(|| format!("{url}: no feed entries"))
}

/// Extract the latest entry identifier from atom/rss XML.
pub fn parse_feed_latest(xml: &str) -> Option<String> {
    // atom <entry> ... <id> or <guid>; rss <item><guid>
    let id_re = regex::Regex::new(
        r"(?s)<(?:entry|item)[^>]*>.*?<(?:id|guid)[^>]*>\s*([^<]+?)\s*</(?:id|guid)>",
    )
    .unwrap();
    if let Some(c) = id_re.captures(xml) {
        return Some(c[1].trim().to_string());
    }
    // fallback: newest <updated>/<pubDate>
    let u_re = regex::Regex::new(r"<(?:updated|pubDate)[^>]*>\s*([^<]+)\s*<").unwrap();
    u_re.captures(xml).map(|c| c[1].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dep_delta_basics() {
        let old = vec![
            "npm:a@1.0".to_string(),
            "npm:b@1.0".to_string(),
            "npm:c@1.0".to_string(),
        ];
        let new = vec![
            "npm:a@1.0".to_string(),
            "npm:b@2.0".to_string(),
            "npm:d@1.0".to_string(),
        ];
        let (add, rem, chg) = dep_delta(&old, &new);
        assert_eq!(add, vec!["npm:d@1.0"]);
        assert_eq!(rem, vec!["npm:c@1.0"]);
        assert_eq!(chg, vec!["npm:b@1.0 -> npm:b@2.0"]);
    }

    #[test]
    fn maintainer_delta_basics() {
        let (a, r) = maintainer_delta(
            &["alice".into(), "bob".into()],
            &["alice".into(), "mallory".into()],
        );
        assert_eq!(a, vec!["mallory"]);
        assert_eq!(r, vec!["bob"]);
    }
}
