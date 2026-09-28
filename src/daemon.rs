//! Daemon mode: HTTP control plane + forge webhooks + watch loop.
//!
//! Endpoints:
//!   GET  /healthz        -> {"ok":true}
//!   GET  /report         -> last scan report JSON
//!   GET  /state          -> watched heads/feeds
//!   POST /scan           -> trigger a rescan of all watched repos
//!   POST /webhook/github -> X-Hub-Signature-256 verified push -> rescan that repo
//!   POST /webhook/gitlab -> X-Gitlab-Token shared-secret check
//!   POST /webhook/gitea  -> X-Gitea-Signature (HMAC) or X-Gitea-Event push
//!
//! New findings since each repo's baseline fingerprint set are POSTed to
//! --notify-url (ntfy.sh or any JSON webhook endpoint).

use crate::finding::{Finding, Report};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;

pub struct Daemon {
    pub state: Mutex<Inner>,
}

pub struct Inner {
    pub last_report: Option<Report>,
    pub heads: HashMap<String, String>,
    pub known: HashMap<String, Vec<String>>,
    /// repo -> dep identities "eco:name@version" at last rescan
    pub deps: HashMap<String, Vec<String>>,
}

impl Default for Daemon {
    fn default() -> Self {
        Self {
            state: Mutex::new(Inner {
                last_report: None,
                heads: HashMap::new(),
                known: HashMap::new(),
                deps: HashMap::new(),
            }),
        }
    }
}

/// HMAC-SHA256 hex for webhook signature verification (GitHub/Gitea).
pub fn hmac_sha256_hex(secret: &str, body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body);
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Verify GitHub webhook X-Hub-Signature-256 (sha256=<hex>).
pub fn verify_github_sig(secret: &str, body: &[u8], sig_header: &str) -> bool {
    let Some(hex) = sig_header.strip_prefix("sha256=") else {
        return false;
    };
    let expected = hmac_sha256_hex(secret, body);
    // constant-time-ish compare
    expected.len() == hex.len()
        && expected
            .bytes()
            .zip(hex.bytes())
            .fold(0u8, |a, (x, y)| a | (x ^ y))
            == 0
}

/// Extract clone info from a webhook payload (best-effort across forges).
/// Returns (full_name, clone_url, head_sha if present).
pub fn repo_from_push(body: &[u8]) -> Option<(String, String, Option<String>)> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let repo = &v["repository"];
    let full = repo["full_name"]
        .as_str()
        .or_else(|| repo["path_with_namespace"].as_str())?
        .to_string();
    let clone = repo["clone_url"]
        .as_str()
        .or_else(|| repo["git_http_url"].as_str())
        .or_else(|| repo["http_url"].as_str())
        .map(String::from)
        .unwrap_or_else(|| format!("https://github.com/{full}.git"));
    let sha = v["after"].as_str().map(str::to_string);
    Some((full, clone, sha))
}

/// POST findings to a notify URL (ntfy.sh or generic webhook sink).
pub fn notify(url: &str, title: &str, findings: &[Finding]) -> Result<(), String> {
    let body = if url.contains("ntfy") {
        // ntfy wants plain text
        let lines: Vec<String> = findings
            .iter()
            .take(20)
            .map(|f| {
                format!(
                    "{} {} {}:{}",
                    f.severity,
                    f.rule_id,
                    f.path,
                    f.line.unwrap_or(0)
                )
            })
            .collect();
        format!("{title}\n{}", lines.join("\n"))
    } else {
        serde_json::json!({
            "title": title,
            "findings": findings.iter().take(50).collect::<Vec<_>>(),
        })
        .to_string()
    };
    ureq::post(url)
        .header("User-Agent", "argus")
        .header("Title", title)
        .send(&body)
        .map_err(|e| format!("notify {url}: {e}"))?;
    Ok(())
}
