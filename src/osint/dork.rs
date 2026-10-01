// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Search URLs for a domain, email, or name.
//! Nothing is fetched. `cache:` is omitted because that operator is gone.
//! Wayback, crt.sh, and urlscan are the archive and certificate pivots.

use super::hash::{hex, md5};
use super::{Hit, Report, Status};
use serde_json::json;
use std::time::Instant;

pub fn scan(raw: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 200 {
        return Err("pass a domain, email, or name".into());
    }
    let urls = if raw.contains('@') {
        email_urls(raw)
    } else if raw.contains('.') && !raw.contains(' ') {
        domain_urls(raw)
    } else {
        name_urls(raw)
    };
    Ok(Report {
        target: raw.to_string(),
        kind: "dork",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings: vec![Hit::new(
            "dork",
            Status::Confirmed,
            format!("{} search link(s)", urls.len()),
            Some(json!({ "links": urls })),
        )],
    })
}

fn domain_urls(domain: &str) -> Vec<String> {
    let q = urlencode(domain);
    vec![
        format!("https://web.archive.org/web/*/https://{domain}/*"),
        format!("https://crt.sh/?q={q}"),
        format!("https://urlscan.io/search/#domain:{domain}"),
        format!("https://www.google.com/search?q=site:{q}"),
        format!("https://www.google.com/search?q=site:{q}+filetype:pdf"),
        format!("https://github.com/search?q={q}&type=code"),
        format!("https://grep.app/search?q={q}"),
    ]
}

fn email_urls(email: &str) -> Vec<String> {
    let q = urlencode(email);
    let hash = hex(&md5(email.trim().to_ascii_lowercase().as_bytes()));
    vec![
        format!("https://www.google.com/search?q=%22{q}%22"),
        format!("https://github.com/search?q={q}&type=code"),
        format!("https://grep.app/search?q={q}"),
        format!("https://www.gravatar.com/avatar/{hash}?d=404"),
        format!("https://crt.sh/?q={q}"),
    ]
}

fn name_urls(name: &str) -> Vec<String> {
    let q = urlencode(name);
    vec![
        format!("https://www.google.com/search?q=%22{q}%22"),
        format!("https://github.com/search?q={q}&type=users"),
        format!("https://grep.app/search?q={q}"),
    ]
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_links_include_the_archives() {
        let urls = domain_urls("example.com");
        assert!(urls.iter().any(|u| u.contains("web.archive.org")));
        assert!(urls.iter().any(|u| u.contains("crt.sh")));
        assert!(!urls.iter().any(|u| u.contains("cache:")));
        let mail = email_urls("ada@example.com");
        assert!(mail.iter().any(|u| u.contains("gravatar.com/avatar/")));
    }
}
