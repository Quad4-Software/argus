// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

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
    /// domain -> last observed public surface
    #[serde(default)]
    pub domains: HashMap<String, DomainSnap>,
    /// forge org -> last seen event id (event feed cursor)
    #[serde(default)]
    pub events: HashMap<String, String>,
    /// code search query -> known result urls
    #[serde(default)]
    pub code_watch: HashMap<String, Vec<String>>,
    /// CVE ids from CISA KEV already alerted on
    #[serde(default)]
    pub kev_seen: Vec<String>,
    /// domain -> live lookalike names at last check
    #[serde(default)]
    pub typos: HashMap<String, Vec<String>>,
}

/// One poll of a domain's public posture. Lists are sorted so a diff is
/// just set-minus in both directions.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct DomainSnap {
    #[serde(default)]
    pub certs: Vec<String>,
    #[serde(default)]
    pub ns: Vec<String>,
    #[serde(default)]
    pub mx: Vec<String>,
    #[serde(default)]
    pub txt: Vec<String>,
    #[serde(default)]
    pub addrs: Vec<String>,
    #[serde(default)]
    pub headers: Vec<String>,
    #[serde(default)]
    pub registrar: String,
    #[serde(default)]
    pub rdap_expires: String,
    /// Latest CT not_after covering the apex, ISO date.
    #[serde(default)]
    pub cert_not_after: String,
    /// cert_not_after value we already warned about.
    #[serde(default)]
    pub cert_warned: String,
    /// rdap_expires value we already warned about.
    #[serde(default)]
    pub expiry_warned: String,
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

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

/// Days until an ISO date/datetime, negative when past. Date prefix only.
pub fn days_until(iso: &str) -> Option<i64> {
    let iso = iso.trim();
    let y: i64 = iso.get(0..4)?.parse().ok()?;
    if iso.as_bytes().get(4) != Some(&b'-') {
        return None;
    }
    let m: u64 = iso.get(5..7)?.parse().ok()?;
    let d: u64 = iso.get(8..10)?.parse().ok()?;
    let days = days_from_civil_pub(y, m, d);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some(days - now.div_euclid(86_400))
}

fn days_from_civil_pub(y: i64, m: u64, d: u64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = ((153 * mp + 2) / 5 + d - 1) as i64;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// One pass over a domain's public posture: CT names, DNS answers,
/// homepage security headers, RDAP registrar/expiry, cert expiry.
pub fn domain_snapshot(domain: &str) -> Result<DomainSnap, String> {
    use crate::osint::{name::normalize_domain, net::Net, surface};
    let domain = normalize_domain(domain)?;
    let net = Net::new();
    let (certs, page, rdap) = std::thread::scope(|s| {
        let certs = s.spawn(|| surface::cert_name_list(&net, &domain));
        let page = s.spawn(|| surface::homepage(&net, &domain));
        let rdap = s.spawn(|| surface::rdap_domain(&net, &domain));
        (
            certs.join().unwrap_or_default(),
            page.join().unwrap_or_default(),
            rdap.join().unwrap_or_else(|_| {
                crate::osint::Hit::new("rdap", crate::osint::Status::Error, "lookup panicked", None)
            }),
        )
    });
    let mut snap = DomainSnap {
        certs: sorted(certs.0),
        cert_not_after: certs.1,
        ..Default::default()
    };
    for (q, dst) in [
        ("NS", &mut snap.ns),
        ("MX", &mut snap.mx),
        ("TXT", &mut snap.txt),
        ("A", &mut snap.addrs),
    ] {
        if let Ok(r) = net.lookup(&domain, q) {
            *dst = sorted(
                r.answers
                    .iter()
                    .map(|a| a.data.trim_end_matches('.').to_string())
                    .collect(),
            );
        }
    }
    for hit in &page {
        if hit.module == "headers"
            && let Some(present) = hit
                .evidence
                .as_ref()
                .and_then(|e| e.get("present"))
                .and_then(|p| p.as_array())
        {
            snap.headers = sorted(
                present
                    .iter()
                    .filter_map(|h| h.as_str().map(str::to_string))
                    .collect(),
            );
        }
    }
    if let Some(ev) = &rdap.evidence {
        snap.registrar = ev
            .get("registrar")
            .and_then(|r| r.as_str())
            .unwrap_or("")
            .to_string();
        snap.rdap_expires = ev
            .get("expiration")
            .and_then(|e| e.as_str())
            .unwrap_or("")
            .to_string();
    }
    Ok(snap)
}

/// Findings for the difference between two snapshots. First sight is a
/// baseline: nothing fires.
pub fn domain_diff(
    domain: &str,
    old: &DomainSnap,
    new: &DomainSnap,
    known: bool,
) -> Vec<crate::finding::Finding> {
    use crate::finding::{Finding, Severity};
    let f = |id: &str, sev: Severity, msg: String| Finding {
        ruleset: "watch".into(),
        rule_id: id.into(),
        severity: sev,
        target: domain.into(),
        path: ".".into(),
        line: None,
        excerpt: None,
        message: msg,
        remediation: None,
        reference: None,
        window: None,
        evidence: None,
    };
    let mut out = Vec::new();
    if !known {
        return out;
    }
    let (add, _) = maintainer_delta(&old.certs, &new.certs);
    for n in add.iter().take(10) {
        out.push(f(
            "DWATCH-001",
            Severity::Medium,
            format!("new certificate name: {n}"),
        ));
    }
    let (add, rem) = maintainer_delta(&old.ns, &new.ns);
    if !add.is_empty() || !rem.is_empty() {
        out.push(f(
            "DWATCH-002",
            Severity::High,
            format!(
                "nameservers changed +[{}] -[{}]",
                add.join(","),
                rem.join(",")
            ),
        ));
    }
    let (add, rem) = maintainer_delta(&old.mx, &new.mx);
    if !add.is_empty() || !rem.is_empty() {
        out.push(f(
            "DWATCH-003",
            Severity::High,
            format!("MX changed +[{}] -[{}]", add.join(","), rem.join(",")),
        ));
    }
    let (add, rem) = maintainer_delta(&old.txt, &new.txt);
    if !add.is_empty() || !rem.is_empty() {
        out.push(f(
            "DWATCH-004",
            Severity::Low,
            format!("TXT changed +{} -{}", add.len(), rem.len()),
        ));
    }
    let (add, rem) = maintainer_delta(&old.addrs, &new.addrs);
    if !add.is_empty() || !rem.is_empty() {
        out.push(f(
            "DWATCH-005",
            Severity::Info,
            format!(
                "addresses changed +[{}] -[{}]",
                add.join(","),
                rem.join(",")
            ),
        ));
    }
    let (_, rem) = maintainer_delta(&old.headers, &new.headers);
    if !rem.is_empty() {
        out.push(f(
            "DWATCH-006",
            Severity::Medium,
            format!("security headers removed: {}", rem.join(", ")),
        ));
    }
    if !old.registrar.is_empty()
        && !new.registrar.is_empty()
        && !old.registrar.eq_ignore_ascii_case(&new.registrar)
    {
        out.push(f(
            "DWATCH-007",
            Severity::High,
            format!("registrar changed {} -> {}", old.registrar, new.registrar),
        ));
    }
    out
}

/// Expiry findings for a fresh snapshot; *_warned slots suppress repeats
/// of the same date.
pub fn domain_expiry(domain: &str, snap: &mut DomainSnap) -> Vec<crate::finding::Finding> {
    use crate::finding::{Finding, Severity};
    let f = |id: &str, sev: Severity, msg: String| Finding {
        ruleset: "watch".into(),
        rule_id: id.into(),
        severity: sev,
        target: domain.into(),
        path: ".".into(),
        line: None,
        excerpt: None,
        message: msg,
        remediation: None,
        reference: None,
        window: None,
        evidence: None,
    };
    let mut out = Vec::new();
    if !snap.cert_not_after.is_empty() && snap.cert_warned != snap.cert_not_after {
        match days_until(&snap.cert_not_after) {
            Some(d) if d < 0 => out.push(f(
                "DWATCH-008",
                Severity::High,
                "serving cert is expired".into(),
            )),
            Some(d) if d <= 14 => out.push(f(
                "DWATCH-008",
                Severity::Medium,
                format!("serving cert expires in {d} days ({})", snap.cert_not_after),
            )),
            _ => {}
        }
        if !out.is_empty() {
            snap.cert_warned = snap.cert_not_after.clone();
        }
    }
    if !snap.rdap_expires.is_empty()
        && snap.expiry_warned != snap.rdap_expires
        && let Some(d) = days_until(&snap.rdap_expires)
        && d <= 30
    {
        out.push(f(
            "DWATCH-009",
            if d <= 7 {
                Severity::High
            } else {
                Severity::Medium
            },
            format!(
                "domain registration expires in {d} days ({})",
                snap.rdap_expires
            ),
        ));
        snap.expiry_warned = snap.rdap_expires.clone();
    }
    out
}

/// Latest CISA KEV entries as (cve, vendor, product) rows.
pub fn kev_feed() -> Result<Vec<(String, String, String)>, String> {
    let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    let net = crate::osint::net::Net::slow();
    let resp = net.get(url, &[("Accept", "application/json")])?;
    if resp.status != 200 {
        return Err(format!("KEV HTTP {}", resp.status));
    }
    let v: serde_json::Value =
        serde_json::from_str(&resp.body).map_err(|_| "KEV was not JSON".to_string())?;
    let rows = v
        .get("vulnerabilities")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get("cveID")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string(),
                r.get("vendorProject")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string(),
                r.get("product")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .collect())
}

/// Public events for a GitHub org, newest first.
pub fn github_org_events(
    api: &str,
    org: &str,
    token: Option<&str>,
) -> Result<Vec<serde_json::Value>, String> {
    let url = format!(
        "{}/orgs/{}/events?per_page=50",
        api.trim_end_matches('/'),
        crate::osint::name::percent_encode(org)
    );
    let v = api_get(&url, token)?;
    v.as_array()
        .cloned()
        .ok_or_else(|| "events response was not a list".to_string())
}

/// Newest html_urls for a code search query (needs a token).
pub fn code_search(api: &str, token: Option<&str>, query: &str) -> Result<Vec<String>, String> {
    let url = format!(
        "{}/search/code?q={}&per_page=10",
        api.trim_end_matches('/'),
        crate::osint::name::percent_encode(query)
    );
    let rows = api_get(&url, token)?;
    Ok(rows
        .get("items")
        .and_then(|i| i.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|i| {
                    i.get("html_url")
                        .and_then(|u| u.as_str())
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default())
}

fn api_get(url: &str, token: Option<&str>) -> Result<serde_json::Value, String> {
    let mut req = ureq::get(url)
        .header("User-Agent", "argus")
        .header("Accept", "application/vnd.github+json");
    if let Some(t) = token {
        req = req.header("Authorization", &format!("Bearer {t}"));
    }
    let mut resp = req.call().map_err(|e| format!("{url}: {e}"))?;
    if resp.status().as_u16() != 200 {
        return Err(format!("{url}: HTTP {}", resp.status().as_u16()));
    }
    let body = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("read {url}: {e}"))?;
    serde_json::from_str(&body).map_err(|e| format!("{url}: {e}"))
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

/// git ls-remote \<url\> HEAD -> sha (forge-agnostic push detection).
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
/// Minimal parser: \<entry\>\<id\>/\<guid\>, \<item\>\<guid\>, fallback \<updated\>/\<pubDate\>.
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

    #[test]
    fn domain_diff_fires_on_the_right_deltas() {
        let old = DomainSnap {
            certs: vec!["a.ex.com".into()],
            ns: vec!["ns1.example".into()],
            mx: vec!["mx.ex.com".into()],
            headers: vec!["strict-transport-security".into()],
            registrar: "Example Inc".into(),
            ..Default::default()
        };
        let mut new = old.clone();
        new.certs.push("evil.ex.com".into());
        new.certs.sort();
        new.ns = vec!["ns1.attacker.example".into()];
        new.headers = Vec::new();
        new.registrar = "Other Reg".into();
        let fs = domain_diff("ex.com", &old, &new, true);
        let ids: Vec<&str> = fs.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"DWATCH-001")); // new cert name
        assert!(ids.contains(&"DWATCH-002")); // ns change
        assert!(ids.contains(&"DWATCH-006")); // header regression
        assert!(ids.contains(&"DWATCH-007")); // registrar drift
        assert!(!fs.iter().any(|f| f.rule_id == "DWATCH-003"));
        // first sight is baseline - nothing fires
        assert!(domain_diff("ex.com", &DomainSnap::default(), &new, false).is_empty());
    }

    #[test]
    fn expiry_warns_once_per_value() {
        let mut snap = DomainSnap {
            cert_not_after: "2000-01-01".into(),
            ..Default::default()
        };
        let fs = domain_expiry("ex.com", &mut snap);
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].rule_id, "DWATCH-008"); // expired cert
        // warned marker set; a repeat poll stays quiet
        assert_eq!(snap.cert_warned, "2000-01-01");
        assert!(domain_expiry("ex.com", &mut snap).is_empty());
    }

    #[test]
    fn days_until_reads_iso_prefix() {
        assert!(days_until("1970-01-02").unwrap() < 0);
        assert!(days_until("2099-01-01T00:00:00Z").unwrap() > 20_000);
        assert_eq!(days_until("not a date"), None);
    }
}
