// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Public HTTP sources shared by domain and email scans.

use super::hash::{hex, md5, wkd_hash};
use super::name::{in_scope, percent_encode};
use super::net::{Net, clip, header};
use super::{Hit, Status};
use serde_json::{Value, json};

pub(crate) fn seo_hit(html: &str) -> Hit {
    let seo = crate::seometa::parse(html);
    let dashes = seo.dashes();
    let empty = seo.description.is_empty()
        && seo.og_description.is_empty()
        && seo.twitter_description.is_empty()
        && seo.generator.is_empty();
    if empty && dashes.is_empty() {
        return Hit::new(
            "seo",
            Status::Absent,
            "no description or generator meta",
            None,
        );
    }
    let summary = if !dashes.is_empty() {
        format!("{} SEO field(s) contain an em dash", dashes.len())
    } else if !seo.generator.is_empty() {
        format!("generator {}", seo.generator)
    } else {
        "description meta present".into()
    };
    Hit::new(
        "seo",
        Status::Confirmed,
        summary,
        Some(json!({
            "title": seo.title,
            "description": seo.description,
            "og_description": seo.og_description,
            "twitter_description": seo.twitter_description,
            "generator": seo.generator,
            "canonical": seo.canonical,
            "em_dash_fields": dashes.iter().map(|d| d.field).collect::<Vec<_>>(),
        })),
    )
}

pub fn homepage(net: &Net, domain: &str) -> Vec<Hit> {
    let url = format!("https://{domain}/");
    let resp = match net.get(&url, &[]) {
        Ok(r) => r,
        Err(e) => {
            return vec![Hit::new(
                "http",
                Status::Error,
                e,
                Some(json!({"url": url})),
            )];
        }
    };
    let server = header(&resp.headers, "server").unwrap_or("").to_string();
    let mut hits = vec![Hit::new(
        "http",
        if (200..400).contains(&resp.status) {
            Status::Confirmed
        } else {
            Status::Inconclusive
        },
        format!(
            "HTTP {}{}",
            resp.status,
            if server.is_empty() {
                String::new()
            } else {
                format!(" server={server}")
            }
        ),
        Some(json!({"url": url, "status": resp.status, "server": server})),
    )];
    const WANT: &[&str] = &[
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
    ];
    let present: Vec<&str> = WANT
        .iter()
        .copied()
        .filter(|n| header(&resp.headers, n).is_some())
        .collect();
    let missing: Vec<&str> = WANT
        .iter()
        .copied()
        .filter(|n| header(&resp.headers, n).is_none())
        .collect();
    hits.push(Hit::new(
        "headers",
        if present.is_empty() {
            Status::Absent
        } else {
            Status::Confirmed
        },
        format!(
            "{} of {} security headers present",
            present.len(),
            WANT.len()
        ),
        Some(json!({"present": present, "missing": missing})),
    ));
    match html_title(&resp.body) {
        Some(title) => hits.push(Hit::new(
            "title",
            Status::Confirmed,
            title.clone(),
            Some(json!({"title": title})),
        )),
        None if resp.status == 200 => {
            hits.push(Hit::new("title", Status::Absent, "page has no title", None))
        }
        None => hits.push(Hit::new(
            "title",
            Status::Inconclusive,
            format!("no title on HTTP {}", resp.status),
            None,
        )),
    }
    let boxes = mailboxes_in(&resp.body, domain);
    if boxes.is_empty() {
        hits.push(Hit::new(
            "mailboxes",
            Status::Absent,
            "no in-scope mailbox on the homepage",
            None,
        ));
    } else {
        hits.push(Hit::new(
            "mailboxes",
            Status::Confirmed,
            format!("{} mailbox(es) on the homepage", boxes.len()),
            Some(json!({"addresses": boxes})),
        ));
    }
    hits.push(seo_hit(&resp.body));
    hits.push(super::waf::detect(&resp.headers, &resp.body));
    hits.push(super::trackers::detect(&resp.headers, &resp.body));
    hits
}

pub fn robots(net: &Net, domain: &str) -> Hit {
    let url = format!("https://{domain}/robots.txt");
    match net.get(&url, &[]) {
        Err(e) => Hit::new("robots", Status::Error, e, None),
        Ok(r) if r.status == 404 => Hit::new("robots", Status::Absent, "no robots.txt", None),
        Ok(r) if r.status != 200 => Hit::new(
            "robots",
            Status::Inconclusive,
            format!("robots.txt HTTP {}", r.status),
            None,
        ),
        Ok(r) if looks_like_html(&r.body) => Hit::new(
            "robots",
            Status::Inconclusive,
            "robots.txt looks like an HTML page",
            None,
        ),
        Ok(r) => {
            let disallow = r
                .body
                .lines()
                .filter(|l| l.trim().to_ascii_lowercase().starts_with("disallow:"))
                .count();
            let sitemaps: Vec<String> = r
                .body
                .lines()
                .filter_map(|l| {
                    let l = l.trim();
                    l.to_ascii_lowercase().strip_prefix("sitemap:").map(|_| {
                        l.split_once(':')
                            .map(|(_, v)| v.trim().to_string())
                            .unwrap_or_default()
                    })
                })
                .filter(|s| !s.is_empty())
                .take(5)
                .collect();
            let pages = sitemap_pages(net, domain, &sitemaps);
            let mut summary = format!(
                "{disallow} disallow lines, {} sitemap links",
                sitemaps.len()
            );
            if !pages.is_empty() {
                summary.push_str(&format!(", {} in-scope page urls", pages.len()));
            }
            Hit::new(
                "robots",
                Status::Confirmed,
                summary,
                Some(json!({
                    "disallow": disallow,
                    "sitemaps": sitemaps,
                    "pages": pages,
                    "content_signal": content_signals(&r.body),
                })),
            )
        }
    }
}

pub fn security_txt(net: &Net, domain: &str) -> Hit {
    let paths = [
        format!("https://{domain}/.well-known/security.txt"),
        format!("https://{domain}/security.txt"),
    ];
    let mut saw_html = false;
    let mut last_err = String::new();
    for url in &paths {
        match net.get(url, &[]) {
            Err(e) => last_err = e,
            Ok(r) if r.status == 200 && looks_like_html(&r.body) => saw_html = true,
            Ok(r) if r.status == 200 => {
                let contacts: Vec<String> = r
                    .body
                    .lines()
                    .filter_map(|l| {
                        let t = l.trim();
                        t.to_ascii_lowercase().strip_prefix("contact:").map(|_| {
                            t.split_once(':')
                                .map(|(_, v)| v.trim().to_string())
                                .unwrap_or_default()
                        })
                    })
                    .filter(|s| !s.is_empty())
                    .take(5)
                    .collect();
                if contacts.is_empty() && !r.body.to_ascii_lowercase().contains("contact:") {
                    return Hit::new(
                        "securitytxt",
                        Status::Inconclusive,
                        "security.txt has no Contact field",
                        Some(json!({"url": url})),
                    );
                }
                return Hit::new(
                    "securitytxt",
                    Status::Confirmed,
                    format!("{} contact line(s)", contacts.len()),
                    Some(json!({"url": url, "contacts": contacts})),
                );
            }
            Ok(_) => {}
        }
    }
    if saw_html {
        return Hit::new(
            "securitytxt",
            Status::Inconclusive,
            "security.txt looks like an HTML page",
            None,
        );
    }
    if !last_err.is_empty() && last_err.contains("timed") {
        return Hit::new("securitytxt", Status::Error, last_err, None);
    }
    Hit::new("securitytxt", Status::Absent, "no security.txt", None)
}

pub fn certs(net: &Net, domain: &str) -> Hit {
    let (spotter, ct) = std::thread::scope(|s| {
        let spotter = s.spawn(|| certspotter(net, domain));
        let ct = s.spawn(|| cert_ct(net, domain));
        (
            spotter
                .join()
                .unwrap_or_else(|_| Feed::fail("certspotter", "lookup panicked")),
            ct.join()
                .unwrap_or_else(|_| Feed::fail("scanmalware", "lookup panicked")),
        )
    });
    let mut names = Vec::new();
    let mut notes = Vec::new();
    for feed in [&spotter, &ct] {
        absorb(feed, domain, &mut names, &mut notes);
    }
    if names.is_empty() {
        absorb(&crtsh(domain), domain, &mut names, &mut notes);
    }
    let rate_limited = notes.iter().any(|n| {
        n.get("source").and_then(|s| s.as_str()) == Some("certspotter")
            && n.get("error")
                .and_then(|e| e.as_str())
                .is_some_and(|e| e.contains("rate limited"))
    });
    if names.is_empty() && rate_limited {
        return Hit::new(
            "certs",
            Status::Inconclusive,
            "cert spotter rate limited and the other logs returned no names",
            Some(json!({"sources": notes})),
        );
    }
    if names.is_empty()
        && notes
            .iter()
            .all(|n| n.get("status").and_then(|s| s.as_str()) == Some("error"))
    {
        return Hit::new(
            "certs",
            Status::Error,
            "certificate indexes failed",
            Some(json!({"sources": notes})),
        );
    }
    if names.is_empty() {
        return Hit::new(
            "certs",
            Status::Absent,
            "no in-scope certificate names",
            Some(json!({"sources": notes})),
        );
    }
    let shown: Vec<&String> = names.iter().take(40).collect();
    Hit::new(
        "certs",
        Status::Confirmed,
        format!("{} certificate names", names.len()),
        Some(json!({"names": shown, "count": names.len(), "sources": notes})),
    )
}

struct Feed {
    source: &'static str,
    names: Vec<String>,
    note: Option<String>,
}

impl Feed {
    fn fail(source: &'static str, note: &str) -> Self {
        Feed {
            source,
            names: Vec::new(),
            note: Some(note.to_string()),
        }
    }

    fn ready(source: &'static str, names: Vec<String>) -> Self {
        Feed {
            source,
            names,
            note: None,
        }
    }
}

fn absorb(feed: &Feed, domain: &str, names: &mut Vec<String>, notes: &mut Vec<Value>) {
    if feed.names.is_empty() {
        if let Some(note) = &feed.note {
            notes.push(json!({"source": feed.source, "status": "error", "error": note}));
        } else {
            notes.push(json!({"source": feed.source, "status": "ok", "count": 0}));
        }
        return;
    }
    let before = names.len();
    keep_hosts(feed.names.iter().cloned(), domain, names);
    notes.push(json!({
        "source": feed.source,
        "status": "ok",
        "count": names.len() - before,
    }));
}

fn certspotter(net: &Net, domain: &str) -> Feed {
    let url = format!(
        "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
        percent_encode(domain)
    );
    let resp = match net.get(&url, &[("Accept", "application/json")]) {
        Ok(r) => r,
        Err(e) => return Feed::fail("certspotter", &e),
    };
    if resp.status == 429 {
        return Feed::fail("certspotter", "rate limited");
    }
    if resp.status != 200 {
        return Feed::fail("certspotter", &format!("HTTP {}", resp.status));
    }
    match names_from_spotter(&resp.body, domain) {
        Ok(names) => Feed::ready("certspotter", names),
        Err(e) => Feed::fail("certspotter", &e),
    }
}

fn cert_ct(net: &Net, domain: &str) -> Feed {
    let url = format!("https://scanmalware.com/api/v1/ct/dns/{domain}?subdomain_limit=500");
    let resp = match net.get(&url, &[("Accept", "application/json")]) {
        Ok(r) => r,
        Err(e) => return Feed::fail("scanmalware", &e),
    };
    if resp.status != 200 {
        return Feed::fail("scanmalware", &format!("HTTP {}", resp.status));
    }
    match names_from_ct(&resp.body, domain) {
        Ok(names) => Feed::ready("scanmalware", names),
        Err(e) => Feed::fail("scanmalware", &e),
    }
}

fn crtsh(domain: &str) -> Feed {
    let url = format!("https://crt.sh/?q=%.{domain}&output=json");
    let resp = match Net::slow().get(&url, &[("Accept", "application/json")]) {
        Ok(r) => r,
        Err(e) => return Feed::fail("crtsh", &e),
    };
    if resp.status != 200 {
        return Feed::fail("crtsh", &format!("HTTP {}", resp.status));
    }
    if resp.body.len() >= 512 * 1024 {
        return Feed::fail("crtsh", "response was truncated");
    }
    match hosts_from_crt(&resp.body, domain) {
        Ok(names) => Feed::ready("crtsh", names),
        Err(e) => Feed::fail("crtsh", &e),
    }
}

pub(crate) fn names_from_spotter(body: &str, domain: &str) -> Result<Vec<String>, String> {
    let rows: Vec<Value> = serde_json::from_str(body)
        .map_err(|_| "cert spotter response was not a list".to_string())?;
    let mut raw = Vec::new();
    for row in &rows {
        let Some(arr) = row.get("dns_names").and_then(|v| v.as_array()) else {
            continue;
        };
        for name in arr {
            if let Some(name) = name.as_str() {
                raw.push(name.to_string());
            }
        }
    }
    let mut names = Vec::new();
    keep_hosts(raw, domain, &mut names);
    Ok(names)
}

pub(crate) fn names_from_ct(body: &str, domain: &str) -> Result<Vec<String>, String> {
    let v: Value = serde_json::from_str(body).map_err(|_| "response was not json".to_string())?;
    let mut raw = Vec::new();
    if let Some(arr) = v.get("dns_records").and_then(|x| x.as_array()) {
        for row in arr {
            if let Some(name) = row.get("domain").and_then(|d| d.as_str()) {
                raw.push(name.to_string());
            }
        }
    }
    let mut names = Vec::new();
    keep_hosts(raw, domain, &mut names);
    Ok(names)
}

pub fn wayback(net: &Net, domain: &str) -> Hit {
    let url = format!(
        "https://web.archive.org/cdx/search/cdx?url={}&matchType=domain&output=json&fl=original&collapse=urlkey&limit=40",
        percent_encode(domain)
    );
    let resp = match net.get(&url, &[]) {
        Ok(r) if r.status == 200 || r.status == 404 => r,
        first => match Net::slow().get(&url, &[]) {
            Ok(r) if r.status == 200 || r.status == 404 => r,
            Ok(r) => match first {
                Ok(earlier) => earlier,
                Err(_) => r,
            },
            Err(e) => match first {
                Ok(earlier) => earlier,
                Err(_) => return Hit::new("wayback", Status::Error, e, None),
            },
        },
    };
    if resp.status == 404 {
        return Hit::new("wayback", Status::Absent, "no archived host names", None);
    }
    if resp.status != 200 {
        return Hit::new(
            "wayback",
            Status::Inconclusive,
            format!("wayback HTTP {}", resp.status),
            None,
        );
    }
    match wayback_hosts(&resp.body, domain) {
        Ok(hosts) if hosts.is_empty() => {
            Hit::new("wayback", Status::Absent, "no archived host names", None)
        }
        Ok(hosts) => Hit::new(
            "wayback",
            Status::Confirmed,
            format!("{} archived host names", hosts.len()),
            Some(json!({"hosts": hosts})),
        ),
        Err(_) => Hit::new(
            "wayback",
            Status::Inconclusive,
            "wayback response was not a table",
            None,
        ),
    }
}

pub(crate) fn wayback_hosts(body: &str, domain: &str) -> Result<Vec<String>, ()> {
    let rows: Vec<Vec<String>> = serde_json::from_str(body).map_err(|_| ())?;
    let mut hosts = Vec::new();
    for row in &rows {
        let Some(orig) = row.first() else { continue };
        if orig.eq_ignore_ascii_case("original") {
            continue;
        }
        let Some(host) = host_of(orig) else { continue };
        if !in_scope(&host, domain) || hosts.contains(&host) {
            continue;
        }
        hosts.push(host);
        if hosts.len() == 30 {
            break;
        }
    }
    Ok(hosts)
}

pub fn rdap_domain(net: &Net, domain: &str) -> Hit {
    let base = match rdap_dns_base(net, domain) {
        Ok(Some(base)) => base,
        Ok(None) => {
            return Hit::new(
                "rdap",
                Status::Absent,
                "no RDAP service for this suffix",
                None,
            );
        }
        Err(e) => return Hit::new("rdap", Status::Error, e, None),
    };
    let url = format!(
        "{}/domain/{}",
        base.trim_end_matches('/'),
        percent_encode(domain)
    );
    rdap(net, "rdap", &url)
}

pub fn rdap_ip(net: &Net, ip: &str) -> Hit {
    let url = format!("https://rdap.org/ip/{}", percent_encode(ip));
    let mut hit = rdap(net, "rdap-ip", &url);
    if !hit.summary.is_empty() {
        hit.summary = format!("{ip} {}", hit.summary);
    }
    hit
}

fn rdap_dns_base(net: &Net, domain: &str) -> Result<Option<String>, String> {
    let resp = net.get(
        "https://data.iana.org/rdap/dns.json",
        &[("Accept", "application/json")],
    )?;
    if resp.status != 200 {
        return Err(format!("RDAP bootstrap HTTP {}", resp.status));
    }
    let v: Value =
        serde_json::from_str(&resp.body).map_err(|_| "RDAP bootstrap was not JSON".to_string())?;
    let services = v
        .get("services")
        .and_then(|s| s.as_array())
        .ok_or_else(|| "RDAP bootstrap has no services".to_string())?;
    let mut best: Option<(usize, String)> = None;
    for svc in services {
        let Some(pair) = svc.as_array() else {
            continue;
        };
        if pair.len() < 2 {
            continue;
        }
        let Some(suffixes) = pair[0].as_array() else {
            continue;
        };
        let Some(urls) = pair[1].as_array() else {
            continue;
        };
        let Some(url) = urls.iter().find_map(|u| u.as_str()) else {
            continue;
        };
        for suf in suffixes.iter().filter_map(|s| s.as_str()) {
            let suf = suf.trim_start_matches('.').to_ascii_lowercase();
            if suf.is_empty() {
                continue;
            }
            if domain == suf || domain.ends_with(&format!(".{suf}")) {
                if best.as_ref().is_none_or(|(n, _)| suf.len() > *n) {
                    best = Some((suf.len(), url.trim_end_matches('/').to_string()));
                }
            }
        }
    }
    Ok(best.map(|(_, url)| url))
}

fn rdap(net: &Net, module: &str, url: &str) -> Hit {
    let resp = match net.get(url, &[("Accept", "application/rdap+json")]) {
        Ok(r) => r,
        Err(e) => return Hit::new(module, Status::Error, e, None),
    };
    if resp.status == 404 {
        return Hit::new(module, Status::Absent, "no RDAP record", None);
    }
    if resp.status != 200 {
        return Hit::new(
            module,
            Status::Error,
            format!("RDAP HTTP {}", resp.status),
            None,
        );
    }
    let v: Value = match serde_json::from_str(&resp.body) {
        Ok(v) => v,
        Err(_) => return Hit::new(module, Status::Error, "RDAP response was not JSON", None),
    };
    let statuses = string_list(v.get("status"));
    let ns = v
        .get("nameservers")
        .and_then(|n| n.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|n| {
                    n.get("ldhName")
                        .and_then(|s| s.as_str())
                        .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let name = v
        .get("name")
        .or_else(|| v.get("ldhName"))
        .and_then(|s| s.as_str())
        .unwrap_or("");
    let handle = v.get("handle").and_then(|s| s.as_str()).unwrap_or("");
    let expires = v.get("events").and_then(|e| e.as_array()).and_then(|arr| {
        arr.iter().find_map(|ev| {
            let action = ev.get("eventAction").and_then(|s| s.as_str())?;
            if action.eq_ignore_ascii_case("expiration") {
                ev.get("eventDate")
                    .and_then(|s| s.as_str())
                    .map(str::to_string)
            } else {
                None
            }
        })
    });
    let summary = if !name.is_empty() && !statuses.is_empty() {
        format!("{name} ({})", statuses.join(", "))
    } else if !name.is_empty() {
        name.to_string()
    } else if !statuses.is_empty() {
        statuses.join(", ")
    } else if !handle.is_empty() {
        handle.to_string()
    } else {
        "RDAP record".to_string()
    };
    Hit::new(
        module,
        Status::Confirmed,
        summary,
        Some(json!({
            "name": name,
            "handle": handle,
            "status": statuses,
            "nameservers": ns,
            "expiration": expires,
        })),
    )
}

pub fn autoconfig(net: &Net, domain: &str) -> Hit {
    let urls = [
        (
            "thunderbird",
            format!("https://autoconfig.thunderbird.net/v1.1/{domain}"),
        ),
        (
            "autoconfig-host",
            format!("https://autoconfig.{domain}/mail/config-v1.1.xml"),
        ),
        (
            "well-known",
            format!("https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml"),
        ),
    ];
    let mut errors = 0;
    for (source, url) in &urls {
        match net.get(url, &[("Accept", "application/xml, text/xml")]) {
            Err(_) => errors += 1,
            Ok(r) if r.status == 200 => {
                let hosts = xml_text(&r.body, "hostname");
                if hosts.is_empty() {
                    continue;
                }
                return Hit::new(
                    "autoconfig",
                    Status::Confirmed,
                    format!("{source} {}", hosts.join(", ")),
                    Some(json!({"source": source, "hosts": hosts})),
                );
            }
            Ok(_) => {}
        }
    }
    if errors == urls.len() {
        Hit::new(
            "autoconfig",
            Status::Error,
            "autoconfig lookups failed",
            None,
        )
    } else {
        Hit::new("autoconfig", Status::Absent, "no autoconfig document", None)
    }
}

pub fn gravatar(net: &Net, email: &str) -> Hit {
    let hash = hex(&md5(email.to_ascii_lowercase().as_bytes()));
    let url = format!("https://www.gravatar.com/avatar/{hash}?d=404");
    match net.get(&url, &[]) {
        Err(e) => Hit::new("gravatar", Status::Error, e, None),
        Ok(r) if r.status == 404 => Hit::new(
            "gravatar",
            Status::Absent,
            "no Gravatar image for this address",
            Some(json!({"hash": hash})),
        ),
        Ok(r) if r.status == 200 => Hit::new(
            "gravatar",
            Status::Confirmed,
            "a Gravatar image is published for this address",
            Some(json!({"hash": hash})),
        ),
        Ok(r) => Hit::new(
            "gravatar",
            Status::Error,
            format!("gravatar HTTP {}", r.status),
            None,
        ),
    }
}

pub fn wkd(net: &Net, local: &str, domain: &str) -> Hit {
    let hash = wkd_hash(local);
    let urls = [
        (
            "direct",
            format!("https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{hash}"),
        ),
        (
            "advanced",
            format!("https://{domain}/.well-known/openpgpkey/hu/{hash}"),
        ),
    ];
    let mut misses = 0;
    let mut last_err = String::new();
    for (method, url) in &urls {
        match net.get(url, &[("Accept", "application/octet-stream")]) {
            Err(e) => last_err = e,
            Ok(r) if r.status == 404 => misses += 1,
            Ok(r) if r.status == 200 && r.body.len() > 20 => {
                return Hit::new(
                    "wkd",
                    Status::Confirmed,
                    format!("{method} key published"),
                    Some(json!({"method": method, "bytes": r.body.len()})),
                );
            }
            Ok(_) => {}
        }
    }
    if misses == 0 && !last_err.is_empty() {
        Hit::new("wkd", Status::Error, last_err, None)
    } else {
        Hit::new("wkd", Status::Absent, "no Web Key Directory key", None)
    }
}

pub fn vks(net: &Net, email: &str) -> Hit {
    let url = format!(
        "https://keys.openpgp.org/vks/v1/by-email/{}",
        percent_encode(email)
    );
    match net.get(&url, &[]) {
        Err(e) => Hit::new("vks", Status::Error, e, None),
        Ok(r) if r.status == 404 => {
            Hit::new("vks", Status::Absent, "no key on keys.openpgp.org", None)
        }
        Ok(r) if r.status == 200 && r.body.contains("BEGIN PGP PUBLIC KEY") => Hit::new(
            "vks",
            Status::Confirmed,
            "key published on keys.openpgp.org",
            Some(json!({"bytes": r.body.len()})),
        ),
        Ok(r) if r.status == 200 => {
            Hit::new("vks", Status::Absent, "no key on keys.openpgp.org", None)
        }
        Ok(r) => Hit::new("vks", Status::Error, format!("vks HTTP {}", r.status), None),
    }
}

pub fn hkp(net: &Net, email: &str) -> Hit {
    let url = format!(
        "https://keyserver.ubuntu.com/pks/lookup?op=index&options=mr&search={}",
        percent_encode(email)
    );
    match net.get(&url, &[]) {
        Err(e) => Hit::new("hkp", Status::Error, e, None),
        Ok(r) if r.status == 404 => Hit::new(
            "hkp",
            Status::Absent,
            "no key on keyserver.ubuntu.com",
            None,
        ),
        Ok(r) if r.status == 200 => {
            let pubs = r.body.lines().filter(|l| l.starts_with("pub:")).count();
            if pubs == 0 {
                Hit::new(
                    "hkp",
                    Status::Absent,
                    "no key on keyserver.ubuntu.com",
                    None,
                )
            } else {
                Hit::new(
                    "hkp",
                    Status::Confirmed,
                    format!("{pubs} key(s) on keyserver.ubuntu.com"),
                    Some(json!({"keys": pubs})),
                )
            }
        }
        Ok(r) => Hit::new("hkp", Status::Error, format!("hkp HTTP {}", r.status), None),
    }
}

pub fn hibp(net: &Net, email: &str) -> Hit {
    hibp_kind(
        net,
        email,
        "hibp",
        "breachedaccount",
        true,
        "not in Have I Been Pwned",
        "breach name(s)",
        "breaches",
    )
}

pub fn pastes(net: &Net, email: &str) -> Hit {
    hibp_kind(
        net,
        email,
        "pastes",
        "pasteaccount",
        false,
        "Have I Been Pwned returned no pastes for this address",
        "paste(s)",
        "pastes",
    )
}

fn hibp_kind(
    net: &Net,
    email: &str,
    module: &str,
    path: &str,
    truncate: bool,
    absent: &str,
    noun: &str,
    key_name: &str,
) -> Hit {
    let key = std::env::var("HIBP_API_KEY").unwrap_or_default();
    if key.is_empty() {
        return Hit::new(
            module,
            Status::Inconclusive,
            "HIBP_API_KEY is not set",
            None,
        );
    }
    let mut url = format!(
        "https://haveibeenpwned.com/api/v3/{path}/{}",
        percent_encode(email)
    );
    if truncate {
        url.push_str("?truncateResponse=false");
    }
    match net.get(
        &url,
        &[("hibp-api-key", &key), ("Accept", "application/json")],
    ) {
        Err(e) => Hit::new(module, Status::Error, e, None),
        Ok(r) if r.status == 404 => Hit::new(module, Status::Absent, absent, None),
        Ok(r) if r.status == 200 => {
            let rows: Vec<Value> = serde_json::from_str(&r.body).unwrap_or_default();
            let names: Vec<&str> = rows
                .iter()
                .filter_map(|v| {
                    v.get("Name")
                        .or_else(|| v.get("Title"))
                        .or_else(|| v.get("Id"))
                        .and_then(|n| n.as_str())
                })
                .take(20)
                .collect();
            Hit::new(
                module,
                Status::Confirmed,
                format!("{} {noun}", names.len()),
                Some(json!({ key_name: names })),
            )
        }
        Ok(r) if r.status == 401 || r.status == 403 => Hit::new(
            module,
            Status::Error,
            "Have I Been Pwned rejected the API key",
            None,
        ),
        Ok(r) => Hit::new(
            module,
            Status::Error,
            format!("{module} HTTP {}", r.status),
            None,
        ),
    }
}

pub fn github(net: &Net, email: &str) -> Hit {
    let url = format!(
        "https://api.github.com/search/commits?q=author-email:{}&per_page=5",
        percent_encode(email)
    );
    let token = std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("ARGUS_GITHUB_TOKEN"))
        .unwrap_or_default();
    let auth = format!("Bearer {token}");
    let extra: Vec<(&str, &str)> = if token.is_empty() {
        vec![("Accept", "application/vnd.github+json")]
    } else {
        vec![
            ("Accept", "application/vnd.github+json"),
            ("Authorization", auth.as_str()),
        ]
    };
    match net.get(&url, &extra) {
        Err(e) => Hit::new("github", Status::Error, e, None),
        Ok(r) if r.status == 403 || r.status == 422 || r.status == 401 => Hit::new(
            "github",
            Status::Inconclusive,
            "GitHub commit search was not available",
            None,
        ),
        Ok(r) if r.status != 200 => Hit::new(
            "github",
            Status::Inconclusive,
            format!("GitHub HTTP {}", r.status),
            None,
        ),
        Ok(r) => {
            let v: Value = match serde_json::from_str(&r.body) {
                Ok(v) => v,
                Err(_) => {
                    return Hit::new(
                        "github",
                        Status::Inconclusive,
                        "GitHub response was not JSON",
                        None,
                    );
                }
            };
            let count = v.get("total_count").and_then(|n| n.as_u64()).unwrap_or(0);
            if count == 0 {
                return Hit::new(
                    "github",
                    Status::Inconclusive,
                    "GitHub commit search returned no hits. The index is not a complete list of addresses",
                    None,
                );
            }
            let repos: Vec<&str> = v
                .get("items")
                .and_then(|i| i.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| {
                            item.get("repository")
                                .and_then(|r| r.get("full_name"))
                                .and_then(|n| n.as_str())
                        })
                        .take(5)
                        .collect()
                })
                .unwrap_or_default();
            Hit::new(
                "github",
                Status::Confirmed,
                format!("{count} public commit(s) with this author email"),
                Some(json!({"count": count, "repos": repos})),
            )
        }
    }
}

pub fn passive_names(net: &Net, domain: &str) -> Hit {
    let jobs = [
        (
            "crtsh",
            format!("https://crt.sh/?q=%.{domain}&output=json"),
            NameKind::Crt,
        ),
        (
            "hackertarget",
            format!("https://api.hackertarget.com/hostsearch/?q={domain}"),
            NameKind::Pairs,
        ),
        (
            "anubis",
            format!("https://anubisdb.com/anubis/subdomains/{domain}"),
            NameKind::Loose,
        ),
        (
            "scanmalware-ct",
            format!("https://scanmalware.com/api/v1/ct/dns/{domain}?subdomain_limit=500"),
            NameKind::Loose,
        ),
        (
            "scanmalware",
            format!("https://scanmalware.com/api/v1/hosts/{domain}?subdomains_only=true"),
            NameKind::Loose,
        ),
    ];
    let rows = std::thread::scope(|s| {
        let handles: Vec<_> = jobs
            .iter()
            .map(|(name, url, kind)| s.spawn(|| (*name, fetch_names(net, domain, url, *kind))))
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| ("", Err("lookup panicked".into())))
            })
            .collect::<Vec<_>>()
    });
    let mut hosts = Vec::new();
    let mut notes = Vec::new();
    let mut ok = 0usize;
    for (name, result) in &rows {
        match result {
            Ok(found) => {
                ok += 1;
                keep_hosts(found.iter().cloned(), domain, &mut hosts);
                notes.push(json!({"source": name, "status": "ok", "count": found.len()}));
            }
            Err(e) => notes.push(json!({"source": name, "status": "error", "error": clip(e)})),
        }
    }
    if hosts.is_empty() && ok == 0 {
        return Hit::new(
            "names",
            Status::Error,
            "every host index failed",
            Some(json!({"sources": notes})),
        );
    }
    if hosts.is_empty() {
        return Hit::new(
            "names",
            Status::Absent,
            "no extra host names in the indexes",
            Some(json!({"sources": notes})),
        );
    }
    Hit::new(
        "names",
        Status::Confirmed,
        format!("{} host name(s) from public indexes", hosts.len()),
        Some(json!({"hosts": hosts, "sources": notes})),
    )
}

#[derive(Clone, Copy)]
enum NameKind {
    Crt,
    Pairs,
    Loose,
}

fn fetch_names(net: &Net, domain: &str, url: &str, kind: NameKind) -> Result<Vec<String>, String> {
    let resp = net.get(url, &[("Accept", "application/json")])?;
    if resp.status != 200 {
        return Err(format!("HTTP {}", resp.status));
    }
    if resp.body.len() >= 512 * 1024 {
        return Err("response was truncated".into());
    }
    match kind {
        NameKind::Crt => hosts_from_crt(&resp.body, domain),
        NameKind::Pairs => hosts_from_pairs(&resp.body, domain),
        NameKind::Loose => hosts_from_loose(&resp.body, domain),
    }
}

pub fn site_files(net: &Net, domain: &str) -> Vec<Hit> {
    vec![
        published(net, "ads", &format!("https://{domain}/ads.txt"), "ads.txt"),
        published(
            net,
            "humans",
            &format!("https://{domain}/humans.txt"),
            "humans.txt",
        ),
        published(
            net,
            "llms",
            &format!("https://{domain}/llms.txt"),
            "llms.txt",
        ),
        published(
            net,
            "llms-full",
            &format!("https://{domain}/llms-full.txt"),
            "llms-full.txt",
        ),
        tdmrep(net, domain),
    ]
}

pub fn openpgpkey(net: &Net, local: &str, domain: &str) -> Hit {
    let name = format!("{}._openpgpkey.{domain}", wkd_hash(local));
    match net.lookup(&name, "OPENPGPKEY") {
        Err(e) => Hit::new("openpgpkey", Status::Error, e, None),
        Ok(r) if r.answers.iter().any(|a| a.typ == 61) => Hit::new(
            "openpgpkey",
            Status::Confirmed,
            format!("OPENPGPKEY published at {name}"),
            Some(json!({"name": name})),
        ),
        Ok(_) => Hit::new(
            "openpgpkey",
            Status::Absent,
            format!("no OPENPGPKEY at {name}"),
            None,
        ),
    }
}

fn published(net: &Net, module: &str, url: &str, label: &str) -> Hit {
    match net.get(url, &[]) {
        Err(e) => Hit::new(module, Status::Error, e, None),
        Ok(r) if r.status == 404 => Hit::new(module, Status::Absent, format!("no {label}"), None),
        Ok(r) if r.status == 200 && looks_like_html(&r.body) => Hit::new(
            module,
            Status::Inconclusive,
            format!("{label} looks like an HTML page"),
            None,
        ),
        Ok(r) if r.status == 200 && !r.body.trim().is_empty() => Hit::new(
            module,
            Status::Confirmed,
            format!("{label} published, {} bytes", r.body.len()),
            Some(json!({"url": url})),
        ),
        Ok(r) if r.status == 200 => {
            Hit::new(module, Status::Absent, format!("{label} is empty"), None)
        }
        Ok(r) => Hit::new(
            module,
            Status::Inconclusive,
            format!("{label} HTTP {}", r.status),
            None,
        ),
    }
}

fn tdmrep(net: &Net, domain: &str) -> Hit {
    let paths = [
        format!("https://{domain}/.well-known/tdmrep.json"),
        format!("https://{domain}/tdmrep.json"),
    ];
    let mut err = String::new();
    for url in &paths {
        match net.get(url, &[("Accept", "application/json")]) {
            Err(e) => err = e,
            Ok(r) if r.status == 404 => {}
            Ok(r) if r.status == 200 && looks_like_html(&r.body) => {
                return Hit::new(
                    "tdmrep",
                    Status::Inconclusive,
                    "tdmrep.json looks like an HTML page",
                    None,
                );
            }
            Ok(r) if r.status == 200 && serde_json::from_str::<Value>(&r.body).is_ok() => {
                return Hit::new(
                    "tdmrep",
                    Status::Confirmed,
                    "tdmrep.json published",
                    Some(json!({"url": url})),
                );
            }
            Ok(r) if r.status == 200 => {
                return Hit::new(
                    "tdmrep",
                    Status::Inconclusive,
                    "tdmrep.json was not JSON",
                    Some(json!({"url": url})),
                );
            }
            Ok(r) => {
                return Hit::new(
                    "tdmrep",
                    Status::Inconclusive,
                    format!("tdmrep.json HTTP {}", r.status),
                    None,
                );
            }
        }
    }
    if err.is_empty() {
        Hit::new("tdmrep", Status::Absent, "no tdmrep.json", None)
    } else {
        Hit::new("tdmrep", Status::Error, err, None)
    }
}

fn sitemap_pages(net: &Net, domain: &str, sitemaps: &[String]) -> Vec<String> {
    let mut pages = Vec::new();
    for url in sitemaps.iter().take(2) {
        let Ok(resp) = net.get(url, &[]) else {
            continue;
        };
        if resp.status != 200 {
            continue;
        }
        sitemap_locs(&resp.body, domain, &mut pages);
        if pages.len() == 12 {
            break;
        }
    }
    pages
}

fn sitemap_locs(body: &str, domain: &str, out: &mut Vec<String>) {
    let lower = body.to_ascii_lowercase();
    let mut from = 0;
    while let Some(rel) = lower[from..].find("<loc>") {
        let start = from + rel + 5;
        let Some(end_rel) = lower[start..].find("</loc>") else {
            break;
        };
        let raw = body[start..start + end_rel].trim();
        if let Some(host) = host_of(raw) {
            if in_scope(&host, domain) && !out.iter().any(|u| u == raw) {
                out.push(raw.to_string());
            }
        }
        from = start + end_rel + 6;
        if out.len() == 12 {
            break;
        }
    }
}

fn content_signals(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|l| {
            l.trim()
                .to_ascii_lowercase()
                .strip_prefix("content-signal:")
                .map(|v| v.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .take(4)
        .collect()
}

fn mailboxes_in(body: &str, domain: &str) -> Vec<String> {
    let lower = body.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'@' {
            i += 1;
            continue;
        }
        let mut start = i;
        while start > 0 && is_local_byte(bytes[start - 1]) {
            start -= 1;
        }
        let mut end = i + 1;
        while end < bytes.len() && is_host_byte(bytes[end]) {
            end += 1;
        }
        if start < i && end > i + 1 {
            let addr = &lower[start..end];
            if let Some((_, host)) = addr.split_once('@') {
                if in_scope(host, domain) && !out.iter().any(|a| a == addr) {
                    out.push(addr.to_string());
                }
            }
        }
        i = end.max(i + 1);
        if out.len() == 20 {
            break;
        }
    }
    out
}

fn is_local_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-')
}

fn is_host_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

pub(crate) fn hosts_from_crt(body: &str, root: &str) -> Result<Vec<String>, String> {
    let v: Value =
        serde_json::from_str(body).map_err(|_| "crt.sh response was not json".to_string())?;
    let arr = v.as_array().ok_or("crt.sh response was not a list")?;
    let names = arr.iter().filter_map(|row| {
        row.get("name_value")
            .and_then(|x| x.as_str())
            .map(str::to_string)
    });
    let mut out = Vec::new();
    keep_hosts(names, root, &mut out);
    Ok(out)
}

pub(crate) fn hosts_from_pairs(body: &str, root: &str) -> Result<Vec<String>, String> {
    let t = body.trim();
    if t.is_empty() {
        return Ok(Vec::new());
    }
    if !t.contains(',') {
        return Err(clip(t));
    }
    let names = t
        .lines()
        .filter_map(|l| l.split(',').next().map(str::to_string));
    let mut out = Vec::new();
    keep_hosts(names, root, &mut out);
    Ok(out)
}

fn hosts_from_loose(body: &str, root: &str) -> Result<Vec<String>, String> {
    let v: Value = serde_json::from_str(body).map_err(|_| "response was not json".to_string())?;
    let mut names = Vec::new();
    collect_names(&v, &mut names, 0);
    let mut out = Vec::new();
    keep_hosts(names, root, &mut out);
    Ok(out)
}

fn collect_names(v: &Value, out: &mut Vec<String>, depth: usize) {
    if depth > 4 || out.len() > 2000 {
        return;
    }
    match v {
        Value::String(s) if s.contains('.') => out.push(s.clone()),
        Value::Array(items) => {
            for item in items {
                collect_names(item, out, depth + 1);
            }
        }
        Value::Object(map) => {
            for (key, val) in map {
                if matches!(
                    key.as_str(),
                    "subdomains" | "name" | "name_value" | "hostname" | "host" | "names"
                ) {
                    collect_names(val, out, depth + 1);
                }
            }
        }
        _ => {}
    }
}

fn keep_hosts(raw: impl IntoIterator<Item = String>, root: &str, out: &mut Vec<String>) {
    for name in raw {
        for part in name.split(|c: char| c.is_whitespace() || c == ',') {
            let host = part
                .trim()
                .trim_matches(|c: char| c == '"' || c == '\'' || c == '*')
                .trim_matches('.')
                .to_ascii_lowercase();
            if host.is_empty() || host.contains('*') || !in_scope(&host, root) {
                continue;
            }
            if !out.iter().any(|have| have == &host) {
                out.push(host);
            }
            if out.len() == 80 {
                return;
            }
        }
    }
}

pub(crate) fn html_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let rest_lower = &lower[start..];
    let gt = rest_lower.find('>')?;
    let content_at = start + gt + 1;
    let end_rel = lower[content_at..].find("</title>")?;
    let raw = &body[content_at..content_at + end_rel];
    let mut text = String::new();
    let mut skip = false;
    for c in raw.chars() {
        if c == '<' {
            skip = true;
            continue;
        }
        if c == '>' {
            skip = false;
            continue;
        }
        if !skip {
            text.push(c);
        }
    }
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        None
    } else {
        Some(collapsed.chars().take(180).collect())
    }
}

fn looks_like_html(body: &str) -> bool {
    let s = body.trim_start();
    let head: String = s.chars().take(32).collect::<String>().to_ascii_lowercase();
    head.starts_with("<!doctype html") || head.starts_with("<html")
}

fn host_of(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = rest.split(['/', ':', '?']).next()?;
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() { None } else { Some(host) }
}

fn xml_text(body: &str, tag: &str) -> Vec<String> {
    let lower = body.to_ascii_lowercase();
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = lower[from..].find(&open) {
        let start = from + rel;
        let Some(gt) = lower[start..].find('>') else {
            break;
        };
        let content_at = start + gt + 1;
        let Some(end_rel) = lower[content_at..].find(&close) else {
            break;
        };
        let text = body[content_at..content_at + end_rel].trim();
        if !text.is_empty() && !text.contains('<') {
            out.push(text.to_string());
        }
        from = content_at + end_rel + close.len();
        if out.len() == 8 {
            break;
        }
    }
    out
}

fn string_list(v: Option<&Value>) -> Vec<String> {
    v.and_then(|s| s.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_ignores_nested_markup() {
        let html = "<html><title> Quad4  -  <b>Software</b> </title></html>";
        assert_eq!(html_title(html).as_deref(), Some("Quad4 - Software"));
        assert!(html_title("<html></html>").is_none());
        assert!(looks_like_html("<!DOCTYPE html><title>x</title>"));
        assert!(!looks_like_html("User-agent: *\nDisallow: /\n"));
    }

    #[test]
    fn crt_and_pair_hosts_stay_in_scope() {
        let crt = r#"[{"name_value":"*.quad4.io\nwww.quad4.io\nother.example"}]"#;
        let hosts = hosts_from_crt(crt, "quad4.io").unwrap();
        assert!(hosts.contains(&"quad4.io".to_string()));
        assert!(hosts.contains(&"www.quad4.io".to_string()));
        assert!(!hosts.iter().any(|h| h.contains("example")));
        let pairs =
            hosts_from_pairs("api.quad4.io,1.2.3.4\nAPI count exceeded", "quad4.io").unwrap();
        assert_eq!(pairs, vec!["api.quad4.io".to_string()]);
        assert!(hosts_from_pairs("API count exceeded", "quad4.io").is_err());
    }

    #[test]
    fn homepage_mailboxes_ignore_other_domains() {
        let html = "mail argus@quad4.io and other@example.com plus argus@quad4.io";
        assert_eq!(
            mailboxes_in(html, "quad4.io"),
            vec!["argus@quad4.io".to_string()]
        );
        let robots = "User-agent: *\nContent-Signal: search=yes,ai-train=no\n";
        assert_eq!(
            content_signals(robots),
            vec!["search=yes,ai-train=no".to_string()]
        );
        let mut pages = Vec::new();
        sitemap_locs(
            "<urlset><url><loc>https://quad4.io/docs</loc></url><url><loc>https://evil.test/x</loc></url></urlset>",
            "quad4.io",
            &mut pages,
        );
        assert_eq!(pages, vec!["https://quad4.io/docs".to_string()]);
    }

    #[test]
    fn wayback_table_skips_the_header() {
        let body = r#"[["original"],["https://quad4.io/docs"],["https://other.example/a"]]"#;
        let hosts = wayback_hosts(body, "quad4.io").unwrap();
        assert_eq!(hosts, vec!["quad4.io".to_string()]);
    }

    #[test]
    fn certificate_names_skip_wildcards_and_read_ct_rows() {
        let spotter = r#"[{"dns_names":["*.quad4.io","www.quad4.io","evil.example"]}]"#;
        let names = names_from_spotter(spotter, "quad4.io").unwrap();
        assert!(names.contains(&"www.quad4.io".to_string()));
        assert!(!names.iter().any(|n| n.contains("example")));
        let ct = r#"{"dns_records":[{"domain":"argus.quad4.io"},{"domain":"quad4.io"}]}"#;
        let names = names_from_ct(ct, "quad4.io").unwrap();
        assert_eq!(
            names,
            vec!["argus.quad4.io".to_string(), "quad4.io".to_string()]
        );
    }
}
