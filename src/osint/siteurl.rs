// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! One public URL. Redirects are followed by hand so a hop cannot land on
//! a loopback, private, or link-local address. The body is not crawled.

use super::intel::urlscan;
use super::name::{public_ip, validate_domain};
use super::net::{Net, header};
use super::surface::html_title;
use super::waf;
use super::{Hit, Report, Status};
use serde_json::json;
use std::io::Read;
use std::net::ToSocketAddrs;
use std::time::{Duration, Instant};

const HOPS: usize = 5;

pub fn scan(raw: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    let start = parse_http_url(raw.trim())?;
    assert_public(&start)?;
    let host = start.host.clone();
    let net = Net::new();
    let (page, scanned) = std::thread::scope(|s| {
        let page = s.spawn(|| fetch(start));
        let scanned = s.spawn(|| {
            if public_ip(&host) {
                Hit::new(
                    "urlscan",
                    Status::Absent,
                    "urlscan is queried by domain name",
                    None,
                )
            } else {
                urlscan(&net, &host)
            }
        });
        (
            page.join().unwrap_or_else(|_| Err("fetch panicked".into())),
            scanned
                .join()
                .unwrap_or_else(|_| Hit::new("urlscan", Status::Error, "lookup panicked", None)),
        )
    });
    let page = page?;
    let waf_hit = waf::detect(&page.headers, &page.body);
    let trackers = super::trackers::detect(&page.headers, &page.body);
    let title = html_title(&page.body).unwrap_or_default();
    let redirect = if page.hops.len() <= 1 {
        Hit::new("redirects", Status::Absent, "no redirect", None)
    } else {
        Hit::new(
            "redirects",
            Status::Confirmed,
            format!("{} hop(s)", page.hops.len() - 1),
            Some(json!({"hops": page.hops})),
        )
    };
    let mut summary = format!("HTTP {}", page.status);
    if !title.is_empty() {
        summary.push_str(&format!(" {title}"));
    }
    Ok(Report {
        target: raw.trim().to_string(),
        kind: "url",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings: vec![
            Hit::new(
                "fetch",
                if (200..400).contains(&page.status) {
                    Status::Confirmed
                } else {
                    Status::Inconclusive
                },
                summary,
                Some(json!({
                    "url": page.final_url,
                    "status": page.status,
                    "bytes": page.body.len(),
                })),
            ),
            redirect,
            waf_hit,
            trackers,
            super::surface::seo_hit(&page.body),
            scanned,
        ],
    })
}

struct Page {
    status: u16,
    final_url: String,
    headers: Vec<(String, String)>,
    body: String,
    hops: Vec<String>,
}

struct Loc {
    scheme: String,
    host: String,
    port: u16,
    path: String,
}

impl Loc {
    fn url(&self) -> String {
        let default = if self.scheme == "https" { 443 } else { 80 };
        let port = if self.port == default {
            String::new()
        } else {
            format!(":{}", self.port)
        };
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!("{}://{}{}{}", self.scheme, host, port, self.path)
    }
}

fn fetch(start: Loc) -> Result<Page, String> {
    let config = ureq::config::Config::builder()
        .timeout_global(Some(Duration::from_secs(6)))
        .max_redirects(0)
        .http_status_as_error(false)
        .user_agent(concat!("argus/", env!("CARGO_PKG_VERSION")))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut current = start;
    let mut hops = Vec::new();
    for _ in 0..=HOPS {
        assert_public(&current)?;
        let url = current.url();
        hops.push(url.clone());
        let mut resp = agent.get(&url).call().map_err(|e| format!("{url}: {e}"))?;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_ascii_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            if hops.len() > HOPS {
                return Err("too many redirects".into());
            }
            let loc = header(&headers, "location").unwrap_or("").trim();
            if loc.is_empty() {
                return Err("redirect had no location".into());
            }
            current = join(&current, loc)?;
            continue;
        }
        let mut body = resp.body_mut().read_to_string().unwrap_or_default();
        if body.len() > 512 * 1024 {
            body.truncate(512 * 1024);
        }
        return Ok(Page {
            status,
            final_url: url,
            headers,
            body,
            hops,
        });
    }
    Err("too many redirects".into())
}

fn fetch_raw(start: Loc, cap: usize) -> Result<(u16, Vec<u8>), String> {
    let config = ureq::config::Config::builder()
        .timeout_global(Some(Duration::from_secs(6)))
        .max_redirects(0)
        .http_status_as_error(false)
        .user_agent(concat!("argus/", env!("CARGO_PKG_VERSION")))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut current = start;
    for _ in 0..=HOPS {
        assert_public(&current)?;
        let url = current.url();
        let mut resp = agent.get(&url).call().map_err(|e| format!("{url}: {e}"))?;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_ascii_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let loc = header(&headers, "location").unwrap_or("").trim();
            if loc.is_empty() {
                return Err("redirect had no location".into());
            }
            current = join(&current, loc)?;
            continue;
        }
        let mut body = Vec::new();
        resp.body_mut()
            .as_reader()
            .take(cap as u64)
            .read_to_end(&mut body)
            .map_err(|e| format!("{url}: {e}"))?;
        return Ok((status, body));
    }
    Err("too many redirects".into())
}

fn join(base: &Loc, location: &str) -> Result<Loc, String> {
    let location = location.trim();
    if location.len() > 2048 {
        return Err("redirect location is too long".into());
    }
    let lower = location.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return parse_http_url(location);
    }
    if lower.starts_with("//") {
        return parse_http_url(&format!("{}:{location}", base.scheme));
    }
    if location.starts_with('/') || location.starts_with('?') {
        let mut next = clone_origin(base);
        if location.starts_with('?') {
            let path = base.path.split('?').next().unwrap_or("/");
            next.path = format!("{path}{location}");
        } else {
            next.path = location.to_string();
        }
        return Ok(next);
    }
    if location.contains("://") {
        return Err("refusing a non-http redirect".into());
    }
    let mut next = clone_origin(base);
    let dir = base.path.split('?').next().unwrap_or("/");
    let dir = match dir.rfind('/') {
        Some(i) => &dir[..=i],
        None => "/",
    };
    next.path = format!("{dir}{location}");
    Ok(next)
}

fn clone_origin(base: &Loc) -> Loc {
    Loc {
        scheme: base.scheme.clone(),
        host: base.host.clone(),
        port: base.port,
        path: base.path.clone(),
    }
}

fn parse_http_url(raw: &str) -> Result<Loc, String> {
    let raw = raw.trim();
    let (scheme, rest) = if let Some(rest) = raw.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = raw.strip_prefix("http://") {
        ("http", rest)
    } else {
        return Err("pass an http or https URL".into());
    };
    if rest.contains('@') {
        return Err("refusing a URL with credentials".into());
    }
    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(i) => {
            let path = if rest[i..].starts_with('#') {
                "/".to_string()
            } else if rest[i..].starts_with('?') {
                format!("/{}", &rest[i..])
            } else {
                rest[i..].split('#').next().unwrap_or("/").to_string()
            };
            (&rest[..i], path)
        }
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return Err("URL has no host".into());
    }
    let (host, port) = split_host(authority, if scheme == "https" { 443 } else { 80 })?;
    if host.is_empty() || host.contains(char::is_whitespace) {
        return Err("URL has a bad host".into());
    }
    Ok(Loc {
        scheme: scheme.to_string(),
        host: host.to_ascii_lowercase(),
        port,
        path,
    })
}

fn split_host(authority: &str, default: u16) -> Result<(String, u16), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']').ok_or("bad IPv6 host")?;
        let host = rest[..end].to_string();
        let tail = &rest[end + 1..];
        let port = if let Some(p) = tail.strip_prefix(':') {
            p.parse().map_err(|_| "bad port".to_string())?
        } else if tail.is_empty() {
            default
        } else {
            return Err("bad IPv6 host".into());
        };
        return Ok((host, port));
    }
    if let Some((host, port)) = authority.rsplit_once(':')
        && !port.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
    {
        let port: u16 = port.parse().map_err(|_| "bad port".to_string())?;
        return Ok((host.to_string(), port));
    }
    Ok((authority.to_string(), default))
}

pub(crate) type Headers = Vec<(String, String)>;
pub(crate) type Fetched = (u16, String, Headers, String);

pub(crate) fn fetch_public(raw: &str) -> Result<Fetched, String> {
    let start = parse_http_url(raw.trim())?;
    assert_public(&start)?;
    let page = fetch(start)?;
    Ok((page.status, page.final_url, page.headers, page.body))
}

pub(crate) fn fetch_public_bytes(raw: &str, cap: usize) -> Result<(u16, Vec<u8>), String> {
    let start = parse_http_url(raw.trim())?;
    assert_public(&start)?;
    let page = fetch_raw(start, cap)?;
    Ok((page.0, page.1))
}

fn assert_public(loc: &Loc) -> Result<(), String> {
    if let Ok(ip) = loc.host.parse::<std::net::IpAddr>() {
        return if public_ip(&ip.to_string()) {
            Ok(())
        } else {
            Err("refusing a non-public address".into())
        };
    }
    if loc
        .host
        .split('.')
        .all(|label| !label.is_empty() && label.chars().all(|c| c.is_ascii_digit()))
    {
        return Err("refusing a non-public address".into());
    }
    validate_domain(&loc.host)?;
    let mut any = false;
    for addr in (loc.host.as_str(), loc.port)
        .to_socket_addrs()
        .map_err(|e| format!("could not resolve {}: {e}", loc.host))?
    {
        any = true;
        if !public_ip(&addr.ip().to_string()) {
            return Err("refusing a non-public address".into());
        }
    }
    if !any {
        return Err(format!("could not resolve {}", loc.host));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_and_odd_urls_are_refused() {
        assert!(parse_http_url("file:///etc/passwd").is_err());
        assert!(parse_http_url("http://user:pass@quad4.io/").is_err());
        assert!(scan("http://127.0.0.1/").is_err());
        assert!(scan("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(scan("http://10.1.1.1/").is_err());
        assert!(scan("http://localhost/").is_err());
        let loc = parse_http_url("https://quad4.io/docs?q=1").unwrap();
        assert_eq!(loc.host, "quad4.io");
        assert_eq!(loc.path, "/docs?q=1");
        let next = join(&loc, "/other").unwrap();
        assert_eq!(next.url(), "https://quad4.io/other");
    }
}
