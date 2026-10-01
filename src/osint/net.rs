// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Short-timeout HTTPS and JSON DNS-over-HTTPS.
//! Cloudflare is tried first. Google is the fallback when that call fails.

use serde_json::Value;
use std::time::Duration;

pub struct Net {
    agent: ureq::Agent,
}

pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct Rr {
    pub typ: i64,
    pub data: String,
}

#[derive(Debug)]
pub struct DnsResp {
    pub status: i64,
    pub ad: bool,
    pub answers: Vec<Rr>,
}

impl Net {
    pub fn new() -> Self {
        Self::with_timeout(6)
    }

    /// Longer budget for one slow public index. Other checks keep the short timeout.
    pub fn slow() -> Self {
        Self::with_timeout(20)
    }

    fn with_timeout(secs: u64) -> Self {
        let config = ureq::config::Config::builder()
            .timeout_global(Some(Duration::from_secs(secs)))
            .http_status_as_error(false)
            .user_agent(concat!("argus/", env!("CARGO_PKG_VERSION")))
            .build();
        Net {
            agent: ureq::Agent::new_with_config(config),
        }
    }

    pub fn get(&self, url: &str, extra: &[(&str, &str)]) -> Result<Resp, String> {
        let mut req = self.agent.get(url);
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        let mut resp = req.call().map_err(|e| clip(&format!("{url}: {e}")))?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_ascii_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();
        let mut body = resp.body_mut().read_to_string().unwrap_or_default();
        if body.len() > 512 * 1024 {
            body.truncate(512 * 1024);
        }
        Ok(Resp {
            status,
            headers,
            body,
        })
    }

    pub fn lookup_via(&self, base: &str, name: &str, qtype: &str) -> Result<DnsResp, String> {
        let name_q = super::name::percent_encode(name);
        let type_q = super::name::percent_encode(qtype);
        let url = format!("{base}?name={name_q}&type={type_q}");
        let resp = self.get(&url, &[("Accept", "application/dns-json")])?;
        if resp.status != 200 {
            return Err(format!("doh http {}", resp.status));
        }
        parse_doh(&resp.body)
    }

    pub fn lookup(&self, name: &str, qtype: &str) -> Result<DnsResp, String> {
        let name_q = super::name::percent_encode(name);
        let type_q = super::name::percent_encode(qtype);
        let mut last = String::from("no resolver");
        for base in [
            "https://cloudflare-dns.com/dns-query",
            "https://dns.google/resolve",
        ] {
            let url = format!("{base}?name={name_q}&type={type_q}");
            match self.get(&url, &[("Accept", "application/dns-json")]) {
                Ok(resp) if resp.status == 200 => match parse_doh(&resp.body) {
                    Ok(parsed) => return Ok(parsed),
                    Err(e) => last = e,
                },
                Ok(resp) => last = format!("doh http {}", resp.status),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    pub fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        let resp = self.lookup(name, "TXT")?;
        if resp.status == 3 {
            return Ok(Vec::new());
        }
        if resp.status != 0 {
            return Err(format!("dns status {}", resp.status));
        }
        Ok(txt_values(&resp.answers))
    }
}

fn parse_doh(body: &str) -> Result<DnsResp, String> {
    let v: Value =
        serde_json::from_str(body).map_err(|_| "doh response was not json".to_string())?;
    let status = v
        .get("Status")
        .and_then(|s| s.as_i64())
        .ok_or_else(|| "doh response had no status".to_string())?;
    let ad = v.get("AD").and_then(|s| s.as_bool()).unwrap_or(false);
    let mut answers = Vec::new();
    if let Some(arr) = v.get("Answer").and_then(|a| a.as_array()) {
        for a in arr {
            let typ = a.get("type").and_then(|t| t.as_i64()).unwrap_or(0);
            let data = a.get("data").and_then(|d| d.as_str()).unwrap_or("").trim();
            if typ != 0 && !data.is_empty() {
                answers.push(Rr {
                    typ,
                    data: data.to_string(),
                });
            }
        }
    }
    Ok(DnsResp {
        status,
        ad,
        answers,
    })
}

pub fn unquote_txt(data: &str) -> String {
    if !data.contains('"') {
        return data.trim().to_string();
    }
    let mut out = String::new();
    let mut in_q = false;
    let mut esc = false;
    for c in data.chars() {
        if esc {
            out.push(c);
            esc = false;
            continue;
        }
        if c == '\\' && in_q {
            esc = true;
            continue;
        }
        if c == '"' {
            in_q = !in_q;
            continue;
        }
        if in_q {
            out.push(c);
        }
    }
    out
}

pub fn txt_values(answers: &[Rr]) -> Vec<String> {
    answers
        .iter()
        .filter(|a| a.typ == 16)
        .map(|a| unquote_txt(&a.data))
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn clip(s: &str) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.chars().take(180).collect()
}

pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_chunks_join_without_added_space() {
        assert_eq!(unquote_txt("\"v=spf1\" \" -all\""), "v=spf1 -all");
        assert_eq!(unquote_txt("v=spf1 -all"), "v=spf1 -all");
        assert_eq!(
            txt_values(&[Rr {
                typ: 16,
                data: "\"google-site-verification=abc\"".into(),
            }]),
            vec!["google-site-verification=abc".to_string()]
        );
    }

    #[test]
    fn doh_json() {
        let raw = r#"{"Status":0,"AD":true,"Answer":[{"name":"example.com","type":1,"TTL":30,"data":"203.0.113.10"}]}"#;
        let p = parse_doh(raw).unwrap();
        assert_eq!(p.status, 0);
        assert!(p.ad);
        assert_eq!(p.answers[0].data, "203.0.113.10");
    }
}
