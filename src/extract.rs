// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Pull emails, URLs, addresses, hashes, and wallet-shaped strings out of text.
//! Callers decide whether to keep a capped report or print matches as they go.
//! A hit is a lead. It is not proof of identity.

use crate::osint::{Hit, Report, Status};
use serde_json::json;
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;
use std::time::Instant;

const LINE_CAP: usize = 1024 * 1024;
const KEEP: usize = 40;

#[derive(Clone, Copy)]
pub enum Pick {
    Emails,
    Urls,
    Addrs,
    Hashes,
    Wallets,
}

impl Pick {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "emails" | "email" => Ok(Pick::Emails),
            "urls" | "url" => Ok(Pick::Urls),
            "addrs" | "ips" | "ip" => Ok(Pick::Addrs),
            "hashes" | "hash" => Ok(Pick::Hashes),
            "wallets" | "wallet" => Ok(Pick::Wallets),
            _ => Err("pick must be emails, urls, addrs, hashes, or wallets".into()),
        }
    }
}

pub struct Bag {
    pub emails: BTreeSet<String>,
    pub urls: BTreeSet<String>,
    pub addrs: BTreeSet<String>,
    pub hashes: BTreeSet<String>,
    pub wallets: BTreeSet<String>,
}

impl Bag {
    fn new() -> Self {
        Self {
            emails: BTreeSet::new(),
            urls: BTreeSet::new(),
            addrs: BTreeSet::new(),
            hashes: BTreeSet::new(),
            wallets: BTreeSet::new(),
        }
    }

    fn full(&self) -> bool {
        self.emails.len() >= KEEP
            && self.urls.len() >= KEEP
            && self.addrs.len() >= KEEP
            && self.hashes.len() >= KEEP
            && self.wallets.len() >= KEEP
    }
}

pub fn scan_target(target: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    let target = target.trim();
    let (label, text) = if target == "-" {
        let mut buf = String::new();
        std::io::Read::take(std::io::stdin(), 2 * 1024 * 1024)
            .read_to_string(&mut buf)
            .map_err(|e| format!("stdin: {e}"))?;
        ("stdin".into(), buf)
    } else if crate::cli::is_http_target(target) {
        let (status, _, _, body) = crate::osint::siteurl::fetch_public(target)?;
        if !(200..400).contains(&status) {
            return Err(format!("HTTP {status}"));
        }
        (target.to_string(), body)
    } else if Path::new(target).is_file() {
        (target.to_string(), read_capped(Path::new(target))?)
    } else {
        (target.to_string(), target.to_string())
    };
    let mut bag = Bag::new();
    for line in text.split_inclusive('\n') {
        let line = if line.len() > LINE_CAP {
            &line[..LINE_CAP]
        } else {
            line
        };
        push_line(&mut bag, line);
        if bag.full() {
            break;
        }
    }
    Ok(report(&label, &bag, t0.elapsed().as_millis() as u64))
}

pub fn emails_in(text: &str) -> Vec<String> {
    let mut bag = Bag::new();
    push_emails(&mut bag, text);
    bag.emails.into_iter().collect()
}

pub fn urls_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 8 < bytes.len() {
        if bytes[i] >= 128 {
            i = skip_utf8(bytes, i);
            continue;
        }
        let rest = &text[i..];
        let https = rest.len() >= 8 && rest.as_bytes()[..8].eq_ignore_ascii_case(b"https://");
        let http = rest.len() >= 7 && rest.as_bytes()[..7].eq_ignore_ascii_case(b"http://");
        if https || http {
            let start = i;
            i += if https { 8 } else { 7 };
            while i < bytes.len() {
                let c = bytes[i];
                if c.is_ascii_whitespace()
                    || matches!(c, b'"' | b'\'' | b'<' | b'>' | b')' | b']' | b',')
                {
                    break;
                }
                i += 1;
            }
            let url = text[start..i].trim_end_matches('.').to_string();
            if url.len() < 400 {
                out.push(url);
            }
        } else {
            i += 1;
        }
    }
    out
}

pub fn addrs_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut dots = 0;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                if bytes[i] == b'.' {
                    dots += 1;
                }
                i += 1;
            }
            if dots == 3 {
                let cand = &text[start..i];
                if is_ipv4(cand) {
                    out.push(cand.to_string());
                }
            }
        } else {
            i += 1;
        }
    }
    out
}

pub fn hashes_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_hexdigit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            let n = i - start;
            let bounded = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
            let end_ok = i == bytes.len() || !bytes[i].is_ascii_alphanumeric();
            if bounded && end_ok && matches!(n, 32 | 40 | 64) {
                out.push(text[start..i].to_ascii_lowercase());
            }
        } else {
            i += 1;
        }
    }
    out
}

pub fn wallets_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 4 < bytes.len() {
        if bytes[i..].starts_with(b"0x") && i + 42 <= bytes.len() {
            let cand = &text[i..i + 42];
            if cand[2..].bytes().all(|c| c.is_ascii_hexdigit())
                && (i + 42 == bytes.len() || !bytes[i + 42].is_ascii_alphanumeric())
            {
                out.push(cand.to_string());
                i += 42;
                continue;
            }
        }
        if matches!(bytes[i], b'1' | b'3') || bytes[i..].starts_with(b"bc1") {
            let start = i;
            while i < bytes.len() && is_b58ish(bytes[i]) {
                i += 1;
            }
            let n = i - start;
            if (26..=62).contains(&n) && (text[start..i].starts_with("bc1") || n <= 42) {
                let cand = &text[start..i];
                if cand.starts_with("bc1") || cand.chars().any(|c| c.is_ascii_uppercase()) {
                    out.push(cand.to_string());
                }
            }
            continue;
        }
        i += 1;
    }
    out
}

pub fn pick_in(pick: Pick, text: &str) -> Vec<String> {
    match pick {
        Pick::Emails => emails_in(text),
        Pick::Urls => urls_in(text),
        Pick::Addrs => addrs_in(text),
        Pick::Hashes => hashes_in(text),
        Pick::Wallets => wallets_in(text),
    }
}

fn push_line(bag: &mut Bag, text: &str) {
    push_emails(bag, text);
    if bag.urls.len() < KEEP {
        for u in urls_in(text) {
            bag.urls.insert(u);
            if bag.urls.len() >= KEEP {
                break;
            }
        }
    }
    if bag.addrs.len() < KEEP {
        for a in addrs_in(text) {
            bag.addrs.insert(a);
        }
    }
    if bag.hashes.len() < KEEP {
        for h in hashes_in(text) {
            bag.hashes.insert(h);
        }
    }
    if bag.wallets.len() < KEEP {
        for w in wallets_in(text) {
            bag.wallets.insert(w);
        }
    }
}

fn push_emails(bag: &mut Bag, text: &str) {
    if bag.emails.len() >= KEEP {
        return;
    }
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'@' {
            let mut a = i;
            while a > 0 && is_mail(bytes[a - 1]) {
                a -= 1;
            }
            let mut b = i + 1;
            while b < bytes.len() && (is_mail(bytes[b]) || bytes[b] == b'.') {
                b += 1;
            }
            let cand = &text[a..b];
            if cand.matches('@').count() == 1
                && cand.contains('.')
                && !cand.starts_with('@')
                && cand.len() < 200
            {
                bag.emails
                    .insert(cand.trim_matches('.').to_ascii_lowercase());
                if bag.emails.len() >= KEEP {
                    return;
                }
            }
            i = b;
        } else {
            i += 1;
        }
    }
}

fn report(label: &str, bag: &Bag, elapsed_ms: u64) -> Report {
    let mut findings = Vec::new();
    push_hit(&mut findings, "emails", &bag.emails);
    push_hit(&mut findings, "urls", &bag.urls);
    push_hit(&mut findings, "addrs", &bag.addrs);
    push_hit(&mut findings, "hashes", &bag.hashes);
    push_hit(&mut findings, "wallets", &bag.wallets);
    Report {
        target: label.to_string(),
        kind: "extract",
        elapsed_ms,
        findings,
    }
}

fn push_hit(findings: &mut Vec<Hit>, module: &str, set: &BTreeSet<String>) {
    if set.is_empty() {
        findings.push(Hit::new(
            module,
            Status::Absent,
            format!("no {module}"),
            None,
        ));
        return;
    }
    let list: Vec<&str> = set.iter().take(KEEP).map(String::as_str).collect();
    findings.push(Hit::new(
        module,
        Status::Confirmed,
        format!("{} {module}", list.len()),
        Some(json!({ "values": list })),
    ));
}

fn read_capped(path: &Path) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut buf = String::new();
    std::io::Read::take(file, 8 * 1024 * 1024)
        .read_to_string(&mut buf)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(buf)
}

fn is_mail(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_b58ish(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u16>().ok().is_some_and(|n| n <= 255)
                && (p.len() == 1 || !p.starts_with('0'))
        })
}

fn skip_utf8(bytes: &[u8], mut i: usize) -> usize {
    i += 1;
    while i < bytes.len() && bytes[i] & 0b1100_0000 == 0b1000_0000 {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pulls_the_common_shapes() {
        let text = "mail ada@example.com see https://example.com/a and 203.0.113.10 \
                    275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f \
                    0x1111111111111111111111111111111111111111";
        assert_eq!(emails_in(text), vec!["ada@example.com".to_string()]);
        assert!(urls_in(text).iter().any(|u| u.contains("example.com/a")));
        assert_eq!(addrs_in(text), vec!["203.0.113.10".to_string()]);
        assert_eq!(hashes_in(text).len(), 1);
        assert!(wallets_in(text)[0].starts_with("0x1111"));
        assert!(
            addrs_in("version 1.2.3.4").is_empty()
                || addrs_in("version 1.2.3.4") == vec!["1.2.3.4".to_string()]
        );
    }
}
