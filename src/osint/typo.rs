// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Lookalike domain surface.
//! dnstwist-style permutations of the registered label, resolved over
//! DNS-over-HTTPS. A lookalike that resolves is a lead; one with MX is a
//! phishing-capable lead.

use super::name::{normalize_domain, registrable};
use super::net::Net;
use super::{Hit, Report, Status};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

const MAX_CANDIDATES: usize = 400;
const WORKERS: usize = 6;

const SWAP_TLDS: &[&str] = &[
    "com", "net", "org", "io", "co", "app", "dev", "info", "biz", "me", "xyz", "online", "site",
    "shop", "cloud",
];

fn confusables(c: char) -> &'static [char] {
    match c {
        'o' | '0' => &['o', '0'],
        'l' | '1' | 'i' => &['l', '1', 'i'],
        'e' | '3' => &['e', '3'],
        's' | '5' | 'z' => &['s', '5', 'z'],
        'a' | '4' => &['a', '4'],
        't' | '7' => &['t', '7'],
        'b' | '8' => &['b', '8'],
        'g' | '9' | 'q' => &['g', '9', 'q'],
        'c' | 'k' => &['c', 'k'],
        'm' | 'n' => &['m', 'n'],
        'u' | 'v' => &['u', 'v'],
        _ => &[],
    }
}

fn valid_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// All permutation candidates for the registered domain, minus the
/// domain itself.
pub(crate) fn candidates(domain: &str) -> Vec<String> {
    let reg = registrable(domain);
    let Some((sld, tld)) = reg.split_once('.') else {
        return Vec::new();
    };
    let sld = sld.to_ascii_lowercase();
    let mut out: Vec<String> = Vec::new();
    let mut push = |label: String, tld: &str| {
        if valid_label(&label) {
            let d = format!("{label}.{tld}");
            if !out.contains(&d) {
                out.push(d);
            }
        }
    };
    let chars: Vec<char> = sld.chars().collect();
    for i in 0..chars.len() {
        // omission
        push(chars[..i].iter().chain(&chars[i + 1..]).collect(), tld);
        // repetition
        let mut r = sld.clone();
        r.insert(i, chars[i]);
        push(r, tld);
        // replacement with confusables
        for &c in confusables(chars[i]) {
            if c == chars[i] {
                continue;
            }
            let mut r = sld.clone();
            r.replace_range(
                sld.char_indices().nth(i).unwrap().0
                    ..sld.char_indices().nth(i).unwrap().0 + chars[i].len_utf8(),
                &c.to_string(),
            );
            push(r, tld);
        }
        // bitsquat: flip each bit, keep printable lowercase
        let b = chars[i] as u8;
        for bit in 0..7 {
            let flipped = b ^ (1 << bit);
            let fc = flipped as char;
            if fc.is_ascii_lowercase() || fc.is_ascii_digit() || fc == '-' {
                let mut r: String = chars[..i].iter().collect();
                r.push(fc);
                r.extend(&chars[i + 1..]);
                push(r, tld);
            }
        }
    }
    // transposition
    for i in 0..chars.len().saturating_sub(1) {
        let mut t = chars.clone();
        t.swap(i, i + 1);
        push(t.iter().collect(), tld);
    }
    // hyphen insertion
    for i in 1..chars.len() {
        let mut r = sld.clone();
        r.insert(i, '-');
        push(r, tld);
    }
    // tld swap on the unchanged label
    for alt in SWAP_TLDS {
        if *alt != tld {
            push(sld.clone(), alt);
        }
    }
    out.truncate(MAX_CANDIDATES);
    out.retain(|d| d != &reg);
    out
}

pub(crate) struct LiveName {
    pub name: String,
    pub addrs: Vec<String>,
    pub mx: Vec<String>,
}

/// Resolve candidates over DoH; live names get an MX probe too.
pub(crate) fn live_names(cands: &[String]) -> Vec<LiveName> {
    let net = Net::new();
    let next = AtomicUsize::new(0);
    let mut out: Vec<LiveName> = Vec::new();
    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for _ in 0..WORKERS.min(cands.len().max(1)) {
            let next = &next;
            let net = &net;
            handles.push(s.spawn(move || {
                let mut mine = Vec::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= cands.len() {
                        break;
                    }
                    let name = &cands[i];
                    let addrs: Vec<String> = net
                        .lookup(name, "A")
                        .map(|r| {
                            if r.status == 0 {
                                r.answers.iter().map(|a| a.data.clone()).take(4).collect()
                            } else {
                                Vec::new()
                            }
                        })
                        .unwrap_or_default();
                    let mx: Vec<String> = net
                        .lookup(name, "MX")
                        .map(|r| {
                            if r.status == 0 {
                                r.answers.iter().map(|a| a.data.clone()).take(4).collect()
                            } else {
                                Vec::new()
                            }
                        })
                        .unwrap_or_default();
                    if addrs.is_empty() && mx.is_empty() {
                        continue;
                    }
                    mine.push(LiveName {
                        name: name.clone(),
                        addrs,
                        mx,
                    });
                }
                mine
            }));
        }
        for h in handles {
            out.extend(h.join().unwrap_or_default());
        }
    });
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

pub fn scan(raw: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    let domain = normalize_domain(raw)?;
    let cands = candidates(&domain);
    let live = live_names(&cands);
    let with_mx = live.iter().filter(|l| !l.mx.is_empty()).count();
    let mut findings = vec![Hit::new(
        "typo",
        if live.is_empty() {
            Status::Absent
        } else {
            Status::Confirmed
        },
        format!(
            "{} permutations checked, {} live lookalike(s){}",
            cands.len(),
            live.len(),
            if with_mx > 0 {
                format!(", {with_mx} with MX")
            } else {
                String::new()
            }
        ),
        Some(json!({"tested": cands.len(), "live": live.len()})),
    )];
    for l in live.iter().take(25) {
        let mut parts = Vec::new();
        if !l.addrs.is_empty() {
            parts.push(format!("A {}", l.addrs.join(", ")));
        }
        if !l.mx.is_empty() {
            parts.push(format!("MX {}", l.mx.join(", ")));
        }
        findings.push(Hit::new(
            "typo-live",
            Status::Confirmed,
            format!("{} resolves ({})", l.name, parts.join("; ")),
            Some(json!({"domain": l.name, "addrs": l.addrs, "mx": l.mx})),
        ));
    }
    Ok(Report {
        target: domain,
        kind: "typo",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permutations_stay_valid_and_bounded() {
        let c = candidates("quad4.io");
        assert!(!c.is_empty());
        assert!(c.len() <= MAX_CANDIDATES);
        assert!(c.iter().all(|d| d != "quad4.io"));
        assert!(
            c.iter()
                .all(|d| d.ends_with(".io")
                    || SWAP_TLDS.iter().any(|t| d.ends_with(&format!(".{t}"))))
        );
        // omission of one char must be present
        assert!(c.contains(&"uad4.io".to_string()));
        // transposition present
        assert!(c.contains(&"uqad4.io".to_string()));
        // tld swap present
        assert!(c.contains(&"quad4.com".to_string()));
    }

    #[test]
    fn single_label_has_no_candidates() {
        assert!(candidates("localhost").is_empty());
    }
}
