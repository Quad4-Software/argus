// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Secrets liveness verification: extract credential-shaped strings from
//! a tree and ask each provider whether the token still works.
//! A confirmed-live secret is a critical finding; a rejected token is
//! an info-level cleanup item. Tokens never leave memory and are masked
//! in output. Network errors report as "unverifiable", not "dead".

use crate::finding::{Finding, Severity};
use std::collections::HashSet;
use std::path::PathBuf;

struct Provider {
    name: &'static str,
    re: &'static str,
    /// (method, url-with-{}-placeholder, header-name)
    url: &'static str,
    header: &'static str,
    /// For providers where auth is a Basic user (key as username).
    basic: bool,
    /// Body field that must match for "live" (slack style "ok":true).
    ok_field: Option<&'static str>,
    /// Extra headers the API requires alongside auth (e.g. anthropic-version).
    extra: &'static [(&'static str, &'static str)],
}

const PROVIDERS: &[Provider] = &[
    Provider {
        name: "GitHub",
        re: r"github_pat_[A-Za-z0-9_]{40,}|gh[opsur]_[A-Za-z0-9]{30,}",
        url: "https://api.github.com/user",
        header: "Authorization",
        basic: false,
        ok_field: None,
        extra: &[],
    },
    Provider {
        name: "GitLab",
        re: r"glpat-[A-Za-z0-9_-]{20,}",
        url: "https://gitlab.com/api/v4/user",
        header: "PRIVATE-TOKEN",
        basic: false,
        ok_field: None,
        extra: &[],
    },
    Provider {
        name: "Telegram",
        re: r"\b[0-9]{6,10}:[A-Za-z0-9_-]{33,}",
        url: "https://api.telegram.org/bot{}/getMe",
        header: "",
        basic: false,
        ok_field: None,
        extra: &[],
    },
    Provider {
        name: "npm",
        re: r"npm_[A-Za-z0-9]{30,}",
        url: "https://registry.npmjs.org/-/whoami",
        header: "Authorization",
        basic: false,
        ok_field: None,
        extra: &[],
    },
    Provider {
        name: "Slack",
        re: r"xox[baprs]-[A-Za-z0-9-]{10,}",
        url: "https://slack.com/api/auth.test",
        header: "Authorization",
        basic: false,
        ok_field: Some("ok"),
        extra: &[],
    },
    Provider {
        name: "HuggingFace",
        re: r"hf_[A-Za-z0-9]{30,}",
        url: "https://huggingface.co/api/whoami-v2",
        header: "Authorization",
        basic: false,
        ok_field: None,
        extra: &[],
    },
    Provider {
        name: "Stripe",
        re: r"[sr]k_live_[A-Za-z0-9]{16,}",
        url: "https://api.stripe.com/v1/customers?limit=1",
        header: "Authorization",
        basic: true,
        ok_field: None,
        extra: &[],
    },
    Provider {
        name: "SendGrid",
        re: r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
        url: "https://api.sendgrid.com/v3/user/profile",
        header: "Authorization",
        basic: false,
        ok_field: None,
        extra: &[],
    },
    Provider {
        name: "OpenAI",
        re: r"sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{40,}",
        url: "https://api.openai.com/v1/models",
        header: "Authorization",
        basic: false,
        ok_field: None,
        extra: &[],
    },
    Provider {
        name: "Anthropic",
        re: r"sk-ant-[A-Za-z0-9_-]{30,}",
        url: "https://api.anthropic.com/v1/models",
        header: "x-api-key",
        basic: false,
        ok_field: None,
        extra: &[("anthropic-version", "2023-06-01")],
    },
    Provider {
        name: "Cloudflare",
        re: r"[A-Za-z0-9_-]{40}",
        url: "https://api.cloudflare.com/client/v4/user/tokens/verify",
        header: "Authorization",
        basic: false,
        ok_field: Some("success"),
        extra: &[],
    },
    Provider {
        name: "DigitalOcean",
        re: r"dop_v1_[A-Za-z0-9]{60,}",
        url: "https://api.digitalocean.com/v2/user",
        header: "Authorization",
        basic: false,
        ok_field: None,
        extra: &[],
    },
    Provider {
        name: "PyPI",
        re: r"pypi-[A-Za-z0-9_-]{30,}",
        url: "https://pypi.org/pypi/legacy/",
        header: "Authorization",
        basic: false,
        ok_field: None,
        extra: &[],
    },
    Provider {
        name: "crates.io",
        re: r"cio[A-Za-z0-9]{20,}",
        url: "https://crates.io/api/v1/me",
        header: "Authorization",
        basic: false,
        ok_field: None,
        extra: &[],
    },
    Provider {
        name: "OpenAI",
        re: r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}",
        url: "https://api.openai.com/v1/models",
        header: "Authorization",
        basic: false,
        ok_field: None,
        extra: &[],
    },
];

#[derive(Debug)]
enum Verdict {
    Live(String), // provider-confirmed identity (e.g. login) for the message
    Dead,
    Unknown,
}

fn mask(t: &str) -> String {
    if t.len() <= 10 {
        return "***".into();
    }
    let head: String = t.chars().take(6).collect();
    let tail: String = t
        .chars()
        .rev()
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}...{tail}")
}

/// Shared client for every provider check: one agent, one timeout/user-
/// agent policy, connection reuse. Never construct one per file/token.
fn http() -> &'static crate::http::HttpClient {
    static HTTP: std::sync::OnceLock<crate::http::HttpClient> = std::sync::OnceLock::new();
    HTTP.get_or_init(|| crate::http::HttpClient::new(vec![]))
}

/// Per-token verdict memoization across files: the same leaked token often
/// appears in dozens of files and provider APIs are rate-limited.
fn check(http: &crate::http::HttpClient, p: &Provider, token: &str) -> Verdict {
    static MEMO: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, Option<String>>>,
    > = std::sync::OnceLock::new();
    let memo = MEMO.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    // Live and Dead verdicts are stable enough to reuse; Some(ident) marks
    // a live token, None a dead one. Unknown is retried, never cached.
    if let Some(cached) = memo.lock().unwrap().get(token) {
        return match cached {
            Some(ident) => Verdict::Live(ident.clone()),
            None => Verdict::Dead,
        };
    }
    let v = check_uncached(http, p, token);
    match &v {
        Verdict::Live(ident) => memo
            .lock()
            .unwrap()
            .insert(token.to_string(), Some(ident.clone())),
        Verdict::Dead => memo.lock().unwrap().insert(token.to_string(), None),
        Verdict::Unknown => None,
    };
    v
}

fn check_uncached(http: &crate::http::HttpClient, p: &Provider, token: &str) -> Verdict {
    let url = p.url.replace("{}", token);
    let mut extra: Vec<(String, String)> = p
        .extra
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    if p.basic {
        extra.push((
            "Authorization".into(),
            format!("Basic {}", b64(&format!("{token}:"))),
        ));
    } else if p.header == "Authorization" {
        extra.push(("Authorization".into(), format!("Bearer {token}")));
    } else if !p.header.is_empty() {
        extra.push((p.header.into(), token.into()));
    }
    let (status, body) = match http.get_raw(&url, &extra) {
        Ok(v) => v,
        Err(_) => return Verdict::Unknown,
    };
    let body = body.text;
    match (status, p.ok_field) {
        (200, _) => {
            let ident = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| {
                    v["login"]
                        .as_str()
                        .map(str::to_string)
                        .or_else(|| v["username"].as_str().map(str::to_string))
                        .or_else(|| v["name"].as_str().map(str::to_string))
                        .or_else(|| v["user"].as_str().map(str::to_string))
                        .or_else(|| v["result"]["username"].as_str().map(str::to_string))
                })
                .map(|s| format!(" as {s}"))
                .unwrap_or_default();
            if let Some(f) = p.ok_field {
                let ok = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v[f].as_bool())
                    .unwrap_or(false);
                return if ok {
                    Verdict::Live(ident)
                } else {
                    Verdict::Dead
                };
            }
            Verdict::Live(ident)
        }
        (401 | 403, _) => Verdict::Dead,
        (429, _) => Verdict::Unknown,
        _ => Verdict::Unknown,
    }
}

fn b64(s: &str) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in s.as_bytes().chunks(3) {
        let n = c.iter().fold(0u32, |a, &b| (a << 8) | b as u32) << ((3 - c.len()) * 8);
        for i in 0..4 {
            if i <= c.len() {
                o.push(T[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                o.push('=');
            }
        }
    }
    o
}

/// One provider-shaped token extracted from file text.
pub(crate) struct Candidate {
    /// Index into PROVIDERS.
    pub provider: usize,
    /// Raw token - held in memory only, masked in any emitted output.
    pub token: String,
    /// 1-based line where the match starts.
    pub line: usize,
}

/// Provider regexes compiled once; scans call candidates() per file.
fn provider_res() -> &'static [regex::Regex] {
    static RES: std::sync::OnceLock<Vec<regex::Regex>> = std::sync::OnceLock::new();
    RES.get_or_init(|| {
        PROVIDERS
            .iter()
            .map(|p| regex::Regex::new(p.re).unwrap())
            .collect()
    })
}

fn line_of(text: &str, byte_off: usize) -> usize {
    text[..byte_off].bytes().filter(|&b| b == b'\n').count() + 1
}

/// Extract provider-token candidates from file text, deduped by token
/// value (first matching provider wins). Every candidate already matches
/// one provider's published token shape - nothing arbitrary is collected,
/// so a token only ever goes to its own provider's API (trufflehog-style).
pub(crate) fn candidates(text: &str) -> Vec<Candidate> {
    let res = provider_res();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut out = Vec::new();
    for (pi, re) in res.iter().enumerate() {
        for m in re.find_iter(text) {
            if seen.insert(m.as_str()) {
                out.push(Candidate {
                    provider: pi,
                    token: m.as_str().to_string(),
                    line: line_of(text, m.start()),
                });
            }
        }
    }
    out
}

fn verdict_finding(
    p: &Provider,
    tok: &str,
    verdict: Verdict,
    target: &str,
    path: &str,
    line: Option<usize>,
) -> Option<Finding> {
    match verdict {
        Verdict::Live(ident) => Some(Finding {
            ruleset: "verify".into(),
            rule_id: "VER-001".into(),
            severity: Severity::Critical,
            target: target.into(),
            path: path.into(),
            line,
            excerpt: Some(mask(tok)),
            message: format!("LIVE {} credential{}: provider confirms it still works", p.name, ident),
            remediation: Some("Revoke NOW - it is valid and usable. Check provider audit logs for abuse, then rotate.".into()),
            reference: None,
            window: None,
            evidence: Some(vec![format!("verified live via {}", p.name)]),
        }),
        Verdict::Dead => Some(Finding {
            ruleset: "verify".into(),
            rule_id: "VER-002".into(),
            severity: Severity::Info,
            target: target.into(),
            path: path.into(),
            line,
            excerpt: Some(mask(tok)),
            message: format!("{} credential {} is rejected by the provider (revoked/expired)", p.name, mask(tok)),
            remediation: Some("Dead but still committed - remove it and scrub history anyway.".into()),
            reference: None,
            window: None,
            evidence: Some(vec![format!("token rejected by {} issuer API", p.name)]),
}),
        Verdict::Unknown => None,
    }
}

/// Scan-side verification (--verify-secrets): extract candidates from
/// already-loaded file text and live-check up to `cap` unique tokens.
/// Findings carry the scan-relative path and the token's line.
pub(crate) fn verify_file_text(text: &str, rel: &str, target: &str, cap: usize) -> Vec<Finding> {
    let mut out = Vec::new();
    for c in candidates(text).into_iter().take(cap) {
        let p = &PROVIDERS[c.provider];
        out.extend(verdict_finding(
            p,
            &c.token,
            check(http(), p, &c.token),
            target,
            rel,
            Some(c.line),
        ));
    }
    out
}

/// Scan roots for provider-token-shaped strings and verify each unique
/// candidate (capped). Returns findings and a note for the report.
pub fn verify(roots: &[PathBuf], verbose: bool) -> (Vec<Finding>, usize) {
    let mut found: Vec<(usize, String, PathBuf, usize)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for root in roots {
        for file in crate::scan::collect_files(root, false, true) {
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            if text.len() > 8 * 1024 * 1024 {
                continue;
            }
            for c in candidates(&text) {
                if seen.insert(c.token.clone()) {
                    found.push((c.provider, c.token, file.clone(), c.line));
                }
            }
        }
    }
    let mut out = Vec::new();
    let cap = 25usize;
    for (pi, tok, path, line) in found.iter().take(cap) {
        let p = &PROVIDERS[*pi];
        if verbose {
            eprintln!("verify: {} {} in {}", p.name, mask(tok), path.display());
        }
        let shown = path.display().to_string();
        out.extend(verdict_finding(
            p,
            tok,
            check(http(), p, tok),
            &shown,
            &shown,
            Some(*line),
        ));
    }
    (out, found.len())
}
