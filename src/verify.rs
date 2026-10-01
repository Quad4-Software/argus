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
    format!("{}...{}", &t[..6], &t[t.len() - 3..])
}

fn check(p: &Provider, token: &str) -> Verdict {
    let url = p.url.replace("{}", token);
    let cfg = ureq::config::Config::builder()
        .timeout_global(Some(std::time::Duration::from_secs(10)))
        .http_status_as_error(false)
        .build();
    let agent = ureq::Agent::new_with_config(cfg);
    let mut req = agent.get(&url);
    if p.basic {
        req = req.header(
            "Authorization",
            format!("Basic {}", b64(&format!("{token}:"))),
        );
    } else if p.header == "Authorization" {
        req = req.header("Authorization", format!("Bearer {token}"));
    } else if !p.header.is_empty() {
        req = req.header(p.header, token);
    }
    req = req.header("User-Agent", concat!("argus/", env!("CARGO_PKG_VERSION")));
    let resp = match req.call() {
        Ok(r) => r,
        Err(_) => return Verdict::Unknown,
    };
    let status = resp.status().as_u16();
    let mut resp = resp;
    let body = resp
        .body_mut()
        .with_config()
        .limit(64 * 1024)
        .read_to_string()
        .unwrap_or_default();
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

/// Scan roots for provider-token-shaped strings and verify each unique
/// candidate (capped). Returns findings and a note for the report.
pub fn verify(roots: &[PathBuf], verbose: bool) -> (Vec<Finding>, usize) {
    let mut found: Vec<(Provider, String, PathBuf)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for root in roots {
        for file in crate::scan::collect_files(root, false) {
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            if text.len() > 8 * 1024 * 1024 {
                continue;
            }
            for p in PROVIDERS {
                let re = regex::Regex::new(p.re).unwrap();
                for m in re.find_iter(&text) {
                    let tok = m.as_str().to_string();
                    if seen.insert(tok.clone()) {
                        found.push((
                            Provider {
                                name: p.name,
                                re: p.re,
                                url: p.url,
                                header: p.header,
                                basic: p.basic,
                                extra: p.extra,
                                ok_field: p.ok_field,
                            },
                            tok,
                            file.clone(),
                        ));
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    let cap = 25usize;
    for (p, tok, path) in found.iter().take(cap) {
        if verbose {
            eprintln!("verify: {} {} in {}", p.name, mask(tok), path.display());
        }
        match check(p, tok) {
            Verdict::Live(ident) => out.push(Finding {
                ruleset: "verify".into(),
                rule_id: "VER-001".into(),
                severity: Severity::Critical,
                target: path.display().to_string(),
                path: path.display().to_string(),
                line: None,
                excerpt: Some(mask(tok)),
                message: format!("LIVE {} credential{}: provider confirms it still works", p.name, ident),
                remediation: Some("Revoke NOW - it is valid and usable. Check provider audit logs for abuse, then rotate.".into()),
                reference: None,
                window: None,
            }),
            Verdict::Dead => out.push(Finding {
                ruleset: "verify".into(),
                rule_id: "VER-002".into(),
                severity: Severity::Info,
                target: path.display().to_string(),
                path: path.display().to_string(),
                line: None,
                excerpt: Some(mask(tok)),
                message: format!("{} credential {} is rejected by the provider (revoked/expired)", p.name, mask(tok)),
                remediation: Some("Dead but still committed - remove it and scrub history anyway.".into()),
                reference: None,
                window: None,
            }),
            Verdict::Unknown => {}
        }
    }
    (out, found.len())
}
