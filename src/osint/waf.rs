// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Markers for WAFs, bot challenges, and captchas in one HTTP response.
//! A miss means this response had no marker. It does not prove the site is unprotected.

use super::{Hit, Status};
use serde_json::json;

struct Rule {
    product: &'static str,
    signal: &'static str,
    saw: fn(&Hay) -> bool,
}

struct Hay<'a> {
    headers: &'a str,
    server: &'a str,
    cookies: &'a str,
    body: &'a str,
}

pub fn detect(headers: &[(String, String)], body: &str) -> Hit {
    let headers_l = headers
        .iter()
        .map(|(n, v)| format!("{}: {}", n.to_ascii_lowercase(), v.to_ascii_lowercase()))
        .collect::<Vec<_>>()
        .join("\n");
    let server = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("server"))
        .map(|(_, v)| v.to_ascii_lowercase())
        .unwrap_or_default();
    let cookies = headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("\n");
    let body_l = body.to_ascii_lowercase();
    let hay = Hay {
        headers: &headers_l,
        server: &server,
        cookies: &cookies,
        body: &body_l,
    };
    let mut hits = Vec::new();
    for rule in RULES {
        if (rule.saw)(&hay) {
            hits.push(json!({"product": rule.product, "signal": rule.signal}));
        }
    }
    if hits.is_empty() {
        return Hit::new(
            "waf",
            Status::Absent,
            "no WAF, challenge, or captcha marker in this response",
            None,
        );
    }
    let names: Vec<&str> = hits
        .iter()
        .filter_map(|v| v.get("product").and_then(|p| p.as_str()))
        .collect();
    Hit::new(
        "waf",
        Status::Confirmed,
        names.join(", "),
        Some(json!({"matches": hits})),
    )
}

const RULES: &[Rule] = &[
    Rule {
        product: "Cloudflare",
        signal: "cf-ray",
        saw: |h| h.headers.contains("cf-ray:") || h.server.contains("cloudflare"),
    },
    Rule {
        product: "Amazon CloudFront",
        signal: "x-amz-cf-id",
        saw: |h| h.headers.contains("x-amz-cf-id:"),
    },
    Rule {
        product: "AWS WAF",
        signal: "awselb",
        saw: |h| {
            h.headers.contains("x-amzn-waf-")
                || h.server.contains("awselb")
                || h.cookies.contains("awsalb")
        },
    },
    Rule {
        product: "Akamai",
        signal: "akamai",
        saw: |h| {
            h.server.contains("akamaighost")
                || h.headers.contains("x-akamai-transformed:")
                || h.headers.contains("akamai-grn:")
        },
    },
    Rule {
        product: "Imperva",
        signal: "incap",
        saw: |h| {
            h.cookies.contains("visid_incap_")
                || h.cookies.contains("incap_ses_")
                || h.headers.contains("x-iinfo:")
        },
    },
    Rule {
        product: "Sucuri",
        signal: "x-sucuri-id",
        saw: |h| h.headers.contains("x-sucuri-id:") || h.server.contains("sucuri"),
    },
    Rule {
        product: "F5 BIG-IP",
        signal: "bigip",
        saw: |h| h.cookies.contains("bigipserver") || h.server.contains("bigip"),
    },
    Rule {
        product: "Barracuda",
        signal: "barracuda",
        saw: |h| h.cookies.contains("barra_counter_session") || h.server.contains("barracuda"),
    },
    Rule {
        product: "FortiWeb",
        signal: "fortiweb",
        saw: |h| h.cookies.contains("fortiwafsid") || h.server.contains("fortiweb"),
    },
    Rule {
        product: "Fastly",
        signal: "fastly",
        saw: |h| {
            h.headers.contains("x-fastly-request-id:") || h.headers.contains("fastly-restarts:")
        },
    },
    Rule {
        product: "Azure Front Door",
        signal: "x-azure-ref",
        saw: |h| h.headers.contains("x-azure-ref:"),
    },
    Rule {
        product: "Vercel",
        signal: "vercel",
        saw: |h| h.server.contains("vercel") || h.headers.contains("x-vercel-id:"),
    },
    Rule {
        product: "SafeLine",
        signal: "sl-session",
        saw: |h| h.server.contains("safeline") || h.cookies.contains("sl-session="),
    },
    Rule {
        product: "BunkerWeb",
        signal: "bunkerweb challenge",
        saw: |h| {
            h.server.contains("bunkerweb")
                || (h.body.contains("--color-bw:")
                    && (h
                        .body
                        .contains("please wait while we check if you are a human")
                        || h.body
                            .contains("please prove that you are human before accessing")))
        },
    },
    Rule {
        product: "Anubis",
        signal: "anubis challenge",
        saw: |h| {
            h.cookies.contains("techaro.lol-anubis")
                || h.cookies.contains("within.website-x-cmd-anubis")
                || h.headers.contains("x-anubis-action:")
                || h.headers.contains("x-anubis-rule:")
                || h.body.contains("/.within.website/x/cmd/anubis/")
        },
    },
    Rule {
        product: "Altcha",
        signal: "altcha-widget",
        saw: |h| {
            h.body.contains("<altcha-widget")
                || h.body.contains("altcha.js")
                || h.body.contains("altcha.mjs")
        },
    },
    Rule {
        product: "Cap",
        signal: "cap-widget",
        saw: |h| h.body.contains("<cap-widget") || h.body.contains("cap-widget"),
    },
    Rule {
        product: "hCaptcha",
        signal: "hcaptcha",
        saw: |h| h.body.contains("hcaptcha.com") || h.body.contains("h-captcha"),
    },
    Rule {
        product: "reCAPTCHA",
        signal: "recaptcha",
        saw: |h| h.body.contains("google.com/recaptcha") || h.body.contains("g-recaptcha"),
    },
    Rule {
        product: "Turnstile",
        signal: "cf-turnstile",
        saw: |h| {
            h.body.contains("cf-turnstile")
                || h.body.contains("challenges.cloudflare.com/turnstile")
        },
    },
    Rule {
        product: "proof-of-work",
        signal: "proof-of-work",
        saw: |h| {
            let pow = h.body.contains("proof-of-work") || h.body.contains("proof of work");
            let hash = h.body.contains("sha-256") || h.body.contains("sha256");
            pow && hash
                && !h.body.contains("/.within.website/x/cmd/anubis/")
                && !h.body.contains("<altcha-widget")
                && !h.body.contains("<cap-widget")
        },
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_match_the_product_and_a_plain_page_does_not() {
        let cf = detect(&[("CF-RAY".into(), "abc".into())], "");
        assert_eq!(cf.summary, "Cloudflare");
        let anubis = detect(
            &[("set-cookie".into(), "techaro.lol-anubis-auth=1".into())],
            "",
        );
        assert_eq!(anubis.summary, "Anubis");
        let widgets = detect(
            &[],
            "<altcha-widget></altcha-widget><cap-widget></cap-widget>",
        );
        assert!(widgets.summary.contains("Altcha"));
        assert!(widgets.summary.contains("Cap"));
        let safe = detect(&[("server".into(), "SafeLine".into())], "");
        assert_eq!(safe.summary, "SafeLine");
        let bunker = detect(
            &[],
            "<title>Bot Detection</title><style>:root { --color-bw: #0b5577; } Please wait while we check if you are a Human",
        );
        assert_eq!(bunker.summary, "BunkerWeb");
        let safe_cookie = detect(&[("set-cookie".into(), "sl-session=abc".into())], "");
        assert_eq!(safe_cookie.summary, "SafeLine");
        let pow = detect(&[], "Solve this proof-of-work using SHA-256");
        assert_eq!(pow.summary, "proof-of-work");
        let plain = detect(&[("server".into(), "nginx".into())], "<html>quad4</html>");
        assert_eq!(plain.status, super::super::Status::Absent);
    }
}
