// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Script and beacon markers for analytics and advertising tags.
//! Privacy-focused means the product is built to avoid ad cookies.
//! It is not a compliance claim. A miss is not proof the page is clean.

use super::{Hit, Status};
use serde_json::json;

struct Rule {
    product: &'static str,
    class: &'static str,
    saw: fn(&str, &str) -> bool,
}

pub fn detect(headers: &[(String, String)], body: &str) -> Hit {
    let header_blob = headers
        .iter()
        .map(|(n, v)| format!("{}: {}", n.to_ascii_lowercase(), v.to_ascii_lowercase()))
        .collect::<Vec<_>>()
        .join("\n");
    let body_l = body.to_ascii_lowercase();
    let mut hits = Vec::new();
    for rule in RULES {
        if (rule.saw)(&header_blob, &body_l) {
            hits.push(json!({"product": rule.product, "class": rule.class}));
        }
    }
    if hits.is_empty() {
        return Hit::new(
            "trackers",
            Status::Absent,
            "no analytics or advertising marker in this response",
            None,
        );
    }
    let names: Vec<&str> = hits
        .iter()
        .filter_map(|v| v.get("product").and_then(|p| p.as_str()))
        .collect();
    Hit::new(
        "trackers",
        Status::Confirmed,
        names.join(", "),
        Some(json!({"matches": hits})),
    )
}

const RULES: &[Rule] = &[
    Rule {
        product: "Cloudflare",
        class: "edge",
        saw: |h, _| h.contains("cf-ray:") || h.contains("server: cloudflare"),
    },
    Rule {
        product: "Cloudflare Insights",
        class: "analytics",
        saw: |_, b| b.contains("cloudflareinsights.com") || b.contains("data-cf-beacon"),
    },
    Rule {
        product: "Google Analytics",
        class: "analytics",
        saw: |_, b| {
            b.contains("google-analytics.com")
                || b.contains("googletagmanager.com")
                || b.contains("gtag(")
                || b.contains("ga('create")
        },
    },
    Rule {
        product: "Google Ads",
        class: "advertising",
        saw: |_, b| b.contains("doubleclick.net") || b.contains("googleadservices.com"),
    },
    Rule {
        product: "Meta Pixel",
        class: "advertising",
        saw: |_, b| b.contains("connect.facebook.net") || b.contains("fbevents.js"),
    },
    Rule {
        product: "Hotjar",
        class: "analytics",
        saw: |_, b| b.contains("hotjar.com") || b.contains("static.hotjar.com"),
    },
    Rule {
        product: "Microsoft Clarity",
        class: "analytics",
        saw: |_, b| b.contains("clarity.ms"),
    },
    Rule {
        product: "Segment",
        class: "analytics",
        saw: |_, b| b.contains("cdn.segment.com") || b.contains("segment.io"),
    },
    Rule {
        product: "Mixpanel",
        class: "analytics",
        saw: |_, b| b.contains("mixpanel.com"),
    },
    Rule {
        product: "PostHog",
        class: "analytics",
        saw: |_, b| b.contains("posthog.com") || b.contains("posthog.js"),
    },
    Rule {
        product: "Plausible",
        class: "privacy",
        saw: |_, b| b.contains("plausible.io") || b.contains("plausible.js"),
    },
    Rule {
        product: "Umami",
        class: "privacy",
        saw: |_, b| {
            b.contains("umami")
                && (b.contains("data-website-id")
                    || b.contains("umami.js")
                    || b.contains("/umami/"))
        },
    },
    Rule {
        product: "Fathom",
        class: "privacy",
        saw: |_, b| b.contains("usefathom.com") || b.contains("cdn.usefathom.com"),
    },
    Rule {
        product: "GoatCounter",
        class: "privacy",
        saw: |_, b| b.contains("goatcounter.com") || b.contains("goatcounter.js"),
    },
    Rule {
        product: "Simple Analytics",
        class: "privacy",
        saw: |_, b| {
            b.contains("simpleanalytics.com") || b.contains("scripts.simpleanalyticscdn.com")
        },
    },
    Rule {
        product: "Matomo",
        class: "privacy",
        saw: |_, b| {
            b.contains("matomo.js")
                || b.contains("piwik.js")
                || b.contains("_paq.push")
                || b.contains("/matomo/")
        },
    },
    Rule {
        product: "Ackee",
        class: "privacy",
        saw: |_, b| b.contains("ackee.js") || b.contains("/ackee/"),
    },
    Rule {
        product: "Pirsch",
        class: "privacy",
        saw: |_, b| b.contains("pirsch.io") || b.contains("api.pirsch.io"),
    },
    Rule {
        product: "Counter",
        class: "privacy",
        saw: |_, b| b.contains("counter.dev"),
    },
    Rule {
        product: "Vercel Analytics",
        class: "analytics",
        saw: |_, b| b.contains("/_vercel/insights") || b.contains("va.vercel-scripts.com"),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insights_and_privacy_tags_are_named() {
        let cf = detect(
            &[("cf-ray".into(), "abc".into())],
            "<script src=\"https://static.cloudflareinsights.com/beacon.min.js\" data-cf-beacon></script>",
        );
        assert!(cf.summary.contains("Cloudflare Insights"));
        assert!(cf.summary.contains("Cloudflare"));
        let privacy = detect(
            &[],
            "<script src=\"/umami.js\" data-website-id=\"abc\"></script>",
        );
        assert_eq!(privacy.summary, "Umami");
        let plain = detect(&[("server".into(), "nginx".into())], "<html>hello</html>");
        assert_eq!(plain.status, Status::Absent);
    }
}
