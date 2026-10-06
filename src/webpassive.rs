// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Passive checks on one fetched page.
//! Headers and body text only. No attack strings are sent.

use crate::finding::{Finding, Severity};

const REF: &str = "https://owasp.org/Top10/2025/";

pub fn assess(
    headers: &[(String, String)],
    body: &str,
    is_https: bool,
    target: &str,
) -> Vec<Finding> {
    let mut out = Vec::new();
    cors(headers, target, &mut out);
    if is_https {
        mixed_content(body, target, &mut out);
    }
    directory_listing(body, target, &mut out);
    error_banner(body, target, &mut out);
    cache_and_cookie(headers, target, &mut out);
    admin_banner(body, target, &mut out);
    out
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn hit(id: &str, sev: Severity, target: &str, msg: &str, fix: &str) -> Finding {
    Finding {
        ruleset: "web".into(),
        rule_id: id.into(),
        severity: sev,
        target: target.into(),
        path: "/".into(),
        line: None,
        excerpt: None,
        message: msg.into(),
        remediation: Some(fix.into()),
        reference: Some(REF.into()),
        window: None,
        evidence: None,
    }
}

fn cors(headers: &[(String, String)], target: &str, out: &mut Vec<Finding>) {
    let Some(origin) = header(headers, "access-control-allow-origin") else {
        return;
    };
    let origin = origin.trim();
    let creds = header(headers, "access-control-allow-credentials")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
    if origin == "*" && !creds {
        out.push(hit(
            "WEB-022",
            Severity::Low,
            target,
            "CORS allows any origin",
            "Pin the origins that should read this response.",
        ));
    }
    if origin.eq_ignore_ascii_case("null") {
        out.push(hit(
            "WEB-023",
            Severity::Medium,
            target,
            "CORS allows the null origin",
            "Do not reflect Origin: null. Sandboxed frames send that value.",
        ));
    }
    if let Some(allow) = header(headers, "access-control-allow-methods")
        && allow
            .to_ascii_lowercase()
            .split(',')
            .any(|m| m.trim() == "trace")
    {
        out.push(hit(
            "WEB-024",
            Severity::Info,
            target,
            "CORS allow-list includes TRACE",
            "Drop TRACE from Access-Control-Allow-Methods.",
        ));
    }
}

fn mixed_content(body: &str, target: &str, out: &mut Vec<Finding>) {
    let re = regex::Regex::new(
        r#"(?i)<(?:script|img|iframe|link)\b[^>]*\b(?:src|href)\s*=\s*["']http://"#,
    )
    .unwrap();
    if re.is_match(body) {
        out.push(hit(
            "WEB-028",
            Severity::Medium,
            target,
            "https page loads a script, image, frame, or stylesheet over http",
            "Use https URLs for those tags.",
        ));
    }
}

fn directory_listing(body: &str, target: &str, out: &mut Vec<Finding>) {
    let head = &body[..body.len().min(4096)];
    if head.to_ascii_lowercase().contains("index of /") {
        out.push(hit(
            "WEB-026",
            Severity::Low,
            target,
            "directory listing is enabled",
            "Turn indexes off in the web server.",
        ));
    }
}

fn error_banner(body: &str, target: &str, out: &mut Vec<Finding>) {
    let re = regex::Regex::new(
        r"(?i)(traceback \(most recent call last\)|you have an error in your sql syntax|SQLException|Microsoft OLE DB Provider|Fatal error:\s+Uncaught|pg_query\(\):)",
    )
    .unwrap();
    if re.is_match(body) {
        out.push(hit(
            "WEB-027",
            Severity::Medium,
            target,
            "response body includes a stack trace or a database error",
            "Return a generic error page. Log the detail on the server.",
        ));
    }
}

fn cache_and_cookie(headers: &[(String, String)], target: &str, out: &mut Vec<Finding>) {
    let cookie = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("set-cookie"));
    if !cookie {
        return;
    }
    let cache = header(headers, "cache-control").unwrap_or("");
    let low = cache.to_ascii_lowercase();
    if !low.contains("no-store") && !low.contains("private") {
        out.push(hit(
            "WEB-029",
            Severity::Low,
            target,
            "a Set-Cookie response is cacheable",
            "Send Cache-Control: no-store on responses that set a session cookie.",
        ));
    }
    for (_, v) in headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
    {
        let low = v.to_ascii_lowercase();
        let none = low
            .split(';')
            .any(|p| p.trim().starts_with("samesite=none"));
        let secure = low.split(';').any(|p| p.trim() == "secure");
        if none && !secure {
            out.push(hit(
                "WEB-044",
                Severity::Medium,
                target,
                "cookie sets SameSite=None without Secure",
                "SameSite=None requires the Secure flag.",
            ));
            break;
        }
    }
}

fn admin_banner(body: &str, target: &str, out: &mut Vec<Finding>) {
    let head = &body[..body.len().min(8192)].to_ascii_lowercase();
    if head.contains("<title>")
        && (head.contains("phpmyadmin") || head.contains("phpinfo()") || head.contains("__schema"))
    {
        out.push(hit(
            "WEB-062",
            Severity::Info,
            target,
            "page exposes an admin tool, phpinfo, or a GraphQL schema",
            "Keep admin and debug pages off the public host.",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passive_page_flags_cors_listing_and_errors() {
        let headers = vec![
            ("Access-Control-Allow-Origin".into(), "null".into()),
            ("Access-Control-Allow-Methods".into(), "GET, TRACE".into()),
            ("Set-Cookie".into(), "sid=1; SameSite=None".into()),
        ];
        let body = "<title>Index of /</title><script src=\"http://cdn.example/a.js\"></script>You have an error in your SQL syntax";
        let hits = assess(&headers, body, true, "example.com");
        let ids: Vec<_> = hits.iter().map(|h| h.rule_id.as_str()).collect();
        for id in [
            "WEB-023", "WEB-024", "WEB-026", "WEB-027", "WEB-028", "WEB-029", "WEB-044",
        ] {
            assert!(ids.contains(&id), "missing {id} in {ids:?}");
        }
    }
}
