// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Web target scanning: fetch a URL and audit what a browser sees.
//! Security headers, cookies, TLS expiry, exposed metadata (.git, .env,
//! robots/security.txt), and client-side secrets inside inline JS,
//! referenced bundles, and their source maps. Fetched assets go through
//! the same rules engine as local files.

use crate::finding::{Finding, Severity};
use crate::rules::CompiledRule;
use crate::scan::{ScanOptions, scan_file};
use std::collections::HashSet;
use ureq::ResponseExt;

const OWASP_HEADERS: &str = "https://owasp.org/www-project-secure-headers/";

struct Resp {
    status: u16,
    final_url: String,
    headers: Vec<(String, String)>,
    body: String,
}

fn get(url: &str) -> Result<Resp, String> {
    let resp = ureq::get(url)
        .header("User-Agent", concat!("argus/", env!("CARGO_PKG_VERSION")))
        .config()
        .timeout_global(Some(std::time::Duration::from_secs(20)))
        .http_status_as_error(false)
        .build()
        .call()
        .map_err(|e| format!("GET {url}: {e} (network unreachable or offline?)"))?;
    let status = resp.status().as_u16();
    let final_url = resp.get_uri().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let mut resp = resp;
    let body = resp
        .body_mut()
        .with_config()
        .limit(8 * 1024 * 1024)
        .read_to_string()
        .map_err(|e| format!("read {url}: {e}"))?;
    Ok(Resp {
        status,
        final_url,
        headers,
        body,
    })
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn mk(
    id: &str,
    sev: Severity,
    target: &str,
    path: &str,
    msg: impl Into<String>,
    fix: &str,
) -> Finding {
    Finding {
        ruleset: "web".into(),
        rule_id: id.into(),
        severity: sev,
        target: target.into(),
        path: path.into(),
        line: None,
        excerpt: None,
        message: msg.into(),
        remediation: Some(fix.into()),
        reference: Some(OWASP_HEADERS.into()),
        window: None,
    }
}

fn base_of(url: &str) -> String {
    format!(
        "{}://{}",
        url.split("://").next().unwrap_or("https"),
        host_of(url)
    )
}

fn host_of(url: &str) -> &str {
    url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
        .split(':')
        .next()
        .unwrap_or(url)
}

fn join(base: &str, link: &str) -> Option<String> {
    if link.starts_with("http://") || link.starts_with("https://") {
        Some(link.to_string())
    } else if link.starts_with("//") {
        let scheme = base.split("://").next().unwrap_or("https");
        Some(format!("{scheme}:{link}"))
    } else if link.starts_with('/') {
        let scheme = base.split("://").next().unwrap_or("https");
        Some(format!("{scheme}://{}{link}", host_of(base)))
    } else {
        let dir = base.rsplit('/').skip(1).collect::<Vec<_>>();
        let mut d = dir.into_iter().rev().collect::<Vec<_>>().join("/");
        if !d.is_empty() {
            d.push('/');
        }
        Some(format!("{d}{link}"))
    }
}

/// Known-public or restriction-protected token shapes in client JS.
/// Some are public by design (info), some are expected-but-risky
/// (medium: fine if restricted, abusable if not).
fn public_key_kind(s: &str) -> Option<(&'static str, Severity)> {
    let l = s.to_lowercase();
    if l.contains("pk_live") || l.contains("pk_test") {
        Some(("Stripe publishable key (public by design)", Severity::Info))
    } else if l.contains("algolia") {
        Some((
            "Algolia key - verify it is the public Search-Only key",
            Severity::Low,
        ))
    } else if l.contains("sentry") && l.contains("dsn") {
        Some(("Sentry DSN (public by design)", Severity::Info))
    } else if (l.contains("firebase") && l.contains("apikey"))
        || l.contains("gsheets")
        || l.contains("maps")
        || s.starts_with("AIza")
    {
        Some((
            "Google/Firebase API key in client JS (expected - verify API restrictions in the console)",
            Severity::Medium,
        ))
    } else {
        None
    }
}

/// Web-context secret patterns the generic engine does not know:
/// env-style JS assignments of key/secret/token variables to literals.
fn web_secrets(rel: &str, text: &str, target: &str, out: &mut Vec<Finding>) {
    let assign_re = regex::Regex::new(
        r#"(?i)([a-z0-9_]*?(api[_-]?key|apikey|secret|token|password|passwd|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|signing[_-]?key))["']?\s*[:=]\s*["']([A-Za-z0-9+/_=\-.]{16,})["']"#,
    )
    .unwrap();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for c in assign_re.captures_iter(text) {
        let (var, val) = (c.get(1).unwrap().as_str(), c.get(3).unwrap().as_str());
        if !seen.insert((var.to_string(), val.to_string())) {
            continue;
        }
        if let Some((kind, sev)) = public_key_kind(&format!("{var}={val}")) {
            out.push(mk(
                "WEB-051",
                sev,
                target,
                rel,
                format!("{var}: {kind}"),
                "Restrict the key in the provider console if it is meant to be private.",
            ));
            continue;
        }
        // skip placeholders and public-analytics ids
        let lv = val.to_lowercase();
        if lv.contains("xxxx")
            || lv.contains("your")
            || lv.contains("example")
            || lv.contains("placeholder")
        {
            continue;
        }
        out.push(mk(
            "WEB-050",
            Severity::High,
            target,
            rel,
            format!("{var} assigned a literal secret in client-side code"),
            "Move secrets server-side; client JS is public. Rotate anything already shipped.",
        ));
    }
}

/// Same-origin page links for depth-limited crawling.
fn page_links(html: &str, host: &str) -> Vec<String> {
    let re = regex::Regex::new(r#"(?i)<a[^>]+href=["']([^"'#]+)["']"#).unwrap();
    let mut out = Vec::new();
    for c in re.captures_iter(html) {
        let h = c[1].trim();
        if h.starts_with("javascript") || h.starts_with("mailto:") || h.starts_with("tel:") {
            continue;
        }
        out.push(h.to_string());
    }
    let _ = host;
    out
}

/// <form action="http://..."> submits credentials over plaintext.
fn form_checks(html: &str, target: &str, page: &str, out: &mut Vec<Finding>) {
    let re = regex::Regex::new(r#"(?i)<form[^>]+action=["'](http://[^"']+)["']"#).unwrap();
    for c in re.captures_iter(html) {
        out.push(mk(
            "WEB-025",
            Severity::High,
            target,
            page,
            format!("form posts to plaintext http endpoint {}", &c[1]),
            "Use a same-origin or https action; mixed-content posts leak credentials.",
        ));
    }
}

/// Collect candidate JS asset URLs from HTML.
fn asset_urls(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let src_re = regex::Regex::new(r#"(?i)<script[^>]+src=["']([^"']+\.js[^"']*)["']"#).unwrap();
    for c in src_re.captures_iter(html) {
        out.push(c[1].to_string());
    }
    let link_re = regex::Regex::new(
        r#"(?i)<link[^>]+(?:as=["']script["'][^>]*href|href)=["']([^"']+\.js[^"']*)["']"#,
    )
    .unwrap();
    for c in link_re.captures_iter(html) {
        out.push(c[1].to_string());
    }
    out
}

/// Inline <script> bodies (no src) joined into one pseudo-file.
fn inline_scripts(html: &str) -> String {
    let re = regex::Regex::new(r"(?is)<script([^>]*)>(.*?)</script>").unwrap();
    re.captures_iter(html)
        .filter(|c| !c[1].to_lowercase().contains("src"))
        .map(|c| c[2].to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct WebScan {
    pub findings: Vec<Finding>,
    pub assets_scanned: usize,
    pub final_url: String,
}

pub fn scan(
    url: &str,
    depth: usize,
    rules: &[CompiledRule],
    opts: &ScanOptions,
    verbose: bool,
) -> Result<WebScan, String> {
    let url = if url.contains("://") {
        url.to_string()
    } else {
        format!("https://{url}")
    };
    let target = host_of(&url).to_string();
    let mut out = Vec::new();
    let mut assets = 0usize;

    let r = get(&url)?;
    if r.status >= 400 {
        return Err(format!("{url}: HTTP {}", r.status));
    }
    let is_https = r.final_url.starts_with("https://");

    // ---- redirect hygiene ----
    if url.starts_with("http://") && is_https {
        // fine: upgrade happened
    } else if url.starts_with("https://") && r.final_url.starts_with("http://") {
        out.push(mk(
            "WEB-001",
            Severity::High,
            &target,
            "/",
            "https URL redirected to plaintext http",
            "Remove the downgrade redirect; issue HSTS once https is canonical.",
        ));
    }

    // ---- security headers ----
    let checks: [(&str, &str, Severity); 5] = [
        ("content-security-policy", "WEB-010", Severity::Medium),
        ("x-content-type-options", "WEB-011", Severity::Low),
        ("x-frame-options", "WEB-012", Severity::Low),
        ("referrer-policy", "WEB-013", Severity::Low),
        ("permissions-policy", "WEB-014", Severity::Low),
    ];
    for (h, id, sev) in checks {
        if header(&r.headers, h).is_none() {
            let msg = match h {
                "content-security-policy" => {
                    "missing Content-Security-Policy (XSS/data-injection surface is open)"
                }
                "x-content-type-options" => "missing X-Content-Type-Options: nosniff",
                "x-frame-options" => {
                    "missing X-Frame-Options/frame-ancestors (clickjacking surface)"
                }
                "referrer-policy" => "missing Referrer-Policy (URLs may leak via Referer)",
                _ => "missing Permissions-Policy",
            };
            out.push(mk(
                id,
                sev,
                &target,
                "/",
                msg,
                "Set the header at the edge/app layer.",
            ));
        }
    }
    if is_https {
        match header(&r.headers, "strict-transport-security") {
            None => out.push(mk(
                "WEB-015",
                Severity::Medium,
                &target,
                "/",
                "no HSTS on https response (ssl-strip downgrade possible on first visit)",
                "Add Strict-Transport-Security once https is stable everywhere.",
            )),
            Some(v) if !hsts_active(v) => out.push(mk(
                "WEB-015",
                Severity::Medium,
                &target,
                "/",
                "HSTS is present with max-age 0, so it does not stick",
                "Set a max-age of months, not zero.",
            )),
            Some(_) => {}
        }
    }
    if let Some(csp) = header(&r.headers, "content-security-policy") {
        let low = csp.to_ascii_lowercase();
        if low.contains("'unsafe-inline'") || low.contains("'unsafe-eval'") {
            out.push(mk(
                "WEB-019",
                Severity::Medium,
                &target,
                "/",
                "Content-Security-Policy allows unsafe-inline or unsafe-eval",
                "Drop those sources once inline scripts and eval are gone.",
            ));
        }
    }
    let mut cross = Vec::new();
    if header(&r.headers, "cross-origin-opener-policy").is_none() {
        cross.push("Cross-Origin-Opener-Policy");
    }
    if header(&r.headers, "cross-origin-resource-policy").is_none() {
        cross.push("Cross-Origin-Resource-Policy");
    }
    if !cross.is_empty() {
        out.push(mk(
            "WEB-021",
            Severity::Info,
            &target,
            "/",
            format!("missing {}", cross.join(" and ")),
            "Set COOP and CORP at the edge when the page does not need to be embedded.",
        ));
    }
    let seo = crate::seometa::parse(&r.body);
    for dash in seo.dashes() {
        out.push(mk(
            "WEB-060",
            Severity::Info,
            &target,
            "/",
            format!(
                "SEO field {} contains {} em dash(es) in {} words. This is a lead, not an identification.",
                dash.field, dash.dashes, dash.words
            ),
            "Read the sentence. Human editors use this punctuation too.",
        ));
    }
    if !seo.generator.is_empty() {
        out.push(mk(
            "WEB-061",
            Severity::Info,
            &target,
            "/",
            format!("generator meta exposes {}", seo.generator),
            "Drop the generator tag if the CMS version is not meant to be public.",
        ));
    }
    for h in ["server", "x-powered-by", "x-aspnet-version", "x-generator"] {
        if let Some(v) = header(&r.headers, h)
            && !v.is_empty()
        {
            out.push(mk(
                "WEB-016",
                Severity::Info,
                &target,
                "/",
                format!("{h} header exposes stack detail: {v}"),
                "Suppress or genericize the banner.",
            ));
        }
    }
    // CORS
    if let (Some(acao), Some(acc)) = (
        header(&r.headers, "access-control-allow-origin"),
        header(&r.headers, "access-control-allow-credentials"),
    ) && acao.trim() == "*"
        && acc.trim().eq_ignore_ascii_case("true")
    {
        out.push(mk(
            "WEB-017",
            Severity::High,
            &target,
            "/",
            "CORS allows any origin WITH credentials",
            "Browsers refuse this combo but the config signals careless CORS; pin origins.",
        ));
    }

    // ---- cookies ----
    let mut seen_cookies: HashSet<String> = HashSet::new();
    for (k, v) in &r.headers {
        if !k.eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        let name = v.split('=').next().unwrap_or("").trim().to_string();
        if name.is_empty() || !seen_cookies.insert(name.clone()) {
            continue;
        }
        let flags = cookie_flags(v);
        let mut missing = Vec::new();
        if is_https && !flags.secure {
            missing.push("Secure");
        }
        if !flags.http_only {
            missing.push("HttpOnly");
        }
        if !flags.same_site {
            missing.push("SameSite");
        }
        if !missing.is_empty() {
            out.push(mk(
                "WEB-020",
                Severity::Low,
                &target,
                "/",
                format!("cookie {name} missing flags: {}", missing.join(", ")),
                "Set Secure, HttpOnly and SameSite=Lax|Strict on session cookies.",
            ));
        }
    }
    out.extend(crate::webpassive::assess(
        &r.headers, &r.body, is_https, &target,
    ));

    // ---- content secrets: html + inline js ----
    let applicable: Vec<&CompiledRule> = rules.iter().filter(|r| r.set == "secrets").collect();
    out.extend(scan_file(
        "/index.html",
        Some(&r.body),
        None,
        &applicable,
        opts,
        &target,
    ));
    let inline = inline_scripts(&r.body);
    if !inline.is_empty() {
        web_secrets("/inline.js", &inline, &target, &mut out);
        out.extend(scan_file(
            "/inline.js",
            Some(&inline),
            None,
            &applicable,
            opts,
            &target,
        ));
    }

    // form check on root page
    form_checks(&r.body, &target, "/", &mut out);

    // ---- depth-limited same-origin crawl ----
    let mut pages_seen: HashSet<String> = HashSet::new();
    pages_seen.insert(r.final_url.clone());
    pages_seen.insert(url.clone());
    let mut frontier: Vec<(String, usize)> = Vec::new();
    if depth > 0 {
        for l in page_links(&r.body, &target) {
            if let Some(u) = join(&r.final_url, &l)
                && host_of(&u) == target
                && pages_seen.insert(u.clone())
            {
                frontier.push((u, 1));
            }
        }
    }
    let mut extra_pages: Vec<(String, Resp)> = Vec::new();
    while let Some((u, d)) = frontier.pop() {
        if extra_pages.len() >= 30 {
            break;
        }
        if let Ok(p) = get(&u) {
            if p.status != 200 {
                continue;
            }
            // inline secrets + forms on each page
            let rel = format!(
                "/{}",
                u.trim_start_matches(&base_of(&r.final_url))
                    .trim_start_matches('/')
            );
            let rel = if rel == "/" { "/page".into() } else { rel };
            let inline2 = inline_scripts(&p.body);
            if !inline2.is_empty() {
                web_secrets(&rel, &inline2, &target, &mut out);
                out.extend(scan_file(
                    &rel,
                    Some(&inline2),
                    None,
                    &applicable,
                    opts,
                    &target,
                ));
            }
            form_checks(&p.body, &target, &rel, &mut out);
            if d < depth {
                for l in page_links(&p.body, &target) {
                    if let Some(u2) = join(&p.final_url, &l)
                        && host_of(&u2) == target
                        && pages_seen.insert(u2.clone())
                    {
                        frontier.push((u2, d + 1));
                    }
                }
            }
            extra_pages.push((rel, p));
        }
    }
    let crawled = extra_pages.len();
    if crawled > 0 && verbose {
        eprintln!("web: crawled {crawled} additional pages");
    }

    // ---- js bundles ----
    let mut urls: Vec<String> = asset_urls(&r.body)
        .iter()
        .filter_map(|u| join(&r.final_url, u))
        .collect();
    for (_, p) in &extra_pages {
        urls.extend(
            asset_urls(&p.body)
                .iter()
                .filter_map(|u| join(&p.final_url, u)),
        );
    }
    urls.sort();
    urls.dedup();
    for u in urls.iter().take(30) {
        if verbose {
            eprintln!("web: fetch asset {u}");
        }
        if let Ok(a) = get(u)
            && a.status == 200
            && !a.body.is_empty()
        {
            assets += 1;
            let rel = format!("/js/{}", u.rsplit('/').next().unwrap_or("bundle.js"));
            web_secrets(&rel, &a.body, &target, &mut out);
            out.extend(scan_file(
                &rel,
                Some(&a.body),
                None,
                &applicable,
                opts,
                &target,
            ));
            // source map ships full source - and often more secrets
            if let Ok(m) = get(&format!("{u}.map"))
                && m.status == 200
                && m.body.contains("sourcesContent")
            {
                out.push(mk(
                    "WEB-040",
                    Severity::Low,
                    &target,
                    &format!("{rel}.map"),
                    "source map ships original source to every visitor",
                    "Publish maps to an internal host or drop them in production.",
                ));
                web_secrets(&format!("{rel}.map"), &m.body, &target, &mut out);
                out.extend(scan_file(
                    &format!("{rel}.map"),
                    Some(&m.body),
                    None,
                    &applicable,
                    opts,
                    &target,
                ));
            }
        }
    }

    // ---- exposed metadata probes ----
    let base = format!(
        "{}://{}",
        r.final_url.split("://").next().unwrap_or("https"),
        host_of(&r.final_url)
    );
    for (path, id, sev, what) in [
        (
            "/.git/HEAD",
            "WEB-030",
            Severity::High,
            "git metadata exposed - history, config and source recoverable",
        ),
        (
            "/.env",
            "WEB-031",
            Severity::Critical,
            ".env served publicly - likely contains credentials",
        ),
        (
            "/.aws/credentials",
            "WEB-032",
            Severity::Critical,
            "AWS credentials file served publicly",
        ),
        (
            "/server-status",
            "WEB-033",
            Severity::Medium,
            "Apache server-status is public",
        ),
        (
            "/actuator/env",
            "WEB-034",
            Severity::High,
            "Spring actuator env is public",
        ),
        (
            "/debug/pprof/",
            "WEB-038",
            Severity::Medium,
            "Go pprof is public",
        ),
        (
            "/phpinfo.php",
            "WEB-043",
            Severity::Medium,
            "phpinfo page is public",
        ),
    ] {
        if let Ok(p) = get(&format!("{base}{path}")) {
            // SPA fallback serves index.html for every path - validate content
            let looks_html = p.body[..p.body.len().min(4096)]
                .to_lowercase()
                .contains("<html");
            let plausible = match path {
                "/.git/HEAD" => p.body.contains("ref:"),
                "/server-status" => p.body.to_lowercase().contains("apache server status"),
                "/actuator/env" => {
                    p.body.contains("propertySources") || p.body.contains("activeProfiles")
                }
                "/debug/pprof/" => p.body.contains("goroutine") || p.body.contains("heap profile"),
                "/phpinfo.php" => p.body.contains("phpinfo()"),
                _ => !looks_html && p.body.contains('='),
            };
            if p.status == 200 && plausible && p.body.len() < 64 * 1024 {
                out.push(mk(
                    id,
                    sev,
                    &target,
                    path,
                    what,
                    "Block dotfiles in the web server config.",
                ));
            }
        }
    }

    // ---- robots / security.txt ----
    if let Ok(p) = get(&format!("{base}/robots.txt"))
        && p.status == 200
    {
        let interesting = regex::Regex::new(
                r"(?im)^\s*Disallow:\s*(/(?:admin|internal|private|backup|backoffice|staging|dashboard|api|config)[^\s]*)",
            )
            .unwrap();
        for c in interesting.captures_iter(&p.body).take(10) {
            out.push(mk(
                "WEB-035",
                Severity::Info,
                &target,
                "/robots.txt",
                format!("robots.txt discloses sensitive path {}", &c[1]),
                "robots.txt is a roadmap, not a control; keep sensitive paths unlisted.",
            ));
        }
    }
    let sec_txt = get(&format!("{base}/.well-known/security.txt"))
        .map(|p| p.status == 200)
        .unwrap_or(false)
        || get(&format!("{base}/security.txt"))
            .map(|p| p.status == 200)
            .unwrap_or(false);
    if !sec_txt {
        out.push(mk(
            "WEB-036",
            Severity::Info,
            &target,
            "/.well-known/security.txt",
            "no security.txt published",
            "Publish /.well-known/security.txt with a security contact (RFC 9116).",
        ));
    }

    // ---- TLS certificate expiry ----
    if is_https && let Some(days) = cert_days_left(&target) {
        if days <= 0 {
            out.push(mk(
                "WEB-045",
                Severity::High,
                &target,
                "/",
                "TLS certificate is expired",
                "Renew the certificate immediately.",
            ));
        } else if days <= 30 {
            out.push(mk(
                "WEB-045",
                Severity::Medium,
                &target,
                "/",
                format!("TLS certificate expires in {days} days"),
                "Renew soon or automate renewal (ACME).",
            ));
        }
    }

    Ok(WebScan {
        findings: out,
        assets_scanned: assets,
        final_url: r.final_url,
    })
}

/// Days until the host's leaf certificate expires (openssl subprocess;
/// returns None if openssl is unavailable or the handshake fails).
fn cookie_flags(header: &str) -> CookieFlags {
    let mut parts = header.split(';');
    let _name = parts.next();
    let mut flags = CookieFlags::default();
    for part in parts {
        let key = part.trim().split('=').next().unwrap_or("").trim();
        if key.eq_ignore_ascii_case("secure") {
            flags.secure = true;
        } else if key.eq_ignore_ascii_case("httponly") {
            flags.http_only = true;
        } else if key.eq_ignore_ascii_case("samesite") {
            flags.same_site = true;
        }
    }
    flags
}

#[derive(Default)]
struct CookieFlags {
    secure: bool,
    http_only: bool,
    same_site: bool,
}

fn hsts_active(value: &str) -> bool {
    let low = value.to_ascii_lowercase();
    let Some(rest) = low.split("max-age=").nth(1) else {
        return false;
    };
    let digits: String = rest
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<u64>().unwrap_or(0) > 0
}

fn cert_days_left(host: &str) -> Option<i64> {
    let out2 = std::process::Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("{host}:443"),
            "-servername",
            host,
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    // extract the first PEM cert and ask x509 for its expiry
    let pem: String = String::from_utf8_lossy(&out2.stdout).to_string();
    let cert = pem
        .find("-----BEGIN CERTIFICATE-----")
        .and_then(|s| {
            pem[s..]
                .find("-----END CERTIFICATE-----")
                .map(|e| pem[s..s + e + 25].to_string())
        })
        .unwrap_or_default();
    let mut x = std::process::Command::new("openssl")
        .args(["x509", "-noout", "-enddate"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    if let Some(mut stdin) = x.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(cert.as_bytes());
        let _ = stdin.flush();
        drop(stdin);
    }
    let out3 = x.wait_with_output().ok()?;
    let t = String::from_utf8_lossy(&out3.stdout);
    let date = t.trim().strip_prefix("notAfter=")?;
    // "Dec  3 12:00:00 2025 GMT"
    let parts: Vec<&str> = date.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| *m == parts[0])
    .map(|p| p as i64 + 1)?;
    let day: i64 = parts[1].parse().ok()?;
    let year: i64 = parts[3].parse().ok()?;
    // days since epoch for the expiry date
    let (y, mo, d) = (year, month, day);
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let exp_days = era * 146097 + doe - 719468;
    let today = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs()
        / 86400) as i64;
    Some(exp_days - today)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_joining() {
        assert_eq!(
            join("https://a.com/x/y.html", "/js/a.js"),
            Some("https://a.com/js/a.js".into())
        );
        assert_eq!(
            join("https://a.com/x/y.html", "https://cdn.com/b.js"),
            Some("https://cdn.com/b.js".into())
        );
        assert_eq!(
            join("https://a.com/x/", "//cdn.com/c.js"),
            Some("https://cdn.com/c.js".into())
        );
    }

    #[test]
    fn secret_assignment_detection() {
        let js = r#"env:{REACT_APP_STEAM_API_KEY:"817F99B5492EFB48E25E54AE49B14260",X:"short"}"#;
        let mut out = Vec::new();
        web_secrets("/a.js", js, "t", &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::High);
        assert!(out[0].message.contains("REACT_APP_STEAM_API_KEY"));

        // public-by-design keys downgrade instead of high
        let js2 = r#"cfg:{algolia_api_key:"94HE6YATEI93HE6YATEI"}"#;
        let mut out2 = Vec::new();
        web_secrets("/a.js", js2, "t", &mut out2);
        assert_eq!(out2.len(), 1);
        assert!(out2[0].severity < Severity::High);

        // duplicates collapse
        let mut out3 = Vec::new();
        web_secrets("/a.js", &format!("{js},{js}"), "t", &mut out3);
        assert_eq!(out3.len(), 1);
    }

    #[test]
    fn cookie_flags_ignore_the_value() {
        let marked = cookie_flags("session=not-secure; HttpOnly; SameSite=Lax");
        assert!(!marked.secure);
        assert!(marked.http_only);
        assert!(marked.same_site);
        let real = cookie_flags("id=1; Secure");
        assert!(real.secure);
        assert!(!hsts_active("max-age=0"));
        assert!(hsts_active("max-age=15552000; includeSubDomains"));
        assert!(!hsts_active("includeSubDomains"));
    }

    #[test]
    fn asset_extraction() {
        let html = r#"<script src="/a/main.js"></script><script>var x=1;</script><link as="script" href="/b.js">"#;
        let urls = asset_urls(html);
        assert!(urls.contains(&"/a/main.js".to_string()));
        let inline = inline_scripts(html);
        assert!(inline.contains("var x=1"));
        assert!(!inline.contains("main.js"));
    }
}
