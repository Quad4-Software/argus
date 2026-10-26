// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! External mode: passive banner fingerprinting over HTTP(S).
//! Sends plain GET requests only; no exploit payloads are ever sent.

use crate::cli::CveArgs;
use crate::cve::probe::Eval;
use crate::cve::{DEFAULT_PORTS, Reach, adv_finding, db, mk, reach};
use crate::finding::{Finding, Severity};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::Duration;

const CONNECT: Duration = Duration::from_millis(300);
const HTTPS_PORTS: &[u16] = &[443, 8443, 9443, 4443];

struct Target {
    host: String,
    port: Option<u16>,
    scheme: Option<String>,
    label: String,
}

fn parse_target(raw: &str) -> Result<Target, String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.contains(char::is_whitespace) {
        return Err(format!("bad target {raw:?}"));
    }
    let (scheme, rest) = if let Some(r) = raw.strip_prefix("https://") {
        (Some("https".to_string()), r)
    } else if let Some(r) = raw.strip_prefix("http://") {
        (Some("http".to_string()), r)
    } else {
        (None, raw)
    };
    if rest.contains('@') {
        return Err(format!("{raw}: credentials in targets are refused"));
    }
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or("");
    if hostport.is_empty() {
        return Err(format!("{raw}: no host"));
    }
    if raw.contains('/') && scheme.is_none() {
        return Err(format!("{raw}: network ranges are not scanned"));
    }
    let (host, port) = if hostport.starts_with('[') {
        let end = hostport.find(']').ok_or(format!("{raw}: bad IPv6"))?;
        let h = &hostport[1..end];
        let tail = &hostport[end + 1..];
        let p = if let Some(t) = tail.strip_prefix(':') {
            Some(t.parse::<u16>().map_err(|_| format!("{raw}: bad port"))?)
        } else {
            None
        };
        (h.to_string(), p)
    } else if hostport.matches(':').count() > 1 {
        return Err(format!("{raw}: wrap an IPv6 address in brackets"));
    } else if let Some((h, t)) = hostport.rsplit_once(':') {
        if !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()) {
            (
                h.to_string(),
                Some(t.parse::<u16>().map_err(|_| format!("{raw}: bad port"))?),
            )
        } else {
            return Err(format!("{raw}: bad host:port"));
        }
    } else {
        (hostport.to_string(), None)
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err(format!("{raw}: no host"));
    }
    Ok(Target {
        label: raw.to_string(),
        host,
        port,
        scheme,
    })
}

fn usable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(o[0] == 0 || o[0] >= 224 || (o[0] == 169 && o[1] == 254) || v.is_broadcast())
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            !(v.is_unspecified() || v.is_multicast() || (s[0] & 0xffc0) == 0xfe80)
        }
    }
}

fn agent() -> ureq::Agent {
    let tls = ureq::tls::TlsConfig::builder()
        // self-signed certs are normal on scanned hosts
        .disable_verification(true)
        .build();
    let cfg = ureq::config::Config::builder()
        .timeout_global(Some(Duration::from_secs(5)))
        .timeout_connect(Some(Duration::from_secs(3)))
        .http_status_as_error(false)
        .max_redirects(0)
        .tls_config(tls)
        .user_agent(concat!("argus/", env!("CARGO_PKG_VERSION")))
        .build();
    ureq::Agent::new_with_config(cfg)
}

struct Resp {
    server: Option<String>,
    powered: Option<String>,
    alt_svc: Option<String>,
    encoding: Option<String>,
    via: Option<String>,
}

fn get(agent: &ureq::Agent, url: &str) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
    agent.get(url).header("Accept-Encoding", "br").call()
}

fn headers(resp: &ureq::http::Response<ureq::Body>) -> Resp {
    let h = |n: &str| {
        resp.headers()
            .get(n)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };
    Resp {
        server: h("server"),
        powered: h("x-powered-by"),
        alt_svc: h("alt-svc"),
        encoding: h("content-encoding"),
        via: h("via"),
    }
}

fn distro_build(server: &str) -> bool {
    [
        "(Ubuntu)",
        "(Debian)",
        "(CentOS)",
        "(Red Hat",
        "(Fedora)",
        "(SUSE",
        "(AlmaLinux",
        "(Rocky",
    ]
    .iter()
    .any(|m| server.contains(m))
}

fn lower(sev: Severity) -> Severity {
    match sev {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        s => s,
    }
}

struct Ctx<'a> {
    dbx: &'a [db::Advisory],
    http3: Eval,
    downgrade: bool,
}

struct Detect<'a> {
    product: &'a str,
    ver: &'a [u64],
    ver_s: &'a str,
    target: &'a str,
    path: &'a str,
    evidence: Vec<String>,
}

fn match_advisories(cx: &Ctx, d: &Detect, out: &mut Vec<Finding>) {
    for adv in db::for_product(cx.dbx, d.product) {
        if !adv.hits(d.ver) {
            continue;
        }
        let mut ev = d.evidence.clone();
        ev.push(format!("detected {} {}", d.product, d.ver_s));
        let evals: Vec<(String, Eval)> = adv
            .needs
            .iter()
            .map(|n| {
                (
                    n.clone(),
                    if n == "http3" {
                        cx.http3
                    } else {
                        Eval::Unknown
                    },
                )
            })
            .collect();
        let mut sev = adv.severity;
        if cx.downgrade {
            sev = lower(sev);
            ev.push("distro build, vendor may have backported the fix".into());
        }
        match reach(adv, &evals) {
            Reach::Yes(y) => {
                ev.extend(y);
                out.push(adv_finding(adv, sev, d.target, d.path, ev));
            }
            Reach::No => {
                let mut f = adv_finding(adv, Severity::Info, d.target, d.path, ev);
                f.message = format!(
                    "{}: version is affected but the feature is not configured or compiled in",
                    adv.id
                );
                if let Some(e) = f.evidence.as_mut() {
                    e.push(format!("probes: {}", adv.needs.join(", ")));
                }
                out.push(f);
            }
            Reach::Unknown(why) => {
                ev.push(why.into());
                out.push(adv_finding(adv, sev, d.target, d.path, ev));
            }
        }
    }
}

fn hidden_version(
    dbx: &[db::Advisory],
    product: &str,
    target: &str,
    path: &str,
    evidence: Vec<String>,
    out: &mut Vec<Finding>,
) {
    let n = db::for_product(dbx, product)
        .iter()
        .filter(|a| a.severity >= Severity::High)
        .count();
    let mut f = mk(
        "CVE-INFO-001",
        Severity::Info,
        target,
        path,
        format!("{product} version hidden, advisories cannot be ruled out"),
    );
    let mut ev = evidence;
    ev.push(format!(
        "{n} critical/high {product} advisories in the database"
    ));
    f.evidence = Some(ev);
    out.push(f);
}

fn scan_port(
    dbx: &[db::Advisory],
    agent: &ureq::Agent,
    host: &str,
    port: u16,
    prefer_https: bool,
    out: &mut Vec<Finding>,
) {
    let schemes: [&str; 2] = if prefer_https {
        ["https", "http"]
    } else {
        ["http", "https"]
    };
    let target = format!("{host}:{port}");
    let cx = Ctx {
        dbx,
        http3: Eval::Unknown,
        downgrade: false,
    };
    let mut got: Option<(String, Resp)> = None;
    for s in schemes {
        let url = format!("{s}://{target}/");
        match get(agent, &url) {
            Ok(resp) => {
                got = Some((s.to_string(), headers(&resp)));
                break;
            }
            Err(_) => continue,
        }
    }
    let Some((scheme, resp)) = got else {
        return;
    };
    let path = format!("{scheme}://{target}/");
    let base_ev = vec![format!("{scheme} port {port}")];
    let http3 = match &resp.alt_svc {
        Some(v) if v.contains("h3") => Eval::Yes,
        _ => Eval::Unknown,
    };

    // product fingerprints from Server and X-Powered-By
    let mut seen = Vec::new();
    if let Some(server) = &resp.server {
        let (product, ver) = parse_server(server);
        if let Some(p) = product {
            seen.push(p);
            let mut ev = base_ev.clone();
            ev.push(format!("detected {p} via Server header: {server}"));
            if let Some(v) = &resp.via {
                ev.push(format!("Via: {v}"));
            }
            match ver {
                Some(vs) => match crate::cve::version::parse(&vs) {
                    Some(v) => match_advisories(
                        &Ctx {
                            http3,
                            downgrade: distro_build(server),
                            ..cx
                        },
                        &Detect {
                            product: p,
                            ver: &v,
                            ver_s: &vs,
                            target: &target,
                            path: &path,
                            evidence: ev,
                        },
                        out,
                    ),
                    None => hidden_version(dbx, p, &target, &path, ev, out),
                },
                None => hidden_version(dbx, p, &target, &path, ev, out),
            }
        }
    }
    if let Some(xpb) = &resp.powered
        && let Some(vs) = php_version(xpb)
    {
        let mut ev = base_ev.clone();
        ev.push(format!("detected php via X-Powered-By: {xpb}"));
        if let Some(v) = crate::cve::version::parse(&vs) {
            seen.push("php");
            match_advisories(
                &cx,
                &Detect {
                    product: "php",
                    ver: &v,
                    ver_s: &vs,
                    target: &target,
                    path: &path,
                    evidence: ev,
                },
                out,
            );
        }
    }
    if let Some(enc) = &resp.encoding
        && enc.eq_ignore_ascii_case("br")
    {
        let product = seen.first().copied().unwrap_or("unknown");
        let mut f = mk(
            "CVE-INFO-002",
            Severity::Info,
            &target,
            &path,
            format!("brotli content encoding is active (product: {product})"),
        );
        f.evidence = Some(base_ev.clone());
        out.push(f);
    }

    // extra probes: traefik api, caddy admin
    if let Ok(mut r) = get(agent, &format!("{scheme}://{target}/api/version"))
        && let Ok(body) = r.body_mut().with_config().limit(64 * 1024).read_to_string()
        && let Ok(j) = serde_json::from_str::<serde_json::Value>(&body)
        && let Some(vs) = j.get("Version").and_then(|v| v.as_str())
    {
        let mut f = mk(
            "CVE-EXPO-001",
            Severity::High,
            &target,
            &format!("{scheme}://{target}/api/version"),
            "Traefik API or dashboard reachable without authentication from this host",
        );
        f.remediation = Some("Disable the api/dashboard entrypoint or put it behind auth".into());
        f.evidence = Some(vec![format!("traefik {vs} via /api/version")]);
        out.push(f);
        if let Some(v) = crate::cve::version::parse(vs) {
            match_advisories(
                &cx,
                &Detect {
                    product: "traefik",
                    ver: &v,
                    ver_s: vs,
                    target: &target,
                    path: &format!("{scheme}://{target}/api/version"),
                    evidence: vec![format!("traefik {vs} via /api/version")],
                },
                out,
            );
        }
    }
    if port == 2019
        && let Ok(r) = get(agent, &format!("{scheme}://{target}/config/"))
        && r.status().as_u16() == 200
    {
        let mut f = mk(
            "CVE-EXPO-002",
            Severity::Critical,
            &target,
            &format!("{scheme}://{target}:2019/config/"),
            "Caddy admin API reachable: /load and /config allow reconfiguring the server",
        );
        f.remediation = Some("Bind the admin endpoint to localhost or disable it".into());
        out.push(f);
    }
}

fn parse_server(server: &str) -> (Option<&'static str>, Option<String>) {
    for (tok, product) in [
        ("nginx", "nginx"),
        ("Apache", "httpd"),
        ("Caddy", "caddy"),
        ("Traefik", "traefik"),
    ] {
        if let Some(pos) = server.find(tok) {
            let rest = &server[pos + tok.len()..];
            let ver = rest
                .strip_prefix('/')
                .map(|r| r.split_whitespace().next().unwrap_or("").to_string())
                .filter(|s| !s.is_empty());
            return (Some(product), ver);
        }
    }
    (None, None)
}

fn php_version(xpb: &str) -> Option<String> {
    let pos = xpb.find("PHP/")?;
    let v = xpb[pos + 4..]
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();
    (!v.is_empty()).then_some(v)
}

fn open_ports(host: &str, ports: &[u16]) -> Vec<u16> {
    let ips: Vec<IpAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => (host, 443)
            .to_socket_addrs()
            .map(|it| it.map(|a| a.ip()).collect())
            .unwrap_or_default(),
    };
    let Some(ip) = ips.into_iter().find(|i| usable(*i)) else {
        return Vec::new();
    };
    let mut open = Vec::new();
    for chunk in ports.chunks(64) {
        let found = std::thread::scope(|s| {
            let hs: Vec<_> = chunk
                .iter()
                .map(|p| {
                    let p = *p;
                    s.spawn(move || {
                        TcpStream::connect_timeout(&std::net::SocketAddr::new(ip, p), CONNECT)
                            .is_ok()
                            .then_some(p)
                    })
                })
                .collect();
            hs.into_iter()
                .filter_map(|h| h.join().ok().flatten())
                .collect::<Vec<_>>()
        });
        open.extend(found);
    }
    open.sort();
    open
}

fn scan_target(dbx: &[db::Advisory], t: &Target, ports: &[u16]) -> Result<Vec<Finding>, String> {
    let mut out = Vec::new();
    let ports: Vec<u16> = match t.port {
        Some(p) => vec![p],
        None => ports.to_vec(),
    };
    let open = open_ports(&t.host, &ports);
    let agent = agent();
    for p in open {
        let prefer_https = t
            .scheme
            .as_deref()
            .map(|s| s == "https")
            .unwrap_or_else(|| HTTPS_PORTS.contains(&p));
        scan_port(dbx, &agent, &t.host, p, prefer_https, &mut out);
    }
    Ok(out)
}

pub fn scan(dbx: &[db::Advisory], targets: &[String], a: &CveArgs) -> Result<Vec<Finding>, String> {
    let mut parsed = Vec::new();
    for t in targets {
        parsed.push(parse_target(t)?);
    }
    let ports: Vec<u16> = match &a.ports {
        Some(spec) => crate::osint::parse_port_spec(spec)?,
        None => DEFAULT_PORTS.to_vec(),
    };
    let jobs = a.jobs.max(1);
    let queue = Mutex::new(parsed.into_iter());
    let results = Mutex::new(Vec::new());
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..jobs.min(targets.len().max(1)))
            .map(|_| {
                s.spawn(|| {
                    loop {
                        let t = queue.lock().unwrap().next();
                        let Some(t) = t else { break };
                        match scan_target(dbx, &t, &ports) {
                            Ok(fs) => results.lock().unwrap().extend(fs),
                            Err(e) => results.lock().unwrap().push({
                                let mut f = mk(
                                    "CVE-INFO-000",
                                    Severity::Info,
                                    &t.label,
                                    "",
                                    format!("target skipped: {e}"),
                                );
                                f.evidence = None;
                                f
                            }),
                        }
                    }
                })
            })
            .collect();
        for h in hs {
            let _ = h.join();
        }
    });
    let mut out = results.into_inner().unwrap_or_default();
    out.sort_by(|x, y| {
        (x.target.clone(), x.rule_id.clone()).cmp(&(y.target.clone(), y.rule_id.clone()))
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parsing() {
        let t = parse_target("127.0.0.1:8080").unwrap();
        assert_eq!(t.port, Some(8080));
        let t = parse_target("https://example.com/path").unwrap();
        assert_eq!(t.scheme.as_deref(), Some("https"));
        assert_eq!(t.host, "example.com");
        assert!(parse_target("10.0.0.0/24").is_err());
        assert!(parse_target("https://u:p@h/").is_err());
    }

    #[test]
    fn server_parsing() {
        assert_eq!(
            parse_server("nginx/1.30.0"),
            (Some("nginx"), Some("1.30.0".into()))
        );
        assert_eq!(parse_server("nginx"), (Some("nginx"), None));
        assert_eq!(
            parse_server("Apache/2.4.62 (Ubuntu)"),
            (Some("httpd"), Some("2.4.62".into()))
        );
        assert_eq!(php_version("PHP/8.3.30"), Some("8.3.30".into()));
    }
}
