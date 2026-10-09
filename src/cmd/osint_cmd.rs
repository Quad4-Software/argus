// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

use crate::cli::{Cli, Cmd, Format};
use crate::osint;
use std::process::ExitCode;

pub(crate) fn run(
    cli: &Cli,
    offline: bool,
    format: Format,
    rules: &[crate::rules::CompiledRule],
    opts: &crate::scan::ScanOptions,
) -> Result<ExitCode, String> {
    match &cli.cmd {
        Cmd::Domain { domain } => {
            let report = osint::scan_domain(domain)?;
            finish(cli, format, &report)
        }
        Cmd::Email { email, smtp } => {
            let report = osint::scan_email(email, *smtp)?;
            finish(cli, format, &report)
        }
        Cmd::Hash { hash } => {
            let report = osint::scan_hash(hash)?;
            finish(cli, format, &report)
        }
        Cmd::Url { url } => {
            let report = osint::scan_url(url)?;
            finish(cli, format, &report)
        }
        Cmd::Ports { host, ports, all } => {
            let report = osint::scan_ports(host, ports.as_deref(), *all)?;
            finish(cli, format, &report)
        }
        Cmd::Intel { indicator } => {
            let report = osint::scan_intel(indicator)?;
            finish(cli, format, &report)
        }
        Cmd::Supply { path } => {
            let report = crate::supply::scan(path)?;
            finish(cli, format, &report)
        }
        Cmd::Records { query } => {
            let rows = crate::db::search(query, 50)?;
            if rows.is_empty() {
                println!("no records");
                return Ok(ExitCode::SUCCESS);
            }
            for row in rows {
                println!("{}  {}  {}", row.kind, row.key, row.id);
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Api { listen } => serve_api(listen),
        Cmd::Stego { path } => finish(cli, format, &crate::stego::scan(path)?),
        Cmd::Codec {
            mode,
            alphabet,
            text,
        } => {
            let input = match text {
                Some(t) if t != "-" => t.clone(),
                _ => read_stdin()?,
            };
            finish(cli, format, &crate::codec::scan(mode, alphabet, &input)?)
        }
        Cmd::Style { a, b, kind } => {
            finish(cli, format, &crate::style::scan(a, b, kind.as_deref())?)
        }
        Cmd::Account { forge, login, host } => finish(
            cli,
            format,
            &osint::scan_account(forge, login, host.as_deref())?,
        ),
        Cmd::Socials { url } => finish(cli, format, &osint::scan_socials(url)?),
        Cmd::Feed { url, query } => finish(cli, format, &osint::scan_feed(url, query.as_deref())?),
        Cmd::Gitmeta { target } => finish(cli, format, &osint::scan_gitmeta(target)?),
        Cmd::Grep {
            pattern,
            paths,
            pick,
            column,
            eq,
            kind,
            table,
            max,
            ignore_case,
        } => grep_cmd(GrepIn {
            pattern: pattern.as_deref(),
            paths,
            pick: pick.as_deref(),
            column: column.clone(),
            eq: eq.clone(),
            kind,
            table: table.clone(),
            max: *max,
            ignore_case: *ignore_case,
            format,
        }),
        Cmd::Extract { target } => finish(cli, format, &crate::extract::scan_target(target)?),
        Cmd::Meta { path } => finish(cli, format, &osint::scan_meta(path)?),
        Cmd::Media { path } => finish(cli, format, &crate::media::scan(path)?),
        Cmd::Dork { query } => finish(cli, format, &osint::scan_dork(query)?),
        Cmd::Favicon { url } => finish(cli, format, &osint::scan_favicon(url)?),
        Cmd::User { name } => finish(cli, format, &osint::scan_user(name)?),
        Cmd::Keybase { name } => finish(cli, format, &osint::scan_keybase(name)?),
        Cmd::Steam { target } => finish(cli, format, &osint::scan_steam(target)?),
        Cmd::Bluesky { handle } => finish(cli, format, &osint::scan_bluesky(handle)?),
        Cmd::Mastodon { target, instance } => {
            finish(cli, format, &osint::scan_mastodon(target, instance)?)
        }
        Cmd::Reddit { user } => finish(cli, format, &osint::scan_reddit(user)?),
        Cmd::Youtube { target } => finish(cli, format, &osint::scan_youtube(target)?),
        Cmd::Tiktok { target } => finish(cli, format, &osint::scan_tiktok(target)?),
        Cmd::Lemmy { target, instance } => finish(
            cli,
            format,
            &osint::scan_lemmy(target, instance.as_deref())?,
        ),
        Cmd::Gharchive(a) => {
            let sel = match (&a.org, &a.user, &a.repo) {
                (Some(n), None, None) => osint::GhSel::Org(n.clone()),
                (None, Some(n), None) => osint::GhSel::User(n.clone()),
                (None, None, Some(n)) => osint::GhSel::Repo(n.clone()),
                (None, None, None) => return Err("pass --org, --user, or --repo".into()),
                _ => return Err("pass only one of --org, --user, --repo".into()),
            };
            let (report, evs) = osint::collect_gharchive(&sel, a.hours, a.events.as_deref())?;
            let code = finish(cli, format, &report)?;
            if a.fetch {
                super::revive::run(&evs, a.fetch_max, rules, opts, cli.verbose > 0);
            }
            Ok(code)
        }
        Cmd::Typo { domain } => finish(cli, format, &osint::scan_typo(domain)?),
        Cmd::Modules => {
            print!("{}", crate::catalog::list());
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Ip { ip, download } => {
            if *download {
                let path = osint::download_geo()?;
                eprintln!(
                    "geo: saved {} (DB-IP City Lite, CC BY 4.0, https://db-ip.com/)",
                    path.display()
                );
            }
            match ip {
                Some(ip) => {
                    let report = osint::scan_ip(ip, offline)?;
                    finish(cli, format, &report)
                }
                None if *download => Ok(ExitCode::SUCCESS),
                None => Err("pass an address or --download".into()),
            }
        }
        _ => Err("not an osint command".into()),
    }
}

fn finish(cli: &Cli, format: Format, report: &osint::Report) -> Result<ExitCode, String> {
    if cli.store {
        let body = osint::render(report, Format::Json);
        match crate::db::put_report(report.kind, &report.target, &body) {
            Ok(id) => {
                for hit in &report.findings {
                    if hit.status == osint::Status::Confirmed {
                        let _ = crate::db::relate(
                            &id,
                            &hit.module,
                            &format!("{}:{}", report.kind, hit.module),
                        );
                    }
                }
            }
            Err(e) => eprintln!("store: {e}"),
        }
    }
    write(cli, &osint::render(report, format))
}

fn serve_api(listen: &str) -> Result<ExitCode, String> {
    let listener =
        std::net::TcpListener::bind(listen).map_err(|e| format!("bind {listen}: {e}"))?;
    eprintln!("api: {listen}");
    crate::http_server::serve(listener, |req| {
        let path = req.path.split('?').next().unwrap_or("/");
        match (req.method.as_str(), path) {
            ("GET", "/health") => (200, "{\"ok\":true}\n".into()),
            ("GET", "/v1/records") => {
                let q = query_param(&req.path, "q").unwrap_or_default();
                match crate::db::search(&q, 50) {
                    Ok(rows) => (
                        200,
                        serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into()) + "\n",
                    ),
                    Err(e) => (500, serde_json::json!({"error": e}).to_string() + "\n"),
                }
            }
            ("POST", "/v1/intel") => {
                let body = String::from_utf8_lossy(&req.body);
                let v: serde_json::Value =
                    serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
                let indicator = v.get("indicator").and_then(|s| s.as_str()).unwrap_or("");
                match osint::scan_intel(indicator) {
                    Ok(report) => (200, osint::render(&report, Format::Json)),
                    Err(e) => (400, serde_json::json!({"error": e}).to_string() + "\n"),
                }
            }
            ("POST", "/v1/account") => {
                let v = json_body(&req.body);
                let forge = v.get("forge").and_then(|s| s.as_str()).unwrap_or("");
                let login = v.get("login").and_then(|s| s.as_str()).unwrap_or("");
                let host = v.get("host").and_then(|s| s.as_str());
                match osint::scan_account(forge, login, host) {
                    Ok(report) => (200, osint::render(&report, Format::Json)),
                    Err(e) => (400, serde_json::json!({"error": e}).to_string() + "\n"),
                }
            }
            ("POST", "/v1/socials") => {
                let v = json_body(&req.body);
                let url = v.get("url").and_then(|s| s.as_str()).unwrap_or("");
                match osint::scan_socials(url) {
                    Ok(report) => (200, osint::render(&report, Format::Json)),
                    Err(e) => (400, serde_json::json!({"error": e}).to_string() + "\n"),
                }
            }
            ("POST", "/v1/keybase") => {
                let v = json_body(&req.body);
                let name = v.get("name").and_then(|s| s.as_str()).unwrap_or("");
                match osint::scan_keybase(name) {
                    Ok(report) => (200, osint::render(&report, Format::Json)),
                    Err(e) => (400, serde_json::json!({"error": e}).to_string() + "\n"),
                }
            }
            ("POST", "/v1/steam") => {
                let v = json_body(&req.body);
                let target = v.get("target").and_then(|s| s.as_str()).unwrap_or("");
                match osint::scan_steam(target) {
                    Ok(report) => (200, osint::render(&report, Format::Json)),
                    Err(e) => (400, serde_json::json!({"error": e}).to_string() + "\n"),
                }
            }
            ("POST", "/v1/bluesky") => {
                let v = json_body(&req.body);
                let handle = v.get("handle").and_then(|s| s.as_str()).unwrap_or("");
                match osint::scan_bluesky(handle) {
                    Ok(report) => (200, osint::render(&report, Format::Json)),
                    Err(e) => (400, serde_json::json!({"error": e}).to_string() + "\n"),
                }
            }
            ("POST", "/v1/mastodon") => {
                let v = json_body(&req.body);
                let target = v.get("target").and_then(|s| s.as_str()).unwrap_or("");
                let instance = v
                    .get("instance")
                    .and_then(|s| s.as_str())
                    .unwrap_or("mastodon.social");
                match osint::scan_mastodon(target, instance) {
                    Ok(report) => (200, osint::render(&report, Format::Json)),
                    Err(e) => (400, serde_json::json!({"error": e}).to_string() + "\n"),
                }
            }
            ("POST", "/v1/reddit") => {
                let v = json_body(&req.body);
                let user = v.get("user").and_then(|s| s.as_str()).unwrap_or("");
                match osint::scan_reddit(user) {
                    Ok(report) => (200, osint::render(&report, Format::Json)),
                    Err(e) => (400, serde_json::json!({"error": e}).to_string() + "\n"),
                }
            }
            ("POST", "/v1/youtube") => {
                let v = json_body(&req.body);
                let target = v.get("target").and_then(|s| s.as_str()).unwrap_or("");
                match osint::scan_youtube(target) {
                    Ok(report) => (200, osint::render(&report, Format::Json)),
                    Err(e) => (400, serde_json::json!({"error": e}).to_string() + "\n"),
                }
            }
            ("POST", "/v1/tiktok") => {
                let v = json_body(&req.body);
                let target = v.get("target").and_then(|s| s.as_str()).unwrap_or("");
                match osint::scan_tiktok(target) {
                    Ok(report) => (200, osint::render(&report, Format::Json)),
                    Err(e) => (400, serde_json::json!({"error": e}).to_string() + "\n"),
                }
            }
            ("POST", "/v1/lemmy") => {
                let v = json_body(&req.body);
                let target = v.get("target").and_then(|s| s.as_str()).unwrap_or("");
                let instance = v.get("instance").and_then(|s| s.as_str());
                match osint::scan_lemmy(target, instance) {
                    Ok(report) => (200, osint::render(&report, Format::Json)),
                    Err(e) => (400, serde_json::json!({"error": e}).to_string() + "\n"),
                }
            }
            ("POST", "/v1/feed") => {
                let v = json_body(&req.body);
                let url = v.get("url").and_then(|s| s.as_str()).unwrap_or("");
                let query = v.get("query").and_then(|s| s.as_str());
                match osint::scan_feed(url, query) {
                    Ok(report) => (200, osint::render(&report, Format::Json)),
                    Err(e) => (400, serde_json::json!({"error": e}).to_string() + "\n"),
                }
            }
            ("POST", "/v1/trackers") => {
                let body = String::from_utf8_lossy(&req.body);
                let v: serde_json::Value =
                    serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
                let url = v.get("url").and_then(|s| s.as_str()).unwrap_or("");
                match osint::scan_url(url) {
                    Ok(report) => (200, osint::render(&report, Format::Json)),
                    Err(e) => (400, serde_json::json!({"error": e}).to_string() + "\n"),
                }
            }
            _ => (404, "{\"error\":\"not found\"}\n".into()),
        }
    });
    Ok(ExitCode::SUCCESS)
}

struct GrepIn<'a> {
    pattern: Option<&'a str>,
    paths: &'a [std::path::PathBuf],
    pick: Option<&'a str>,
    column: Option<String>,
    eq: Option<String>,
    kind: &'a str,
    table: Option<String>,
    max: usize,
    ignore_case: bool,
    format: Format,
}

fn grep_cmd(args: GrepIn<'_>) -> Result<ExitCode, String> {
    let GrepIn {
        pattern,
        paths,
        pick,
        column,
        eq,
        kind,
        table,
        max,
        ignore_case,
        format,
    } = args;
    let (pattern, paths) = crate::search::positionals(
        pattern.map(str::to_string),
        paths.to_vec(),
        pick.is_some() || eq.is_some(),
    );
    let pattern = match pattern {
        Some(p) => Some(crate::search::compile_pattern(&p, ignore_case)?),
        None => None,
    };
    let pick = match pick {
        Some(p) => Some(crate::extract::Pick::parse(p)?),
        None => None,
    };
    let query = crate::search::Query {
        pattern,
        pick,
        column,
        eq,
        kind: crate::search::parse_kind(kind)?,
        table,
        max,
        json: matches!(format, Format::Json | Format::Sarif | Format::Codeclimate),
    };
    crate::search::run(&paths, &query)?;
    Ok(ExitCode::SUCCESS)
}

fn json_body(body: &[u8]) -> serde_json::Value {
    let body = String::from_utf8_lossy(body);
    serde_json::from_str(&body).unwrap_or(serde_json::json!({}))
}

fn read_stdin() -> Result<String, String> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin()
        .take(1024 * 1024)
        .read_to_string(&mut buf)
        .map_err(|e| format!("stdin: {e}"))?;
    Ok(buf)
}

fn query_param(path: &str, name: &str) -> Option<String> {
    let query = path.split_once('?')?.1;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == name
        {
            return Some(v.replace('+', " "));
        }
    }
    None
}

fn write(cli: &Cli, text: &str) -> Result<ExitCode, String> {
    match &cli.output {
        Some(p) => {
            std::fs::write(p, text).map_err(|e| format!("write {}: {e}", p.display()))?;
        }
        None => print!("{text}"),
    }
    Ok(ExitCode::SUCCESS)
}
