// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! MCP server over stdio (NDJSON JSON-RPC).
//! Legacy clients use the initialize handshake (2025-06-18 and 2025-11-25).
//! 2026-07-28 clients send the protocol version on each request and may call server/discover.
//! Configure a client with:
//!   {"mcpServers": {"argus": {"command": "argus", "args": ["mcp"]}}}

use crate::finding::Severity;
use crate::rules::CompiledRule;
use crate::scan::ScanOptions;
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::process::ExitCode;

const LEGACY: &str = "2025-06-18";
const SUPPORTED: &[&str] = &["2025-06-18", "2025-11-25", "2026-07-28"];

pub fn serve(rules: Vec<CompiledRule>, opts: ScanOptions) -> Result<ExitCode, String> {
    let rules = std::sync::Arc::new(rules);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut w = stdout.lock();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(line) {
            Ok(m) => m,
            Err(e) => {
                respond(
                    &mut w,
                    Value::Null,
                    None,
                    Some(err(-32700, &format!("parse error: {e}"))),
                );
                continue;
            }
        };
        // JSON-RPC batch not supported (rarely used by clients)
        let id = msg["id"].clone();
        let method = msg["method"].as_str().unwrap_or("");
        let is_notification = msg.get("id").is_none();

        let result = match method {
            "initialize" => Some(negotiate(msg["params"]["protocolVersion"].as_str()).map(
                |version| {
                    json!({
                        "protocolVersion": version,
                        "capabilities": {"tools": {"listChanged": false}},
                        "serverInfo": {"name": "argus", "version": env!("CARGO_PKG_VERSION")}
                    })
                },
            )),
            "server/discover" => Some(Ok(json!({
                "protocolVersions": SUPPORTED,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "argus", "version": env!("CARGO_PKG_VERSION")}
            }))),
            "ping" => Some(Ok(json!({}))),
            "notifications/initialized" | "notifications/cancelled" | "notifications/progress" => {
                None
            }
            "tools/list" => Some(Ok(tools_list())),
            "tools/call" => {
                let name = msg["params"]["name"].as_str().unwrap_or("");
                let args = msg["params"]["arguments"].clone();
                Some(call_tool(name, &args, &rules, &opts))
            }
            _ => {
                if is_notification {
                    None
                } else {
                    Some(Err(err(-32601, &format!("method not found: {method}"))))
                }
            }
        };
        if let Some(res) = result {
            match res {
                Ok(v) => respond(&mut w, id, Some(v), None),
                Err(e) => respond(&mut w, id, None, Some(e)),
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn negotiate(requested: Option<&str>) -> Result<Value, Value> {
    match requested {
        None => Ok(json!(LEGACY)),
        Some(v) if SUPPORTED.contains(&v) => Ok(json!(v)),
        Some(_) => Err(json!({
            "code": -32022,
            "message": "unsupported protocol version",
            "data": {"supported": SUPPORTED}
        })),
    }
}

fn err(code: i64, msg: &str) -> Value {
    json!({"code": code, "message": msg})
}

fn respond(w: &mut impl Write, id: Value, result: Option<Value>, error: Option<Value>) {
    let mut r = json!({"jsonrpc": "2.0", "id": id});
    match (result, error) {
        (Some(v), _) => r["result"] = v,
        (_, Some(e)) => r["error"] = e,
        _ => r["result"] = Value::Null,
    }
    let s = serde_json::to_string(&r).unwrap();
    let _ = w.write_all(s.as_bytes());
    let _ = w.write_all(b"\n");
    let _ = w.flush();
}

fn tools_list() -> Value {
    json!({"tools": [
        {
            "name": "scan",
            "title": "Supply-chain scan",
            "description": "Scan local paths for supply-chain attack indicators (Shai-Hulud family, compromised actions, AUR/PyPI/npm campaigns, secrets, typosquats, workflow weaknesses).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "paths": {"type": "array", "items": {"type": "string"}, "description": "directories or files to scan"},
                    "min_severity": {"type": "string", "enum": ["info","low","medium","high","critical"], "description": "minimum reported severity"},
                    "include_git": {"type": "boolean", "description": "also scan .git internals (worm branches/hooks)"},
                    "diff": {"type": "string", "description": "only files changed vs this git ref (PR mode)"}
                },
                "required": ["paths"]
            },
            "outputSchema": {"type": "object"}
        },
        {
            "name": "scan_system",
            "title": "System indicator scan",
            "description": "Scan this machine: /tmp, systemd units, shell rc files, autostart, ~/.local/bin, pacman foreign packages vs known-compromised lists.",
            "inputSchema": {"type": "object", "properties": {}},
            "outputSchema": {"type": "object"}
        },
        {
            "name": "list_rules",
            "title": "List rules",
            "description": "List all loaded detection rules with id, severity, description.",
            "inputSchema": {"type": "object", "properties": {
                "ruleset": {"type": "string", "description": "filter to one ruleset"}
            }},
            "outputSchema": {"type": "object"}
        },
        {
            "name": "intel",
            "title": "Threat intel lookup",
            "description": "Look up an IP, domain, URL, or file hash in OTX, ThreatFox, Feodo Tracker, and CIRCL.",
            "inputSchema": {
                "type": "object",
                "properties": {"indicator": {"type": "string"}},
                "required": ["indicator"]
            },
            "outputSchema": {"type": "object"}
        },
        {
            "name": "store_search",
            "title": "Search stored records",
            "description": "Search saved scan and intel records.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"]
            },
            "outputSchema": {"type": "object"}
        },
        {
            "name": "supply",
            "title": "Supply chain inventory",
            "description": "Count pinned packages from lockfiles under a path, including nested dependencies.",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"]
            },
            "outputSchema": {"type": "object"}
        },
        {"name": "stego", "title": "Steganography signals", "description": "Look for appended payloads and zero-width text channels.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}, "outputSchema": {"type": "object"}},
        {"name": "codec", "title": "Base64 and base32", "description": "Encode or decode base64 or base32.", "inputSchema": {"type": "object", "properties": {"mode": {"type": "string"}, "alphabet": {"type": "string"}, "text": {"type": "string"}}, "required": ["mode", "alphabet", "text"]}, "outputSchema": {"type": "object"}},
        {"name": "style", "title": "Style distance", "description": "Pairwise prose or code style distance. A lead, not an identification.", "inputSchema": {"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "string"}, "kind": {"type": "string"}}, "required": ["a", "b"]}, "outputSchema": {"type": "object"}},
        {"name": "account", "title": "Forge account", "description": "Public GitHub or GitLab account metadata.", "inputSchema": {"type": "object", "properties": {"forge": {"type": "string"}, "login": {"type": "string"}, "host": {"type": "string"}}, "required": ["forge", "login"]}, "outputSchema": {"type": "object"}},
        {"name": "socials", "title": "Social and resume links", "description": "Extract social and resume links from a public page, including link-in-bio hubs.", "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}, "outputSchema": {"type": "object"}},
        {"name": "feed", "title": "Feed search", "description": "Fetch an RSS, Atom, or JSON feed and optionally search it.", "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}, "query": {"type": "string"}}, "required": ["url"]}, "outputSchema": {"type": "object"}},
        {"name": "gitmeta", "title": "Git identity", "description": "Local git names and emails, or a public .git/HEAD check that does not download objects.", "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}, "outputSchema": {"type": "object"}},
        {"name": "keybase", "title": "Keybase profile and devices", "description": "Public Keybase profile, identity proofs, and the account device list with created and last-updated dates.", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}, "outputSchema": {"type": "object"}},
        {"name": "steam", "title": "Steam profile", "description": "Public Steam community profile: persona, identity, level, counts, name history, and recent games.", "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}, "outputSchema": {"type": "object"}},
        {"name": "bluesky", "title": "Bluesky profile", "description": "Public Bluesky profile via the appview: DID, counts, self-labels, and verification.", "inputSchema": {"type": "object", "properties": {"handle": {"type": "string"}}, "required": ["handle"]}, "outputSchema": {"type": "object"}},
        {"name": "mastodon", "title": "Mastodon account", "description": "Public Mastodon account: profile, counts, flags, and profile fields.", "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}, "instance": {"type": "string"}}, "required": ["target"]}, "outputSchema": {"type": "object"}},
        {"name": "reddit", "title": "Reddit account history", "description": "Public Reddit account history from the Arctic Shift archive: karma, archive counts, recent posts and comments.", "inputSchema": {"type": "object", "properties": {"user": {"type": "string"}}, "required": ["user"]}, "outputSchema": {"type": "object"}},
        {"name": "youtube", "title": "YouTube video or channel", "description": "Public YouTube video or channel: oembed metadata, subscribers, verification, and recent uploads.", "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}, "outputSchema": {"type": "object"}},
        {"name": "tiktok", "title": "TikTok video or profile", "description": "Public TikTok video or profile: oembed metadata and page account data.", "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}, "outputSchema": {"type": "object"}},
        {"name": "lemmy", "title": "Lemmy account", "description": "Public Lemmy account: person view, counts, moderated communities, recent posts and comments.", "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}, "instance": {"type": "string"}}, "required": ["target"]}, "outputSchema": {"type": "object"}},
        {"name": "gharchive", "title": "GHArchive event filter", "description": "Filter the GHArchive public event firehose for an org, user, or repo. Returns push SHAs, public flips, and ref creates/deletes.", "inputSchema": {"type": "object", "properties": {"org": {"type": "string"}, "user": {"type": "string"}, "repo": {"type": "string"}, "hours": {"type": "integer"}, "events": {"type": "string"}}}, "outputSchema": {"type": "object"}}
    ]})
}

fn call_tool(
    name: &str,
    args: &Value,
    rules: &[CompiledRule],
    opts: &ScanOptions,
) -> Result<Value, Value> {
    match name {
        "scan" => {
            let paths: Vec<std::path::PathBuf> = args["paths"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(Into::into))
                        .collect()
                })
                .ok_or_else(|| err(-32602, "missing paths"))?;
            let min = args["min_severity"].as_str().map(|s| match s {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                _ => Severity::Info,
            });
            let mut o = opts.clone();
            if args["include_git"].as_bool().unwrap_or(false) {
                o.include_git = true;
            }
            let mut report = crate::finding::Report::new();
            for p in &paths {
                let label = p.display().to_string();
                let (mut findings, files) = if let Some(base) = args["diff"].as_str() {
                    let rels = crate::changed_files_pub(p, base);
                    crate::scan::scan_selected(p, &rels, &label, rules, &o)
                } else {
                    crate::scan::scan_root(p, &label, rules, &o)
                };
                report.files_scanned += files;
                report.targets.push(crate::finding::TargetStat {
                    label,
                    files,
                    findings: findings.len(),
                });
                report.findings.append(&mut findings);
            }
            report.finalize(min.unwrap_or(Severity::Info));
            let v = serde_json::to_value(&report).unwrap_or(json!({}));
            Ok(tool_result(&serde_json::to_string_pretty(&v).unwrap(), v))
        }
        "scan_system" => {
            let mut report = crate::finding::Report::new();
            crate::scan_system_pub(&mut report, rules, opts, 0);
            report.finalize(Severity::Info);
            let v = serde_json::to_value(&report).unwrap_or(json!({}));
            Ok(tool_result(&serde_json::to_string_pretty(&v).unwrap(), v))
        }
        "intel" => {
            let indicator = args["indicator"].as_str().unwrap_or("");
            match crate::osint::scan_intel(indicator) {
                Ok(report) => {
                    let v = serde_json::to_value(&report).unwrap_or(json!({}));
                    Ok(tool_result(&serde_json::to_string_pretty(&v).unwrap(), v))
                }
                Err(e) => Err(err(-32602, &e)),
            }
        }
        "store_search" => {
            let query = args["query"].as_str().unwrap_or("");
            match crate::db::search(query, 50) {
                Ok(rows) => {
                    let v = serde_json::json!({"records": rows});
                    Ok(tool_result(&serde_json::to_string_pretty(&v).unwrap(), v))
                }
                Err(e) => Err(err(-32603, &e)),
            }
        }
        "supply" => {
            let path = args["path"].as_str().unwrap_or(".");
            match crate::supply::scan(std::path::Path::new(path)) {
                Ok(report) => {
                    let v = serde_json::to_value(&report).unwrap_or(json!({}));
                    Ok(tool_result(&serde_json::to_string_pretty(&v).unwrap(), v))
                }
                Err(e) => Err(err(-32602, &e)),
            }
        }
        "stego" => osint_tool(crate::stego::scan(std::path::Path::new(
            args["path"].as_str().unwrap_or("."),
        ))),
        "codec" => osint_tool(crate::codec::scan(
            args["mode"].as_str().unwrap_or(""),
            args["alphabet"].as_str().unwrap_or(""),
            args["text"].as_str().unwrap_or(""),
        )),
        "style" => osint_tool(crate::style::scan(
            std::path::Path::new(args["a"].as_str().unwrap_or("")),
            std::path::Path::new(args["b"].as_str().unwrap_or("")),
            args["kind"].as_str(),
        )),
        "account" => osint_tool(crate::osint::scan_account(
            args["forge"].as_str().unwrap_or(""),
            args["login"].as_str().unwrap_or(""),
            args["host"].as_str(),
        )),
        "socials" => osint_tool(crate::osint::scan_socials(
            args["url"].as_str().unwrap_or(""),
        )),
        "keybase" => osint_tool(crate::osint::scan_keybase(
            args["name"].as_str().unwrap_or(""),
        )),
        "steam" => osint_tool(crate::osint::scan_steam(
            args["target"].as_str().unwrap_or(""),
        )),
        "bluesky" => osint_tool(crate::osint::scan_bluesky(
            args["handle"].as_str().unwrap_or(""),
        )),
        "mastodon" => osint_tool(crate::osint::scan_mastodon(
            args["target"].as_str().unwrap_or(""),
            args["instance"].as_str().unwrap_or("mastodon.social"),
        )),
        "reddit" => osint_tool(crate::osint::scan_reddit(
            args["user"].as_str().unwrap_or(""),
        )),
        "youtube" => osint_tool(crate::osint::scan_youtube(
            args["target"].as_str().unwrap_or(""),
        )),
        "tiktok" => osint_tool(crate::osint::scan_tiktok(
            args["target"].as_str().unwrap_or(""),
        )),
        "lemmy" => osint_tool(crate::osint::scan_lemmy(
            args["target"].as_str().unwrap_or(""),
            args["instance"].as_str(),
        )),
        "feed" => osint_tool(crate::osint::scan_feed(
            args["url"].as_str().unwrap_or(""),
            args["query"].as_str(),
        )),
        "gitmeta" => osint_tool(crate::osint::scan_gitmeta(
            args["target"].as_str().unwrap_or("."),
        )),
        "gharchive" => {
            let sel = match (
                args["org"].as_str(),
                args["user"].as_str(),
                args["repo"].as_str(),
            ) {
                (Some(n), None, None) => crate::osint::GhSel::Org(n.to_string()),
                (None, Some(n), None) => crate::osint::GhSel::User(n.to_string()),
                (None, None, Some(n)) => crate::osint::GhSel::Repo(n.to_string()),
                _ => return Err(err(-32602, "pass exactly one of org, user, repo")),
            };
            let hours = args["hours"].as_u64().unwrap_or(3) as u32;
            osint_tool(crate::osint::scan_gharchive(
                &sel,
                hours,
                args["events"].as_str(),
            ))
        }
        "list_rules" => {
            let filter = args["ruleset"].as_str();
            let list: Vec<Value> = rules.iter()
                .filter(|r| filter.is_none_or(|f| r.set == f))
                .map(|r| json!({"id": r.id, "ruleset": r.set, "severity": r.severity.to_string(), "description": r.description}))
                .collect();
            let v = json!({"count": list.len(), "rules": list});
            Ok(tool_result(&serde_json::to_string_pretty(&v).unwrap(), v))
        }
        other => Err(err(-32602, &format!("unknown tool: {other}"))),
    }
}

fn osint_tool(result: Result<crate::osint::Report, String>) -> Result<Value, Value> {
    match result {
        Ok(report) => {
            let v = serde_json::to_value(&report).unwrap_or(json!({}));
            Ok(tool_result(
                &serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into()),
                v,
            ))
        }
        Err(e) => Err(err(-32602, &e)),
    }
}

fn tool_result(text: &str, structured: Value) -> Value {
    json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured
    })
}
