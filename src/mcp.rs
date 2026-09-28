//! MCP server: Model Context Protocol 2025-06-18 over stdio (NDJSON JSON-RPC).
//! Exposes argus as agent tools. Configure a client with:
//!   {"mcpServers": {"argus": {"command": "argus", "args": ["mcp"]}}}

use crate::finding::Severity;
use crate::rules::CompiledRule;
use crate::scan::ScanOptions;
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::process::ExitCode;

const PROTOCOL: &str = "2025-06-18";

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
            "initialize" => Some(Ok(json!({
                "protocolVersion": PROTOCOL,
                "capabilities": {"tools": {"listChanged": false}},
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
        }
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

fn tool_result(text: &str, structured: Value) -> Value {
    json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured
    })
}
