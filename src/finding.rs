//! Finding and report data model plus text/JSON renderers.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRIT",
            Severity::High => "HIGH",
            Severity::Medium => "MED ",
            Severity::Low => "LOW ",
            Severity::Info => "INFO",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub ruleset: String,
    pub rule_id: String,
    pub severity: Severity,
    /// Scan target label: repo name for remote scans, scanned root for local.
    pub target: String,
    /// Path relative to the scanned root.
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Compromise window (start,end) when the rule tracks a known campaign window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<(String, String)>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TargetStat {
    pub label: String,
    pub files: usize,
    pub findings: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub tool: String,
    pub version: String,
    pub generated_at_unix: u64,
    pub generated_at: String,
    pub targets: Vec<TargetStat>,
    pub files_scanned: usize,
    pub findings: Vec<Finding>,
    pub summary: Summary,
    /// Non-fatal problems (clone failures, unreadable repos, ...).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Summary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
    /// Findings already in the loaded baseline (informational).
    #[serde(default)]
    pub baselined: usize,
}

impl Report {
    pub fn new() -> Self {
        let now = unix_now();
        Report {
            tool: "argus".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            generated_at_unix: now,
            generated_at: iso8601(now),
            ..Default::default()
        }
    }

    /// Recompute summary after all findings are collected. min filters out
    /// findings below the reporting threshold.
    pub fn finalize(&mut self, min: Severity) {
        // deterministic ordering: severity desc, then path/line/rule
        self.findings.sort_by(|a, b| {
            (b.severity as u8)
                .cmp(&(a.severity as u8))
                .then_with(|| a.target.cmp(&b.target))
                .then_with(|| a.path.cmp(&b.path))
                .then_with(|| a.line.cmp(&b.line))
                .then_with(|| a.rule_id.cmp(&b.rule_id))
                .then_with(|| a.excerpt.cmp(&b.excerpt))
                .then_with(|| a.message.cmp(&b.message))
        });
        self.findings.retain(|f| f.severity >= min);
        self.findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(a.path.cmp(&b.path))
                .then(a.line.cmp(&b.line))
        });
        let mut s = Summary::default();
        for f in &self.findings {
            s.total += 1;
            match f.severity {
                Severity::Critical => s.critical += 1,
                Severity::High => s.high += 1,
                Severity::Medium => s.medium += 1,
                Severity::Low => s.low += 1,
                Severity::Info => s.info += 1,
            }
        }
        self.summary = s;
    }

    pub fn worst(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report serialization")
    }

    pub fn to_text(&self, st: &crate::color::Styles) -> String {
        let mut out = String::new();
        let mut last_target: Option<&str> = None;
        for f in &self.findings {
            if last_target != Some(f.target.as_str()) {
                if last_target.is_some() {
                    out.push('\n');
                }
                last_target = Some(&f.target);
                out.push_str(&st.bold(&format!("== {} ==", f.target)));
                out.push('\n');
            }
            let loc = match f.line {
                Some(l) => format!("{}:{}", f.path, l),
                None => f.path.clone(),
            };
            out.push_str(&format!(
                "  {}  {}  {}\n",
                st.severity(f.severity),
                st.cyan(&f.rule_id),
                loc
            ));
            if let Some(ex) = &f.excerpt {
                out.push_str(&format!("        {}\n", st.dim(&truncate(ex.trim(), 160))));
            }
            out.push_str(&format!("        {}\n", f.message));
            if let Some(rem) = &f.remediation {
                out.push_str(&format!("        fix: {}\n", rem));
            }
            if let Some(r) = &f.reference {
                out.push_str(&format!("        ref: {}\n", st.dim(r)));
            }
        }
        let s = &self.summary;
        let n = |sev: Severity, count: usize| -> String {
            let t = format!("{} {}", count, sev);
            if count > 0 {
                st.severity(sev).replace(sev.label(), &t)
            } else {
                st.dim(&t)
            }
        };
        out.push_str(&format!(
            "\n{} {} files, {} targets | {}\n",
            st.bold("Scan:"),
            self.files_scanned,
            self.targets.len(),
            [
                n(Severity::Critical, s.critical),
                n(Severity::High, s.high),
                n(Severity::Medium, s.medium),
                n(Severity::Low, s.low),
                n(Severity::Info, s.info),
            ]
            .join(", "),
        ));
        out
    }

    /// Markdown table, e.g. for GitHub/Gitea/Forgejo/GitLab PR comments.
    pub fn to_markdown(&self) -> String {
        let mut out = String::from("## argus scan\n\n");
        if self.findings.is_empty() {
            out.push_str("No findings.\n\n");
        } else {
            out.push_str("| Severity | Rule | Location | Detail |\n|---|---|---|---|\n");
            for f in &self.findings {
                let loc = match f.line {
                    Some(l) => format!("`{}:{}`", f.path, l),
                    None => format!("`{}`", f.path),
                };
                let msg = f.message.replace('|', "\\|").replace('\n', " ");
                let msg = if msg.len() > 200 {
                    format!("{}...", &msg[..msg.floor_char_boundary(200)])
                } else {
                    msg
                };
                out.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    f.severity, f.rule_id, loc, msg
                ));
            }
            out.push('\n');
        }
        let s = &self.summary;
        out.push_str(&format!(
            "**Scan** - {} files, {} targets | {} crit, {} high, {} med, {} low, {} info\n",
            self.files_scanned,
            self.targets.len(),
            s.critical,
            s.high,
            s.medium,
            s.low,
            s.info
        ));
        if !self.errors.is_empty() {
            out.push_str(&format!(
                "\n**{} scan errors** (see logs).\n",
                self.errors.len()
            ));
        }
        out
    }

    /// Single-file HTML report: severity cards, filters, grouped findings.
    /// Self-contained (inline css/js), safe for email/wiki publishing.
    pub fn to_html(&self) -> String {
        fn esc(s: &str) -> String {
            s.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
        }
        let s = &self.summary;
        let mut rows = String::new();
        for f in &self.findings {
            let loc = match f.line {
                Some(l) => format!("{}:{}", f.path, l),
                None => f.path.clone(),
            };
            let ex = f
                .excerpt
                .as_deref()
                .map(|e| format!("<div class=ex>{}</div>", esc(&e[..e.len().min(300)])))
                .unwrap_or_default();
            let rem = f
                .remediation
                .as_deref()
                .map(|r| format!("<div class=rem><b>fix:</b> {}</div>", esc(r)))
                .unwrap_or_default();
            rows.push_str(&format!(
                "<tr class=\"row sev-{}\"><td><span class=\"badge {}\">{}</span></td><td class=rid>{}</td><td class=tgt>{}</td><td class=loc title=\"{}\">{}</td><td>{}{}{}</td></tr>\n",
                f.severity.to_string().to_lowercase(),
                f.severity.to_string().to_lowercase(),
                f.severity,
                esc(&f.rule_id),
                esc(&f.target),
                esc(&loc),
                esc(&loc),
                esc(&f.message),
                ex,
                rem
            ));
        }
        let errs = if self.errors.is_empty() {
            String::new()
        } else {
            format!(
                "<h2>Scan errors ({})</h2><ul>{}</ul>",
                self.errors.len(),
                self.errors
                    .iter()
                    .map(|e| format!("<li><code>{}</code></li>", esc(e)))
                    .collect::<Vec<_>>()
                    .join("")
            )
        };
        format!(
            r##"<!DOCTYPE html><html><head><meta charset=utf-8>
<title>argus report - {}</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root {{ --bg:#0d1117; --panel:#161b22; --fg:#e6edf3; --dim:#8b949e; --crit:#ff7b72; --high:#ffa657; --med:#f2cc60; --low:#79c0ff; --info:#8b949e; }}
* {{ box-sizing:border-box }} body {{ background:var(--bg); color:var(--fg); font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; margin:0; padding:24px; }}
h1 {{ font-size:22px }} .sub {{ color:var(--dim); margin-bottom:18px }}
.cards {{ display:flex; gap:12px; flex-wrap:wrap; margin:16px 0 }}
.card {{ background:var(--panel); border-radius:8px; padding:12px 18px; min-width:110px; cursor:pointer; border:1px solid #30363d }}
.card .n {{ font-size:26px; font-weight:700 }} .card small {{ color:var(--dim); display:block }}
.card.crit .n {{ color:var(--crit) }} .card.high .n {{ color:var(--high) }} .card.med .n {{ color:var(--med) }} .card.low .n {{ color:var(--low) }} .card.info .n {{ color:var(--info) }}
.card.off {{ opacity:.35 }}
#q {{ width:100%; padding:8px 12px; background:var(--panel); border:1px solid #30363d; border-radius:6px; color:var(--fg); margin-bottom:12px }}
table {{ width:100%; border-collapse:collapse; background:var(--panel); border-radius:8px; overflow:hidden }}
th {{ text-align:left; color:var(--dim); padding:8px; border-bottom:1px solid #30363d; font-weight:500 }}
td {{ padding:8px; border-bottom:1px solid #21262d; vertical-align:top }}
tr.row:hover {{ background:#1c2128 }}
.badge {{ padding:2px 8px; border-radius:10px; font-size:11px; font-weight:600; text-transform:uppercase }}
.badge.critical {{ background:#da3633; color:#fff }} .badge.high {{ background:#9e6a03; color:#fff }}
.badge.medium {{ background:#7a5d00; color:#fff }} .badge.low {{ background:#1158c7; color:#fff }}
.badge.info {{ background:#30363d; color:var(--dim) }}
.rid {{ font-family:ui-monospace,monospace; color:#79c0ff; white-space:nowrap }}
.tgt {{ color:var(--dim) }} .loc {{ font-family:ui-monospace,monospace; font-size:12px; max-width:280px; overflow:hidden; text-overflow:ellipsis }}
.ex {{ font-family:ui-monospace,monospace; font-size:12px; color:#ffa657; background:#21262d; padding:4px 8px; border-radius:4px; margin-top:4px; white-space:pre-wrap; word-break:break-all }}
.rem {{ color:#7ee787; font-size:12px; margin-top:4px }}
footer {{ color:var(--dim); margin-top:16px; font-size:12px }}
</style></head><body>
<h1>argus report</h1>
<div class=sub>generated {} | {} files | {} targets</div>
<div class=cards>
<div class="card crit" data-sev=critical onclick=tog(this)><div class=n>{}</div><small>critical</small></div>
<div class="card high" data-sev=high onclick=tog(this)><div class=n>{}</div><small>high</small></div>
<div class="card med" data-sev=medium onclick=tog(this)><div class=n>{}</div><small>medium</small></div>
<div class="card low" data-sev=low onclick=tog(this)><div class=n>{}</div><small>low</small></div>
<div class="card info" data-sev=info onclick=tog(this)><div class=n>{}</div><small>info</small></div>
</div>
<input id=q placeholder="filter findings (rule, path, message)..." oninput=fil()>
<table><thead><tr><th></th><th>rule</th><th>target</th><th>location</th><th>detail</th></tr></thead><tbody>
{}</tbody></table>
{}
<footer>argus {} - supply-chain and repository security scanner</footer>
<script>
const rows=[...document.querySelectorAll('tr.row')];
function tog(c){{c.classList.toggle('off');fil();}}
function fil(){{
 const q=document.getElementById('q').value.toLowerCase();
 const hidden=new Set([...document.querySelectorAll('.card.off')].map(c=>c.dataset.sev));
 rows.forEach(r=>{{
  const sev=r.className.split('sev-')[1].split(' ')[0];
  const ok=!hidden.has(sev)&&(!q||r.textContent.toLowerCase().includes(q));
  r.style.display=ok?'':'none';
 }});
}}
</script></body></html>"##,
            esc(&self.generated_at),
            self.generated_at,
            self.files_scanned,
            self.targets.len(),
            s.critical,
            s.high,
            s.medium,
            s.low,
            s.info,
            rows,
            errs,
            self.version
        )
    }

    /// SARIF 2.1.0 for GitHub code scanning / generic tooling.
    pub fn to_sarif(&self) -> String {
        let mut seen_rules = std::collections::BTreeMap::new();
        for f in &self.findings {
            seen_rules
                .entry(f.rule_id.clone())
                .or_insert(serde_json::json!({
                    "id": f.rule_id,
                    "name": f.rule_id,
                    "shortDescription": {"text": f.message.chars().take(120).collect::<String>()},
                    "properties": {"ruleset": f.ruleset, "severity": f.severity.to_string()}
                }));
        }
        let results: Vec<serde_json::Value> = self
            .findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "ruleId": f.rule_id,
                    "level": match f.severity {
                        Severity::Critical | Severity::High => "error",
                        Severity::Medium | Severity::Low => "warning",
                        Severity::Info => "note",
                    },
                    "message": {"text": f.message},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path, "uriBaseId": "SRCROOT"},
                            "region": {"startLine": f.line.unwrap_or(1)}
                        }
                    }],
                    "partialFingerprints": {
                        "argus/v1": format!("{}|{}|{}", f.rule_id, f.path, f.line.unwrap_or(0))
                    }
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {
                    "name": "argus",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/Quad4-Software/argus",
                    "rules": seen_rules.into_values().collect::<Vec<_>>()
                }},
                "results": results
            }]
        }))
        .expect("sarif serialization")
    }

    /// Code Climate JSON - consumed by GitLab as a codequality report artifact.
    pub fn to_codeclimate(&self) -> String {
        let issues: Vec<serde_json::Value> = self
            .findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "type": "issue",
                    "check_name": f.rule_id,
                    "description": f.message,
                    "categories": ["Security"],
                    "severity": match f.severity {
                        Severity::Critical => "blocker",
                        Severity::High => "critical",
                        Severity::Medium => "major",
                        Severity::Low => "minor",
                        Severity::Info => "info",
                    },
                    "location": {"path": f.path, "lines": {"begin": f.line.unwrap_or(1)}},
                    "fingerprint": format!("{:x}", md5ish(&format!("{}|{}|{}", f.rule_id, f.path, f.line.unwrap_or(0))))
                })
            })
            .collect();
        serde_json::to_string_pretty(&issues).expect("codeclimate serialization")
    }

    /// CI annotations: ::error/::warning/::notice lines understood by GitHub
    /// Actions and Forgejo/Gitea act_runner.
    pub fn to_annotations(&self) -> String {
        let mut out = String::new();
        for f in &self.findings {
            let kind = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium | Severity::Low => "warning",
                Severity::Info => "notice",
            };
            let msg = f
                .message
                .replace('%', "%25")
                .replace('\n', "%0A")
                .replace('\r', "%0D")
                .replace(':', "%3A")
                .replace(',', "%2C");
            match f.line {
                Some(l) => out.push_str(&format!(
                    "::{kind} file={},line={},title={}::{}\n",
                    f.path, l, f.rule_id, msg
                )),
                None => out.push_str(&format!(
                    "::{kind} file={},title={}::{}\n",
                    f.path, f.rule_id, msg
                )),
            }
        }
        out
    }
}

fn md5ish(s: &str) -> u64 {
    // FNV-1a 64 - stable fingerprint without pulling a crypto dep.
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Unix epoch seconds -> "YYYY-MM-DDTHH:MM:SSZ" (Hinnant civil-from-days).
pub fn iso8601_pub() -> String {
    iso8601(unix_now())
}

pub fn iso8601(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = if mo <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", yr, mo, d, h, m, s)
}
