// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! GHArchive public event firehose.
//! Downloads hourly dumps from data.gharchive.org and keeps the events
//! that touch one org, user, or repo. Push SHAs stay in the archive after
//! a force push or branch delete, which is what makes the archive worth
//! scanning for abandoned secrets. The same row extraction backs the
//! GitHub events feed used by `argus account`.

use super::{Hit, Report, Status};
use flate2::read::GzDecoder;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BASE: &str = "https://data.gharchive.org";
const MAX_HOURS: u32 = 168;
const MAX_KEEP_PER_HOUR: usize = 20_000;
const EVIDENCE_CAP: usize = 40;
const WORKERS: usize = 4;

/// Who to keep events for.
#[derive(Debug, Clone)]
pub enum Sel {
    /// Org login: matches the event org field or the repo owner.
    Org(String),
    /// User login: matches the actor or the repo owner.
    User(String),
    /// owner/name: matches the repo name exactly.
    Repo(String),
}

impl Sel {
    fn label(&self) -> String {
        match self {
            Sel::Org(n) => format!("org:{n}"),
            Sel::User(n) => format!("user:{n}"),
            Sel::Repo(n) => format!("repo:{n}"),
        }
    }

    /// Lowercase needle for the cheap line prefilter. Parsing decides.
    fn needle(&self) -> String {
        match self {
            Sel::Org(n) | Sel::User(n) => n.to_ascii_lowercase(),
            Sel::Repo(r) => r.to_ascii_lowercase(),
        }
    }

    fn matches(&self, ev: &Value) -> bool {
        let repo = ev
            .get("repo")
            .and_then(|r| r.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("");
        let owner = repo.split('/').next().unwrap_or("");
        match self {
            Sel::Repo(r) => repo.eq_ignore_ascii_case(r),
            Sel::Org(n) => {
                owner.eq_ignore_ascii_case(n)
                    || ev
                        .get("org")
                        .and_then(|o| o.get("login"))
                        .and_then(|l| l.as_str())
                        .is_some_and(|l| l.eq_ignore_ascii_case(n))
            }
            Sel::User(n) => {
                owner.eq_ignore_ascii_case(n)
                    || ev
                        .get("actor")
                        .and_then(|a| a.get("login"))
                        .and_then(|l| l.as_str())
                        .is_some_and(|l| l.eq_ignore_ascii_case(n))
            }
        }
    }
}

/// One event compressed to the fields a report keeps.
#[derive(Debug)]
pub(crate) struct Ev {
    pub kind: String,
    pub repo: String,
    pub actor: String,
    pub created: String,
    pub git_ref: String,
    pub head: String,
    pub before: String,
    pub action: String,
    pub detail: String,
    /// "name \<email\>" commit identities inside a PushEvent payload.
    /// GHArchive drops or truncates these at times; empty is normal.
    pub emails: Vec<String>,
}

impl Ev {
    pub(crate) fn from(ev: &Value) -> Ev {
        let payload = ev.get("payload");
        let get = |k: &str| {
            payload
                .and_then(|p| p.get(k))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        let kind = ev
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        let detail = match kind.as_str() {
            "ForkEvent" => payload
                .and_then(|p| p.get("forkee"))
                .and_then(|f| f.get("full_name"))
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string(),
            "CreateEvent" => {
                let t = get("ref_type");
                if t == "repository" {
                    "new repository".to_string()
                } else {
                    t
                }
            }
            "DeleteEvent" => get("ref_type"),
            "ReleaseEvent" => payload
                .and_then(|p| p.get("release"))
                .and_then(|r| r.get("tag_name"))
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string(),
            "PullRequestEvent" | "IssuesEvent" => payload
                .and_then(|p| p.get("number"))
                .map(|n| format!("#{n}"))
                .unwrap_or_default(),
            "MemberEvent" => payload
                .and_then(|p| p.get("member"))
                .and_then(|m| m.get("login"))
                .and_then(|l| l.as_str())
                .unwrap_or("")
                .to_string(),
            _ => String::new(),
        };
        let emails: Vec<String> = payload
            .and_then(|p| p.get("commits"))
            .and_then(|c| c.as_array())
            .map(|arr| {
                let mut seen: Vec<String> = Vec::new();
                for c in arr.iter().take(30) {
                    let author = c.get("author");
                    let mail = author
                        .and_then(|a| a.get("email"))
                        .and_then(|e| e.as_str())
                        .unwrap_or("")
                        .trim();
                    let name = author
                        .and_then(|a| a.get("name"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .trim();
                    if mail.is_empty() {
                        continue;
                    }
                    let id = if name.is_empty() {
                        mail.to_string()
                    } else {
                        format!("{name} <{mail}>")
                    };
                    if !seen.contains(&id) {
                        seen.push(id);
                    }
                }
                seen
            })
            .unwrap_or_default();
        Ev {
            kind,
            repo: ev
                .get("repo")
                .and_then(|r| r.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string(),
            actor: ev
                .get("actor")
                .and_then(|a| a.get("display_login").or_else(|| a.get("login")))
                .and_then(|l| l.as_str())
                .unwrap_or("")
                .to_string(),
            created: ev
                .get("created_at")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string(),
            git_ref: get("ref"),
            head: get("head"),
            before: get("before"),
            action: get("action"),
            detail,
            emails,
        }
    }

    fn row(&self) -> Value {
        let mut v = json!({
            "kind": self.kind,
            "repo": self.repo,
            "actor": self.actor,
            "created": self.created,
        });
        if !self.git_ref.is_empty() {
            v["ref"] = json!(self.git_ref);
        }
        if !self.head.is_empty() {
            v["head"] = json!(self.head);
        }
        if !self.before.is_empty() {
            v["before"] = json!(self.before);
        }
        if !self.action.is_empty() {
            v["action"] = json!(self.action);
        }
        if !self.detail.is_empty() {
            v["detail"] = json!(self.detail);
        }
        if !self.emails.is_empty() {
            v["emails"] = json!(self.emails);
        }
        v
    }
}

/// Rows for the GitHub events API, same schema as the archive.
pub(crate) fn events_from_values(arr: &[Value]) -> Vec<Ev> {
    arr.iter().map(Ev::from).collect()
}

/// Shared summary hit for a set of events (API feed or archive filter).
pub(crate) fn events_hit(evs: &[Ev], module: &str) -> Hit {
    if evs.is_empty() {
        return Hit::new(module, Status::Absent, "no public events", None);
    }
    let mut by_kind: Vec<(&str, usize)> = Vec::new();
    for ev in evs {
        match by_kind.iter_mut().find(|(k, _)| *k == ev.kind) {
            Some((_, n)) => *n += 1,
            None => by_kind.push((ev.kind.as_str(), 1)),
        }
    }
    by_kind.sort_by_key(|a| std::cmp::Reverse(a.1));
    let pushes: Vec<Value> = evs
        .iter()
        .filter(|e| e.kind == "PushEvent")
        .take(10)
        .map(|e| e.row())
        .collect();
    let summary = format!(
        "{} public event(s): {}",
        evs.len(),
        by_kind
            .iter()
            .take(6)
            .map(|(k, n)| format!("{n}x{}", k.trim_end_matches("Event")))
            .collect::<Vec<_>>()
            .join(", ")
    );
    Hit::new(
        module,
        Status::Confirmed,
        summary,
        Some(json!({
            "total": evs.len(),
            "by_kind": by_kind.iter().map(|(k, n)| json!({"kind": k, "count": n})).collect::<Vec<_>>(),
            "pushes": pushes,
        })),
    )
}

struct Kinds(Vec<String>);

impl Kinds {
    /// "push" and "PushEvent" both normalize to "pushevent".
    fn parse(raw: &str) -> Kinds {
        let mut out = Vec::new();
        for part in raw.split(',') {
            let mut norm: String = part
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .flat_map(|c| c.to_lowercase())
                .collect();
            if norm.is_empty() {
                continue;
            }
            if !norm.ends_with("event") {
                norm.push_str("event");
            }
            out.push(norm);
        }
        Kinds(out)
    }

    fn keeps(&self, kind: &str) -> bool {
        if self.0.is_empty() {
            return true;
        }
        let norm: String = kind
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(|c| c.to_lowercase())
            .collect();
        self.0.contains(&norm)
    }
}

struct HourOut {
    stamp: String,
    events: Vec<Ev>,
    bytes: u64,
    scanned: u64,
    error: Option<String>,
    truncated: bool,
}

fn agent() -> ureq::Agent {
    let config = ureq::config::Config::builder()
        .timeout_global(Some(Duration::from_secs(180)))
        .http_status_as_error(false)
        .user_agent(concat!("argus/", env!("CARGO_PKG_VERSION")))
        .build();
    ureq::Agent::new_with_config(config)
}

/// Days-from-civil inverse (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

/// The `hours` most recent completed hour stamps, newest first.
fn hour_stamps(hours: u32) -> Vec<String> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let mut out = Vec::new();
    // The current hour is still being collected by GHArchive. Start at
    // the last completed hour and walk back.
    let mut t = (secs / 3600 - 1) * 3600;
    for _ in 0..hours {
        let days = t.div_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        let h = t.rem_euclid(86_400) / 3600;
        out.push(format!("{y:04}-{m:02}-{d:02}-{h}"));
        t -= 3600;
    }
    out
}

fn fetch_hour(agent: &ureq::Agent, stamp: &str, sel: &Sel, kinds: &Kinds) -> HourOut {
    let url = format!("{BASE}/{stamp}.json.gz");
    let mut out = HourOut {
        stamp: stamp.to_string(),
        events: Vec::new(),
        bytes: 0,
        scanned: 0,
        error: None,
        truncated: false,
    };
    let needle = sel.needle();
    let mut resp = match agent.get(&url).call() {
        Ok(r) => r,
        Err(e) => {
            out.error = Some(format!("{e}").chars().take(140).collect());
            return out;
        }
    };
    if resp.status().as_u16() == 404 {
        out.error = Some("hour file not published".into());
        return out;
    }
    if resp.status().as_u16() != 200 {
        out.error = Some(format!("HTTP {}", resp.status().as_u16()));
        return out;
    }
    let gz = GzDecoder::new(resp.body_mut().as_reader());
    let reader = BufReader::with_capacity(256 * 1024, gz);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                out.error = Some(format!("decompress: {e}").chars().take(140).collect());
                break;
            }
        };
        out.bytes += line.len() as u64;
        out.scanned += 1;
        if !line.to_ascii_lowercase().contains(&needle) {
            continue;
        }
        let Ok(ev) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if !sel.matches(&ev) {
            continue;
        }
        let kind = ev.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if !kinds.keeps(kind) {
            continue;
        }
        if out.events.len() >= MAX_KEEP_PER_HOUR {
            out.truncated = true;
            continue;
        }
        out.events.push(Ev::from(&ev));
    }
    out
}

fn hit_list(module: &str, noun: &str, evs: Vec<&&Ev>, empty: &str) -> Hit {
    if evs.is_empty() {
        return Hit::new(module, Status::Absent, empty, None);
    }
    let rows: Vec<Value> = evs.iter().take(EVIDENCE_CAP).map(|e| e.row()).collect();
    Hit::new(
        module,
        Status::Confirmed,
        format!(
            "{} {noun}{}",
            evs.len(),
            if evs.len() > EVIDENCE_CAP {
                format!(", showing {EVIDENCE_CAP}")
            } else {
                String::new()
            }
        ),
        Some(json!({"count": evs.len(), "events": rows})),
    )
}

/// Report plus the matched events (revive --fetch needs the SHAs).
pub fn collect(
    sel: &Sel,
    hours: u32,
    kinds_raw: Option<&str>,
) -> Result<(Report, Vec<Ev>), String> {
    let t0 = Instant::now();
    let hours = hours.clamp(1, MAX_HOURS);
    let name = sel.needle();
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/')
    {
        return Err("name must be letters, digits, dot, underscore, hyphen, or slash".into());
    }
    let kinds = Kinds::parse(kinds_raw.unwrap_or(""));
    let stamps = hour_stamps(hours);
    let agent = agent();
    let next = AtomicUsize::new(0);
    let results = std::thread::scope(|s| {
        let mut handles = Vec::new();
        for _ in 0..WORKERS.min(stamps.len()) {
            let stamps = &stamps;
            let next = &next;
            let agent = &agent;
            let kinds = &kinds;
            handles.push(s.spawn(move || {
                let mut mine = Vec::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= stamps.len() {
                        break;
                    }
                    let stamp = stamps[i].clone();
                    mine.push((i, fetch_hour(agent, &stamp, sel, kinds)));
                }
                mine
            }));
        }
        let mut done: Vec<(usize, HourOut)> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect();
        done.sort_by_key(|(i, _)| *i);
        done.into_iter().map(|(_, o)| o).collect::<Vec<_>>()
    });

    let mut ok_hours = 0usize;
    let mut scanned_lines = 0u64;
    let mut bytes = 0u64;
    let mut hour_notes = Vec::new();
    let mut any_truncated = false;
    for o in &results {
        bytes += o.bytes;
        scanned_lines += o.scanned;
        if let Some(e) = &o.error {
            hour_notes.push(json!({"hour": o.stamp, "status": "error", "error": e}));
        } else {
            ok_hours += 1;
            hour_notes.push(json!({"hour": o.stamp, "status": "ok", "matched": o.events.len()}));
        }
        any_truncated |= o.truncated;
    }
    let mut owned: Vec<Ev> = Vec::new();
    for o in results {
        owned.extend(o.events);
    }
    owned.sort_by(|a, b| b.created.cmp(&a.created));
    let all: Vec<&Ev> = owned.iter().collect();

    let mut findings = Vec::new();
    if ok_hours == 0 {
        findings.push(Hit::new(
            "gharchive",
            Status::Error,
            "no GHArchive hour files were reachable",
            Some(json!({"hours": hour_notes})),
        ));
    } else {
        findings.push(Hit::new(
            "gharchive",
            if all.is_empty() {
                Status::Absent
            } else {
                Status::Confirmed
            },
            format!(
                "{} matching event(s) in {ok_hours} hour file(s) ({} MiB scanned){}",
                all.len(),
                bytes / (1024 * 1024),
                if any_truncated { ", capped" } else { "" }
            ),
            Some(json!({
                "selector": sel.label(),
                "events": all.len(),
                "lines": scanned_lines,
                "bytes": bytes,
                "hours": hour_notes,
            })),
        ));
    }

    let pushes: Vec<&&Ev> = all.iter().filter(|e| e.kind == "PushEvent").collect();
    let head_shas: Vec<&str> = {
        let mut seen: Vec<&str> = Vec::new();
        for e in &pushes {
            if !e.head.is_empty() && !seen.contains(&e.head.as_str()) {
                seen.push(e.head.as_str());
            }
        }
        seen
    };
    let mut push_hit = hit_list(
        "gh-push",
        "push event(s)",
        pushes,
        "no pushes in the window",
    );
    if push_hit.status == Status::Confirmed {
        let mut v = push_hit.evidence.take().unwrap_or(json!({}));
        v["head_shas"] = json!(head_shas.iter().take(EVIDENCE_CAP).collect::<Vec<_>>());
        v["note"] =
            json!("before/head SHAs survive force pushes; fetch the repo for dangling commits");
        push_hit.evidence = Some(v);
    }
    findings.push(push_hit);

    findings.push(hit_list(
        "gh-public",
        "repo(s) flipped to public",
        all.iter().filter(|e| e.kind == "PublicEvent").collect(),
        "no repositories flipped to public",
    ));
    findings.push(hit_list(
        "gh-create",
        "creation event(s)",
        all.iter().filter(|e| e.kind == "CreateEvent").collect(),
        "no ref or repo creations",
    ));
    findings.push(hit_list(
        "gh-delete",
        "deletion event(s)",
        all.iter().filter(|e| e.kind == "DeleteEvent").collect(),
        "no ref deletions",
    ));

    let rest: Vec<&&Ev> = all
        .iter()
        .filter(|e| {
            !matches!(
                e.kind.as_str(),
                "PushEvent" | "PublicEvent" | "CreateEvent" | "DeleteEvent"
            )
        })
        .collect();
    if rest.is_empty() {
        findings.push(Hit::new(
            "gh-kinds",
            Status::Absent,
            "no other event kinds",
            None,
        ));
    } else {
        let mut by_kind: Vec<(&str, usize)> = Vec::new();
        for ev in &rest {
            match by_kind.iter_mut().find(|(k, _)| *k == ev.kind) {
                Some((_, n)) => *n += 1,
                None => by_kind.push((ev.kind.as_str(), 1)),
            }
        }
        by_kind.sort_by_key(|a| std::cmp::Reverse(a.1));
        findings.push(Hit::new(
            "gh-kinds",
            Status::Confirmed,
            format!(
                "other kinds: {}",
                by_kind
                    .iter()
                    .map(|(k, n)| format!("{n}x{k}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Some(json!({
                "by_kind": by_kind.iter().map(|(k, n)| json!({"kind": k, "count": n})).collect::<Vec<_>>(),
            })),
        ));
    }

    // commit identities seen inside push payloads
    let mut emails: Vec<String> = Vec::new();
    for e in &all {
        for id in &e.emails {
            if !emails.contains(id) {
                emails.push(id.clone());
            }
        }
    }
    if emails.is_empty() {
        findings.push(Hit::new(
            "gh-emails",
            Status::Absent,
            "no commit author identities in the window",
            None,
        ));
    } else {
        findings.push(Hit::new(
            "gh-emails",
            Status::Confirmed,
            format!("{} commit author identit(ies)", emails.len()),
            Some(json!({"emails": emails.iter().take(60).collect::<Vec<_>>()})),
        ));
    }

    Ok((
        Report {
            target: sel.label(),
            kind: "gharchive",
            elapsed_ms: t0.elapsed().as_millis() as u64,
            findings,
        },
        owned,
    ))
}

pub fn scan(sel: &Sel, hours: u32, kinds_raw: Option<&str>) -> Result<Report, String> {
    collect(sel, hours, kinds_raw).map(|(r, _)| r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: &str, repo: &str, actor: &str) -> Value {
        json!({
            "type": kind,
            "actor": {"login": actor, "display_login": actor},
            "repo": {"name": repo},
            "payload": {},
            "created_at": "2026-01-01T00:00:00Z",
        })
    }

    #[test]
    fn org_matches_owner_and_org_field() {
        let sel = Sel::Org("rust-lang".into());
        assert!(sel.matches(&ev("PushEvent", "rust-lang/crates", "someone")));
        let mut with_org = ev("PushEvent", "other/fork", "someone");
        with_org["org"] = json!({"login": "rust-lang"});
        assert!(sel.matches(&with_org));
        assert!(!sel.matches(&ev("PushEvent", "someone/else", "rust-lang-bot")));
    }

    #[test]
    fn user_matches_actor_and_owner() {
        let sel = Sel::User("octocat".into());
        assert!(sel.matches(&ev("PushEvent", "octocat/notes", "octocat")));
        assert!(sel.matches(&ev("IssueCommentEvent", "rust-lang/rfcs", "octocat")));
        assert!(!sel.matches(&ev("PushEvent", "someone/else", "someone")));
    }

    #[test]
    fn repo_matches_exactly() {
        let sel = Sel::Repo("quad4-software/argus".into());
        assert!(sel.matches(&ev("WatchEvent", "quad4-software/argus", "fan")));
        assert!(!sel.matches(&ev("WatchEvent", "quad4-software/other", "fan")));
    }

    #[test]
    fn kinds_normalize_short_names() {
        let k = Kinds::parse("push, PullRequest,PublicEvent");
        assert!(k.keeps("PushEvent"));
        assert!(k.keeps("PullRequestEvent"));
        assert!(k.keeps("PublicEvent"));
        assert!(!k.keeps("DeleteEvent"));
        assert!(Kinds(vec![]).keeps("AnythingEvent"));
    }

    #[test]
    fn civil_roundtrip_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19000), (2022, 1, 8));
        let (y, m, d) = civil_from_days(20_490);
        assert_eq!((y, m, d), (2026, 2, 6));
    }

    #[test]
    fn hour_stamps_look_right() {
        let stamps = hour_stamps(3);
        assert_eq!(stamps.len(), 3);
        for s in &stamps {
            assert!(s.len() == 13 || s.len() == 12, "stamp {s}");
            assert!(s.chars().nth(4) == Some('-') && s.chars().nth(7) == Some('-'));
        }
    }

    #[test]
    fn row_extracts_push_shas() {
        let mut push = ev("PushEvent", "o/r", "act");
        push["payload"] = json!({
            "ref": "refs/heads/main",
            "head": "abc123",
            "before": "def456",
            "size": 2,
        });
        let e = Ev::from(&push);
        assert_eq!(e.head, "abc123");
        assert_eq!(e.before, "def456");
        assert_eq!(e.git_ref, "refs/heads/main");
    }
}
