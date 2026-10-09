// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

use crate::cli;
use crate::cli::Cli;
use crate::cmd::deps::collect_deps;
use crate::cmd::*;
use crate::color::{ColorMode, Styles};
use crate::emit;
use crate::finding::{Finding, Report, Severity};
use crate::provider::RepoSpec;
use crate::scan::ScanOptions;
use crate::{
    agentwatch, baseline, clone, config, http, osv, provider, registry, rules, scan, watch,
};
use std::path::Path;
use std::process::ExitCode;

/// Repo-relative files changed between two commits in a workdir clone.
/// None on any failure - callers fall back to a full scan.
pub(crate) fn delta_files(dest: &Path, old: &str, new: &str) -> Option<Vec<String>> {
    let out = std::process::Command::new("git")
        .args([
            "-C",
            &*dest.to_string_lossy(),
            "diff",
            "--name-only",
            old,
            new,
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let files: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    Some(files)
}

pub(crate) fn head_of(dest: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["-C", &*dest.to_string_lossy(), "rev-parse", "HEAD"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub(crate) fn watch_cmd(
    cli: &Cli,
    a: &cli::WatchArgs,
    cfg: &config::ConfigFile,
    rules: &[rules::CompiledRule],
    opts: &ScanOptions,
) -> Result<ExitCode, String> {
    let mut state = watch::load_state();
    let workdir = a.workdir.clone().unwrap_or_else(|| {
        std::env::home_dir()
            .unwrap_or_else(|| "/tmp".into())
            .join(".local/share/argus/watch-clones")
    });
    std::fs::create_dir_all(&workdir).map_err(|e| e.to_string())?;

    // resolve repo targets
    let (api, env_tok, cfg_tok): (String, &[&str], Option<String>) = match a.forge.as_str() {
        "github" => (
            provider::github::api_base(a.host.as_deref()),
            &["GITHUB_TOKEN", "GH_TOKEN", "ARGUS_TOKEN"][..],
            cfg.tokens.github.clone(),
        ),
        "gitlab" => (
            provider::gitlab::api_base(a.host.as_deref().or(cfg.gitlab.host.as_deref())),
            &["GITLAB_TOKEN", "ARGUS_TOKEN"][..],
            cfg.tokens.gitlab.clone(),
        ),
        "gitea" => (
            a.host
                .clone()
                .or(cfg.gitea.host.clone())
                .map(|h| provider::gitea::api_base(&h))
                .unwrap_or_else(|| "https://codeberg.org/api/v1".into()),
            &["GITEA_TOKEN", "ARGUS_TOKEN"][..],
            cfg.tokens.gitea.clone(),
        ),
        o => return Err(format!("unknown forge {o:?}")),
    };
    let token = config::resolve_token(
        a.token.as_deref(),
        cli.token.as_deref(),
        env_tok,
        cfg_tok.as_deref(),
    );

    let mut repos: Vec<RepoSpec> = Vec::new();
    if !a.repo.is_empty() {
        for r in &a.repo {
            let url = match a.forge.as_str() {
                "github" => format!("https://github.com/{r}.git"),
                "gitlab" => format!(
                    "https://{}/{}.git",
                    a.host.as_deref().unwrap_or("gitlab.com"),
                    r
                ),
                _ => format!("{r}.git"),
            };
            repos.push(RepoSpec {
                full_name: r.clone(),
                clone_url: url,
                private: false,
                archived: false,
                fork: false,
                updated_at: None,
                created_at: None,
            });
        }
    } else if a.org.is_none()
        && a.user.is_none()
        && (!a.feed.is_empty() || !a.domain.is_empty() || !a.code_watch.is_empty())
    {
        // feed/domain/query-only watch: no repo enumeration needed
    } else {
        let sel = if let Some(o) = &a.org {
            provider::Selector::Org(o.clone())
        } else if let Some(u) = &a.user {
            provider::Selector::User(u.clone())
        } else {
            provider::Selector::Me
        };
        let list = match a.forge.as_str() {
            "github" => provider::github::list_repos,
            "gitlab" => provider::gitlab::list_repos,
            _ => provider::gitea::list_repos,
        };
        repos = list(&api, token.as_deref(), &sel)?;
    }
    let mut feeds = a.feed.clone();
    if a.advisories {
        feeds.push("https://github.com/advisories.atom".into());
    }
    eprintln!(
        "watching {} repos, {} feeds, {} domains, every {}s",
        repos.len(),
        feeds.len(),
        a.domain.len(),
        a.interval
    );
    if a.gh_events && (a.forge != "github" || a.org.is_none()) {
        eprintln!("warn: --gh-events needs github forge and --org");
    }
    if !a.code_watch.is_empty() && token.is_none() {
        eprintln!("warn: --code-watch queries need a github token; skipping");
    }
    if a.typo && a.domain.is_empty() {
        eprintln!("warn: --typo has no --domain to permute");
    }

    // shared rescan closure: clone-or-fetch into watch workdir, scan, delta.
    // Returns (findings, deps) so the caller can do dep deltas and
    // maintainer monitoring without a second walk.
    let rescan = |full: &str, url: &str| -> Result<(Vec<Finding>, Vec<osv::Dep>), String> {
        let dest = workdir.join(full.replace('/', "__"));
        let auth = token.clone().map(|t| clone::GitAuth {
            username: "x-access-token".into(),
            password: t,
        });
        let old = head_of(&dest);
        if !dest.join(".git").exists() {
            clone::clone_repo(url, &dest, auth.as_ref(), &workdir, cli.verbose > 1)?;
        } else {
            let d = dest.to_string_lossy();
            let _ = std::process::Command::new("git")
                .args(["-C", &d, "fetch", "--depth", "50", "-q", "origin", "HEAD"])
                .status();
            let _ = std::process::Command::new("git")
                .args(["-C", &d, "checkout", "-qf", "FETCH_HEAD"])
                .status();
        }
        // delta: only files changed since the last scanned head
        let changed = old
            .as_deref()
            .and_then(|o| head_of(&dest).and_then(|n| delta_files(&dest, o, &n)));
        let (findings, _n) = match changed {
            Some(rels) if rels.len() <= 500 => scan::scan_selected(&dest, &rels, full, rules, opts),
            _ => scan::scan_root(&dest, full, rules, opts),
        };
        let mut deps = Vec::new();
        collect_deps(&dest, "", opts, &mut deps);
        Ok((findings, deps))
    };

    loop {
        for repo in &repos {
            let key = repo.full_name.clone();
            match watch::remote_head(&repo.clone_url) {
                Ok(sha) => {
                    let changed = state.heads.get(&key) != Some(&sha);
                    if changed {
                        let known = state.heads.contains_key(&key);
                        eprintln!(
                            "{}: {} {}",
                            key,
                            &sha[..12.min(sha.len())],
                            if known {
                                "push detected, rescanning"
                            } else {
                                "first seen, scanning"
                            }
                        );
                        let (findings, deps) = match rescan(&key, &repo.clone_url) {
                            Ok(f) => f,
                            Err(e) => {
                                report_err(&e);
                                continue;
                            }
                        };
                        // dep delta vs stored baseline (silent on first sight)
                        let mut findings = findings;
                        let mut dep_ids: Vec<String> = deps
                            .iter()
                            .map(|d| format!("{}:{}@{}", d.ecosystem, d.name, d.version))
                            .collect();
                        dep_ids.sort();
                        dep_ids.dedup();
                        if let Some(old) = state.deps.get(&key) {
                            let (add, rem, chg) = watch::dep_delta(old, &dep_ids);
                            for d in add {
                                findings.push(watch_finding(
                                    &key,
                                    "DEPD-001",
                                    Severity::Medium,
                                    format!("dependency added in push: {d}"),
                                ));
                            }
                            for d in rem {
                                findings.push(watch_finding(
                                    &key,
                                    "DEPD-002",
                                    Severity::Info,
                                    format!("dependency removed: {d}"),
                                ));
                            }
                            for d in chg {
                                findings.push(watch_finding(
                                    &key,
                                    "DEPD-003",
                                    Severity::Low,
                                    format!("dependency version changed: {d}"),
                                ));
                            }
                        }
                        state.deps.insert(key.clone(), dep_ids);
                        // maintainer-set monitoring (opt-in: costs registry calls)
                        if a.dep_watch {
                            findings.extend(maintainer_check(&deps, &key, &mut state));
                        }
                        // delta vs previously-known findings
                        let known: std::collections::HashSet<String> = state
                            .known_findings
                            .get(&key)
                            .cloned()
                            .unwrap_or_default()
                            .into_iter()
                            .collect();
                        let new: Vec<_> = findings
                            .iter()
                            .filter(|f| !known.contains(&baseline::fingerprint(f)))
                            .collect();
                        if !new.is_empty() {
                            let mut r = Report::new();
                            r.findings = new.into_iter().cloned().collect();
                            r.finalize(Severity::Info);
                            emit(&r.to_text(&Styles::new(cli.color.unwrap_or(ColorMode::Auto))));
                        }
                        state.known_findings.insert(
                            key.clone(),
                            findings.iter().map(baseline::fingerprint).collect(),
                        );
                        state.heads.insert(key, sha);
                    }
                }
                Err(e) => eprintln!("warn: {key}: {e}"),
            }
        }
        for feed in &feeds {
            match watch::latest_feed_entry(feed) {
                Ok(latest) => {
                    if state.feeds.get(feed) != Some(&latest) {
                        let fresh = state.feeds.contains_key(feed);
                        state.feeds.insert(feed.clone(), latest.clone());
                        eprintln!(
                            "feed {feed}: {} [{}]",
                            if fresh { "new entry" } else { "baseline" },
                            latest
                        );
                        if fresh {
                            on_feed_event(feed, &latest, a, cfg, &repos, &rescan);
                        }
                    }
                }
                Err(e) => eprintln!("warn: feed {feed}: {e}"),
            }
        }
        for domain in &a.domain {
            let domain = match crate::osint::name::normalize_domain(domain) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("warn: domain {domain}: {e}");
                    continue;
                }
            };
            match watch::domain_snapshot(&domain) {
                Ok(mut snap) => {
                    let old = state.domains.get(&domain).cloned();
                    let known = old.is_some();
                    let old = old.unwrap_or_default();
                    // warn-once flags ride on the new snapshot
                    snap.cert_warned = old.cert_warned.clone();
                    snap.expiry_warned = old.expiry_warned.clone();
                    let mut findings = watch::domain_diff(&domain, &old, &snap, known);
                    findings.extend(watch::domain_expiry(&domain, &mut snap));
                    if a.typo {
                        let cands = crate::osint::typo_candidates(&domain);
                        let mut live: Vec<String> = crate::osint::typo_live(&cands)
                            .iter()
                            .map(|l| l.name.clone())
                            .collect();
                        live.sort();
                        let old_live = state.typos.get(&domain).cloned().unwrap_or_default();
                        if state.typos.contains_key(&domain) {
                            for n in live.iter().filter(|n| !old_live.contains(n)) {
                                findings.push(watch_finding(
                                    &domain,
                                    "DWATCH-010",
                                    Severity::Medium,
                                    format!("lookalike domain went live: {n}"),
                                ));
                            }
                        }
                        state.typos.insert(domain.clone(), live);
                    }
                    state.domains.insert(domain.clone(), snap);
                    emit_findings(findings, cli);
                }
                Err(e) => eprintln!("warn: domain {domain}: {e}"),
            }
        }
        if a.gh_events
            && a.forge == "github"
            && let Some(org) = &a.org
        {
            gh_events_poll(org, &api, token.as_deref(), &mut state, cli, &rescan);
        }
        if a.kev {
            kev_poll(&mut state, cli);
        }
        for q in &a.code_watch {
            if token.is_none() {
                break;
            }
            match watch::code_search(&api, token.as_deref(), q) {
                Ok(urls) => {
                    let known = state.code_watch.contains_key(q);
                    let old = state.code_watch.get(q).cloned().unwrap_or_default();
                    if known {
                        let mut findings = Vec::new();
                        for u in urls.iter().filter(|u| !old.contains(u)).take(5) {
                            findings.push(watch_finding(
                                q,
                                "CWATCH-001",
                                Severity::Medium,
                                format!("new code search hit: {u}"),
                            ));
                        }
                        emit_findings(findings, cli);
                    }
                    state.code_watch.insert(q.clone(), urls);
                }
                Err(e) => eprintln!("warn: code watch {q}: {e}"),
            }
        }
        if a.agent_surface {
            let (surface, _snap) = agentwatch::check_once(&a.agent_dir);
            if !surface.is_empty() {
                let mut r = Report::new();
                r.findings = surface;
                emit(&r.to_text(&Styles::new(cli.color.unwrap_or(ColorMode::Auto))));
            }
        }
        let _ = watch::save_state(&state);
        if a.once {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(a.interval));
    }
    Ok(ExitCode::SUCCESS)
}

/// New feed entry arrived. For the GitHub advisories feed, malicious-package
/// advisories trigger a rules refresh and a rescan of every watched repo.
pub(crate) fn on_feed_event(
    feed: &str,
    latest: &str,
    a: &cli::WatchArgs,
    cfg: &config::ConfigFile,
    repos: &[RepoSpec],
    rescan: &impl Fn(&str, &str) -> Result<(Vec<Finding>, Vec<osv::Dep>), String>,
) {
    let advisoryish = feed.contains("advisories")
        || latest.to_lowercase().contains("malware")
        || latest.to_lowercase().contains("malicious");
    if !advisoryish {
        return;
    }
    eprintln!("advisory feed event: {latest}");
    // refresh rules from the configured feed, then rescan everything watched
    if let Some(feed_url) = cfg.defaults.rules_feed.clone() {
        match rules_update(&feed_url, 0) {
            Ok(_) => eprintln!("rules refreshed from {feed_url}"),
            Err(e) => eprintln!("warn: rules refresh failed: {e}"),
        }
    }
    if a.rescan_on_feed {
        for repo in repos {
            match rescan(&repo.full_name, &repo.clone_url) {
                Ok((new, _)) if !new.is_empty() => {
                    eprintln!(
                        "{}: {} new findings post-advisory",
                        repo.full_name,
                        new.len()
                    );
                }
                _ => {}
            }
        }
    }
}

fn emit_findings(findings: Vec<Finding>, cli: &Cli) {
    if findings.is_empty() {
        return;
    }
    let mut r = Report::new();
    r.findings = findings;
    r.finalize(Severity::Info);
    emit(&r.to_text(&Styles::new(cli.color.unwrap_or(ColorMode::Auto))));
}

/// Poll the org events feed and turn fresh events into findings.
/// Public flips and new repos also get an immediate clone+scan.
fn gh_events_poll(
    org: &str,
    api: &str,
    token: Option<&str>,
    state: &mut watch::WatchState,
    cli: &Cli,
    rescan: &impl Fn(&str, &str) -> Result<(Vec<Finding>, Vec<osv::Dep>), String>,
) {
    let rows = match watch::github_org_events(api, org, token) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("warn: org events {org}: {e}");
            return;
        }
    };
    let last = state.events.get(org).cloned();
    let mut fresh: Vec<serde_json::Value> = Vec::new();
    for r in &rows {
        let id = r.get("id").and_then(|i| i.as_str()).unwrap_or("");
        if last.as_deref() == Some(id) {
            break;
        }
        fresh.push(r.clone());
    }
    if let Some(newest) = rows
        .first()
        .and_then(|r| r.get("id"))
        .and_then(|i| i.as_str())
    {
        state.events.insert(org.to_string(), newest.to_string());
    }
    if last.is_none() {
        return; // first poll is the baseline
    }
    let mut findings = Vec::new();
    let mut chain: std::collections::HashMap<(String, String), String> =
        std::collections::HashMap::new();
    for ev in crate::osint::events_from_values(&fresh).iter().rev() {
        let repo_url = format!("https://github.com/{}.git", ev.repo);
        match ev.kind.as_str() {
            "PublicEvent" => {
                findings.push(watch_finding(
                    org,
                    "GHEV-001",
                    Severity::High,
                    format!("repo flipped public: {}", ev.repo),
                ));
                if let Ok((f, _)) = rescan(&ev.repo, &repo_url) {
                    findings.extend(f);
                }
            }
            "CreateEvent" if ev.detail == "new repository" => {
                findings.push(watch_finding(
                    org,
                    "GHEV-002",
                    Severity::Info,
                    format!("new repo {} by {}", ev.repo, ev.actor),
                ));
                if let Ok((f, _)) = rescan(&ev.repo, &repo_url) {
                    findings.extend(f);
                }
            }
            "DeleteEvent" if ev.detail == "repository" => {
                findings.push(watch_finding(
                    org,
                    "GHEV-003",
                    Severity::Medium,
                    format!("repo deleted: {}", ev.repo),
                ));
            }
            "MemberEvent" if ev.action == "added" => {
                findings.push(watch_finding(
                    org,
                    "GHEV-004",
                    Severity::Medium,
                    format!("org member added: {}", ev.detail),
                ));
            }
            "PushEvent" => {
                // Chain continuity: a push's `before` must equal the head
                // of the previous push on the same repo+ref. A break is a
                // force push or a rewritten branch.
                let key = (ev.repo.clone(), ev.git_ref.clone());
                if let Some(exp) = chain.get(&key)
                    && !ev.before.is_empty()
                    && ev.before != *exp
                {
                    findings.push(watch_finding(
                        org,
                        "GHEV-005",
                        Severity::High,
                        format!(
                            "history rewritten on {} {}: pushed onto {} but previous head was {}",
                            ev.repo,
                            ev.git_ref,
                            &ev.before[..12.min(ev.before.len())],
                            &exp[..12.min(exp.len())]
                        ),
                    ));
                }
                if !ev.head.is_empty() {
                    chain.insert(key, ev.head.clone());
                }
            }
            _ => {}
        }
    }
    emit_findings(findings, cli);
}

/// New CISA KEV entries matched against the stored dep baselines.
fn kev_poll(state: &mut watch::WatchState, cli: &Cli) {
    let rows = match watch::kev_feed() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("warn: KEV feed: {e}");
            return;
        }
    };
    let norm = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(|c| c.to_lowercase())
            .collect()
    };
    let mut findings = Vec::new();
    for (cve, vendor, product) in &rows {
        if cve.is_empty() || state.kev_seen.iter().any(|k| k == cve) {
            continue;
        }
        state.kev_seen.push(cve.clone());
        let prod = norm(product);
        let vend = norm(vendor);
        if prod.len() < 4 && vend.len() < 4 {
            continue;
        }
        for (repo, deps) in &state.deps {
            for d in deps {
                // "eco:name@version" -> bare name
                let name = d
                    .split_once(':')
                    .map(|(_, r)| r.split('@').next().unwrap_or(""))
                    .unwrap_or("");
                let name = norm(name);
                if name.len() < 4 {
                    continue;
                }
                let hit = (!prod.is_empty() && (prod == name || prod.contains(&name)))
                    || (!vend.is_empty() && vend == name);
                if hit {
                    findings.push(watch_finding(
                        repo,
                        "KEV-001",
                        Severity::High,
                        format!("{cve} ({vendor} {product}) is exploited and matches dep {d}"),
                    ));
                }
            }
        }
    }
    state.kev_seen.truncate(6000);
    emit_findings(findings, cli);
}

pub(crate) fn watch_finding(target: &str, id: &str, sev: Severity, msg: String) -> Finding {
    Finding {
        ruleset: "watch".into(),
        rule_id: id.into(),
        severity: sev,
        target: target.into(),
        path: ".".into(),
        line: None,
        excerpt: None,
        message: msg,
        remediation: Some(
            "Review the change; unexpected dep churn is a leading supply-chain signal.".into(),
        ),
        reference: None,
        window: None,
        evidence: None,
    }
}

/// Compare each dep's registry maintainer set with the stored one;
/// a changed maintainer list is the classic package-hijack indicator.
pub(crate) fn maintainer_check(
    deps: &[osv::Dep],
    target: &str,
    state: &mut watch::WatchState,
) -> Vec<Finding> {
    let http = http::HttpClient::new(vec![]);
    let mut out = Vec::new();
    let mut checked = 0usize;
    for d in deps {
        if checked >= 30 {
            break;
        }
        if !matches!(d.ecosystem, "npm" | "PyPI" | "crates.io") {
            continue;
        }
        let key = format!("{}:{}", d.ecosystem, d.name);
        let Ok(info) = registry::lookup(&http, d) else {
            continue;
        };
        checked += 1;
        if info.maintainers.is_empty() {
            continue;
        }
        match state.maintainers.get(&key) {
            None => {
                state.maintainers.insert(key, info.maintainers.clone());
            }
            Some(old) if *old != info.maintainers => {
                let (add, rem) = watch::maintainer_delta(old, &info.maintainers);
                state
                    .maintainers
                    .insert(key.clone(), info.maintainers.clone());
                out.push(Finding {
                    ruleset: "watch".into(),
                    rule_id: "DEPD-010".into(),
                    severity: Severity::High,
                    target: target.into(),
                    path: ".".into(),
                    line: None,
                    excerpt: None,
                    message: format!(
                        "maintainer set changed for {key}: +[{}] -[{}]",
                        add.join(", "),
                        rem.join(", ")
                    ),
                    remediation: Some("A maintainer change is the top package-hijack signal: diff the latest release, pin the last known-good version, verify the new owner's history.".into()),
                    reference: None,
                    window: None,
                                evidence: None,
});
            }
            _ => {}
        }
    }
    out
}
