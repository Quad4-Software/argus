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
use crate::{baseline, clone, config, http, osv, provider, registry, rules, scan, watch};
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
    } else if a.org.is_none() && a.user.is_none() && !a.feed.is_empty() {
        // feed-only watch: no repo enumeration needed
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
        "watching {} repos, {} feeds, every {}s",
        repos.len(),
        feeds.len(),
        a.interval
    );

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
                });
            }
            _ => {}
        }
    }
    out
}
