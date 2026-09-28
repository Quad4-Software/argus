use crate::audit;
use crate::cli;
use crate::cli::{Cli, Format};
use crate::cmd::*;
use crate::color::{ColorMode, Styles};
use crate::finding::{Report, Severity, TargetStat};
use crate::provider::RepoSpec;
use crate::scan::ScanOptions;
use crate::{clone, config, finding, provider, roam, rules, scan};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub(crate) fn in_ci() -> bool {
    std::env::var_os("ARGUS_CI").is_some()
        || std::env::var_os("GITHUB_ACTIONS").is_some()
        || std::env::var_os("GITEA_ACTIONS").is_some()
        || std::env::var_os("GITLAB_CI").is_some()
        || std::env::var("CI").is_ok_and(|v| v == "true" || v == "1")
}

pub(crate) fn scan_system(
    report: &mut Report,
    rules: &[rules::CompiledRule],
    opts: &ScanOptions,
    extra: &[PathBuf],
    verbose: u8,
) {
    let mut roots: Vec<PathBuf> = Vec::new();
    // Temp / shared-memory / service dirs.
    for p in [
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/var/spool/cron",
        "/etc/ld.so.preload",
    ] {
        roots.push(PathBuf::from(p));
    }
    // Per-user locations: current user plus /root and /home/*.
    let mut homes: Vec<PathBuf> = Vec::new();
    if let Some(h) = std::env::home_dir() {
        homes.push(h);
    }
    for base in ["/root", "/home"] {
        let b = PathBuf::from(base);
        if b.is_dir()
            && let Ok(rd) = std::fs::read_dir(&b)
        {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() && !homes.contains(&p) {
                    homes.push(p);
                }
            }
        }
    }
    for h in homes {
        for sub in [
            ".local/bin",
            ".config/systemd/user",
            ".config/autostart",
            ".bashrc",
            ".zshrc",
            ".profile",
            ".bash_profile",
            ".npmrc",
            ".gitconfig",
            ".ssh",
            ".gnupg",
        ] {
            roots.push(h.join(sub));
        }
    }
    roots.extend(extra.iter().cloned());

    for root in roots {
        if !root.exists() {
            continue;
        }
        let label = format!("system:{}", root.display());
        if verbose > 0 {
            eprintln!("scanning {label} ...");
        }
        let (mut findings, files) = scan::scan_root(&root, &label, rules, opts);
        report.files_scanned += files;
        report.targets.push(TargetStat {
            label,
            files,
            findings: findings.len(),
        });
        report.findings.append(&mut findings);
    }

    // Installed foreign packages (Arch/AUR).
    if let Ok(out) = std::process::Command::new("pacman").arg("-Qqm").output() {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            if verbose > 0 {
                eprintln!("checking {} foreign packages", text.lines().count());
            }
            let mut f = scan::scan_text("PACMAN-FOREIGN-PACKAGES", &text, rules, "pacman:foreign");
            report.findings.append(&mut f);
        }
    } else if verbose > 0 {
        eprintln!("pacman not available; skipping foreign-package check");
    }
}

/// rules update: git clone/pull or single-file download into the user rules dir.
pub(crate) fn rules_update(feed: &str, verbose: u8) -> Result<ExitCode, String> {
    let dir = std::env::home_dir()
        .ok_or("no home dir")?
        .join(".config/argus/rules");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let is_file_url = feed.starts_with("http://") || feed.starts_with("https://");
    let is_file_url = is_file_url
        && (feed.ends_with(".toml") || feed.ends_with(".json") || feed.ends_with(".txt"));
    if !is_file_url {
        // treat as git repo
        let dest = dir.join("feed-repo");
        let st = if dest.join(".git").exists() {
            std::process::Command::new("git")
                .args([
                    "-C",
                    &dest.to_string_lossy(),
                    "pull",
                    "--ff-only",
                    "--quiet",
                ])
                .status()
        } else {
            std::process::Command::new("git")
                .args(["clone", "--depth", "1", "--quiet", feed])
                .arg(&dest)
                .status()
        };
        match st {
            Ok(s) if s.success() => eprintln!("updated feed repo in {}", dest.display()),
            _ => return Err(format!("git fetch failed for {feed}")),
        }
    } else {
        // single-file TOML ruleset download
        let name = feed.rsplit('/').next().unwrap_or("feed.toml");
        let dest = dir.join(name);
        let mut r = ureq::get(feed)
            .call()
            .map_err(|e| format!("GET {feed}: {e}"))?;
        let body = r
            .body_mut()
            .read_to_string()
            .map_err(|e| format!("GET {feed}: {e}"))?;
        // validate before installing
        toml::from_str::<rules::RuleSetFile>(&body)
            .map_err(|e| format!("{feed}: not a valid ruleset: {e}"))?;
        std::fs::write(&dest, &body).map_err(|e| e.to_string())?;
        eprintln!("wrote {}", dest.display());
    }
    if verbose > 0 {
        eprintln!("done");
    }
    Ok(ExitCode::SUCCESS)
}

/// For every ActionRef finding with a window, resolve the repo's GitHub remote
/// and count workflow runs inside the window. Emits CRITICAL findings when runs
/// exist - that is the difference between "exposed" and "executed the payload".
pub(crate) fn check_runs(cli: &Cli, report: &mut Report) {
    let token = config::resolve_token(
        None,
        cli.token.as_deref(),
        &["GITHUB_TOKEN", "GH_TOKEN", "ARGUS_TOKEN"],
        None,
    );
    let api = "https://api.github.com";
    // local scan: resolve origin per scanned path
    let mut repo_for_path: std::collections::HashMap<String, Option<(String, String, String)>> =
        std::collections::HashMap::new();
    let mut seen = std::collections::HashSet::new();
    let mut new_findings = Vec::new();
    for f in &report.findings {
        let Some(win) = &f.window else { continue };
        if !f.path.contains("workflows/") {
            continue;
        }
        // target label: for remote scans it's owner/repo; for local it's the path.
        let (owner, repo) = if f.target.contains('/') && !f.target.starts_with(['.', '/']) {
            let mut it = f.target.split('/');
            (
                it.next().unwrap_or("").to_string(),
                it.next().unwrap_or("").to_string(),
            )
        } else {
            let root = PathBuf::from(&f.target);
            let entry = repo_for_path
                .entry(f.target.clone())
                .or_insert_with(|| audit::origin_repo(&root))
                .clone();
            let Some((host, o, r)) = entry else { continue };
            if !host.contains("github") {
                continue;
            }
            (o, r)
        };
        if !seen.insert((repo.clone(), f.path.clone(), win.clone())) {
            continue;
        }
        match audit::github_runs_in_window(api, token.as_deref(), &owner, &repo, &f.path, win) {
            Ok(n) if n > 0 => new_findings.push(finding::Finding {
                ruleset: "run-check".into(),
                rule_id: "RUNCHECK-001".into(),
                severity: Severity::Critical,
                target: f.target.clone(),
                path: f.path.clone(),
                line: f.line,
                excerpt: f.excerpt.clone(),
                message: format!(
                    "{owner}/{repo}: workflow ran {n} time(s) inside the compromise window {}..{} - payload likely executed",
                    win.0, win.1
                ),
                remediation: Some("Rotate every secret available to this workflow and audit run logs.".into()),
                reference: f.reference.clone(),
                window: Some(win.clone()),
            }),
            Ok(_) => {}
            Err(e) => report.errors.push(format!("run-check {owner}/{repo}: {e}")),
        }
    }
    report.findings.extend(new_findings);
}

/// Files changed vs base (git diff base...HEAD) plus untracked files.
pub(crate) fn staged_files(repo: &Path) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let r = repo.to_string_lossy();
    for args in [
        vec!["diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        vec!["ls-files", "-o", "--exclude-standard"],
    ] {
        if let Ok(o) = std::process::Command::new("git")
            .args(["-C", &r])
            .args(&args)
            .output()
            && o.status.success()
        {
            out.extend(
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .map(|l| l.to_string()),
            );
        }
    }
    out.sort();
    out.dedup();
    out
}

pub(crate) fn changed_files(repo: &Path, base: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let r = repo.to_string_lossy();
    for args in [
        vec![
            "diff",
            "--name-only",
            "--diff-filter=ACMR",
            &format!("{base}...HEAD"),
        ],
        vec!["diff", "--name-only", "--diff-filter=ACMR", base], // uncommitted vs base too
        vec!["ls-files", "-o", "--exclude-standard"],
    ] {
        if let Ok(o) = std::process::Command::new("git")
            .args(["-C", &r])
            .args(&args)
            .output()
            && o.status.success()
        {
            out.extend(
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .map(|l| l.to_string()),
            );
        }
    }
    out.sort();
    out.dedup();
    out
}

pub(crate) fn roam_cmd(
    cli: &Cli,
    a: &cli::RoamArgs,
    cfg: &config::ConfigFile,
    rules: &[rules::CompiledRule],
    opts: &ScanOptions,
    report: &mut Report,
) -> Result<(), String> {
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
        "gitea" => {
            let host = a
                .host
                .clone()
                .or(cfg.gitea.host.clone())
                .ok_or("roam gitea: --host required")?;
            (
                provider::gitea::api_base(&host),
                &["GITEA_TOKEN", "FORGEJO_TOKEN", "ARGUS_TOKEN"][..],
                cfg.tokens.gitea.clone(),
            )
        }
        other => return Err(format!("unknown forge {other:?}")),
    };
    let token = config::resolve_token(
        a.token.as_deref(),
        cli.token.as_deref(),
        env_tok,
        cfg_tok.as_deref(),
    );
    if a.code_search.is_some() && token.is_none() && a.forge == "github" {
        return Err("--code-search requires a GitHub token (GITHUB_TOKEN)".into());
    }
    let q = roam::RoamQuery {
        query: a.query.clone(),
        topic: a.topic.clone(),
        language: a.language.clone(),
        min_stars: a.min_stars,
        code_search: a.code_search.clone(),
        limit: a.limit,
    };
    let repos = roam::search(&api, &a.forge, token.as_deref(), &q)?;
    eprintln!("roam({}): {} repositories", api, repos.len());

    let workdir = a
        .workdir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join(format!("argus-roam-{}", std::process::id())));
    std::fs::create_dir_all(&workdir).map_err(|e| e.to_string())?;
    let auth = token.map(|t| clone::GitAuth {
        username: "x-access-token".into(),
        password: t,
    });
    let osv_flag = cli.osv || cli.dep_check || cfg.defaults.osv.unwrap_or(false);
    let acc = clone_scan_pool(repos, &workdir, auth, cli, rules, opts, osv_flag);
    for (repo, entry) in acc {
        match entry {
            Ok((mut findings, files)) => {
                report.files_scanned += files;
                report.targets.push(TargetStat {
                    label: repo.full_name.clone(),
                    files,
                    findings: findings.len(),
                });
                if let Some(f) = young_repo_finding(&repo) {
                    findings.push(f);
                }
                report.findings.append(&mut findings);
            }
            Err(e) => report.errors.push(format!("{}: {e}", repo.full_name)),
        }
    }
    if !a.keep && a.workdir.is_none() {
        let _ = std::fs::remove_dir_all(&workdir);
    }
    Ok(())
}

/// OSINT: a repo created days ago carrying CI workflows or dependency
/// manifests is a classic throwaway-account smell.
pub(crate) fn young_repo_finding(repo: &RepoSpec) -> Option<finding::Finding> {
    let created = repo.created_at.as_deref()?;
    let days = days_since(created)?;
    if days > 30 {
        return None;
    }
    Some(finding::Finding {
        rule_id: "OSINT-001".into(),
        ruleset: "osint".into(),
        severity: Severity::Low,
        target: repo.full_name.clone(),
        path: "-".into(),
        line: None,
        excerpt: None,
        message: format!(
            "repository created {days} day(s) ago ({created}) - new repos cloned into supply-chain positions are a throwaway-account pattern"
        ),
        remediation: Some(
            "Check the publisher account age and history before trusting this code.".into(),
        ),
        reference: None,
        window: None,
    })
}

pub(crate) fn days_since(iso: &str) -> Option<i64> {
    // expects 2026-03-19T12:00:00Z
    let date = iso.get(..10)?;
    let parse = |s: &str| -> Option<u64> {
        let y: u64 = s.get(0..4)?.parse().ok()?;
        let m: u64 = s.get(5..7)?.parse().ok()?;
        let d: u64 = s.get(8..10)?.parse().ok()?;
        // days since epoch (civil)
        Some(days_from_civil(y as i64, m, d))
    };
    let then = parse(date)?;
    let now = chrono_days_now();
    Some(now as i64 - then as i64)
}

pub(crate) fn days_from_civil(y: i64, m: u64, d: u64) -> u64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146097 + doe - 719468) as u64
}

pub(crate) fn chrono_days_now() -> u64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secs / 86400
}

// ---------------- watch ----------------

pub(crate) fn report_err(e: &str) {
    eprintln!("warn: {e}");
}

// ---------------- authors ----------------

pub(crate) fn authors_cmd(
    cli: &Cli,
    paths: &[PathBuf],
    fmt: Format,
    rules: &[rules::CompiledRule],
) -> Result<ExitCode, String> {
    let paths = if paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        paths.to_vec()
    };
    let mut out = serde_json::json!({"repos": []});
    let arr = out["repos"].as_array_mut().unwrap();
    let mut flagged: Vec<finding::Finding> = Vec::new();
    for p in paths {
        if !p.join(".git").exists() {
            eprintln!("warn: {}: not a git repo", p.display());
            continue;
        }
        let authors = audit::authors(p.as_path());
        // run the actor watchlist rules over the author text
        let text = audit::authors_text(p.as_path());
        flagged.extend(scan::scan_text(
            "git-authors",
            &text,
            rules,
            &p.display().to_string(),
        ));
        arr.push(serde_json::json!({
            "path": p.display().to_string(),
            "authors": authors.iter().map(|(n,e,c)| serde_json::json!({"name": n, "email": e, "commits": c})).collect::<Vec<_>>()
        }));
    }
    match fmt {
        Format::Json => println!("{}", serde_json::to_string_pretty(&out).unwrap()),
        _ => {
            for r in arr {
                println!("{}", r["path"].as_str().unwrap_or(""));
                for a in r["authors"].as_array().unwrap_or(&vec![]) {
                    println!(
                        "  {:>5}  {} <{}>",
                        a["commits"].as_u64().unwrap_or(0),
                        a["name"].as_str().unwrap_or(""),
                        a["email"].as_str().unwrap_or("")
                    );
                }
            }
            if !flagged.is_empty() {
                let mut r = Report::new();
                r.findings = flagged;
                r.finalize(Severity::Info);
                eprintln!(
                    "{}",
                    r.to_text(&Styles::new(cli.color.unwrap_or(ColorMode::Auto)))
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------- daemon ----------------

/// Scan git history diffs for committed-and-removed secrets.
pub(crate) fn history_secrets(
    paths: &[std::path::PathBuf],
    rules: &[crate::rules::CompiledRule],
    opts: &crate::scan::ScanOptions,
    report: &mut crate::finding::Report,
    verbose: u8,
) {
    for p in paths {
        if p.join(".git").exists() {
            let label = p.display().to_string();
            report.findings.extend(crate::history::scan_history(
                p, rules, opts, &label, verbose,
            ));
        }
    }
}

/// Registry-side image audit through the OCI API.
pub(crate) fn remote_image(image: &str, report: &mut crate::finding::Report, verbose: u8) {
    let http = crate::http::HttpClient::new(vec![]);
    match crate::regimg::audit_remote(&http, image, verbose) {
        Ok(fs) => report.findings.extend(fs),
        Err(e) => report.errors.push(e),
    }
}
