// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

use crate::cli::{Cli, Cmd, RemoteArgs};
use crate::cmd::deps::{REMOTE_DEPS, collect_deps};
use crate::cmd::*;
use crate::finding::{Report, TargetStat};
use crate::provider::{RepoSpec, Selector};
use crate::scan::ScanOptions;
use crate::{clone, config, finding, provider, rules, scan, settings};
use std::path::Path;
use std::sync::Mutex;

pub(crate) fn selector_of(a: &RemoteArgs, have_token: bool) -> Result<Selector, String> {
    if let Some(u) = &a.user {
        Ok(Selector::User(u.clone()))
    } else if let Some(o) = &a.org {
        Ok(Selector::Org(o.clone()))
    } else if a.me || have_token {
        Ok(Selector::Me)
    } else {
        Err("pick a scope: --user, --org, or provide a token for --me".into())
    }
}

pub(crate) fn scan_remote(
    cli: &Cli,
    a: &RemoteArgs,
    cfg: &config::ConfigFile,
    rules: &[rules::CompiledRule],
    opts: &ScanOptions,
    report: &mut Report,
) -> Result<(), String> {
    let (api, cfg_tok, env_tok, git_user, list): (
        String,
        Option<String>,
        &[&str],
        Option<String>,
        _,
    ) = match &cli.cmd {
        Cmd::Github(_) => (
            provider::github::api_base(a.host.as_deref()),
            cfg.tokens.github.clone(),
            &["GITHUB_TOKEN", "GH_TOKEN", "ARGUS_TOKEN"][..],
            a.git_user
                .clone()
                .or(cfg.github.git_user.clone())
                .or(Some("x-access-token".into())),
            provider::github::list_repos
                as fn(&str, Option<&str>, &Selector) -> Result<Vec<RepoSpec>, String>,
        ),
        Cmd::Gitlab(_) => (
            provider::gitlab::api_base(a.host.as_deref().or(cfg.gitlab.host.as_deref())),
            cfg.tokens.gitlab.clone(),
            &["GITLAB_TOKEN", "ARGUS_TOKEN"][..],
            a.git_user
                .clone()
                .or(cfg.gitlab.git_user.clone())
                .or(Some("oauth2".into())),
            provider::gitlab::list_repos,
        ),
        Cmd::Gitea(_) => {
            let host = a
                .host
                .clone()
                .or(cfg.gitea.host.clone())
                .ok_or("gitea: --host is required (or set gitea.host in config)")?;
            (
                provider::gitea::api_base(&host),
                cfg.tokens.gitea.clone(),
                &["GITEA_TOKEN", "FORGEJO_TOKEN", "ARGUS_TOKEN"][..],
                a.git_user
                    .clone()
                    .or(cfg.gitea.git_user.clone())
                    .or(Some("oauth2".into())),
                provider::gitea::list_repos,
            )
        }
        _ => unreachable!(),
    };

    let token = config::resolve_token(
        a.token.as_deref(),
        cli.token.as_deref(),
        env_tok,
        cfg_tok.as_deref(),
    );
    let sel = selector_of(a, token.is_some())?;

    if cli.verbose > 0 {
        eprintln!("enumerating repos via {api} ...");
    }
    let mut repos = list(&api, token.as_deref(), &sel)?;
    let before = repos.len();
    repos.retain(|r| {
        !(a.skip_archived && r.archived || a.skip_forks && r.fork || a.skip_private && r.private)
            && a.updated_since
                .as_deref()
                .is_none_or(|s| r.updated_at.as_deref().is_none_or(|u| u >= s))
            && a.updated_before
                .as_deref()
                .is_none_or(|s| r.updated_at.as_deref().is_none_or(|u| u <= s))
    });
    let filtered = before - repos.len();
    let limited = a.limit.is_some_and(|l| repos.len() > l);
    if let Some(l) = a.limit {
        repos.truncate(l);
    }
    eprintln!(
        "{}: {} repositories{}{}",
        api,
        repos.len(),
        if filtered > 0 {
            format!(" ({filtered} filtered out)")
        } else {
            String::new()
        },
        if limited {
            " (limited)".to_string()
        } else {
            String::new()
        }
    );

    if a.settings {
        if matches!(cli.cmd, Cmd::Github(_)) {
            if cli.verbose > 0 {
                eprintln!("auditing org/repo security settings ...");
            }
            let f = settings::audit_github(&api, token.as_deref(), &sel, &repos);
            report.findings.extend(f);
        } else {
            report
                .errors
                .push("settings audit is github-only for now".into());
        }
    }

    let osv_flag = cli.osv || cli.dep_check || cfg.defaults.osv.unwrap_or(false);
    let workdir = a
        .workdir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join(format!("argus-{}", std::process::id())));
    std::fs::create_dir_all(&workdir).map_err(|e| format!("workdir {}: {e}", workdir.display()))?;

    let auth = token.map(|t| clone::GitAuth {
        username: git_user.unwrap_or_else(|| "oauth2".into()),
        password: t,
    });

    let acc = clone_scan_pool(repos, &workdir, auth, cli, rules, opts, osv_flag);

    for (repo, entry) in acc {
        match entry {
            Ok((mut findings, files)) => {
                report.files_scanned += files;
                report.targets.push(TargetStat {
                    label: repo.full_name,
                    files,
                    findings: findings.len(),
                });
                report.findings.append(&mut findings);
            }
            Err(e) => report.errors.push(format!("{}: {e}", repo.full_name)),
        }
    }

    if !a.keep {
        let _ = std::fs::remove_dir_all(&workdir);
    } else {
        eprintln!("kept clones in {}", workdir.display());
    }
    Ok(())
}

/// Shared clone+scan pool used by remote providers, roam, and watch.
pub(crate) fn clone_scan_pool(
    repos: Vec<RepoSpec>,
    workdir: &Path,
    auth: Option<clone::GitAuth>,
    cli: &Cli,
    rules: &[rules::CompiledRule],
    opts: &ScanOptions,
    osv_flag: bool,
) -> Vec<(RepoSpec, CloneScanResult)> {
    let queue = Mutex::new(repos.into_iter());
    let acc = Mutex::new(Vec::new());
    let auth = &auth;

    std::thread::scope(|scope| {
        for _ in 0..opts.jobs.max(1) {
            let queue = &queue;
            let acc = &acc;
            scope.spawn(move || {
                loop {
                    let repo = {
                        let mut q = queue.lock().unwrap();
                        q.next()
                    };
                    let Some(repo) = repo else { break };
                    let dest = workdir.join(repo.full_name.replace('/', "__"));
                    let entry: Result<(Vec<finding::Finding>, usize), String> = (|| {
                        clone::clone_repo(
                            &repo.clone_url,
                            &dest,
                            auth.as_ref(),
                            workdir,
                            cli.verbose > 1,
                        )?;
                        let (f, n) = scan::scan_root(&dest, &repo.full_name, rules, opts);
                        if osv_flag {
                            let mut v = REMOTE_DEPS.lock().unwrap();
                            collect_deps(&dest, &repo.full_name, opts, &mut v);
                        }
                        Ok((f, n))
                    })(
                    );
                    acc.lock().unwrap().push((repo, entry));
                }
            });
        }
    });
    acc.into_inner().unwrap()
}
