use crate::cli;
use crate::cli::Cli;
use crate::cmd::deps::collect_deps;
use crate::cmd::*;
use crate::finding::{Finding, Report, Severity};
use crate::provider::RepoSpec;
use crate::scan::ScanOptions;
use crate::{baseline, clone, config, daemon, http_server, rules, scan, watch};
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Mutex;

pub(crate) fn daemon_cmd(
    cli: &Cli,
    a: &cli::DaemonArgs,
    _cfg: &config::ConfigFile,
    rules: &[rules::CompiledRule],
    opts: &ScanOptions,
) -> Result<ExitCode, String> {
    let secret = a
        .webhook_secret
        .clone()
        .or_else(|| std::env::var("ARGUS_WEBHOOK_SECRET").ok());
    let workdir = a.workdir.clone().unwrap_or_else(|| {
        std::env::home_dir()
            .unwrap_or_else(|| "/tmp".into())
            .join(".local/share/argus/daemon-clones")
    });
    std::fs::create_dir_all(&workdir).map_err(|e| e.to_string())?;

    let token = config::resolve_token(
        a.token.as_deref(),
        cli.token.as_deref(),
        &["GITHUB_TOKEN", "GITLAB_TOKEN", "GITEA_TOKEN", "ARGUS_TOKEN"],
        None,
    );

    let state = std::sync::Arc::new(daemon::Daemon::default());
    let pending: std::sync::Arc<Mutex<Vec<(String, String)>>> =
        std::sync::Arc::new(Mutex::new(Vec::new()));

    // spawn HTTP control + webhook listener (webhooks enqueue rescans for
    // the main loop so rules/opts stay borrowed, not 'static)
    let listener = TcpListener::bind(&a.listen).map_err(|e| format!("bind {}: {e}", a.listen))?;
    eprintln!("argus daemon listening on {}", a.listen);
    {
        let pending = pending.clone();
        let secret2 = secret.clone();
        let state_http = state.clone();
        std::thread::spawn(move || {
            http_server::serve(listener, move |req| {
                match (req.method.as_str(), req.path.as_str()) {
                    ("GET", "/healthz") => (200, r#"{"ok":true}"#.to_string()),
                    ("GET", "/report") => {
                        let inner = state_http.state.lock().unwrap();
                        match &inner.last_report {
                            Some(r) => (200, serde_json::to_string_pretty(r).unwrap_or_default()),
                            None => (200, r#"{"report":"no scans yet"}"#.to_string()),
                        }
                    }
                    ("GET", "/state") => {
                        let inner = state_http.state.lock().unwrap();
                        (200, serde_json::json!({"heads": inner.heads}).to_string())
                    }
                    ("POST", "/scan") => (200, r#"{"queued":true}"#.to_string()),
                    ("POST", p) if p.starts_with("/webhook/") => {
                        let forge = p.trim_start_matches("/webhook/");
                        // verify signatures / shared secret
                        if let Some(sec) = &secret2 {
                            let ok = match forge {
                                "github" => req
                                    .header("x-hub-signature-256")
                                    .is_some_and(|s| daemon::verify_github_sig(sec, &req.body, s)),
                                "gitlab" => req.header("x-gitlab-token") == Some(sec.as_str()),
                                "gitea" => {
                                    req.header("x-gitea-signature").is_some_and(|s| {
                                        s == daemon::hmac_sha256_hex(sec, &req.body)
                                    }) || req
                                        .header("authorization")
                                        .and_then(|a| a.strip_prefix("token "))
                                        == Some(sec.as_str())
                                }
                                _ => false,
                            };
                            if !ok {
                                return (401, r#"{"error":"bad signature"}"#.to_string());
                            }
                        }
                        match daemon::repo_from_push(&req.body) {
                            Some((full, url, _sha)) => {
                                pending.lock().unwrap().push((full, url));
                                (200, r#"{"rescanned":true}"#.to_string())
                            }
                            None => (400, r#"{"error":"no repository in payload"}"#.to_string()),
                        }
                    }
                    _ => (404, r#"{"error":"not found"}"#.to_string()),
                }
            })
        });
    }

    // watch-poll loop (webhook fallback / feed polling)
    let mut state2 = watch::load_state();
    let repos: Vec<RepoSpec> = a
        .repo
        .iter()
        .map(|r| RepoSpec {
            full_name: r.clone(),
            clone_url: format!("https://github.com/{r}.git"),
            private: false,
            archived: false,
            fork: false,
            updated_at: None,
            created_at: None,
        })
        .collect();
    // rescan one repo into the persistent clone; returns NEW findings
    let rescan = |full: &str, clone_url: &str| -> Result<Vec<Finding>, String> {
        let dest = workdir.join(full.replace('/', "__"));
        let auth = token.clone().map(|t| clone::GitAuth {
            username: "x-access-token".into(),
            password: t,
        });
        let old = head_of(&dest);
        if !dest.join(".git").exists() {
            clone::clone_repo(clone_url, &dest, auth.as_ref(), &workdir, false)?;
        } else {
            let d = dest.to_string_lossy();
            let _ = std::process::Command::new("git")
                .args(["-C", &d, "fetch", "--depth", "50", "-q", "origin", "HEAD"])
                .status();
            let _ = std::process::Command::new("git")
                .args(["-C", &d, "checkout", "-qf", "FETCH_HEAD"])
                .status();
        }
        let changed = old
            .as_deref()
            .and_then(|o| head_of(&dest).and_then(|n| delta_files(&dest, o, &n)));
        let (mut findings, _n) = match changed {
            Some(rels) if rels.len() <= 500 => scan::scan_selected(&dest, &rels, full, rules, opts),
            _ => scan::scan_root(&dest, full, rules, opts),
        };
        // dep delta vs daemon-persistent baseline
        let dep_ids: Vec<String> = {
            let mut dd = Vec::new();
            collect_deps(&dest, "", opts, &mut dd);
            let mut ids: Vec<String> = dd
                .iter()
                .map(|d| format!("{}:{}@{}", d.ecosystem, d.name, d.version))
                .collect();
            ids.sort();
            ids.dedup();
            ids
        };
        let mut inner = state.state.lock().unwrap();
        if let Some(old) = inner.deps.get(full) {
            let (add, rem, chg) = watch::dep_delta(old, &dep_ids);
            for d in add {
                findings.push(watch_finding(
                    full,
                    "DEPD-001",
                    Severity::Medium,
                    format!("dependency added in push: {d}"),
                ));
            }
            for d in rem {
                findings.push(watch_finding(
                    full,
                    "DEPD-002",
                    Severity::Info,
                    format!("dependency removed: {d}"),
                ));
            }
            for d in chg {
                findings.push(watch_finding(
                    full,
                    "DEPD-003",
                    Severity::Low,
                    format!("dependency version changed: {d}"),
                ));
            }
        }
        inner.deps.insert(full.to_string(), dep_ids);
        let known: std::collections::HashSet<String> = inner
            .known
            .get(full)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        let new: Vec<Finding> = findings
            .into_iter()
            .filter(|f| !known.contains(&baseline::fingerprint(f)))
            .collect();
        let mut all: Vec<String> = known.into_iter().collect();
        all.extend(new.iter().map(baseline::fingerprint));
        inner.known.insert(full.to_string(), all);
        let mut r = Report::new();
        r.findings = new.clone();
        r.finalize(Severity::Info);
        inner.last_report = Some(r);
        Ok(new)
    };

    loop {
        // drain webhook-triggered rescans
        let jobs: Vec<(String, String)> = pending.lock().unwrap().drain(..).collect();
        for (full, url) in jobs {
            match rescan(&full, &url) {
                Ok(new) if !new.is_empty() => {
                    eprintln!("{full}: {} new findings", new.len());
                    if let Some(u) = &a.notify_url {
                        let _ = daemon::notify(
                            u,
                            &format!("argus: {} new findings in {full}", new.len()),
                            &new,
                        );
                    }
                }
                Ok(_) => eprintln!("{full}: rescanned, no new findings"),
                Err(e) => eprintln!("warn: {full}: {e}"),
            }
        }
        for repo in &repos {
            if let Ok(sha) = watch::remote_head(&repo.clone_url)
                && state2.heads.get(&repo.full_name) != Some(&sha)
            {
                let had = state2.heads.contains_key(&repo.full_name);
                state2.heads.insert(repo.full_name.clone(), sha.clone());
                state
                    .state
                    .lock()
                    .unwrap()
                    .heads
                    .insert(repo.full_name.clone(), sha);
                if had {
                    eprintln!("{}: push detected via poll", repo.full_name);
                    match rescan(&repo.full_name, &repo.clone_url) {
                        Ok(new) if !new.is_empty() => {
                            eprintln!("{}: {} new findings", repo.full_name, new.len());
                            if let Some(u) = &a.notify_url {
                                let _ = daemon::notify(
                                    u,
                                    &format!(
                                        "argus: {} new findings in {}",
                                        new.len(),
                                        repo.full_name
                                    ),
                                    &new,
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        let _ = watch::save_state(&state2);
        std::thread::sleep(std::time::Duration::from_secs(a.interval));
    }
}
