// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

mod ai;
mod audit;
mod baseline;
mod cache;
mod catalog;
mod cli;
mod clone;
mod cmd;
mod codec;
mod color;
mod config;
mod container_audit;
mod daemon;
mod db;
mod depcheck;
mod entropy;
mod extract;
mod finding;
mod fix;
mod history;
mod hooks;
mod host;
mod http;
mod http_server;
mod ignore;
mod image;
mod ioc;
mod license;
mod mcp;
mod media;
mod osint;
mod osv;
mod progress;
mod provider;
mod publish;
mod regimg;
mod registry;
mod roam;
mod rules;
mod rulesign;
mod sandbox;
mod sbom;
mod scan;
mod search;
mod seometa;
mod settings;
mod similar;
mod stego;
mod store;
mod style;
mod supply;
mod sysaudit;
mod verify;
mod vex;
mod watch;
mod webpassive;
mod webscan;
mod workflow_audit;
#[cfg(feature = "yara")]
mod yarascan;

use clap::Parser;
use cli::{Cli, Cmd, Format};
use cmd::*;
use color::{ColorMode, Styles};
use finding::{Report, Severity, TargetStat};
use scan::ScanOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: &Cli) -> Result<ExitCode, String> {
    let t0 = std::time::Instant::now();
    let (cfg, _cfg_path) = config::load(cli.config.as_deref())?;

    let format = cli.format.or(cfg.defaults.format).unwrap_or_default();
    let color_mode = cli.color.or(cfg.defaults.color).unwrap_or(ColorMode::Auto);
    let styles = Styles::new(if matches!(format, Format::Json) {
        ColorMode::Never
    } else {
        color_mode
    });
    let jobs = cli.jobs.or(cfg.defaults.jobs).unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });
    // live progress only for commands that walk/scan files; -v already
    // narrates, and machine-facing subcommands keep stderr clean
    let scans_fs = crate::cli::scans_files(&cli.cmd);
    let progress_on = cli
        .progress
        .or(cfg.defaults.progress)
        .unwrap_or_default()
        .enabled()
        && cli.verbose == 0
        && scans_fs;
    let min_sev = cli
        .severity
        .or(cfg.defaults.severity)
        .unwrap_or(Severity::Info);
    let fail_on = cli
        .fail_on
        .or(cfg.defaults.fail_on)
        .unwrap_or(Severity::Low);
    let max_kb = cli
        .max_file_size_kb
        .or(cfg.defaults.max_file_size_kb)
        .unwrap_or(8192);

    let mut extra_rules = cli.rules.clone();
    extra_rules.extend(cfg.defaults.rules_dirs.iter().cloned());
    // signed-ruleset gate: every custom file/dir must verify
    if let Some(pk) = &cli.rules_pubkey {
        cmd::misc::verify_signed_rules(&extra_rules, pk)?;
    }
    let (mut rules, set_names) = rules::load(&extra_rules, cli.no_builtin_rules)?;

    // --ruleset filter / --disable-rule + config equivalents
    let mut only: std::collections::HashSet<String> = cli.ruleset.iter().cloned().collect();
    only.extend(cfg.defaults.rulesets.iter().cloned());
    if !only.is_empty() {
        rules.retain(|r| only.contains(&r.set));
    }
    let mut disabled: std::collections::HashSet<String> =
        cli.disable_rule.iter().cloned().collect();
    disabled.extend(cfg.defaults.disable_rules.iter().cloned());
    rules.retain(|r| !disabled.contains(&r.id));

    // Flat IoC lists (flag + config).
    let ioc_sev = cli.ioc_severity.unwrap_or(Severity::High);
    let mut ioc_files = cli.iocs.clone();
    ioc_files.extend(cfg.defaults.ioc_files.iter().cloned());
    for f in &ioc_files {
        rules.extend(ioc::load_file(f, ioc_sev)?);
    }

    // YARA rulesets (flag + config).
    #[cfg(feature = "yara")]
    let yara_rules = {
        let mut paths = cli.yara.clone();
        paths.extend(cfg.defaults.yara_dirs.iter().cloned());
        if paths.is_empty() {
            None
        } else {
            Some(std::sync::Arc::new(yarascan::compile(&paths)?))
        }
    };
    if cli.verbose > 0 {
        eprintln!(
            "argus: {} rules from {} rulesets",
            rules.len(),
            set_names.len()
        );
    }

    let mut exclude_pats = cli.exclude.clone();
    exclude_pats.extend(cfg.defaults.excludes.iter().cloned());
    let exclude: Vec<regex::Regex> = exclude_pats
        .iter()
        .map(|p| regex::Regex::new(p).map_err(|e| format!("bad --exclude /{p}/: {e}")))
        .collect::<Result<_, _>>()?;

    let opts = ScanOptions {
        max_file_size: max_kb * 1024,
        jobs,
        exclude,
        include_git: cli.include_git,
        disabled: disabled.clone(),
        only_sets: only.clone(),
        incremental: cli.incremental,
        progress: progress_on,
        styles,
        #[cfg(feature = "yara")]
        yara: yara_rules,
        ..ScanOptions::default()
    };

    // offline mode: hard-refuse network commands, skip online extras
    let offline = cli.offline
        || cfg.defaults.offline.unwrap_or(false)
        || std::env::var_os("ARGUS_OFFLINE").is_some_and(|v| v != "0");
    if offline {
        if crate::cli::needs_network(&cli.cmd) {
            return Err("offline mode: this command needs the network".into());
        }
        if cli.osv || cli.check_runs {
            eprintln!("offline: skipping --osv/--check-runs");
        }
    }

    // Landlock sandbox: narrow fs/net for the scan phase. Config, rules and
    // tokens are already loaded; nothing below needs more than read on scan
    // roots (+/etc for resolver/TLS), write on clone/output dirs, and TCP
    // 443/22 only for remote work.
    // git operations under the sandbox are read-only safe, but diff/
    // ls-files may try to refresh the index (a write) - resolve changed
    // file lists before sandboxing.
    let diff_map: std::collections::HashMap<String, Vec<String>> =
        if let Cmd::Scan { paths } = &cli.cmd {
            if cli.staged {
                paths
                    .iter()
                    .map(|p| (p.display().to_string(), staged_files(p)))
                    .collect()
            } else if let Some(base) = &cli.diff {
                paths
                    .iter()
                    .map(|p| (p.display().to_string(), changed_files(p, base)))
                    .collect()
            } else {
                std::collections::HashMap::new()
            }
        } else {
            std::collections::HashMap::new()
        };

    // container-runtime commands are left unsandboxed: rootless
    // podman/docker manage their own user+mount namespaces, which
    // per-path Landlock grants cannot express (same tradeoff as
    // trivy/grype). Everything else stays sandboxed.
    if cli.incremental || matches!(cli.cmd, Cmd::Ip { .. }) {
        let _ = std::fs::create_dir_all(crate::cache::cache_dir());
    }
    let local_runtime = matches!(cli.cmd, Cmd::Image { remote: false, .. });
    let sandboxable = !local_runtime
        && !matches!(cli.cmd, Cmd::Host(crate::host::Cmd::Conns { ref command, .. }) if !command.is_empty());
    if sandboxable && !cli.no_sandbox && !cfg.defaults.no_sandbox.unwrap_or(false) {
        apply_sandbox(cli, &opts);
    } else if local_runtime && cli.verbose > 0 {
        eprintln!("note: image audit runs the container runtime unsandboxed");
    }

    let mut report = Report::new();
    match &cli.cmd {
        Cmd::Rules => {
            print_rules(&rules, &set_names, &styles);
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::RulesKeygen { privkey, pubkey } => {
            println!("{}", rulesign::keygen(privkey, pubkey)?);
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::RulesSign { file, key } => {
            println!("{}", rulesign::sign(file, key)?);
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::RulesUpdate { feed } => {
            let feed = feed
                .clone()
                .or_else(|| cfg.defaults.rules_feed.clone())
                .ok_or("no feed given (use --feed or defaults.rules_feed)")?;
            return rules_update(&feed, cli.verbose);
        }
        Cmd::Completions(a) => {
            let mut c = <Cli as clap::CommandFactory>::command();
            clap_complete::generate(a.shell, &mut c, "argus", &mut std::io::stdout());
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::Mcp => {
            return mcp::serve(rules, opts);
        }
        Cmd::Scan { paths } | Cmd::Review { paths } => {
            for p in paths {
                if !p.exists() {
                    report
                        .errors
                        .push(format!("{}: not found, skipped", p.display()));
                    continue;
                }
                let label = p.display().to_string();
                if cli.verbose > 0 {
                    eprintln!("scanning {label} ...");
                }
                let (mut findings, files) = if let Some(rels) = diff_map.get(&label) {
                    if cli.verbose > 0 {
                        let how = if cli.staged { "staged" } else { "changed" };
                        eprintln!("{}: {} {} files", label, rels.len(), how);
                    }
                    scan::scan_selected(p, rels, &label, &rules, &opts)
                } else {
                    scan::scan_root(p, &label, &rules, &opts)
                };
                report.files_scanned += files;
                report.targets.push(TargetStat {
                    label: label.clone(),
                    files,
                    findings: findings.len(),
                });
                report.findings.append(&mut findings);
            }
            if cli.history_secrets {
                cmd::misc::history_secrets(paths, &rules, &opts, &mut report, cli.verbose);
            }
            if let Some(refpath) = &cli.similar {
                crate::cmd::similar_cmd::vendored_check(
                    paths,
                    refpath,
                    &opts,
                    &mut report,
                    cli.verbose,
                );
            }
        }
        Cmd::Similar { a, b } => {
            crate::cmd::similar_cmd::similar_cmd(a, b.as_deref(), &opts, &mut report);
        }
        Cmd::Roam(a) => {
            roam_cmd(cli, a, &cfg, &rules, &opts, &mut report)?;
        }
        Cmd::Init { path, force } => {
            let root = path.clone().unwrap_or_else(|| PathBuf::from("."));
            let hooks = root.join(".git/hooks");
            let hook = hooks.join("pre-commit");
            if hook.exists() && !force {
                eprintln!("pre-commit hook exists - rerun with --force to overwrite");
                return Ok(ExitCode::from(2));
            }
            if let Err(e) = std::fs::create_dir_all(&hooks) {
                eprintln!("cannot create {}: {e}", hooks.display());
                return Ok(ExitCode::from(2));
            }
            let body = "#!/bin/sh
# argus pre-commit: scan staged files for secrets/IaC issues
exec argus scan --staged --fail-on medium
";
            match std::fs::write(&hook, body) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ =
                            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755));
                    }
                    println!("installed {}", hook.display());
                    return Ok(ExitCode::SUCCESS);
                }
                Err(e) => {
                    eprintln!("write {}: {e}", hook.display());
                    return Ok(ExitCode::from(2));
                }
            }
        }
        Cmd::Watch(a) => {
            return watch_cmd(cli, a, &cfg, &rules, &opts);
        }
        Cmd::Fix {
            paths,
            write,
            containers,
            iac,
            deps,
        } => {
            return cmd::misc::fix_cmd(cli, paths, *write, *containers, *iac, *deps);
        }
        Cmd::License { paths, deps } => {
            cmd::misc::license_cmd(paths, *deps, &opts, &mut report);
        }
        Cmd::Publish { paths } => {
            let roots = if paths.is_empty() {
                vec![PathBuf::from(".")]
            } else {
                paths.clone()
            };
            for root in &roots {
                match publish::collect(root, cli.verbose > 0) {
                    Ok(set) => {
                        eprintln!(
                            "publish pre-flight: {} [{}] ({} files via {})",
                            root.display(),
                            set.kind,
                            set.files.len(),
                            set.method
                        );
                        let mut fs = publish::name_checks(&set);
                        let (mut scan_fs, n) = scan::scan_selected(
                            root,
                            &set.files,
                            &root.display().to_string(),
                            &rules,
                            &opts,
                        );
                        report.files_scanned += n;
                        fs.append(&mut scan_fs);
                        report.findings.extend(fs);
                    }
                    Err(e) => report.errors.push(e),
                }
            }
        }
        Cmd::Verify { paths } => {
            let roots = if paths.is_empty() {
                vec![PathBuf::from(".")]
            } else {
                paths.clone()
            };
            let (fs, n) = verify::verify(&roots, cli.verbose > 0);
            eprintln!("verify: checked {} candidate tokens", n.min(25));
            report.findings.extend(fs);
        }
        osint_arms!() => return cmd::osint_cmd::run(cli, offline, format),
        Cmd::Host(_) => return cmd::host_cmd::run(cli, offline, format),
        Cmd::Web { url, depth } => match webscan::scan(url, *depth, &rules, &opts, cli.verbose > 0)
        {
            Ok(ws) => {
                eprintln!(
                    "web: {} ({} js assets scanned)",
                    ws.final_url, ws.assets_scanned
                );
                report.findings.extend(ws.findings);
            }
            Err(e) => report.errors.push(e),
        },
        Cmd::Image { image, remote, .. } if *remote => {
            // OCI registry API - no container runtime, network required
            cmd::misc::remote_image(image, &mut report, cli.verbose);
        }
        Cmd::Image {
            image,
            deep,
            remote: _,
        } => match image::audit(image, *deep, cli.verbose > 1) {
            Ok((mut fs, export, _rt)) => {
                if let Some(root) = &export {
                    let (mut more, n) = scan::scan_root(root, image, &rules, &opts);
                    report.files_scanned += n;
                    fs.append(&mut more);
                    // OS packages in the image -> OSV (Debian/Alpine)
                    if cli.osv || cli.dep_check {
                        let mut deps = image::os_packages(root);
                        deps.sort();
                        deps.dedup();
                        if !deps.is_empty() {
                            eprintln!("osv: querying {} os packages in image", deps.len());
                            let http = http::HttpClient::new(vec![]);
                            match osv::query_batch(&http, &deps) {
                                Ok(hits) => {
                                    // OS packages have no source-level
                                    // reference - empty map keeps them high
                                    let reach = Default::default();
                                    fs.extend(cmd::deps::vuln_findings(&deps, hits, "osv", &reach))
                                }
                                Err(e) => report.errors.push(format!("osv: {e}")),
                            }
                        }
                    }
                }
                report.findings.extend(fs);
            }
            Err(e) => report.errors.push(e),
        },
        Cmd::Trends { path } => {
            cmd::trends_cmd::trends_cmd(&path.display().to_string(), &mut report);
        }
        Cmd::Authors { paths, format: fmt } => {
            return authors_cmd(cli, paths, *fmt, &rules);
        }
        Cmd::Sbom { path, sbom_format } => {
            let out = match sbom_format {
                cli::SbomFmt::Cyclonedx => sbom::sbom(path, &opts),
                cli::SbomFmt::Spdx => sbom::sbom_spdx(path, &opts),
            };
            println!("{out}");
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::Ai { paths } => {
            let paths = if paths.is_empty() {
                vec![PathBuf::from(".")]
            } else {
                paths.clone()
            };
            let mut reports = Vec::new();
            for p in &paths {
                if !p.join(".git").exists() {
                    eprintln!("warn: {}: not a git repo", p.display());
                    continue;
                }
                reports.push(ai::analyze(p));
            }
            match cli.format.unwrap_or(Format::Text) {
                Format::Json => println!("{}", serde_json::to_string_pretty(&reports).unwrap()),
                _ => {
                    for r in &reports {
                        println!(
                            "{} - score {} ({}) [{} commits]",
                            r.repo, r.score, r.verdict, r.commits_sampled
                        );
                        for e in &r.evidence {
                            println!("  [{}] {}: {}", e.tier, e.kind, e.detail);
                        }
                        for s in &r.human_signals {
                            println!("  [human] {s}");
                        }
                    }
                }
            }
            return Ok(ExitCode::SUCCESS);
        }
        Cmd::Daemon(a) => {
            return daemon_cmd(cli, a, &cfg, &rules, &opts);
        }
        Cmd::System { extra } => {
            report.findings.extend(sysaudit::audit());
            scan_system(&mut report, &rules, &opts, extra, cli.verbose);
            report.targets.push(TargetStat {
                label: "pacman:foreign".into(),
                files: 0,
                findings: report
                    .findings
                    .iter()
                    .filter(|f| f.target == "pacman:foreign")
                    .count(),
            });
        }
        Cmd::Github(a) | Cmd::Gitlab(a) | Cmd::Gitea(a) => {
            scan_remote(cli, a, &cfg, &rules, &opts, &mut report)?;
        }
    }

    // git history audit (local repo paths only; remote clones are depth-1)
    if (cli.audit_history || cfg.defaults.audit_history.unwrap_or(false))
        && let Cmd::Scan { paths } = &cli.cmd
    {
        for p in paths {
            audit::audit_history(
                p,
                &p.display().to_string(),
                &mut report.findings,
                cli.verbose,
            );
        }
    }

    // run-window correlation: did flagged workflows actually execute in-window?
    if !offline && (cli.check_runs || cfg.defaults.check_runs.unwrap_or(false)) {
        check_runs(cli, &mut report);
    }

    // OSV advisories for pinned deps
    if !offline
        && (cli.osv || cli.dep_check || cfg.defaults.osv.unwrap_or(false))
        && let Err(e) = osv_scan(cli, &opts, &mut report)
    {
        report.errors.push(format!("osv: {e}"));
    }

    report.finalize(min_sev);

    // .argusignore suppressions - read from each scan root + cwd
    ignore::apply_report(&mut report);

    if let Some(vx) = &cli.vex {
        match vex::load(&vx.to_string_lossy()) {
            Ok(stmts) => {
                let (kept, sup) = vex::apply(std::mem::take(&mut report.findings), &stmts);
                report.findings = kept;
                report.summary.total -= sup;
                eprintln!("vex: {} finding(s) suppressed by {}", sup, vx.display());
            }
            Err(e) => report.errors.push(format!("vex: {e}")),
        }
    }
    if let Some(vout) = &cli.vex_out {
        let doc = vex::emit(
            &report.findings,
            concat!("argus/", env!("CARGO_PKG_VERSION")),
        );
        if let Err(e) = std::fs::write(vout, &doc) {
            eprintln!("vex-out: {e}");
        } else {
            eprintln!("vex: wrote {}", vout.display());
        }
    }

    // baseline handling
    let mut base_known = std::collections::HashSet::new();
    let baseline_path = cli
        .baseline
        .clone()
        .or_else(|| cfg.defaults.baseline.clone().map(PathBuf::from));
    if let Some(bp) = &baseline_path {
        base_known = baseline::load(bp)?;
    }
    let new_worst = if !base_known.is_empty() {
        let (_known, new) = baseline::partition(std::mem::take(&mut report.findings), &base_known);
        let w = baseline::worst_of(&new);
        report.summary.baselined = _known.len();
        if cli.fail_on_new {
            report.findings = new;
        } else {
            report.findings.extend(_known);
        }
        w
    } else {
        report.worst()
    };
    if let Some(bp) = &cli.write_baseline {
        baseline::write(bp, &report.findings)?;
        eprintln!("baseline written to {}", bp.display());
    }

    // persist scan for trend diffs
    if cli.store {
        for t in &report.targets {
            if let Err(e) = store::store_scan(&report, &t.label) {
                report.errors.push(format!("store: {e}"));
            }
        }
    }

    report.duration_ms = t0.elapsed().as_millis() as u64;

    if matches!(cli.cmd, Cmd::Review { .. }) {
        let s = cmd::review_cmd::review_cmd(cli, &report.findings);
        print!("{s}");
        return Ok(ExitCode::SUCCESS);
    }

    let rendered = match format {
        Format::Json => report.to_json(),
        Format::Markdown => report.to_markdown(),
        Format::Sarif => report.to_sarif(),
        Format::Codeclimate => report.to_codeclimate(),
        Format::Html => report.to_html(),
        Format::Text => report.to_text(&styles),
    };
    match &cli.output {
        Some(p) => {
            std::fs::write(p, &rendered).map_err(|e| format!("write {}: {e}", p.display()))?;
            eprintln!("report written to {}", p.display());
        }
        None => emit(&rendered),
    }
    // explicit --ci always annotates; auto-detect only for text output so
    // json/sarif stdout stays machine-parseable inside CI environments
    if cli.ci || cfg.defaults.ci.unwrap_or(false) || (in_ci() && matches!(format, Format::Text)) {
        emit(&report.to_annotations());
        if let Ok(sum) = std::env::var("GITHUB_STEP_SUMMARY") {
            let _ = std::fs::OpenOptions::new()
                .append(true)
                .open(&sum)
                .and_then(|mut f| {
                    std::io::Write::write_all(&mut f, report.to_markdown().as_bytes())
                });
        }
    }
    if matches!(format, Format::Text) {
        for e in &report.errors {
            eprintln!("warn: {e}");
        }
    }
    let worst = if cli.fail_on_new && !base_known.is_empty() {
        new_worst
    } else {
        report.worst()
    };
    Ok(if worst.is_some_and(|w| w >= fail_on) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

pub(crate) fn emit(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes());
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

pub fn scan_system_pub(
    report: &mut Report,
    rules: &[rules::CompiledRule],
    opts: &ScanOptions,
    verbose: u8,
) {
    scan_system(report, rules, opts, &[], verbose);
}

pub fn changed_files_pub(repo: &Path, base: &str) -> Vec<String> {
    changed_files(repo, base)
}
