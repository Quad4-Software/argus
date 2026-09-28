use crate::cli::{Cli, Cmd};
use crate::finding::{Finding, Report, Severity};
use crate::scan::ScanOptions;
use crate::{config, depcheck, finding, http, osv, rules, scan};
use std::path::{Path, PathBuf};

/// Collect pinned deps from manifests under one root.
pub(crate) fn collect_deps(
    root: &Path,
    prefix: &str,
    opts: &ScanOptions,
    deps: &mut Vec<osv::Dep>,
) {
    let manifest_re = regex::Regex::new(rules::CompiledRule::DEP_MANIFESTS_RE).unwrap();
    for f in scan::collect_files(root, false) {
        let rel = f
            .strip_prefix(root)
            .unwrap_or(&f)
            .to_string_lossy()
            .replace('\\', "/");
        let is_wf = rel.contains("workflows/") && (rel.ends_with(".yml") || rel.ends_with(".yaml"));
        if !manifest_re.is_match(&rel) && !is_wf {
            continue;
        }
        if let Ok(b) = std::fs::read(&f) {
            if !b.is_empty() && b.len() <= opts.max_file_size as usize {
                for mut d in osv::extract_deps(&rel, &String::from_utf8_lossy(&b)) {
                    if !prefix.is_empty() {
                        d.path = format!("{prefix}/{}", d.path);
                    }
                    deps.push(d);
                }
            }
        }
    }
}

/// Collect pinned deps from manifests under the scanned roots, query OSV.
pub(crate) fn osv_scan(cli: &Cli, opts: &ScanOptions, report: &mut Report) -> Result<(), String> {
    let mut deps: Vec<osv::Dep> = Vec::new();
    let roots: Vec<PathBuf> = match &cli.cmd {
        Cmd::Scan { paths } => paths.clone(),
        Cmd::System { .. } => vec![],
        _ => vec![],
    };
    for root in roots {
        collect_deps(&root, "", opts, &mut deps);
    }
    // remote scans: deps collected during clone loop get merged here
    run_osv_queries(cli, deps, report)
}

pub(crate) fn cfg_deps_prefixes() -> Vec<String> {
    config::load(None)
        .map(|(c, _)| c.defaults.internal_prefixes)
        .unwrap_or_default()
}

/// Probe whether a github "owner/repo" path is archived (token-aware).
pub(crate) fn dep_upstream_probe() -> impl Fn(&str) -> Option<bool> {
    let token = std::env::var("GITHUB_TOKEN")
        .ok()
        .or_else(|| std::env::var("GH_TOKEN").ok());
    let mut headers = vec![(
        "Accept".to_string(),
        "application/vnd.github+json".to_string(),
    )];
    if let Some(t) = &token {
        headers.push(("Authorization".into(), format!("Bearer {t}")));
    }
    let http = http::HttpClient::new(headers);
    move |repo: &str| match http.get_status_json(&format!("https://api.github.com/repos/{repo}")) {
        Ok((200, v)) => Some(v["archived"].as_bool().unwrap_or(false)),
        _ => None,
    }
}

pub(crate) fn run_osv_queries(
    cli: &Cli,
    mut deps: Vec<osv::Dep>,
    report: &mut Report,
) -> Result<(), String> {
    deps.extend(REMOTE_DEPS.lock().unwrap().drain(..));
    deps.sort();
    deps.dedup();
    if deps.is_empty() {
        if cli.verbose > 0 {
            eprintln!("osv: no pinned deps found");
        }
        return Ok(());
    }
    let http = http::HttpClient::new(vec![]);

    // registry hygiene: confusion + unmaintained (independent of osv)
    if cli.dep_check {
        let mut prefixes = cli.internal_prefixes.clone();
        prefixes.extend(cfg_deps_prefixes());
        eprintln!("dep-check: registry lookups on {} deps", deps.len());
        let probe = dep_upstream_probe();
        report.findings.extend(depcheck::check(
            &deps,
            "deps",
            &prefixes,
            &http,
            Some(&probe),
        ));
    }
    if !cli.osv {
        return Ok(());
    }
    eprintln!("osv: querying {} pinned deps", deps.len());
    let hits = osv::query_batch(&http, &deps)?;
    report.findings.extend(vuln_findings(&deps, hits, "osv"));
    Ok(())
}

/// Shared vuln-hit -> finding mapping used by scan --osv and image --deep.
pub(crate) fn vuln_findings(
    deps: &[osv::Dep],
    hits: Vec<(usize, String, String)>,
    ruleset: &str,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, id, summary) in hits {
        let d = &deps[i];
        let is_mal = id.starts_with("MAL-");
        out.push(finding::Finding {
            ruleset: ruleset.into(),
            rule_id: id.clone(),
            severity: if is_mal {
                Severity::Critical
            } else {
                Severity::High
            },
            target: d.path.clone(),
            path: d.path.clone(),
            line: None,
            excerpt: Some(format!("{} {}@{}", d.ecosystem, d.name, d.version)),
            message: format!(
                "OSV advisory {id} for {} {}@{}{}{}",
                d.ecosystem,
                d.name,
                d.version,
                if is_mal { " (malicious package)" } else { "" },
                if summary.is_empty() {
                    String::new()
                } else {
                    format!(": {summary}")
                }
            ),
            remediation: Some(if is_mal {
                "Malicious package version; do not install, rotate credentials on hosts that did."
                    .into()
            } else {
                "Review the advisory and upgrade if affected.".into()
            }),
            reference: Some(format!("https://osv.dev/vulnerability/{id}")),
            window: None,
        });
    }
    out
}

pub(crate) static REMOTE_DEPS: std::sync::Mutex<Vec<osv::Dep>> = std::sync::Mutex::new(Vec::new());

pub(crate) type CloneScanResult = Result<(Vec<finding::Finding>, usize), String>;
