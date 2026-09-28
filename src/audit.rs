//! Git history audit + GitHub run-window correlation.
//! audit_history: suspicious commits in known compromise windows.
//! check_runs: did a workflow using a compromised action actually run inside
//! the window? (GitHub API; needs token for private repos / higher limits.)

use crate::finding::{Finding, Severity};
use std::path::Path;
use std::process::Command;

/// Known compromise windows as (label, start, end) ISO dates.
/// Aligned with the campaign rulesets.
pub const WINDOWS: &[(&str, &str, &str)] = &[
    (
        "tj-actions/reviewdog compromise",
        "2025-03-11",
        "2025-03-15",
    ),
    ("AUR CHAOS RAT", "2025-07-16", "2025-07-19"),
    ("Shai-Hulud npm worm", "2025-09-14", "2025-09-19"),
    (
        "TeamPCP trivy/canisterworm/litellm",
        "2026-03-19",
        "2026-03-27",
    ),
    ("Mini Shai-Hulud antv wave", "2026-05-18", "2026-05-19"),
    (
        "actions-cool re-enabled (payload live again)",
        "2026-09-16",
        "2026-09-25",
    ),
];

fn is_git_repo(root: &Path) -> bool {
    root.join(".git").exists()
}

/// git remote get-url origin -> Some((host, owner, repo)) for github/gitlab/gitea https or ssh urls.
pub fn origin_repo(root: &Path) -> Option<(String, String, String)> {
    let out = Command::new("git")
        .args([
            "-C",
            &*root.to_string_lossy(),
            "remote",
            "get-url",
            "origin",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_remote(String::from_utf8_lossy(&out.stdout).trim())
}

pub fn parse_remote(url: &str) -> Option<(String, String, String)> {
    let url = url.trim().trim_end_matches(".git");
    // https://host/owner/repo or ssh://git@host/owner/repo or git@host:owner/repo
    if let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    {
        let mut it = rest.split('/');
        let host = it.next()?.to_string();
        let owner = it.next()?.to_string();
        let repo = it.next()?.to_string();
        return Some((host, owner, repo));
    }
    if let Some(rest) = url
        .strip_prefix("ssh://")
        .or_else(|| url.strip_prefix("git@"))
    {
        let rest = rest.trim_start_matches(|c: char| !c.is_alphanumeric() && c != '@');
        let rest = rest.split('@').next_back().unwrap_or(rest);
        let (host, path) = rest.split_once(':').or_else(|| rest.split_once('/'))?;
        let mut it = path.split('/');
        let owner = it.next()?.to_string();
        let repo = it.next()?.to_string();
        return Some((host.to_string(), owner, repo));
    }
    None
}

/// Audit commits in compromise windows + forged-author hints.
/// Only runs when root is a git repo.
pub fn audit_history(root: &Path, target: &str, findings: &mut Vec<Finding>, verbose: u8) {
    if !is_git_repo(root) {
        return;
    }
    let r = root.to_string_lossy();
    for (label, start, end) in WINDOWS {
        let out = Command::new("git")
            .args([
                "-C",
                &r,
                "log",
                "--all",
                &format!("--since={start}T00:00:00"),
                &format!("--until={end}T23:59:59"),
                "--format=%H|%ad|%an|%ae|%s",
                "--date=short",
            ])
            .output();
        let Ok(out) = out else { continue };
        if !out.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let mut p = line.split('|');
            let (sha, date, author, _email, subj) = (
                p.next().unwrap_or(""),
                p.next().unwrap_or(""),
                p.next().unwrap_or(""),
                p.next().unwrap_or(""),
                p.next().unwrap_or(""),
            );
            findings.push(Finding {
                ruleset: "git-audit".into(),
                rule_id: "GIT-WIN".into(),
                severity: Severity::Medium,
                target: target.into(),
                path: ".git".into(),
                line: None,
                excerpt: Some(format!(
                    "{date} {author} \"{}\" ({})",
                    &subj[..subj.len().min(80)],
                    &sha[..sha.len().min(12)]
                )),
                message: format!("commit inside the {label} window ({start}..{end})"),
                remediation: Some(
                    "Confirm the commit is expected; forged committer identity is trivial in git."
                        .into(),
                ),
                reference: None,
                window: Some((start.to_string(), end.to_string())),
            });
        }
        if verbose > 1 {
            eprintln!(
                "audit {}: {} commit(s) in {}",
                r,
                text.lines().count(),
                label
            );
        }
    }
}

/// For a GitHub-hosted repo with a flagged workflow file, list runs of that
/// workflow inside window (YYYY-MM-DD). Returns count of runs observed.
pub fn github_runs_in_window(
    api_base: &str,
    token: Option<&str>,
    owner: &str,
    repo: &str,
    workflow_path: &str,
    window: &(String, String),
) -> Result<usize, String> {
    let http = crate::http::HttpClient::new(match token {
        Some(t) => vec![
            ("Authorization".into(), format!("Bearer {t}")),
            ("Accept".into(), "application/vnd.github+json".into()),
        ],
        None => vec![("Accept".into(), "application/vnd.github+json".into())],
    });
    // workflow_id accepts a path like "stale.yml" when using the filename form;
    // use the runs endpoint filtered by workflow file name.
    let fname = workflow_path.rsplit('/').next().unwrap_or(workflow_path);
    let url = format!(
        "{api_base}/repos/{owner}/{repo}/actions/workflows/{fname}/runs?created={}..{}&per_page=100",
        window.0, window.1
    );
    let v = http.get_json(&url)?;
    Ok(v["total_count"].as_u64().unwrap_or(0) as usize)
}

/// Unique commit authors (name + email + count) across all branches.
/// Sorted by commit count desc - the import list for identity review.
pub fn authors(root: &Path) -> Vec<(String, String, usize)> {
    let r = root.to_string_lossy();
    let out = Command::new("git")
        .args(["-C", &r, "log", "--all", "--format=%an|%ae"])
        .output();
    let Ok(out) = out else { return vec![] };
    if !out.status.success() {
        return vec![];
    }
    let mut counts: std::collections::HashMap<(String, String), usize> =
        std::collections::HashMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some((n, e)) = line.split_once('|') {
            *counts.entry((n.to_string(), e.to_string())).or_default() += 1;
        }
    }
    let mut v: Vec<(String, String, usize)> =
        counts.into_iter().map(|((n, e), c)| (n, e, c)).collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.2));
    v
}

/// Render the author list as text for content-rule scanning (ACTOR-*).
pub fn authors_text(root: &Path) -> String {
    authors(root)
        .iter()
        .map(|(n, e, c)| format!("{n} <{e}> ({c} commits)"))
        .collect::<Vec<_>>()
        .join("\n")
}
