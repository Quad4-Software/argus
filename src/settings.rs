// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Org/repo security-settings audit via forge APIs.
//!
//! Distinct from file scanning: this checks posture the working tree cannot
//! show - branch protection, Actions permissions, org default permissions,
//! 2FA enforcement. GitHub API for now; gitlab/gitea get a stub notice.
//! Everything degrades gracefully: 401/403 means "cannot tell", not failure.

use crate::finding::{Finding, Severity};
use crate::http::HttpClient;
use crate::provider::{RepoSpec, Selector};

fn finding(target: &str, id: &str, sev: Severity, msg: String, remediation: &str) -> Finding {
    Finding {
        ruleset: "repo-settings".into(),
        rule_id: id.into(),
        severity: sev,
        target: target.into(),
        path: ".".into(),
        line: None,
        excerpt: None,
        message: msg,
        remediation: Some(remediation.into()),
        reference: None,
        window: None,
    }
}

/// Audit org + repo posture on GitHub. repos is the already-filtered list;
/// without a token the unauthenticated API budget (~60/hr) caps per-repo
/// checks to the first few repos.
pub fn audit_github(
    api: &str,
    token: Option<&str>,
    sel: &Selector,
    repos: &[RepoSpec],
) -> Vec<Finding> {
    let mut headers = vec![
        (
            "Accept".to_string(),
            "application/vnd.github+json".to_string(),
        ),
        ("X-GitHub-Api-Version".to_string(), "2022-11-28".to_string()),
    ];
    if let Some(t) = token {
        headers.push(("Authorization".to_string(), format!("Bearer {t}")));
    }
    let http = HttpClient::new(headers);
    let mut out = Vec::new();

    if let Selector::Org(org) = sel {
        org_findings(&http, api, org, &mut out);
    }

    // unauthenticated API is ~60 req/hr; cap repo-level calls accordingly
    let budgeted = if token.is_some() { repos.len() } else { 8 };
    for repo in repos.iter().take(budgeted) {
        repo_findings(&http, api, repo, &mut out);
    }
    if repos.len() > budgeted {
        out.push(finding(
            "settings",
            "RST-000",
            Severity::Info,
            format!(
                "settings audit covered {budgeted}/{} repos - pass --token (or GITHUB_TOKEN) for full coverage",
                repos.len()
            ),
            "Set a token; unauthenticated GitHub API is rate-limited to ~60 requests/hour.",
        ));
    }
    out
}

fn org_findings(http: &HttpClient, api: &str, org: &str, out: &mut Vec<Finding>) {
    let t = format!("org:{org}");
    if let Ok((st, v)) = http.get_status_json(&format!("{api}/orgs/{org}"))
        && st == 200
    {
        match v["default_repository_permission"].as_str() {
                Some("write") | Some("admin") => out.push(finding(
                    &t,
                    "RST-101",
                    Severity::Medium,
                    format!(
                        "org default repository permission is {:?} - every member can push to every repo",
                        v["default_repository_permission"].as_str().unwrap_or_default()
                    ),
                    "Set org Settings > Member privileges > base permission to Read or None.",
                )),
                Some(_) => {}
                None => {}
            }
        if v["members_can_create_repositories"].as_bool() == Some(true) {
            out.push(finding(
                &t,
                "RST-102",
                Severity::Info,
                "org members can create repositories - repos may appear outside review".into(),
                "Disable member repo creation or set it to private-only.",
            ));
        }
        if v["two_factor_requirement_enabled"].as_bool() == Some(false) {
            out.push(finding(
                &t,
                "RST-103",
                Severity::Medium,
                "org does not require two-factor authentication".into(),
                "Enable 2FA requirement in org security settings.",
            ));
        }
    }
    match http.get_status_json(&format!("{api}/orgs/{org}/actions/permissions")) {
        Ok((200, v)) => {
            if v["allowed_actions"].as_str() == Some("all") {
                out.push(finding(
                    &t,
                    "RST-110",
                    Severity::Medium,
                    "org Actions policy allows ALL actions - any unpinned third-party action can run in every workflow".into(),
                    "Restrict to selected actions / verified creators, or fork-internal actions only.",
                ));
            }
        }
        Ok((404, _)) => {} // fine-grained default; nothing configured
        _ => {}
    }
}

fn repo_findings(http: &HttpClient, api: &str, repo: &RepoSpec, out: &mut Vec<Finding>) {
    let t = &repo.full_name;
    let mut default_branch = "main".to_string();
    if let Ok((st, v)) = http.get_status_json(&format!("{api}/repos/{t}"))
        && st == 200
    {
        if let Some(b) = v["default_branch"].as_str() {
            default_branch = b.to_string();
        }
        if repo.private && v["allow_forking"].as_bool() == Some(true) {
            out.push(finding(
                t,
                "RST-201",
                Severity::Medium,
                "private repo allows forking - members can copy code outside the org".into(),
                "Disable forking on the repo or org policy.",
            ));
        }
        if v["web_commit_signoff_required"].as_bool() == Some(false) && !repo.fork && !repo.archived
        {
            out.push(finding(
                    t,
                    "RST-202",
                    Severity::Info,
                    "web commits do not require signoff (DCO)".into(),
                    "Enable 'Require contributors to sign off on web-based commits' if the project wants DCO provenance.",
                ));
        }
    }
    match http.get_status_json(&format!(
        "{api}/repos/{t}/branches/{default_branch}/protection"
    )) {
        Ok((200, v)) => {
            if v["required_pull_request_reviews"].is_null() {
                out.push(finding(
                    t,
                    "RST-211",
                    Severity::Info,
                    format!("{default_branch} is protected but requires no pull-request reviews"),
                    "Add required approving reviews to the protection rule.",
                ));
            }
        }
        Ok((404, _)) if !repo.fork && !repo.archived => {
            out.push(finding(
                t,
                "RST-210",
                Severity::Medium,
                format!("default branch {default_branch} has no protection - direct pushes can rewrite release history"),
                "Add a branch protection rule: require PRs, dismiss stale reviews, restrict force pushes.",
            ));
        }
        _ => {} // 401/403: cannot determine, stay quiet
    }
    if let Ok((200, v)) = http.get_status_json(&format!("{api}/repos/{t}/actions/permissions"))
        && v["allowed_actions"].as_str() == Some("all")
    {
        out.push(finding(
                t,
                "RST-220",
                Severity::Medium,
                "Actions policy allows all actions - unpinned third-party actions run with repo secrets".into(),
                "Set 'Allow actions created by GitHub and verified Marketplace creators' or a selected allowlist.",
            ));
    }
}
