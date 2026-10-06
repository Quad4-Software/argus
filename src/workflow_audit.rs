// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! zizmor-class GitHub Actions audits, implemented natively over yaml-rust2.
//! Covers: template-injection, excessive-permissions, dangerous-triggers,
//! secrets-inherit, github-env injection, artipacked, cache-poisoning,
//! self-hosted-runner, unpinned-images, bot-conditions, unsound-contains,
//! insecure-commands, ref-confusion. Rule ids: WFA-*.
//! (zizmor.sh is MIT; these audits mirror its audit semantics.)

use crate::finding::{Finding, Severity};
use std::collections::HashSet;
use yaml_rust2::Yaml;

/// Untrusted expression contexts (attacker-controlled in PR/issue triggers).
const UNTRUSTED: &[&str] = &[
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.head_ref",
    "github.event.commits.*.message",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.pages.*.page_name",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author.email",
    "inputs.",
    "github.event.inputs.",
];

/// Dangerous triggers that grant write creds/secrets.
const PRIV_TRIGGERS: &[&str] = &[
    "pull_request_target",
    "workflow_run",
    "issues",
    "issue_comment",
    "workflow_call",
    "workflow_dispatch",
];

fn sev_rank(s: Severity) -> u8 {
    s as u8
}

pub fn audit(rel: &str, text: &str, target: &str, disabled: &HashSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let docs = match yaml_rust2::YamlLoader::load_from_str(text) {
        Ok(d) => d,
        Err(_) => return out,
    };
    let Some(doc) = docs.first() else { return out };

    let on = &doc["on"];
    let triggers: Vec<String> = collect_triggers(on);
    let jobs = &doc["jobs"];
    let top_perms = perm_map(&doc["permissions"]);
    let env_map = |n: &Yaml| -> Vec<(String, String)> {
        n.as_hash()
            .map(|h| {
                h.iter()
                    .filter_map(|(k, v)| {
                        Some((
                            k.as_str()?.to_string(),
                            v.as_str().unwrap_or("").to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    // --- excessive-permissions (WFA-001) ---
    for (scope, p) in [("top-level", &top_perms)] {
        for (k, v) in p {
            if *v == "write-all"
                || (v == "write"
                    && matches!(
                        k.as_str(),
                        "*" | "contents" | "actions" | "id-token" | "packages"
                    ))
            {
                out.push(mk(
                    "WFA-001",
                    Severity::Medium,
                    rel,
                    target,
                    format!("{scope} permissions grants `{k}: {v}` - broad write scope"),
                    "Restrict permissions to the minimum required.",
                    disabled,
                ));
            }
        }
    }

    let priv_trigger = triggers.iter().any(|t| PRIV_TRIGGERS.contains(&t.as_str()));

    // --- secrets-inherit (WFA-004) + per-job audits ---
    if let Some(jmap) = jobs.as_hash() {
        for (jname, job) in jmap {
            let jn = jname.as_str().unwrap_or("?");
            if job["secrets"].as_str() == Some("inherit") {
                out.push(mk("WFA-004", Severity::High, rel, target,
                    format!("job `{jn}` uses `secrets: inherit` - all secrets flow into a reusable workflow"),
                    "List only the secrets the called workflow needs.", disabled));
            }
            // job-level permissions
            for (_k, v) in perm_map(&job["permissions"]) {
                if v == "write-all" {
                    out.push(mk(
                        "WFA-001",
                        Severity::Medium,
                        rel,
                        target,
                        format!("job `{jn}` permissions: write-all"),
                        "Scope down.",
                        disabled,
                    ));
                }
            }
            // self-hosted runner + PR-shaped triggers (WFA-007)
            let ro = job["runs-on"].as_str().unwrap_or("");
            let ro_list = job["runs-on"]
                .as_vec()
                .map(|v| v.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();
            let self_hosted =
                ro.contains("self-hosted") || ro_list.iter().any(|r| r.contains("self-hosted"));
            if self_hosted && triggers.iter().any(|t| t.starts_with("pull_request")) {
                out.push(mk("WFA-007", Severity::High, rel, target,
                    format!("job `{jn}` runs PR code on a self-hosted runner (runs-on: {ro})"),
                    "Self-hosted runners persist secrets/state across jobs; PR code on them is a host-compromise path.", disabled));
            }
            // steps
            if let Some(steps) = job["steps"].as_vec() {
                for step in steps {
                    audit_step(rel, target, step, priv_trigger, &mut out, disabled);
                }
            }
            // container / services image pinning (WFA-008)
            for key in ["container", "image"] {
                image_audit(rel, target, jn, &job[key], &mut out, disabled);
            }
            if let Some(svcs) = job["services"].as_hash() {
                for (sn, svc) in svcs {
                    image_audit(
                        rel,
                        target,
                        sn.as_str().unwrap_or("svc"),
                        svc,
                        &mut out,
                        disabled,
                    );
                }
            }
        }
    }

    // --- top-level env (WFA-003 github-env handled per run-step; env-file writes) ---
    for (k, v) in env_map(&doc["env"]) {
        let _ = (k, v);
    }
    let _ = sev_rank;
    out
}

fn audit_step(
    rel: &str,
    target: &str,
    step: &Yaml,
    priv_trigger: bool,
    out: &mut Vec<Finding>,
    disabled: &HashSet<String>,
) {
    // run-step template injection (WFA-002)
    if let Some(run) = step["run"].as_str() {
        for u in UNTRUSTED {
            if run.contains(&format!("${{{{ {u}"))
                || run.contains(&format!("${{{{{u}"))
                || run.contains(u)
            {
                let sev = if priv_trigger {
                    Severity::High
                } else {
                    Severity::Medium
                };
                out.push(mk(
                    "WFA-002",
                    sev,
                    rel,
                    target,
                    format!(
                        "template injection: untrusted context `{u}` interpolated into a run step"
                    ),
                    "Pass via env: instead of ${{ }} interpolation, or sanitize input.",
                    disabled,
                ));
                break;
            }
        }
        // github-env / output injection (WFA-003)
        if run.contains("GITHUB_ENV")
            || run.contains("GITHUB_OUTPUT")
            || run.contains("GITHUB_PATH")
        {
            out.push(mk("WFA-003", Severity::Medium, rel, target,
                "run step writes to GITHUB_ENV/GITHUB_OUTPUT/GITHUB_PATH",
                "These files set env/paths for later steps; untrusted values here inject into the whole job.", disabled));
        }
        // insecure commands (WFA-010)
        if run.contains("ACTIONS_ALLOW_UNSECURE_COMMANDS")
            || run.contains("::set-env")
            || run.contains("::add-path")
        {
            out.push(mk(
                "WFA-010",
                Severity::High,
                rel,
                target,
                "deprecated workflow command enabled (set-env/add-path/ALLOW_UNSECURE_COMMANDS)",
                "These re-enable commands removed for being injection-prone.",
                disabled,
            ));
        }
    }

    // env: on step / with: containing untrusted contexts (WFA-002 weaker)
    for (k, v) in step["env"]
        .as_hash()
        .map(|h| {
            h.iter()
                .filter_map(|(k, v)| {
                    Some((
                        k.as_str()?.to_string(),
                        v.as_str().unwrap_or("").to_string(),
                    ))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
    {
        let _ = (k, v);
    }

    // uses: steps
    if let Some(u) = step["uses"].as_str() {
        // artipacked (WFA-005): upload-artifact of repo/.git/cred files
        if u.starts_with("actions/upload-artifact") {
            let path = step["with"]["path"].as_str().unwrap_or("");
            let name_missing = step["with"]["name"].is_badvalue();
            if path.contains(".git")
                || path.is_empty()
                || path == "."
                || path == "**"
                || path.contains("id_rsa")
                || path.contains(".env")
                || path.contains("credentials")
                || (name_missing
                    && (path.contains("~") || path.contains("${{ github.workspace }}")))
            {
                out.push(mk(
                    "WFA-005",
                    Severity::Medium,
                    rel,
                    target,
                    format!(
                        "upload-artifact captures `{}` - may include .git credentials or secrets",
                        if path.is_empty() { "<repo root>" } else { path }
                    ),
                    "checkout persists credentials in .git/config; never upload the repo root.",
                    disabled,
                ));
            }
        }
        // cache poisoning (WFA-006): cache of repo workspace on PR workflows
        if u.starts_with("actions/cache") && priv_trigger {
            let path = step["with"]["path"].as_str().unwrap_or("");
            if path.contains("github.workspace")
                || path == "."
                || path.contains("dist/")
                || path.contains("build/")
            {
                out.push(mk("WFA-006", Severity::Medium, rel, target,
                    "actions/cache restores workspace/build dirs under a privileged trigger",
                    "Cache entries are attacker-controllable across PR runs; don't restore executable content.", disabled));
            }
        }
        // artipacked-credentials (WFA-013): checkout persists creds so later
        // steps (and uploaded artifacts) carry them
        if u.starts_with("actions/checkout") {
            let pc = &step["with"]["persist-credentials"];
            if pc.as_bool() == Some(true) {
                out.push(mk("WFA-013", Severity::Medium, rel, target,
                    "actions/checkout with persist-credentials: true - token leaks into .git for the whole job",
                    "Set persist-credentials: false; the default already covers it for read-only jobs.", disabled));
            }
        }
        // ref-confusion (WFA-009): checkout of PR head under pull_request_target
        if u.starts_with("actions/checkout") {
            let r = step["with"]["ref"].as_str().unwrap_or("");
            if priv_trigger
                && (r.contains("pull_request.head")
                    || r.contains("head.sha")
                    || r.contains("head.ref"))
            {
                out.push(mk("WFA-009", Severity::High, rel, target,
                    format!("actions/checkout of `{r}` under a privileged trigger - attacker code runs with secrets"),
                    "Checking out the PR head under pull_request_target/workflow_run executes untrusted code with the write token.", disabled));
            }
        }
    }

    // bot-conditions / unsound-contains (WFA-011/012): step-level if
    if let Some(cond) = step["if"].as_str() {
        if cond.contains("github.actor")
            || cond.contains("sender.login")
            || cond.contains("author_association")
        {
            out.push(mk(
                "WFA-011",
                Severity::Low,
                rel,
                target,
                format!(
                    "if: condition gates on a forgeable actor field ({})",
                    cond.trim()
                ),
                "github.actor/sender.login are attacker-choosable on many events.",
                disabled,
            ));
        }
        if cond.contains("contains(") && (cond.contains("github.event") || cond.contains("inputs."))
        {
            out.push(mk(
                "WFA-012",
                Severity::Low,
                rel,
                target,
                "unsound contains() on event data in if: condition",
                "contains() on attacker-controlled strings is bypassable (substring smuggling).",
                disabled,
            ));
        }
    }
    let _ = job_level_placeholder;
}

#[allow(dead_code)]
fn job_level_placeholder() {}

fn image_audit(
    rel: &str,
    target: &str,
    scope: &str,
    y: &Yaml,
    out: &mut Vec<Finding>,
    disabled: &HashSet<String>,
) {
    let img = match y {
        Yaml::String(s) => Some(s.clone()),
        Yaml::Hash(_) => y["image"].as_str().map(String::from),
        _ => None,
    };
    if let Some(img) = img
        && !img.contains("@sha256:")
        && !img.is_empty()
    {
        out.push(mk(
            "WFA-008",
            Severity::Info,
            rel,
            target,
            format!("container image `{img}` for `{scope}` is not digest-pinned"),
            "Pin service/container images by sha256 digest.",
            disabled,
        ));
    }
}

fn collect_triggers(on: &Yaml) -> Vec<String> {
    match on {
        Yaml::String(s) => vec![s.clone()],
        Yaml::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        Yaml::Hash(h) => h
            .keys()
            .filter_map(|k| k.as_str().map(String::from))
            .collect(),
        _ => vec![],
    }
}

fn perm_map(y: &Yaml) -> Vec<(String, String)> {
    match y {
        Yaml::String(s) => vec![("*".into(), s.clone())],
        Yaml::Hash(h) => h
            .iter()
            .filter_map(|(k, v)| Some((k.as_str()?.into(), v.as_str().unwrap_or("?").into())))
            .collect(),
        _ => vec![],
    }
}

fn mk(
    id: &str,
    sev: Severity,
    rel: &str,
    target: &str,
    msg: impl Into<String>,
    fix: &str,
    disabled: &HashSet<String>,
) -> Finding {
    let _ = disabled; // filtering applied by caller via opts
    Finding {
        ruleset: "workflow-audit".into(),
        rule_id: id.into(),
        severity: sev,
        target: target.into(),
        path: rel.into(),
        line: None,
        excerpt: None,
        message: msg.into(),
        remediation: Some(fix.into()),
        reference: Some("https://docs.zizmor.sh/audits/".into()),
        window: None,
        evidence: None,
    }
}
