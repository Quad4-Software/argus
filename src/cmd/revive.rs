// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Dangling-commit recovery. GHArchive keeps push SHAs after a force
//! push or branch delete; GitHub still serves those objects by SHA
//! (allowAnySHA1InWant). Fetch the SHA, check it out, scan the tree.

use crate::finding::Severity;
use crate::osint::GhEvent;
use crate::rules::CompiledRule;
use crate::scan::ScanOptions;
use std::process::Command;

fn git(dir: &std::path::Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// repo -> SHAs to fetch (head and before of each push), deduped.
fn push_targets(evs: &[GhEvent]) -> Vec<(String, Vec<String>)> {
    let mut repos: Vec<(String, Vec<String>)> = Vec::new();
    for e in evs {
        if e.kind != "PushEvent" || e.repo.is_empty() {
            continue;
        }
        let entry = match repos.iter_mut().find(|(r, _)| *r == e.repo) {
            Some((_, v)) => v,
            None => {
                repos.push((e.repo.clone(), Vec::new()));
                &mut repos.last_mut().unwrap().1
            }
        };
        for sha in [&e.head, &e.before] {
            if !sha.is_empty() && sha.chars().all(|c| c.is_ascii_hexdigit()) && !entry.contains(sha)
            {
                entry.push(sha.clone());
            }
        }
    }
    repos
}

/// For each repo in the push events, fetch the observed SHAs and scan
/// each one. Findings are labeled repo@sha. Emitted to stderr/stdout as
/// a second report after the archive report itself.
pub(crate) fn run(
    evs: &[GhEvent],
    max: usize,
    rules: &[CompiledRule],
    opts: &ScanOptions,
    verbose: bool,
) {
    let repos = push_targets(evs);
    if repos.is_empty() {
        eprintln!("revive: no push SHAs to fetch");
        return;
    }
    let workdir = std::env::home_dir()
        .unwrap_or_else(|| "/tmp".into())
        .join(".local/share/argus/gharchive-clones");
    if let Err(e) = std::fs::create_dir_all(&workdir) {
        eprintln!("revive: {workdir:?}: {e}");
        return;
    }
    let mut fetched = 0usize;
    for (repo, shas) in &repos {
        if fetched >= max {
            break;
        }
        let dest = workdir.join(repo.replace('/', "__"));
        let url = format!("https://github.com/{repo}.git");
        if !dest.join(".git").exists()
            && let Err(e) = crate::clone::clone_repo(&url, &dest, None, &workdir, verbose)
        {
            eprintln!("revive: clone {repo}: {e}");
            continue;
        }
        for sha in shas {
            if fetched >= max {
                break;
            }
            if !git(&dest, &["fetch", "-q", "--depth", "200", "origin", sha]) {
                eprintln!("revive: {repo}@{sha}: fetch failed (GC'd or private)");
                continue;
            }
            fetched += 1;
            if !git(&dest, &["checkout", "-qf", sha]) {
                eprintln!("revive: {repo}@{sha}: checkout failed");
                continue;
            }
            let short = &sha[..12.min(sha.len())];
            let label = format!("{repo}@{short}");
            let changed = git(&dest, &["rev-parse", "--verify", &format!("{sha}~1")])
                .then(|| super::watcher::delta_files(&dest, &format!("{sha}~1"), sha))
                .flatten();
            let (mut findings, _) = match changed {
                Some(rels) if rels.len() <= 500 => {
                    crate::scan::scan_selected(&dest, &rels, &label, rules, opts)
                }
                _ => crate::scan::scan_root(&dest, &label, rules, opts),
            };
            eprintln!("revive: {label}: {} finding(s)", findings.len());
            for f in &mut findings {
                f.target = label.clone();
            }
            let mut r = crate::finding::Report::new();
            r.findings = findings;
            r.finalize(Severity::Info);
            crate::emit(&r.to_text(&crate::color::Styles::new(crate::color::ColorMode::Auto)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push(repo: &str, head: &str, before: &str) -> GhEvent {
        GhEvent {
            kind: "PushEvent".into(),
            repo: repo.into(),
            actor: "a".into(),
            created: String::new(),
            git_ref: "refs/heads/main".into(),
            head: head.into(),
            before: before.into(),
            action: String::new(),
            detail: String::new(),
            emails: Vec::new(),
        }
    }

    #[test]
    fn groups_shas_per_repo_deduped() {
        let evs = vec![
            push("a/b", "aa11", "bb22"),
            push("a/b", "cc33", "aa11"), // aa11 repeats
            push("c/d", "ee55", ""),
            GhEvent {
                kind: "WatchEvent".into(),
                ..push("x/y", "ff66", "77")
            },
        ];
        let t = push_targets(&evs);
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].0, "a/b");
        assert_eq!(t[0].1, vec!["aa11", "bb22", "cc33"]);
        assert_eq!(t[1].1, vec!["ee55"]); // empty before dropped
    }
}
