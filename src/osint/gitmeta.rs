// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Names and emails from a local git history, plus a check for a public
//! .git/HEAD. Config passwords are redacted. Objects are not downloaded.

use super::siteurl::fetch_public;
use super::{Hit, Report, Status};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

pub fn scan(target: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    let target = target.trim();
    let findings = if crate::cli::is_http_target(target) {
        remote(target)?
    } else {
        local(Path::new(target))?
    };
    Ok(Report {
        target: target.to_string(),
        kind: "gitmeta",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

fn local(root: &Path) -> Result<Vec<Hit>, String> {
    if !root.exists() {
        return Err(format!("path not found: {}", root.display()));
    }
    let mut findings = Vec::new();
    if root.join(".git").exists() || root.is_file() && root.ends_with(".git") {
        let repo = if root.is_file() {
            root.parent().unwrap_or(root)
        } else {
            root
        };
        findings.extend(from_git(repo));
        findings.extend(remotes(repo));
    } else if root.is_file() {
        findings.extend(emails_in_text(
            &std::fs::read_to_string(root).unwrap_or_default(),
            &root.display().to_string(),
        ));
    }
    if root.is_dir() {
        findings.extend(manifests(root));
    }
    if findings.is_empty() {
        findings.push(Hit::new(
            "identity",
            Status::Absent,
            "no git history or identity files",
            None,
        ));
    }
    Ok(findings)
}

fn from_git(repo: &Path) -> Vec<Hit> {
    let out = Command::new("git")
        .args([
            "-C",
            &repo.to_string_lossy(),
            "log",
            "--all",
            "--format=%an%x09%ae%x09%cn%x09%ce%x09%aI",
        ])
        .output();
    let Ok(out) = out else {
        return vec![Hit::new(
            "git",
            Status::Error,
            "git log failed to start",
            None,
        )];
    };
    if !out.status.success() {
        return vec![Hit::new(
            "git",
            Status::Inconclusive,
            "not a readable git history",
            None,
        )];
    }
    let mut people: BTreeMap<(String, String, String), (usize, String, String)> = BTreeMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 5 {
            continue;
        }
        let date = parts[4].to_string();
        for (role, name, email) in [
            ("author", parts[0], parts[1]),
            ("committer", parts[2], parts[3]),
        ] {
            let key = (role.to_string(), name.to_string(), email.to_string());
            let entry = people.entry(key).or_insert((0, date.clone(), date.clone()));
            entry.0 += 1;
            if date < entry.1 {
                entry.1 = date.clone();
            }
            if date > entry.2 {
                entry.2 = date.clone();
            }
        }
    }
    if people.is_empty() {
        return vec![Hit::new("git", Status::Absent, "no commits", None)];
    }
    let mut rows = Vec::new();
    for ((role, name, email), (count, first, last)) in &people {
        rows.push(json!({
            "role": role,
            "name": name,
            "email": email,
            "commits": count,
            "first": first,
            "last": last,
            "noreply": email.contains("noreply"),
        }));
    }
    vec![Hit::new(
        "identity",
        Status::Confirmed,
        format!("{} name and email row(s)", rows.len()),
        Some(json!({ "people": rows })),
    )]
}

fn remotes(repo: &Path) -> Vec<Hit> {
    let out = Command::new("git")
        .args(["-C", &repo.to_string_lossy(), "remote", "-v"])
        .output();
    let Ok(out) = out else {
        return Vec::new();
    };
    let mut urls = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut parts = line.split_whitespace();
        let name = parts.next().unwrap_or("");
        let url = parts.next().unwrap_or("");
        if url.is_empty() {
            continue;
        }
        let clean = redact_url(url);
        if !urls.iter().any(|u| u == &clean) {
            urls.push(format!("{name} {clean}"));
        }
    }
    if urls.is_empty() {
        Vec::new()
    } else {
        vec![Hit::new(
            "remotes",
            Status::Confirmed,
            format!("{} remote(s)", urls.len()),
            Some(json!({ "remotes": urls })),
        )]
    }
}

fn manifests(root: &Path) -> Vec<Hit> {
    let mut hits = Vec::new();
    for name in [
        ".mailmap",
        "Cargo.toml",
        "package.json",
        "pyproject.toml",
        "composer.json",
        "AUTHORS",
    ] {
        let path = root.join(name);
        if path.is_file() {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            hits.extend(emails_in_text(&text, name));
        }
    }
    hits
}

fn emails_in_text(text: &str, label: &str) -> Vec<Hit> {
    let mut found = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'@' {
            let mut a = i;
            while a > 0 && is_email_char(bytes[a - 1]) {
                a -= 1;
            }
            let mut b = i + 1;
            while b < bytes.len() && (is_email_char(bytes[b]) || bytes[b] == b'.') {
                b += 1;
            }
            let candidate = &text[a..b];
            if candidate.matches('@').count() == 1
                && candidate.contains('.')
                && !candidate.starts_with('@')
                && !found.iter().any(|e| e == candidate)
            {
                found.push(candidate.to_string());
            }
            i = b;
        } else {
            i += 1;
        }
    }
    if found.is_empty() {
        Vec::new()
    } else {
        vec![Hit::new(
            "manifest",
            Status::Confirmed,
            format!("{label}: {} address(es)", found.len()),
            Some(json!({ "file": label, "emails": found })),
        )]
    }
}

fn is_email_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn remote(raw: &str) -> Result<Vec<Hit>, String> {
    let head_url = git_child(raw, "HEAD");
    let (status, _, _, body) = fetch_public(&head_url)?;
    if !head_exposed(status, &body) {
        return Ok(vec![Hit::new(
            "exposed-git",
            Status::Absent,
            "no public .git/HEAD",
            None,
        )]);
    }
    let mut findings = vec![Hit::new(
        "exposed-git",
        Status::Confirmed,
        format!("public git HEAD at {head_url}. Block dotfiles. Objects were not downloaded"),
        Some(json!({ "head": body.trim() })),
    )];
    let config_url = git_child(raw, "config");
    if let Ok((st, _, _, cfg)) = fetch_public(&config_url)
        && st == 200
        && !cfg.to_ascii_lowercase().contains("<html")
        && cfg.len() < 64 * 1024
    {
        let clean = redact_config(&cfg);
        findings.push(Hit::new(
            "git-config",
            Status::Confirmed,
            "public .git/config with secrets redacted",
            Some(json!({ "config": clean })),
        ));
    }
    Ok(findings)
}

pub(crate) fn head_exposed(status: u16, body: &str) -> bool {
    status == 200
        && body.len() < 4096
        && body.contains("ref:")
        && !body.to_ascii_lowercase().contains("<html")
}

fn git_child(raw: &str, child: &str) -> String {
    let t = raw.trim().trim_end_matches('/');
    if t.to_ascii_lowercase().ends_with(".git") {
        format!("{t}/{child}")
    } else {
        format!("{t}/.git/{child}")
    }
}

pub(crate) fn redact_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let Some((userinfo, host)) = rest.split_once('@') else {
        return url.to_string();
    };
    if userinfo.is_empty() {
        return url.to_string();
    }
    format!("{scheme}://{host}")
}

pub(crate) fn redact_config(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        let trimmed = lower.trim_start();
        if (trimmed.starts_with("password")
            || trimmed.starts_with("token")
            || trimmed.starts_with("secret"))
            && let Some((k, _)) = line.split_once('=')
        {
            out.push_str(k.trim_end());
            out.push_str(" = [redacted]\n");
            continue;
        }
        if line.contains("://") {
            let mut rewritten = String::new();
            for word in line.split_whitespace() {
                if !rewritten.is_empty() {
                    rewritten.push(' ');
                }
                rewritten.push_str(&redact_url(word));
            }
            out.push_str(&rewritten);
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_stripped_and_html_is_not_a_head() {
        assert_eq!(
            redact_url("https://user:s3cret@git.example.com/a.git"),
            "https://git.example.com/a.git"
        );
        let cfg = "[remote \"origin\"]\n\turl = https://pat:hunter2@github.com/org/repo.git\n\tpassword = hunter2\n";
        let clean = redact_config(cfg);
        assert!(!clean.contains("hunter2"));
        assert!(!clean.contains("pat:"));
        assert!(clean.contains("[redacted]"));
        assert!(!head_exposed(200, "<html>ref: refs/heads/main</html>"));
        assert!(head_exposed(200, "ref: refs/heads/main\n"));
    }

    #[test]
    fn local_repo_lists_the_author() {
        let dir = std::env::temp_dir().join(format!(
            "argus-gitmeta-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let git = |args: &[&str]| {
            let st = Command::new("git")
                .args([
                    "-c",
                    "user.email=ada@example.com",
                    "-c",
                    "user.name=Ada Example",
                ])
                .args(args)
                .current_dir(&dir)
                .env("GIT_AUTHOR_NAME", "Ada Example")
                .env("GIT_AUTHOR_EMAIL", "ada@example.com")
                .env("GIT_COMMITTER_NAME", "Ada Example")
                .env("GIT_COMMITTER_EMAIL", "ada@example.com")
                .status()
                .unwrap();
            assert!(st.success());
        };
        git(&["init"]);
        std::fs::write(dir.join("note.txt"), "hello\n").unwrap();
        git(&["add", "note.txt"]);
        git(&["commit", "-m", "init"]);
        let report = scan(&dir.display().to_string()).unwrap();
        let id = report
            .findings
            .iter()
            .find(|h| h.module == "identity")
            .unwrap();
        assert!(
            id.summary.contains("ada@example.com")
                || id
                    .evidence
                    .as_ref()
                    .unwrap()
                    .to_string()
                    .contains("ada@example.com")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
