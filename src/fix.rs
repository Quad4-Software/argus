//! Auto-remediation for workflow findings: pin uses: refs to commit
//! SHAs (resolved via git ls-remote, tag kept as a comment) and inject
//! a top-level permissions: block when absent. Dry-run by default.

use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Edit {
    pub file: PathBuf,
    pub description: String,
    pub before: String,
    pub after: String,
}

fn is_sha(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Resolve owner/repo@ref to a commit sha via git ls-remote.
/// Prefers the dereferenced tag object (ref^{}) over the tag ref.
fn resolve_ref(repo: &str, refname: &str, verbose: bool) -> Option<String> {
    let url = format!("https://github.com/{repo}");
    let out = std::process::Command::new("git")
        .args([
            "ls-remote",
            &url,
            &format!("refs/tags/{refname}"),
            &format!("refs/tags/{refname}^{{}}"),
            &format!("refs/heads/{refname}"),
        ])
        .stdin(std::process::Stdio::null())
        .stderr(if verbose {
            std::process::Stdio::inherit()
        } else {
            std::process::Stdio::null()
        })
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut tag_obj = None;
    let mut peeled = None;
    let mut head = None;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (sha, r) = (parts.next()?, parts.next()?);
        if r.ends_with("^{}") {
            peeled = Some(sha.to_string());
        } else if r.contains("refs/tags/") {
            tag_obj = Some(sha.to_string());
        } else if r.contains("refs/heads/") {
            head = Some(sha.to_string());
        }
    }
    peeled.or(tag_obj).or(head)
}

fn workflow_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for d in [
        ".github/workflows",
        ".gitea/workflows",
        ".forgejo/workflows",
        ".gitlab",
    ] {
        let dir = root.join(d);
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
                if ext == "yml" || ext == "yaml" {
                    out.push(p);
                }
            }
        }
    }
    // GitLab style is a single .gitlab-ci.yml at the root
    for f in [".gitlab-ci.yml", ".gitlab-ci.yaml"] {
        let p = root.join(f);
        if p.is_file() {
            out.push(p);
        }
    }
    out
}

/// Compute the edits for one workflow file. Pure transform; resolution
/// results are passed in so the function stays offline-testable.
fn fix_workflow_text(
    path: &Path,
    text: &str,
    resolve: &dyn Fn(&str, &str) -> Option<String>,
) -> (String, Vec<Edit>) {
    let mut edits = Vec::new();
    let mut out = String::with_capacity(text.len());
    let uses_re = regex::Regex::new(r"^(\s*-?\s*uses:\s*)([\w.\-]+/[\w.\-/]+)@([\w.\-/]+)(.*)$")
        .expect("uses regex");
    let mut has_permissions = false;
    let mut insert_at = None;
    for line in text.lines() {
        if line.starts_with("permissions:") || line.starts_with("permissions :") {
            has_permissions = true;
        }
        if insert_at.is_none() && line.starts_with("jobs:") {
            insert_at = Some(out.len());
        }
        if let Some(c) = uses_re.captures(line) {
            let (pre, action, refname, post) = (
                c[1].to_string(),
                c[2].to_string(),
                c[3].to_string(),
                c[4].to_string(),
            );
            if !is_sha(&refname)
                && !action.starts_with("./")
                && !action.starts_with("docker")
                && let Some(sha) = resolve(&action, &refname)
            {
                let comment = if post.contains('#') {
                    post.clone()
                } else {
                    format!("{post} # {refname}").trim_end().to_string()
                };
                let newline = format!("{pre}{action}@{sha}{comment}");
                edits.push(Edit {
                    file: path.to_path_buf(),
                    description: format!("pin {action}@{refname} to {sha}"),
                    before: line.to_string(),
                    after: newline.clone(),
                });
                out.push_str(&newline);
                out.push('\n');
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    if !has_permissions && let Some(pos) = insert_at {
        let block = "# least privilege: declare per-job permissions or keep this empty\npermissions: {}\n\n";
        out.insert_str(pos, block);
        edits.push(Edit {
            file: path.to_path_buf(),
            description: "add empty top-level permissions block".into(),
            before: String::new(),
            after: block.trim_end().to_string(),
        });
    }
    (out, edits)
}

/// Apply fixes across workflow files under each root. write applies;
/// dry-run just reports. Returns (edits, errors).
pub fn run(roots: &[PathBuf], write: bool, verbose: bool) -> (Vec<Edit>, Vec<String>) {
    let mut edits = Vec::new();
    let mut errors = Vec::new();
    let resolve = |action: &str, refname: &str| resolve_ref(action, refname, verbose);
    for root in roots {
        for wf in workflow_files(root) {
            let Ok(text) = std::fs::read_to_string(&wf) else {
                errors.push(format!("{}: unreadable", wf.display()));
                continue;
            };
            let (new, mut es) = fix_workflow_text(&wf, &text, &resolve);
            if es.is_empty() {
                continue;
            }
            if write && let Err(e) = std::fs::write(&wf, &new) {
                errors.push(format!("{}: write failed: {e}", wf.display()));
                continue;
            }
            edits.append(&mut es);
        }
    }
    (edits, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_mutable_refs_and_adds_permissions() {
        let text = "name: ci\non: [push]\njobs:\n  b:\n    steps:\n      - uses: a/b@v2\n      - uses: o/p@4c8250dc9a6b8f5e2c1d0e9f8a7b6c5d4e3f2a1b\n";
        let resolve =
            |_: &str, _: &str| Some("4c8250dc9a6b8f5e2c1d0e9f8a7b6c5d4e3f2a1b".to_string());
        let (out, edits) = fix_workflow_text(Path::new("w.yml"), text, &resolve);
        assert!(out.contains("a/b@4c8250dc9a6b8f5e2c1d0e9f8a7b6c5d4e3f2a1b # v2"));
        assert!(out.contains("permissions: {}"));
        assert!(edits.iter().any(|e| e.description.contains("pin a/b")));
        assert!(edits.iter().any(|e| e.description.contains("permissions")));
        // sha-pinned refs untouched, skipped from edits
        assert_eq!(
            edits
                .iter()
                .filter(|e| e.description.contains("pin"))
                .count(),
            1
        );
    }

    #[test]
    fn existing_permissions_untouched() {
        let text = "name: ci\npermissions:\n  contents: read\njobs:\n  b:\n    steps:\n      - uses: a/b@v2\n";
        let resolve = |_: &str, _: &str| None;
        let (out, _) = fix_workflow_text(Path::new("w.yml"), text, &resolve);
        assert_eq!(out, text);
    }
}

// ---------------- container fixes ----------------

/// Resolve an image ref to a digest via whatever tool exists:
/// crane, skopeo, docker, or podman. Returns sha256 digest or None.
fn resolve_digest(img: &str, verbose: bool) -> Option<String> {
    let tries: Vec<(String, Vec<String>)> = vec![
        ("crane".into(), vec!["digest".into(), img.into()]),
        (
            "skopeo".into(),
            vec![
                "inspect".into(),
                format!("docker://{img}"),
                "--format".into(),
                "{{.Digest}}".into(),
            ],
        ),
        (
            "docker".into(),
            vec![
                "buildx".into(),
                "imagetools".into(),
                "inspect".into(),
                img.into(),
                "--format".into(),
                "{{json .Manifest.Digest}}".into(),
            ],
        ),
        (
            "podman".into(),
            vec![
                "inspect".into(),
                format!("docker://{img}"),
                "--format".into(),
                "{{.Digest}}".into(),
            ],
        ),
    ];
    for (prog, args) in tries {
        if std::process::Command::new(&prog)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_err()
        {
            continue;
        }
        let out = std::process::Command::new(&prog)
            .args(&args)
            .stdin(std::process::Stdio::null())
            .stderr(if verbose {
                std::process::Stdio::inherit()
            } else {
                std::process::Stdio::null()
            })
            .output()
            .ok()?;
        if !out.status.success() {
            continue;
        }
        let t = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if let Some(d) = t.strip_prefix("sha256:").map(|s| format!("sha256:{s}")) {
            return Some(d);
        }
        if t.starts_with("sha256:") {
            return Some(t);
        }
        // docker returns "sha256:..." inside quotes sometimes
        if let Some(s) = t.trim_matches('"').strip_prefix("sha256:") {
            return Some(format!("sha256:{s}"));
        }
        if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(format!("sha256:{t}"));
        }
    }
    None
}

/// Tag part of an image ref (registry ports live in earlier segments).
fn img_tag(img: &str) -> Option<&str> {
    let core = img.split('@').next().unwrap_or(img);
    core.rsplit('/').next()?.split_once(':').map(|(_, t)| t)
}

/// Pin mutable FROM refs to digests and inject USER when absent.
fn fix_dockerfile_text(
    path: &Path,
    text: &str,
    resolve: &mut dyn FnMut(&str) -> Option<String>,
) -> (String, Vec<Edit>) {
    let mut out = String::with_capacity(text.len() + 256);
    let mut edits = Vec::new();
    let mut has_user = false;
    let mut last_cmd_pos = None;
    let mut pending_lines: Vec<String> = Vec::new();
    for line in text.lines() {
        let upper = line.trim().to_uppercase();
        if upper.starts_with("USER ") {
            has_user = true;
        }
        if upper.starts_with("FROM ") {
            let img = line[5..].split_whitespace().next().unwrap_or("");
            let pinned = img.contains('@');
            let mutable = !img.eq_ignore_ascii_case("scratch")
                && !pinned
                && (img_tag(img).is_none() || img_tag(img) == Some("latest"));
            if mutable && let Some(d) = resolve(img) {
                let newl = format!("FROM {img}@{d}");
                edits.push(Edit {
                    file: path.to_path_buf(),
                    description: format!("pin base image {img} to digest"),
                    before: line.to_string(),
                    after: newl.clone(),
                });
                pending_lines.push(newl);
                continue;
            }
        }
        if upper.starts_with("CMD ") || upper.starts_with("ENTRYPOINT") {
            last_cmd_pos = Some(pending_lines.len());
        }
        pending_lines.push(line.to_string());
    }
    if !has_user && !pending_lines.is_empty() {
        let pos = last_cmd_pos.unwrap_or(pending_lines.len());
        pending_lines.insert(pos, "USER 1000:1000".to_string());
        edits.push(Edit {
            file: path.to_path_buf(),
            description: "add USER 1000:1000 (container ran as root)".into(),
            before: String::new(),
            after: "USER 1000:1000".into(),
        });
    }
    out.push_str(&pending_lines.join("\n"));
    if text.ends_with('\n') {
        out.push('\n');
    }
    (out, edits)
}

/// Compose hardening: add no-new-privileges to each service missing it.
fn fix_compose_text(path: &Path, text: &str) -> (String, Vec<Edit>) {
    let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
    let mut edits = Vec::new();
    let mut in_services = false;
    let mut i = 0usize;
    while i < lines.len() {
        let l = lines[i].clone();
        let t = l.trim().to_string();
        if t == "services:" {
            in_services = true;
        }
        if in_services {
            // service name line: two-space indented key under services:
            if l.starts_with("  ")
                && !l.starts_with("   ")
                && t.ends_with(':')
                && !t.starts_with('-')
            {
                // look ahead inside this service block for security_opt
                let mut j = i + 1;
                let mut has_nnp = false;
                let mut insert_idx = None;
                while j < lines.len() {
                    let lj = &lines[j];
                    if lj.starts_with("  ")
                        && !lj.starts_with("   ")
                        && lj.trim().ends_with(':')
                        && !lj.trim().starts_with('-')
                    {
                        break; // next service
                    }
                    if lj.trim().starts_with("security_opt:") {
                        has_nnp = true;
                    }
                    insert_idx = Some(j);
                    j += 1;
                }
                if !has_nnp && let Some(at) = insert_idx {
                    lines.insert(at + 1, "    security_opt: [no-new-privileges:true]".into());
                    edits.push(Edit {
                        file: path.to_path_buf(),
                        description: format!(
                            "add no-new-privileges to service {}",
                            t.trim_end_matches(':')
                        ),
                        before: String::new(),
                        after: "security_opt: [no-new-privileges:true]".into(),
                    });
                    i += 1;
                }
            }
        }
        i += 1;
    }
    let mut out = lines.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    (out, edits)
}

fn container_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut depth_guard = 0usize;
    while let Some(d) = stack.pop() {
        if depth_guard > 20000 {
            break;
        }
        depth_guard += 1;
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                let n = p
                    .file_name()
                    .map(|x| x.to_string_lossy().to_string())
                    .unwrap_or_default();
                if !n.starts_with('.') && n != "node_modules" && n != "target" {
                    stack.push(p);
                }
            } else {
                let rel = p
                    .strip_prefix(root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .to_string();
                use crate::container_audit::{Kind, kind_of};
                match kind_of(&rel) {
                    Kind::Dockerfile | Kind::Compose => out.push(p),
                    _ => {}
                }
            }
        }
    }
    out
}

/// Apply container fixes across roots. Reuses the same Edit report
/// shape as workflow fixes.
pub fn run_containers(roots: &[PathBuf], write: bool, verbose: bool) -> (Vec<Edit>, Vec<String>) {
    let mut edits = Vec::new();
    let mut errors = Vec::new();
    let mut digest_cache: std::collections::HashMap<String, Option<String>> = Default::default();
    for root in roots {
        for f in container_files(root) {
            let Ok(text) = std::fs::read_to_string(&f) else {
                errors.push(format!("{}: unreadable", f.display()));
                continue;
            };
            let rel = f
                .strip_prefix(root)
                .unwrap_or(&f)
                .to_string_lossy()
                .to_string();
            use crate::container_audit::{Kind, kind_of};
            let (new, mut es) = match kind_of(&rel) {
                Kind::Dockerfile => fix_dockerfile_text(&f, &text, &mut |img| {
                    digest_cache
                        .entry(img.to_string())
                        .or_insert_with(|| resolve_digest(img, verbose))
                        .clone()
                }),
                Kind::Compose => fix_compose_text(&f, &text),
                _ => continue,
            };
            if es.is_empty() {
                continue;
            }
            if write && let Err(e) = std::fs::write(&f, &new) {
                errors.push(format!("{}: write failed: {e}", f.display()));
                continue;
            }
            edits.append(&mut es);
        }
    }
    (edits, errors)
}

#[cfg(test)]
mod container_tests {
    use super::*;

    #[test]
    fn dockerfile_user_and_pin() {
        let df = "FROM ubuntu:latest\nRUN apt update\nCMD [\"sh\"]\n";
        let resolve = |_: &str| Some("sha256:deadbeef".to_string());
        let mut r = resolve;
        let (out, edits) = fix_dockerfile_text(Path::new("Dockerfile"), df, &mut r);
        assert!(out.contains("FROM ubuntu:latest@sha256:deadbeef"));
        assert!(out.contains("USER 1000:1000"));
        // USER lands before CMD
        assert!(out.find("USER").unwrap() < out.find("CMD").unwrap());
        assert_eq!(edits.len(), 2);
    }

    #[test]
    fn compose_nnp_once() {
        let y = "services:\n  a:\n    image: x\n  b:\n    image: y\n    security_opt: [no-new-privileges:true]\n";
        let (out, edits) = fix_compose_text(Path::new("compose.yml"), y);
        assert_eq!(edits.len(), 1);
        assert!(out.contains("security_opt: [no-new-privileges:true]"));
        assert!(edits[0].description.contains("service a"));
    }
}
