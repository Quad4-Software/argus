//! Publish pre-flight: enumerate the files a package would actually ship
//! (npm pack / cargo package / git ls-files fallback), then run the rules
//! engine over just that set plus filename-level checks for the classics:
//! .env, key material, rc files with tokens, editor/git leftovers.

use crate::finding::{Finding, Severity};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct PublishSet {
    /// "npm" | "cargo" | "pypi" | "git-files"
    pub kind: &'static str,
    pub root: PathBuf,
    /// repo-relative paths that would ship
    pub files: Vec<String>,
    /// how the list was produced, for reporting
    pub method: String,
}

/// File names that must never ship in a package.
const SENSITIVE_NAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".envrc",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "credentials",
    "kubeconfig",
    ".keystore",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    "service-account.json",
];

const SENSITIVE_EXT: &[&str] = &["pem", "key", "p12", "pfx", "jks", "kdbx", "asc"];
const JUNK: &[&str] = &[".ds_store", "thumbs.db", ".directory"];

/// Determine which files would be published. Prefers the packager's own
/// answer (npm pack --dry-run, cargo package --list); falls back to
/// git ls-files (tracked+untracked-but-not-ignored) as a decent proxy for
/// source distributions.
/// Scratch dir for packager caches (npm/cargo write state even in
/// read-only modes); sandbox-friendly because it is inside the temp dir
/// the command already gets write access to.
fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("argus-publish-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&d);
    d
}

pub fn collect(root: &Path, verbose: bool) -> Result<PublishSet, String> {
    let has = |f: &str| root.join(f).is_file();
    let scratch = scratch();
    if has("package.json") {
        let out = std::process::Command::new("npm")
            .args(["pack", "--dry-run", "--json"])
            .current_dir(root)
            .env("npm_config_cache", scratch.join("npm"))
            .env("XDG_CACHE_HOME", &scratch)
            .stdin(std::process::Stdio::null())
            .stderr(if verbose {
                std::process::Stdio::inherit()
            } else {
                std::process::Stdio::null()
            })
            .output()
            .map_err(|e| format!("spawn npm: {e}"))?;
        if out.status.success() {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                // npm >=10 emits {"name": {files:[]}}; older emits [{files:[]}]
                let pkg = if v.is_object() {
                    v.as_object().and_then(|o| o.values().next())
                } else {
                    v.get(0)
                };
                let files: Vec<String> = pkg
                    .and_then(|p| p["files"].as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|f| f["path"].as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                if !files.is_empty() {
                    return Ok(PublishSet {
                        kind: "npm",
                        root: root.into(),
                        files,
                        method: "npm pack --dry-run".into(),
                    });
                }
            }
        }
        // npm failed: package.json "files" field or git-files proxy
    }
    if has("Cargo.toml") {
        let out = std::process::Command::new("cargo")
            .args(["package", "--list", "--allow-dirty", "--offline"])
            .current_dir(root)
            // real CARGO_HOME has the cached index; only build output is
            // redirected (publish never builds, but keep the env clean)
            .env("CARGO_TARGET_DIR", scratch.join("target"))
            .stdin(std::process::Stdio::null())
            .stderr(if verbose {
                std::process::Stdio::inherit()
            } else {
                std::process::Stdio::null()
            })
            .output()
            .map_err(|e| format!("spawn cargo: {e}"))?;
        if out.status.success() {
            let files: Vec<String> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect();
            if !files.is_empty() {
                return Ok(PublishSet {
                    kind: "cargo",
                    root: root.into(),
                    files,
                    method: "cargo package --list".into(),
                });
            }
        }
    }
    // fallback: everything git would include
    let out = std::process::Command::new("git")
        .args([
            "-C",
            &*root.to_string_lossy(),
            "ls-files",
            "-co",
            "--exclude-standard",
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("spawn git: {e}"))?;
    if out.status.success() {
        let files: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_string)
            .collect();
        if !files.is_empty() {
            let kind = if has("pyproject.toml") || has("setup.py") {
                "pypi"
            } else {
                "git-files"
            };
            return Ok(PublishSet {
                kind,
                root: root.into(),
                files,
                method: "git ls-files (approximation)".into(),
            });
        }
    }
    Err(format!(
        "{}: no package manifest or git file list found",
        root.display()
    ))
}

/// Filename-level findings over the publish set.
pub fn name_checks(set: &PublishSet) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut push = |rel: &str, id: &str, sev: Severity, msg: String| {
        out.push(Finding {
            ruleset: "publish".into(),
            rule_id: id.into(),
            severity: sev,
            target: set.root.display().to_string(),
            path: rel.to_string(),
            line: None,
            excerpt: None,
            message: msg,
            remediation: Some("Remove it from the package (files field, .npmignore/.gitignore, exclude=) or rotate the secret if it already shipped.".into()),
            reference: None,
            window: None,
        });
    };
    for rel in &set.files {
        let base = rel.rsplit('/').next().unwrap_or(rel).to_lowercase();
        let lower = rel.to_lowercase();
        if SENSITIVE_NAMES.contains(&base.as_str())
            || SENSITIVE_EXT
                .iter()
                .any(|e| base.ends_with(&format!(".{e}")))
            || lower.contains(".ssh/")
            || lower.contains(".aws/")
            || lower.ends_with("/credentials")
        {
            push(
                rel,
                "PUB-001",
                Severity::Critical,
                format!("sensitive file would ship in the package: {rel}"),
            );
            continue;
        }
        if lower.starts_with(".git/")
            || lower.contains("/.git/")
            || lower.contains("node_modules/")
            || lower.starts_with("node_modules/")
        {
            push(
                rel,
                "PUB-002",
                Severity::Medium,
                format!("vcs/vendored artifact inside the package: {rel}"),
            );
            continue;
        }
        if JUNK.contains(&base.as_str())
            || base.ends_with(".bak")
            || base.ends_with(".orig")
            || base.ends_with('~')
            || base.ends_with(".pyc")
            || lower.contains("__pycache__/")
        {
            push(
                rel,
                "PUB-003",
                Severity::Low,
                format!("junk/editor artifact inside the package: {rel}"),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_sensitive_and_junk() {
        let set = PublishSet {
            kind: "npm",
            root: PathBuf::from("/x"),
            files: vec![
                "index.js".into(),
                ".env".into(),
                "certs/server.pem".into(),
                "node_modules/x/index.js".into(),
                "a.bak".into(),
            ],
            method: "t".into(),
        };
        let fs = name_checks(&set);
        let ids: Vec<_> = fs
            .iter()
            .map(|f| (f.rule_id.as_str(), f.severity))
            .collect();
        assert!(ids.contains(&("PUB-001", Severity::Critical)));
        assert!(ids.contains(&("PUB-002", Severity::Medium)));
        assert!(ids.contains(&("PUB-003", Severity::Low)));
        assert!(!fs.iter().any(|f| f.path == "index.js"));
    }
}
