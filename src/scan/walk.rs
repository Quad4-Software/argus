// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! File walking and dep-manifest name heuristics.

use std::path::{Path, PathBuf};

/// Directories that hold vendored dependencies or build output. Scanning
/// them floods findings with generated-code noise, so they are pruned by
/// default (`--no-prune` walks them anyway).
pub const PRUNE_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "dist",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".nuxt",
    ".turbo",
    ".cache",
    ".gradle",
    ".idea",
    ".vscode",
];

/// Basenames that stay scannable even when an ignore file excludes them.
/// `.env`, key material and credential stores are exactly where leaked
/// secrets live, and they are gitignored precisely because they hold them.
fn secretish_name(name: &str) -> bool {
    let n = name.to_lowercase();
    n == ".env"
        || n.starts_with(".env.")
        || n == ".netrc"
        || n == ".npmrc"
        || n == ".pypirc"
        || n == ".htpasswd"
        || n == ".pgpass"
        || n == "id_rsa"
        || n == "id_dsa"
        || n == "id_ecdsa"
        || n == "id_ed25519"
        || n.ends_with(".pem")
        || n.ends_with(".key")
        || n.ends_with(".p12")
        || n.ends_with(".pfx")
        || n.ends_with(".keystore")
        || n.ends_with(".jks")
        || n.contains("credential")
        || n.contains("secret")
}

/// True when a directory entry should be pruned: VCS internals, bulk git
/// object stores, and (when `prune`) dependency/build directories.
fn prune_entry(e: &ignore::DirEntry, include_git: bool, prune: bool) -> bool {
    if e.file_type().is_some_and(|t| t.is_dir()) {
        let name = e.file_name().to_string_lossy();
        if name == ".hg" || name == ".svn" || (name == ".git" && !include_git) {
            return false;
        }
        let ps = e.path().to_string_lossy();
        if ps.ends_with(".git/objects") || ps.ends_with(".git/lfs") {
            return false;
        }
        if prune && PRUNE_DIRS.contains(&name.as_ref()) {
            return false;
        }
    }
    true
}

/// Recursively collect files under root. Honors .gitignore/.ignore/git
/// excludes even outside a repo, prunes `PRUNE_DIRS`, and never descends
/// symlinked directories. Symlinked files are kept only when the target
/// resolves under root - a checkout must not make argus read /etc.
///
/// Ignore-file verdicts have one carve-out: basenames that are themselves
/// secret material (see `secretish_name`) are collected anyway via a second
/// sweep, because a `.gitignore`d `.env` on disk is exactly what a secrets
/// scan exists to find.
pub fn collect_files(root: &Path, include_git: bool, prune: bool) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    if root.is_file() {
        out.push(root.to_path_buf());
        return out;
    }
    let root_canon = root.canonicalize().ok();
    let mut wb = ignore::WalkBuilder::new(root);
    // --no-prune means walk everything: no ignore-file handling at all.
    wb.hidden(false)
        .git_ignore(prune)
        .git_global(prune)
        .git_exclude(prune)
        .ignore(prune)
        .require_git(false)
        .parents(false)
        .follow_links(false)
        .filter_entry(move |e| prune_entry(e, include_git, prune));
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for e in wb.build().flatten() {
        if e.depth() == 0 {
            continue;
        }
        let p = e.path();
        let Some(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            if let (Some(rc), Ok(c)) = (root_canon.as_ref(), p.canonicalize())
                && c.is_file()
                && c.starts_with(rc)
                && seen.insert(p.to_path_buf())
            {
                out.push(p.to_path_buf());
            }
            continue;
        }
        if ft.is_file() && seen.insert(p.to_path_buf()) {
            out.push(p.to_path_buf());
        }
    }
    if !prune {
        return out;
    }
    // Second sweep: secret-shaped files that ignore rules hid from pass one.
    // Same pruning, but gitignore verdicts are not consulted.
    let mut wb2 = ignore::WalkBuilder::new(root);
    wb2.hidden(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .ignore(false)
        .require_git(false)
        .parents(false)
        .follow_links(false)
        .filter_entry(move |e| prune_entry(e, include_git, true));
    for e in wb2.build().flatten() {
        if e.depth() == 0 {
            continue;
        }
        let p = e.path();
        if !e.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let name = e.file_name().to_string_lossy();
        if secretish_name(&name) && seen.insert(p.to_path_buf()) {
            out.push(p.to_path_buf());
        }
    }
    out
}

pub(crate) fn rel_path(root: &Path, file: &Path) -> String {
    let rel = file
        .strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .replace('\\', "/");
    // single-file scan (root == file): extension-scoped rules still need
    // the basename to see ".tsx" etc.
    if rel.is_empty() {
        return file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
    }
    rel
}
/// Extract real dependency names (not prose tokens) from a manifest/lockfile.
/// Returns (name, byte-offset) pairs for typosquat comparison.
pub(crate) fn dep_name_candidates(rel: &str, text: &str) -> Vec<(String, usize)> {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    let mut out = Vec::new();
    match base {
        "package.json" | "npm-shrinkwrap.json" | "package-lock.json" => {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
                return out;
            };
            let mut names: Vec<String> = Vec::new();
            let local = |s: &str| {
                s.starts_with("file:")
                    || s.starts_with("link:")
                    || s.starts_with("workspace:")
                    || s.starts_with("portal:")
                    || s.starts_with("patch:")
                    || s.starts_with("git")
                    || s.starts_with("http")
            };
            for sect in [
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
                "bundledDependencies",
                "overrides",
            ] {
                if let Some(o) = v.get(sect).and_then(|s| s.as_object()) {
                    names.extend(o.iter().filter_map(|(k, v)| {
                        // file:/link:/workspace:/git specs resolve locally -
                        // not registry packages, so no squat/registry checks
                        match v.as_str() {
                            Some(spec) if local(spec) => None,
                            _ => Some(k.clone()),
                        }
                    }));
                }
            }
            // lockfile: packages."node_modules/<name>" keys
            if let Some(o) = v.get("packages").and_then(|s| s.as_object()) {
                for k in o.keys() {
                    if let Some(n) = k.rsplit("node_modules/").next()
                        && !n.is_empty()
                        && n != *k
                    {
                        names.push(n.to_string());
                    }
                }
            }
            for n in names {
                let needle = format!("\"{n}\"");
                let off = text.find(&needle).unwrap_or(0);
                out.push((n, off));
            }
        }
        "Cargo.toml" | "Cargo.lock" => {
            // Cargo.lock: [[package]] name = "x" entries.
            // Cargo.toml: keys inside [dependencies]/[dev-dependencies]/
            // [build-dependencies]/[target.*.dependencies] tables.
            let is_lock = base == "Cargo.lock";
            let mut section_deps = false;
            for (i, line) in text.lines().enumerate() {
                let t = line.trim();
                if t.starts_with('[') {
                    section_deps = !is_lock
                        && t.trim_matches('[')
                            .trim_matches(']')
                            .ends_with("dependencies");
                }
                if is_lock && t == "[[package]]" {
                    section_deps = true;
                    continue;
                }
                if section_deps {
                    if is_lock {
                        if let Some(n) = t.strip_prefix("name") {
                            let n = n.trim_start_matches([' ', '=']).trim_matches('"');
                            if !n.is_empty() {
                                out.push((n.to_string(), text.find(t).unwrap_or(0)));
                            }
                            section_deps = false; // only name line right after header
                            let _ = i;
                        }
                    } else if let Some(n) = t.split('=').next() {
                        let n = n.trim().trim_matches('"');
                        // `foo = { path = ".." }` / `foo.workspace = true`
                        // / `foo = { git = ".." }` resolve locally, not to
                        // a crates.io package. Key-shaped matches only so
                        // a crate named mypath is not mis-skiped.
                        let rhs_is_local = t.contains("path =")
                            || t.contains("path=")
                            || t.contains("workspace")
                            || t.contains("git =")
                            || t.contains("git=");
                        if !n.is_empty()
                            && !rhs_is_local
                            && n.chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                        {
                            out.push((n.to_string(), text.find(t).unwrap_or(0)));
                        }
                    }
                }
            }
        }
        "pnpm-lock.yaml" | "yarn.lock" => {
            // quoted/unquoted dep keys: pnpm '/name/version' or yarn
            // 'name@range:' where range may start with ^~*>=<v or a digit
            let re = regex::Regex::new(
                r#"(?m)^\s{0,4}['\"]?/?(@?[a-zA-Z0-9][a-zA-Z0-9._/-]*?)[@/](?:npm:)?[\^~*v\d]"#,
            )
            .unwrap();
            for c in re.captures_iter(text) {
                out.push((c[1].to_string(), c.get(1).map(|m| m.start()).unwrap_or(0)));
            }
        }
        _ => {
            // python manifests: line-start names before version specifiers
            let re = regex::Regex::new(
                r"(?im)^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:==|>=|<=|~=|!=|~=|>|<|;|$)",
            )
            .unwrap();
            for c in re.captures_iter(text) {
                out.push((c[1].to_string(), c.get(1).map(|m| m.start()).unwrap_or(0)));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("argus-walk-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("node_modules/dep")).unwrap();
        fs::create_dir_all(dir.join("target/debug")).unwrap();
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join(".gitignore"), "ignored/\nbuild/\n").unwrap();
        fs::create_dir_all(dir.join("ignored")).unwrap();
        fs::create_dir_all(dir.join("build")).unwrap();
        fs::write(dir.join("ignored/x.js"), "x").unwrap();
        fs::write(dir.join("build/gen.js"), "x").unwrap();
        fs::write(dir.join("node_modules/dep/i.js"), "x").unwrap();
        fs::write(dir.join("target/debug/out.rs"), "x").unwrap();
        fs::write(dir.join("src/app.js"), "x").unwrap();
        fs::write(dir.join("src/.env"), "x").unwrap();
        fs::write(dir.join(".env.production"), "x").unwrap();
        dir
    }

    fn names(root: &Path, files: &[PathBuf]) -> Vec<String> {
        let mut v: Vec<String> = files
            .iter()
            .map(|p| p.strip_prefix(root).unwrap().to_string_lossy().to_string())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn default_prunes_build_dep_and_ignored_dirs_but_keeps_dotenv() {
        let dir = fixture("prune");
        let got = names(&dir, &collect_files(&dir, false, true));
        assert_eq!(
            got,
            vec![".env.production", ".gitignore", "src/.env", "src/app.js"],
            "got {got:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_prune_walks_everything() {
        let dir = fixture("all");
        let got = names(&dir, &collect_files(&dir, false, false));
        for want in [
            "node_modules/dep/i.js",
            "target/debug/out.rs",
            "ignored/x.js",
            "build/gen.js",
            "src/app.js",
        ] {
            assert!(got.contains(&want.to_string()), "missing {want}: {got:?}");
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
