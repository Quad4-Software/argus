// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! File walking and dep-manifest name heuristics.

use std::path::{Path, PathBuf};

/// Recursively collect files under root, skipping VCS internals and
/// symlinked directories. Returns repo-relative paths.
pub fn collect_files(root: &Path, include_git: bool) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if root.is_file() {
        out.push(root.to_path_buf());
        return out;
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for e in entries.flatten() {
            let p = e.path();
            let name = e.file_name();
            let name = name.to_string_lossy();
            let ft = match e.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ft.is_symlink() {
                // Follow symlinked files only; skip dirs to avoid loops, and
                // only when the target stays under root - a checkout must not
                // make argus read /etc or other outside paths into findings.
                let Ok(root_canon) = root.canonicalize() else {
                    continue;
                };
                if p.is_file()
                    && p.canonicalize()
                        .map(|c| c.starts_with(&root_canon))
                        .unwrap_or(false)
                {
                    out.push(p);
                }
                continue;
            }
            if ft.is_dir() {
                if name == ".hg" || name == ".svn" || (name == ".git" && !include_git) {
                    continue;
                }
                // Always skip bulk VCS object stores (opaque blobs).
                let pp = p.to_string_lossy();
                if pp.ends_with(".git/objects") || pp.ends_with(".git/lfs") {
                    continue;
                }
                stack.push(p);
            } else if ft.is_file() {
                out.push(p);
            }
        }
    }
    out
}

pub(crate) fn rel_path(root: &Path, file: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .replace('\\', "/")
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
            for sect in [
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
                "bundledDependencies",
                "overrides",
            ] {
                if let Some(o) = v.get(sect).and_then(|s| s.as_object()) {
                    names.extend(o.keys().cloned());
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
                        if !n.is_empty()
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
            // quoted/unquoted dep keys: '/name/version' or name@version:
            let re = regex::Regex::new(
                r#"(?m)^\s{0,4}['\"]?/?(@?[a-zA-Z0-9][a-zA-Z0-9._/-]*?)[@/][v\d]"#,
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
