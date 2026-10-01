// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Recursive supply-chain inventory.
//! Walks a tree for lockfiles and manifests, including nested dependency
//! blocks, go.sum, and transitive NuGet locks. node_modules and build
//! output are skipped so the walk stays on the project's own files.

use crate::osint::{Hit, Report, Status};
use crate::osv::{self, Dep};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

const SKIP: &[&str] = &[".git", "node_modules", "target", "vendor", "dist", ".argus"];

pub fn scan(root: &Path) -> Result<Report, String> {
    let t0 = Instant::now();
    if !root.exists() {
        return Err(format!("path not found: {}", root.display()));
    }
    let mut deps = Vec::new();
    let mut files = 0usize;
    walk(root, &mut deps, &mut files, 0)?;
    let mut by_eco: BTreeMap<&str, usize> = BTreeMap::new();
    let mut seen = std::collections::BTreeSet::new();
    for d in &deps {
        if seen.insert((d.ecosystem, d.name.clone(), d.version.clone())) {
            *by_eco.entry(d.ecosystem).or_insert(0) += 1;
        }
    }
    let total: usize = by_eco.values().sum();
    let mut findings = vec![Hit::new(
        "supply",
        if total == 0 {
            Status::Absent
        } else {
            Status::Confirmed
        },
        format!("{total} pinned package(s) across {} lockfile(s)", files),
        None,
    )];
    for (eco, n) in &by_eco {
        findings.push(Hit::new(
            eco,
            Status::Confirmed,
            format!("{n} package(s)"),
            None,
        ));
    }
    Ok(Report {
        target: root.display().to_string(),
        kind: "supply",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

fn walk(dir: &Path, deps: &mut Vec<Dep>, files: &mut usize, depth: usize) -> Result<(), String> {
    if depth > 12 || *files > 400 {
        return Ok(());
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if SKIP.iter().any(|s| name == *s) {
            continue;
        }
        if path.is_dir() {
            walk(&path, deps, files, depth + 1)?;
            continue;
        }
        if !is_manifest(&name) {
            continue;
        }
        let text = match std::fs::read(&path) {
            Ok(b) if b.len() <= 8 * 1024 * 1024 => b,
            _ => continue,
        };
        let rel = path.display().to_string();
        let found = osv::extract_deps(&rel, &String::from_utf8_lossy(&text));
        if !found.is_empty() {
            *files += 1;
            deps.extend(found);
        }
    }
    Ok(())
}

fn is_manifest(name: &str) -> bool {
    matches!(
        name,
        "package-lock.json"
            | "npm-shrinkwrap.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "Cargo.lock"
            | "go.sum"
            | "go.mod"
            | "Gemfile.lock"
            | "poetry.lock"
            | "uv.lock"
            | "composer.lock"
            | "packages.lock.json"
            | "pubspec.lock"
            | "mix.lock"
            | "pom.xml"
    ) || name.starts_with("requirements")
        || name.ends_with(".csproj")
        || name.ends_with(".fsproj")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_lock_is_counted() {
        let dir = std::env::temp_dir().join(format!("argus-supply-{}", std::process::id()));
        let nested = dir.join("apps").join("web");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("package-lock.json"),
            r#"{"dependencies":{"left-pad":{"version":"1.0.0","dependencies":{"nested-dep":{"version":"2.0.0"}}}}}"#,
        )
        .unwrap();
        let report = scan(&dir).unwrap();
        assert!(report.findings[0].summary.contains("2 pinned"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
