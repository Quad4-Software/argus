//! License audit: detect the project license, compare against
//! manifest-declared licenses, and flag strong-copyleft dependencies.

use crate::finding::{Finding, Severity};
use crate::http::HttpClient;
use crate::osv::Dep;
use std::collections::HashSet;
use std::path::Path;

/// SPDX-ish short id from license file content (first ~8KB).
pub fn classify(text: &str) -> Option<&'static str> {
    let t = text.to_lowercase();
    let head = &t[..t.len().min(8192)];
    let has = |a: &str, b: &str| head.contains(a) && head.contains(b);
    // order matters: check more specific licenses before their bases
    if head.contains("gnu affero general public license") || head.contains("agpl") {
        Some("AGPL-3.0")
    } else if head.contains("gnu lesser general public license") || head.contains("lgpl") {
        Some("LGPL")
    } else if head.contains("gnu general public license") && head.contains("version 3") {
        Some("GPL-3.0")
    } else if head.contains("gnu general public license") && head.contains("version 2") {
        Some("GPL-2.0")
    } else if head.contains("mozilla public license") {
        Some("MPL-2.0")
    } else if head.contains("apache license") && head.contains("version 2") {
        Some("Apache-2.0")
    } else if head.contains("bsd zero clause") || head.contains("0bsd") {
        Some("0BSD")
    } else if has("redistribution and use", "neither the name") {
        Some("BSD-3-Clause")
    } else if has("redistribution and use", "copyright notice") {
        Some("BSD-2-Clause")
    } else if head.contains("mit license") || has("permission is hereby granted", "mit") {
        Some("MIT")
    } else if head.contains("isc license") || has("permission to use, copy, modify", "isc") {
        Some("ISC")
    } else if head
        .contains("this is free and unencumbered software released into the public domain")
        || head.contains("unlicense")
    {
        Some("Unlicense")
    } else if head.contains("creative commons zero") || head.contains("cc0") {
        Some("CC0-1.0")
    } else {
        None
    }
}

/// Strong copyleft / restricted licenses that conflict with permissive projects.
const COPYLEFT: &[&str] = &[
    "gpl",
    "agpl",
    "lgpl",
    "sspl",
    "commons clause",
    "busl",
    "cpal",
    "osl",
    "eupl",
];

fn is_copyleft(license: &str) -> bool {
    let l = license.to_lowercase();
    COPYLEFT.iter().any(|c| l.contains(c))
}

fn finding(target: &str, path: &str, id: &str, sev: Severity, msg: String) -> Finding {
    Finding {
        ruleset: "license".into(),
        rule_id: id.into(),
        severity: sev,
        target: target.into(),
        path: path.into(),
        line: None,
        excerpt: None,
        message: msg,
        remediation: None,
        reference: None,
        window: None,
    }
}

const LICENSE_FILES: &[&str] = &[
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
    "LICENCE",
    "COPYING",
    "COPYING.md",
    "license",
    "license.txt",
    "COPYRIGHT",
];

/// Declared license fields in manifests: (file, key path).
fn manifest_license(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Ok(b) = std::fs::read(root.join("package.json"))
        && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&b)
    {
        if let Some(l) = v["license"].as_str() {
            out.push(("package.json".into(), l.to_string()));
        }
        if let Some(l) = v["license"]["type"].as_str() {
            out.push(("package.json".into(), l.to_string()));
        }
    }
    if let Ok(t) = std::fs::read_to_string(root.join("Cargo.toml"))
        && let Ok(v) = toml::from_str::<toml::Value>(&t)
    {
        for path in [
            &["package", "license"][..],
            &["workspace", "package", "license"][..],
        ] {
            if let Some(l) = path
                .iter()
                .try_fold(&v, |acc, k| acc.get(*k))
                .and_then(|x| x.as_str())
            {
                out.push(("Cargo.toml".into(), l.to_string()));
            }
        }
    }
    if let Ok(t) = std::fs::read_to_string(root.join("pyproject.toml"))
        && let Ok(v) = toml::from_str::<toml::Value>(&t)
    {
        let lic = v.get("project").and_then(|p| p.get("license"));
        if let Some(l) = lic.and_then(|x| x.get("text")).and_then(|x| x.as_str()) {
            out.push(("pyproject.toml".into(), l.to_string()));
        } else if let Some(l) = lic.and_then(|x| x.as_str()) {
            out.push(("pyproject.toml".into(), l.to_string()));
        }
    }
    out
}

/// Local audit: project license file + manifest consistency.
/// No network. Dep-license cross-check happens separately via registry.
pub fn audit(root: &Path, target: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut file_license: Option<(String, &'static str)> = None;
    for name in LICENSE_FILES {
        let p = root.join(name);
        if p.is_file() {
            if let Ok(t) = std::fs::read_to_string(&p) {
                match classify(&t) {
                    Some(spdx) => {
                        file_license = Some((name.to_string(), spdx));
                    }
                    None => out.push(finding(
                        target,
                        name,
                        "LIC-002",
                        Severity::Info,
                        format!("{name} present but license text not recognized"),
                    )),
                }
            }
            break;
        }
    }
    if file_license.is_none() {
        out.push(finding(
            target,
            ".",
            "LIC-001",
            Severity::Low,
            "no LICENSE/COPYING file at repo root".into(),
        ));
    }
    for (mf, declared) in manifest_license(root) {
        if let Some((lf, spdx)) = &file_license {
            // loose equality: "MIT"=="MIT", "GPL-3.0" matches "GPL-3.0-only"
            let norm = |s: &str| s.to_lowercase().replace("-only", "").replace(" ", "");
            if !norm(&declared).contains(&norm(spdx)) && !norm(spdx).contains(&norm(&declared)) {
                out.push(finding(
                    target,
                    &mf,
                    "LIC-003",
                    Severity::Medium,
                    format!("{mf} declares {declared:?} but {lf} is {spdx}"),
                ));
            }
        }
    }
    if let Some((lf, spdx)) = &file_license
        && is_copyleft(spdx)
    {
        out.push(finding(
            target,
            lf,
            "LIC-004",
            Severity::Info,
            format!("project license is copyleft ({spdx}) - dependents inherit obligations"),
        ));
    }
    out
}

/// Dep license cross-check via registry metadata (needs network).
/// Flags copyleft deps inside permissive projects and unknown licenses.
pub fn dep_licenses(
    deps: &[Dep],
    target: &str,
    project_is_copyleft: bool,
    http: &HttpClient,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut unique: Vec<&Dep> = Vec::new();
    for d in deps {
        if seen.insert(format!("{}:{}", d.ecosystem, d.name)) {
            unique.push(d);
        }
    }
    // registry metadata is one request per dep and crates.io throttles
    // hard; cap the pass rather than stall the audit for minutes
    let mut out_capped = None;
    if unique.len() > 120 {
        out_capped = Some(finding(
            target,
            ".",
            "LIC-012",
            Severity::Info,
            format!(
                "dep license check sampled first 120 of {} deps (registry rate limits)",
                unique.len()
            ),
        ));
        unique.truncate(120);
    }
    // parallel lookups, bounded pool (same shape as depcheck)
    let queue = std::sync::Mutex::new(unique.iter().peekable());
    let mut infos: std::collections::HashMap<usize, crate::registry::RegistryInfo> = {
        let results = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    loop {
                        let i = {
                            let mut q = queue.lock().unwrap();
                            let before = q.len();
                            q.next();
                            if before == 0 {
                                None
                            } else {
                                Some(unique.len() - before)
                            }
                        };
                        let Some(i) = i else { break };
                        if let Ok(info) = crate::registry::lookup(http, unique[i]) {
                            results.lock().unwrap().push((i, info));
                        }
                    }
                });
            }
        });
        results.into_inner().unwrap().into_iter().collect()
    };
    if let Some(f) = out_capped {
        out.push(f);
    }
    for (i, d) in unique.iter().enumerate() {
        let Some(info) = infos.remove(&i) else {
            continue;
        };
        if !info.exists {
            continue;
        }
        match &info.license {
            None => out.push(finding(
                target,
                &d.path,
                "LIC-010",
                Severity::Info,
                format!("{} declares no license on {}", d.name, d.ecosystem),
            )),
            Some(l) => {
                if l.trim().is_empty() {
                    out.push(finding(
                        target,
                        &d.path,
                        "LIC-010",
                        Severity::Info,
                        format!("{} declares an empty license on {}", d.name, d.ecosystem),
                    ));
                } else if is_copyleft(l) && !project_is_copyleft {
                    out.push(finding(
                        target,
                        &d.path,
                        "LIC-011",
                        Severity::Medium,
                        format!(
                            "copyleft dep {} ({}) inside a permissively-licensed project",
                            d.name, l
                        ),
                    ));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_common_licenses() {
        assert_eq!(
            classify("MIT License\n\nPermission is hereby granted"),
            Some("MIT")
        );
        assert_eq!(
            classify("GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3"),
            Some("AGPL-3.0")
        );
        assert_eq!(classify("Apache License\nVersion 2.0"), Some("Apache-2.0"));
        assert_eq!(
            classify("GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007"),
            Some("GPL-3.0")
        );
        assert_eq!(classify("some random text"), None);
    }
}
