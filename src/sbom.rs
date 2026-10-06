// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! CycloneDX 1.5 SBOM export from lockfile/manifest dependency extraction.

use crate::osv::Dep;
use crate::rules;
use crate::scan::ScanOptions;
use serde_json::json;
use std::path::Path;

fn purl(d: &Dep) -> String {
    let t = match d.ecosystem {
        "crates.io" => "cargo",
        "PyPI" => "pypi",
        "npm" => "npm",
        "Go" => "golang",
        "RubyGems" => "gem",
        "GitHub Actions" => "github",
        other => other,
    };
    format!("pkg:{t}/{}@{}", d.name, d.version)
}

/// Walk root for manifests and emit CycloneDX JSON.
pub fn sbom(root: &Path, opts: &ScanOptions) -> String {
    cyclonedx(&collect(root, opts), &root.display().to_string())
}

/// Walk root for manifests and emit SPDX 2.3 JSON.
pub fn sbom_spdx(root: &Path, opts: &ScanOptions) -> String {
    let deps = collect(root, opts);
    let pkgs: Vec<_> = deps
        .iter()
        .enumerate()
        .map(|(i, d)| {
            json!({
                "SPDXID": format!("SPDXRef-Package-{i}"),
                "name": d.name,
                "versionInfo": d.version,
                "downloadLocation": "NOASSERTION",
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl(d),
                }],
            })
        })
        .collect();
    let rels: Vec<_> = deps
        .iter()
        .enumerate()
        .map(|(i, _)| {
            json!({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": format!("SPDXRef-Package-{i}"),
                "relationshipType": "DESCRIBES",
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "argus-sbom",
        "documentNamespace": format!("https://quad4.software/argus/sbom/{}", uuid_short()),
        "creationInfo": {
            "created": crate::finding::iso8601_pub(),
            "creators": [format!("Tool: argus-{}", env!("CARGO_PKG_VERSION"))],
        },
        "packages": pkgs,
        "relationships": rels,
    }))
    .unwrap_or_default()
}

fn uuid_short() -> String {
    use sha2::Digest;
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    sha2::Sha256::digest(t.to_string().as_bytes())
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

fn collect(root: &Path, opts: &ScanOptions) -> Vec<Dep> {
    let manifest_re = regex::Regex::new(rules::CompiledRule::DEP_MANIFESTS_RE).unwrap();
    let mut deps: Vec<Dep> = Vec::new();
    for f in crate::scan::collect_files(root, false, true) {
        let rel = f
            .strip_prefix(root)
            .unwrap_or(&f)
            .to_string_lossy()
            .replace('\\', "/");
        if !manifest_re.is_match(&rel) {
            continue;
        }
        if let Ok(b) = std::fs::read(&f)
            && !b.is_empty()
            && b.len() <= opts.max_file_size as usize
        {
            deps.extend(crate::osv::extract_deps(&rel, &String::from_utf8_lossy(&b)));
        }
    }
    deps.sort();
    deps.dedup();
    deps
}

fn cyclonedx(deps: &[Dep], name: &str) -> String {
    let components: Vec<_> = deps
        .iter()
        .map(|d| {
            json!({
                "type": "library",
                "name": d.name,
                "version": d.version,
                "purl": purl(d),
            })
        })
        .collect();
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tool": { "vendor": "argus", "name": "argus", "version": env!("CARGO_PKG_VERSION") },
            "component": { "name": name, "type": "application" }
        },
        "components": components
    })
    .to_string()
}
