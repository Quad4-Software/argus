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
    let manifest_re = regex::Regex::new(rules::CompiledRule::DEP_MANIFESTS_RE).unwrap();
    let mut deps: Vec<Dep> = Vec::new();
    for f in crate::scan::collect_files(root, false) {
        let rel = f
            .strip_prefix(root)
            .unwrap_or(&f)
            .to_string_lossy()
            .replace('\\', "/");
        if !manifest_re.is_match(&rel) {
            continue;
        }
        if let Ok(b) = std::fs::read(&f) {
            if !b.is_empty() && b.len() <= opts.max_file_size as usize {
                deps.extend(crate::osv::extract_deps(&rel, &String::from_utf8_lossy(&b)));
            }
        }
    }
    deps.sort();
    deps.dedup();
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
            "component": { "name": root.display().to_string(), "type": "application" }
        },
        "components": components
    })
    .to_string()
}
