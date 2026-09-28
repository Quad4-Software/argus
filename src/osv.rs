//! OSV.dev integration: extract pinned deps from manifests/lockfiles,
//! batch-query OSV, map advisories (MAL-* = malicious) into findings.

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Dep {
    pub ecosystem: &'static str, // "npm" | "PyPI" | "GitHub Actions" | "crates.io" | "Go" | "RubyGems"
    pub name: String,
    pub version: String,
    /// manifest/lockfile path it was found in
    pub path: String,
}

/// Extract pinned deps from a manifest file's text. Cheap parsers:
/// JSON manifests via serde_json; text formats via regex.
pub fn extract_deps(rel: &str, text: &str) -> Vec<Dep> {
    let mut out = Vec::new();
    let base = rel.rsplit('/').next().unwrap_or(rel);
    match base {
        "package-lock.json" | "npm-shrinkwrap.json" => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
                // modern lockfile: packages."node_modules/<name>".version
                if let Some(pkgs) = v.get("packages").and_then(|p| p.as_object()) {
                    for (k, meta) in pkgs {
                        // nested keys look like node_modules/a/node_modules/b -> b
                        if let Some(name) = k
                            .rsplit("node_modules/")
                            .next()
                            .filter(|n| !n.is_empty() && *n != *k && k.contains("node_modules/"))
                            && let Some(ver) = meta.get("version").and_then(|v| v.as_str())
                        {
                            out.push(Dep {
                                ecosystem: "npm",
                                name: name.into(),
                                version: ver.into(),
                                path: rel.into(),
                            });
                        }
                    }
                }
                // legacy: dependencies.<name>.version
                if let Some(deps) = v.get("dependencies").and_then(|d| d.as_object()) {
                    for (name, meta) in deps {
                        if let Some(ver) = meta.get("version").and_then(|v| v.as_str()) {
                            out.push(Dep {
                                ecosystem: "npm",
                                name: name.clone(),
                                version: ver.into(),
                                path: rel.into(),
                            });
                        }
                    }
                }
            }
        }
        "pnpm-lock.yaml" | "yarn.lock" => {
            // '/name/version' or 'name@version' style keys
            let re = regex::Regex::new(r#"(?m)['"]?(?:/?)(@?[a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._-]+)?)[@/]v?(\d+\.\d+\.\d+[0-9a-zA-Z.-]*)['"]?\s*[:{]"#).unwrap();
            for c in re.captures_iter(text) {
                out.push(Dep {
                    ecosystem: "npm",
                    name: c[1].trim_start_matches('/').to_string(),
                    version: c[2].into(),
                    path: rel.into(),
                });
            }
        }
        _ if base.starts_with("requirements") || base == "constraints.txt" => {
            let re = regex::Regex::new(r"(?im)^\s*([a-zA-Z0-9._-]+)\s*==\s*([0-9][0-9a-zA-Z._-]*)")
                .unwrap();
            for c in re.captures_iter(text) {
                out.push(Dep {
                    ecosystem: "PyPI",
                    name: c[1].to_lowercase(),
                    version: c[2].into(),
                    path: rel.into(),
                });
            }
        }
        "poetry.lock" | "uv.lock" => {
            // [[package]] name = "x" version = "y" blocks
            let re = regex::Regex::new(r#"(?m)name\s*=\s*"([a-zA-Z0-9._-]+)"\s*\n\s*version\s*=\s*"([0-9][0-9a-zA-Z._-]*)""#).unwrap();
            for c in re.captures_iter(text) {
                out.push(Dep {
                    ecosystem: "PyPI",
                    name: c[1].to_lowercase(),
                    version: c[2].into(),
                    path: rel.into(),
                });
            }
        }
        "Cargo.lock" => {
            // [[package]] name = "x" version = "y"
            let re = regex::Regex::new(
                r#"(?m)name\s*=\s*"([^"]+)"\s*
\s*version\s*=\s*"([^"]+)""#,
            )
            .unwrap();
            for c in re.captures_iter(text) {
                out.push(Dep {
                    ecosystem: "crates.io",
                    name: c[1].into(),
                    version: c[2].into(),
                    path: rel.into(),
                });
            }
        }
        "go.mod" => {
            // require blocks: module/path v1.2.3
            let re = regex::Regex::new(r"(?m)^\s*([a-zA-Z0-9._~/-]+)\s+v([0-9][0-9a-zA-Z.+-]*)")
                .unwrap();
            for c in re.captures_iter(text) {
                let name = c[1].to_string();
                if name == "module" || name == "go" || name == "toolchain" {
                    continue;
                }
                out.push(Dep {
                    ecosystem: "Go",
                    name,
                    version: format!("v{}", &c[2]),
                    path: rel.into(),
                });
            }
        }
        "Gemfile.lock" => {
            // GEM specs section:     name (1.2.3)
            let re = regex::Regex::new(r"(?m)^    ([a-zA-Z0-9._-]+) \(([0-9][0-9a-zA-Z.-]*)\)\s*$")
                .unwrap();
            for c in re.captures_iter(text) {
                out.push(Dep {
                    ecosystem: "RubyGems",
                    name: c[1].into(),
                    version: c[2].into(),
                    path: rel.into(),
                });
            }
        }
        _ => {
            // CI workflows: uses: owner/repo@ref -> GitHub Actions ecosystem advisories
            if rel.contains("workflows/") || base.ends_with(".action.yml") || base == "action.yml" {
                let re = regex::Regex::new(r#"(?m)uses\s*[:=]\s*["']?([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+)@(v?[0-9][0-9a-zA-Z._-]*)"#).unwrap();
                for c in re.captures_iter(text) {
                    out.push(Dep {
                        ecosystem: "GitHub Actions",
                        name: c[1].to_string(),
                        version: c[2].into(),
                        path: rel.into(),
                    });
                }
            }
        }
    }
    out
}

#[derive(Serialize)]
struct Q<'a> {
    queries: Vec<QI<'a>>,
}
#[derive(Serialize)]
struct QI<'a> {
    package: QP<'a>,
    version: &'a str,
}
#[derive(Serialize)]
struct QP<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

/// POST /v1/querybatch; returns Vec<(dep_index, advisory_id, summary)>.
pub fn query_batch(
    http: &crate::http::HttpClient,
    deps: &[Dep],
) -> Result<Vec<(usize, String, String)>, String> {
    const BATCH: usize = 1000;
    let mut out = Vec::new();
    for (ci, chunk) in deps.chunks(BATCH).enumerate() {
        let q = Q {
            queries: chunk
                .iter()
                .map(|d| QI {
                    package: QP {
                        name: &d.name,
                        ecosystem: d.ecosystem,
                    },
                    version: &d.version,
                })
                .collect(),
        };
        let body = serde_json::to_string(&q).map_err(|e| e.to_string())?;
        let v = http.post_json("https://api.osv.dev/v1/querybatch", &body)?;
        let results = v["results"].as_array().cloned().unwrap_or_default();
        for (i, r) in results.iter().enumerate() {
            let Some(vulns) = r["vulns"].as_array() else {
                continue;
            };
            for vuln in vulns {
                let id = vuln["id"].as_str().unwrap_or("?").to_string();
                let summary = vuln["summary"].as_str().unwrap_or("").to_string();
                out.push((ci * BATCH + i, id, summary));
            }
        }
    }
    Ok(out)
}
