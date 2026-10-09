// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Dependency risk signals and advisory enrichment.
//!
//! ecosyste.ms package stats (downloads, package age, release cadence)
//! feed the dep-hygiene checks in depcheck.rs. CISA KEV membership and
//! FIRST EPSS scores enrich OSV advisory findings. Everything here is
//! best-effort: fetch failures degrade to "unknown", never invented data.

use crate::finding::{Finding, Severity};
use crate::http::HttpClient;
use crate::osv::Dep;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

const TTL: u64 = 24 * 3600;
const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL: &str = "https://api.first.org/data/v1/epss";
const ECO_URL: &str = "https://packages.ecosyste.ms/api/v1";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cache_dir() -> PathBuf {
    std::env::home_dir()
        .unwrap_or_else(|| "/tmp".into())
        .join(".local/share/argus")
}

/// Minimal path-segment percent-encoding: scoped npm "@a/b", maven
/// "g:a", and go module paths all need it.
fn enc(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// ecosyste.ms package stats
// ---------------------------------------------------------------------------

/// Usage/cadence metadata for one package, from ecosyste.ms.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EcoInfo {
    /// package exists in ecosyste.ms data at all
    pub exists: bool,
    /// monthly downloads, only when the registry reports a last-month
    /// period (Go/Maven/NuGet do not report download counts)
    pub downloads_monthly: Option<u64>,
    /// dependent-repo count - popularity fallback where downloads are absent
    pub dependent_repos: Option<u64>,
    /// days since the first published release (package age)
    pub age_days: Option<u64>,
    /// days between the two most recent releases (dormancy gap)
    pub latest_release_gap_days: Option<u64>,
}

/// argus ecosystem -> ecosyste.ms registry host.
pub fn ecosystem_registry(eco: &str) -> Option<&'static str> {
    match eco {
        "npm" => Some("npmjs.org"),
        "PyPI" => Some("pypi.org"),
        "crates.io" => Some("crates.io"),
        "RubyGems" => Some("rubygems.org"),
        "Go" => Some("proxy.golang.org"),
        "Maven" => Some("repo1.maven.org"),
        "NuGet" => Some("nuget.org"),
        "Packagist" => Some("packagist.org"),
        "Hex" => Some("hex.pm"),
        "Pub" => Some("pub.dev"),
        _ => None,
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Cache {
    /// key "eco:name" -> (fetched unix ts, info)
    entries: HashMap<String, (u64, EcoInfo)>,
}

fn cache_path() -> PathBuf {
    cache_dir().join("ecosystems-cache.json")
}

/// Package stats for one dep; cached 24h under ~/.local/share/argus,
/// same pattern as registry.rs. Negative results (exists=false) are
/// cached too so re-scans do not re-probe dead names.
pub fn lookup(http: &HttpClient, dep: &Dep) -> Result<EcoInfo, String> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<Cache>> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| {
        let c: Cache = std::fs::read_to_string(cache_path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        std::sync::Mutex::new(c)
    });
    let Some(reg) = ecosystem_registry(dep.ecosystem) else {
        return Err(format!("no ecosyste.ms registry for {}", dep.ecosystem));
    };
    let key = format!("{}:{}", dep.ecosystem, dep.name);
    {
        let c = cache.lock().unwrap();
        if let Some((ts, info)) = c.entries.get(&key)
            && now().saturating_sub(*ts) < TTL
        {
            return Ok(info.clone());
        }
    }
    let base = format!("{ECO_URL}/registries/{reg}/packages/{}", enc(&dep.name));
    let (st, v) = http.get_status_json(&base)?;
    let mut info = if st == 404 {
        EcoInfo::default()
    } else if st != 200 {
        return Err(format!("{base}: HTTP {st}"));
    } else {
        let monthly = if v["downloads_period"].as_str() == Some("last-month") {
            v["downloads"].as_u64()
        } else {
            None
        };
        EcoInfo {
            exists: true,
            downloads_monthly: monthly,
            dependent_repos: v["dependent_repos_count"].as_u64(),
            // created_at is the ecosyste.ms record date, not the package
            // date; first_release_published_at is the honest age signal
            age_days: v["first_release_published_at"]
                .as_str()
                .or_else(|| v["created_at"].as_str())
                .and_then(crate::registry::parse_time_days),
            latest_release_gap_days: None,
        }
    };
    // release cadence: versions come back newest-first; the gap between
    // the two latest exposes dormancy-then-release takeovers
    if info.exists
        && let Ok(vers) = http.get_json(&format!("{base}/versions?per_page=2"))
        && let Some(arr) = vers.as_array()
    {
        let ago: Vec<u64> = arr
            .iter()
            .filter_map(|e| e["published_at"].as_str())
            .filter_map(crate::registry::parse_time_days)
            .collect();
        if ago.len() >= 2 {
            info.latest_release_gap_days = Some(ago[0].abs_diff(ago[1]));
        }
    }
    {
        let mut c = cache.lock().unwrap();
        c.entries.insert(key, (now(), info.clone()));
        if let Some(d) = cache_path().parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let _ = std::fs::write(
            cache_path(),
            serde_json::to_string(&c.entries).unwrap_or_default(),
        );
    }
    Ok(info)
}

// ---------------------------------------------------------------------------
// CISA Known Exploited Vulnerabilities
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct KevDisk {
    fetched: u64,
    cves: Vec<String>,
}

fn kev_path() -> PathBuf {
    cache_dir().join("kev.json")
}

/// All CVE ids in the CISA KEV catalog, cached 24h at
/// ~/.local/share/argus/kev.json. Empty set on any fetch failure.
pub fn kev_cves(http: &HttpClient) -> HashSet<String> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<Option<HashSet<String>>>> =
        std::sync::OnceLock::new();
    let m = CACHE.get_or_init(|| std::sync::Mutex::new(None));
    let mut g = m.lock().unwrap();
    if let Some(s) = &*g {
        return s.clone();
    }
    let s = load_kev(http);
    *g = Some(s.clone());
    s
}

fn load_kev(http: &HttpClient) -> HashSet<String> {
    if let Ok(t) = std::fs::read_to_string(kev_path())
        && let Ok(d) = serde_json::from_str::<KevDisk>(&t)
        && now().saturating_sub(d.fetched) < TTL
    {
        return d.cves.into_iter().collect();
    }
    let Ok(v) = http.get_json(KEV_URL) else {
        return HashSet::new();
    };
    let cves: Vec<String> = v["vulnerabilities"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| e["cveID"].as_str().map(str::to_string))
        .collect();
    if !cves.is_empty() {
        if let Some(d) = kev_path().parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let _ = std::fs::write(
            kev_path(),
            serde_json::to_string(&KevDisk {
                fetched: now(),
                cves: cves.clone(),
            })
            .unwrap_or_default(),
        );
    }
    cves.into_iter().collect()
}

/// True when `cve_or_ghsa` is a KEV-listed CVE. The catalog keys on CVE
/// ids only; GHSA ids match when callers resolve aliases first.
/// Single-id convenience wrapper; batch paths use kev_cves directly.
#[allow(dead_code)]
pub fn is_kev(http: &HttpClient, cve_or_ghsa: &str) -> bool {
    kev_cves(http).contains(&cve_or_ghsa.to_uppercase())
}

// ---------------------------------------------------------------------------
// FIRST EPSS
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default)]
pub struct Epss {
    pub score: f64,
    pub percentile: f64,
}

/// Batch EPSS scores for a set of CVE ids (one request per 100 CVEs).
/// CVEs with no EPSS record are simply absent from the map.
pub fn epss_scores(http: &HttpClient, cves: &HashSet<String>) -> HashMap<String, Epss> {
    let mut out = HashMap::new();
    let mut all: Vec<&String> = cves.iter().collect();
    all.sort();
    for chunk in all.chunks(100) {
        let q = chunk
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let Ok(v) = http.get_json(&format!("{EPSS_URL}?cve={q}")) else {
            continue;
        };
        for e in v["data"].as_array().into_iter().flatten() {
            let Some(cve) = e["cve"].as_str() else {
                continue;
            };
            let num = |k: &str| {
                e[k].as_str()
                    .and_then(|s| s.parse::<f64>().ok())
                    .or_else(|| e[k].as_f64())
                    .unwrap_or(0.0)
            };
            out.insert(
                cve.to_string(),
                Epss {
                    score: num("epss"),
                    percentile: num("percentile"),
                },
            );
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Advisory enrichment
// ---------------------------------------------------------------------------

/// Resolve each advisory id to CVE ids: the id itself when it already is
/// a CVE, else the aliases carried by the full OSV record (querybatch
/// returns abbreviated records without aliases, so GHSA/MAL ids need one
/// bounded lookup each). Failures leave the id unmatched.
fn resolve_cves(http: &HttpClient, ids: &[String]) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    let mut fetch: Vec<&String> = Vec::new();
    for id in ids {
        if out.contains_key(id) {
            continue;
        }
        if id.starts_with("CVE-") {
            out.insert(id.clone(), vec![id.clone()]);
        } else if fetch.len() < 256 {
            fetch.push(id);
        }
    }
    let queue = std::sync::Mutex::new(fetch.iter());
    let results = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..4 {
            s.spawn(|| {
                loop {
                    let id = { queue.lock().unwrap().next().copied() };
                    let Some(id) = id else { break };
                    if let Some(v) = crate::osv::get_vuln(http, id) {
                        let cves: Vec<String> = v["aliases"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(|a| a.as_str())
                            .filter(|a| a.starts_with("CVE-"))
                            .map(str::to_string)
                            .collect();
                        results.lock().unwrap().push((id.clone(), cves));
                    }
                }
            });
        }
    });
    for (id, cves) in results.into_inner().unwrap() {
        out.insert(id, cves);
    }
    out
}

/// Append \[KEV\] / \[EPSS x.xx pNN\] markers to advisory findings and bump
/// KEV-listed hits to at least High. Findings keep their field schema;
/// the advisory id is read from rule_id. Skipped entirely by callers
/// under --no-enrich / --offline.
pub fn enrich_findings(http: &HttpClient, findings: &mut [Finding]) {
    let ids: Vec<String> = findings.iter().map(|f| f.rule_id.clone()).collect();
    if ids.is_empty() {
        return;
    }
    let resolved = resolve_cves(http, &ids);
    let all: HashSet<String> = resolved.values().flatten().cloned().collect();
    if all.is_empty() {
        return;
    }
    let kev = kev_cves(http);
    let epss = epss_scores(http, &all);
    if kev.is_empty() && epss.is_empty() {
        return;
    }
    for f in findings.iter_mut() {
        let Some(cves) = resolved.get(&f.rule_id) else {
            continue;
        };
        let mut marks = String::new();
        if cves.iter().any(|c| kev.contains(c)) {
            marks.push_str("[KEV]");
            if f.severity < Severity::High {
                f.severity = Severity::High;
            }
        }
        // highest EPSS score across the advisory's CVEs wins the marker
        if let Some(best) = cves.iter().filter_map(|c| epss.get(c)).max_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        }) {
            marks.push_str(&format!(
                "[EPSS {:.2} p{:.0}]",
                best.score,
                best.percentile * 100.0
            ));
        }
        if !marks.is_empty() {
            f.message = format!("{} {}", f.message.trim_end(), marks);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_path_segments() {
        assert_eq!(enc("@scope/pkg"), "%40scope%2Fpkg");
        assert_eq!(enc("com.google.guava:guava"), "com.google.guava%3Aguava");
        assert_eq!(enc("github.com/a/b"), "github.com%2Fa%2Fb");
        assert_eq!(enc("plain-name_1.2~x"), "plain-name_1.2~x");
    }

    #[test]
    fn registry_mapping() {
        assert_eq!(ecosystem_registry("npm"), Some("npmjs.org"));
        assert_eq!(ecosystem_registry("PyPI"), Some("pypi.org"));
        assert_eq!(ecosystem_registry("crates.io"), Some("crates.io"));
        assert_eq!(ecosystem_registry("GitHub Actions"), None);
    }

    #[test]
    fn parse_epss_shape() {
        // epss/percentile arrive as strings in the live API
        let e = serde_json::json!({"cve": "CVE-2021-44228", "epss": "0.999990000", "percentile": "1.000000000"});
        let score: f64 = e["epss"].as_str().unwrap().parse().unwrap();
        assert!(score > 0.99);
    }
}
