//! Package-registry metadata lookups (npm/PyPI/crates.io) with a small
//! on-disk cache. Shared by dependency-confusion checks, unmaintained-dep
//! detection, maintainer-change monitoring, and license audits.

use crate::http::HttpClient;
use crate::osv::Dep;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryInfo {
    /// package exists on the public registry at all
    pub exists: bool,
    /// days since the most recent release (0 = unknown)
    pub last_release_days: Option<u64>,
    /// sorted maintainer/owner identities where the registry exposes them
    pub maintainers: Vec<String>,
    /// upstream repository URL if declared
    pub repo_url: Option<String>,
    /// declared license expression if any
    pub license: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct Cache {
    /// key "eco:name" -> (fetched unix ts, info)
    entries: HashMap<String, (u64, RegistryInfo)>,
}

fn cache_path() -> PathBuf {
    std::env::home_dir()
        .unwrap_or_else(|| "/tmp".into())
        .join(".local/share/argus/registry-cache.json")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

const TTL: u64 = 24 * 3600;

/// Metadata for one dep; cached 24h under ~/.local/share/argus.
pub fn lookup(http: &HttpClient, dep: &Dep) -> Result<RegistryInfo, String> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<Cache>> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| {
        let c: Cache = std::fs::read_to_string(cache_path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        std::sync::Mutex::new(c)
    });
    let key = format!("{}:{}", dep.ecosystem, dep.name);
    {
        let c = cache.lock().unwrap();
        if let Some((ts, info)) = c.entries.get(&key)
            && now().saturating_sub(*ts) < TTL
        {
            return Ok(info.clone());
        }
    }
    let info = match dep.ecosystem {
        "npm" => npm(http, &dep.name)?,
        "PyPI" => pypi(http, &dep.name)?,
        "crates.io" => crates(http, &dep.name)?,
        _ => return Err(format!("no registry metadata for {}", dep.ecosystem)),
    };
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

fn parse_time_days(ts: &str) -> Option<u64> {
    // ISO "2024-05-01T12:00:00.000Z" -> days ago; cheap parse, no chrono
    let (y, mo, d): (i64, i64, i64) = (
        ts.get(0..4)?.parse().ok()?,
        ts.get(5..7)?.parse().ok()?,
        ts.get(8..10)?.parse().ok()?,
    );
    // days since civil (Howard Hinnant)
    let y = if mo <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let today = (now() / 86400) as i64;
    Some((today - days).max(0) as u64)
}

fn npm(http: &HttpClient, name: &str) -> Result<RegistryInfo, String> {
    let enc = name.replace('/', "%2f");
    let (st, v) = http.get_status_json(&format!("https://registry.npmjs.org/{enc}"))?;
    if st != 200 {
        return Ok(RegistryInfo::default());
    }
    let mut info = RegistryInfo {
        exists: true,
        ..Default::default()
    };
    if let Some(m) = v["time"]["modified"].as_str() {
        info.last_release_days = parse_time_days(m);
    }
    if let Some(arr) = v["maintainers"].as_array() {
        info.maintainers = arr
            .iter()
            .filter_map(|m| {
                m["name"].as_str().map(str::to_string).or_else(|| {
                    m.as_str()
                        .map(|s| s.split_whitespace().next().unwrap_or(s).to_string())
                })
            })
            .collect();
        info.maintainers.sort();
    }
    info.repo_url = v["repository"]["url"].as_str().map(str::to_string);
    info.license = v["license"]
        .as_str()
        .map(str::to_string)
        .or_else(|| v["license"]["type"].as_str().map(str::to_string));
    Ok(info)
}

fn pypi(http: &HttpClient, name: &str) -> Result<RegistryInfo, String> {
    let (st, v) = http.get_status_json(&format!("https://pypi.org/pypi/{name}/json"))?;
    if st != 200 {
        return Ok(RegistryInfo::default());
    }
    let mut info = RegistryInfo {
        exists: true,
        ..Default::default()
    };
    // newest upload across the latest release's files
    let mut newest: Option<u64> = None;
    if let Some(ver) = v["info"]["version"].as_str()
        && let Some(files) = v["releases"][ver].as_array()
    {
        for f in files {
            if let Some(t) = f["upload_time_iso_8601"].as_str()
                && let Some(d) = parse_time_days(t)
            {
                newest = Some(newest.map_or(d, |n: u64| n.min(d)));
            }
        }
    }
    info.last_release_days = newest;
    for k in ["author_email", "maintainer_email", "author", "maintainer"] {
        if let Some(s) = v["info"][k].as_str()
            && !s.is_empty()
        {
            info.maintainers.push(s.to_string());
        }
    }
    info.maintainers.sort();
    info.maintainers.dedup();
    info.repo_url = v["info"]["project_urls"]["Source"]
        .as_str()
        .map(str::to_string);
    info.license = v["info"]["license"]
        .as_str()
        .map(str::to_string)
        .or_else(|| {
            v["info"]["classifiers"].as_array().and_then(|c| {
                c.iter()
                    .filter_map(|x| x.as_str())
                    .find(|s| s.contains("License ::"))
                    .map(str::to_string)
            })
        });
    Ok(info)
}

fn crates(http: &HttpClient, name: &str) -> Result<RegistryInfo, String> {
    let (st, v) = http.get_status_json(&format!("https://crates.io/api/v1/crates/{name}"))?;
    if st != 200 {
        return Ok(RegistryInfo::default());
    }
    let mut info = RegistryInfo {
        exists: true,
        ..Default::default()
    };
    if let Some(t) = v["crate"]["updated_at"].as_str() {
        info.last_release_days = parse_time_days(t);
    }
    info.repo_url = v["crate"]["repository"].as_str().map(str::to_string);
    info.license = v["crate"]["license"].as_str().map(str::to_string);
    if let Ok((200, o)) =
        http.get_status_json(&format!("https://crates.io/api/v1/crates/{name}/owners"))
        && let Some(users) = o["users"].as_array()
    {
        info.maintainers = users
            .iter()
            .filter_map(|u| u["login"].as_str().map(str::to_string))
            .collect();
        info.maintainers.sort();
    }
    Ok(info)
}
