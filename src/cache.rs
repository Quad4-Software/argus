//! Incremental scan cache - skip re-reading files whose (mtime,size)
//! and the active ruleset fingerprint are unchanged. Cache lives at
//! <root>/.arguscache.json and is written back after the scan.

use crate::finding::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Default, Serialize, Deserialize)]
pub struct ScanCache {
    /// sha256 of the compiled ruleset - stale caches are dropped wholesale.
    pub ruleset_fp: String,
    /// rel path -> cached scan result
    pub files: HashMap<String, Entry>,
}

#[derive(Serialize, Deserialize)]
pub struct Entry {
    pub mtime_ns: u128,
    pub size: u64,
    pub findings: Vec<Finding>,
}

fn path_for(root: &Path) -> std::path::PathBuf {
    use sha2::Digest;
    let canon = root
        .canonicalize()
        .unwrap_or_else(|_| root.to_path_buf())
        .display()
        .to_string();
    let h = sha2::Sha256::digest(canon.as_bytes());
    let key = h[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    cache_dir().join(format!("{key}.json"))
}

/// ~/.cache/argus (or XDG_CACHE_HOME/argus)
pub fn cache_dir() -> std::path::PathBuf {
    if let Ok(x) = std::env::var("XDG_CACHE_HOME") {
        return Path::new(&x).join("argus");
    }
    if let Ok(h) = std::env::var("HOME") {
        return Path::new(&h).join(".cache").join("argus");
    }
    std::env::temp_dir().join("argus-cache")
}

/// sha256 over sorted rule ids+descriptions - any ruleset change
/// invalidates the whole cache.
pub fn ruleset_fp(rules: &[&crate::rules::CompiledRule]) -> String {
    use sha2::Digest;
    let mut ids: Vec<String> = rules
        .iter()
        .map(|r| format!("{}:{}:{}", r.set, r.id, r.description))
        .collect();
    ids.sort();
    let h = sha2::Sha256::digest(ids.join("\n").as_bytes());
    h[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Load the cache; returns empty on mismatch/missing/corrupt.
pub fn load(root: &Path, fp: &str) -> ScanCache {
    let Ok(text) = std::fs::read_to_string(path_for(root)) else {
        return ScanCache::default();
    };
    let Ok(c) = serde_json::from_str::<ScanCache>(&text) else {
        return ScanCache::default();
    };
    if c.ruleset_fp != fp {
        return ScanCache::default();
    }
    c
}

pub fn store(root: &Path, cache: &ScanCache) {
    let dir = cache_dir();
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(j) = serde_json::to_string(cache) {
        let _ = std::fs::write(path_for(root), j);
    }
}

/// Stat signature for change detection.
pub fn stat_sig(path: &Path) -> Option<(u128, u64)> {
    let m = std::fs::metadata(path).ok()?;
    let mt = m
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    Some((mt.as_nanos(), m.len()))
}
