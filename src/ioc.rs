//! Flat IoC list import: one indicator per line, auto-classified.
//! sha256 (64 hex) -> file-hash rule; domain/IP/URL -> content rule;
//  anything else -> literal substring rule at the list's severity.

use crate::finding::Severity;
use crate::rules::{CompiledKind, CompiledRule, UnsafeRefs};
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;

pub fn load_file(path: &Path, severity: Severity) -> Result<Vec<CompiledRule>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let set = format!(
        "ioc:{}",
        path.file_name().unwrap_or_default().to_string_lossy()
    );
    let sha256_re = Regex::new(r"^[0-9a-fA-F]{64}$").unwrap();
    let hash_re = Regex::new(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$").unwrap();
    let ip_re = Regex::new(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$").unwrap();
    let domain_re = Regex::new(r"(?i)^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$").unwrap();
    let url_re = Regex::new(r"^https?://\S+$").unwrap();
    let path_re = Regex::new(r"^[~/.a-zA-Z0-9_\\-]+(/[^\s]+)+$").unwrap();

    let mut hashes = HashSet::new();
    let mut needles: Vec<(String, String)> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        // tolerate common decorations: "1.2.3.4,", "[.]", "hxxp://", trailing ;
        let cleaned = line
            .trim_end_matches([',', ';'])
            .replace("[.]", ".")
            .replace("hxxp://", "http://")
            .replace("hxxps://", "https://");
        let v = cleaned.trim();
        if v.is_empty() {
            continue;
        }
        if sha256_re.is_match(v) {
            hashes.insert(v.to_lowercase());
        } else if ip_re.is_match(v) {
            needles.push((v.into(), "ip".to_string()));
        } else if url_re.is_match(v) {
            needles.push((v.into(), "url".to_string()));
        } else if domain_re.is_match(v) {
            needles.push((v.into(), "domain".to_string()));
        } else if hash_re.is_match(v) {
            needles.push((v.into(), "md5/sha1".to_string()));
        } else if path_re.is_match(v) {
            needles.push((v.into(), "path".to_string()));
        } else {
            needles.push((v.into(), "string".to_string()));
        }
        let _ = i;
    }

    let mut rules: Vec<CompiledRule> = Vec::new();
    if !hashes.is_empty() {
        rules.push(CompiledRule {
            set: set.clone(),
            id: format!("{}:sha256", set),
            severity,
            description: "File hash in IoC list (sha256)".into(),
            remediation: Some(
                "Investigate the file; hash matched a known-bad indicator list.".into(),
            ),
            reference: Some(path.display().to_string()),
            window: None,
            kind: CompiledKind::Hash { sha256: hashes },
        });
    }
    for (n, kind) in needles {
        rules.push(CompiledRule {
            set: set.clone(),
            id: format!("IOC-{}", kind),
            severity,
            description: format!("IoC list match ({kind})"),
            remediation: Some("Indicator matched a supplied IoC list; verify context.".into()),
            reference: Some(path.display().to_string()),
            window: None,
            kind: CompiledKind::Content {
                exclude: None,
                path: None,
                contains: vec![n],
                contains_all: false,
                regex: None,
                unless: None,
            },
        });
    }
    // dedup identical content rules (same single needle) via contains set merge not needed; keep simple
    let _ = UnsafeRefs::Tags;
    Ok(rules)
}
