// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Advisory database: two embedded TOML files plus user --db extras.
//! Later entries with the same id override earlier ones.

use crate::cve::version;
use crate::finding::Severity;
use serde::Deserialize;
use std::path::Path;

const WEB: &str = include_str!("../../rules/data/cve-web.toml");
const GHSA: &str = include_str!("../../rules/data/cve-ghsa.toml");

#[derive(Clone, Debug, Deserialize)]
pub struct Advisory {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub product: String,
    pub severity: Severity,
    pub title: String,
    #[serde(default)]
    pub affected: Vec<String>,
    #[serde(default)]
    pub fixed: String,
    #[serde(default)]
    pub needs: Vec<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub rce: bool,
    #[serde(default)]
    pub kev: bool,
    #[serde(default)]
    pub exploited: bool,
    #[serde(rename = "ref", default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub published: Option<String>,
}

#[derive(Deserialize)]
struct File {
    #[serde(default)]
    advisory: Vec<Advisory>,
}

impl Advisory {
    pub fn hits(&self, v: &[u64]) -> bool {
        version::affected(&self.affected, v)
    }

    pub fn flag_bits(&self) -> Vec<&'static str> {
        let mut f = Vec::new();
        if self.exploited {
            f.push("exploited");
        }
        if self.kev {
            f.push("kev");
        }
        if self.rce {
            f.push("rce");
        }
        f
    }
}

fn parse(text: &str, src: &str) -> Result<Vec<Advisory>, String> {
    let f: File = toml::from_str(text).map_err(|e| format!("{src}: {e}"))?;
    Ok(f.advisory)
}

/// Merged database: embedded web + ghsa files, then every --db file in
/// order. A repeated id overrides the previous entry in place.
pub fn load(extra: &[std::path::PathBuf]) -> Result<Vec<Advisory>, String> {
    let mut out: Vec<Advisory> = Vec::new();
    let mut pos = std::collections::HashMap::new();
    let mut merge = |list: Vec<Advisory>| {
        for a in list {
            if let Some(i) = pos.get(&a.id).copied() {
                out[i] = a;
            } else {
                pos.insert(a.id.clone(), out.len());
                out.push(a);
            }
        }
    };
    merge(parse(WEB, "cve-web.toml")?);
    merge(parse(GHSA, "cve-ghsa.toml")?);
    for p in extra {
        let text = std::fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display()))?;
        merge(parse(&text, &p.display().to_string())?);
    }
    Ok(out)
}

pub fn for_product<'a>(db: &'a [Advisory], product: &str) -> Vec<&'a Advisory> {
    db.iter().filter(|a| a.product == product).collect()
}

/// Rows for --list, sorted by product then id.
pub fn list(db: &[Advisory], only: &[String]) -> String {
    let mut rows: Vec<&Advisory> = db
        .iter()
        .filter(|a| only.is_empty() || only.iter().any(|p| p == &a.product))
        .collect();
    rows.sort_by(|a, b| a.product.cmp(&b.product).then(a.id.cmp(&b.id)));
    let mut out = String::from("id               product  severity flags        fixed\n");
    for a in rows {
        let flags = if a.flag_bits().is_empty() {
            "-".to_string()
        } else {
            a.flag_bits().join(",")
        };
        out.push_str(&format!(
            "{:<16} {:<8} {:<8} {:<10} {}\n",
            a.id, a.product, a.severity, flags, a.fixed
        ));
    }
    out
}

/// Read one advisory source file; used by tests and --db validation.
#[allow(dead_code)]
pub fn load_file(p: &Path) -> Result<Vec<Advisory>, String> {
    let text = std::fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display()))?;
    parse(&text, &p.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_db_loads_and_is_consistent() {
        let db = load(&[]).unwrap();
        assert!(db.len() > 40);
        let mut seen = std::collections::HashSet::new();
        for a in &db {
            assert!(
                seen.insert((a.product.clone(), a.id.clone())),
                "dup {}",
                a.id
            );
            assert!(!a.affected.is_empty(), "{} has no ranges", a.id);
            for r in &a.affected {
                for c in r.split_whitespace() {
                    let v = c.trim_start_matches(['>', '<', '=']);
                    assert!(version::parse(v).is_some(), "{}: bad constraint {c}", a.id);
                }
            }
        }
        for p in ["nginx", "php", "brotli", "httpd", "traefik", "caddy"] {
            assert!(!for_product(&db, p).is_empty(), "no advisories for {p}");
        }
    }

    #[test]
    fn extra_db_overrides_by_id() {
        let dir = std::env::temp_dir().join(format!("argus-cvedb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("extra.toml");
        std::fs::write(
            &f,
            "[[advisory]]\nid = \"CVE-2026-93479\"\nproduct = \"nginx\"\nseverity = \"low\"\ntitle = \"x\"\naffected = [\"<1.0.0\"]\nfixed = \"y\"\n\n[[advisory]]\nid = \"CVE-TEST-1\"\nproduct = \"nginx\"\nseverity = \"high\"\ntitle = \"y\"\naffected = [\"<9.9.9\"]\nfixed = \"z\"\n",
        )
        .unwrap();
        let db = load(std::slice::from_ref(&f)).unwrap();
        let a = db.iter().find(|a| a.id == "CVE-2026-93479").unwrap();
        assert_eq!(a.severity, Severity::Low);
        assert_eq!(db.iter().filter(|x| x.id == "CVE-2026-93479").count(), 1);
        assert!(db.iter().any(|x| x.id == "CVE-TEST-1"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
