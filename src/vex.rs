//! OpenVEX support: ingest a VEX document to suppress/annotate findings,
//! and emit VEX documents for the vulns a scan found.
//!
//! Spec: https://github.com/openvex/spec - statements carry
//! {vulnerability: {name}, products: [...], status, justification}.
//! Statuses: not_affected | affected | fixed | under_investigation.

use crate::finding::{Finding, Severity};

pub struct Statement {
    pub vuln: String,
    pub status: String,
    pub justification: String,
}

/// Load an OpenVEX document. Tolerates the common shapes:
/// {"statements":[...]}, {"statement":[...]}, or a bare [...].
pub fn load(path: &str) -> Result<Vec<Statement>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{path}: bad JSON: {e}"))?;
    let stmts = v["statements"]
        .as_array()
        .or_else(|| v["statement"].as_array())
        .or_else(|| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for s in stmts {
        let name = s["vulnerability"]["name"]
            .as_str()
            .or_else(|| s["vulnerability"]["id"].as_str())
            .or_else(|| s["vulnerability"].as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        out.push(Statement {
            vuln: name,
            status: s["status"].as_str().unwrap_or("").to_lowercase(),
            justification: s["justification"]
                .as_str()
                .or_else(|| s["status_notes"].as_str())
                .unwrap_or("")
                .to_string(),
        });
    }
    Ok(out)
}

/// Apply statements to findings: drop `not_affected`/`fixed`, annotate
/// `under_investigation` in the message. Returns (kept, suppressed-count).
pub fn apply(findings: Vec<Finding>, stmts: &[Statement]) -> (Vec<Finding>, usize) {
    let mut suppressed = 0usize;
    let mut out = Vec::with_capacity(findings.len());
    for mut f in findings {
        // match on rule_id or any id-shaped token in the message
        let hit = stmts.iter().find(|s| {
            f.rule_id == s.vuln
                || f.message.contains(&s.vuln)
                || f.excerpt.as_deref() == Some(&s.vuln)
        });
        match hit.map(|s| s.status.as_str()) {
            Some("not_affected") | Some("fixed") => suppressed += 1,
            Some("under_investigation") => {
                let j = hit.map(|s| s.justification.clone()).unwrap_or_default();
                f.message = format!(
                    "[vex: under_investigation{}] {}",
                    if j.is_empty() {
                        String::new()
                    } else {
                        format!(" - {j}")
                    },
                    f.message
                );
                // visibility over suppression: drop one severity notch
                if f.severity > Severity::Medium {
                    f.severity = Severity::Medium;
                }
                out.push(f);
            }
            _ => out.push(f),
        }
    }
    (out, suppressed)
}

/// Build a purl from "ecosystem name@version" excerpt text.
fn purl_of(excerpt: &str) -> Option<String> {
    let (eco, rest) = excerpt.split_once(' ')?;
    let (name, ver) = rest.rsplit_once('@')?;
    let ty = match eco {
        "npm" => "npm",
        "PyPI" => "pypi",
        "crates.io" => "cargo",
        "Go" => "golang",
        "RubyGems" => "gem",
        "GitHub Actions" => "githubactions",
        _ => return None,
    };
    Some(format!("pkg:{ty}/{}@{}", name, ver))
}

/// Emit an OpenVEX document covering every osv finding as
/// under_investigation (the honest starting state before triage).
pub fn emit(findings: &[Finding], tool: &str) -> String {
    let stmts: Vec<serde_json::Value> = findings
        .iter()
        .filter(|f| f.ruleset == "osv")
        .map(|f| {
            let product = f
                .excerpt
                .as_deref()
                .and_then(purl_of)
                .unwrap_or_else(|| f.path.clone());
            serde_json::json!({
                "vulnerability": {"name": f.rule_id},
                "products": [{"@id": product}],
                "status": "under_investigation",
                "status_notes": format!("{} detected at {}", tool, f.path),
            })
        })
        .collect();
    serde_json::json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": format!("urn:argus:vex:{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)),
        "author": tool,
        "role": "Document Creator",
        "timestamp": crate::finding::iso8601_pub(),
        "version": 1,
        "statements": stmts,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;

    fn f(id: &str, sev: Severity) -> Finding {
        Finding {
            ruleset: "osv".into(),
            rule_id: id.into(),
            severity: sev,
            target: "t".into(),
            path: "lock".into(),
            line: None,
            excerpt: Some("npm lodash@4.17.20".into()),
            message: format!("OSV advisory {id}"),
            remediation: None,
            reference: None,
            window: None,
        }
    }

    #[test]
    fn suppress_and_annotate() {
        let stmts = vec![
            Statement {
                vuln: "GHSA-a".into(),
                status: "not_affected".into(),
                justification: "code not present".into(),
            },
            Statement {
                vuln: "GHSA-b".into(),
                status: "under_investigation".into(),
                justification: "triage".into(),
            },
            Statement {
                vuln: "GHSA-c".into(),
                status: "fixed".into(),
                justification: "upgraded".into(),
            },
        ];
        let findings = vec![
            f("GHSA-a", Severity::High),
            f("GHSA-b", Severity::High),
            f("GHSA-c", Severity::Critical),
            f("GHSA-d", Severity::High),
        ];
        let (kept, sup) = apply(findings, &stmts);
        assert_eq!(sup, 2);
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].rule_id, "GHSA-b");
        assert_eq!(kept[0].severity, Severity::Medium);
        assert!(kept[0].message.contains("under_investigation"));
        assert_eq!(kept[1].rule_id, "GHSA-d");
    }

    #[test]
    fn purl_mapping() {
        assert_eq!(
            purl_of("npm lodash@4.17.20"),
            Some("pkg:npm/lodash@4.17.20".into())
        );
        assert_eq!(
            purl_of("crates.io serde@1.0.0"),
            Some("pkg:cargo/serde@1.0.0".into())
        );
        assert_eq!(purl_of("weird x"), None);
    }
}
