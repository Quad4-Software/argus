//! Real YARA evaluation via yara-x. Load .yar/.yara sources, scan file bytes.

use crate::finding::{Finding, Severity};
use std::path::PathBuf;

/// Compile every .yar/.yara file in the given files/dirs into one rule set.
pub fn compile(paths: &[PathBuf]) -> Result<yara_x::Rules, String> {
    let mut files = Vec::new();
    for p in paths {
        if p.is_dir() {
            collect_dir(p, &mut files)?;
        } else {
            files.push(p.clone());
        }
    }
    if files.is_empty() {
        return Err("no .yar/.yara files found".into());
    }
    let mut compiler = yara_x::Compiler::new();
    let mut errs = Vec::new();
    for f in &files {
        let src = std::fs::read_to_string(f).map_err(|e| format!("{}: {e}", f.display()))?;
        if let Err(e) = compiler.add_source(src.as_str()) {
            errs.push(format!("{}: {e}", f.display()));
        }
    }
    if !errs.is_empty() {
        return Err(format!(
            "{} yara file(s) failed to compile:\n  {}",
            errs.len(),
            errs.join("\n  ")
        ));
    }
    Ok(compiler.build())
}

fn collect_dir(dir: &std::path::Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d)
            .map_err(|e| format!("{}: {e}", d.display()))?
            .flatten()
        {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "yar" || x == "yara") {
                out.push(p);
            }
        }
    }
    Ok(())
}

/// Per-call scan. Creates a fresh Scanner (Scanner holds state; cheap to make).
pub fn scan_bytes(rel: &str, bytes: &[u8], rules: &yara_x::Rules, target: &str) -> Vec<Finding> {
    let mut scanner = yara_x::Scanner::new(rules);
    let results = match scanner.scan(bytes) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    results
        .matching_rules()
        .map(|r| {
            let sev = meta_severity(&r);
            Finding {
                ruleset: "yara".into(),
                rule_id: format!("YARA:{}", r.identifier()),
                severity: sev,
                target: target.into(),
                path: rel.into(),
                line: None,
                excerpt: None,
                message: format!("YARA rule {} matched", r.identifier()),
                remediation: None,
                reference: meta_str(&r, "reference"),
                window: None,
            }
        })
        .collect()
}

fn meta_severity(r: &yara_x::Rule<'_, '_>) -> Severity {
    for (k, v) in r.metadata() {
        if k == "severity" {
            if let yara_x::MetaValue::String(s) = v {
                return match s.to_ascii_lowercase().as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => Severity::Info,
                };
            }
        }
    }
    Severity::Medium
}

fn meta_str(r: &yara_x::Rule<'_, '_>, want: &str) -> Option<String> {
    for (k, v) in r.metadata() {
        if k == want {
            if let yara_x::MetaValue::String(s) = v {
                return Some(s.to_string());
            }
        }
    }
    None
}
