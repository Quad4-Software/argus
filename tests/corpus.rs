//! Ruleset fixture corpus: every case dir under tests/corpus/ holds a
//! fixture file plus expected.txt listing rule ids that MUST fire
//! (one per line) or `!id` lines for ids that MUST NOT fire on it.
//! Adding a rule without a matching fixture will eventually leave it
//! unproven - keep coverage honest.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_argus"))
}

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus")
}

#[test]
fn corpus_cases_match_expected() {
    let mut failures: Vec<String> = Vec::new();
    let mut cases = 0usize;
    for e in std::fs::read_dir(corpus()).unwrap().flatten() {
        let dir = e.path();
        if !dir.is_dir() {
            continue;
        }
        let exp = dir.join("expected.txt");
        if !exp.exists() {
            failures.push(format!("{}: missing expected.txt", dir.display()));
            continue;
        }
        // the fixture is the single non-expected file in the dir
        let fixture: Option<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|f| f.file_name().to_string_lossy().to_string())
            .find(|n| n != "expected.txt");
        let Some(fixture) = fixture else {
            failures.push(format!("{}: no fixture file", dir.display()));
            continue;
        };

        let out = bin()
            .arg("scan")
            .arg(&dir)
            .args(["--format", "json", "--color", "never"])
            .output()
            .unwrap();
        let report: Value = serde_json::from_slice(&out.stdout).expect("valid json");
        let ids_for_fixture: Vec<String> = report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| {
                f["path"]
                    .as_str()
                    .map(|p| p.ends_with(&fixture))
                    .unwrap_or(false)
            })
            .map(|f| f["rule_id"].as_str().unwrap_or("").to_string())
            .collect();

        for line in std::fs::read_to_string(&exp).unwrap().lines() {
            for tok in line.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                if let Some(id) = tok.strip_prefix('!') {
                    if ids_for_fixture.iter().any(|x| x == id) {
                        failures.push(format!("{}: {id} fired but is forbidden", dir.display()));
                    }
                } else if !ids_for_fixture.iter().any(|x| x == tok) {
                    failures.push(format!(
                        "{}: expected {tok} on {fixture}, got {:?}",
                        dir.display(),
                        ids_for_fixture
                    ));
                }
            }
        }
        cases += 1;
    }
    assert!(cases > 10, "corpus vanished - only {cases} cases");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    eprintln!("corpus: {cases} cases passed");
}
