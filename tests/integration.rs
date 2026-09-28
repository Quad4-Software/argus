//! End-to-end tests against the fixture repos.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_argus"))
}

fn fixture(name: &str) -> std::path::PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

use std::path::PathBuf;

#[test]
fn dirty_repo_flags_all_planted_iocs() {
    let out = bin()
        .args(["scan"])
        .arg(fixture("dirty-repo"))
        .args(["--color", "never", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ids: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap())
        .collect();
    for want in [
        "MSH-001", "MSH-002", "MSH-003", "MSH-004", "MSH-005", "MSH-006", "MSH-007", "MSH-008",
        "MSH-009", "SHC-001", "SHC-002", "SHC-003", "ACT-001", "ACT-002", "ACT-003", "HYG-002",
        "HYG-003", "HYG-005", "HYG-001",
    ] {
        assert!(ids.contains(&want), "missing finding {want}; got {ids:?}");
    }
    // Pinned clean SHA must not fire.
    let pins_clean = v["findings"].as_array().unwrap().iter().any(|f| {
        f["path"].as_str().unwrap_or("").ends_with("stale.yml")
            && f["excerpt"]
                .as_str()
                .unwrap_or("")
                .contains("actions/checkout")
    });
    assert!(!pins_clean, "clean SHA pin should not be flagged");
}

#[test]
fn clean_repo_exits_zero() {
    let out = bin()
        .args(["scan"])
        .arg(fixture("clean-repo"))
        .args(["--color", "never"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("0 critical"));
}

#[test]
fn severity_filter_and_fail_on() {
    // Report only critical; still exit 1.
    let out = bin()
        .args(["scan"])
        .arg(fixture("dirty-repo"))
        .args(["--color", "never", "--severity", "critical"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!text.contains("HIGH"), "should hide non-critical findings");

    // Fail only on... unreachable level: everything passes.
    let out = bin()
        .args(["scan"])
        .arg(fixture("dirty-repo"))
        .args([
            "--color",
            "never",
            "--fail-on",
            "critical",
            "--severity",
            "high",
        ])
        .output()
        .unwrap();
    // highs exist but severity filter hides them -> still finds critical? no:
    // severity=high reports >=high incl critical -> fail_on critical -> exit 1
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn aur_and_pypi_fixtures() {
    let out = bin()
        .args(["scan"])
        .arg(fixture("dirty-aur"))
        .arg(fixture("dirty-pypi"))
        .args(["--color", "never", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ids: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap())
        .collect();
    for want in [
        "AUR-001", "AUR-002", "AUR-004", "AUR-005", "AUR-010", "AUR-011", "AUR-020", "TPCP-007",
        "TPCP-008", "TPCP-009", "TPCP-011", "PYPI-001", "PYPI-003", "PYPI-005", "PYPI-006",
    ] {
        assert!(ids.contains(&want), "missing finding {want}; got {ids:?}");
    }
    // clean dep versions must not fire package-version rules
    let clean_ver = v["findings"].as_array().unwrap().iter().any(|f| {
        f["rule_id"].as_str() == Some("TPCP-007")
            && f["excerpt"].as_str().unwrap_or("").contains("requests==")
    });
    assert!(!clean_ver);
}

#[test]
fn markdown_and_sarif_formats() {
    for (fmt, check) in [
        ("markdown", "| critical" as &str),
        ("sarif", "\"2.1.0\""),
        ("codeclimate", "check_name"),
    ] {
        let out = bin()
            .args(["scan"])
            .arg(fixture("dirty-repo"))
            .args(["--format", fmt])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains(check), "{fmt} output missing {check}");
    }
}

#[test]
fn ioc_list_import() {
    use sha2::Digest;
    // sha256 of the fixture bundle.js lands as a hash rule.
    let data = std::fs::read(fixture("dirty-repo").join("bundle.js")).unwrap();
    let hash = sha2::Sha256::digest(&data)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    let dir = std::env::temp_dir().join(format!("argus-ioc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let list = dir.join("iocs.txt");
    std::fs::write(&list, format!("{hash}\nm-kosche.com\n")).unwrap();
    let out = bin()
        .args(["scan"])
        .arg(fixture("dirty-repo"))
        .arg("--iocs")
        .arg(&list)
        .args(["--color", "never", "--format", "json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ioc_hits = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["ruleset"].as_str().unwrap_or("").starts_with("ioc:"))
        .count();
    assert!(ioc_hits >= 2, "expected sha256+domain ioc hits");
}

#[test]
fn json_schema_shape() {
    let out = bin()
        .args(["scan"])
        .arg(fixture("dirty-repo"))
        .args(["--format", "json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["tool"], "argus");
    assert!(v["generated_at"].as_str().unwrap().ends_with('Z'));
    assert!(v["files_scanned"].as_u64().unwrap() > 0);
    let f = &v["findings"][0];
    for key in [
        "ruleset", "rule_id", "severity", "target", "path", "message",
    ] {
        assert!(f.get(key).is_some(), "finding missing {key}");
    }
}
