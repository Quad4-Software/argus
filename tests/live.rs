// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Live network tests - ignored by default, run by the `live` CI job on
//! schedule/manual trigger. These hit real endpoints; do not make them
//! part of the PR gate.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_argus"))
}

#[test]
#[ignore]
fn osv_batch_finds_known_advisory() {
    let dir = std::env::temp_dir().join(format!("argus-live-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}"#,
    )
    .unwrap();
    let out = bin()
        .args(["--osv", "scan"])
        .arg(&dir)
        .args(["--format", "json"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("GHSA-"),
        "expected advisory hits, got: {text}"
    );
}

#[test]
#[ignore]
fn web_scan_live_headers() {
    let out = bin()
        .args(["web", "https://example.com", "--format", "json"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&text).expect("valid json");
    assert!(v["findings"].is_array());
}

#[test]
#[ignore]
fn npm_registry_lookup_live() {
    let dir = std::env::temp_dir().join(format!("argus-live-reg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"packages":{"node_modules/left-pad":{"version":"1.3.0"}}}"#,
    )
    .unwrap();
    let out = bin()
        .args(["scan"])
        .arg(&dir)
        .args(["--dep-check", "--format", "json"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("DEP-"), "expected dep-check findings: {text}");
}
