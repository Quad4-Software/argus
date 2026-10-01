// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Live checks against public targets, plus input rejection.

use serde_json::Value;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_argus"))
}

fn json_cmd(args: &[&str]) -> (bool, String, String) {
    let out = bin()
        .args([
            "--color",
            "never",
            "--progress",
            "never",
            "--format",
            "json",
        ])
        .args(args)
        .output()
        .expect("spawn argus");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn finding<'a>(doc: &'a Value, module: &str) -> &'a Value {
    doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["module"] == module)
        .unwrap_or_else(|| panic!("missing module {module} in {doc}"))
}

#[test]
fn rejects_non_public_and_offline() {
    let bad = bin()
        .args(["--color", "never", "domain", "localhost"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
    let mail = bin()
        .args(["--color", "never", "email", "not-an-email"])
        .output()
        .unwrap();
    assert_eq!(mail.status.code(), Some(2));
    let off = bin()
        .args(["--offline", "--color", "never", "domain", "quad4.io"])
        .output()
        .unwrap();
    assert_eq!(off.status.code(), Some(2));
    let dir = std::env::temp_dir().join(format!("argus-geo-empty-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let bare = bin()
        .env("XDG_CACHE_HOME", &dir)
        .args(["--offline", "--color", "never", "ip", "1.1.1.1"])
        .output()
        .unwrap();
    assert_eq!(
        bare.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&bare.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
    let local = bin()
        .args(["--color", "never", "ip", "127.0.0.1"])
        .output()
        .unwrap();
    assert_eq!(local.status.code(), Some(2));
}

#[test]
#[ignore = "needs public DNS"]
fn live_public_ip() {
    let (ok, stdout, stderr) = json_cmd(&["ip", "1.1.1.1"]);
    assert!(ok, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).expect("ip json");
    assert_eq!(doc["target"], "1.1.1.1");
    assert_eq!(doc["kind"], "ip");
    let elapsed = doc["elapsed_ms"].as_u64().unwrap();
    assert!(elapsed < 20_000, "ip scan took {elapsed} ms");
    let geo = finding(&doc, "geo");
    assert_eq!(geo["status"], "confirmed", "{}", geo["summary"]);
    let ports = finding(&doc, "internetdb");
    assert_ne!(ports["status"], "error", "{}", ports["summary"]);
    let _ = finding(&doc, "hudsonrock");
    let _ = finding(&doc, "ptr");
    let _ = finding(&doc, "rdap");
    let asn = finding(&doc, "asn");
    assert_eq!(asn["status"], "confirmed", "{}", asn["summary"]);
    assert!(
        asn["summary"].as_str().unwrap().contains("13335")
            || asn["summary"].as_str().unwrap().contains("CLOUDFLARE"),
        "{}",
        asn["summary"]
    );
    let _ = finding(&doc, "vpn");
}

#[test]
#[ignore = "needs public DNS"]
fn live_hash_and_url() {
    let eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    let (ok, stdout, stderr) = json_cmd(&["hash", eicar]);
    assert!(ok, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).expect("hash json");
    let circl = finding(&doc, "circl");
    assert_eq!(circl["status"], "confirmed", "{}", circl["summary"]);
    assert!(
        circl["summary"].as_str().unwrap().contains("eicar"),
        "{}",
        circl["summary"]
    );
    let miss = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let (ok, stdout, stderr) = json_cmd(&["hash", miss]);
    assert!(ok, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).expect("hash miss json");
    assert_ne!(finding(&doc, "circl")["status"], "error");
    let (ok, stdout, stderr) = json_cmd(&["url", "https://quad4.io"]);
    assert!(ok, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).expect("url json");
    assert_ne!(finding(&doc, "fetch")["status"], "error");
    let _ = finding(&doc, "waf");
    let _ = finding(&doc, "redirects");
}

#[test]
fn ports_refuses_a_range_and_reports_a_closed_port() {
    let range = bin()
        .args(["--color", "never", "ports", "10.0.0.0/24"])
        .output()
        .unwrap();
    assert_eq!(range.status.code(), Some(2));
    let (ok, stdout, stderr) = json_cmd(&["ports", "127.0.0.1", "--ports", "1"]);
    assert!(ok, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).expect("ports json");
    let row = finding(&doc, "ports");
    let status = row["status"].as_str().unwrap_or("");
    assert!(
        status == "absent" || status == "inconclusive",
        "{}",
        row["summary"]
    );
    let off = bin()
        .args(["--offline", "--color", "never", "hash", "aa"])
        .output()
        .unwrap();
    assert_eq!(off.status.code(), Some(2));
}

#[test]
#[ignore = "needs public DNS"]
fn live_quad4_domain_and_mailbox() {
    let (ok, stdout, stderr) = json_cmd(&["domain", "https://quad4.io/docs"]);
    assert!(ok, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).expect("domain json");
    assert_eq!(doc["target"], "quad4.io");
    assert_eq!(doc["kind"], "domain");
    let elapsed = doc["elapsed_ms"].as_u64().unwrap();
    assert!(elapsed < 20_000, "domain scan took {elapsed} ms");
    let a = finding(&doc, "a");
    let aaaa = finding(&doc, "aaaa");
    assert!(
        a["status"] == "confirmed" || aaaa["status"] == "confirmed",
        "expected an address, got a={} aaaa={}",
        a["status"],
        aaaa["status"]
    );
    assert_eq!(finding(&doc, "ns")["status"], "confirmed");
    assert!(
        finding(&doc, "http")["status"] == "confirmed"
            || finding(&doc, "http")["status"] == "inconclusive"
    );
    for module in [
        "names",
        "ptr",
        "llms",
        "tdmrep",
        "mailboxes",
        "hudsonrock",
        "urlscan",
    ] {
        let status = finding(&doc, module)["status"].as_str().unwrap();
        assert!(
            matches!(status, "confirmed" | "absent" | "inconclusive" | "error"),
            "{module} {status}"
        );
    }

    let (ok, stdout, stderr) = json_cmd(&["email", "argus@quad4.io"]);
    assert!(ok, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).expect("email json");
    assert_eq!(doc["target"], "argus@quad4.io");
    assert_eq!(finding(&doc, "syntax")["summary"], "argus@quad4.io");
    assert_eq!(finding(&doc, "role")["status"], "absent");
    assert_eq!(finding(&doc, "disposable")["status"], "absent");
    assert_eq!(finding(&doc, "provider")["status"], "absent");
    let mx = finding(&doc, "mx");
    assert!(
        mx["status"] == "confirmed" || mx["status"] == "absent",
        "mx lookup failed: {}",
        mx["summary"]
    );
    let spf = finding(&doc, "spf");
    assert_ne!(spf["status"], "error", "spf: {}", spf["summary"]);
    let dmarc = finding(&doc, "dmarc");
    assert_ne!(dmarc["status"], "error", "dmarc: {}", dmarc["summary"]);
    if spf["status"] == "confirmed" {
        assert!(
            spf["summary"].as_str().unwrap().starts_with("SPF "),
            "{}",
            spf["summary"]
        );
    }
    if dmarc["status"] == "confirmed" {
        let s = dmarc["summary"].as_str().unwrap();
        assert!(
            s.contains("p=none") || s.contains("p=quarantine") || s.contains("p=reject"),
            "{s}"
        );
    }
    let elapsed = doc["elapsed_ms"].as_u64().unwrap();
    assert!(elapsed < 20_000, "email scan took {elapsed} ms");
    assert_eq!(finding(&doc, "hibp")["status"], "inconclusive");
    let _ = finding(&doc, "hudsonrock");
    assert_eq!(finding(&doc, "pastes")["status"], "inconclusive");
    assert_eq!(finding(&doc, "smtp")["status"], "inconclusive");
    assert!(
        finding(&doc, "smtp")["summary"]
            .as_str()
            .unwrap()
            .contains("--smtp")
    );
    for module in ["openpgpkey", "rdap-network", "hudsonrock"] {
        let status = finding(&doc, module)["status"].as_str().unwrap();
        assert!(
            matches!(status, "confirmed" | "absent" | "inconclusive" | "error"),
            "{module} {status}"
        );
    }
}

#[test]
#[ignore = "needs public DNS"]
fn live_account_feed_socials_and_exposed_git() {
    let (ok, stdout, stderr) = json_cmd(&["account", "github", "octocat"]);
    assert!(ok, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).expect("github json");
    assert_eq!(finding(&doc, "profile")["status"], "confirmed");
    assert!(
        finding(&doc, "profile")["summary"]
            .as_str()
            .unwrap()
            .contains("octocat")
    );
    assert_eq!(finding(&doc, "repos")["status"], "confirmed");
    let evidence = &finding(&doc, "profile")["evidence"];
    assert!(evidence["age_days"].as_i64().unwrap() > 1000);
    assert!(evidence["followers"].as_i64().unwrap() > 0);

    let (ok, stdout, stderr) = json_cmd(&["account", "gitlab", "dzaporozhets"]);
    assert!(ok, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).expect("gitlab json");
    assert_eq!(finding(&doc, "profile")["status"], "confirmed");
    assert!(
        finding(&doc, "profile")["summary"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase()
            .contains("dzaporozhets")
    );
    let repos = finding(&doc, "repos")["status"].as_str().unwrap();
    assert!(
        repos == "confirmed" || repos == "absent",
        "{}",
        finding(&doc, "repos")
    );

    let (ok, stdout, stderr) = json_cmd(&[
        "feed",
        "https://blog.rust-lang.org/feed.xml",
        "--query",
        "rust",
    ]);
    assert!(ok, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).expect("feed json");
    assert_eq!(finding(&doc, "feed")["status"], "confirmed");
    assert!(
        finding(&doc, "feed")["evidence"]["matched"]
            .as_u64()
            .unwrap()
            > 0
    );

    let (ok, stdout, stderr) = json_cmd(&["socials", "https://example.com"]);
    assert!(ok, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).expect("socials json");
    assert!(finding(&doc, "socials")["status"].is_string());
    assert!(finding(&doc, "resume")["status"].is_string());

    let (ok, stdout, stderr) = json_cmd(&["gitmeta", "https://example.com"]);
    assert!(ok, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).expect("gitmeta json");
    assert_eq!(finding(&doc, "exposed-git")["status"], "absent");
}

#[test]
#[ignore = "needs public DNS"]
fn live_user_and_favicon() {
    let (ok, stdout, stderr) = json_cmd(&["user", "octocat"]);
    assert!(ok, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).expect("user json");
    assert_eq!(finding(&doc, "github")["status"], "confirmed");

    let (ok, stdout, stderr) = json_cmd(&["favicon", "https://example.com"]);
    assert!(ok, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).expect("favicon json");
    let status = finding(&doc, "favicon")["status"].as_str().unwrap();
    assert!(
        matches!(status, "confirmed" | "absent" | "inconclusive"),
        "{status} {doc}"
    );
}

#[test]
fn local_grep_streams_a_column() {
    let dir = std::env::temp_dir().join(format!("argus-grep-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("rows.csv");
    std::fs::write(&path, "email,note\nada@example.com,hi\n").unwrap();
    let out = bin()
        .args([
            "--color",
            "never",
            "--progress",
            "never",
            "grep",
            "--column",
            "email",
            "--eq",
            "ada@example.com",
            "--max",
            "1",
        ])
        .arg(&path)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stdout.contains("ada@example.com"), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}
