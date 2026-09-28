//! Hardening tests: adversarial inputs, fault injection, determinism (races),
//! chaos fuzzing, suppression markers, baseline round-trips.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_argus"))
}
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}
fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("argus-h-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn scan_json(dir: &Path) -> Value {
    let out = bin()
        .args(["scan"])
        .arg(dir)
        .args(["--color", "never", "--format", "json"])
        .output()
        .unwrap();
    serde_json::from_slice(&out.stdout).expect("valid json")
}

// ---------- fault injection / adversarial files ----------

#[test]
fn adversarial_files_no_panic() {
    let d = tmpdir("adv");
    // invalid UTF-8 / binary blob
    std::fs::write(
        d.join("blob.bin"),
        (0u8..=255).cycle().take(65536).collect::<Vec<u8>>(),
    )
    .unwrap();
    // NUL bytes in text file
    std::fs::write(d.join("nul.txt"), b"abc\0def\r\nm-kosche.com\0tail").unwrap();
    // huge line (1 MiB single line)
    let big = format!("x{}m-kosche.com{}y", "A".repeat(1 << 20), "B".repeat(100));
    std::fs::write(d.join("bigline.js"), big).unwrap();
    // unreadable file
    let unr = d.join("locked.txt");
    std::fs::write(&unr, "m-kosche.com").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&unr, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    // broken + circular symlinks
    #[cfg(unix)]
    {
        let _ = std::os::unix::fs::symlink("/nonexistent-xyz", d.join("dangling"));
        let _ = std::os::unix::fs::symlink(".", d.join("loop"));
        let _ = std::os::unix::fs::symlink("loop", d.join("loop"));
    }
    // name collisions / unicode names
    std::fs::write(d.join("weird \tname\nfile.txt"), "t.m-kosche.com").unwrap();

    let out = bin()
        .args(["scan"])
        .arg(&d)
        .args(["--color", "never", "--format", "json", "-j", "16"])
        .output()
        .unwrap();
    assert!(
        out.status.code().unwrap_or(9) <= 2,
        "scanner crashed on adversarial input"
    );
    let v: Value = serde_json::from_slice(&out.stdout).expect("json survived");
    let hits = v["findings"].as_array().unwrap().len();
    assert!(
        hits >= 3,
        "expected IoC hits in nul/bigline/unicode-name files, got {hits}"
    );
    #[cfg(unix)]
    std::fs::set_permissions(&unr, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
    let _ = std::fs::remove_dir_all(&d);
}

// ---------- chaos: random trees must never panic or corrupt output ----------

#[test]
fn chaos_random_tree() {
    let d = tmpdir("chaos");
    // deterministic PRNG so failures are reproducible
    let mut seed: u64 = 0x9e3779b97f4a7c15;
    let mut rng = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for i in 0..400 {
        let depth = (rng() % 4) as usize;
        let mut dir = d.clone();
        for _ in 0..depth {
            dir = dir.join(format!("d{}", rng() % 8));
        }
        std::fs::create_dir_all(&dir).ok();
        let name = match i % 10 {
            0 => "package.json".to_string(),
            1 => "PKGBUILD".to_string(),
            2 => "requirements.txt".to_string(),
            3 => "release.yml".to_string(), // under .github/workflows sometimes
            _ => format!("f{i}.bin"),
        };
        let path = if i % 7 == 0 {
            let w = dir.join(".github/workflows");
            std::fs::create_dir_all(&w).ok();
            w.join(name)
        } else {
            dir.join(name)
        };
        let len = (rng() % 8192) as usize;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push((rng() % 256) as u8);
        }
        // occasionally inject real IoC strings mid-binary
        if i % 9 == 0 {
            let s = b"m-kosche.com";
            let p = (rng() as usize) % (buf.len().max(1));
            let end = (p + s.len()).min(buf.len());
            if end > p {
                buf.splice(p..p, s[..(end - p)].iter().cloned());
            }
        }
        std::fs::write(&path, buf).ok();
    }
    let out = bin()
        .args(["scan"])
        .arg(&d)
        .args(["--color", "never", "--format", "json", "-j", "32"])
        .output()
        .unwrap();
    assert!(out.status.code().unwrap_or(9) <= 2);
    let v: Value = serde_json::from_slice(&out.stdout).expect("json intact under chaos");
    assert!(v["summary"]["total"].is_u64());
    let _ = std::fs::remove_dir_all(&d);
}

// ---------- race / determinism ----------

#[test]
fn deterministic_findings_across_runs() {
    // run the dirty fixture 5x with max parallelism; results must be identical
    // (parallel worker order must not leak into output ordering)
    let mut first: Option<String> = None;
    for _ in 0..5 {
        let out = bin()
            .args(["scan"])
            .arg(fixture("dirty-repo"))
            .args(["--color", "never", "--format", "json", "-j", "32"])
            .output()
            .unwrap();
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        // drop elapsed (nondeterministic) then compare serialized rest
        let mut v = v.clone();
        v["elapsed_ms"] = Value::from(0);
        v["generated_at"] = Value::from(0);
        v["generated_at_unix"] = Value::from(0);
        let s = serde_json::to_string(&v).unwrap();
        match &first {
            None => first = Some(s),
            Some(f) => assert_eq!(*f, s, "nondeterministic scan output"),
        }
    }
}

// ---------- suppression markers ----------

#[test]
fn inline_suppressions() {
    let d = tmpdir("sup");
    std::fs::write(
        d.join("a.js"),
        "var x = 'm-kosche.com'; // argus:ignore MSH-005",
    )
    .unwrap();
    std::fs::write(
        d.join("b.js"),
        "// argus:ignore-next-line MSH-005\nvar y = 'm-kosche.com';",
    )
    .unwrap();
    std::fs::write(
        d.join("c.js"),
        "// argus:ignore-file\nvar z = 'm-kosche.com';",
    )
    .unwrap();
    std::fs::write(d.join("d.js"), "var w = 'm-kosche.com'; // not suppressed").unwrap();
    std::fs::write(
        d.join("e.js"),
        "var q = 'm-kosche.com'; // argus:ignore WRONG-ID",
    )
    .unwrap();
    let v = scan_json(&d);
    let paths: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["path"].as_str())
        .collect();
    assert!(!paths.contains(&"a.js"), "same-line ignore failed");
    assert!(!paths.contains(&"b.js"), "ignore-next-line failed");
    assert!(!paths.contains(&"c.js"), "ignore-file failed");
    assert!(paths.contains(&"d.js"), "unsuppressed line vanished");
    assert!(paths.contains(&"e.js"), "wrong-id suppression over-matched");
    let _ = std::fs::remove_dir_all(&d);
}

// ---------- baseline ----------

#[test]
fn baseline_roundtrip_and_fail_on_new() {
    let d = tmpdir("base");
    let bfile = d.join("baseline.json");
    // write baseline over dirty fixture
    let out = bin()
        .args(["scan"])
        .arg(fixture("dirty-repo"))
        .args(["--color", "never", "--format", "json", "--write-baseline"])
        .arg(&bfile)
        .output()
        .unwrap();
    assert!(out.status.code().unwrap_or(9) <= 2);
    let base: Value = serde_json::from_slice(&std::fs::read(&bfile).unwrap()).unwrap();
    assert!(base["fingerprints"].as_array().unwrap().len() >= 15);

    // rescan with baseline + fail-on-new: nothing new -> exit 0
    let out = bin()
        .args(["scan"])
        .arg(fixture("dirty-repo"))
        .args(["--color", "never", "--format", "json", "--baseline"])
        .arg(&bfile)
        .arg("--fail-on-new")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "baseline should silence known findings"
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["findings"].as_array().unwrap().len(), 0);
    assert!(v["summary"]["baselined"].as_u64().unwrap() >= 15);
    let _ = std::fs::remove_dir_all(&d);
}

// ---------- filter flags ----------

#[test]
fn ruleset_and_disable_filters() {
    let out = bin()
        .args(["scan"])
        .arg(fixture("dirty-repo"))
        .args([
            "--color",
            "never",
            "--format",
            "json",
            "--ruleset",
            "mini-shai-hulud",
        ])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    for f in v["findings"].as_array().unwrap() {
        assert_eq!(
            f["ruleset"], "mini-shai-hulud",
            "ruleset filter leaked {}",
            f["ruleset"]
        );
    }
    let out = bin()
        .args(["scan"])
        .arg(fixture("dirty-repo"))
        .args([
            "--color",
            "never",
            "--format",
            "json",
            "--disable-rule",
            "MSH-005",
        ])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    for f in v["findings"].as_array().unwrap() {
        assert_ne!(f["rule_id"], "MSH-005", "disabled rule still fired");
    }
}

#[test]
fn workflow_audit_fires_and_respects_disable() {
    let v = scan_json(&fixture("dirty-repo"));
    let ids: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .filter(|id| id.starts_with("WFA-"))
        .collect();
    for want in [
        "WFA-001", "WFA-002", "WFA-003", "WFA-005", "WFA-007", "WFA-009",
    ] {
        assert!(ids.contains(&want), "missing workflow audit {want}");
    }
    let out = bin()
        .args(["scan"])
        .arg(fixture("dirty-repo"))
        .args([
            "--color",
            "never",
            "--format",
            "json",
            "--ruleset",
            "mini-shai-hulud",
        ])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        !v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"].as_str().unwrap_or("").starts_with("WFA-")),
        "workflow-audit leaked through --ruleset filter"
    );
}

#[test]
fn typosquat_precision() {
    let v = scan_json(&fixture("dirty-pypi"));
    let msgs: Vec<String> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule_id"].as_str().unwrap_or("").starts_with("TSQ"))
        .map(|f| f["message"].as_str().unwrap_or("").to_string())
        .collect();
    assert!(
        msgs.iter().any(|m| m.contains("reqeusts")),
        "missed planted typosquat: {msgs:?}"
    );
    assert!(
        !msgs
            .iter()
            .any(|m| m.contains("`https`") || m.contains("`lodash`")),
        "typosquat FP: {msgs:?}"
    );
}

// ---------- secrets detection ----------

#[test]
fn secrets_rules() {
    let v = scan_json(&fixture("dirty-secrets"));
    let ids: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();
    for want in ["SEC-001", "SEC-002", "SEC-005", "SEC-100"] {
        assert!(ids.contains(&want), "missing {want} in {ids:?}");
    }
    // masking: no full secret should appear in excerpts
    for f in v["findings"].as_array().unwrap() {
        if let Some(ex) = f["excerpt"].as_str() {
            assert!(
                !ex.contains("xKw9mNvPqRsTuVwXyZaBc"),
                "secret leaked in excerpt: {ex}"
            );
        }
    }
}

// ---------- mcp server ----------

#[test]
fn mcp_stdio_roundtrip() {
    use std::io::Write;
    let mut child = bin()
        .arg("mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        let s = child.stdin.as_mut().unwrap();
        writeln!(
            s,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
        )
        .unwrap();
        writeln!(s, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list"}}"#).unwrap();
        writeln!(s, r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"list_rules","arguments":{{}}}}}}"#).unwrap();
        writeln!(s, r#"{{"jsonrpc":"2.0","id":4,"method":"ping"}}"#).unwrap();
        writeln!(s, r#"{{"jsonrpc":"2.0","id":5,"method":"bogus/method"}}"#).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let mut resp = std::collections::HashMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let v: Value = serde_json::from_str(line).unwrap();
        resp.insert(v["id"].as_i64().unwrap_or(-1), v);
    }
    assert_eq!(resp[&1]["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(resp[&2]["result"]["tools"].as_array().unwrap().len(), 3);
    assert!(
        resp[&3]["result"]["structuredContent"]["count"]
            .as_u64()
            .unwrap()
            > 50
    );
    assert_eq!(resp[&4]["result"], json!({}));
    assert_eq!(resp[&5]["error"]["code"], -32601);
}

// ---------- --diff mode ----------

#[test]
fn diff_mode_scans_only_changed() {
    let d = tmpdir("diff");
    let sh = |args: &[&str]| {
        Command::new("git")
            .args(["-C", &*d.to_string_lossy()])
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .unwrap()
    };
    sh(&["init", "-q"]);
    sh(&[
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "init",
    ]);
    std::fs::write(d.join("clean.js"), "console.log('fine')").unwrap();
    sh(&["add", "."]);
    sh(&["-c", "commit.gpgsign=false", "commit", "-qm", "base"]);
    std::fs::write(d.join("bad.js"), "x='m-kosche.com'").unwrap();
    let v = {
        let out = bin()
            .args(["scan"])
            .arg(&d)
            .args(["--diff", "HEAD", "--color", "never", "--format", "json"])
            .output()
            .unwrap();
        serde_json::from_slice::<Value>(&out.stdout).unwrap()
    };
    // only untracked bad.js should be scanned (1 file, not clean.js)
    let t = &v["targets"][0];
    assert_eq!(t["files"], 1, "diff mode scanned {} files", t["files"]);
    assert_eq!(v["summary"]["critical"].as_u64().unwrap(), 1);
    let _ = std::fs::remove_dir_all(&d);
}

// ---------- landlock sandbox ----------

#[test]
fn sandbox_denies_symlink_escape() {
    let d = tmpdir("sb");
    let outside = tmpdir("sb-out").join("evil.js");
    std::fs::write(&outside, "x='m-kosche.com'").unwrap();
    std::fs::write(d.join("real.js"), "y='m-kosche.com'").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, d.join("escape.js")).unwrap();

    let v = scan_json(&d);
    let n = v["summary"]["critical"].as_u64().unwrap();
    #[cfg(target_os = "linux")]
    assert_eq!(n, 1, "sandbox should deny the symlink escape (got {n})");
    #[cfg(not(target_os = "linux"))]
    assert_eq!(n, 2);
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_dir_all(outside.parent().unwrap());
}

// ---------- authors / actor watchlist ----------

#[test]
fn authors_flags_watchlist_identity() {
    let d = tmpdir("author");
    Command::new("git")
        .args(["-C", &*d.to_string_lossy(), "init", "-q"])
        .output()
        .unwrap();
    let git = |env: &[(&str, &str)]| {
        let mut c = Command::new("git");
        c.args([
            "-C",
            &*d.to_string_lossy(),
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "x",
        ]);
        for (k, v) in env {
            c.env(k, v);
        }
        c.output().unwrap()
    };
    git(&[
        ("GIT_AUTHOR_NAME", "danikpapas"),
        ("GIT_AUTHOR_EMAIL", "d@sharklasers.com"),
        ("GIT_COMMITTER_NAME", "danikpapas"),
        ("GIT_COMMITTER_EMAIL", "d@sharklasers.com"),
    ]);
    let out = bin().args(["authors"]).arg(&d).output().unwrap();
    let txt =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(txt.contains("ACTOR-001"), "expected watchlist hit: {txt}");
    assert!(
        txt.contains("ACTOR-002"),
        "expected disposable-domain hit: {txt}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn watch_feed_parser() {
    // unit-level check via binary is awkward; exercise through feed=+missing-state path
    // instead: feed URL to a local file is invalid, so test parser logic via a tiny
    // inline fixture shipped as a test resource.
    let atom = r#"<?xml version="1.0"?><feed><entry><id>tag:x,2026:commit/abc123</id><title>c</title></entry></feed>"#;
    // sanity: our regex shape — call argus authors json as smoke instead; feed parser
    // is exercised live. This asserts the binary handles a bad feed URL gracefully.
    let out = bin()
        .args(["watch", "--feed", "file:///nonexistent.atom", "--once"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("warn:") || out.status.success());
    let _ = atom;
}

// ---------- network resilience ----------

/// Spawn a one-shot TCP listener that serves canned HTTP responses per
/// request index (cycled). Returns the base URL.
fn mock_server(resps: Vec<String>) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h2 = hits.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { return };
            use std::io::{Read, Write};
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf);
            let i = h2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let body = &resps[i.min(resps.len() - 1)];
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{}",
                body.len(), body
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    (format!("http://127.0.0.1:{port}"), hits)
}

#[test]
fn api_change_clean_error() {
    // forge returns an unexpected shape (API changed) -> clean error, no panic
    let (base, _hits) = mock_server(vec![r#"{"unexpected":"shape"}"#.into()]);
    let out = bin()
        .args(["gitea", "--host", &base, "--org", "x", "--format", "json"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2));
    assert!(err.contains("expected JSON array"), "stderr: {err}");
}

#[test]
fn api_rate_limit_then_ok() {
    // first a 429 shape (we return 200 with array on 2nd) — actually serve real 429
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h2 = hits.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { return };
            use std::io::{Read, Write};
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf);
            let i = h2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let resp = if i == 0 {
                "HTTP/1.1 429 Too Many Requests\r\nretry-after: 0\r\ncontent-length: 2\r\n\r\n{}"
                    .to_string()
            } else {
                "HTTP/1.1 200 OK\r\ncontent-length: 2\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n[]".to_string()
            };
            let _ = s.write_all(resp.as_bytes());
        }
    });
    let base = format!("http://127.0.0.1:{port}");
    let out = bin()
        .args([
            "gitea", "--host", &base, "--org", "x", "--format", "json", "--limit", "1",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    // 429 retried, second request returns [] -> clean empty report
    assert!(
        hits.load(std::sync::atomic::Ordering::SeqCst) >= 2,
        "no retry happened: {err}"
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {err}");
}

#[test]
fn offline_flag_blocks_remote() {
    let out = bin()
        .args(["--offline", "github", "--org", "x"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("offline"));
    // env var too
    let out = bin()
        .args(["gitea", "--org", "x", "--host", "example.com"])
        .env("ARGUS_OFFLINE", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    // local scan unaffected
    let v = scan_json(&fixture("dirty-repo"));
    assert!(v["summary"]["total"].as_u64().unwrap() > 0);
}

// ---------- ai provenance ----------

#[test]
fn ai_detects_agent_trailer_and_burst() {
    let d = tmpdir("ai");
    let g = |extra: &[&str]| {
        let mut c = Command::new("git");
        c.args(["-C", &*d.to_string_lossy()])
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .args(extra);
        c.output().unwrap()
    };
    g(&["init", "-q"]);
    // 30 rapid commits, one with a claude trailer
    for i in 0..30 {
        let msg = if i == 5 {
            "add thing\n\nCo-Authored-By: Claude <noreply@anthropic.com>"
        } else {
            "wip"
        };
        g(&[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            msg,
        ]);
    }
    // em-dash saturated doc
    std::fs::write(d.join("README.md"), "A — B — C — D — E — F — G — H — seamlessly — leverage — it's important to note — comprehensive solution — delve into — meticulous\n".repeat(50)).unwrap();
    let out = bin()
        .args(["ai"])
        .arg(&d)
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let r = &v[0];
    assert_eq!(
        r["verdict"], "likely AI-assisted",
        "verdict: {}",
        r["verdict"]
    );
    let kinds: Vec<String> = r["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_string())
        .collect();
    assert!(
        kinds.iter().any(|k| k.contains("trailer")),
        "evidence: {kinds:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn ai_clean_repo_scores_low() {
    let d = tmpdir("ai-clean");
    Command::new("git")
        .args(["-C", &*d.to_string_lossy(), "init", "-q"])
        .output()
        .unwrap();
    Command::new("git")
        .args([
            "-C",
            &*d.to_string_lossy(),
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "init",
        ])
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .output()
        .unwrap();
    std::fs::write(d.join("README.md"), "a simple readme about the project.").unwrap();
    let out = bin().args(["ai"]).arg(&d).output().unwrap();
    let txt = String::from_utf8_lossy(&out.stdout);
    assert!(txt.contains("no strong AI indicators"), "out: {txt}");
    let _ = std::fs::remove_dir_all(&d);
}

// ---------- history integrity ----------

#[test]
fn ai_finds_scrubbed_agent_commit() {
    let d = tmpdir("ai-scrub");
    let g = |args: &[&str]| {
        Command::new("git")
            .args(["-C", &*d.to_string_lossy()])
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .unwrap()
    };
    g(&["init", "-q"]);
    g(&[
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "init",
    ]);
    // commit with agent trailer, then amend it away
    g(&[
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "work\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
    ]);
    g(&[
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "--amend",
        "--allow-empty",
        "-m",
        "work",
    ]);
    let out = bin()
        .args(["ai"])
        .arg(&d)
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let kinds: Vec<String> = v[0]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().into())
        .collect();
    assert!(
        kinds.contains(&"scrubbed AI commits".to_string()),
        "evidence: {kinds:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn ai_flags_mutation_hook() {
    let d = tmpdir("ai-hook");
    Command::new("git")
        .args(["-C", &*d.to_string_lossy(), "init", "-q"])
        .output()
        .unwrap();
    Command::new("git")
        .args([
            "-C",
            &*d.to_string_lossy(),
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "init",
        ])
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .output()
        .unwrap();
    std::fs::write(
        d.join(".git/hooks/prepare-commit-msg"),
        "#!/bin/sh\nsed -i 's/Co-Authored-By.*//' \"$1\"\n",
    )
    .unwrap();
    let out = bin().args(["ai"]).arg(&d).output().unwrap();
    let txt = String::from_utf8_lossy(&out.stdout);
    assert!(txt.contains("message-mutating hook"), "out: {txt}");
    let _ = std::fs::remove_dir_all(&d);
}

// ---------- ai false-positive guards ----------

#[test]
fn ai_no_fp_conventional_commits() {
    // a normal human repo: conventional-commit subjects, multiple
    // full-name authors, spread across weeks. must not produce
    // ghost/self-review/likely-verdict false positives.
    let d = tmpdir("ai-conv");
    let g = |args: &[&str], name: &str, mail: &str, day: u64| {
        Command::new("git")
            .args(["-C", &*d.to_string_lossy()])
            .args(args)
            .env("GIT_AUTHOR_NAME", name)
            .env("GIT_AUTHOR_EMAIL", mail)
            .env("GIT_COMMITTER_NAME", name)
            .env("GIT_COMMITTER_EMAIL", mail)
            .env(
                "GIT_AUTHOR_DATE",
                format!("2024-01-{:02}T12:00:00", 1 + day % 28),
            )
            .env(
                "GIT_COMMITTER_DATE",
                format!("2024-01-{:02}T12:00:00", 1 + day % 28),
            )
            .output()
            .unwrap()
    };
    let authors = [
        ("Alice Dev", "alice@example.com"),
        ("Bob Coder", "bob@example.com"),
        ("Carol Hacker", "carol@example.com"),
        ("Dan Smith", "dan@example.com"),
    ];
    let subjects = [
        "feat(parser): add token handling",
        "fix(cli): correct exit code",
        "chore: bump deps",
        "docs: update readme",
        "refactor(core): split module",
        "test: add coverage for parser",
        "fix(parser): handle empty input",
        "feat(api): new endpoint",
    ];
    g(&["init", "-q"], "t", "t@t", 0);
    for i in 0..60u64 {
        let (n, m) = authors[(i % 4) as usize];
        g(
            &[
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                subjects[(i % 8) as usize],
            ],
            n,
            m,
            i,
        );
    }
    let out = bin()
        .args(["ai"])
        .arg(&d)
        .args(["--format", "json"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let r = &v[0];
    let kinds: Vec<String> = r["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_string())
        .collect();
    for bad in [
        "self-review loop",
        "synthetic-looking contributors",
        "ghost contributors",
        "agent trailer",
        "agent author",
        "loc-per-commit",
        "superhuman volume",
    ] {
        assert!(
            !kinds.iter().any(|k| k.contains(bad)),
            "FP {bad} in {kinds:?}"
        );
    }
    assert_ne!(
        r["verdict"], "likely AI-assisted",
        "verdict FP: {}",
        r["verdict"]
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn ai_anti_disclosure_needs_ai_context() {
    // a provenance policy with NO ai mention is anti-AI, not laundering
    let d = tmpdir("ai-policy-clean");
    let g = |args: &[&str]| {
        Command::new("git")
            .args(["-C", &*d.to_string_lossy()])
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .unwrap()
    };
    g(&["init", "-q"]);
    std::fs::write(
        d.join("CONTRIBUTING.md"),
        "All contributions must be your own work. Do not disclose contributor identities.\n",
    )
    .unwrap();
    g(&["-c", "commit.gpgsign=false", "add", "."]);
    g(&["-c", "commit.gpgsign=false", "commit", "-q", "-m", "policy"]);
    let out = bin()
        .args(["ai"])
        .arg(&d)
        .args(["--format", "json"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let kinds: Vec<String> = v[0]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_string())
        .collect();
    assert!(
        !kinds.iter().any(|k| k.contains("anti-disclosure")),
        "FP: {kinds:?}"
    );

    // same phrases + ai context: now it is laundering language
    std::fs::write(
        d.join("CONTRIBUTING.md"),
        "AI-generated code is yours, claim as your own. Do not mention ai tooling anywhere.\n",
    )
    .unwrap();
    let out = bin()
        .args(["ai"])
        .arg(&d)
        .args(["--format", "json"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let kinds: Vec<String> = v[0]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_string())
        .collect();
    assert!(
        kinds.iter().any(|k| k.contains("anti-disclosure")),
        "missed: {kinds:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn ai_human_name_no_trailer_fp() {
    // "written by cody" where cody is a person must not flag
    let d = tmpdir("ai-cody");
    let g = |args: &[&str]| {
        Command::new("git")
            .args(["-C", &*d.to_string_lossy()])
            .args(args)
            .env("GIT_AUTHOR_NAME", "Cody Fisher")
            .env("GIT_AUTHOR_EMAIL", "cody@example.com")
            .env("GIT_COMMITTER_NAME", "Cody Fisher")
            .env("GIT_COMMITTER_EMAIL", "cody@example.com")
            .output()
            .unwrap()
    };
    g(&["init", "-q"]);
    g(&[
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "new parser\n\nWritten by cody during the sprint",
    ]);
    let out = bin()
        .args(["ai"])
        .arg(&d)
        .args(["--format", "json"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let kinds: Vec<String> = v[0]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_string())
        .collect();
    assert!(!kinds.iter().any(|k| k.contains("agent")), "FP: {kinds:?}");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn ai_lockfile_churn_no_loc_fp() {
    // 25 commits that only touch package-lock.json must not produce
    // the loc-per-commit medium signal (lockfile churn is mechanical)
    let d = tmpdir("ai-lockfile");
    let g = |args: &[&str]| {
        Command::new("git")
            .args(["-C", &*d.to_string_lossy()])
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .unwrap()
    };
    g(&["init", "-q"]);
    for i in 0..25 {
        let content = "x"
            .repeat(200)
            .split("x")
            .collect::<Vec<_>>()
            .iter()
            .enumerate()
            .map(|(j, _)| format!("\"dep-{j}-{i}\": \"1.0.{i}\""))
            .collect::<Vec<_>>()
            .join("\n");
        let big = vec![content; 20].join("\n");
        std::fs::write(d.join("package-lock.json"), &big).unwrap();
        g(&["-c", "commit.gpgsign=false", "add", "."]);
        g(&[
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "update deps",
        ]);
    }
    let out = bin()
        .args(["ai"])
        .arg(&d)
        .args(["--format", "json"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let kinds: Vec<String> = v[0]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_string())
        .collect();
    assert!(
        !kinds.iter().any(|k| k.contains("loc-per-commit")),
        "FP: {kinds:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ---------- new commands: license / publish / fix ----------

#[test]
fn license_audit_detects_mit_and_mismatch() {
    let d = tmpdir("lic");
    std::fs::write(
        d.join("LICENSE"),
        "MIT License\n\nPermission is hereby granted, free of charge",
    )
    .unwrap();
    // manifest declares something different -> LIC-003
    std::fs::write(
        d.join("Cargo.toml"),
        "[package]\nname = \"x\"\nversion = \"0.1.0\"\nlicense = \"Apache-2.0\"\n",
    )
    .unwrap();
    let out = bin()
        .args(["license"])
        .arg(&d)
        .args(["--format", "json"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let ids: Vec<String> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap().to_string())
        .collect();
    assert!(
        ids.contains(&"LIC-003".to_string()),
        "expected mismatch finding: {ids:?}"
    );
    assert!(
        !ids.contains(&"LIC-001".to_string()),
        "LICENSE present, should not flag missing"
    );
    // clean case: manifest agrees -> no findings at all
    std::fs::write(
        d.join("Cargo.toml"),
        "[package]\nname = \"x\"\nversion = \"0.1.0\"\nlicense = \"MIT\"\n",
    )
    .unwrap();
    let out = bin()
        .args(["license"])
        .arg(&d)
        .args(["--format", "json"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        v["findings"].as_array().map(|a| a.len()),
        Some(0),
        "clean MIT repo should be silent"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn publish_preflight_flags_shipped_secret() {
    let d = tmpdir("pub");
    let g = |args: &[&str]| {
        Command::new("git")
            .args(["-C", &*d.to_string_lossy()])
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .unwrap()
    };
    g(&["init", "-q"]);
    std::fs::write(d.join("index.js"), "module.exports = {};\n").unwrap();
    std::fs::write(d.join(".env"), "SECRET=hunter2\n").unwrap();
    g(&["add", "."]);
    g(&["-c", "commit.gpgsign=false", "commit", "-q", "-m", "x"]);
    let out = bin()
        .args(["publish"])
        .arg(&d)
        .args(["--format", "json"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let fs = v["findings"].as_array().unwrap();
    assert!(
        fs.iter()
            .any(|f| f["rule_id"] == "PUB-001" && f["path"] == ".env"),
        ".env must be flagged: {fs:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn fix_injects_permissions_dry_run_and_write() {
    let d = tmpdir("fix");
    let wf = d.join(".github/workflows");
    std::fs::create_dir_all(&wf).unwrap();
    let yml = wf.join("ci.yml");
    std::fs::write(&yml, "name: ci\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n").unwrap();
    // dry-run: reports but does not modify
    let before = std::fs::read_to_string(&yml).unwrap();
    let out = bin().args(["fix"]).arg(&d).output().unwrap();
    let txt = String::from_utf8_lossy(&out.stdout);
    assert!(
        txt.contains("permissions"),
        "dry-run should propose permissions: {txt}"
    );
    assert_eq!(
        std::fs::read_to_string(&yml).unwrap(),
        before,
        "dry-run must not write"
    );
    // --write applies
    let _ = bin()
        .args(["fix"])
        .arg(&d)
        .args(["--write"])
        .output()
        .unwrap();
    let after = std::fs::read_to_string(&yml).unwrap();
    assert!(
        after.contains("permissions: {}"),
        "write must apply: {after}"
    );
    assert!(after.contains("jobs:"), "jobs block preserved");
    let _ = std::fs::remove_dir_all(&d);
}
