// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! End-to-end tests for `argus cve`: --root fixture scan, external
//! banner fingerprinting against a local listener, and --list.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_argus"))
}

fn write(p: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

fn build_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!("argus-cve-root-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    write(
        &root.join("usr/sbin/nginx"),
        b"\x7fELF fake nginx version: nginx/1.30.0\nconfigure arguments: --with-http_v3_module --conf-path=/etc/nginx/nginx.conf\x00",
    );
    write(
        &root.join("etc/nginx/nginx.conf"),
        b"http {\n include /etc/nginx/conf.d/*.conf;\n}\n",
    );
    write(
        &root.join("etc/nginx/conf.d/app.conf"),
        b"server {\n location / {\n  rewrite ^/old/(.*)$ /new?path=$1;\n }\n}\n",
    );
    write(
        &root.join("usr/sbin/php-fpm8.3"),
        b"\x7fELF fake X-Powered-By: PHP/8.3.30\x00",
    );
    write(
        &root.join("etc/php/8.3/fpm/php.ini"),
        b"memory_limit = 256M\npost_max_size = 16M\n",
    );
    write(
        &root.join("var/lib/dpkg/status"),
        b"Package: nginx\nVersion: 1.30.0-1\nStatus: install ok installed\n\nPackage: php8.3-fpm\nVersion: 8.3.30-1\nStatus: install ok installed\n\n",
    );
    write(
        &root.join("var/lib/dpkg/info/nginx:amd64.list"),
        b"/usr/sbin/nginx\n/etc/nginx/nginx.conf\n",
    );
    write(
        &root.join("var/lib/dpkg/info/php8.3-fpm:amd64.list"),
        b"/usr/sbin/php-fpm8.3\n",
    );
    // nginx changelog names nothing; the php one backports the php2shell CVE
    write_gz(
        &root.join("usr/share/doc/php8.3-fpm/changelog.Debian.gz"),
        b"php8.3-fpm (8.3.30-1) stable; urgency=high\n\n  * backport fix for CVE-2026-109618\n",
    );
    write_gz(
        &root.join("usr/share/doc/nginx/changelog.Debian.gz"),
        b"nginx (1.30.0-1) stable; urgency=low\n\n  * routine rebuild\n",
    );
    write(
        &root.join("usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.1.0"),
        b"\x7fELF fake brotli",
    );
    std::os::unix::fs::symlink(
        "libbrotlidec.so.1.1.0",
        root.join("usr/lib/x86_64-linux-gnu/libbrotlidec.so.1"),
    )
    .unwrap();
    root
}

fn write_gz(p: &Path, data: &[u8]) {
    use flate2::write::GzEncoder;
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    let f = std::fs::File::create(p).unwrap();
    let mut gz = GzEncoder::new(f, flate2::Compression::fast());
    gz.write_all(data).unwrap();
    gz.finish().unwrap();
}

fn findings(v: &serde_json::Value) -> &Vec<serde_json::Value> {
    v["findings"].as_array().unwrap()
}

#[test]
fn local_root_scan_matches_and_backports() {
    let root = build_root();
    let run = || {
        let out = bin()
            .args(["cve", "--root"])
            .arg(&root)
            .args(["--format", "json", "--fail-on", "high"])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(1),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()
    };
    let v = run();
    let f = findings(&v);
    let by_id = |id: &str| f.iter().filter(|x| x["rule_id"] == id).collect::<Vec<_>>();

    let rift = by_id("CVE-2026-42945");
    assert_eq!(rift.len(), 1, "expected one Rift finding");
    assert_eq!(rift[0]["severity"], "critical");

    assert!(
        !by_id("CVE-2026-109619").is_empty(),
        "php2shell 109619 missing"
    );
    for x in by_id("CVE-2026-109618") {
        assert_eq!(x["severity"], "info", "109618 should be a backport info");
        assert!(x["message"].as_str().unwrap().contains("backport"));
    }
    assert!(
        !by_id("CVE-2026-111497").is_empty(),
        "brotli finding missing"
    );
    assert!(!by_id("CVE-INFO-003").is_empty(), "summary finding missing");

    // deterministic across runs
    let v2 = run();
    assert_eq!(findings(&v), findings(&v2));
    let _ = std::fs::remove_dir_all(&root);
}

fn serve(headers: &'static str) -> (u16, std::thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        for _ in 0..8 {
            match l.accept() {
                Ok((mut s, _)) => {
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf);
                    let body = "ok";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{}\r\n{}",
                        body.len(),
                        headers,
                        body
                    );
                    let _ = s.write_all(resp.as_bytes());
                }
                Err(_) => break,
            }
        }
    });
    (port, h)
}

#[test]
fn external_scan_fingerprints_banners() {
    // no --no-sandbox: exercises the Landlock net wiring (warns when the
    // kernel lacks the ABI)
    let (port, _h) =
        serve("Server: nginx/1.30.0\r\nX-Powered-By: PHP/8.3.30\r\nAlt-Svc: h3=\":8443\"\r\n");
    let out = bin()
        .args([
            "cve",
            &format!("127.0.0.1:{port}"),
            "--ports",
            &port.to_string(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ids: Vec<&str> = findings(&v)
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"CVE-2026-42945"), "got {ids:?}");
    assert!(ids.contains(&"CVE-2026-109618"), "got {ids:?}");

    let (port2, _h2) = serve("Server: nginx\r\n");
    let out2 = bin()
        .args([
            "cve",
            &format!("127.0.0.1:{port2}"),
            "--ports",
            &port2.to_string(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let v2: serde_json::Value = serde_json::from_slice(&out2.stdout).unwrap();
    let ids2: Vec<&str> = findings(&v2)
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap())
        .collect();
    assert!(ids2.contains(&"CVE-INFO-001"), "got {ids2:?}");
}

#[test]
fn list_prints_and_exits_zero() {
    let out = bin().args(["cve", "--list"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("CVE-2026-42945"));
    assert!(text.contains("product"));
}
