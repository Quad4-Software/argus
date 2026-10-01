// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Hash signatures and file heuristics.
//! The database is ClamAV daily.cvd hash rows (.hsb and .hdb) written to a
//! local list. Bytecode signatures are not executed. A hash hit is a known
//! file. A heuristic hit is a lead, not an identification.

use crate::osint::hash::{hex, md5};
use crate::osint::{Hit, Report, Status};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

const MAIN_URL: &str = "https://database.clamav.net/main.cvd";
const CVD_URL: &str = "https://database.clamav.net/daily.cvd";
const MAX_CVD: u64 = 250 * 1024 * 1024;
const MAX_FILES: usize = 20_000;

pub struct Hashed {
    pub sha256: String,
    pub md5: Option<String>,
}

pub fn scan(
    path: &Path,
    db: Option<&Path>,
    no_update: bool,
    max_age_hours: u64,
    offline: bool,
) -> Result<Report, String> {
    let t0 = Instant::now();
    let cache = cache_hashes();
    let mut findings = Vec::new();
    let db_path = if let Some(db) = db {
        if db.extension().is_some_and(|e| e == "cvd") {
            let out = cache.clone();
            let n = extract_hashes(db, &out, false)?;
            findings.push(Hit::new(
                "db",
                Status::Confirmed,
                format!("{n} hash signatures from {}", db.display()),
                None,
            ));
            out
        } else {
            db.to_path_buf()
        }
    } else if offline || no_update {
        cache
    } else {
        match ensure_db(&cache, max_age_hours) {
            Ok(note) => {
                findings.push(note);
                cache
            }
            Err(e) => {
                findings.push(Hit::new(
                    "db",
                    if cache.exists() {
                        Status::Inconclusive
                    } else {
                        Status::Absent
                    },
                    e,
                    None,
                ));
                cache
            }
        }
    };
    let files = collect(path);
    let mut wanted: HashMap<String, String> = HashMap::new();
    for (file, hashed, leads) in &files {
        wanted.insert(hashed.sha256.clone(), file.display().to_string());
        if let Some(md5) = &hashed.md5 {
            wanted.insert(md5.clone(), file.display().to_string());
        }
        findings.extend(leads.iter().cloned());
    }
    if db_path.exists() {
        let n = match_db(&db_path, &wanted, &mut findings)?;
        if !findings.iter().any(|h| h.module == "db") {
            findings.insert(
                0,
                Hit::new(
                    "db",
                    Status::Confirmed,
                    format!("{n} signatures compared"),
                    None,
                ),
            );
        }
    }
    if findings.iter().all(|h| h.module == "db") {
        findings.push(Hit::new(
            "signatures",
            Status::Absent,
            format!("{} file(s), no hash or heuristic lead", files.len()),
            None,
        ));
    }
    Ok(Report {
        target: path.display().to_string(),
        kind: "signatures",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

pub fn extract_hashes(cvd: &Path, out: &Path, append: bool) -> Result<u64, String> {
    let mut file = std::fs::File::open(cvd).map_err(|e| format!("open {}: {e}", cvd.display()))?;
    let mut header = [0u8; 512];
    file.read_exact(&mut header)
        .map_err(|e| format!("cvd header: {e}"))?;
    if !header.starts_with(b"ClamAV-VDB:") {
        return Err("not a ClamAV CVD".into());
    }
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let dest_path = if append {
        out.to_path_buf()
    } else {
        out.with_extension("tmp")
    };
    let mut dest = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append)
        .open(&dest_path)
        .map_err(|e| e.to_string())?;
    let mut dec = GzDecoder::new(file);
    let n = unpack_hashes(&mut dec, &mut dest)?;
    dest.flush().map_err(|e| e.to_string())?;
    if !append {
        std::fs::rename(&dest_path, out).map_err(|e| e.to_string())?;
    }
    Ok(n)
}

fn unpack_hashes(dec: &mut impl Read, dest: &mut impl Write) -> Result<u64, String> {
    let mut n = 0u64;
    loop {
        let mut hdr = [0u8; 512];
        if !read_full(dec, &mut hdr)? {
            break;
        }
        if hdr.iter().all(|b| *b == 0) {
            break;
        }
        let name = tar_name(&hdr);
        let size = tar_octal(&hdr[124..136]);
        let kind = hdr[156];
        let want =
            (kind == b'0' || kind == 0) && (name.ends_with(".hsb") || name.ends_with(".hdb"));
        if want {
            let mut left = size;
            let mut buf = Vec::new();
            while left > 0 {
                let chunk = left.min(64 * 1024) as usize;
                let mut block = vec![0u8; chunk];
                dec.read_exact(&mut block)
                    .map_err(|e| format!("cvd member: {e}"))?;
                buf.extend_from_slice(&block);
                left -= chunk as u64;
            }
            let text = String::from_utf8_lossy(&buf);
            for line in text.lines() {
                if let Some((hash, sig)) = split_sig(line) {
                    writeln!(dest, "{hash}\t{sig}").map_err(|e| e.to_string())?;
                    n += 1;
                }
            }
            skip_pad(dec, size)?;
        } else {
            skip_bytes(dec, size)?;
        }
    }
    Ok(n)
}

fn ensure_db(cache: &Path, max_age_hours: u64) -> Result<Hit, String> {
    if fresh(cache, max_age_hours) {
        return Ok(Hit::new(
            "db",
            Status::Confirmed,
            "cached hash database is still inside the refresh interval",
            None,
        ));
    }
    let dir = cache
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let main = dir.join("main.cvd");
    download(MAIN_URL, &main)?;
    let n_main = extract_hashes(&main, cache, false)?;
    let _ = std::fs::remove_file(&main);
    let daily = dir.join("daily.cvd");
    let daily_note = match download(CVD_URL, &daily) {
        Ok(()) => {
            let extracted = extract_hashes(&daily, cache, true);
            let _ = std::fs::remove_file(&daily);
            match extracted {
                Ok(n) => format!(", {n} from daily.cvd"),
                Err(e) => format!(", daily.cvd skipped: {e}"),
            }
        }
        Err(e) => format!(", daily.cvd skipped: {e}"),
    };
    Ok(Hit::new(
        "db",
        Status::Confirmed,
        format!("{n_main} hash signatures from main.cvd{daily_note}"),
        None,
    ))
}

fn download(url: &str, dest: &Path) -> Result<(), String> {
    let config = ureq::config::Config::builder()
        .timeout_global(Some(std::time::Duration::from_secs(180)))
        .http_status_as_error(false)
        .user_agent(concat!(
            "ClamAV/1.4.3 (argus/",
            env!("CARGO_PKG_VERSION"),
            ")"
        ))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut resp = agent.get(url).call().map_err(|e| format!("{url}: {e}"))?;
    let status = resp.status().as_u16();
    if status != 200 {
        return Err(format!("{url}: http {status}"));
    }
    let mut src = resp.body_mut().as_reader();
    let tmp = dest.with_extension("part");
    let mut file = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = src.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_CVD {
            let _ = std::fs::remove_file(&tmp);
            return Err("signature download exceeded 250 MiB".into());
        }
        file.write_all(&buf[..n]).map_err(|e| e.to_string())?;
    }
    file.flush().map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, dest).map_err(|e| e.to_string())?;
    Ok(())
}

fn match_db(
    path: &Path,
    wanted: &HashMap<String, String>,
    out: &mut Vec<Hit>,
) -> Result<u64, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let reader = std::io::BufReader::new(file);
    let mut n = 0u64;
    for line in std::io::BufRead::lines(reader) {
        let line = line.map_err(|e| e.to_string())?;
        n += 1;
        let Some((hash, name)) = line.split_once('\t') else {
            continue;
        };
        if let Some(file) = wanted.get(hash) {
            out.push(Hit::new(
                "hash",
                Status::Confirmed,
                format!("{file} matches {name}"),
                None,
            ));
        }
    }
    Ok(n)
}

fn collect(path: &Path) -> Vec<(PathBuf, Hashed, Vec<Hit>)> {
    let mut files = Vec::new();
    walk(path, &mut files);
    files
}

fn walk(path: &Path, out: &mut Vec<(PathBuf, Hashed, Vec<Hit>)>) {
    if out.len() >= MAX_FILES {
        return;
    }
    if path.is_dir() {
        let Ok(rd) = std::fs::read_dir(path) else {
            return;
        };
        for ent in rd.flatten() {
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if matches!(name.as_ref(), ".git" | "node_modules" | "target" | "vendor") {
                continue;
            }
            walk(&ent.path(), out);
        }
        return;
    }
    if let Some(row) = hash_file(path) {
        out.push(row);
    }
}

fn hash_file(path: &Path) -> Option<(PathBuf, Hashed, Vec<Hit>)> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut sha = Sha256::new();
    let mut md5_buf = Vec::new();
    let mut head = Vec::new();
    let mut tail = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        sha.update(&buf[..n]);
        if total < 32 * 1024 * 1024 {
            md5_buf.extend_from_slice(&buf[..n]);
        }
        if head.len() < 64 * 1024 {
            let take = (64 * 1024 - head.len()).min(n);
            head.extend_from_slice(&buf[..take]);
        }
        tail.clear();
        tail.extend_from_slice(&buf[..n.min(8192)]);
        total += n as u64;
    }
    let sha256 = hex(&sha.finalize());
    let md5 = if total <= 32 * 1024 * 1024 {
        Some(hex(&md5(&md5_buf)))
    } else {
        None
    };
    let leads = heuristics(path, &head, &tail);
    Some((path.to_path_buf(), Hashed { sha256, md5 }, leads))
}

pub fn heuristics(path: &Path, head: &[u8], tail: &[u8]) -> Vec<Hit> {
    let mut out = Vec::new();
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if double_extension(name) {
        out.push(Hit::new(
            "heuristic",
            Status::Confirmed,
            format!("{name} hides an executable extension"),
            None,
        ));
    }
    if head.windows(4).any(|w| w == b"UPX!")
        && (head.starts_with(b"MZ") || head.starts_with(b"\x7fELF"))
    {
        out.push(Hit::new(
            "heuristic",
            Status::Confirmed,
            format!("{} is packed with UPX", path.display()),
            None,
        ));
    }
    let image = head.starts_with(&[0xff, 0xd8]) || head.starts_with(b"\x89PNG");
    let script = tail.windows(5).any(|w| w == b"<?php") || tail.windows(7).any(|w| w == b"<script");
    if image && script {
        out.push(Hit::new(
            "heuristic",
            Status::Confirmed,
            format!("{} has a script after image bytes", path.display()),
            None,
        ));
    }
    if (head.starts_with(b"MZ") || head.starts_with(b"\x7fELF")) && entropy(head) > 7.5 {
        out.push(Hit::new(
            "heuristic",
            Status::Inconclusive,
            format!("{} is an executable with high entropy", path.display()),
            None,
        ));
    }
    out
}

pub fn double_extension(name: &str) -> bool {
    const DOC: &[&str] = &[
        "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "gif", "txt", "zip",
    ];
    const BAD: &[&str] = &[
        "exe", "scr", "js", "jse", "vbs", "vbe", "hta", "ps1", "bat", "cmd", "dll", "msi", "lnk",
    ];
    let mut parts = name.rsplit('.');
    let last = parts.next().unwrap_or("").to_ascii_lowercase();
    let prev = parts.next().unwrap_or("").to_ascii_lowercase();
    DOC.contains(&prev.as_str()) && BAD.contains(&last.as_str())
}

pub fn split_sig(line: &str) -> Option<(String, String)> {
    let mut parts = line.split(':');
    let hash = parts.next()?.trim().to_ascii_lowercase();
    if hash.len() != 32 && hash.len() != 64 {
        return None;
    }
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let _size = parts.next()?;
    let name = parts.next()?.trim();
    if name.is_empty() {
        return None;
    }
    Some((hash, name.to_string()))
}

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0;
    for v in counts {
        if v == 0 {
            continue;
        }
        let p = v as f64 / n;
        h -= p * p.log2();
    }
    h
}

fn cache_hashes() -> PathBuf {
    crate::cache::cache_dir().join("malware").join("hashes.txt")
}

fn fresh(path: &Path, hours: u64) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .map(|age| age.as_secs() < hours.saturating_mul(3600))
        .unwrap_or(false)
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> Result<bool, String> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) if off == 0 => return Ok(false),
            Ok(0) => return Err("truncated tar header".into()),
            Ok(n) => off += n,
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(true)
}

fn tar_name(hdr: &[u8]) -> String {
    let name = cstr(&hdr[..100]);
    let prefix = cstr(&hdr[345..500]);
    if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    }
}

fn cstr(buf: &[u8]) -> String {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

fn tar_octal(buf: &[u8]) -> u64 {
    let text = cstr(buf);
    u64::from_str_radix(text.trim(), 8).unwrap_or(0)
}

fn skip_bytes(r: &mut impl Read, size: u64) -> Result<(), String> {
    let padded = size.div_ceil(512) * 512;
    let mut left = padded;
    let mut buf = [0u8; 8192];
    while left > 0 {
        let n = left.min(buf.len() as u64) as usize;
        r.read_exact(&mut buf[..n])
            .map_err(|e| format!("skip cvd member: {e}"))?;
        left -= n as u64;
    }
    Ok(())
}

fn skip_pad(r: &mut impl Read, size: u64) -> Result<(), String> {
    let pad = (512 - (size % 512)) % 512;
    if pad == 0 {
        return Ok(());
    }
    let mut buf = vec![0u8; pad as usize];
    r.read_exact(&mut buf).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    #[test]
    fn cvd_extracts_sha256_names() {
        let hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let body = format!("{hash}:*:Test.Lead\n");
        let cvd = gzip_tar("daily.hsb", body.as_bytes());
        let dir = std::env::temp_dir().join(format!("argus-cvd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cvd_path = dir.join("daily.cvd");
        std::fs::write(&cvd_path, cvd).unwrap();
        let out = dir.join("hashes.txt");
        let n = extract_hashes(&cvd_path, &out, false).unwrap();
        assert_eq!(n, 1);
        std::fs::write(dir.join("hello.txt"), "hello").unwrap();
        let report = scan(&dir.join("hello.txt"), Some(&out), true, 24, true).unwrap();
        assert!(report.findings.iter().any(|h| h.module == "hash"));
        std::fs::write(dir.join("invoice.pdf.exe"), "MZ").unwrap();
        let leads = heuristics(&dir.join("invoice.pdf.exe"), b"MZ", b"");
        assert!(
            leads
                .iter()
                .any(|h| h.summary.contains("hides an executable"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn gzip_tar(name: &str, body: &[u8]) -> Vec<u8> {
        let mut raw = tar_header(name, body.len());
        raw.extend_from_slice(body);
        let pad = (512 - (body.len() % 512)) % 512;
        raw.extend(std::iter::repeat_n(0u8, pad));
        raw.extend(std::iter::repeat_n(0u8, 1024));
        let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
        enc.write_all(&raw).unwrap();
        let gz = enc.finish().unwrap();
        let mut cvd = b"ClamAV-VDB:0:1:1:1:0:0:argus:1".to_vec();
        cvd.resize(512, b' ');
        cvd.extend(gz);
        cvd
    }

    fn tar_header(name: &str, size: usize) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        put_octal(&mut h[100..108], 0o644);
        put_octal(&mut h[108..116], 0);
        put_octal(&mut h[116..124], 0);
        put_octal(&mut h[124..136], size as u64);
        put_octal(&mut h[136..148], 0);
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        for b in &mut h[148..156] {
            *b = b' ';
        }
        let sum: u32 = h.iter().map(|b| *b as u32).sum();
        let text = format!("{sum:06o}\0 ");
        h[148..156].copy_from_slice(text.as_bytes());
        h
    }

    fn put_octal(buf: &mut [u8], val: u64) {
        let s = format!("{val:o}");
        let pad = buf.len() - 1 - s.len();
        for b in &mut buf[..pad] {
            *b = b'0';
        }
        buf[pad..pad + s.len()].copy_from_slice(s.as_bytes());
        buf[buf.len() - 1] = 0;
    }
}
