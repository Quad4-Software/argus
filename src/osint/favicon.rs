// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Favicon hash in the form Shodan and FOFA publish.
//! MurmurHash3 x86 32-bit over MIME base64 (a newline every 76 characters,
//! and one at the end). The result is a signed 32-bit integer.
//! This does not query Shodan. Paste the filter into a search box yourself.

use super::siteurl::fetch_public_bytes;
use super::{Hit, Report, Status};
use crate::codec;
use serde_json::json;
use std::time::Instant;

pub fn scan(raw: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    let url = favicon_url(raw.trim())?;
    let (status, bytes) = fetch_public_bytes(&url, 1024 * 1024)?;
    if status == 404 || bytes.is_empty() {
        return Ok(Report {
            target: raw.trim().to_string(),
            kind: "favicon",
            elapsed_ms: t0.elapsed().as_millis() as u64,
            findings: vec![Hit::new("favicon", Status::Absent, "no icon body", None)],
        });
    }
    if !(200..300).contains(&status) {
        return Err(format!("favicon HTTP {status}"));
    }
    let hash = shodan_hash(&bytes);
    Ok(Report {
        target: raw.trim().to_string(),
        kind: "favicon",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings: vec![Hit::new(
            "favicon",
            Status::Confirmed,
            format!("http.favicon.hash:{hash}"),
            Some(json!({
                "hash": hash,
                "shodan": format!("http.favicon.hash:{hash}"),
                "fofa": format!("icon_hash=\"{hash}\""),
                "bytes": bytes.len(),
                "url": url,
            })),
        )],
    })
}

pub fn shodan_hash(data: &[u8]) -> i32 {
    let wrapped = mime_b64(data);
    murmur3_32(wrapped.as_bytes(), 0) as i32
}

fn mime_b64(data: &[u8]) -> String {
    let raw = codec::encode_base64(data);
    let mut out = String::new();
    for (i, c) in raw.chars().enumerate() {
        if i > 0 && i % 76 == 0 {
            out.push('\n');
        }
        out.push(c);
    }
    out.push('\n');
    out
}

fn favicon_url(raw: &str) -> Result<String, String> {
    if raw.ends_with(".ico") || raw.ends_with(".png") || raw.ends_with(".svg") {
        return Ok(raw.to_string());
    }
    let base = raw.trim_end_matches('/');
    if base.starts_with("http://") || base.starts_with("https://") {
        Ok(format!("{base}/favicon.ico"))
    } else {
        Ok(format!("https://{base}/favicon.ico"))
    }
}

pub fn murmur3_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h1 = seed;
    let chunks = data.len() / 4;
    for i in 0..chunks {
        let k = u32::from_le_bytes(data[i * 4..i * 4 + 4].try_into().unwrap());
        let k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h1 ^= k;
        h1 = h1.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    let tail = &data[chunks * 4..];
    let mut k1 = 0u32;
    if tail.len() >= 3 {
        k1 ^= (tail[2] as u32) << 16;
    }
    if tail.len() >= 2 {
        k1 ^= (tail[1] as u32) << 8;
    }
    if !tail.is_empty() {
        k1 ^= tail[0] as u32;
        k1 = k1.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h1 ^= k1;
    }
    h1 ^= data.len() as u32;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85eb_ca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2_ae35);
    h1 ^= h1 >> 16;
    h1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foo_matches_the_published_mmh3_vector() {
        assert_eq!(murmur3_32(b"foo", 0) as i32, -156908512);
        assert_eq!(mime_b64(b"a"), "YQ==\n");
    }
}
