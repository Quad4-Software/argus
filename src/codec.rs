// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! RFC 4648 base64 and base32. The result is printed. It is not executed.

use crate::osint::{Hit, Report, Status};
use std::time::Instant;

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn scan(mode: &str, alphabet: &str, text: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    if text.len() > 1024 * 1024 {
        return Err("input is larger than 1 MiB".into());
    }
    let alpha = match alphabet.to_ascii_lowercase().as_str() {
        "base64" | "b64" => 64,
        "base32" | "b32" => 32,
        _ => return Err("alphabet must be base64 or base32".into()),
    };
    let summary = match mode.to_ascii_lowercase().as_str() {
        "encode" | "e" => {
            let raw = text.as_bytes();
            if alpha == 64 {
                encode64(raw)
            } else {
                encode32(raw)
            }
        }
        "decode" | "d" => {
            let bytes = if alpha == 64 {
                decode64(text)?
            } else {
                decode32(text)?
            };
            match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(e) => {
                    let bytes = e.into_bytes();
                    format!(
                        "{} byte(s), not utf-8, hex {}",
                        bytes.len(),
                        hex_prefix(&bytes)
                    )
                }
            }
        }
        _ => return Err("mode must be encode or decode".into()),
    };
    Ok(Report {
        target: alphabet.to_string(),
        kind: "codec",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings: vec![Hit::new(mode, Status::Confirmed, summary, None)],
    })
}

fn hex_prefix(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let n = bytes.len().min(32);
    let mut out = String::with_capacity(n * 2);
    for b in &bytes[..n] {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

pub(crate) fn encode_base64(data: &[u8]) -> String {
    encode64(data)
}

fn encode64(data: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | data[i + 2] as u32;
        push4(&mut out, B64, n, 4);
        i += 3;
    }
    let rest = data.len() - i;
    if rest == 1 {
        let n = (data[i] as u32) << 16;
        push4(&mut out, B64, n, 2);
        out.push('=');
        out.push('=');
    } else if rest == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        push4(&mut out, B64, n, 3);
        out.push('=');
    }
    out
}

fn encode32(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buf: u64 = 0;
    let mut bits = 0;
    for b in data {
        buf = (buf << 8) | *b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 31) as usize;
            out.push(B32[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 31) as usize;
        out.push(B32[idx] as char);
    }
    while out.len() % 8 != 0 {
        out.push('=');
    }
    out
}

fn push4(out: &mut String, alpha: &[u8], n: u32, count: usize) {
    let chars = [
        alpha[((n >> 18) & 63) as usize] as char,
        alpha[((n >> 12) & 63) as usize] as char,
        alpha[((n >> 6) & 63) as usize] as char,
        alpha[(n & 63) as usize] as char,
    ];
    for c in chars.into_iter().take(count) {
        out.push(c);
    }
}

fn decode64(text: &str) -> Result<Vec<u8>, String> {
    let clean = strip_ws(text);
    if clean.is_empty() {
        return Err("empty input".into());
    }
    if clean.len() % 4 != 0 {
        return Err("base64 length is not a multiple of 4".into());
    }
    let mut out = Vec::new();
    let bytes = clean.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let (a, b, c, d) = (
            val64(bytes[i])?,
            val64(bytes[i + 1])?,
            if bytes[i + 2] == b'=' {
                0
            } else {
                val64(bytes[i + 2])?
            },
            if bytes[i + 3] == b'=' {
                0
            } else {
                val64(bytes[i + 3])?
            },
        );
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push((n >> 16) as u8);
        if bytes[i + 2] != b'=' {
            out.push((n >> 8) as u8);
        }
        if bytes[i + 3] != b'=' {
            out.push(n as u8);
        }
        i += 4;
    }
    Ok(out)
}

fn decode32(text: &str) -> Result<Vec<u8>, String> {
    let clean = strip_ws(text).trim_end_matches('=').to_string();
    if clean.is_empty() {
        return Err("empty input".into());
    }
    let mut out = Vec::new();
    let mut buf: u64 = 0;
    let mut bits = 0;
    for c in clean.bytes() {
        let v = val32(c)?;
        buf = (buf << 5) | v as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn strip_ws(text: &str) -> String {
    text.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}

fn val64(c: u8) -> Result<u32, String> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return Err("invalid base64 character".into()),
    };
    Ok(v as u32)
}

fn val32(c: u8) -> Result<u32, String> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a',
        b'2'..=b'7' => c - b'2' + 26,
        _ => return Err("invalid base32 character".into()),
    };
    Ok(v as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors_roundtrip() {
        assert_eq!(encode64(b"foobar"), "Zm9vYmFy");
        assert_eq!(decode64("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(encode32(b"foobar"), "MZXW6YTBOI======");
        assert_eq!(decode32("MZXW6YTBOI======").unwrap(), b"foobar");
        let report = scan("decode", "base64", "aGVsbG8=").unwrap();
        assert_eq!(report.findings[0].summary, "hello");
    }
}
