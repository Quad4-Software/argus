// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Structural steganography signals.
//! Appended bytes after a format end marker, odd container chunks, and
//! zero-width text channels. This does not extract a hidden message.

use crate::osint::{Hit, Report, Status};
use std::path::Path;
use std::time::Instant;

const SKIP: &[&str] = &[".git", "node_modules", "target", "vendor", "dist", ".argus"];
const MAX_FILES: usize = 400;
const MAX_BYTES: usize = 8 * 1024 * 1024;

pub fn scan(path: &Path) -> Result<Report, String> {
    let t0 = Instant::now();
    if !path.exists() {
        return Err(format!("path not found: {}", path.display()));
    }
    let mut hits = Vec::new();
    let mut files = 0usize;
    if path.is_file() {
        files = 1;
        consider(path, &mut hits);
    } else {
        walk(path, &mut hits, &mut files, 0);
    }
    if hits.is_empty() {
        hits.push(Hit::new(
            "stego",
            Status::Absent,
            format!("no appended payload or text channel in {files} file(s)"),
            None,
        ));
    }
    Ok(Report {
        target: path.display().to_string(),
        kind: "stego",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings: hits,
    })
}

pub(crate) fn inspect(name: &str, bytes: &[u8]) -> Vec<Hit> {
    let mut hits = Vec::new();
    if let Some(n) = png_trailing(bytes) {
        push(&mut hits, name, "png", n);
    }
    png_odd_chunks(name, bytes, &mut hits);
    if let Some(n) = jpeg_trailing(bytes) {
        push(&mut hits, name, "jpeg", n);
    }
    if let Some(n) = gif_trailing(bytes) {
        push(&mut hits, name, "gif", n);
    }
    if let Some(n) = bmp_trailing(bytes) {
        push(&mut hits, name, "bmp", n);
    }
    if let Some(n) = riff_trailing(bytes) {
        push(&mut hits, name, "riff", n);
    }
    if let Some(n) = pdf_trailing(bytes) {
        push(&mut hits, name, "pdf", n);
    }
    if let Some(n) = zip_trailing(bytes) {
        push(&mut hits, name, "zip", n);
    }
    if let Some(n) = zero_width(bytes) {
        hits.push(Hit::new(
            "text",
            Status::Confirmed,
            format!("{name}: {n} zero-width character(s)"),
            None,
        ));
    }
    hits
}

fn push(hits: &mut Vec<Hit>, name: &str, kind: &str, extra: usize) {
    hits.push(Hit::new(
        kind,
        Status::Confirmed,
        format!("{name}: {extra} byte(s) after the {kind} end marker"),
        None,
    ));
}

fn consider(path: &Path, hits: &mut Vec<Hit>) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if meta.len() as usize > MAX_BYTES || meta.len() == 0 {
        return;
    }
    let Ok(bytes) = std::fs::read(path) else {
        return;
    };
    let name = path.display().to_string();
    hits.extend(inspect(&name, &bytes));
}

fn walk(dir: &Path, hits: &mut Vec<Hit>, files: &mut usize, depth: usize) {
    if depth > 8 || *files >= MAX_FILES || hits.len() >= 40 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if *files >= MAX_FILES || hits.len() >= 40 {
            return;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if SKIP.iter().any(|s| name == *s) {
            continue;
        }
        if path.is_dir() {
            walk(&path, hits, files, depth + 1);
            continue;
        }
        *files += 1;
        consider(&path, hits);
    }
}

fn png_trailing(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 24 || &bytes[..8] != b"\x89PNG\r\n\x1a\n" {
        return None;
    }
    let mut i = 8usize;
    while i + 12 <= bytes.len() {
        let len = u32::from_be_bytes(bytes[i..i + 4].try_into().ok()?) as usize;
        let kind = &bytes[i + 4..i + 8];
        let next = i + 12 + len;
        if next > bytes.len() {
            return None;
        }
        if kind == b"IEND" {
            let extra = bytes.len() - next;
            return if extra > 0 { Some(extra) } else { None };
        }
        i = next;
    }
    None
}

fn png_odd_chunks(name: &str, bytes: &[u8], hits: &mut Vec<Hit>) {
    if bytes.len() < 8 || &bytes[..8] != b"\x89PNG\r\n\x1a\n" {
        return;
    }
    let known = [
        "IHDR", "PLTE", "IDAT", "IEND", "tRNS", "cHRM", "gAMA", "iCCP", "sBIT", "sRGB", "tEXt",
        "zTXt", "iTXt", "bKGD", "hIST", "pHYs", "sPLT", "tIME", "eXIf",
    ];
    let mut i = 8usize;
    while i + 12 <= bytes.len() {
        let len = u32::from_be_bytes(bytes[i..i + 4].try_into().unwrap_or([0; 4])) as usize;
        let kind = &bytes[i + 4..i + 8];
        let next = i.saturating_add(12).saturating_add(len);
        if next > bytes.len() {
            return;
        }
        let label = String::from_utf8_lossy(kind).to_string();
        if (label == "tEXt" || label == "zTXt" || label == "iTXt") && len > 256 {
            hits.push(Hit::new(
                "png",
                Status::Inconclusive,
                format!("{name}: PNG {label} chunk is {len} bytes"),
                None,
            ));
        } else if !known.contains(&label.as_str()) && label.chars().all(|c| c.is_ascii_alphabetic())
        {
            hits.push(Hit::new(
                "png",
                Status::Inconclusive,
                format!("{name}: unknown PNG chunk {label}"),
                None,
            ));
        }
        if kind == b"IEND" {
            return;
        }
        i = next;
    }
}

fn jpeg_trailing(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 4 || bytes[0] != 0xff || bytes[1] != 0xd8 {
        return None;
    }
    let mut i = 2usize;
    while i + 1 < bytes.len() {
        if bytes[i] != 0xff {
            i += 1;
            continue;
        }
        while i < bytes.len() && bytes[i] == 0xff {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
        let marker = bytes[i];
        i += 1;
        if marker == 0xd9 {
            let extra = bytes.len() - i;
            return if extra > 0 { Some(extra) } else { None };
        }
        if marker == 0xd8 || marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        if i + 2 > bytes.len() {
            return None;
        }
        let seglen = u16::from_be_bytes([bytes[i], bytes[i + 1]]) as usize;
        if seglen < 2 || i + seglen > bytes.len() {
            return None;
        }
        i += seglen;
    }
    None
}

fn gif_trailing(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 6 || (&bytes[..6] != b"GIF87a" && &bytes[..6] != b"GIF89a") {
        return None;
    }
    let last = bytes.iter().rposition(|b| *b == 0x3b)?;
    let extra = bytes.len() - last - 1;
    if extra > 16 { Some(extra) } else { None }
}

fn bmp_trailing(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 14 || &bytes[..2] != b"BM" {
        return None;
    }
    let declared = u32::from_le_bytes(bytes[2..6].try_into().ok()?) as usize;
    if declared > 14 && declared < bytes.len() {
        let extra = bytes.len() - declared;
        if extra > 16 { Some(extra) } else { None }
    } else {
        None
    }
}

fn riff_trailing(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 12 || &bytes[..4] != b"RIFF" {
        return None;
    }
    let declared = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
    let end = declared.saturating_add(8);
    if end > 12 && end < bytes.len() {
        let extra = bytes.len() - end;
        if extra > 16 { Some(extra) } else { None }
    } else {
        None
    }
}

fn pdf_trailing(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 8 || &bytes[..5] != b"%PDF-" {
        return None;
    }
    let window = bytes;
    let mut last = None;
    let mut i = 0;
    while i + 5 <= window.len() {
        if &window[i..i + 5] == b"%%EOF" {
            last = Some(i + 5);
        }
        i += 1;
    }
    let end = last?;
    let tail = &bytes[end..];
    let extra = tail.iter().filter(|b| !b.is_ascii_whitespace()).count();
    if extra > 32 { Some(extra) } else { None }
}

fn zip_trailing(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 22 || &bytes[..2] != b"PK" {
        return None;
    }
    let start = bytes.len().saturating_sub(22 + 65535);
    let mut eocd = None;
    let mut i = start;
    while i + 22 <= bytes.len() {
        if bytes[i] == 0x50 && bytes[i + 1] == 0x4b && bytes[i + 2] == 0x05 && bytes[i + 3] == 0x06
        {
            eocd = Some(i);
        }
        i += 1;
    }
    let eocd = eocd?;
    let comment = u16::from_le_bytes([bytes[eocd + 20], bytes[eocd + 21]]) as usize;
    let end = eocd + 22 + comment;
    if end < bytes.len() {
        let extra = bytes.len() - end;
        if extra > 0 { Some(extra) } else { None }
    } else {
        None
    }
}

fn zero_width(bytes: &[u8]) -> Option<usize> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return None;
    };
    let n = text
        .chars()
        .filter(|c| {
            matches!(
                *c,
                '\u{200b}'
                    | '\u{200c}'
                    | '\u{200d}'
                    | '\u{feff}'
                    | '\u{2060}'
                    | '\u{180e}'
                    | '\u{2062}'
                    | '\u{2063}'
                    | '\u{2064}'
            ) || ('\u{E0001}'..='\u{E007F}').contains(c)
        })
        .count();
    if n >= 6 { Some(n) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osint::Status;

    fn png(extra: &[u8]) -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend_from_slice(&13u32.to_be_bytes());
        v.extend_from_slice(b"IHDR");
        v.extend_from_slice(&[0; 13]);
        v.extend_from_slice(&[0; 4]);
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(b"IEND");
        v.extend_from_slice(&[0; 4]);
        v.extend_from_slice(extra);
        v
    }

    #[test]
    fn trailing_bytes_and_zero_width_are_named() {
        assert!(inspect("clean.png", &png(b"")).is_empty());
        let hit = &inspect("hid.png", &png(b"HIDDEN"))[0];
        assert_eq!(hit.status, Status::Confirmed);
        assert!(hit.summary.contains("6 byte"));
        let jpeg = [0xff, 0xd8, 0xff, 0xd9, b'H', b'I'];
        assert!(inspect("a.jpg", &jpeg)[0].summary.contains("jpeg"));
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&[0x3b]);
        gif.extend(std::iter::repeat(b'Z').take(20));
        assert!(inspect("a.gif", &gif)[0].summary.contains("gif"));
        let text = format!("hello{}world", "\u{200b}".repeat(6));
        assert!(
            inspect("note.txt", text.as_bytes())[0]
                .summary
                .contains("zero-width")
        );
    }
}
