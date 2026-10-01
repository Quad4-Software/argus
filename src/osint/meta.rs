// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Document metadata from the file itself.
//! PDF info strings, JPEG EXIF ASCII tags, PNG text chunks, and the
//! docx core.xml entry. Large image payloads are skipped with a seek.
//! This is not a full EXIF dump.

use super::{Hit, Report, Status};
use flate2::read::DeflateDecoder;
use serde_json::json;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;

pub fn scan(path: &Path) -> Result<Report, String> {
    let t0 = Instant::now();
    if !path.is_file() {
        return Err(format!("not a file: {}", path.display()));
    }
    let mut file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut head = [0u8; 16];
    let n = file.read(&mut head).unwrap_or(0);
    file.seek(SeekFrom::Start(0)).ok();
    let fields = if n >= 5 && &head[..5] == b"%PDF-" {
        pdf_fields(&mut file)
    } else if n >= 3 && head[0] == 0xff && head[1] == 0xd8 {
        jpeg_fields(&mut file)
    } else if n >= 8 && &head[..8] == b"\x89PNG\r\n\x1a\n" {
        png_fields(&mut file)
    } else if n >= 2 && &head[..2] == b"PK" {
        docx_fields(&mut file)
    } else {
        Vec::new()
    };
    let findings = if fields.is_empty() {
        vec![Hit::new(
            "meta",
            Status::Absent,
            "no author, creator, or title field in the header",
            None,
        )]
    } else {
        fields
            .into_iter()
            .map(|(k, v)| {
                Hit::new(
                    &k,
                    Status::Confirmed,
                    v.clone(),
                    Some(json!({ "field": k, "value": v })),
                )
            })
            .collect()
    };
    Ok(Report {
        target: path.display().to_string(),
        kind: "meta",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

fn pdf_fields(file: &mut File) -> Vec<(String, String)> {
    let buf = head_tail(file, 256 * 1024, 128 * 1024);
    let text = String::from_utf8_lossy(&buf);
    let mut out = Vec::new();
    for key in ["Author", "Creator", "Producer", "Title", "CreationDate"] {
        if let Some(val) = pdf_string(&text, key) {
            out.push((key.to_ascii_lowercase(), val));
        }
    }
    out
}

fn pdf_string(text: &str, key: &str) -> Option<String> {
    let marker = format!("/{key}");
    let at = text.find(&marker)?;
    let rest = text[at + marker.len()..].trim_start();
    let rest = rest.strip_prefix('(')?;
    let mut out = String::new();
    let mut esc = false;
    for c in rest.chars().take(300) {
        if esc {
            out.push(c);
            esc = false;
            continue;
        }
        if c == '\\' {
            esc = true;
            continue;
        }
        if c == ')' {
            break;
        }
        out.push(c);
    }
    let out = out.trim().to_string();
    if out.is_empty() { None } else { Some(out) }
}

fn jpeg_fields(file: &mut File) -> Vec<(String, String)> {
    let mut buf = vec![0u8; 2 * 1024 * 1024];
    let n = file.read(&mut buf).unwrap_or(0);
    let bytes = &buf[..n];
    let mut i = 2usize;
    let mut out = Vec::new();
    while i + 4 < bytes.len() {
        if bytes[i] != 0xff {
            break;
        }
        while i < bytes.len() && bytes[i] == 0xff {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let marker = bytes[i];
        i += 1;
        if marker == 0xda || marker == 0xd9 {
            break;
        }
        if i + 2 > bytes.len() {
            break;
        }
        let seglen = u16::from_be_bytes([bytes[i], bytes[i + 1]]) as usize;
        if seglen < 2 || i + seglen > bytes.len() {
            break;
        }
        let seg = &bytes[i + 2..i + seglen];
        if marker == 0xe1 && seg.starts_with(b"Exif\0\0") {
            out.extend(exif_ascii(&seg[6..]));
        }
        i += seglen;
    }
    out
}

fn exif_ascii(tiff: &[u8]) -> Vec<(String, String)> {
    if tiff.len() < 8 {
        return Vec::new();
    }
    let be = &tiff[..2] == b"MM";
    let le = &tiff[..2] == b"II";
    if !be && !le {
        return Vec::new();
    }
    let u16 = |o: usize| -> Option<u16> {
        let b = tiff.get(o..o + 2)?;
        Some(if be {
            u16::from_be_bytes([b[0], b[1]])
        } else {
            u16::from_le_bytes([b[0], b[1]])
        })
    };
    let u32 = |o: usize| -> Option<u32> {
        let b = tiff.get(o..o + 4)?;
        Some(if be {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        })
    };
    let ifd = u32(4).unwrap_or(0) as usize;
    let count = u16(ifd).unwrap_or(0) as usize;
    if count > 256 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for n in 0..count {
        let e = ifd + 2 + n * 12;
        let tag = u16(e).unwrap_or(0);
        let typ = u16(e + 2).unwrap_or(0);
        let nval = u32(e + 4).unwrap_or(0) as usize;
        let name = match tag {
            271 => "make",
            272 => "model",
            305 => "software",
            315 => "artist",
            33432 => "copyright",
            _ => continue,
        };
        if typ != 2 || nval == 0 || nval > 200 {
            continue;
        }
        let at = if nval <= 4 {
            e + 8
        } else {
            u32(e + 8).unwrap_or(0) as usize
        };
        if let Some(slice) = tiff.get(at..at + nval) {
            let text = String::from_utf8_lossy(slice)
                .trim_end_matches('\0')
                .trim()
                .to_string();
            if !text.is_empty() {
                out.push((name.to_string(), text));
            }
        }
    }
    out
}

fn png_fields(file: &mut File) -> Vec<(String, String)> {
    file.seek(SeekFrom::Start(8)).ok();
    let mut out = Vec::new();
    for _ in 0..64 {
        let mut hdr = [0u8; 8];
        if file.read_exact(&mut hdr).is_err() {
            break;
        }
        let len = u32::from_be_bytes(hdr[0..4].try_into().unwrap()) as u64;
        let kind = &hdr[4..8];
        if kind == b"tEXt" && len > 0 && len < 8192 {
            let mut body = vec![0u8; len as usize];
            if file.read_exact(&mut body).is_ok()
                && let Some(z) = body.iter().position(|b| *b == 0)
            {
                let key = String::from_utf8_lossy(&body[..z]).to_string();
                let val = String::from_utf8_lossy(&body[z + 1..]).trim().to_string();
                if !val.is_empty() {
                    out.push((key, val));
                }
            }
            let _ = file.seek(SeekFrom::Current(4));
        } else if kind == b"IEND" {
            break;
        } else {
            let _ = file.seek(SeekFrom::Current(len as i64 + 4));
        }
    }
    out
}

fn docx_fields(file: &mut File) -> Vec<(String, String)> {
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut pos = 0u64;
    while pos + 30 < len && pos < 32 * 1024 * 1024 {
        file.seek(SeekFrom::Start(pos)).ok();
        let mut hdr = [0u8; 30];
        if file.read_exact(&mut hdr).is_err() || &hdr[0..4] != b"PK\x03\x04" {
            break;
        }
        let method = u16::from_le_bytes([hdr[8], hdr[9]]);
        let comp = u32::from_le_bytes(hdr[18..22].try_into().unwrap()) as u64;
        let name_len = u16::from_le_bytes([hdr[26], hdr[27]]) as u64;
        let extra = u16::from_le_bytes([hdr[28], hdr[29]]) as u64;
        let mut name = vec![0u8; name_len as usize];
        if file.read_exact(&mut name).is_err() {
            break;
        }
        let _ = file.seek(SeekFrom::Current(extra as i64));
        let data_at = pos + 30 + name_len + extra;
        if name.ends_with(b"docProps/core.xml") && comp > 0 && comp < 256 * 1024 {
            file.seek(SeekFrom::Start(data_at)).ok();
            let mut comp_bytes = vec![0u8; comp as usize];
            if file.read_exact(&mut comp_bytes).is_ok() {
                let xml = if method == 0 {
                    String::from_utf8_lossy(&comp_bytes).into_owned()
                } else if method == 8 {
                    let dec = DeflateDecoder::new(comp_bytes.as_slice());
                    let mut xml = String::new();
                    dec.take(256 * 1024).read_to_string(&mut xml).ok();
                    xml
                } else {
                    String::new()
                };
                return core_xml(&xml);
            }
        }
        pos = data_at + comp;
    }
    Vec::new()
}

fn core_xml(xml: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (tag, label) in [
        ("dc:creator", "creator"),
        ("cp:lastModifiedBy", "modified_by"),
        ("dc:title", "title"),
        ("dc:subject", "subject"),
    ] {
        if let Some(val) = xml_text(xml, tag) {
            out.push((label.to_string(), val));
        }
    }
    out
}

fn xml_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let at = xml.find(&open)?;
    let rest = &xml[at + open.len()..];
    let gt = rest.find('>')?;
    if rest[..gt].ends_with('/') {
        return None;
    }
    let inner = &rest[gt + 1..];
    let close = format!("</{tag}>");
    let end = inner.find(&close)?;
    let val = inner[..end]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if val.is_empty() { None } else { Some(val) }
}

fn head_tail(file: &mut File, head: u64, tail: u64) -> Vec<u8> {
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut buf = vec![0u8; head.min(len) as usize];
    let n = file.read(&mut buf).unwrap_or(0);
    buf.truncate(n);
    if len > head + tail {
        let _ = file.seek(SeekFrom::End(-(tail as i64)));
        let mut rest = vec![0u8; tail as usize];
        let n = file.read(&mut rest).unwrap_or(0);
        buf.extend_from_slice(&rest[..n]);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdf_author_is_read_from_the_header() {
        let path = std::env::temp_dir().join(format!("argus-meta-{}.pdf", std::process::id()));
        std::fs::write(
            &path,
            b"%PDF-1.4\n1 0 obj << /Author (Ada Example) /Title (Notes) >>\n%%EOF\n",
        )
        .unwrap();
        let report = scan(&path).unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|h| h.module == "author" && h.summary == "Ada Example")
        );
        let _ = std::fs::remove_file(&path);
    }
}
