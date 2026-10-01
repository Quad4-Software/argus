// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Document metadata from the file itself.
//! PDF info and XMP, JPEG and WebP Exif, PNG text, GIF comments,
//! ID3 text frames, and docx core.xml. Large image bodies are skipped.

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
    let mut fields = if n >= 5 && &head[..5] == b"%PDF-" {
        pdf_fields(&mut file)
    } else if n >= 3 && head[0] == 0xff && head[1] == 0xd8 {
        jpeg_fields(&mut file)
    } else if n >= 8 && &head[..8] == b"\x89PNG\r\n\x1a\n" {
        png_fields(&mut file)
    } else if n >= 6 && (head[..6] == *b"GIF87a" || head[..6] == *b"GIF89a") {
        gif_fields(&mut file)
    } else if n >= 12 && &head[..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        webp_fields(&mut file)
    } else if n >= 3 && &head[..3] == b"ID3" {
        id3_fields(&mut file)
    } else if n >= 2 && &head[..2] == b"PK" {
        docx_fields(&mut file)
    } else {
        Vec::new()
    };
    file_stat(path, &mut fields);
    let document = fields.iter().any(|(k, _)| k != "size" && k != "mtime");
    let findings = if !document {
        let mut hits = vec![Hit::new(
            "meta",
            Status::Absent,
            "no author, title, comment, or date field in this file",
            None,
        )];
        hits.extend(fields.into_iter().map(|(k, v)| {
            Hit::new(
                &k,
                Status::Confirmed,
                v.clone(),
                Some(json!({ "field": k, "value": v })),
            )
        }));
        hits
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
    let mut out = xmp_fields(text.as_bytes());
    for key in [
        "Author",
        "Creator",
        "Producer",
        "Title",
        "Subject",
        "Keywords",
        "CreationDate",
        "ModDate",
    ] {
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
        } else if marker == 0xe1 && seg.starts_with(b"http://ns.adobe.com/xap/1.0/\0") {
            out.extend(xmp_fields(seg));
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
    let mut out = Vec::new();
    walk_ifd(
        tiff,
        u32(4).unwrap_or(0) as usize,
        false,
        &u16,
        &u32,
        &mut out,
        0,
    );
    out
}

fn walk_ifd(
    tiff: &[u8],
    ifd: usize,
    gps: bool,
    u16: &dyn Fn(usize) -> Option<u16>,
    u32: &dyn Fn(usize) -> Option<u32>,
    out: &mut Vec<(String, String)>,
    depth: u8,
) {
    if depth > 2 {
        return;
    }
    let count = u16(ifd).unwrap_or(0) as usize;
    if count > 256 {
        return;
    }
    for n in 0..count {
        let e = ifd + 2 + n * 12;
        let tag = u16(e).unwrap_or(0);
        let typ = u16(e + 2).unwrap_or(0);
        let nval = u32(e + 4).unwrap_or(0) as usize;
        if (tag == 34665 || tag == 34853) && typ == 4 {
            walk_ifd(
                tiff,
                u32(e + 8).unwrap_or(0) as usize,
                tag == 34853,
                u16,
                u32,
                out,
                depth + 1,
            );
            continue;
        }
        if gps && (tag == 2 || tag == 4) && typ == 5 {
            if let Some(text) = gps_dms(tiff, e, nval, u32) {
                out.push((
                    if tag == 2 {
                        "gps_latitude".into()
                    } else {
                        "gps_longitude".into()
                    },
                    text,
                ));
            }
            continue;
        }
        let name = match tag {
            270 => "description",
            271 => "make",
            272 => "model",
            305 => "software",
            306 => "datetime",
            315 => "artist",
            36867 => "datetime_original",
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
}

fn gps_dms(
    tiff: &[u8],
    entry: usize,
    count: usize,
    u32: &dyn Fn(usize) -> Option<u32>,
) -> Option<String> {
    if count != 3 {
        return None;
    }
    let be = tiff.starts_with(b"MM");
    let at = u32(entry + 8).unwrap_or(0) as usize;
    let mut parts = [0f64; 3];
    for (i, part) in parts.iter_mut().enumerate() {
        let o = at + i * 8;
        let b = tiff.get(o..o + 8)?;
        let (num, den) = if be {
            (
                u32::from_be_bytes(b[0..4].try_into().ok()?),
                u32::from_be_bytes(b[4..8].try_into().ok()?),
            )
        } else {
            (
                u32::from_le_bytes(b[0..4].try_into().ok()?),
                u32::from_le_bytes(b[4..8].try_into().ok()?),
            )
        };
        if den == 0 {
            return None;
        }
        *part = num as f64 / den as f64;
    }
    let decimal = parts[0] + parts[1] / 60.0 + parts[2] / 3600.0;
    Some(format!("{decimal:.5}"))
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
        if (kind == b"tEXt" || kind == b"zTXt" || kind == b"iTXt") && len > 0 && len < 64 * 1024 {
            let mut body = vec![0u8; len as usize];
            if file.read_exact(&mut body).is_ok()
                && let Some((key, val)) = png_text(kind, &body)
            {
                out.push((key, val));
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

fn png_text(kind: &[u8], body: &[u8]) -> Option<(String, String)> {
    let z = body.iter().position(|b| *b == 0)?;
    let key = String::from_utf8_lossy(&body[..z]).trim().to_string();
    if key.is_empty() {
        return None;
    }
    let rest = &body[z + 1..];
    let raw = if kind == b"tEXt" {
        rest.to_vec()
    } else if kind == b"zTXt" {
        inflate(rest.get(1..)?)?
    } else {
        let flag = *rest.first()?;
        let mut p = 2usize;
        p += rest.get(p..)?.iter().position(|b| *b == 0)? + 1;
        p += rest.get(p..)?.iter().position(|b| *b == 0)? + 1;
        let text = rest.get(p..)?;
        if flag == 1 {
            inflate(text)?
        } else {
            text.to_vec()
        }
    };
    let val = String::from_utf8_lossy(&raw).trim().to_string();
    if val.is_empty() {
        None
    } else {
        Some((key, val))
    }
}

fn inflate(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(data)
        .take(32 * 1024)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}

fn gif_fields(file: &mut File) -> Vec<(String, String)> {
    let mut buf = Vec::new();
    file.take(1024 * 1024).read_to_end(&mut buf).ok();
    if buf.len() < 13 {
        return Vec::new();
    }
    let mut i = 13usize;
    if buf[10] & 0x80 != 0 {
        let n = 3 * (1usize << ((buf[10] & 7) + 1));
        i = i.saturating_add(n);
    }
    let mut out = Vec::new();
    while i < buf.len() && out.len() < 8 {
        match buf[i] {
            0x3b => break,
            0x21 => {
                if i + 1 >= buf.len() {
                    break;
                }
                let label = buf[i + 1];
                i += 2;
                if label == 0xfe {
                    if let Some(text) = gif_subblocks(&buf, &mut i) {
                        let val = text.trim().to_string();
                        if !val.is_empty() {
                            out.push(("comment".into(), val));
                        }
                    }
                } else {
                    gif_subblocks(&buf, &mut i);
                }
            }
            0x2c => {
                if i + 10 >= buf.len() {
                    break;
                }
                let packed = buf[i + 9];
                i += 10;
                if packed & 0x80 != 0 {
                    let n = 3 * (1usize << ((packed & 7) + 1));
                    i = i.saturating_add(n);
                }
                if i >= buf.len() {
                    break;
                }
                i += 1;
                gif_subblocks(&buf, &mut i);
            }
            _ => break,
        }
    }
    out
}

fn gif_subblocks(buf: &[u8], i: &mut usize) -> Option<String> {
    let mut text = Vec::new();
    while *i < buf.len() && buf[*i] != 0 {
        let n = buf[*i] as usize;
        *i += 1;
        if *i + n > buf.len() {
            return None;
        }
        text.extend_from_slice(&buf[*i..*i + n]);
        *i += n;
    }
    if *i < buf.len() {
        *i += 1;
    }
    Some(String::from_utf8_lossy(&text).into_owned())
}

fn webp_fields(file: &mut File) -> Vec<(String, String)> {
    let mut buf = Vec::new();
    file.take(2 * 1024 * 1024).read_to_end(&mut buf).ok();
    if buf.len() < 12 || &buf[..4] != b"RIFF" || &buf[8..12] != b"WEBP" {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 12usize;
    while i + 8 <= buf.len() && out.len() < 16 {
        let kind = &buf[i..i + 4];
        let len = u32::from_le_bytes(buf[i + 4..i + 8].try_into().unwrap_or([0; 4])) as usize;
        let start = i + 8;
        let end = start.saturating_add(len).min(buf.len());
        let chunk = &buf[start..end];
        if kind == b"EXIF" {
            let tiff = chunk.strip_prefix(b"Exif\0\0").unwrap_or(chunk);
            out.extend(exif_ascii(tiff));
        } else if kind == b"XMP " {
            out.extend(xmp_fields(chunk));
        }
        i = end + (len % 2);
    }
    out
}

fn id3_fields(file: &mut File) -> Vec<(String, String)> {
    let mut buf = vec![0u8; 256 * 1024];
    let n = file.read(&mut buf).unwrap_or(0);
    let bytes = &buf[..n];
    if bytes.len() < 10 || &bytes[..3] != b"ID3" {
        return Vec::new();
    }
    let ver = bytes[3];
    let mut i = 10usize;
    let mut out = Vec::new();
    while i + 10 <= bytes.len() && out.len() < 12 {
        let id = &bytes[i..i + 4];
        if id.iter().all(|b| *b == 0) {
            break;
        }
        let size = if ver >= 4 {
            synchsafe(&bytes[i + 4..i + 8])
        } else {
            u32::from_be_bytes(bytes[i + 4..i + 8].try_into().unwrap_or([0; 4])) as usize
        };
        let start = i + 10;
        let end = start.saturating_add(size).min(bytes.len());
        let name = match id {
            b"TIT2" => "title",
            b"TPE1" => "artist",
            b"TALB" => "album",
            b"TYER" | b"TDRC" => "year",
            b"COMM" => "comment",
            _ => "",
        };
        if !name.is_empty()
            && let Some(text) = id3_text(&bytes[start..end])
        {
            out.push((name.to_string(), text));
        }
        if size == 0 {
            break;
        }
        i = end;
    }
    out
}

fn synchsafe(b: &[u8]) -> usize {
    if b.len() < 4 {
        return 0;
    }
    ((b[0] as usize & 0x7f) << 21)
        | ((b[1] as usize & 0x7f) << 14)
        | ((b[2] as usize & 0x7f) << 7)
        | (b[3] as usize & 0x7f)
}

fn id3_text(frame: &[u8]) -> Option<String> {
    let enc = *frame.first()?;
    let raw = &frame[1..];
    let text = match enc {
        0 | 3 => String::from_utf8_lossy(raw).into_owned(),
        1 if raw.len() >= 2 && raw[0] == 0xff && raw[1] == 0xfe => {
            let units: Vec<u16> = raw[2..]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|u| *u != 0)
                .collect();
            String::from_utf16_lossy(&units)
        }
        _ => return None,
    };
    let text = text.trim_matches('\0').trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn xmp_fields(bytes: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(bytes);
    if !text.contains("xmp") && !text.contains("dc:") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (tag, label) in [
        ("dc:creator", "creator"),
        ("dc:title", "title"),
        ("dc:description", "description"),
        ("xmp:CreatorTool", "creator_tool"),
        ("pdf:Producer", "producer"),
    ] {
        if let Some(val) = xml_text(&text, tag) {
            out.push((label.to_string(), val));
        }
    }
    out
}

fn file_stat(path: &Path, out: &mut Vec<(String, String)>) {
    let Ok(meta) = path.metadata() else {
        return;
    };
    out.push(("size".into(), meta.len().to_string()));
    if let Ok(modified) = meta.modified()
        && let Ok(dur) = modified.duration_since(std::time::UNIX_EPOCH)
    {
        out.push(("mtime".into(), dur.as_secs().to_string()));
    }
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
    let mut plain = String::new();
    let mut in_tag = false;
    for c in inner[..end].chars() {
        if c == '<' {
            in_tag = true;
            continue;
        }
        if c == '>' {
            in_tag = false;
            plain.push(' ');
            continue;
        }
        if !in_tag {
            plain.push(c);
        }
    }
    let val = plain.split_whitespace().collect::<Vec<_>>().join(" ");
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

    fn write_scan(name: &str, bytes: &[u8]) -> Report {
        let path = std::env::temp_dir().join(format!("argus-meta-{}-{}", std::process::id(), name));
        std::fs::write(&path, bytes).unwrap();
        let report = scan(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        report
    }

    fn has(report: &Report, module: &str, summary: &str) -> bool {
        report
            .findings
            .iter()
            .any(|h| h.module == module && h.summary == summary)
    }

    #[test]
    fn png_ztxt_gif_comment_webp_exif_and_id3_are_read() {
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        let mut payload = b"Comment\0".to_vec();
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        use std::io::Write;
        enc.write_all(b"hidden note").unwrap();
        payload.push(0);
        payload.extend(enc.finish().unwrap());
        png.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        png.extend_from_slice(b"zTXt");
        png.extend_from_slice(&payload);
        png.extend_from_slice(&[0, 0, 0, 0]);
        png.extend_from_slice(&0u32.to_be_bytes());
        png.extend_from_slice(b"IEND");
        png.extend_from_slice(&[0, 0, 0, 0]);
        assert!(has(&write_scan("a.png", &png), "Comment", "hidden note"));

        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&[1, 0, 1, 0, 0, 0, 0]);
        gif.extend_from_slice(&[0x21, 0xfe, 3, b'H', b'i', b'!', 0, 0x3b]);
        assert!(has(&write_scan("a.gif", &gif), "comment", "Hi!"));

        let tiff = tiny_exif_datetime();
        let mut webp = b"RIFF".to_vec();
        let mut body = b"WEBP".to_vec();
        body.extend_from_slice(b"EXIF");
        body.extend_from_slice(&(tiff.len() as u32).to_le_bytes());
        body.extend_from_slice(&tiff);
        webp.extend_from_slice(&(body.len() as u32).to_le_bytes());
        webp.extend_from_slice(&body);
        assert!(has(
            &write_scan("a.webp", &webp),
            "datetime",
            "2020:01:02 03:04:05"
        ));

        let mut id3 = b"ID3\x03\x00\x00".to_vec();
        let frame = b"\x03Title text";
        let mut frames = b"TIT2".to_vec();
        frames.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        frames.extend_from_slice(&[0, 0]);
        frames.extend_from_slice(frame);
        id3.extend_from_slice(&synchsafe_size(frames.len()));
        id3.extend_from_slice(&frames);
        assert!(has(&write_scan("a.mp3", &id3), "title", "Title text"));
    }

    fn synchsafe_size(n: usize) -> [u8; 4] {
        [
            ((n >> 21) & 0x7f) as u8,
            ((n >> 14) & 0x7f) as u8,
            ((n >> 7) & 0x7f) as u8,
            (n & 0x7f) as u8,
        ]
    }

    fn tiny_exif_datetime() -> Vec<u8> {
        let text = b"2020:01:02 03:04:05\0";
        let mut t = b"II*\0\x08\0\0\0".to_vec();
        t.extend_from_slice(&1u16.to_le_bytes());
        t.extend_from_slice(&306u16.to_le_bytes());
        t.extend_from_slice(&2u16.to_le_bytes());
        t.extend_from_slice(&(text.len() as u32).to_le_bytes());
        t.extend_from_slice(&26u32.to_le_bytes());
        t.extend_from_slice(&0u32.to_le_bytes());
        t.extend_from_slice(text);
        t
    }

    #[test]
    fn xmp_creator_is_read_from_a_pdf_packet() {
        let pdf = b"%PDF-1.4\n<dc:creator><rdf:li>Ada Example</rdf:li></dc:creator>\n%%EOF\n";
        assert!(has(&write_scan("x.pdf", pdf), "creator", "Ada Example"));
    }

    #[test]
    fn jpeg_gps_rationals_become_decimal_degrees() {
        let mut tiff = b"II*\0".to_vec();
        tiff.extend_from_slice(&8u32.to_le_bytes());
        tiff.extend_from_slice(&1u16.to_le_bytes());
        tiff.extend_from_slice(&34853u16.to_le_bytes());
        tiff.extend_from_slice(&4u16.to_le_bytes());
        tiff.extend_from_slice(&1u32.to_le_bytes());
        tiff.extend_from_slice(&26u32.to_le_bytes());
        tiff.extend_from_slice(&0u32.to_le_bytes());
        tiff.extend_from_slice(&1u16.to_le_bytes());
        tiff.extend_from_slice(&2u16.to_le_bytes());
        tiff.extend_from_slice(&5u16.to_le_bytes());
        tiff.extend_from_slice(&3u32.to_le_bytes());
        tiff.extend_from_slice(&44u32.to_le_bytes());
        tiff.extend_from_slice(&0u32.to_le_bytes());
        for (num, den) in [(1u32, 1u32), (30, 1), (0, 1)] {
            tiff.extend_from_slice(&num.to_le_bytes());
            tiff.extend_from_slice(&den.to_le_bytes());
        }
        let mut jpeg = vec![0xff, 0xd8, 0xff, 0xe1];
        let mut seg = b"Exif\0\0".to_vec();
        seg.extend_from_slice(&tiff);
        jpeg.extend_from_slice(&((seg.len() + 2) as u16).to_be_bytes());
        jpeg.extend_from_slice(&seg);
        jpeg.extend_from_slice(&[0xff, 0xd9]);
        assert!(has(
            &write_scan("gps.jpg", &jpeg),
            "gps_latitude",
            "1.50000"
        ));
    }
}
