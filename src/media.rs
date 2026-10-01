// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Provenance markers in local images, audio, and video.
//! A hit means the file declares a tool or a content-credentials block.
//! Pixels, samples, and a square canvas are not treated as proof.
//! The signature on a C2PA manifest is not validated here.

use crate::osint::{Hit, Report, Status};
use serde_json::json;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;

const HEAD: u64 = 1024 * 1024;
const TAIL: u64 = 256 * 1024;
const FILES: usize = 400;
const KEEP: usize = 40;

const GENERATORS: &[(&[u8], &str)] = &[
    (b"midjourney", "Midjourney"),
    (b"stable diffusion", "Stable Diffusion"),
    (b"novelai", "NovelAI"),
    (b"dall-e", "DALL-E"),
    (b"adobe firefly", "Adobe Firefly"),
    (b"comfyui", "ComfyUI"),
    (b"automatic1111", "Automatic1111"),
    (b"leonardo.ai", "Leonardo"),
    (b"elevenlabs", "ElevenLabs"),
    (b"suno.ai", "Suno"),
];

const CANVAS: &[(u32, u32)] = &[
    (512, 512),
    (768, 768),
    (1024, 1024),
    (1024, 1536),
    (1536, 1024),
    (1024, 1792),
    (1792, 1024),
];

pub fn scan(path: &Path) -> Result<Report, String> {
    let t0 = Instant::now();
    let mut files = 0usize;
    let mut hits = Vec::new();
    if path.is_file() {
        files = 1;
        hits.extend(file_hits(path)?);
    } else if path.is_dir() {
        walk(path, &mut files, &mut hits)?;
    } else {
        return Err(format!("path not found: {}", path.display()));
    }
    if hits.is_empty() {
        let summary = if files == 0 {
            "no image, audio, or video files"
        } else {
            "no embedded provenance marker in the scanned windows"
        };
        hits.push(Hit::new(
            "provenance",
            if files == 0 {
                Status::Inconclusive
            } else {
                Status::Absent
            },
            summary,
            Some(json!({"files": files})),
        ));
    }
    Ok(Report {
        target: path.display().to_string(),
        kind: "media",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings: hits,
    })
}

fn walk(dir: &Path, files: &mut usize, hits: &mut Vec<Hit>) -> Result<(), String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        if hits.len() >= KEEP || *files >= FILES {
            return Ok(());
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".git" || name == "node_modules" || name == "target" || name == "vendor" {
            continue;
        }
        if path.is_dir() {
            walk(&path, files, hits)?;
            continue;
        }
        if !is_media(&path) {
            continue;
        }
        *files += 1;
        hits.extend(file_hits(&path)?);
    }
    Ok(())
}

fn file_hits(path: &Path) -> Result<Vec<Hit>, String> {
    let (head, tail) = read_edges(path)?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let found = markers_in(&head, &tail, &ext);
    Ok(found
        .into_iter()
        .take(4)
        .map(|detail| {
            Hit::new(
                "provenance",
                Status::Confirmed,
                format!("{}: {detail}", path.display()),
                Some(json!({"path": path.display().to_string(), "detail": detail})),
            )
        })
        .collect())
}

fn read_edges(path: &Path) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let len = file
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?
        .len();
    if len <= HEAD {
        let mut buf = Vec::new();
        file.take(HEAD)
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        return Ok((buf, Vec::new()));
    }
    let mut head = vec![0u8; HEAD as usize];
    file.read_exact(&mut head).map_err(|e| e.to_string())?;
    let tail_len = TAIL.min(len - HEAD) as usize;
    file.seek(SeekFrom::End(-(tail_len as i64)))
        .map_err(|e| e.to_string())?;
    let mut tail = vec![0u8; tail_len];
    file.read_exact(&mut tail).map_err(|e| e.to_string())?;
    Ok((head, tail))
}

pub(crate) fn markers_in(head: &[u8], tail: &[u8], ext: &str) -> Vec<String> {
    let mut out = Vec::new();
    if head.starts_with(&[0xFF, 0xD8]) {
        jpeg(head, &mut out);
    } else if head.starts_with(b"\x89PNG\r\n\x1a\n") {
        png(head, &mut out);
    } else if is_container(head, ext) {
        edges(head, "head", &mut out);
        if !tail.is_empty() {
            edges(tail, "tail", &mut out);
        }
        boxes(head, &mut out);
    }
    if !tail.is_empty()
        && (head.starts_with(&[0xFF, 0xD8]) || head.starts_with(b"\x89PNG\r\n\x1a\n"))
    {
        phrases(tail, "tail", &mut out);
    }
    out.sort();
    out.dedup();
    out
}

fn is_container(head: &[u8], ext: &str) -> bool {
    matches!(
        ext,
        "mp4"
            | "mov"
            | "m4a"
            | "m4v"
            | "webm"
            | "mkv"
            | "avi"
            | "mp3"
            | "wav"
            | "flac"
            | "ogg"
            | "aac"
            | "webp"
            | "gif"
    ) || head.get(4..8) == Some(b"ftyp")
        || head.starts_with(b"RIFF")
        || head.starts_with(b"ID3")
        || head.starts_with(b"OggS")
        || head.starts_with(b"fLaC")
}

fn jpeg(bytes: &[u8], out: &mut Vec<String>) {
    let mut i = 2usize;
    let mut size = None;
    while i + 4 < bytes.len() {
        if bytes[i] != 0xFF {
            break;
        }
        while i < bytes.len() && bytes[i] == 0xFF {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let marker = bytes[i];
        i += 1;
        if marker == 0xD8 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            continue;
        }
        if marker == 0xDA || marker == 0xD9 {
            break;
        }
        if i + 2 > bytes.len() {
            break;
        }
        let seglen = u16::from_be_bytes([bytes[i], bytes[i + 1]]) as usize;
        if seglen < 2 || i + seglen > bytes.len() {
            break;
        }
        let payload = &bytes[i + 2..i + seglen];
        if marker == 0xEB && (has(payload, b"c2pa") || has(payload, b"jumb")) {
            out.push(note("C2PA APP11 marker", size));
        }
        if matches!(marker, 0xE0 | 0xE1 | 0xED) {
            phrases(payload, "JPEG metadata", out);
        }
        if matches!(marker, 0xC0 | 0xC1 | 0xC2) && payload.len() >= 7 && size.is_none() {
            let h = u16::from_be_bytes([payload[1], payload[2]]) as u32;
            let w = u16::from_be_bytes([payload[3], payload[4]]) as u32;
            size = Some((w, h));
        }
        i += seglen;
    }
    if let Some((w, h)) = size {
        annotate(out, w, h);
    }
}

fn png(bytes: &[u8], out: &mut Vec<String>) {
    let mut i = 8usize;
    let mut size = None;
    while i + 12 <= bytes.len() {
        let n = u32::from_be_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
        let typ = &bytes[i + 4..i + 8];
        let data_at = i + 8;
        let data_end = data_at.saturating_add(n).min(bytes.len());
        let data = &bytes[data_at..data_end];
        if typ == b"IHDR" && data.len() >= 8 && size.is_none() {
            let w = u32::from_be_bytes(data[0..4].try_into().unwrap());
            let h = u32::from_be_bytes(data[4..8].try_into().unwrap());
            size = Some((w, h));
        }
        if typ == b"caBX" {
            out.push(note("C2PA caBX chunk", size));
            phrases(data, "PNG caBX", out);
        }
        if typ == b"tEXt" || typ == b"iTXt" || typ == b"zTXt" {
            phrases(data, "PNG text", out);
        }
        if typ == b"IEND" {
            break;
        }
        let step = 12usize.saturating_add(n);
        if step == 0 || i + step <= i {
            break;
        }
        i += step;
    }
    if let Some((w, h)) = size {
        annotate(out, w, h);
    }
}

fn boxes(bytes: &[u8], out: &mut Vec<String>) {
    let mut i = 0usize;
    let mut depth = 0u8;
    walk_box(bytes, &mut i, bytes.len(), &mut depth, out);
}

fn walk_box(bytes: &[u8], i: &mut usize, end: usize, depth: &mut u8, out: &mut Vec<String>) {
    if *depth > 6 {
        return;
    }
    while *i + 8 <= end && *i + 8 <= bytes.len() {
        let size32 = u32::from_be_bytes(bytes[*i..*i + 4].try_into().unwrap()) as u64;
        let typ = &bytes[*i + 4..*i + 8];
        let header = 8usize;
        let size = if size32 == 1 && *i + 16 <= bytes.len() {
            u64::from_be_bytes(bytes[*i + 8..*i + 16].try_into().unwrap())
        } else if size32 == 0 {
            (end - *i) as u64
        } else {
            size32
        };
        if size < header as u64 {
            break;
        }
        let box_end = (*i as u64).saturating_add(size).min(end as u64) as usize;
        let payload_at = if size32 == 1 { *i + 16 } else { *i + 8 };
        if typ == b"c2pa"
            || (typ == b"uuid" && has(&bytes[payload_at..box_end.min(payload_at + 4096)], b"c2pa"))
        {
            out.push("C2PA box in ISO media".into());
        }
        if matches!(typ, b"moov" | b"udta" | b"meta" | b"ilst" | b"traf") && payload_at < box_end {
            *depth += 1;
            let mut child = payload_at;
            walk_box(bytes, &mut child, box_end, depth, out);
            *depth -= 1;
        }
        if box_end <= *i {
            break;
        }
        *i = box_end;
    }
}

fn edges(region: &[u8], where_: &str, out: &mut Vec<String>) {
    let n = region.len().min(64 * 1024);
    phrases(&region[..n], where_, out);
    if has(&region[..n], b"c2pa")
        && (has(&region[..n], b"jumb") || has(&region[..n], b"claim_generator"))
    {
        out.push(format!("C2PA text in {where_}"));
    }
}

fn phrases(region: &[u8], where_: &str, out: &mut Vec<String>) {
    if has(region, b"compositeWithTrainedAlgorithmicMedia") {
        out.push(format!(
            "IPTC compositeWithTrainedAlgorithmicMedia in {where_}"
        ));
    } else if has(region, b"trainedAlgorithmicMedia") {
        out.push(format!("IPTC trainedAlgorithmicMedia in {where_}"));
    }
    for (needle, name) in GENERATORS {
        if has(region, needle) {
            out.push(format!("generator tag {name} in {where_}"));
        }
    }
}

fn annotate(out: &mut [String], w: u32, h: u32) {
    if !CANVAS.contains(&(w, h)) {
        return;
    }
    for line in out {
        if !line.contains("canvas") {
            line.push_str(&format!(". canvas {w}x{h} is a common generator size"));
        }
    }
}

fn note(what: &str, size: Option<(u32, u32)>) -> String {
    match size {
        Some((w, h)) if CANVAS.contains(&(w, h)) => {
            format!("{what}. canvas {w}x{h} is a common generator size")
        }
        _ => what.to_string(),
    }
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && hay
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
}

fn is_media(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str(),
        "jpg"
            | "jpeg"
            | "png"
            | "webp"
            | "gif"
            | "mp3"
            | "wav"
            | "flac"
            | "ogg"
            | "m4a"
            | "aac"
            | "mp4"
            | "mov"
            | "webm"
            | "mkv"
            | "avi"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jpeg_app11_and_png_cabx_are_markers() {
        let jpeg = [
            0xFF, 0xD8, 0xFF, 0xEB, 0x00, 0x0B, b'c', b'2', b'p', b'a', b'-', b't', b'e', b's',
            b't', 0xFF, 0xD9,
        ];
        let marks = markers_in(&jpeg, &[], "jpg");
        assert!(marks.iter().any(|m| m.contains("APP11")), "{marks:?}");

        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend(png_chunk(b"IHDR", &[0, 0, 4, 0, 0, 0, 4, 0, 8, 2, 0, 0, 0]));
        png.extend(png_chunk(b"caBX", b"c2pa manifest"));
        png.extend(png_chunk(b"IEND", b""));
        let marks = markers_in(&png, &[], "png");
        assert!(marks.iter().any(|m| m.contains("caBX")), "{marks:?}");
    }

    #[test]
    fn a_plain_jpeg_has_no_marker() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xD9];
        assert!(markers_in(&jpeg, &[], "jpg").is_empty());
    }

    #[test]
    fn iptc_phrase_is_read_from_an_app_segment() {
        let mut seg = b"trainedAlgorithmicMedia".to_vec();
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE1];
        let seglen = (seg.len() + 2) as u16;
        jpeg.extend(seglen.to_be_bytes());
        jpeg.append(&mut seg);
        jpeg.extend([0xFF, 0xD9]);
        let marks = markers_in(&jpeg, &[], "jpg");
        assert!(
            marks.iter().any(|m| m.contains("trainedAlgorithmicMedia")),
            "{marks:?}"
        );
    }

    fn png_chunk(typ: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut v = (data.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(typ);
        v.extend_from_slice(data);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v
    }
}
