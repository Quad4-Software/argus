// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Pairwise style distance for prose and source code.
//! Prose uses English closed-class word rates (cosine and mean absolute
//! difference) plus character trigrams. Code adds layout ratios.
//! There is no reference corpus here, so this is not a calibrated
//! percentile and not an imposter score. The result is a lead, not an
//! identification. Short samples and a genre mismatch dominate the error.

use crate::osint::{Hit, Report, Status};
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

const FUNCTION_WORDS: &[&str] = &[
    "a",
    "about",
    "above",
    "after",
    "again",
    "against",
    "all",
    "am",
    "an",
    "and",
    "any",
    "are",
    "as",
    "at",
    "be",
    "because",
    "been",
    "before",
    "being",
    "below",
    "between",
    "both",
    "but",
    "by",
    "can",
    "could",
    "did",
    "do",
    "does",
    "doing",
    "down",
    "during",
    "each",
    "few",
    "for",
    "from",
    "further",
    "had",
    "has",
    "have",
    "having",
    "he",
    "her",
    "here",
    "hers",
    "herself",
    "him",
    "himself",
    "his",
    "how",
    "i",
    "if",
    "in",
    "into",
    "is",
    "it",
    "its",
    "itself",
    "just",
    "me",
    "more",
    "most",
    "my",
    "myself",
    "no",
    "nor",
    "not",
    "now",
    "of",
    "off",
    "on",
    "once",
    "only",
    "or",
    "other",
    "our",
    "ours",
    "ourselves",
    "out",
    "over",
    "own",
    "same",
    "she",
    "should",
    "so",
    "some",
    "such",
    "than",
    "that",
    "the",
    "their",
    "theirs",
    "them",
    "themselves",
    "then",
    "there",
    "these",
    "they",
    "this",
    "those",
    "through",
    "to",
    "too",
    "under",
    "until",
    "up",
    "very",
    "was",
    "we",
    "were",
    "what",
    "when",
    "where",
    "which",
    "while",
    "who",
    "whom",
    "why",
    "will",
    "with",
    "would",
    "you",
    "your",
    "yours",
    "yourself",
    "yourselves",
];

pub fn scan(a: &Path, b: &Path, kind: Option<&str>) -> Result<Report, String> {
    let t0 = Instant::now();
    let left = load(a)?;
    let right = load(b)?;
    if left.trim().is_empty() || right.trim().is_empty() {
        return Err("both sides need text".into());
    }
    let forced = match kind.map(|k| k.to_ascii_lowercase()).as_deref() {
        Some("prose") => Some(false),
        Some("code") => Some(true),
        Some(_) => return Err("kind must be prose or code".into()),
        None => None,
    };
    let code_a = forced.unwrap_or_else(|| looks_like_code(&left, a));
    let code_b = forced.unwrap_or_else(|| looks_like_code(&right, b));
    let mismatch = forced.is_none() && code_a != code_b;
    let as_code = forced.unwrap_or(code_a && code_b);
    let metrics = compare(&left, &right, as_code);
    let reliability = if as_code {
        tier_lines(metrics.lines_a, metrics.lines_b)
    } else {
        tier_words(metrics.words_a, metrics.words_b)
    };
    let primary = if as_code {
        metrics.layout_cosine
    } else {
        metrics.fw_cosine
    };
    let mut summary = format!(
        "cosine {:.3}, distance {:.3}. A lead, not an identification",
        primary,
        1.0 - primary
    );
    if mismatch {
        summary.push_str(". Genre mismatch, so the distance is weak");
    }
    let status = if mismatch || reliability == "unreliable" {
        Status::Inconclusive
    } else {
        Status::Confirmed
    };
    Ok(Report {
        target: format!("{} {}", a.display(), b.display()),
        kind: "style",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings: vec![
            Hit::new(
                if as_code { "code" } else { "prose" },
                status,
                summary,
                Some(json!({
                    "cosine_similarity": round(primary),
                    "cosine_distance": round(1.0 - primary),
                    "function_word_cosine": round(metrics.fw_cosine),
                    "function_word_manhattan": round(metrics.fw_manhattan),
                    "char3_cosine": round(metrics.char3_cosine),
                    "layout_cosine": round(metrics.layout_cosine),
                    "words_a": metrics.words_a,
                    "words_b": metrics.words_b,
                    "reliability": reliability,
                    "genre_mismatch": mismatch,
                })),
            ),
            Hit::new(
                "reliability",
                if reliability == "usable" {
                    Status::Confirmed
                } else {
                    Status::Inconclusive
                },
                format!("{reliability} sample size"),
                None,
            ),
        ],
    })
}

struct Metrics {
    fw_cosine: f64,
    fw_manhattan: f64,
    char3_cosine: f64,
    layout_cosine: f64,
    words_a: usize,
    words_b: usize,
    lines_a: usize,
    lines_b: usize,
}

fn compare(a: &str, b: &str, as_code: bool) -> Metrics {
    let ta = tokens(a);
    let tb = tokens(b);
    let fa = fw_rates(&ta);
    let fb = fw_rates(&tb);
    Metrics {
        fw_cosine: cosine(&fa, &fb),
        fw_manhattan: manhattan(&fa, &fb),
        char3_cosine: char_cosine(a, b),
        layout_cosine: if as_code {
            cosine(&layout(a), &layout(b))
        } else {
            0.0
        },
        words_a: ta.len(),
        words_b: tb.len(),
        lines_a: a.lines().count(),
        lines_b: b.lines().count(),
    }
}

fn tier_words(a: usize, b: usize) -> &'static str {
    let n = a.min(b);
    if n >= 1000 {
        "usable"
    } else if n >= 200 {
        "reduced"
    } else {
        "unreliable"
    }
}

fn tier_lines(a: usize, b: usize) -> &'static str {
    let n = a.min(b);
    if n >= 150 {
        "usable"
    } else if n >= 40 {
        "reduced"
    } else {
        "unreliable"
    }
}

fn load(path: &Path) -> Result<String, String> {
    if !path.exists() {
        return Err(format!("path not found: {}", path.display()));
    }
    if path.is_file() {
        return read_capped(path);
    }
    let mut out = String::new();
    let mut files = 0usize;
    collect(path, &mut out, &mut files, 0);
    if out.is_empty() {
        return Err(format!("no text under {}", path.display()));
    }
    Ok(out)
}

fn collect(dir: &Path, out: &mut String, files: &mut usize, depth: usize) {
    if depth > 6 || *files > 40 || out.len() > 200_000 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if *files > 40 || out.len() > 200_000 {
            return;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".git" || name == "target" || name == "node_modules" || name == "vendor" {
            continue;
        }
        if path.is_dir() {
            collect(&path, out, files, depth + 1);
            continue;
        }
        if !text_ext(&name) {
            continue;
        }
        if let Ok(chunk) = read_capped(&path) {
            out.push_str(&chunk);
            out.push('\n');
            *files += 1;
        }
    }
}

fn text_ext(name: &str) -> bool {
    matches!(
        name.rsplit('.').next(),
        Some("txt")
            | Some("md")
            | Some("rs")
            | Some("py")
            | Some("js")
            | Some("ts")
            | Some("go")
            | Some("c")
            | Some("h")
            | Some("java")
            | Some("rb")
            | Some("html")
            | Some("css")
    )
}

fn read_capped(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let n = bytes.len().min(100_000);
    Ok(String::from_utf8_lossy(&bytes[..n]).into_owned())
}

fn looks_like_code(text: &str, path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str())
        && matches!(
            ext,
            "rs" | "py" | "js" | "ts" | "go" | "c" | "h" | "java" | "rb" | "css"
        )
    {
        return true;
    }
    let lines = text.lines().take(80).collect::<Vec<_>>();
    if lines.is_empty() {
        return false;
    }
    let hits = lines
        .iter()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("fn ")
                || t.starts_with("def ")
                || t.starts_with("function ")
                || t.starts_with("class ")
                || t.starts_with("import ")
                || t.starts_with("#include")
                || t.starts_with("package ")
        })
        .count();
    hits * 10 >= lines.len()
}

fn tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_ascii_lowercase())
        .collect()
}

fn fw_rates(words: &[String]) -> Vec<f64> {
    let n = words.len().max(1) as f64;
    let mut counts = HashMap::<&str, usize>::new();
    for w in words {
        *counts.entry(w.as_str()).or_default() += 1;
    }
    FUNCTION_WORDS
        .iter()
        .map(|w| *counts.get(w).unwrap_or(&0) as f64 / n)
        .collect()
}

fn layout(text: &str) -> Vec<f64> {
    let lines: Vec<&str> = text.lines().collect();
    let n = lines.len().max(1) as f64;
    let mut len_sum = 0.0;
    let mut tabs = 0.0;
    let mut spaces = 0.0;
    let mut comments = 0.0;
    for line in &lines {
        len_sum += line.chars().count() as f64;
        if line.starts_with('\t') {
            tabs += 1.0;
        } else if line.starts_with("    ") || line.starts_with(' ') {
            spaces += 1.0;
        }
        let t = line.trim_start();
        if t.starts_with("//") || t.starts_with('#') || t.starts_with("/*") || t.starts_with('*') {
            comments += 1.0;
        }
    }
    let idents = identifiers(text);
    let ident_n = idents.len().max(1) as f64;
    let mut snake = 0.0;
    let mut camel = 0.0;
    let mut ident_len = 0.0;
    for id in &idents {
        ident_len += id.len() as f64;
        if id.contains('_') {
            snake += 1.0;
        } else if id.chars().any(|c| c.is_ascii_uppercase()) {
            camel += 1.0;
        }
    }
    let punct = text
        .chars()
        .filter(|c| matches!(c, '{' | '}' | '(' | ')' | ';'))
        .count() as f64
        / text.chars().count().max(1) as f64;
    vec![
        (len_sum / n) / 120.0,
        tabs / n,
        spaces / n,
        comments / n,
        snake / ident_n,
        camel / ident_n,
        (ident_len / ident_n) / 24.0,
        punct,
    ]
}

fn identifiers(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            cur.push(c);
        } else if !cur.is_empty() {
            if cur.chars().any(|ch| ch.is_ascii_alphabetic()) && cur.len() > 1 {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.chars().any(|ch| ch.is_ascii_alphabetic()) && cur.len() > 1 {
        out.push(cur);
    }
    out
}

fn char_cosine(a: &str, b: &str) -> f64 {
    let ca = ngrams(a);
    let cb = ngrams(b);
    let mut keys: Vec<String> = ca.keys().chain(cb.keys()).cloned().collect();
    keys.sort();
    keys.dedup();
    if keys.len() > 400 {
        keys.truncate(400);
    }
    let va: Vec<f64> = keys.iter().map(|k| *ca.get(k).unwrap_or(&0.0)).collect();
    let vb: Vec<f64> = keys.iter().map(|k| *cb.get(k).unwrap_or(&0.0)).collect();
    cosine(&va, &vb)
}

fn ngrams(text: &str) -> HashMap<String, f64> {
    let flat: String = text
        .chars()
        .map(|c| {
            if c.is_whitespace() {
                ' '
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    let mut collapsed = String::new();
    let mut prev_space = false;
    for c in flat.chars().take(20_000) {
        if c == ' ' {
            if !prev_space {
                collapsed.push(' ');
            }
            prev_space = true;
        } else {
            collapsed.push(c);
            prev_space = false;
        }
    }
    let chars: Vec<char> = collapsed.chars().collect();
    let mut counts: HashMap<String, usize> = HashMap::new();
    if chars.len() < 3 {
        return HashMap::new();
    }
    for w in chars.windows(3) {
        *counts.entry(w.iter().collect()).or_default() += 1;
    }
    let total = counts.values().sum::<usize>().max(1) as f64;
    let mut ranked: Vec<(String, usize)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    ranked.truncate(200);
    ranked
        .into_iter()
        .map(|(k, n)| (k, n as f64 / total))
        .collect()
}

fn cosine(a: &[f64], b: &[f64]) -> f64 {
    let mut dot = 0.0;
    let mut na = 0.0;
    let mut nb = 0.0;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / na.sqrt() / nb.sqrt()
    }
}

fn manhattan(a: &[f64], b: &[f64]) -> f64 {
    if a.is_empty() {
        return 0.0;
    }
    a.iter().zip(b).map(|(x, y)| (x - y).abs()).sum::<f64>() / a.len() as f64
}

fn round(n: f64) -> f64 {
    (n * 1000.0).round() / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "the cat and the dog were in the house and the cat was with the dog for the day and the dog was in the yard with the cat";
    const B: &str = "the bird and the dog were in the house and the bird was with the dog for the day and the dog was in the yard with the bird";
    const C: &str = "However researchers therefore conclude results remain unclear they suggest otherwise about measured data from field sites";

    #[test]
    fn same_prose_is_closer_than_a_different_register() {
        let near = compare(A, B, false);
        let far = compare(A, C, false);
        assert!(near.fw_cosine > far.fw_cosine);
        assert!(near.fw_manhattan < far.fw_manhattan);
        let same = compare(A, A, false);
        assert!(same.fw_cosine > 0.99);
    }

    #[test]
    fn same_layout_is_closer() {
        let rust_a =
            "fn alpha_one() {\n    let value_name = 1;\n    let other_name = value_name;\n}\n";
        let rust_b =
            "fn beta_two() {\n    let value_name = 2;\n    let other_name = value_name;\n}\n";
        let js = "function AlphaOne(){const valueName=1;const otherName=valueName;}\n";
        let near = compare(rust_a, rust_b, true);
        let far = compare(rust_a, js, true);
        assert!(near.layout_cosine > far.layout_cosine);
    }
}
