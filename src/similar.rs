//! Code similarity scoring via normalized token shingling and winnowing
//! fingerprints (MOSS/SCANOSS lineage). Deterministic, no external deps.
//!
//! Pipeline: tokenize (identifiers->ID, literals->LIT so renames do not
//! evade) -> k-gram shingles hashed (FNV-1a) -> winnow: smallest hash per
//! window -> fingerprint set. Score = Jaccard on fingerprint sets, plus a
//! containment score for "A embedded in B" cases.

use std::path::{Path, PathBuf};

const K: usize = 5; // shingle size in tokens
const WIN: usize = 15; // winnowing window in shingles

/// File fingerprint: the winnowed hash set plus line positions for reporting.
pub struct Fingerprint {
    pub path: PathBuf,
    pub hashes: Vec<u64>,
    pub total_shingles: usize,
}

fn fnv(data: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Normalize into token ids: [A-Za-z_][A-Za-z0-9_]* -> ID, numbers/strings ->
/// LIT, everything else verbatim; comments and whitespace dropped.
fn tokenize(src: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len() / 4);
    let b = src.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
        } else if c.is_ascii_alphabetic() || c == b'_' {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            // keywords keep verbatim? normalize ALL word tokens: lang-agnostic
            // similarity must not care whether the token was `fn` or `def`,
            // but structural keywords shared across a language carry weight;
            // keep short keywords verbatim, normalize only 4+ char words? No:
            // identifiers are the renames. Track heuristic: words that follow
            // ` `+`(` or appear after def/fn/class... simplest robust split:
            // normalize words unless they are ALL-lowercase <=4 chars? Too
            // clever. Normalize every word: the residual structure (punct,
            // arity, ordering) still discriminates code shape well.
            out.push(b'W');
        } else if c.is_ascii_digit() || c == b'"' || c == b'\'' {
            if c == b'"' || c == b'\'' {
                let q = c;
                i += 1;
                while i < b.len() && b[i] != q {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            i += 1;
            out.push(b'L');
        } else if !c.is_ascii_whitespace() {
            out.push(c);
            i += 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Fingerprint one source text.
pub fn fingerprint(path: &Path, src: &str) -> Fingerprint {
    let toks = tokenize(src);
    let mut shingles: Vec<(u64, usize)> = Vec::new();
    if toks.len() >= K {
        for w in toks.windows(K) {
            // byte-position of the shingle start approximates a line later;
            // token index suffices for ordering the fingerprint anyway
            shingles.push((fnv(w), shingles.len()));
        }
    }
    let total = shingles.len();
    // winnow: in each window of WIN shingles pick the smallest hash; dedupe
    let mut hashes = Vec::new();
    if !shingles.is_empty() {
        for w in shingles.windows(WIN.min(shingles.len())) {
            let (h, idx) = w.iter().min_by_key(|x| x.0).copied().unwrap();
            if hashes.last() != Some(&h) {
                let _ = idx;
                hashes.push(h);
            }
        }
    }
    Fingerprint {
        path: path.into(),
        hashes,
        total_shingles: total,
    }
}

/// Jaccard similarity 0.0..1.0 over fingerprint sets.
pub fn jaccard(a: &Fingerprint, b: &Fingerprint) -> f64 {
    if a.hashes.is_empty() || b.hashes.is_empty() {
        return 0.0;
    }
    let mut i = 0;
    let mut j = 0;
    let mut both = 0usize;
    let (ah, bh) = (&a.hashes, &b.hashes);
    // hash lists are not sorted - sort copies for merge
    let mut sa = ah.clone();
    let mut sb = bh.clone();
    sa.sort_unstable();
    sb.sort_unstable();
    while i < sa.len() && j < sb.len() {
        if sa[i] == sb[j] {
            both += 1;
            i += 1;
            j += 1;
        } else if sa[i] < sb[j] {
            i += 1;
        } else {
            j += 1;
        }
    }
    both as f64 / (sa.len() + sb.len() - both) as f64
}

/// Containment: fraction of A's fingerprints also present in B. High when A
/// was copied INTO B even if B is much larger.
pub fn containment(a: &Fingerprint, b: &Fingerprint) -> f64 {
    if a.hashes.is_empty() {
        return 0.0;
    }
    let mut sa = a.hashes.clone();
    sa.sort_unstable();
    let mut sb = b.hashes.clone();
    sb.sort_unstable();
    let mut both = 0usize;
    let mut i = 0;
    let mut j = 0;
    while i < sa.len() && j < sb.len() {
        if sa[i] == sb[j] {
            both += 1;
            i += 1;
            j += 1;
        } else if sa[i] < sb[j] {
            i += 1;
        } else {
            j += 1;
        }
    }
    both as f64 / sa.len() as f64
}

/// Source-ish extensions worth fingerprinting.
fn is_source(p: &Path) -> bool {
    matches!(
        p.extension().and_then(|e| e.to_str()).unwrap_or(""),
        "rs" | "py"
            | "js"
            | "ts"
            | "tsx"
            | "jsx"
            | "go"
            | "c"
            | "h"
            | "cpp"
            | "hpp"
            | "java"
            | "kt"
            | "rb"
            | "php"
            | "cs"
            | "swift"
            | "m"
            | "sh"
            | "bash"
            | "zsh"
            | "pl"
            | "lua"
            | "zig"
            | "sol"
            | "ex"
            | "exs"
            | "erl"
            | "hs"
            | "ml"
            | "fs"
            | "scala"
            | "clj"
            | "dart"
            | "r"
            | "mjs"
            | "cjs"
            | "vue"
            | "svelte"
    )
}

/// Fingerprint every source file under a path (file or dir).
pub fn index(root: &Path, max_file_size: u64) -> Vec<Fingerprint> {
    let files = crate::scan::collect_files(root, true)
        .into_iter()
        .filter(|p| is_source(p))
        .collect::<Vec<_>>();
    files
        .into_iter()
        .filter_map(|p| {
            let md = p.metadata().ok()?;
            if md.len() == 0 || md.len() > max_file_size {
                return None;
            }
            let text = std::fs::read_to_string(&p).ok()?;
            if text.lines().count() < 10 {
                return None; // too small to clone
            }
            Some(fingerprint(&p, &text))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(src: &str) -> Fingerprint {
        fingerprint(Path::new("a.rs"), src)
    }

    #[test]
    fn identical_files_score_one() {
        let s = "fn main() {\n let x = compute(a, b);\n let y = x * 2;\n println!(\"{}\", y);\n}\n"
            .repeat(4);
        assert_eq!(jaccard(&fp(&s), &fp(&s)), 1.0);
    }

    #[test]
    fn renamed_identifiers_still_match() {
        let a =
            "fn process() {\n let alpha = load(input);\n let beta = alpha * 2;\n return beta;\n}\n"
                .repeat(4);
        let b = "fn handle() {\n let cat = fetch(req);\n let dog = cat * 2;\n return dog;\n}\n"
            .repeat(4);
        let j = jaccard(&fp(&a), &fp(&b));
        assert!(j > 0.7, "renames must not hide copying: {j}");
    }

    #[test]
    fn unrelated_files_score_low() {
        let a = "fn main() {\n let a = read();\n process(a);\n print(a);\n}\n".repeat(5);
        let b = "struct S {\n data: Vec<u8>,\n}\nimpl S {\n fn new() -> Self { Self { data: vec![] } }\n}\n".repeat(5);
        let j = jaccard(&fp(&a), &fp(&b));
        assert!(j < 0.2, "unrelated code should score low: {j}");
    }

    #[test]
    fn containment_detects_embedded_copy() {
        let a = "fn f() {\n let x = g(1);\n let y = h(x);\n return y;\n}\n".repeat(3);
        let b = format!("{a}fn big() {{\n {} }}\n", " unrelated(); ".repeat(300));
        assert!(containment(&fp(&a), &fp(&b)) > 0.8);
    }
}
