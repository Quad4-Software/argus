// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Code similarity scoring via normalized token shingling and winnowing
//! fingerprints (MOSS/SCANOSS lineage). Deterministic, no external deps.
//!
//! Pipeline: tokenize (identifiers->ID, literals->LIT so renames do not
//! evade) -> k-gram shingles hashed (FNV-1a) -> winnow: smallest hash per
//! window -> fingerprint set. Score = Jaccard on fingerprint sets, plus a
//! containment score for "A embedded in B" cases.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::finding::{Finding, Report, Severity};

const K: usize = 5; // shingle size in tokens
const WIN: usize = 15; // winnowing window in shingles

// MinHash LSH index parameters: 64 permutations split into 16 bands of 4
// rows; a candidate pair must collide in every row of at least one band.
const MH_PERMS: usize = 64;
const MH_BANDS: usize = 16;
const MH_ROWS: usize = MH_PERMS / MH_BANDS;
const M61: u64 = (1 << 61) - 1; // Mersenne prime, permutation modulus

// Shared SIM thresholds; classify() applies them for both the in-memory
// pair scorer (SIM-001/002 in cmd/similar_cmd.rs) and the indexed-corpus
// path (SIM-003/004 here) so the two never drift.
const JACCARD_MIN: f64 = 0.70;
const CONTAIN_MIN: f64 = 0.80;
const MIN_SHINGLES_EACH: usize = 60;
const MIN_SHINGLES_SMALL: usize = 120;

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

/// Normalize into token ids: \[A-Za-z_\]\[A-Za-z0-9_\]* -> ID, numbers/strings ->
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
    index_filtered(root, max_file_size, &|_, _, _| false)
}

/// Same as index() but files for which `skip(path, mtime_secs, size)` is
/// true are not re-fingerprinted - callers keep their existing rows.
pub(crate) fn index_filtered(
    root: &Path,
    max_file_size: u64,
    skip: &dyn Fn(&Path, i64, i64) -> bool,
) -> Vec<Fingerprint> {
    let files = crate::scan::collect_files(root, false, true)
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
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            if skip(&p, mtime, md.len() as i64) {
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

/// Which SIM threshold fired for a fingerprint pair, and the score.
pub struct SimHit {
    /// true: whole-file near-duplicate (jaccard); false: embedded copy
    /// (containment).
    pub jaccard: bool,
    /// The score that fired: jaccard value or containment value, 0.0..1.0.
    pub score: f64,
    /// Containment direction: true when b embeds a's fingerprint, false
    /// when a embeds b's. Meaningless when `jaccard` is true.
    pub b_embeds_a: bool,
}

/// Apply the shared SIM thresholds to a fingerprint pair. Both reporting
/// paths (SIM-001/002 pair scoring, SIM-003/004 index query) use this so
/// their verdicts stay identical for the same two fingerprints.
pub fn classify(fa: &Fingerprint, fb: &Fingerprint) -> Option<SimHit> {
    let j = jaccard(fa, fb);
    // small fingerprints hit coincidental structural overlaps too easily;
    // containment on a small side is where false positives concentrate
    let enough = fa.total_shingles >= MIN_SHINGLES_EACH && fb.total_shingles >= MIN_SHINGLES_EACH;
    if j >= JACCARD_MIN && enough {
        return Some(SimHit {
            jaccard: true,
            score: j,
            b_embeds_a: false,
        });
    }
    let ca = containment(fa, fb);
    let cb = containment(fb, fa);
    let c = ca.max(cb);
    let small = fa.total_shingles.min(fb.total_shingles);
    if c >= CONTAIN_MIN && enough && small >= MIN_SHINGLES_SMALL {
        return Some(SimHit {
            jaccard: false,
            score: c,
            b_embeds_a: ca >= cb,
        });
    }
    None
}

/// Deterministic PRNG step (splitmix64): a fixed-seed generator keeps the
/// MinHash permutations stable across runs, builds, and machines.
fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// The 64 fixed (a, b) permutation coefficients. `a` must be nonzero mod p
/// for (a*h + b) mod p to behave as a permutation of the hash space.
fn mh_coeffs() -> [(u64, u64); MH_PERMS] {
    let mut out = [(0u64, 0u64); MH_PERMS];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut a = splitmix64(0xA1_5EED_u64.wrapping_add(i as u64)) % M61;
        if a == 0 {
            a = 1;
        }
        let b = splitmix64(0xB1_5EED_u64.wrapping_add(i as u64)) % M61;
        *slot = (a, b);
    }
    out
}

/// MinHash signature: for each permutation, the minimum of
/// (a*h + b) mod M61 over the fingerprint's hash set. Two signatures agree
/// in position i with probability ~= jaccard of the underlying sets.
/// u128 intermediates keep the multiply exact before reduction.
pub(crate) fn minhash(hashes: &[u64]) -> [u64; MH_PERMS] {
    let coeffs = mh_coeffs();
    let mut sig = [u64::MAX; MH_PERMS];
    for &h in hashes {
        for (i, &(a, b)) in coeffs.iter().enumerate() {
            let v = ((a as u128 * h as u128 + b as u128) % M61 as u128) as u64;
            if v < sig[i] {
                sig[i] = v;
            }
        }
    }
    sig
}

/// LSH band keys: SHA-256 (truncated to 16 bytes) of each band's four
/// minhash rows. Equal band keys mean all four rows matched.
pub(crate) fn band_keys(sig: &[u64; MH_PERMS]) -> [(i64, [u8; 16]); MH_BANDS] {
    use sha2::Digest;
    let mut out = [(0i64, [0u8; 16]); MH_BANDS];
    for (bi, band) in out.iter_mut().enumerate() {
        let mut bytes = [0u8; MH_ROWS * 8];
        for (r, &v) in sig[bi * MH_ROWS..(bi + 1) * MH_ROWS].iter().enumerate() {
            bytes[r * 8..r * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        let d = sha2::Sha256::digest(bytes);
        band.0 = bi as i64;
        band.1.copy_from_slice(&d[..16]);
    }
    out
}

/// Pack/unpack a fingerprint's u64 hash list as a little-endian blob.
pub(crate) fn fp_blob(hashes: &[u64]) -> Vec<u8> {
    hashes.iter().flat_map(|h| h.to_le_bytes()).collect()
}

fn blob_fp(blob: &[u8]) -> Vec<u64> {
    blob.as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c))
        .collect()
}

/// Default index location: $XDG_DATA_HOME/argus/similar.db or
/// ~/.local/share/argus/similar.db.
pub(crate) fn default_db_path() -> PathBuf {
    if let Ok(x) = std::env::var("XDG_DATA_HOME") {
        return Path::new(&x).join("argus").join("similar.db");
    }
    if let Ok(h) = std::env::var("HOME") {
        return Path::new(&h).join(".local/share/argus/similar.db");
    }
    std::env::temp_dir().join("argus-similar.db")
}

pub(crate) fn index_connect(db: &Path, write: bool) -> Result<rusqlite::Connection, String> {
    if write && let Some(parent) = db.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let conn = if write {
        rusqlite::Connection::open(db)
    } else {
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
    }
    .map_err(|e| format!("{}: {e}", db.display()))?;
    if write {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS files(
                id INTEGER PRIMARY KEY,
                path TEXT NOT NULL UNIQUE,
                root TEXT NOT NULL,
                mtime INTEGER NOT NULL,
                size INTEGER NOT NULL,
                total_shingles INTEGER NOT NULL,
                fp BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS bands(
                band_idx INTEGER NOT NULL,
                band_key BLOB NOT NULL,
                file_id INTEGER NOT NULL);
             CREATE INDEX IF NOT EXISTS bands_idx ON bands(band_idx, band_key);",
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(conn)
}

/// Canonical-path equality so ./a.rs and /abs/a.rs cannot self-match.
fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a == b,
    }
}

/// Fingerprint every source file under `root` into a persistent MinHash
/// band index (SQLite). `db` overrides the default location
/// ~/.local/share/argus/similar.db. Rows upsert by canonical path, so a
/// re-run refreshes changed files instead of duplicating them, and rows
/// under `root` for files no longer fingerprintable are pruned.
pub fn index_build(
    root: &Path,
    db: Option<&Path>,
    max_file_size: u64,
    report: &mut Report,
) -> Result<(), String> {
    let _ = report;
    let dbp = db.map(PathBuf::from).unwrap_or_else(default_db_path);
    let mut conn = index_connect(&dbp, true)?;
    let root_key = root
        .canonicalize()
        .unwrap_or_else(|_| root.to_path_buf())
        .display()
        .to_string();
    // incremental: files whose stored (mtime,size) still match are kept
    // as-is - no re-read, no re-fingerprint, no band rewrite
    let existing: HashMap<PathBuf, (i64, i64)> = {
        let mut q = conn
            .prepare("SELECT path,mtime,size FROM files WHERE root=?1")
            .map_err(|e| e.to_string())?;
        q.query_map(rusqlite::params![root_key], |r| {
            Ok((
                PathBuf::from(r.get::<_, String>(0)?),
                (r.get::<_, i64>(1)?, r.get::<_, i64>(2)?),
            ))
        })
        .map_err(|e| e.to_string())?
        .flatten()
        .collect()
    };
    let mut seen: HashSet<String> = HashSet::new();
    // Unchanged files keep their stored rows; they must also count as
    // seen so the stale-file prune below does not delete them. Stored
    // paths are canonical; walked paths are not, so canonicalize in the
    // skip check. A file that changed (or stopped being fingerprintable)
    // is NOT pre-marked - if it yields no fingerprint this run, the prune
    // drops its stale row.
    for (p, (emt, esz)) in &existing {
        let unchanged = std::fs::metadata(p).ok().is_some_and(|md| {
            let mt = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            *emt == mt && *esz == md.len() as i64
        });
        if unchanged {
            seen.insert(p.display().to_string());
        }
    }
    let fps = index_filtered(root, max_file_size, &|p, mt, sz| {
        let canon = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
        existing
            .get(&canon)
            .is_some_and(|&(emt, esz)| emt == mt && esz == sz)
    });
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let mut n = 0usize;
    {
        let mut up = tx
            .prepare(
                "INSERT INTO files(path,root,mtime,size,total_shingles,fp)
                 VALUES(?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(path) DO UPDATE SET
                    root=excluded.root, mtime=excluded.mtime,
                    size=excluded.size,
                    total_shingles=excluded.total_shingles, fp=excluded.fp
                 RETURNING id",
            )
            .map_err(|e| e.to_string())?;
        let mut del_bands = tx
            .prepare("DELETE FROM bands WHERE file_id=?1")
            .map_err(|e| e.to_string())?;
        let mut ins_band = tx
            .prepare("INSERT INTO bands(band_idx,band_key,file_id) VALUES(?1,?2,?3)")
            .map_err(|e| e.to_string())?;
        for fp in &fps {
            if fp.hashes.is_empty() {
                continue; // empty fingerprint: nothing indexable
            }
            let canon = fp.path.canonicalize().unwrap_or_else(|_| fp.path.clone());
            let pstr = canon.display().to_string();
            seen.insert(pstr.clone());
            let md = fp.path.metadata().ok();
            let mtime = md
                .as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let size = md.map(|m| m.len() as i64).unwrap_or(0);
            let id: i64 = up
                .query_row(
                    rusqlite::params![
                        pstr,
                        root_key,
                        mtime,
                        size,
                        fp.total_shingles as i64,
                        fp_blob(&fp.hashes)
                    ],
                    |r| r.get(0),
                )
                .map_err(|e| e.to_string())?;
            // bands change with the fingerprint: rebuild them wholesale
            del_bands
                .execute(rusqlite::params![id])
                .map_err(|e| e.to_string())?;
            for (bi, key) in band_keys(&minhash(&fp.hashes)) {
                ins_band
                    .execute(rusqlite::params![bi, key.as_slice(), id])
                    .map_err(|e| e.to_string())?;
            }
            n += 1;
        }
        // prune rows under this root whose files vanished or stopped
        // being fingerprintable since the last build
        let stale: Vec<(i64, String)> = {
            let mut q = tx
                .prepare("SELECT id,path FROM files WHERE root=?1")
                .map_err(|e| e.to_string())?;
            q.query_map(rusqlite::params![root_key], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?
            .flatten()
            .collect()
        };
        for (id, p) in stale {
            if !seen.contains(&p) {
                del_bands
                    .execute(rusqlite::params![id])
                    .map_err(|e| e.to_string())?;
                tx.execute("DELETE FROM files WHERE id=?1", rusqlite::params![id])
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    tx.commit().map_err(|e| e.to_string())?;
    eprintln!("similar: indexed {n} files into {}", dbp.display());
    Ok(())
}

/// Score every source file under `root` against the persistent index:
/// LSH band candidates first, exact Jaccard/containment on candidates.
/// Findings use the shared classify() thresholds as SIM-003/SIM-004.
pub fn index_query(
    root: &Path,
    db: Option<&Path>,
    max_file_size: u64,
    report: &mut Report,
) -> Result<(), String> {
    let dbp = db.map(PathBuf::from).unwrap_or_else(default_db_path);
    if !dbp.exists() {
        return Err(format!(
            "similar index {} not found - run --index-build first",
            dbp.display()
        ));
    }
    let conn = index_connect(&dbp, false)?;
    let fps = index(root, max_file_size);
    query_db(&conn, &dbp.display().to_string(), &fps, None, report)?;
    Ok(())
}

/// Shared LSH scan for index_query and corpus_lookup: collect file ids
/// colliding in >=1 band, fetch stored fingerprints, classify. `corpus`
/// labels findings with the corpus name so signed-corpus hits stay
/// distinguishable from local-index hits. Returns findings emitted.
pub(crate) fn query_db(
    conn: &rusqlite::Connection,
    label: &str,
    fps: &[Fingerprint],
    corpus: Option<String>,
    report: &mut Report,
) -> Result<usize, String> {
    let not_index = |e: rusqlite::Error| format!("{label}: not an argus similar index ({e})");
    let mut cand_stmt = conn
        .prepare("SELECT DISTINCT file_id FROM bands WHERE band_idx=?1 AND band_key=?2")
        .map_err(not_index)?;
    let mut fp_stmt = conn
        .prepare("SELECT path,total_shingles,fp FROM files WHERE id=?1")
        .map_err(not_index)?;
    let mut compared = 0usize;
    let mut matched = 0usize;
    for fa in fps {
        if fa.hashes.is_empty() {
            continue;
        }
        compared += 1;
        let mut cands: HashSet<i64> = HashSet::new();
        for (bi, key) in band_keys(&minhash(&fa.hashes)) {
            let rows = cand_stmt
                .query_map(rusqlite::params![bi, key.as_slice()], |r| {
                    r.get::<_, i64>(0)
                })
                .map_err(|e| e.to_string())?;
            for r in rows {
                cands.insert(r.map_err(|e| e.to_string())?);
            }
        }
        for id in cands {
            let got = fp_stmt.query_row(rusqlite::params![id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            });
            let Ok((path, total, blob)) = got else {
                continue; // row pruned between band read and fetch
            };
            let fb = Fingerprint {
                path: PathBuf::from(&path),
                hashes: blob_fp(&blob),
                total_shingles: total as usize,
            };
            if same_file(&fa.path, &fb.path) {
                continue; // a file must not match itself in the corpus
            }
            let before = report.findings.len();
            push_index_similar(report, fa, &fb, corpus.as_deref());
            matched += report.findings.len() - before;
        }
    }
    eprintln!("similar: queried {compared} files against {label} - {matched} matches");
    Ok(matched)
}

/// Emit a SIM-003/SIM-004 finding for a query-file vs indexed-file match.
/// Same thresholds as push_similar via classify(); the message names the
/// indexed corpus path instead of a second scanned path. `corpus` marks
/// hits coming from the signed downloadable corpus rather than the local
/// index.
fn push_index_similar(
    report: &mut Report,
    fa: &Fingerprint,
    fb: &Fingerprint,
    corpus: Option<&str>,
) {
    let Some(hit) = classify(fa, fb) else {
        return;
    };
    let (id, sev, msg) = if hit.jaccard {
        (
            "SIM-003",
            Severity::High,
            format!(
                "{} shares {:.0}% of its code fingerprint with indexed corpus file {}",
                fa.path.display(),
                hit.score * 100.0,
                fb.path.display()
            ),
        )
    } else if hit.b_embeds_a {
        (
            "SIM-004",
            Severity::Medium,
            format!(
                "indexed corpus file {} embeds {:.0}% of {}'s fingerprint - possible copied region inside a larger file",
                fb.path.display(),
                hit.score * 100.0,
                fa.path.display()
            ),
        )
    } else {
        (
            "SIM-004",
            Severity::Medium,
            format!(
                "{} embeds {:.0}% of indexed corpus file {}'s fingerprint - possible copied region inside a larger file",
                fa.path.display(),
                hit.score * 100.0,
                fb.path.display()
            ),
        )
    };
    report.findings.push(Finding {
        ruleset: "similarity".into(),
        rule_id: id.into(),
        severity: sev,
        target: fa.path.display().to_string(),
        path: fb.path.display().to_string(),
        line: None,
        excerpt: None,
        message: msg,
        remediation: Some(
            "Check provenance: if this is a vendored copy, track upstream for CVEs and license obligations."
                .into(),
        ),
        reference: None,
        window: None,
        evidence: corpus.map(|c| vec![format!("matched signed similarity corpus {c}")]),
});
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

    #[test]
    fn minhash_is_deterministic() {
        let s = "fn a() {\n let x = y(z);\n emit(x);\n}\n".repeat(6);
        let f1 = fp(&s);
        let f2 = fp(&s);
        assert_eq!(minhash(&f1.hashes), minhash(&f1.hashes));
        // same content in a different Fingerprint instance, same signature
        assert_eq!(minhash(&f1.hashes), minhash(&f2.hashes));
        // and the coefficients are regenerated identically each call
        assert_eq!(mh_coeffs(), mh_coeffs());
    }

    #[test]
    fn bands_collide_for_identical_not_unrelated() {
        let s = "fn main() {\n let x = compute(a, b);\n let y = x * 2;\n println!(\"{}\", y);\n}\n"
            .repeat(4);
        let other = "struct S {\n data: Vec<u8>,\n}\nimpl S {\n fn new() -> Self { Self { data: vec![] } }\n}\n"
            .repeat(5);
        let ka = band_keys(&minhash(&fp(&s).hashes));
        let kb = band_keys(&minhash(&fp(&s).hashes));
        assert_eq!(ka, kb, "identical content must collide in all bands");
        let kc = band_keys(&minhash(&fp(&other).hashes));
        let shared = ka.iter().zip(kc.iter()).filter(|(x, y)| x == y).count();
        assert_eq!(shared, 0, "unrelated code should not share a band");
    }

    /// Scratch dir under temp for index tests; returns (dir, db).
    fn tmp_corpus(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("argus-sim-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("similar.db");
        (dir, db)
    }

    fn corpus_src() -> String {
        "fn work() {\n let total = load(input);\n let adj = total * factor;\n \
         if adj > limit {\n emit(adj);\n }\n log(adj);\n}\n"
            .repeat(12)
    }

    #[test]
    fn index_build_upserts_without_duplicates() {
        let (dir, db) = tmp_corpus("upsert");
        std::fs::write(dir.join("one.rs"), corpus_src()).unwrap();
        std::fs::write(dir.join("two.rs"), corpus_src().replace("work", "go")).unwrap();
        let mut rep = Report::default();
        index_build(&dir, Some(&db), 1 << 20, &mut rep).unwrap();
        index_build(&dir, Some(&db), 1 << 20, &mut rep).unwrap();
        let conn = rusqlite::Connection::open(&db).unwrap();
        let files: i64 = conn
            .query_row("SELECT count(*) FROM files", [], |r| r.get(0))
            .unwrap();
        assert_eq!(files, 2, "second build must upsert, not duplicate");
        let bands: i64 = conn
            .query_row("SELECT count(*) FROM bands", [], |r| r.get(0))
            .unwrap();
        assert_eq!(bands, 2 * MH_BANDS as i64);
        // deleting a source file then rebuilding prunes its stale row
        std::fs::remove_file(dir.join("two.rs")).unwrap();
        index_build(&dir, Some(&db), 1 << 20, &mut rep).unwrap();
        let files: i64 = conn
            .query_row("SELECT count(*) FROM files", [], |r| r.get(0))
            .unwrap();
        assert_eq!(files, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn index_query_finds_indexed_copy_and_skips_self() {
        let (corpus, db) = tmp_corpus("corpus");
        std::fs::write(corpus.join("orig.rs"), corpus_src()).unwrap();
        let mut rep = Report::default();
        index_build(&corpus, Some(&db), 1 << 20, &mut rep).unwrap();

        // querying the corpus itself must not self-match
        index_query(&corpus, Some(&db), 1 << 20, &mut rep).unwrap();
        assert!(
            rep.findings.is_empty(),
            "self-matches must be skipped: {:?}",
            rep.findings.iter().map(|f| &f.message).collect::<Vec<_>>()
        );

        // a copy in another directory is found via the band index
        let (probe, _) = tmp_corpus("probe");
        std::fs::write(probe.join("copy.rs"), corpus_src()).unwrap();
        index_query(&probe, Some(&db), 1 << 20, &mut rep).unwrap();
        assert!(
            rep.findings
                .iter()
                .any(|f| f.rule_id == "SIM-003" && f.message.contains("indexed corpus file")),
            "copy should hit SIM-003: {:?}",
            rep.findings.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(&corpus);
        let _ = std::fs::remove_dir_all(&probe);
    }
}

pub(crate) mod corpus;

pub(crate) use corpus::{build_corpus, corpus_lookup, corpus_path, fetch_corpus};
