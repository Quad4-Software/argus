// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Signed downloadable similarity corpus: fetch+verify of a published
//! fingerprint db, lookup against it, and the maintainer-side builder.
//! Split from similar.rs so the file-size cap holds; shared plumbing
//! (index_connect, query_db, fp_blob) stays in the parent module.

use super::{
    band_keys, default_db_path, fp_blob, index, index_connect, index_filtered, minhash, query_db,
};
use crate::finding::Report;
use std::path::{Path, PathBuf};

/// Default corpus location: sibling of the index db, so the corpus
/// inherits whatever XDG/temp fallback convention the index already has.
pub fn corpus_path() -> PathBuf {
    default_db_path()
        .parent()
        .map(|p| p.join("corpus.db"))
        .unwrap_or_else(|| PathBuf::from("corpus.db"))
}

/// ed25519 public key that signs the published argus similarity corpus.
/// The private half lives in maintainer release infrastructure and is
/// never committed to this repo. Rotating the corpus signer requires a
/// new argus release, which is the point: an attacker able to swap this
/// key could already ship a doctored scanner.
pub const CORPUS_PUBKEY_HEX: &str =
    "1613b12809ab492474f0fb868e4391931034c9be1aea91f039e1ae96444e82a4";

/// Cap on a downloaded corpus db. One corpus row plus 16 band rows per
/// source file puts 512 MiB at roughly half a million files.
const CORPUS_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// Corpus builds skip files larger than this. Same order as the scanner
/// default; a checked-out package should not contain bigger sources.
const CORPUS_MAX_FILE: u64 = 8 * 1024 * 1024;
/// Score files under `root` against the downloaded signed corpus db,
/// opened read-only. `corpus_db` overrides the default corpus_path().
/// The corpus stores package-relative identities, so findings name the
/// corpus file (pkg/path) rather than any local filename.
pub fn corpus_lookup(
    root: &Path,
    corpus_db: Option<&Path>,
    max_file_size: u64,
    report: &mut Report,
) -> Result<(), String> {
    let dbp = corpus_db.map(PathBuf::from).unwrap_or_else(corpus_path);
    if !dbp.exists() {
        return Err(format!(
            "similar corpus {} not found - fetch it first (--fetch-corpus)",
            dbp.display()
        ));
    }
    let conn = index_connect(&dbp, false)?;
    // corpus_meta is optional: a hand-rolled or older corpus db may lack
    // it, and the fingerprints still work without the label
    let meta = corpus_meta(&conn);
    let label = match &meta {
        Some((name, ver, at)) => format!("corpus {name} {ver} (built {at})"),
        None => format!("corpus {}", dbp.display()),
    };
    let fps = index(root, max_file_size);
    query_db(
        &conn,
        &label,
        &fps,
        meta.map(|(n, v, _)| format!("{n} {v}")),
        report,
    )?;
    Ok(())
}

/// Optional corpus_meta(name, version, built_at) row; absent on dbs that
/// only carry the index schema.
fn corpus_meta(conn: &rusqlite::Connection) -> Option<(String, String, String)> {
    conn.query_row(
        "SELECT name,version,built_at FROM corpus_meta LIMIT 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .ok()
}

/// Download `<url>` (a corpus .db) and its detached signature `<url>.sig`
/// (base64 ed25519), verify the signature over the db bytes, and only
/// then install the db at `dest`. `pubkey` overrides the embedded
/// CORPUS_PUBKEY_HEX for privately built corpora. Verified bytes are
/// staged via temp+rename so a failed or forged fetch can never leave a
/// partial db behind.
pub fn fetch_corpus(url: &str, dest: &Path, pubkey: Option<&Path>) -> Result<String, String> {
    let db = http_get_bytes(url, CORPUS_MAX_BYTES)?;
    if !db.starts_with(b"SQLite format 3\0") {
        // catches 200-with-HTML error pages and other wrong-content fetches
        return Err(format!("{url}: not a sqlite database (corpus db expected)"));
    }
    let sig_url = format!("{url}.sig");
    let sig_bytes = http_get_bytes(&sig_url, 64 * 1024)?;
    let sig_b64 = String::from_utf8(sig_bytes)
        .map_err(|_| format!("{sig_url}: signature is not utf-8 base64"))?;
    verify_corpus_bytes(&db, &sig_b64, pubkey)?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = dest.with_extension("part");
    std::fs::write(&tmp, &db).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, dest).map_err(|e| format!("{}: {e}", dest.display()))?;
    Ok(format!(
        "corpus signature verified; {} bytes -> {}",
        db.len(),
        dest.display()
    ))
}

/// Binary GET with a hard size cap. HttpClient only exposes text bodies,
/// which cannot carry a sqlite db without corrupting non-utf8 bytes.
fn http_get_bytes(url: &str, max: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let config = ureq::config::Config::builder()
        .timeout_global(Some(std::time::Duration::from_secs(120)))
        .http_status_as_error(false)
        .user_agent(concat!("argus/", env!("CARGO_PKG_VERSION")))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut resp = agent.get(url).call().map_err(|e| format!("{url}: {e}"))?;
    let status = resp.status().as_u16();
    if status != 200 {
        return Err(format!("{url}: http {status}"));
    }
    let mut src = resp.body_mut().as_reader();
    let mut out = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = src.read(&mut buf).map_err(|e| format!("{url}: {e}"))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        if out.len() as u64 > max {
            return Err(format!("{url}: response exceeds {max} byte cap"));
        }
    }
    Ok(out)
}

/// Verify a downloaded corpus db against its base64 detached signature.
/// pubkey None trusts the embedded CORPUS_PUBKEY_HEX; Some(path) reads a
/// rulesign-format key file (64 hex chars). Pure verify: no fs side
/// effects beyond the optional key read, so tests exercise it directly.
pub fn verify_corpus_bytes(db: &[u8], sig_b64: &str, pubkey: Option<&Path>) -> Result<(), String> {
    let key_hex = match pubkey {
        Some(p) => {
            std::fs::read_to_string(p).map_err(|e| format!("corpus pubkey {}: {e}", p.display()))?
        }
        None => CORPUS_PUBKEY_HEX.to_string(),
    };
    verify_corpus_hex(db, sig_b64, key_hex.trim())
}

fn verify_corpus_hex(db: &[u8], sig_b64: &str, key_hex: &str) -> Result<(), String> {
    use base64::Engine;
    use ed25519_dalek::Verifier;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&unhex32(key_hex)?)
        .map_err(|e| format!("corpus pubkey: {e}"))?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim())
        .map_err(|_| "corpus signature is not valid base64".to_string())?;
    if sig_bytes.len() != 64 {
        return Err("corpus signature must be 64 bytes".into());
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let sig = ed25519_dalek::Signature::from_bytes(&arr);
    vk.verify(db, &sig)
        .map_err(|_| "corpus signature verification failed".to_string())
}

/// rulesign-format key material: 64 hex chars carrying one 32-byte key.
fn unhex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err("key file must be 64 hex chars (32 bytes)".into());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| "bad hex in key file".to_string())?;
    }
    Ok(out)
}

/// Maintainer-side corpus builder: fingerprint every source file under
/// each src dir into a fresh sqlite db carrying the index schema plus a
/// corpus_meta row. Rows are stored under a corpus identity of
/// `<srcdir-basename>/<relative-path>` so lookup findings report which
/// package a hit came from instead of a builder-local absolute path.
pub fn build_corpus(src_dirs: &[PathBuf], out: &Path, name: &str) -> Result<String, String> {
    if src_dirs.is_empty() {
        return Err("build_corpus: no source dirs".into());
    }
    // always a fresh db: leftover rows would keep fingerprints for
    // packages the corpus manifest no longer ships
    let _ = std::fs::remove_file(out);
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut conn = index_connect(out, true)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS corpus_meta(
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            built_at TEXT NOT NULL);",
    )
    .map_err(|e| e.to_string())?;
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
        for dir in src_dirs {
            // the package dir name prefixes every identity it contributes
            let pkg = dir
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| dir.display().to_string());
            for fp in index_filtered(dir, CORPUS_MAX_FILE, &|_, _, _| false) {
                if fp.hashes.is_empty() {
                    continue;
                }
                let rel = fp.path.strip_prefix(dir).unwrap_or(&fp.path);
                let ident = if rel == fp.path.as_path() {
                    // `dir` was itself a file: the package name is the id
                    pkg.clone()
                } else {
                    format!("{pkg}/{}", rel.display())
                };
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
                            ident,
                            pkg,
                            mtime,
                            size,
                            fp.total_shingles as i64,
                            fp_blob(&fp.hashes)
                        ],
                        |r| r.get(0),
                    )
                    .map_err(|e| e.to_string())?;
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
        }
        let built_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|_| "0".into());
        tx.execute(
            "INSERT INTO corpus_meta(name,version,built_at) VALUES(?1,?2,?3)",
            rusqlite::params![name, env!("CARGO_PKG_VERSION"), built_at],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(format!(
        "corpus {name}: {n} files fingerprinted -> {}",
        out.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Report;
    use crate::similar::index_build;

    fn tmp_corpus(tag: &str) -> (PathBuf, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("argus-corpus-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        (dir, db)
    }

    fn corpus_src() -> String {
        "fn work() {
 let total = load(input);
 let adj = total * factor;
          if adj > limit {
 emit(adj);
 }
 log(adj);
}
"
        .repeat(12)
    }

    #[test]
    fn corpus_build_stores_pkg_identities() {
        let (dir, db) = tmp_corpus("pkgbuild");
        let pkg = dir.join("fakelib-1.0");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("a.rs"), corpus_src()).unwrap();
        std::fs::write(pkg.join("b.rs"), corpus_src().replace("work", "go")).unwrap();
        let msg = build_corpus(&[pkg], &db, "testcorpus").unwrap();
        assert!(msg.contains("2 files"), "{msg}");
        let conn = rusqlite::Connection::open(&db).unwrap();
        let meta: String = conn
            .query_row("SELECT name FROM corpus_meta", [], |r| r.get(0))
            .unwrap();
        assert_eq!(meta, "testcorpus");
        // corpus paths carry package identity, not builder-local abs paths
        let p: String = conn
            .query_row("SELECT path FROM files LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert!(
            p.starts_with("fakelib-1.0/"),
            "corpus path must carry pkg identity: {p}"
        );
        assert!(!p.contains(dir.display().to_string().as_str()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corpus_lookup_finds_copied_file() {
        let (dir, db) = tmp_corpus("corplookup");
        let pkg = dir.join("vend-2.0");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("orig.rs"), corpus_src()).unwrap();
        build_corpus(&[pkg], &db, "vendcorpus").unwrap();

        let (probe, _) = tmp_corpus("corpprobe");
        std::fs::write(probe.join("copy.rs"), corpus_src()).unwrap();
        let mut rep = Report::default();
        corpus_lookup(&probe, Some(&db), 1 << 20, &mut rep).unwrap();
        assert!(
            rep.findings.iter().any(|f| f.rule_id == "SIM-003"
                && f.message.contains("vend-2.0/")
                && f.evidence.is_some()),
            "copy should hit SIM-003 with corpus evidence: {:?}",
            rep.findings.iter().map(|f| &f.message).collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&probe);
    }

    #[test]
    fn corpus_lookup_tolerates_missing_meta_table() {
        // a plain index db has no corpus_meta; lookup must still work
        let (dir, db) = tmp_corpus("nometa");
        std::fs::write(dir.join("orig.rs"), corpus_src()).unwrap();
        let mut rep = Report::default();
        index_build(&dir, Some(&db), 1 << 20, &mut rep).unwrap();
        let (probe, _) = tmp_corpus("nometaprobe");
        std::fs::write(probe.join("copy.rs"), corpus_src()).unwrap();
        corpus_lookup(&probe, Some(&db), 1 << 20, &mut rep).unwrap();
        assert!(rep.findings.iter().any(|f| f.rule_id == "SIM-003"));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&probe);
    }

    #[test]
    fn corpus_signature_gate() {
        let (dir, _) = tmp_corpus("corpsig");
        let privk = dir.join("priv.hex");
        let pubk = dir.join("pub.hex");
        crate::rulesign::keygen(&privk, &pubk).unwrap();
        let db = b"SQLite format 3\0 fake-corpus-bytes";
        let sig = crate::rulesign::sign_bytes(db, &privk).unwrap();
        verify_corpus_bytes(db, &sig, Some(&pubk)).unwrap();
        // a tampered db must fail under the right key
        let mut bad = db.to_vec();
        bad[20] ^= 0xff;
        assert!(verify_corpus_bytes(&bad, &sig, Some(&pubk)).is_err());
        // a valid sig under a different key must fail
        let priv2 = dir.join("p2.hex");
        let pub2 = dir.join("u2.hex");
        crate::rulesign::keygen(&priv2, &pub2).unwrap();
        assert!(verify_corpus_bytes(db, &sig, Some(&pub2)).is_err());
        // the embedded-key path must reject garbage rather than panic
        assert!(verify_corpus_bytes(db, "AAAA", None).is_err());
        assert!(verify_corpus_bytes(db, &sig, Some(&dir.join("missing"))).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
