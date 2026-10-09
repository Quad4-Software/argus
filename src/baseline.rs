// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Baseline mode: record accepted findings, fail only on new ones.
//!
//! Two formats share one loader. Legacy baselines are a bare
//! {tool, created_at, fingerprints: [fp..]} document. Extended
//! (schema_version 2) baselines add provenance (reviewed_by, reason,
//! expires_at), a per-entry object form carrying a rename-proof content
//! fingerprint, and an optional embedded or detached ed25519 signature
//! so a reviewer-approved suppression list is auditable.

use crate::finding::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// One fingerprints[] element. Bare strings are the legacy form; the
/// object form adds provenance and the path-independent content fp.
/// Untagged keeps old files byte-compatible in both directions.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum Entry {
    Legacy(String),
    Full {
        fp: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fp_content: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<String>,
    },
}

impl Entry {
    /// The path-bound fingerprint every entry must carry.
    pub fn fp(&self) -> &str {
        match self {
            Entry::Legacy(s) => s,
            Entry::Full { fp, .. } => fp,
        }
    }

    // read via content_set once the extended format is consumed
    pub fn fp_content(&self) -> Option<&str> {
        match self {
            Entry::Legacy(_) => None,
            Entry::Full { fp_content, .. } => fp_content.as_deref(),
        }
    }

    pub fn expires_at(&self) -> Option<&str> {
        match self {
            Entry::Legacy(_) => None,
            Entry::Full { expires_at, .. } => expires_at.as_deref(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Baseline {
    pub tool: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Baseline-wide expiry; once past, every entry counts as expired.
    /// A blanket acceptance must not keep suppressing forever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Embedded ed25519 signature (base64) over canonical fps. A
    /// detached \<file\>.sig takes precedence when both exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    pub fingerprints: Vec<Entry>,
}

impl Baseline {
    /// Path-bound fingerprints; this is what suppression matches on.
    pub fn fingerprint_set(&self) -> HashSet<String> {
        self.fingerprints
            .iter()
            .map(|e| e.fp().to_string())
            .collect()
    }

    /// Content fingerprints from extended entries. Empty for legacy
    /// baselines, so callers degrade cleanly to path-bound matching.
    // exercised once the rename-aware baseline path is wired into main
    pub fn content_set(&self) -> HashSet<String> {
        self.fingerprints
            .iter()
            .filter_map(|e| e.fp_content().map(|s| s.to_string()))
            .collect()
    }
}

/// Result of load_full: the parsed baseline (expired entries already
/// dropped) plus how many entries expiry removed.
pub struct LoadedBaseline {
    pub baseline: Baseline,
    // read by callers that surface dropped-entry counts to the user
    pub expired: usize,
}

/// Stable identity of a finding: rule + path + normalized excerpt.
/// Line numbers intentionally excluded (they drift on unrelated edits).
pub fn fingerprint(f: &Finding) -> String {
    let excerpt = f.excerpt.as_deref().unwrap_or("").trim();
    let mut h: u64 = 0xcbf29ce484222325;
    for b in format!("{}|{}|{}", f.rule_id, f.path, excerpt).as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", h)
}

/// Path-independent identity: rule + normalized content + severity.
/// A git mv keeps this stable, so rename-aware suppression can tell
/// "accepted finding that moved" from "genuinely new finding". sha256
/// because these values are embedded in signed baselines and the cheap
/// FNV used by fingerprint() is not collision-resistant enough there.
pub fn fingerprint_content(f: &Finding) -> String {
    use sha2::Digest;
    let excerpt = f.excerpt.as_deref().unwrap_or("").trim();
    sha2::Sha256::digest(format!("{}|{}|{}", f.rule_id, excerpt, f.severity).as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Canonical signing input: path-bound fps sorted, joined by \n.
/// Computed over the file as stored, expired entries included, so a
/// signature stays verifiable after individual entries age out.
// used by sign, verify and write_signed once wired into main
fn canonical(b: &Baseline) -> Vec<u8> {
    let mut fps: Vec<&str> = b.fingerprints.iter().map(|e| e.fp()).collect();
    fps.sort_unstable();
    fps.join("\n").into_bytes()
}

// detached signature lives beside the baseline as <file>.sig
fn sig_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sig", path.display()))
}

/// Parse and structurally validate a baseline without applying expiry.
/// Signing and verification must see the file exactly as stored.
fn read_baseline(path: &Path) -> Result<Baseline, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn write_baseline(path: &Path, b: &Baseline) -> Result<(), String> {
    let text = serde_json::to_string_pretty(b).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Civil calendar to days-since-epoch (Howard Hinnant's algorithm).
/// Duplicated from cmd::misc so this module stays free of cmd deps and
/// no chrono dependency is needed for expiry checks.
fn days_from_civil(y: i64, m: u64, d: u64) -> u64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146097 + doe - 719468) as u64
}

/// Parse an expiry timestamp: YYYY-MM-DD or RFC3339. A bare date stays
/// valid through the end of that day (UTC) so reviewers can write plain
/// dates without thinking about timezones. Returns unix seconds.
fn parse_expiry(s: &str) -> Option<u64> {
    let s = s.trim();
    let y: i64 = s.get(0..4)?.parse().ok()?;
    if s.as_bytes().get(4) != Some(&b'-') || s.as_bytes().get(7) != Some(&b'-') {
        return None;
    }
    let m: u64 = s.get(5..7)?.parse().ok()?;
    let d: u64 = s.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let days = days_from_civil(y, m, d);
    if s.len() == 10 {
        return Some(days * 86400 + 86399);
    }
    let t = &s[10..];
    let t = t
        .strip_prefix('T')
        .or_else(|| t.strip_prefix('t'))
        .or_else(|| t.strip_prefix(' '))?;
    let hh: u64 = t.get(0..2)?.parse().ok()?;
    if t.as_bytes().get(2) != Some(&b':') {
        return None;
    }
    let mm: u64 = t.get(3..5)?.parse().ok()?;
    let mut idx = 5;
    let mut ss: u64 = 0;
    if t.as_bytes().get(idx) == Some(&b':') {
        ss = t.get(idx + 1..idx + 3)?.parse().ok()?;
        idx += 3;
        // fractional seconds carry no meaning for expiry; skip them
        if t.as_bytes().get(idx) == Some(&b'.') {
            idx += 1;
            while t.as_bytes().get(idx).is_some_and(|c| c.is_ascii_digit()) {
                idx += 1;
            }
        }
    }
    if hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let tod = hh * 3600 + mm * 60 + ss;
    let rest = &t[idx..];
    let offset: i64 = match rest {
        "" | "Z" | "z" => 0,
        _ => {
            let (sign, num) = if let Some(r) = rest.strip_prefix('+') {
                (1i64, r)
            } else {
                (-1i64, rest.strip_prefix('-')?)
            };
            // accept HH:MM and HHMM offsets
            let digits: String = num.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() != 4 {
                return None;
            }
            let oh: i64 = digits[0..2].parse().ok()?;
            let om: i64 = digits[2..4].parse().ok()?;
            sign * (oh * 3600 + om * 60)
        }
    };
    let total = days as i64 * 86400 + tod as i64 - offset;
    if total < 0 {
        return None;
    }
    Some(total as u64)
}

/// Load a baseline, dropping entries whose expires_at (or the
/// baseline-level expires_at) is already past. A malformed expires_at
/// is a hard error: silently keeping it would suppress forever, and
/// silently dropping it would surprise the reviewer who wrote it.
pub fn load_full(path: &Path) -> Result<LoadedBaseline, String> {
    let mut b = read_baseline(path)?;
    let now = crate::finding::unix_now();
    let base_exp = b
        .expires_at
        .as_deref()
        .map(|s| {
            parse_expiry(s).ok_or_else(|| format!("{}: malformed expires_at {s:?}", path.display()))
        })
        .transpose()?;
    let mut expired = 0usize;
    let mut kept = Vec::with_capacity(b.fingerprints.len());
    for e in b.fingerprints.drain(..) {
        let ent_exp = e
            .expires_at()
            .map(|s| {
                parse_expiry(s)
                    .ok_or_else(|| format!("{}: malformed expires_at {s:?}", path.display()))
            })
            .transpose()?;
        let stale = ent_exp.is_some_and(|t| now > t) || base_exp.is_some_and(|t| now > t);
        if stale {
            expired += 1;
        } else {
            kept.push(e);
        }
    }
    b.fingerprints = kept;
    Ok(LoadedBaseline {
        baseline: b,
        expired,
    })
}

/// Compat loader: returns only the live path-bound fingerprint set.
/// Handles both legacy and extended files; expiry is applied silently.
/// Callers wanting the expired count or content fps should use
/// load_full instead.
#[allow(dead_code)] // compat shim: callers use load_full
pub fn load(path: &Path) -> Result<HashSet<String>, String> {
    Ok(load_full(path)?.baseline.fingerprint_set())
}

/// Write a detached \<file\>.sig signature over the canonical fps.
/// Signs the file as stored so verification stays stable as entries
/// age out.
// invoked by the baseline signing CLI flag once wired into main
pub fn sign(path: &Path, key: &Path) -> Result<String, String> {
    let b = read_baseline(path)?;
    let sig = crate::rulesign::sign_bytes(&canonical(&b), key)?;
    let out = sig_path(path);
    std::fs::write(&out, &sig).map_err(|e| format!("{}: {e}", out.display()))?;
    Ok(format!("signed {} -> {}", path.display(), out.display()))
}

/// Verify a baseline's signature against a public key. A detached
/// \<file\>.sig wins over the embedded signature field; an unsigned
/// baseline is an error so callers enforcing review can rely on this.
// invoked by the baseline pubkey enforcement flag once wired into main
pub fn verify(path: &Path, pubkey: &Path) -> Result<(), String> {
    let b = read_baseline(path)?;
    let bytes = canonical(&b);
    let sp = sig_path(path);
    if sp.exists() {
        let s = std::fs::read_to_string(&sp).map_err(|e| format!("{}: {e}", sp.display()))?;
        return crate::rulesign::verify_bytes(&bytes, &s, pubkey)
            .map_err(|e| format!("{}: {e}", path.display()));
    }
    match &b.signature {
        Some(s) => crate::rulesign::verify_bytes(&bytes, s, pubkey)
            .map_err(|e| format!("{}: {e}", path.display())),
        None => Err(format!(
            "{}: unsigned baseline (no {} and no embedded signature)",
            path.display(),
            sp.display()
        )),
    }
}

/// Build the extended (schema_version 2) baseline from findings: one
/// object entry per finding carrying both the path-bound and the
/// content fingerprint.
// shared by write_v2 and write_signed once wired into main
fn build_v2(
    findings: &[Finding],
    note: Option<&str>,
    reviewed_by: Option<&str>,
    reason: Option<&str>,
    expires_at: Option<&str>,
) -> Baseline {
    let mut entries: Vec<Entry> = findings
        .iter()
        .map(|f| Entry::Full {
            fp: fingerprint(f),
            fp_content: Some(fingerprint_content(f)),
            note: note.map(|s| s.to_string()),
            expires_at: None,
        })
        .collect();
    entries.sort_by(|a, b| a.fp().cmp(b.fp()));
    entries.dedup_by(|a, b| a.fp() == b.fp());
    Baseline {
        tool: "argus".into(),
        created_at: crate::finding::iso8601(crate::finding::unix_now()),
        schema_version: Some(2),
        reviewed_by: reviewed_by.map(|s| s.to_string()),
        reason: reason.map(|s| s.to_string()),
        expires_at: expires_at.map(|s| s.to_string()),
        signature: None,
        fingerprints: entries,
    }
}

/// Legacy writer, kept byte-compatible: bare-string fingerprint list,
/// no provenance fields. New callers should prefer write_v2.
pub fn write(path: &Path, findings: &[Finding]) -> Result<(), String> {
    let mut entries: Vec<Entry> = findings
        .iter()
        .map(|f| Entry::Legacy(fingerprint(f)))
        .collect();
    entries.sort_by(|a, b| a.fp().cmp(b.fp()));
    entries.dedup_by(|a, b| a.fp() == b.fp());
    let b = Baseline {
        tool: "argus".into(),
        created_at: crate::finding::iso8601(crate::finding::unix_now()),
        schema_version: None,
        reviewed_by: None,
        reason: None,
        expires_at: None,
        signature: None,
        fingerprints: entries,
    };
    write_baseline(path, &b)
}

/// Extended writer: every entry carries fp + fp_content so the
/// baseline survives renames via partition_aware. note applies to all
/// entries (per-entry notes need the extended file format edited by
/// hand or written via write_signed's metadata fields).
// invoked by the extended baseline writer flag once wired into main
pub fn write_v2(path: &Path, findings: &[Finding], note: Option<&str>) -> Result<(), String> {
    write_baseline(path, &build_v2(findings, note, None, None, None))
}

/// Write an extended baseline with review provenance, signed inline.
/// expires_at applies to the whole baseline; a malformed value is
/// rejected rather than written, because a typo must not produce a
/// baseline that either never expires or fails to load later.
// invoked by the signed baseline writer flag once wired into main
pub fn write_signed(
    path: &Path,
    findings: &[Finding],
    reviewed_by: Option<&str>,
    reason: Option<&str>,
    expires_at: Option<&str>,
    key: &Path,
) -> Result<(), String> {
    if let Some(s) = expires_at
        && parse_expiry(s).is_none()
    {
        return Err(format!(
            "malformed expires_at {s:?}: want YYYY-MM-DD or RFC3339"
        ));
    }
    let mut b = build_v2(findings, None, reviewed_by, reason, expires_at);
    b.signature = Some(crate::rulesign::sign_bytes(&canonical(&b), key)?);
    write_baseline(path, &b)
}

/// Split findings into (known, new) given a loaded baseline.
/// Critical findings are never suppressed: a baselined file that now
/// hides a live credential (the classic "baseline swallowed a prod
/// secret" failure) must still surface. `unsuppressed` counts them.
#[allow(dead_code)] // compat shim: callers use partition_aware
pub fn partition(
    findings: Vec<Finding>,
    base: &HashSet<String>,
    unsuppressed: &mut usize,
) -> (Vec<Finding>, Vec<Finding>) {
    partition_aware(base, &HashSet::new(), findings, unsuppressed)
}

/// Rename-aware variant of partition. A finding whose path-bound fp
/// misses but whose content fp hits is still suppressed (the accepted
/// issue moved, it did not reappear), and the suppressed entry gains an
/// evidence line recording the move so audits can spot mass renames.
/// Critical findings are kept visible exactly as in partition.
pub fn partition_aware(
    set: &HashSet<String>,
    content_set: &HashSet<String>,
    findings: Vec<Finding>,
    unsuppressed: &mut usize,
) -> (Vec<Finding>, Vec<Finding>) {
    let mut known = Vec::new();
    let mut new = Vec::new();
    for mut f in findings {
        let path_hit = set.contains(&fingerprint(&f));
        let content_hit = !path_hit && content_set.contains(&fingerprint_content(&f));
        if path_hit || content_hit {
            if content_hit {
                f.evidence.get_or_insert_with(Vec::new).push(
                    "baseline matched on content fingerprint only: file moved or was renamed since the baseline was taken".into(),
                );
            }
            if f.severity == Severity::Critical {
                *unsuppressed += 1;
                f.evidence.get_or_insert_with(Vec::new).push(
                    "matches baseline fingerprint but kept visible: Critical findings are never suppressed".into(),
                );
                new.push(f);
            } else {
                known.push(f);
            }
        } else {
            new.push(f);
        }
    }
    (known, new)
}

/// Worst severity among new findings (what --fail-on-new gates on).
pub fn worst_of(new: &[Finding]) -> Option<Severity> {
    new.iter().map(|f| f.severity).max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;

    fn mk(sev: Severity, id: &str, path: &str) -> Finding {
        Finding {
            ruleset: "test".into(),
            rule_id: id.into(),
            severity: sev,
            target: "t".into(),
            path: path.into(),
            line: None,
            excerpt: None,
            message: "m".into(),
            remediation: None,
            reference: None,
            window: None,
            evidence: None,
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("argus-baseline-test-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn critical_never_suppressed() {
        let live = mk(Severity::Critical, "VER-001", "a.env");
        let low = mk(Severity::Low, "X-1", "b.txt");
        let base: HashSet<String> = [fingerprint(&live), fingerprint(&low)]
            .into_iter()
            .collect();
        let mut unsup = 0usize;
        let (known, new) = partition(vec![live, low], &base, &mut unsup);
        assert_eq!(known.len(), 1);
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].severity, Severity::Critical);
        assert_eq!(unsup, 1);
        assert!(
            new[0]
                .evidence
                .as_ref()
                .unwrap()
                .iter()
                .any(|e| e.contains("never suppressed"))
        );
    }

    #[test]
    fn legacy_file_loads() {
        let d = tmpdir("legacy");
        let p = d.join("b.json");
        std::fs::write(
            &p,
            r#"{"tool":"argus","created_at":"2026-01-01T00:00:00Z","fingerprints":["aa","bb"]}"#,
        )
        .unwrap();
        let s = load(&p).unwrap();
        assert!(s.contains("aa") && s.contains("bb") && s.len() == 2);
        let lb = load_full(&p).unwrap();
        assert_eq!(lb.expired, 0);
        assert_eq!(lb.baseline.fingerprints.len(), 2);
        // legacy entries carry no content fp
        assert!(lb.baseline.content_set().is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn signed_baseline_roundtrips() {
        let d = tmpdir("sig");
        let priv_k = d.join("k.priv");
        let pub_k = d.join("k.pub");
        crate::rulesign::keygen(&priv_k, &pub_k).unwrap();
        let p = d.join("b.json");
        let fs = [
            mk(Severity::Low, "X-1", "a.txt"),
            mk(Severity::High, "Y-2", "b.txt"),
        ];
        write_signed(
            &p,
            &fs,
            Some("reviewer@example.com"),
            Some("accepted noise"),
            Some("2999-01-01"),
            &priv_k,
        )
        .unwrap();
        // embedded signature verifies
        verify(&p, &pub_k).unwrap();
        // provenance survives the roundtrip
        let lb = load_full(&p).unwrap();
        assert_eq!(
            lb.baseline.reviewed_by.as_deref(),
            Some("reviewer@example.com")
        );
        assert_eq!(lb.baseline.reason.as_deref(), Some("accepted noise"));
        assert_eq!(lb.baseline.fingerprints.len(), 2);
        // detached signature path also verifies
        sign(&p, &priv_k).unwrap();
        assert!(d.join("b.json.sig").exists());
        verify(&p, &pub_k).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn expired_entries_drop_and_count() {
        let d = tmpdir("expiry");
        let p = d.join("b.json");
        std::fs::write(
            &p,
            r#"{"tool":"argus","created_at":"x","fingerprints":[
                "old",
                {"fp":"dead","expires_at":"2000-01-01"},
                {"fp":"live","expires_at":"2999-01-01T00:00:00Z"}
            ]}"#,
        )
        .unwrap();
        let lb = load_full(&p).unwrap();
        assert_eq!(lb.expired, 1);
        let s = lb.baseline.fingerprint_set();
        assert!(s.contains("old") && s.contains("live") && !s.contains("dead"));
        // baseline-level expiry sinks every entry
        let p2 = d.join("b2.json");
        std::fs::write(
            &p2,
            r#"{"tool":"argus","created_at":"x","expires_at":"2001-06-01","fingerprints":["a","b"]}"#,
        )
        .unwrap();
        let lb2 = load_full(&p2).unwrap();
        assert_eq!(lb2.expired, 2);
        assert!(load(&p2).unwrap().is_empty());
        // malformed expiry is a hard error, not a silent keep-or-drop
        let p3 = d.join("b3.json");
        std::fs::write(
            &p3,
            r#"{"tool":"argus","created_at":"x","fingerprints":[{"fp":"z","expires_at":"soon"}]}"#,
        )
        .unwrap();
        assert!(load_full(&p3).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn content_fp_survives_rename() {
        let d = tmpdir("rename");
        let p = d.join("b.json");
        let mut f1 = mk(Severity::Medium, "SEC-1", "old/name.txt");
        f1.excerpt = Some("token = hunter2".into());
        write_v2(&p, std::slice::from_ref(&f1), Some("accepted")).unwrap();
        let lb = load_full(&p).unwrap();
        let set = lb.baseline.fingerprint_set();
        let cset = lb.baseline.content_set();
        assert_eq!(cset.len(), 1);
        // same finding after git mv
        let mut f2 = f1.clone();
        f2.path = "new/name.txt".into();
        assert_ne!(fingerprint(&f1), fingerprint(&f2));
        assert_eq!(fingerprint_content(&f1), fingerprint_content(&f2));
        let mut unsup = 0usize;
        let (known, new) = partition_aware(&set, &cset, vec![f2], &mut unsup);
        assert_eq!(new.len(), 0);
        assert_eq!(known.len(), 1);
        assert!(
            known[0]
                .evidence
                .as_ref()
                .unwrap()
                .iter()
                .any(|e| e.contains("moved"))
        );
        // content fp does not rescue a genuinely different finding
        let other = mk(Severity::Medium, "SEC-2", "new/name.txt");
        let (_k, new2) = partition_aware(&set, &cset, vec![other], &mut unsup);
        assert_eq!(new2.len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tampered_signature_rejected() {
        let d = tmpdir("tamper");
        let priv_k = d.join("k.priv");
        let pub_k = d.join("k.pub");
        crate::rulesign::keygen(&priv_k, &pub_k).unwrap();
        let p = d.join("b.json");
        write_signed(
            &p,
            &[mk(Severity::Low, "X-1", "a.txt")],
            None,
            None,
            None,
            &priv_k,
        )
        .unwrap();
        // attacker appends a fingerprint to suppress their own finding
        let mut v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        v["fingerprints"]
            .as_array_mut()
            .unwrap()
            .push("deadbeef".into());
        std::fs::write(&p, serde_json::to_string_pretty(&v).unwrap()).unwrap();
        assert!(verify(&p, &pub_k).is_err());
        // unsigned baseline also fails when verification is required
        let p2 = d.join("b2.json");
        std::fs::write(
            &p2,
            r#"{"tool":"argus","created_at":"x","fingerprints":["aa"]}"#,
        )
        .unwrap();
        assert!(verify(&p2, &pub_k).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn write_v2_emits_extended_entries() {
        let d = tmpdir("v2fmt");
        let p = d.join("b.json");
        let mut f = mk(Severity::Low, "X-1", "a.txt");
        f.excerpt = Some("abc".into());
        write_v2(&p, &[f], None).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(v["schema_version"], 2);
        let e = &v["fingerprints"][0];
        assert!(e["fp"].is_string());
        assert_eq!(e["fp_content"].as_str().unwrap().len(), 64);
        // legacy write stays bare-string for byte compat
        let p2 = d.join("b2.json");
        write(&p2, &[mk(Severity::Low, "X-1", "a.txt")]).unwrap();
        let v2: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p2).unwrap()).unwrap();
        assert!(v2["fingerprints"][0].is_string());
        assert!(v2.get("schema_version").is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}
