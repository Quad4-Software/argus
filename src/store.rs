//! Persistent results store: scan runs and findings in sqlite at
//! ~/.local/share/argus/argus.db. Enables `argus trends` diffs -
//! what appeared, what got fixed, what persists across runs.

use crate::finding::{Finding, Report};
use std::path::Path;

fn db_path() -> std::path::PathBuf {
    if let Ok(x) = std::env::var("XDG_DATA_HOME") {
        return Path::new(&x).join("argus").join("argus.db");
    }
    if let Ok(h) = std::env::var("HOME") {
        return Path::new(&h).join(".local/share/argus/argus.db");
    }
    std::env::temp_dir().join("argus.db")
}

/// Stable finding identity for diffing across scans.
pub fn fingerprint(f: &Finding) -> String {
    use sha2::Digest;
    let s = format!(
        "{}|{}|{}|{}|{}",
        f.rule_id,
        f.path,
        f.line.unwrap_or(0),
        f.excerpt.as_deref().unwrap_or(""),
        f.severity as u8
    );
    sha2::Sha256::digest(s.as_bytes())
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn connect() -> Result<rusqlite::Connection, String> {
    let p = db_path();
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let conn = rusqlite::Connection::open(&p).map_err(|e| e.to_string())?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY,
            root TEXT NOT NULL,
            ts INTEGER NOT NULL,
            files INTEGER NOT NULL,
            findings INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS findings(
            scan_id INTEGER NOT NULL,
            fp TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            path TEXT NOT NULL,
            line INTEGER,
            message TEXT NOT NULL);",
    )
    .map_err(|e| e.to_string())?;
    Ok(conn)
}

/// Persist a scan report (one row per root + its findings).
pub fn store_scan(report: &Report, root: &str) -> Result<(), String> {
    let conn = connect()?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    conn.execute(
        "INSERT INTO scans(root,ts,files,findings) VALUES(?1,?2,?3,?4)",
        rusqlite::params![
            root,
            ts as i64,
            report.files_scanned as i64,
            report.findings.len() as i64
        ],
    )
    .map_err(|e| e.to_string())?;
    let id = conn.last_insert_rowid();
    let mut st = conn
        .prepare(
            "INSERT INTO findings(scan_id,fp,rule_id,severity,path,line,message)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
        )
        .map_err(|e| e.to_string())?;
    for f in &report.findings {
        st.execute(rusqlite::params![
            id,
            fingerprint(f),
            f.rule_id,
            f.severity.label().trim(),
            f.path,
            f.line.map(|l| l as i64),
            f.message
        ])
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Two most recent scans for a root: (prev_findings_fps, current).
pub fn trend(root: &str) -> Result<Option<(ScanRow, Option<ScanRow>)>, String> {
    let conn = connect()?;
    let mut st = conn
        .prepare("SELECT id,ts,files,findings FROM scans WHERE root=?1 ORDER BY ts DESC LIMIT 2")
        .map_err(|e| e.to_string())?;
    let rows: Vec<ScanRow> = st
        .query_map(rusqlite::params![root], |r| {
            Ok(ScanRow {
                id: r.get(0)?,
                ts: r.get(1)?,
                files: r.get(2)?,
                findings: r.get(3)?,
            })
        })
        .map_err(|e| e.to_string())?
        .flatten()
        .collect();
    let Some(cur) = rows.first().cloned() else {
        return Ok(None);
    };
    Ok(Some((cur, rows.get(1).cloned())))
}

#[derive(Clone)]
pub struct ScanRow {
    pub id: i64,
    pub ts: i64,
    pub files: i64,
    pub findings: i64,
}

/// Findings of one scan as (fp, rule_id, severity, path, message).
pub fn scan_findings(id: i64) -> Vec<(String, String, String, String, String)> {
    let Ok(conn) = connect() else {
        return Vec::new();
    };
    let Ok(mut st) =
        conn.prepare("SELECT fp,rule_id,severity,path,message FROM findings WHERE scan_id=?1")
    else {
        return Vec::new();
    };
    st.query_map(rusqlite::params![id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
        ))
    })
    .map(|it| it.flatten().collect())
    .unwrap_or_default()
}

/// Count of stored scans for a root.
pub fn scan_count(root: &str) -> usize {
    let Ok(conn) = connect() else {
        return 0;
    };
    conn.query_row(
        "SELECT count(*) FROM scans WHERE root=?1",
        rusqlite::params![root],
        |r| r.get::<_, i64>(0),
    )
    .unwrap_or(0) as usize
}
