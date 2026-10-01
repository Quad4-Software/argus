// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Store drivers.
//! sqlite is built in. postgres:// needs the postgres feature.
//! surreal:// and surreals:// talk to a SurrealDB server over HTTP /sql.

use crate::hooks;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Record {
    pub id: String,
    pub kind: String,
    pub key: String,
    pub body: String,
    pub ts: i64,
}

pub(crate) trait Driver: Send {
    fn put(&self, kind: &str, key: &str, body: &str) -> Result<String, String>;
    fn link(&self, from: &str, rel: &str, to: &str) -> Result<(), String>;
    fn search(&self, query: &str, limit: usize) -> Result<Vec<Record>, String>;
}

pub fn open() -> Result<Box<dyn Driver>, String> {
    let spec = configured_url();
    open_url(&spec)
}

fn configured_url() -> String {
    if let Ok(url) = std::env::var("ARGUS_STORE_URL")
        && !url.is_empty()
    {
        return url;
    }
    if let Ok((cfg, _)) = crate::config::load(None)
        && let Some(url) = cfg.store.url.filter(|s| !s.is_empty())
    {
        let driver = cfg.store.driver.as_deref().unwrap_or("sqlite");
        if driver == "sqlite" && !url.contains("://") {
            return format!("sqlite://{url}");
        }
        return url;
    }
    String::new()
}

fn open_url(spec: &str) -> Result<Box<dyn Driver>, String> {
    let spec = spec.trim();
    if spec.starts_with("postgres://") || spec.starts_with("postgresql://") {
        #[cfg(feature = "postgres")]
        {
            return Ok(Box::new(Pg::connect(spec)?));
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = spec;
            return Err("postgres connector needs a build with --features postgres".into());
        }
    }
    if spec.starts_with("surreal://") || spec.starts_with("surreals://") {
        return Ok(Box::new(Surreal::connect(spec)?));
    }
    let path = if spec.is_empty() || spec == "sqlite" {
        crate::store::db_path()
    } else if let Some(rest) = spec.strip_prefix("sqlite://") {
        PathBuf::from(rest)
    } else {
        PathBuf::from(spec)
    };
    Ok(Box::new(Sqlite::open(&path)?))
}

pub fn put_report(kind: &str, key: &str, body: &str) -> Result<String, String> {
    let db = open()?;
    let id = db.put(kind, key, body)?;
    hooks::notify(
        "record.saved",
        &serde_json::json!({"id": id, "kind": kind, "key": key}),
    );
    Ok(id)
}

pub fn search(query: &str, limit: usize) -> Result<Vec<Record>, String> {
    open()?.search(query, limit)
}

pub fn relate(from: &str, rel: &str, to: &str) -> Result<(), String> {
    open()?.link(from, rel, to)
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn record_id(kind: &str, key: &str) -> String {
    format!("{kind}:{key}")
}

fn like_pattern(query: &str) -> String {
    let mut out = String::from("%");
    for c in query.chars() {
        if c == '%' || c == '_' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

struct Sqlite {
    conn: Mutex<rusqlite::Connection>,
}

impl Sqlite {
    fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let conn = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS records(
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                key TEXT NOT NULL,
                body TEXT NOT NULL,
                ts INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS links(
                src TEXT NOT NULL,
                rel TEXT NOT NULL,
                dst TEXT NOT NULL,
                PRIMARY KEY(src, rel, dst));",
        )
        .map_err(|e| e.to_string())?;
        Ok(Sqlite {
            conn: Mutex::new(conn),
        })
    }
}

impl Driver for Sqlite {
    fn put(&self, kind: &str, key: &str, body: &str) -> Result<String, String> {
        let id = record_id(kind, key);
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO records(id,kind,key,body,ts) VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(id) DO UPDATE SET body=excluded.body, ts=excluded.ts",
            rusqlite::params![id, kind, key, body, now()],
        )
        .map_err(|e| e.to_string())?;
        Ok(id)
    }

    fn link(&self, from: &str, rel: &str, to: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR IGNORE INTO links(src,rel,dst) VALUES(?1,?2,?3)",
            rusqlite::params![from, rel, to],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn search(&self, query: &str, limit: usize) -> Result<Vec<Record>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut st = conn
            .prepare(
                "SELECT id,kind,key,body,ts FROM records
                 WHERE key LIKE ?1 ESCAPE '\\' OR body LIKE ?1 ESCAPE '\\'
                 ORDER BY ts DESC LIMIT ?2",
            )
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map(rusqlite::params![like_pattern(query), limit as i64], |r| {
                Ok(Record {
                    id: r.get(0)?,
                    kind: r.get(1)?,
                    key: r.get(2)?,
                    body: r.get(3)?,
                    ts: r.get(4)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }
}

struct Surreal {
    endpoint: String,
    ns: String,
    db: String,
    auth: String,
}

impl Surreal {
    fn connect(spec: &str) -> Result<Self, String> {
        let https = spec.starts_with("surreals://");
        let rest = spec
            .trim_start_matches("surreals://")
            .trim_start_matches("surreal://");
        let (userinfo, hostpath) = match rest.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, rest),
        };
        let (hostport, path) = match hostpath.split_once('/') {
            Some((h, p)) => (h, p),
            None => (hostport_err(hostpath)?, ""),
        };
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.len() < 2 {
            return Err("surreal url needs /namespace/database".into());
        }
        let scheme = if https { "https" } else { "http" };
        let auth = match userinfo {
            Some(u) => format!("Basic {}", b64(u.as_bytes())),
            None => String::new(),
        };
        Ok(Surreal {
            endpoint: format!("{scheme}://{hostport}/sql"),
            ns: parts[0].to_string(),
            db: parts[1].to_string(),
            auth,
        })
    }

    fn sql(&self, statement: &str) -> Result<serde_json::Value, String> {
        let config = ureq::config::Config::builder()
            .timeout_global(Some(std::time::Duration::from_secs(6)))
            .http_status_as_error(false)
            .user_agent(concat!("argus/", env!("CARGO_PKG_VERSION")))
            .build();
        let agent = ureq::Agent::new_with_config(config);
        let mut req = agent
            .post(&self.endpoint)
            .header("Accept", "application/json")
            .header("NS", &self.ns)
            .header("DB", &self.db)
            .header("Surreal-NS", &self.ns)
            .header("Surreal-DB", &self.db)
            .header("Content-Type", "text/plain");
        if !self.auth.is_empty() {
            req = req.header("Authorization", &self.auth);
        }
        let mut resp = req.send(statement).map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.body_mut().read_to_string().unwrap_or_default();
        if status != 200 {
            return Err(format!("surreal HTTP {status}"));
        }
        serde_json::from_str(&text).map_err(|_| "surreal response was not JSON".into())
    }
}

fn hostport_err(host: &str) -> Result<&str, String> {
    if host.is_empty() {
        Err("surreal url has no host".into())
    } else {
        Ok(host)
    }
}

impl Driver for Surreal {
    fn put(&self, kind: &str, key: &str, body: &str) -> Result<String, String> {
        let id = record_id(kind, key);
        let statement = format!(
            "UPSERT record:`{}` CONTENT {{ kind: '{}', key: '{}', body: '{}', ts: {} }};",
            escape_surreal(&id),
            escape_surreal(kind),
            escape_surreal(key),
            escape_surreal(body),
            now()
        );
        let v = self.sql(&statement)?;
        surreal_ok(&v)?;
        Ok(id)
    }

    fn link(&self, from: &str, rel: &str, to: &str) -> Result<(), String> {
        let statement = format!(
            "RELATE record:`{}`->{}->record:`{}`;",
            escape_surreal(from),
            escape_ident(rel)?,
            escape_surreal(to)
        );
        let v = self.sql(&statement)?;
        surreal_ok(&v)
    }

    fn search(&self, query: &str, limit: usize) -> Result<Vec<Record>, String> {
        let q = escape_surreal(&query.to_ascii_lowercase());
        let statement = format!(
            "SELECT id, kind, key, body, ts FROM record WHERE string::lowercase(key) CONTAINS '{q}' OR string::lowercase(body) CONTAINS '{q}' LIMIT {limit};"
        );
        let v = self.sql(&statement)?;
        surreal_ok(&v)?;
        let rows = v
            .as_array()
            .and_then(|a| a.first())
            .and_then(|s| s.get("result"))
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::new();
        for row in rows {
            out.push(Record {
                id: row
                    .get("id")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string(),
                kind: row
                    .get("kind")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .into(),
                key: row.get("key").and_then(|s| s.as_str()).unwrap_or("").into(),
                body: row
                    .get("body")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .into(),
                ts: row.get("ts").and_then(|n| n.as_i64()).unwrap_or(0),
            });
        }
        Ok(out)
    }
}

fn escape_surreal(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

fn escape_ident(s: &str) -> Result<String, String> {
    let cleaned: String = s.chars().map(|c| if c == '-' { '_' } else { c }).collect();
    if cleaned.is_empty()
        || !cleaned
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err("link name must be letters, digits, or underscore".into());
    }
    Ok(cleaned)
}

fn surreal_ok(v: &serde_json::Value) -> Result<(), String> {
    let Some(arr) = v.as_array() else {
        return Err("surreal response was not a statement list".into());
    };
    for st in arr {
        let status = st.get("status").and_then(|s| s.as_str()).unwrap_or("");
        if status != "OK" {
            let detail = st
                .get("result")
                .map(|r| r.to_string())
                .unwrap_or_else(|| "query failed".into());
            return Err(detail);
        }
    }
    Ok(())
}

fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | data[i + 2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(T[((n >> 6) & 63) as usize] as char);
        out.push(T[(n & 63) as usize] as char);
        i += 3;
    }
    if i < data.len() {
        let left = data.len() - i;
        let mut n = (data[i] as u32) << 16;
        if left == 2 {
            n |= (data[i + 1] as u32) << 8;
        }
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if left == 2 {
            out.push(T[((n >> 6) & 63) as usize] as char);
            out.push('=');
        } else {
            out.push('=');
            out.push('=');
        }
    }
    out
}

#[cfg(feature = "postgres")]
struct Pg {
    client: Mutex<postgres::Client>,
}

#[cfg(feature = "postgres")]
impl Pg {
    fn connect(url: &str) -> Result<Self, String> {
        let mut client =
            postgres::Client::connect(url, postgres::NoTls).map_err(|e| e.to_string())?;
        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS records(
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    key TEXT NOT NULL,
                    body TEXT NOT NULL,
                    ts BIGINT NOT NULL);
                 CREATE TABLE IF NOT EXISTS links(
                    src TEXT NOT NULL,
                    rel TEXT NOT NULL,
                    dst TEXT NOT NULL,
                    PRIMARY KEY(src, rel, dst));",
            )
            .map_err(|e| e.to_string())?;
        Ok(Pg {
            client: Mutex::new(client),
        })
    }
}

#[cfg(feature = "postgres")]
impl Driver for Pg {
    fn put(&self, kind: &str, key: &str, body: &str) -> Result<String, String> {
        let id = record_id(kind, key);
        let ts = now();
        let mut client = self.client.lock().map_err(|e| e.to_string())?;
        client
            .execute(
                "INSERT INTO records(id,kind,key,body,ts) VALUES($1,$2,$3,$4,$5)
                 ON CONFLICT(id) DO UPDATE SET body=EXCLUDED.body, ts=EXCLUDED.ts",
                &[&id, &kind, &key, &body, &ts],
            )
            .map_err(|e| e.to_string())?;
        Ok(id)
    }

    fn link(&self, from: &str, rel: &str, to: &str) -> Result<(), String> {
        let mut client = self.client.lock().map_err(|e| e.to_string())?;
        client
            .execute(
                "INSERT INTO links(src,rel,dst) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
                &[&from, &rel, &to],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn search(&self, query: &str, limit: usize) -> Result<Vec<Record>, String> {
        let mut client = self.client.lock().map_err(|e| e.to_string())?;
        let rows = client
            .query(
                "SELECT id,kind,key,body,ts FROM records
                 WHERE key ILIKE $1 OR body ILIKE $1
                 ORDER BY ts DESC LIMIT $2",
                &[&like_pattern(query), &(limit as i64)],
            )
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(Record {
                id: row.get(0),
                kind: row.get(1),
                key: row.get(2),
                body: row.get(3),
                ts: row.get(4),
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_roundtrip_links_and_search() {
        let path =
            std::env::temp_dir().join(format!("argus-db-{}-{}.db", std::process::id(), now()));
        let db = Sqlite::open(&path).unwrap();
        let id = db
            .put("domain", "example.com", "{\"title\":\"Example\"}")
            .unwrap();
        assert_eq!(id, "domain:example.com");
        db.link(&id, "resolves", "ip:203.0.113.10").unwrap();
        let hits = db.search("Example", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].key, "example.com");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn surreal_url_keeps_namespace() {
        let s = Surreal::connect("surreal://root:root@127.0.0.1:8000/argus/argus").unwrap();
        assert_eq!(s.endpoint, "http://127.0.0.1:8000/sql");
        assert_eq!(s.ns, "argus");
        assert_eq!(s.db, "argus");
        assert!(s.auth.starts_with("Basic "));
    }
}
