// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Streaming search over text, CSV, JSON, JSONL, and SQLite.
//! Matches are printed as they are found. The file is not loaded whole,
//! rows are not accumulated, and nothing is uploaded or written back.
//! SQLite is opened read-only. Table and column names are checked before
//! they are quoted. Values stay in bound parameters.

use crate::extract::{self, Pick};
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;

const LINE_CAP: usize = 1024 * 1024;
const SHOW: usize = 240;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Auto,
    Text,
    Csv,
    Tsv,
    Json,
    Jsonl,
    Sqlite,
}

pub struct Query {
    pub pattern: Option<Regex>,
    pub pick: Option<Pick>,
    pub column: Option<String>,
    pub eq: Option<String>,
    pub kind: Kind,
    pub table: Option<String>,
    pub max: usize,
    pub json: bool,
}

pub fn positionals(
    pattern: Option<String>,
    mut paths: Vec<std::path::PathBuf>,
    filtered: bool,
) -> (Option<String>, Vec<std::path::PathBuf>) {
    if pattern.is_some() || filtered || paths.is_empty() {
        return (pattern, paths);
    }
    let first = paths.remove(0);
    (Some(first.to_string_lossy().into_owned()), paths)
}

pub fn run(paths: &[std::path::PathBuf], query: &Query) -> Result<usize, String> {
    if paths.is_empty() {
        return Err("pass at least one file".into());
    }
    if query.pattern.is_none() && query.pick.is_none() && query.eq.is_none() {
        return Err("pass a pattern, --pick, or --eq".into());
    }
    let mut total = 0usize;
    let mut files = 0usize;
    for path in paths {
        if path.as_os_str() == "-" {
            files += 1;
            total += scan_reader(path, &mut std::io::stdin().lock(), query, &mut 0, total)?;
            continue;
        }
        if !path.exists() {
            return Err(format!("path not found: {}", path.display()));
        }
        if path.is_file() {
            files += 1;
            total += scan_file(path, query, total)?;
        } else {
            walk(path, query, &mut files, &mut total)?;
        }
        if query.max > 0 && total >= query.max {
            break;
        }
    }
    eprintln!("grep: {total} match(es) in {files} file(s)");
    Ok(total)
}

fn walk(dir: &Path, query: &Query, files: &mut usize, total: &mut usize) -> Result<(), String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        if query.max > 0 && *total >= query.max {
            return Ok(());
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".git" || name == "node_modules" || name == "target" || name == "vendor" {
            continue;
        }
        if path.is_dir() {
            walk(&path, query, files, total)?;
            continue;
        }
        *files += 1;
        *total += scan_file(&path, query, *total)?;
    }
    Ok(())
}

fn scan_file(path: &Path, query: &Query, already: usize) -> Result<usize, String> {
    let kind = resolve_kind(path, query.kind);
    if kind == Kind::Sqlite {
        return scan_sqlite(path, query, already);
    }
    let file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    if looks_binary(&mut reader)? {
        return Ok(0);
    }
    scan_reader(path, &mut reader, query, &mut 0, already)
}

fn scan_reader(
    path: &Path,
    reader: &mut dyn BufRead,
    query: &Query,
    _line_base: &mut u64,
    already: usize,
) -> Result<usize, String> {
    let kind = if path.as_os_str() == "-" {
        if query.kind == Kind::Auto {
            Kind::Text
        } else {
            query.kind
        }
    } else {
        resolve_kind(path, query.kind)
    };
    match kind {
        Kind::Csv => scan_delim(path, reader, b',', query, already),
        Kind::Tsv => scan_delim(path, reader, b'\t', query, already),
        Kind::Jsonl => scan_jsonl(path, reader, query, already),
        Kind::Json => scan_json(path, reader, query, already),
        Kind::Sqlite => Ok(0),
        Kind::Auto | Kind::Text => scan_text(path, reader, query, already),
    }
}

fn scan_text(
    path: &Path,
    reader: &mut dyn BufRead,
    query: &Query,
    already: usize,
) -> Result<usize, String> {
    let mut hits = 0usize;
    let mut line_no = 0u64;
    loop {
        if query.max > 0 && already + hits >= query.max {
            break;
        }
        line_no += 1;
        match read_line_capped(reader)? {
            None => break,
            Some(None) => continue,
            Some(Some(line)) => {
                for text in line_hits(&line, query) {
                    hits += 1;
                    emit(path, line_no, &text, query.json);
                    if query.max > 0 && already + hits >= query.max {
                        return Ok(hits);
                    }
                }
            }
        }
    }
    Ok(hits)
}

fn scan_delim(
    path: &Path,
    reader: &mut dyn BufRead,
    sep: u8,
    query: &Query,
    already: usize,
) -> Result<usize, String> {
    let Some(header) = read_record(reader, sep)? else {
        return Ok(0);
    };
    let col = query.column.as_deref();
    let idx = if let Some(name) = col {
        header
            .iter()
            .position(|h| h == name)
            .ok_or_else(|| format!("{}: no column {name}", path.display()))?
    } else if query.eq.is_some() && query.pick.is_none() && query.pattern.is_none() {
        return Err("csv and json filters need --column".into());
    } else {
        usize::MAX
    };
    let mut hits = 0usize;
    let mut line_no = 1u64;
    while let Some(rec) = read_record(reader, sep)? {
        line_no += 1;
        if query.max > 0 && already + hits >= query.max {
            break;
        }
        let field = if idx == usize::MAX {
            rec.join(if sep == b'\t' { "\t" } else { "," })
        } else {
            rec.get(idx).cloned().unwrap_or_default()
        };
        for text in line_hits(&field, query) {
            hits += 1;
            emit(path, line_no, &text, query.json);
            if query.max > 0 && already + hits >= query.max {
                return Ok(hits);
            }
        }
    }
    Ok(hits)
}

fn scan_jsonl(
    path: &Path,
    reader: &mut dyn BufRead,
    query: &Query,
    already: usize,
) -> Result<usize, String> {
    let mut hits = 0usize;
    let mut line_no = 0u64;
    loop {
        if query.max > 0 && already + hits >= query.max {
            break;
        }
        line_no += 1;
        match read_line_capped(reader)? {
            None => break,
            Some(None) => continue,
            Some(Some(line)) => {
                let text = json_field(&line, query.column.as_deref()).unwrap_or(line);
                for hit in line_hits(&text, query) {
                    hits += 1;
                    emit(path, line_no, &hit, query.json);
                    if query.max > 0 && already + hits >= query.max {
                        return Ok(hits);
                    }
                }
            }
        }
    }
    Ok(hits)
}

fn scan_json(
    path: &Path,
    reader: &mut dyn BufRead,
    query: &Query,
    already: usize,
) -> Result<usize, String> {
    loop {
        let data = reader.fill_buf().map_err(|e| e.to_string())?;
        if data.is_empty() {
            return Ok(0);
        }
        if data[0].is_ascii_whitespace() {
            reader.consume(1);
            continue;
        }
        if data[0] != b'[' {
            return scan_jsonl(path, reader, query, already);
        }
        reader.consume(1);
        break;
    }
    let mut hits = 0usize;
    let mut n = 0u64;
    while let Some(obj) = next_json_value(reader)? {
        n += 1;
        if query.max > 0 && already + hits >= query.max {
            break;
        }
        let text = json_field(&obj, query.column.as_deref()).unwrap_or(obj);
        for hit in line_hits(&text, query) {
            hits += 1;
            emit(path, n, &hit, query.json);
            if query.max > 0 && already + hits >= query.max {
                return Ok(hits);
            }
        }
    }
    Ok(hits)
}

fn scan_sqlite(path: &Path, query: &Query, already: usize) -> Result<usize, String> {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| format!("sqlite {}: {e}", path.display()))?;
    conn.pragma_update(None, "query_only", "ON")
        .map_err(|e| e.to_string())?;
    let tables = if let Some(table) = &query.table {
        vec![ident(table)?]
    } else {
        sqlite_tables(&conn)?
    };
    let mut hits = 0usize;
    for table in tables {
        if query.max > 0 && already + hits >= query.max {
            break;
        }
        let cols = if let Some(col) = &query.column {
            vec![ident(col)?]
        } else {
            sqlite_text_cols(&conn, &table)?
        };
        for col in cols {
            if query.max > 0 && already + hits >= query.max {
                break;
            }
            hits += sqlite_col(&conn, path, &table, &col, query, already + hits)?;
        }
    }
    Ok(hits)
}

fn sqlite_col(
    conn: &rusqlite::Connection,
    path: &Path,
    table: &str,
    col: &str,
    query: &Query,
    already: usize,
) -> Result<usize, String> {
    let sql = if query.eq.is_some() && query.pattern.is_none() && query.pick.is_none() {
        format!("SELECT \"{col}\" FROM \"{table}\" WHERE \"{col}\" = ?1")
    } else {
        format!("SELECT \"{col}\" FROM \"{table}\"")
    };
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let mut rows = if let Some(eq) = &query.eq {
        if query.pattern.is_none() && query.pick.is_none() {
            stmt.query(rusqlite::params![eq])
                .map_err(|e| e.to_string())?
        } else {
            stmt.query([]).map_err(|e| e.to_string())?
        }
    } else {
        stmt.query([]).map_err(|e| e.to_string())?
    };
    let mut hits = 0usize;
    let mut n = 0u64;
    loop {
        let row = rows.next().map_err(|e| e.to_string())?;
        let Some(row) = row else { break };
        n += 1;
        if query.max > 0 && already + hits >= query.max {
            break;
        }
        let val: Option<String> = row.get(0).unwrap_or(None);
        let val = val.unwrap_or_default();
        for text in line_hits(&val, query) {
            hits += 1;
            emit(path, n, &format!("{table}.{col} {text}"), query.json);
            if query.max > 0 && already + hits >= query.max {
                return Ok(hits);
            }
        }
    }
    Ok(hits)
}

fn sqlite_tables(conn: &rusqlite::Connection) -> Result<Vec<String>, String> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        if let Ok(name) = row
            && ident(&name).is_ok()
        {
            out.push(name);
        }
    }
    Ok(out)
}

fn sqlite_text_cols(conn: &rusqlite::Connection, table: &str) -> Result<Vec<String>, String> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info(\"{table}\")"))
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        let Ok((name, ty)) = row else { continue };
        let ty = ty.to_ascii_lowercase();
        if (ty.is_empty() || ty.contains("char") || ty.contains("text") || ty.contains("clob"))
            && ident(&name).is_ok()
        {
            out.push(name);
        }
    }
    Ok(out)
}

fn line_hits(text: &str, query: &Query) -> Vec<String> {
    if let Some(eq) = &query.eq {
        let ok = if query.pattern.is_some() || query.pick.is_some() {
            eq_match(
                text,
                eq,
                query
                    .pattern
                    .as_ref()
                    .map(|r| r.as_str().contains("(?i)"))
                    .unwrap_or(false),
            ) && field_ok(text, query)
        } else {
            eq_match(text, eq, false)
        };
        return if ok { vec![clip(text)] } else { Vec::new() };
    }
    if let Some(pick) = query.pick {
        return extract::pick_in(pick, text)
            .into_iter()
            .filter(|v| query.pattern.as_ref().is_none_or(|re| re.is_match(v)))
            .map(|v| clip(&v))
            .collect();
    }
    if let Some(re) = &query.pattern
        && re.is_match(text)
    {
        return vec![clip(text)];
    }
    Vec::new()
}

fn field_ok(text: &str, query: &Query) -> bool {
    if let Some(pick) = query.pick {
        return !extract::pick_in(pick, text).is_empty();
    }
    if let Some(re) = &query.pattern {
        return re.is_match(text);
    }
    true
}

fn eq_match(text: &str, eq: &str, ignore: bool) -> bool {
    if ignore {
        text.eq_ignore_ascii_case(eq)
    } else {
        text == eq
    }
}

fn json_field(raw: &str, column: Option<&str>) -> Option<String> {
    let column = column?;
    let v: serde_json::Value = serde_json::from_str(raw.trim()).ok()?;
    let cur = if let Some((a, b)) = column.split_once('.') {
        v.get(a)?.get(b)?
    } else {
        v.get(column)?
    };
    Some(match cur {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    })
}

fn emit(path: &Path, line: u64, text: &str, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "path": path.display().to_string(),
                "line": line,
                "text": text,
            })
        );
    } else {
        println!("{}:{line}:{text}", path.display());
    }
}

fn clip(s: &str) -> String {
    let flat: String = s
        .chars()
        .filter(|c| *c != '\n' && *c != '\r')
        .take(SHOW)
        .collect();
    if s.chars().count() > SHOW {
        format!("{flat}...")
    } else {
        flat
    }
}

fn resolve_kind(path: &Path, kind: Kind) -> Kind {
    if kind != Kind::Auto {
        return kind;
    }
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("csv") => Kind::Csv,
        Some("tsv") => Kind::Tsv,
        Some("jsonl") | Some("ndjson") => Kind::Jsonl,
        Some("json") => Kind::Json,
        Some("sqlite" | "sqlite3" | "db") => Kind::Sqlite,
        _ => Kind::Text,
    }
}

fn ident(s: &str) -> Result<String, String> {
    if !s.is_empty() && s.len() <= 80 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Ok(s.to_string())
    } else {
        Err("table and column names must be letters, digits, or underscore".into())
    }
}

fn looks_binary(reader: &mut BufReader<File>) -> Result<bool, String> {
    let buf = reader.fill_buf().map_err(|e| e.to_string())?;
    let n = buf.len().min(8192);
    let binary = buf[..n].contains(&0);
    reader.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    Ok(binary)
}

fn read_line_capped(reader: &mut dyn BufRead) -> Result<Option<Option<String>>, String> {
    let mut buf = Vec::new();
    let mut oversized = false;
    loop {
        let data = reader.fill_buf().map_err(|e| e.to_string())?;
        if data.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }
        if let Some(i) = data.iter().position(|b| *b == b'\n') {
            if !oversized {
                buf.extend_from_slice(&data[..=i]);
            }
            reader.consume(i + 1);
            break;
        }
        if buf.len() + data.len() > LINE_CAP {
            oversized = true;
            buf.clear();
        }
        let n = data.len();
        if !oversized {
            buf.extend_from_slice(data);
        }
        reader.consume(n);
    }
    if oversized {
        return Ok(Some(None));
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    Ok(Some(Some(String::from_utf8_lossy(&buf).into_owned())))
}

fn read_record(reader: &mut dyn BufRead, sep: u8) -> Result<Option<Vec<String>>, String> {
    let mut fields = Vec::new();
    let mut cur = Vec::new();
    let mut in_quotes = false;
    let mut saw = false;
    let mut bytes = 0usize;
    loop {
        let data = reader.fill_buf().map_err(|e| e.to_string())?;
        if data.is_empty() {
            if !saw {
                return Ok(None);
            }
            break;
        }
        let mut i = 0;
        let mut done = false;
        while i < data.len() {
            let c = data[i];
            bytes += 1;
            if bytes > LINE_CAP {
                reader.consume(i + 1);
                return Err("a record is larger than 1 MiB".into());
            }
            if in_quotes {
                if c == b'"' {
                    if data.get(i + 1) == Some(&b'"') {
                        cur.push(b'"');
                        i += 2;
                        continue;
                    }
                    in_quotes = false;
                } else {
                    cur.push(c);
                }
            } else if c == b'"' && cur.is_empty() {
                in_quotes = true;
            } else if c == sep {
                fields.push(String::from_utf8_lossy(&cur).into_owned());
                cur.clear();
            } else if c == b'\n' {
                done = true;
                i += 1;
                break;
            } else if c != b'\r' {
                cur.push(c);
            }
            i += 1;
            saw = true;
        }
        reader.consume(i);
        if done {
            break;
        }
    }
    fields.push(String::from_utf8_lossy(&cur).into_owned());
    Ok(Some(fields))
}

fn next_json_value(reader: &mut dyn BufRead) -> Result<Option<String>, String> {
    let mut buf = Vec::new();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut esc = false;
    let mut started = false;
    loop {
        let data = reader.fill_buf().map_err(|e| e.to_string())?;
        if data.is_empty() {
            return Ok(None);
        }
        let mut i = 0;
        let mut done = false;
        while i < data.len() {
            let c = data[i];
            if !started {
                if c == b',' || c.is_ascii_whitespace() {
                    i += 1;
                    continue;
                }
                if c == b']' {
                    reader.consume(i + 1);
                    return Ok(None);
                }
                started = true;
            }
            if buf.len() > LINE_CAP {
                return Err("a JSON value is larger than 1 MiB".into());
            }
            buf.push(c);
            if in_str {
                if esc {
                    esc = false;
                } else if c == b'\\' {
                    esc = true;
                } else if c == b'"' {
                    in_str = false;
                }
            } else if c == b'"' {
                in_str = true;
            } else if c == b'{' || c == b'[' {
                depth += 1;
            } else if c == b'}' || c == b']' {
                depth -= 1;
                if depth <= 0 {
                    done = true;
                    i += 1;
                    break;
                }
            }
            i += 1;
        }
        reader.consume(i);
        if done {
            break;
        }
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

pub fn compile_pattern(pattern: &str, ignore_case: bool) -> Result<Regex, String> {
    let pat = if ignore_case {
        format!("(?i){pattern}")
    } else {
        pattern.to_string()
    };
    Regex::new(&pat).map_err(|e| format!("pattern: {e}"))
}

pub fn parse_kind(s: &str) -> Result<Kind, String> {
    match s.to_ascii_lowercase().as_str() {
        "auto" => Ok(Kind::Auto),
        "text" | "txt" => Ok(Kind::Text),
        "csv" => Ok(Kind::Csv),
        "tsv" => Ok(Kind::Tsv),
        "json" => Ok(Kind::Json),
        "jsonl" | "ndjson" => Ok(Kind::Jsonl),
        "sqlite" | "sqlite3" | "db" => Ok(Kind::Sqlite),
        _ => Err("kind must be auto, text, csv, tsv, json, jsonl, or sqlite".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    #[test]
    fn first_positional_is_the_regex_until_a_filter_is_set() {
        let (pat, paths) = positionals(
            None,
            vec![PathBuf::from("foo"), PathBuf::from("a.txt")],
            false,
        );
        assert_eq!(pat.as_deref(), Some("foo"));
        assert_eq!(paths, vec![PathBuf::from("a.txt")]);
        let (pat, paths) = positionals(None, vec![PathBuf::from("a.txt")], true);
        assert!(pat.is_none());
        assert_eq!(paths, vec![PathBuf::from("a.txt")]);
        let (pat, paths) = positionals(Some("bar".into()), vec![PathBuf::from("a.txt")], false);
        assert_eq!(pat.as_deref(), Some("bar"));
        assert_eq!(paths, vec![PathBuf::from("a.txt")]);
    }

    fn temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("argus-grep-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let mut f = File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        path
    }

    #[test]
    fn csv_jsonl_and_sqlite_stream_a_column() {
        let csv = temp(
            "rows.csv",
            b"email,note\nada@example.com,hi\nother@example.com,no\n",
        );
        let q = Query {
            pattern: None,
            pick: None,
            column: Some("email".into()),
            eq: Some("ada@example.com".into()),
            kind: Kind::Auto,
            table: None,
            max: 10,
            json: false,
        };
        assert_eq!(run(std::slice::from_ref(&csv), &q).unwrap(), 1);

        let jsonl = temp(
            "rows.jsonl",
            b"{\"email\":\"ada@example.com\"}\n{\"email\":\"no@example.com\"}\n",
        );
        let q = Query {
            pattern: Some(compile_pattern("ada@", false).unwrap()),
            pick: None,
            column: Some("email".into()),
            eq: None,
            kind: Kind::Jsonl,
            table: None,
            max: 10,
            json: false,
        };
        assert_eq!(run(std::slice::from_ref(&jsonl), &q).unwrap(), 1);

        let db = temp("rows.sqlite", b"");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE people (email TEXT); INSERT INTO people VALUES ('ada@example.com');",
        )
        .unwrap();
        drop(conn);
        let q = Query {
            pattern: None,
            pick: None,
            column: Some("email".into()),
            eq: Some("ada@example.com".into()),
            kind: Kind::Sqlite,
            table: Some("people".into()),
            max: 10,
            json: false,
        };
        assert_eq!(run(std::slice::from_ref(&db), &q).unwrap(), 1);
        let _ = std::fs::remove_file(&csv);
        let _ = std::fs::remove_file(&jsonl);
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn a_huge_line_is_skipped() {
        let mut body = vec![b'x'; LINE_CAP + 10];
        body.push(b'\n');
        body.extend(b"keep ada@example.com\n");
        let path = temp("big.txt", &body);
        let q = Query {
            pattern: None,
            pick: Some(Pick::Emails),
            column: None,
            eq: None,
            kind: Kind::Text,
            table: None,
            max: 10,
            json: false,
        };
        assert_eq!(run(std::slice::from_ref(&path), &q).unwrap(), 1);
        let _ = std::fs::remove_file(&path);
    }
}
