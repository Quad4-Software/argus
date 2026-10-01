// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Optional local IP geolocation database.
//! The file is DB-IP City Lite under CC BY 4.0. Lookups name that source.

use super::intel::geo_hit;
use super::{Hit, Status};
use flate2::read::GzDecoder;
use serde::Deserialize;
use serde_json::json;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_BYTES: u64 = 250 * 1024 * 1024;
const NOTICE: &str = "\
DB-IP City Lite
https://db-ip.com/
Licensed under Creative Commons Attribution 4.0 International
https://creativecommons.org/licenses/by/4.0/
Results that use this file must keep the DB-IP attribution.
";

pub fn db_path() -> PathBuf {
    crate::cache::cache_dir().join("dbip-city-lite.mmdb")
}

pub fn has_db() -> bool {
    db_path().is_file()
}

pub fn download() -> Result<PathBuf, String> {
    let dir = crate::cache::cache_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("geo cache: {e}"))?;
    let (year, month) = year_month(now_secs());
    let months = [format!("{year:04}-{month:02}"), prev_month(year, month)];
    let mut last = String::from("no database");
    for stamp in &months {
        let url = format!("https://download.db-ip.com/free/dbip-city-lite-{stamp}.mmdb.gz");
        match fetch_month(&dir, &url, stamp) {
            Ok(path) => return Ok(path),
            Err(e) if e.contains("HTTP 404") => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

pub fn lookup(ip: &str) -> Hit {
    let path = db_path();
    if !path.is_file() {
        return Hit::new(
            "geo",
            Status::Absent,
            "no local geolocation database. Pass --download to fetch DB-IP City Lite",
            None,
        );
    }
    let parsed: IpAddr = match ip.parse() {
        Ok(ip) => ip,
        Err(_) => return Hit::new("geo", Status::Error, "not an address", None),
    };
    let reader = match maxminddb::Reader::open_readfile(&path) {
        Ok(r) => r,
        Err(e) => return Hit::new("geo", Status::Error, e.to_string(), None),
    };
    let found = match reader.lookup(parsed) {
        Ok(r) => r,
        Err(e) => return Hit::new("geo", Status::Error, e.to_string(), None),
    };
    let place: Option<Place> = match found.decode() {
        Ok(p) => p,
        Err(e) => return Hit::new("geo", Status::Error, e.to_string(), None),
    };
    let Some(place) = place else {
        return Hit::new(
            "geo",
            Status::Absent,
            "no city record for this address",
            Some(json!({"source": source_name()})),
        );
    };
    let country = en_name(place.country.as_ref().map(|c| &c.names));
    let code = place
        .country
        .as_ref()
        .and_then(|c| c.iso_code.clone())
        .unwrap_or_default();
    let region = place
        .subdivisions
        .as_ref()
        .and_then(|s| s.first())
        .map(|s| en_name(Some(&s.names)))
        .unwrap_or_default();
    let city = en_name(place.city.as_ref().map(|c| &c.names));
    let (lat, lon, tz) = place
        .location
        .as_ref()
        .map(|l| {
            (
                l.latitude,
                l.longitude,
                l.time_zone.clone().unwrap_or_default(),
            )
        })
        .unwrap_or((None, None, String::new()));
    let flat = json!({
        "country": country,
        "country_code": code,
        "region": region,
        "city": city,
        "latitude": lat,
        "longitude": lon,
        "timezone": tz,
    });
    let mut hit = geo_hit("geo", &source_name(), &flat, true);
    if let Some(ev) = hit.evidence.as_mut()
        && let Ok(month) = std::fs::read_to_string(path.with_extension("month"))
    {
        ev["month"] = json!(month.trim());
    }
    hit
}

fn source_name() -> String {
    "DB-IP City Lite, CC BY 4.0, https://db-ip.com/".into()
}

fn fetch_month(dir: &Path, url: &str, stamp: &str) -> Result<PathBuf, String> {
    let config = ureq::config::Config::builder()
        .timeout_global(Some(Duration::from_secs(180)))
        .http_status_as_error(false)
        .https_only(true)
        .max_redirects(2)
        .user_agent(concat!("argus/", env!("CARGO_PKG_VERSION")))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut resp = agent
        .get(url)
        .call()
        .map_err(|e| format!("geo download: {e}"))?;
    let status = resp.status().as_u16();
    if status == 404 {
        return Err(format!("geo download HTTP 404 for {stamp}"));
    }
    if status != 200 {
        return Err(format!("geo download HTTP {status}"));
    }
    let gz_path = dir.join("dbip-city-lite.mmdb.gz.partial");
    let mmdb_path = dir.join("dbip-city-lite.mmdb.partial");
    let final_path = db_path();
    let gz_file = std::fs::File::create(&gz_path).map_err(|e| format!("geo cache: {e}"))?;
    let mut limited = Limited::new(resp.body_mut().as_reader(), MAX_BYTES);
    io::copy(&mut limited, &mut std::io::BufWriter::new(gz_file))
        .map_err(|e| cleanup(&gz_path, &mmdb_path, e.to_string()))?;
    let gz = std::fs::File::open(&gz_path).map_err(|e| format!("geo cache: {e}"))?;
    let mut magic = [0u8; 2];
    (&gz)
        .read(&mut magic)
        .map_err(|e| format!("geo cache: {e}"))?;
    if magic != [0x1f, 0x8b] {
        let _ = std::fs::remove_file(&gz_path);
        return Err("geolocation download was not gzip".into());
    }
    let gz = std::fs::File::open(&gz_path).map_err(|e| format!("geo cache: {e}"))?;
    let decoder = GzDecoder::new(gz);
    let mut out = std::fs::File::create(&mmdb_path).map_err(|e| format!("geo cache: {e}"))?;
    io::copy(&mut Limited::new(decoder, MAX_BYTES), &mut out)
        .map_err(|e| cleanup(&gz_path, &mmdb_path, e.to_string()))?;
    out.flush().map_err(|e| format!("geo cache: {e}"))?;
    std::fs::rename(&mmdb_path, &final_path).map_err(|e| format!("geo cache: {e}"))?;
    let _ = std::fs::remove_file(&gz_path);
    let _ = std::fs::write(final_path.with_extension("month"), format!("{stamp}\n"));
    let _ = std::fs::write(dir.join("dbip-city-lite.NOTICE"), NOTICE);
    Ok(final_path)
}

fn cleanup(gz: &Path, mmdb: &Path, err: String) -> String {
    let _ = std::fs::remove_file(gz);
    let _ = std::fs::remove_file(mmdb);
    err
}

fn en_name(names: Option<&std::collections::BTreeMap<String, String>>) -> String {
    names.and_then(|n| n.get("en").cloned()).unwrap_or_default()
}

#[derive(Deserialize)]
struct Place {
    country: Option<Country>,
    city: Option<Named>,
    subdivisions: Option<Vec<Named>>,
    location: Option<Loc>,
}

#[derive(Deserialize)]
struct Country {
    iso_code: Option<String>,
    #[serde(default)]
    names: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Named {
    #[serde(default)]
    names: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Loc {
    latitude: Option<f64>,
    longitude: Option<f64>,
    time_zone: Option<String>,
}

struct Limited<R> {
    inner: R,
    left: u64,
}

impl<R> Limited<R> {
    fn new(inner: R, left: u64) -> Self {
        Limited { inner, left }
    }
}

impl<R: Read> Read for Limited<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "geolocation database is larger than 250 MB",
            ));
        }
        let max = buf.len().min(self.left as usize);
        let n = self.inner.read(&mut buf[..max])?;
        self.left -= n as u64;
        Ok(n)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn year_month(unix_secs: u64) -> (i32, u32) {
    let z = (unix_secs / 86400) as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32)
}

fn prev_month(year: i32, month: u32) -> String {
    let (y, m) = if month <= 1 {
        (year - 1, 12)
    } else {
        (year, month - 1)
    };
    format!("{y:04}-{m:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_month_from_unix() {
        assert_eq!(year_month(0), (1970, 1));
        assert_eq!(year_month(1_788_220_800), (2026, 9));
    }
}
