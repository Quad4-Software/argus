//! Registry-side image audit: OCI distribution API, no docker/podman needed.
//! Fetches manifest + config blob: env, labels, history, root user, age.
//! Layer blobs are not downloaded (size); deep scans still need a runtime.

use crate::finding::{Finding, Severity};

struct Ref {
    registry: String,
    repo: String,
    tag: String,
}

/// `nginx:latest` -> registry-1.docker.io/library/nginx
/// `ghcr.io/org/img:v1` -> ghcr.io/org/img
fn parse(r: &str) -> Option<Ref> {
    let mut name = r;
    let mut tag = "latest".to_string();
    if let Some(i) = name.rfind(':') {
        let after = &name[i + 1..];
        if !after.contains('/') {
            tag = after.to_string();
            name = &name[..i];
        }
    }
    let mut registry = "registry-1.docker.io".to_string();
    let mut repo = name.to_string();
    if let Some(i) = name.find('/') {
        let first = &name[..i];
        if first.contains('.') || first == "localhost" {
            registry = first.to_string();
            repo = name[i + 1..].to_string();
        }
    }
    if registry == "registry-1.docker.io" && !repo.contains('/') {
        repo = format!("library/{repo}");
    }
    if repo.is_empty() {
        return None;
    }
    Some(Ref {
        registry,
        repo,
        tag,
    })
}

/// Bearer token for the standard anonymous OAuth flow.
fn token_for(http: &crate::http::HttpClient, challenge: &str) -> Option<String> {
    // WWW-Authenticate: Bearer realm="..",service="..",scope=".."
    let realm = field(challenge, "realm")?;
    let mut url = realm.to_string();
    let mut sep = '?';
    for k in ["service", "scope"] {
        if let Some(v) = field(challenge, k) {
            url = format!("{url}{sep}{k}={v}");
            sep = '&';
        }
    }
    let body = http.get(&url).ok()?;
    serde_json::from_str::<serde_json::Value>(&body).ok()?["token"]
        .as_str()
        .map(str::to_string)
}

fn field<'a>(h: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("{key}=\"");
    let i = h.find(&pat)? + pat.len();
    let rest = &h[i..];
    let e = rest.find('"')?;
    Some(&rest[..e])
}

/// Audit a registry image reference. Returns findings + image meta.
pub fn audit_remote(
    http: &crate::http::HttpClient,
    image: &str,
    verbose: u8,
) -> Result<Vec<Finding>, String> {
    let r = parse(image).ok_or_else(|| format!("bad image ref {image}"))?;
    let base = format!("https://{}/v2/{}", r.registry, r.repo);
    let accept = "application/vnd.docker.distribution.manifest.v2+json,\
                  application/vnd.docker.distribution.manifest.list.v2+json,\
                  application/vnd.oci.image.manifest.v1+json,\
                  application/vnd.oci.image.index.v1+json";
    let mut token: Option<String> = None;
    let mut manifest = String::new();
    for attempt in 0..2 {
        let url = format!("{base}/manifests/{}", r.tag);
        let mut headers = vec![("accept".into(), accept.to_string())];
        if let Some(t) = &token {
            headers.push(("authorization".into(), format!("Bearer {t}")));
        }
        match http.get_headers(&url, &headers) {
            Ok((200, body)) => {
                manifest = body.text;
                break;
            }
            Ok((401, body)) if attempt == 0 => {
                let ch = body.challenge.unwrap_or_default();
                token = token_for(http, &ch);
                if token.is_none() {
                    return Err(format!("{image}: registry auth failed"));
                }
            }
            Ok((s, _)) => return Err(format!("{image}: registry returned {s}")),
            Err(e) => return Err(format!("{image}: {e}")),
        }
    }
    if manifest.is_empty() {
        return Err(format!("{image}: no manifest"));
    }
    let m: serde_json::Value =
        serde_json::from_str(&manifest).map_err(|e| format!("manifest: {e}"))?;
    // index/manifest list: pick first linux/amd64 entry (or the first entry)
    let mut dig = m["config"]["digest"].as_str().map(str::to_string);
    if dig.is_none()
        && let Some(ms) = m["manifests"].as_array()
    {
        let pick = ms
            .iter()
            .find(|x| {
                let p = &x["platform"];
                p["os"].as_str() == Some("linux") && p["architecture"].as_str() == Some("amd64")
            })
            .or_else(|| ms.first());
        if let Some(x) = pick {
            // fetch that manifest, then its config digest
            let d2 = x["digest"].as_str().unwrap_or_default().to_string();
            let mut headers = vec![("accept".into(), accept.to_string())];
            if let Some(t) = &token {
                headers.push(("authorization".into(), format!("Bearer {t}")));
            }
            let url = format!("{base}/manifests/{d2}");
            if let Ok((200, b)) = http.get_headers(&url, &headers) {
                let m2: serde_json::Value = serde_json::from_str(&b.text).unwrap_or_default();
                dig = m2["config"]["digest"].as_str().map(str::to_string);
            }
        }
    }
    let cdigest = dig.ok_or("manifest had no config digest")?;
    let mut headers = Vec::new();
    if let Some(t) = &token {
        headers.push(("authorization".into(), format!("Bearer {t}")));
    }
    let (st, cfg) = http.get_headers(&format!("{base}/blobs/{cdigest}"), &headers)?;
    if st != 200 {
        return Err(format!("config blob returned {st}"));
    }
    if verbose > 0 {
        eprintln!("image: remote config {cdigest}");
    }
    let v: serde_json::Value =
        serde_json::from_str(&cfg.text).map_err(|e| format!("config: {e}"))?;
    Ok(config_findings(image, &v, &r.tag))
}

fn config_findings(image: &str, v: &serde_json::Value, tag: &str) -> Vec<Finding> {
    let t = format!("img:{image}");
    let mk = |id: &str, sev: Severity, msg: String, rem: &str| Finding {
        ruleset: "image".into(),
        rule_id: id.into(),
        severity: sev,
        target: t.clone(),
        path: image.into(),
        line: None,
        excerpt: None,
        message: msg,
        remediation: Some(rem.into()),
        reference: None,
        window: None,
    };
    let mut out = Vec::new();
    let cfg = &v["config"];
    if tag == "latest" {
        out.push(mk(
            "IMG-001",
            Severity::Medium,
            "image referenced by :latest - unpinned releases drift".into(),
            "Pin a version tag or digest.",
        ));
    }
    if cfg["User"]
        .as_str()
        .is_none_or(|u| u.is_empty() || u == "0" || u == "root")
    {
        out.push(mk(
            "IMG-002",
            Severity::High,
            "image runs as root (no USER configured)".into(),
            "Set a non-root USER in the Dockerfile.",
        ));
    }
    // env secrets
    if let Some(env) = cfg["Env"].as_array() {
        for e in env {
            let e = e.as_str().unwrap_or_default();
            let (k, val) = e.split_once('=').unwrap_or((e, ""));
            if crate::container_audit::secretish(k) && !val.is_empty() && !val.starts_with('$') {
                out.push(mk(
                    "IMG-005",
                    Severity::Critical,
                    format!("image env bakes a literal {k} - secret ships inside the image"),
                    "Inject secrets at runtime; rotate anything already published.",
                ));
            }
        }
    }
    // history secret scan
    if let Some(h) = v["history"].as_array() {
        let re = regex::Regex::new(
            "(?i)\\b(password|passwd|secret|token|api[_-]?key|auth)\\b\\s*[=:]\\s*[^\\s'\"]+|BEGIN [A-Z ]*PRIVATE KEY",
        )
        .unwrap();
        for h in h {
            let cb = h["created_by"].as_str().unwrap_or_default();
            if re.is_match(cb) {
                out.push(mk(
                    "IMG-004",
                    Severity::Critical,
                    format!(
                        "build history embeds secret-like content: {}",
                        &cb[..cb.len().min(120)]
                    ),
                    "Rebuild without secrets (--secret mounts); rotate anything exposed.",
                ));
            }
        }
    }
    // age from config.created
    if let Some(created) = v["created"].as_str()
        && let Some(days) = days_since(created)
        && days > 365
    {
        out.push(mk(
            "IMG-003",
            Severity::Low,
            format!("image is {days} days old - likely stale base packages"),
            "Rebuild on a current base and rescan.",
        ));
    }
    out
}

fn days_since(ts: &str) -> Option<u64> {
    // 2024-01-02T03:04:05.123Z
    let (date, _) = ts.split_once('T')?;
    let p: Vec<u64> = date.split('-').filter_map(|x| x.parse().ok()).collect();
    if p.len() < 3 {
        return None;
    }
    let (y, m, d) = (p[0], p[1], p[2]);
    let days = (y * 365 + m * 30 + d) as i64;
    let now = {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        let (ny, nm, nd) = epoch_to_ymd(t.as_secs());
        ny * 365 + nm * 30 + nd
    } as i64;
    Some((now - days).max(0) as u64)
}

fn epoch_to_ymd(secs: u64) -> (u64, u64, u64) {
    let days = secs / 86400;
    let mut y = 1970u64;
    let mut d = days;
    loop {
        let dy = if y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400)) {
            366
        } else {
            365
        };
        if d < dy {
            break;
        }
        d -= dy;
        y += 1;
    }
    let leap = y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let mut m = 1u64;
    for ml in [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ] {
        if d < ml {
            break;
        }
        d -= ml;
        m += 1;
    }
    (y, m, d + 1)
}
