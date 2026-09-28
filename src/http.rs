//! Minimal JSON-over-HTTPS helper built on ureq.

use std::time::Duration;

/// Response body for get_raw: text plus the WWW-Authenticate challenge
/// (registries send 401 + Bearer realm for anonymous token flow).
pub struct RawBody {
    pub text: String,
    pub challenge: Option<String>,
}

pub struct HttpClient {
    agent: ureq::Agent,
    headers: Vec<(String, String)>,
}

struct HttpErr {
    msg: String,
    retryable: bool,
    retry_after: Option<u64>,
}

impl HttpClient {
    pub fn new(headers: Vec<(String, String)>) -> Self {
        let config = ureq::config::Config::builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false) // we read status+headers ourselves
            .user_agent(concat!("argus/", env!("CARGO_PKG_VERSION")))
            .build();
        HttpClient {
            agent: ureq::Agent::new_with_config(config),
            headers,
        }
    }

    /// GET url, parse the body as JSON. Retries transient failures
    /// (429/5xx/connect/timeouts) with backoff + Retry-After; surfaces
    /// rate-limit and offline diagnostics in the error text.
    pub fn get_json(&self, url: &str) -> Result<serde_json::Value, String> {
        let mut last = String::new();
        for attempt in 0..3u32 {
            match self.get_once(url) {
                Ok(v) => return Ok(v),
                Err(e) if e.retryable && attempt < 2 => {
                    let wait = e.retry_after.unwrap_or(1 << attempt); // 1s, 2s
                    std::thread::sleep(Duration::from_secs(wait.min(30)));
                    last = e.msg;
                    continue;
                }
                Err(e) => return Err(e.msg),
            }
        }
        Err(last)
    }

    /// Raw GET with extra request headers; returns
    /// (status, body, www-authenticate header if present).
    pub fn get_raw(&self, url: &str, extra: &[(String, String)]) -> Result<(u16, RawBody), String> {
        let mut req = self.agent.get(url);
        for (k, v) in &self.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        for (k, v) in extra {
            req = req.header(k.as_str(), v.as_str());
        }
        let mut resp = req.call().map_err(|e| format!("{url}: {e}"))?;
        let status = resp.status().as_u16();
        let challenge = resp
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| format!("{url}: {e}"))?;
        Ok((
            status,
            RawBody {
                text: body,
                challenge,
            },
        ))
    }

    /// Plain-text GET.
    pub fn get(&self, url: &str) -> Result<String, String> {
        let (st, b) = self.get_raw(url, &[])?;
        if st == 200 {
            Ok(b.text)
        } else {
            Err(format!("{url}: {st}"))
        }
    }

    /// GET with custom headers, returns (status, RawBody).
    pub fn get_headers(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<(u16, RawBody), String> {
        self.get_raw(url, headers)
    }

    fn get_once(&self, url: &str) -> Result<serde_json::Value, HttpErr> {
        let mut req = self.agent.get(url);
        for (k, v) in &self.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let resp = match req.call() {
            Ok(r) => r,
            Err(e) => return Err(transport_err(url, &e)),
        };
        parse_resp(url, resp)
    }

    /// GET url, returning (status, parsed-body-or-Null). Unlike get_json,
    /// 4xx responses are returned as data so callers can distinguish
    /// "resource absent" (404) from "cannot determine" (401/403).
    pub fn get_status_json(&self, url: &str) -> Result<(u16, serde_json::Value), String> {
        let mut last = String::new();
        for attempt in 0..3u32 {
            match self.get_once_status(url) {
                Ok(v) => return Ok(v),
                Err(e) if e.retryable && attempt < 2 => {
                    let wait = e.retry_after.unwrap_or(1 << attempt);
                    std::thread::sleep(Duration::from_secs(wait.min(30)));
                    last = e.msg;
                    continue;
                }
                Err(e) => return Err(e.msg),
            }
        }
        Err(last)
    }

    fn get_once_status(&self, url: &str) -> Result<(u16, serde_json::Value), HttpErr> {
        let mut req = self.agent.get(url);
        for (k, v) in &self.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let mut resp = match req.call() {
            Ok(r) => r,
            Err(e) => return Err(transport_err(url, &e)),
        };
        let status = resp.status().as_u16();
        // 4xx: caller inspects the status; do not retry or error
        if (400..500).contains(&status) {
            let _ = resp.body_mut().read_to_string();
            return Ok((status, serde_json::Value::Null));
        }
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());
        if status >= 500 || status == 429 {
            return Err(http_status_err(url, status, retry_after));
        }
        let body = resp.body_mut().read_to_string().map_err(|e| HttpErr {
            msg: format!("{url}: read body: {e}"),
            retryable: true,
            retry_after: None,
        })?;
        let v = serde_json::from_str(&body).map_err(|e| HttpErr {
            msg: format!("{url}: bad JSON: {e} (API response format may have changed)"),
            retryable: false,
            retry_after: None,
        })?;
        Ok((status, v))
    }

    /// Paginated GET: appends &page=N (or ?page=N) until a page returns
    /// fewer than per_page array entries. Concatenates all items.
    pub fn get_paged(
        &self,
        base_url: &str,
        per_page: usize,
    ) -> Result<Vec<serde_json::Value>, String> {
        let mut out = Vec::new();
        let sep = if base_url.contains('?') { '&' } else { '?' };
        for page in 1..=1000usize {
            let url = format!("{base_url}{sep}per_page={per_page}&page={page}");
            let v = self.get_json(&url)?;
            let arr = match &v {
                serde_json::Value::Array(a) => a.clone(),
                other => {
                    return Err(format!(
                        "{url}: expected JSON array, got {}",
                        kind_of(other)
                    ));
                }
            };
            let n = arr.len();
            out.extend(arr);
            if n < per_page {
                break;
            }
        }
        Ok(out)
    }

    /// POST JSON body, return parsed JSON response. One retry on transient.
    pub fn post_json(&self, url: &str, body: &str) -> Result<serde_json::Value, String> {
        let mut last = String::new();
        for attempt in 0..2u32 {
            let mut req = self
                .agent
                .post(url)
                .header("Content-Type", "application/json");
            for (k, v) in &self.headers {
                req = req.header(k.as_str(), v.as_str());
            }
            match req.send(body) {
                Ok(resp) => return parse_resp(url, resp).map_err(|e| e.msg),
                Err(e) => {
                    let he = transport_err(url, &e);
                    if !he.retryable || attempt == 1 {
                        return Err(he.msg);
                    }
                    last = he.msg;
                }
            }
        }
        Err(last)
    }
}

fn http_status_err(url: &str, code: u16, retry_after: Option<u64>) -> HttpErr {
    let retryable = matches!(code, 429 | 500 | 502 | 503 | 504);
    let detail = match code {
        401 | 403 => "auth required or token invalid (set --token / provider env)",
        404 => "not found (org/user name or host wrong?)",
        429 => "rate limited",
        _ => "",
    };
    HttpErr {
        msg: format!("{url}: HTTP {code} {detail}").trim().to_string(),
        retryable,
        retry_after,
    }
}

fn transport_err(url: &str, e: &ureq::Error) -> HttpErr {
    let s = e.to_string();
    let offline_hint = s.contains("resolve")
        || s.contains("dns")
        || s.contains("refused")
        || s.contains("unreachable")
        || s.contains("timed out")
        || s.contains("Connect");
    HttpErr {
        msg: if offline_hint {
            format!("{url}: {s} (network unreachable or offline; local scans still work)")
        } else {
            format!("{url}: {s}")
        },
        retryable: true,
        retry_after: None,
    }
}

/// Read a 200-range response body as JSON.
fn parse_resp(
    url: &str,
    mut resp: ureq::http::Response<ureq::Body>,
) -> Result<serde_json::Value, HttpErr> {
    let status = resp.status().as_u16();
    let retry_after = resp
        .headers()
        .get("retry-after")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse().ok());
    let ratelimit_zero = resp
        .headers()
        .get("x-ratelimit-remaining")
        .and_then(|h| h.to_str().ok())
        == Some("0");
    let body = resp.body_mut().read_to_string().map_err(|e| HttpErr {
        msg: format!("{url}: read body: {e}"),
        retryable: true,
        retry_after: None,
    })?;
    if status >= 400 {
        let mut e = http_status_err(url, status, retry_after);
        if status == 403 && ratelimit_zero {
            e.msg = format!("{url}: rate limited (x-ratelimit-remaining: 0)");
            e.retryable = retry_after.is_some();
        }
        e.msg = format!("{} :: {}", e.msg, &body[..body.len().min(200)]);
        return Err(e);
    }
    serde_json::from_str(&body).map_err(|e| HttpErr {
        msg: format!("{url}: bad JSON: {e} (API response format may have changed)"),
        retryable: false,
        retry_after: None,
    })
}

fn kind_of(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}
