// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Outbound webhooks for automation.
//! A hook is an http or https URL from config. Link-local targets are refused.
//! Set ARGUS_WEBHOOK_SECRET to sign the body with HMAC-SHA256.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub fn notify(event: &str, payload: &serde_json::Value) {
    let Ok((cfg, _)) = crate::config::load(None) else {
        return;
    };
    if cfg.webhooks.is_empty() {
        return;
    }
    let body = serde_json::json!({
        "event": event,
        "payload": payload,
    });
    let raw = serde_json::to_string(&body).unwrap_or_default();
    for hook in &cfg.webhooks {
        if !hook.events.is_empty() && !hook.events.iter().any(|e| e == event) {
            continue;
        }
        if let Err(e) = post(&hook.url, &raw) {
            eprintln!("webhook: {e}");
        }
    }
}

fn post(url: &str, body: &str) -> Result<(), String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("webhook url must be http or https".into());
    }
    if url_is_link_local(url) {
        return Err("refusing a link-local webhook".into());
    }
    let config = ureq::config::Config::builder()
        .timeout_global(Some(std::time::Duration::from_secs(6)))
        .http_status_as_error(false)
        .user_agent(concat!("argus/", env!("CARGO_PKG_VERSION")))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut req = agent.post(url).header("Content-Type", "application/json");
    if let Ok(secret) = std::env::var("ARGUS_WEBHOOK_SECRET")
        && !secret.is_empty()
    {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|e| e.to_string())?;
        mac.update(body.as_bytes());
        let sig = mac.finalize().into_bytes();
        let hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
        req = req.header("X-Argus-Signature", &format!("sha256={hex}"));
    }
    let resp = req.send(body).map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(format!("{url} HTTP {status}"));
    }
    Ok(())
}

fn url_is_link_local(url: &str) -> bool {
    let rest = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    host == "169.254.169.254" || host.starts_with("169.254.")
}
