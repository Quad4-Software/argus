// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Domain and email OSINT.
//! Records come from public DNS-over-HTTPS, RDAP, certificate logs, and
//! pages the domain itself publishes. A miss is not treated as proof.

mod account;
mod domain;
mod dork;
mod email;
mod favicon;
mod feed;
mod filehash;
mod filters;
mod geo;
mod gitmeta;
mod hash;
mod intel;
mod ip;
mod meta;
mod name;
mod net;
mod policy;
mod ports;
pub(crate) mod siteurl;
mod smtp;
mod socials;
mod surface;
mod threat;
mod trackers;
mod user;
mod waf;

use crate::cli::Format;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Confirmed,
    Absent,
    Inconclusive,
    Error,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Confirmed => "confirmed",
            Status::Absent => "absent",
            Status::Inconclusive => "inconclusive",
            Status::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub module: String,
    pub status: Status,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Value>,
}

impl Hit {
    pub fn new(
        module: &str,
        status: Status,
        summary: impl Into<String>,
        evidence: Option<Value>,
    ) -> Self {
        Hit {
            module: module.to_string(),
            status,
            summary: summary.into(),
            evidence,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub target: String,
    pub kind: &'static str,
    pub elapsed_ms: u64,
    pub findings: Vec<Hit>,
}

pub use account::scan as scan_account;
pub use domain::scan as scan_domain;
pub use dork::scan as scan_dork;
pub use email::scan as scan_email;
pub use favicon::scan as scan_favicon;
pub use feed::scan as scan_feed;
pub use filehash::scan as scan_hash;
pub use geo::download as download_geo;
pub use gitmeta::scan as scan_gitmeta;
pub use ip::scan as scan_ip;
pub use meta::scan as scan_meta;
pub use ports::scan as scan_ports;
pub use siteurl::scan as scan_url;
pub use socials::scan as scan_socials;
pub use threat::scan as scan_intel;
pub use user::scan as scan_user;

pub fn render(report: &Report, format: Format) -> String {
    match format {
        Format::Json | Format::Sarif | Format::Codeclimate => {
            serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into()) + "\n"
        }
        Format::Markdown | Format::Html => {
            let mut out = format!(
                "# {} {}\n\n{} findings in {} ms\n\n| status | module | summary |\n| --- | --- | --- |\n",
                report.kind,
                report.target,
                report.findings.len(),
                report.elapsed_ms
            );
            for h in &report.findings {
                let summary = h.summary.replace('|', "\\|");
                out.push_str(&format!(
                    "| {} | {} | {} |\n",
                    h.status.as_str(),
                    h.module,
                    summary
                ));
            }
            out
        }
        Format::Text => {
            let mut out = format!(
                "{}  {}  {} ms  {} findings\n",
                report.target,
                report.kind,
                report.elapsed_ms,
                report.findings.len()
            );
            for h in &report.findings {
                out.push_str(&format!(
                    "  {:<13}  {:<12}  {}\n",
                    h.status.as_str(),
                    h.module,
                    h.summary
                ));
            }
            out
        }
    }
}
