// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! A short public-profile table for one username.
//! Add or remove a site by editing SITES. A 200 from the API is a lead.
//! A miss is not proof the person has no account. This does not try
//! password-reset or login endpoints.

use super::siteurl::fetch_public;
use super::{Hit, Report, Status};
use std::time::Instant;

struct Site {
    name: &'static str,
    url: fn(&str) -> String,
    present: fn(u16, &str) -> Status,
}

const SITES: &[Site] = &[
    Site {
        name: "github",
        url: |n| format!("https://api.github.com/users/{n}"),
        present: |status, body| json_user(status, body, "login"),
    },
    Site {
        name: "gitlab",
        url: |n| format!("https://gitlab.com/api/v4/users?username={n}"),
        present: |status, body| {
            if status != 200 {
                return Status::Inconclusive;
            }
            if body.trim() == "[]" {
                Status::Absent
            } else if body.contains("\"username\"") {
                Status::Confirmed
            } else {
                Status::Inconclusive
            }
        },
    },
    Site {
        name: "codeberg",
        url: |n| format!("https://codeberg.org/api/v1/users/{n}"),
        present: |status, body| json_user(status, body, "login"),
    },
    Site {
        name: "crates",
        url: |n| format!("https://crates.io/api/v1/users/{n}"),
        present: |status, body| json_user(status, body, "login"),
    },
    Site {
        name: "keybase",
        url: |n| format!("https://keybase.io/_/api/1.0/user/lookup.json?usernames={n}"),
        present: |status, body| {
            if status != 200 {
                return Status::Inconclusive;
            }
            if body.contains("\"them\":[]") || body.contains("\"them\":null") {
                Status::Absent
            } else if body.contains("\"them\"") {
                Status::Confirmed
            } else {
                Status::Inconclusive
            }
        },
    },
];

fn json_user(status: u16, body: &str, key: &str) -> Status {
    if status == 404 {
        Status::Absent
    } else if status == 200 && body.contains(&format!("\"{key}\"")) {
        Status::Confirmed
    } else {
        Status::Inconclusive
    }
}

pub fn scan(name: &str) -> Result<Report, String> {
    let t0 = Instant::now();
    let name = name.trim();
    if name.is_empty()
        || name.len() > 40
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err("username must be letters, digits, dot, underscore, or hyphen".into());
    }
    let findings = std::thread::scope(|s| {
        let mut joins = Vec::new();
        for site in SITES {
            joins.push(s.spawn(move || check(site, name)));
        }
        joins
            .into_iter()
            .map(|j| {
                j.join()
                    .unwrap_or_else(|_| Hit::new("user", Status::Error, "check panicked", None))
            })
            .collect::<Vec<_>>()
    });
    Ok(Report {
        target: name.to_string(),
        kind: "user",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

fn check(site: &Site, name: &str) -> Hit {
    let url = (site.url)(name);
    match fetch_public(&url) {
        Err(e) => Hit::new(site.name, Status::Error, e, None),
        Ok((status, _, _, body)) => {
            let status = (site.present)(status, &body);
            let summary = match status {
                Status::Confirmed => format!("profile API returned the name ({url})"),
                Status::Absent => "no public profile at this API".into(),
                Status::Inconclusive => format!("HTTP response was not a clear yes or no"),
                Status::Error => "lookup failed".into(),
            };
            Hit::new(site.name, status, summary, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_site_table_is_unique() {
        let mut names: Vec<_> = SITES.iter().map(|s| s.name).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), SITES.len());
        assert!(json_user(404, "", "login") == Status::Absent);
        assert!(json_user(200, "{\"login\":\"octocat\"}", "login") == Status::Confirmed);
    }
}
