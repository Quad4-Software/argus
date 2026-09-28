//! Dependency hygiene beyond known-CVEs: dependency-confusion exposure,
//! unmaintained upstreams, and maintainer-set monitoring.
//!
//! Confusion model:
//!   - dep does NOT resolve on the public registry -> medium (typo,
//!     renamed-away, or genuinely internal name; either way worth a look)
//!   - dep resolves publicly AND its name matches a configured internal
//!     prefix -> high (an attacker-owned public package can shadow your
//!     private one; this is the classic dependency-confusion incident)

use crate::finding::{Finding, Severity};
use crate::http::HttpClient;
use crate::osv::Dep;
use std::collections::HashSet;

/// Probe "owner/repo" -> Some(archived) on the upstream forge.
pub type UpstreamProbe<'a> = &'a dyn Fn(&str) -> Option<bool>;

fn finding(target: &str, dep: &Dep, id: &str, sev: Severity, msg: String, rem: &str) -> Finding {
    Finding {
        ruleset: "dep-hygiene".into(),
        rule_id: id.into(),
        severity: sev,
        target: target.into(),
        path: dep.path.clone(),
        line: None,
        excerpt: Some(format!("{} {}@{}", dep.ecosystem, dep.name, dep.version)),
        message: msg,
        remediation: Some(rem.into()),
        reference: None,
        window: None,
    }
}

/// Names that look organization-internal: configured prefixes, plus a few
/// generic internal markers. Kept explicit so normal public names never
/// get flagged.
fn looks_internal(name: &str, prefixes: &[String]) -> bool {
    let l = name.to_lowercase();
    if prefixes
        .iter()
        .any(|p| !p.is_empty() && l.starts_with(&p.to_lowercase()))
    {
        return true;
    }
    l.contains("-internal")
        || l.starts_with("internal-")
        || l.contains(".internal")
        || l.ends_with("-priv")
        || l.ends_with("-private")
}

/// Registry metadata pass over the dep set. target labels findings.
/// internal prefixes come from --internal-prefix / config; without them
/// the shadow-check only fires on generic internal markers.
pub fn check(
    deps: &[Dep],
    target: &str,
    internal_prefixes: &[String],
    http: &HttpClient,
    upstream_probe: Option<UpstreamProbe>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut unique: Vec<&Dep> = Vec::new();
    for d in deps {
        if seen.insert((d.ecosystem.to_string(), d.name.clone())) {
            unique.push(d);
        }
    }

    // parallel registry lookups, bounded pool
    let queue = std::sync::Mutex::new(unique.iter().peekable());
    let infos: Vec<Option<(usize, crate::registry::RegistryInfo)>> = {
        let results = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    loop {
                        let idx = {
                            let mut q = queue.lock().unwrap();
                            {
                                let before = q.len();
                                q.next();
                                (before > 0).then(|| unique.len() - before)
                            }
                        };
                        let Some(i) = idx else { break };
                        if let Ok(info) = crate::registry::lookup(http, unique[i]) {
                            results.lock().unwrap().push(Some((i, info)));
                        }
                    }
                });
            }
        });
        results.into_inner().unwrap()
    };
    let mut by_idx: std::collections::HashMap<usize, crate::registry::RegistryInfo> =
        infos.into_iter().flatten().collect();
    let mut upstream_checked = 0usize;
    for (i, d) in unique.iter().enumerate() {
        let Some(info) = by_idx.remove(&i) else {
            continue; // transient lookup failure: skip rather than invent
        };
        if !info.exists {
            out.push(finding(
                target,
                d,
                "DEP-001",
                Severity::Medium,
                format!(
                    "{} {} not found on the public {} registry: typo, renamed package, or private name",
                    d.ecosystem, d.name, d.ecosystem
                ),
                "Verify the name. If internal-only, ensure builds pin the private registry so a squatter cannot shadow it.",
            ));
            continue;
        }
        if let Some((victim, dist)) = typosquat(&d.name) {
            out.push(finding(
                target,
                d,
                "DEP-020",
                Severity::Medium,
                format!(
                    "dep name {} is edit-distance {dist} from popular package {victim}: possible typosquat",
                    d.name
                ),
                "Verify the intended package; a one/two-char difference is the classic squat pattern.",
            ));
        }
        if looks_internal(&d.name, internal_prefixes) {
            out.push(finding(
                target,
                d,
                "DEP-002",
                Severity::High,
                format!(
                    "internal-looking dep {} resolves on the public {} registry: dependency-confusion exposure",
                    d.name, d.ecosystem
                ),
                "Publish/claim the name publicly, force private-registry resolution (.npmrc/pip.conf), or alias to a vendored copy.",
            ));
        }
        if let Some(days) = info.last_release_days
            && days > 730
        {
            out.push(finding(
                    target,
                    d,
                    "DEP-010",
                    Severity::Low,
                    format!(
                        "{} last released {} days ago (>{} years) - dormant packages are takeover targets",
                        d.name,
                        days,
                        days / 365
                    ),
                    "Pin exact versions, watch the package for maintainer changes, or plan a maintained replacement.",
                ));
        }
        // archived upstream repo: only probe a bounded number to keep runs fast
        if upstream_checked < 20
            && let (Some(url), Some(probe)) = (&info.repo_url, upstream_probe)
            && let Some(repo_path) = github_repo_path(url)
        {
            upstream_checked += 1;
            if probe(&repo_path) == Some(true) {
                out.push(finding(
                    target,
                    d,
                    "DEP-011",
                    Severity::Medium,
                    format!("upstream repository for {} is archived/read-only", d.name),
                    "Treat as unmaintained: pin the version and monitor for forks.",
                ));
            }
        }
    }
    out
}

/// "git@github.com:o/r.git" / "https://github.com/o/r" -> "o/r"
pub fn github_repo_path(url: &str) -> Option<String> {
    let u = url.trim_end_matches(".git").trim_end_matches('/');
    for pat in ["github.com/", "github.com:"] {
        if let Some(pos) = u.find(pat) {
            let rest = &u[pos + pat.len()..];
            let mut parts = rest.split('/');
            if let (Some(o), Some(r)) = (parts.next(), parts.next())
                && !o.is_empty()
                && !r.is_empty()
            {
                return Some(format!("{o}/{r}"));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_names() {
        let p = vec!["@quad4".to_string(), "rns-".to_string()];
        assert!(looks_internal("@quad4/lib", &p));
        assert!(looks_internal("rns-utils", &p));
        assert!(looks_internal("acme-internal", &[]));
        assert!(!looks_internal("lodash", &p));
        assert!(!looks_internal("internalize", &[]));
    }

    #[test]
    fn github_paths() {
        assert_eq!(
            github_repo_path("https://github.com/o/r.git"),
            Some("o/r".into())
        );
        assert_eq!(github_repo_path("git@github.com:o/r"), Some("o/r".into()));
        assert_eq!(github_repo_path("https://gitlab.com/o/r"), None);
    }
}

/// Popular packages by name - the canonical typosquat targets.
const POPULAR: &[&str] = &[
    "lodash",
    "react",
    "express",
    "axios",
    "next",
    "vue",
    "angular",
    "jquery",
    "typescript",
    "webpack",
    "eslint",
    "babel",
    "moment",
    "chalk",
    "commander",
    "debug",
    "request",
    "fs-extra",
    "uuid",
    "dotenv",
    "minimist",
    "semver",
    "yargs",
    "inquirer",
    "glob",
    "rimraf",
    "mkdirp",
    "async",
    "underscore",
    "bluebird",
    "styled-components",
    "tailwindcss",
    "postcss",
    "vite",
    "requests",
    "numpy",
    "pandas",
    "django",
    "flask",
    "boto3",
    "urllib3",
    "setuptools",
    "pytest",
    "sqlalchemy",
    "matplotlib",
    "scipy",
    "pillow",
    "tensorflow",
    "torch",
    "sklearn",
    "opencv-python",
    "selenium",
    "aiohttp",
    "fastapi",
    "pydantic",
    "click",
    "pyyaml",
    "cryptography",
    "tqdm",
    "serde",
    "tokio",
    "rand",
    "reqwest",
    "clap",
    "anyhow",
    "thiserror",
    "regex",
    "chrono",
    "futures",
];

/// Nearest popular name within edit distance <= 2 (1 for short names).
pub(crate) fn typosquat(name: &str) -> Option<(&'static str, usize)> {
    let l = name.to_lowercase();
    if POPULAR.contains(&l.as_str()) {
        return None; // the real package, not a squat
    }
    let mut best: Option<(&'static str, usize)> = None;
    for p in POPULAR {
        let dist = lev(&l, p);
        let max = if l.len() < 6 { 1 } else { 2 };
        if dist > 0 && dist <= max && best.is_none_or(|(_, b)| dist < b) {
            best = Some((p, dist));
        }
    }
    best
}

/// Classic Levenshtein with early-exit bound.
fn lev(a: &str, b: &str) -> usize {
    if (a.len() as isize - b.len() as isize).unsigned_abs() > 2 {
        return 3;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, &ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, &cb) in b.iter().enumerate() {
            cur.push(
                (prev[j + 1] + 1)
                    .min(cur[j] + 1)
                    .min(prev[j] + (ca != cb) as usize),
            );
        }
        prev = cur;
    }
    prev[b.len()]
}

#[cfg(test)]
mod tq_tests {
    #[test]
    fn catches_renamed_requests() {
        assert_eq!(super::typosquat("reqeusts").map(|x| x.0), Some("requests"));
        assert!(super::typosquat("some-entirely-different-name").is_none()); // no popular near
        assert!(super::typosquat("requests").is_none()); // exact match excluded
    }
}
