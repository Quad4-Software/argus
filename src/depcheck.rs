// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

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
        evidence: None,
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

    // parallel registry + ecosyste.ms lookups, bounded pool
    let queue = std::sync::Mutex::new(unique.iter().peekable());
    let infos: Vec<(
        usize,
        Option<crate::registry::RegistryInfo>,
        Option<crate::risk::EcoInfo>,
    )> = {
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
                        let reg = crate::registry::lookup(http, unique[i]).ok();
                        let eco = crate::risk::lookup(http, unique[i]).ok();
                        if reg.is_some() || eco.is_some() {
                            results.lock().unwrap().push((i, reg, eco));
                        }
                    }
                });
            }
        });
        results.into_inner().unwrap()
    };
    let mut by_idx: std::collections::HashMap<
        usize,
        (
            Option<crate::registry::RegistryInfo>,
            Option<crate::risk::EcoInfo>,
        ),
    > = infos
        .into_iter()
        .map(|(i, reg, eco)| (i, (reg, eco)))
        .collect();
    let mut upstream_checked = 0usize;
    for (i, d) in unique.iter().enumerate() {
        let Some((reg, eco)) = by_idx.remove(&i) else {
            continue; // transient lookup failure: skip rather than invent
        };
        let eco = eco.filter(|e| e.exists);
        if let Some(info) = &reg {
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
            } else {
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
        }
        if let Some(eco) = &eco {
            risk_checks(target, d, eco, &mut out);
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

// ---------------------------------------------------------------------------
// ecosyste.ms-backed risk checks (DEP-030+)
// ---------------------------------------------------------------------------

/// Per-ecosystem dep-name normalization before distance checks:
/// lowercase everywhere; PyPI collapses runs of [-_.] to '-' (PEP 503,
/// as documented by deps.dev); npm scoped names keep '@scope/'.
pub(crate) fn norm_dep_name(eco: &str, name: &str) -> String {
    let l = name.trim().to_lowercase();
    if eco != "PyPI" {
        return l;
    }
    let mut out = String::with_capacity(l.len());
    let mut sep = false;
    for c in l.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !sep {
                out.push('-');
            }
            sep = true;
        } else {
            out.push(c);
            sep = false;
        }
    }
    out
}

/// Builtin top-package lists per ecosystem - the same data the
/// typosquat ruleset (rules/typosquat.toml) compiles from.
fn popular_list(eco: &str) -> Option<&'static str> {
    match eco {
        "npm" => Some(include_str!("../rules/data/top-npm.txt")),
        "PyPI" => Some(include_str!("../rules/data/top-pypi.txt")),
        "crates.io" => Some(include_str!("../rules/data/top-crates.txt")),
        _ => None,
    }
}

/// Closest popular package name in the dep's ecosystem within edit
/// distance <= 2; adjacent transpositions count as one edit (the
/// engine's bounded damerau-levenshtein). Exact self-matches excluded.
fn nearest_popular(eco: &str, norm: &str) -> Option<(String, usize)> {
    let list = popular_list(eco)?;
    let mut best: Option<(String, usize)> = None;
    for raw in list.lines() {
        let p = norm_dep_name(eco, raw);
        if p.is_empty() || p == norm {
            continue;
        }
        let dist = if crate::scan::engine::lev_at_most(norm, &p, 1) {
            1
        } else if crate::scan::engine::lev_at_most(norm, &p, 2) {
            2
        } else {
            continue;
        };
        if best.as_ref().is_none_or(|(_, b)| dist < *b) {
            best = Some((p, dist));
        }
    }
    best
}

/// Human-readable usage summary for finding messages.
fn usage_str(eco: &crate::risk::EcoInfo) -> String {
    match (eco.downloads_monthly, eco.dependent_repos) {
        (Some(d), Some(r)) => format!("{d} downloads/mo, {r} dependent repos"),
        (Some(d), None) => format!("{d} downloads/mo"),
        (None, Some(r)) => format!("{r} dependent repos"),
        (None, None) => "no usage data".into(),
    }
}

/// DEP-030/031/032: popularity- and cadence-scored squat signals from
/// ecosyste.ms metadata. All three need the package to exist there;
/// unknown fields abstain rather than invent.
fn risk_checks(target: &str, d: &Dep, eco: &crate::risk::EcoInfo, out: &mut Vec<Finding>) {
    let norm = norm_dep_name(d.ecosystem, &d.name);
    let near = nearest_popular(d.ecosystem, &norm);

    // usage gates: downloads where the registry reports them, dependent
    // repos as fallback. Truly unknown usage cannot prove popularity -
    // and "near a popular name but unmeasurable" IS the squat signal.
    let low_usage = match eco.downloads_monthly {
        Some(dl) => dl < 15_000, // TypoGard popularity threshold
        None => eco.dependent_repos.is_none_or(|r| r < 500),
    };
    let tiny = match eco.downloads_monthly {
        Some(dl) => dl < 1_000,
        None => eco.dependent_repos.is_none_or(|r| r < 50),
    };

    if let Some((victim, 1)) = &near
        && low_usage
    {
        out.push(finding(
            target,
            d,
            "DEP-030",
            Severity::High,
            format!(
                "dep name {} is edit distance 1 from popular package {victim} and low-usage ({}): typosquat-scored",
                d.name,
                usage_str(eco)
            ),
            "Verify the intended package and publisher. A distance-1 neighbour of a popular name that is itself unpopular is the textbook squat shape.",
        ));
    }

    if let Some(age) = eco.age_days
        && age < 180
        && tiny
        && let Some((victim, dist)) = &near
    {
        out.push(finding(
            target,
            d,
            "DEP-031",
            Severity::Medium,
            format!(
                "{} was first published {age} days ago with minimal usage ({}), {dist} edit(s) from popular package {victim}: AI-hallucination slopsquat pattern",
                d.name,
                usage_str(eco)
            ),
            "Confirm this package was chosen deliberately, not suggested by an LLM and claimed by a squatter. Check the publisher, source repo, and release diff.",
        ));
    }

    if let Some(gap) = eco.latest_release_gap_days
        && gap >= 365
    {
        out.push(finding(
            target,
            d,
            "DEP-032",
            Severity::Medium,
            format!(
                "{} latest release landed after a {gap}-day gap (>= 1 year dormancy): dormancy-then-release",
                d.name
            ),
            "A sudden release on a long-dormant package matches maintainer-takeover / account-hijack campaigns (event-stream, eslint-scope). Review the release diff and maintainer changes before upgrading.",
        ));
    }
}

#[cfg(test)]
mod risk_tests {
    use super::*;

    fn dep(name: &str) -> Dep {
        Dep {
            ecosystem: "npm",
            name: name.into(),
            version: "1.0.0".into(),
            path: "package.json".into(),
        }
    }

    #[test]
    fn pypi_names_collapse_separators() {
        assert_eq!(norm_dep_name("PyPI", "My_Pkg..Name"), "my-pkg-name");
        assert_eq!(norm_dep_name("npm", "@Scope/Name"), "@scope/name");
        assert_eq!(norm_dep_name("crates.io", "Serde_Json"), "serde_json");
    }

    #[test]
    fn nearest_popular_uses_lists() {
        assert_eq!(
            nearest_popular("npm", "crossenv"),
            Some(("cross-env".to_string(), 1))
        );
        // transposition counts as one edit
        assert_eq!(nearest_popular("npm", "raect").map(|(_, d)| d), Some(1));
        // "react" itself is 1 edit from "preact" - distance alone is not
        // exclusion; DEP-030's usage gate is what spares popular names
        assert_eq!(
            nearest_popular("npm", "react").map(|(v, _)| v),
            Some("preact".to_string())
        );
        assert!(nearest_popular("npm", "totally-unrelated-pkg").is_none());
        assert!(nearest_popular("Go", "anything").is_none()); // no list
    }

    #[test]
    fn dep030_scored_squat() {
        let eco = crate::risk::EcoInfo {
            exists: true,
            downloads_monthly: Some(7_000),
            dependent_repos: Some(76),
            ..Default::default()
        };
        let mut out = Vec::new();
        risk_checks("t", &dep("crossenv"), &eco, &mut out);
        assert!(
            out.iter()
                .any(|f| f.rule_id == "DEP-030" && f.severity == Severity::High)
        );
        // popular package itself must not be flagged
        let big = crate::risk::EcoInfo {
            exists: true,
            downloads_monthly: Some(50_000_000),
            dependent_repos: Some(1_000_000),
            ..Default::default()
        };
        out.clear();
        risk_checks("t", &dep("crossenv"), &big, &mut out);
        assert!(out.iter().all(|f| f.rule_id != "DEP-030"));
    }

    #[test]
    fn dep031_and_dep032() {
        let young = crate::risk::EcoInfo {
            exists: true,
            downloads_monthly: Some(12),
            age_days: Some(30),
            ..Default::default()
        };
        let mut out = Vec::new();
        // "axois" is one transposition from npm's "axios"
        risk_checks("t", &dep("axois"), &young, &mut out);
        assert!(
            out.iter()
                .any(|f| f.rule_id == "DEP-031" && f.severity == Severity::Medium)
        );

        let dormant_then_release = crate::risk::EcoInfo {
            exists: true,
            latest_release_gap_days: Some(400),
            ..Default::default()
        };
        out.clear();
        risk_checks("t", &dep("some-pkg"), &dormant_then_release, &mut out);
        assert!(
            out.iter()
                .any(|f| f.rule_id == "DEP-032" && f.severity == Severity::Medium)
        );
    }
}
