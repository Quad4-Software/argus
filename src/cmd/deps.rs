// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

use crate::cli::{Cli, Cmd};
use crate::finding::{Finding, Report, Severity};
use crate::scan::ScanOptions;
use crate::{config, depcheck, finding, http, osv, rules, scan};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Collect pinned deps from manifests under one root.
pub(crate) fn collect_deps(
    root: &Path,
    prefix: &str,
    opts: &ScanOptions,
    deps: &mut Vec<osv::Dep>,
) {
    let manifest_re = regex::Regex::new(rules::CompiledRule::DEP_MANIFESTS_RE).unwrap();
    for f in scan::collect_files(root, false, true) {
        let rel = f
            .strip_prefix(root)
            .unwrap_or(&f)
            .to_string_lossy()
            .replace('\\', "/");
        let is_wf = rel.contains("workflows/") && (rel.ends_with(".yml") || rel.ends_with(".yaml"));
        if !manifest_re.is_match(&rel) && !is_wf {
            continue;
        }
        if let Ok(b) = std::fs::read(&f)
            && !b.is_empty()
            && b.len() <= opts.max_file_size as usize
        {
            for mut d in osv::extract_deps(&rel, &String::from_utf8_lossy(&b)) {
                if !prefix.is_empty() {
                    d.path = format!("{prefix}/{}", d.path);
                }
                deps.push(d);
            }
        }
    }
}

/// Collect pinned deps from manifests under the scanned roots, query OSV.
pub(crate) fn osv_scan(cli: &Cli, opts: &ScanOptions, report: &mut Report) -> Result<(), String> {
    let mut deps: Vec<osv::Dep> = Vec::new();
    let roots: Vec<PathBuf> = match &cli.cmd {
        Cmd::Scan { paths } => paths.clone(),
        Cmd::System { .. } => vec![],
        _ => vec![],
    };
    for root in &roots {
        collect_deps(root, "", opts, &mut deps);
    }
    // remote scans: deps collected during clone loop get merged here
    let reach = dep_reachability(&roots, &deps, opts);
    run_osv_queries(cli, deps, report, reach, opts)
}

pub(crate) fn cfg_deps_prefixes() -> Vec<String> {
    config::load(None)
        .map(|(c, _)| c.defaults.internal_prefixes)
        .unwrap_or_default()
}

/// Probe whether a github "owner/repo" path is archived (token-aware).
pub(crate) fn dep_upstream_probe() -> impl Fn(&str) -> Option<bool> {
    let token = std::env::var("GITHUB_TOKEN")
        .ok()
        .or_else(|| std::env::var("GH_TOKEN").ok());
    let mut headers = vec![(
        "Accept".to_string(),
        "application/vnd.github+json".to_string(),
    )];
    if let Some(t) = &token {
        headers.push(("Authorization".into(), format!("Bearer {t}")));
    }
    let http = http::HttpClient::new(headers);
    move |repo: &str| match http.get_status_json(&format!("https://api.github.com/repos/{repo}")) {
        Ok((200, v)) => Some(v["archived"].as_bool().unwrap_or(false)),
        _ => None,
    }
}

pub(crate) fn run_osv_queries(
    cli: &Cli,
    mut deps: Vec<osv::Dep>,
    report: &mut Report,
    reach: std::collections::HashMap<String, Reach>,
    opts: &ScanOptions,
) -> Result<(), String> {
    deps.extend(REMOTE_DEPS.lock().unwrap().drain(..));
    deps.sort();
    deps.dedup();
    if deps.is_empty() {
        if cli.verbose > 0 {
            eprintln!("osv: no pinned deps found");
        }
        return Ok(());
    }
    let http = http::HttpClient::new(vec![]);

    // registry hygiene: confusion + unmaintained (independent of osv)
    if cli.dep_check {
        let mut prefixes = cli.internal_prefixes.clone();
        prefixes.extend(cfg_deps_prefixes());
        eprintln!("dep-check: registry lookups on {} deps", deps.len());
        let probe = dep_upstream_probe();
        report.findings.extend(depcheck::check(
            &deps,
            "deps",
            &prefixes,
            &http,
            Some(&probe),
        ));
    }
    if !cli.osv {
        return Ok(());
    }
    eprintln!("osv: querying {} pinned deps", deps.len());
    let hits = osv::query_batch(&http, &deps)?;
    // symbol reachability: fetch advisory symbol lists for Go/Rust deps
    // that are load-bearing, then grep their call sites
    let roots: Vec<PathBuf> = match &cli.cmd {
        Cmd::Scan { paths } => paths.clone(),
        _ => vec![],
    };
    // fetch advisory symbol lists in parallel (one request per unique
    // advisory id), then grep each dep's sources once over the union of
    // symbols so per-advisory results share the same file pass
    let eligible: Vec<(usize, String)> = hits
        .iter()
        .filter(|(i, _, _, _)| {
            let d = &deps[*i];
            (d.ecosystem == "Go" || d.ecosystem == "crates.io")
                && !matches!(reach.get(&d.name), Some(Reach::Absent))
                && !roots.is_empty()
        })
        .map(|(i, id, _, _)| (*i, id.clone()))
        .collect();
    let unique_ids: Vec<String> = {
        let mut v: Vec<String> = eligible.iter().map(|(_, id)| id.clone()).collect();
        v.sort();
        v.dedup();
        v
    };
    let sym_lists: std::collections::HashMap<String, Vec<String>> = std::thread::scope(|s| {
        let http = &http;
        let handles: Vec<_> = unique_ids
            .iter()
            .map(|id| s.spawn(|| (id.clone(), advisory_symbols(http, id))))
            .collect();
        handles
            .into_iter()
            .filter_map(|h| h.join().ok())
            .filter_map(|(id, syms)| syms.map(|s2| (id, s2)))
            .collect()
    });
    // one file pass per dep index over the union of its advisories' symbols
    let mut dep_union: std::collections::HashMap<usize, Vec<String>> =
        std::collections::HashMap::new();
    for (i, id) in &eligible {
        if let Some(syms) = sym_lists.get(id) {
            let u = dep_union.entry(*i).or_default();
            for s in syms {
                if !u.contains(s) {
                    u.push(s.clone());
                }
            }
        }
    }
    let dep_used: std::collections::HashMap<usize, std::collections::HashSet<String>> = dep_union
        .iter()
        .filter(|(_, u)| !u.is_empty())
        .map(|(i, u)| (*i, symbols_used(&roots, deps[*i].ecosystem, u, opts)))
        .collect();
    let mut sym: SymbolMap = SymbolMap::new();
    for (i, id) in &eligible {
        if let Some(syms) = sym_lists.get(id) {
            let used: std::collections::HashSet<String> = dep_used
                .get(i)
                .map(|u| syms.iter().filter(|s| u.contains(*s)).cloned().collect())
                .unwrap_or_default();
            sym.insert((*i, id.clone()), (syms.clone(), used));
        }
    }
    let mut fs = vuln_findings(&deps, hits, "osv", &reach, &sym);
    // KEV/EPSS advisory enrichment; offline runs never reach this point
    if !cli.no_enrich {
        crate::risk::enrich_findings(&http, &mut fs);
    }
    report.findings.extend(fs);
    Ok(())
}

/// How strongly a dep is observed in scanned sources.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Reach {
    /// An import/require/use of the dep's import name was found.
    Imported,
    /// The name appears in source text but never in an import position.
    Mentioned,
    /// Neither imported nor mentioned under the scanned roots.
    Absent,
}

/// Per-extension import-name extraction. One regex pass per file yields
/// the set of imported package names; deps then check membership instead
/// of substring-matching the whole file (a dep named "react" must not
/// count "create-react-app" in a comment).
fn imported_names(t: &str, ext: &str, out: &mut std::collections::HashSet<String>) {
    use std::sync::OnceLock;
    macro_rules! res {
        ($($e:expr),* $(,)?) => {{
            $({
                static R: OnceLock<regex::Regex> = OnceLock::new();
                let re = R.get_or_init(|| regex::Regex::new($e).unwrap());
                for c in re.captures_iter(t) {
                    out.insert(c[1].to_string());
                }
            })*
        }};
    }
    match ext {
        "js" | "ts" | "tsx" | "jsx" | "mjs" | "cjs" | "vue" | "svelte" => {
            // require("x") / import "x" / import x from "x" / import("x")
            res!(
                r#"(?:require|import)\s*\(?\s*["']([^"'\s]+)["']"#,
                r#"from\s+["']([^"'\s]+)["']"#
            );
        }
        "py" | "pyw" => {
            res!(r"(?m)^\s*(?:import|from)\s+([A-Za-z0-9_][A-Za-z0-9_.]*)");
        }
        "rs" => {
            res!(r"(?m)^\s*(?:use|extern\s+crate)\s+([a-zA-Z0-9_]+)");
        }
        "go" => {
            // quoted import paths always contain a slash
            res!(r#"(?m)^\s*(?:[\w.]+\s+)?"([a-zA-Z0-9._~-]+/[a-zA-Z0-9._~/-]+)""#);
        }
        "rb" => {
            res!(r#"require\s+["']([^"']+)["']"#);
        }
        "java" | "kt" => {
            res!(r"(?m)^\s*import\s+(?:static\s+)?([a-zA-Z0-9_.]+)");
        }
        "cs" | "fs" => {
            res!(r"(?m)^\s*using\s+(?!static)([A-Za-z0-9_.]+)");
        }
        "php" => {
            res!(r"(?m)^\s*use\s+([A-Za-z0-9_\\]+)");
        }
        "ex" | "exs" => {
            res!(r"(?m)^\s*(?:use|import|alias)\s+([A-Z][A-Za-z0-9_.]*)");
        }
        "dart" => {
            res!(r#"import\s+['"]package:([a-zA-Z0-9_]+)"#);
        }
        _ => {}
    }
}

/// `foo-bar` -> `FooBar` (elixir module names)
fn camelize(s: &str) -> String {
    s.split(['-', '_'])
        .map(|w| {
            let mut c = w.chars();
            c.next()
                .map(|f| f.to_uppercase().chain(c).collect::<String>())
                .unwrap_or_default()
        })
        .collect()
}

/// Whether imported name `imp` refers to dep `name` in `eco`.
fn refers(imp: &str, eco: &str, name: &str) -> bool {
    match eco {
        "npm" | "RubyGems" | "NuGet" => {
            imp == name
                || imp.starts_with(&format!("{name}/"))
                || imp.starts_with(&format!("{name}."))
        }
        "PyPI" | "crates.io" => {
            let n = name.replace('-', "_").to_lowercase();
            let i = imp.replace('-', "_").to_lowercase();
            i == n || i.starts_with(&format!("{n}.")) || i == name.to_lowercase()
        }
        "Go" => imp == name || imp.starts_with(&format!("{name}/")),
        "Maven" => name
            .split_once(':')
            .is_some_and(|(g, _)| imp.starts_with(&format!("{g}."))),
        "Packagist" => imp.eq_ignore_ascii_case(&name.replace('/', "\\")),
        "Hex" => imp == camelize(name) || imp.starts_with(&format!("{}.", camelize(name))),
        "Pub" => imp == name,
        _ => false,
    }
}

/// Which deps are observed in sources under roots, at import strength.
/// `imported_names` runs once per file; a dep counts Imported when its
/// import spelling appears, Mentioned when only the bare name shows up
/// in text (comments, strings), Absent otherwise. Not a callgraph - it
/// answers "is the package loaded anywhere", not "is the vuln hit".
pub(crate) fn dep_reachability(
    roots: &[std::path::PathBuf],
    deps: &[osv::Dep],
    opts: &ScanOptions,
) -> std::collections::HashMap<String, Reach> {
    use std::collections::{HashMap, HashSet};
    let mut levels: HashMap<String, Reach> = deps
        .iter()
        .map(|d| (d.name.clone(), Reach::Absent))
        .collect();
    static CODE: OnceLock<regex::Regex> = OnceLock::new();
    let code = CODE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)\.(py|pyw|js|ts|mjs|cjs|jsx|tsx|rs|go|rb|php|java|kt|cs|fs|ex|exs|dart|vue|svelte)$",
        )
        .unwrap()
    });
    for root in roots {
        for f in crate::scan::collect_files(root, false, true) {
            let Some(ext) = f
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_lowercase())
            else {
                continue;
            };
            if !code.is_match(&format!("x.{ext}")) {
                continue; // manifests name themselves
            }
            let Ok(b) = std::fs::read(&f) else { continue };
            if b.len() > opts.max_file_size as usize || crate::scan::looks_binary(&b) {
                continue;
            }
            let t = String::from_utf8_lossy(&b);
            let mut imps: HashSet<String> = HashSet::new();
            imported_names(&t, &ext, &mut imps);
            for d in deps {
                if matches!(levels.get(&d.name), Some(Reach::Imported)) {
                    continue;
                }
                let imported = imps.iter().any(|i| refers(i, d.ecosystem, &d.name));
                if imported {
                    levels.insert(d.name.clone(), Reach::Imported);
                } else if !matches!(levels.get(&d.name), Some(Reach::Mentioned))
                    && t.contains(d.name.as_str())
                {
                    levels.insert(d.name.clone(), Reach::Mentioned);
                }
            }
        }
    }
    levels
}

/// Per-(dep index, advisory id) symbol evidence: (symbols listed by the
/// advisory, symbols actually referenced in call position in sources).
/// Keyed per advisory - different advisories on the same dep name carry
/// different affected symbol lists.
pub(crate) type SymbolMap =
    std::collections::HashMap<(usize, String), (Vec<String>, std::collections::HashSet<String>)>;

pub(crate) fn vuln_findings(
    deps: &[osv::Dep],
    hits: Vec<(usize, String, String, String)>,
    ruleset: &str,
    reach: &std::collections::HashMap<String, Reach>,
    sym: &SymbolMap,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, id, summary, fix) in hits {
        let d = &deps[i];
        let is_mal = id.starts_with("MAL-");
        // absent from map = unknown (e.g. image OS pkgs) -> keep reached
        let reach_lvl = reach.get(&d.name).copied().unwrap_or(Reach::Imported);
        let reached = !matches!(reach_lvl, Reach::Absent);
        // symbol-level: advisory listed affected functions and the dep is
        // load-bearing, but none of the symbols are called -> downgrade
        // confidence. Symbols referenced -> the vuln path is exercised.
        let (listed, used) = sym.get(&(i, id.clone())).cloned().unwrap_or_default();
        let sym_hit = !used.is_empty();
        let sym_clear = !listed.is_empty() && used.is_empty() && reached;
        out.push(finding::Finding {
            ruleset: ruleset.into(),
            rule_id: id.clone(),
            severity: if is_mal || sym_hit {
                Severity::Critical
            } else if !reached || sym_clear {
                Severity::Medium // present but not exercised in sources
            } else {
                Severity::High
            },
            target: d.path.clone(),
            path: d.path.clone(),
            line: None,
            excerpt: Some(format!("{} {}@{}", d.ecosystem, d.name, d.version)),
            message: if is_mal {
                format!(
                    "OSV advisory {id} for {} {}@{}: package version is a confirmed malicious package (OpenSSF/OSV)",
                    d.ecosystem, d.name, d.version
                )
            } else {
                format!(
                    "OSV advisory {id} for {} {}@{}{}{}",
                    d.ecosystem,
                    d.name,
                    d.version,
                    match reach_lvl {
                        Reach::Imported => "",
                        Reach::Mentioned => " (referenced in source, no import found)",
                        Reach::Absent => " (no source reference - likely not reachable)",
                    },
                    if summary.is_empty() {
                        String::new()
                    } else {
                        format!(": {summary}")
                    }
                )
            },
            remediation: Some(if is_mal {
                "Malicious package version; do not install, rotate credentials on hosts that did."
                    .into()
            } else if fix.is_empty() {
                "Review the advisory and upgrade if affected.".into()
            } else {
                format!("Upgrade to {fix} or later.")
            }),
            reference: Some(format!("https://osv.dev/vulnerability/{id}")),
            window: None,
            evidence: Some({
                let mut ev = vec![format!(
                    "reach: {}",
                    match reach_lvl {
                        Reach::Imported => "imported in scanned sources",
                        Reach::Mentioned => "name mentioned, never imported",
                        Reach::Absent => "absent from scanned sources",
                    }
                )];
                if sym_hit {
                    ev.push(format!(
                        "vulnerable symbols referenced: {}",
                        used.iter().take(4).cloned().collect::<Vec<_>>().join(", ")
                    ));
                } else if sym_clear {
                    ev.push(format!(
                        "advisory lists {} affected symbols; none referenced in sources",
                        listed.len()
                    ));
                }
                ev
            }),
        });
    }
    out
}

pub(crate) static REMOTE_DEPS: std::sync::Mutex<Vec<osv::Dep>> = std::sync::Mutex::new(Vec::new());

pub(crate) type CloneScanResult = Result<(Vec<finding::Finding>, usize), String>;

/// Affected symbols advertised by the advisory itself. Go vulndb data
/// ships imports[].symbols per affected package; RustSec lists
/// affects.functions as crate::path::name. Other ecosystems rarely carry
/// symbol data - None means "advisory does not say".
fn advisory_symbols(http: &crate::http::HttpClient, id: &str) -> Option<Vec<String>> {
    let v = osv::get_vuln(http, id)?;
    let mut syms = Vec::new();
    for a in v["affected"].as_array().into_iter().flatten() {
        let es = &a["ecosystem_specific"];
        for imp in es["imports"].as_array().into_iter().flatten() {
            for s in imp["symbols"].as_array().into_iter().flatten() {
                if let Some(s) = s.as_str() {
                    syms.push(s.to_string());
                }
            }
        }
        for s in es["affects"]["functions"].as_array().into_iter().flatten() {
            if let Some(s) = s.as_str() {
                syms.push(s.rsplit("::").next().unwrap_or(s).to_string());
            }
        }
        // rustsec also publishes affected_functions as a map of
        // crate::path::func -> affected versions
        for (fname, _) in es["affected_functions"].as_object().into_iter().flatten() {
            syms.push(fname.rsplit("::").next().unwrap_or(fname).to_string());
        }
        for s in es["affected_functions"].as_array().into_iter().flatten() {
            if let Some(s) = s.as_str() {
                syms.push(s.rsplit("::").next().unwrap_or(s).to_string());
            }
        }
    }
    if syms.is_empty() { None } else { Some(syms) }
}

/// Which of the given function/method names appear in call position in
/// source files for the dep's language. Plain names (Get, Error) are
/// common enough that a hit is suggestive, not proof - callers only get
/// an annotation, never a silent dismissal.
fn symbols_used(
    roots: &[std::path::PathBuf],
    eco: &str,
    syms: &[String],
    opts: &ScanOptions,
) -> std::collections::HashSet<String> {
    use std::collections::HashSet;
    let exts: &[&str] = match eco {
        "Go" => &["go"],
        "crates.io" => &["rs"],
        _ => return HashSet::new(),
    };
    // build one matcher: `Type.Method(` -> `\.Method\(`, `name(` -> `name\(`
    let pats: Vec<(String, regex::Regex)> = syms
        .iter()
        .filter_map(|s| {
            let leaf = s.rsplit('.').next().unwrap_or(s);
            let pat = if s.contains('.') {
                format!(r"\.{leaf}\s*\(")
            } else {
                // dotted call sites are the norm (pkg.Sym()); only reject
                // when an identifier char precedes the name. the regex
                // crate has no lookbehind - use a prefix alternation
                format!(r"(?:^|[^A-Za-z0-9_]){leaf}\s*\(")
            };
            regex::Regex::new(&pat).ok().map(|r| (s.clone(), r))
        })
        .collect();
    let mut used: HashSet<String> = HashSet::new();
    for root in roots {
        for f in crate::scan::collect_files(root, false, true) {
            if !exts.iter().any(|e| f.extension().is_some_and(|x| x == *e)) {
                continue;
            }
            let Ok(b) = std::fs::read(&f) else { continue };
            if b.len() > opts.max_file_size as usize || crate::scan::looks_binary(&b) {
                continue;
            }
            let t = String::from_utf8_lossy(&b);
            for (s, re) in &pats {
                if !used.contains(s) && re.is_match(&t) {
                    used.insert(s.clone());
                }
            }
        }
    }
    used
}

#[cfg(test)]
mod sym_tests {
    use std::fs;
}

#[cfg(test)]
mod reach_tests {
    use super::*;
    use std::fs;

    #[test]
    fn import_vs_mention_vs_absent() {
        let dir = std::env::temp_dir().join(format!("argus-reach-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src/main.rs"), "use serde_json;\nuse anyhow;\n").unwrap();
        fs::write(
            dir.join("src/util.rs"),
            "// we should not use lodash here - see notes\nlet x = 1;",
        )
        .unwrap();
        let deps = vec![
            osv::Dep {
                ecosystem: "crates.io",
                name: "serde-json".into(),
                version: "1".into(),
                path: "Cargo.toml".into(),
            },
            osv::Dep {
                ecosystem: "crates.io",
                name: "anyhow".into(),
                version: "1".into(),
                path: "Cargo.toml".into(),
            },
            osv::Dep {
                ecosystem: "npm",
                name: "lodash".into(),
                version: "1".into(),
                path: "package.json".into(),
            },
            osv::Dep {
                ecosystem: "npm",
                name: "axios".into(),
                version: "1".into(),
                path: "package.json".into(),
            },
        ];
        let opts = ScanOptions::default();
        let r = dep_reachability(&[dir.clone()], &deps, &opts);
        assert_eq!(r["serde-json"], Reach::Imported); // serde_json use
        assert_eq!(r["anyhow"], Reach::Imported);
        assert_eq!(r["lodash"], Reach::Mentioned); // comment only
        assert_eq!(r["axios"], Reach::Absent);
        let _ = fs::remove_dir_all(&dir);
    }
}
