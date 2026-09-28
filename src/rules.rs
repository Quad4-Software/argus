//! TOML ruleset model, builtin rulesets, and compilation to executable matchers.

use crate::finding::Severity;
use regex::Regex;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// TOML schema
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
pub struct RuleSetFile {
    pub ruleset: RuleSetMeta,
    #[serde(rename = "rule", default)]
    pub rules: Vec<RuleDef>,
}

#[derive(Debug, serde::Deserialize)]
pub struct RuleSetMeta {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct RuleDef {
    pub id: String,
    #[serde(default)]
    pub severity: Severity,
    pub description: String,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub reference: Option<String>,
    /// Optional compromise window (YYYY-MM-DD) for run-history correlation.
    #[serde(default)]
    pub window: Option<Window>,
    #[serde(flatten)]
    pub kind: RuleKindDef,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct Window {
    pub start: String,
    pub end: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleKindDef {
    /// Fire on file content matches. With no content matchers, behaves like path.
    Content {
        /// Regex applied to the repo-relative path; file must match to be checked.
        #[serde(default)]
        path: Option<String>,
        /// Substring checks; any match fires unless contains_all.
        #[serde(default)]
        contains: Vec<String>,
        #[serde(default)]
        contains_all: bool,
        /// Content regex.
        #[serde(default)]
        regex: Option<String>,
        /// Suppression regex: if it matches anywhere in the file, rule is skipped.
        #[serde(default)]
        unless: Option<String>,
        /// Per-match suppression: matched text matching this regex is skipped.
        #[serde(default)]
        exclude: Option<String>,
    },
    /// Check uses: owner/repo@ref refs. repo = "* matches any action ref.
    ActionRef {
        repo: String,
        /// Full-length SHAs known to resolve to malicious content.
        #[serde(default)]
        malicious_shas: Vec<String>,
        /// Which refs are findings: tags (anything that is not a full SHA) or all.
        #[serde(default)]
        unsafe_refs: UnsafeRefs,
    },
    /// File content SHA-256 match (files hashed during scan).
    Hash { sha256: Vec<String> },
    /// Audit dependency-source URLs in manifests/lockfiles: flag any
    /// resolved/registry/index/source URL whose host is not in allowed_hosts.
    SourceUrl {
        #[serde(default)]
        allowed_hosts: Vec<String>,
    },
    /// Secret detection: regex must capture the candidate secret in group 1;
    /// finding fires only if it passes the entropy floor and isn't a placeholder.
    Secret {
        regex: String,
        /// Shannon entropy floor (bits/char). Default 3.8.
        entropy: Option<f64>,
        /// Minimum candidate length. Default 20.
        min_len: Option<usize>,
    },
    /// Typosquat check: flag manifest dep names within edit distance 1 of a
    /// popular package (builtin lists npm/pypi), or containing non-ASCII.
    Typosquat {
        list: String,
        #[serde(default)]
        names: Vec<String>,
    },
    /// Dependency manifest match: package names (and optional exact versions)
    /// in dependency files (package.json, lockfiles, requirements.txt, ...).
    /// A name ending in "/" is a scope/prefix match (e.g. "@emilgroup/").
    Package {
        names: Vec<String>,
        #[serde(default)]
        versions: Vec<String>,
    },
    /// Fire on the presence of a matching repo-relative path.
    Path { regex: String },
}

#[derive(Clone, Copy, Debug, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnsafeRefs {
    #[default]
    Tags,
    All,
}

// ---------------------------------------------------------------------------
// Compiled form
// ---------------------------------------------------------------------------

pub struct CompiledRule {
    pub set: String,
    pub id: String,
    pub severity: Severity,
    pub description: String,
    pub remediation: Option<String>,
    pub reference: Option<String>,
    pub window: Option<(String, String)>,
    pub kind: CompiledKind,
}

pub enum CompiledKind {
    Content {
        path: Option<Regex>,
        contains: Vec<String>,
        contains_all: bool,
        regex: Option<Regex>,
        unless: Option<Regex>,
        exclude: Option<Regex>,
    },
    ActionRef {
        uses_re: Regex,
        /// true: captures (repo, ref); false: captures (ref) for a fixed repo.
        wildcard: bool,
        malicious: HashSet<String>,
        unsafe_refs: UnsafeRefs,
    },
    Package {
        /// Matches one of the names as a whole token (or scope prefix).
        names_re: Regex,
        versions: Vec<String>,
    },
    Hash {
        sha256: HashSet<String>,
    },
    SourceUrl {
        /// (key-regex, allowed hosts)
        line_re: Regex,
        allowed: Vec<String>,
    },
    Typosquat {
        /// normalized popular names (lowercase, [-_.] -> -)
        top: HashSet<String>,
        /// ecosystem-scoped manifest paths
        scope_re: Regex,
    },
    Secret {
        re: Regex,
        entropy: f64,
        min_len: usize,
    },
    Path {
        regex: Regex,
    },
}

impl CompiledRule {
    /// Does this rule need file contents (vs only the path)?
    pub fn needs_content(&self) -> bool {
        !matches!(self.kind, CompiledKind::Path { .. })
    }

    /// Needs raw file bytes (hashing, yara) rather than text.
    pub fn needs_bytes(&self) -> bool {
        matches!(self.kind, CompiledKind::Hash { .. })
    }

    /// Builtin path scope for dependency manifests used by package rules.
    pub const DEP_MANIFESTS_RE: &'static str = concat!(
        r"(?i)(^|/)(",
        r"package\.json|package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|",
        r"yarn\.lock|bun\.lock|bun\.lockb|",
        r"requirements[^/]*\.(txt|in)|constraints[^/]*\.(txt|in)|",
        r"pyproject\.toml|setup\.py|setup\.cfg|pipfile|pipfile\.lock|poetry\.lock|uv\.lock|",
        r"environment\.ya?ml|",
        r"Cargo\.toml|Cargo\.lock|go\.mod|Gemfile\.lock|composer\.lock|Podfile\.lock|",
        r"\.github/dependabot\.ya?ml",
        r")$"
    );

    /// Pre-filter: can this rule apply to the given relative path at all?
    /// Content rules with a path regex are scoped; everything else is global.
    pub fn path_in_scope(&self, rel: &str) -> bool {
        match &self.kind {
            CompiledKind::Content { path: Some(p), .. } => p.is_match(rel),
            CompiledKind::Package { .. } | CompiledKind::SourceUrl { .. } => {
                static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
                RE.get_or_init(|| Regex::new(CompiledRule::DEP_MANIFESTS_RE).unwrap())
                    .is_match(rel)
            }
            CompiledKind::Typosquat { scope_re, .. } => scope_re.is_match(rel),
            _ => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

pub fn compile(def: &RuleDef, set: &str) -> Result<CompiledRule, String> {
    let kind = match &def.kind {
        RuleKindDef::Content {
            path,
            contains,
            contains_all,
            regex,
            unless,
            exclude,
        } => CompiledKind::Content {
            path: opt_re(path)?,
            contains: contains.clone(),
            contains_all: *contains_all,
            regex: opt_re(regex)?,
            unless: opt_re(unless)?,
            exclude: opt_re(exclude)?,
        },
        RuleKindDef::ActionRef {
            repo,
            malicious_shas,
            unsafe_refs,
        } => {
            let wildcard = repo == "*";
            let uses_re = if wildcard {
                Regex::new(r#"(?i)\buses:\s*['"]?(docker://|https?://)?([A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._/-]*)@([0-9A-Za-z._/-]+)"#)
            } else {
                Regex::new(&format!(
                    r#"(?i)\buses:\s*['"]?{}@([0-9A-Za-z._/-]+)"#,
                    regex::escape(repo)
                ))
            }
            .map_err(|e| format!("rule {}: bad action_ref regex: {e}", def.id))?;
            CompiledKind::ActionRef {
                uses_re,
                wildcard,
                malicious: malicious_shas.iter().map(|s| s.to_lowercase()).collect(),
                unsafe_refs: *unsafe_refs,
            }
        }
        RuleKindDef::Package { names, versions } => {
            if names.is_empty() {
                return Err(format!(
                    "rule {}: package rule needs non-empty `names`",
                    def.id
                ));
            }
            // Longest-first so "@scope/" prefixes win; "/" suffix = prefix match.
            let mut pats: Vec<String> = names
                .iter()
                .map(|n| {
                    if n.ends_with('/') {
                        format!("{}[A-Za-z0-9_.-]*", regex::escape(n))
                    } else {
                        regex::escape(n)
                    }
                })
                .collect();
            pats.sort_by_key(|b| std::cmp::Reverse(b.len()));
            let re = Regex::new(&format!(
                "(?i)(?:^|[^A-Za-z0-9_.@-])({})(?:[^A-Za-z0-9_-]|$)",
                pats.join("|")
            ))
            .map_err(|e| format!("rule {}: bad package regex: {e}", def.id))?;
            CompiledKind::Package {
                names_re: re,
                versions: versions.clone(),
            }
        }
        RuleKindDef::Secret {
            regex,
            entropy,
            min_len,
        } => CompiledKind::Secret {
            re: Regex::new(regex).map_err(|e| format!("rule {}: bad regex: {e}", def.id))?,
            entropy: entropy.unwrap_or(3.8),
            min_len: min_len.unwrap_or(20),
        },
        RuleKindDef::Typosquat { list, names } => {
            let mut top: HashSet<String> = HashSet::new();
            let builtin = match list.as_str() {
                "npm" => include_str!("../rules/data/top-npm.txt"),
                "pypi" => include_str!("../rules/data/top-pypi.txt"),
                "crates" => include_str!("../rules/data/top-crates.txt"),
                other => {
                    return Err(format!(
                        "rule {}: unknown typosquat list {other:?} (npm|pypi|crates)",
                        def.id
                    ))
                }
            };
            for n in builtin.lines().chain(names.iter().map(|s| s.as_str())) {
                let n = norm_name(n);
                if !n.is_empty() {
                    top.insert(n);
                }
            }
            let scope_re = Regex::new(match list.as_str() {
                "npm" => r"(?i)(^|/)(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|\.npmrc)$",
                "crates" => r"(?i)(^|/)(Cargo\.toml|Cargo\.lock)$",
                _ => r"(?i)(^|/)(requirements[^/]*\.txt|constraints\.txt|pyproject\.toml|setup\.py|setup\.cfg|Pipfile(\.lock)?|poetry\.lock|uv\.lock|environment\.ya?ml)$",
            }).map_err(|e| format!("rule {}: typosquat scope: {e}", def.id))?;
            CompiledKind::Typosquat { top, scope_re }
        }
        RuleKindDef::Hash { sha256 } => CompiledKind::Hash {
            sha256: sha256.iter().map(|s| s.to_lowercase()).collect(),
        },
        RuleKindDef::SourceUrl { allowed_hosts } => {
            let mut allowed: Vec<String> = allowed_hosts.iter().map(|h| h.to_lowercase()).collect();
            if allowed.is_empty() {
                allowed = [
                    "registry.npmjs.org",
                    "registry.yarnpkg.com",
                    "pypi.org",
                    "files.pythonhosted.org",
                    "crates.io",
                    "static.crates.io",
                    "index.crates.io",
                    "github.com",
                    "gitlab.com",
                    "rubygems.org",
                    "proxy.golang.org",
                    "sum.golang.org",
                    "packagist.org",
                    "repo.packagist.org",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect();
            }
            CompiledKind::SourceUrl {
                line_re: Regex::new(
                    r#"(?i)(resolved|registry|index[-_]?url|source|url)\s*[=:"]\s*["']?(https?://[^\s"',}\]]+)"#
                ).map_err(|e| format!("rule {}: source_url regex: {e}", def.id))?,
                allowed,
            }
        }
        RuleKindDef::Path { regex } => CompiledKind::Path {
            regex: Regex::new(regex)
                .map_err(|e| format!("rule {}: bad path regex: {e}", def.id))?,
        },
    };
    Ok(CompiledRule {
        set: set.into(),
        id: def.id.clone(),
        severity: def.severity,
        description: def.description.clone(),
        remediation: def.remediation.clone(),
        reference: def.reference.clone(),
        window: def
            .window
            .as_ref()
            .map(|w| (w.start.clone(), w.end.clone())),
        kind,
    })
}

fn opt_re(p: &Option<String>) -> Result<Option<Regex>, String> {
    match p {
        Some(s) => Regex::new(s).map(Some).map_err(|e| e.to_string()),
        None => Ok(None),
    }
}

const BUILTIN_SETS: &[(&str, &str)] = &[
    (
        "mini-shai-hulud",
        include_str!("../rules/mini-shai-hulud.toml"),
    ),
    (
        "shai-hulud-classic",
        include_str!("../rules/shai-hulud-classic.toml"),
    ),
    (
        "action-compromises",
        include_str!("../rules/action-compromises.toml"),
    ),
    ("aur-attacks", include_str!("../rules/aur.toml")),
    ("teampcp", include_str!("../rules/teampcp.toml")),
    ("pypi", include_str!("../rules/pypi.toml")),
    ("npm-generic", include_str!("../rules/npm-generic.toml")),
    (
        "manifest-hygiene",
        include_str!("../rules/manifest-hygiene.toml"),
    ),
    ("aur-pkglists", include_str!("../rules/aur-pkglists.toml")),
    (
        "workflow-security",
        include_str!("../rules/workflow-security.toml"),
    ),
    (
        "workflow-audit",
        include_str!("../rules/workflow-audit.toml"),
    ),
    (
        "actor-watchlist",
        include_str!("../rules/actor-watchlist.toml"),
    ),
    ("secrets", include_str!("../rules/secrets.toml")),
    ("crates", include_str!("../rules/crates.toml")),
    ("typosquat", include_str!("../rules/typosquat.toml")),
    ("hygiene", include_str!("../rules/hygiene.toml")),
    ("malware", include_str!("../rules/malware.toml")),
];

/// Load builtin rulesets (unless disabled) plus any extra TOML files/dirs.
pub fn load(
    extra: &[PathBuf],
    no_builtin: bool,
) -> Result<(Vec<CompiledRule>, Vec<String>), String> {
    let mut rules = Vec::new();
    let mut names = Vec::new();
    let mut seen_ids: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    let mut ingest = |text: &str, origin: &str| -> Result<(), String> {
        let f: RuleSetFile = toml::from_str(text).map_err(|e| format!("{origin}: {e}"))?;
        let v = if f.ruleset.version.is_empty() {
            String::new()
        } else {
            format!(" v{}", f.ruleset.version)
        };
        let d = if f.ruleset.description.is_empty() {
            String::new()
        } else {
            format!(" - {}", f.ruleset.description)
        };
        let s = f
            .ruleset
            .source
            .as_deref()
            .map(|s| format!(" [{}]", s))
            .unwrap_or_default();
        names.push(format!("{}{}{} ({}){}", f.ruleset.name, v, d, origin, s));
        for def in &f.rules {
            // Later sources override earlier ones (feeds > user > builtin).
            if let Some(&i) = seen_ids.get(&def.id) {
                rules[i] = compile(def, &f.ruleset.name)?;
                continue;
            }
            seen_ids.insert(def.id.clone(), rules.len());
            rules.push(compile(def, &f.ruleset.name)?);
        }
        Ok(())
    };

    if !no_builtin {
        for (name, text) in BUILTIN_SETS {
            ingest(text, name)?;
        }
    }

    // Auto-load user rules dir.
    if let Some(home) = std::env::home_dir() {
        let dir = home.join(".config/argus/rules");
        if dir.is_dir() {
            load_dir(&dir, &mut |t, o| ingest(t, o))?;
        }
    }

    for p in extra {
        if p.is_dir() {
            load_dir(p, &mut |t, o| ingest(t, o))?;
        } else {
            let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            ingest(&text, &p.display().to_string())?;
        }
    }

    Ok((rules, names))
}

fn load_dir(
    dir: &Path,
    ingest: &mut dyn FnMut(&str, &str) -> Result<(), String>,
) -> Result<(), String> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d)
            .map_err(|e| format!("{}: {e}", d.display()))?
            .flatten()
        {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "toml") {
                files.push(p);
            }
        }
    }
    files.sort();
    for f in files {
        let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        ingest(&text, &f.display().to_string())?;
    }
    Ok(())
}

/// Package-name normalization used by typosquat checks (PEP 503 style).
pub fn norm_name(s: &str) -> String {
    s.trim()
        .to_lowercase()
        .chars()
        .map(|c| if c == '_' || c == '.' { '-' } else { c })
        .collect()
}
