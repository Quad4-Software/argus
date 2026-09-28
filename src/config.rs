//! TOML config file + flag/env/config precedence resolution.

use crate::cli::Format;
use crate::color::ColorMode;
use crate::finding::Severity;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, serde::Deserialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub tokens: Tokens,
    #[serde(default)]
    pub github: ProviderConf,
    #[serde(default)]
    pub gitlab: ProviderConf,
    #[serde(default)]
    pub gitea: ProviderConf,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct Defaults {
    pub format: Option<Format>,
    pub color: Option<ColorMode>,
    pub jobs: Option<usize>,
    pub severity: Option<Severity>,
    pub fail_on: Option<Severity>,
    pub max_file_size_kb: Option<u64>,
    #[serde(default)]
    pub rules_dirs: Vec<PathBuf>,
    #[serde(default)]
    pub excludes: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub yara_dirs: Vec<PathBuf>,
    #[serde(default)]
    pub ioc_files: Vec<PathBuf>,
    #[serde(default)]
    pub ci: Option<bool>,
    #[serde(default)]
    pub disable_rules: Vec<String>,
    #[serde(default)]
    pub rulesets: Vec<String>,
    #[serde(default)]
    pub osv: Option<bool>,
    #[serde(default)]
    pub audit_history: Option<bool>,
    #[serde(default)]
    pub check_runs: Option<bool>,
    #[serde(default)]
    pub baseline: Option<String>,
    #[serde(default)]
    pub rules_feed: Option<String>,
    #[serde(default)]
    pub no_sandbox: Option<bool>,
    #[serde(default)]
    pub offline: Option<bool>,

    /// Dependency-name prefixes treated as organization-internal for
    /// dependency-confusion detection (e.g. "@myorg", "internal-").
    #[serde(default)]
    pub internal_prefixes: Vec<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct Tokens {
    pub github: Option<String>,
    pub gitlab: Option<String>,
    pub gitea: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct ProviderConf {
    pub host: Option<String>,
    pub git_user: Option<String>,
}

impl<'de> serde::Deserialize<'de> for Format {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        match s.to_ascii_lowercase().as_str() {
            "text" => Ok(Format::Text),
            "json" => Ok(Format::Json),
            "markdown" | "md" => Ok(Format::Markdown),
            "sarif" => Ok(Format::Sarif),
            "codeclimate" | "code_quality" => Ok(Format::Codeclimate),
            other => Err(serde::de::Error::custom(format!("bad format {other:?}"))),
        }
    }
}

impl<'de> serde::Deserialize<'de> for ColorMode {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(ColorMode::Auto),
            "always" => Ok(ColorMode::Always),
            "never" => Ok(ColorMode::Never),
            other => Err(serde::de::Error::custom(format!(
                "bad color mode {other:?}"
            ))),
        }
    }
}

/// Config file search order: --config > ARGUS_CONFIG > ./argus.toml > ~/.config/argus/argus.toml
pub fn load(explicit: Option<&Path>) -> Result<(ConfigFile, Option<PathBuf>), String> {
    let path: Option<PathBuf> = if let Some(p) = explicit {
        Some(p.to_path_buf())
    } else if let Ok(p) = std::env::var("ARGUS_CONFIG") {
        Some(PathBuf::from(p))
    } else if Path::new("argus.toml").is_file() {
        Some(PathBuf::from("argus.toml"))
    } else {
        std::env::home_dir()
            .map(|h| h.join(".config/argus/argus.toml"))
            .filter(|p| p.is_file())
    };
    match path {
        Some(p) => {
            let text =
                std::fs::read_to_string(&p).map_err(|e| format!("config {}: {e}", p.display()))?;
            let cfg: ConfigFile =
                toml::from_str(&text).map_err(|e| format!("config {}: {e}", p.display()))?;
            Ok((cfg, Some(p)))
        }
        None => Ok((ConfigFile::default(), None)),
    }
}

/// Token precedence: provider flag > global flag > provider env > ARGUS_TOKEN > config.
pub fn resolve_token(
    flag: Option<&str>,
    global_flag: Option<&str>,
    envs: &[&str],
    cfg: Option<&str>,
) -> Option<String> {
    if let Some(t) = flag.filter(|s| !s.is_empty()) {
        return Some(t.to_string());
    }
    if let Some(t) = global_flag.filter(|s| !s.is_empty()) {
        return Some(t.to_string());
    }
    for e in envs {
        if let Ok(v) = std::env::var(e) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    cfg.filter(|s| !s.is_empty()).map(str::to_string)
}
