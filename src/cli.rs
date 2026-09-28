//! Command-line surface (clap derive).

use crate::color::ColorMode;
use crate::finding::Severity;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum Format {
    #[default]
    Text,
    Json,
    /// Markdown table (PR comments, step summaries).
    Markdown,
    /// SARIF 2.1.0 (GitHub code scanning, generic tooling).
    Sarif,
    /// Code Climate JSON (GitLab codequality artifact).
    Codeclimate,
    /// Single-file interactive HTML report.
    Html,
}

#[derive(Parser)]
#[command(
    name = "argus",
    version,
    about = "Supply-chain attack indicator scanner for repositories and CI workflows",
    long_about = "Scans local checkouts or remote GitHub/GitLab/Gitea repositories for indicators of known supply-chain compromises (Shai-Hulud family, compromised GitHub Actions, malicious lifecycle scripts) and hygiene risks like mutable action tags."
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,

    #[arg(
        long,
        global = true,
        value_name = "FILE",
        help = "Config file (TOML); default: ./argus.toml or ~/.config/argus/argus.toml"
    )]
    pub config: Option<PathBuf>,

    #[arg(long, global = true, value_enum, help = "Output format")]
    pub format: Option<Format>,

    #[arg(
        long,
        global = true,
        value_enum,
        help = "Color mode (honors NO_COLOR in auto)"
    )]
    pub color: Option<ColorMode>,

    #[arg(
        short = 'j',
        long,
        global = true,
        help = "Parallel workers (files or repos)"
    )]
    pub jobs: Option<usize>,

    #[arg(
        long,
        global = true,
        help = "Auth token for all providers (env ARGUS_TOKEN)"
    )]
    pub token: Option<String>,

    #[arg(
        long,
        global = true,
        value_name = "FILE_OR_DIR",
        help = "Extra ruleset TOML file or directory"
    )]
    pub rules: Vec<PathBuf>,

    #[arg(long, global = true, help = "Do not load builtin rulesets")]
    pub no_builtin_rules: bool,

    #[arg(long, global = true, value_enum, help = "Minimum severity to report")]
    pub severity: Option<Severity>,

    #[arg(
        long,
        global = true,
        value_enum,
        help = "Findings at or above this severity set exit code 1 (default: low)"
    )]
    pub fail_on: Option<Severity>,

    #[arg(
        long,
        global = true,
        value_name = "KB",
        help = "Max file size to inspect"
    )]
    pub max_file_size_kb: Option<u64>,

    #[arg(
        long,
        global = true,
        value_name = "REGEX",
        help = "Skip repo-relative paths matching this regex (repeatable)"
    )]
    pub exclude: Vec<String>,

    #[arg(
        long,
        global = true,
        value_name = "FILE_OR_DIR",
        help = "YARA rules file or directory (.yar/.yara)"
    )]
    pub yara: Vec<PathBuf>,

    #[arg(
        long,
        global = true,
        value_name = "FILE",
        help = "Flat IoC list file (sha256/domain/IP/URL/string per line)"
    )]
    pub iocs: Vec<PathBuf>,

    #[arg(
        long,
        global = true,
        value_enum,
        help = "Severity assigned to IoC-list matches (default: high)"
    )]
    pub ioc_severity: Option<Severity>,

    #[arg(
        long,
        global = true,
        help = "Also walk .git internals (refs, hooks, config) for worm artifacts"
    )]
    pub include_git: bool,

    #[arg(
        long,
        global = true,
        value_name = "FILE",
        help = "Write report to file instead of stdout"
    )]
    pub output: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        help = "CI mode: emit ::error/::warning annotations and append step summary"
    )]
    pub ci: bool,

    #[arg(
        long,
        global = true,
        value_name = "FILE",
        help = "Load baseline of accepted findings"
    )]
    pub baseline: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        value_name = "FILE",
        help = "Write current findings as a new baseline file"
    )]
    pub write_baseline: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        help = "Only report/exit on findings not present in --baseline"
    )]
    pub fail_on_new: bool,

    #[arg(
        long,
        global = true,
        help = "Query OSV.dev for advisories on pinned deps in manifests/lockfiles"
    )]
    pub osv: bool,

    #[arg(
        long,
        global = true,
        help = "Audit git history: commits inside known compromise windows"
    )]
    pub audit_history: bool,

    #[arg(
        long,
        global = true,
        help = "Check deps against registries: confusion exposure, missing packages, unmaintained upstreams"
    )]
    pub dep_check: bool,

    #[arg(
        long = "internal-prefix",
        global = true,
        help = "Mark dep names with these prefixes as organization-internal (dependency-confusion)"
    )]
    pub internal_prefixes: Vec<String>,

    #[arg(
        long,
        global = true,
        help = "GitHub: check whether flagged workflows ran inside the compromise window"
    )]
    pub check_runs: bool,

    #[arg(
        long,
        global = true,
        value_name = "NAME",
        help = "Only run rules from this ruleset (repeatable)"
    )]
    pub ruleset: Vec<String>,

    #[arg(
        long,
        global = true,
        value_name = "ID",
        help = "Disable a rule by id (repeatable)"
    )]
    pub disable_rule: Vec<String>,

    #[arg(
        long,
        global = true,
        value_name = "REF",
        help = "PR mode: only scan files changed vs this git ref (plus untracked)"
    )]
    pub diff: Option<String>,

    #[arg(
        long,
        global = true,
        value_name = "FILE",
        help = "OpenVEX document: suppress not_affected/fixed findings, annotate under_investigation"
    )]
    pub vex: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        value_name = "FILE",
        help = "Emit an OpenVEX document for the vulnerabilities found"
    )]
    pub vex_out: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        help = "Scan only files staged for commit (pre-commit mode)"
    )]
    pub staged: bool,

    /// Disable the Landlock sandbox (Linux).
    #[arg(long, global = true)]
    pub no_sandbox: bool,

    /// Fully offline mode: no HTTP/git-remote activity at all (env: ARGUS_OFFLINE).
    #[arg(long, global = true)]
    pub offline: bool,

    #[arg(short, global = true, action = clap::ArgAction::Count, help = "Verbosity (-v, -vv)")]
    pub verbose: u8,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Scan the running system: temp dirs, systemd units, shell rc files,
    /// plus the installed foreign-package list (pacman -Qqm).
    System {
        /// Extra paths to scan on top of the default system set.
        #[arg(long)]
        extra: Vec<PathBuf>,
    },
    /// Scan local directories or repository checkouts.
    Scan {
        /// Paths to scan (default: current directory).
        #[arg(default_value = ".")]
        paths: Vec<PathBuf>,
    },
    /// Install a pre-commit hook that runs argus scan --staged.
    Init {
        /// Repo path (default: .)
        path: Option<PathBuf>,
        /// Overwrite an existing hook.
        #[arg(long)]
        force: bool,
    },

    /// Enumerate and scan repositories on GitHub or GitHub Enterprise.
    Github(RemoteArgs),
    /// Enumerate and scan repositories on GitLab or self-hosted GitLab.
    Gitlab(RemoteArgs),
    /// Enumerate and scan repositories on Gitea or Forgejo.
    Gitea(RemoteArgs),
    /// List loaded rulesets and rules.
    Rules,
    /// Update rulesets in ~/.config/argus/rules from a feed.
    /// Feed is a git URL (cloned/pulled) or https URL to a single TOML file.
    /// Without --feed, uses config defaults.rules_feed.
    RulesUpdate {
        /// Feed URL (git repo or TOML file).
        #[arg(long)]
        feed: Option<String>,
    },
    /// Print shell completions.
    Completions(CompletionsArgs),
    /// Run an MCP stdio server (JSON-RPC tools for AI agents).
    Mcp,

    /// Roam: discover repos via forge search (topic/query/code-search) and scan them.
    Roam(RoamArgs),

    /// Watch: poll repos for pushes (ls-remote / feeds) and rescan on change.
    Watch(WatchArgs),

    /// Daemon: HTTP control plane + webhook receiver + watch loop.
    Daemon(DaemonArgs),

    /// Emit a CycloneDX 1.5 SBOM (JSON) for a path's lockfiles/manifests.
    Sbom { path: PathBuf },

    /// AI-provenance analysis: agent trailers, commit velocity, prose tells.
    Ai {
        /// Repo paths (default: .)
        paths: Vec<PathBuf>,
    },

    /// Auto-fix workflow findings: pin mutable uses: refs to SHAs and
    /// add a top-level permissions block. Dry-run unless --write.
    Fix {
        /// Repo paths (default: .)
        paths: Vec<PathBuf>,
        /// Apply edits instead of listing them.
        #[arg(long)]
        write: bool,
        /// Also fix container files: pin FROM/image digests, inject
        /// USER, add no-new-privileges to compose services.
        #[arg(long)]
        containers: bool,
    },

    /// License audit: project license detection, manifest mismatch,
    /// missing license, and (with --deps) copyleft deps via registry.
    License {
        /// Repo paths (default: .)
        paths: Vec<PathBuf>,
        /// Also check dependency licenses via registry metadata.
        #[arg(long)]
        deps: bool,
    },

    /// Publish pre-flight: scan only the files a package would ship
    /// (npm pack / cargo package file list, git ls-files fallback).
    Publish {
        /// Package roots (default: .)
        paths: Vec<PathBuf>,
    },

    /// Web audit: fetch a URL and check security headers, cookies, TLS,
    /// exposed metadata (.git/.env/robots), and secrets inside
    /// client-side JS bundles and source maps.
    Web {
        /// URL to audit (https:// added if missing).
        url: String,
        /// Same-origin crawl depth (0 = just this page, cap 30 pages).
        #[arg(long, default_value = "0")]
        depth: usize,
    },

    /// Verify whether found secrets still work: extract provider tokens
    /// and check them against GitHub/GitLab/Telegram/npm/Slack/etc.
    /// Live secrets report as critical.
    Verify {
        /// Paths to scan for secrets (default: .)
        paths: Vec<PathBuf>,
    },

    /// Audit a container image: baked-in secrets, root user, history
    /// leakage; --deep also exports and scans every layer's files.
    Image {
        /// Image reference (docker/podman must be installed).
        image: String,
        /// Export the image and run the full scanner over its filesystem.
        #[arg(long)]
        deep: bool,
    },

    /// List git commit authors (name/email/count) per repo, flagging watchlist identities.
    Authors {
        /// Repo paths (default: .)
        paths: Vec<PathBuf>,
        /// Output format: text table or JSON.
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
}

#[derive(Args)]
pub struct RoamArgs {
    /// Forge to search: github | gitlab | gitea.
    #[arg(long, default_value = "github")]
    pub forge: String,
    /// API host for gitlab/gitea (github defaults to api.github.com).
    #[arg(long)]
    pub host: Option<String>,
    /// Free-text search query (forge-native syntax).
    #[arg(long)]
    pub query: Option<String>,
    /// Filter by topic.
    #[arg(long)]
    pub topic: Option<String>,
    /// Filter by language.
    #[arg(long)]
    pub language: Option<String>,
    /// Minimum stars.
    #[arg(long)]
    pub min_stars: Option<u64>,
    /// GitHub code search term (requires token): find repos containing an IoC.
    #[arg(long)]
    pub code_search: Option<String>,
    /// Max repos to scan.
    #[arg(long, default_value = "20")]
    pub limit: usize,
    /// Provider token.
    #[arg(long)]
    pub token: Option<String>,
    /// Clone destination (default: temp dir).
    #[arg(long)]
    pub workdir: Option<PathBuf>,
    /// Keep clones after scanning.
    #[arg(long)]
    pub keep: bool,
}

#[derive(Args)]
pub struct DaemonArgs {
    /// Listen address for control/webhook API.
    #[arg(long, default_value = "127.0.0.1:8694")]
    pub listen: String,
    /// Shared secret for webhook signature verification (HMAC-SHA256).
    /// Falls back to $ARGUS_WEBHOOK_SECRET.
    #[arg(long)]
    pub webhook_secret: Option<String>,
    /// URL to POST new findings to (ntfy.sh topic URL or JSON webhook).
    #[arg(long)]
    pub notify_url: Option<String>,
    /// Poll watched repos every N seconds as a webhook fallback.
    #[arg(long, default_value = "900")]
    pub interval: u64,
    /// Forge for repo enumeration: github | gitlab | gitea.
    #[arg(long, default_value = "github")]
    pub forge: String,
    #[arg(long)]
    pub host: Option<String>,
    #[arg(long)]
    pub org: Option<String>,
    #[arg(long)]
    pub user: Option<String>,
    /// Explicit repos owner/name (repeatable).
    #[arg(long)]
    pub repo: Vec<String>,
    /// Provider token.
    #[arg(long)]
    pub token: Option<String>,
    /// Persistent clone dir.
    #[arg(long)]
    pub workdir: Option<PathBuf>,
}

#[derive(Args)]
pub struct WatchArgs {
    /// Forge for repo targets: github | gitlab | gitea.
    #[arg(long, default_value = "github")]
    pub forge: String,
    #[arg(long)]
    pub host: Option<String>,
    #[arg(long)]
    pub org: Option<String>,
    #[arg(long)]
    pub user: Option<String>,
    /// Explicit repos owner/name (repeatable) - overrides org/user.
    #[arg(long)]
    pub repo: Vec<String>,
    /// Atom/RSS feed URLs to also poll (repeatable); newest entry change triggers a note.
    #[arg(long)]
    pub feed: Vec<String>,
    /// Shortcut for GitHub's advisories atom feed.
    #[arg(long)]
    pub advisories: bool,
    /// Rescan all watched repos when an advisory feed fires.
    #[arg(long)]
    pub rescan_on_feed: bool,
    /// Monitor registry maintainer sets for every dep found in watched
    /// repos; a changed maintainer list is a package-hijack signal.
    #[arg(long)]
    pub dep_watch: bool,
    /// Poll interval seconds.
    #[arg(long, default_value = "300")]
    pub interval: u64,
    /// Single pass then exit (for cron/systemd use).
    #[arg(long)]
    pub once: bool,
    /// Provider token.
    #[arg(long)]
    pub token: Option<String>,
    /// Persistent clone dir (kept between polls for incremental speed).
    #[arg(long)]
    pub workdir: Option<PathBuf>,
}

#[derive(Args)]
pub struct RemoteArgs {
    /// Scan repos of this user.
    #[arg(long, conflicts_with_all = ["org", "me"])]
    pub user: Option<String>,
    /// Scan repos of this org/group.
    #[arg(long, conflicts_with_all = ["user", "me"])]
    pub org: Option<String>,
    /// Scan repos visible to the authenticated token (default when a token is set).
    #[arg(long)]
    pub me: bool,
    /// API host, e.g. gitlab.example.com or gitea.internal.lan (default: github.com / gitlab.com).
    #[arg(long)]
    pub host: Option<String>,
    /// Provider token (env: GITHUB_TOKEN / GITLAB_TOKEN / GITEA_TOKEN / ARGUS_TOKEN).
    #[arg(long)]
    pub token: Option<String>,
    /// Username for git https clone auth (defaults per provider).
    #[arg(long)]
    pub git_user: Option<String>,
    /// Clone destination (default: temp dir).
    #[arg(long)]
    pub workdir: Option<PathBuf>,
    /// Keep clones after scanning.
    #[arg(long)]
    pub keep: bool,
    /// Skip archived repositories.
    #[arg(long)]
    pub skip_archived: bool,
    /// Skip forked repositories.
    #[arg(long)]
    pub skip_forks: bool,
    /// Skip private repositories.
    #[arg(long)]
    pub skip_private: bool,
    /// Max number of repos to scan.
    #[arg(long)]
    pub limit: Option<usize>,
    /// Only repos updated since this date (YYYY-MM-DD).
    #[arg(long)]
    pub updated_since: Option<String>,
    /// Only repos updated before this date (YYYY-MM-DD).
    #[arg(long)]
    pub updated_before: Option<String>,
    /// Audit org/repo security settings via the API (branch protection,
    /// Actions permissions, org defaults). GitHub only for now.
    #[arg(long)]
    pub settings: bool,
}

/// Generate shell completions: argus completions bash > ...
#[derive(Args)]
pub struct CompletionsArgs {
    pub shell: clap_complete::Shell,
}
