// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Argument structs for subcommands with their own option sets.

use clap::Args;
use std::path::PathBuf;

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
