// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Command-line surface (clap derive).

use crate::color::ColorMode;
use crate::finding::Severity;
use crate::progress::ProgressMode;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

mod args;
pub use args::*;

mod gates;
pub use gates::*;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum SbomFmt {
    #[default]
    Cyclonedx,
    Spdx,
}

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
        long,
        global = true,
        value_enum,
        help = "Progress display on stderr (auto hides it when not a tty or with -v)"
    )]
    pub progress: Option<ProgressMode>,

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

    #[arg(
        long = "rules-pubkey",
        global = true,
        help = "Require --rules files to carry a valid .toml.sig by this ed25519 public key"
    )]
    pub rules_pubkey: Option<PathBuf>,

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
        help = "Walk everything: skip .gitignore/.ignore handling and the built-in dependency/build dir pruning"
    )]
    pub no_prune: bool,

    #[arg(
        long,
        global = true,
        help = "Live-verify provider-shaped tokens found during scan (needs network)"
    )]
    pub verify_secrets: bool,

    #[arg(
        long,
        global = true,
        help = "Do not enrich advisory findings with EPSS/KEV data"
    )]
    pub no_enrich: bool,

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
        value_name = "FILE",
        help = "Require the baseline to verify with this ed25519 pubkey"
    )]
    pub baseline_pubkey: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        value_name = "FILE",
        help = "ed25519 key for signing baselines and scan attestations"
    )]
    pub baseline_key: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        value_name = "FILE",
        help = "Write a detached .sig for an existing baseline (needs --baseline-key)"
    )]
    pub baseline_sign: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        value_name = "FILE",
        help = "Write baseline v2 with provenance and content fingerprints"
    )]
    pub write_baseline_v2: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        value_name = "STR",
        help = "Recorded reviewer for --write-baseline-v2"
    )]
    pub baseline_reviewed_by: Option<String>,

    #[arg(
        long,
        global = true,
        value_name = "STR",
        help = "Recorded review reason for --write-baseline-v2"
    )]
    pub baseline_reason: Option<String>,

    #[arg(
        long,
        global = true,
        value_name = "STR",
        help = "Per-entry note for --write-baseline-v2"
    )]
    pub baseline_note: Option<String>,

    #[arg(
        long,
        global = true,
        value_name = "N",
        help = "Baseline expiry in days from now (--write-baseline-v2)"
    )]
    pub baseline_ttl_days: Option<u64>,

    #[arg(
        long,
        global = true,
        value_name = "FILE",
        help = "Emit a signed in-toto scan attestation to FILE"
    )]
    pub emit_attestation: Option<PathBuf>,

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
        long = "store",
        global = true,
        help = "Persist this scan to ~/.local/share/argus/argus.db for trend diffs"
    )]
    pub store: bool,

    #[arg(
        long = "incremental",
        global = true,
        help = "Reuse findings for unchanged files via .arguscache.json"
    )]
    pub incremental: bool,

    #[arg(
        long = "history-secrets",
        global = true,
        help = "Scan git history diffs for secrets committed and later removed (up to 500 commits)"
    )]
    pub history_secrets: bool,

    #[arg(
        long = "similar",
        global = true,
        value_name = "PATH",
        help = "Vendored-code check: compare scanned files against this reference tree (winnowing fingerprints)"
    )]
    pub similar: Option<PathBuf>,

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
    /// Connections, signatures, threat leads, and chat service records.
    #[command(flatten)]
    Host(crate::host::Cmd),

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
    /// Generate an ed25519 keypair for ruleset signing.
    RulesKeygen {
        /// Private key output (PEM).
        #[arg(long)]
        privkey: PathBuf,
        /// Public key output (PEM).
        #[arg(long)]
        pubkey: PathBuf,
    },
    /// Detached-sign a ruleset file, writing a .sig file beside it.
    RulesSign {
        /// Ruleset TOML to sign.
        file: PathBuf,
        /// ed25519 private key PEM.
        #[arg(long)]
        key: PathBuf,
    },
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

    /// Emit an SBOM (CycloneDX 1.5 or SPDX 2.3) for a path's lockfiles.
    Sbom {
        /// Root path to inventory.
        path: PathBuf,
        /// SBOM spec: cyclonedx (default) or spdx.
        #[arg(long, value_enum, default_value = "cyclonedx")]
        sbom_format: SbomFmt,
    },

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
        /// Flip unsafe IaC booleans (encryption, public acl, deletion
        /// protection, public-ip mapping).
        #[arg(long)]
        iac: bool,
        /// Bump pinned deps to OSV-fixed versions (requirements.txt,
        /// Cargo.toml). Queries OSV; needs network.
        #[arg(long)]
        deps: bool,
    },

    /// Interactive triage: walk findings, suppress via .argusignore.
    Review {
        /// Repo paths (default: .)
        paths: Vec<PathBuf>,
    },

    /// Trend diff: what appeared, what fixed, what persists across
    /// stored scans of a root. Requires `argus scan --store` history.
    Trends {
        /// Root path to diff.
        path: PathBuf,
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

    /// Domain OSINT. DNS, RDAP, certificate names, Wayback hosts, and the public page.
    Domain {
        /// Domain name or https URL.
        domain: String,
    },

    /// IP OSINT. Geolocation, ASN, VPN classification, RDAP, Shodan InternetDB, and Hudson Rock.
    Ip {
        /// Download the DB-IP City Lite database into the local cache.
        #[arg(long)]
        download: bool,
        /// Public address. Omit it when you only want --download.
        ip: Option<String>,
    },

    /// Email OSINT. Mailbox syntax, mail DNS, keys, and optional breach lookup.
    Email {
        /// Address to check.
        email: String,
        /// Ask the mail server on port 25 whether this address is accepted.
        #[arg(long)]
        smtp: bool,
    },

    /// File hash lookup. CIRCL hashlookup, plus MalwareBazaar when ABUSECH_AUTH_KEY is set.
    Hash {
        /// MD5, SHA-1, or SHA-256 hex digest.
        hash: String,
    },

    /// Public URL check. One fetch, redirect chain, and WAF or challenge markers.
    Url {
        /// http or https URL.
        url: String,
    },

    /// TCP connect scan of one host. Modern ports are tried first.
    Ports {
        /// Host name, address, or http URL. A network range is refused.
        host: String,
        /// Comma list or ranges, such as 443,80,8000-8010.
        #[arg(long)]
        ports: Option<String>,
        /// Check TCP ports 1 through 65535, still starting with the modern list.
        #[arg(long)]
        all: bool,
    },

    /// Threat intel lookup. OTX and ThreatFox need API keys. Feodo Tracker does not.
    Intel {
        /// IP, domain, URL, or file hash.
        indicator: String,
    },

    /// Recursive supply-chain inventory from lockfiles in a tree.
    Supply {
        /// Project root.
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Search stored records.
    Records {
        /// Text to find in keys and saved reports.
        query: String,
    },

    /// Local JSON API for records, intel, and tracker checks.
    Api {
        /// Listen address. Defaults to localhost.
        #[arg(long, default_value = "127.0.0.1:9876")]
        listen: String,
    },

    /// Structural steganography check across common file formats.
    Stego {
        /// File or directory.
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Base64 or base32 encode and decode (RFC 4648).
    Codec {
        /// encode or decode.
        mode: String,
        /// base64 or base32.
        alphabet: String,
        /// Input text. Omit or pass - to read stdin.
        text: Option<String>,
    },

    /// Pairwise style distance for prose or source code.
    Style {
        /// First file or directory.
        a: PathBuf,
        /// Second file or directory.
        b: PathBuf,
        /// prose or code. Omit to decide from the text.
        #[arg(long)]
        kind: Option<String>,
    },

    /// Public GitHub or GitLab account metadata.
    Account {
        /// github or gitlab.
        forge: String,
        /// Account login.
        login: String,
        /// GitLab host when it is not gitlab.com.
        #[arg(long)]
        host: Option<String>,
    },

    /// Social and resume links from a page, including link-in-bio hubs.
    Socials {
        /// http or https page.
        url: String,
    },

    /// Fetch and search an RSS, Atom, or JSON feed.
    Feed {
        /// Feed URL.
        url: String,
        /// Case-insensitive match against titles and summaries.
        #[arg(long)]
        query: Option<String>,
    },

    /// Git author and committer names, emails, remotes, and exposed .git metadata.
    Gitmeta {
        /// Local path or public http(s) URL.
        #[arg(default_value = ".")]
        target: String,
    },

    /// Stream a search over text, CSV, JSON, JSONL, or SQLite.
    Grep {
        /// Regex. Use this when --pick or --eq is also set.
        #[arg(long)]
        pattern: Option<String>,
        /// Files or directories. Use - for stdin.
        /// Without --pick, --eq, or --pattern, the first value is the regex.
        paths: Vec<PathBuf>,
        /// emails, urls, addrs, hashes, or wallets.
        #[arg(long)]
        pick: Option<String>,
        /// Column or JSON field. One dot is allowed in JSON.
        #[arg(long)]
        column: Option<String>,
        /// Exact field or line value.
        #[arg(long)]
        eq: Option<String>,
        /// auto, text, csv, tsv, json, jsonl, or sqlite.
        #[arg(long, default_value = "auto")]
        kind: String,
        /// SQLite table. Omit to walk user tables.
        #[arg(long)]
        table: Option<String>,
        /// Stop after this many matches. 0 means no cap.
        #[arg(long, default_value_t = 100)]
        max: usize,
        /// Case-insensitive pattern.
        #[arg(short = 'i', long)]
        ignore_case: bool,
    },

    /// Emails, URLs, addresses, hashes, and wallet-shaped strings.
    Extract {
        /// File, URL, or a short blob of text. - reads stdin.
        target: String,
    },

    /// PDF, JPEG, PNG, and docx metadata.
    Meta { path: PathBuf },

    /// Provenance markers in images, audio, and video. A hit is a declaration, not proof.
    Media {
        /// File or directory.
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Search links for a domain, email, or name. Nothing is fetched.
    Dork { query: String },

    /// Favicon hash for Shodan http.favicon.hash and FOFA icon_hash.
    Favicon {
        /// Site or direct icon URL.
        url: String,
    },

    /// Public username check against a small built-in site table.
    User { name: String },

    /// Keybase profile, identity proofs, and the public device list.
    Keybase {
        /// Keybase username.
        name: String,
    },

    /// Public Steam community profile: persona, identity, counts, and
    /// recent games. Private profiles report what they hide.
    Steam {
        /// Vanity name, id64, or profile URL.
        target: String,
    },

    /// Public Bluesky profile via the appview: DID, counts, self-labels,
    /// and verification. No account needed.
    Bluesky {
        /// Handle, DID, or bsky.app profile URL.
        handle: String,
    },

    /// Public Mastodon account: profile, counts, flags, and profile
    /// fields. The lookup endpoint needs no token.
    Mastodon {
        /// user@instance or a profile URL.
        target: String,
        /// Instance used for a bare username.
        #[arg(long, default_value = "mastodon.social")]
        instance: String,
    },

    /// Public Reddit account history from the Arctic Shift archive:
    /// karma, archive counts, and recent posts and comments.
    Reddit {
        /// Username, u/name, or profile URL.
        user: String,
    },

    /// Public YouTube video or channel: oembed metadata, subscribers,
    /// verification, and recent uploads from the Atom feed.
    Youtube {
        /// Video id or url, @handle, or channel url.
        target: String,
    },

    /// Public TikTok video or profile: oembed metadata and the page
    /// account blob (followers, likes, verification, bio links).
    Tiktok {
        /// Video id or url, @user, or profile url.
        target: String,
    },

    /// Public Lemmy account: person view, counts, moderated
    /// communities, and recent posts and comments.
    Lemmy {
        /// name@instance or a /u/ URL.
        target: String,
        /// Instance used for a bare username.
        #[arg(long)]
        instance: Option<String>,
    },

    /// GHArchive firehose: filter hourly dumps of all public GitHub
    /// events (data.gharchive.org) for one org, user, or repo. Push SHAs
    /// survive force pushes and branch deletes in the archive.
    Gharchive(GharchiveArgs),

    /// Lookalike domains: dnstwist-style permutations of the registered
    /// label (omission, transposition, bitsquat, confusables, TLD swap)
    /// resolved over DNS. A live lookalike with MX is phishing-capable.
    Typo {
        /// Domain to permute (registered form, e.g. example.com).
        domain: String,
    },

    /// List built-in modules.
    Modules,

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

    /// Verify a sigstore bundle, npm publish attestation, or cosign
    /// .sig/.cert pair - offline against embedded Fulcio/Rekor roots.
    Attest {
        /// .sigstore.json / .bundle file to verify.
        bundle: Option<PathBuf>,
        /// Artifact file the attestation claims to cover (digest check).
        #[arg(long, value_name = "FILE")]
        artifact: Option<PathBuf>,
        /// Fetch and verify npm publish attestations for package or package@version.
        #[arg(long, value_name = "PKG")]
        npm: Option<String>,
        /// Legacy cosign mode: detached .sig file (base64 or raw).
        #[arg(long, value_name = "FILE")]
        sig: Option<PathBuf>,
        /// Legacy cosign mode: signing .cert/.crt PEM file.
        #[arg(long, value_name = "FILE")]
        cert: Option<PathBuf>,
        /// PEM public key for a private rekor/tlog instance (production
        /// rekor.sigstore.dev key is already embedded).
        #[arg(long, value_name = "FILE")]
        rekor_pub: Option<PathBuf>,
        /// Require the attested source repo to match (substring, e.g. owner/name).
        #[arg(long, value_name = "REPO")]
        expect_repo: Option<String>,
        /// Require a certificate identity SAN to match.
        #[arg(long, value_name = "SAN")]
        expect_identity: Option<String>,
        /// Require the OIDC issuer to match exactly.
        #[arg(long, value_name = "URL")]
        expect_issuer: Option<String>,
        /// Verify a scan attestation emitted via --emit-attestation.
        #[arg(long, value_name = "FILE")]
        verify_attestation: Option<PathBuf>,
        /// Public key for --verify-attestation (rulesign hex format).
        #[arg(long, value_name = "FILE")]
        attest_pubkey: Option<PathBuf>,
    },

    /// Code similarity scoring: normalized-token winnowing fingerprints.
    /// Two paths = pair score; one path = near-duplicate pairs inside it.
    Similar {
        /// Left side (file or directory).
        a: PathBuf,
        /// Right side (file or directory). Omit for internal dedup of `a`.
        b: Option<PathBuf>,
        /// Fingerprint index DB (default: ~/.local/share/argus/similar.db).
        #[arg(long, value_name = "FILE")]
        index: Option<PathBuf>,
        /// Fingerprint files under `a` into the index (corpus build mode).
        #[arg(long)]
        index_build: bool,
        /// Score files under `a` against the indexed corpus (MinHash LSH).
        #[arg(long)]
        index_query: bool,
        /// Download a signed similarity corpus from URL (db + .sig verified).
        #[arg(long, value_name = "URL")]
        fetch_corpus: Option<String>,
        /// Corpus DB path (default: ~/.local/share/argus/corpus.db).
        #[arg(long, value_name = "FILE")]
        corpus_db: Option<PathBuf>,
        /// Ed25519 pubkey for the corpus (default: embedded release key).
        #[arg(long, value_name = "FILE")]
        corpus_pubkey: Option<PathBuf>,
        /// Also query the downloaded corpus during --index-query.
        #[arg(long)]
        index_lookup_corpus: bool,
        /// Build a corpus db from files under `a`, tagged with NAME.
        #[arg(long, value_name = "NAME")]
        corpus_build: Option<String>,
    },

    /// Audit a container image: baked-in secrets, root user, history
    /// leakage; --deep also exports and scans every layer's files.
    Image {
        /// Image reference (docker/podman must be installed, or use --remote).
        image: String,
        /// Export the image and run the full scanner over its filesystem.
        #[arg(long)]
        deep: bool,
        /// Query the registry directly over the OCI API (no container runtime).
        #[arg(long)]
        remote: bool,
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
