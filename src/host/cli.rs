// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum Cmd {
    /// TCP and UDP sockets on this host, with an optional egress allow list.
    Conns {
        /// Allow file. One `ip`, `ip:port`, `name`, `name:port`, `*:port`, or IPv4 CIDR per line.
        #[arg(long)]
        allow: Option<PathBuf>,
        /// Sample for this many seconds when no command is given.
        #[arg(long, default_value_t = 0)]
        watch: u64,
        /// Procfs root. Defaults to /proc.
        #[arg(long)]
        proc: Option<PathBuf>,
        /// Command to run while sampling. Put it after `--`.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Hash signatures and file heuristics. The database refreshes unless --no-update.
    Signatures {
        /// File or directory to scan.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Keep the cached database even when it is older than --max-age-hours.
        #[arg(long)]
        no_update: bool,
        /// Signature file or ClamAV CVD. Defaults to the cache.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Refresh when the cached database is older than this many hours.
        #[arg(long, default_value_t = 24)]
        max_age_hours: u64,
    },
    /// Open files for processes on this host.
    Files {
        /// Only paths under this file or directory.
        #[arg(long)]
        path: Option<PathBuf>,
        /// Sample for this many seconds when no command is given.
        #[arg(long, default_value_t = 0)]
        watch: u64,
        /// Procfs root. Defaults to /proc.
        #[arg(long)]
        proc: Option<PathBuf>,
        /// Command to run while sampling. Put it after `--`.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Rootkit, infostealer, and backdoor leads on this host.
    Threats {
        /// Tree to read. Defaults to /.
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// XMPP and IRC SRV records. Does not connect.
    Chat {
        /// Domain name.
        domain: String,
    },
}

impl Cmd {
    pub fn wraps_command(&self) -> bool {
        match self {
            Cmd::Conns { command, .. } | Cmd::Files { command, .. } => !command.is_empty(),
            _ => false,
        }
    }

    pub fn needs_network(&self) -> bool {
        match self {
            Cmd::Chat { .. } => true,
            Cmd::Signatures { no_update, db, .. } => !no_update && db.is_none(),
            Cmd::Conns { .. } | Cmd::Threats { .. } | Cmd::Files { .. } => false,
        }
    }
}
