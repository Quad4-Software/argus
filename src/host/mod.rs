// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Host connections, signature scan, and local threat leads.

mod cli;
mod conns;
mod files;
mod sigscan;
mod threats;

pub use cli::Cmd;
pub use conns::{
    Allow, Flow, is_metadata, observe, parse_allow, pending_names, proc_root, remember_name,
    unexpected,
};
pub use files::{Touch, collect as collect_files, proc_root as files_root};
pub use sigscan::scan as scan_signatures;
pub use threats::scan as scan_threats;

use crate::sandbox::Sandbox;
use std::path::PathBuf;

pub fn grant(cmd: &Cmd, sb: &mut Sandbox) {
    match cmd {
        Cmd::Signatures { path, db, .. } => {
            sb.reads.push(path.clone());
            if let Some(db) = db {
                sb.reads.push(db.clone());
            }
            let dir = crate::cache::cache_dir().join("malware");
            let _ = std::fs::create_dir_all(&dir);
            sb.reads.push(dir.clone());
            sb.writes.push(dir);
        }
        Cmd::Threats { root } => {
            if let Some(root) = root {
                sb.reads.push(root.clone());
            }
            for p in [
                "/tmp",
                "/var/tmp",
                "/dev/shm",
                "/etc",
                "/usr/lib/systemd",
                "/var/spool/cron",
                "/proc",
                "/sys",
            ] {
                sb.reads.push(p.into());
            }
        }
        Cmd::Files { path, proc, .. } => {
            sb.reads
                .push(proc.clone().unwrap_or_else(|| PathBuf::from("/proc")));
            if let Some(path) = path {
                sb.reads.push(path.clone());
            }
        }
        Cmd::Conns { allow, proc, .. } => {
            sb.reads
                .push(proc.clone().unwrap_or_else(|| PathBuf::from("/proc")));
            if let Some(allow) = allow {
                sb.reads.push(allow.clone());
            }
        }
        Cmd::Chat { .. } => {}
    }
}
