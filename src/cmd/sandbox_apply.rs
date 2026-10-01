// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

use crate::cli::{Cli, Cmd};
use crate::sandbox;
use crate::scan::ScanOptions;
use std::path::PathBuf;

pub(crate) fn apply_sandbox(cli: &Cli, opts: &ScanOptions) {
    let net_needed = cli.osv
        || cli.dep_check
        || cli.check_runs
        || cfg_needs_net(&cli.cmd)
        || matches!(
            cli.cmd,
            Cmd::Daemon(_)
                | Cmd::Fix { .. }
                | Cmd::Web { .. }
                | Cmd::Verify { .. }
                | Cmd::Domain { .. }
                | Cmd::Email { .. }
                | Cmd::Ip { .. }
                | Cmd::Hash { .. }
                | Cmd::Url { .. }
                | Cmd::Ports { .. }
                | Cmd::Intel { .. }
                | Cmd::Api { .. }
        );
    let mut sb = sandbox::Sandbox {
        reads: Vec::new(),
        writes: Vec::new(),
        net_ports: if net_needed { vec![443, 22] } else { vec![] },
        // remote commands reach arbitrary forge ports; local scans get none
        net_open: net_needed,
        net_bind_ports: match &cli.cmd {
            Cmd::Daemon(a) => a
                .listen
                .rsplit(':')
                .next()
                .and_then(|p| p.parse().ok())
                .into_iter()
                .collect(),
            Cmd::Api { listen } => listen
                .rsplit(':')
                .next()
                .and_then(|p| p.parse().ok())
                .into_iter()
                .collect(),
            _ => vec![],
        },
    };
    // resolver + TLS roots needed whenever we do any I/O that might resolve;
    // cheap to grant read-only
    // Resolver/TLS roots, /proc (Rust reads /proc/self/fd when spawning
    // children), /sys, /dev, and every PATH dir (execvpe stats each entry).
    for p in [
        "/etc",
        "/usr/share",
        "/proc",
        "/sys",
        "/dev",
        "/usr/lib",
        "/lib",
    ] {
        sb.reads.push(p.into());
    }
    for d in std::env::var("PATH").unwrap_or_default().split(':') {
        if !d.is_empty() {
            sb.reads.push(PathBuf::from(d));
        }
    }
    sb.writes.push("/dev/null".into());
    // git subprocesses (clone/diff/audit) read user config
    if let Some(h) = std::env::home_dir() {
        sb.reads.push(h.join(".gitconfig"));
        sb.reads.push(h.join(".config/git"));
        sb.reads.push(h.join(".ssh"));
    }
    match &cli.cmd {
        Cmd::Scan { paths } | Cmd::Review { paths } => {
            sb.reads.extend(paths.iter().cloned());
            // review writes .argusignore in cwd
            if matches!(cli.cmd, Cmd::Review { .. }) {
                sb.writes.push(std::path::PathBuf::from(".argusignore"));
            }
            if cli.incremental {
                // shared cache dir keyed by canonical root
                sb.writes.push(crate::cache::cache_dir());
            }
            if let Some(r) = &cli.similar {
                sb.reads.push(r.clone());
            }
        }
        Cmd::Similar { a, b } => {
            sb.reads.push(a.clone());
            if let Some(b) = b {
                sb.reads.push(b.clone());
            }
        }
        Cmd::Host(h) => crate::host::grant(h, &mut sb),
        Cmd::System { extra } => {
            sb.reads.extend(extra.iter().cloned());
            for p in [
                "/tmp",
                "/var/tmp",
                "/dev/shm",
                "/etc",
                "/usr/lib/systemd",
                "/var/spool/cron",
                "/proc",
                "/sys",
                "/boot",
                "/run",
            ] {
                sb.reads.push(p.into());
            }
            for base in ["/root", "/home"] {
                sb.reads.push(base.into());
            }
            if let Some(h) = std::env::home_dir() {
                sb.reads.push(h);
            }
        }
        Cmd::Github(a) | Cmd::Gitlab(a) | Cmd::Gitea(a) => {
            let dir = a.workdir.clone().unwrap_or_else(|| {
                std::env::temp_dir().join(format!("argus-{}", std::process::id()))
            });
            // PathFd::new needs the dir to exist for the grant to take.
            let _ = std::fs::create_dir_all(&dir);
            if let Some(h) = std::env::home_dir() {
                sb.reads.push(h);
            }
            sb.writes.push(dir.clone());
            sb.reads.push(dir);
        }
        Cmd::Roam(a) => {
            let dir = a.workdir.clone().unwrap_or_else(|| {
                std::env::temp_dir().join(format!("argus-roam-{}", std::process::id()))
            });
            let _ = std::fs::create_dir_all(&dir);
            sb.writes.push(dir.clone());
            sb.reads.push(dir);
            if let Some(h) = std::env::home_dir() {
                sb.reads.push(h);
            }
        }
        Cmd::Watch(a) => {
            let dir = a.workdir.clone().unwrap_or_else(|| {
                std::env::home_dir()
                    .unwrap_or_else(|| "/tmp".into())
                    .join(".local/share/argus/watch-clones")
            });
            let _ = std::fs::create_dir_all(&dir);
            sb.writes.push(dir.clone());
            sb.reads.push(dir);
            if let Some(h) = std::env::home_dir() {
                sb.writes.push(h.join(".local/share/argus"));
                sb.reads.push(h);
            }
        }
        Cmd::Daemon(a) => {
            let dir = a.workdir.clone().unwrap_or_else(|| {
                std::env::home_dir()
                    .unwrap_or_else(|| "/tmp".into())
                    .join(".local/share/argus/daemon-clones")
            });
            let _ = std::fs::create_dir_all(&dir);
            sb.writes.push(dir.clone());
            sb.reads.push(dir);
            if let Some(h) = std::env::home_dir() {
                sb.writes.push(h.join(".local/share/argus"));
                sb.reads.push(h);
            }
        }
        Cmd::Mcp => {
            // agent tool: arbitrary scan targets requested per call; read-only
            // fs, no net, no write is still a real constraint
            sb.reads.push("/".into());
        }
        Cmd::Authors { paths, .. } => sb.reads.extend(paths.iter().cloned()),
        Cmd::Sbom { path, .. } => sb.reads.push(path.clone()),
        Cmd::Ai { paths } => sb.reads.extend(paths.iter().cloned()),
        Cmd::License { paths, .. } => sb.reads.extend(paths.iter().cloned()),
        Cmd::Publish { paths } => {
            // read the package root; packager caches go under a scratch dir
            sb.reads.extend(paths.iter().cloned());
            if let Some(h) = std::env::home_dir() {
                // cargo reads its cached registry index; npm reads config
                sb.reads.push(h.join(".cargo"));
                sb.reads.push(h.join(".rustup"));
                sb.reads.push(h.join(".npmrc"));
                sb.reads.push(h.join(".config/npm"));
            }
            let s = std::env::temp_dir().join(format!("argus-publish-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&s);
            sb.writes.push(s);
        }
        Cmd::Verify { paths } => {
            sb.reads.extend(paths.iter().cloned());
        }
        Cmd::Init { path, .. } => {
            let root = path.clone().unwrap_or_else(|| PathBuf::from("."));
            sb.reads.push(root.clone());
            sb.writes.push(root.join(".git/hooks"));
        }
        Cmd::Fix { paths, write, .. } => {
            sb.reads.extend(paths.iter().cloned());
            if *write {
                sb.writes.extend(paths.iter().cloned());
            }
        }
        Cmd::Image { remote: true, .. } => {
            sb.net_open = true; // registry api on arbitrary hosts/ports
        }
        Cmd::Image { deep, .. } => {
            sb.reads.push("/var/run".into());
            sb.reads.push("/run/user".into());
            sb.writes.push("/run/user".into());
            let xdg = std::env::temp_dir().join(format!("argus-image-xdg-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&xdg);
            sb.writes.push(xdg);
            // podman spawns helpers (crun, conmon, catatonit) and reads
            // cgroup state under /sys/fs/cgroup - /sys is already granted
            if let Some(h) = std::env::home_dir() {
                sb.reads.push(h.join(".docker"));
                sb.reads.push(h.join(".config/containers"));
                // rootless podman storage + its lock/pid files
                sb.writes.push(h.join(".local/share/containers"));
                sb.reads.push(h.join(".local/share/containers"));
                sb.writes.push(h.join(".config/containers"));
            }
            if *deep {
                let wd = std::env::temp_dir().join(format!("argus-image-{}", std::process::id()));
                let _ = std::fs::create_dir_all(&wd);
                sb.writes.push(wd.clone());
                sb.reads.push(wd);
            }
        }
        Cmd::Ip { .. } => {
            let dir = crate::cache::cache_dir();
            sb.reads.push(dir.clone());
            sb.writes.push(dir);
        }
        Cmd::Supply { path } | Cmd::Stego { path } | Cmd::Media { path } => {
            sb.reads.push(path.clone());
        }
        Cmd::Style { a, b, .. } => {
            sb.reads.push(a.clone());
            sb.reads.push(b.clone());
        }
        Cmd::Gitmeta { target } if !crate::cli::is_http_target(target) => {
            sb.reads.push(PathBuf::from(target));
        }
        Cmd::Grep {
            pattern,
            paths,
            pick,
            eq,
            ..
        } => {
            let (_, paths) = crate::search::positionals(
                pattern.clone(),
                paths.clone(),
                pick.is_some() || eq.is_some(),
            );
            for p in paths {
                if p.as_os_str() != "-" {
                    sb.reads.push(p);
                }
            }
        }
        Cmd::Meta { path } => sb.reads.push(path.clone()),
        Cmd::Extract { target } if !crate::cli::is_http_target(target) => {
            sb.reads.push(PathBuf::from(target));
        }
        _ => {}
    }
    if cli.store || matches!(cli.cmd, Cmd::Records { .. } | Cmd::Api { .. }) {
        let path = crate::store::db_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
            sb.reads.push(parent.to_path_buf());
            sb.writes.push(parent.to_path_buf());
        }
    }
    if let Some(out) = &cli.output
        && let Some(parent) = out.parent()
    {
        sb.writes.push(parent.to_path_buf());
    }
    if let Some(vx) = &cli.vex {
        sb.reads.push(vx.clone());
    }
    if let Some(vout) = &cli.vex_out
        && let Some(parent) = vout.parent()
    {
        sb.writes.push(parent.to_path_buf());
    }
    if let Some(bp) = &cli.baseline
        && let Some(parent) = bp.parent()
    {
        sb.reads.push(parent.to_path_buf());
    }
    if let Some(bp) = &cli.baseline
        && let Some(parent) = bp.parent()
    {
        sb.reads.push(parent.to_path_buf());
    }
    if let Some(bp) = &cli.write_baseline
        && let Some(parent) = bp.parent()
    {
        sb.writes.push(parent.to_path_buf());
    }
    let _ = opts;
    if let Err(e) = sandbox::apply(&sb) {
        eprintln!("warn: sandbox not applied: {e}");
    } else if cli.verbose > 0 {
        eprintln!("landlock sandbox applied");
    }
}

pub(crate) fn cfg_needs_net(cmd: &Cmd) -> bool {
    matches!(
        cmd,
        Cmd::Github(_)
            | Cmd::Gitlab(_)
            | Cmd::Gitea(_)
            | Cmd::Roam(_)
            | Cmd::Watch(_)
            | Cmd::Daemon(_)
            | Cmd::Domain { .. }
            | Cmd::Email { .. }
            | Cmd::Ip { .. }
            | Cmd::Hash { .. }
            | Cmd::Url { .. }
            | Cmd::Ports { .. }
            | Cmd::Intel { .. }
            | Cmd::Api { .. }
            | Cmd::Account { .. }
            | Cmd::Socials { .. }
            | Cmd::Feed { .. }
            | Cmd::Favicon { .. }
            | Cmd::User { .. }
    ) || matches!(cmd, Cmd::Gitmeta { target } if crate::cli::is_http_target(target))
        || matches!(cmd, Cmd::Extract { target } if crate::cli::is_http_target(target))
        || matches!(cmd, Cmd::Host(h) if h.needs_network())
}

// ---------------- roam ----------------
