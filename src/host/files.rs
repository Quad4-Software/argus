// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Open files for processes on this host.
//! Reads comm, cwd, exe, and fd symlinks under a procfs root.
//! A watched path reports the processes that currently have it open.
//! A short poll covers files that are opened and closed while a command runs.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Touch {
    pub pid: u32,
    pub comm: String,
    pub kind: String,
    pub path: String,
}

pub fn proc_root(proc: Option<&PathBuf>) -> PathBuf {
    proc.cloned().unwrap_or_else(|| PathBuf::from("/proc"))
}

pub fn collect(
    root: &Path,
    watch: Option<&Path>,
    command: &[String],
    seconds: u64,
) -> Result<(Vec<Touch>, Option<i32>), String> {
    let mut seen = BTreeSet::new();
    let mut child = if command.is_empty() {
        None
    } else {
        let mut cmd = Command::new(&command[0]);
        cmd.args(&command[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        Some(
            cmd.spawn()
                .map_err(|e| format!("spawn {}: {e}", command[0]))?,
        )
    };
    let deadline =
        Instant::now() + Duration::from_secs(seconds.max(if command.is_empty() { 0 } else { 30 }));
    loop {
        for row in snapshot(root, watch) {
            seen.insert(row);
            if seen.len() >= 400 {
                break;
            }
        }
        let done = child
            .as_mut()
            .is_some_and(|c| matches!(c.try_wait(), Ok(Some(_))))
            || Instant::now() >= deadline;
        if done || seen.len() >= 400 {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let code = if let Some(mut child) = child {
        match child.wait() {
            Ok(status) => Some(status.code().unwrap_or(1)),
            Err(e) => return Err(format!("wait: {e}")),
        }
    } else {
        None
    };
    Ok((seen.into_iter().collect(), code))
}

pub fn snapshot(root: &Path, watch: Option<&Path>) -> Vec<Touch> {
    let watch_raw = watch.map(|p| p.display().to_string());
    let watch_canon = watch.map(normalize);
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let dir = entry.path();
        let comm = read_comm(&dir);
        let mut rows = Vec::new();
        if let Some(path) = link_path(&dir.join("exe")) {
            rows.push(("exe", path));
        }
        if let Some(path) = link_path(&dir.join("cwd")) {
            rows.push(("cwd", path));
        }
        if let Ok(fds) = std::fs::read_dir(dir.join("fd")) {
            for fd in fds.flatten().take(64) {
                if let Some(path) = link_path(&fd.path()) {
                    rows.push(("fd", path));
                }
            }
        }
        for (kind, path) in rows {
            if !wanted(&path, watch_raw.as_deref(), watch_canon.as_deref()) {
                continue;
            }
            out.push(Touch {
                pid,
                comm: comm.clone(),
                kind: kind.to_string(),
                path,
            });
            if out.len() >= 400 {
                return out;
            }
        }
    }
    out
}

fn wanted(path: &str, raw: Option<&str>, canon: Option<&str>) -> bool {
    match (raw, canon) {
        (None, None) => true,
        _ => covers(path, raw) || covers(path, canon),
    }
}

fn covers(path: &str, watch: Option<&str>) -> bool {
    let Some(watch) = watch else {
        return false;
    };
    path == watch || path.starts_with(&format!("{watch}/"))
}

fn normalize(path: &Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

fn read_comm(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("comm"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn link_path(path: &Path) -> Option<String> {
    let target = std::fs::read_link(path).ok()?;
    let text = target.display().to_string();
    let text = text.split(" (deleted)").next().unwrap_or(&text);
    if text.starts_with('/') {
        Some(text.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_watched_directory_names_the_process_that_has_it_open() {
        let root = std::env::temp_dir().join(format!("argus-proc-{}", std::process::id()));
        let pid = root.join("42");
        let fd = pid.join("fd");
        std::fs::create_dir_all(&fd).unwrap();
        std::fs::write(pid.join("comm"), "cat\n").unwrap();
        let note = root.join("note.txt");
        std::fs::write(&note, "hello").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&note, fd.join("3")).unwrap();
            std::os::unix::fs::symlink("/usr/bin/cat", pid.join("exe")).unwrap();
            std::os::unix::fs::symlink(root.join("note-dir"), pid.join("cwd")).unwrap();
        }
        #[cfg(unix)]
        {
            let rows = snapshot(&root, Some(&root));
            assert!(
                rows.iter()
                    .any(|r| r.pid == 42 && r.comm == "cat" && r.path.ends_with("note.txt"))
            );
            assert!(snapshot(&root, Some(Path::new("/no/such"))).is_empty());
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_is_listed_while_a_file_stays_open() {
        let path = std::env::temp_dir().join(format!("argus-hold-{}", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();
        let rows = snapshot(Path::new("/proc"), Some(&path));
        drop(file);
        let _ = std::fs::remove_file(&path);
        assert!(
            rows.iter()
                .any(|r| r.pid == std::process::id() && r.kind == "fd")
        );
    }
}
