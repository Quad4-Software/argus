//! `git clone` wrapper with token auth via GIT_ASKPASS (token stays out of argv).

use std::path::{Path, PathBuf};
use std::process::Command;

pub struct GitAuth {
    pub username: String,
    pub password: String,
}

/// Write the askpass helper script into `workdir`; returns its path.
fn write_askpass(workdir: &Path) -> Result<PathBuf, String> {
    let script = workdir.join("askpass.sh");
    let body = "#!/bin/sh\ncase \"$1\" in\n  *assword*|*Password*) printf '%s' \"$ARGUS_ASKPASS_PASSWORD\" ;;\n  *) printf '%s' \"$ARGUS_ASKPASS_USERNAME\" ;;\nesac\n";
    std::fs::write(&script, body).map_err(|e| format!("write {}: {e}", script.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::fs::metadata(&script)
            .map_err(|e| e.to_string())?
            .permissions();
        p.set_mode(0o700);
        std::fs::set_permissions(&script, p).map_err(|e| e.to_string())?;
    }
    Ok(script)
}

/// Shallow-clone `url` into `dest`. Uses GIT_ASKPASS for https credentials so
/// the token never appears in the process list.
pub fn clone_repo(
    url: &str,
    dest: &Path,
    auth: Option<&GitAuth>,
    workdir: &Path,
    verbose: bool,
) -> Result<(), String> {
    let mut cmd = Command::new("git");
    cmd.args(["clone", "--depth", "1", "--single-branch", "--quiet"])
        .arg("--")
        .arg(url)
        .arg(dest)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_LFS_SKIP_SMUDGE", "1");

    if let Some(a) = auth {
        let askpass = write_askpass(workdir)?;
        cmd.env("GIT_ASKPASS", &askpass)
            .env("ARGUS_ASKPASS_USERNAME", &a.username)
            .env("ARGUS_ASKPASS_PASSWORD", &a.password);
    }
    if verbose {
        eprintln!("  cloning {url}");
    }
    let out = cmd.output().map_err(|e| format!("spawn git: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    // one retry on transient-looking failures (reset/timeout/tls/503)
    let transient = [
        "reset",
        "timeout",
        "timed out",
        "TLS",
        "early EOF",
        "503",
        "502",
        "Operation timed",
        "Connection",
        "unexpected disconnect",
    ]
    .iter()
    .any(|p| stderr.contains(p));
    if !transient {
        return Err(format!("git clone {url}: {}", stderr.trim()));
    }
    let _ = std::fs::remove_dir_all(dest);
    std::thread::sleep(std::time::Duration::from_secs(2));
    let out = cmd.output().map_err(|e| format!("spawn git: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(format!("git clone {url}: {}", stderr.trim()))
    }
}
