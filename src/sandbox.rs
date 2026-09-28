//! Landlock LSM sandboxing (Linux). Granted: read on scan roots /etc-ish paths,
//! write only on clone/output targets, TCP connect only when remote work needs
//! it. Unhandled right classes (exec, etc.) stay unrestricted.
//! Non-Linux or unavailable kernel support degrades to a warning, never a fail.

use std::path::PathBuf;

pub struct Sandbox {
    /// paths readable (ReadFile|ReadDir)
    pub reads: Vec<PathBuf>,
    /// paths fully writable (all fs rights)
    pub writes: Vec<PathBuf>,
    /// allow TCP connect to these ports; empty + net_governed = no egress.
    pub net_ports: Vec<u16>,
    /// allow TCP bind to these ports (daemon listener)
    pub net_bind_ports: Vec<u16>,
    /// when true, TCP connect is unrestricted (remote scans need arbitrary
    /// ports: gitea/gitlab/ghe on :8080/:8443, git/ssh, http mirrors).
    /// false = only net_ports may connect.
    pub net_open: bool,
}

#[cfg(target_os = "linux")]
pub fn apply(sb: &Sandbox) -> Result<(), String> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath, PathFd,
        Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    };
    let abi = ABI::V5;
    // Govern everything EXCEPT Execute: subprocesses (git etc.) must still run.
    let fs_all = AccessFs::from_all(abi) & !AccessFs::Execute;
    let status = Ruleset::default()
        .handle_access(fs_all)
        .map_err(|e| e.to_string())?;
    // only govern net when we intend to restrict it
    let status = if sb.net_open {
        status
    } else {
        status
            .handle_access(AccessNet::from_all(abi))
            .map_err(|e| e.to_string())?
    };
    let status = status
        .set_compatibility(CompatLevel::BestEffort)
        .create()
        .map_err(|e| e.to_string())?;

    let read = AccessFs::ReadFile | AccessFs::ReadDir;
    let all_fs = fs_all;
    let mut created = status;
    for p in &sb.reads {
        match PathFd::new(p) {
            Ok(fd) => {
                created = created
                    .add_rule(PathBeneath::new(fd, read))
                    .map_err(|e| e.to_string())?;
            }
            Err(_) => continue,
        }
    }
    for p in &sb.writes {
        // the path must exist for the grant to take; writes are always dirs
        // or file-parents we already control - create them now.
        let _ = std::fs::create_dir_all(p);
        if let Ok(fd) = PathFd::new(p) {
            created = created
                .add_rule(PathBeneath::new(fd, all_fs))
                .map_err(|e| e.to_string())?;
        }
    }
    if !sb.net_open {
        for port in &sb.net_ports {
            created = created
                .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
                .map_err(|e| e.to_string())?;
        }
        for port in &sb.net_bind_ports {
            created = created
                .add_rule(NetPort::new(*port, AccessNet::BindTcp))
                .map_err(|e| e.to_string())?;
        }
    }
    let st = created.restrict_self().map_err(|e| e.to_string())?;
    match st.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        RulesetStatus::PartiallyEnforced => {
            eprintln!("warn: landlock partially enforced (older kernel ABI)");
            Ok(())
        }
        _ => Err("landlock not enforced".into()),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn apply(_sb: &Sandbox) -> Result<(), String> {
    eprintln!("warn: landlock unavailable on this platform; running unsandboxed");
    Ok(())
}
