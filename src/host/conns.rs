// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Local socket table.
//! Linux publishes it in /proc/net. The allow list is the CI check: a
//! connection that is not listed is unexpected egress, including cloud
//! metadata addresses.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flow {
    pub dir: &'static str,
    pub proto: &'static str,
    pub state: &'static str,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub inode: u64,
    pub pid: Option<u32>,
    pub comm: String,
    pub name: String,
}

#[derive(Clone, Debug, Default)]
pub struct Allow {
    ips: HashSet<String>,
    ip_port: HashSet<(String, u16)>,
    ports: HashSet<u16>,
    cidrs: Vec<(u32, u32)>,
    names: Vec<(String, Option<u16>)>,
}

pub struct Observe {
    pub flows: Vec<Flow>,
    pub child_code: Option<i32>,
}

pub fn parse_allow(text: &str) -> Allow {
    let mut allow = Allow::default();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(port) = line.strip_prefix("*:") {
            if let Ok(port) = port.parse::<u16>() {
                allow.ports.insert(port);
            }
            continue;
        }
        if let Some((addr, bits)) = line.split_once('/') {
            if let (Some(net), Some(bits)) = (parse_v4(addr), bits.parse::<u32>().ok())
                && bits <= 32
            {
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                allow.cidrs.push((net & mask, mask));
            }
            continue;
        }
        if let Some((host, port)) = line.rsplit_once(':')
            && let Ok(port) = port.parse::<u16>()
        {
            if host.parse::<std::net::Ipv4Addr>().is_ok() || host.contains(':') {
                allow.ip_port.insert((normalize_ip(host), port));
            } else if !host.is_empty() {
                allow.names.push((host.to_ascii_lowercase(), Some(port)));
            }
            continue;
        }
        if line.parse::<std::net::Ipv4Addr>().is_ok() || line.contains(':') {
            allow.ips.insert(normalize_ip(line));
        } else {
            allow.names.push((line.to_ascii_lowercase(), None));
        }
    }
    allow
}

pub fn remember_name(allow: &mut Allow, name: &str, port: Option<u16>, ips: &[String]) {
    for ip in ips {
        match port {
            Some(port) => {
                allow.ip_port.insert((normalize_ip(ip), port));
            }
            None => {
                allow.ips.insert(normalize_ip(ip));
            }
        }
    }
    allow.names.retain(|(n, p)| !(n == name && *p == port));
}

pub fn pending_names(allow: &Allow) -> Vec<(String, Option<u16>)> {
    allow.names.clone()
}

pub fn allows(allow: &Allow, ip: &str, port: u16) -> bool {
    let ip = normalize_ip(ip);
    if allow.ports.contains(&port)
        || allow.ips.contains(&ip)
        || allow.ip_port.contains(&(ip.clone(), port))
    {
        return true;
    }
    if let Some(v4) = parse_v4(&ip) {
        return allow.cidrs.iter().any(|(net, mask)| v4 & mask == *net);
    }
    false
}

pub fn is_metadata(ip: &str) -> bool {
    matches!(
        normalize_ip(ip).as_str(),
        "169.254.169.254" | "169.254.170.2" | "fd00:ec2::254"
    )
}

pub fn parse_proc_table(text: &str, v6: bool, proto: &'static str) -> Vec<Flow> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let Some((lip, lp)) = decode_addr(cols[1], v6) else {
            continue;
        };
        let Some((rip, rp)) = decode_addr(cols[2], v6) else {
            continue;
        };
        let state = state_name(cols[3]);
        let inode = cols[9].parse().unwrap_or(0);
        let dir = direction(state, lp, rp, &rip);
        out.push(Flow {
            dir,
            proto,
            state,
            local_ip: lip,
            local_port: lp,
            remote_ip: rip,
            remote_port: rp,
            inode,
            pid: None,
            comm: String::new(),
            name: String::new(),
        });
    }
    out
}

pub fn attach_pids(flows: &mut [Flow], proc_root: &Path) {
    if flows.is_empty() {
        return;
    }
    let mut by_inode: HashMap<u64, (u32, String)> = HashMap::new();
    let Ok(rd) = std::fs::read_dir(proc_root) else {
        return;
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let fd_dir = ent.path().join("fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue;
        };
        let comm = std::fs::read_to_string(ent.path().join("comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let text = target.to_string_lossy();
            let Some(rest) = text.strip_prefix("socket:[") else {
                continue;
            };
            let Some(ino) = rest.strip_suffix(']').and_then(|s| s.parse().ok()) else {
                continue;
            };
            by_inode.entry(ino).or_insert((pid, comm.clone()));
        }
    }
    for flow in flows {
        if let Some((pid, comm)) = by_inode.get(&flow.inode) {
            flow.pid = Some(*pid);
            flow.comm = comm.clone();
        }
    }
}

pub fn read_proc(proc_root: &Path) -> Vec<Flow> {
    let mut flows = Vec::new();
    for (file, v6, proto) in [
        ("net/tcp", false, "tcp"),
        ("net/tcp6", true, "tcp"),
        ("net/udp", false, "udp"),
        ("net/udp6", true, "udp"),
    ] {
        if let Ok(text) = std::fs::read_to_string(proc_root.join(file)) {
            flows.extend(parse_proc_table(&text, v6, proto));
        }
    }
    attach_pids(&mut flows, proc_root);
    flows
}

pub fn observe(proc_root: &Path, command: &[String], watch_secs: u64) -> Result<Observe, String> {
    let mut merged: HashMap<String, Flow> = HashMap::new();
    let mut take = |flows: Vec<Flow>| {
        for flow in flows {
            let key = format!(
                "{}:{}:{}:{}:{}:{}:{}",
                flow.proto,
                flow.local_ip,
                flow.local_port,
                flow.remote_ip,
                flow.remote_port,
                flow.inode,
                flow.dir
            );
            merged.entry(key).or_insert(flow);
        }
    };
    if command.is_empty() {
        let secs = watch_secs.min(3600);
        let end = Instant::now() + Duration::from_secs(secs);
        loop {
            take(read_proc(proc_root));
            if secs == 0 || Instant::now() >= end {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        return Ok(Observe {
            flows: merged.into_values().collect(),
            child_code: None,
        });
    }
    let mut child = std::process::Command::new(&command[0])
        .args(&command[1..])
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", command[0]))?;
    loop {
        take(read_proc(proc_root));
        match child.try_wait() {
            Ok(Some(status)) => {
                take(read_proc(proc_root));
                let child_code = if status.success() {
                    Some(0)
                } else {
                    Some(status.code().unwrap_or(1))
                };
                return Ok(Observe {
                    flows: merged.into_values().collect(),
                    child_code,
                });
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(200)),
            Err(e) => return Err(format!("wait {}: {e}", command[0])),
        }
    }
}

pub fn unexpected<'a>(flows: &'a [Flow], allow: &Allow) -> Vec<&'a Flow> {
    flows
        .iter()
        .filter(|f| f.dir == "out" || is_metadata(&f.remote_ip))
        .filter(|f| is_metadata(&f.remote_ip) || !allows(allow, &f.remote_ip, f.remote_port))
        .collect()
}

pub fn proc_root(over: Option<&PathBuf>) -> PathBuf {
    over.cloned().unwrap_or_else(|| PathBuf::from("/proc"))
}

fn direction(state: &str, local_port: u16, remote_port: u16, remote_ip: &str) -> &'static str {
    if state == "LISTEN" || remote_port == 0 || remote_ip == "0.0.0.0" || remote_ip == "::" {
        "listen"
    } else if local_port < 1024 && remote_port >= 1024 {
        "in"
    } else {
        "out"
    }
}

fn state_name(hex: &str) -> &'static str {
    match u8::from_str_radix(hex, 16).unwrap_or(0) {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0a => "LISTEN",
        0x0b => "CLOSING",
        _ => "OTHER",
    }
}

fn decode_addr(text: &str, v6: bool) -> Option<(String, u16)> {
    let (addr, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = if v6 {
        decode_v6(addr)?
    } else {
        decode_v4(addr)?
    };
    Some((ip, port))
}

fn decode_v4(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    let n = u32::from_str_radix(hex, 16).ok()?;
    let b = n.to_le_bytes();
    Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
}

fn decode_v6(hex: &str) -> Option<String> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let word = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok()?;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(std::net::Ipv6Addr::from(bytes).to_string())
}

fn parse_v4(text: &str) -> Option<u32> {
    let ip: std::net::Ipv4Addr = text.parse().ok()?;
    Some(u32::from(ip))
}

fn normalize_ip(text: &str) -> String {
    if let Ok(ip) = text.parse::<std::net::Ipv6Addr>() {
        return ip.to_string();
    }
    text.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_tcp_decodes_local_v4() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1234 1 0000000000000000 100 0 0 10 0\n\
   1: 0100007F:C350 01010101:01BB 01 00000000:00000000 00:00000000 00000000     0        0 99 1 0000000000000000 100 0 0 10 0\n";
        let flows = parse_proc_table(text, false, "tcp");
        assert_eq!(flows[0].local_ip, "127.0.0.1");
        assert_eq!(flows[0].local_port, 80);
        assert_eq!(flows[0].dir, "listen");
        assert_eq!(flows[1].remote_ip, "1.1.1.1");
        assert_eq!(flows[1].remote_port, 443);
        assert_eq!(flows[1].dir, "out");
        assert_eq!(flows[1].inode, 99);
    }

    #[test]
    fn allow_list_flags_unexpected_egress() {
        let allow = parse_allow("1.1.1.1:443\n203.0.113.0/24\n*:53\n");
        assert!(allows(&allow, "1.1.1.1", 443));
        assert!(!allows(&allow, "1.1.1.1", 80));
        assert!(allows(&allow, "203.0.113.10", 443));
        assert!(allows(&allow, "8.8.8.8", 53));
        let bad = Flow {
            dir: "out",
            proto: "tcp",
            state: "ESTABLISHED",
            local_ip: "127.0.0.1".into(),
            local_port: 40000,
            remote_ip: "169.254.169.254".into(),
            remote_port: 80,
            inode: 1,
            pid: None,
            comm: String::new(),
            name: String::new(),
        };
        assert_eq!(unexpected(&[bad], &allow).len(), 1);
    }
}
