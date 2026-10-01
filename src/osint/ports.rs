// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! TCP connect check of one host.
//! Modern services are tried first. Closed means the host refused the
//! connection. Filtered means it did not answer in time.
//! This does not send UDP, spoof a source, or walk a network range.

use super::{Hit, Report, Status};
use serde_json::json;
use std::collections::HashSet;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const CONNECT: Duration = Duration::from_millis(300);
const BANNER: Duration = Duration::from_millis(150);
const WORKERS: usize = 64;

/// Ports people actually run in 2026, then the older services still worth a look.
const MODERN: &[(u16, &str)] = &[
    (443, "https"),
    (80, "http"),
    (8443, "https-alt"),
    (8080, "http-alt"),
    (22, "ssh"),
    (8000, "http-dev"),
    (3000, "http-dev"),
    (5000, "http-dev"),
    (5173, "vite"),
    (4173, "vite-preview"),
    (8081, "http-alt"),
    (8888, "http-alt"),
    (9000, "http-alt"),
    (9443, "https-alt"),
    (4443, "https-alt"),
    (2053, "http-alt"),
    (2083, "https-alt"),
    (2087, "https-alt"),
    (2096, "https-alt"),
    (2222, "ssh-alt"),
    (3389, "rdp"),
    (5900, "vnc"),
    (25, "smtp"),
    (465, "smtps"),
    (587, "submission"),
    (143, "imap"),
    (993, "imaps"),
    (110, "pop3"),
    (995, "pop3s"),
    (853, "dns-over-tls"),
    (3306, "mysql"),
    (5432, "postgres"),
    (6379, "redis"),
    (27017, "mongodb"),
    (9200, "elasticsearch"),
    (5672, "amqp"),
    (15672, "rabbitmq"),
    (9092, "kafka"),
    (1433, "mssql"),
    (2375, "docker"),
    (2376, "docker-tls"),
    (6443, "kubernetes"),
    (10250, "kubelet"),
    (2379, "etcd"),
    (8500, "consul"),
    (8200, "vault"),
    (9090, "prometheus"),
    (9100, "node-exporter"),
    (8086, "influxdb"),
    (1883, "mqtt"),
    (8883, "mqtts"),
    (21, "ftp"),
    (445, "smb"),
    (139, "netbios"),
    (389, "ldap"),
    (636, "ldaps"),
    (873, "rsync"),
    (2049, "nfs"),
    (6000, "x11"),
    (10000, "webmin"),
    (5601, "kibana"),
    (8161, "activemq"),
    (7001, "weblogic"),
    (4848, "glassfish"),
    (554, "rtsp"),
    (1935, "rtmp"),
    (8291, "winbox"),
    (502, "modbus"),
    (102, "s7"),
    (44818, "ethernet-ip"),
    (47808, "bacnet"),
];

pub fn scan(raw: &str, spec: Option<&str>, all: bool) -> Result<Report, String> {
    let t0 = Instant::now();
    if all && spec.is_some() {
        return Err("pass either --ports or --all".into());
    }
    let host = host_name(raw)?;
    let ip = resolve(&host)?;
    let ports = if all {
        let every: Vec<u16> = (1..=65535).collect();
        order(&every)
    } else if let Some(spec) = spec {
        parse_spec(spec)?
    } else {
        MODERN.iter().map(|(p, _)| *p).collect()
    };
    let mut open = Vec::new();
    let mut closed = 0u32;
    let mut filtered = 0u32;
    for chunk in ports.chunks(WORKERS) {
        let found = std::thread::scope(|s| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|port| {
                    let port = *port;
                    s.spawn(move || probe(ip, port))
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or(Probe::filtered(0)))
                .collect::<Vec<_>>()
        });
        for hit in found {
            match hit.state {
                State::Open { banner } => open.push(OpenPort {
                    port: hit.port,
                    banner,
                }),
                State::Closed => closed += 1,
                State::Filtered => filtered += 1,
            }
        }
    }
    open.sort_by_key(|row| {
        ports
            .iter()
            .position(|p| *p == row.port)
            .unwrap_or(usize::MAX)
    });
    let n = ports.len();
    let listed: Vec<String> = open
        .iter()
        .take(12)
        .map(|row| format!("{} {}", row.port, service(row.port)))
        .collect();
    let (status, summary) = if open.is_empty() && filtered == 0 {
        (Status::Absent, format!("no open ports in {n} checked"))
    } else if open.is_empty() {
        (
            Status::Inconclusive,
            format!("no open ports in {n} checked, {filtered} filtered"),
        )
    } else {
        let extra = open.len().saturating_sub(listed.len());
        let tail = if extra == 0 {
            String::new()
        } else {
            format!(" and {extra} more")
        };
        (
            Status::Confirmed,
            format!(
                "{} open of {n} checked: {}{tail}",
                open.len(),
                listed.join(", ")
            ),
        )
    };
    let evidence_open: Vec<_> = open
        .iter()
        .map(|row| {
            json!({
                "port": row.port,
                "service": service(row.port),
                "banner": row.banner,
            })
        })
        .collect();
    Ok(Report {
        target: host,
        kind: "ports",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings: vec![Hit::new(
            "ports",
            status,
            summary,
            Some(json!({
                "address": ip.to_string(),
                "checked": n,
                "open": evidence_open,
                "closed": closed,
                "filtered": filtered,
            })),
        )],
    })
}

struct OpenPort {
    port: u16,
    banner: String,
}

struct Probe {
    port: u16,
    state: State,
}

enum State {
    Open { banner: String },
    Closed,
    Filtered,
}

impl Probe {
    fn filtered(port: u16) -> Self {
        Probe {
            port,
            state: State::Filtered,
        }
    }
}

fn probe(ip: IpAddr, port: u16) -> Probe {
    let addr = SocketAddr::new(ip, port);
    match TcpStream::connect_timeout(&addr, CONNECT) {
        Ok(mut stream) => {
            let _ = stream.set_read_timeout(Some(BANNER));
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).unwrap_or(0);
            Probe {
                port,
                state: State::Open {
                    banner: printable(&buf[..n]),
                },
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Probe {
            port,
            state: State::Closed,
        },
        Err(_) => Probe {
            port,
            state: State::Filtered,
        },
    }
}

fn printable(buf: &[u8]) -> String {
    let text: String = buf
        .iter()
        .map(|b| {
            let c = *b as char;
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                ' '
            }
        })
        .collect();
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn service(port: u16) -> &'static str {
    MODERN
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, name)| *name)
        .unwrap_or("tcp")
}

pub(crate) fn order(ports: &[u16]) -> Vec<u16> {
    let wanted: HashSet<u16> = ports.iter().copied().collect();
    let mut out = Vec::with_capacity(wanted.len());
    let mut seen = HashSet::new();
    for (port, _) in MODERN {
        if wanted.contains(port) && seen.insert(*port) {
            out.push(*port);
        }
    }
    for port in ports {
        if seen.insert(*port) {
            out.push(*port);
        }
    }
    out
}

pub(crate) fn parse_spec(spec: &str) -> Result<Vec<u16>, String> {
    let mut raw = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let start: u32 = a.trim().parse().map_err(|_| format!("bad port {part}"))?;
            let end: u32 = b.trim().parse().map_err(|_| format!("bad port {part}"))?;
            if start == 0 || end == 0 || end < start || end > 65535 {
                return Err(format!("bad port range {part}"));
            }
            for port in start..=end {
                raw.push(port as u16);
                if raw.len() > 4096 {
                    return Err(
                        "that list is too long. Pass --all to scan every TCP port, modern ports first"
                            .into(),
                    );
                }
            }
        } else {
            let port: u32 = part.parse().map_err(|_| format!("bad port {part}"))?;
            if port == 0 || port > 65535 {
                return Err(format!("bad port {part}"));
            }
            raw.push(port as u16);
        }
    }
    if raw.is_empty() {
        return Err("no ports in that list".into());
    }
    Ok(order(&raw))
}

fn host_name(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.contains(char::is_whitespace) {
        return Err("pass one host".into());
    }
    if raw.contains('/') && !raw.contains("://") {
        return Err("pass one host. A network range is not scanned".into());
    }
    let mut host = if let Some(rest) = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("http://"))
    {
        if rest.contains('@') {
            return Err("pass a host without credentials".into());
        }
        rest.split(['/', '?', '#']).next().unwrap_or("").to_string()
    } else {
        raw.to_string()
    };
    if host.starts_with('[') {
        let end = host.find(']').ok_or("bad IPv6 host")?;
        if host[end + 1..].starts_with(':') {
            return Err("pass the port with --ports".into());
        }
        host = host[1..end].to_string();
    } else if host.matches(':').count() > 1 {
        return Err("wrap an IPv6 address in brackets".into());
    } else if let Some((_, tail)) = host.rsplit_once(':') {
        if tail.chars().all(|c| c.is_ascii_digit()) && !tail.is_empty() {
            return Err("pass the port with --ports".into());
        }
        return Err("pass one host".into());
    }
    host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err("pass one host".into());
    }
    Ok(host)
}

fn resolve(host: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return if usable(ip) {
            Ok(ip)
        } else {
            Err("refusing a link-local, multicast, or unspecified address".into())
        };
    }
    let mut found = None;
    for addr in (host, 443)
        .to_socket_addrs()
        .map_err(|e| format!("could not resolve {host}: {e}"))?
    {
        if usable(addr.ip()) {
            found = Some(addr.ip());
            break;
        }
    }
    found.ok_or_else(|| "refusing a link-local, multicast, or unspecified address".into())
}

fn usable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(o[0] == 0 || o[0] >= 224 || (o[0] == 169 && o[1] == 254) || v.is_broadcast())
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            !(v.is_unspecified() || v.is_multicast() || (s[0] & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_ports_are_scheduled_first() {
        let ordered = parse_spec("9,22,80").unwrap();
        assert_eq!(ordered, vec![80, 22, 9]);
        assert_eq!(order(&[22, 443, 9]), vec![443, 22, 9]);
    }

    #[test]
    fn ranges_and_bad_targets_are_rejected() {
        assert!(parse_spec("1-7000").is_err());
        assert!(host_name("10.0.0.0/24").is_err());
        assert!(host_name("example.com:22").is_err());
        assert!(resolve("169.254.169.254").is_err());
        assert!(resolve("255.255.255.255").is_err());
        assert_eq!(resolve("127.0.0.1").unwrap().to_string(), "127.0.0.1");
    }

    #[test]
    fn closed_local_port_is_absent() {
        let report = scan("127.0.0.1", Some("1"), false).unwrap();
        assert_eq!(report.findings[0].status, Status::Absent);
        assert!(report.findings[0].summary.contains("no open ports"));
    }
}
