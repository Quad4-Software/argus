// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Public records for one address.

use super::domain::ptr_lookup;
use super::geo;
use super::intel::{asn, geo_online, hudson_ip, internetdb, vpn};
use super::name::public_ip;
use super::net::Net;
use super::surface::rdap_ip;
use super::{Hit, Report, Status};
use std::time::Instant;

pub fn scan(raw: &str, offline: bool) -> Result<Report, String> {
    let t0 = Instant::now();
    let ip = raw.trim().to_string();
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err("not an IP address".into());
    }
    if !public_ip(&ip) {
        return Err("refusing a local or private address".into());
    }
    let local = if geo::has_db() {
        Some(geo::lookup(&ip))
    } else {
        None
    };
    if offline {
        let Some(local) = local else {
            return Err(
                "offline mode needs a local geolocation database. Run argus ip --download first"
                    .into(),
            );
        };
        let mut findings = vec![
            local,
            Hit::new(
                "network",
                Status::Inconclusive,
                "offline, network sources were not queried",
                None,
            ),
        ];
        sort_ip(&mut findings);
        return Ok(Report {
            target: ip,
            kind: "ip",
            elapsed_ms: t0.elapsed().as_millis() as u64,
            findings,
        });
    }
    let net = Net::new();
    let (online, rdap, ports, rock, ptr, origin, anon) = std::thread::scope(|s| {
        let online = s.spawn(|| geo_online(&net, &ip));
        let rdap = s.spawn(|| {
            let mut hit = rdap_ip(&net, &ip);
            hit.module = "rdap".into();
            hit
        });
        let ports = s.spawn(|| internetdb(&net, &ip));
        let rock = s.spawn(|| hudson_ip(&net, &ip));
        let ptr = s.spawn(|| ptr_for(&net, &ip));
        let origin = s.spawn(|| asn(&net, &ip));
        let anon = s.spawn(|| vpn(&net, &ip));
        (
            join(online, "geo"),
            join(rdap, "rdap"),
            join(ports, "internetdb"),
            join(rock, "hudsonrock"),
            join(ptr, "ptr"),
            join(origin, "asn"),
            join(anon, "vpn"),
        )
    });
    let mut findings = Vec::new();
    match local {
        Some(hit) => {
            findings.push(hit);
            let mut net_hit = online;
            net_hit.module = "geo-net".into();
            findings.push(net_hit);
        }
        None => findings.push(online),
    }
    findings.extend([ptr, origin, anon, rdap, ports, rock]);
    sort_ip(&mut findings);
    Ok(Report {
        target: ip,
        kind: "ip",
        elapsed_ms: t0.elapsed().as_millis() as u64,
        findings,
    })
}

fn ptr_for(net: &Net, ip: &str) -> Hit {
    ptr_lookup(net, ip)
}

fn join(h: std::thread::ScopedJoinHandle<Hit>, module: &str) -> Hit {
    h.join()
        .unwrap_or_else(|_| Hit::new(module, Status::Error, "lookup panicked", None))
}

fn sort_ip(findings: &mut [Hit]) {
    fn rank(m: &str) -> u8 {
        match m {
            "geo" => 0,
            "geo-net" => 1,
            "ptr" => 2,
            "asn" => 3,
            "vpn" => 4,
            "rdap" => 5,
            "internetdb" => 6,
            "hudsonrock" => 7,
            "network" => 8,
            _ => 40,
        }
    }
    findings.sort_by_key(|h| rank(&h.module));
}
