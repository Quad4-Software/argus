// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Operator-facing module list.
//! Each row is one command. Removing a command means deleting its source
//! file, its row here, and its CLI arm.

pub struct Module {
    pub name: &'static str,
    pub group: &'static str,
    pub about: &'static str,
}

pub fn modules() -> &'static [Module] {
    &[
        Module {
            name: "domain",
            group: "osint",
            about: "DNS, RDAP, certs, page, archives",
        },
        Module {
            name: "email",
            group: "osint",
            about: "Mail policy, keys, gravatar, breach hook",
        },
        Module {
            name: "chat",
            group: "osint",
            about: "XMPP and IRC SRV records",
        },
        Module {
            name: "ip",
            group: "osint",
            about: "Geolocation, ASN, VPN, InternetDB",
        },
        Module {
            name: "hash",
            group: "osint",
            about: "CIRCL hashlookup and optional MalwareBazaar",
        },
        Module {
            name: "url",
            group: "osint",
            about: "Fetch, redirects, WAF, trackers",
        },
        Module {
            name: "ports",
            group: "osint",
            about: "TCP connect scan, modern ports first",
        },
        Module {
            name: "intel",
            group: "osint",
            about: "OTX, ThreatFox, Feodo, CIRCL",
        },
        Module {
            name: "account",
            group: "osint",
            about: "GitHub or GitLab public profile",
        },
        Module {
            name: "socials",
            group: "osint",
            about: "Profile links, link-in-bio hubs, resumes",
        },
        Module {
            name: "user",
            group: "osint",
            about: "Small public username table",
        },
        Module {
            name: "keybase",
            group: "osint",
            about: "Profile, proofs, and the device list",
        },
        Module {
            name: "steam",
            group: "osint",
            about: "Public Steam community profile",
        },
        Module {
            name: "bluesky",
            group: "osint",
            about: "Public Bluesky profile",
        },
        Module {
            name: "mastodon",
            group: "osint",
            about: "Public Mastodon account",
        },
        Module {
            name: "reddit",
            group: "osint",
            about: "Archive karma and recent activity",
        },
        Module {
            name: "youtube",
            group: "osint",
            about: "Public video and channel metadata",
        },
        Module {
            name: "tiktok",
            group: "osint",
            about: "Public video and profile metadata",
        },
        Module {
            name: "lemmy",
            group: "osint",
            about: "Public Lemmy account",
        },
        Module {
            name: "dork",
            group: "osint",
            about: "Search links only, no fetch",
        },
        Module {
            name: "favicon",
            group: "osint",
            about: "Shodan-style favicon hash",
        },
        Module {
            name: "feed",
            group: "osint",
            about: "RSS, Atom, and JSON Feed",
        },
        Module {
            name: "gitmeta",
            group: "osint",
            about: "Git names, emails, exposed HEAD",
        },
        Module {
            name: "gharchive",
            group: "osint",
            about: "Public GitHub event firehose filter",
        },
        Module {
            name: "typo",
            group: "osint",
            about: "Lookalike domain permutations, DNS liveness",
        },
        Module {
            name: "extract",
            group: "local",
            about: "Emails, URLs, addresses, hashes, wallets",
        },
        Module {
            name: "meta",
            group: "local",
            about: "PDF, JPEG, PNG, and docx metadata",
        },
        Module {
            name: "media",
            group: "local",
            about: "C2PA, IPTC, and generator tags in media",
        },
        Module {
            name: "grep",
            group: "local",
            about: "Stream text, CSV, JSON, and SQLite",
        },
        Module {
            name: "stego",
            group: "local",
            about: "Appended payloads and zero-width text",
        },
        Module {
            name: "codec",
            group: "local",
            about: "Base64 and base32",
        },
        Module {
            name: "style",
            group: "local",
            about: "Pairwise prose or code distance",
        },
        Module {
            name: "files",
            group: "host",
            about: "Open files and watched paths",
        },
        Module {
            name: "conns",
            group: "host",
            about: "Sockets, domains, and egress allow lists",
        },
        Module {
            name: "signatures",
            group: "host",
            about: "Hash signatures and file heuristics",
        },
        Module {
            name: "threats",
            group: "host",
            about: "Preload, cron cradles, staging files",
        },
        Module {
            name: "supply",
            group: "local",
            about: "Lockfile closure",
        },
        Module {
            name: "records",
            group: "store",
            about: "Search saved reports",
        },
    ]
}

pub fn list() -> String {
    let mut out = String::from("name      group   about\n");
    for m in modules() {
        out.push_str(&format!("{:<10} {:<7} {}\n", m.name, m.group, m.about));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique() {
        let mut names: Vec<_> = modules().iter().map(|m| m.name).collect();
        let n = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), n);
        assert!(list().contains("grep"));
    }
}
