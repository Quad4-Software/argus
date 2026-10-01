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
