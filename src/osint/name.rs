// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Domain and mailbox checks that do not touch the network.

/// Multi-label public suffixes and well-known private suffixes.
/// Longest match wins. This is a working set for organizational-domain
/// DMARC, not a copy of the Public Suffix List.
const SUFFIXES: &[&str] = &[
    "azurewebsites.net",
    "blogspot.com",
    "cloudfront.net",
    "firebaseapp.com",
    "githubusercontent.com",
    "herokuapp.com",
    "amazonaws.com",
    "netlify.app",
    "vercel.app",
    "wordpress.com",
    "appspot.com",
    "github.io",
    "gitlab.io",
    "pages.dev",
    "web.app",
    "workers.dev",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "gov.au",
    "asn.au",
    "id.au",
    "com.br",
    "net.br",
    "org.br",
    "gov.br",
    "com.mx",
    "org.mx",
    "gob.mx",
    "com.ar",
    "com.co",
    "com.tr",
    "com.sg",
    "com.hk",
    "com.tw",
    "com.cn",
    "com.my",
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "ltd.uk",
    "plc.uk",
    "me.uk",
    "net.uk",
    "sch.uk",
    "co.nz",
    "net.nz",
    "org.nz",
    "govt.nz",
    "co.za",
    "org.za",
    "net.za",
    "web.za",
    "co.jp",
    "or.jp",
    "ne.jp",
    "ac.jp",
    "go.jp",
    "co.kr",
    "or.kr",
    "ne.kr",
    "go.kr",
    "co.in",
    "net.in",
    "org.in",
    "gen.in",
    "firm.in",
    "ind.in",
    "co.il",
    "org.il",
    "net.il",
    "ac.il",
    "com.ua",
    "co.il",
];

pub fn normalize_domain(raw: &str) -> Result<String, String> {
    let mut s = raw
        .trim()
        .trim_matches(|c| c == '<' || c == '>')
        .to_ascii_lowercase();
    if let Some(rest) = s.strip_prefix("https://") {
        s = rest.to_string();
    } else if let Some(rest) = s.strip_prefix("http://") {
        s = rest.to_string();
    }
    if let Some((host, _)) = s.split_once('/') {
        s = host.to_string();
    }
    if s.contains('@') {
        s = s.rsplit('@').next().unwrap_or("").to_string();
    }
    if let Some((host, port)) = s.rsplit_once(':')
        && !port.contains(':')
        && port.chars().all(|c| c.is_ascii_digit())
    {
        s = host.to_string();
    }
    s = s.trim_end_matches('.').to_string();
    validate_domain(&s)?;
    Ok(s)
}

pub fn validate_domain(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("empty domain".into());
    }
    if name.len() > 253 {
        return Err("domain longer than 253".into());
    }
    if !name.contains('.') {
        return Err("domain needs a dot".into());
    }
    if name.starts_with('.') || name.ends_with('.') || name.contains("..") {
        return Err("bad domain dots".into());
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        return Err("domain needs a dot".into());
    }
    for lab in &labels {
        if lab.is_empty() || lab.len() > 63 {
            return Err("bad domain label".into());
        }
        if lab.starts_with('-') || lab.ends_with('-') {
            return Err("domain label cannot start or end with a hyphen".into());
        }
        if !lab.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err("domain must be ASCII letters, digits, and hyphens".into());
        }
    }
    let tld = labels[labels.len() - 1];
    if matches!(name, "localhost" | "localhost.localdomain")
        || tld == "local"
        || tld == "localhost"
        || tld == "internal"
        || tld == "invalid"
        || tld == "test"
        || tld == "example"
        || tld == "onion"
    {
        return Err("refusing a non-public domain".into());
    }
    if labels.iter().any(|l| *l == "localhost") {
        return Err("refusing a non-public domain".into());
    }
    Ok(())
}

/// DNS name we are willing to query. Underscores are allowed for SRV and DKIM.
pub fn safe_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 || name.contains("..") {
        return false;
    }
    name.split('.').all(|lab| {
        !lab.is_empty()
            && lab.len() <= 63
            && !lab.starts_with('-')
            && !lab.ends_with('-')
            && lab
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

pub fn registrable(domain: &str) -> String {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return d;
    }
    let mut best: Option<&str> = None;
    for suf in SUFFIXES {
        if d == *suf || d.ends_with(&format!(".{suf}")) {
            if best.is_none_or(|b| suf.len() > b.len()) {
                best = Some(suf);
            }
        }
    }
    if let Some(suf) = best {
        if d == suf {
            return d;
        }
        let rest = &d[..d.len() - suf.len() - 1];
        let label = rest.rsplit('.').next().unwrap_or(rest);
        if label.is_empty() {
            return d;
        }
        return format!("{label}.{suf}");
    }
    let mut parts = d.split('.');
    let Some(left) = parts.next_back() else {
        return d;
    };
    let Some(right) = parts.next_back() else {
        return d;
    };
    format!("{right}.{left}")
}

pub fn org_chain(domain: &str) -> Vec<String> {
    let org = registrable(domain);
    let mut out = Vec::new();
    let mut cur = domain.to_ascii_lowercase();
    loop {
        out.push(cur.clone());
        if cur == org || !cur.contains('.') || out.len() == 6 {
            break;
        }
        let Some((_, parent)) = cur.split_once('.') else {
            break;
        };
        if parent.is_empty() {
            break;
        }
        cur = parent.to_string();
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    pub raw: String,
    pub local: String,
    pub domain: String,
}

impl Mailbox {
    pub fn address(&self) -> String {
        format!("{}@{}", self.local, self.domain)
    }
}

pub fn parse_mailbox(raw: &str) -> Result<Mailbox, String> {
    let raw_trim = raw.trim();
    if raw_trim.is_empty() {
        return Err("empty address".into());
    }
    if raw_trim.contains('\n') || raw_trim.contains('\r') {
        return Err("address contains a line break".into());
    }
    let addr = if let (Some(a), Some(b)) = (raw_trim.rfind('<'), raw_trim.rfind('>')) {
        if a < b {
            raw_trim[a + 1..b].trim()
        } else {
            raw_trim
        }
    } else {
        raw_trim
    };
    if addr.contains(' ') || addr.contains('\t') {
        return Err("address contains whitespace".into());
    }
    let Some((local, domain)) = addr.rsplit_once('@') else {
        return Err("missing @".into());
    };
    if local.is_empty() || domain.is_empty() {
        return Err("missing local part or domain".into());
    }
    if local.contains('@') || domain.contains('@') {
        return Err("more than one @".into());
    }
    if local.len() > 64 {
        return Err("local part longer than 64".into());
    }
    let local = local.to_ascii_lowercase();
    let domain = normalize_domain(domain)?;
    if local.len() + 1 + domain.len() > 254 {
        return Err("address longer than 254".into());
    }
    if !local
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-' | b'='))
    {
        return Err("local part has a character this checker does not query".into());
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err("bad dots in the local part".into());
    }
    Ok(Mailbox {
        raw: raw_trim.to_string(),
        local,
        domain,
    })
}

pub fn local_base(local: &str) -> &str {
    local.split('+').next().unwrap_or(local)
}

pub fn is_role(local: &str) -> bool {
    let local = local.to_ascii_lowercase();
    matches!(
        local_base(&local),
        "abuse"
            | "admin"
            | "administrator"
            | "alerts"
            | "billing"
            | "careers"
            | "compliance"
            | "contact"
            | "dpo"
            | "hello"
            | "help"
            | "hostmaster"
            | "info"
            | "jobs"
            | "legal"
            | "mail"
            | "marketing"
            | "media"
            | "newsletter"
            | "noc"
            | "no-reply"
            | "noreply"
            | "notifications"
            | "office"
            | "postmaster"
            | "press"
            | "privacy"
            | "root"
            | "sales"
            | "security"
            | "support"
            | "team"
            | "webmaster"
    )
}

pub fn provider(domain: &str) -> Option<&'static str> {
    Some(match domain {
        "gmail.com" | "googlemail.com" => "Google",
        "outlook.com" | "hotmail.com" | "live.com" | "msn.com" => "Microsoft",
        "yahoo.com" | "ymail.com" | "rocketmail.com" => "Yahoo",
        "icloud.com" | "me.com" | "mac.com" => "Apple",
        "proton.me" | "protonmail.com" | "pm.me" => "Proton",
        "tuta.com" | "tutanota.com" => "Tuta",
        "fastmail.com" | "fastmail.fm" => "Fastmail",
        "zoho.com" | "zohomail.com" => "Zoho",
        "gmx.com" | "gmx.net" | "gmx.de" => "GMX",
        "aol.com" => "AOL",
        "hey.com" => "Hey",
        "yandex.com" | "yandex.ru" => "Yandex",
        "qq.com" => "Tencent",
        "163.com" | "126.com" => "NetEase",
        "mail.com" => "mail.com",
        _ => return None,
    })
}

pub fn is_disposable(domain: &str) -> bool {
    matches!(
        domain,
        "mailinator.com"
            | "mailinator.net"
            | "guerrillamail.com"
            | "guerrillamail.net"
            | "guerrillamail.org"
            | "guerrillamail.biz"
            | "guerrillamail.de"
            | "guerrillamailblock.com"
            | "sharklasers.com"
            | "grr.la"
            | "pokemail.net"
            | "yopmail.com"
            | "yopmail.fr"
            | "10minutemail.com"
            | "10minutemail.net"
            | "tempmail.com"
            | "temp-mail.org"
            | "tempmailo.com"
            | "tempinbox.com"
            | "trashmail.com"
            | "trashmail.de"
            | "trash-mail.com"
            | "trashmailer.com"
            | "dispostable.com"
            | "maildrop.cc"
            | "getnada.com"
            | "fakeinbox.com"
            | "mailnesia.com"
            | "moakt.com"
            | "throwawaymail.com"
            | "mailcatch.com"
            | "spamgourmet.com"
            | "mintemail.com"
            | "mytrashmail.com"
            | "spam4.me"
            | "mailnull.com"
            | "spambox.us"
            | "emailondeck.com"
            | "inboxkitten.com"
            | "mohmal.com"
            | "getairmail.com"
    )
}

pub fn mail_service(host: &str) -> Option<&'static str> {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    const MAP: &[(&str, &str)] = &[
        ("messagingengine.com", "Fastmail"),
        ("protection.outlook.com", "Microsoft 365"),
        ("outlook.com", "Microsoft 365"),
        ("googlemail.com", "Google"),
        ("google.com", "Google"),
        ("protonmail.ch", "Proton"),
        ("proton.me", "Proton"),
        ("pphosted.com", "Proofpoint"),
        ("mimecast.com", "Mimecast"),
        ("zoho.com", "Zoho"),
        ("yahoodns.net", "Yahoo"),
        ("icloud.com", "Apple"),
        ("secureserver.net", "GoDaddy"),
        ("mailgun.org", "Mailgun"),
        ("sendgrid.net", "SendGrid"),
        ("amazonses.com", "Amazon SES"),
    ];
    for (suf, name) in MAP {
        if h == *suf {
            return Some(*name);
        }
        if h.len() > suf.len() + 1
            && h.ends_with(suf)
            && h.as_bytes()[h.len() - suf.len() - 1] == b'.'
        {
            return Some(*name);
        }
    }
    None
}

pub fn public_ip(raw: &str) -> bool {
    let Ok(ip) = raw.parse::<std::net::IpAddr>() else {
        return false;
    };
    match ip {
        std::net::IpAddr::V4(v) => {
            let o = v.octets();
            !(o[0] == 0
                || o[0] == 10
                || o[0] == 127
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 169 && o[1] == 254)
                || (o[0] == 172 && (o[1] & 0xf0) == 16)
                || (o[0] == 192 && o[1] == 168)
                || o[0] >= 224)
        }
        std::net::IpAddr::V6(v) => {
            let s = v.segments();
            !(v.is_loopback()
                || v.is_unspecified()
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xff00) == 0xff00)
        }
    }
}

pub fn percent_encode(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char);
            }
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

pub fn in_scope(name: &str, root: &str) -> bool {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    let r = root.to_ascii_lowercase();
    n == r || n.ends_with(&format!(".{r}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_normalization() {
        assert_eq!(
            normalize_domain("https://Quad4.IO/docs").unwrap(),
            "quad4.io"
        );
        assert_eq!(normalize_domain("quad4.io.").unwrap(), "quad4.io");
        assert_eq!(normalize_domain("argus@quad4.io").unwrap(), "quad4.io");
        assert!(normalize_domain("localhost").is_err());
        assert!(normalize_domain("foo.local").is_err());
        assert!(normalize_domain("-bad.com").is_err());
        assert!(normalize_domain("has_underscore.com").is_err());
    }

    #[test]
    fn registrable_and_chain() {
        assert_eq!(registrable("quad4.io"), "quad4.io");
        assert_eq!(registrable("www.quad4.io"), "quad4.io");
        assert_eq!(registrable("mail.example.co.uk"), "example.co.uk");
        assert_eq!(registrable("foo.github.io"), "foo.github.io");
        assert_eq!(
            org_chain("a.mail.example.co.uk"),
            vec![
                "a.mail.example.co.uk",
                "mail.example.co.uk",
                "example.co.uk"
            ]
        );
    }

    #[test]
    fn mailbox_ivan() {
        let m = parse_mailbox("Ada <argus@Quad4.io>").unwrap();
        assert_eq!(m.address(), "argus@quad4.io");
        assert!(!is_role(&m.local));
        assert!(provider(&m.domain).is_none());
        assert!(!is_disposable(&m.domain));
        assert!(is_role("Postmaster+tag"));
        assert_eq!(provider("gmail.com"), Some("Google"));
        assert!(is_disposable("mailinator.com"));
        assert!(parse_mailbox("not-an-email").is_err());
        assert!(parse_mailbox("a@b").is_err());
    }

    #[test]
    fn mail_host_and_ip() {
        assert_eq!(
            mail_service("in1-smtp.messagingengine.com"),
            Some("Fastmail")
        );
        assert_eq!(
            mail_service("quad4-io.mail.protection.outlook.com"),
            Some("Microsoft 365")
        );
        assert!(mail_service("mx.quad4.io").is_none());
        assert!(public_ip("203.0.113.10"));
        assert!(!public_ip("192.168.1.1"));
        assert!(!public_ip("10.1.2.3"));
        assert!(!public_ip("127.0.0.1"));
        assert!(public_ip("2606:4700:4700::1111"));
        assert!(!public_ip("fe80::1"));
    }
}
