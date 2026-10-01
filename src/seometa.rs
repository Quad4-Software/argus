// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Title, description, and generator tags from one HTML page.
//! An em dash in a short description is a lead. It is not an identification.

const SCAN_CAP: usize = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seo {
    pub title: String,
    pub description: String,
    pub og_description: String,
    pub twitter_description: String,
    pub generator: String,
    pub canonical: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dash {
    pub field: &'static str,
    pub dashes: usize,
    pub words: usize,
}

impl Seo {
    pub fn dashes(&self) -> Vec<Dash> {
        let mut out = Vec::new();
        for (field, text) in [
            ("description", self.description.as_str()),
            ("og:description", self.og_description.as_str()),
            ("twitter:description", self.twitter_description.as_str()),
        ] {
            let dashes = text.chars().filter(|c| *c == '\u{2014}').count();
            if dashes > 0 {
                out.push(Dash {
                    field,
                    dashes,
                    words: text.split_whitespace().count(),
                });
            }
        }
        out
    }
}

pub fn parse(html: &str) -> Seo {
    let end = html.floor_char_boundary(SCAN_CAP.min(html.len()));
    let html = &html[..end];
    let mut seo = Seo {
        title: String::new(),
        description: String::new(),
        og_description: String::new(),
        twitter_description: String::new(),
        generator: String::new(),
        canonical: String::new(),
    };
    if let Some(title) = between(html, "<title", "</title>") {
        seo.title = clip(&decode(&strip_tags(title)));
    }
    let lower = html.to_ascii_lowercase();
    let mut i = 0;
    while let Some(rel) = lower[i..].find("<meta") {
        let start = i + rel;
        let Some(end_rel) = lower[start..].find('>') else {
            break;
        };
        let tag = &html[start..start + end_rel];
        let key = attr(tag, "property")
            .or_else(|| attr(tag, "name"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        let content = decode(&attr(tag, "content").unwrap_or_default());
        match key.as_str() {
            "description" if seo.description.is_empty() => seo.description = clip(&content),
            "og:description" if seo.og_description.is_empty() => {
                seo.og_description = clip(&content)
            }
            "twitter:description" if seo.twitter_description.is_empty() => {
                seo.twitter_description = clip(&content)
            }
            "generator" if seo.generator.is_empty() => seo.generator = clip(&content),
            _ => {}
        }
        i = start + end_rel + 1;
    }
    i = 0;
    while let Some(rel) = lower[i..].find("<link") {
        let start = i + rel;
        let Some(end_rel) = lower[start..].find('>') else {
            break;
        };
        let tag = &html[start..start + end_rel];
        if attr(tag, "rel")
            .unwrap_or_default()
            .eq_ignore_ascii_case("canonical")
            && seo.canonical.is_empty()
        {
            seo.canonical = clip(&attr(tag, "href").unwrap_or_default());
        }
        i = start + end_rel + 1;
    }
    seo
}

fn between<'a>(html: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let lower = html.to_ascii_lowercase();
    let start = lower.find(open)?;
    let after = html[start..].find('>')? + start + 1;
    let end = lower[after..].find(close)? + after;
    Some(html[after..end].trim())
}

fn strip_tags(s: &str) -> String {
    let mut out = String::new();
    let mut on = true;
    for c in s.chars() {
        match c {
            '<' => on = false,
            '>' => on = true,
            _ if on => out.push(c),
            _ => {}
        }
    }
    out
}

fn attr(tag: &str, key: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let needle = format!("{key}=");
    let mut search = 0;
    while let Some(rel) = lower[search..].find(&needle) {
        let at = search + rel;
        if at > 0 {
            let prev = lower.as_bytes()[at - 1];
            if prev.is_ascii_alphanumeric() || prev == b'-' || prev == b':' {
                search = at + needle.len();
                continue;
            }
        }
        return Some(read_value(&tag[at + needle.len()..]));
    }
    None
}

fn read_value(rest: &str) -> String {
    let bytes = rest.as_bytes();
    if bytes.is_empty() {
        return String::new();
    }
    let quote = bytes[0];
    if quote == b'"' || quote == b'\'' {
        let body = &rest[1..];
        let end = body.find(quote as char).unwrap_or(body.len());
        body[..end].to_string()
    } else {
        rest.split(|c: char| c.is_whitespace() || c == '>')
            .next()
            .unwrap_or("")
            .to_string()
    }
}

fn decode(s: &str) -> String {
    s.replace("&mdash;", "\u{2014}")
        .replace("&#8212;", "\u{2014}")
        .replace("&#x2014;", "\u{2014}")
        .replace("&#X2014;", "\u{2014}")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

fn clip(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(240)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_entity_is_an_em_dash() {
        let html = r#"<html><head>
            <title>Example</title>
            <meta content="Hello &#8212; world and more words here" name="description">
            <meta property="og:description" content="plain text">
            <meta name="generator" content="WordPress 6.8">
            <link rel="canonical" href="https://example.com/">
        </head></html>"#;
        let seo = parse(html);
        assert_eq!(seo.title, "Example");
        assert_eq!(seo.generator, "WordPress 6.8");
        assert_eq!(seo.canonical, "https://example.com/");
        let dashes = seo.dashes();
        assert_eq!(dashes.len(), 1);
        assert_eq!(dashes[0].field, "description");
        assert_eq!(dashes[0].dashes, 1);
        assert!(seo.og_description.starts_with("plain"));
    }
}
