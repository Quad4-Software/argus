//! .argusignore - declarative suppression of findings by rule id and path
//! glob. Format: one entry per line, `#` comments allowed.
//!
//! Entries look like:
//!
//!     SEC-001                      suppress rule everywhere
//!     SEC-001 tests/fixtures/**    suppress rule under a glob
//!     * vendor/                    suppress everything under a path
//!     SEC-001 .github/workflows/ci.yml
//!
//! The file is read from each scanned root (and cwd for non-path scans).

use crate::finding::Finding;

pub struct Ignore {
    /// (rule_id or "*", path glob or None = any path)
    rules: Vec<(String, Option<glob::Pattern>)>,
}

mod glob {
    /// Minimal glob: `*` = any within a segment, `**` = any depth, `?` = one char.
    pub struct Pattern(String);

    impl Pattern {
        pub fn new(pat: &str) -> Self {
            Pattern(pat.to_string())
        }
        pub fn matches(&self, s: &str) -> bool {
            match_parts(&self.0, s)
        }
    }

    fn match_parts(pat: &str, s: &str) -> bool {
        // recursive matcher over '**' and '*'/'?'
        let (p, s) = (pat.as_bytes(), s.as_bytes());
        fn m(p: &[u8], s: &[u8]) -> bool {
            if p.is_empty() {
                return s.is_empty();
            }
            match p[0] {
                b'*' if p.len() > 1 && p[1] == b'*' => {
                    // '**' = zero or more chars incl '/'
                    for i in 0..=s.len() {
                        if m(&p[2..], &s[i..]) {
                            return true;
                        }
                    }
                    false
                }
                b'*' => {
                    // '*' = zero or more chars except '/'
                    for i in 0..=s.len() {
                        if s[..i].contains(&b'/') {
                            break;
                        }
                        if m(&p[1..], &s[i..]) {
                            return true;
                        }
                    }
                    false
                }
                b'?' => !s.is_empty() && s[0] != b'/' && m(&p[1..], &s[1..]),
                c => !s.is_empty() && s[0] == c && m(&p[1..], &s[1..]),
            }
        }
        m(p, s)
    }
}

pub fn load_file(path: &std::path::Path) -> Option<Ignore> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut rules = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let Some(id) = it.next() else { continue };
        let glob = it.next().map(glob::Pattern::new);
        rules.push((id.to_string(), glob));
    }
    Some(Ignore { rules })
}

/// Load `.argusignore` files for each scan root plus cwd.
pub fn load(roots: &[&std::path::Path]) -> Ignore {
    let mut rules = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for r in roots
        .iter()
        .map(|p| p.join(".argusignore"))
        .chain(std::iter::once(std::path::PathBuf::from(".argusignore")))
    {
        if seen.insert(r.clone())
            && let Some(ig) = load_file(&r)
        {
            rules.extend(ig.rules);
        }
    }
    Ignore { rules }
}

impl Ignore {
    /// True when the finding is suppressed.
    pub fn suppresses(&self, f: &Finding) -> bool {
        for (id, g) in &self.rules {
            if id != "*" && !f.rule_id.eq_ignore_ascii_case(id) {
                continue;
            }
            match g {
                None => return true,
                Some(g) if g.matches(&f.path) => return true,
                _ => {}
            }
        }
        false
    }
}

/// Filter findings; returns (kept, suppressed count).
pub fn apply(findings: Vec<Finding>, ig: &Ignore) -> (Vec<Finding>, usize) {
    if ig.rules.is_empty() {
        return (findings, 0);
    }
    let mut kept = Vec::with_capacity(findings.len());
    let mut n = 0;
    for f in findings {
        if ig.suppresses(&f) {
            n += 1;
        } else {
            kept.push(f);
        }
    }
    (kept, n)
}

/// Load suppressions for every scanned root and apply to a report.
pub fn apply_report(report: &mut crate::finding::Report) {
    let roots: Vec<std::path::PathBuf> = report
        .targets
        .iter()
        .map(|t| std::path::PathBuf::from(&t.label))
        .collect();
    let roots: Vec<&std::path::Path> = roots.iter().map(|p| p.as_path()).collect();
    let ig = load(&roots);
    let (kept, sup) = apply(std::mem::take(&mut report.findings), &ig);
    report.findings = kept;
    if sup > 0 {
        report.summary.total -= sup;
        eprintln!("ignore: {sup} finding(s) suppressed by .argusignore");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_star_and_starstar() {
        assert!(glob::Pattern::new("src/*.rs").matches("src/main.rs"));
        assert!(!glob::Pattern::new("src/*.rs").matches("src/a/b.rs"));
        assert!(glob::Pattern::new("src/**").matches("src/a/b.rs"));
        assert!(glob::Pattern::new("**/*.js").matches("a/b/c.js"));
        assert!(glob::Pattern::new("f?.txt").matches("f1.txt"));
        assert!(!glob::Pattern::new("f?.txt").matches("f12.txt"));
    }
}
