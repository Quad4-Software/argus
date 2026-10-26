// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Dotted-numeric version parsing and range matching.
//! Distro and pre-release suffixes are ignored: only a leading
//! digit.digit... run counts (8.2.30-1+deb12u1 -> 8.2.30,
//! 8.5.0RC1 -> 8.5.0).

/// Leading dotted numeric version, as segments. Missing tail
/// segments compare as zero.
pub fn parse(s: &str) -> Option<Vec<u64>> {
    let s = s.trim().trim_start_matches(['v', 'V']);
    let mut end = 0;
    let mut last_digit = false;
    for (i, c) in s.char_indices() {
        if c.is_ascii_digit() {
            end = i + 1;
            last_digit = true;
        } else if c == '.' && last_digit {
            end = i + 1; // may be trimmed below
            last_digit = false;
        } else {
            break;
        }
    }
    let head = s[..end].trim_end_matches('.');
    if head.is_empty() {
        return None;
    }
    let segs: Result<Vec<u64>, _> = head.split('.').map(|p| p.parse()).collect();
    segs.ok().filter(|v| !v.is_empty())
}

pub fn cmp(a: &[u64], b: &[u64]) -> std::cmp::Ordering {
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            std::cmp::Ordering::Equal => {}
            o => return o,
        }
    }
    std::cmp::Ordering::Equal
}

enum Op {
    Ge,
    Gt,
    Le,
    Lt,
    Eq,
}

fn constraint(c: &str, v: &[u64]) -> Option<bool> {
    let (op, rest) = if let Some(r) = c.strip_prefix(">=") {
        (Op::Ge, r)
    } else if let Some(r) = c.strip_prefix("<=") {
        (Op::Le, r)
    } else if let Some(r) = c.strip_prefix('>') {
        (Op::Gt, r)
    } else if let Some(r) = c.strip_prefix('<') {
        (Op::Lt, r)
    } else if let Some(r) = c.strip_prefix('=') {
        (Op::Eq, r)
    } else {
        (Op::Eq, c)
    };
    let other = parse(rest)?;
    Some(match op {
        Op::Ge => cmp(v, &other) != std::cmp::Ordering::Less,
        Op::Gt => cmp(v, &other) == std::cmp::Ordering::Greater,
        Op::Le => cmp(v, &other) != std::cmp::Ordering::Greater,
        Op::Lt => cmp(v, &other) == std::cmp::Ordering::Less,
        Op::Eq => cmp(v, &other) == std::cmp::Ordering::Equal,
    })
}

/// One range is a space separated set of constraints that must all
/// hold. affected is an OR of ranges.
pub fn in_range(range: &str, v: &[u64]) -> bool {
    let mut any = false;
    for c in range.split_whitespace() {
        match constraint(c, v) {
            Some(true) => any = true,
            _ => return false,
        }
    }
    any && !range.trim().is_empty()
}

pub fn affected(ranges: &[String], v: &[u64]) -> bool {
    ranges.iter().any(|r| in_range(r, v))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Vec<u64> {
        parse(s).unwrap()
    }

    #[test]
    fn parses_prefixes() {
        assert_eq!(v("8.2.30-1+deb12u1"), vec![8, 2, 30]);
        assert_eq!(v("8.5.0RC1"), vec![8, 5, 0]);
        assert_eq!(v("v2.11.0"), vec![2, 11, 0]);
        assert_eq!(v("1.30"), vec![1, 30]);
        assert!(parse("abc").is_none());
        assert!(parse("").is_none());
    }

    #[test]
    fn compares_segmentwise() {
        assert!(cmp(&v("1.30"), &v("1.30.0")).is_eq());
        assert!(cmp(&v("1.30.10"), &v("1.30.6")).is_gt());
        assert!(cmp(&v("2.0"), &v("10.0")).is_lt());
    }

    #[test]
    fn nginx_branch_ranges() {
        let r = [
            ">=1.30.0 <1.30.6".to_string(),
            ">=1.31.2 <1.31.7".to_string(),
        ];
        assert!(affected(&r, &v("1.30.5"))); // CVE-2026-93479
        assert!(!affected(&r, &v("1.30.6")));
        assert!(!affected(&r, &v("1.31.1")));
        assert!(affected(&r, &v("1.31.2")));
        assert!(!affected(&r, &v("1.31.7")));
    }

    #[test]
    fn php_ranges() {
        let r = [
            ">=5.0.0 <8.2.35".to_string(),
            ">=8.3.0 <8.3.36".to_string(),
            ">=8.4.0 <8.4.27".to_string(),
            ">=8.5.0 <8.5.12".to_string(),
        ];
        // CVE-2026-109618
        assert!(affected(&r, &v("8.3.35")));
        assert!(!affected(&r, &v("8.3.36")));
        assert!(!affected(&r, &v("8.2.35")));
        assert!(affected(&r, &v("8.1.34")));
        assert!(affected(&r, &v("7.4.33")));
    }
}
