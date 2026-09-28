//! Entropy-based secret detection - catches high-entropy tokens that no
//! shape-specific rule recognizes.

/// Filenames where long hashes are structural, not secrets.
pub(crate) fn is_lockfile_name(rel: &str) -> bool {
    matches!(
        rel.rsplit('/').next().unwrap_or(rel),
        "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "Cargo.lock"
            | "poetry.lock"
            | "uv.lock"
            | "composer.lock"
            | "go.sum"
            | "mix.lock"
            | "pubspec.lock"
            | "packages.lock.json"
            | "Gemfile.lock"
            | "flake.lock"
            | "conan.lock"
    )
}

/// Token candidates >=24 chars of secret-ish alphabet with Shannon entropy
/// >= 4.5 bits. Returns up to 8 hits per line.
pub(crate) fn tokens(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    if line.len() < 24 || out.len() >= 8 {
        return out;
    }
    let low = line.to_lowercase();
    // hash/context guards: lines that are obviously hashes, urls, paths,
    // translation strings or data-uris are not secrets
    if low.contains("sha256")
        || low.contains("sha512")
        || low.contains("integrity")
        || low.contains("http://")
        || low.contains("https://")
        || low.contains("data:")
    {
        return out;
    }
    let mut cur = String::new();
    for ch in line.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '_' | '-' | '.') {
            cur.push(ch);
        } else {
            take(&mut cur, &mut out);
            if out.len() >= 8 {
                break;
            }
        }
    }
    take(&mut cur, &mut out);
    out
}

fn take(tok: &mut String, out: &mut Vec<String>) {
    if tok.len() >= 24 && entropy(tok) >= 4.5 {
        // pure hex of 64+ is almost always a checksum, not a credential
        let pure_hex = tok.chars().all(|c| c.is_ascii_hexdigit());
        let all_upper = tok.chars().all(|c| !c.is_ascii_lowercase());
        if !(pure_hex || (all_upper && tok.chars().all(|c| c.is_ascii_alphanumeric()))) {
            out.push(std::mem::take(tok));
            return;
        }
    }
    tok.clear();
}

fn entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    let mut e = 0.0;
    for c in counts.iter().filter(|c| **c > 0) {
        let p = *c as f64 / n;
        e -= p * p.log2();
    }
    e
}
