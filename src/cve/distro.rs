// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Distro backport check: find the owning package for a binary and
//! look for the advisory id in its changelog.

use flate2::read::GzDecoder;
use std::io::Read;
use std::path::{Path, PathBuf};

pub struct Pkg {
    pub name: String,
    pub version: String,
    pub manager: &'static str,
}

fn run(prog: &str, args: &[&str]) -> Option<String> {
    let (out, ok) = crate::cve::run_cmd(prog, args, std::time::Duration::from_secs(5))?;
    (ok && !out.trim().is_empty()).then_some(out)
}

/// Owning package for a file. root is "/" on a live system or the
/// --root tree (dpkg metadata only there).
pub fn owner(root: &Path, live: bool, path: &Path) -> Option<Pkg> {
    if live {
        if let Some(out) = run("dpkg-query", &["-S", &path.to_string_lossy()]) {
            // "pkg: /usr/sbin/nginx" or "pkg:arch, pkg2: path"
            if let Some(line) = out.lines().next()
                && let Some((pkg, _)) = line.split_once(':')
            {
                let name = pkg.split(',').next()?.trim().to_string();
                let ver = run("dpkg-query", &["-W", "-f=${Version}", &name])
                    .map(|v| v.trim().to_string())
                    .unwrap_or_default();
                return Some(Pkg {
                    name,
                    version: ver,
                    manager: "dpkg",
                });
            }
        }
        if let Some(out) = run("rpm", &["-qf", &path.to_string_lossy()]) {
            let line = out.lines().next()?.trim();
            if !line.is_empty() && !line.contains("not owned") {
                // nvra: strip the last two dash-separated fields for the name
                let parts: Vec<_> = line.rsplitn(3, '-').collect();
                let name = parts.last().unwrap_or(&line).to_string();
                return Some(Pkg {
                    name,
                    version: line.to_string(),
                    manager: "rpm",
                });
            }
        }
        // pacman: "<path> is owned by <pkg> <ver>"; no changelog check
        if let Some(out) = run("pacman", &["-Qo", &path.to_string_lossy()])
            && let Some((name, ver)) = out
                .lines()
                .next()
                .and_then(|l| l.split(" is owned by ").nth(1))
                .and_then(|t| t.rsplit_once(' '))
        {
            return Some(Pkg {
                name: name.to_string(),
                version: ver.to_string(),
                manager: "pacman",
            });
        }
        // apk: "<path> is owned by <pkg>-<ver>"
        if let Some(out) = run("apk", &["info", "--who-owns", &path.to_string_lossy()])
            && let Some(t) = out
                .lines()
                .next()
                .and_then(|l| l.split(" is owned by ").nth(1))
        {
            return Some(Pkg {
                name: t.trim().to_string(),
                version: t.trim().to_string(),
                manager: "apk",
            });
        }
        return None;
    }
    // --root mode: map path through dpkg .list files
    if let Some(p) = apk_owner(root, path) {
        return Some(p);
    }
    let info = root.join("var/lib/dpkg/info");
    let want = format!("/{}", path.strip_prefix("/").unwrap_or(path).display());
    let rd = std::fs::read_dir(&info).ok()?;
    for e in rd.flatten() {
        let p = e.path();
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".list") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        if text.lines().any(|l| l.trim() == want) {
            let pkg = name
                .trim_end_matches(".list")
                .split(':')
                .next()
                .unwrap_or(name)
                .to_string();
            let version = dpkg_status_version(root, &pkg).unwrap_or_default();
            return Some(Pkg {
                name: pkg,
                version,
                manager: "dpkg",
            });
        }
    }
    None
}

/// apk installed db: stanzas with P:/V: fields and F:<dir>/R:<file>
/// records naming installed files.
fn apk_owner(root: &Path, path: &Path) -> Option<Pkg> {
    let text = std::fs::read_to_string(root.join("lib/apk/db/installed")).ok()?;
    let want = format!("/{}", path.strip_prefix("/").unwrap_or(path).display());
    let (mut pkg, mut ver, mut dir) = (String::new(), String::new(), String::new());
    for line in text.lines() {
        if line.is_empty() {
            pkg.clear();
            ver.clear();
            dir.clear();
            continue;
        }
        if let Some(v) = line.strip_prefix("P:") {
            pkg = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("V:") {
            ver = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("F:") {
            dir = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("R:") {
            let f = v.split_whitespace().next().unwrap_or("");
            if format!("/{dir}/{f}") == want {
                return Some(Pkg {
                    name: pkg.clone(),
                    version: ver.clone(),
                    manager: "apk",
                });
            }
        }
    }
    None
}

fn dpkg_status_version(root: &Path, pkg: &str) -> Option<String> {
    let text = std::fs::read_to_string(root.join("var/lib/dpkg/status")).ok()?;
    let mut cur = String::new();
    for line in text.lines().chain(std::iter::once("")) {
        if line.is_empty() {
            if cur == pkg {
                return None; // seen below via track
            }
            cur.clear();
            continue;
        }
        if let Some(v) = line.strip_prefix("Package: ") {
            cur = v.trim().to_string();
        } else if cur == pkg
            && let Some(v) = line.strip_prefix("Version: ")
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

/// Whole-token search for an id inside changelog text.
pub fn mentions(text: &str, ids: &[&str]) -> bool {
    ids.iter().any(|id| {
        text.match_indices(id).any(|(i, _)| {
            let before = text[..i].chars().last();
            let after = text[i + id.len()..].chars().next();
            before.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '-')
                && after.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '-')
        })
    })
}

fn gunzip(p: &Path) -> Option<String> {
    let f = std::fs::File::open(p).ok()?;
    let mut s = String::new();
    GzDecoder::new(f).read_to_string(&mut s).ok()?;
    Some(s)
}

/// True when the vendor changelog names the advisory or an alias.
pub fn backported(root: &Path, live: bool, pkg: &Pkg, ids: &[&str]) -> bool {
    match pkg.manager {
        "dpkg" => {
            let doc = root.join("usr/share/doc").join(&pkg.name);
            for n in ["changelog.Debian.gz", "changelog.gz"] {
                if let Some(text) = gunzip(&doc.join(n))
                    && mentions(&text, ids)
                {
                    return true;
                }
            }
            false
        }
        "rpm" if live => {
            run("rpm", &["-q", "--changelog", &pkg.name]).is_some_and(|t| mentions(&t, ids))
        }
        _ => false,
    }
}

#[allow(dead_code)]
pub fn no_such(_p: &PathBuf) {}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use std::io::Write;

    #[test]
    fn token_search_boundaries() {
        assert!(mentions("fix CVE-2026-109618 here", &["CVE-2026-109618"]));
        assert!(!mentions("CVE-2026-1096180 not it", &["CVE-2026-109618"]));
        assert!(mentions("alias GHSA-x y", &["CVE-1", "GHSA-x"]));
    }

    #[test]
    fn debian_changelog_gz_search() {
        let dir = std::env::temp_dir().join(format!("argus-dpkg-{}", std::process::id()));
        let doc = dir.join("usr/share/doc/nginx");
        std::fs::create_dir_all(&doc).unwrap();
        let f = std::fs::File::create(doc.join("changelog.Debian.gz")).unwrap();
        let mut gz = GzEncoder::new(f, flate2::Compression::fast());
        gz.write_all(b"nginx (1.30.0-1) stable; urgency=medium\n\n  * CVE-2026-109618 backport\n")
            .unwrap();
        gz.finish().unwrap();
        let pkg = Pkg {
            name: "nginx".into(),
            version: "1.30.0-1".into(),
            manager: "dpkg",
        };
        assert!(backported(&dir, false, &pkg, &["CVE-2026-109618"]));
        assert!(!backported(&dir, false, &pkg, &["CVE-2026-999999"]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn root_dpkg_owner_lookup() {
        let dir = std::env::temp_dir().join(format!("argus-dpkgo-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("var/lib/dpkg/info")).unwrap();
        std::fs::write(
            dir.join("var/lib/dpkg/info/nginx:amd64.list"),
            "/usr/sbin/nginx\n/etc/nginx/nginx.conf\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("var/lib/dpkg/status"),
            "Package: nginx\nVersion: 1.30.0-1\nStatus: install ok installed\n\nPackage: php\nVersion: 8.3.30-1\n\n",
        )
        .unwrap();
        let p = owner(&dir, false, Path::new("/usr/sbin/nginx")).unwrap();
        assert_eq!(p.name, "nginx");
        assert_eq!(p.version, "1.30.0-1");
        assert!(owner(&dir, false, Path::new("/bin/none")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
