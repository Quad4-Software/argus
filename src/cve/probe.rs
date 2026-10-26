// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Config probes: build a comment-stripped blob per product and answer
//! named feature questions with Yes, No or Unknown.

use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Eval {
    Yes,
    No,
    Unknown,
}

/// Comment-stripped config text per product, collected under root
/// ("/" or the --root tree). None means the config could not be read.
#[derive(Default)]
pub struct Cfg {
    pub nginx: Option<String>,
    pub httpd: Option<String>,
    pub php: Option<String>,
}

/// nginx compile flags learned from the binary's configure arguments
/// line. None means the string was not found.
#[derive(Default)]
pub struct Compiled {
    pub args: Option<String>,
}

impl Compiled {
    fn has(&self, flag: &str) -> Eval {
        match &self.args {
            Some(a) if a.contains(flag) => Eval::Yes,
            Some(_) => Eval::No,
            None => Eval::Unknown,
        }
    }
}

fn strip_comments(text: &str) -> String {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

const MAX_DEPTH: usize = 8;
const MAX_BYTES: usize = 4 * 1024 * 1024;

fn read_nginx_conf(path: &Path, root: &Path, out: &mut String, depth: usize) {
    if depth > MAX_DEPTH || out.len() >= MAX_BYTES {
        return;
    }
    let real = root.join(path.strip_prefix("/").unwrap_or(path));
    let Ok(text) = std::fs::read_to_string(&real) else {
        return;
    };
    out.push_str(&text);
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim().to_string();
        let Some(rest) = line.strip_prefix("include") else {
            continue;
        };
        let inc = rest.trim().trim_end_matches(';').trim().to_string();
        if inc.is_empty() {
            continue;
        }
        let inc = if inc.starts_with('/') {
            inc
        } else {
            match path.parent() {
                Some(p) => p.join(&inc).to_string_lossy().to_string(),
                None => continue,
            }
        };
        if inc.contains('*') {
            // glob only in the last segment
            let (dir, pat) = match inc.rsplit_once('/') {
                Some((d, p)) => (d.to_string(), p.to_string()),
                None => continue,
            };
            let rdir = root.join(dir.strip_prefix('/').unwrap_or(&dir));
            if let Ok(rd) = std::fs::read_dir(&rdir) {
                let mut names: Vec<PathBuf> = rd
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| glob_last(&pat, p))
                    .collect();
                names.sort();
                for p in names {
                    let logical = Path::new("/").join(p.strip_prefix(root).unwrap_or(&p));
                    read_nginx_conf(&logical, root, out, depth + 1);
                }
            }
        } else {
            read_nginx_conf(Path::new(&inc), root, out, depth + 1);
        }
    }
}

fn glob_last(pat: &str, path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let mut parts = pat.split('*');
    let mut rest = name;
    let first = parts.next().unwrap_or("");
    if !rest.starts_with(first) {
        return false;
    }
    rest = &rest[first.len()..];
    let segs: Vec<&str> = parts.collect();
    for (i, seg) in segs.iter().enumerate() {
        if i == segs.len() - 1 {
            if !rest.ends_with(seg) {
                return false;
            }
        } else if let Some(p) = rest.find(seg) {
            rest = &rest[p + seg.len()..];
        } else {
            return false;
        }
    }
    true
}

fn read_tree(dir: &Path, root: &Path, out: &mut String, depth: usize) {
    if depth > MAX_DEPTH || out.len() >= MAX_BYTES {
        return;
    }
    let real = root.join(dir.strip_prefix("/").unwrap_or(dir));
    let Ok(rd) = std::fs::read_dir(&real) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        let Ok(ft) = p.metadata().map(|m| m.file_type()) else {
            continue;
        };
        if ft.is_dir() {
            let logical = Path::new("/").join(p.strip_prefix(root).unwrap_or(&p));
            read_tree(&logical, root, out, depth + 1);
        } else if let Ok(text) = std::fs::read_to_string(&p) {
            out.push_str(&text);
            out.push('\n');
        }
    }
}

fn read_glob(root: &Path, dir: &str, pat: &str, out: &mut String) {
    let rdir = root.join(dir.strip_prefix('/').unwrap_or(dir));
    if let Ok(rd) = std::fs::read_dir(&rdir) {
        let mut names: Vec<_> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| glob_last(pat, p))
            .collect();
        names.sort();
        for p in names {
            if p.is_dir() && pat == "*" {
                continue;
            }
            if p.is_dir() {
                if let Ok(rd2) = std::fs::read_dir(&p) {
                    for e in rd2.flatten() {
                        let _ = std::fs::read_to_string(e.path()).map(|t| out.push_str(&t));
                    }
                }
            } else if let Ok(text) = std::fs::read_to_string(&p) {
                out.push_str(&text);
                out.push('\n');
            }
        }
    }
}

/// Collect config blobs under root. conf_path comes from the nginx
/// binary's configure arguments when known.
pub fn collect(root: &Path, conf_path: Option<&str>) -> Cfg {
    let mut nginx = String::new();
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(c) = conf_path {
        candidates.push(PathBuf::from(c));
    }
    for c in [
        "/etc/nginx/nginx.conf",
        "/usr/local/nginx/conf/nginx.conf",
        "/usr/local/etc/nginx/nginx.conf",
    ] {
        candidates.push(PathBuf::from(c));
    }
    for c in candidates {
        read_nginx_conf(&c, root, &mut nginx, 0);
    }

    let mut httpd = String::new();
    read_tree(Path::new("/etc/apache2"), root, &mut httpd, 0);
    read_tree(Path::new("/etc/httpd"), root, &mut httpd, 0);

    let mut php = String::new();
    // /etc/php/<ver>/{fpm,apache2,cgi,cli}/{php.ini,conf.d/*.ini,pool.d/*.conf}
    let base = root.join("etc/php");
    if let Ok(rd) = std::fs::read_dir(&base) {
        let mut vers: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        vers.sort();
        for v in vers {
            for sapi in ["fpm", "apache2", "cgi", "cli"] {
                let d = v.join(sapi);
                if let Ok(t) = std::fs::read_to_string(d.join("php.ini")) {
                    php.push_str(&t);
                }
                for sub in ["conf.d", "pool.d"] {
                    let sd = d.join(sub);
                    if let Ok(rd2) = std::fs::read_dir(&sd) {
                        let mut names: Vec<_> = rd2.flatten().map(|e| e.path()).collect();
                        names.sort();
                        for p in names {
                            let _ = std::fs::read_to_string(&p).map(|t| php.push_str(&t));
                        }
                    }
                }
            }
        }
    }
    for (dir, pat) in [
        ("/etc", "php.ini"),
        ("/etc/php.d", "*.ini"),
        ("/etc/php-fpm.d", "*.conf"),
    ] {
        read_glob(root, dir, pat, &mut php);
    }

    Cfg {
        nginx: (!nginx.is_empty()).then(|| strip_comments(&nginx)),
        httpd: (!httpd.is_empty()).then(|| strip_comments(&httpd)),
        php: (!php.is_empty()).then(|| strip_comments(&php)),
    }
}

fn line_re(text: &str, pat: &str) -> bool {
    regex::Regex::new(&format!("(?m){pat}"))
        .map(|r| r.is_match(text))
        .unwrap_or(false)
}

fn map_block_has_tilde(text: &str) -> bool {
    let mut depth = 0i32;
    let mut in_map = false;
    for line in text.lines() {
        let t = line.trim();
        if !in_map && depth == 0 && t.starts_with("map ") && t.contains('{') {
            in_map = true;
        }
        if in_map && t.contains('~') {
            return true;
        }
        depth += t.matches('{').count() as i32;
        depth -= t.matches('}').count() as i32;
        if in_map && depth <= 0 {
            in_map = false;
            depth = 0;
        }
    }
    false
}

/// Evaluate one named need. blob is the product config text, compiled
/// the nginx configure flags. Product picks which blob applies.
pub fn eval(need: &str, product: &str, cfg: &Cfg, compiled: &Compiled) -> Eval {
    let blob = match product {
        "nginx" => cfg.nginx.as_deref(),
        "httpd" => cfg.httpd.as_deref(),
        "php" => cfg.php.as_deref(),
        _ => None,
    };
    // compiled-flag gates: if we know the module was not built in, the
    // feature cannot be on regardless of config text
    let flag = match need {
        "http3" => Some("--with-http_v3_module"),
        "mp4" => Some("--with-http_mp4_module"),
        "dav" => Some("--with-http_dav_module"),
        "slice" => Some("--with-http_slice_module"),
        "mail" => Some("--with-mail"),
        _ => None,
    };
    let text_yes = |b: &str| -> bool {
        match need {
            "alias_rewrite" => {
                line_re(b, r"\balias\s")
                    && (b.contains("rewrite") || b.contains("request_filename"))
            }
            "map_regex" => map_block_has_tilde(b),
            "aio" => line_re(b, r"\baio\s+(on|threads)\b"),
            "ssi" => line_re(b, r"\bssi\s+on\b"),
            "http3" => line_re(b, r"listen\s+[^;]*\bquic\b") || line_re(b, r"\bhttp3\s+on\b"),
            "slice" => line_re(b, r"\bslice\s+\d"),
            "grpc_h2" => b.contains("grpc_pass") || line_re(b, r"proxy_http_version\s+2"),
            "charset" => line_re(b, r"\b(charset|source_charset|override_charset)\s"),
            "rewrite_q" => line_re(b, r"\brewrite\s+[^;{]*\?"),
            "scgi_uwsgi" => line_re(b, r"\b(scgi_pass|uwsgi_pass)\s"),
            "ocsp" => {
                line_re(b, r"\bssl_ocsp\s+(on|leaf)\b") || line_re(b, r"\bssl_stapling\s+on\b")
            }
            "dav" => {
                if product == "httpd" {
                    b.contains("LoadModule dav_") || line_re(b, r"(?i)^\s*Dav\s+On")
                } else {
                    line_re(b, r"\bdav_methods\s")
                }
            }
            "mp4" => line_re(b, r"\bmp4\s*;"),
            "mail" => line_re(b, r"^mail\s*\{"),
            "ssl_upstream" => {
                b.contains("proxy_pass https://")
                    || b.contains("grpc_pass grpcs://")
                    || b.contains("proxy_ssl_")
            }
            "resolver" => line_re(b, r"\bresolver\s"),
            "nginx_fpm_split" => b.contains("fastcgi_split_path_info"),
            "http2" => {
                b.contains("LoadModule http2_module")
                    || (line_re(b, r"(?i)^\s*Protocols\s") && {
                        b.lines().any(|l| {
                            let l = l.trim();
                            l.len() > 9
                                && l[..9].eq_ignore_ascii_case("protocols")
                                && l.contains("h2")
                        })
                    })
            }
            "vhost_alias" => b.contains("VirtualDocumentRoot"),
            _ => false,
        }
    };
    // a compiled-in flag also answers Yes: the module is loaded and
    // can be enabled per vhost without a config marker
    if let Some(b) = blob
        && text_yes(b)
    {
        return Eval::Yes;
    }
    match (blob, flag) {
        (Some(_), Some(f)) if compiled.has(f) == Eval::Yes => Eval::Yes,
        (Some(_), _) => Eval::No,
        (None, Some(f)) => compiled.has(f),
        (None, None) => Eval::Unknown,
    }
}

/// php2shell mitigation evidence. Does not change severity.
pub fn php2shell_evidence(cfg: &Cfg) -> Vec<String> {
    let mut ev = Vec::new();
    let Some(php) = cfg.php.as_deref() else {
        ev.push("php.ini could not be read, mitigation state unknown".into());
        return ev;
    };
    let val = |key: &str| -> Option<String> {
        php.lines().find_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix(key)?;
            let rest = rest.trim_start();
            let rest = rest.strip_prefix('=')?.trim();
            Some(rest.to_string())
        })
    };
    let sup = val("session.upload_progress.enabled").unwrap_or_else(|| "On (default)".into());
    ev.push(format!("session.upload_progress.enabled = {sup}"));
    ev.push(format!(
        "memory_limit = {}",
        val("memory_limit").unwrap_or_else(|| "128M (default)".into())
    ));
    ev.push(format!(
        "post_max_size = {}",
        val("post_max_size").unwrap_or_else(|| "8M (default)".into())
    ));
    let locked = php.contains("php_admin_value") || php.contains("php_admin_flag");
    ev.push(format!(
        "php_admin_value/php_admin_flag locks: {}",
        if locked { "present" } else { "none found" }
    ));
    ev
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(nginx: &str) -> Cfg {
        Cfg {
            nginx: Some(nginx.into()),
            ..Default::default()
        }
    }
    fn no_compiled() -> Compiled {
        Compiled::default()
    }

    #[test]
    fn rewrite_with_question_marks() {
        let c = cfg("location / {\n rewrite ^/a/(.*)$ /b?x=$1;\n}\n");
        assert_eq!(eval("rewrite_q", "nginx", &c, &no_compiled()), Eval::Yes);
        let c2 = cfg("location / { root /srv; }\n");
        assert_eq!(eval("rewrite_q", "nginx", &c2, &no_compiled()), Eval::No);
        let c3 = Cfg::default();
        assert_eq!(
            eval("rewrite_q", "nginx", &c3, &no_compiled()),
            Eval::Unknown
        );
    }

    #[test]
    fn map_regex_and_alias() {
        let c = cfg("map $uri $x {\n ~(?<a>foo) 1;\n}\n");
        assert_eq!(eval("map_regex", "nginx", &c, &no_compiled()), Eval::Yes);
        let c2 = cfg("location /i { alias /srv/; rewrite ^ /x; }\n");
        assert_eq!(
            eval("alias_rewrite", "nginx", &c2, &no_compiled()),
            Eval::Yes
        );
        assert_eq!(eval("map_regex", "nginx", &c2, &no_compiled()), Eval::No);
    }

    #[test]
    fn compiled_gates_module_needs() {
        let c = Cfg::default();
        let comp = Compiled {
            args: Some("--prefix=/usr --with-http_v3_module".into()),
        };
        assert_eq!(eval("http3", "nginx", &c, &comp), Eval::Yes);
        let comp2 = Compiled {
            args: Some("--prefix=/usr".into()),
        };
        assert_eq!(eval("mp4", "nginx", &c, &comp2), Eval::No);
    }

    #[test]
    fn httpd_probes() {
        let c = Cfg {
            httpd: Some("LoadModule http2_module modules/m.so\nDav On\n".into()),
            ..Default::default()
        };
        assert_eq!(eval("http2", "httpd", &c, &no_compiled()), Eval::Yes);
        assert_eq!(eval("dav", "httpd", &c, &no_compiled()), Eval::Yes);
        assert_eq!(eval("vhost_alias", "httpd", &c, &no_compiled()), Eval::No);
    }

    #[test]
    fn php2shell_lines() {
        let c = Cfg {
            php: Some(
                "memory_limit = 256M\npost_max_size = 16M\nphp_admin_value[open_basedir]=/srv\n"
                    .into(),
            ),
            ..Default::default()
        };
        let ev = php2shell_evidence(&c);
        assert!(ev.iter().any(|l| l.contains("upload_progress")));
        assert!(ev.iter().any(|l| l.contains("256M")));
        assert!(ev.iter().any(|l| l.contains("present")));
    }
}
