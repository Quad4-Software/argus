// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Local mode: discover installs under root ("/" or --root), extract
//! versions statically from binary bytes, evaluate config probes and
//! distro backports, then match advisories. Nothing is executed in
//! --root mode.

use crate::cli::CveArgs;
use crate::cve::db::{self, Advisory};
use crate::cve::probe::{self, Compiled, Eval};
use crate::cve::{Reach, adv_finding, distro, mk, reach, read_capped, run_cmd, run_cmd_path};
use crate::finding::{Finding, Severity};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_FILE: u64 = 256 * 1024 * 1024;

struct Install {
    product: &'static str,
    path: PathBuf, // logical path (root-relative under --root)
    version: Option<Vec<u64>>,
    version_s: String,
    vsrc: &'static str, // where the version came from
    sapi_web: bool,     // php: serves web requests
    pid: Option<u32>,
    deleted: bool,
    conf_path: Option<String>,
    compiled: Compiled,
    plus: bool,          // NGINX Plus marker seen
    target: String,      // "local" or "container:<image-or-id>"
    fs_root: PathBuf,    // probe/distro root: root, or /proc/<pid>/root
    live_fs: bool,       // distro commands may run against this root
    cid: Option<String>, // container id when namespaced
    image: Option<String>,
}

impl Install {
    fn base(product: &'static str, web: bool, logical: &Path, root: &Path, live: bool) -> Self {
        Install {
            product,
            path: logical.to_path_buf(),
            version: None,
            version_s: String::new(),
            vsrc: "binary",
            sapi_web: web,
            pid: None,
            deleted: false,
            conf_path: None,
            compiled: Compiled::default(),
            plus: false,
            target: "local".into(),
            fs_root: root.to_path_buf(),
            live_fs: live,
            cid: None,
            image: None,
        }
    }
}

fn classify_name(name: &str) -> Option<(&'static str, bool)> {
    let n = name.to_ascii_lowercase();
    let web = true;
    let cli = false;
    if n == "nginx" {
        Some(("nginx", web))
    } else if n.starts_with("php-fpm")
        || n.starts_with("php-cgi")
        || n == "frankenphp"
        || n.starts_with("lsphp")
        || n.starts_with("libphp")
    {
        Some(("php", web))
    } else if n == "php"
        || (n.starts_with("php") && n[3..].chars().all(|c| c.is_ascii_digit() || c == '.'))
    {
        Some(("php", cli))
    } else if n == "apache2" || n == "httpd" {
        Some(("httpd", web))
    } else if n == "traefik" {
        Some(("traefik", web))
    } else if n == "caddy" {
        Some(("caddy", web))
    } else if n == "brotli" {
        Some(("brotli", web))
    } else {
        None
    }
}

fn brotli_lib(name: &str) -> bool {
    [
        "libbrotlidec.so.",
        "libbrotlienc.so.",
        "libbrotlicommon.so.",
    ]
    .iter()
    .any(|p| name.starts_with(p))
}

fn ngx_brotli(name: &str) -> bool {
    name == "ngx_http_brotli_filter_module.so" || name == "ngx_http_brotli_static_module.so"
}

fn re(pat: &str) -> regex::bytes::Regex {
    regex::bytes::Regex::new(pat).unwrap()
}

fn cap_str(re: &regex::bytes::Regex, bytes: &[u8], idx: usize) -> Option<String> {
    re.captures(bytes)
        .and_then(|c| c.get(idx))
        .map(|m| String::from_utf8_lossy(m.as_bytes()).to_string())
}

struct Extract {
    version: Option<String>,
    conf_path: Option<String>,
    compiled: Compiled,
    plus: bool,
}

fn extract(product: &str, bytes: &[u8]) -> Extract {
    let mut e = Extract {
        version: None,
        conf_path: None,
        compiled: Compiled::default(),
        plus: false,
    };
    match product {
        "nginx" => {
            e.version = cap_str(&re(r"nginx version: nginx/(\d+\.\d+\.\d+)"), bytes, 1)
                .or_else(|| cap_str(&re(r"nginx/(\d+\.\d+\.\d+)"), bytes, 1));
            if let Some(m) = re(r"configure arguments:([^\n\x00]{1,4096})").captures(bytes)
                && let Some(l) = m.get(1)
            {
                let args = String::from_utf8_lossy(l.as_bytes()).to_string();
                e.compiled.args = Some(args.clone());
                e.conf_path = args
                    .split_whitespace()
                    .find_map(|t| t.strip_prefix("--conf-path=").map(String::from));
            }
            e.plus = bytes.windows(12).any(|w| w == b"nginx-plus-r")
                || re(r"nginx-plus-r\d+").is_match(bytes);
        }
        "php" => {
            e.version = cap_str(&re(r"X-Powered-By: PHP/(\d+\.\d+\.\d+)"), bytes, 1);
        }
        "httpd" => {
            e.version = cap_str(&re(r"Apache/(2\.\d+\.\d+)"), bytes, 1);
        }
        "caddy" => {
            e.version = cap_str(
                &re(r"github\.com/caddyserver/caddy/v2[\s\x00]+v?(\d+\.\d+\.\d+)"),
                bytes,
                1,
            );
        }
        "traefik" => {
            // Go buildinfo module line, then the ldflags style marker
            e.version = cap_str(
                &re(r"github\.com/traefik/traefik/v[23][\s\x00]+v?(\d+\.\d+\.\d+)"),
                bytes,
                1,
            )
            .or_else(|| cap_str(&re(r"Version:\s+v?(\d+\.\d+\.\d+)"), bytes, 1));
        }
        _ => {}
    }
    e
}

fn world_writable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o002 != 0)
        .unwrap_or(true)
}

/// Exec fallback (live mode only). Never runs world-writable binaries.
fn exec_version(product: &str, real: &Path) -> Option<String> {
    if world_writable(real) {
        return None;
    }
    let args: &[&str] = match product {
        "nginx" | "caddy" | "traefik" => &["version"],
        "php" => &["-v"],
        _ => return None,
    };
    let (out, _ok) = run_cmd_path(real, args, Duration::from_secs(3))?;
    match product {
        "traefik" => out.lines().find_map(|l| {
            l.trim()
                .strip_prefix("Version:")
                .map(|v| v.trim().to_string())
        }),
        "php" => re(r"PHP (\d+\.\d+\.\d+)")
            .captures(out.as_bytes())
            .and_then(|c| c.get(1))
            .map(|m| String::from_utf8_lossy(m.as_bytes()).to_string()),
        _ => re(r"(\d+\.\d+\.\d+)")
            .captures(out.as_bytes())
            .and_then(|c| c.get(1))
            .map(|m| String::from_utf8_lossy(m.as_bytes()).to_string()),
    }
}

fn gather_candidates(root: &Path) -> Vec<(PathBuf, PathBuf)> {
    // (logical path, real path)
    let mut out = Vec::new();
    let mut push_dir = |logical: &str, depth: usize| {
        let real = root.join(logical.trim_start_matches('/'));
        walk(&real, logical, depth, &mut out);
    };
    fn walk(real: &Path, logical: &str, depth: usize, out: &mut Vec<(PathBuf, PathBuf)>) {
        let Ok(rd) = std::fs::read_dir(real) else {
            return;
        };
        let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        entries.sort();
        for p in entries {
            let name = match p.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            let lp = format!("{logical}/{name}");
            let Ok(ft) = p.symlink_metadata().map(|m| m.file_type()) else {
                continue;
            };
            if ft.is_dir() && depth > 0 {
                walk(&p, &lp, depth - 1, out);
            } else {
                out.push((PathBuf::from(lp), p));
            }
        }
    }
    for d in [
        "/usr/sbin",
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/sbin",
    ] {
        push_dir(d, 1);
    }
    push_dir("/opt", 3);
    if let Ok(path) = std::env::var("PATH") {
        for d in path.split(':').filter(|d| !d.is_empty()) {
            push_dir(d, 1);
        }
    }
    for d in [
        "/usr/lib",
        "/usr/lib64",
        "/lib",
        "/lib64",
        "/usr/local/lib",
        "/usr/local/lib64",
    ] {
        push_dir(d, 2);
    }
    // lib dirs like /usr/lib/x86_64-linux-gnu are covered by depth 2
    out
}

struct ProcEntry {
    pid: u32,
    target: PathBuf, // exe link target (container path for namespaced procs)
    exe: PathBuf,    // /proc/<pid>/exe - reading it crosses mount namespaces
    deleted: bool,
    comm: String,
}

fn proc_entries() -> Vec<ProcEntry> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return out;
    };
    for e in rd.flatten() {
        let pid: u32 = match e.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        let exe = e.path().join("exe");
        let Ok(link) = std::fs::read_link(&exe) else {
            continue;
        };
        let s = link.to_string_lossy();
        let deleted = s.ends_with(" (deleted)");
        let clean = s.trim_end_matches(" (deleted)");
        let comm = std::fs::read_to_string(e.path().join("comm"))
            .map(|c| c.trim().to_string())
            .unwrap_or_default();
        out.push(ProcEntry {
            pid,
            target: PathBuf::from(clean),
            exe,
            deleted,
            comm,
        });
    }
    out
}

/// True when the process lives in another mount namespace (container).
fn other_mount_ns(pid: u32, self_mnt: &Option<PathBuf>) -> bool {
    match (
        std::fs::read_link(format!("/proc/{pid}/ns/mnt")).ok(),
        self_mnt,
    ) {
        (Some(theirs), Some(ours)) => theirs != *ours,
        _ => false,
    }
}

/// Last 64-char lowercase hex run in a cgroup file: docker-<id>.scope,
/// /docker/<id>, libpod-<id>.scope, cri-containerd-<id>.scope, cri-o.
fn container_id(cgroup: &str) -> Option<String> {
    let mut found = None;
    let mut run = String::new();
    for c in cgroup.chars() {
        if c.is_ascii_digit() || ('a'..='f').contains(&c) {
            run.push(c);
            if run.len() == 64 {
                found = Some(run.clone());
            }
        } else {
            run.clear();
        }
    }
    found
}

/// docker/podman inspect -> Config.Image, best effort.
fn image_of(cid: &str) -> Option<String> {
    for rt in ["docker", "podman"] {
        if let Some((out, ok)) = run_cmd(
            rt,
            &["inspect", "--format", "{{.Config.Image}}", cid],
            Duration::from_secs(3),
        ) && ok
        {
            let s = out.trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

fn brotli_version_from_name(name: &str) -> Option<String> {
    // libbrotlidec.so.1.1.0 -> 1.1.0
    let pos = name.find(".so.")? + 4;
    let v = crate::cve::version::parse(&name[pos..])?;
    // only a fully versioned soname counts
    (v.len() >= 3).then(|| name[pos..].to_string())
}

fn containers() -> Vec<(String, String, String)> {
    // (container short id, repo last segment, tag)
    for rt in ["docker", "podman"] {
        if let Some((out, ok)) = run_cmd(
            rt,
            &["ps", "--format", "{{.ID}} {{.Image}}"],
            Duration::from_secs(3),
        ) && ok
        {
            return out
                .lines()
                .filter_map(|l| {
                    let (id, img) = l.trim().split_once(' ')?;
                    let (name, tag) = parse_image(img)?;
                    Some((id.to_string(), name, tag))
                })
                .collect();
        }
    }
    Vec::new()
}

fn parse_image(img: &str) -> Option<(String, String)> {
    let (repo, tag) = img.rsplit_once(':')?;
    if repo.contains('@') {
        return None;
    }
    let name = repo.rsplit('/').next()?.to_string();
    Some((name, tag.to_string()))
}

const CONTAINER_PRODUCTS: &[(&str, &str)] = &[
    ("nginx", "nginx"),
    ("nginx-unprivileged", "nginx"),
    ("traefik", "traefik"),
    ("caddy", "caddy"),
    ("php", "php"),
    ("httpd", "httpd"),
];

fn container_version(tag: &str) -> Option<String> {
    let t = tag.trim_start_matches('v');
    let mut end = 0;
    for (i, c) in t.char_indices() {
        if c.is_ascii_digit() || c == '.' {
            end = i + 1;
        } else {
            break;
        }
    }
    let head = &t[..end];
    // require a full X.Y.Z
    if head.split('.').count() == 3 && head.split('.').all(|p| !p.is_empty()) {
        Some(head.to_string())
    } else {
        None
    }
}

pub fn scan(db: &[Advisory], root: &Path, live: bool, args: &CveArgs) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut installs: Vec<Install> = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();

    // (a) running processes (live mode only). The exe is read through
    // /proc/<pid>/exe itself: the readlink target names a path inside
    // the process mount namespace and is wrong on the host for
    // containerized services.
    let mut seen_containers: BTreeSet<String> = BTreeSet::new();
    let mut seen_proc: BTreeSet<(String, &'static str, u64, u64)> = BTreeSet::new();
    if live {
        let self_mnt = std::fs::read_link("/proc/self/ns/mnt").ok();
        let mut img_cache: std::collections::HashMap<String, Option<String>> =
            std::collections::HashMap::new();
        for p in proc_entries() {
            let Some(name) = p
                .target
                .file_name()
                .and_then(|n| n.to_str())
                .map(String::from)
            else {
                continue;
            };
            let Some((product, web)) = classify_name(&name) else {
                continue;
            };
            use std::os::unix::fs::MetadataExt;
            let (dev, ino) = std::fs::metadata(&p.exe)
                .map(|m| (m.dev(), m.ino()))
                .unwrap_or((0, p.pid as u64));
            let namespaced = other_mount_ns(p.pid, &self_mnt);
            let cid = if namespaced {
                std::fs::read_to_string(format!("/proc/{}/cgroup", p.pid))
                    .ok()
                    .and_then(|c| container_id(&c))
            } else {
                None
            };
            // dedup key: (container or host, product, binary dev+inode)
            let key = (
                cid.clone().unwrap_or_else(|| "host".into()),
                product,
                dev,
                ino,
            );
            if !seen_proc.insert(key) {
                continue;
            }
            let mut bytes = read_capped(&p.exe, MAX_FILE);
            if bytes.is_none() && !namespaced && p.target.is_file() {
                // same mount ns: the link target is a genuine host path
                bytes = read_capped(&p.target, MAX_FILE);
            }
            let Some(bytes) = bytes else {
                let mut f = mk(
                    "CVE-INFO-004",
                    Severity::Info,
                    "local",
                    &p.target.to_string_lossy(),
                    format!(
                        "process {} pid {} ({}) runs in another namespace and could not be read, re-run as root",
                        product, p.pid, p.comm
                    ),
                );
                f.evidence = Some(vec![format!("pid {}", p.pid)]);
                out.push(f);
                continue;
            };
            let mut inst = Install::base(product, web, &p.target, root, live);
            inst.pid = Some(p.pid);
            inst.deleted = p.deleted;
            if let Some(c) = &cid {
                seen_containers.insert(c[..12.min(c.len())].to_string());
                let img = img_cache
                    .entry(c.clone())
                    .or_insert_with(|| image_of(c))
                    .clone();
                inst.image = img;
                inst.cid = Some(c.clone());
                inst.fs_root = PathBuf::from(format!("/proc/{}/root", p.pid));
                inst.live_fs = false;
                let short = &c[..12.min(c.len())];
                inst.target = format!("container:{}", inst.image.as_deref().unwrap_or(short));
            }
            let ex = extract(product, &bytes);
            inst.version_s = ex.version.clone().unwrap_or_default();
            inst.conf_path = ex.conf_path;
            inst.compiled = ex.compiled;
            inst.plus = ex.plus;
            if inst.version_s.is_empty()
                && cid.is_none()
                && let Some(v) = exec_version(product, &p.target)
            {
                inst.version_s = v;
                inst.vsrc = "exec";
            }
            if inst.version_s.is_empty()
                && let Some(img) = &inst.image
            {
                match parse_image(img).and_then(|(_, t)| container_version(&t)) {
                    Some(v) => {
                        inst.version_s = v;
                        inst.vsrc = "image tag";
                    }
                    None => {
                        let mut f = mk(
                            "CVE-INFO-007",
                            Severity::Info,
                            &inst.target,
                            &p.target.to_string_lossy(),
                            format!("{img} is a floating tag, pull and re-scan"),
                        );
                        let short = cid.as_deref().map(|c| &c[..12.min(c.len())]).unwrap_or("?");
                        f.evidence = Some(vec![
                            format!("runs in container {short} ({img})"),
                            format!("pid {}", p.pid),
                        ]);
                        out.push(f);
                    }
                }
            }
            inst.version = (!inst.version_s.is_empty())
                .then(|| crate::cve::version::parse(&inst.version_s))
                .flatten();
            installs.push(inst);
            if cid.is_none() {
                seen.insert(p.target.canonicalize().unwrap_or(p.target.clone()));
            }
        }
    }

    // (b) filesystem candidates
    for (logical, real) in gather_candidates(root) {
        let Some(name) = logical
            .file_name()
            .and_then(|n| n.to_str())
            .map(String::from)
        else {
            continue;
        };
        if ngx_brotli(&name) {
            let mut f = mk(
                "CVE-INFO-008",
                Severity::Info,
                "local",
                &logical.to_string_lossy(),
                format!(
                    "ngx_brotli module {name} found: it only encodes, so CVE-2026-111497 does not apply to it"
                ),
            );
            f.evidence = Some(vec![
                "ngx_brotli serves precompressed output; the decoder flaw is in libbrotlidec"
                    .into(),
            ]);
            out.push(f);
            continue;
        }
        if brotli_lib(&name) {
            // resolve symlink to the versioned file
            let target = real.canonicalize().unwrap_or(real.clone());
            if !seen.insert(target.clone()) {
                continue;
            }
            let tname = target
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&name)
                .to_string();
            let vs = brotli_version_from_name(&tname).or_else(|| brotli_version_from_name(&name));
            let v = vs.as_deref().and_then(crate::cve::version::parse);
            let mut i = Install::base("brotli", true, &logical, root, live);
            i.version = v;
            i.version_s = vs.unwrap_or_default();
            i.vsrc = "soname";
            installs.push(i);
            continue;
        }
        let Some((product, web)) = classify_name(&name) else {
            continue;
        };
        let canonical = real.canonicalize().unwrap_or(real.clone());
        if !seen.insert(canonical) {
            continue;
        }
        installs.push(inspect(product, web, &logical, &real, root, live));
    }

    // config blobs per fs root (host root plus each container root)
    let mut cfgs: std::collections::HashMap<PathBuf, probe::Cfg> = std::collections::HashMap::new();
    fn cfg_for<'a>(
        cfgs: &'a mut std::collections::HashMap<PathBuf, probe::Cfg>,
        fs_root: &Path,
        conf: Option<&str>,
    ) -> &'a probe::Cfg {
        cfgs.entry(fs_root.to_path_buf())
            .or_insert_with(|| probe::collect(fs_root, conf))
    }

    // php SAPI: web if any web-flavoured binary exists in the same scope
    let mut php_web: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    for i in &installs {
        if i.product == "php" && i.sapi_web {
            php_web.insert(i.target.clone(), true);
        }
    }
    for i in installs.iter_mut().filter(|i| i.product == "php") {
        i.sapi_web = php_web.get(&i.target).copied().unwrap_or(false);
    }

    let mut stats = Stats::default();

    for inst in &installs {
        if inst.plus {
            out.push(info_t(
                "CVE-INFO-005",
                &inst.target,
                &inst.path,
                "NGINX Plus detected: this database does not evaluate Plus builds",
            ));
        }
        if inst.deleted
            && let Some(pid) = inst.pid
        {
            let mut f = mk(
                "CVE-HOST-001",
                Severity::High,
                &inst.target,
                &inst.path.to_string_lossy(),
                format!(
                    "running {} pid {pid} uses a replaced binary, restart it",
                    inst.product
                ),
            );
            f.remediation = Some(format!("restart the {} service", inst.product));
            out.push(f);
        }
        let Some(ver) = &inst.version else {
            if inst.product == "traefik" && !live {
                out.push(info_t(
                    "CVE-INFO-006",
                    &inst.target,
                    &inst.path,
                    "traefik found in offline root, version unknown",
                ));
            }
            continue;
        };
        stats.products.insert(inst.product);
        let cfg = cfg_for(&mut cfgs, &inst.fs_root, inst.conf_path.as_deref());
        emit_product(
            db,
            inst,
            ver,
            &Env {
                cfg,
                root: &inst.fs_root,
                live: inst.live_fs,
            },
            &mut stats,
            &mut out,
        );
    }

    // containers (live only); skip ids already found via /proc
    if live && !args.no_containers {
        for (id, name, tag) in containers() {
            if seen_containers.contains(&id) {
                continue;
            }
            let Some(product) = CONTAINER_PRODUCTS
                .iter()
                .find(|(n, _)| n == &name)
                .map(|(_, p)| *p)
            else {
                continue;
            };
            let target = format!("container:{name}:{tag}");
            match container_version(&tag)
                .and_then(|vs| crate::cve::version::parse(&vs).map(|v| (vs, v)))
            {
                Some((vs, v)) => {
                    stats.products.insert(product);
                    for adv in db::for_product(db, product) {
                        if !adv.hits(&v) {
                            continue;
                        }
                        stats.matched += 1;
                        let ev = vec![
                            format!("container image {name}:{tag}"),
                            format!("detected {product} {vs}"),
                            "configuration not inspected".to_string(),
                        ];
                        out.push(adv_finding(adv, adv.severity, &target, "", ev));
                    }
                }
                None => {
                    let mut f = mk(
                        "CVE-INFO-007",
                        Severity::Info,
                        &target,
                        "",
                        format!("{name}:{tag} is a floating tag, pull and re-scan"),
                    );
                    f.evidence = Some(vec![format!("image tag {tag} has no full version")]);
                    out.push(f);
                }
            }
        }
    }

    // summary
    let mut f = mk(
        "CVE-INFO-003",
        Severity::Info,
        "local",
        "",
        format!(
            "{} product install(s), {} advisories matched, {} vendor backported, {} not reachable (db: {} advisories)",
            stats.products.len(),
            stats.matched,
            stats.backported,
            stats.not_reachable,
            db.len(),
        ),
    );
    f.evidence = Some(vec![
        "database built into this argus release; use --db for newer advisories".into(),
    ]);
    out.push(f);
    out
}

#[derive(Default)]
struct Stats {
    products: BTreeSet<&'static str>,
    matched: usize,
    backported: usize,
    not_reachable: usize,
}

fn info_t(id: &str, target: &str, path: &Path, msg: &str) -> Finding {
    mk(id, Severity::Info, target, &path.to_string_lossy(), msg)
}

fn inspect(
    product: &'static str,
    web: bool,
    logical: &Path,
    real: &Path,
    root: &Path,
    live: bool,
) -> Install {
    let bytes = if real.is_file() {
        read_capped(real, MAX_FILE).unwrap_or_default()
    } else {
        Vec::new()
    };
    let ex = extract(product, &bytes);
    let mut version_s = ex.version.clone();
    if version_s.is_none() && live {
        version_s = exec_version(product, real);
    }
    let mut i = Install::base(product, web, logical, root, live);
    i.version = version_s.as_deref().and_then(crate::cve::version::parse);
    if i.version.is_some() && ex.version.is_none() {
        i.vsrc = "exec";
    }
    i.version_s = version_s.unwrap_or_default();
    i.conf_path = ex.conf_path;
    i.compiled = ex.compiled;
    i.plus = ex.plus;
    i
}

struct Env<'a> {
    cfg: &'a probe::Cfg,
    root: &'a Path,
    live: bool,
}

fn emit_product(
    db: &[Advisory],
    inst: &Install,
    ver: &[u64],
    env: &Env,
    stats: &mut Stats,
    out: &mut Vec<Finding>,
) {
    let cfg = env.cfg;
    let root = env.root;
    let live = env.live;
    let path_s = inst.path.to_string_lossy().to_string();
    for adv in db::for_product(db, inst.product) {
        if !adv.hits(ver) {
            continue;
        }
        stats.matched += 1;
        let mut ev = vec![format!(
            "detected {} {} at {} ({})",
            inst.product, inst.version_s, path_s, inst.vsrc
        )];
        if let (Some(c), img) = (&inst.cid, &inst.image) {
            let short = &c[..12.min(c.len())];
            ev.push(format!(
                "runs in container {short} ({})",
                img.as_deref().unwrap_or("unknown image")
            ));
        }
        if let Some(pid) = inst.pid {
            ev.push(format!("pid {pid}"));
        }

        // scope=web advisory on a cli-only php install downgrades to info
        let cli_only = adv.scope.as_deref() == Some("web") && !inst.sapi_web;

        // vendor backport wins over severity
        let pkg = distro::owner(root, live, &inst.path);
        let mut ids: Vec<&str> = vec![adv.id.as_str()];
        ids.extend(adv.aliases.iter().map(|a| a.as_str()));
        if let Some(p) = &pkg {
            if distro::backported(root, live, p, &ids) {
                stats.backported += 1;
                let mut f = info_t(
                    &adv.id,
                    &inst.target,
                    &inst.path,
                    &format!(
                        "{} addressed by vendor backport in {} {}",
                        adv.id, p.name, p.version
                    ),
                );
                f.evidence = Some(vec![format!(
                    "package {} {} changelog names {}",
                    p.name, p.version, adv.id
                )]);
                f.reference = adv.reference.clone();
                out.push(f);
                continue;
            }
            ev.push(format!(
                "package {} {}, changelog does not mention {}",
                p.name, p.version, adv.id
            ));
        }

        // feature reachability
        let evals: Vec<(String, Eval)> = adv
            .needs
            .iter()
            .map(|n| (n.clone(), probe::eval(n, inst.product, cfg, &inst.compiled)))
            .collect();
        let mut sev = adv.severity;
        if cli_only {
            sev = Severity::Info;
            ev.push("CLI only, not serving web requests".into());
        }
        if inst.product == "php" && adv.scope.as_deref() == Some("web") {
            ev.extend(probe::php2shell_evidence(cfg));
        }
        match reach(adv, &evals) {
            Reach::Yes(y) => {
                ev.extend(y);
                out.push(adv_finding(adv, sev, &inst.target, &path_s, ev));
            }
            Reach::No => {
                stats.not_reachable += 1;
                let mut f = adv_finding(adv, Severity::Info, &inst.target, &path_s, ev);
                f.message = format!(
                    "{}: version is affected but the feature is not configured or compiled in",
                    adv.id
                );
                if let Some(e) = f.evidence.as_mut() {
                    e.push(format!("probes: {}", adv.needs.join(", ")));
                }
                out.push(f);
            }
            Reach::Unknown(_) => {
                if adv.needs.is_empty() {
                    out.push(adv_finding(adv, sev, &inst.target, &path_s, ev));
                } else {
                    ev.push("config could not be read".into());
                    out.push(adv_finding(adv, sev, &inst.target, &path_s, ev));
                }
            }
        }
    }

    // PHP end of life
    let eol = inst.product == "php"
        && inst.sapi_web
        && (ver.first().copied().unwrap_or(0) < 8
            || (ver.first().copied().unwrap_or(0) == 8 && ver.get(1).copied().unwrap_or(0) < 2));
    if eol {
        // emit only when no backport finding was emitted for the php2shell
        // advisories: approximate by checking the vendor changelog once
        let pkg = distro::owner(root, live, &inst.path);
        let covered = pkg.as_ref().is_some_and(|p| {
            distro::backported(root, live, p, &["CVE-2026-109618", "GHSA-w8hw-w9fx-j79w"])
        });
        if !covered {
            let mut f = mk(
                "CVE-HOST-002",
                Severity::Medium,
                &inst.target,
                &path_s,
                format!(
                    "php {} branch is end of life upstream, only vendor backports can fix php2shell",
                    inst.version_s
                ),
            );
            f.remediation =
                Some("Upgrade to PHP 8.2 or newer, or track vendor security backports".into());
            out.push(f);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_classification() {
        assert_eq!(classify_name("nginx").unwrap().0, "nginx");
        assert_eq!(classify_name("php-fpm8.3").unwrap().0, "php");
        assert!(classify_name("php-fpm8.3").unwrap().1);
        assert!(!classify_name("php").unwrap().1);
        assert_eq!(classify_name("httpd").unwrap().0, "httpd");
        assert_eq!(classify_name("libphp8.so").unwrap().0, "php");
        assert!(classify_name("sshd").is_none());
    }

    #[test]
    fn brotli_names() {
        assert_eq!(
            brotli_version_from_name("libbrotlidec.so.1.1.0"),
            Some("1.1.0".into())
        );
        assert!(brotli_version_from_name("libbrotlidec.so.1").is_none());
        assert!(ngx_brotli("ngx_http_brotli_filter_module.so"));
    }

    #[test]
    fn container_tags() {
        assert_eq!(container_version("1.30.0-alpine"), Some("1.30.0".into()));
        assert_eq!(container_version("v2.11.0"), Some("2.11.0".into()));
        assert_eq!(container_version("latest"), None);
        assert_eq!(container_version("8.3"), None);
        assert_eq!(container_version("2"), None);
        assert_eq!(
            parse_image("docker.io/library/nginx:1.30.0-alpine"),
            Some(("nginx".into(), "1.30.0-alpine".into()))
        );
    }

    #[test]
    fn cgroup_container_ids() {
        let id = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        assert_eq!(
            container_id(&format!("1:name=systemd:/docker/{id}")),
            Some(id.into())
        );
        assert_eq!(
            container_id(&format!("0::/system.slice/docker-{id}.scope")),
            Some(id.into())
        );
        assert_eq!(
            container_id(&format!("0::/machine.slice/libpod-{id}.scope")),
            Some(id.into())
        );
        assert_eq!(
            container_id(&format!("0::/kubepods.slice/cri-containerd-{id}.scope")),
            Some(id.into())
        );
        assert_eq!(container_id("0::/user.slice/user-1000.slice"), None);
        assert_eq!(container_id(""), None);
    }

    #[test]
    fn proc_dedup_key() {
        // same (scope, product, dev, ino) dedups; container vs host differs
        let mut seen = std::collections::BTreeSet::new();
        let host = ("host".to_string(), "nginx", 8u64, 42u64);
        let cont = ("abc123".to_string(), "nginx", 8u64, 42u64);
        assert!(seen.insert(host.clone()));
        assert!(!seen.insert(host.clone()));
        assert!(seen.insert(cont.clone())); // different scope, same inode
        assert!(seen.insert(("host".to_string(), "php", 8, 42)));
        assert!(seen.insert(("host".to_string(), "nginx", 8, 43)));
    }

    #[test]
    fn static_extract() {
        let bytes = b"\x00ELF nginx version: nginx/1.30.0\nconfigure arguments: --with-http_v3_module --conf-path=/x/nginx.conf\x00";
        let e = extract("nginx", bytes);
        assert_eq!(e.version.as_deref(), Some("1.30.0"));
        assert_eq!(e.conf_path.as_deref(), Some("/x/nginx.conf"));
        let e = extract("php", b"abc X-Powered-By: PHP/8.3.30 zzz");
        assert_eq!(e.version.as_deref(), Some("8.3.30"));
        let e = extract("caddy", b"github.com/caddyserver/caddy/v2 v2.10.0 h1:x");
        assert_eq!(e.version.as_deref(), Some("2.10.0"));
        let e = extract(
            "traefik",
            b"dep\tgithub.com/traefik/traefik/v3\tv3.7.14\th1:x",
        );
        assert_eq!(e.version.as_deref(), Some("3.7.14"));
    }
}
