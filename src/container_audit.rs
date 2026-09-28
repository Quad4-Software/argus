//! Container configuration audit: Dockerfiles, docker-compose files and
//! Kubernetes manifests. Rules are mapped to the OWASP Docker Security
//! Cheat Sheet and the OWASP Kubernetes hardening guidance.

use crate::finding::{Finding, Severity};
use std::collections::HashSet;
use yaml_rust2::Yaml;

const OWASP_DOCKER: &str =
    "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html";
const OWASP_K8S: &str =
    "https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html";

/// File kinds this audit understands.
pub enum Kind {
    Dockerfile,
    Compose,
    Kubernetes,
    None,
}

pub fn kind_of(rel: &str) -> Kind {
    let base = rel.rsplit('/').next().unwrap_or(rel).to_lowercase();
    if base == "dockerfile"
        || base == "containerfile"
        || base.starts_with("dockerfile.")
        || base.ends_with(".dockerfile")
        || base.starts_with("containerfile.")
    {
        return Kind::Dockerfile;
    }
    if base == "docker-compose.yml"
        || base == "docker-compose.yaml"
        || base == "compose.yml"
        || base == "compose.yaml"
        || base.ends_with(".compose.yaml")
        || base.ends_with(".compose.yml")
    {
        return Kind::Compose;
    }
    if (base.ends_with(".yaml") || base.ends_with(".yml"))
        && (rel.contains("k8s/") || rel.contains("kubernetes/") || rel.contains("manifests/"))
    {
        return Kind::Kubernetes;
    }
    Kind::None
}

/// Does an image ref carry a real tag? Tags live in the last path
/// segment so registry ports ("host:5000/img") do not count.
fn image_tag(img: &str) -> Option<&str> {
    let core = img.split('@').next().unwrap_or(img);
    let last = core.rsplit('/').next().unwrap_or(core);
    last.split_once(':').map(|(_, t)| t)
}

/// Secret-looking variable names: a literal value assigned to these is
/// almost always a leaked credential.
fn secretish(name: &str) -> bool {
    let n = name.to_uppercase();
    for m in [
        "PASSWORD",
        "PASSWD",
        "SECRET",
        "TOKEN",
        "APIKEY",
        "API_KEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "AUTH",
        "CREDENTIAL",
        "PASS",
    ] {
        if n.contains(m) {
            // exempt obvious non-secrets
            if n.contains("AUTH_METHOD") || n.contains("TOKENIZ") || n.contains("PASSPHRASE_FILE") {
                return false;
            }
            return true;
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn mk(
    id: &str,
    sev: Severity,
    rel: &str,
    target: &str,
    msg: impl Into<String>,
    fix: &str,
    reference: &str,
    disabled: &HashSet<String>,
) -> Option<Finding> {
    if disabled.contains(id) {
        return None;
    }
    Some(Finding {
        ruleset: "container-audit".into(),
        rule_id: id.into(),
        severity: sev,
        target: target.into(),
        path: rel.into(),
        line: None,
        excerpt: None,
        message: msg.into(),
        remediation: Some(fix.into()),
        reference: Some(reference.into()),
        window: None,
    })
}

pub fn audit(rel: &str, text: &str, target: &str, disabled: &HashSet<String>) -> Vec<Finding> {
    match kind_of(rel) {
        Kind::Dockerfile => dockerfile(rel, text, target, disabled),
        Kind::Compose => compose(rel, text, target, disabled),
        Kind::Kubernetes => kubernetes(rel, text, target, disabled),
        Kind::None => Vec::new(),
    }
}

// ---------- Dockerfile ----------

fn dockerfile(rel: &str, text: &str, target: &str, disabled: &HashSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut has_user = false;
    let mut from_lines = 0usize;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let upper = line.to_uppercase();
        if upper.starts_with("USER ") || upper.starts_with("USER\t") {
            has_user = true;
        }
        if upper.starts_with("FROM ") {
            from_lines += 1;
            let img = line[5..].split_whitespace().next().unwrap_or("");
            let tag = image_tag(img);
            // "FROM x AS build" names are stage aliases, not images
            if !img.eq_ignore_ascii_case("scratch")
                && (tag.is_none() || tag == Some("latest"))
                && !line.to_uppercase().contains(" AS ")
            {
                if let Some(f) = mk(
                    "CNT-004",
                    Severity::Medium,
                    rel,
                    target,
                    format!("unpinned base image {img} (mutable tag)"),
                    "Pin to a digest (FROM img@sha256:...) or at least a version tag.",
                    OWASP_DOCKER,
                    disabled,
                ) {
                    out.push(f);
                }
            }
        }
        if upper.starts_with("ADD ") && (line.contains("http://") || line.contains("https://")) {
            if let Some(f) = mk(
                "CNT-003",
                Severity::Medium,
                rel,
                target,
                "ADD fetches a remote URL without integrity verification",
                "Use COPY for local files; fetch artifacts with curl + checksum instead.",
                OWASP_DOCKER,
                disabled,
            ) {
                out.push(f);
            }
        }
        if (upper.starts_with("RUN ")
            || upper.starts_with("CMD ")
            || upper.starts_with("ENTRYPOINT"))
            && (line.contains("curl") || line.contains("wget"))
            && (line.contains("| sh")
                || line.contains("|sh")
                || line.contains("| bash")
                || line.contains("|bash"))
        {
            if let Some(f) = mk(
                "CNT-002",
                Severity::High,
                rel,
                target,
                "pipe-to-shell install (curl|sh) executes unverified remote code at build time",
                "Download the artifact, verify a checksum/signature, then run it.",
                OWASP_DOCKER,
                disabled,
            ) {
                out.push(f);
            }
        }
        for instr in ["ENV ", "ARG "] {
            if upper.starts_with(instr) {
                let rest = line[instr.len()..].trim();
                for kv in rest.split_whitespace().take(2) {
                    let (k, v) = match kv.split_once('=') {
                        Some(x) => x,
                        None => (kv, ""),
                    };
                    if secretish(k) && !v.is_empty() && !v.starts_with('$') && !v.starts_with("${")
                    {
                        if let Some(f) = mk(
                            "CNT-005",
                            Severity::Critical,
                            rel,
                            target,
                            format!("{instr}assigns a literal value to {k} - secrets bake into image layers and history"),
                            "Pass secrets at runtime (docker -e, secrets manager) or use --secret mounts for build-time needs.",
                            OWASP_DOCKER,
                            disabled,
                        ) {
                            out.push(f);
                        }
                    }
                }
            }
        }
        if upper.starts_with("COPY ") {
            let low = line.to_lowercase();
            for bad in [
                ".env",
                "id_rsa",
                ".ssh",
                ".aws",
                ".npmrc",
                ".netrc",
                "kubeconfig",
            ] {
                if low.contains(bad) {
                    if let Some(f) = mk(
                        "CNT-009",
                        Severity::High,
                        rel,
                        target,
                        format!("COPY pulls sensitive path into the image ({bad})"),
                        "Exclude with .dockerignore; inject credentials at runtime.",
                        OWASP_DOCKER,
                        disabled,
                    ) {
                        out.push(f);
                    }
                }
            }
        }
        if upper.contains("CHMOD 777") || upper.contains("CHMOD -R 777") {
            if let Some(f) = mk(
                "CNT-006",
                Severity::Low,
                rel,
                target,
                "chmod 777 makes files world-writable inside the image",
                "Set the narrowest ownership/permission needed.",
                OWASP_DOCKER,
                disabled,
            ) {
                out.push(f);
            }
        }
        if upper.starts_with("EXPOSE 22") {
            if let Some(f) = mk(
                "CNT-010",
                Severity::Medium,
                rel,
                target,
                "image exposes ssh (port 22) - in-container sshd is a common malware/backdoor pattern",
                "Prefer docker exec / orchestrator shells over sshd in images.",
                OWASP_DOCKER,
                disabled,
            ) {
                out.push(f);
            }
        }
    }
    if from_lines > 0 && !has_user {
        if let Some(f) = mk(
            "CNT-001",
            Severity::High,
            rel,
            target,
            "no USER instruction: container process runs as root (OWASP rule #2)",
            "Create an unprivileged user and add USER before the entrypoint.",
            OWASP_DOCKER,
            disabled,
        ) {
            out.push(f);
        }
    }
    out
}

// ---------- docker-compose ----------

fn service_env_secret(
    name: &str,
    val: &str,
    rel: &str,
    target: &str,
    out: &mut Vec<Finding>,
    disabled: &HashSet<String>,
) {
    if secretish(name) && !val.is_empty() && !val.starts_with('$') && !val.starts_with("${") {
        if let Some(f) = mk(
            "CNT-105",
            Severity::High,
            rel,
            target,
            format!("environment assigns a literal secret to {name}"),
            "Use env_file, secrets:, or runtime injection instead of literals in compose.",
            OWASP_DOCKER,
            disabled,
        ) {
            out.push(f);
        }
    }
}

fn compose(rel: &str, text: &str, target: &str, disabled: &HashSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let docs = match yaml_rust2::YamlLoader::load_from_str(text) {
        Ok(d) => d,
        Err(_) => return out,
    };
    for doc in &docs {
        let services = &doc["services"];
        let Some(map) = services.as_hash() else {
            continue;
        };
        for (name, svc) in map {
            let svc_name = name.as_str().unwrap_or("?");
            if svc["privileged"].as_bool() == Some(true) {
                if let Some(f) = mk("CNT-101", Severity::High, rel, target,
                    format!("service {svc_name} runs privileged (OWASP rule #3: full host capabilities)"),
                    "Drop privileged; grant only the capabilities the service needs.",
                    OWASP_DOCKER, disabled) { out.push(f); }
            }
            for ns in ["network_mode", "pid", "ipc", "uts"] {
                if svc[ns].as_str() == Some("host") || svc[ns].as_str() == Some("host:") {
                    if let Some(f) = mk(
                        "CNT-103",
                        Severity::Medium,
                        rel,
                        target,
                        format!("service {svc_name} shares the host {ns} namespace"),
                        "Host namespaces break container isolation; avoid unless required.",
                        OWASP_DOCKER,
                        disabled,
                    ) {
                        out.push(f);
                    }
                }
            }
            for vol in svc["volumes"].as_vec().into_iter().flatten() {
                let v = vol.as_str().unwrap_or("");
                if v.contains("/var/run/docker.sock") {
                    if let Some(f) = mk("CNT-102", Severity::High, rel, target,
                        format!("service {svc_name} mounts the docker socket (container escape to full host control)"),
                        "Avoid the docker socket; use a proxy (socket-proxy) with restricted API if needed.",
                        OWASP_DOCKER, disabled) { out.push(f); }
                }
                if v == "/:/host" || v.starts_with("/:/") || v == "/:/host:ro" {
                    if let Some(f) = mk(
                        "CNT-102",
                        Severity::High,
                        rel,
                        target,
                        format!("service {svc_name} mounts the host root filesystem"),
                        "Mount only the specific directories required.",
                        OWASP_DOCKER,
                        disabled,
                    ) {
                        out.push(f);
                    }
                }
            }
            if let Some(img) = svc["image"].as_str() {
                if !img.contains('@') && (image_tag(img).is_none() || img.ends_with(":latest")) {
                    if let Some(f) = mk(
                        "CNT-104",
                        Severity::Medium,
                        rel,
                        target,
                        format!("service {svc_name} uses mutable image tag {img}"),
                        "Pin image versions or digests for reproducible deploys.",
                        OWASP_DOCKER,
                        disabled,
                    ) {
                        out.push(f);
                    }
                }
            }
            for kv in svc["environment"].as_hash().into_iter().flatten() {
                if let (Some(k), Some(v)) = (kv.0.as_str(), kv.1.as_str()) {
                    service_env_secret(k, v, rel, target, &mut out, disabled);
                }
            }
            for e in svc["environment"].as_vec().into_iter().flatten() {
                if let Some(s) = e.as_str() {
                    if let Some((k, v)) = s.split_once('=') {
                        service_env_secret(k, v, rel, target, &mut out, disabled);
                    }
                }
            }
            for cap in svc["cap_add"].as_vec().into_iter().flatten() {
                if let Some(c) = cap.as_str() {
                    if matches!(
                        c,
                        "SYS_ADMIN" | "ALL" | "NET_ADMIN" | "SYS_MODULE" | "SYS_PTRACE"
                    ) {
                        if let Some(f) = mk(
                            "CNT-106",
                            Severity::High,
                            rel,
                            target,
                            format!("service {svc_name} adds dangerous capability {c}"),
                            "Grant the minimum capability set; SYS_ADMIN/ALL is near-privileged.",
                            OWASP_DOCKER,
                            disabled,
                        ) {
                            out.push(f);
                        }
                    }
                }
            }
            for so in svc["security_opt"].as_vec().into_iter().flatten() {
                if let Some(s) = so.as_str() {
                    if s.contains("unconfined")
                        || s.contains("seccomp=unconfined")
                        || s == "apparmor=unconfined"
                    {
                        if let Some(f) = mk("CNT-106", Severity::High, rel, target,
                            format!("service {svc_name} disables syscall confinement ({s})"),
                            "Keep default seccomp/apparmor profiles; drop them only for a proven need.",
                            OWASP_DOCKER, disabled) { out.push(f); }
                    }
                }
            }
            for p in svc["ports"].as_vec().into_iter().flatten() {
                if let Some(s) = p.as_str() {
                    if s.contains("2375") {
                        if let Some(f) = mk("CNT-107", Severity::High, rel, target,
                            format!("service {svc_name} publishes unencrypted docker API port {s}"),
                            "The docker API must be TLS-protected (2376) or unix-socket only; 2375 is remote root.",
                            OWASP_DOCKER, disabled) { out.push(f); }
                    }
                }
            }
        }
    }
    out
}

// ---------- kubernetes ----------

fn kubernetes(rel: &str, text: &str, target: &str, disabled: &HashSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let docs = match yaml_rust2::YamlLoader::load_from_str(text) {
        Ok(d) => d,
        Err(_) => return out,
    };
    for doc in &docs {
        let kind = doc["kind"].as_str().unwrap_or("");
        if !matches!(
            kind,
            "Pod" | "Deployment" | "DaemonSet" | "StatefulSet" | "Job" | "CronJob" | "ReplicaSet"
        ) {
            continue;
        }
        let name = doc["metadata"]["name"].as_str().unwrap_or("?");
        // walk every container-like node
        fn containers<'a>(y: &'a Yaml, acc: &mut Vec<&'a Yaml>) {
            match y {
                Yaml::Hash(h) => {
                    for (k, v) in h {
                        if k.as_str() == Some("containers") || k.as_str() == Some("initContainers")
                        {
                            if let Some(arr) = v.as_vec() {
                                acc.extend(arr.iter());
                            }
                        } else {
                            containers(v, acc);
                        }
                    }
                }
                Yaml::Array(a) => a.iter().for_each(|x| containers(x, acc)),
                _ => {}
            }
        }
        let mut cs = Vec::new();
        containers(doc, &mut cs);
        for c in cs {
            let cname = c["name"].as_str().unwrap_or(name);
            let sc = &c["securityContext"];
            if sc["privileged"].as_bool() == Some(true) {
                if let Some(f) = mk(
                    "CNT-201",
                    Severity::High,
                    rel,
                    target,
                    format!("container {cname} in {kind}/{name} is privileged"),
                    "Drop privileged; grant specific capabilities instead.",
                    OWASP_K8S,
                    disabled,
                ) {
                    out.push(f);
                }
            }
            if sc["allowPrivilegeEscalation"].as_bool() == Some(true) {
                if let Some(f) = mk("CNT-207", Severity::Medium, rel, target,
                    format!("container {cname} allows privilege escalation"),
                    "Set allowPrivilegeEscalation: false and drop ALL capabilities then add back what is needed.",
                    OWASP_K8S, disabled) { out.push(f); }
            }
            if sc["runAsUser"].as_i64() == Some(0) {
                if let Some(f) = mk(
                    "CNT-202",
                    Severity::Medium,
                    rel,
                    target,
                    format!("container {cname} runs as uid 0"),
                    "Set runAsNonRoot: true and a non-zero runAsUser.",
                    OWASP_K8S,
                    disabled,
                ) {
                    out.push(f);
                }
            }
            if let Some(img) = c["image"].as_str() {
                if !img.contains('@') && (image_tag(img).is_none() || img.ends_with(":latest")) {
                    if let Some(f) = mk(
                        "CNT-205",
                        Severity::Medium,
                        rel,
                        target,
                        format!("container {cname} uses mutable image tag {img}"),
                        "Pin image digests; consider an admission policy requiring them.",
                        OWASP_K8S,
                        disabled,
                    ) {
                        out.push(f);
                    }
                }
            }
            for kv in c["env"].as_vec().into_iter().flatten() {
                let n = kv["name"].as_str().unwrap_or("");
                let v = kv["value"].as_str().unwrap_or("");
                if secretish(n) && !v.is_empty() {
                    if let Some(f) = mk(
                        "CNT-206",
                        Severity::High,
                        rel,
                        target,
                        format!("container {cname} inlines a literal secret in env {n}"),
                        "Use a Secret + valueFrom.secretKeyRef (or an external-secrets operator).",
                        OWASP_K8S,
                        disabled,
                    ) {
                        out.push(f);
                    }
                }
            }
            for vm in c["volumeMounts"].as_vec().into_iter().flatten() {
                let p = vm["mountPath"].as_str().unwrap_or("");
                if p == "/var/run/docker.sock" {
                    if let Some(f) = mk(
                        "CNT-204",
                        Severity::High,
                        rel,
                        target,
                        format!("container {cname} mounts the docker socket"),
                        "Containerd/k8s clusters should never expose the runtime socket to pods.",
                        OWASP_K8S,
                        disabled,
                    ) {
                        out.push(f);
                    }
                }
            }
        }
        let spec = &doc["spec"]["template"]["spec"];
        let host_spec = if spec.is_null() { &doc["spec"] } else { spec };
        for ns in ["hostNetwork", "hostPID", "hostIPC"] {
            if host_spec[ns].as_bool() == Some(true) {
                if let Some(f) = mk(
                    "CNT-203",
                    Severity::Medium,
                    rel,
                    target,
                    format!("{kind}/{name} sets {ns}: true"),
                    "Host namespaces break pod isolation; avoid unless strictly required.",
                    OWASP_K8S,
                    disabled,
                ) {
                    out.push(f);
                }
            }
        }
        for v in host_spec["volumes"].as_vec().into_iter().flatten() {
            if let Some(p) = v["hostPath"]["path"].as_str() {
                if matches!(p, "/" | "/etc" | "/root" | "/var/run" | "/var/lib/kubelet")
                    || p.contains("docker.sock")
                {
                    if let Some(f) = mk(
                        "CNT-204",
                        Severity::High,
                        rel,
                        target,
                        format!("{kind}/{name} mounts sensitive host path {p}"),
                        "Restrict hostPath mounts; prefer projected/configMap/secret volumes.",
                        OWASP_K8S,
                        disabled,
                    ) {
                        out.push(f);
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dis() -> HashSet<String> {
        HashSet::new()
    }

    #[test]
    fn kind_detection() {
        assert!(matches!(kind_of("a/Dockerfile"), Kind::Dockerfile));
        assert!(matches!(kind_of("Dockerfile.prod"), Kind::Dockerfile));
        assert!(matches!(kind_of("docker-compose.yml"), Kind::Compose));
        assert!(matches!(kind_of("k8s/deploy.yaml"), Kind::Kubernetes));
        assert!(matches!(kind_of("src/main.rs"), Kind::None));
    }

    #[test]
    fn dockerfile_root_and_secrets() {
        let df = "FROM ubuntu\nRUN curl x | sh\nENV API_KEY=abc\n";
        let fs = audit("Dockerfile", df, "t", &dis());
        let ids: Vec<_> = fs.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"CNT-001"), "no USER: {ids:?}");
        assert!(ids.contains(&"CNT-002"), "pipe-to-shell: {ids:?}");
        assert!(ids.contains(&"CNT-004"), "untagged FROM: {ids:?}");
        assert!(ids.contains(&"CNT-005"), "env secret: {ids:?}");
    }

    #[test]
    fn dockerfile_clean() {
        let df = "FROM ubuntu:24.04@sha256:abc\nUSER app\n";
        let fs = audit("Dockerfile", df, "t", &dis());
        assert!(
            fs.is_empty(),
            "unexpected: {:?}",
            fs.iter().map(|f| f.rule_id.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn compose_flags() {
        let y = "services:\n  x:\n    image: n:latest\n    privileged: true\n    volumes: [/var/run/docker.sock:/sock]\n";
        let fs = audit("compose.yml", y, "t", &dis());
        let ids: Vec<_> = fs.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"CNT-101"));
        assert!(ids.contains(&"CNT-102"));
        assert!(ids.contains(&"CNT-104"));
    }

    #[test]
    fn k8s_flags() {
        let y = "kind: Deployment\nmetadata:\n  name: a\nspec:\n  template:\n    spec:\n      hostNetwork: true\n      containers:\n        - name: c\n          image: i:1\n          securityContext:\n            privileged: true\n          env:\n            - name: TOKEN\n              value: x\n";
        let fs = audit("k8s/d.yaml", y, "t", &dis());
        let ids: Vec<_> = fs.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"CNT-201"), "{ids:?}");
        assert!(ids.contains(&"CNT-203"), "{ids:?}");
        assert!(ids.contains(&"CNT-206"), "{ids:?}");
    }

    #[test]
    fn registry_port_is_not_a_tag() {
        assert_eq!(image_tag("reg:5000/img"), None);
        assert_eq!(image_tag("reg:5000/img:1.2"), Some("1.2"));
        assert_eq!(image_tag("img@sha256:abc"), None);
    }
}
