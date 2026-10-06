// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

use super::*;
pub(crate) fn git_out(root: &Path, args: &[&str]) -> String {
    Command::new("git")
        .args(["-C", &root.to_string_lossy()])
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Sample commit metadata: "name|email|unix_ts|body" per commit, NUL-split.
/// (author, author-email, timestamp, committer, body)
pub(crate) fn commit_meta(root: &Path, n: usize) -> Vec<(String, String, i64, String, String)> {
    let raw = git_out(
        root,
        &[
            "log",
            &format!("-n{n}"),
            "--format=%an%x00%ae%x00%ct%x00%cn%x00%B%x00%x01",
        ],
    );
    raw.split('\x01')
        .filter_map(|rec| {
            let mut f = rec.trim_matches(|c| c == '\0' || c == '\n').split('\x00');
            Some((
                f.next()?.to_string(),
                f.next()?.to_string(),
                f.next()?.parse().ok()?,
                f.next()?.to_string(),
                f.next().unwrap_or("").to_string(),
            ))
        })
        .collect()
}

/// Paths whose line counts say nothing about human output rate:
/// lockfiles, generated code, bundled/minified assets.
pub(crate) fn is_generated_name(path: &str) -> bool {
    let base = path.rsplit('/').next().unwrap_or(path);
    const LOCKFILES: &[&str] = &[
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "cargo.lock",
        "go.sum",
        "gemfile.lock",
        "composer.lock",
        "poetry.lock",
        "flake.lock",
        "pubspec.lock",
    ];
    let b = base.to_lowercase();
    if LOCKFILES.contains(&b.as_str()) {
        return true;
    }
    if b.contains(".min.")
        || b.contains(".bundle.")
        || b.contains(".generated.")
        || b.contains(".gen.")
        || b.ends_with(".pb.go")
        || b.ends_with("_pb2.py")
        || b.ends_with(".designer.cs")
    {
        return true;
    }
    path.split('/').any(|c| {
        matches!(
            c,
            "node_modules"
                | "vendor"
                | "third_party"
                | "external"
                | "generated"
                | "__generated__"
                | "dist"
                | "target"
                | ".venv"
                | "deps"
        )
    })
}

/// Per-commit added+deleted line counts (bounded sample, generated files excluded).
pub(crate) fn loc_per_commit(root: &Path, n: usize) -> Vec<u64> {
    let raw = git_out(root, &["log", &format!("-n{n}"), "--numstat", "--format=x"]);
    let mut per: Vec<u64> = Vec::new();
    let mut cur = 0u64;
    let mut in_c = false;
    for line in raw.lines() {
        if line == "x" {
            if in_c {
                per.push(cur);
            }
            cur = 0;
            in_c = true;
            continue;
        }
        if in_c {
            let mut parts = line.splitn(3, '\t');
            let (adds, path) = (parts.next().unwrap_or("0"), parts.nth(1).unwrap_or(""));
            if !is_generated_name(path)
                && let Ok(v) = adds.parse::<u64>()
            {
                cur += v;
            }
        }
    }
    if in_c {
        per.push(cur);
    }
    per
}

pub(crate) fn is_vendored(f: &Path) -> bool {
    f.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        s == "node_modules" || s == "target" || s == "vendor" || s == ".venv" || s == "dist"
    })
}

pub(crate) fn median(v: &mut [u64]) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v.sort();
    v[v.len() / 2]
}

/// Docs/prose tells in the working tree (bounded).
pub(crate) fn prose_tells(root: &Path, max: usize) -> Vec<AiEvidence> {
    let mut out = Vec::new();
    let files = crate::scan::collect_files(root, false, true);
    for f in files {
        if is_vendored(&f) {
            continue;
        }
        let name = f
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        let is_doc = name.ends_with(".md")
            || name.ends_with(".txt")
            || name.ends_with(".rst")
            || name.starts_with("readme")
            || name.ends_with(".adoc");
        if !is_doc {
            continue;
        }
        let Ok(b) = std::fs::read(&f) else { continue };
        if b.len() > 256 * 1024 {
            continue;
        }
        let text = String::from_utf8_lossy(&b);
        let rel = f
            .strip_prefix(root)
            .unwrap_or(&f)
            .to_string_lossy()
            .replace('\\', "/");
        let dashes = text.matches('\u{2014}').count();
        let words = text.split_whitespace().count().max(1);
        if dashes >= 6 && dashes * 500 > words {
            out.push(AiEvidence {
                kind: "em-dash density",
                tier: "low",
                detail: format!("{rel}: {dashes} em-dashes in {words} words"),
            });
        }
        let lower = text.to_lowercase();
        let hits: Vec<&str> = CLICHES
            .iter()
            .filter(|c| lower.contains(*c))
            .cloned()
            .collect();
        if hits.len() >= 3 {
            out.push(AiEvidence {
                kind: "ai-cliche prose",
                tier: "low",
                detail: format!(
                    "{rel}: {} cliche phrases ({})",
                    hits.len(),
                    hits[..3.min(hits.len())].join(", ")
                ),
            });
        }
        if out.len() >= max {
            break;
        }
    }
    out
}

/// Comment-line tells inside code (//, #, /* markers + cliches + dashes).
pub(crate) fn code_comment_tells(root: &Path, max: usize) -> Vec<AiEvidence> {
    let code_ext = [
        "rs", "py", "js", "ts", "go", "c", "h", "cpp", "java", "rb", "sh",
    ];
    let mut out = Vec::new();
    for f in crate::scan::collect_files(root, false, true) {
        if is_vendored(&f) {
            continue;
        }
        let ext = f
            .extension()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        if !code_ext.contains(&ext.as_str()) {
            continue;
        }
        let Ok(b) = std::fs::read(&f) else { continue };
        if b.len() > 128 * 1024 {
            continue;
        }
        let text = String::from_utf8_lossy(&b);
        let mut dash_comments = 0usize;
        let mut cliche_hits = 0usize;
        for line in text.lines() {
            let t = line.trim();
            let is_comment = t.starts_with("//")
                || t.starts_with('#')
                || t.starts_with('*')
                || t.starts_with("/*");
            if !is_comment {
                continue;
            }
            if t.contains('\u{2014}') {
                dash_comments += 1;
            }
            let l = t.to_lowercase();
            if CLICHES.iter().any(|c| l.contains(c)) {
                cliche_hits += 1;
            }
        }
        let rel = f
            .strip_prefix(root)
            .unwrap_or(&f)
            .to_string_lossy()
            .replace('\\', "/");
        if dash_comments >= 3 {
            out.push(AiEvidence {
                kind: "em-dash comments",
                tier: "low",
                detail: format!("{rel}: {dash_comments} comments use em-dashes"),
            });
        }
        if cliche_hits >= 2 {
            out.push(AiEvidence {
                kind: "ai-cliche comments",
                tier: "low",
                detail: format!("{rel}: {cliche_hits} cliche phrase comments"),
            });
        }
        if out.len() >= max {
            break;
        }
    }
    out
}

/// Committed agent-tooling config/instruction files.
pub(crate) fn agent_config_files(root: &Path) -> Vec<AiEvidence> {
    let mut out: Vec<String> = Vec::new();
    for f in crate::scan::collect_files(root, false, true) {
        if is_vendored(&f) {
            continue;
        }
        let rel = f
            .strip_prefix(root)
            .unwrap_or(&f)
            .to_string_lossy()
            .to_lowercase()
            .replace('\\', "/");
        for marker in AGENT_CONFIG_PATHS {
            let hit = if marker.contains('/') {
                rel.contains(marker)
            } else {
                rel.rsplit('/').next() == Some(marker)
            };
            if hit {
                out.push(rel.clone());
                break;
            }
        }
        if out.len() >= 15 {
            break;
        }
    }
    if out.is_empty() {
        return Vec::new();
    }
    vec![AiEvidence {
        kind: "agent config files",
        tier: "medium",
        detail: format!(
            "{} committed AI-tool config file(s): {}",
            out.len(),
            out.iter().take(4).cloned().collect::<Vec<_>>().join(", ")
        ),
    }]
}

/// Agent integrations inside CI workflows.
pub(crate) fn agent_ci(root: &Path) -> Vec<AiEvidence> {
    let mut out = Vec::new();
    let dirs = [
        ".github/workflows",
        ".forgejo/workflows",
        ".gitea/workflows",
    ];
    for d in dirs {
        let wf = root.join(d);
        let Ok(rd) = std::fs::read_dir(&wf) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(b) = std::fs::read(&p) else { continue };
            let text = String::from_utf8_lossy(&b).to_lowercase();
            let hits: Vec<&str> = AGENT_CI_MARKERS
                .iter()
                .filter(|m| text.contains(*m))
                .cloned()
                .collect();
            if !hits.is_empty() {
                out.push(AiEvidence {
                    kind: "agent CI integration",
                    tier: "medium",
                    detail: format!(
                        "{}: {}",
                        p.file_name().unwrap_or_default().to_string_lossy(),
                        hits.join(", ")
                    ),
                });
            }
        }
    }
    out
}

/// Comments narrating obvious code: 'initialize the counter', 'check if x'.
pub(crate) fn narrated_comments(root: &Path) -> Option<AiEvidence> {
    let re = regex::Regex::new(
        r"(?i)^\s*(?://|#|\*)\s*(initialize|initialise|check|create|define|handle|call|iterate|loop|fetch|retrieve|store|return|set|get|compute|calculate|increment|decrement|open|close|read|write|parse|validate|build|generate|process)\s+(the|a|an|to|whether|if)\b",
    )
    .ok()?;
    let code_ext = [
        "rs", "py", "js", "ts", "go", "c", "h", "cpp", "java", "rb", "sh",
    ];
    let mut files_hit = 0usize;
    let mut total = 0usize;
    for f in crate::scan::collect_files(root, false, true) {
        let ext = f
            .extension()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        if !code_ext.contains(&ext.as_str()) || is_vendored(&f) {
            continue;
        }
        let Ok(b) = std::fs::read(&f) else { continue };
        if b.len() > 128 * 1024 {
            continue;
        }
        let n = String::from_utf8_lossy(&b)
            .lines()
            .filter(|l| re.is_match(l))
            .count();
        if n >= 2 {
            files_hit += 1;
            total += n;
        }
        if files_hit > 30 {
            break;
        }
    }
    if total >= 30 && files_hit >= 5 {
        Some(AiEvidence {
            kind: "narrated-obvious comments",
            tier: "low",
            detail: format!("{total} comments restating the code across {files_hit} files"),
        })
    } else {
        None
    }
}

/// Commit subjects that look like a machine's self-review pass rather than
/// human feedback. Only pass-shaped verbs count (review/polish/align...);
/// targeted-change verbs like fix/update/refactor are conventional-commit
/// staples in every human repo and would false-positive constantly.
pub(crate) fn self_review_loop(
    commits: &[(String, String, i64, String, String)],
) -> Option<AiEvidence> {
    if commits.len() < 20 {
        return None;
    }
    let re = regex::Regex::new(
        "(?i)^(review|polish|align|tighten|reconcile|refine|rework|rephrase|sweep|audit|consolidate|verify|harden|iterate)[^a-z]"
    ).ok()?;
    let mut hits = 0usize;
    for c in commits {
        let subj = c.4.lines().next().unwrap_or("").trim();
        // scoped subjects ("audit(security): x") are targeted human work;
        // machine passes are bare ("Review and polish changes")
        if re.is_match(subj) && !subj.contains('(') {
            hits += 1;
        }
    }
    if hits >= 8 && hits * 5 >= commits.len() * 2 {
        Some(AiEvidence {
            kind: "self-review loop",
            tier: "medium",
            detail: format!(
                "{hits}/{} subjects are unscoped review/polish passes, machine revising its own output",
                commits.len()
            ),
        })
    } else {
        None
    }
}

/// Plurality that looks fabricated: many author names, but most are
/// single-token lowercase handles and the whole history is compressed.
/// Subject-style uniformity is NOT used here because conventional commits
/// make every modern multi-author repo look identical.
pub(crate) fn ghost_contributors(
    commits: &[(String, String, i64, String, String)],
) -> Option<AiEvidence> {
    if commits.len() < 50 {
        return None;
    }
    let mut authors: HashMap<String, usize> = HashMap::new();
    for c in commits {
        *authors.entry(c.0.to_lowercase()).or_default() += 1;
    }
    if authors.len() < 3 {
        return None;
    }
    // handle-shaped names: one token, all lowercase, no digits-only
    let handle_authors = authors
        .keys()
        .filter(|n| !n.contains(' ') && n.chars().all(|c| c.is_ascii_lowercase()) && n.len() >= 2)
        .count();
    if handle_authors * 10 < authors.len() * 6 {
        return None;
    }
    let mut ts: Vec<i64> = commits.iter().map(|c| c.2).collect();
    ts.sort();
    let span_days = (ts.last().unwrap_or(&0) - ts.first().unwrap_or(&0)) / 86400;
    if span_days <= 30 {
        Some(AiEvidence {
            kind: "synthetic-looking contributors",
            tier: "low",
            detail: format!(
                "{handle_authors}/{} author names are bare lowercase handles over a {span_days}-day history",
                authors.len()
            ),
        })
    } else {
        None
    }
}

/// Total output volume vs history span: superhuman sustained rate.
pub(crate) fn superhuman_volume(root: &Path, span_days: u64) -> Option<AiEvidence> {
    if span_days == 0 {
        return None;
    }
    let code_ext = [
        "rs", "py", "js", "ts", "go", "c", "h", "cpp", "java", "rb", "sh", "lua",
    ];
    let mut loc = 0u64;
    for f in crate::scan::collect_files(root, false, true) {
        let ext = f
            .extension()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        if !code_ext.contains(&ext.as_str()) || is_vendored(&f) {
            continue;
        }
        let rel = f
            .strip_prefix(root)
            .unwrap_or(&f)
            .to_string_lossy()
            .replace('\\', "/");
        if is_generated_name(&rel) {
            continue;
        }
        if let Ok(b) = std::fs::read(&f) {
            loc += b.iter().filter(|&&c| c == b'\n').count() as u64;
        }
    }
    let rate = loc / span_days;
    if rate >= 2000 && loc >= 10000 {
        Some(AiEvidence {
            kind: "superhuman volume",
            tier: "medium",
            detail: format!("{loc} LoC over {span_days} day(s) = ~{rate} LoC/day sustained"),
        })
    } else {
        None
    }
}

/// Anti-disclosure policy: contribution docs that pre-empt attribution.
pub(crate) fn anti_disclosure_policy(root: &Path) -> Option<AiEvidence> {
    const PATTERNS: &[&str] = &[
        "your own work",
        "your own creation",
        "you certify you wrote",
        "do not disclose",
        "no attribution",
        "attribution not required",
        "do not credit",
        "claim as your own",
        "generated code is yours",
        "don't mention ai",
        "do not mention",
        "acts as if you wrote it",
    ];
    const DOCS: &[&str] = &[
        "CONTRIBUTING.md",
        "contributing.md",
        "CODE_OF_CONDUCT.md",
        ".github/pull_request_template.md",
        ".github/PULL_REQUEST_TEMPLATE.md",
        "pull_request_template.md",
        ".github/ISSUE_TEMPLATE",
    ];
    // the doc must actually talk about AI/generated output; without that
    // context "must be your own work" is an ANTI-AI provenance policy
    // (the opposite of laundering)
    let ai_ctx =
        regex::Regex::new(r"\b(ai|llm|gpt|chatgpt|copilot|generated|machine[- ]generated|model)\b")
            .ok()?;
    let check = |name: &str, text: String| -> Option<AiEvidence> {
        let t = text.to_lowercase();
        if !ai_ctx.is_match(&t) {
            return None;
        }
        let hits: Vec<&str> = PATTERNS
            .iter()
            .filter(|m| t.contains(*m))
            .cloned()
            .collect();
        if hits.len() >= 2 {
            Some(AiEvidence {
                kind: "anti-disclosure policy",
                tier: "medium",
                detail: format!("{name}: anti-attribution language ({})", hits.join(", ")),
            })
        } else {
            None
        }
    };
    for d in DOCS {
        let p = root.join(d);
        if p.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&p) {
                for e in rd.flatten() {
                    if let Ok(b) = std::fs::read(e.path()) {
                        let name = e
                            .path()
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        if let Some(ev) = check(&name, String::from_utf8_lossy(&b).into_owned()) {
                            return Some(ev);
                        }
                    }
                }
            }
            continue;
        }
        if let Ok(b) = std::fs::read(&p)
            && let Some(ev) = check(d, String::from_utf8_lossy(&b).into_owned())
        {
            return Some(ev);
        }
    }
    None
}

/// Trailer/disclosure lines anywhere in a commit body.
pub(crate) fn body_agent_hit(body: &str) -> Option<String> {
    static NAMES_AI: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let names_ai_re = NAMES_AI
        .get_or_init(|| regex::Regex::new(r"\b(ai|llm|gpt|chatgpt|copilot|agent)\b").unwrap());
    let lower = body.to_lowercase();
    for line in lower.lines() {
        let l = line.trim();
        // trailer-style "x-by: <agent>" and prose disclosures
        let strong = AGENT_MARKERS.iter().any(|m| l.contains(m));
        // ambiguous names need corroborating AI context on the same line
        let weak = !strong
            && AMBIG_MARKERS.iter().any(|m| l.contains(m))
            && (names_ai_re.is_match(l)
                || l.contains("[bot")
                || l.contains("@anthropic")
                || l.contains("@openai")
                || l.contains("@google")
                || l.contains("@cursor")
                || l.contains("anysphere"));
        let trailer = (l.contains("co-authored-by")
            || l.contains("signed-off-by")
            || l.contains("generated")
            || l.contains("assisted")
            || l.contains("written")
            || l.contains("created"))
            && (strong || weak);
        // disclosures must name AI explicitly - "written by foo()" is prose
        let names_ai = names_ai_re.is_match(l);
        let disclosure = l.contains("ai-generated")
            || l.contains("generated using")
            || l.contains("with the help of")
            || ((l.contains("generated by") || l.contains("written by")) && names_ai);
        if trailer || disclosure {
            return Some(line.trim().to_string());
        }
    }
    None
}

/// History-integrity forensics: rewritten/scrubbed history, custom hooks,
/// signature-continuity breaks, notes, shallow-clone caveat.
pub(crate) fn history_integrity(root: &Path) -> Vec<AiEvidence> {
    let mut out = Vec::new();
    let gitdir = root.join(".git");

    // shallow clone limits what forensics can see
    if gitdir.join("shallow").exists() {
        out.push(AiEvidence {
            kind: "truncated history",
            tier: "low",
            detail: "shallow clone: reflog/object forensics limited".into(),
        });
    }

    // reflog residue: amend/rebase/reset/filter operations
    let reflog = git_out(root, &["reflog", "--all", "--format=%gs"]);
    if !reflog.is_empty() {
        let mut rewrites = 0usize;
        for l in reflog.lines() {
            let l = l.to_lowercase();
            if l.contains("rebase")
                || l.contains("amend")
                || l.contains("filter-branch")
                || l.contains("reset:")
                || l.contains("reset --")
            {
                rewrites += 1;
            }
        }
        if rewrites >= 5 {
            out.push(AiEvidence {
                kind: "rewritten history",
                tier: "medium",
                detail: format!("{rewrites} amend/rebase/reset operations in reflog"),
            });
        } else if rewrites > 0 {
            out.push(AiEvidence {
                kind: "rewritten history",
                tier: "low",
                detail: format!("{rewrites} amend/rebase/reset operations in reflog"),
            });
        }
    }

    // unreachable commits: scrubbed work may still exist as objects
    let fsck = git_out(
        root,
        &[
            "fsck",
            "--unreachable",
            "--dangling",
            "--no-reflogs",
            "--no-progress",
        ],
    );
    let mut dangling = 0usize;
    let mut scrubbed_agent = 0usize;
    for line in fsck.lines() {
        if !(line.contains("commit")) {
            continue;
        }
        dangling += 1;
        if let Some(sha) = line.split_whitespace().last() {
            let body = git_out(root, &["show", "-s", "--format=%B", sha]);
            if body_agent_hit(&body).is_some() || body.contains("🤖") {
                scrubbed_agent += 1;
            }
        }
        if dangling > 200 {
            break;
        }
    }
    if scrubbed_agent > 0 {
        out.push(AiEvidence {
            kind: "scrubbed AI commits",
            tier: "high",
            detail: format!(
                "{scrubbed_agent} unreachable commit(s) carry agent attribution: attribution was removed from reachable history"
            ),
        });
    } else if dangling >= 10 {
        out.push(AiEvidence {
            kind: "dangling commits",
            tier: "low",
            detail: format!(
                "{dangling} unreachable commits (rewritten/deleted work objects remain)"
            ),
        });
    }

    // signature continuity: signed earlier, unsigned recent bulk
    let sigs = git_out(root, &["log", "-n100", "--format=%GG"]);
    let mut signed = 0usize;
    let mut unsigned = 0usize;
    for l in sigs.lines() {
        match l.trim() {
            "G" | "U" | "E" => signed += 1,
            "" | "N" => unsigned += 1,
            _ => {}
        }
    }
    // transition: mostly signed earlier but recent 30% unsigned
    if signed > 10 && unsigned > signed / 2 {
        out.push(AiEvidence {
            kind: "signature discontinuity",
            tier: "medium",
            detail: format!(
                "{signed} signed vs {unsigned} unsigned commits: commit attribution regime changed"
            ),
        });
    }

    // custom hooks: message-mutating hooks can rewrite attribution in-flight
    let hooks = gitdir.join("hooks");
    if let Ok(rd) = std::fs::read_dir(&hooks) {
        for e in rd.flatten() {
            let p = e.path();
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            if name.ends_with(".sample") || name == "." || name == ".." {
                continue;
            }
            let body = std::fs::read(&p)
                .map(|b| String::from_utf8_lossy(&b).to_lowercase())
                .unwrap_or_default();
            let mutates = (name.starts_with("commit-msg")
                || name.starts_with("prepare-commit-msg"))
                && (body.contains("sed") || body.contains("rewrite") || body.contains("append"));
            out.push(AiEvidence {
                kind: if mutates {
                    "message-mutating hook"
                } else {
                    "custom git hook"
                },
                tier: if mutates { "medium" } else { "low" },
                detail: format!(
                    ".git/hooks/{name}{}",
                    if mutates {
                        ": modifies commit messages in-flight"
                    } else {
                        ""
                    }
                ),
            });
        }
    }
    // hooksPath redirect hides hooks entirely
    let cfg = std::fs::read_to_string(gitdir.join("config")).unwrap_or_default();
    if cfg.contains("hookspath") {
        out.push(AiEvidence {
            kind: "hooksPath redirect",
            tier: "medium",
            detail: "core.hooksPath redirects hook lookup outside .git/hooks".into(),
        });
    }

    // notes can carry scrubbed attribution
    if !git_out(root, &["notes", "list"]).trim().is_empty() {
        out.push(AiEvidence {
            kind: "git notes present",
            tier: "low",
            detail: "repo has git notes: check for attribution context".into(),
        });
    }
    out
}
