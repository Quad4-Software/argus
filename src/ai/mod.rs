//! AI-provenance analysis: evidence-based, not accusatory.
//!
//! Signal tiers:
//!   HIGH   - known agent attribution: Co-Authored-By/Generated-by trailers,
//!            bot commit authors, assistant watermarks
//!   MED    - behavioral: commit bursts at superhuman cadence, huge LoC/commit
//!   LOW    - stylistic: em-dash density in prose, AI-cliche phrasing in docs
//!            and code comments
//!
//! Output is an evidence list + weighted score. A single low-tier signal never
//! reaches "likely" - the verdict requires clustering.

mod signals;
use serde::Serialize;
use signals::*;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
#[derive(Debug, Serialize)]
pub struct AiEvidence {
    pub kind: &'static str,
    pub tier: &'static str, // high | medium | low
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct AiReport {
    pub repo: String,
    pub commits_sampled: usize,
    pub evidence: Vec<AiEvidence>,
    /// mitigating signals: patterns consistent with human agency
    pub human_signals: Vec<String>,
    pub score: u32,
    pub verdict: String,
}

/// Known AI tooling markers in commit metadata/bodies.
const AGENT_MARKERS: &[&str] = &[
    "claude",
    "copilot",
    "aider",
    "codeium",
    "devin",
    "openhands",
    "cursoragent",
    "gpt-engineer",
    "devlo",
    "amazon-q",
    "coderabbit",
    "github-copilot",
    "chatgpt",
    "opencode",
    "gemini-code-assist",
    "tabnine",
    "windsurf",
    "greptile",
];

/// Markers that also occur as ordinary human names or project words.
/// They only count when the same line carries explicit AI context or a
/// bot/noreply convention, so "written by Cody" (a person) is not flagged.
const AMBIG_MARKERS: &[&str] = &["cody", "cursor", "sweep", "codex", "gemini"];

/// Agent workflow artifacts: committed config/instruction files for AI tools.
/// Presence means the project deliberately uses agent tooling (medium signal).
const AGENT_CONFIG_PATHS: &[&str] = &[
    "claude.md",
    "agents.md",
    "warp.md",
    "cursorrules",
    ".cursorrules",
    ".cursor/rules",
    ".cursorignore",
    ".windsurf/",
    ".windsurfrules",
    ".aider.conf",
    ".aiderignore",
    ".continue/",
    ".codeium/",
    ".github/copilot-instructions.md",
    ".github/instructions/",
    ".claude/",
    ".codex/",
    ".opencode/",
    "devin.json",
    ".devin/",
    "claude_code_instructions.md",
    ".gemini/",
    ".aider/",
];

/// AI agent GitHub integrations in workflows.
const AGENT_CI_MARKERS: &[&str] = &[
    "claude-code-action",
    "coderabbit",
    "aider-action",
    "openhands-action",
    "copilot-workspace",
    "sweep-ai",
    "devin-action",
    "opencode-action",
    "gemini-code-assist",
    "cody-action",
    "codeium",
];

/// AI-flavored phrasing common in generated prose (weak signal each).
const CLICHES: &[&str] = &[
    "it's important to note",
    "it is important to note",
    "in conclusion",
    "seamlessly",
    "seamless integration",
    "leverage the",
    "meticulous",
    "comprehensive solution",
    "delve into",
    "dive into",
    "elevate",
    "cutting-edge",
    "state-of-the-art",
    "robust solution",
    "in the realm of",
    "this commit introduces",
    "this change implements",
    "i hope this helps",
    "certainly!",
    "here's a summary",
    "note: in a real-world",
    "in production, you would",
    "for brevity,",
    "as an ai",
];

/// Full provenance analysis of one repo.
pub fn analyze(root: &Path) -> AiReport {
    let mut ev: Vec<AiEvidence> = Vec::new();
    let commits = commit_meta(root, 400);
    let n = commits.len();

    // ---- HIGH: agent attribution ----
    let mut bots: HashMap<String, usize> = HashMap::new();
    let mut subjects: Vec<&str> = Vec::with_capacity(commits.len());
    let mut verbose_bodies = 0usize;
    for (name, email, _ts, committer, body) in &commits {
        subjects.push(body.lines().next().unwrap_or(""));
        let bullet_lines = body
            .lines()
            .filter(|l| {
                let t = l.trim();
                t.starts_with('-') || t.starts_with('*')
            })
            .count();
        if bullet_lines >= 3 {
            verbose_bodies += 1;
        }
        for who in [name, committer] {
            let nl = who.to_lowercase();
            let el = email.to_lowercase();
            for m in AGENT_MARKERS {
                if nl.contains(&format!("{m}[")) || (el.contains(m) && el.contains("bot")) {
                    *bots.entry(who.clone()).or_default() += 1;
                }
            }
            // ambiguous names need the explicit [bot convention
            for m in AMBIG_MARKERS {
                if nl.contains(&format!("{m}[bot")) || (el.contains(m) && el.contains("bot")) {
                    *bots.entry(who.clone()).or_default() += 1;
                }
            }
        }
        if let Some(line) = body_agent_hit(body) {
            ev.push(AiEvidence {
                kind: "agent trailer",
                tier: "high",
                detail: format!("commit: {line}"),
            });
        }
        if body.to_lowercase().contains("🤖") {
            ev.push(AiEvidence {
                kind: "agent trailer",
                tier: "high",
                detail: "commit contains 🤖 agent emoji".into(),
            });
        }
    }
    for (b, c) in &bots {
        ev.push(AiEvidence {
            kind: "agent author",
            tier: "high",
            detail: format!("{b}: {c} commit(s) authored by agent account"),
        });
    }

    // message uniformity: >85% of subjects share one template
    if n >= 30 {
        let conv = subjects
            .iter()
            .filter(|s| {
                let bytes = s.as_bytes();
                bytes.first().is_some_and(|b| b.is_ascii_lowercase())
                    && s.contains(':')
                    && s.chars()
                        .nth(s.find(':').unwrap_or(0).saturating_sub(1))
                        .is_some_and(|c| c == ')' || c.is_ascii_alphanumeric())
            })
            .count();
        let emoji_first = subjects
            .iter()
            .filter(|s| !s.chars().next().unwrap_or('a').is_ascii())
            .count();
        let same = conv.max(emoji_first);
        if same * 100 >= n * 85 {
            ev.push(AiEvidence {
                kind: "uniform commit style",
                tier: "low",
                detail: format!("{same}/{n} subjects share one message template"),
            });
        }
        // verbose structured bodies in most commits
        if verbose_bodies * 2 >= n {
            ev.push(AiEvidence {
                kind: "verbose uniform bodies",
                tier: "low",
                detail: format!("{verbose_bodies}/{n} commits have structured multi-bullet bodies"),
            });
        }
        // essay-length bodies: generated commit messages run paragraphs,
        // humans mostly write a line or two
        let mut words: Vec<u64> = commits
            .iter()
            .map(|c| c.4.split_whitespace().count() as u64)
            .collect();
        let mw = median(&mut words);
        if mw >= 120 {
            ev.push(AiEvidence {
                kind: "essay-length messages",
                tier: "medium",
                detail: format!("median commit body is {mw} words"),
            });
        }
    }

    // ---- MEDIUM: velocity ----
    if n >= 20 {
        let mut ts: Vec<i64> = commits.iter().map(|c| c.2).collect();
        ts.sort();
        // max commits in any 24h window
        let mut max_day = 0usize;
        for i in 0..ts.len() {
            let day_end = ts[i] + 86400;
            let cnt = ts[i..].iter().take_while(|t| **t <= day_end).count();
            max_day = max_day.max(cnt);
        }
        if max_day >= 60 {
            ev.push(AiEvidence {
                kind: "commit burst",
                tier: "medium",
                detail: format!("{max_day} commits inside one 24h window"),
            });
        }
        // median gap between consecutive commits
        let mut gaps: Vec<u64> = ts
            .windows(2)
            .map(|w| (w[1] - w[0]).unsigned_abs())
            .collect();
        let mg = median(&mut gaps);
        if mg < 90 && n >= 50 {
            ev.push(AiEvidence {
                kind: "superhuman cadence",
                tier: "medium",
                detail: format!("median inter-commit gap {mg}s across {n} commits"),
            });
        }
        let mut locs = loc_per_commit(root, 200);
        let ml = median(&mut locs);
        if ml >= 2500 {
            ev.push(AiEvidence {
                kind: "loc-per-commit",
                tier: "medium",
                detail: format!("median {ml} changed lines per commit"),
            });
        }
        // compressed history: a mature project's worth of commits in ~2 weeks
        if n >= 150 {
            if let (Some(&newest), Some(&oldest)) = (ts.last(), ts.first()) {
                let span_days = (newest - oldest).max(1) / 86400;
                if span_days <= 14 {
                    ev.push(AiEvidence {
                        kind: "compressed history",
                        tier: "medium",
                        detail: format!("{n} commits compressed into {span_days} day(s)"),
                    });
                }
            }
        }
        // big-bang first commit: an entire project appearing at once
        let files0 = git_out(
            root,
            &[
                "show",
                "--format=",
                "--name-only",
                "--max-parents=0",
                "HEAD",
            ],
        );
        let fc = files0.lines().filter(|l| !l.is_empty()).count();
        if fc >= 120 {
            ev.push(AiEvidence {
                kind: "big-bang initial commit",
                tier: "low",
                detail: format!("{fc} files in the root commit: one-shot generated project shape"),
            });
        }
        // volume needs a real history window; shallow samples produce a
        // fake "1 day" span that makes every repo look superhuman
        if n >= 50 {
            if let (Some(&newest), Some(&oldest)) = (ts.last(), ts.first()) {
                let span = ((newest - oldest) / 86400).max(1) as u64;
                if let Some(e) = superhuman_volume(root, span) {
                    ev.push(e);
                }
            }
        }
    }

    // ---- MEDIUM: declared agent tooling ----
    ev.extend(agent_config_files(root));
    ev.extend(agent_ci(root));

    // ---- history integrity ----
    ev.extend(history_integrity(root));

    // ---- LOW: prose + comments ----
    if let Some(e) = narrated_comments(root) {
        ev.push(e);
    }
    let prose = prose_tells(root, 50);
    let comments = code_comment_tells(root, 50);
    // pervasive stylometric consistency across many files is stronger than
    // any one file: a single author's prose varies; generated text does not
    if prose.len() + comments.len() >= 10 {
        ev.push(AiEvidence {
            kind: "pervasive uniform style",
            tier: "medium",
            detail: format!(
                "{} files share the same em-dash/cliche-heavy style",
                prose.len() + comments.len()
            ),
        });
    }
    ev.extend(prose);
    ev.extend(comments);

    // ---- substitution-pattern detectors ----
    if let Some(e) = self_review_loop(&commits) {
        ev.push(e);
    }
    if let Some(e) = ghost_contributors(&commits) {
        ev.push(e);
    }
    if let Some(e) = anti_disclosure_policy(root) {
        ev.push(e);
    }

    // ---- human-agency counter-evidence ----
    let mut human_signals: Vec<String> = Vec::new();
    if n >= 10 {
        let reverts = commits
            .iter()
            .filter(|c| {
                let s = c.4.lines().next().unwrap_or("").to_lowercase();
                s.starts_with("revert")
            })
            .count();
        if reverts >= 2 {
            human_signals.push(format!(
                "{reverts} revert commits (contested decisions on record)"
            ));
        }
        let oops = commits
            .iter()
            .filter(|c| {
                let s = c.4.lines().next().unwrap_or("").to_lowercase();
                s.starts_with("oops")
                    || s.starts_with("fix my")
                    || s.contains("typo")
                    || s.starts_with("whoops")
            })
            .count();
        if oops >= 2 {
            human_signals.push(format!(
                "{oops} mistake-acknowledging commits (human fallibility)"
            ));
        }
        let fixups = commits
            .iter()
            .filter(|c| {
                let s = c.4.lines().next().unwrap_or("").to_lowercase();
                s.starts_with("fixup") || s.starts_with("squash")
            })
            .count();
        if fixups >= 3 {
            human_signals.push(format!(
                "{fixups} fixup/squash commits (iterative human workflow)"
            ));
        }
    }

    // ---- score ----
    let mut strong_score = 0u32;
    let mut low_score = 0u32;
    for e in &ev {
        match e.tier {
            "high" => strong_score += 40,
            "medium" => strong_score += 15,
            _ => low_score += 4,
        }
    }
    // stylistic tells alone can never exceed the "some indicators" band
    let score = (strong_score + low_score.min(30)).min(100);
    let strong = ev.iter().any(|e| e.tier != "low");
    let has_high = ev.iter().any(|e| e.tier == "high");
    let verdict = if has_high || (score >= 60 && strong) {
        // an agent trailer/bot author is definitive attribution
        "likely AI-assisted".to_string()
    } else if score >= 25 {
        "some AI indicators".to_string()
    } else {
        "no strong AI indicators".to_string()
    };
    AiReport {
        repo: root.display().to_string(),
        commits_sampled: n,
        evidence: ev,
        human_signals,
        score,
        verdict,
    }
}
