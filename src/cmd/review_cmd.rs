//! `argus review` - interactive finding triage. Walks each finding and
//! accepts single-keystroke commands on stdin:
//!   enter/space = skip   s = suppress (append to .argusignore)
//!   d = detail           q = quit

use crate::cli::Cli;
use crate::finding::Finding;

pub(crate) fn review_cmd(cli: &Cli, findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "no findings to review\n".into();
    }
    let stdin = std::io::stdin();
    let mut buf = String::new();
    let mut suppressed = 0;
    let mut quit = false;
    use std::io::BufRead;
    let mut lines = stdin.lock();
    for (i, f) in findings.iter().enumerate() {
        if quit {
            break;
        }
        eprint!(
            "[{}/{}] {} {} {}:{}\n  {}\n(enter=skip s=suppress d=detail q=quit) > ",
            i + 1,
            findings.len(),
            f.severity.label().trim(),
            f.rule_id,
            f.path,
            f.line.map(|l| l.to_string()).unwrap_or_default(),
            f.message
        );
        buf.clear();
        if lines.read_line(&mut buf).unwrap_or(0) == 0 {
            break; // eof
        }
        let cmd = buf.trim();
        match cmd {
            "q" | "quit" => quit = true,
            "s" | "suppress" => {
                let line = format!("{} {}\n", f.rule_id, f.path);
                let path = std::path::Path::new(".argusignore");
                use std::io::Write;
                if let Ok(mut fh) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    let _ = fh.write_all(line.as_bytes());
                    suppressed += 1;
                    eprintln!("  suppressed via .argusignore");
                }
            }
            "d" | "detail" => {
                eprintln!(
                    "  ruleset: {}\n  excerpt: {}\n  remediation: {}\n  reference: {}\n",
                    f.ruleset,
                    f.excerpt.as_deref().unwrap_or(""),
                    f.remediation.as_deref().unwrap_or(""),
                    f.reference.as_deref().unwrap_or(""),
                );
            }
            _ => {}
        }
    }
    let _ = cli;
    format!("{suppressed} finding(s) suppressed\n")
}
