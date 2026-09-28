//! Structural gate: keep command code out of god files.
//! New subcommands go in src/cmd/<domain>.rs, not main.rs.
//! If a module legitimately outgrows a cap, split it - do not bump the
//! number to silence the gate without a note here.

use std::path::PathBuf;

fn lines(p: &str) -> usize {
    std::fs::read_to_string(p).unwrap().lines().count()
}

#[test]
fn main_stays_thin() {
    // main.rs is dispatch + glue only; command bodies live in src/cmd/.
    assert!(
        lines("src/main.rs") <= 700,
        "src/main.rs grew to {} lines - move command logic into src/cmd/",
        lines("src/main.rs")
    );
}

#[test]
fn no_file_over_1000_lines() {
    // Soft ceiling: anything approaching this wants a domain split.
    for e in std::fs::read_dir("src").unwrap().flatten() {
        let p: PathBuf = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("rs") {
            continue;
        }
        let n = lines(&p.to_string_lossy());
        assert!(
            n <= 1000,
            "{} is {} lines - split it before it becomes the next god file",
            p.display(),
            n
        );
    }
}

#[test]
fn cmd_modules_exist_and_stay_bounded() {
    // cmd/* modules are the designated home for command implementations.
    for e in std::fs::read_dir("src/cmd").unwrap().flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("rs") {
            continue;
        }
        let n = lines(&p.to_string_lossy());
        assert!(
            n <= 1000,
            "{} is {} lines - split the command module by domain",
            p.display(),
            n
        );
    }
}
