// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Terminal progress line on stderr: ASCII spinner + counters, no deps.

use crate::color::Styles;
use std::io::{IsTerminal, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// --progress flag / defaults.progress values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ProgressMode {
    #[default]
    Auto,
    Always,
    Never,
}

impl ProgressMode {
    /// Auto = stderr is a tty and TERM is not dumb. Color handling for the
    /// rendered line comes from Styles, not from this check.
    pub fn enabled(self) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => {
                std::io::stderr().is_terminal()
                    && std::env::var("TERM").map_or(true, |t| t != "dumb")
            }
        }
    }
}

const FRAMES: [&str; 4] = ["|", "/", "-", "\\"];
const MIN_RENDER: Duration = Duration::from_millis(60);
const MAX_LABEL: usize = 48;

/// Live progress line for one scan target. Drop or finish() erases it.
pub struct Progress {
    label: String,
    total: usize,
    done: AtomicUsize,
    findings: AtomicUsize,
    frame: AtomicUsize,
    last: Mutex<Instant>,
    styles: Styles,
    enabled: bool,
}

impl Progress {
    /// total of 0 renders an indeterminate spinner (network waits, clones).
    pub fn new(label: &str, total: usize, enabled: bool, styles: Styles) -> Self {
        Self {
            label: label.into(),
            total,
            done: AtomicUsize::new(0),
            findings: AtomicUsize::new(0),
            frame: AtomicUsize::new(0),
            last: Mutex::new(Instant::now() - MIN_RENDER),
            styles,
            enabled,
        }
    }

    /// One more file visited. Renders at most every 60 ms.
    pub fn tick(&self) {
        self.done.fetch_add(1, Ordering::Relaxed);
        self.render();
    }

    pub fn add_findings(&self, n: usize) {
        if n > 0 {
            self.findings.fetch_add(n, Ordering::Relaxed);
        }
    }

    fn render(&self) {
        if !self.enabled {
            return;
        }
        let Ok(mut last) = self.last.try_lock() else {
            return;
        };
        if last.elapsed() < MIN_RENDER {
            return;
        }
        *last = Instant::now();
        let frame = FRAMES[self.frame.fetch_add(1, Ordering::Relaxed) % FRAMES.len()];
        let done = self.done.load(Ordering::Relaxed);
        let hits = self.findings.load(Ordering::Relaxed);
        let mut chars = self.label.chars();
        let label = if self.label.chars().count() > MAX_LABEL {
            format!(
                "{}...",
                chars.by_ref().take(MAX_LABEL - 3).collect::<String>()
            )
        } else {
            self.label.clone()
        };
        let mut line = format!("{} {}", self.styles.cyan(frame), self.styles.bold(&label));
        if self.total > 0 {
            line.push_str(&self.styles.dim(&format!(" {done}/{} files", self.total)));
        }
        if hits > 0 {
            line.push_str(&format!(
                " {}",
                self.styles.yellow(&format!("{hits} findings"))
            ));
        }
        let mut err = std::io::stderr().lock();
        let _ = write!(err, "\x1b[2K\r{line}");
        let _ = err.flush();
    }

    /// Erase the line. Safe to call repeatedly.
    pub fn finish(&self) {
        if self.enabled {
            let mut err = std::io::stderr().lock();
            let _ = write!(err, "\x1b[2K\r");
            let _ = err.flush();
        }
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        self.finish();
    }
}
