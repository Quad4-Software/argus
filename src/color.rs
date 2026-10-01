// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! ANSI color handling with NO_COLOR / TERM=dumb / tty detection.

use std::io::IsTerminal;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorMode {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy)]
pub struct Styles {
    enabled: bool,
}

impl Styles {
    pub fn new(mode: ColorMode) -> Self {
        let enabled = match mode {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => {
                std::env::var_os("NO_COLOR").is_none()
                    && std::env::var("TERM").map_or(true, |t| t != "dumb")
                    && std::io::stdout().is_terminal()
            }
        };
        Self { enabled }
    }

    pub fn wrap(&self, code: &str, s: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    pub fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    pub fn red(&self, s: &str) -> String {
        self.wrap("31", s)
    }
    pub fn yellow(&self, s: &str) -> String {
        self.wrap("33", s)
    }
    pub fn blue(&self, s: &str) -> String {
        self.wrap("34", s)
    }
    pub fn green(&self, s: &str) -> String {
        self.wrap("32", s)
    }
    pub fn cyan(&self, s: &str) -> String {
        self.wrap("36", s)
    }
    pub fn severity(&self, sev: crate::finding::Severity) -> String {
        use crate::finding::Severity::*;
        let label = sev.label();
        match sev {
            Critical => self.wrap("1;31", label),
            High => self.red(label),
            Medium => self.yellow(label),
            Low => self.blue(label),
            Info => self.dim(label),
        }
    }
}
