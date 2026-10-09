// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Command classification: file walkers, network users, osint arms.
//! Each list is kept beside the others so a new command is added to all
//! three in one edit.

use super::Cmd;

/// File-walking commands. Progress stays off for machine-facing ones.
pub fn scans_files(cmd: &Cmd) -> bool {
    !matches!(
        cmd,
        Cmd::Rules
            | Cmd::RulesKeygen { .. }
            | Cmd::RulesSign { .. }
            | Cmd::RulesUpdate { .. }
            | Cmd::Completions(_)
            | Cmd::Mcp
            | Cmd::Init { .. }
            | Cmd::Authors { .. }
            | Cmd::Sbom { .. }
            | Cmd::Ai { .. }
            | Cmd::Domain { .. }
            | Cmd::Email { .. }
            | Cmd::Ip { .. }
            | Cmd::Hash { .. }
            | Cmd::Url { .. }
            | Cmd::Ports { .. }
            | Cmd::Intel { .. }
            | Cmd::Supply { .. }
            | Cmd::Records { .. }
            | Cmd::Api { .. }
            | Cmd::Stego { .. }
            | Cmd::Codec { .. }
            | Cmd::Style { .. }
            | Cmd::Account { .. }
            | Cmd::Socials { .. }
            | Cmd::Feed { .. }
            | Cmd::Gitmeta { .. }
            | Cmd::Grep { .. }
            | Cmd::Extract { .. }
            | Cmd::Meta { .. }
            | Cmd::Media { .. }
            | Cmd::Dork { .. }
            | Cmd::Favicon { .. }
            | Cmd::User { .. }
            | Cmd::Keybase { .. }
            | Cmd::Steam { .. }
            | Cmd::Bluesky { .. }
            | Cmd::Mastodon { .. }
            | Cmd::Reddit { .. }
            | Cmd::Youtube { .. }
            | Cmd::Tiktok { .. }
            | Cmd::Lemmy { .. }
            | Cmd::Gharchive(_)
            | Cmd::Typo { .. }
            | Cmd::Modules
            | Cmd::Host(_)
    )
}

#[macro_export]
macro_rules! osint_arms {
    () => {
        $crate::cli::Cmd::Domain { .. }
            | $crate::cli::Cmd::Email { .. }
            | $crate::cli::Cmd::Hash { .. }
            | $crate::cli::Cmd::Url { .. }
            | $crate::cli::Cmd::Ports { .. }
            | $crate::cli::Cmd::Ip { .. }
            | $crate::cli::Cmd::Intel { .. }
            | $crate::cli::Cmd::Supply { .. }
            | $crate::cli::Cmd::Records { .. }
            | $crate::cli::Cmd::Api { .. }
            | $crate::cli::Cmd::Stego { .. }
            | $crate::cli::Cmd::Codec { .. }
            | $crate::cli::Cmd::Style { .. }
            | $crate::cli::Cmd::Account { .. }
            | $crate::cli::Cmd::Socials { .. }
            | $crate::cli::Cmd::Feed { .. }
            | $crate::cli::Cmd::Gitmeta { .. }
            | $crate::cli::Cmd::Grep { .. }
            | $crate::cli::Cmd::Extract { .. }
            | $crate::cli::Cmd::Meta { .. }
            | $crate::cli::Cmd::Media { .. }
            | $crate::cli::Cmd::Dork { .. }
            | $crate::cli::Cmd::Favicon { .. }
            | $crate::cli::Cmd::User { .. }
            | $crate::cli::Cmd::Keybase { .. }
            | $crate::cli::Cmd::Steam { .. }
            | $crate::cli::Cmd::Bluesky { .. }
            | $crate::cli::Cmd::Mastodon { .. }
            | $crate::cli::Cmd::Reddit { .. }
            | $crate::cli::Cmd::Youtube { .. }
            | $crate::cli::Cmd::Tiktok { .. }
            | $crate::cli::Cmd::Lemmy { .. }
            | $crate::cli::Cmd::Gharchive(_)
            | $crate::cli::Cmd::Typo { .. }
            | $crate::cli::Cmd::Modules
    };
}

pub fn is_http_target(s: &str) -> bool {
    let t = s.trim();
    t.len() >= 8
        && (t[..8].eq_ignore_ascii_case("https://") || t[..7].eq_ignore_ascii_case("http://"))
}

/// Commands that cannot run without the network.
pub fn needs_network(cmd: &Cmd) -> bool {
    matches!(
        cmd,
        Cmd::Github(_)
            | Cmd::Gitlab(_)
            | Cmd::Gitea(_)
            | Cmd::Roam(_)
            | Cmd::Watch(_)
            | Cmd::Daemon(_)
            | Cmd::RulesUpdate { .. }
            | Cmd::Domain { .. }
            | Cmd::Email { .. }
            | Cmd::Hash { .. }
            | Cmd::Url { .. }
            | Cmd::Ports { .. }
            | Cmd::Intel { .. }
            | Cmd::Account { .. }
            | Cmd::Socials { .. }
            | Cmd::Feed { .. }
            | Cmd::Favicon { .. }
            | Cmd::User { .. }
            | Cmd::Keybase { .. }
            | Cmd::Steam { .. }
            | Cmd::Bluesky { .. }
            | Cmd::Mastodon { .. }
            | Cmd::Reddit { .. }
            | Cmd::Youtube { .. }
            | Cmd::Tiktok { .. }
            | Cmd::Lemmy { .. }
            | Cmd::Gharchive(_)
            | Cmd::Typo { .. }
    ) || matches!(cmd, Cmd::Gitmeta { target } if is_http_target(target))
        || matches!(cmd, Cmd::Host(h) if h.needs_network())
        || matches!(cmd, Cmd::Extract { target } if is_http_target(target))
}
