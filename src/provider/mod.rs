// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Remote provider abstraction: enumerate repos, then clone+scan.

pub mod gitea;
pub mod github;
pub mod gitlab;

use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct RepoSpec {
    /// e.g. "owner/repo"
    pub full_name: String,
    /// https clone URL.
    pub clone_url: String,
    pub private: bool,
    pub archived: bool,
    pub fork: bool,
    /// ISO timestamp of last push/activity when the provider reports it.
    #[serde(default)]
    pub updated_at: Option<String>,
    /// ISO creation timestamp when the provider reports it.
    #[serde(default)]
    pub created_at: Option<String>,
}

/// Which repos to enumerate.
#[derive(Clone, Debug)]
pub enum Selector {
    /// Repos visible to the authenticated token.
    Me,
    /// Repos owned by a user account.
    User(String),
    /// Repos owned by an org/group.
    Org(String),
}
