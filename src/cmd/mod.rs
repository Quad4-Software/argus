// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Command implementations extracted from main.rs. Each submodule owns
//! one command family; main.rs keeps only cli dispatch and glue.

// modules are re-exported per-function below; child files import
// crate paths directly since private modules cannot be re-exported

pub(crate) mod attest_cmd;
pub mod daemon_cmd;
pub mod deps;
pub mod host_cmd;
pub mod misc;
pub mod osint_cmd;
pub mod remote;
pub(crate) mod revive;
pub mod sandbox_apply;
pub mod watcher;

pub(crate) use daemon_cmd::*;
pub(crate) use deps::*;
pub(crate) use misc::*;
pub(crate) use remote::*;
pub(crate) use sandbox_apply::*;
pub(crate) use watcher::*;
pub mod review_cmd;
pub(crate) mod similar_cmd;
pub mod trends_cmd;
