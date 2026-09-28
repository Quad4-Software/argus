//! Command implementations extracted from main.rs. Each submodule owns
//! one command family; main.rs keeps only cli dispatch and glue.

// modules are re-exported per-function below; child files import
// crate paths directly since private modules cannot be re-exported

pub mod daemon_cmd;
pub mod deps;
pub mod misc;
pub mod remote;
pub mod sandbox_apply;
pub mod watcher;

pub(crate) use daemon_cmd::*;
pub(crate) use deps::*;
pub(crate) use misc::*;
pub(crate) use remote::*;
pub(crate) use sandbox_apply::*;
pub(crate) use watcher::*;
pub(crate) mod similar_cmd;
