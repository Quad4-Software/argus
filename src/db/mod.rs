// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! Linked record store for scans, intel, and crawler output.
//! SQLite is the default. Postgres and SurrealDB are connectors.

mod driver;

pub use driver::{put_report, relate, search};
