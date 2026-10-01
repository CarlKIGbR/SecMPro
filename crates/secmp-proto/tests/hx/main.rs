// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! The SecMP-INV/HX tests (milestone M4): one test crate, so that the shared harness is used by something in
//! every build.
//!
//! - `generator`, `vectors`: the `hx` vector suite (`vectors/SCHEMA-4.10-hx.md`) — the Rust generator (an
//!   independent construction, `common/hx_gen.rs`) against the vector file, and the replay of the file through
//!   the library;
//! - `fixture`: an inviter, an invitee and the honest run, built from the library's public API;
//! - `flow`: the end-to-end run with OS randomness.

#[path = "../common/hx_gen.rs"]
mod hx_gen;

mod accept;
mod accept_ok;
mod build;
mod envelope;
mod fixture;
mod flow;
mod generator;
mod inv;
mod layout;
mod scenario;
mod store;
mod vectors;
