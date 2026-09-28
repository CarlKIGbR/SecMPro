// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-relay` — the relay server (library + binary).
//!
//! **Responsibility.** The SecMP-LINK server, the SecMP-Q executor for the eight commands, the RAM-only queue
//! and link-data stores, memory budget, sweeper, listeners and in-process sandboxing (docs/02 §5, docs/05). It
//! keeps nothing on disk and logs no per-request data (ADR-022, CLAUDE.md §1.1).
//!
//! **Allowed dependencies** (docs/02 §3): `secmp-crypto`, `secmp-proto`, `secmp-sys-mem` only among workspace
//! crates — never desktop code; third-party runtime crates (async runtime, `tracing`) added with an ADR.
//!
//! **Status.** M0 skeleton — no code (implementation starts in M5).
#![forbid(unsafe_code)]
