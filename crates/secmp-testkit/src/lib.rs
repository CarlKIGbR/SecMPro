// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-testkit` — test infrastructure (never shipped).
//!
//! **Responsibility.** The in-process harness (relay + N clients, virtual clock, scenario DSL), KAT loaders,
//! `turmoil` simulations, fault injection and the `two-clients` binary (docs/02 §3, docs/06 §4, M5/M6). M1
//! provides the known-answer-test loaders ([`kat`]) for the Wycheproof and ACVP files under `vectors/external/`
//! and the SecMP vector files.
//!
//! **Allowed dependencies** (docs/02 §3): any workspace crate except `secmp-ui`; test-only third-party crates
//! added with an ADR (`serde_json`, ADR-037). It must never be a normal (non-dev) dependency of a shipped crate.
#![forbid(unsafe_code)]

pub mod kat;
