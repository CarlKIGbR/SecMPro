// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-client-core` — the client core behind every user interface.
//!
//! **Responsibility.** Contacts, sessions (HX/TR orchestration), invitations, the constant-rate scheduler
//! (spec §10), outbox, queue pool, settings, the injectable `clock` (the sanctioned `SystemTime::now` site of
//! docs/06 §2), and the async request/response + event `Api` used by `secmp-ui` and `secmp-cli` (docs/02 §4).
//!
//! **Allowed dependencies** (docs/02 §3): `secmp-proto`, `secmp-crypto`, `secmp-transport`, `secmp-store`,
//! `secmp-sys-desktop`, `secmp-sys-mem`; an async runtime, added with an ADR.
//!
//! **Status.** M6 Phase A: [`clock`], [`timing`] and the sans-IO constant-rate [`scheduler`] with its `ControlOps`,
//! `QueuePool` and `outbox` (in-memory behind traits). Contacts, sessions, invitations and the `Api` are M7.
#![forbid(unsafe_code)]

pub mod clock;
#[cfg(kani)]
mod kani_proofs;
pub mod scheduler;
pub mod timing;
