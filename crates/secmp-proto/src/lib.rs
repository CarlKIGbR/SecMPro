// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-proto` — the sans-IO SecMP/1 protocol core.
//!
//! **Responsibility.** Hand-written fixed-layout big-endian encodings of every structure in spec Appendix D
//! (spec §4.1; no serde on the wire), cell and frame layouts, and the SecMP-INV, SecMP-HX, SecMP-TR and
//! SecMP-LINK state machines and SecMP-Q command types. Decoders are total, exact-fit and canonical.
//!
//! **Allowed dependencies** (docs/02 §3): `secmp-crypto` only among workspace crates; no cryptographic crate
//! directly (all cryptography goes through `secmp-crypto`); sans-IO: no tokio, no I/O crate. Its dependency
//! closure must have zero cargo-vet exemptions.
//!
//! **Status.** M0 skeleton — no code (implementation starts in M2).
#![forbid(unsafe_code)]
