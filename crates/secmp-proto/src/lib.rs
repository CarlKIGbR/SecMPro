// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-proto` — the sans-IO SecMP/1 protocol core.
//!
//! **Responsibility.** Hand-written fixed-layout big-endian encodings of every structure in spec Appendix D
//! (spec §4.1; no serde on the wire), cell and frame layouts, and — from M3 on — the SecMP-INV, SecMP-HX,
//! SecMP-TR and SecMP-LINK state machines and SecMP-Q command types. Decoders are total, exact-fit and canonical.
//!
//! **Allowed dependencies** (docs/02 §3): `secmp-crypto` only among workspace crates; no cryptographic crate
//! directly (all cryptography goes through `secmp-crypto`); sans-IO: no tokio, no I/O crate. Its dependency
//! closure must have zero cargo-vet exemptions.
//!
//! **M2 (encodings).** [`codec`] (reader, writer, padding), [`sizes`] (Appendix B, checked at compile time),
//! [`keys`] (the key and signature fields with the decoder obligations of spec §4.1) and [`wire`] (every
//! Appendix D structure). Every failure is [`Error::Rejected`].
//!
//! Arithmetic: the workspace denies `clippy::arithmetic_side_effects`, `indexing_slicing` and `as_conversions`
//! (docs/06 §2); this crate repeats the deny set so that it holds even if the workspace table changes. Lengths
//! are split off the input or converted with `try_from`; sizes are compile-time constants.
#![forbid(unsafe_code)]
#![deny(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

pub mod codec;
mod error;
pub mod keys;
pub mod sizes;
pub mod wire;

pub use codec::{Decode, Encode};
pub use error::{Error, Result};
