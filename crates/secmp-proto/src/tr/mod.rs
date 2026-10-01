// SPDX-License-Identifier: AGPL-3.0-or-later
//! SecMP-TR — the hybrid ratchet (spec §7): the Signal Double Ratchet, header-encryption variant, with an
//! ML-KEM-768 secret mixed into the root KDF in both halves of every DH step and each chain's KEM material in every
//! message (ADR-004). Sans-IO: the caller moves cells and persists the state.
//!
//! - [`RatchetState`] (§7.1) with its persistence encoding ([`RatchetState::to_bytes`], `from_bytes`);
//!   initialisation from a supplied `SK` and transcript (§7.2; SecMP-HX supplies them from M4 on).
//! - [`RatchetState::encrypt`] (§7.3) → [`Sealed`] (persist-before-send) and [`RatchetState::decrypt`] (§7.4,
//!   transactional) → [`Opened`] (persist-before-ack); a refusal hands the unchanged state back ([`Refused`]).
//! - [`content`]: dummies, delivery, fragment reassembly, key changes (§7.6, §7.7).
//!
//! Every input-dependent failure is the uniform [`crate::Error::Rejected`]; [`crate::Error::Unavailable`] means OS
//! randomness or locked memory was missing (M3 plan D1). All cryptography is `secmp-crypto`'s; secrets are
//! `secmp-crypto` types, compared and selected in constant time.

pub mod content;
mod entropy;
mod ratchet;
pub(crate) mod select;
mod state;
#[cfg(test)]
mod tests;

#[cfg(feature = "kat")]
pub use entropy::FixedEntropy;
pub use entropy::{Entropy, OsEntropy};
pub use ratchet::{Opened, Plaintext, Refused, Sealed};
pub use select::{MAX_FF, MAX_SKIPPED, SKIP_WINDOW};
pub use state::RatchetState;
