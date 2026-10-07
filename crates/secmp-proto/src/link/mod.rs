// SPDX-License-Identifier: AGPL-3.0-or-later
//! SecMP-LINK (spec §8) and the sans-IO side of SecMP-Q (spec §9): the client↔relay layer.
//!
//! - [`client`]: `HELLO`, the checks of `RELAYINFO` (§8.2), `HS1`, `HS2` (§8.3) as a typestate chain; the result is a
//!   [`Link`]. The client is anonymous: it takes no long-term secret.
//! - [`relay`]: the relay's identity and static keys ([`relay::RelayKeys`]), `RELAYINFO`, and the responder
//!   (`HELLO` → `RELAYINFO` → `HS1` → `HS2`).
//! - [`frame`]: the link state ([`Link`]): XChaCha20-Poly1305 frames of 4352 B under the direction keys, the strict
//!   `+1` counters, `LINK_MAX_FRAMES` (§8.4), and the decoding of the frame plaintext as a request or response.
//! - [`cont`]: multi-frame assembly (`LINK_PUT`, `LINKR`; §9.2, D.2).
//! - [`ids`]: the derived identifiers, `akc` and the access token (§5.3, §9.1, §9.6).
//!
//! **Rejection (spec §8.5, ADR-048 (b)).** Every failed check of a received record or frame is the one
//! [`Error::Rejected`], with no detail; the failing check is observable only through the `kat` trace of the
//! tests. A receiver whose check fails is consumed (a typestate transition) or leaves its counters and state
//! unchanged ([`Link::open_unit`] does not mutate), and emits nothing.
//!
//! **Randomness.** Drawn from the [`crate::tr::Entropy`] in the order of reading OPEN-1 (`vectors/SCHEMA-4.11-link.md`):
//! the client draws `e_c_sk`, `ek_c_seed`, then `sk_e1` and `m1` (the `HybridKEM-1024` encapsulation); the relay
//! draws `sk_er` and `m2` (the `HybridKEM-768` encapsulation) only after `mac1` has verified (reading OPEN-2).

pub mod client;
pub mod cont;
pub mod frame;
mod handshake;
pub mod ids;
pub mod relay;

use core::fmt;

pub use frame::{Link, Opened};

/// `valid_until − now` of a `RELAYINFO` the client accepts: 60 days (spec §8.2, ADR-048 (a)); exactly 60 days is
/// accepted.
pub const MAX_VALIDITY_SECS: u64 = 5_184_000;

/// `LINK_MAX_FRAMES` (spec §4.2): the client seals no frame beyond this counter in either direction and opens a
/// new link instead (ADR-048 (OPEN-M5-03)).
pub const LINK_MAX_FRAMES: u64 = 1 << 20;

/// The error of the link layer. [`Error::Rejected`] is the one verdict on received bytes (spec §8.5); the others
/// are local conditions that never reach the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A received record or frame failed a check (spec §8.5): one uniform error, no detail.
    Rejected,
    /// The 64-bit frame counter of a direction is exhausted (spec §8.4, `checked_add`): the link is unusable.
    CounterOverflow,
    /// A frame payload longer than 4335 B (the padding needs one marker byte).
    PayloadTooLong,
    /// The client's counter reached [`LINK_MAX_FRAMES`]: open a new link.
    NewLinkRequired,
    /// The local environment could not provide randomness or locked memory.
    Unavailable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Rejected => "rejected",
            Self::CounterOverflow => "counter overflow",
            Self::PayloadTooLong => "payload too long",
            Self::NewLinkRequired => "new link required",
            Self::Unavailable => "unavailable",
        })
    }
}

impl std::error::Error for Error {}

impl From<crate::Error> for Error {
    fn from(e: crate::Error) -> Self {
        match e {
            crate::Error::Unavailable => Self::Unavailable,
            crate::Error::Rejected => Self::Rejected,
        }
    }
}

impl From<secmp_crypto::Error> for Error {
    fn from(e: secmp_crypto::Error) -> Self {
        crate::Error::from(e).into()
    }
}

/// `Result` with the link [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

/// The values of one handshake that the vectors compare (feature `kat`, never in a shipped build): every
/// intermediate of spec §8.3, as the client or the relay computed it. Fields a side has not computed yet are zero.
#[cfg(feature = "kat")]
#[derive(Clone, Default)]
pub struct HandshakeTrace {
    /// `ss1` (`HybridKEM-1024`).
    pub ss1: [u8; 32],
    /// `h0`.
    pub h0: [u8; 32],
    /// `ck1`.
    pub ck1: [u8; 32],
    /// `mac1`.
    pub mac1: [u8; 32],
    /// `ss2` (`HybridKEM-768`).
    pub ss2: [u8; 32],
    /// `h1`.
    pub h1: [u8; 32],
    /// `ck2`.
    pub ck2: [u8; 32],
    /// `mac2`.
    pub mac2: [u8; 32],
    /// `k_c2r`.
    pub k_c2r: [u8; 32],
    /// `k_r2c`.
    pub k_r2c: [u8; 32],
    /// `sess_id`.
    pub sess_id: [u8; 16],
}
