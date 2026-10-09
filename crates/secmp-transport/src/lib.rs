// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-transport` — moving opaque cells between a client and a relay.
//!
//! **Responsibility.** The `QueueTransport` trait; the SecMP-LINK client over an abstract byte stream; the
//! relay-queue transport; the Tor (`arti-client`) and direct TLS stream providers. It only ever sees opaque,
//! already end-to-end-encrypted cells and capabilities — never identifiers or plaintext (docs/02 §6).
//!
//! **Allowed dependencies** (docs/02 §3, §7): `secmp-proto`, `secmp-crypto`; `arti-client` (features
//! `onion-service-client` + `rustls`, never `hs-pow-full` — ADR-024); `rustls` with `aws-lc-rs` for TLS only
//! (exempt from the "only `secmp-crypto`" rule and never used for SecMP constructions); an async runtime, each
//! added with an ADR.
//!
//! **M5.** [`Session`] (the SecMP-LINK handshake and frame I/O over any [`std::io::Read`] + [`std::io::Write`]
//! stream, spec §8), [`RelayQueueTransport`] (the [`QueueTransport`] of spec §12.1 for a SecMP relay: signing,
//! tokens, the `cmd_seq` sequence, and the fail-closed check of every response against its request, OPEN-M5-11 A),
//! and the opaque capabilities [`RecvCap`] / [`SendCap`]. The trait is synchronous: no async runtime is in the
//! vetted closure yet (ADR-049), and the in-process streams of the test harness need none. The Tor and TLS stream
//! providers and an asynchronous driver are M6.
#![forbid(unsafe_code)]
#![deny(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

pub mod caps;
pub mod channel;
pub mod error;
pub mod evicted;
pub mod relay_queue;
pub mod session;

pub use caps::{CAP_LEN, QueueRef, RecvCap, SendCap};
pub use channel::{Channel, Command, Completed, Outcome, Prepared};
pub use error::{Error, Result};
pub use relay_queue::{
    Bucket, CellId, FetchMultiOutcome, LdId, LinkGetMode, LinkGetOutcome, QueueTransport,
    RelayQueueTransport, SendOutcome, Token,
};
pub use session::{ConnectOutcome, Session};
