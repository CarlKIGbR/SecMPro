// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-relay` — the relay server (library + binary).
//!
//! **Responsibility.** The SecMP-LINK server, the SecMP-Q executor for the eight commands, the RAM-only queue
//! and link-data stores, memory budget, sweeper, listeners and in-process sandboxing (docs/02 §5, docs/05). It
//! keeps nothing on disk and logs no per-request data (ADR-022, CLAUDE.md §1.1).
//!
//! **Allowed dependencies** (docs/02 §3): `secmp-crypto`, `secmp-proto`, `secmp-sys-mem` only among workspace
//! crates — never desktop code; third-party runtime crates (async runtime, `tracing`) added with an ADR. M5 uses
//! none (ADR-049): the listener is `std::net`, the event sink is [`event`]'s closed set.
//!
//! **Structure (M5).** Sans-IO from the bytes up — every component takes its time and randomness from the caller,
//! so the tests run on a virtual clock with derandomised entropy:
//! - [`conn`]: one connection — `HELLO`/`RELAYINFO`/`HS1`/`HS2` records (via `secmp_proto::link::relay`), then
//!   4352-byte units to the [`executor`]; handshake rate, `HELLO`→`HS1` timeout, one link per connection.
//! - [`executor`]: one link — frame open, decode, multi-frame assembly, the frame rate, `cmd_seq` ([`cmdseq`]),
//!   then the command ([`exec`]) and its response frames ([`plan`]).
//! - [`relay`]: the shared state behind one lock — [`queue`] (`QueueStore`, cells in [`cells`]), [`linkdata`]
//!   (`LinkDataStore`), [`budget`] (`MemoryBudget`), drain, the sweeper; buffers that wipe on delete ([`buf`]).
//! - [`keys`] (key file, `keygen`, `rotate-static`, the key ring), [`config`], [`clock`] (hour buckets),
//!   [`rate`] (token buckets), [`event`] (what the relay may report), [`server`] (`std::net`), [`error`].
#![forbid(unsafe_code)]
#![deny(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

pub mod budget;
pub mod buf;
pub mod cells;
pub mod clock;
pub mod cmdseq;
pub mod config;
pub mod conn;
pub mod error;
pub mod event;
pub mod exec;
pub mod executor;
#[cfg(kani)]
mod kani_proofs;
pub mod keys;
pub mod linkdata;
pub mod plan;
pub mod queue;
pub mod rate;
pub mod relay;
pub mod server;

pub use clock::{HourBucket, Now};
pub use config::{Config, Limits};
pub use conn::{Connection, Output};
pub use error::{Error, Result};
pub use executor::{Executor, Outcome};
pub use keys::{KeyFile, KeyRing};
pub use relay::Relay;
