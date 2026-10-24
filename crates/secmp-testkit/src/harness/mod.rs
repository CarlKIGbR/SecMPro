// SPDX-License-Identifier: AGPL-3.0-or-later
//! The in-process harness (feature `kat`; `docs/07` M5): a relay and N clients over in-process byte streams, a
//! virtual clock, derandomised entropy and a scenario surface that M6's `two-clients` builds on.
//!
//! - [`Harness`] / [`HarnessConfig`] / [`ClientId`] / [`Client`]: the world — clients connect (a SecMP-LINK handshake
//!   per connection), create queues, advance the clock, and the relay can restart.
//! - [`HarnessStream`] / [`Capture`] / [`Split`]: the streams, the byte captures, the cut-into-pieces mode (H-11).
//! - [`Clock`], [`EntropyPool`]: the virtual clock and the per-actor deterministic randomness.
//! - [`Side`] and friends ([`ratchet_pair`], [`text_content`]): one side of a conversation over relay queues.
//! - [`verify_frames`]: opens every captured frame under the link's keys (H-08).
//! - [`cert`], [`DirectRelay`]: test certificates and the relay behind its direct TLS listener on loopback (M6).

pub mod cert;
mod clock;
mod convo;
mod direct;
mod driver;
mod entropy;
mod mem;
mod stream;
mod tokio_driver;
mod verify;
mod world;

pub use clock::Clock;
pub use convo::{Polled, Side, ratchet_pair, text_content, text_of};
pub use direct::DirectRelay;
pub use driver::{
    Audit, CONTROL_SLOT_BASE, Conv, Convs, Costs, Dir, Gate, GateState, Inspect, LinkMaterial,
    Material, Options, SimClient, Trace, TraceEntry, VirtualDriver,
};
pub use entropy::EntropyPool;
pub use mem::{Chunking, MemProvider, MemRelay, StoreChange, Unit};
/// The relay's direct listener and configuration, for the TLS rows of `secmp-transport` (TLS-12, TLS-14), which have
/// no dependency on the relay crate of their own.
pub use secmp_relay::tls as relay_tls;
pub use secmp_relay::{Config as RelayConfig, Limits as RelayLimits};
pub use stream::{
    CLIENT_HANDSHAKE_BYTES, Capture, FRAME, HarnessStream, RELAY_HANDSHAKE_BYTES, Split,
};
pub use tokio_driver::{
    ControlMaterial, CostedWorker, JobRecord, TestControl, TestDirectory, TestHandshakes,
};
pub use verify::{FrameCheck, verify_frames};
pub use world::{Client, ClientId, Harness, HarnessConfig, START_UNIX};
