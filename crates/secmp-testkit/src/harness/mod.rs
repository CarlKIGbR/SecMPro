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

mod clock;
mod convo;
mod driver;
mod entropy;
mod stream;
mod verify;
mod world;

pub use clock::Clock;
pub use driver::{
    Audit, CONTROL_SLOT_BASE, Gate, GateState, Conv, Convs, Dir, Inspect, LinkMaterial, Material, Options, SimClient, Trace, TraceEntry, VirtualDriver,
};
pub use convo::{Polled, Side, ratchet_pair, text_content, text_of};
pub use entropy::EntropyPool;
pub use stream::{
    CLIENT_HANDSHAKE_BYTES, Capture, FRAME, HarnessStream, RELAY_HANDSHAKE_BYTES, Split,
};
pub use verify::{FrameCheck, verify_frames};
pub use world::{Client, ClientId, Harness, HarnessConfig, START_UNIX};
