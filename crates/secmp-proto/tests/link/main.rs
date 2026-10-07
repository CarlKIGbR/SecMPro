// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! The SecMP-LINK vector tests of milestone M5, Phase A (`docs/reviews/M05-planning/TEST-SPEC-M5.md` (a)): the
//! replay of the handshake groups of `link.json` (V-01…V-05, V-17…V-19, V-21). The client, relay and frame tests
//! are the test crates `link_client`, `link_relay` and `link_frames`; they share `link/fixture.rs`.

mod fixture;
mod vectors;
