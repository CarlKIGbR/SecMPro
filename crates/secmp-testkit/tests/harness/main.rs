// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! The M5 harness tests (TEST-SPEC-M5 (b6) T-01…T-09, T-11 and (c) H-01…H-06, H-08…H-13, G-06) — one test crate.
//! Everything here uses only `pub` items of `secmp-testkit`, `secmp-transport`, `secmp-relay` and `secmp-proto`
//! (H-09).

mod fixture;
mod invitation;
mod m6_channel;
mod m6_common;
mod m6_sched;
mod m6_sched_bal;
mod m6_sched_io;
mod m6_sched_life;
mod scenarios;
mod scripted;
mod transport;
