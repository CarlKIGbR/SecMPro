// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! RH-01…RH-15: the relay handshake (spec §8.2–§8.3) (TEST-SPEC-M5 (b); `docs/reviews/M05-planning/TEST-SPEC-M5.md`).

#[path = "link/fixture.rs"]
mod fixture;
