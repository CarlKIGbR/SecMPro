// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! F-01…F-10, F-12 and P-01…P-05: frames (spec §8.4), the response decoder and the properties (TEST-SPEC-M5 (b); `docs/reviews/M05-planning/TEST-SPEC-M5.md`).

#[path = "link/fixture.rs"]
mod fixture;
