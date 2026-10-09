// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! The SecMP-LINK tests of milestone M5, Phase A (`docs/reviews/M05-planning/TEST-SPEC-M5.md`): one test crate, so
//! that the shared fixture is used by something in every build.
//!
//! - `fixture`: the reference file `link.json`, the relay of case 1, and an independent composition of the handshake
//!   that the negative tests use to re-MAC manipulated records;
//! - `vectors`: V-01…V-05, V-17…V-19, V-21 (the handshake groups of the `link` suite);
//! - `client` (C-01…C-22), `relay_hs` (RH-01…RH-15), `frames` (F-01…F-10, F-12, P-01…P-05).

mod client;
mod fixture;
mod frames;
mod relay_hs;
mod vectors;
