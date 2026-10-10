// SPDX-License-Identifier: AGPL-3.0-or-later
//! The constant-rate scheduler (spec §10; `docs/02` §4.4): the sans-IO [`core`], the one-shot [`control`] operations,
//! the [`pool`] of spare queues, the [`outbox`] and the in-memory [`conversation`] behind the cell source.

pub mod control;
pub mod core;
// compiled out under Kani: `secmp-proto`'s codec types are stand-ins there, and the harnesses need only the pure core
#[cfg(not(kani))]
pub mod conversation;
pub mod outbox;
pub mod params;
pub mod pool;
pub mod types;
