// SPDX-License-Identifier: AGPL-3.0-or-later
//! The constant-rate scheduler (spec §10; `docs/02` §4.4): the sans-IO [`core`], the one-shot [`control`] operations,
//! the [`pool`] of spare queues, the [`outbox`] and the in-memory [`conversation`] behind the cell source.

pub mod control;
pub mod core;
pub mod params;
pub mod pool;
pub mod types;
pub mod conversation;
pub mod outbox;
