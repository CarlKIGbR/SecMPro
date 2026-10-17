// SPDX-License-Identifier: AGPL-3.0-or-later
//! The constant-rate scheduler (spec §10; `docs/02` §4.4): the sans-IO [`core`], the one-shot [`control`] operations,
//! the [`pool`] of spare queues, the [`outbox`] and the in-memory [`conversation`] behind the cell source.

//!
//! **What a driver must do** (the virtual driver of the testkit does it; so must the asynchronous one of M6 Phase B):
//! - call [`core::Scheduler::poll_due`] first at every wake-up and write the frames it returns *before* it calls
//!   anything else, then [`core::Scheduler::work`], and report the instant the work ended with
//!   [`core::Scheduler::prepared_until`] (a frame prepared after its tick is an overrun);
//! - resolve every [`types::Output::Connect`] with `link_up` or `connect_failed`: a link in `Connecting` has no
//!   deadline in [`core::Scheduler::next_deadline`], so a connect attempt the driver forgets is never retried;
//! - wake at every [`core::Scheduler::next_deadline`], including the `FETCH`-lead deadline (`tick − fetch_lead_ms`): it
//!   is load-bearing — a driver that wakes only at the ticks prepares a `FETCH` whose previous response is still
//!   outstanding too late and loses the tick;
//! - run preparation off the path of the I/O loop: its cost may decide when a frame is *ready*, never when a due frame
//!   *leaves*. A cell source may answer "not ready"; the core then asks the same queue again at its next pass: a "not
//!   ready" answer never advances the queue choice, and the Balanced round robin advances when the `SEND` frame is
//!   *completely written* — not when its cell is obtained and not when the core hands the frame out at the tick (`last_send`
//!   stays at the tick): the driver reports every completed frame write, oldest first, with
//!   [`core::Scheduler::frame_written`]; a link torn down before its frame was written leaves the rotation where it was
//!   (GLM2B-1, FIN-2), and the next `SEND` is chosen from the position the newest still-unwritten one will commit, so the
//!   choice never depends on when a write completes (FIN2-1) — and a "not ready" answer never lets a tick's `FETCH` part
//!   be sealed before its `SEND` part (WEISUNG M6-B-6, EXTB-1).

pub mod control;
pub mod core;
// compiled out under Kani: `secmp-proto`'s codec types are stand-ins there, and the harnesses need only the pure core
#[cfg(not(kani))]
pub mod conversation;
pub mod outbox;
pub mod params;
pub mod pool;
#[cfg(not(kani))]
pub mod run;
pub mod types;
