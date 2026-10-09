// SPDX-License-Identifier: AGPL-3.0-or-later
//! The harness's virtual clock (docs/06 §4: no wall clock in a test). Time moves only when the scenario says so;
//! the wall clock (Unix seconds, for hour buckets and `RELAYINFO` validity) and the monotonic clock (milliseconds,
//! for rates and timeouts) move together.

use std::cell::Cell;
use std::rc::Rc;

use secmp_relay::Now;

/// A shared virtual clock: every clone reads and moves the same time.
#[derive(Clone)]
pub struct Clock(Rc<Cell<Now>>);

impl Clock {
    /// A clock at `unix_secs`, monotonic time 0.
    #[must_use]
    pub fn new(unix_secs: u64) -> Self {
        Self(Rc::new(Cell::new(Now {
            unix_secs,
            mono_ms: 0,
        })))
    }

    /// The time now.
    #[must_use]
    pub fn now(&self) -> Now {
        self.0.get()
    }

    /// Unix seconds now.
    #[must_use]
    pub fn unix(&self) -> u64 {
        self.0.get().unix_secs
    }

    /// Move the clock forward by `secs` seconds (both clocks).
    pub fn advance_secs(&self, secs: u64) {
        let now = self.0.get();
        self.0.set(Now {
            unix_secs: now.unix_secs.saturating_add(secs),
            mono_ms: now.mono_ms.saturating_add(secs.saturating_mul(1000)),
        });
    }

    /// Move the clock forward by `ms` milliseconds (the monotonic clock exactly, the wall clock by whole seconds
    /// carried over).
    pub fn advance_ms(&self, ms: u64) {
        let now = self.0.get();
        let mono_ms = now.mono_ms.saturating_add(ms);
        let whole = (mono_ms / 1000).saturating_sub(now.mono_ms / 1000);
        self.0.set(Now {
            unix_secs: now.unix_secs.saturating_add(whole),
            mono_ms,
        });
    }

    /// Move the clock forward by `hours` hours.
    pub fn advance_hours(&self, hours: u64) {
        self.advance_secs(hours.saturating_mul(3600));
    }
}
