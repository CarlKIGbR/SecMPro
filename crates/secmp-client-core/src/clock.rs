// SPDX-License-Identifier: AGPL-3.0-or-later
//! The injectable clock (`docs/06` §2, §4): the only module of the client that reads a real clock. Everything else
//! gets time as an argument or through [`Clock`]; the tests run on [`ManualClock`] (virtual milliseconds).

use std::cell::Cell;
use std::rc::Rc;

/// A source of time.
pub trait Clock {
    /// Monotonic milliseconds since an arbitrary origin (periods, ticks, lifetimes).
    fn mono_ms(&self) -> u64;
    /// Unix seconds (hour buckets, `RELAYINFO` validity).
    fn unix_secs(&self) -> u64;
}

/// The real clocks. The one `Instant::now` / `SystemTime::now` site of the client (`docs/06` §2).
pub struct SystemClock {
    origin: std::time::Instant,
}

impl SystemClock {
    /// A clock whose monotonic origin is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn mono_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn unix_secs(&self) -> u64 {
        // docs/06 §2: sanctioned site (secmp-client-core::clock); expect::LINT_ALLOWANCES lists it
        #[allow(clippy::disallowed_methods)]
        let now = std::time::SystemTime::now();
        now.duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// A virtual clock: time moves only when told to. Clones share the time.
#[derive(Clone)]
pub struct ManualClock {
    mono_ms: Rc<Cell<u64>>,
    unix_origin: u64,
}

impl ManualClock {
    /// A clock at monotonic time 0 whose Unix time is `unix_origin` + the elapsed whole seconds.
    #[must_use]
    pub fn new(unix_origin: u64) -> Self {
        Self {
            mono_ms: Rc::new(Cell::new(0)),
            unix_origin,
        }
    }

    /// Move the clock forward by `ms`.
    pub fn advance_ms(&self, ms: u64) {
        self.mono_ms.set(self.mono_ms.get().saturating_add(ms));
    }

    /// Set the monotonic time (never backwards).
    pub fn set_ms(&self, ms: u64) {
        self.mono_ms.set(self.mono_ms.get().max(ms));
    }
}

impl Clock for ManualClock {
    fn mono_ms(&self) -> u64 {
        self.mono_ms.get()
    }

    fn unix_secs(&self) -> u64 {
        self.unix_origin
            .saturating_add(self.mono_ms.get().checked_div(1000).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_moves_only_when_told() {
        let c = ManualClock::new(1_000);
        let d = c.clone();
        assert_eq!((c.mono_ms(), c.unix_secs()), (0, 1_000));
        d.advance_ms(2_500);
        assert_eq!((c.mono_ms(), c.unix_secs()), (2_500, 1_002));
        c.set_ms(1);
        assert_eq!(c.mono_ms(), 2_500, "never backwards");
    }

    #[test]
    fn system_clock_reads_real_time() {
        let c = SystemClock::new();
        assert!(c.unix_secs() > 1_700_000_000);
        assert!(c.mono_ms() < 60_000);
    }
}
