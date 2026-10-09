// SPDX-License-Identifier: AGPL-3.0-or-later
//! Time as the relay sees it (spec §9.1, §9.7 item 3; `docs/06` §2).
//!
//! The stores hold **hour buckets only** ([`HourBucket`], hours since the Unix epoch as `u32`, spec §9.1): no store
//! field carries a finer time. The connection layer needs a monotonic clock in milliseconds for the rate limits and
//! the `HELLO`→`HS1` timeout; both are passed in by the caller ([`Now`]) so that every component is sans-IO and the
//! tests run on a virtual clock. The one wall-clock read of the crate is [`wall_clock_unix_secs`], the relay's
//! hour-bucket function sanctioned by `docs/06` §2.

/// Seconds per hour bucket.
const SECS_PER_HOUR: u64 = 3600;

/// An hour bucket: hours since the Unix epoch (spec §9.1, "Buckets are hours since epoch (`u32`)").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HourBucket(pub u32);

impl HourBucket {
    /// The bucket of a Unix time in seconds; a time beyond the `u32` range of hours (the year 491 936) is the last
    /// bucket.
    #[must_use]
    pub fn from_unix_secs(secs: u64) -> Self {
        Self(u32::try_from(secs.checked_div(SECS_PER_HOUR).unwrap_or(0)).unwrap_or(u32::MAX))
    }

    /// `self + hours`, or `None` past the last bucket.
    #[must_use]
    pub const fn plus(self, hours: u32) -> Option<Self> {
        match self.0.checked_add(hours) {
            Some(b) => Some(Self(b)),
            None => None,
        }
    }

    /// Whether something anchored at `self` with a time-to-live of `ttl` hours has expired at `now`: expired iff
    /// `now > self + ttl` (OPEN-M5-05 B: a TTL is a delivery promise, never shortened by bucket rounding). An anchor
    /// so late that `self + ttl` passes the last bucket never expires.
    #[must_use]
    pub const fn expired_at(self, ttl: u32, now: Self) -> bool {
        match self.0.checked_add(ttl) {
            Some(end) => now.0 > end,
            None => false,
        }
    }
}

/// The time inputs of one relay operation: the wall clock (for the hour bucket and the `RelayInfo` validity) and a
/// monotonic clock in milliseconds (rate limits, handshake timeout). Supplied by the caller: the server reads the
/// clocks, the tests use virtual ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Now {
    /// Unix time in seconds.
    pub unix_secs: u64,
    /// Monotonic milliseconds since an arbitrary origin.
    pub mono_ms: u64,
}

impl Now {
    /// The hour bucket of [`Now::unix_secs`].
    #[must_use]
    pub fn bucket(self) -> HourBucket {
        HourBucket::from_unix_secs(self.unix_secs)
    }
}

/// The wall clock in Unix seconds — the relay's hour-bucket function, the only `SystemTime::now` site of the crate
/// (`docs/06` §2; test RL-11). A clock before the epoch reads as 0.
#[must_use]
pub fn wall_clock_unix_secs() -> u64 {
    // docs/06 §2: sanctioned site (the relay's hour-bucket function); expect::LINT_ALLOWANCES lists it
    #[allow(clippy::disallowed_methods)]
    let now = std::time::SystemTime::now();
    now.duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_hours_since_the_epoch() {
        assert_eq!(HourBucket::from_unix_secs(0), HourBucket(0));
        assert_eq!(HourBucket::from_unix_secs(3599), HourBucket(0));
        assert_eq!(HourBucket::from_unix_secs(3600), HourBucket(1));
        // the suite's `now` (vectors/SCHEMA-4.11-link.md constants)
        assert_eq!(
            HourBucket::from_unix_secs(1_700_000_100),
            HourBucket(472_222)
        );
        assert_eq!(HourBucket::from_unix_secs(u64::MAX), HourBucket(u32::MAX));
    }

    #[test]
    fn expiry_is_strictly_after_the_ttl() {
        let b = HourBucket(100);
        assert!(!b.expired_at(168, HourBucket(268)));
        assert!(b.expired_at(168, HourBucket(269)));
        assert!(!HourBucket(u32::MAX).expired_at(1, HourBucket(u32::MAX)));
        assert_eq!(b.plus(5), Some(HourBucket(105)));
        assert_eq!(HourBucket(u32::MAX).plus(1), None);
    }

    #[test]
    fn now_has_its_bucket() {
        let now = Now {
            unix_secs: 7200,
            mono_ms: 0,
        };
        assert_eq!(now.bucket(), HourBucket(2));
        assert!(wall_clock_unix_secs() > 1_700_000_000);
    }
}
