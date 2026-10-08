// SPDX-License-Identifier: AGPL-3.0-or-later
//! Rate limits (spec §9.7 item 7; ADR-048 (p); OPEN-M5-02 values): token buckets on the monotonic clock.
//!
//! - Per link: every request frame (a `CONT` included) takes one token; a command one of whose frames finds the
//!   bucket empty is over the rate — not executed, answered with exactly one ERR 7 frame (for `LINK_PUT` after its
//!   third frame), its `cmd_seq` recorded. Defaults: burst 8, refill 1 per second.
//! - Per listener: every `HELLO` takes one token; over the rate the connection is closed before `RELAYINFO`.
//!   Defaults: burst 16, refill 4 per second.
//!
//! The limits are configuration; the vector replay runs without them. Tokens are kept in thousandths so that a
//! refill rate in tokens per second needs no division.

/// One limit: a burst of `burst` tokens, refilled at `per_sec` tokens per second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimit {
    /// Bucket size in tokens.
    pub burst: u32,
    /// Refill in tokens per second.
    pub per_sec: u32,
}

impl RateLimit {
    /// The per-link default (OPEN-M5-02): burst 8 request frames, refill 1 per second.
    pub const LINK_DEFAULT: Self = Self {
        burst: 8,
        per_sec: 1,
    };

    /// The per-listener `HELLO` default (OPEN-M5-02): burst 16, refill 4 per second.
    pub const HELLO_DEFAULT: Self = Self {
        burst: 16,
        per_sec: 4,
    };
}

/// Thousandths of a token per token.
const MILLI: u64 = 1000;

/// A token bucket, full at creation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenBucket {
    limit: RateLimit,
    /// Tokens in thousandths.
    milli_tokens: u64,
    /// The monotonic time of the last refill.
    last_ms: u64,
}

impl TokenBucket {
    /// A full bucket at monotonic time `now_ms`.
    #[must_use]
    pub fn new(limit: RateLimit, now_ms: u64) -> Self {
        Self {
            limit,
            milli_tokens: u64::from(limit.burst).saturating_mul(MILLI),
            last_ms: now_ms,
        }
    }

    /// Refill for the time since the last call, then take one token; `false` if none is left (nothing taken).
    /// A clock that steps backwards refills nothing.
    pub fn take(&mut self, now_ms: u64) -> bool {
        let elapsed = now_ms.saturating_sub(self.last_ms);
        self.last_ms = self.last_ms.max(now_ms);
        // per_sec tokens per 1000 ms = per_sec thousandths per millisecond
        let refill = elapsed.saturating_mul(u64::from(self.limit.per_sec));
        let cap = u64::from(self.limit.burst).saturating_mul(MILLI);
        self.milli_tokens = self.milli_tokens.saturating_add(refill).min(cap);
        if self.milli_tokens >= MILLI {
            self.milli_tokens = self.milli_tokens.saturating_sub(MILLI);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_then_the_refill_rate() {
        let mut b = TokenBucket::new(RateLimit::LINK_DEFAULT, 0);
        for _ in 0..8 {
            assert!(b.take(0));
        }
        assert!(!b.take(0));
        assert!(!b.take(999));
        assert!(b.take(1000));
        assert!(!b.take(1000));
        // a long pause refills to the burst, not beyond
        for _ in 0..8 {
            assert!(b.take(1_000_000));
        }
        assert!(!b.take(1_000_000));
    }

    #[test]
    fn the_hello_default_and_a_backwards_clock() {
        let mut b = TokenBucket::new(RateLimit::HELLO_DEFAULT, 5000);
        for _ in 0..16 {
            assert!(b.take(5000));
        }
        assert!(!b.take(4000));
        assert!(b.take(5250));
        assert!(!b.take(5250));
        let mut z = TokenBucket::new(
            RateLimit {
                burst: 0,
                per_sec: 0,
            },
            0,
        );
        assert!(!z.take(u64::MAX));
    }
}
