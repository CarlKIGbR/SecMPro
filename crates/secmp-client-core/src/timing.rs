// SPDX-License-Identifier: AGPL-3.0-or-later
//! `TimingRng`: the randomness of the schedule (link phases and lifetimes, control-operation delays, re-creation
//! delays, back-off), kept apart from the content entropy of the ratchet, the handshakes and the padding
//! (TEST-SPEC-M6 "Conventions", two entropy streams). What it draws never depends on user activity (spec §10.1), and
//! the count of draws ([`TimingRng::draws`]) is observable for the tests.
//!
//! A shipped build draws from the operating system. A `kat` build can be seeded (`SplitMix64`: a test generator, not a
//! cryptographic one; it does not exist in a shipped build).

use secmp_crypto::SecretBytes;

/// Randomness is unavailable (fail closed, CLAUDE.md §1.5): no schedule is made without it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unavailable;

impl core::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("randomness unavailable")
    }
}

impl std::error::Error for Unavailable {}

enum Source {
    Os,
    #[cfg(any(test, feature = "kat"))]
    Seeded(u64),
}

/// The timing randomness (see the module documentation).
pub struct TimingRng {
    source: Source,
    draws: u64,
}

/// One round of rejection sampling over a 64-bit draw `x` for the interval `[lo, lo + span - 1]` (`span ≥ 1`):
/// `Some(value)` if `x` is accepted, `None` if the round is rejected. Accepted values are uniform: `x` is accepted
/// only below the largest multiple of `span` that fits in 64 bits (no modulo bias).
#[must_use]
pub fn sample_round(x: u64, lo: u64, span: u64) -> Option<u64> {
    let ceiling = u64::MAX.checked_div(span)?.checked_mul(span)?;
    if x >= ceiling {
        return None;
    }
    x.checked_rem(span)?.checked_add(lo)
}

impl TimingRng {
    /// The operating system's randomness.
    #[must_use]
    pub const fn os() -> Self {
        Self {
            source: Source::Os,
            draws: 0,
        }
    }

    /// A deterministic generator (tests only).
    #[cfg(any(test, feature = "kat"))]
    #[must_use]
    pub const fn seeded(seed: u64) -> Self {
        Self {
            source: Source::Seeded(seed),
            draws: 0,
        }
    }

    /// A second generator for a separate purpose (the control operations): seeded from this one's next 64 bits, so the two
    /// streams do not move each other. The fork is not a uniform draw and is not counted.
    ///
    /// # Errors
    /// [`Unavailable`] if the operating system has no randomness.
    pub fn fork(&mut self) -> Result<Self, Unavailable> {
        let seed = self.next_u64()?;
        Ok(match self.source {
            Source::Os => {
                let _ = seed;
                Self::os()
            }
            #[cfg(any(test, feature = "kat"))]
            Source::Seeded(_) => Self::seeded(seed ^ 0xa5a5_a5a5_5a5a_5a5a),
        })
    }

    /// How many uniform draws were made ([`TimingRng::uniform`] calls that returned).
    #[must_use]
    pub const fn draws(&self) -> u64 {
        self.draws
    }

    fn next_u64(&mut self) -> Result<u64, Unavailable> {
        match &mut self.source {
            Source::Os => {
                let bytes = SecretBytes::<8>::random().map_err(|_| Unavailable)?;
                Ok(u64::from_be_bytes(*bytes.expose_secret()))
            }
            #[cfg(any(test, feature = "kat"))]
            Source::Seeded(state) => {
                *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = *state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                Ok(z ^ (z >> 31))
            }
        }
    }

    /// A uniform value in `[lo, hi]` (inclusive), by rejection sampling on 64-bit draws.
    ///
    /// # Errors
    /// [`Unavailable`] if the operating system has no randomness.
    pub fn uniform(&mut self, lo: u64, hi: u64) -> Result<u64, Unavailable> {
        let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
        self.draws = self.draws.saturating_add(1);
        // `hi - lo + 1`; 0 stands for the whole 64-bit range
        let span = hi.wrapping_sub(lo).wrapping_add(1);
        if span == 0 {
            return self.next_u64();
        }
        loop {
            let x = self.next_u64()?;
            if let Some(v) = sample_round(x, lo, span) {
                return Ok(v);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_stays_in_range_and_counts_draws() -> Result<(), Unavailable> {
        let mut rng = TimingRng::seeded(7);
        for _ in 0..1000 {
            let v = rng.uniform(10, 20)?;
            assert!((10..=20).contains(&v));
        }
        assert_eq!(rng.draws(), 1000);
        assert_eq!(rng.uniform(5, 5)?, 5);
        assert!((3..=9).contains(&rng.uniform(9, 3)?));
        Ok(())
    }

    #[test]
    fn rejection_round_is_unbiased_at_the_edge() {
        // span 3: the ceiling is the largest multiple of 3 below 2^64
        let ceiling = u64::MAX / 3 * 3;
        assert_eq!(sample_round(ceiling - 1, 0, 3), Some(2));
        assert_eq!(sample_round(ceiling, 0, 3), None);
        assert_eq!(sample_round(u64::MAX, 0, 3), None);
        assert_eq!(sample_round(5, 100, 1), Some(100));
    }

    #[test]
    fn os_source_draws() -> Result<(), Unavailable> {
        let mut rng = TimingRng::os();
        assert!(rng.uniform(0, 180_000)? <= 180_000);
        Ok(())
    }
}
