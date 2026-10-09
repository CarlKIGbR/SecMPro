// SPDX-License-Identifier: AGPL-3.0-or-later
//! The scheduler's parameters (spec §4.2 provisional values, ADR-018; TEST-SPEC-M6 "Conventions") and the integer
//! rate bound of spec §10.2.

/// The scheduler mode (spec §10.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// One isolated link per queue.
    Strict,
    /// One link per relay, a slot every `T_BALANCED`.
    Balanced,
    /// As Balanced with `T_LOWBW`.
    LowBw,
}

/// The values of spec §4.2 and OPEN-M6-12…17 (all times in milliseconds).
#[derive(Clone, Debug)]
pub struct Params {
    /// `PERIODS`.
    pub periods_ms: [u64; 4],
    /// `T_BALANCED`.
    pub t_balanced_ms: u64,
    /// `T_LOWBW`.
    pub t_lowbw_ms: u64,
    /// `F`: cells per `FETCH`.
    pub f: u64,
    /// `F_M`: cells per `FETCH_MULTI`.
    pub f_m: u64,
    /// The largest random start offset of a link (spec §10.6 (1)).
    pub phase_max_ms: u64,
    /// `LINK_LIFETIME`, inclusive.
    pub lifetime_ms: (u64, u64),
    /// Ticks whose responses may be outstanding (spec §10.3).
    pub max_in_flight: u8,
    /// The delay of a control operation from a related one (spec §10.6 (2)), inclusive.
    pub control_delay_ms: (u64, u64),
    /// The delay before a recipient re-creates a queue (spec §9.1), inclusive.
    pub recreate_delay_ms: (u64, u64),
    /// How long before a tick a `FETCH` is built if the previous response is not committed (OPEN-M6-13).
    pub fetch_lead_ms: u64,
    /// The cap of the reconnect back-off (OPEN-M6-14).
    pub backoff_cap_ms: u64,
    /// The period of a pool queue (OPEN-M6-17).
    pub p_pool_ms: u64,
    /// How late a tick may be written before the link is torn down instead (a late frame would be an activity-correlated
    /// signal, OPEN-M6-13).
    pub late_tolerance_ms: u64,
    /// Spare queues per relay in the pool (spec §10.6 (3)).
    pub pool_target: usize,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            periods_ms: [10_000, 20_000, 40_000, 80_000],
            t_balanced_ms: 10_000,
            t_lowbw_ms: 30_000,
            f: 4,
            f_m: 8,
            phase_max_ms: 180_000,
            lifetime_ms: (21_600_000, 86_400_000),
            max_in_flight: 2,
            control_delay_ms: (60_000, 3_600_000),
            recreate_delay_ms: (10_000, 300_000),
            fetch_lead_ms: 1_000,
            backoff_cap_ms: 3_600_000,
            p_pool_ms: 80_000,
            late_tolerance_ms: 1_000,
            pool_target: 2,
        }
    }
}

/// The `FETCH_MULTI` entry limit (spec D.2).
pub const FETCH_MULTI_LIMIT: usize = 32;

impl Params {
    /// Whether `period_ms` is in `PERIODS` (spec §9.8).
    #[must_use]
    pub fn period_valid(&self, period_ms: u64) -> bool {
        self.periods_ms.contains(&period_ms)
    }

    /// The slot length of a mode that has one.
    #[must_use]
    pub const fn slot_ms(&self, mode: Mode) -> Option<u64> {
        match mode {
            Mode::Strict => None,
            Mode::Balanced => Some(self.t_balanced_ms),
            Mode::LowBw => Some(self.t_lowbw_ms),
        }
    }

    /// The integer form of `Σ 1/P_q ≤ F_M / (2·T)` (spec §10.2): `Σ (8·T)/P_q ≤ 4·F_M` (Balanced: `Σ 80 000/P ≤ 32`;
    /// Low-bw: `Σ 240 000/P ≤ 32`). Strict has no such bound.
    #[must_use]
    pub fn rate_bound_ok(&self, mode: Mode, periods_ms: impl IntoIterator<Item = u64>) -> bool {
        let Some(slot) = self.slot_ms(mode) else {
            return true;
        };
        let (Some(scale), Some(limit)) = (slot.checked_mul(8), self.f_m.checked_mul(4)) else {
            return false;
        };
        rate_sum_ok(periods_ms, scale, limit)
    }
}

/// `Σ scale/P ≤ limit` over `periods_ms`, exact (each `P` divides `scale` for `PERIODS`; a period that does not is
/// rounded up, which can only refuse more).
#[must_use]
pub fn rate_sum_ok(periods_ms: impl IntoIterator<Item = u64>, scale: u64, limit: u64) -> bool {
    let mut sum = 0_u64;
    for p in periods_ms {
        let Some(q) = scale.checked_div(p) else {
            return false;
        };
        let q = if q.checked_mul(p) == Some(scale) {
            q
        } else {
            q.saturating_add(1)
        };
        sum = sum.saturating_add(q);
        if sum > limit {
            return false;
        }
    }
    true
}

/// `min(base · 2^(n−1), cap)` for `n ≥ 1` (OPEN-M6-14, spec §9.7 (7)): the upper bound of the n-th consecutive
/// reconnect delay. Never overflows.
#[must_use]
pub fn backoff_cap(n: u32, base_ms: u64, cap_ms: u64) -> u64 {
    let shift = n.saturating_sub(1).min(63);
    let scaled = base_ms.checked_shl(shift).filter(|v| v >> shift == base_ms);
    scaled.map_or(cap_ms, |v| v.min(cap_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_caps_follow_the_table() {
        let caps: Vec<u64> = (1..=8).map(|n| backoff_cap(n, 180_000, 3_600_000)).collect();
        assert_eq!(
            caps,
            [180_000, 360_000, 720_000, 1_440_000, 2_880_000, 3_600_000, 3_600_000, 3_600_000]
        );
        assert_eq!(backoff_cap(u32::MAX, 180_000, 3_600_000), 3_600_000);
    }

    #[test]
    fn rate_bound_is_integer() {
        let p = Params::default();
        let ten = |n: usize| vec![10_000_u64; n];
        assert!(p.rate_bound_ok(Mode::Balanced, ten(4)));
        assert!(!p.rate_bound_ok(Mode::Balanced, ten(5)));
        assert!(p.rate_bound_ok(Mode::LowBw, vec![40_000; 5]));
        assert!(!p.rate_bound_ok(Mode::LowBw, vec![40_000; 6]));
        assert!(p.rate_bound_ok(Mode::Strict, ten(100)));
    }
}
