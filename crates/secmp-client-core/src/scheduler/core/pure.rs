// SPDX-License-Identifier: AGPL-3.0-or-later
//! The pure decisions of the scheduler core, small enough for Kani (K-01…K-03) and free of state.

/// The queue a Balanced slot sends to (spec §10.2): the first queue, from the round-robin pointer `rr`, whose previous
/// `SEND` is at least `P_q` before the slot `slot_ms` (or that was never sent to). `None`: nothing is due, the slot
/// carries a `PING`. `queues` is `(last_send_ms, period_ms)` in the fixed round-robin order.
#[must_use]
pub fn rr_select(rr: usize, queues: &[(Option<u64>, u64)], slot_ms: u64) -> Option<usize> {
    let n = queues.len();
    if n == 0 {
        return None;
    }
    for step in 0..n {
        let at = rr.checked_add(step)?.checked_rem(n)?;
        let (last, period) = queues.get(at).copied()?;
        let due = last.is_none_or(|l| slot_ms.checked_sub(l).is_some_and(|d| d >= period));
        if due {
            return Some(at);
        }
    }
    None
}

/// The time of tick `k`: `t_up + k·period` (K-03). `None` on overflow — never wraps.
#[must_use]
pub fn tick_time(t_up: u64, k: u32, period_ms: u64) -> Option<u64> {
    u64::from(k).checked_mul(period_ms)?.checked_add(t_up)
}

/// Ticks whose responses are outstanding (spec §10.3): a third tick with two outstanding tears the link down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flight {
    count: u8,
    max: u8,
}

impl Flight {
    /// No tick outstanding; at most `max` allowed.
    #[must_use]
    pub const fn new(max: u8) -> Self {
        Self { count: 0, max }
    }

    /// Ticks outstanding.
    #[must_use]
    pub const fn count(&self) -> u8 {
        self.count
    }

    /// A tick is due: `false` (and nothing changes) if `max` ticks are already outstanding — the caller tears the link
    /// down before writing anything.
    #[must_use]
    pub const fn on_tick(&mut self) -> bool {
        if self.count >= self.max {
            return false;
        }
        self.count = self.count.saturating_add(1);
        true
    }

    /// The responses of the oldest outstanding tick are complete.
    pub const fn on_response(&mut self) {
        self.count = self.count.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rr_walks_from_the_pointer_and_pings_when_nothing_is_due() {
        let q = [(Some(0), 10), (None, 40), (Some(5), 40)];
        assert_eq!(rr_select(0, &q, 10), Some(0));
        assert_eq!(rr_select(1, &q, 10), Some(1));
        assert_eq!(rr_select(2, &q, 10), Some(0));
        let none = [(Some(0), 10), (Some(5), 40)];
        assert_eq!(rr_select(0, &none, 5), None);
        assert_eq!(rr_select(0, &[], 5), None);
    }

    #[test]
    fn tick_time_never_wraps() {
        assert_eq!(tick_time(5, 3, 10), Some(35));
        assert_eq!(tick_time(u64::MAX, 1, 10), None);
        assert_eq!(tick_time(0, u32::MAX, u64::MAX), None);
    }

    #[test]
    fn flight_allows_two() {
        let mut f = Flight::new(2);
        assert!(f.on_tick());
        assert!(f.on_tick());
        assert!(!f.on_tick());
        assert_eq!(f.count(), 2);
        f.on_response();
        assert!(f.on_tick());
        f.on_response();
        f.on_response();
        f.on_response();
        assert_eq!(f.count(), 0);
    }
}
