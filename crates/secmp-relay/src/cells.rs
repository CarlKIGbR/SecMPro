// SPDX-License-Identifier: AGPL-3.0-or-later
//! The cells of one queue (spec §9.1, §9.3, §9.5): a FIFO of at most `CAP` cells with per-queue `cell_id`s from 1.
//!
//! - `SEND` ([`Cells::push`]) stores the cell under the next `cell_id`; at capacity it first evicts the oldest cell
//!   and reports its `cell_id` (§9.5). `cell_id`s keep increasing (`checked_add`: an exhausted id space is a local
//!   abort, never a wrap).
//! - `FETCH` acknowledgement ([`Cells::ack`]) deletes every cell with `cell_id ≤ ack` (cumulative, §9.3); the caller
//!   has checked `ack < next_cell_id` (§9.1).
//! - Expiry ([`Cells::expire`]) deletes cells whose arrival bucket is past `CELL_TTL` (§9.7 item 3).
//!
//! The type is generic over the buffer `B` and the capacity so that the Kani harness `kani_queue_eviction_bounds`
//! runs the same logic at a capacity of 3 with a plain buffer (the relay's buffer zeroizes on drop, which Kani cannot
//! execute). A deleted or evicted slot is dropped at once, so its buffer is wiped at once (§9.7 item 5).

use std::collections::VecDeque;

use crate::clock::HourBucket;

/// One stored cell.
pub struct Slot<B> {
    /// Per-queue id, from 1.
    pub cell_id: u64,
    /// The relay-global arrival counter (oldest-first selection across queues, `FETCH_MULTI`).
    pub arrival: u64,
    /// The arrival hour bucket (expiry anchor).
    pub bucket: HourBucket,
    /// The cell.
    pub buf: B,
}

/// The per-queue `cell_id` space is exhausted (2^64 − 1 cells): a local abort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdsExhausted;

/// The cells of one queue, oldest first, at most `CAP`.
pub struct Cells<B, const CAP: usize> {
    slots: VecDeque<Slot<B>>,
    next_cell_id: u64,
}

impl<B, const CAP: usize> Default for Cells<B, CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B, const CAP: usize> Cells<B, CAP> {
    /// No cells; the first `cell_id` is 1 (§9.1).
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: VecDeque::new(),
            next_cell_id: 1,
        }
    }

    /// The number of stored cells.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether no cell is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// The `cell_id` the next stored cell gets.
    #[must_use]
    pub const fn next_cell_id(&self) -> u64 {
        self.next_cell_id
    }

    /// The stored cells, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &Slot<B>> {
        self.slots.iter()
    }

    /// Store a cell (spec §9.5): at capacity the oldest cell is evicted first and its id returned.
    ///
    /// # Errors
    /// [`IdsExhausted`] if the next `cell_id` would not fit; nothing changes then.
    pub fn push(
        &mut self,
        arrival: u64,
        bucket: HourBucket,
        buf: B,
    ) -> Result<(u64, Option<u64>), IdsExhausted> {
        let cell_id = self.next_cell_id;
        let next = cell_id.checked_add(1).ok_or(IdsExhausted)?;
        let evicted = if self.slots.len() >= CAP {
            // dropping the slot drops its buffer: the evicted cell is wiped here (spec §9.7 item 5)
            self.slots.pop_front().map(|s| s.cell_id)
        } else {
            None
        };
        self.slots.push_back(Slot {
            cell_id,
            arrival,
            bucket,
            buf,
        });
        self.next_cell_id = next;
        Ok((cell_id, evicted))
    }

    /// Delete every cell with `cell_id ≤ ack` (spec §9.3, cumulative); returns how many were deleted.
    pub fn ack(&mut self, ack: u64) -> usize {
        let mut deleted = 0_usize;
        while self.slots.front().is_some_and(|s| s.cell_id <= ack) {
            self.slots.pop_front();
            deleted = deleted.saturating_add(1);
        }
        deleted
    }

    /// Delete every cell whose arrival bucket has expired at `now` under `ttl` hours (spec §9.7 item 3,
    /// OPEN-M5-05 B); returns how many were deleted.
    pub fn expire(&mut self, ttl: u32, now: HourBucket) -> usize {
        let before = self.slots.len();
        self.slots.retain(|s| !s.bucket.expired_at(ttl, now));
        before.saturating_sub(self.slots.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids<const C: usize>(c: &Cells<u8, C>) -> Vec<u64> {
        c.iter().map(|s| s.cell_id).collect()
    }

    #[test]
    fn ids_start_at_one_and_eviction_reports_the_oldest() -> Result<(), IdsExhausted> {
        let mut c: Cells<u8, 3> = Cells::new();
        assert!(c.is_empty());
        assert_eq!(c.push(1, HourBucket(0), 10)?, (1, None));
        assert_eq!(c.push(2, HourBucket(0), 11)?, (2, None));
        assert_eq!(c.push(3, HourBucket(0), 12)?, (3, None));
        assert_eq!(c.push(4, HourBucket(0), 13)?, (4, Some(1)));
        assert_eq!(c.push(5, HourBucket(0), 14)?, (5, Some(2)));
        assert_eq!(ids(&c), vec![3, 4, 5]);
        assert_eq!(c.len(), 3);
        assert_eq!(c.next_cell_id(), 6);
        Ok(())
    }

    #[test]
    fn ack_deletes_exactly_the_ids_up_to_it() -> Result<(), IdsExhausted> {
        let mut c: Cells<u8, 8> = Cells::default();
        for i in 1..=5 {
            c.push(i, HourBucket(0), 0)?;
        }
        assert_eq!(c.ack(0), 0);
        assert_eq!(c.ack(2), 2);
        assert_eq!(ids(&c), vec![3, 4, 5]);
        assert_eq!(c.ack(2), 0);
        assert_eq!(c.ack(5), 3);
        assert!(c.is_empty());
        assert_eq!(c.next_cell_id(), 6);
        Ok(())
    }

    #[test]
    fn expiry_follows_the_arrival_bucket() -> Result<(), IdsExhausted> {
        let mut c: Cells<u8, 8> = Cells::new();
        c.push(1, HourBucket(10), 0)?;
        c.push(2, HourBucket(11), 0)?;
        assert_eq!(c.expire(168, HourBucket(178)), 0);
        assert_eq!(c.expire(168, HourBucket(179)), 1);
        assert_eq!(ids(&c), vec![2]);
        Ok(())
    }

    #[test]
    fn an_exhausted_id_space_changes_nothing() {
        let mut c: Cells<u8, 2> = Cells::new();
        c.next_cell_id = u64::MAX;
        assert_eq!(c.push(1, HourBucket(0), 0), Err(IdsExhausted));
        assert!(c.is_empty());
        assert_eq!(c.next_cell_id(), u64::MAX);
    }
}
