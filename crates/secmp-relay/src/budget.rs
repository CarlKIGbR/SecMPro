// SPDX-License-Identifier: AGPL-3.0-or-later
//! The global memory budget (spec §9.7 item 4; OPEN-M5-07 A): two byte pools with **worst-case reservations**.
//!
//! - The queue pool reserves [`QUEUE_RESERVATION`] bytes at `QUEUE_NEW` — a full queue (`QUEUE_CAPACITY` cells of
//!   4096 B) plus its bookkeeping — so that a `SEND` never needs memory beyond its queue's reservation and is never
//!   refused for the budget (eviction bounds memory per queue, §9.7 item 4).
//! - The link-data pool reserves [`LINKDATA_RESERVATION`] bytes at `LINK_PUT` (the 12360-B blob plus its entry); a
//!   consume of one-time link data releases the blob part and the consumption marker keeps [`LINKDATA_OVERHEAD`]
//!   until it expires.
//!
//! A reservation that would make a pool exceed its limit fails ("exceeded": `QUEUE_NEW`/`LINK_PUT` then answer
//! `ERR_FULL`); `None` is an unlimited pool. Deletion, consumption and expiry release exactly what was reserved.

/// The bookkeeping of one queue besides its cells (keys, ids, buckets, the deque): a fixed charge.
pub const QUEUE_OVERHEAD: u64 = 512;

/// The bookkeeping of one link-data entry or consumption marker besides its blob: a fixed charge.
pub const LINKDATA_OVERHEAD: u64 = 128;

/// The worst-case bytes of one queue: `QUEUE_CAPACITY` (128) cells of `CELL_LEN` (4096) bytes plus
/// [`QUEUE_OVERHEAD`] (checked against the size constants by a unit test).
pub const QUEUE_RESERVATION: u64 = 524_800;

/// The bytes of one stored blob, `LINK_BLOB_LEN` (the part a consume releases).
pub const LINKDATA_BLOB_CHARGE: u64 = 12_360;

/// The worst-case bytes of one link-data entry: the blob plus [`LINKDATA_OVERHEAD`].
pub const LINKDATA_RESERVATION: u64 = 12_488;

/// The limits of the two pools (`None`: unlimited).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetLimits {
    /// Bytes of the queue pool.
    pub queue_bytes: Option<u64>,
    /// Bytes of the link-data pool.
    pub linkdata_bytes: Option<u64>,
}

impl BudgetLimits {
    /// The budget of the `link` vectors (OPEN-M5-07, reading OPEN-12): room for exactly two queues, link data
    /// unlimited.
    #[must_use]
    pub const fn vectors() -> Self {
        Self {
            queue_bytes: Some(QUEUE_RESERVATION.saturating_mul(2)),
            linkdata_bytes: None,
        }
    }
}

/// Which pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pool {
    /// Queues.
    Queues,
    /// Link data.
    LinkData,
}

/// The pools in use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryBudget {
    limits: BudgetLimits,
    queue_used: u64,
    linkdata_used: u64,
}

impl MemoryBudget {
    /// Empty pools with these limits.
    #[must_use]
    pub const fn new(limits: BudgetLimits) -> Self {
        Self {
            limits,
            queue_used: 0,
            linkdata_used: 0,
        }
    }

    /// The limits.
    #[must_use]
    pub const fn limits(&self) -> BudgetLimits {
        self.limits
    }

    /// Bytes reserved in `pool`.
    #[must_use]
    pub const fn used(&self, pool: Pool) -> u64 {
        match pool {
            Pool::Queues => self.queue_used,
            Pool::LinkData => self.linkdata_used,
        }
    }

    fn slot(&mut self, pool: Pool) -> (&mut u64, Option<u64>) {
        match pool {
            Pool::Queues => (&mut self.queue_used, self.limits.queue_bytes),
            Pool::LinkData => (&mut self.linkdata_used, self.limits.linkdata_bytes),
        }
    }

    /// Whether `bytes` more would still fit in `pool` (the check of [`MemoryBudget::reserve`] without the effect).
    #[must_use]
    pub fn fits(&self, pool: Pool, bytes: u64) -> bool {
        let (used, limit) = match pool {
            Pool::Queues => (self.queue_used, self.limits.queue_bytes),
            Pool::LinkData => (self.linkdata_used, self.limits.linkdata_bytes),
        };
        match (used.checked_add(bytes), limit) {
            (Some(total), Some(limit)) => total <= limit,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    /// Reserve `bytes` in `pool`.
    ///
    /// # Errors
    /// [`Exceeded`] if the pool would exceed its limit; nothing is reserved then.
    pub fn reserve(&mut self, pool: Pool, bytes: u64) -> Result<(), Exceeded> {
        if !self.fits(pool, bytes) {
            return Err(Exceeded);
        }
        let (used, _) = self.slot(pool);
        *used = used.saturating_add(bytes);
        Ok(())
    }

    /// Release `bytes` from `pool` (a release never underflows: it saturates at zero).
    pub fn release(&mut self, pool: Pool, bytes: u64) {
        let (used, _) = self.slot(pool);
        *used = used.saturating_sub(bytes);
    }
}

/// A reservation would exceed its pool (spec §9.7 item 4: `ERR_FULL`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exceeded;

#[cfg(test)]
mod tests {
    use super::*;
    use secmp_proto::link::QUEUE_CAPACITY;
    use secmp_proto::sizes::{CELL_LEN, LINK_BLOB_LEN};

    #[test]
    fn reservations_are_the_worst_case() {
        let cells = QUEUE_CAPACITY.checked_mul(CELL_LEN).map(u64::try_from);
        assert_eq!(
            cells.map(|c| c.map(|c| c.checked_add(QUEUE_OVERHEAD))),
            Some(Ok(Some(QUEUE_RESERVATION)))
        );
        assert_eq!(u64::try_from(LINK_BLOB_LEN), Ok(LINKDATA_BLOB_CHARGE));
        assert_eq!(
            LINKDATA_BLOB_CHARGE.checked_add(LINKDATA_OVERHEAD),
            Some(LINKDATA_RESERVATION)
        );
    }

    #[test]
    fn a_reservation_fails_exactly_when_it_would_exceed() {
        let mut b = MemoryBudget::new(BudgetLimits {
            queue_bytes: Some(10),
            linkdata_bytes: Some(0),
        });
        assert_eq!(b.reserve(Pool::Queues, 6), Ok(()));
        assert_eq!(b.reserve(Pool::Queues, 4), Ok(()));
        assert_eq!(b.reserve(Pool::Queues, 1), Err(Exceeded));
        assert_eq!(b.used(Pool::Queues), 10);
        b.release(Pool::Queues, 4);
        assert_eq!(b.reserve(Pool::Queues, 4), Ok(()));
        assert_eq!(b.reserve(Pool::LinkData, 1), Err(Exceeded));
        assert_eq!(b.reserve(Pool::LinkData, 0), Ok(()));
        b.release(Pool::LinkData, 9);
        assert_eq!(b.used(Pool::LinkData), 0);
        assert_eq!(b.reserve(Pool::Queues, u64::MAX), Err(Exceeded));
    }

    #[test]
    fn an_unlimited_pool_refuses_only_overflow() {
        let mut b = MemoryBudget::new(BudgetLimits::vectors());
        assert_eq!(b.reserve(Pool::LinkData, u64::MAX), Ok(()));
        assert_eq!(b.reserve(Pool::LinkData, 1), Err(Exceeded));
        assert_eq!(b.reserve(Pool::Queues, QUEUE_RESERVATION), Ok(()));
        assert_eq!(b.reserve(Pool::Queues, QUEUE_RESERVATION), Ok(()));
        assert!(!b.fits(Pool::Queues, 1));
        assert_eq!(b.limits(), BudgetLimits::vectors());
    }
}
