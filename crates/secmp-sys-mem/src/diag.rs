// SPDX-License-Identifier: AGPL-3.0-or-later
//! WIN2-DIAG (D-CI14, Q260; a throw-away commit, reverted before any further unit): process-wide counters of the page
//! allocations and page locks of this crate, read and printed by the instrumented harness tests. Counts, durations and
//! process totals only: no address, no content, no key.

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(test, all(windows, not(any(miri, kani)))))]
use std::time::Duration;

/// `SecretPage`s allocated (every backend).
pub(crate) static ALLOCS: AtomicU64 = AtomicU64::new(0);
/// `SecretPage`s dropped (every backend).
pub(crate) static FREES: AtomicU64 = AtomicU64::new(0);
/// Calls of the Windows backend's `lock` (one per allocation).
pub(crate) static LOCKS: AtomicU64 = AtomicU64::new(0);
/// Locks whose first `VirtualLock` failed with `ERROR_WORKING_SET_QUOTA` (the growth path).
pub(crate) static QUOTA_PATHS: AtomicU64 = AtomicU64::new(0);
/// Locks that ended in an error.
pub(crate) static FAILED: AtomicU64 = AtomicU64::new(0);
/// `VirtualLock` calls of `lock` (first attempts and retries).
pub(crate) static VLOCK_CALLS: AtomicU64 = AtomicU64::new(0);
/// Nanoseconds inside those `VirtualLock` calls.
pub(crate) static VLOCK_NS: AtomicU64 = AtomicU64::new(0);
/// `GetProcessWorkingSetSize` calls of the growth path.
pub(crate) static SIZES_CALLS: AtomicU64 = AtomicU64::new(0);
/// `SetProcessWorkingSetSize` calls of the growth path.
pub(crate) static SET_CALLS: AtomicU64 = AtomicU64::new(0);
/// Nanoseconds inside those `SetProcessWorkingSetSize` calls.
pub(crate) static SET_NS: AtomicU64 = AtomicU64::new(0);
/// Nanoseconds from asking for `GROW` to holding it, summed over every lock.
pub(crate) static WAIT_NS: AtomicU64 = AtomicU64::new(0);
/// The longest of those waits.
pub(crate) static WAIT_MAX_NS: AtomicU64 = AtomicU64::new(0);
/// Nanoseconds `GROW` was held, summed over every lock.
pub(crate) static HOLD_NS: AtomicU64 = AtomicU64::new(0);
/// The longest of those holds.
pub(crate) static HOLD_MAX_NS: AtomicU64 = AtomicU64::new(0);
/// `VirtualUnlock` calls of a dropped page.
pub(crate) static UNLOCKS: AtomicU64 = AtomicU64::new(0);
/// Nanoseconds inside those `VirtualUnlock` calls.
pub(crate) static UNLOCK_NS: AtomicU64 = AtomicU64::new(0);

/// Add `n` to `counter`.
pub(crate) fn add(counter: &AtomicU64, n: u64) {
    counter.fetch_add(n, Ordering::Relaxed);
}

/// Raise `counter` to `n` if `n` is larger.
#[cfg(any(test, all(windows, not(any(miri, kani)))))]
pub(crate) fn raise(counter: &AtomicU64, n: u64) {
    counter.fetch_max(n, Ordering::Relaxed);
}

/// `d` in whole nanoseconds, saturated.
#[cfg(any(test, all(windows, not(any(miri, kani)))))]
pub(crate) fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

fn get(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

/// The counters at one moment (each read on its own; concurrent locks may fall between the reads).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LockStats {
    /// `SecretPage`s allocated.
    pub allocs: u64,
    /// `SecretPage`s dropped.
    pub frees: u64,
    /// Windows: calls of `lock`.
    pub locks: u64,
    /// Windows: locks that took the growth path (first `VirtualLock` failed with the quota error).
    pub quota_paths: u64,
    /// Windows: locks that failed.
    pub failed: u64,
    /// Windows: `VirtualLock` calls of `lock`.
    pub vlock_calls: u64,
    /// Windows: nanoseconds inside them.
    pub vlock_ns: u64,
    /// Windows: `GetProcessWorkingSetSize` calls of the growth path.
    pub sizes_calls: u64,
    /// Windows: `SetProcessWorkingSetSize` calls of the growth path.
    pub set_calls: u64,
    /// Windows: nanoseconds inside them.
    pub set_ns: u64,
    /// Windows: nanoseconds waited for `GROW`, summed.
    pub wait_ns: u64,
    /// Windows: the longest wait for `GROW`.
    pub wait_max_ns: u64,
    /// Windows: nanoseconds `GROW` was held, summed.
    pub hold_ns: u64,
    /// Windows: the longest hold of `GROW`.
    pub hold_max_ns: u64,
    /// Windows: `VirtualUnlock` calls of dropped pages.
    pub unlocks: u64,
    /// Windows: nanoseconds inside them.
    pub unlock_ns: u64,
}

/// The counters now.
#[must_use]
pub fn snapshot() -> LockStats {
    LockStats {
        allocs: get(&ALLOCS),
        frees: get(&FREES),
        locks: get(&LOCKS),
        quota_paths: get(&QUOTA_PATHS),
        failed: get(&FAILED),
        vlock_calls: get(&VLOCK_CALLS),
        vlock_ns: get(&VLOCK_NS),
        sizes_calls: get(&SIZES_CALLS),
        set_calls: get(&SET_CALLS),
        set_ns: get(&SET_NS),
        wait_ns: get(&WAIT_NS),
        wait_max_ns: get(&WAIT_MAX_NS),
        hold_ns: get(&HOLD_NS),
        hold_max_ns: get(&HOLD_MAX_NS),
        unlocks: get(&UNLOCKS),
        unlock_ns: get(&UNLOCK_NS),
    }
}

impl fmt::Display for LockStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "allocs={} frees={} locks={} quota_paths={} failed={} vlock_calls={} vlock_ns={} sizes_calls={} \
             set_calls={} set_ns={} wait_ns={} wait_max_ns={} hold_ns={} hold_max_ns={} unlocks={} unlock_ns={}",
            self.allocs,
            self.frees,
            self.locks,
            self.quota_paths,
            self.failed,
            self.vlock_calls,
            self.vlock_ns,
            self.sizes_calls,
            self.set_calls,
            self.set_ns,
            self.wait_ns,
            self.wait_max_ns,
            self.hold_ns,
            self.hold_max_ns,
            self.unlocks,
            self.unlock_ns
        )
    }
}

/// Totals of the current process (Windows): working-set bounds, CPU time, I/O operations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessStats {
    /// Minimum working set, bytes.
    pub ws_min: usize,
    /// Maximum working set, bytes.
    pub ws_max: usize,
    /// Kernel-mode CPU time of all threads, 100 ns units.
    pub kernel_100ns: u64,
    /// User-mode CPU time of all threads, 100 ns units.
    pub user_100ns: u64,
    /// Read operations (files, pipes, devices).
    pub reads: u64,
    /// Write operations (files, pipes — the captured stderr included —, devices).
    pub writes: u64,
    /// Other I/O operations (e.g. flushes, control calls).
    pub others: u64,
    /// Bytes read.
    pub read_bytes: u64,
    /// Bytes written.
    pub write_bytes: u64,
    /// Bytes of the other operations.
    pub other_bytes: u64,
}

impl fmt::Display for ProcessStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ws_min={} ws_max={} kernel_100ns={} user_100ns={} io_reads={} io_writes={} io_others={} \
             io_read_bytes={} io_write_bytes={} io_other_bytes={}",
            self.ws_min,
            self.ws_max,
            self.kernel_100ns,
            self.user_100ns,
            self.reads,
            self.writes,
            self.others,
            self.read_bytes,
            self.write_bytes,
            self.other_bytes
        )
    }
}

/// The process totals now; `None` off Windows (and under Miri/Kani) or if a query fails.
#[must_use]
pub fn process() -> Option<ProcessStats> {
    #[cfg(all(windows, not(any(miri, kani))))]
    {
        crate::secret_page::process_stats()
    }
    #[cfg(not(all(windows, not(any(miri, kani)))))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The counters move with allocations and drops on every backend.
    #[test]
    fn allocations_and_drops_are_counted() -> Result<(), crate::Error> {
        let before = snapshot();
        let page = crate::SecretPage::<32>::new()?;
        let during = snapshot();
        drop(page);
        let after = snapshot();
        assert!(during.allocs > before.allocs);
        assert!(after.frees > during.frees);
        assert_eq!(
            process().is_some(),
            cfg!(all(windows, not(any(miri, kani))))
        );
        Ok(())
    }

    #[test]
    fn raise_keeps_the_maximum_and_nanos_saturate() {
        let c = AtomicU64::new(5);
        raise(&c, 3);
        assert_eq!(get(&c), 5);
        raise(&c, 9);
        assert_eq!(get(&c), 9);
        add(&c, 2);
        assert_eq!(get(&c), 11);
        assert_eq!(nanos(Duration::from_micros(3)), 3_000);
        assert_eq!(nanos(Duration::MAX), u64::MAX);
    }
}
