// SPDX-License-Identifier: AGPL-3.0-or-later
//! Windows backend of `SecretPage` (docs/04 CS-2.2): one `VirtualAlloc` allocation of three `PAGE_NOACCESS`
//! pages; the middle (data) page is made read-write and `VirtualLock`ed. When the lock quota (the minimum working
//! set) is exhausted, the working set is enlarged in doubling steps up to a bound and the lock retried after each
//! (`grow::lock_with_growth`); every lock and every enlargement of this crate runs under one process-wide lock
//! (ADR-061).

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::{self, NonNull};
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use windows_sys::Win32::Foundation::{ERROR_WORKING_SET_QUOTA, FILETIME, GetLastError};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    VirtualAlloc, VirtualFree, VirtualLock, VirtualProtect, VirtualUnlock,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessIoCounters, GetProcessTimes, GetProcessWorkingSetSize,
    IO_COUNTERS, SetProcessWorkingSetSize,
};

use super::grow::{Growth, LockError, lock_with_growth};
use super::{Backend, Error};
use crate::diag;

/// Serialises every `VirtualLock` of a data page and every working-set change of this crate, so that a step one
/// thread takes cannot be lost to another thread's read-modify-write of the sizes. It guards no data.
static GROW: Mutex<()> = Mutex::new(());

/// The system page size.
pub(super) fn page_size() -> Result<usize, Error> {
    let mut info = MaybeUninit::<SYSTEM_INFO>::zeroed();
    // SAFETY: `GetSystemInfo` fills the `SYSTEM_INFO` it is given and has no other preconditions.
    unsafe { GetSystemInfo(info.as_mut_ptr()) };
    // SAFETY: the structure is plain data, was zero-initialised (a valid value) and then filled.
    let info = unsafe { info.assume_init() };
    usize::try_from(info.dwPageSize)
        .ok()
        .filter(|p| p.is_power_of_two())
        .ok_or(Error::new())
}

/// The allocation `[guard | data | guard]`, owned exclusively.
pub(super) struct Mapping {
    base: NonNull<u8>,
    page: usize,
    locked: bool,
}

// SAFETY: `Mapping` owns its pages exclusively, like a `Box`; nothing in it is bound to the creating thread
// (allocations and page locks are process-wide), so it may be moved to another thread.
unsafe impl Send for Mapping {}
// SAFETY: through `&Mapping` (and `&SecretPage`) the data page is only read; writing needs `&mut`.
unsafe impl Sync for Mapping {}

impl Mapping {
    pub(super) fn new(page: usize, _allow_secretmem: bool) -> Result<Self, Error> {
        let total = page.checked_mul(3).ok_or(Error::new())?;
        // SAFETY: reserves and commits new pages at an address chosen by the system; no existing memory is
        // affected.
        let raw =
            unsafe { VirtualAlloc(ptr::null(), total, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS) };
        let base = NonNull::new(raw.cast::<u8>()).ok_or(Error::new())?;
        // From here on, dropping `map` releases the whole allocation on every early return.
        let mut map = Self {
            base,
            page,
            locked: false,
        };
        let data = map.data().cast::<c_void>().cast_const();
        let mut old: PAGE_PROTECTION_FLAGS = 0;
        // SAFETY: changes the protection of the data page of our own allocation; `old` is a valid out-pointer.
        if unsafe { VirtualProtect(data, page, PAGE_READWRITE, &raw mut old) } == 0 {
            return Err(Error::new());
        }
        lock(data, page)?;
        map.locked = true;
        Ok(map)
    }

    /// Start of the data page.
    pub(super) fn data(&self) -> *mut u8 {
        self.base.as_ptr().wrapping_add(self.page)
    }

    pub(super) fn backend(&self) -> Backend {
        let _ = self;
        Backend::VirtualLock
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        if self.locked {
            let started = Instant::now();
            // SAFETY: unlocks the data page that `new` locked.
            let _ = unsafe { VirtualUnlock(self.data().cast::<c_void>().cast_const(), self.page) };
            diag::add(&diag::UNLOCK_NS, diag::nanos(started.elapsed()));
            diag::add(&diag::UNLOCKS, 1);
        }
        // SAFETY: releases the whole allocation made by `VirtualAlloc` in `new` (`MEM_RELEASE` requires size 0);
        // `self` owns it and `SecretPage` hands out references only for the duration of a borrow of itself.
        let _ = unsafe { VirtualFree(self.base.as_ptr().cast::<c_void>(), 0, MEM_RELEASE) };
    }
}

/// Lock the data page; on `ERROR_WORKING_SET_QUOTA` enlarge the working set in bounded steps and retry
/// (`grow::lock_with_growth`), all under [`GROW`].
fn lock(data: *const c_void, page: usize) -> Result<(), Error> {
    let growth = Growth::working_set(page)?;
    diag::add(&diag::LOCKS, 1);
    let asked = Instant::now();
    // A panic of another holder leaves nothing inconsistent: `GROW` guards no data and every step re-reads the sizes.
    let _serial = GROW.lock().unwrap_or_else(PoisonError::into_inner);
    let held = Instant::now();
    let waited = diag::nanos(held.saturating_duration_since(asked));
    diag::add(&diag::WAIT_NS, waited);
    diag::raise(&diag::WAIT_MAX_NS, waited);
    // SAFETY: returns the pseudo-handle of the current process; no preconditions.
    let process = unsafe { GetCurrentProcess() };
    let mut first = true;
    let locked = lock_with_growth(
        || {
            let started = Instant::now();
            // SAFETY: locks the committed read-write data page of our own allocation; its contents are not accessed.
            let ok = unsafe { VirtualLock(data, page) } != 0;
            // SAFETY: reads the calling thread's last-error value, right after the call; no preconditions.
            let quota = !ok && unsafe { GetLastError() } == ERROR_WORKING_SET_QUOTA;
            diag::add(&diag::VLOCK_NS, diag::nanos(started.elapsed()));
            diag::add(&diag::VLOCK_CALLS, 1);
            if first && quota {
                diag::add(&diag::QUOTA_PATHS, 1);
            }
            first = false;
            if ok {
                Ok(())
            } else if quota {
                Err(LockError::Quota)
            } else {
                Err(LockError::Other)
            }
        },
        || {
            diag::add(&diag::SIZES_CALLS, 1);
            let (mut min, mut max) = (0_usize, 0_usize);
            // SAFETY: the current-process pseudo-handle has full access; `min` and `max` are valid out-pointers.
            if unsafe { GetProcessWorkingSetSize(process, &raw mut min, &raw mut max) } == 0 {
                return Err(Error::new());
            }
            Ok((min, max))
        },
        |min, max| {
            let started = Instant::now();
            // SAFETY: the current-process pseudo-handle has `PROCESS_SET_QUOTA`; `lock_with_growth` only raises both
            // sizes, the minimum at most to its cap.
            let ok = unsafe { SetProcessWorkingSetSize(process, min, max) } != 0;
            diag::add(&diag::SET_NS, diag::nanos(started.elapsed()));
            diag::add(&diag::SET_CALLS, 1);
            if ok { Ok(()) } else { Err(Error::new()) }
        },
        growth,
    );
    let held_ns = diag::nanos(held.elapsed());
    diag::add(&diag::HOLD_NS, held_ns);
    diag::raise(&diag::HOLD_MAX_NS, held_ns);
    if locked.is_err() {
        diag::add(&diag::FAILED, 1);
    }
    locked
}

/// WIN2-DIAG (D-CI14): the working-set bounds, CPU times and I/O counters of the current process; `None` if a query
/// fails.
pub(crate) fn process_stats() -> Option<diag::ProcessStats> {
    // SAFETY: returns the pseudo-handle of the current process; no preconditions.
    let process = unsafe { GetCurrentProcess() };
    let (mut ws_min, mut ws_max) = (0_usize, 0_usize);
    // SAFETY: the current-process pseudo-handle has full access; both are valid out-pointers.
    if unsafe { GetProcessWorkingSetSize(process, &raw mut ws_min, &raw mut ws_max) } == 0 {
        return None;
    }
    let (mut created, mut exited) = (FILETIME::default(), FILETIME::default());
    let (mut kernel, mut user) = (FILETIME::default(), FILETIME::default());
    // SAFETY: the current-process pseudo-handle has full access; the four are valid out-pointers.
    let timed = unsafe {
        GetProcessTimes(
            process,
            &raw mut created,
            &raw mut exited,
            &raw mut kernel,
            &raw mut user,
        )
    };
    if timed == 0 {
        return None;
    }
    let mut io = IO_COUNTERS::default();
    // SAFETY: the current-process pseudo-handle has full access; `io` is a valid out-pointer.
    if unsafe { GetProcessIoCounters(process, &raw mut io) } == 0 {
        return None;
    }
    Some(diag::ProcessStats {
        ws_min,
        ws_max,
        kernel_100ns: ticks(kernel),
        user_100ns: ticks(user),
        reads: io.ReadOperationCount,
        writes: io.WriteOperationCount,
        others: io.OtherOperationCount,
        read_bytes: io.ReadTransferCount,
        write_bytes: io.WriteTransferCount,
        other_bytes: io.OtherTransferCount,
    })
}

/// A `FILETIME` as one count of 100 ns units.
fn ticks(t: FILETIME) -> u64 {
    u64::from(t.dwHighDateTime).checked_shl(32).unwrap_or(0) | u64::from(t.dwLowDateTime)
}

#[cfg(test)]
fn query(addr: *const u8) -> windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION {
    use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery};
    let mut mbi = MaybeUninit::<MEMORY_BASIC_INFORMATION>::zeroed();
    // SAFETY: `VirtualQuery` writes at most `size_of::<MEMORY_BASIC_INFORMATION>()` bytes into `mbi`.
    let n = unsafe {
        VirtualQuery(
            addr.cast::<c_void>(),
            mbi.as_mut_ptr(),
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    assert_eq!(
        n,
        size_of::<MEMORY_BASIC_INFORMATION>(),
        "VirtualQuery failed"
    );
    // SAFETY: plain data, zero-initialised and filled by `VirtualQuery`.
    unsafe { mbi.assume_init() }
}

/// Whether the page at `addr` is readable, per `VirtualQuery`.
#[cfg(test)]
pub(super) fn probe_readable(addr: *const u8) -> bool {
    let m = query(addr);
    m.State == MEM_COMMIT && m.Protect == PAGE_READWRITE
}

/// The data page is committed and read-write; the lock itself is evidenced by `VirtualLock` succeeding.
#[cfg(test)]
pub(super) fn assert_protected(data: *mut u8, backend: Backend) {
    let m = query(data.cast_const());
    assert_eq!(m.State, MEM_COMMIT);
    assert_eq!(m.Protect, PAGE_READWRITE);
    assert_eq!(backend, Backend::VirtualLock);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::Duration;

    use super::super::SecretPage;
    use super::*;

    /// 8 threads lock 64 pages each at once, far more than the default minimum working set lets a process lock (about
    /// 50 pages): every lock succeeds through the bounded growth, and every page is released afterwards.
    #[test]
    fn concurrent_locks_beyond_the_default_quota_all_succeed() -> Result<(), Error> {
        let start = Arc::new(std::sync::Barrier::new(8));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let start = Arc::clone(&start);
            workers.push(thread::spawn(move || -> Result<Vec<usize>, Error> {
                start.wait();
                let mut pages = Vec::new();
                for i in 0..64_u8 {
                    let mut p = SecretPage::<32>::new()?;
                    p.get_mut().fill(i);
                    pages.push(p);
                }
                for (i, p) in (0..64_u8).zip(&pages) {
                    assert!(p.get().iter().all(|b| *b == i));
                    assert_protected(p.map.data(), p.backend());
                }
                let released = pages.iter().map(|p| p.map.data().addr()).collect();
                // The lock evidence: `VirtualUnlock` succeeds only on a locked page (it leaves each page unlocked
                // until its drop, whose own `VirtualUnlock` then fails and is ignored).
                for p in &pages {
                    assert!(unlocks(p.map.data(), p.map.page), "page was not locked");
                }
                Ok(released)
            }));
        }
        let mut released = Vec::new();
        for w in workers {
            released.extend(w.join().map_err(|_| Error::new())??);
        }
        assert_eq!(released.len(), 512);
        for addr in released {
            assert_eq!(
                query(ptr::without_provenance(addr)).State,
                windows_sys::Win32::System::Memory::MEM_FREE,
                "page released"
            );
        }
        Ok(())
    }

    /// Whether `VirtualUnlock` of the page at `data` succeeds, i.e. whether it was locked.
    fn unlocks(data: *mut u8, page: usize) -> bool {
        // SAFETY: unlocks a data page of a live `SecretPage` of this test; its contents are not accessed, and the
        // page stays committed and read-write until the `SecretPage` is dropped.
        unsafe { VirtualUnlock(data.cast::<c_void>().cast_const(), page) != 0 }
    }

    /// Every lock of a data page waits for [`GROW`]: while the test holds it, an allocation on another thread does not
    /// complete; once it is released, the allocation succeeds. No assertion on time: the wait only gives a lock that
    /// bypassed `GROW` the chance to show itself.
    #[test]
    fn every_lock_waits_for_the_growth_lock() -> Result<(), Error> {
        let done = Arc::new(AtomicBool::new(false));
        let (started, wait_started) = mpsc::channel();
        let held = GROW.lock().unwrap_or_else(PoisonError::into_inner);
        let worker = {
            let done = Arc::clone(&done);
            thread::spawn(move || -> Result<(), Error> {
                started.send(()).map_err(|_| Error::new())?;
                let p = SecretPage::<32>::new()?;
                done.store(true, Ordering::SeqCst);
                drop(p);
                Ok(())
            })
        };
        wait_started.recv().map_err(|_| Error::new())?;
        thread::sleep(Duration::from_millis(200));
        assert!(
            !done.load(Ordering::SeqCst),
            "a page was locked while GROW was held"
        );
        drop(held);
        worker.join().map_err(|_| Error::new())??;
        assert!(done.load(Ordering::SeqCst));
        Ok(())
    }

    /// Bytes of one simulated `SQLite` allocation: four share a 4 KiB page, as small heap blocks do.
    const W2_CHUNK: usize = 1024;
    /// The simulated heap: 8 MiB.
    const W2_HEAP: usize = 8_388_608;
    /// Passes over the simulated heap per regime.
    const W2_ROUNDS: u8 = 4;
    /// The headroom of the second regime: 64 MiB more minimum (and maximum) working set.
    const W2_HEADROOM: usize = 67_108_864;

    /// One regime's totals.
    #[derive(Debug, Default)]
    struct W2Pass {
        lock_ok: u64,
        lock_quota: u64,
        lock_other: u64,
        lock_ns: u64,
        touch_ns: u64,
        unlock_ok: u64,
        unlock_failed: u64,
        unlock_ns: u64,
    }

    /// `SQLCipher`'s `cipher_memory_security` pattern on a simulated heap: per block `VirtualLock`, a write (the use), then
    /// per block `VirtualUnlock` (on Windows a second unlock of a page already unlocked by a neighbour fails and, per
    /// the documentation, removes the page from the working set, so the next write faults it back).
    fn w2_pass(heap: &mut [u8]) -> W2Pass {
        let mut pass = W2Pass::default();
        for round in 0..W2_ROUNDS {
            for chunk in heap.chunks_mut(W2_CHUNK) {
                let started = Instant::now();
                // SAFETY: locks bytes of a live heap buffer of this test; its contents are not accessed by the call.
                let ok = unsafe { VirtualLock(chunk.as_ptr().cast::<c_void>(), chunk.len()) } != 0;
                // SAFETY: reads the calling thread's last-error value, right after the call; no preconditions.
                let quota = !ok && unsafe { GetLastError() } == ERROR_WORKING_SET_QUOTA;
                pass.lock_ns = pass.lock_ns.saturating_add(diag::nanos(started.elapsed()));
                match (ok, quota) {
                    (true, _) => pass.lock_ok = pass.lock_ok.saturating_add(1),
                    (false, true) => pass.lock_quota = pass.lock_quota.saturating_add(1),
                    (false, false) => pass.lock_other = pass.lock_other.saturating_add(1),
                }
            }
            let started = Instant::now();
            heap.fill(round);
            pass.touch_ns = pass.touch_ns.saturating_add(diag::nanos(started.elapsed()));
            for chunk in heap.chunks_mut(W2_CHUNK) {
                let started = Instant::now();
                // SAFETY: unlocks bytes of a live heap buffer of this test; its contents are not accessed by the call.
                let ok =
                    unsafe { VirtualUnlock(chunk.as_ptr().cast::<c_void>(), chunk.len()) } != 0;
                pass.unlock_ns = pass
                    .unlock_ns
                    .saturating_add(diag::nanos(started.elapsed()));
                if ok {
                    pass.unlock_ok = pass.unlock_ok.saturating_add(1);
                } else {
                    pass.unlock_failed = pass.unlock_failed.saturating_add(1);
                }
            }
            // the reuse after the frees: a write to every block
            let started = Instant::now();
            heap.fill(round.wrapping_add(1));
            pass.touch_ns = pass.touch_ns.saturating_add(diag::nanos(started.elapsed()));
        }
        pass
    }

    /// WIN2-DIAG SE-130 (D-CI14): the cost per block of the pattern above, first with the process's default working
    /// set (most locks fail with the quota error, as `SQLCipher`'s did before the working set grew), then with 64 MiB
    /// more minimum working set (every lock succeeds). No assertion on the numbers: one `W2DIAG-BENCH` line per regime
    /// on stdout, shown in a green run by the `.config/nextest.toml` override of this unit.
    #[test]
    fn w2diag_sqlcipher_pattern_cost() -> Result<(), Error> {
        use std::io::Write;

        let mut heap = vec![0_u8; W2_HEAP];
        let mut lines = Vec::new();
        for regime in ["default", "headroom"] {
            if regime == "headroom" {
                // SAFETY: returns the pseudo-handle of the current process; no preconditions.
                let process = unsafe { GetCurrentProcess() };
                let (mut min, mut max) = (0_usize, 0_usize);
                // SAFETY: the current-process pseudo-handle has full access; both are valid out-pointers.
                if unsafe { GetProcessWorkingSetSize(process, &raw mut min, &raw mut max) } == 0 {
                    return Err(Error::new());
                }
                let min = min.checked_add(W2_HEADROOM).ok_or(Error::new())?;
                let max = max.checked_add(W2_HEADROOM).ok_or(Error::new())?;
                // SAFETY: the current-process pseudo-handle has `PROCESS_SET_QUOTA`; both sizes only grow.
                if unsafe { SetProcessWorkingSetSize(process, min, max) } == 0 {
                    return Err(Error::new());
                }
            }
            let before = process_stats().ok_or(Error::new())?;
            let started = Instant::now();
            let pass = w2_pass(&mut heap);
            let wall_ns = diag::nanos(started.elapsed());
            let after = process_stats().ok_or(Error::new())?;
            lines.push(format!(
                "W2DIAG-BENCH regime={regime} blocks_per_round={} rounds={W2_ROUNDS} lock_ok={} lock_quota={} \
                 lock_other={} lock_ns={} touch_ns={} unlock_ok={} unlock_failed={} unlock_ns={} wall_ns={wall_ns} \
                 kernel_100ns={} user_100ns={} ws_min={} ws_max={}\n",
                W2_HEAP.checked_div(W2_CHUNK).unwrap_or(0),
                pass.lock_ok,
                pass.lock_quota,
                pass.lock_other,
                pass.lock_ns,
                pass.touch_ns,
                pass.unlock_ok,
                pass.unlock_failed,
                pass.unlock_ns,
                after.kernel_100ns.saturating_sub(before.kernel_100ns),
                after.user_100ns.saturating_sub(before.user_100ns),
                after.ws_min,
                after.ws_max,
            ));
        }
        let mut out = std::io::stdout().lock();
        for line in lines {
            out.write_all(line.as_bytes()).map_err(|_| Error::new())?;
        }
        out.flush().map_err(|_| Error::new())?;
        Ok(())
    }
}
