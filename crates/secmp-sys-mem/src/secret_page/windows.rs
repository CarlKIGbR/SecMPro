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

use windows_sys::Win32::Foundation::{ERROR_WORKING_SET_QUOTA, GetLastError};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    VirtualAlloc, VirtualFree, VirtualLock, VirtualProtect, VirtualUnlock,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessWorkingSetSize, SetProcessWorkingSetSize,
};

use super::grow::{Growth, LockError, lock_with_growth};
use super::{Backend, Error};

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
            // SAFETY: unlocks the data page that `new` locked.
            let _ = unsafe { VirtualUnlock(self.data().cast::<c_void>().cast_const(), self.page) };
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
    // A panic of another holder leaves nothing inconsistent: `GROW` guards no data and every step re-reads the sizes.
    let _serial = GROW.lock().unwrap_or_else(PoisonError::into_inner);
    // SAFETY: returns the pseudo-handle of the current process; no preconditions.
    let process = unsafe { GetCurrentProcess() };
    lock_with_growth(
        || {
            // SAFETY: locks the committed read-write data page of our own allocation; its contents are not accessed.
            if unsafe { VirtualLock(data, page) } != 0 {
                return Ok(());
            }
            // SAFETY: reads the calling thread's last-error value, right after the failed call; no preconditions.
            if unsafe { GetLastError() } == ERROR_WORKING_SET_QUOTA {
                Err(LockError::Quota)
            } else {
                Err(LockError::Other)
            }
        },
        || {
            let (mut min, mut max) = (0_usize, 0_usize);
            // SAFETY: the current-process pseudo-handle has full access; `min` and `max` are valid out-pointers.
            if unsafe { GetProcessWorkingSetSize(process, &raw mut min, &raw mut max) } == 0 {
                return Err(Error::new());
            }
            Ok((min, max))
        },
        |min, max| {
            // SAFETY: the current-process pseudo-handle has `PROCESS_SET_QUOTA`; `lock_with_growth` only raises both
            // sizes, the minimum at most to its cap.
            if unsafe { SetProcessWorkingSetSize(process, min, max) } == 0 {
                Err(Error::new())
            } else {
                Ok(())
            }
        },
        growth,
    )
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
}
