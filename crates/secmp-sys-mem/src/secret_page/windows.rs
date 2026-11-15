// SPDX-License-Identifier: AGPL-3.0-or-later
//! Windows backend of `SecretPage` (docs/04 CS-2.2): one `VirtualAlloc` allocation of three `PAGE_NOACCESS`
//! pages; the middle (data) page is made read-write and `VirtualLock`ed. When the lock quota (the minimum working
//! set) is exhausted, the working set is enlarged once and the lock retried.

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::{self, NonNull};

use windows_sys::Win32::Foundation::{ERROR_WORKING_SET_QUOTA, GetLastError};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    VirtualAlloc, VirtualFree, VirtualLock, VirtualProtect, VirtualUnlock,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessWorkingSetSize, SetProcessWorkingSetSize,
};

use super::{Backend, Error};

/// Pages added to the working-set minimum and maximum when `VirtualLock` runs out of quota.
const WORKING_SET_STEP_PAGES: usize = 64;

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

/// Lock the data page; on `ERROR_WORKING_SET_QUOTA` enlarge the working set once and retry.
fn lock(data: *const c_void, page: usize) -> Result<(), Error> {
    // SAFETY: locks the committed read-write data page of our own allocation; its contents are not accessed.
    if unsafe { VirtualLock(data, page) } != 0 {
        return Ok(());
    }
    // SAFETY: reads the calling thread's last-error value; no preconditions.
    if unsafe { GetLastError() } != ERROR_WORKING_SET_QUOTA {
        return Err(Error::new());
    }
    grow_working_set(page)?;
    // SAFETY: as above.
    if unsafe { VirtualLock(data, page) } != 0 {
        Ok(())
    } else {
        Err(Error::new())
    }
}

/// Raise the working-set minimum and maximum of this process by `WORKING_SET_STEP_PAGES` pages (the number of
/// lockable pages is bounded by the minimum working set).
fn grow_working_set(page: usize) -> Result<(), Error> {
    let step = page
        .checked_mul(WORKING_SET_STEP_PAGES)
        .ok_or(Error::new())?;
    // SAFETY: returns the pseudo-handle of the current process; no preconditions.
    let process = unsafe { GetCurrentProcess() };
    let (mut min, mut max) = (0_usize, 0_usize);
    // SAFETY: the current-process pseudo-handle has full access; `min` and `max` are valid out-pointers.
    if unsafe { GetProcessWorkingSetSize(process, &raw mut min, &raw mut max) } == 0 {
        return Err(Error::new());
    }
    let min = min.checked_add(step).ok_or(Error::new())?;
    let max = max.checked_add(step).ok_or(Error::new())?;
    // SAFETY: the current-process pseudo-handle has `PROCESS_SET_QUOTA`; both sizes grow.
    if unsafe { SetProcessWorkingSetSize(process, min, max) } == 0 {
        return Err(Error::new());
    }
    Ok(())
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
