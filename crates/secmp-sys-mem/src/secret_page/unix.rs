// SPDX-License-Identifier: AGPL-3.0-or-later
//! Unix backend of `SecretPage` (docs/04 CS-2.2): one `mmap` reservation of three pages with `PROT_NONE`; the
//! middle (data) page becomes `memfd_secret` memory (Linux) or is made read-write and `mlock`ed.

use core::ptr::{self, NonNull};

use super::{Backend, Error};

/// The system page size.
pub(super) fn page_size() -> Result<usize, Error> {
    // SAFETY: `sysconf` has no preconditions and `_SC_PAGESIZE` is a valid name.
    let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(raw)
        .ok()
        .filter(|p| p.is_power_of_two())
        .ok_or(Error::new())
}

/// An owned file descriptor, closed on drop.
#[cfg(any(target_os = "linux", test))]
struct Fd(libc::c_int);

#[cfg(any(target_os = "linux", test))]
impl Drop for Fd {
    fn drop(&mut self) {
        // SAFETY: closes a descriptor that this value owns exclusively; it is not used afterwards.
        let _ = unsafe { libc::close(self.0) };
    }
}

/// The reservation `[guard | data | guard]`, owned exclusively.
pub(super) struct Mapping {
    base: NonNull<u8>,
    page: usize,
    total: usize,
    backend: Backend,
}

// SAFETY: `Mapping` owns its pages exclusively, like a `Box`; nothing in it is bound to the creating thread
// (mappings and memory locks are process-wide), so it may be moved to another thread.
unsafe impl Send for Mapping {}
// SAFETY: through `&Mapping` (and `&SecretPage`) the data page is only read; writing needs `&mut`.
unsafe impl Sync for Mapping {}

impl Mapping {
    pub(super) fn new(page: usize, allow_secretmem: bool) -> Result<Self, Error> {
        let total = page.checked_mul(3).ok_or(Error::new())?;
        // SAFETY: creates a new private anonymous mapping at an address chosen by the kernel; it cannot overlap
        // any memory this process already uses.
        let raw = unsafe {
            libc::mmap(
                ptr::null_mut(),
                total,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(Error::new());
        }
        let base = NonNull::new(raw.cast::<u8>()).ok_or(Error::new())?;
        // From here on, dropping `map` releases the whole reservation on every early return.
        let map = Self {
            base,
            page,
            total,
            backend: Backend::Mlock,
        };
        #[cfg(target_os = "linux")]
        if allow_secretmem && let Some(fd) = linux::secretmem_fd(page) {
            linux::map_secretmem(map.data(), page, &fd)?;
            return Ok(map.with_backend(Backend::MemfdSecret));
        }
        #[cfg(not(target_os = "linux"))]
        let _ = allow_secretmem;
        map.protect_and_lock()?;
        Ok(map)
    }

    /// Fallback data page: read-write, locked, and on Linux excluded from core dumps and wiped in `fork`
    /// children.
    fn protect_and_lock(&self) -> Result<(), Error> {
        let data = self.data().cast::<libc::c_void>();
        // SAFETY: changes the protection of the data page of our own reservation only.
        if unsafe { libc::mprotect(data, self.page, libc::PROT_READ | libc::PROT_WRITE) } != 0 {
            return Err(Error::new());
        }
        // SAFETY: locks the data page of our own reservation into RAM; `mlock` does not access its contents.
        if unsafe { libc::mlock(data, self.page) } != 0 {
            return Err(Error::new());
        }
        #[cfg(target_os = "linux")]
        {
            linux::advise(self.data(), self.page, libc::MADV_DONTDUMP)?;
            linux::advise(self.data(), self.page, libc::MADV_WIPEONFORK)?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn with_backend(mut self, backend: Backend) -> Self {
        self.backend = backend;
        self
    }

    /// Start of the data page.
    pub(super) fn data(&self) -> *mut u8 {
        self.base.as_ptr().wrapping_add(self.page)
    }

    pub(super) fn backend(&self) -> Backend {
        self.backend
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        if self.backend == Backend::Mlock {
            // SAFETY: unlocks the data page of our own reservation (harmless if it was never locked).
            let _ = unsafe { libc::munlock(self.data().cast::<libc::c_void>(), self.page) };
        }
        // SAFETY: releases exactly the reservation created in `new`, which `self` owns; `SecretPage` hands out
        // references only for the duration of a borrow of itself, so none outlives this call.
        let _ = unsafe { libc::munmap(self.base.as_ptr().cast::<libc::c_void>(), self.total) };
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Error, Fd};

    /// A `memfd_secret(2)` descriptor sized to one page, or `None` if the kernel does not provide one (no
    /// syscall before 5.14, disabled with `secretmem.enable=0`, or a resource limit).
    pub(super) fn secretmem_fd(page: usize) -> Option<Fd> {
        // SAFETY: `memfd_secret` takes one flags argument and returns a new descriptor or -1; it does not access
        // this process's memory.
        let ret = unsafe { libc::syscall(libc::SYS_memfd_secret, libc::O_CLOEXEC) };
        let fd = Fd(libc::c_int::try_from(ret).ok().filter(|fd| *fd >= 0)?);
        let len = libc::off_t::try_from(page).ok()?;
        // SAFETY: `fd.0` is a valid descriptor owned by `fd`.
        if unsafe { libc::ftruncate(fd.0, len) } != 0 {
            return None;
        }
        Some(fd)
    }

    /// Map the secret memory over the data page (`MAP_FIXED` replaces exactly that page of the reservation) and
    /// keep it out of `fork` children (`MADV_DONTFORK`; the kernel already marks it locked and not dumpable).
    pub(super) fn map_secretmem(data: *mut u8, page: usize, fd: &Fd) -> Result<(), Error> {
        // SAFETY: `MAP_FIXED` at `data` replaces exactly the data page of the caller's own reservation, never
        // memory owned by anything else; `fd` is a valid `memfd_secret` descriptor of size `page`.
        let raw = unsafe {
            libc::mmap(
                data.cast::<libc::c_void>(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd.0,
                0,
            )
        };
        if raw != data.cast::<libc::c_void>() {
            return Err(Error::new());
        }
        advise(data, page, libc::MADV_DONTFORK)
    }

    pub(super) fn advise(data: *mut u8, page: usize, advice: libc::c_int) -> Result<(), Error> {
        // SAFETY: advice for the data page of the caller's own reservation; `MADV_DONTDUMP`, `MADV_WIPEONFORK`
        // and `MADV_DONTFORK` do not change the page contents in this process.
        if unsafe { libc::madvise(data.cast::<libc::c_void>(), page, advice) } == 0 {
            Ok(())
        } else {
            Err(Error::new())
        }
    }
}

/// Whether one byte at `addr` is readable, asked of the kernel: `write(2)` into a pipe fails with `EFAULT` instead
/// of faulting when the source is inaccessible.
#[cfg(test)]
pub(super) fn probe_readable(addr: *const u8) -> bool {
    let mut fds: [libc::c_int; 2] = [-1; 2];
    // SAFETY: `pipe` writes two descriptors into the provided array of two `c_int`.
    let ok = unsafe { libc::pipe(fds.as_mut_ptr()) } == 0;
    assert!(ok, "pipe(2) failed");
    let [r, w] = fds;
    let (_r, w) = (Fd(r), Fd(w));
    // SAFETY: `write` reads at most one byte at `addr`; the kernel validates the access and returns EFAULT
    // rather than faulting if the page is not readable.
    let n = unsafe { libc::write(w.0, addr.cast::<libc::c_void>(), 1) };
    n == 1
}

/// Linux: the kernel's view of the data page (`VmFlags` of its VMA in `/proc/self/smaps`): locked (`lo`) and
/// excluded from core dumps (`dd`) for both backends, plus wiped on fork (`wf`) for `mlock` or not inherited
/// (`dc`) for `memfd_secret`. Other Unix systems (the macOS development host) have no such interface; `mlock`
/// succeeding is the evidence there.
#[cfg(test)]
pub(super) fn assert_protected(data: *mut u8, backend: Backend) {
    #[cfg(target_os = "linux")]
    {
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap_or_default();
        let head = format!("{:x}-", data.addr());
        // the VMA's header line, then its `Key: value` lines up to the next header
        let block: Vec<&str> = smaps
            .lines()
            .skip_while(|l| !l.starts_with(&head))
            .take_while(|l| {
                l.starts_with(&head)
                    || l.split_whitespace()
                        .next()
                        .is_some_and(|t| t.ends_with(':'))
            })
            .collect();
        assert!(!block.is_empty(), "no VMA at {head} in /proc/self/smaps");
        let flags = block
            .iter()
            .find_map(|l| l.strip_prefix("VmFlags:"))
            .unwrap_or_default();
        let want: &[&str] = match backend {
            Backend::MemfdSecret => &["lo", "dd", "dc"],
            _ => &["lo", "dd", "wf"],
        };
        for f in want {
            assert!(
                flags.split_whitespace().any(|x| x == *f),
                "{backend:?}: VmFlags {flags:?} lacks {f}"
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = data;
        assert_eq!(backend, Backend::Mlock);
    }
}
