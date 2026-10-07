// SPDX-License-Identifier: AGPL-3.0-or-later
//! [`SecretPage`]: a fixed-size secret in its own locked page between two inaccessible guard pages
//! (docs/04 CS-2.2).
//!
//! Layout of one reservation: `[guard page | data page | guard page]`. The guard pages are never accessible, so
//! a linear overflow or underflow out of the data page faults instead of reading or writing neighbouring memory.
//! The data page is kept out of swap and core dumps and is zeroised before it is released:
//!
//! | Platform | Data page |
//! |---|---|
//! | Linux | `memfd_secret(2)` (removed from the kernel direct map, implicitly locked and excluded from core dumps), not inherited across `fork` (`MADV_DONTFORK`); where `memfd_secret` is unavailable, `mlock` + `MADV_DONTDUMP` + `MADV_WIPEONFORK` |
//! | Windows | `VirtualLock` (the working set is enlarged when the lock quota is exhausted) |
//! | macOS (development host) | `mlock` |
//! | Miri, Kani | a heap allocation (verification backends: neither tool executes the operating-system calls) |
//!
//! Failure to obtain protected memory is an error, never a silent downgrade (fail closed, CLAUDE.md §1.5).

use core::fmt;

use zeroize::Zeroize;

#[cfg(any(miri, kani))]
#[path = "secret_page/heap.rs"]
mod os;
#[cfg(all(unix, not(any(miri, kani))))]
#[path = "secret_page/unix.rs"]
mod os;
#[cfg(all(windows, not(any(miri, kani))))]
#[path = "secret_page/windows.rs"]
mod os;

/// The mechanism that protects the data page of a [`SecretPage`] (observable so that tests and the security
/// status of the client can report it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// Linux `memfd_secret(2)`.
    MemfdSecret,
    /// `mmap` + `mlock` (on Linux with `MADV_DONTDUMP` and `MADV_WIPEONFORK`).
    Mlock,
    /// Windows `VirtualAlloc` + `VirtualLock`.
    VirtualLock,
    /// Heap memory, used only when running under Miri or Kani.
    Heap,
}

/// Protected memory could not be obtained (the operating system refused a mapping, a protection change or the
/// lock), or the requested size does not fit in one page. Carries no further detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(());

impl Error {
    pub(crate) const fn new() -> Self {
        Self(())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("protected secret memory is unavailable")
    }
}

impl std::error::Error for Error {}

/// `N` secret bytes in a locked page between two guard pages. The bytes start zeroed and are zeroised when the
/// page is dropped. `N` must not exceed the page size (4 KiB on `x86_64`, 16 KiB on Apple Silicon).
///
/// No `Clone`, no `Debug` of the contents, no comparison: the owner exposes the bytes deliberately through
/// [`SecretPage::get`] / [`SecretPage::get_mut`].
pub struct SecretPage<const N: usize> {
    map: os::Mapping,
}

impl<const N: usize> SecretPage<N> {
    /// Allocate a zeroed, protected page for `N` bytes.
    ///
    /// # Errors
    /// [`Error`] if `N` exceeds the page size or the operating system refuses the mapping, the protection change
    /// or the lock (e.g. `RLIMIT_MEMLOCK` exhausted).
    pub fn new() -> Result<Self, Error> {
        Self::with_options(true)
    }

    /// As [`SecretPage::new`]; `allow_secretmem = false` skips `memfd_secret` so that the `mlock` fallback of
    /// Linux can be tested on kernels that do offer `memfd_secret`.
    fn with_options(allow_secretmem: bool) -> Result<Self, Error> {
        let page = os::page_size()?;
        if N > page {
            return Err(Error::new());
        }
        Ok(Self {
            map: os::Mapping::new(page, allow_secretmem)?,
        })
    }

    /// The mechanism protecting this page.
    #[must_use]
    pub fn backend(&self) -> Backend {
        self.map.backend()
    }

    /// The secret bytes.
    #[must_use]
    pub fn get(&self) -> &[u8; N] {
        // SAFETY: `data()` points to the start of the data page, which is readable and writable for at least
        // `page ≥ N` bytes (checked in `with_options`) for as long as `self.map` lives, and is owned exclusively
        // by `self`; `[u8; N]` has alignment 1; the shared borrow of `self` excludes mutation for the lifetime of
        // the returned reference.
        unsafe { &*self.map.data().cast::<[u8; N]>() }
    }

    /// The secret bytes, mutably.
    #[must_use]
    pub fn get_mut(&mut self) -> &mut [u8; N] {
        // SAFETY: as in `get`; the exclusive borrow of `self` makes this the only reference to the data page for
        // the lifetime of the returned reference.
        unsafe { &mut *self.map.data().cast::<[u8; N]>() }
    }
}

impl<const N: usize> Drop for SecretPage<N> {
    fn drop(&mut self) {
        // Zeroise first; `self.map` is dropped afterwards and unlocks and releases the pages.
        self.get_mut().zeroize();
    }
}

impl<const N: usize> fmt::Debug for SecretPage<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretPage")
            .field("len", &N)
            .field("backend", &self.backend())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn starts_zeroed_and_round_trips() -> Result<(), Error> {
        let mut p = SecretPage::<64>::new()?;
        assert!(p.get().iter().all(|b| *b == 0));
        for (i, b) in p.get_mut().iter_mut().enumerate() {
            *b = u8::try_from(i).map_err(|_| Error::new())?;
        }
        assert_eq!(p.get().first(), Some(&0));
        assert_eq!(p.get().last(), Some(&63));
        Ok(())
    }

    #[test]
    fn full_page_fits_and_larger_is_refused() -> Result<(), Error> {
        // 4096 fits on every platform; the refusal is checked against the real page size.
        let mut p = SecretPage::<4096>::new()?;
        p.get_mut().fill(0xa5);
        assert!(p.get().iter().all(|b| *b == 0xa5));
        assert_eq!(SecretPage::<65537>::new().err(), Some(Error::new()));
        Ok(())
    }

    #[test]
    fn backend_is_the_expected_one() -> Result<(), Error> {
        let p = SecretPage::<32>::new()?;
        let b = p.backend();
        if cfg!(miri) {
            assert_eq!(b, Backend::Heap);
        } else if cfg!(target_os = "linux") {
            assert!(b == Backend::MemfdSecret || b == Backend::Mlock, "{b:?}");
        } else if cfg!(windows) {
            assert_eq!(b, Backend::VirtualLock);
        } else {
            assert_eq!(b, Backend::Mlock);
        }
        let q = SecretPage::<32>::with_options(false)?;
        assert_ne!(q.backend(), Backend::MemfdSecret);
        Ok(())
    }

    /// The heap backend is a verification backend: a build without `cfg(miri)` and `cfg(kani)` — every test and
    /// production build — has the operating-system backend.
    #[test]
    fn heap_backend_only_under_miri_or_kani() -> Result<(), Error> {
        let verification = cfg!(any(miri, kani));
        assert_eq!(
            SecretPage::<32>::new()?.backend() == Backend::Heap,
            verification
        );
        assert_eq!(
            SecretPage::<32>::with_options(false)?.backend() == Backend::Heap,
            verification
        );
        Ok(())
    }

    #[test]
    fn many_pages_are_independent() -> Result<(), Error> {
        let mut pages = Vec::new();
        for i in 0..16_u8 {
            let mut p = SecretPage::<16>::new()?;
            p.get_mut().fill(i);
            pages.push(p);
        }
        for (i, p) in (0..16_u8).zip(&pages) {
            assert!(p.get().iter().all(|b| *b == i));
        }
        Ok(())
    }

    #[test]
    fn debug_shows_no_contents() -> Result<(), Error> {
        let mut p = SecretPage::<4>::new()?;
        p.get_mut().copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let s = format!("{p:?}");
        assert!(s.starts_with("SecretPage { len: 4, backend: "), "{s}");
        // neither the decimal nor the hex form of any byte appears
        for needle in ["222", "173", "190", "239", "dead", "beef", "["] {
            assert!(!s.contains(needle), "{s}");
        }
        assert_eq!(
            Error::new().to_string(),
            "protected secret memory is unavailable"
        );
        Ok(())
    }

    #[test]
    fn is_send_and_sync() {
        assert_send_sync::<SecretPage<32>>();
        assert_send_sync::<Error>();
    }

    #[test]
    fn drop_zeroises_before_release() -> Result<(), Error> {
        let mut p = SecretPage::<32>::new()?;
        p.get_mut().fill(0xff);
        // Run the zeroisation step of `Drop` explicitly and observe it while the page is still mapped.
        p.get_mut().zeroize();
        assert!(p.get().iter().all(|b| *b == 0));
        Ok(())
    }

    /// Operating-system view of the pages: the data page is accessible, both guard pages are not, and the data
    /// page is locked (Linux: `VmFlags` in `/proc/self/smaps`). Not compiled under Miri or Kani, which have no OS.
    #[cfg(not(any(miri, kani)))]
    #[test]
    fn guard_pages_and_locking_as_seen_by_the_os() -> Result<(), Error> {
        let page = os::page_size()?;
        for allow_secretmem in [true, false] {
            let p = SecretPage::<32>::with_options(allow_secretmem)?;
            let data = p.map.data();
            assert!(os::probe_readable(data), "data page must be readable");
            assert!(
                !os::probe_readable(data.wrapping_sub(page)),
                "leading guard page must not be readable"
            );
            assert!(
                !os::probe_readable(data.wrapping_add(page)),
                "trailing guard page must not be readable"
            );
            os::assert_protected(data, p.backend());
        }
        Ok(())
    }
}
