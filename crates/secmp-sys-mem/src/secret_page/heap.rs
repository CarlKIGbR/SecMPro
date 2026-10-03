// SPDX-License-Identifier: AGPL-3.0-or-later
//! Miri and Kani backend of `SecretPage`: a heap allocation of one page. Neither tool executes `mmap`/`mlock`/
//! `VirtualLock`; this backend lets Miri check the safe wrapper (the raw-pointer accessors and zeroisation) and Kani
//! run code that holds secrets (the prekey store). It is compiled only under `cfg(miri)` or `cfg(kani)` and never
//! in a real build.

use core::ptr::{self, NonNull};

use super::{Backend, Error};

/// The page size assumed under Miri and Kani.
const PAGE: usize = 4096;

pub(super) fn page_size() -> Result<usize, Error> {
    Ok(PAGE)
}

/// One heap page, owned exclusively.
pub(super) struct Mapping {
    data: NonNull<u8>,
    len: usize,
}

// SAFETY: `Mapping` owns its allocation exclusively, like the `Box` it came from.
unsafe impl Send for Mapping {}
// SAFETY: through `&Mapping` the allocation is only read; writing needs `&mut`.
unsafe impl Sync for Mapping {}

impl Mapping {
    pub(super) fn new(page: usize, _allow_secretmem: bool) -> Result<Self, Error> {
        let raw = Box::into_raw(vec![0_u8; page].into_boxed_slice());
        let data = NonNull::new(raw.cast::<u8>()).ok_or(Error::new())?;
        Ok(Self { data, len: page })
    }

    pub(super) fn data(&self) -> *mut u8 {
        self.data.as_ptr()
    }

    pub(super) fn backend(&self) -> Backend {
        let _ = self;
        Backend::Heap
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        let slice = ptr::slice_from_raw_parts_mut(self.data.as_ptr(), self.len);
        // SAFETY: `slice` is the pointer and length that `Box::into_raw` returned in `new`; it is released
        // exactly once, here.
        drop(unsafe { Box::from_raw(slice) });
    }
}
