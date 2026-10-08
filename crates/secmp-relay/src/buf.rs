// SPDX-License-Identifier: AGPL-3.0-or-later
//! The buffers the stores keep (spec §9.7 item 5 "Zeroize cell buffers on delete"): a stored cell ([`CellBuf`]) and
//! a stored link-data blob ([`BlobBuf`]). Both wipe their bytes when dropped, and every delete path of the stores
//! (acknowledgement, eviction, `QUEUE_DEL`, the TTLs, consumption, link-data expiry) drops them at once.
//!
//! Feature `kat` adds a per-thread count of the live buffers (test RL-10): the relay runs a command on the calling
//! thread, so a test sees exactly its own buffers.

use secmp_crypto::{Zeroize, ZeroizeOnDrop, Zeroizing};
use secmp_proto::sizes::{CELL_LEN, LINK_BLOB_LEN};

#[cfg(feature = "kat")]
mod live {
    use std::cell::Cell;

    std::thread_local! {
        static LIVE: Cell<u64> = const { Cell::new(0) };
    }

    pub(super) fn inc() {
        LIVE.with(|c| c.set(c.get().saturating_add(1)));
    }

    pub(super) fn dec() {
        LIVE.with(|c| c.set(c.get().saturating_sub(1)));
    }

    pub(super) fn get() -> u64 {
        LIVE.with(Cell::get)
    }
}

#[cfg(not(feature = "kat"))]
mod live {
    pub(super) const fn inc() {}
    pub(super) const fn dec() {}
}

/// The number of live [`CellBuf`] and [`BlobBuf`] values of this thread (feature `kat`, tests only).
#[cfg(feature = "kat")]
#[must_use]
pub fn live_buffers_kat() -> u64 {
    live::get()
}

/// A stored cell, 4096 B, wiped on drop.
pub struct CellBuf(Box<[u8; CELL_LEN]>);

impl CellBuf {
    /// Keep `cell` (the allocation of the decoded request, not a copy: `Cell::into_boxed`).
    #[must_use]
    pub fn new(cell: Box<[u8; CELL_LEN]>) -> Self {
        live::inc();
        Self(cell)
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; CELL_LEN] {
        &self.0
    }
}

impl Drop for CellBuf {
    fn drop(&mut self) {
        self.0.zeroize();
        live::dec();
    }
}

impl ZeroizeOnDrop for CellBuf {}

/// A stored link-data blob, 12360 B, wiped on drop.
pub struct BlobBuf(Zeroizing<Vec<u8>>);

/// A blob of another length than 12360 B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrongLength;

impl BlobBuf {
    /// Keep `blob` (the assembler's zeroizing buffer, not a copy).
    ///
    /// # Errors
    /// [`WrongLength`] unless `blob` is 12360 bytes (the `LINK_PUT` assembler guarantees it).
    pub fn new(blob: Zeroizing<Vec<u8>>) -> Result<Self, WrongLength> {
        if blob.len() != LINK_BLOB_LEN {
            return Err(WrongLength);
        }
        live::inc();
        Ok(Self(blob))
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for BlobBuf {
    fn drop(&mut self) {
        // the Zeroizing field wipes the bytes after this
        live::dec();
    }
}

impl ZeroizeOnDrop for BlobBuf {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffers_keep_their_bytes() -> Result<(), WrongLength> {
        let c = CellBuf::new(Box::new([7; CELL_LEN]));
        assert_eq!(c.as_bytes().first(), Some(&7));
        let b = BlobBuf::new(Zeroizing::new(vec![9; LINK_BLOB_LEN]))?;
        assert_eq!(b.as_bytes().len(), LINK_BLOB_LEN);
        assert!(BlobBuf::new(Zeroizing::new(vec![0; 3])).is_err());
        Ok(())
    }

    #[cfg(feature = "kat")]
    #[test]
    fn the_live_count_follows_the_buffers() -> Result<(), WrongLength> {
        let before = live_buffers_kat();
        let c = CellBuf::new(Box::new([0; CELL_LEN]));
        let b = BlobBuf::new(Zeroizing::new(vec![0; LINK_BLOB_LEN]))?;
        assert_eq!(live_buffers_kat(), before.saturating_add(2));
        drop(c);
        assert_eq!(live_buffers_kat(), before.saturating_add(1));
        drop(b);
        assert_eq!(live_buffers_kat(), before);
        Ok(())
    }
}
