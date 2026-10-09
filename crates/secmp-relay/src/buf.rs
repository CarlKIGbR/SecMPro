// SPDX-License-Identifier: AGPL-3.0-or-later
//! The buffers the stores keep (spec §9.7 item 5 "Zeroize cell buffers on delete"): a stored cell ([`CellBuf`]) and
//! a stored link-data blob ([`BlobBuf`]). Both wipe their bytes when dropped, and every delete path of the stores
//! (acknowledgement, eviction, `QUEUE_DEL`, the TTLs, consumption, link-data expiry) drops them at once. The copy of
//! a stored cell that a `FETCH` or `FETCH_MULTI` response is built from ([`CellCopy`]) wipes on drop as well, and so
//! does every `Cell`, `CONT` and `blob_part` of the frames (M5 review C-4, R-111).
//!
//! Feature `kat` adds a per-thread count of the live buffers and of the dropped response copies (test RL-10): the
//! relay runs a command on the calling thread, so a test sees exactly its own buffers.

use secmp_crypto::{SecretBytes, ZeroizeOnDrop, Zeroizing};
use secmp_proto::sizes::{CELL_LEN, LINK_BLOB_LEN};
use secmp_proto::wire::cell::Cell;

#[cfg(feature = "kat")]
mod live {
    use std::cell::Cell;

    std::thread_local! {
        static LIVE: Cell<u64> = const { Cell::new(0) };
        static COPIES_DROPPED: Cell<u64> = const { Cell::new(0) };
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

    pub(super) fn copy_dropped() {
        COPIES_DROPPED.with(|c| c.set(c.get().saturating_add(1)));
    }

    pub(super) fn copies_dropped() -> u64 {
        COPIES_DROPPED.with(Cell::get)
    }
}

#[cfg(not(feature = "kat"))]
mod live {
    pub(super) const fn inc() {}
    pub(super) const fn dec() {}
    pub(super) const fn copy_dropped() {}
}

/// The number of live [`CellBuf`] and [`BlobBuf`] values of this thread (feature `kat`, tests only).
#[cfg(feature = "kat")]
#[must_use]
pub fn live_buffers_kat() -> u64 {
    live::get()
}

/// The number of [`CellCopy`] values dropped — and so wiped — on this thread so far (feature `kat`, tests only;
/// RL-10, M5 review C-4).
#[cfg(feature = "kat")]
#[must_use]
pub fn cell_copies_wiped_kat() -> u64 {
    live::copies_dropped()
}

/// A stored cell, 4096 B, wiped on drop (by the [`Cell`] it holds).
pub struct CellBuf(Cell);

impl CellBuf {
    /// Keep `cell` (the allocation of the decoded request, not a copy).
    #[must_use]
    pub fn new(cell: Cell) -> Self {
        live::inc();
        Self(cell)
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; CELL_LEN] {
        self.0.as_bytes()
    }
}

impl Drop for CellBuf {
    fn drop(&mut self) {
        // the Cell wipes its bytes after this
        live::dec();
    }
}

impl ZeroizeOnDrop for CellBuf {}

/// A copy of a stored cell for a response (`FETCH`, `FETCH_MULTI`), wiped on drop: the executor builds the response
/// `Cell` from it — itself wiped once its frame is sealed — and drops both (M5 review C-4, R-111).
pub struct CellCopy(SecretBytes<CELL_LEN>);

impl CellCopy {
    /// A copy of `bytes`.
    ///
    /// # Errors
    /// [`WrongLength`] unless `bytes` is 4096 bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, WrongLength> {
        SecretBytes::from_slice(bytes)
            .map(Self)
            .map_err(|_| WrongLength)
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; CELL_LEN] {
        self.0.expose_secret()
    }
}

impl Drop for CellCopy {
    fn drop(&mut self) {
        // the SecretBytes wipe the bytes after this
        live::copy_dropped();
    }
}

impl ZeroizeOnDrop for CellCopy {}

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

    fn cell(fill: u8) -> Result<Cell, WrongLength> {
        Cell::from_bytes(&[fill; CELL_LEN]).map_err(|_| WrongLength)
    }

    #[test]
    fn buffers_keep_their_bytes() -> Result<(), WrongLength> {
        let c = CellBuf::new(cell(7)?);
        assert_eq!(c.as_bytes().first(), Some(&7));
        let b = BlobBuf::new(Zeroizing::new(vec![9; LINK_BLOB_LEN]))?;
        assert_eq!(b.as_bytes().len(), LINK_BLOB_LEN);
        assert!(BlobBuf::new(Zeroizing::new(vec![0; 3])).is_err());
        let copy = CellCopy::new(c.as_bytes())?;
        assert_eq!(copy.as_bytes(), c.as_bytes());
        assert!(CellCopy::new(&[0; 3]).is_err());
        Ok(())
    }

    #[cfg(feature = "kat")]
    #[test]
    fn the_live_count_follows_the_buffers() -> Result<(), WrongLength> {
        let before = live_buffers_kat();
        let c = CellBuf::new(cell(0)?);
        let b = BlobBuf::new(Zeroizing::new(vec![0; LINK_BLOB_LEN]))?;
        assert_eq!(live_buffers_kat(), before.saturating_add(2));
        drop(c);
        assert_eq!(live_buffers_kat(), before.saturating_add(1));
        drop(b);
        assert_eq!(live_buffers_kat(), before);
        // a response copy is counted when it drops, and is no stored buffer
        let copies = cell_copies_wiped_kat();
        let copy = CellCopy::new(&[1; CELL_LEN])?;
        assert_eq!(live_buffers_kat(), before);
        assert_eq!(cell_copies_wiped_kat(), copies);
        drop(copy);
        assert_eq!(cell_copies_wiped_kat(), copies.saturating_add(1));
        Ok(())
    }
}
