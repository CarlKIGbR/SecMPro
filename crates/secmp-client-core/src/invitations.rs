// SPDX-License-Identifier: AGPL-3.0-or-later
//! The invitations the user issued (spec §5, §6.5, §6.6, §9.4, §9.7): the sealed record of each, from issue to consumption
//! or expiry.
//!
//! **The record (§5.2, Q147 (ii), IN-03).** `invitations.record` holds, sealed per record (ADR-053 item 5; `invitations`
//! `K_t`, row key = `ld_id` as `len u8 ‖ bytes`), the 128-byte `InvitationRecord` encoding of `secmp-proto` — `ld_id`,
//! `link_key`, the link-data owner seed, the invitation queue's recipient seed, `spk_id`, `opk_id`, `expires` — followed by
//! this crate's trailer: the relay and queue the invitation queue was taken from (so that its retirement can be
//! scheduled), a flags byte, and the 12 360-byte link-data blob that `LINK_PUT` sent (§9.7 (1): the identical `LINK_PUT`
//! is re-issued from it, never re-sealed).
//!
//! **No resident secret (Q173, IN-21).** A record is opened for one step — issue, owner status, one fetch round — and
//! dropped (zeroizing) at its end; [`live_records_kat`] counts the opened records that are still alive.

#[cfg(test)]
use secmp_crypto::Zeroizing;
use secmp_proto::prekeys::{InvitationRecord, RECORD_LEN};
use secmp_proto::wire::Id;
use secmp_store::Store;

use crate::api::Error;
use crate::scheduler::types::{QueueId, RelayId};

/// The record trailer is `relay u32 ‖ queue u32 ‖ flags u8 ‖ blob_present u8`.
#[cfg(test)]
const TRAILER_LEN: usize = 4 + 4 + 1 + 1;

/// Flag: the owner status said that the link data was consumed (§9.4); with no handshake before `expires` the user is told
/// the invitation was used by someone else (§5.2).
pub const FLAG_CONSUMED_SEEN: u8 = 1;

#[cfg(feature = "kat")]
std::thread_local! {
    static LIVE_RECORDS: core::cell::Cell<i64> = const { core::cell::Cell::new(0) };
}

/// The number of opened invitation records alive on this thread (feature `kat`; IN-21, the ST-19 pattern): it is 0 outside
/// an issue, owner-status or fetch step.
#[cfg(feature = "kat")]
#[must_use]
pub fn live_records_kat() -> i64 {
    LIVE_RECORDS.with(core::cell::Cell::get)
}

/// Counts an opened record while it lives (feature `kat`; a zero-sized no-op otherwise).
struct LiveGuard;

impl LiveGuard {
    fn new() -> Self {
        #[cfg(feature = "kat")]
        LIVE_RECORDS.with(|c| c.set(c.get().saturating_add(1)));
        Self
    }
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        #[cfg(feature = "kat")]
        LIVE_RECORDS.with(|c| c.set(c.get().saturating_sub(1)));
    }
}

/// An invitation record as stored (see the module documentation); zeroized on drop.
pub(crate) struct Stored {
    pub(crate) record: InvitationRecord,
    pub(crate) relay: RelayId,
    pub(crate) queue: QueueId,
    pub(crate) flags: u8,
}

impl Stored {
    /// The plaintext that is sealed: the record and the trailer (the link-data blob follows from B-2, IN-19).
    #[cfg(test)]
    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(RECORD_LEN.saturating_add(TRAILER_LEN)));
        v.extend_from_slice(&self.record.to_bytes());
        v.extend_from_slice(&self.relay.0.to_be_bytes());
        v.extend_from_slice(&self.queue.0.to_be_bytes());
        v.push(self.flags);
        v.push(0);
        v
    }

    /// The record of its plaintext.
    ///
    /// # Errors
    /// [`Error::Unavailable`] for anything but the encoding of [`Stored::encode`].
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (rec, rest) = bytes
            .split_at_checked(RECORD_LEN)
            .ok_or(Error::Unavailable)?;
        let record = InvitationRecord::from_bytes(rec)?;
        let mut c = Cursor::new(rest);
        let relay = RelayId(c.u32()?);
        let queue = QueueId(c.u32()?);
        let flags = c.u8()?;
        // no blob is stored yet (it is, from B-2): a record that says so is not one this build wrote
        if c.u8()? != 0 {
            return Err(Error::Unavailable);
        }
        c.finish()?;
        Ok(Self {
            record,
            relay,
            queue,
            flags,
        })
    }
}

/// An invitation record opened for one step.
pub(crate) struct Loaded {
    pub(crate) stored: Stored,
    _guard: LiveGuard,
}

/// Open the record of `ld_id` (`None`: no such invitation).
///
/// # Errors
/// [`Error::Unavailable`] if the row does not open or does not decode.
pub(crate) fn load(store: &Store, ld_id: &Id) -> Result<Option<Loaded>, Error> {
    let Some(plain) = store.invitation_record(ld_id)? else {
        return Ok(None);
    };
    let guard = LiveGuard::new();
    let stored = Stored::decode(&plain)?;
    if stored.record.ld_id != *ld_id {
        return Err(Error::Unavailable);
    }
    Ok(Some(Loaded {
        stored,
        _guard: guard,
    }))
}

/// A cursor over bytes of this crate's own persistence formats: every read is bounds-checked, `finish` refuses a
/// trailing byte.
pub(crate) struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(Error::Unavailable)?;
        self.0 = rest;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Unavailable)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) const fn finish(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Unavailable)
        }
    }
}
