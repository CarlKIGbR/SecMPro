// SPDX-License-Identifier: AGPL-3.0-or-later
//! The invitations (spec §5, §6.5, §6.6, §9.4, §9.7): the inviter's side — issue, owner status, the fetch rounds of the
//! invitation queue and the transactional accept — and the invitee's checks (§5.5).
//!
//! **The record (§5.2, Q147 (ii), IN-03).** `invitations.record` holds, sealed per record (ADR-053 item 5; `invitations`
//! `K_t`, row key = `ld_id` as `len u8 ‖ bytes`), the 128-byte `InvitationRecord` encoding of `secmp-proto` — `ld_id`,
//! `link_key`, the link-data owner seed, the invitation queue's recipient seed, `spk_id`, `opk_id`, `expires` — followed by
//! this crate's trailer: the relay and queue the invitation queue was taken from (so that its retirement can be
//! scheduled), a flags byte, and the 12 360-byte link-data blob that `LINK_PUT` sent (§9.7 (1): the identical `LINK_PUT`
//! is re-issued from it, never re-sealed).
//!
//! **No resident secret (Q173, IN-21).** A record is opened for one step — issue, owner status, one fetch round — and
//! dropped (zeroizing) at its end; `live_records_kat` counts the opened records that are still alive. The prekeys a step
//! needs are loaded from their sealed rows into a [`StagedPrekeys`] for that step only.
//!
//! **The queue pool (§10.6 (3), ADR-048 (m)).** An invitation is issued on one of the user's spare recv-queues, so that no
//! `QUEUE_NEW` is needed at that moment; the spare queues' seeds are in `relays.pool` (sealed, Q151).
//!
//! **The fetch round (§6.5, RT-1, F-M7).** [`Invitations::process_round`] classifies the cells fetched from the invitation
//! queue together with the (at most 24) it retained: a complete group is spent after one `accept`, the others are
//! retained ([`crate::retention`], Q148) in the same store commit that decides the fetched cells, before the cells are
//! acknowledged (Q149). The accept itself — the OPK delete, the record's consumption, the contact and the session — is one
//! store transaction, written after `Responder::accept_classified` returned `Ok` over a [`StagedPrekeys`] that only
//! staged the two deletions (C-12, R-26).

use std::collections::BTreeMap;

use secmp_crypto::{Ed25519SigningKey, SecretBytes, Zeroizing};
use secmp_proto::hx::{Accepted, Initiator, Responder};
use secmp_proto::inv::{
    self, InviteeAccepted, URI_PREFIX, base64url_decode, check_issue_bounds, invitation_uri,
    parse_invitation_uri,
};
use secmp_proto::keys::Ed25519Pk;
use secmp_proto::prekeys::{
    IdentityKeys, InvitationRecord, IssueParams, Issued, OpkSecrets, PoolQueueSeeds, PrekeyStore,
    RECORD_LEN, SpkGeneration, issue_on_parts,
};
use secmp_proto::sizes::{CELL_LEN, LINK_BLOB_LEN};
use secmp_proto::tr::{Entropy, RatchetParts};
use secmp_proto::wire::cell::{Cell, RelayQueue, RouteDescriptor};
use secmp_proto::wire::inv::{InvitationV1, LinkBlob, Profile as WireProfile, RelayRef};
use secmp_proto::wire::{Id, Period};
use secmp_proto::{Decode as _, Encode as _};
use secmp_store::Store;
use secmp_store::profile::{
    INVITATION_CONSUMED, INVITATION_OPEN, INVITATION_RETIRING, KIND_OPK, KIND_SPK,
    delete_invitation, delete_prekey, insert_invitation, insert_prekey, put_invitation_record,
    put_invitation_retained, put_relay_pool, set_invitation_status,
};

use crate::api::{ContactId, Error, Event, InviteReject, RetireReason};
use crate::clock::Clock;
use crate::contacts::{self, NewContact};
use crate::persist::SharedStore;
use crate::profile::{Profile, Retired};
use crate::retention::{RETAIN_MAX, retain};
use crate::scheduler::control::{OpSpec, When};
use crate::scheduler::types::{ControlKind, QueueId, RelayId};
use crate::sessions::rotation::{QueueEntry, QueueSet};

/// Flag: the owner status said that the link data was consumed (§9.4); with no handshake before `expires` the user is told
/// the invitation was used by someone else (§5.2).
pub const FLAG_CONSUMED_SEEN: u8 = 1;

// The trailer after the record: `relay u32 ‖ queue u32 ‖ flags u8 ‖ blob_present u8`.

/// The most cells a fetch round holds in all: what one `FETCH` returns (`QUEUE_CAPACITY`, `docs/03:168`) and the cells
/// retained from earlier rounds.
const ROUND_CELLS_MAX: usize = 128 + RETAIN_MAX;

#[cfg(feature = "kat")]
std::thread_local! {
    static LIVE_RECORDS: core::cell::Cell<i64> = const { core::cell::Cell::new(0) };
    static LIVE_PEAK: core::cell::Cell<i64> = const { core::cell::Cell::new(0) };
    static ACCEPT_CALLS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// The number of opened invitation records alive on this thread (feature `kat`; IN-21, the ST-19 pattern): it is 0 outside
/// an issue, owner-status or fetch step.
#[cfg(feature = "kat")]
#[must_use]
pub fn live_records_kat() -> i64 {
    LIVE_RECORDS.with(core::cell::Cell::get)
}

/// The most opened records alive at once on this thread since [`reset_live_peak_kat`] (feature `kat`; IN-21: during a step
/// the record is in memory, after it none is).
#[cfg(feature = "kat")]
#[must_use]
pub fn live_records_peak_kat() -> i64 {
    LIVE_PEAK.with(core::cell::Cell::get)
}

/// Reset [`live_records_peak_kat`] to the number alive now (feature `kat`).
#[cfg(feature = "kat")]
pub fn reset_live_peak_kat() {
    LIVE_PEAK.with(|p| p.set(LIVE_RECORDS.with(core::cell::Cell::get)));
}

/// How many times this thread called `Responder::accept_classified` (feature `kat`; IN-11: only offered records reach it).
#[cfg(feature = "kat")]
#[must_use]
pub fn accept_calls_kat() -> u64 {
    ACCEPT_CALLS.with(core::cell::Cell::get)
}

/// Counts an opened record while it lives (feature `kat`; a zero-sized no-op otherwise).
struct LiveGuard;

impl LiveGuard {
    fn new() -> Self {
        #[cfg(feature = "kat")]
        LIVE_RECORDS.with(|c| {
            c.set(c.get().saturating_add(1));
            LIVE_PEAK.with(|p| p.set(p.get().max(c.get())));
        });
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
    /// The Ed25519 seed of the invitation queue's sender key (`inv_send_seed` of the invitation): with the record's
    /// recipient seed what a `QUEUE_NEW` after a relay restart needs to be identical (`docs/03:582,589`; Q199).
    pub(crate) inv_send_seed: SecretBytes<32>,
    /// The invitation queue's period in seconds (`inv_period_s`), a [`Period`] (Q199).
    pub(crate) inv_period_s: u16,
    /// The sealed link data `LINK_PUT` sent, kept byte for byte (§9.7 (1)).
    pub(crate) blob: Option<Zeroizing<Vec<u8>>>,
}

impl Stored {
    /// The plaintext that is sealed: the record, the trailer, the blob if any.
    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let blob_len = self.blob.as_ref().map_or(0, |b| b.len());
        let mut v = Zeroizing::new(Vec::with_capacity(blob_len.saturating_add(RECORD_LEN)));
        v.extend_from_slice(&self.record.to_bytes());
        v.extend_from_slice(&self.relay.0.to_be_bytes());
        v.extend_from_slice(&self.queue.0.to_be_bytes());
        v.push(self.flags);
        v.extend_from_slice(self.inv_send_seed.expose_secret());
        v.extend_from_slice(&self.inv_period_s.to_be_bytes());
        match &self.blob {
            Some(b) => {
                v.push(1);
                v.extend_from_slice(b);
            }
            None => v.push(0),
        }
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
        let inv_send_seed = SecretBytes::from_slice(c.take(32)?)?;
        let inv_period_s = u16::from_be_bytes(c.array()?);
        Period::from_seconds(inv_period_s).map_err(|_| Error::Unavailable)?;
        let blob = match c.u8()? {
            0 => None,
            1 => Some(Zeroizing::new(c.take(LINK_BLOB_LEN)?.to_vec())),
            _ => return Err(Error::Unavailable),
        };
        c.finish()?;
        Ok(Self {
            record,
            relay,
            queue,
            flags,
            inv_send_seed,
            inv_period_s,
            blob,
        })
    }

    /// The invitation queue as an owned-queue entry (Q199): the record's recipient seed, the sender seed and the period of
    /// the trailer; no deadline.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if a seed does not copy.
    pub(crate) fn entry(&self) -> Result<QueueEntry, Error> {
        Ok(QueueEntry {
            relay: self.relay.0,
            queue: self.queue.0,
            seed: SecretBytes::from_slice(self.record.invq_recv_seed.expose_secret())?,
            send_seed: Some(SecretBytes::from_slice(self.inv_send_seed.expose_secret())?),
            period_s: self.inv_period_s,
            retire_at_ms: None,
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

/// The `ld_id` of a row.
fn ld_id_of(bytes: &[u8]) -> Result<Id, Error> {
    bytes.try_into().map_err(|_| Error::Unavailable)
}

/// The ids of the one-time prekeys that an open invitation references (each record is opened and dropped).
///
/// # Errors
/// [`Error::Unavailable`] if a record does not open.
pub(crate) fn referenced_opks(store: &Store) -> Result<Vec<u32>, Error> {
    let mut ids = Vec::new();
    for row in store.invitations()? {
        if row.status != INVITATION_OPEN {
            continue;
        }
        let loaded = load(store, &ld_id_of(&row.ld_id)?)?.ok_or(Error::Unavailable)?;
        ids.push(loaded.stored.record.opk_id);
    }
    Ok(ids)
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

    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn seed(&mut self) -> Result<SecretBytes<32>, Error> {
        Ok(SecretBytes::from_slice(self.take(32)?)?)
    }

    pub(crate) const fn finish(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Unavailable)
        }
    }
}

/// A spare recv-queue of the pool: the seeds of its recipient key and of its sender key (§9.1, §10.6 (3)).
pub struct PoolQueue {
    /// The scheduler's id of the queue.
    pub queue: QueueId,
    /// The Ed25519 seed of the recipient key.
    pub recv_seed: SecretBytes<32>,
    /// The Ed25519 seed of the sender key.
    pub send_seed: SecretBytes<32>,
}

/// A spare queue's id and seeds `(queue, recipient, sender)`, typed and zeroized (Q211).
pub type PoolSeeds = (QueueId, SecretBytes<32>, SecretBytes<32>);

/// The pool of one relay as `relays.pool` holds it: `next u32 ‖ count u8 ‖ {queue u32 ‖ recv_seed ‖ send_seed} × count`.
struct PoolBlob {
    next: u32,
    queues: Vec<PoolQueue>,
}

impl PoolBlob {
    const fn empty() -> Self {
        Self {
            next: 1,
            queues: Vec::new(),
        }
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut v = Zeroizing::new(Vec::with_capacity(
            5_usize.saturating_add(self.queues.len().saturating_mul(68)),
        ));
        v.extend_from_slice(&self.next.to_be_bytes());
        v.push(u8::try_from(self.queues.len()).map_err(|_| Error::Unavailable)?);
        for q in &self.queues {
            v.extend_from_slice(&q.queue.0.to_be_bytes());
            v.extend_from_slice(q.recv_seed.expose_secret());
            v.extend_from_slice(q.send_seed.expose_secret());
        }
        Ok(v)
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut c = Cursor::new(bytes);
        let next = c.u32()?;
        let count = c.u8()?;
        let mut queues = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            queues.push(PoolQueue {
                queue: QueueId(c.u32()?),
                recv_seed: c.seed()?,
                send_seed: c.seed()?,
            });
        }
        c.finish()?;
        Ok(Self { next, queues })
    }

    fn read(store: &Store, relay: RelayId) -> Result<Self, Error> {
        store
            .relay_pool(i64::from(relay.0))?
            .map_or_else(|| Ok(Self::empty()), |b| Self::decode(&b))
    }
}

/// The spare recv-queues of the user's relays (sealed, `relays.pool`): the invitations and the invitee's reply routes
/// draw their queues from here, so that creating or accepting an invitation needs no `QUEUE_NEW` at that moment.
pub struct SparePool {
    store: SharedStore,
}

impl SparePool {
    /// The pools in `store`; the relay rows must exist (`secmp_store::profile::put_relay`).
    #[must_use]
    pub const fn new(store: SharedStore) -> Self {
        Self { store }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Store>, Error> {
        self.store.lock().map_err(|_| Error::Unavailable)
    }

    /// Top the pool of `relay` up to `target` spare queues with seeds from `entropy` (the recipient seed, then the sender
    /// seed, of each queue); returns how many were added. The queues' creation on the relay is the scheduler's.
    ///
    /// # Errors
    /// [`Error::Unavailable`] without randomness, for an unknown relay or if the store cannot be written.
    pub fn fill(
        &self,
        relay: RelayId,
        target: usize,
        entropy: &mut impl Entropy,
    ) -> Result<usize, Error> {
        let mut store = self.lock()?;
        let mut pool = PoolBlob::read(&store, relay)?;
        let mut added = 0_usize;
        while pool.queues.len() < target {
            let recv_seed = entropy.secret::<32>()?;
            let send_seed = entropy.secret::<32>()?;
            pool.queues.push(PoolQueue {
                queue: QueueId(pool.next),
                recv_seed,
                send_seed,
            });
            pool.next = pool.next.checked_add(1).ok_or(Error::Unavailable)?;
            added = added.saturating_add(1);
        }
        if added > 0 {
            let blob = pool.encode()?;
            store.txn(|tx| put_relay_pool(tx, i64::from(relay.0), Some(&blob)))?;
        }
        Ok(added)
    }

    /// The ids and seeds `(queue, recipient, sender)` of the spare queues of `relay`, oldest first (the queues' creation on
    /// the relay is the scheduler's; a test driver that made them earlier needs their seeds).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read.
    pub fn seeds(&self, relay: RelayId) -> Result<Vec<PoolSeeds>, Error> {
        let store = self.lock()?;
        PoolBlob::read(&store, relay)?
            .queues
            .iter()
            .map(|q| {
                Ok((
                    q.queue,
                    SecretBytes::from_slice(q.recv_seed.expose_secret())?,
                    SecretBytes::from_slice(q.send_seed.expose_secret())?,
                ))
            })
            .collect()
    }

    /// The spare queues of `relay`.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read.
    pub fn len(&self, relay: RelayId) -> Result<usize, Error> {
        let store = self.lock()?;
        Ok(PoolBlob::read(&store, relay)?.queues.len())
    }

    /// Whether `relay` has no spare queue.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read.
    pub fn is_empty(&self, relay: RelayId) -> Result<bool, Error> {
        Ok(self.len(relay)? == 0)
    }

    /// Hand out the oldest spare queue of `relay` and write the pool without it, in one store transaction.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read or written (the queue stays in the pool).
    pub fn take(&self, relay: RelayId) -> Result<Option<PoolQueue>, Error> {
        let mut store = self.lock()?;
        let Some((queue, rest)) = take_oldest(&store, relay)? else {
            return Ok(None);
        };
        store.txn(|tx| put_relay_pool(tx, i64::from(relay.0), Some(&rest)))?;
        Ok(Some(queue))
    }
}

/// A spare queue taken from a pool, with the encoding of the pool that is left.
pub(crate) type Taken = (PoolQueue, Zeroizing<Vec<u8>>);

/// The oldest spare queue of `relay` and the encoding of the pool without it (nothing is written).
pub(crate) fn take_oldest(store: &Store, relay: RelayId) -> Result<Option<Taken>, Error> {
    let mut pool = PoolBlob::read(store, relay)?;
    if pool.queues.is_empty() {
        return Ok(None);
    }
    let queue = pool.queues.remove(0);
    let rest = pool.encode()?;
    Ok(Some((queue, rest)))
}

/// The scheduler's id of the link data of `ld_id`: its first four bytes (`ControlKind::LinkPut(n)`); a collision with
/// another invitation is refused at issue (2⁻³² per pair).
fn link_data_n(ld_id: &Id) -> u32 {
    let [a, b, c, d, ..] = *ld_id;
    u32::from_be_bytes([a, b, c, d])
}

/// The Ed25519 public key of a 32-byte seed.
pub(crate) fn ed25519_pk_of(seed: &SecretBytes<32>) -> Result<Ed25519Pk, Error> {
    let key = Ed25519SigningKey::from_seed(seed.expose_secret())?;
    Ok(Ed25519Pk::from_bytes(key.verifying_key().as_bytes())?)
}

/// What to issue.
pub struct IssueRequest {
    /// The relay (a row of `relays`) whose spare queue becomes the invitation queue.
    pub relay: RelayId,
    /// The invitation queue's period.
    pub inv_period: Period,
    /// The inviter's profile for the link data.
    pub profile: WireProfile,
    /// `expires` of the invitation (Unix seconds, at most 30 days on).
    pub expires: u64,
}

/// An issued invitation: what goes to the invitee out of band and what the host does next.
pub struct Issuance {
    /// The invitation (a secret).
    pub invitation: InvitationV1,
    /// Its URI (a secret): `secmp://i/` and 322 characters.
    pub uri: Zeroizing<String>,
    /// The sealed link data for `LINK_PUT`.
    pub blob: LinkBlob,
    /// The control operations to queue: the `LINK_PUT`, at once, on a one-shot link (a user waits, §10.6 (2)); never a
    /// `QUEUE_NEW`.
    pub ops: Vec<OpSpec>,
}

/// An open invitation's queue, for the scheduler to fetch (the host registers it with the invitation's period).
pub struct OpenQueue {
    /// The invitation.
    pub ld_id: Id,
    /// Its link-data number (`ControlKind::LinkPut(n)`).
    pub n: u32,
    /// The relay.
    pub relay: RelayId,
    /// The queue's id.
    pub queue: QueueId,
    /// The Ed25519 seed of the recipient key.
    pub recv_seed: SecretBytes<32>,
    /// The Ed25519 seed of the sender key (for an identical `QUEUE_NEW` after a relay restart, Q199).
    pub send_seed: SecretBytes<32>,
    /// The queue's period in seconds, as the invitation names it (Q199).
    pub period_s: u16,
}

/// The link-data id and number of an invitation URI (the invitee's `LINK_GET` names them before anything else is known).
///
/// # Errors
/// [`Error::Invitation`] (`Invalid`) for a URI that does not parse.
pub fn uri_link_data(uri: &str) -> Result<(Id, u32), Error> {
    let invitation =
        inv::parse_invitation_uri(uri).map_err(|_| Error::Invitation(InviteReject::Invalid))?;
    Ok((invitation.ld_id, link_data_n(&invitation.ld_id)))
}

/// The arguments of a `LINK_PUT` of an issued invitation (§9.3), read from its sealed record.
pub struct LinkPutArgs {
    /// The link-data id.
    pub ld_id: Id,
    /// The public key of the link-data owner key.
    pub owner_pk: Ed25519Pk,
    /// The seed of the owner key, which signs the `LINK_PUT` (§9.3).
    pub owner_seed: SecretBytes<32>,
    /// The sealed link data, byte for byte as issued (12 360 bytes).
    pub blob: Zeroizing<Vec<u8>>,
    /// `expires` of the invitation (Unix seconds).
    pub expires: u64,
}

/// The answer of an owner-status `LINK_GET` (§9.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerStatus {
    /// The relay holds the link data.
    pub present: bool,
    /// The link data was consumed.
    pub consumed: bool,
}

/// What one fetch round decided (see [`Invitations::process_round`]).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Round {
    /// The cell to acknowledge on the invitation queue: everything up to it is decided and durable. `None` if no cell was
    /// decided.
    pub ack_through: Option<u64>,
    /// The contact of the accepted handshake.
    pub accepted: Option<ContactId>,
    /// Events for the user.
    pub events: Vec<Event>,
    /// Control operations to queue (the retirement of an expired invitation's queue).
    pub ops: Vec<OpSpec>,
    /// The ids of the fetched cells that belong to the session of a consumed invitation (Q193, `docs/03:351`), in fetch
    /// order: the caller feeds them to that session's receive path, which acknowledges them through its own commit. The
    /// caller still holds the cells.
    pub to_session: Vec<u64>,
    /// The relay and the queue of the invitation whose handshake was accepted: the first reply replaces the queue with a
    /// pooled one and retires it (§6.6 step 4, §10.6 (5); [`crate::sessions::rotation::rotate`]).
    pub invitation_queue: Option<(RelayId, QueueId)>,
}

/// What [`Invitations::maintain`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Maintained {
    /// Events for the user.
    pub events: Vec<Event>,
    /// `QUEUE_DEL` of the queue of every invitation that expired unused, at `U[1 min, 60 min]` (§10.6 (4), Q163: after an
    /// empty `FETCH`, which the host's queue runs before the deletion).
    pub ops: Vec<OpSpec>,
}

/// The inviter's invitations (see the module documentation).
pub struct Invitations {
    profile: Profile,
}

impl Invitations {
    /// The invitations of `profile`.
    #[must_use]
    pub const fn new(profile: Profile) -> Self {
        Self { profile }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Store>, Error> {
        self.profile.lock_store()
    }

    /// Issue an invitation (§5.2, §5.4, §6.3): rotate the signed prekey if due, take an unreferenced one-time prekey (or
    /// draw one), sign the bundle, draw `ld_id`, `link_key`, a discarded 16 bytes, the blob nonce and the owner seed
    /// (`secmp_proto::prekeys::issue_on_parts`, the construction of `MemoryPrekeyStore::issue_invitation_on`), seal the
    /// link data, take a spare queue of the relay as the invitation queue and record the invitation. Three store
    /// transactions: the rotation of the signed prekey (if due) commits first and on its own; then the drawn one-time
    /// prekey (if any), the pool without the taken queue and the invitation in one transaction; then the refill of the
    /// unreferenced one-time prekeys (`Profile::fill_opks`) on its own. The queue's seeds are the pool's, drawn before
    /// and independent of any identity key (IN-02, `docs/03:597`).
    ///
    /// # Errors
    /// [`Error::Unsupported`] for an `expires` outside §5.2/§6.3; [`Error::Unavailable`] if the relay has no spare
    /// queue, randomness or the store is unavailable (no invitation is recorded; a rotation that committed before
    /// stays).
    pub fn issue(
        &self,
        req: &IssueRequest,
        clock: &impl Clock,
        entropy: &mut impl Entropy,
    ) -> Result<Issuance, Error> {
        let now = clock.unix_secs();
        // §6.3: `spk_expiry` ≥ `expires`; the signed prekey is retained until the invitation expires (§6.1)
        check_issue_bounds(now, req.expires, req.expires).map_err(|_| Error::Unsupported)?;
        let spk_id = self.profile.rotate_if_due(clock, entropy)?;
        let identity = self.profile.identity()?;
        let issuance = {
            let mut store = self.lock()?;
            issue_in(&mut store, &identity, spk_id, req, now, entropy)?
        };
        // keep the pool of unreferenced one-time prekeys full (the draws come after the invitation's)
        self.profile.fill_opks(1, entropy)?;
        Ok(issuance)
    }

    /// The queue of the invitation `ld_id`, open or consumed (the host fetches it until it is retired).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if there is no such invitation or its record does not open.
    pub fn queue_of(&self, ld_id: &Id) -> Result<OpenQueue, Error> {
        let store = self.lock()?;
        let loaded = load(&store, ld_id)?.ok_or(Error::Unavailable)?;
        Ok(OpenQueue {
            ld_id: *ld_id,
            n: link_data_n(ld_id),
            relay: loaded.stored.relay,
            queue: loaded.stored.queue,
            recv_seed: SecretBytes::from_slice(
                loaded.stored.record.invq_recv_seed.expose_secret(),
            )?,
            send_seed: SecretBytes::from_slice(loaded.stored.inv_send_seed.expose_secret())?,
            period_s: loaded.stored.inv_period_s,
        })
    }

    /// The queues of the open invitations (after a restart the host registers them with the scheduler again).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if a record does not open.
    pub fn open_queues(&self) -> Result<Vec<OpenQueue>, Error> {
        let rows = self.lock()?.invitations()?;
        let mut out = Vec::new();
        for row in rows {
            if row.status == INVITATION_OPEN {
                out.push(self.queue_of(&ld_id_of(&row.ld_id)?)?);
            }
        }
        Ok(out)
    }

    /// The arguments of the `LINK_PUT` of link data `n` (`ControlKind::LinkPut(n)`), from the sealed record: the same bytes
    /// whenever it is asked (§9.7 (1)).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if no invitation has link data `n`, or its record does not open.
    pub fn link_put_args(&self, n: u32) -> Result<LinkPutArgs, Error> {
        let store = self.lock()?;
        for row in store.invitations()? {
            // a retiring invitation holds only its queue's entry (Q201)
            if row.status == INVITATION_RETIRING {
                continue;
            }
            let ld_id = ld_id_of(&row.ld_id)?;
            if link_data_n(&ld_id) != n {
                continue;
            }
            let loaded = load(&store, &ld_id)?.ok_or(Error::Unavailable)?;
            let blob = loaded.stored.blob.clone().ok_or(Error::Unavailable)?;
            return Ok(LinkPutArgs {
                ld_id,
                owner_pk: loaded.stored.record.owner_pk()?,
                owner_seed: SecretBytes::from_slice(
                    loaded.stored.record.owner_seed.expose_secret(),
                )?,
                blob,
                expires: loaded.stored.record.expires,
            });
        }
        Err(Error::Unavailable)
    }

    /// The owner status of the link data of `ld_id` (§9.4, §9.7 (1)): `present = 0, consumed = 0` before `expires` means the
    /// relay restarted — the identical `LINK_PUT` is queued again, delayed `U[1 min, 60 min]` (no user waits, §10.6 (2)); a
    /// consumed link data is noted, and with no handshake before `expires` the invitation is reported as used by someone
    /// else ([`Invitations::maintain`]).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the invitation is unknown or the store cannot be written.
    pub fn on_owner_status(
        &self,
        ld_id: &Id,
        status: OwnerStatus,
        clock: &impl Clock,
    ) -> Result<Vec<OpSpec>, Error> {
        let now = clock.unix_secs();
        let mut store = self.lock()?;
        // a retiring invitation holds only its queue's entry, no record to open (Q201)
        if offer_state(&store, ld_id, None, now)? == OfferState::Retiring {
            return Ok(Vec::new());
        }
        // the record is opened once, through `load` (counted while it lives, IN-21), for the whole step
        let mut loaded = load(&store, ld_id)?.ok_or(Error::Unavailable)?;
        let relay = loaded.stored.relay;
        if offer_state(&store, ld_id, None, now)? != OfferState::Offered {
            return Ok(Vec::new());
        }
        if status.consumed {
            loaded.stored.flags |= FLAG_CONSUMED_SEEN;
            let plain = loaded.stored.encode();
            store.txn(|tx| put_invitation_record(tx, ld_id, &plain))?;
            return Ok(Vec::new());
        }
        if status.present {
            return Ok(Vec::new());
        }
        let n = link_data_n(ld_id);
        Ok(vec![OpSpec {
            kind: ControlKind::LinkPut(n),
            relay,
            related: u64::from(n),
            when: When::Delayed,
        }])
    }

    /// Retire what has expired (§6.1, §5.2): the profile's retirement ([`Profile::retire`]), the `QUEUE_DEL` of the queue
    /// of every invitation that expired unused (a consumed invitation's queue is retired with its session), and
    /// [`Event::InvitationUsedElsewhere`] once for an invitation whose link data was consumed and that no handshake
    /// answered.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read or written.
    pub fn maintain(&self, clock: &impl Clock) -> Result<Maintained, Error> {
        Ok(retirement(&self.profile.retire(clock)?, None))
    }

    /// The earliest `expires` (Unix seconds) of an open invitation (`None` without one): when the host runs
    /// [`Invitations::maintain`] next (IN-11, Q208).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read.
    pub fn next_expiry(&self) -> Result<Option<u64>, Error> {
        Ok(self
            .lock()?
            .invitations()?
            .iter()
            .filter(|r| r.status == INVITATION_OPEN)
            .map(|r| r.expires_ms.div_ceil(1000))
            .min())
    }

    /// The queues of the invitations that were retired unconsumed and whose `QUEUE_DEL` is not yet acknowledged (Q201): each
    /// with its invitation and the entry that signs its `FETCH` and `QUEUE_DEL` (the deadline is set). After a restart the
    /// host fetches them again until the empty `FETCH` and re-arms the deletion.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if a row does not open.
    pub fn retiring(&self) -> Result<Vec<(Id, QueueEntry)>, Error> {
        let store = self.lock()?;
        let mut out = Vec::new();
        for row in store.invitations()? {
            if row.status != INVITATION_RETIRING {
                continue;
            }
            let ld_id = ld_id_of(&row.ld_id)?;
            let plain = store.invitation_record(&ld_id)?.ok_or(Error::Unavailable)?;
            out.push((ld_id, QueueEntry::decode_one(&plain)?));
        }
        Ok(out)
    }

    /// The `QUEUE_DEL` of `queue` was acknowledged (or the relay says the queue is gone), in one transaction: the retiring
    /// entry of `queue` leaves every contact's `contacts.queues`, and the row of the invitation that held it goes — a
    /// retiring one (Q201) or a consumed one, which the expiry sweep keeps while its queue is routed (Q207). `Ok(false)` if
    /// no invitation row holds `queue`.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read or written.
    pub fn queue_deleted(&self, relay: RelayId, queue: QueueId) -> Result<bool, Error> {
        let mut store = self.lock()?;
        let mut gone = None;
        for row in store.invitations()? {
            if row.status == INVITATION_OPEN {
                continue;
            }
            let ld_id = ld_id_of(&row.ld_id)?;
            let (r, q) = if row.status == INVITATION_RETIRING {
                let plain = store.invitation_record(&ld_id)?.ok_or(Error::Unavailable)?;
                let entry = QueueEntry::decode_one(&plain)?;
                (entry.relay, entry.queue)
            } else {
                let loaded = load(&store, &ld_id)?.ok_or(Error::Unavailable)?;
                (loaded.stored.relay.0, loaded.stored.queue.0)
            };
            if q == queue.0 && r == relay.0 {
                gone = Some(ld_id);
                break;
            }
        }
        let mut sets = Vec::new();
        for c in store.contacts()? {
            let Some(bytes) = store.contact_queues(c.id)? else {
                continue;
            };
            let mut set = QueueSet::decode(&bytes)?;
            let before = set.entries.len();
            set.entries.retain(|e| {
                !(e.queue == queue.0 && e.relay == relay.0 && e.retire_at_ms.is_some())
            });
            if set.entries.len() != before {
                sets.push((c.id, set.encode()?));
            }
        }
        store.txn(|tx| {
            for (contact, encoded) in &sets {
                secmp_store::contacts::put_contact_queues(tx, *contact, encoded)?;
            }
            match &gone {
                Some(ld_id) => delete_invitation(tx, ld_id),
                None => Ok(()),
            }
        })?;
        Ok(gone.is_some())
    }

    /// The ids of the cells that invitation `ld_id` retains (ascending).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read.
    pub fn retained_ids(&self, ld_id: &Id) -> Result<Vec<u64>, Error> {
        let store = self.lock()?;
        Ok(decode_retained(
            store
                .invitation_retained(ld_id)?
                .as_ref()
                .map(|z| z.as_slice()),
        )?
        .into_iter()
        .map(|(id, _)| id)
        .collect())
    }
}

/// The events and the control operations of retired invitations: `QUEUE_DEL` of the queue of each one that was not
/// consumed (a consumed invitation's queue is retired with its session), [`Event::InvitationUsedElsewhere`] once for one
/// whose link data was consumed without a handshake, and — for an identity rotation (`rotated`) —
/// [`Event::InvitationRetired`].
#[must_use]
pub fn retirement(retired: &[Retired], rotated: Option<RetireReason>) -> Maintained {
    let mut out = Maintained::default();
    for r in retired {
        if r.used_elsewhere {
            out.events.push(Event::InvitationUsedElsewhere);
        }
        if r.consumed {
            continue;
        }
        if let Some(reason) = rotated {
            out.events.push(Event::InvitationRetired {
                id: link_data_n(&r.ld_id),
                reason,
            });
        }
        out.ops.push(OpSpec {
            kind: ControlKind::QueueDel(r.queue),
            relay: r.relay,
            related: u64::from(link_data_n(&r.ld_id)),
            // §10.6 (4), Q163, Q194: after a FETCH of the queue that held no present cell, then U[1 min, 60 min]
            when: When::AfterEmptyFetch(r.queue),
        });
    }
    out
}

/// [`Invitations::issue`] under the store lock: the store work around the construction of `secmp-proto`
/// (`prekeys::issue_on_parts` on the pool queue's seeds, Q189), written in one store transaction.
fn issue_in(
    store: &mut Store,
    identity: &IdentityKeys,
    spk_id: u32,
    req: &IssueRequest,
    now: u64,
    entropy: &mut impl Entropy,
) -> Result<Issuance, Error> {
    let spk = SpkGeneration::from_seeds(
        &store
            .prekey_secret(KIND_SPK, i64::from(spk_id))?
            .ok_or(Error::Unavailable)?,
    )?;
    let (opk, opk_is_new) = unreferenced_opk(store, entropy)?;
    let relay_ref = RelayRef::decode(
        &store
            .relay_ref(i64::from(req.relay.0))?
            .ok_or(Error::Unavailable)?,
    )?;
    let (queue, pool_rest) = take_oldest(store, req.relay)?.ok_or(Error::Unavailable)?;
    let PoolQueue {
        queue,
        recv_seed,
        send_seed,
    } = queue;

    // §5.2, §6.3: the one construction of `secmp-proto`, on the pool queue's seeds (§5.2 `docs/03:211`)
    let params = IssueParams {
        relay: relay_ref,
        inv_period: req.inv_period,
        profile: req.profile.clone(),
        now,
        expires: req.expires,
        spk_expiry: req.expires,
    };
    let inv_send_seed = SecretBytes::from_slice(send_seed.expose_secret())?;
    let seeds = PoolQueueSeeds {
        invq_recv_seed: recv_seed,
        inv_send_seed: send_seed,
    };
    let (Issued { invitation, blob }, record) =
        issue_on_parts(identity, &spk, &opk, params, Some(seeds), entropy)
            .map_err(|_| Error::Unavailable)?;
    let ld_id = record.ld_id;
    let n = link_data_n(&ld_id);
    for row in store.invitations()? {
        if link_data_n(&ld_id_of(&row.ld_id)?) == n {
            return Err(Error::Unavailable);
        }
    }
    let stored = Stored {
        record,
        relay: req.relay,
        queue,
        flags: 0,
        inv_send_seed,
        inv_period_s: req.inv_period.seconds(),
        blob: Some(blob.encode()?),
    };
    let plain = stored.encode();
    let expires_ms = req.expires.checked_mul(1000).ok_or(Error::Unavailable)?;
    store.txn(|tx| {
        if opk_is_new {
            insert_prekey(tx, KIND_OPK, i64::from(opk.id()), &opk.to_seeds(), None)?;
        }
        put_relay_pool(tx, i64::from(req.relay.0), Some(&pool_rest))?;
        insert_invitation(tx, &ld_id, &plain, expires_ms)
    })?;
    let uri = invitation_uri(&invitation)?;
    Ok(Issuance {
        invitation,
        uri,
        blob,
        ops: vec![OpSpec {
            kind: ControlKind::LinkPut(n),
            relay: req.relay,
            related: u64::from(n),
            when: When::Prompt,
        }],
    })
}

/// The lowest-numbered one-time prekey that no open invitation references; if there is none, a fresh one (drawn now, to be
/// inserted by the caller's transaction), numbered after the largest. The flag says which.
fn unreferenced_opk(
    store: &Store,
    entropy: &mut impl Entropy,
) -> Result<(OpkSecrets, bool), Error> {
    let referenced = referenced_opks(store)?;
    let rows = store.prekeys(KIND_OPK)?;
    for row in &rows {
        if referenced.iter().any(|o| i64::from(*o) == row.id) {
            continue;
        }
        let seeds = store
            .prekey_secret(KIND_OPK, row.id)?
            .ok_or(Error::Unavailable)?;
        return Ok((OpkSecrets::from_seeds(&seeds)?, false));
    }
    let next = rows.last().map_or(Ok(1_u32), |r| {
        u32::try_from(r.id)
            .map_err(|_| Error::Unavailable)?
            .checked_add(1)
            .ok_or(Error::Unavailable)
    })?;
    Ok((OpkSecrets::generate(next, entropy)?, true))
}

/// The cells of `invitations.retained`: `count u8 ‖ {cell_id u64 ‖ cell [4096]} × count`, ascending by id.
fn decode_retained(bytes: Option<&[u8]>) -> Result<Vec<(u64, Cell)>, Error> {
    let Some(bytes) = bytes else {
        return Ok(Vec::new());
    };
    let mut c = Cursor::new(bytes);
    let count = usize::from(c.u8()?);
    if count > RETAIN_MAX {
        return Err(Error::Unavailable);
    }
    let mut cells = Vec::with_capacity(count);
    for _ in 0..count {
        let id = c.u64()?;
        cells.push((id, Cell::from_bytes(c.take(CELL_LEN)?)?));
    }
    c.finish()?;
    Ok(cells)
}

fn encode_retained(cells: &[(u64, &Cell)]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut v = Zeroizing::new(Vec::with_capacity(
        1_usize.saturating_add(cells.len().saturating_mul(CELL_LEN.saturating_add(8))),
    ));
    v.push(u8::try_from(cells.len()).map_err(|_| Error::Unavailable)?);
    for (id, cell) in cells {
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(cell.as_bytes());
    }
    Ok(v)
}

/// The prekeys of one accept step, loaded from their sealed rows for the step and dropped after it: a [`PrekeyStore`] whose
/// `delete_opk` and `commit_accept` validate and only **stage** (F-M7, C-12). The caller writes the deletions — with the
/// record's consumption, the contact and the session — in one store transaction after `accept` returned `Ok`; if that
/// transaction fails, this store is dropped and nothing was changed (R-26).
pub struct StagedPrekeys {
    spk: Option<SpkGeneration>,
    opk: Option<OpkSecrets>,
    ld_id: Id,
    opk_id: u32,
    staged: bool,
}

impl StagedPrekeys {
    /// The prekeys that `record` names; one that is missing (retired) makes every handshake on it fail.
    fn load(store: &Store, record: &InvitationRecord) -> Result<Self, Error> {
        let spk = store
            .prekey_secret(KIND_SPK, i64::from(record.spk_id))?
            .map(|s| SpkGeneration::from_seeds(&s))
            .transpose()?;
        let opk = store
            .prekey_secret(KIND_OPK, i64::from(record.opk_id))?
            .map(|s| OpkSecrets::from_seeds(&s))
            .transpose()?;
        Ok(Self {
            spk,
            opk,
            ld_id: record.ld_id,
            opk_id: record.opk_id,
            staged: false,
        })
    }

    /// Whether `commit_accept` has staged the deletions.
    #[must_use]
    pub const fn staged(&self) -> bool {
        self.staged
    }
}

impl PrekeyStore for StagedPrekeys {
    fn spk(&self, spk_id: u32) -> Option<&SpkGeneration> {
        self.spk.as_ref().filter(|s| s.id() == spk_id)
    }

    fn opk(&self, opk_id: u32) -> Option<&OpkSecrets> {
        if self.staged {
            return None;
        }
        self.opk.as_ref().filter(|o| o.id() == opk_id)
    }

    fn delete_opk(&mut self, opk_id: u32) -> secmp_proto::Result<()> {
        if self.opk(opk_id).is_none() {
            return Err(secmp_proto::Error::Rejected);
        }
        self.staged = true;
        Ok(())
    }

    fn commit_accept(&mut self, opk_id: u32, ld_id: &Id) -> secmp_proto::Result<()> {
        // both must exist, and the record must name exactly this OPK, before anything is staged (M4 review R-64)
        if *ld_id != self.ld_id || opk_id != self.opk_id || self.opk(opk_id).is_none() {
            return Err(secmp_proto::Error::Rejected);
        }
        self.staged = true;
        Ok(())
    }
}

impl Invitations {
    /// One fetch round of the invitation queue of `ld_id` (§6.5, §6.6, RT-1, F-M7) — `on`, the queue the host fetched it
    /// from (relay, queue): `fetched` are the cells `FETCH` returned, with their `cell_id`s.
    ///
    /// Only a record that is **offered** — open and unexpired — reaches `accept` (R-69, ADR-044 (d)); for an expired one
    /// the invitation is retired instead ([`Invitations::maintain`]: `QUEUE_DEL` in `Round::ops`). The fetched cells and
    /// the cells retained from earlier rounds are classified by `Responder::accept_classified`: a complete group is spent
    /// after one call, accepted or not; the others are retained, at most the newest 24 ([`retain`], Q148).
    ///
    /// The decision is one store commit — on an accept: the OPK row delete, the record's consumption, the contact, the
    /// session (the `Accepted.state` in its parts) and the cleared retained cells; otherwise the retained cells — and only
    /// after it is durable is `Round::ack_through` set (persist-before-ack, CLAUDE.md §1.7). If the commit fails the call is
    /// [`Error::Unavailable`], nothing was changed and nothing is acknowledged: the same cells come again.
    ///
    /// A record that is gone while its queue is still a session's recv-queue (in a contact's `contacts.queues`) is not
    /// decided (Q207, fail closed): nothing is acknowledged, the round is [`Error::Unavailable`] — its cells may be the
    /// session's (Q193).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the record, the prekeys or the store are unavailable, `accept` could not be made durable,
    /// or the record is gone while `on` is routed.
    pub fn process_round(
        &self,
        ld_id: &Id,
        on: (RelayId, QueueId),
        fetched: &[(u64, Cell)],
        clock: &impl Clock,
        entropy: &mut impl Entropy,
    ) -> Result<Round, Error> {
        let fetched_max = fetched.iter().map(|(id, _)| *id).max();
        let state = offer_state(&*self.lock()?, ld_id, Some(on), clock.unix_secs())?;
        match state {
            OfferState::Offered => {}
            OfferState::Unavailable => return Err(Error::Unavailable),
            // consumed: the cells are TR cells of the session (Q193, §6.6 step 4), decided by its receive path
            OfferState::Consumed => {
                return Ok(Round {
                    to_session: fetched.iter().map(|(id, _)| *id).collect(),
                    ..Round::default()
                });
            }
            // retired, or retiring until its `QUEUE_DEL` is acknowledged: a handshake on it is dropped silently, never
            // answered, no event (Q164, Q201)
            OfferState::Retired | OfferState::Retiring => {
                return Ok(Round {
                    ack_through: fetched_max,
                    ..Round::default()
                });
            }
            OfferState::Expired => {
                let m = self.maintain(clock)?;
                return Ok(Round {
                    events: m.events,
                    ops: m.ops,
                    ..Round::default()
                });
            }
        }
        self.decide(ld_id, on, fetched, fetched_max, clock, entropy)
    }

    /// The classification and the commit of one round of an offered record. The record's status and expiry are checked
    /// again under the lock that the decision holds (Q192): a record consumed or expired since [`Self::process_round`]
    /// looked never reaches `accept`.
    fn decide(
        &self,
        ld_id: &Id,
        on: (RelayId, QueueId),
        fetched: &[(u64, Cell)],
        fetched_max: Option<u64>,
        clock: &impl Clock,
        entropy: &mut impl Entropy,
    ) -> Result<Round, Error> {
        let identity = self.profile.identity()?;
        let mut store = self.lock()?;
        match offer_state(&store, ld_id, Some(on), clock.unix_secs())? {
            OfferState::Offered => {}
            // gone while routed: not decided (Q207)
            OfferState::Unavailable => return Err(Error::Unavailable),
            // consumed: the cells are TR cells of the session (Q193, §6.6 step 4), decided by its receive path
            OfferState::Consumed => {
                return Ok(Round {
                    to_session: fetched.iter().map(|(id, _)| *id).collect(),
                    ..Round::default()
                });
            }
            // expired: nothing is decided or acknowledged; the retirement is `maintain`'s
            OfferState::Expired => return Ok(Round::default()),
            // retired: a handshake on it is dropped silently, never answered (Q164)
            OfferState::Retired | OfferState::Retiring => {
                return Ok(Round {
                    ack_through: fetched_max,
                    ..Round::default()
                });
            }
        }
        let loaded = load(&store, ld_id)?.ok_or(Error::Unavailable)?;
        let mut union: BTreeMap<u64, Cell> = BTreeMap::new();
        let retained = decode_retained(
            store
                .invitation_retained(ld_id)?
                .as_ref()
                .map(|z| z.as_slice()),
        )?;
        let retained_ids: Vec<u64> = retained.iter().map(|(id, _)| *id).collect();
        union.extend(retained);
        for (id, cell) in fetched {
            union.insert(*id, Cell::from_bytes(cell.as_bytes())?);
        }
        if union.len() > ROUND_CELLS_MAX {
            return Err(Error::Unavailable);
        }
        let (ids, cells): (Vec<u64>, Vec<Cell>) = union.into_iter().unzip();
        let fetched_ids: Vec<u64> = fetched.iter().map(|(id, _)| *id).collect();

        let mut staged = StagedPrekeys::load(&store, &loaded.stored.record)?;
        #[cfg(feature = "kat")]
        ACCEPT_CALLS.with(|c| c.set(c.get().saturating_add(1)));
        let (result, spent) = Responder::accept_classified(
            &cells,
            &loaded.stored.record,
            &mut staged,
            &identity.responder_keys(),
            entropy,
        );
        let mut spent_ids: Vec<u64> = spent
            .indices()
            .iter()
            .filter_map(|i| ids.get(*i).copied())
            .collect();
        spent_ids.extend(duplicates_of_spent(&ids, &cells, &spent_ids));
        match result {
            // nothing was committed: the same cells are fetched again, nothing is spent or acknowledged (VD2-7)
            Err(secmp_proto::Error::Unavailable) => Err(Error::Unavailable),
            Err(_) => {
                let mut keep = [0_u64; RETAIN_MAX];
                let n = retain(&retained_ids, &fetched_ids, &spent_ids, &mut keep);
                let kept: Vec<(u64, &Cell)> = keep
                    .get(..n)
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|id| {
                        let at = ids.iter().position(|i| i == id)?;
                        Some((*id, cells.get(at)?))
                    })
                    .collect();
                let blob = encode_retained(&kept)?;
                store.txn(|tx| put_invitation_retained(tx, ld_id, Some(&blob)))?;
                Ok(after_commit(Round {
                    ack_through: fetched_max,
                    ..Round::default()
                }))
            }
            Ok(accepted) => {
                if !staged.staged() {
                    return Err(Error::Unavailable);
                }
                let (contact, events) = commit_accept(
                    &mut store,
                    ld_id,
                    &loaded.stored,
                    &accepted,
                    clock.unix_secs().saturating_mul(1_000),
                )?;
                Ok(after_commit(Round {
                    ack_through: fetched_max,
                    accepted: Some(contact),
                    events,
                    ops: Vec::new(),
                    to_session: Vec::new(),
                    invitation_queue: Some((loaded.stored.relay, loaded.stored.queue)),
                }))
            }
        }
    }
}

/// The ids of the cells that are byte-identical (constant time) to a spent cell but not spent themselves (Q202, EXTB1-4): a
/// complete group is spent after one `accept`, and a duplicate of one of its chunks in the same round's union must not be
/// kept to form the group again.
fn duplicates_of_spent(ids: &[u64], cells: &[Cell], spent_ids: &[u64]) -> Vec<u64> {
    use secmp_crypto::ConstantTimeEq as _;

    let spent: Vec<&Cell> = ids
        .iter()
        .zip(cells)
        .filter(|(id, _)| spent_ids.contains(id))
        .map(|(_, cell)| cell)
        .collect();
    ids.iter()
        .zip(cells)
        .filter(|(id, _)| !spent_ids.contains(id))
        .filter(|(_, cell)| {
            spent.iter().fold(false, |any, s| {
                any | bool::from(s.as_bytes().ct_eq(cell.as_bytes()))
            })
        })
        .map(|(id, _)| *id)
        .collect()
}

/// Whether the invitation of `ld_id` is offered at `now` (open and unexpired, R-69, ADR-044 (d)), consumed, or expired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OfferState {
    Offered,
    Consumed,
    Expired,
    Retired,
    /// Expired (or retired by an identity rotation) unconsumed; the row holds the queue's entry until the `QUEUE_DEL` is
    /// acknowledged (Q201).
    Retiring,
    /// No row, but the queue is still a session's recv-queue: a consumed record the sweep must have kept (Q207). Nothing is
    /// decided.
    Unavailable,
}

/// The [`OfferState`] of `ld_id` at `now` (Unix seconds), from its row; `on` is the queue a round fetched it from.
///
/// # Errors
/// [`Error::Unavailable`] if the store cannot be read.
fn offer_state(
    store: &Store,
    ld_id: &Id,
    on: Option<(RelayId, QueueId)>,
    now: u64,
) -> Result<OfferState, Error> {
    let Some(row) = store.invitations()?.into_iter().find(|r| r.ld_id == *ld_id) else {
        // no row while the queue is routed to a session: fail closed (Q207); otherwise retired (an unconsumed invitation
        // whose `QUEUE_DEL` completed, Q164, Q201)
        return Ok(match on {
            Some((relay, queue)) if routed(store, relay, queue)? => OfferState::Unavailable,
            _ => OfferState::Retired,
        });
    };
    Ok(if row.status == INVITATION_RETIRING {
        OfferState::Retiring
    } else if row.status != INVITATION_OPEN {
        OfferState::Consumed
    } else if row.expires_ms / 1000 <= now {
        OfferState::Expired
    } else {
        OfferState::Offered
    })
}

/// Whether `queue` of `relay` is a recv-queue of a session: an entry of a contact's `contacts.queues` (Q207).
///
/// # Errors
/// [`Error::Unavailable`] if the store cannot be read or a set does not decode.
pub(crate) fn routed(store: &Store, relay: RelayId, queue: QueueId) -> Result<bool, Error> {
    for c in store.contacts()? {
        if let Some(bytes) = store.contact_queues(c.id)?
            && QueueSet::decode(&bytes)?
                .entries
                .iter()
                .any(|e| e.relay == relay.0 && e.queue == queue.0)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// After the commit, before the acknowledgement (`CrashAt::AfterCommitBeforeAck`).
fn after_commit(round: Round) -> Round {
    #[cfg(feature = "kat")]
    secmp_store::kat::crash_point(secmp_store::kat::CrashAt::AfterCommitBeforeAck);
    round
}

/// The accept transaction (F-M7, C-12): the OPK row delete, the record's consumption, the cleared retained cells, the
/// contact (`peer`, `routes`, `profile`) and the session (`Accepted.state` in its parts), in one store transaction.
fn commit_accept(
    store: &mut Store,
    ld_id: &Id,
    stored: &Stored,
    accepted: &Accepted,
    now_ms: u64,
) -> Result<(ContactId, Vec<Event>), Error> {
    let record = &stored.record;
    let planned = contacts::plan(store, &accepted.peer)?;
    let routes = encode_routes(&accepted.routes)?;
    let queues = encode_queues(stored, now_ms)?;
    let session = planned.id.0;
    let new = NewContact {
        peer: &accepted.peer,
        profile: &accepted.profile,
        routes: Some(&routes),
        queues: Some(&queues),
    };
    store.txn(|tx| {
        delete_prekey(tx, KIND_OPK, i64::from(record.opk_id))?;
        set_invitation_status(tx, ld_id, INVITATION_CONSUMED)?;
        put_invitation_retained(tx, ld_id, None)?;
        contacts::write(tx, &planned, &new)?;
        crate::sessions::write_initial(tx, session, &accepted.state)
    })?;
    Ok((planned.id, contacts::events_of(&planned)))
}

/// `contacts.routes`: `count u8 ‖ RouteDescriptor × count` (the peer's reply routes, byte-identical to what it sent).
fn encode_routes(routes: &[RouteDescriptor]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut v = Zeroizing::new(vec![
        u8::try_from(routes.len()).map_err(|_| Error::Unavailable)?,
    ]);
    for r in routes {
        v.extend_from_slice(&r.encode()?);
    }
    Ok(v)
}

/// `contacts.queues` ([`QueueSet`]): the recv-queues of the session so far: the invitation queue, until the first reply
/// moves the session to a queue of its own (§6.6 step 4). Its entry is the record's ([`Stored::entry`], Q199): recipient seed,
/// sender seed and the invitation's period.
fn encode_queues(stored: &Stored, now_ms: u64) -> Result<Zeroizing<Vec<u8>>, Error> {
    QueueSet::first(stored.entry()?, now_ms).encode()
}

/// §5.5 as the invitee runs it on the invitation it was given and the link data `LINK_GET` returned, in this order
/// (IN-12, Q154): the URI decodes (`Invalid`); the version byte is 0x01 (`Invalid`) and the kind byte is 0x01
/// (`Unsupported`); the invitation parses (`Invalid`); `now ≥ expires` (`Expired`); the blob opens under the invitation's
/// key (`Invalid`); the inviter's fingerprint is the invitation's (`Mismatch`, compared in constant time); then
/// `invitee_check` — the signature of the bundle and its expiry (`Invalid`). The class is computed here, from the
/// invitation and the opened link data, shown to the user, never logged or sent; the protocol's own error stays uniform.
///
/// # Errors
/// [`InviteReject`] as above.
pub fn check_invitation(uri: &str, blob: &[u8], now: u64) -> Result<InviteeAccepted, InviteReject> {
    use secmp_crypto::{ConstantTimeEq as _, Fingerprint};

    let text = uri.strip_prefix(URI_PREFIX).ok_or(InviteReject::Invalid)?;
    let bytes = base64url_decode(text).map_err(|_| InviteReject::Invalid)?;
    match bytes.as_slice() {
        [ver, ..] if *ver != 1 => return Err(InviteReject::Invalid),
        [_, kind, ..] if *kind != 1 => return Err(InviteReject::Unsupported),
        [_, _, ..] => {}
        _ => return Err(InviteReject::Invalid),
    }
    let invitation = parse_invitation_uri(uri).map_err(|_| InviteReject::Invalid)?;
    if now >= invitation.expires {
        return Err(InviteReject::Expired);
    }
    let link_data = inv::open_blob(&invitation.ld_id, &invitation.link_key, blob)
        .map_err(|_| InviteReject::Invalid)?;
    let iks = link_data
        .inviter_iks
        .encode()
        .map_err(|_| InviteReject::Invalid)?;
    let fp = Fingerprint::of_encoded_iks(&iks).map_err(|_| InviteReject::Invalid)?;
    if !bool::from(fp.as_bytes().ct_eq(&invitation.inviter_fp)) {
        return Err(InviteReject::Mismatch);
    }
    inv::invitee_check(invitation, blob, now).map_err(|_| InviteReject::Invalid)
}

/// What the invitee holds after accepting an invitation: the three handshake cells, released only after they were made
/// durable together with the session (persist-before-send, §6.5), the contact it made of the inviter, and the pool queue
/// that became its reply queue.
pub struct InviteeStart {
    /// The three sealed handshake cells, byte-identical to the persisted ones (`sessions` part 4, Q150).
    pub cells: [Cell; 3],
    /// The contact made of the inviter (unverified); its id is its session's.
    pub contact: ContactId,
    /// Events (a duplicate identity, ADR-044 (f)).
    pub events: Vec<Event>,
    /// The spare queue the reply route names (no `QUEUE_NEW` at that moment, §5.5 step 5).
    pub reply_queue: QueueId,
}

/// What the invitee needs besides the invitation and its link data.
pub struct AcceptRequest<'a> {
    /// The user's relay whose spare queue becomes the reply queue.
    pub relay: RelayId,
    /// The period the user asks for on its reply queue.
    pub reply_period: Period,
    /// The user's own profile for the handshake.
    pub profile: &'a WireProfile,
}

impl Invitations {
    /// The invitee's side of an invitation (§5.5 steps 1–5, §6.4–§6.5): the checks of [`check_invitation`], the reply route
    /// from a spare queue of the user's relay (the pool's, so that no `QUEUE_NEW` is needed now), and the handshake
    /// (`Initiator::start`) with the user's own profile.
    ///
    /// # Errors
    /// [`Error::Invitation`] for a refused invitation; [`Error::Unavailable`] if the relay has no spare queue, randomness
    /// or the store is unavailable.
    pub fn accept_invitation(
        &self,
        uri: &str,
        blob: &[u8],
        req: &AcceptRequest<'_>,
        clock: &impl Clock,
        entropy: &mut impl Entropy,
    ) -> Result<InviteeStart, Error> {
        let now = clock.unix_secs();
        let accepted = check_invitation(uri, blob, now).map_err(Error::Invitation)?;
        let identity = self.profile.identity()?;
        let mut store = self.lock()?;
        let own_relay = RelayRef::decode(
            &store
                .relay_ref(i64::from(req.relay.0))?
                .ok_or(Error::Unavailable)?,
        )?;
        let (queue, rest) = take_oldest(&store, req.relay)?.ok_or(Error::Unavailable)?;
        let recv_seed = SecretBytes::<32>::from_slice(queue.recv_seed.expose_secret())?;
        let send_seed = SecretBytes::<32>::from_slice(queue.send_seed.expose_secret())?;
        let reply_queue = queue.queue;
        let route = RelayQueue::derived(
            own_relay,
            &ed25519_pk_of(&queue.recv_seed)?,
            queue.send_seed,
            req.reply_period,
        )?;
        let (cells, state) = Initiator::start(
            &accepted,
            &identity.initiator_keys(),
            &[RouteDescriptor::RelayQueue(route)],
            req.profile,
            now,
            entropy,
        )?;
        // the inviter: its identity and profile from the link data, the invitation queue as its route
        let invitation = accepted.invitation();
        let inviter_route = RouteDescriptor::RelayQueue(RelayQueue {
            relay: invitation.relay.clone(),
            sid: invitation.inv_sid,
            send_seed: SecretBytes::from_slice(invitation.inv_send_seed.expose_secret())?,
            period_s: invitation.inv_period_s,
        });
        let routes = encode_routes(&[inviter_route])?;
        let queues = QueueSet::first(
            QueueEntry {
                relay: req.relay.0,
                queue: reply_queue.0,
                seed: recv_seed,
                send_seed: Some(send_seed),
                period_s: req.reply_period.seconds(),
                retire_at_ms: None,
            },
            now.saturating_mul(1_000),
        )
        .encode()?;
        let link_data = accepted.link_data();
        let planned = contacts::plan(&store, &link_data.inviter_iks)?;
        let new = NewContact {
            peer: &link_data.inviter_iks,
            profile: &link_data.profile,
            routes: Some(&routes),
            queues: Some(&queues),
        };
        // persist-before-send: the pool queue, the contact, the session and the three cells are one transaction, and the
        // cells are released only after it committed (a failed start above took nothing from the pool)
        let released = cells.release(&state, |cell_bytes, state_bytes| {
            let parts = RatchetParts::split(state_bytes)?;
            store
                .txn(|tx| {
                    put_relay_pool(tx, i64::from(req.relay.0), Some(&rest))?;
                    contacts::write(tx, &planned, &new)?;
                    crate::sessions::write_initial_parts(tx, planned.id.0, &parts)?;
                    secmp_store::sessions::put_handshake(tx, planned.id.0, cell_bytes)
                })
                .map_err(Error::from)
        })?;
        Ok(InviteeStart {
            cells: released,
            contact: planned.id,
            events: contacts::events_of(&planned),
            reply_queue,
        })
    }
}

#[cfg(test)]
#[path = "invitations_tests.rs"]
mod tests;
