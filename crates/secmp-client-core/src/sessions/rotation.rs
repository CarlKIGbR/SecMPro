// SPDX-License-Identifier: AGPL-3.0-or-later
//! The rotation of a contact's recv-queue (spec §10.6 (4), §10.2; `docs/02` §4.3): every 30 days or on demand the recipient
//! takes a pooled queue, announces it with a `RouteUpdate` and keeps the previous queue, fetched for `U[1 h, 24 h]` more
//! (its `QUEUE_DEL` follows an empty `FETCH`, Q194). The queues of a contact are `contacts.queues` ([`QueueSet`], sealed,
//! Q151); a rotation that would exceed the rate bound or the 32 entries of a `FETCH_MULTI` does not start (§10.2).

use secmp_crypto::{SecretBytes, Zeroizing};
use secmp_proto::Decode as _;
use secmp_proto::wire::Period;
use secmp_proto::wire::cell::{RelayQueue, RouteDescriptor};
use secmp_proto::wire::inv::RelayRef;
use secmp_store::contacts::put_contact_queues;
use secmp_store::profile::put_relay_pool;

use super::StoreConversation;
use super::actor::EntropySource;
use crate::api::{ContactId, Error, Event};
use crate::invitations::{ed25519_pk_of, take_oldest};
use crate::persist::SharedStore;
use crate::scheduler::control::{OpSpec, When};
use crate::scheduler::params::{FETCH_MULTI_LIMIT, Mode, Params};
use crate::scheduler::types::{ControlKind, QueueId, RelayId};
use crate::timing::TimingRng;

/// `PERIODS` in seconds (spec §9.8).
const PERIODS_S: [u16; 4] = [10, 20, 40, 80];

/// A recv-queue is rotated at the latest after 30 days (`docs/02:115`).
pub const ROTATION_INTERVAL_MS: u64 = 30 * 24 * 3_600_000;

/// How long the previous queue is fetched after a rotation, `U[1 h, 24 h]` (§10.6 (4)).
pub const OVERLAP_MS: (u64, u64) = (3_600_000, 86_400_000);

/// One recv-queue of a contact: where it lives, its keys (the recipient seed, and the sender seed if the queue can be
/// re-created identically after a relay restart, spec §9.1), its period, and — while it is in overlap — the end of its fetch
/// period.
pub struct QueueEntry {
    /// The relay (a row of `relays`).
    pub relay: u32,
    /// The scheduler's id of the queue.
    pub queue: u32,
    /// The Ed25519 seed of the recipient key.
    pub seed: SecretBytes<32>,
    /// The Ed25519 seed of the sender key; `None` for an invitation queue (it is replaced by the first reply and not
    /// re-created).
    pub send_seed: Option<SecretBytes<32>>,
    /// The queue's period in seconds (`PERIODS`).
    pub period_s: u16,
    /// When the queue stops being fetched (Unix milliseconds); `None` for the current queue.
    pub retire_at_ms: Option<u64>,
}

/// One entry of `contacts.queues` on the wire: `relay u32 ‖ queue u32 ‖ seed [32] ‖ send_seed [32] ‖ period_s u16 ‖ flags u8 ‖
/// retire_at_ms u64`.
const ENTRY_LEN: usize = 83;

/// `contacts.queues`: `count u8 ‖ rotated_ms u64 ‖ entry × count`. The newest entry is the current queue, the others are in
/// overlap; `flags` bit 0 is set (and `retire_at_ms` given) for a queue in overlap, bit 1 when the sender seed is known (else
/// its 32 bytes are zero); no other bit.
pub struct QueueSet {
    /// When the current queue was made current (Unix milliseconds).
    pub rotated_ms: u64,
    /// The queues, oldest first.
    pub entries: Vec<QueueEntry>,
}

impl QueueEntry {
    /// The entry on the wire (see [`QueueSet`]).
    fn write(&self, v: &mut Vec<u8>) {
        v.extend_from_slice(&self.relay.to_be_bytes());
        v.extend_from_slice(&self.queue.to_be_bytes());
        v.extend_from_slice(self.seed.expose_secret());
        match &self.send_seed {
            Some(s) => v.extend_from_slice(s.expose_secret()),
            None => v.extend_from_slice(&[0; 32]),
        }
        v.extend_from_slice(&self.period_s.to_be_bytes());
        v.push(u8::from(self.retire_at_ms.is_some()) | (u8::from(self.send_seed.is_some()) << 1));
        v.extend_from_slice(&self.retire_at_ms.unwrap_or(0).to_be_bytes());
    }

    /// One entry of exactly [`ENTRY_LEN`] bytes: a period of `PERIODS`, the flags as in [`QueueSet`], a zero deadline and
    /// zero sender seed where there is none.
    fn read(entry: &[u8]) -> Result<Self, Error> {
        if entry.len() != ENTRY_LEN {
            return Err(Error::Unavailable);
        }
        let relay = be32(entry.get(..4).ok_or(Error::Unavailable)?)?;
        let queue = be32(entry.get(4..8).ok_or(Error::Unavailable)?)?;
        let recv = entry.get(8..40).ok_or(Error::Unavailable)?;
        let sender = entry.get(40..72).ok_or(Error::Unavailable)?;
        let period_s = u16::from_be_bytes(
            entry
                .get(72..74)
                .ok_or(Error::Unavailable)?
                .try_into()
                .map_err(|_| Error::Unavailable)?,
        );
        let flags = *entry.get(74).ok_or(Error::Unavailable)?;
        let at = u64::from_be_bytes(
            entry
                .get(75..83)
                .ok_or(Error::Unavailable)?
                .try_into()
                .map_err(|_| Error::Unavailable)?,
        );
        if flags & !0b11 != 0 || !PERIODS_S.contains(&period_s) {
            return Err(Error::Unavailable);
        }
        let retire_at_ms = (flags & 1 == 1).then_some(at);
        if retire_at_ms.is_none() && at != 0 {
            return Err(Error::Unavailable);
        }
        let send_seed = if flags & 2 == 2 {
            Some(SecretBytes::from_slice(sender)?)
        } else if sender.iter().all(|b| *b == 0) {
            None
        } else {
            return Err(Error::Unavailable);
        };
        Ok(Self {
            relay,
            queue,
            seed: SecretBytes::from_slice(recv)?,
            send_seed,
            period_s,
            retire_at_ms,
        })
    }

    /// The entry alone, sealed by the caller (the row of a retiring invitation, Q201): [`ENTRY_LEN`] bytes.
    #[must_use]
    pub fn encode_one(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(ENTRY_LEN));
        self.write(&mut v);
        v
    }

    /// The entry of [`QueueEntry::encode_one`] (total: exact length, canonical as in [`QueueSet`]).
    ///
    /// # Errors
    /// [`Error::Unavailable`] for anything else.
    pub fn decode_one(bytes: &[u8]) -> Result<Self, Error> {
        Self::read(bytes)
    }
}

fn be32(b: &[u8]) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        b.try_into().map_err(|_| Error::Unavailable)?,
    ))
}

impl QueueSet {
    /// The set of a contact's first queue.
    #[must_use]
    pub fn first(entry: QueueEntry, now_ms: u64) -> Self {
        Self {
            rotated_ms: now_ms,
            entries: vec![entry],
        }
    }

    /// The encoding.
    ///
    /// # Errors
    /// [`Error::Unavailable`] for more than 255 entries.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let count = u8::try_from(self.entries.len()).map_err(|_| Error::Unavailable)?;
        let mut v = Zeroizing::new(Vec::with_capacity(
            self.entries
                .len()
                .saturating_mul(ENTRY_LEN)
                .saturating_add(9),
        ));
        v.push(count);
        v.extend_from_slice(&self.rotated_ms.to_be_bytes());
        for e in &self.entries {
            e.write(&mut v);
        }
        Ok(v)
    }

    /// Decode (total and canonical: exact length, at least one entry, a period of `PERIODS`, the flags as above, a zero
    /// deadline and zero sender seed where there is none, a deadline on every entry but the last and on no other).
    ///
    /// # Errors
    /// [`Error::Unavailable`] for anything else.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (count, rest) = bytes.split_first().ok_or(Error::Unavailable)?;
        let (rotated, mut rest) = rest.split_at_checked(8).ok_or(Error::Unavailable)?;
        let rotated_ms = u64::from_be_bytes(rotated.try_into().map_err(|_| Error::Unavailable)?);
        let mut entries = Vec::with_capacity(usize::from(*count));
        for i in 0..usize::from(*count) {
            let (entry, tail) = rest.split_at_checked(ENTRY_LEN).ok_or(Error::Unavailable)?;
            let entry = QueueEntry::read(entry)?;
            let last = i.checked_add(1) == Some(usize::from(*count));
            if last == entry.retire_at_ms.is_some() {
                return Err(Error::Unavailable);
            }
            entries.push(entry);
            rest = tail;
        }
        if entries.is_empty() || !rest.is_empty() {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            rotated_ms,
            entries,
        })
    }

    /// Whether the 30 days since the current queue was made current have passed (`docs/02:115`).
    #[must_use]
    pub fn due(&self, now_ms: u64) -> bool {
        self.rotated_ms
            .checked_add(ROTATION_INTERVAL_MS)
            .is_none_or(|at| now_ms >= at)
    }
}

/// Whether a rotation onto a queue of `new_period_ms` may start (§10.2): in Balanced and Low-bandwidth mode the queues in
/// overlap count toward the rate bound `Σ 1/P_q ≤ F_M / (2·T)` and toward the 32 entries of a `FETCH_MULTI`; Strict mode has
/// one link per queue and no such bound. `recv_periods_ms` are the periods of every recv-queue of the scheduler, the ones in
/// overlap included.
#[must_use]
pub fn rotation_fits(
    params: &Params,
    mode: Mode,
    recv_periods_ms: &[u64],
    new_period_ms: u64,
) -> bool {
    match mode {
        Mode::Strict => true,
        Mode::Balanced | Mode::LowBw => {
            recv_periods_ms.len() < FETCH_MULTI_LIMIT
                && params
                    .rate_bound_ok(mode, recv_periods_ms.iter().copied().chain([new_period_ms]))
        }
    }
}

/// What a rotation asks for.
pub struct RotateRequest<'a> {
    /// The contact.
    pub contact: ContactId,
    /// The relay whose pool provides the new queue.
    pub relay: RelayId,
    /// The new queue's period.
    pub period: Period,
    /// The effective scheduler mode.
    pub mode: Mode,
    /// The scheduler's parameters.
    pub params: &'a Params,
    /// The periods (ms) of every recv-queue of the scheduler, those in overlap included.
    pub recv_periods_ms: &'a [u64],
    /// The scheduler's id of the queue that is replaced, if the caller knows it: its `QUEUE_DEL` is asked for
    /// ([`Rotated::Started::retire_op`]).
    pub old_queue: Option<QueueId>,
    /// The Unix milliseconds at monotonic time 0 (the scheduler's clock) — the overlap deadline is Unix time in the store.
    pub unix_base_ms: u64,
}

/// The outcome of a rotation.
pub enum Rotated {
    /// A pooled queue became the contact's current recv-queue and the `RouteUpdate` is queued.
    Started {
        /// The scheduler's id of the new queue.
        queue: QueueId,
        /// Its recipient seed.
        recv_seed: SecretBytes<32>,
        /// The previous queue's recipient seed, now in overlap.
        retired: SecretBytes<32>,
        /// The end of the previous queue's fetch window (Unix milliseconds).
        retire_at_ms: u64,
        /// The `QUEUE_DEL` of the previous queue: after an empty `FETCH` at or after the end of its window, then
        /// `U[1 min, 60 min]` (§10.6 (2), (4)); `Some` if the request named the queue.
        retire_op: Option<OpSpec>,
    },
    /// The rotation did not start; the event says so (§10.2).
    Deferred(Event),
}

/// Rotate the recv-queue of `req.contact` at `now_ms`: the pooled queue, the new `contacts.queues` and the pool that is left
/// are one transaction; the `RouteUpdate` is queued on the conversation after it (a slot of the schedule carries it — no
/// slot is added or moved, spec §10.1).
///
/// # Errors
/// [`Error::Unavailable`] if the store, the relay row or the randomness is unavailable.
pub fn rotate<S: EntropySource>(
    store: &SharedStore,
    conversation: &mut StoreConversation<S>,
    req: &RotateRequest<'_>,
    now_ms: u64,
    rng: &mut TimingRng,
) -> Result<Rotated, Error> {
    let deferred = || Rotated::Deferred(Event::RotationDeferred(req.contact));
    let period_ms = u64::from(req.period.seconds()).saturating_mul(1_000);
    if !rotation_fits(req.params, req.mode, req.recv_periods_ms, period_ms) {
        return Ok(deferred());
    }
    let mut guard = store.lock().map_err(|_| Error::Unavailable)?;
    let mut set = QueueSet::decode(
        &guard
            .contact_queues(req.contact.0)?
            .ok_or(Error::Unavailable)?,
    )?;
    let own_relay = RelayRef::decode(
        &guard
            .relay_ref(i64::from(req.relay.0))?
            .ok_or(Error::Unavailable)?,
    )?;
    let Some((taken, rest)) = take_oldest(&guard, req.relay)? else {
        return Ok(deferred());
    };
    let retire_at_ms = now_ms.saturating_add(
        rng.uniform(OVERLAP_MS.0, OVERLAP_MS.1)
            .map_err(|_| Error::Unavailable)?,
    );
    let recv_seed = SecretBytes::<32>::from_slice(taken.recv_seed.expose_secret())?;
    let retired = {
        let last = set.entries.last_mut().ok_or(Error::Unavailable)?;
        last.retire_at_ms = Some(retire_at_ms);
        SecretBytes::<32>::from_slice(last.seed.expose_secret())?
    };
    set.entries.push(QueueEntry {
        relay: req.relay.0,
        queue: taken.queue.0,
        seed: SecretBytes::from_slice(recv_seed.expose_secret())?,
        send_seed: Some(SecretBytes::from_slice(taken.send_seed.expose_secret())?),
        period_s: req.period.seconds(),
        retire_at_ms: None,
    });
    set.rotated_ms = now_ms;
    let route = RouteDescriptor::RelayQueue(RelayQueue::derived(
        own_relay,
        &ed25519_pk_of(&recv_seed)?,
        taken.send_seed,
        req.period,
    )?);
    let encoded = set.encode()?;
    guard.txn(|tx| {
        put_relay_pool(tx, i64::from(req.relay.0), Some(&rest))?;
        put_contact_queues(tx, req.contact.0, &encoded)
    })?;
    drop(guard);
    conversation.queue_route_update(vec![route]);
    let retire_op = req.old_queue.map(|old| OpSpec {
        kind: ControlKind::QueueDel(old),
        relay: req.relay,
        related: u64::from(old.0),
        when: When::AfterEmptyFetchFrom(old, retire_at_ms.saturating_sub(req.unix_base_ms)),
    });
    Ok(Rotated::Started {
        queue: taken.queue,
        recv_seed,
        retired,
        retire_at_ms,
        retire_op,
    })
}
