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

/// A recv-queue is rotated at the latest after 30 days (`docs/02:115`).
pub const ROTATION_INTERVAL_MS: u64 = 30 * 24 * 3_600_000;

/// How long the previous queue is fetched after a rotation, `U[1 h, 24 h]` (§10.6 (4)).
pub const OVERLAP_MS: (u64, u64) = (3_600_000, 86_400_000);

/// One recv-queue of a contact: its recipient seed, and while it is in overlap the end of its fetch window.
pub struct QueueEntry {
    /// The Ed25519 seed of the recipient key.
    pub seed: SecretBytes<32>,
    /// When the queue stops being fetched (Unix milliseconds); `None` for the current queue.
    pub retire_at_ms: Option<u64>,
}

/// `contacts.queues`: `count u8 ‖ rotated_ms u64 ‖ {seed [32] ‖ flag u8 ‖ retire_at_ms u64} × count`. The newest entry is the
/// current queue, the others are in overlap; `flag` is 0 (and `retire_at_ms` 0) for the current queue, 1 otherwise.
pub struct QueueSet {
    /// When the current queue was made current (Unix milliseconds).
    pub rotated_ms: u64,
    /// The queues, oldest first.
    pub entries: Vec<QueueEntry>,
}

impl QueueSet {
    /// The set of a contact's first queue.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the seed does not copy.
    pub fn first(seed: &SecretBytes<32>, now_ms: u64) -> Result<Self, Error> {
        Ok(Self {
            rotated_ms: now_ms,
            entries: vec![QueueEntry {
                seed: SecretBytes::from_slice(seed.expose_secret())?,
                retire_at_ms: None,
            }],
        })
    }

    /// The encoding.
    ///
    /// # Errors
    /// [`Error::Unavailable`] for more than 255 entries.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let count = u8::try_from(self.entries.len()).map_err(|_| Error::Unavailable)?;
        let mut v = Zeroizing::new(vec![count]);
        v.extend_from_slice(&self.rotated_ms.to_be_bytes());
        for e in &self.entries {
            v.extend_from_slice(e.seed.expose_secret());
            v.push(u8::from(e.retire_at_ms.is_some()));
            v.extend_from_slice(&e.retire_at_ms.unwrap_or(0).to_be_bytes());
        }
        Ok(v)
    }

    /// Decode (total and canonical: exact length, at least one entry, the flag 0 or 1, 0 with a zero deadline, only the last
    /// entry without a deadline).
    ///
    /// # Errors
    /// [`Error::Unavailable`] for anything else.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (count, rest) = bytes.split_first().ok_or(Error::Unavailable)?;
        let (rotated, mut rest) = rest.split_at_checked(8).ok_or(Error::Unavailable)?;
        let rotated_ms = u64::from_be_bytes(rotated.try_into().map_err(|_| Error::Unavailable)?);
        let mut entries = Vec::with_capacity(usize::from(*count));
        for i in 0..usize::from(*count) {
            let (seed, tail) = rest.split_at_checked(32).ok_or(Error::Unavailable)?;
            let (flag, tail) = tail.split_first().ok_or(Error::Unavailable)?;
            let (at, tail) = tail.split_at_checked(8).ok_or(Error::Unavailable)?;
            let at = u64::from_be_bytes(at.try_into().map_err(|_| Error::Unavailable)?);
            let retire_at_ms = match (*flag, at) {
                (0, 0) => None,
                (1, at) => Some(at),
                _ => return Err(Error::Unavailable),
            };
            let last = i.checked_add(1) == Some(usize::from(*count));
            if last == retire_at_ms.is_some() {
                return Err(Error::Unavailable);
            }
            entries.push(QueueEntry {
                seed: SecretBytes::from_slice(seed)?,
                retire_at_ms,
            });
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
        seed: SecretBytes::from_slice(recv_seed.expose_secret())?,
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
