// SPDX-License-Identifier: AGPL-3.0-or-later
//! The hub (`docs/02` §4.4, D-C2-1): the client core as the scheduler's one cell source and the author of its
//! registrations. It owns the [`Core`] (profile, sessions, the `Api`'s state), routes a cell by the queue it is for —
//! an invitation queue goes to the invitation round, every other queue to its session — and turns what the sessions and
//! the invitations decide into [`Action`]s for the scheduler: queues to fetch and to send to, queues to retire, control
//! operations. The driver applies the actions; the hub never reaches into the scheduler (sans-IO, spec §10.1: an action
//! adds or retires a queue, it never adds a slot of its own).
//!
//! **Stable ids.** A queue's id is the one its pool entry or its invitation record carries, and the contact's
//! `contacts.queues` ([`crate::sessions::rotation::QueueSet`]) persists it, so a restart registers the same queues under
//! the same ids. A send queue's id is the hub's own (above [`SEND_BASE`]); it lives as long as the route it was made from.
//!
//! **Handshake as scheduled operations.** An invitation is `LINK_PUT` on a one-shot link, the invitee's `LINK_GET` another,
//! and the three handshake cells go out on the scheduled `SEND` slots of the invitation queue: nothing here is a set-up
//! link outside the schedule (IN-17).

use std::collections::{BTreeMap, BTreeSet};

use secmp_crypto::SecretBytes;
use secmp_proto::Decode as _;
use secmp_proto::wire::cell::{Cell, RouteDescriptor, RouteUpdateBody};
use secmp_proto::wire::inv::Profile as WireProfile;
use secmp_proto::wire::{Id, Period};

use crate::api::{ContactId, Core, Error};
use crate::clock::Clock;
use crate::invitations::{
    AcceptRequest, Invitations, Issuance, IssueRequest, LinkPutArgs, uri_link_data,
};
use crate::scheduler::control::{OpSpec, When};
use crate::scheduler::types::{
    CellSource, CellToken, ControlKind, Delivered, PreparedCell, QueueId, RelayId, SendFailure,
    SourceError,
};
use crate::sessions::actor::EntropySource;
use crate::sessions::rotation::{OVERLAP_MS, QueueSet};

/// The first id of the send queues the hub numbers itself; pool and invitation queues are below it.
pub const SEND_BASE: u32 = 0x4000_0000;

/// How long a queue in send overlap carries dummies when no draw is possible: the longest the recipient keeps fetching the
/// old queue, `U[1 h, 24 h]` (§10.6 (4)), and a minute more. The hub draws its own `U[1 h, 24 h]` (the sender stops at a
/// time of its own, so that the recipient's last `FETCH` of the old queue finds it empty and its `QUEUE_DEL` can follow).
pub const OLD_SEND_MS: u64 = 24 * 3_600_000 + 60_000;

/// What the hub asks of the scheduler.
pub enum Action {
    /// Fetch `queue` of `relay` (recipient seed `seed`) every `period_ms`.
    AddRecv {
        /// The queue's id.
        queue: QueueId,
        /// Its relay.
        relay: RelayId,
        /// The Ed25519 seed of the recipient key.
        seed: SecretBytes<32>,
        /// Its period.
        period_ms: u64,
    },
    /// Send to the queue `sid` of `relay` (sender seed `seed`) once per `period_ms`.
    AddSend {
        /// The hub's id for the queue.
        queue: QueueId,
        /// Its relay.
        relay: RelayId,
        /// The queue's sender id (spec §9.1).
        sid: Id,
        /// The Ed25519 seed of the sender key.
        seed: SecretBytes<32>,
        /// Its period.
        period_ms: u64,
    },
    /// Stop fetching or sending `queue`.
    Remove {
        /// The queue.
        queue: QueueId,
    },
    /// A control operation on a one-shot link (spec §10.6 (2)).
    Control(OpSpec),
}

/// What the hub needs to know about its user.
pub struct HubConfig {
    /// The relay of the user (a row of `relays`).
    pub relay: RelayId,
    /// The period of an invitation queue the hub issues.
    pub inv_period: Period,
    /// The period of the reply queue an invitation accepted by the hub asks for, and of the queue its first reply names.
    pub reply_period: Period,
    /// The profile the user presents in a handshake and in link data.
    pub profile: WireProfile,
}

/// The hub (see the module documentation).
pub struct Hub<C: Clock, S: EntropySource> {
    core: Core<C, S>,
    config: HubConfig,
    invitations: Invitations,
    /// The invitation queues the hub fetches, with their invitation.
    inv_queues: BTreeMap<QueueId, Id>,
    /// Invitations the user is accepting: link-data number → URI, until the `LINK_GET` returns.
    waiting: BTreeMap<u32, String>,
    registered: BTreeSet<QueueId>,
    send_ids: BTreeMap<i64, QueueId>,
    retiring_sends: Vec<(u64, QueueId)>,
    /// The queue each contact sent to before its latest route update.
    previous_sends: BTreeMap<i64, QueueId>,
    next_send: u32,
    /// The period of every recv-queue the hub has registered and not removed: the rate bound of a rotation counts them all
    /// (§10.2), also the ones in overlap.
    recv_periods: BTreeMap<QueueId, u64>,
    actions: Vec<Action>,
    rng: crate::timing::TimingRng,
}

impl<C: Clock, S: EntropySource> Hub<C, S> {
    /// The hub of `core`: every contact with a session and every open invitation is registered (the actions are taken with
    /// [`Hub::take_actions`]).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read.
    pub fn new(core: Core<C, S>, config: HubConfig) -> Result<Self, Error> {
        let invitations = Invitations::new(core.profile.clone());
        let mut hub = Self {
            core,
            config,
            invitations,
            inv_queues: BTreeMap::new(),
            waiting: BTreeMap::new(),
            registered: BTreeSet::new(),
            send_ids: BTreeMap::new(),
            retiring_sends: Vec::new(),
            previous_sends: BTreeMap::new(),
            next_send: 0,
            recv_periods: BTreeMap::new(),
            actions: Vec::new(),
            rng: crate::timing::TimingRng::os(),
        };
        for open in hub.invitations.open_queues()? {
            let period = u64::from(hub.config.inv_period.seconds()).saturating_mul(1_000);
            hub.register_recv(open.relay, open.queue, &open.recv_seed, period);
            hub.inv_queues.insert(open.queue, open.ld_id);
        }
        let contacts: Vec<ContactId> = hub.core.index.keys().map(|c| ContactId(*c)).collect();
        for contact in contacts {
            hub.register_contact(contact)?;
        }
        Ok(hub)
    }

    /// Seed the timing randomness of the hub and of its core: tests only, for runs that repeat.
    #[cfg(feature = "kat")]
    pub fn seed_timing_kat(&mut self, seed: u64) {
        self.rng = crate::timing::TimingRng::seeded(seed);
        self.core.seed_timing_kat(seed);
    }

    /// Whether the conversation that sends on `queue` has something real waiting for a slot (the cost models of the test
    /// drivers; the scheduler never asks).
    pub fn pending_real(&mut self, queue: QueueId) -> bool {
        self.core.convs.pending_real(queue)
    }

    /// `fingerprint(IKSPublic)` of the user (§6.2; public).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the profile has no identity.
    pub fn own_fingerprint(&self) -> Result<[u8; 32], Error> {
        self.core.profile.fingerprint()
    }

    /// The user's `IKSPublic` encoding (public; a test searches the wire for it).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the profile has no identity.
    pub fn own_iks(&self) -> Result<Vec<u8>, Error> {
        use secmp_proto::Encode as _;

        Ok(self.core.profile.identity()?.public().encode()?.to_vec())
    }

    /// The profile's store (a test reads rows through it).
    #[must_use]
    pub fn profile_store(&self) -> crate::persist::SharedStore {
        self.core.profile_store()
    }

    /// The core (the `Api`'s state).
    pub const fn core_mut(&mut self) -> &mut Core<C, S> {
        &mut self.core
    }

    /// The core.
    #[must_use]
    pub const fn core(&self) -> &Core<C, S> {
        &self.core
    }

    /// What the hub asks of the scheduler since the last call.
    pub fn take_actions(&mut self) -> Vec<Action> {
        core::mem::take(&mut self.actions)
    }

    fn unix_base(&self) -> u64 {
        self.core.now_ms().saturating_sub(self.core.clock.mono_ms())
    }

    fn register_recv(
        &mut self,
        relay: RelayId,
        queue: QueueId,
        seed: &SecretBytes<32>,
        period_ms: u64,
    ) {
        if !self.registered.insert(queue) {
            return;
        }
        if let Ok(seed) = SecretBytes::from_slice(seed.expose_secret()) {
            self.recv_periods.insert(queue, period_ms);
            self.sync_view();
            self.actions.push(Action::AddRecv {
                queue,
                relay,
                seed,
                period_ms,
            });
        }
    }

    /// What the core's rotation sees of the scheduler's recv-queues.
    fn sync_view(&mut self) {
        self.core.view.recv_periods_ms = self.recv_periods.values().copied().collect();
    }

    fn alloc_send(&mut self) -> QueueId {
        self.next_send = self.next_send.saturating_add(1);
        QueueId(SEND_BASE.saturating_add(self.next_send))
    }

    /// Register the queues of `contact`: the recv-queues of its queue set (the ones in overlap with their retirement), the
    /// send queue of its route, and bind them to its conversation.
    fn register_contact(&mut self, contact: ContactId) -> Result<(), Error> {
        if !self.core.index.contains_key(&contact.0) {
            self.core.open_session(contact)?;
        }
        let (queues, routes) = {
            let s = self.core.store.lock().map_err(|_| Error::Unavailable)?;
            (s.contact_queues(contact.0)?, s.contact_routes(contact.0)?)
        };
        let base = self.unix_base();
        let at = *self.core.index.get(&contact.0).ok_or(Error::Unavailable)?;
        if let Some(bytes) = queues {
            let set = QueueSet::decode(&bytes)?;
            for entry in &set.entries {
                let queue = QueueId(entry.queue);
                self.register_recv(
                    RelayId(entry.relay),
                    queue,
                    &entry.seed,
                    u64::from(entry.period_s).saturating_mul(1_000),
                );
                if let Some(conversation) = self.core.convs.get_mut(at) {
                    conversation.rotate_recv_queue(queue);
                }
                if let Some(retire_at) = entry.retire_at_ms {
                    // re-armed from the stored deadline after a restart (Q194)
                    let from = retire_at.saturating_sub(base);
                    self.actions.push(Action::Control(OpSpec {
                        kind: ControlKind::QueueDel(queue),
                        relay: RelayId(entry.relay),
                        related: u64::from(queue.0),
                        when: When::AfterEmptyFetchFrom(queue, from),
                    }));
                }
            }
        }
        if let Some(bytes) = routes {
            self.register_route(contact, at, &bytes)?;
        }
        Ok(())
    }

    /// The send queue of the first route of a kind this version knows.
    fn register_route(&mut self, contact: ContactId, at: usize, bytes: &[u8]) -> Result<(), Error> {
        let body = RouteUpdateBody::decode(bytes)?;
        let Some(route) = body.routes.iter().find_map(|r| match r {
            RouteDescriptor::RelayQueue(q) => Some(q),
            RouteDescriptor::Unknown { .. } => None,
        }) else {
            return Ok(());
        };
        let queue = self.alloc_send();
        self.actions.push(Action::AddSend {
            queue,
            relay: self.config.relay,
            sid: route.sid,
            seed: SecretBytes::from_slice(route.send_seed.expose_secret())?,
            period_ms: u64::from(route.period_s.seconds()).saturating_mul(1_000),
        });
        self.registered.insert(queue);
        let previous = self.send_ids.insert(contact.0, queue);
        if let Some(conversation) = self.core.convs.get_mut(at) {
            match previous {
                Some(_) => {
                    conversation.switch_send_queue(queue);
                }
                None => conversation.set_send_queue(queue),
            }
        }
        if let Some(old) = previous {
            self.previous_sends.insert(contact.0, old);
            let overlap = self
                .rng
                .uniform(OVERLAP_MS.0, OVERLAP_MS.1)
                .unwrap_or(OLD_SEND_MS);
            let until = self.core.clock.mono_ms().saturating_add(overlap);
            self.retiring_sends.push((until, old));
        }
        Ok(())
    }

    /// Issue an invitation (§5.2): the invitation queue is fetched at the configured period and the `LINK_PUT` runs at once
    /// on a one-shot link.
    ///
    /// # Errors
    /// As [`Invitations::issue`].
    pub fn invite(&mut self, expires: u64) -> Result<Issuance, Error> {
        let mut source = (self.core.make_source)();
        let issued = self.invitations.issue(
            &IssueRequest {
                relay: self.config.relay,
                inv_period: self.config.inv_period,
                profile: self.config.profile.clone(),
                expires,
            },
            &self.core.clock,
            source.entropy(),
        )?;
        let open = self.invitations.queue_of(&issued.invitation.ld_id)?;
        let period = u64::from(self.config.inv_period.seconds()).saturating_mul(1_000);
        self.register_recv(open.relay, open.queue, &open.recv_seed, period);
        self.inv_queues.insert(open.queue, open.ld_id);
        for op in &issued.ops {
            self.actions.push(Action::Control(*op));
        }
        Ok(issued)
    }

    /// The queue `contact` sends to now and the one before it (in send overlap), if it has switched (SE-02).
    #[must_use]
    pub fn sends_of(&self, contact: ContactId) -> Option<(QueueId, QueueId)> {
        let current = *self.send_ids.get(&contact.0)?;
        let previous = self.previous_sends.get(&contact.0).copied()?;
        Some((previous, current))
    }

    /// The queue of the invitation `ld_id` the hub fetches.
    #[must_use]
    pub fn invitation_queue(&self, ld_id: &Id) -> Option<QueueId> {
        self.inv_queues
            .iter()
            .find(|(_, l)| *l == ld_id)
            .map(|(q, _)| *q)
    }

    /// The `LINK_PUT` arguments of link data `n` (the driver's control operation asks for them).
    ///
    /// # Errors
    /// As [`Invitations::link_put_args`].
    pub fn link_put_args(&self, n: u32) -> Result<LinkPutArgs, Error> {
        self.invitations.link_put_args(n)
    }

    /// The user is accepting `uri`: the consuming `LINK_GET` runs at once on a one-shot link (a user waits, §10.6 (2)); its
    /// result comes back through [`Hub::link_consumed`]. Returns the link-data number.
    ///
    /// # Errors
    /// [`Error::Invitation`] for a URI that does not parse.
    pub fn begin_accept(&mut self, uri: &str) -> Result<(Id, u32), Error> {
        let (ld_id, n) = uri_link_data(uri)?;
        self.waiting.insert(n, uri.to_owned());
        self.actions.push(Action::Control(OpSpec {
            kind: ControlKind::LinkGetConsume(n),
            relay: self.config.relay,
            related: u64::from(n),
            when: When::Prompt,
        }));
        Ok((ld_id, n))
    }

    /// The consuming `LINK_GET` of link data `n` returned (`blob` is the link data, `None` if it was gone): the accept —
    /// the checks of §5.5, the reply queue from the pool, the handshake — and the registration of the new contact's queues.
    ///
    /// # Errors
    /// [`Error::Invitation`] / [`Error::Unavailable`] as [`Invitations::accept_invitation`].
    pub fn link_consumed(&mut self, n: u32, blob: Option<&[u8]>) -> Result<ContactId, Error> {
        let uri = self.waiting.remove(&n).ok_or(Error::Unavailable)?;
        let blob = blob.ok_or(Error::Invitation(crate::api::InviteReject::Invalid))?;
        let mut source = (self.core.make_source)();
        let start = self.invitations.accept_invitation(
            &uri,
            blob,
            &AcceptRequest {
                relay: self.config.relay,
                reply_period: self.config.reply_period,
                profile: &self.config.profile,
            },
            &self.core.clock,
            source.entropy(),
        )?;
        for event in start.events {
            self.core.raise(event);
        }
        self.register_contact(start.contact)?;
        Ok(start.contact)
    }

    /// Deliver one cell of an invitation queue to the invitation round (§6.5). A complete handshake is accepted; the first
    /// reply then names a pool queue and retires the invitation queue (§6.6 step 4, §10.6 (5)).
    fn deliver_invitation(
        &mut self,
        (queue, ld_id): (QueueId, Id),
        generation: u64,
        id: u64,
        cell: &Cell,
    ) -> Result<Delivered, SourceError> {
        let copy = Cell::from_bytes(cell.as_bytes()).map_err(|_| SourceError)?;
        let mut source = (self.core.make_source)();
        let round = self
            .invitations
            .process_round(&ld_id, &[(id, copy)], &self.core.clock, source.entropy())
            .map_err(|_| SourceError)?;
        for event in round.events {
            self.core.raise(event);
        }
        for op in round.ops {
            self.actions.push(Action::Control(op));
        }
        if let Some(contact) = round.accepted {
            self.on_accepted(contact, round.invitation_queue)
                .map_err(|_| SourceError)?;
        }
        if round.to_session.contains(&id) {
            // a cell of a consumed invitation's queue is a cell of its session (Q193)
            return self.core.convs.deliver(queue, generation, id, cell);
        }
        match round.ack_through {
            Some(through) if through >= id => Ok(Delivered::Committed),
            _ => Err(SourceError),
        }
    }

    fn on_accepted(
        &mut self,
        contact: ContactId,
        invitation_queue: Option<(RelayId, QueueId)>,
    ) -> Result<(), Error> {
        self.core.open_session(contact)?;
        self.register_contact(contact)?;
        // the first reply names a pool queue and retires the invitation queue (§6.6 step 4, §10.6 (5))
        if let Some((relay, _)) = invitation_queue {
            self.core.rotation_period = self.config.reply_period;
            self.core.rotate_contact(contact, relay)?;
        }
        Ok(())
    }

    /// Take what the sessions delivered, and act on it: the application's messages and events (`Core::pump`), a route that
    /// moved the send queue.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read or written.
    pub fn pump(&mut self) -> Result<(), Error> {
        self.core.pump()?;
        for done in core::mem::take(&mut self.core.rotated) {
            let period = u64::from(done.period.seconds()).saturating_mul(1_000);
            self.register_recv(done.relay, done.queue, &done.recv_seed, period);
            if let Some(op) = done.retire_op {
                self.actions.push(Action::Control(op));
            }
        }
        let changed = core::mem::take(&mut self.core.routes_changed);
        for contact in changed {
            let routes = self
                .core
                .store
                .lock()
                .map_err(|_| Error::Unavailable)?
                .contact_routes(contact.0)?;
            let at = *self.core.index.get(&contact.0).ok_or(Error::Unavailable)?;
            if let Some(bytes) = routes {
                self.register_route(contact, at, &bytes)?;
            }
        }
        Ok(())
    }

    /// Time passes: the queues that carried dummies in overlap long enough are dropped.
    pub fn tick(&mut self, now_ms: u64) {
        let (due, keep): (Vec<_>, Vec<_>) = core::mem::take(&mut self.retiring_sends)
            .into_iter()
            .partition(|(until, _)| *until <= now_ms);
        self.retiring_sends = keep;
        for (_, queue) in due {
            for (_, at) in self.core.index.clone() {
                if let Some(c) = self.core.convs.get_mut(at) {
                    c.drop_send_queue(queue);
                }
            }
            self.actions.push(Action::Remove { queue });
        }
    }

    /// The `QUEUE_DEL` of `queue` ran: the queue leaves its contact's queue set, its conversation and the scheduler.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be written.
    pub fn queue_deleted(&mut self, queue: QueueId) -> Result<(), Error> {
        self.inv_queues.remove(&queue);
        self.recv_periods.remove(&queue);
        self.sync_view();
        let contacts: Vec<(i64, usize)> = self.core.index.iter().map(|(c, i)| (*c, *i)).collect();
        for (contact, at) in contacts {
            let bytes = self
                .core
                .store
                .lock()
                .map_err(|_| Error::Unavailable)?
                .contact_queues(contact)?;
            let Some(bytes) = bytes else { continue };
            let mut set = QueueSet::decode(&bytes)?;
            let before = set.entries.len();
            set.entries
                .retain(|e| !(e.queue == queue.0 && e.retire_at_ms.is_some()));
            if set.entries.len() == before {
                continue;
            }
            let encoded = set.encode()?;
            self.core
                .store
                .lock()
                .map_err(|_| Error::Unavailable)?
                .txn(|tx| secmp_store::contacts::put_contact_queues(tx, contact, &encoded))?;
            if let Some(c) = self.core.convs.get_mut(at) {
                c.drop_recv_queue(queue);
            }
        }
        self.actions.push(Action::Remove { queue });
        Ok(())
    }

    /// The seeds `(recipient, sender)` of the queue `queue`, for a `QUEUE_NEW` or `QUEUE_DEL` the scheduler asks for (the
    /// sender seed is all zero for an invitation queue, which is not re-created).
    #[must_use]
    pub fn queue_material(&self, queue: QueueId) -> Option<([u8; 32], [u8; 32])> {
        let s = self.core.store.lock().ok()?;
        for contact in self.core.index.keys() {
            let Ok(Some(bytes)) = s.contact_queues(*contact) else {
                continue;
            };
            let Ok(set) = QueueSet::decode(&bytes) else {
                continue;
            };
            if let Some(e) = set.entries.iter().find(|e| e.queue == queue.0) {
                let recv = *e.seed.expose_secret();
                let send = e.send_seed.as_ref().map_or([0; 32], |s| *s.expose_secret());
                return Some((recv, send));
            }
        }
        drop(s);
        let ld_id = self.inv_queues.get(&queue)?;
        let open = self.invitations.queue_of(ld_id).ok()?;
        Some((*open.recv_seed.expose_secret(), [0; 32]))
    }
}

impl<C: Clock, S: EntropySource> CellSource for Hub<C, S> {
    fn prepare_cell(
        &mut self,
        queue: QueueId,
        now: u64,
    ) -> Result<Option<PreparedCell>, SourceError> {
        self.core.convs.prepare_cell(queue, now)
    }

    fn relayed(&mut self, queue: QueueId, token: CellToken, cell_id: u64) {
        self.core.convs.relayed(queue, token, cell_id);
    }

    fn evicted(&mut self, queue: QueueId, cell_id: u64) {
        self.core.convs.evicted(queue, cell_id);
    }

    fn send_failed(&mut self, queue: QueueId, token: CellToken, why: SendFailure) {
        self.core.convs.send_failed(queue, token, why);
    }

    fn discard(&mut self, queue: QueueId, token: CellToken) {
        self.core.convs.discard(queue, token);
    }

    fn queue_lost(&mut self, queue: QueueId) {
        self.core.convs.queue_lost(queue);
    }

    fn deliver(
        &mut self,
        queue: QueueId,
        generation: u64,
        cell_id: u64,
        cell: &Cell,
    ) -> Result<Delivered, SourceError> {
        if let Some(ld_id) = self.inv_queues.get(&queue).copied() {
            return self.deliver_invitation((queue, ld_id), generation, cell_id, cell);
        }
        self.core.convs.deliver(queue, generation, cell_id, cell)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "kat")]
    use super::*;
    #[cfg(feature = "kat")]
    use crate::api::{Request, Response};
    #[cfg(feature = "kat")]
    use crate::clock::ManualClock;
    #[cfg(feature = "kat")]
    use crate::scheduler::outbox::{MsgState, Outbox as _};
    #[cfg(feature = "kat")]
    use crate::sessions::tests::{R, big, ms, party};
    #[cfg(feature = "kat")]
    use crate::testutil::{DAY, Fixed, Fixture, T0, entropy, wire_profile};
    #[cfg(feature = "kat")]
    use crate::timing::TimingRng;
    #[cfg(feature = "kat")]
    use secmp_proto::Encode as _;
    #[cfg(feature = "kat")]
    use std::sync::Arc;

    /// A hub over the profile of `fx`, its randomness a fixed stream by `seed`.
    #[cfg(feature = "kat")]
    fn hub_over(
        fx: &Fixture,
        name: &str,
        seed: u64,
    ) -> Result<Hub<ManualClock, Fixed>, crate::api::Error> {
        let mut count = 0_u64;
        let core = Core::with_profile(fx.profile.clone(), fx.clock.clone(), move || {
            count = count.saturating_add(1);
            Fixed(entropy(seed.saturating_add(count)))
        })?;
        Hub::new(
            core,
            HubConfig {
                relay: RelayId(1),
                inv_period: Period::S10,
                reply_period: Period::S10,
                profile: wire_profile(name).map_err(|_| crate::api::Error::Unavailable)?,
            },
        )
    }

    /// The `AddSend` of `actions`: its queue.
    #[cfg(feature = "kat")]
    fn added_send(actions: &[Action]) -> Option<QueueId> {
        actions.iter().find_map(|a| match a {
            Action::AddSend { queue, .. } => Some(*queue),
            _ => None,
        })
    }

    /// The state the steps of the hub contract share: both hubs and what one step hands the next.
    #[cfg(feature = "kat")]
    struct Scene {
        host: Fixture,
        inviter: Hub<ManualClock, Fixed>,
        invitee: Hub<ManualClock, Fixed>,
        issued: Option<crate::invitations::Issuance>,
        inv_queue: QueueId,
        n_link: u32,
        material_recv: [u8; 32],
        guest_send: QueueId,
        host_send: QueueId,
        reply_queue: QueueId,
        contact: ContactId,
        pooled: QueueId,
        retire_from: u64,
        moved: QueueId,
    }

    /// Step 1: the inviter issues: the invitation queue is fetched, the `LINK_PUT` runs at once.
    #[cfg(feature = "kat")]
    fn step_invite(sc: &mut Scene) -> R {
        assert_eq!(OLD_SEND_MS, 24 * 3_600_000 + 60_000);
        assert_eq!(SEND_BASE, 0x4000_0000);
        assert!(sc.inviter.take_actions().is_empty() && sc.invitee.take_actions().is_empty());
        // the timing draws are the seed's
        sc.inviter.seed_timing_kat(9);
        sc.invitee.seed_timing_kat(5);
        assert_eq!(
            sc.inviter.rng.uniform(1, 1_000),
            TimingRng::seeded(9).uniform(1, 1_000)
        );
        assert_eq!(
            sc.inviter.core.rng.uniform(1, 1_000),
            TimingRng::seeded(9).uniform(1, 1_000)
        );
        sc.inviter.seed_timing_kat(9);
        // the identity the hub shows
        assert_eq!(
            sc.inviter.own_fingerprint()?,
            sc.host.profile.fingerprint()?
        );
        let iks = sc.inviter.own_iks()?;
        assert_eq!(iks.len(), 2_017);
        assert_eq!(
            secmp_proto::prekeys::fingerprint_of(&secmp_proto::wire::inv::IksPublic::decode(
                &iks
            )?)?,
            sc.inviter.own_fingerprint()?
        );
        assert!(Arc::ptr_eq(
            &sc.inviter.profile_store(),
            &sc.host.profile.store()
        ));

        let issued = sc.inviter.invite(T0 + 5 * DAY)?;
        let inv_queue = sc
            .inviter
            .invitation_queue(&issued.invitation.ld_id)
            .ok_or("queue")?;
        assert_eq!(sc.inviter.invitation_queue(&[0xee; 16]), None);
        let actions = sc.inviter.take_actions();
        let [
            Action::AddRecv {
                queue,
                period_ms: 10_000,
                ..
            },
            Action::Control(put),
        ] = actions.as_slice()
        else {
            return Err("issue: AddRecv, LinkPut".into());
        };
        assert_eq!(*queue, inv_queue);
        let ControlKind::LinkPut(n_link) = put.kind else {
            return Err("a LinkPut".into());
        };
        assert!(matches!(put.when, When::Prompt));
        assert_eq!(
            sc.inviter.link_put_args(n_link)?.ld_id,
            issued.invitation.ld_id
        );
        let (material_recv, material_send) =
            sc.inviter.queue_material(inv_queue).ok_or("material")?;
        assert_eq!(
            material_recv,
            *sc.inviter
                .invitations
                .queue_of(&issued.invitation.ld_id)?
                .recv_seed
                .expose_secret()
        );
        assert_eq!(
            material_send, [0; 32],
            "an invitation queue has no sender seed"
        );
        assert_eq!(sc.inviter.queue_material(QueueId(999)), None);
        sc.issued = Some(issued);
        sc.inv_queue = inv_queue;
        sc.n_link = n_link;
        sc.material_recv = material_recv;
        Ok(())
    }

    /// Step 2: the invitee accepts: `LINK_GET` at once, then the contact, its reply queue and the route to the invitation queue.
    #[cfg(feature = "kat")]
    fn step_accept(sc: &mut Scene) -> R {
        let issued = sc.issued.as_ref().ok_or("issued")?;
        let n = sc.n_link;
        let (ld_id, n_get) = sc.invitee.begin_accept(&issued.uri)?;
        assert_eq!((ld_id, n_get), (issued.invitation.ld_id, n));
        let actions = sc.invitee.take_actions();
        assert!(matches!(
            actions.as_slice(),
            [Action::Control(OpSpec { kind: ControlKind::LinkGetConsume(m), when: When::Prompt, .. })] if *m == n
        ));
        assert!(
            sc.invitee
                .link_consumed(n.saturating_add(1), Some(&[0]))
                .is_err(),
            "not waiting for it"
        );
        assert!(
            sc.invitee.link_consumed(n, None).is_err(),
            "the link data is gone"
        );
        sc.invitee.begin_accept(&issued.uri)?;
        sc.invitee.take_actions();
        let blob = issued.blob.encode()?;
        sc.contact = sc.invitee.link_consumed(n, Some(&blob))?;
        let actions = sc.invitee.take_actions();
        sc.guest_send = added_send(&actions).ok_or("the route to the invitation queue")?;
        let [
            Action::AddRecv {
                queue: reply_queue,
                relay: RelayId(1),
                period_ms: 10_000,
                ..
            },
            Action::AddSend {
                sid,
                period_ms: 10_000,
                ..
            },
        ] = actions.as_slice()
        else {
            return Err("accept: AddRecv, AddSend".into());
        };
        assert_eq!(*sid, issued.invitation.inv_sid);
        assert!(sc.guest_send.0 >= SEND_BASE);
        sc.reply_queue = *reply_queue;
        Ok(())
    }

    /// Step 3: the three handshake cells reach the inviter's round; a send that failed is sent again as persisted;
    /// accepted: the route to the invitee's reply queue; then, after `pump`, the pooled queue and the retirement.
    #[cfg(feature = "kat")]
    fn step_handshake(sc: &mut Scene) -> R {
        let (guest_send, inv_queue) = (sc.guest_send, sc.inv_queue);
        let first = sc
            .invitee
            .prepare_cell(guest_send, ms(0))
            .map_err(|_| "prepare")?
            .ok_or("cell 0")?;
        let bytes = first.cell.as_bytes().to_vec();
        sc.invitee
            .send_failed(guest_send, first.token, SendFailure::Unknown);
        let again = sc
            .invitee
            .prepare_cell(guest_send, ms(1))
            .map_err(|_| "prepare")?
            .ok_or("cell 0 again")?;
        assert_eq!(again.cell.as_bytes(), bytes.as_slice());
        let mut cells = vec![again];
        for at in 2..4 {
            cells.push(
                sc.invitee
                    .prepare_cell(guest_send, ms(at))
                    .map_err(|_| "prepare")?
                    .ok_or("cell")?,
            );
        }
        for (n_cell, cell) in cells.iter().enumerate() {
            let id = u64::try_from(n_cell)?.saturating_add(1);
            sc.invitee.relayed(guest_send, cell.token, id);
            let decided = sc.inviter.deliver(inv_queue, 0, id, &cell.cell);
            assert_eq!(decided, Ok(Delivered::Committed), "cell {n_cell}");
        }
        let actions = sc.inviter.take_actions();
        sc.host_send = added_send(&actions).ok_or("the route to the reply queue")?;
        assert!(sc.inviter.sends_of(ContactId(1)).is_none());
        sc.inviter.pump()?;
        let actions = sc.inviter.take_actions();
        let mut pooled = None;
        let mut retire_from = None;
        for action in &actions {
            match action {
                Action::AddRecv {
                    queue,
                    period_ms: 10_000,
                    ..
                } => pooled = Some(*queue),
                Action::Control(OpSpec {
                    kind: ControlKind::QueueDel(q),
                    when: When::AfterEmptyFetchFrom(w, from),
                    ..
                }) if *q == inv_queue && *w == inv_queue => retire_from = Some(*from),
                _ => {}
            }
        }
        sc.pooled = pooled.ok_or("the first reply's pooled queue")?;
        sc.retire_from = retire_from.ok_or("the invitation queue's retirement")?;
        assert!(
            (3_600_000..=86_400_000).contains(&sc.retire_from),
            "the window ends U[1 h, 24 h] after now (monotonic): {}",
            sc.retire_from
        );
        assert_eq!(
            sc.inviter.core.view.recv_periods_ms,
            vec![10_000, 10_000],
            "both recv-queues count"
        );
        let (pooled_recv, pooled_send) = sc
            .inviter
            .queue_material(sc.pooled)
            .ok_or("pooled material")?;
        assert_ne!(pooled_send, [0; 32]);
        assert_ne!(pooled_recv, sc.material_recv);
        Ok(())
    }

    /// Step 4: a restart registers the same queues and re-arms the retirement from the stored deadline.
    #[cfg(feature = "kat")]
    fn step_restart(sc: &Scene) -> R {
        let (pooled, inv_queue, from) = (sc.pooled, sc.inv_queue, sc.retire_from);
        let mut restarted = hub_over(&sc.host, "host", 400)?;
        let again = restarted.take_actions();
        assert!(
            again
                .iter()
                .any(|a| matches!(a, Action::AddRecv { queue, .. } if *queue == pooled))
        );
        assert!(
            again
                .iter()
                .any(|a| matches!(a, Action::AddRecv { queue, .. } if *queue == inv_queue))
        );
        assert!(added_send(&again).is_some());
        assert!(again.iter().any(|a| matches!(
            a,
            Action::Control(OpSpec { kind: ControlKind::QueueDel(q), when: When::AfterEmptyFetchFrom(w, f), .. })
                if *q == inv_queue && *w == inv_queue && *f == from
        )));
        Ok(())
    }

    /// Step 5: the first reply reaches the invitee, whose send queue then moves to the pooled queue; the old queue
    /// carries dummies for U[1 h, 24 h] more, then it is dropped (exactly at its time).
    #[cfg(feature = "kat")]
    fn step_reply(sc: &mut Scene) -> R {
        let reply = sc
            .inviter
            .prepare_cell(sc.host_send, ms(10))
            .map_err(|_| "prepare")?
            .ok_or("the first reply")?;
        let decided = sc.invitee.deliver(sc.reply_queue, 0, 1, &reply.cell);
        assert_eq!(decided, Ok(Delivered::Committed));
        sc.invitee.pump()?;
        let actions = sc.invitee.take_actions();
        sc.moved = added_send(&actions).ok_or("the new send queue")?;
        assert_ne!(sc.moved, sc.guest_send);
        assert_eq!(
            sc.invitee.sends_of(sc.contact),
            Some((sc.guest_send, sc.moved))
        );
        let overlap = TimingRng::seeded(5)
            .uniform(3_600_000, 86_400_000)
            .map_err(|_| "draw")?;
        sc.invitee.tick(overlap.saturating_sub(1));
        assert!(sc.invitee.take_actions().is_empty());
        sc.invitee.tick(overlap);
        let actions = sc.invitee.take_actions();
        let old = sc.guest_send;
        assert!(matches!(actions.as_slice(), [Action::Remove { queue }] if *queue == old));
        assert!(!sc.invitee.pending_real(sc.moved));
        Ok(())
    }

    /// Step 6: a message goes out on the new queue; what the scheduler reports of it reaches the session.
    #[cfg(feature = "kat")]
    fn step_message(sc: &mut Scene) -> R {
        let (moved, contact) = (sc.moved, sc.contact);
        let guest = &mut sc.invitee;
        let Response::Sent(id) = guest.core_mut().handle(Request::Send {
            contact,
            kind: 1,
            payload: secmp_crypto::Zeroizing::new(b"hello".to_vec()),
            expire_after: 0,
        })?
        else {
            return Err("sent".into());
        };
        assert!(guest.pending_real(moved));
        let at = *guest.core.index.get(&contact.0).ok_or("index")?;
        let state = |hub: &Hub<ManualClock, Fixed>| {
            hub.core.convs.get(at).and_then(|c| c.outbox().state(&id))
        };
        let cell_at = |hub: &mut Hub<ManualClock, Fixed>, t: u64| {
            hub.prepare_cell(moved, ms(t))
                .map_err(|_| "prepare")?
                .ok_or("message cell")
        };
        let cell = cell_at(guest, 20)?;
        guest.relayed(moved, cell.token, 7);
        assert_eq!(state(guest), Some(MsgState::Relayed(7)));
        guest.evicted(moved, 7);
        assert_eq!(state(guest), Some(MsgState::Queued));
        let cell = cell_at(guest, 21)?;
        guest.send_failed(moved, cell.token, SendFailure::Unknown);
        assert_eq!(state(guest), Some(MsgState::Queued));
        let cell = cell_at(guest, 22)?;
        guest.discard(moved, cell.token);
        assert_eq!(state(guest), Some(MsgState::Queued));
        let cell = cell_at(guest, 23)?;
        guest.relayed(moved, cell.token, 8);
        assert_eq!(state(guest), Some(MsgState::Relayed(8)));
        guest.queue_lost(moved);
        assert_eq!(state(guest), Some(MsgState::Queued));
        Ok(())
    }

    /// Step 7: the `QUEUE_DEL` ran: the retiring entry leaves the set, the queue the scheduler.
    #[cfg(feature = "kat")]
    fn step_retire(sc: &mut Scene) -> R {
        let (inv_queue, pooled) = (sc.inv_queue, sc.pooled);
        let host = &mut sc.inviter;
        // a rotation of the contact retires the pooled queue too: its entry must outlive the other queue's deletion
        let rotated = host.core_mut().handle(Request::Rotate {
            contact: ContactId(1),
            relay: 1,
        })?;
        assert!(matches!(rotated, Response::Rotated(true)));
        host.pump()?;
        host.take_actions();
        host.queue_deleted(inv_queue)?;
        let actions = host.take_actions();
        assert!(matches!(actions.as_slice(), [Action::Remove { queue }] if *queue == inv_queue));
        let set = {
            let store = host.profile_store();
            let bytes = store
                .lock()
                .map_err(|_| "lock")?
                .contact_queues(1)?
                .ok_or("queues")?;
            QueueSet::decode(&bytes)?
        };
        assert_eq!(
            set.entries.len(),
            2,
            "the pooled queue, retiring, and the new one"
        );
        assert!(
            set.entries
                .iter()
                .any(|e| QueueId(e.queue) == pooled && e.retire_at_ms.is_some())
        );
        assert!(set.entries.iter().all(|e| QueueId(e.queue) != inv_queue));
        assert_eq!(host.queue_material(inv_queue), None);
        Ok(())
    }

    /// B-4…B-7 killers for `Hub` (the invitation, the first reply, a route update, the retirement) without a scheduler: every
    /// step is the call a driver makes, and the actions it gets back are asserted. Alone it is the hub's contract; the
    /// driver tests (IN-17, SE-02, SE-03, SE-14) run it on the virtual clock.
    #[test]
    #[cfg(feature = "kat")]
    fn invitation_reply_route_update_and_retirement() -> R {
        big(|| {
            let (host, guest) = (party("hub-h", 71)?, party("hub-g", 73)?);
            let mut sc = Scene {
                inviter: hub_over(&host, "host", 200)?,
                invitee: hub_over(&guest, "guest", 300)?,
                host,
                issued: None,
                inv_queue: QueueId(0),
                n_link: 0,
                material_recv: [0; 32],
                guest_send: QueueId(0),
                host_send: QueueId(0),
                reply_queue: QueueId(0),
                contact: ContactId(0),
                pooled: QueueId(0),
                retire_from: 0,
                moved: QueueId(0),
            };
            step_invite(&mut sc)?;
            step_accept(&mut sc)?;
            step_handshake(&mut sc)?;
            step_restart(&sc)?;
            step_reply(&mut sc)?;
            step_message(&mut sc)?;
            step_retire(&mut sc)
        })
    }
}
