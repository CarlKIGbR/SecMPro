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
