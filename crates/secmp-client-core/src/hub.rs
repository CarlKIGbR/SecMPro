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

use secmp_crypto::{ConstantTimeEq as _, SecretBytes, Zeroizing};
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
use crate::scheduler::params::{Mode, Params};
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

/// B17c (Q264, OPEN-M7-B-28): the cells an old send queue carries after its anchor before its overlap may end — a
/// `KeyChange` copy stranded there is counted away by `QUEUE_CAPACITY` (128) later cells (ADR-060 (2)), one of unknown outcome
/// takes the first later id plus the link's in-flight depth (2) and needs 131; one interval more covers the phase and the
/// `OK_SEND`. Counted at every switch, with or without a `KeyChange` (spec §10.1).
pub const FLOOR_CELLS: u64 = 132;

/// B17c (Q266): the longest send overlap from its switch: the drawn share above `U[1 h, 24 h]`'s lower bound (at most
/// `OLD_SEND_MS − 1 h`, the fallback) and the capped floor term [`FLOOR_TERM_CAP_MS`] together stop here, and a restart
/// registers no stored end further away (the clock went back). Two days and a minute: past the recipient's longest window
/// (24 h) its `QUEUE_DEL` can follow, and the `ERR_NOQUEUE` that answers a `SEND` then is the loss proof (Q241).
pub const MAX_SEND_OVERLAP_MS: u64 = 48 * 3_600_000 + 60_000;

/// B17c (Q266, verification R1 M-2): the longest floor term `FLOOR_CELLS · I`. Only this term is capped, never the drawn
/// share: the end stays uniform over the 23 h of the draw for every I and n (a cap on the sum would put the end at a fixed
/// distance from the switch). 25 h = `MAX_SEND_OVERLAP_MS − (OLD_SEND_MS − 1 h)`; above `I` = 681.8 s the floor is cut (fail
/// closed).
pub const FLOOR_TERM_CAP_MS: u64 = 25 * 3_600_000;

/// B17c (Q264): an old send queue in overlap. Its end is `max(drawn end, from + blur + min(FLOOR_CELLS · I, cap))`, I the
/// longest interval between two cells of the queue in the current mode with the send queues on its link now
/// ([`cell_interval_ms`]); the end only grows, and a longer one is used only after its row is durable (Q265).
struct Retiring {
    /// The queue.
    queue: QueueId,
    /// The monotonic time the hub drops it (the row keeps it as Unix ms).
    until: u64,
    /// The floor's anchor: the switch of this process. `None` for a queue a restart registered again (Q267, option (a)):
    /// it ends at exactly its stored end, which holds every floor that was durable before the restart; a restart raises
    /// no floor and rewrites no row, so the relay sees no end at a fixed distance from the restart, and restarts cannot
    /// keep an old queue beyond the end its switch set.
    floor: Option<Anchor>,
}

/// B17c (Q264): the anchor of an old send queue's floor, taken at its switch.
#[derive(Clone, Copy)]
struct Anchor {
    /// The switch (monotonic).
    from: u64,
    /// The drawn overlap above `OVERLAP_MS.0`: the floor is shifted by it, so that the end stays as random as the draw
    /// (spec §10.6 (4)) and never sits at a fixed distance from the switch.
    blur: u64,
}

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
    /// The encoded `RouteDescriptor` each contact's current send queue was registered from: a re-sent `RouteUpdate`
    /// registers no second queue (Q222). It holds a send seed: compared in constant time.
    send_routes: BTreeMap<i64, Zeroizing<Vec<u8>>>,
    retiring_sends: Vec<Retiring>,
    /// B17c: the period of every send queue a route registered and not removed (the floor of an old queue after its switch).
    send_periods: BTreeMap<QueueId, u64>,
    /// The physical queue (relay, `sid`) of every send queue registered and not removed — current or in send overlap: one
    /// sender per physical queue (spec §10.2, Q236).
    send_targets: BTreeMap<QueueId, (RelayId, Id)>,
    /// The queue each contact sent to before its latest route update.
    previous_sends: BTreeMap<i64, QueueId>,
    next_send: u32,
    /// The period of every recv-queue the hub has registered and not removed: the rate bound of a rotation counts them all
    /// (§10.2), also the ones in overlap.
    recv_periods: BTreeMap<QueueId, u64>,
    actions: Vec<Action>,
    rng: crate::timing::TimingRng,
    /// The earliest `expires` (Unix seconds) of an open invitation: [`Hub::tick`] runs `Invitations::maintain` from then on
    /// (IN-11, Q208); refreshed after every `maintain`, issue and [`Hub::new`].
    next_expiry: Option<u64>,
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
            send_routes: BTreeMap::new(),
            retiring_sends: Vec::new(),
            send_periods: BTreeMap::new(),
            send_targets: BTreeMap::new(),
            previous_sends: BTreeMap::new(),
            next_send: 0,
            recv_periods: BTreeMap::new(),
            actions: Vec::new(),
            rng: crate::timing::TimingRng::os(),
            next_expiry: None,
        };
        // once after a restart (IN-11, Q208): the invitations that expired while the client was down are retired now; their
        // `QUEUE_DEL` waits for an empty `FETCH` (Q194) and is not re-armed from the stub below a second time
        let fresh = hub.maintain()?;
        for open in hub.invitations.open_queues()? {
            let period = u64::from(open.period_s).saturating_mul(1_000);
            hub.register_recv(open.relay, open.queue, &open.recv_seed, period);
            hub.inv_queues.insert(open.queue, open.ld_id);
        }
        // the queues of invitations retired unconsumed whose `QUEUE_DEL` did not run yet: fetched again until the empty
        // `FETCH`, then deleted (Q201); their cells are acknowledged and dropped
        for (ld_id, entry) in hub.invitations.retiring()? {
            let queue = QueueId(entry.queue);
            let period = u64::from(entry.period_s).saturating_mul(1_000);
            hub.register_recv(RelayId(entry.relay), queue, &entry.seed, period);
            hub.inv_queues.insert(queue, ld_id);
            if fresh.contains(&queue) {
                continue;
            }
            // the same form as the live retirement (Q213); the stub's `retire_at_ms` is an informational upper bound
            hub.actions.push(Action::Control(OpSpec {
                kind: ControlKind::QueueDel(queue),
                relay: RelayId(entry.relay),
                related: u64::from(queue.0),
                when: When::AfterEmptyFetch(queue),
            }));
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
        self.resume_overlaps(contact, at)
    }

    /// Q253 (B17b-3, OPEN-M7-B-27): the old send queues of `contact` whose send overlap a restart interrupted are
    /// registered again, in overlap, until the end their row keeps (Q252) — only an end still ahead and at most
    /// [`MAX_SEND_OVERLAP_MS`] away (the longest overlap a switch writes, B17c, Q266), and exactly until that end (Q267: no
    /// floor, no row rewritten): an end that passed while the client was down (or the clock went forward), or one
    /// further away than any (the clock went back), registers nothing, the row goes and a `KeyChange` marker of that
    /// queue keeps holding (fail closed); and only a physical queue not registered already (spec §10.2, Q236). The set of
    /// send queues therefore does not depend on whether a `KeyChange` exists (spec §10.1): every switch writes its row.
    fn resume_overlaps(&mut self, contact: ContactId, at: usize) -> Result<(), Error> {
        let read = match self.core.convs.get(at) {
            Some(conversation) => conversation
                .overlaps_read()
                .map_err(|_| Error::Unavailable)?,
            None => return Ok(()),
        };
        let now = self.core.now_ms();
        let mono = self.core.clock.mono_ms();
        // B17c (Q265): the latest end of each `sid` — a lengthened end is written before the row it replaces goes
        let mut ends: BTreeMap<Id, u64> = BTreeMap::new();
        for route in &read {
            let end = ends.entry(route.sid).or_insert(route.until_ms);
            *end = (*end).max(route.until_ms);
        }
        for route in read {
            let Some(left) = ends
                .get(&route.sid)
                .and_then(|until| until.checked_sub(now))
                .filter(|left| *left > 0 && *left <= MAX_SEND_OVERLAP_MS)
            else {
                continue;
            };
            let target = (self.config.relay, route.sid);
            if self.send_targets.values().any(|known| *known == target) {
                continue;
            }
            let queue = self.alloc_send();
            self.actions.push(Action::AddSend {
                queue,
                relay: self.config.relay,
                sid: route.sid,
                seed: route.seed,
                period_ms: u64::from(route.period.seconds()).saturating_mul(1_000),
            });
            self.registered.insert(queue);
            self.send_targets.insert(queue, target);
            self.previous_sends.insert(contact.0, queue);
            // B17c (Q267): exactly the stored end — no floor, no row rewritten at a restart
            self.retiring_sends.push(Retiring {
                queue,
                until: mono.saturating_add(left),
                floor: None,
            });
            if let Some(conversation) = self.core.convs.get_mut(at) {
                conversation.resume_overlap(queue, route.sid);
            }
        }
        Ok(())
    }

    /// The send queue of the first route of a kind this version knows; a route byte-equal to the one the current send
    /// queue was registered from is a re-sent `RouteUpdate` and registers nothing (Q222); so is a route to a physical
    /// queue (relay, `sid`) that is registered already, current or in send overlap — a stale `RouteUpdate` (A → B → A),
    /// which must not give that queue a second sender (spec §10.2, Q236).
    fn register_route(&mut self, contact: ContactId, at: usize, bytes: &[u8]) -> Result<(), Error> {
        let body = RouteUpdateBody::decode(bytes)?;
        let Some((descriptor, route)) = body.routes.iter().find_map(|r| match r {
            RouteDescriptor::RelayQueue(q) => Some((r, q)),
            RouteDescriptor::Unknown { .. } => None,
        }) else {
            return Ok(());
        };
        let encoded = secmp_proto::Encode::encode(descriptor)?;
        if self
            .send_routes
            .get(&contact.0)
            .is_some_and(|stored| bool::from(stored.as_slice().ct_eq(encoded.as_slice())))
        {
            return Ok(());
        }
        let target = (self.config.relay, route.sid);
        if self.send_targets.values().any(|t| *t == target) {
            // the stored routes follow the live registration, so a restart registers the current queue (Q236, D-B71)
            return self.store_current_route(contact);
        }
        let queue = self.alloc_send();
        let period_ms = u64::from(route.period_s.seconds()).saturating_mul(1_000);
        self.actions.push(Action::AddSend {
            queue,
            relay: self.config.relay,
            sid: route.sid,
            seed: SecretBytes::from_slice(route.send_seed.expose_secret())?,
            period_ms,
        });
        self.registered.insert(queue);
        self.send_targets.insert(queue, target);
        self.send_periods.insert(queue, period_ms);
        let previous = self.send_ids.insert(contact.0, queue);
        let previous_route = self.send_routes.insert(contact.0, encoded);
        if let Some(conversation) = self.core.convs.get_mut(at) {
            // `T_RS` follows the queue it is sent to (SE-13b, Q210 d)
            conversation.set_receipt_timeout_ms(crate::sessions::actor::receipt_timeout_ms(
                u64::from(route.period_s.seconds()).saturating_mul(1_000),
            ));
            // the physical queue a `KeyChange`'s marker names (Q248)
            conversation.set_send_sid(queue, route.sid);
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
            let mono = self.core.clock.mono_ms();
            // B17c: the floor counts from the switch, shifted by the draw above its lower bound (the next tick applies it)
            self.retiring_sends.push(Retiring {
                queue: old,
                until: mono.saturating_add(overlap),
                floor: Some(Anchor {
                    from: mono,
                    blur: overlap.saturating_sub(OVERLAP_MS.0),
                }),
            });
            // Q252: the overlap is durable — its route and its end — so a restart sends to `old` again until then (Q253)
            let end = self.core.now_ms().saturating_add(overlap);
            if let (Some(bytes), Some(conversation)) = (previous_route, self.core.convs.get_mut(at))
                && let RouteDescriptor::RelayQueue(r) =
                    &<RouteDescriptor as secmp_proto::Decode>::decode(&bytes)?
            {
                let seed: SecretBytes<32> = SecretBytes::from_slice(r.send_seed.expose_secret())?;
                conversation.keep_overlap(old, r.sid, seed, r.period_s, end);
            }
        }
        Ok(())
    }

    /// Write the route `contact`'s send queue was registered from back to its stored routes, so that a restart registers
    /// the queue it sends to live (Q236, D-B71, Q242); a contact without a send registration keeps its stored routes.
    fn store_current_route(&mut self, contact: ContactId) -> Result<(), Error> {
        if let Some(current) = self.send_routes.get(&contact.0) {
            let routes = secmp_proto::Encode::encode(&RouteUpdateBody {
                routes: vec![<RouteDescriptor as secmp_proto::Decode>::decode(current)?],
            })?;
            self.core
                .store
                .lock()
                .map_err(|_| Error::Unavailable)?
                .txn(|tx| secmp_store::contacts::put_contact_routes(tx, contact.0, &routes))?;
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
        let period = u64::from(open.period_s).saturating_mul(1_000);
        self.register_recv(open.relay, open.queue, &open.recv_seed, period);
        self.inv_queues.insert(open.queue, open.ld_id);
        for op in &issued.ops {
            self.actions.push(Action::Control(*op));
        }
        self.next_expiry = self.invitations.next_expiry()?;
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
            .process_round(
                &ld_id,
                (self.config.relay, queue),
                &[(id, copy)],
                &self.core.clock,
                source.entropy(),
            )
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
    /// moved the send queue, and the control operations the core left — the `QUEUE_DEL`s of the invitations an identity
    /// rotation retired (Q164, Q208).
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
        for op in self.core.take_ops() {
            self.actions.push(Action::Control(op));
        }
        // the routes of every `RouteUpdate` committed since the last pump, per contact in arrival order, not the stored body:
        // that holds only the last of them, and a stale last one must not hide a newer one before it (Q242)
        self.core.routes_changed.clear();
        let contacts: Vec<(i64, usize)> = self.core.index.iter().map(|(c, i)| (*c, *i)).collect();
        for (id, at) in contacts {
            let Some(conversation) = self.core.convs.get_mut(at) else {
                continue;
            };
            let routes = conversation.persist_mut().take_routes();
            if routes.is_empty() {
                continue;
            }
            let contact = ContactId(id);
            for bytes in &routes {
                self.register_route(contact, at, bytes)?;
            }
            // the store ends on the route the contact sends to, whatever the order of the updates was (Q242, D-B71)
            self.store_current_route(contact)?;
        }
        Ok(())
    }

    /// Retire the invitations that expired unused (`Invitations::maintain`, IN-11): their `QUEUE_DEL`s go to the scheduler,
    /// their events to the core; [`Hub::tick`]'s next check is the earliest `expires` left. Returns the retired queues.
    fn maintain(&mut self) -> Result<BTreeSet<QueueId>, Error> {
        let maintained = self.invitations.maintain(&self.core.clock)?;
        let mut queues = BTreeSet::new();
        for event in maintained.events {
            self.core.raise(event);
        }
        for op in maintained.ops {
            if let ControlKind::QueueDel(queue) = op.kind {
                queues.insert(queue);
            }
            self.actions.push(Action::Control(op));
        }
        self.next_expiry = self.invitations.next_expiry()?;
        Ok(queues)
    }

    /// Time passes (`now_ms` monotonic, it only triggers the checks): the queues that carried dummies in overlap long
    /// enough are dropped, and once the core clock's Unix time reaches the earliest `expires` of an open invitation the
    /// expired ones are retired (Q208). A store that cannot be read leaves the retirement to the next tick.
    pub fn tick(&mut self, now_ms: u64) {
        if self
            .next_expiry
            .is_some_and(|at| self.core.clock.unix_secs() >= at)
        {
            let _ = self.maintain();
        }
        self.raise_floors();
        let (due, keep): (Vec<_>, Vec<_>) = core::mem::take(&mut self.retiring_sends)
            .into_iter()
            .partition(|r| r.until <= now_ms);
        self.retiring_sends = keep;
        for Retiring { queue, .. } in due {
            for (_, at) in self.core.index.clone() {
                if let Some(c) = self.core.convs.get_mut(at) {
                    c.drop_send_queue(queue);
                }
            }
            self.send_targets.remove(&queue);
            self.send_periods.remove(&queue);
            self.actions.push(Action::Remove { queue });
        }
    }

    /// B17c (Q264, Q265): every old send queue switched in this process ends no earlier than its floor, `from + blur +
    /// min(FLOOR_CELLS · I, FLOOR_TERM_CAP_MS)`, I its [`cell_interval_ms`] in the effective mode with the send queues on
    /// its link now — so the floor follows a mode change and a growing N; it never shortens an end. A queue a restart
    /// registered again has no floor (Q267). A longer end is used only once its
    /// conversation has written it (CLAUDE.md §1.7); a failed write leaves the end as it was, for the next tick. A function
    /// of the mode, the periods, the set of send queues and the draw at the switch only (spec §10.1).
    fn raise_floors(&mut self) {
        let mode = effective_mode(self.core.settings.mode, self.core.view.direct);
        let params = Params::default();
        let base = self.unix_base();
        for i in 0..self.retiring_sends.len() {
            let Some(r) = self.retiring_sends.get(i) else {
                break;
            };
            // Q267: a queue a restart registered again keeps its stored end
            let (queue, Some(Anchor { from, blur })) = (r.queue, r.floor) else {
                continue;
            };
            let Some((relay, _)) = self.send_targets.get(&queue).copied() else {
                continue;
            };
            let n = self
                .send_targets
                .values()
                .filter(|(r, _)| *r == relay)
                .count();
            let Some(period) = self.send_periods.get(&queue).copied() else {
                continue;
            };
            let interval =
                cell_interval_ms(&params, mode, period, u64::try_from(n).unwrap_or(u64::MAX));
            let floor = floor_end(from, blur, interval);
            // the row keeps the later end; `extend_overlap` writes only one that is later than the row's
            let end = base.saturating_add(floor);
            let mut durable = false;
            for at in self.core.index.values() {
                if let Some(c) = self.core.convs.get_mut(*at)
                    && let Some(written) = c.extend_overlap(queue, end)
                {
                    durable = written;
                    break;
                }
            }
            if durable && let Some(r) = self.retiring_sends.get_mut(i) {
                r.until = r.until.max(floor);
            }
        }
    }

    /// The `QUEUE_DEL` of `queue` ran: the queue leaves its contact's queue set, its conversation and the scheduler.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be written.
    pub fn queue_deleted(&mut self, queue: QueueId) -> Result<(), Error> {
        // the sessions that receive on `queue` in overlap: their entry goes in the store below, here in memory after it
        let mut overlapping = Vec::new();
        for (contact, at) in &self.core.index {
            let bytes = self
                .core
                .store
                .lock()
                .map_err(|_| Error::Unavailable)?
                .contact_queues(*contact)?;
            let Some(bytes) = bytes else { continue };
            if QueueSet::decode(&bytes)?
                .entries
                .iter()
                .any(|e| e.queue == queue.0 && e.retire_at_ms.is_some())
            {
                overlapping.push(*at);
            }
        }
        // one transaction: the retiring entries of `queue` and the invitation row that held it — a stub (Q201) or a
        // consumed record (Q207)
        self.invitations.queue_deleted(self.config.relay, queue)?;
        self.inv_queues.remove(&queue);
        self.recv_periods.remove(&queue);
        self.sync_view();
        for at in overlapping {
            if let Some(c) = self.core.convs.get_mut(at) {
                c.drop_recv_queue(queue);
            }
        }
        self.actions.push(Action::Remove { queue });
        Ok(())
    }

    /// The seeds `(recipient, sender)` of the queue `queue`, for a `QUEUE_NEW` or `QUEUE_DEL` the scheduler asks for: the
    /// stored entry's (Q199), also for an invitation queue — typed and zeroized; `None` for an entry without a sender seed
    /// (Q211).
    #[must_use]
    pub fn queue_material(
        &self,
        queue: QueueId,
    ) -> Option<(SecretBytes<32>, Option<SecretBytes<32>>)> {
        let s = self.core.store.lock().ok()?;
        for contact in self.core.index.keys() {
            let Ok(Some(bytes)) = s.contact_queues(*contact) else {
                continue;
            };
            let Ok(set) = QueueSet::decode(&bytes) else {
                continue;
            };
            if let Some(e) = set.entries.iter().find(|e| e.queue == queue.0) {
                return typed(&e.seed, e.send_seed.as_ref());
            }
        }
        drop(s);
        let ld_id = self.inv_queues.get(&queue)?;
        if let Ok(open) = self.invitations.queue_of(ld_id) {
            return typed(&open.recv_seed, Some(&open.send_seed));
        }
        // retiring: the entry in the invitation's row (Q201)
        let (_, entry) = self
            .invitations
            .retiring()
            .ok()?
            .into_iter()
            .find(|(_, e)| e.queue == queue.0)?;
        typed(&entry.seed, entry.send_seed.as_ref())
    }
}

/// The effective scheduler mode (as `Core` computes it for a rotation): direct transport implies Balanced (spec §10.2).
const fn effective_mode(mode: Mode, direct: bool) -> Mode {
    match (mode, direct) {
        (Mode::Strict, true) => Mode::Balanced,
        (m, _) => m,
    }
}

/// B17c (Q264): the longest interval between two cells of a send queue of period `period_ms` in `mode`, with `n` send queues
/// on its link (spec §10.2): Strict mode sends it once per period; Balanced and Low-bandwidth mode one queue per slot `T`,
/// round-robin among the due ones — once due (after `⌈P_q / T⌉` slots), a queue waits at most for the `n − 1` others, so
/// `(⌈P_q / T⌉ + n − 1) · T` (≥ `max(P_q, n · T)`). `None` on an overflow (the floor is then the cap).
#[must_use]
pub fn cell_interval_ms(params: &Params, mode: Mode, period_ms: u64, n: u64) -> Option<u64> {
    let Some(slot) = params.slot_ms(mode) else {
        return Some(period_ms);
    };
    let due = period_ms
        .checked_add(slot.checked_sub(1)?)?
        .checked_div(slot)?;
    due.checked_add(n.saturating_sub(1))?.checked_mul(slot)
}

/// B17c (Q264, Q266): the floor of an old send queue anchored at `from` with the drawn share `blur`: `from + blur +
/// min(FLOOR_CELLS · interval, FLOOR_TERM_CAP_MS)`; an unknown interval or an overflow takes the term's cap. Only the
/// term is capped, so the end moves with `blur` for every interval (uniform over the draw's 23 h); the span stays at most
/// `MAX_SEND_OVERLAP_MS` (`blur` ≤ `OLD_SEND_MS − 1 h`; a larger one is cut there).
fn floor_end(from: u64, blur: u64, interval: Option<u64>) -> u64 {
    let term = interval
        .and_then(|i| FLOOR_CELLS.checked_mul(i))
        .map_or(FLOOR_TERM_CAP_MS, |t| t.min(FLOOR_TERM_CAP_MS));
    let span = blur
        .checked_add(term)
        .map_or(MAX_SEND_OVERLAP_MS, |s| s.min(MAX_SEND_OVERLAP_MS));
    from.saturating_add(span)
}

/// Copies of a queue's seeds, typed (`queue_material`).
fn typed(
    recv: &SecretBytes<32>,
    send: Option<&SecretBytes<32>>,
) -> Option<(SecretBytes<32>, Option<SecretBytes<32>>)> {
    let recv = SecretBytes::from_slice(recv.expose_secret()).ok()?;
    let send = match send {
        Some(s) => Some(SecretBytes::from_slice(s.expose_secret()).ok()?),
        None => None,
    };
    Some((recv, send))
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
        hub_with(fx, name, seed, Period::S10)
    }

    /// [`hub_over`] with the period of the invitation queues it issues.
    #[cfg(feature = "kat")]
    fn hub_with(
        fx: &Fixture,
        name: &str,
        seed: u64,
        inv_period: Period,
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
                inv_period,
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

    /// A scene of two hubs over `host` and `guest`, nothing done yet.
    #[cfg(feature = "kat")]
    fn scene(host: Fixture, guest: &Fixture) -> Result<Scene, crate::api::Error> {
        Ok(Scene {
            inviter: hub_over(&host, "host", 200)?,
            invitee: hub_over(guest, "guest", 300)?,
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
        })
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
        let material_recv = *material_recv.expose_secret();
        assert_eq!(
            material_recv,
            *sc.inviter
                .invitations
                .queue_of(&issued.invitation.ld_id)?
                .recv_seed
                .expose_secret()
        );
        assert_eq!(
            material_send.map(|s| *s.expose_secret()),
            Some(*issued.invitation.inv_send_seed.expose_secret()),
            "the stored entry's sender seed (Q199)"
        );
        assert!(sc.inviter.queue_material(QueueId(999)).is_none());
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
        assert!(pooled_send.is_some_and(|s| *s.expose_secret() != [0; 32]));
        assert_ne!(*pooled_recv.expose_secret(), sc.material_recv);
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
        let invitation_rows =
            |host: &Hub<ManualClock, Fixed>| -> Result<usize, crate::testutil::E> {
                Ok(host
                    .profile_store()
                    .lock()
                    .map_err(|_| "lock")?
                    .invitations()?
                    .len())
            };
        let rows = invitation_rows(host)?;
        host.queue_deleted(inv_queue)?;
        // the consumed record goes in the transaction that removes the queue's entry (Q207)
        assert_eq!(invitation_rows(host)?, rows.saturating_sub(1));
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
        assert!(host.queue_material(inv_queue).is_none());
        // B-4c killer (`queue_deleted`, Q207): a queue that is no retiring entry — the current one — stays its session's
        // recv-queue, also while another entry of the set is retiring
        let current = set
            .entries
            .iter()
            .find(|e| e.retire_at_ms.is_none())
            .map(|e| QueueId(e.queue))
            .ok_or("current")?;
        host.queue_deleted(current)?;
        let conv = host
            .core_mut()
            .conversations_mut()
            .get(0)
            .ok_or("conversation")?;
        assert_eq!(conv.recv_queues_kat().0, Some(current));
        assert!(conv.recv_queues_kat().1.contains(&pooled));
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

    /// Q199: the invitation queue is fetched at the period its invitation names, after a restart too, and its sender seed is
    /// the stored entry's — what an identical `QUEUE_NEW` after a relay restart needs.
    #[test]
    #[cfg(feature = "kat")]
    fn invitation_queue_period_and_sender_seed_come_from_the_entry() -> R {
        big(|| {
            let host = party("hub-e", 75)?;
            let mut hub = hub_with(&host, "host", 210, Period::S80)?;
            let issued = hub.invite(T0 + 5 * DAY)?;
            let queue = hub
                .invitation_queue(&issued.invitation.ld_id)
                .ok_or("queue")?;
            let periods = |actions: &[Action]| {
                actions
                    .iter()
                    .filter_map(|a| match a {
                        Action::AddRecv {
                            queue: q,
                            period_ms,
                            ..
                        } if *q == queue => Some(*period_ms),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            };
            assert_eq!(periods(&hub.take_actions()), vec![80_000]);
            // a restart over the same profile, whose configuration says 10 s: the entry decides
            let mut again = hub_with(&host, "host", 220, Period::S10)?;
            assert_eq!(periods(&again.take_actions()), vec![80_000]);
            let (recv, send) = again.queue_material(queue).ok_or("material")?;
            let send = *send.ok_or("sender seed")?.expose_secret();
            assert_eq!(send, *issued.invitation.inv_send_seed.expose_secret());
            assert_ne!(*recv.expose_secret(), send);
            Ok(())
        })
    }

    /// Q201: the queue of an invitation retired unconsumed is, after a restart, fetched again at its period and its
    /// `QUEUE_DEL` re-armed from the stored deadline; the material the deletion is signed with is the stub's; the
    /// acknowledged deletion removes the stub.
    #[test]
    #[cfg(feature = "kat")]
    fn retiring_invitation_queue_is_rearmed_after_a_restart() -> R {
        big(|| {
            let host = party("hub-r", 77)?;
            let mut hub = hub_with(&host, "host", 230, Period::S40)?;
            let issued = hub.invite(T0 + 5 * DAY)?;
            let queue = hub
                .invitation_queue(&issued.invitation.ld_id)
                .ok_or("queue")?;
            hub.take_actions();
            let material = exposed(hub.queue_material(queue)).ok_or("open material")?;
            host.at_day(6);
            let retired = hub.invitations.maintain(&host.clock)?;
            assert_eq!(retired.ops.len(), 1);
            assert_eq!(
                exposed(hub.queue_material(queue)),
                Some(material),
                "the stub's keys are the invitation's"
            );
            let mut again = hub_with(&host, "host", 240, Period::S10)?;
            let actions = again.take_actions();
            assert!(actions.iter().any(|a| matches!(
                a,
                Action::AddRecv { queue: q, period_ms: 40_000, .. } if *q == queue
            )));
            let rearmed_whens: Vec<When> = actions
                .iter()
                .filter_map(|a| match a {
                    Action::Control(OpSpec {
                        kind: ControlKind::QueueDel(q),
                        when,
                        ..
                    }) if *q == queue => Some(*when),
                    _ => None,
                })
                .collect();
            // Q213: one form live and after a restart
            assert_eq!(rearmed_whens, vec![When::AfterEmptyFetch(queue)]);
            assert_eq!(rearmed_whens.first(), retired.ops.first().map(|o| &o.when));
            assert_eq!(exposed(again.queue_material(queue)), Some(material));
            again.queue_deleted(queue)?;
            assert!(matches!(
                again.take_actions().as_slice(),
                [Action::Remove { queue: q }] if *q == queue
            ));
            assert!(again.invitations.retiring()?.is_empty());
            assert!(again.queue_material(queue).is_none());
            Ok(())
        })
    }

    /// SE-38 (Q222): a re-sent `RouteUpdate` (the byte-equal descriptor) registers no second send queue; a descriptor that
    /// differs is a new route.
    #[test]
    #[cfg(feature = "kat")]
    fn repeated_route_update_registers_one_send_queue() -> R {
        use secmp_proto::wire::cell::{RelayQueue, RouteDescriptor, RouteUpdateBody};

        big(|| {
            let (host, guest) = (party("hub-rr-h", 81)?, party("hub-rr-g", 83)?);
            let mut sc = scene(host, &guest)?;
            step_invite(&mut sc)?;
            step_accept(&mut sc)?;
            step_handshake(&mut sc)?;
            step_reply(&mut sc)?;
            let (contact, hub) = (sc.contact, &mut sc.invitee);
            let at = *hub.core.index.get(&contact.0).ok_or("index")?;
            hub.take_actions();
            let update = |n: u8| -> Result<Vec<u8>, crate::testutil::E> {
                Ok(RouteUpdateBody {
                    routes: vec![RouteDescriptor::RelayQueue(RelayQueue {
                        relay: crate::testutil::relay_ref(),
                        sid: [n; 16],
                        send_seed: secmp_crypto::SecretBytes::from_slice(&[n; 32])?,
                        period_s: Period::S80,
                    })],
                }
                .encode()?
                .to_vec())
            };
            let add_sends = |hub: &mut Hub<ManualClock, Fixed>| {
                hub.take_actions()
                    .iter()
                    .filter(|a| matches!(a, Action::AddSend { .. }))
                    .count()
            };
            let mut counts = Vec::new();
            hub.register_route(contact, at, &update(9)?)?;
            counts.push(add_sends(hub));
            hub.register_route(contact, at, &update(9)?)?;
            counts.push(add_sends(hub));
            hub.register_route(contact, at, &update(4)?)?;
            counts.push(add_sends(hub));
            assert_eq!(counts, [1, 0, 1], "AddSend per register_route");
            Ok(())
        })
    }

    /// A scene after the first reply (the invitee's contact, its conversation's index) and a `RouteUpdate` body of the
    /// relay queue `n` with period `period`.
    #[cfg(feature = "kat")]
    fn routed(label: &str, seed: u64) -> Result<(Scene, ContactId, usize), crate::testutil::E> {
        let (host, guest) = (
            party(&format!("{label}-h"), seed)?,
            party(&format!("{label}-g"), seed.wrapping_add(2))?,
        );
        let mut sc = scene(host, &guest)?;
        step_invite(&mut sc)?;
        step_accept(&mut sc)?;
        step_handshake(&mut sc)?;
        step_reply(&mut sc)?;
        let contact = sc.contact;
        let at = *sc.invitee.core.index.get(&contact.0).ok_or("index")?;
        sc.invitee.take_actions();
        Ok((sc, contact, at))
    }

    #[cfg(feature = "kat")]
    fn route_body(n: u8, period: Period) -> Result<Vec<u8>, crate::testutil::E> {
        use secmp_proto::wire::cell::{RelayQueue, RouteDescriptor, RouteUpdateBody};
        Ok(RouteUpdateBody {
            routes: vec![RouteDescriptor::RelayQueue(RelayQueue {
                relay: crate::testutil::relay_ref(),
                sid: [n; 16],
                send_seed: secmp_crypto::SecretBytes::from_slice(&[n; 32])?,
                period_s: period,
            })],
        }
        .encode()?
        .to_vec())
    }

    /// The queues of the `AddSend`s among the actions taken since the last call, with their `sid`.
    #[cfg(feature = "kat")]
    fn add_sends(hub: &mut Hub<ManualClock, Fixed>) -> Vec<(QueueId, Id)> {
        hub.take_actions()
            .iter()
            .filter_map(|a| match a {
                Action::AddSend { queue, sid, .. } => Some((*queue, *sid)),
                _ => None,
            })
            .collect()
    }

    /// SE-54 (Q236, EXT2c-3; spec §10.2): A → B → A while A is still in send overlap registers nothing for the third
    /// update — one sender per physical queue — and the contact keeps sending to B.
    #[test]
    #[cfg(feature = "kat")]
    fn route_back_to_a_queue_in_overlap_registers_nothing() -> R {
        big(|| {
            let (mut sc, contact, at) = routed("hub-aba", 85)?;
            let hub = &mut sc.invitee;
            let mut counts = Vec::new();
            hub.register_route(contact, at, &route_body(9, Period::S80)?)?;
            let a = add_sends(hub);
            counts.push(a.len());
            hub.register_route(contact, at, &route_body(4, Period::S80)?)?;
            let b = add_sends(hub);
            counts.push(b.len());
            hub.register_route(contact, at, &route_body(9, Period::S80)?)?;
            let actions = hub.take_actions();
            counts.push(
                actions
                    .iter()
                    .filter(|x| matches!(x, Action::AddSend { .. }))
                    .count(),
            );
            assert_eq!(counts, [1, 1, 0], "AddSend per register_route");
            assert!(
                !actions.iter().any(|x| matches!(x, Action::Remove { .. })),
                "nothing removed"
            );
            let (qa, qb) = (a.first().ok_or("A")?.0, b.first().ok_or("B")?.0);
            assert_eq!(hub.sends_of(contact), Some((qa, qb)), "still sending to B");
            Ok(())
        })
    }

    /// SE-55 (Q236): a route to the current physical queue (relay, `sid`) that differs in another field registers nothing.
    #[test]
    #[cfg(feature = "kat")]
    fn route_to_the_current_queue_registers_nothing() -> R {
        big(|| {
            let (mut sc, contact, at) = routed("hub-cur", 93)?;
            let hub = &mut sc.invitee;
            hub.register_route(contact, at, &route_body(9, Period::S80)?)?;
            let a = add_sends(hub);
            hub.register_route(contact, at, &route_body(9, Period::S40)?)?;
            assert_eq!((a.len(), add_sends(hub).len()), (1, 0));
            assert_eq!(hub.send_ids.get(&contact.0), a.first().map(|x| &x.0));
            Ok(())
        })
    }

    /// SE-56 (Q236): once A has left send overlap (its registration is removed), a route to A registers it once more —
    /// one live registration of A.
    #[test]
    #[cfg(feature = "kat")]
    fn route_back_after_its_overlap_registers_once() -> R {
        big(|| {
            let (mut sc, contact, at) = routed("hub-abta", 97)?;
            let hub = &mut sc.invitee;
            hub.register_route(contact, at, &route_body(9, Period::S80)?)?;
            let a = add_sends(hub);
            hub.register_route(contact, at, &route_body(4, Period::S80)?)?;
            add_sends(hub);
            hub.tick(u64::MAX);
            let removed = hub
                .take_actions()
                .iter()
                .filter(|x| matches!(x, Action::Remove { queue } if Some(queue) == a.first().map(|y| &y.0)))
                .count();
            hub.register_route(contact, at, &route_body(9, Period::S80)?)?;
            let again = add_sends(hub);
            let live_a = hub
                .send_targets
                .values()
                .filter(|(_, sid)| *sid == [9_u8; 16])
                .count();
            assert_eq!((removed, again.len(), live_a), (1, 1, 1));
            Ok(())
        })
    }

    /// SE-59 (ADR-054 item 5, EXT2c-5): an inviter whose `Profile.name` holds C1 and C0 characters is accepted (the
    /// handshake completes), its contact shows the name as empty, the stored name is the one received, and so after a
    /// reopen.
    #[test]
    #[cfg(feature = "kat")]
    fn peer_name_with_control_characters_is_shown_empty() -> R {
        big(|| {
            let (host, guest) = (party("hub-nm-h", 89)?, party("hub-nm-g", 91)?);
            let mut sc = scene(host, &guest)?;
            sc.inviter = hub_over(&sc.host, "A\u{85}B\n", 200)?;
            step_invite(&mut sc)?;
            step_accept(&mut sc)?;
            step_handshake(&mut sc)?;
            let shown = |core: &mut Core<ManualClock, Fixed>| -> Result<Vec<Option<String>>, crate::testutil::E> {
                let Response::Contacts(list) = core.handle(Request::Contacts)? else {
                    return Err("contacts".into());
                };
                Ok(list.into_iter().map(|c| c.display_name).collect())
            };
            assert_eq!(shown(&mut sc.invitee.core)?, [Some(String::new())]);
            let stored: Vec<Option<String>> = guest
                .profile
                .store()
                .lock()
                .map_err(|_| "lock")?
                .contacts()?
                .into_iter()
                .map(|c| c.display_name)
                .collect();
            assert_eq!(
                stored,
                [Some("A\u{85}B\n".to_owned())],
                "stored as received"
            );
            let mut again = Core::with_profile(guest.profile.clone(), guest.clock.clone(), || {
                Fixed(entropy(995))
            })?;
            assert_eq!(shown(&mut again)?, [Some(String::new())], "after a reopen");
            Ok(())
        })
    }

    /// SE-57 (Q236, negative control): a genuinely new route registers exactly once each time (A, B, C).
    #[test]
    #[cfg(feature = "kat")]
    fn new_routes_register_once_each() -> R {
        big(|| {
            let (mut sc, contact, at) = routed("hub-abc", 101)?;
            let hub = &mut sc.invitee;
            let mut sids = Vec::new();
            for n in [9_u8, 4, 7] {
                hub.register_route(contact, at, &route_body(n, Period::S80)?)?;
                sids.extend(add_sends(hub).into_iter().map(|(_, sid)| sid));
            }
            assert_eq!(sids, [[9_u8; 16], [4; 16], [7; 16]]);
            Ok(())
        })
    }

    /// SE-63 (Q236, D-B71): A, B, then A again as the receive path does it (routes stored, then registered); after a
    /// restart (the profile opened again from its files) the contact registers B, the queue it sends to live, not the
    /// stale A.
    #[test]
    #[cfg(feature = "kat")]
    fn restart_after_a_stale_route_registers_the_current_queue() -> R {
        big(|| {
            let (host, guest) = (party("hub-rst-h", 185)?, party("hub-rst-g", 187)?);
            let mut sc = scene(host, &guest)?;
            step_invite(&mut sc)?;
            step_accept(&mut sc)?;
            step_handshake(&mut sc)?;
            step_reply(&mut sc)?;
            let contact = sc.contact;
            let at = *sc.invitee.core.index.get(&contact.0).ok_or("index")?;
            sc.invitee.take_actions();
            for n in [9_u8, 4, 9] {
                let body = route_body(n, Period::S80)?;
                guest
                    .profile
                    .store()
                    .lock()
                    .map_err(|_| "lock")?
                    .txn(|tx| secmp_store::contacts::put_contact_routes(tx, contact.0, &body))?;
                sc.invitee.register_route(contact, at, &body)?;
            }
            drop(sc);
            // a restart: the profile is opened again from its files
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 900)?;
            let rows: Vec<Id> = overlaps_of(&again, contact)?.iter().map(|r| r.0).collect();
            let sids: Vec<Id> = add_sends(&mut again)
                .into_iter()
                .map(|(_, sid)| sid)
                .collect();
            assert_eq!(
                (sids.first(), sids.get(1..)),
                (Some(&[4_u8; 16]), Some(rows.as_slice())),
                "after a restart: B, then the old queues in overlap (Q253)"
            );
            assert!(rows.contains(&[9; 16]), "A is one of them");
            Ok(())
        })
    }

    /// A scene after the first reply whose invitee then sent to A (`sid` 9) and B (`sid` 4), one pump each: B is its
    /// current send queue, A is in send overlap. Also the invitee's fixture (for a restart) and its contact.
    #[cfg(feature = "kat")]
    fn on_b(label: &str, seed: u64) -> Result<(Scene, Fixture, ContactId), crate::testutil::E> {
        let (host, guest) = (
            party(&format!("{label}-h"), seed)?,
            party(&format!("{label}-g"), seed.wrapping_add(2))?,
        );
        let mut sc = scene(host, &guest)?;
        step_invite(&mut sc)?;
        step_accept(&mut sc)?;
        step_handshake(&mut sc)?;
        step_reply(&mut sc)?;
        let contact = sc.contact;
        sc.invitee.take_actions();
        for (n, now) in [(9_u8, 20), (4, 30)] {
            send_route(&mut sc, n, ms(now))?;
            sc.invitee.pump()?;
            assert_eq!(sids(&mut sc.invitee), [[n; 16]], "the setup registers {n}");
        }
        Ok((sc, guest, contact))
    }

    /// The inviter sends a `RouteUpdate` of the relay queue `n` (period S80) in one cell at `now`, and the invitee's
    /// receive commit takes it (its routes are stored); no pump.
    #[cfg(feature = "kat")]
    fn send_route(sc: &mut Scene, n: u8, now: u64) -> R {
        let at = *sc.inviter.core.index.get(&1).ok_or("host index")?;
        let routes = RouteUpdateBody::decode(&route_body(n, Period::S80)?)?.routes;
        sc.inviter
            .core
            .convs
            .get_mut(at)
            .ok_or("host conversation")?
            .queue_route_update(routes);
        let cell = sc
            .inviter
            .prepare_cell(sc.host_send, now)
            .map_err(|_| "prepare")?
            .ok_or("cell")?;
        let decided = sc.invitee.deliver(sc.reply_queue, 0, 1, &cell.cell);
        assert_eq!(decided, Ok(Delivered::Committed), "route {n}");
        Ok(())
    }

    /// The `sid`s of the `AddSend`s among the actions taken since the last call.
    #[cfg(feature = "kat")]
    fn sids(hub: &mut Hub<ManualClock, Fixed>) -> Vec<Id> {
        add_sends(hub).into_iter().map(|(_, sid)| sid).collect()
    }

    /// The `sid` of the first relay-queue route stored for `contact`.
    #[cfg(feature = "kat")]
    fn stored_sid(
        hub: &Hub<ManualClock, Fixed>,
        contact: ContactId,
    ) -> Result<Option<Id>, crate::testutil::E> {
        let store = hub.profile_store();
        let bytes = store
            .lock()
            .map_err(|_| "lock")?
            .contact_routes(contact.0)?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        Ok(RouteUpdateBody::decode(&bytes)?
            .routes
            .iter()
            .find_map(|r| match r {
                RouteDescriptor::RelayQueue(q) => Some(q.sid),
                RouteDescriptor::Unknown { .. } => None,
            }))
    }

    /// The queue the `AddSend` of `sid` registered among `added`.
    #[cfg(feature = "kat")]
    fn queue_of(added: &[(QueueId, Id)], sid: u8) -> Option<QueueId> {
        added.iter().find(|(_, s)| *s == [sid; 16]).map(|(q, _)| *q)
    }

    /// SE-77 (Q242, OPEN-M7-B-22): a new route C (`sid` 7) and then a stale A (in send overlap), received before one pump:
    /// C is registered once and the contact sends to it, A registers nothing, and the store holds C.
    #[test]
    #[cfg(feature = "kat")]
    fn new_route_then_stale_one_in_one_pump_registers_the_new_one() -> R {
        big(|| {
            let (mut sc, _guest, contact) = on_b("hub-ca", 105)?;
            let b = sc.invitee.send_ids.get(&contact.0).copied();
            send_route(&mut sc, 7, ms(40))?;
            send_route(&mut sc, 9, ms(50))?;
            sc.invitee.pump()?;
            let added = add_sends(&mut sc.invitee);
            let sids: Vec<Id> = added.iter().map(|(_, s)| *s).collect();
            assert_eq!(sids, [[7_u8; 16]], "Q242: C once, A nothing");
            let c = queue_of(&added, 7);
            assert_eq!(sc.invitee.sends_of(contact), b.zip(c), "Q242: from B to C");
            assert_eq!(
                stored_sid(&sc.invitee, contact)?,
                Some([7; 16]),
                "Q242: the store holds C"
            );
            Ok(())
        })
    }

    /// SE-78 (Q242): the mirror order — the stale A first, then C, before one pump: C is registered once, A registers
    /// nothing, and the store ends on C (A's write-back of B is overwritten).
    #[test]
    #[cfg(feature = "kat")]
    fn stale_route_then_new_one_in_one_pump_registers_the_new_one() -> R {
        big(|| {
            let (mut sc, _guest, contact) = on_b("hub-ac", 107)?;
            let b = sc.invitee.send_ids.get(&contact.0).copied();
            send_route(&mut sc, 9, ms(40))?;
            send_route(&mut sc, 7, ms(50))?;
            sc.invitee.pump()?;
            let added = add_sends(&mut sc.invitee);
            let sids: Vec<Id> = added.iter().map(|(_, s)| *s).collect();
            assert_eq!(sids, [[7_u8; 16]], "Q242: C once, A nothing");
            assert_eq!(sc.invitee.sends_of(contact), b.zip(queue_of(&added, 7)));
            assert_eq!(
                stored_sid(&sc.invitee, contact)?,
                Some([7; 16]),
                "Q242: the store ends on C"
            );
            Ok(())
        })
    }

    /// SE-79 (Q242): C (`sid` 7), D (`sid` 5) and the stale A in one pump register C then D, in arrival order; the
    /// contact sends to D, C is in send overlap, and the store holds D.
    #[test]
    #[cfg(feature = "kat")]
    fn three_routes_in_one_pump_register_in_arrival_order() -> R {
        big(|| {
            let (mut sc, _guest, contact) = on_b("hub-cda", 109)?;
            for (n, now) in [(7_u8, 40), (5, 50), (9, 60)] {
                send_route(&mut sc, n, ms(now))?;
            }
            sc.invitee.pump()?;
            let added = add_sends(&mut sc.invitee);
            let sids: Vec<Id> = added.iter().map(|(_, s)| *s).collect();
            assert_eq!(sids, [[7_u8; 16], [5; 16]], "Q242: C, then D");
            assert_eq!(
                sc.invitee.sends_of(contact),
                queue_of(&added, 7).zip(queue_of(&added, 5)),
                "Q242: from C to D"
            );
            assert_eq!(stored_sid(&sc.invitee, contact)?, Some([5; 16]));
            Ok(())
        })
    }

    /// SE-80 (Q242, negative control): one route per pump behaves as before — C registers once, then the stale A and a
    /// byte-equal repeat of C register nothing (Q236, Q222); each pump raises one `RoutesChanged` and the store holds C.
    #[test]
    #[cfg(feature = "kat")]
    fn one_route_per_pump_registers_as_before() -> R {
        big(|| {
            let (mut sc, _guest, contact) = on_b("hub-1pp", 111)?;
            sc.invitee.core_mut().take_events();
            let mut seen = Vec::new();
            for (n, now) in [(7_u8, 40), (9, 50), (7, 60)] {
                send_route(&mut sc, n, ms(now))?;
                sc.invitee.pump()?;
                let changed = sc
                    .invitee
                    .core_mut()
                    .take_events()
                    .iter()
                    .filter(|e| e.event == crate::api::Event::RoutesChanged(contact))
                    .count();
                seen.push((
                    sids(&mut sc.invitee).len(),
                    changed,
                    stored_sid(&sc.invitee, contact)?,
                ));
            }
            let c = Some([7_u8; 16]);
            assert_eq!(
                seen,
                [(1, 1, c), (0, 1, c), (0, 1, c)],
                "(AddSend, RoutesChanged, stored) per pump"
            );
            Ok(())
        })
    }

    /// SE-81 (Q242, D-B71): after C and the stale A in one pump, in either order, a restart (the profile opened again
    /// from its files) registers C only.
    #[test]
    #[cfg(feature = "kat")]
    fn restart_after_routes_in_one_pump_registers_the_new_one() -> R {
        big(|| {
            let mut after = Vec::new();
            for (label, seed, order) in [("hub-rca", 113_u64, [7_u8, 9]), ("hub-rac", 117, [9, 7])]
            {
                let (mut sc, guest, contact) = on_b(label, seed)?;
                for (n, now) in order.into_iter().zip([40, 50]) {
                    send_route(&mut sc, n, ms(now))?;
                }
                sc.invitee.pump()?;
                drop(sc);
                let guest = guest.reopen()?;
                let mut again = hub_over(&guest, "guest", 900)?;
                let rows: Vec<Id> = overlaps_of(&again, contact)?.iter().map(|r| r.0).collect();
                let added = sids(&mut again);
                assert_eq!(
                    added.get(1..),
                    Some(rows.as_slice()),
                    "{label}: the old queues in overlap (Q253)"
                );
                assert!(rows.ends_with(&[[9; 16], [4; 16]]), "{label}: A, then B");
                after.push(added.first().copied());
            }
            assert_eq!(
                after,
                [Some([7_u8; 16]), Some([7; 16])],
                "Q242: after a restart"
            );
            Ok(())
        })
    }

    /// SE-83 (Q242): a pump without a new `RouteUpdate` registers nothing, also after the old queue's send overlap ended
    /// (the routes already taken are not taken again: an old route replayed after its overlap would register it anew).
    #[test]
    #[cfg(feature = "kat")]
    fn pump_after_the_overlap_registers_nothing_again() -> R {
        big(|| {
            let (mut sc, _guest, contact) = on_b("hub-again", 119)?;
            sc.invitee.tick(ms(200_000));
            sc.invitee.take_actions();
            sc.invitee.pump()?;
            assert_eq!(sids(&mut sc.invitee), Vec::<Id>::new(), "Q242: nothing new");
            assert_eq!(stored_sid(&sc.invitee, contact)?, Some([4; 16]));
            Ok(())
        })
    }

    /// SE-84 (Q242): a second contact (conversation 1) of the same hub receives a new route C (`sid` 7): its own routes
    /// register it, and the first contact's stored route stays B.
    #[test]
    #[cfg(feature = "kat")]
    fn second_contact_registers_its_own_routes() -> R {
        big(|| {
            let (mut sc, guest, first) = on_b("hub-two", 121)?;
            // the first contact's overlaps end first, so the second scene's steps see only their own queues
            sc.invitee.tick(ms(200_000));
            let mut sc2 = scene(party("hub-two-h2", 125)?, &guest)?;
            core::mem::swap(&mut sc2.invitee, &mut sc.invitee);
            sc2.invitee.take_actions();
            step_invite(&mut sc2)?;
            step_accept(&mut sc2)?;
            step_handshake(&mut sc2)?;
            step_reply(&mut sc2)?;
            let second = sc2.contact;
            let at = sc2.invitee.core.index.get(&second.0).copied();
            assert_eq!(
                (first.0, second.0, at),
                (1, 2, Some(1)),
                "two conversations"
            );
            sc2.invitee.take_actions();
            send_route(&mut sc2, 7, ms(40))?;
            sc2.invitee.pump()?;
            assert_eq!(
                sids(&mut sc2.invitee),
                [[7_u8; 16]],
                "Q242: the second contact's C"
            );
            assert_eq!(
                (
                    stored_sid(&sc2.invitee, first)?,
                    stored_sid(&sc2.invitee, second)?
                ),
                (Some([4; 16]), Some([7; 16]))
            );
            Ok(())
        })
    }

    /// SE-90 (B22-delta D-03, D-B78; Q241, Q242, Q244): the invitee's `KeyChange` relayed on B (ids 1–4), then the routes
    /// C (`sid` 7) and D (`sid` 5) in one pump — two switches, no cell on C. The copy on B is marked on B and nothing is
    /// marked on C: after the new copy on D has left its window, B's id 131 releases nothing, and B's id 132 alone — no
    /// `OK_SEND` on C at all — releases the `KeyChange` (its row goes at the next preparation).
    #[test]
    #[cfg(feature = "kat")]
    fn two_routes_in_one_pump_keep_the_mark_on_the_sent_queue() -> R {
        big(|| {
            let (mut sc, _guest, contact) = on_b("hub-kc-cd", 113)?;
            let hub = &mut sc.invitee;
            let at = *hub.core.index.get(&contact.0).ok_or("index")?;
            let b = *hub.send_ids.get(&contact.0).ok_or("B")?;
            assert!(matches!(
                hub.core_mut().handle(Request::RotateIdentity)?,
                Response::IdentityRotated(_)
            ));
            let on = |hub: &mut Hub<ManualClock, Fixed>, q: QueueId, now: u64, id: u64| -> R {
                let p = hub
                    .prepare_cell(q, now)
                    .map_err(|_| "prepare")?
                    .ok_or("cell")?;
                hub.relayed(q, p.token, id);
                Ok(())
            };
            for i in 0..4_u64 {
                on(hub, b, ms(60 + i), 1 + i)?;
            }
            send_route(&mut sc, 7, ms(70))?;
            send_route(&mut sc, 5, ms(80))?;
            let hub = &mut sc.invitee;
            hub.pump()?;
            let added = add_sends(hub);
            let (c, d) = (
                queue_of(&added, 7).ok_or("C")?,
                queue_of(&added, 5).ok_or("D")?,
            );
            assert_eq!(
                hub.sends_of(contact),
                Some((c, d)),
                "two switches in one pump"
            );
            for i in 0..4_u64 {
                on(hub, d, ms(90 + i), 1 + i)?;
            }
            on(hub, d, ms(100), 261)?;
            on(hub, d, ms(101), 262)?;
            let live = |hub: &Hub<ManualClock, Fixed>| {
                hub.core
                    .convs
                    .get(at)
                    .is_some_and(crate::sessions::actor::Conversation::key_change_in_flight)
            };
            assert!(live(hub), "the copy on B may still be fetched");
            on(hub, b, ms(104), 131)?;
            on(hub, d, ms(105), 264)?;
            assert!(live(hub), "B's 131 is not enough");
            on(hub, b, ms(106), 132)?;
            on(hub, d, ms(107), 265)?;
            assert!(!live(hub), "B's 132 alone releases: nothing on C");
            Ok(())
        })
    }

    /// SE-95 (Q248, Q249; D-B73): through the hub, the first `KeyChange` cell on B (`sid` 4) is sealed after its marker
    /// names B. A restart (the profile opened again from its files) registered on B again reads the marker back on the
    /// queue it names: the re-read copy leaving its window releases the `KeyChange` and its markers. When the peer's
    /// `RouteUpdate` C (`sid` 7) was committed before the restart (no pump), the restart registers C and B's copy is held
    /// for good: C's window releases nothing, both markers stay.
    #[test]
    #[cfg(feature = "kat")]
    fn restart_reads_the_marker_of_the_sent_queue() -> R {
        use crate::sessions::tests::control_tags;

        big(|| {
            let mut out = Vec::new();
            for (label, seed, moved) in
                [("hub-mk-same", 131_u64, false), ("hub-mk-moved", 137, true)]
            {
                let (mut sc, guest, contact) = on_b(label, seed)?;
                let hub = &mut sc.invitee;
                let b = *hub.send_ids.get(&contact.0).ok_or("B")?;
                assert!(matches!(
                    hub.core_mut().handle(Request::RotateIdentity)?,
                    Response::IdentityRotated(_)
                ));
                let on = |hub: &mut Hub<ManualClock, Fixed>, q: QueueId, now: u64, id: u64| -> R {
                    let p = hub
                        .prepare_cell(q, now)
                        .map_err(|_| "prepare")?
                        .ok_or("cell")?;
                    hub.relayed(q, p.token, id);
                    Ok(())
                };
                on(hub, b, ms(60), 1)?;
                assert_eq!(
                    control_tags(&hub.profile_store(), contact.0)?,
                    (vec![5, 5, 3, 4], vec![[4_u8; 16]]),
                    "{label}: the marker names B (after the overlap rows of the two earlier switches, Q252)"
                );
                for i in 1..4_u64 {
                    on(hub, b, ms(60 + i), 1 + i)?;
                }
                if moved {
                    send_route(&mut sc, 7, ms(70))?;
                }
                drop(sc);
                let guest = guest.reopen()?;
                let mut again = hub_over(&guest, "guest", 900)?;
                let Some(&(q, sid)) = add_sends(&mut again).first() else {
                    return Err("a send queue".into());
                };
                let at = *again.core.index.get(&contact.0).ok_or("index")?;
                for i in 0..4_u64 {
                    on(&mut again, q, ms(200 + i), 1 + i)?;
                }
                for id in [261_u64, 262, 263] {
                    on(&mut again, q, ms(300 + id), id)?;
                }
                out.push((
                    sid,
                    again
                        .core
                        .convs
                        .get(at)
                        .is_some_and(crate::sessions::actor::Conversation::key_change_in_flight),
                    control_tags(&again.profile_store(), contact.0)?.1,
                ));
            }
            assert_eq!(
                out,
                [
                    ([4_u8; 16], false, vec![]),
                    ([7; 16], true, vec![[4; 16], [7; 16]])
                ],
                "Q249: same queue released by its window; moved: held by B's marker"
            );
            Ok(())
        })
    }

    /// What an overlap row (Q252) names besides its seed: `sid`, period, end, newest id, unknown.
    #[cfg(feature = "kat")]
    type Seen = (Id, Period, u64, u64, bool);

    /// The overlap rows (Q252) of `contact`'s session in `ord` order: what each names besides its seed.
    #[cfg(feature = "kat")]
    fn overlaps_of(
        hub: &Hub<ManualClock, Fixed>,
        contact: ContactId,
    ) -> Result<Vec<Seen>, crate::testutil::E> {
        let rows = hub
            .profile_store()
            .lock()
            .map_err(|_| "lock")?
            .pending_controls(contact.0)?;
        let mut out = Vec::new();
        for (_, row) in &rows {
            if let Some(r) = crate::sessions::actor::overlap_of(row).map_err(|_| "overlap")? {
                out.push((r.sid, r.period, r.until_ms, r.newest, r.unknown));
            }
        }
        Ok(out)
    }

    /// One cell of `q` prepared at `now` with its `OK_SEND` as cell `id`.
    #[cfg(feature = "kat")]
    fn on(hub: &mut Hub<ManualClock, Fixed>, q: QueueId, now: u64, id: u64) -> R {
        let p = hub
            .prepare_cell(q, now)
            .map_err(|_| "prepare")?
            .ok_or("cell")?;
        hub.relayed(q, p.token, id);
        Ok(())
    }

    /// Whether `contact`'s `KeyChange` is live.
    #[cfg(feature = "kat")]
    fn kc_live(hub: &Hub<ManualClock, Fixed>, contact: ContactId) -> bool {
        hub.core
            .index
            .get(&contact.0)
            .and_then(|at| hub.core.convs.get(*at))
            .is_some_and(crate::sessions::actor::Conversation::key_change_in_flight)
    }

    /// SE-113 (Q252, Q253; spec §10.1, §10.6 (1), (4)): every switch writes the old queue's overlap row — here without any
    /// `KeyChange` — with its route and the end drawn at the switch (the same as the hub's own retirement); a restart
    /// registers that queue again, in overlap, until that end: it carries cells, the tick 1 ms before the end keeps it,
    /// the tick at the end removes it and deletes its row.
    #[test]
    #[cfg(feature = "kat")]
    fn restart_registers_the_old_send_queue_until_its_end() -> R {
        big(|| {
            let (sc, guest, contact) = on_b("hub-ov", 151)?;
            let hub = &sc.invitee;
            let a = *hub.previous_sends.get(&contact.0).ok_or("A")?;
            let end = hub
                .retiring_sends
                .iter()
                .find(|r| r.queue == a)
                .map(|r| r.until)
                .ok_or("A retires")?;
            let left = end.saturating_sub(hub.core.clock.mono_ms());
            let until = hub.core.now_ms().saturating_add(left);
            let rows = overlaps_of(hub, contact)?;
            assert_eq!(
                rows.last(),
                Some(&([9; 16], Period::S80, until, 0, false)),
                "Q252: A's route and the drawn end"
            );
            let before = rows.len();
            drop(sc);
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 900)?;
            let added = add_sends(&mut again);
            let (a2, b2) = again.sends_of(contact).ok_or("sends")?;
            assert_eq!(
                (queue_of(&added, 4), queue_of(&added, 9)),
                (Some(b2), Some(a2)),
                "Q253: B current, A in overlap again"
            );
            assert!(
                again
                    .prepare_cell(a2, ms(10))
                    .map_err(|_| "prepare")?
                    .is_some(),
                "A carries cells"
            );
            let mono = again.core.clock.mono_ms();
            let left = until.saturating_sub(again.core.now_ms());
            again.tick(mono.saturating_add(left).saturating_sub(1));
            assert!(
                !again
                    .take_actions()
                    .iter()
                    .any(|x| matches!(x, Action::Remove { queue } if *queue == a2)),
                "1 ms before the end"
            );
            again.tick(mono.saturating_add(left));
            assert!(
                again
                    .take_actions()
                    .iter()
                    .any(|x| matches!(x, Action::Remove { queue } if *queue == a2)),
                "at the end"
            );
            assert_eq!(
                overlaps_of(&again, contact)?.len(),
                before.saturating_sub(1),
                "A's row goes with it"
            );
            Ok(())
        })
    }

    /// SE-114 (Q253, Q236, Q266; re-dictated by B17c): only an end still ahead and at most `MAX_SEND_OVERLAP_MS` away
    /// registers its queue again (rows of `sid` 21: the end now; 22: 1 ms ahead; 23: `MAX_SEND_OVERLAP_MS` ahead; 24: 1 ms
    /// more; 25: 1 ms ago), and only a physical
    /// queue not registered already (26 = B's `sid` 4, the current queue). The rows not registered go at the first
    /// preparation; the others stay.
    #[test]
    #[cfg(feature = "kat")]
    fn restart_registers_only_an_end_ahead_within_the_longest_overlap() -> R {
        use crate::clock::Clock as _;
        use crate::sessions::actor::OverlapRoute;

        big(|| {
            let (sc, guest, contact) = on_b("hub-ov-end", 153)?;
            let before = overlaps_of(&sc.invitee, contact)?;
            drop(sc);
            let now = guest.clock.unix_secs().saturating_mul(1_000);
            let store = guest.profile.store();
            for (sid, until) in [
                (21_u8, now),
                (22, now.saturating_add(1)),
                (23, now.saturating_add(MAX_SEND_OVERLAP_MS)),
                (
                    24,
                    now.saturating_add(MAX_SEND_OVERLAP_MS).saturating_add(1),
                ),
                (25, now.saturating_sub(1)),
                (4, now.saturating_add(1_000)),
            ] {
                let row = OverlapRoute {
                    sid: [sid; 16],
                    seed: SecretBytes::from_slice(&[sid; 32])?,
                    period: Period::S20,
                    until_ms: until,
                    newest: 0,
                    unknown: false,
                }
                .row();
                store
                    .lock()
                    .map_err(|_| "lock")?
                    .txn(|tx| secmp_store::sessions::insert_pending_control(tx, contact.0, &row))?;
            }
            drop(store);
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 900)?;
            let added: Vec<Id> = add_sends(&mut again).into_iter().map(|(_, s)| s).collect();
            let mut want: Vec<Id> = vec![[4; 16]];
            want.extend(before.iter().map(|r| r.0));
            want.extend([[22; 16], [23; 16]]);
            assert_eq!(added, want, "Q253: 22 and 23 only, and B once");
            let (_, b2) = again.sends_of(contact).ok_or("sends")?;
            on(&mut again, b2, ms(10), 1)?;
            let mut left: Vec<Id> = before.iter().map(|r| r.0).collect();
            left.extend([[22; 16], [23; 16]]);
            assert_eq!(
                overlaps_of(&again, contact)?
                    .iter()
                    .map(|r| r.0)
                    .collect::<Vec<_>>(),
                left,
                "the rows not registered go"
            );
            Ok(())
        })
    }

    /// SE-115 (Q252–Q254; OPEN-M7-B-27, D-B81): through the hub, the `KeyChange` relayed on B (`sid` 4, ids 1–4), then the
    /// route C (`sid` 7) — B in overlap, its row naming the copy's id 4; C's window passes, B's id 100 counts nothing; restart.
    /// B is registered again and counts the pre-restart copy away (131 is not enough, 132 is), and the `KeyChange` goes
    /// with its markers after the re-sent copy on C has left its window. (Before B17b-3 this held for good.)
    #[test]
    #[cfg(feature = "kat")]
    fn restart_in_overlap_counts_the_copy_away() -> R {
        big(|| {
            let (mut sc, guest, contact) = kc_on_b_then_c("hub-kc-ov", 157)?;
            let rows = overlaps_of(&sc.invitee, contact)?;
            assert_eq!(
                rows.last().map(|r| (r.0, r.3, r.4)),
                Some(([4; 16], 4, false)),
                "Q254: B's copy, id 4"
            );
            let hub = &mut sc.invitee;
            let (b, _) = hub.sends_of(contact).ok_or("sends")?;
            on(hub, b, ms(150), 100)?;
            drop(sc);
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 900)?;
            let added = add_sends(&mut again);
            let (c2, b2) = (
                queue_of(&added, 7).ok_or("C")?,
                queue_of(&added, 4).ok_or("B")?,
            );
            for i in 0..4_u64 {
                on(&mut again, c2, ms(200 + i), 300 + i)?;
            }
            for i in 0..3_u64 {
                on(&mut again, c2, ms(210 + i), 600 + i)?;
            }
            assert!(
                kc_live(&again, contact),
                "Q254: B's copy is not counted yet"
            );
            on(&mut again, b2, ms(220), 131)?;
            on(&mut again, c2, ms(221), 603)?;
            assert!(kc_live(&again, contact), "131 is not enough for 4 + 128");
            on(&mut again, b2, ms(222), 132)?;
            on(&mut again, c2, ms(223), 604)?;
            assert!(!kc_live(&again, contact), "132 counts B's copy away");
            assert_eq!(
                crate::sessions::tests::control_tags(&again.profile_store(), contact.0)?.1,
                Vec::<Id>::new(),
                "no marker left"
            );
            Ok(())
        })
    }

    /// SE-116 (Q253, Q241, Q250; D-B81 remaining trigger): as SE-115 up to the restart; B's overlap then ends before the
    /// count (the tick at its end): the marks stay, the `KeyChange` holds, B's row goes; a second restart registers no
    /// B and the `KeyChange` still holds (fail closed, no release by time).
    #[test]
    #[cfg(feature = "kat")]
    fn overlap_end_before_the_count_holds() -> R {
        big(|| {
            let (sc, guest, contact) = kc_on_b_then_c("hub-kc-end", 163)?;
            drop(sc);
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 900)?;
            let added = add_sends(&mut again);
            let (c2, b2) = (
                queue_of(&added, 7).ok_or("C")?,
                queue_of(&added, 4).ok_or("B")?,
            );
            let end = again
                .retiring_sends
                .iter()
                .find(|r| r.queue == b2)
                .map(|r| r.until)
                .ok_or("B retires")?;
            again.tick(end);
            for i in 0..4_u64 {
                on(&mut again, c2, ms(200 + i), 300 + i)?;
            }
            for i in 0..3_u64 {
                on(&mut again, c2, ms(210 + i), 600 + i)?;
            }
            assert!(
                kc_live(&again, contact),
                "Q241: the end of B's overlap does not clear its mark"
            );
            assert!(
                !overlaps_of(&again, contact)?.iter().any(|r| r.0 == [4; 16]),
                "B's row is gone"
            );
            drop(again);
            let guest = guest.reopen()?;
            let mut third = hub_over(&guest, "guest", 900)?;
            assert_eq!(
                queue_of(&add_sends(&mut third), 4),
                None,
                "no B after the end"
            );
            let c3 = *third.send_ids.get(&contact.0).ok_or("C")?;
            for i in 0..4_u64 {
                on(&mut third, c3, ms(300 + i), 700 + i)?;
            }
            for i in 0..3_u64 {
                on(&mut third, c3, ms(310 + i), 1_000 + i)?;
            }
            assert!(kc_live(&third, contact), "held for good (D-B81)");
            Ok(())
        })
    }

    /// SE-117 (Q253; D-B81 remaining trigger): as SE-115 up to the restart, but the client stays down past B's end: the
    /// restart registers no B, B's row goes at the first preparation, B's marker stays and the `KeyChange` holds.
    #[test]
    #[cfg(feature = "kat")]
    fn end_passed_while_down_holds() -> R {
        use crate::clock::Clock as _;

        big(|| {
            let (sc, guest, contact) = kc_on_b_then_c("hub-kc-down", 167)?;
            let until = overlaps_of(&sc.invitee, contact)?
                .iter()
                .find(|r| r.0 == [4; 16])
                .map(|r| r.2)
                .ok_or("B's row")?;
            drop(sc);
            let ahead = until.saturating_sub(guest.clock.unix_secs().saturating_mul(1_000));
            guest.clock.advance_ms(ahead.saturating_add(1_000));
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 900)?;
            let added = add_sends(&mut again);
            assert_eq!(queue_of(&added, 4), None, "Q253: the end has passed");
            let c2 = queue_of(&added, 7).ok_or("C")?;
            for i in 0..4_u64 {
                on(&mut again, c2, ms(200 + i), 300 + i)?;
            }
            for i in 0..3_u64 {
                on(&mut again, c2, ms(210 + i), 600 + i)?;
            }
            assert!(kc_live(&again, contact), "B's copy holds");
            assert!(!overlaps_of(&again, contact)?.iter().any(|r| r.0 == [4; 16]));
            assert!(
                crate::sessions::tests::control_tags(&again.profile_store(), contact.0)?
                    .1
                    .contains(&[4; 16]),
                "B's marker stays"
            );
            Ok(())
        })
    }

    /// SE-115…SE-117: `on_b`, `RotateIdentity`, the `KeyChange` relayed on B (ids 1–4), the route C (`sid` 7) pumped (B in
    /// overlap), the re-sent copy on C relayed (ids 1–4) and out of its window (261, 262).
    #[cfg(feature = "kat")]
    fn kc_on_b_then_c(
        label: &str,
        seed: u64,
    ) -> Result<(Scene, Fixture, ContactId), crate::testutil::E> {
        let (mut sc, guest, contact) = on_b(label, seed)?;
        let hub = &mut sc.invitee;
        let b = *hub.send_ids.get(&contact.0).ok_or("B")?;
        assert!(matches!(
            hub.core_mut().handle(Request::RotateIdentity)?,
            Response::IdentityRotated(_)
        ));
        for i in 0..4_u64 {
            on(hub, b, ms(60_u64.saturating_add(i)), i.saturating_add(1))?;
        }
        send_route(&mut sc, 7, ms(70))?;
        let hub = &mut sc.invitee;
        hub.pump()?;
        let c = queue_of(&add_sends(hub), 7).ok_or("C")?;
        for i in 0..4_u64 {
            on(hub, c, ms(90_u64.saturating_add(i)), i.saturating_add(1))?;
        }
        on(hub, c, ms(100), 261)?;
        on(hub, c, ms(101), 262)?;
        assert!(kc_live(hub, contact), "B's copy holds before the restart");
        Ok((sc, guest, contact))
    }

    /// SE-119 (Q252, Q253; verification R1 of B17b-3): every overlap row keeps the old route it was switched away from —
    /// A (`sid` 9, seed `[9; 32]`, 80 s) and the queue before it (10 s, its own seed), not the new route's seed or period —
    /// and a restart registers B and each old queue again with exactly that seed and period.
    #[test]
    #[cfg(feature = "kat")]
    fn restart_registers_each_old_queue_with_its_own_route() -> R {
        big(|| {
            let (sc, guest, contact) = on_b("hub-ov-own", 171)?;
            let mut rows: Vec<(Id, SecretBytes<32>, u64)> = Vec::new();
            for (_, row) in &sc
                .invitee
                .profile_store()
                .lock()
                .map_err(|_| "lock")?
                .pending_controls(contact.0)?
            {
                if let Some(r) = crate::sessions::actor::overlap_of(row).map_err(|_| "overlap")? {
                    rows.push((
                        r.sid,
                        r.seed,
                        u64::from(r.period.seconds()).saturating_mul(1_000),
                    ));
                }
            }
            let a = rows.iter().find(|r| r.0 == [9; 16]).ok_or("A's row")?;
            assert!(
                a.1.expose_secret() == &[9_u8; 32] && a.2 == 80_000,
                "Q252: A's row keeps A's seed and period"
            );
            let x = rows
                .iter()
                .find(|r| r.0 != [9; 16])
                .ok_or("the row before A")?;
            assert!(
                x.1.expose_secret() != &[9_u8; 32] && x.2 == 10_000,
                "Q252: the first row keeps its own seed and its period of 10 s"
            );
            rows.push(([4; 16], SecretBytes::from_slice(&[4; 32])?, 80_000));
            drop(sc);
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 900)?;
            let sends: Vec<(Id, SecretBytes<32>, u64)> = again
                .take_actions()
                .into_iter()
                .filter_map(|a| match a {
                    Action::AddSend {
                        sid,
                        seed,
                        period_ms,
                        ..
                    } => Some((sid, seed, period_ms)),
                    _ => None,
                })
                .collect();
            assert_eq!(sends.len(), rows.len(), "B and the old queues, once each");
            for (sid, seed, period) in &rows {
                assert!(
                    sends.iter().any(|s| s.0 == *sid
                        && s.1.expose_secret() == seed.expose_secret()
                        && s.2 == *period),
                    "Q253: registered again with its own seed and period"
                );
            }
            Ok(())
        })
    }

    /// SE-122 (Q253, Q236; spec §10.2; verification R1 of B17b-3): after a restart one physical queue has one sender — two
    /// overlap rows of one `sid` (22), both with an end ahead (as a failed delete can leave behind), register it once and
    /// both rows stay with it; a route to A (`sid` 9), registered again in overlap, registers nothing and B stays current.
    #[test]
    #[cfg(feature = "kat")]
    fn restart_keeps_one_sender_per_physical_queue() -> R {
        use crate::clock::Clock as _;
        use crate::sessions::actor::OverlapRoute;

        big(|| {
            let (sc, guest, contact) = on_b("hub-ov-once", 173)?;
            let before = overlaps_of(&sc.invitee, contact)?;
            drop(sc);
            let now = guest.clock.unix_secs().saturating_mul(1_000);
            let store = guest.profile.store();
            for until in [now.saturating_add(5_000), now.saturating_add(9_000)] {
                let row = OverlapRoute {
                    sid: [22; 16],
                    seed: SecretBytes::from_slice(&[22; 32])?,
                    period: Period::S20,
                    until_ms: until,
                    newest: 0,
                    unknown: false,
                }
                .row();
                store
                    .lock()
                    .map_err(|_| "lock")?
                    .txn(|tx| secmp_store::sessions::insert_pending_control(tx, contact.0, &row))?;
            }
            drop(store);
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 900)?;
            let added: Vec<Id> = add_sends(&mut again).into_iter().map(|(_, s)| s).collect();
            let mut want: Vec<Id> = vec![[4; 16]];
            want.extend(before.iter().map(|r| r.0));
            want.push([22; 16]);
            assert_eq!(added, want, "Q236: 22 once");
            let (_, b2) = again.sends_of(contact).ok_or("sends")?;
            on(&mut again, b2, ms(10), 1)?;
            assert_eq!(
                overlaps_of(&again, contact)?
                    .iter()
                    .filter(|r| r.0 == [22; 16])
                    .count(),
                2,
                "both rows of 22 stay with it"
            );
            let at = *again.core.index.get(&contact.0).ok_or("index")?;
            again.register_route(contact, at, &route_body(9, Period::S80)?)?;
            assert!(
                add_sends(&mut again).is_empty(),
                "Q236: A in overlap again is not registered a second time"
            );
            assert_eq!(again.send_ids.get(&contact.0), Some(&b2), "B stays current");
            Ok(())
        })
    }

    /// C1-8 a (SE-13b, Q210 d): `register_route` sets `T_RS` of the conversation from the period of the queue it sends to. The
    /// timeout is set to 0 first (every `PERIODS` value gives the minimum of 24 h, which `open_session` has set already, so
    /// only a 0 → 24 h change is observable); after a `RouteUpdate` with period `S80` it is `receipt_timeout_ms(80_000)`, and
    /// through the `Api` a relayed message of the verified contact is reported `NotConfirmed` only once that long has passed.
    #[test]
    #[cfg(feature = "kat")]
    fn register_route_sets_t_rs() -> R {
        use crate::sessions::actor::receipt_timeout_ms;
        use secmp_proto::wire::cell::{RelayQueue, RouteDescriptor, RouteUpdateBody};

        big(|| {
            let (host, guest) = (party("hub-t-h", 77)?, party("hub-t-g", 79)?);
            let mut sc = scene(host, &guest)?;
            step_invite(&mut sc)?;
            step_accept(&mut sc)?;
            step_handshake(&mut sc)?;
            step_reply(&mut sc)?;
            let (contact, hub) = (sc.contact, &mut sc.invitee);
            let at = *hub.core.index.get(&contact.0).ok_or("index")?;
            let timeout = |hub: &Hub<ManualClock, Fixed>| {
                hub.core
                    .convs
                    .get(at)
                    .map(crate::sessions::actor::Conversation::receipt_timeout_ms_kat)
            };
            hub.core
                .convs
                .get_mut(at)
                .ok_or("conversation")?
                .set_receipt_timeout_ms(0);
            assert_eq!(timeout(hub), Some(0));
            let update = RouteUpdateBody {
                routes: vec![RouteDescriptor::RelayQueue(RelayQueue {
                    relay: crate::testutil::relay_ref(),
                    sid: [9; 16],
                    send_seed: secmp_crypto::SecretBytes::from_slice(&[9; 32])?,
                    period_s: Period::S80,
                })],
            };
            hub.register_route(contact, at, &update.encode()?)?;
            assert_eq!(timeout(hub), Some(receipt_timeout_ms(80_000)));
            // through the Api: relayed on the new queue, reported only after `T_RS`
            let new_queue = hub.take_actions().iter().find_map(|a| match a {
                Action::AddSend { queue, .. } => Some(*queue),
                _ => None,
            });
            let new_queue = new_queue.ok_or("the new send queue")?;
            let Response::SafetyNumber(digits) =
                hub.core_mut().handle(Request::SafetyNumber { contact })?
            else {
                return Err("safety number".into());
            };
            assert!(matches!(
                hub.core_mut().handle(Request::Verify { contact, digits })?,
                Response::Verified(true)
            ));
            let Response::Sent(id) = hub.core_mut().handle(Request::Send {
                contact,
                kind: 1,
                payload: secmp_crypto::Zeroizing::new(b"t_rs".to_vec()),
                expire_after: 0,
            })?
            else {
                return Err("sent".into());
            };
            let cell = hub
                .prepare_cell(new_queue, ms(100))
                .map_err(|_| "prepare")?
                .ok_or("cell")?;
            hub.relayed(new_queue, cell.token, 3);
            hub.core_mut().take_events();
            let reported = |hub: &mut Hub<ManualClock, Fixed>,
                            now: u64|
             -> Result<usize, crate::testutil::E> {
                hub.prepare_cell(new_queue, now).map_err(|_| "prepare")?;
                hub.pump()?;
                Ok(hub
                    .core_mut()
                    .take_events()
                    .iter()
                    .filter(|e| {
                        e.event
                            == crate::api::Event::NotConfirmed {
                                contact,
                                msg_id: id,
                            }
                    })
                    .count())
            };
            let t_rs = receipt_timeout_ms(80_000);
            let relayed_at = ms(100);
            assert_eq!(
                reported(hub, relayed_at.saturating_add(t_rs).saturating_sub(1))?,
                0
            );
            assert_eq!(reported(hub, relayed_at.saturating_add(t_rs))?, 1);
            Ok(())
        })
    }

    /// The bytes of a queue's typed material (Q211), for comparing.
    #[cfg(feature = "kat")]
    fn exposed(
        m: Option<(SecretBytes<32>, Option<SecretBytes<32>>)>,
    ) -> Option<([u8; 32], Option<[u8; 32]>)> {
        m.map(|(r, s)| (*r.expose_secret(), s.map(|s| *s.expose_secret())))
    }

    /// The `QUEUE_DEL` ops of `queue` among `actions`.
    #[cfg(feature = "kat")]
    fn queue_dels(actions: &[Action], queue: QueueId) -> Vec<OpSpec> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Control(op) if op.kind == ControlKind::QueueDel(queue) => Some(*op),
                _ => None,
            })
            .collect()
    }

    /// Q208 (VERIFY-B4 P1 M-1 = P2 M-1; Q164): an identity rotation retires the open invitation, and its `QUEUE_DEL` — left
    /// in the core's ops — reaches the scheduler as an `Action::Control` after `pump`, behind an empty `FETCH` (Q194).
    #[cfg(feature = "kat")]
    #[test]
    fn identity_rotation_queue_del_reaches_scheduler() -> R {
        big(|| {
            let host = party("q208-h", 81)?;
            let mut hub = hub_over(&host, "host", 82)?;
            let issued = hub.invite(T0 + 5 * DAY)?;
            let inv_queue = hub.invitations.queue_of(&issued.invitation.ld_id)?.queue;
            hub.take_actions();
            let rotated = hub.core_mut().handle(Request::RotateIdentity)?;
            assert!(matches!(rotated, Response::IdentityRotated(_)));
            hub.pump()?;
            let dels = queue_dels(&hub.take_actions(), inv_queue);
            assert_eq!(dels.len(), 1, "one QUEUE_DEL of the invitation queue");
            assert_eq!(
                dels.first().map(|op| op.when),
                Some(When::AfterEmptyFetch(inv_queue))
            );
            hub.pump()?;
            assert!(
                queue_dels(&hub.take_actions(), inv_queue).is_empty(),
                "once"
            );
            Ok(())
        })
    }

    /// Q208 (VERIFY-B4 P2 M-1; IN-11, Q194): an invitation queue that never receives a cell is retired on schedule — no
    /// `QUEUE_DEL` before `expires`; once the core clock is past it, `tick` retires it, and its `QUEUE_DEL` waits for an
    /// empty `FETCH` (none is due before it) and then `U[1 min, 60 min]`; a later tick does not retire it twice.
    #[cfg(feature = "kat")]
    #[test]
    fn expired_invitation_queue_del_without_traffic() -> R {
        use crate::scheduler::control::ControlOps;
        use crate::scheduler::params::Params;
        use crate::scheduler::types::OpId;

        big(|| {
            let host = party("q208e-h", 83)?;
            let mut hub = hub_over(&host, "host", 84)?;
            let issued = hub.invite(T0 + DAY)?;
            let inv_queue = hub.invitations.queue_of(&issued.invitation.ld_id)?.queue;
            hub.take_actions();
            hub.tick(ms(10));
            assert!(
                queue_dels(&hub.take_actions(), inv_queue).is_empty(),
                "not expired"
            );
            host.at_day(2);
            let now = host.clock.mono_ms();
            hub.tick(now);
            let dels = queue_dels(&hub.take_actions(), inv_queue);
            assert_eq!(dels.len(), 1, "the expired invitation's QUEUE_DEL");
            let op = dels.first().ok_or("QUEUE_DEL")?;
            assert_eq!(op.when, When::AfterEmptyFetch(inv_queue));
            // the scheduler's control queue: nothing due before the empty FETCH, then U[1 min, 60 min]
            let (params, mut rng) = (Params::default(), TimingRng::seeded(17));
            let mut queue = ControlOps::new();
            queue.schedule(&params, &mut rng, OpId(1), now, *op)?;
            assert!(queue.take_due(u64::MAX).is_empty());
            let fetched = now.saturating_add(10_000);
            queue.note_empty_fetch(&params, &mut rng, inv_queue, fetched);
            let due = queue.due_of(OpId(1)).ok_or("due")?;
            assert!(
                (fetched + 60_000..=fetched + 3_600_000).contains(&due),
                "{due}"
            );
            hub.tick(now.saturating_add(1_000));
            assert!(
                queue_dels(&hub.take_actions(), inv_queue).is_empty(),
                "once"
            );
            Ok(())
        })
    }

    /// SE-126 (Q253, Q236; verification R2 of B17b-3): a row skipped at the restart because its physical queue is
    /// registered already (here one of B, the current queue) does not end the re-registration: the row after it in `ord`
    /// order (`sid` 22, its end ahead) is still registered, and both rows of the restart stay until the first preparation
    /// decides (B's goes, 22's stays with its queue).
    #[test]
    #[cfg(feature = "kat")]
    fn restart_registers_the_rows_after_a_skipped_one() -> R {
        use crate::clock::Clock as _;
        use crate::sessions::actor::OverlapRoute;

        big(|| {
            let (sc, guest, contact) = on_b("hub-ov-skip", 179)?;
            let before = overlaps_of(&sc.invitee, contact)?;
            drop(sc);
            let now = guest.clock.unix_secs().saturating_mul(1_000);
            let store = guest.profile.store();
            for sid in [4_u8, 22] {
                let row = OverlapRoute {
                    sid: [sid; 16],
                    seed: SecretBytes::from_slice(&[sid; 32])?,
                    period: Period::S20,
                    until_ms: now.saturating_add(5_000),
                    newest: 0,
                    unknown: false,
                }
                .row();
                store
                    .lock()
                    .map_err(|_| "lock")?
                    .txn(|tx| secmp_store::sessions::insert_pending_control(tx, contact.0, &row))?;
            }
            drop(store);
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 900)?;
            let added: Vec<Id> = add_sends(&mut again).into_iter().map(|(_, s)| s).collect();
            let mut want: Vec<Id> = vec![[4; 16]];
            want.extend(before.iter().map(|r| r.0));
            want.push([22; 16]);
            assert_eq!(added, want, "Q253: 22 after the skipped row of B");
            let (_, b2) = again.sends_of(contact).ok_or("sends")?;
            on(&mut again, b2, ms(10), 1)?;
            let mut left: Vec<Id> = before.iter().map(|r| r.0).collect();
            left.push([22; 16]);
            assert_eq!(
                overlaps_of(&again, contact)?
                    .iter()
                    .map(|r| r.0)
                    .collect::<Vec<_>>(),
                left,
                "B's row goes, 22's stays"
            );
            Ok(())
        })
    }

    /// SE-128 (Q253, D-B88; verification R2 of B17b-3): a restart a minute into A's overlap keeps A's stored end: the queue
    /// registered again retires at the restart's monotonic time plus what is left of the overlap on the core clock (the
    /// minute the client was off counts against it), not measured from monotonic 0: the tick 1 ms before keeps it, the tick
    /// at that end removes it.
    #[test]
    #[cfg(feature = "kat")]
    fn restart_later_keeps_the_stored_end() -> R {
        use crate::clock::Clock as _;

        big(|| {
            let (sc, guest, contact) = on_b("hub-ov-later", 181)?;
            let until = overlaps_of(&sc.invitee, contact)?
                .iter()
                .find(|r| r.0 == [9; 16])
                .map(|r| r.2)
                .ok_or("A's row")?;
            drop(sc);
            guest.clock.advance_ms(60_000);
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 900)?;
            let a2 = queue_of(&add_sends(&mut again), 9).ok_or("A again")?;
            let mono = again.core.clock.mono_ms();
            assert!(mono >= 60_000, "the restart is a minute later");
            let left = until
                .checked_sub(again.core.now_ms())
                .ok_or("A's end is ahead")?;
            again.tick(mono.saturating_add(left).saturating_sub(1));
            assert!(
                !again
                    .take_actions()
                    .iter()
                    .any(|x| matches!(x, Action::Remove { queue } if *queue == a2)),
                "1 ms before the stored end"
            );
            again.tick(mono.saturating_add(left));
            assert!(
                again
                    .take_actions()
                    .iter()
                    .any(|x| matches!(x, Action::Remove { queue } if *queue == a2)),
                "at the stored end"
            );
            Ok(())
        })
    }
    /// SE-140 (Q264; spec §10.2): the longest interval between two cells of a send queue — Strict: its period, whatever
    /// the link; Balanced (`T` = 10 s) and Low-bandwidth (`T` = 30 s): `(⌈P_q / T⌉ + n − 1) · T` (an exact and a rounded-up
    /// division, one queue counted as one, none as one); an overflow and a zero slot give `None`; direct transport makes
    /// Strict Balanced and changes no other mode.
    #[test]
    fn cell_interval_follows_mode_period_and_queues() {
        use super::{cell_interval_ms, effective_mode};
        use crate::scheduler::params::{Mode, Params};

        let p = Params::default();
        let cases = [
            (Mode::Strict, 80_000, 5, Some(80_000)),
            (Mode::Strict, 10_000, 1, Some(10_000)),
            (Mode::Balanced, 80_000, 1, Some(80_000)),
            (Mode::Balanced, 80_000, 3, Some(100_000)),
            (Mode::Balanced, 85_000, 1, Some(90_000)),
            (Mode::Balanced, 10_000, 4, Some(40_000)),
            (Mode::Balanced, 10_000, 0, Some(10_000)),
            (Mode::LowBw, 80_000, 1, Some(90_000)),
            (Mode::LowBw, 90_000, 1, Some(90_000)),
            (Mode::LowBw, 80_000, 10, Some(360_000)),
            (Mode::LowBw, 10_000, 12, Some(360_000)),
            (Mode::Balanced, u64::MAX, 1, None),
            (Mode::Balanced, 80_000, u64::MAX, None),
        ];
        for (mode, period, n, want) in cases {
            assert_eq!(
                cell_interval_ms(&p, mode, period, n),
                want,
                "{mode:?} {period} {n}"
            );
        }
        let zero = Params {
            t_balanced_ms: 0,
            ..Params::default()
        };
        assert_eq!(cell_interval_ms(&zero, Mode::Balanced, 80_000, 1), None);
        assert_eq!(effective_mode(Mode::Strict, true), Mode::Balanced);
        assert_eq!(effective_mode(Mode::Strict, false), Mode::Strict);
        assert_eq!(effective_mode(Mode::LowBw, true), Mode::LowBw);
        assert_eq!(effective_mode(Mode::LowBw, false), Mode::LowBw);
        assert_eq!(effective_mode(Mode::Balanced, true), Mode::Balanced);
    }

    /// SE-141 (Q264, Q266; re-dictated by B17c R1 M-2): `FLOOR_CELLS` = `QUEUE_CAPACITY` + the in-flight depth + 2 = 132;
    /// the longest overlap is two days and a minute, above `OLD_SEND_MS`; only the term `132 · I` is capped, at 25 h =
    /// `MAX_SEND_OVERLAP_MS − (OLD_SEND_MS − 1 h)`: `from + blur + min(132 · I, 25 h)` one interval below and above the
    /// term's cap, for an unknown interval and on an overflow; the fallback draw at the term's cap is the longest overlap,
    /// a larger share is cut there.
    #[test]
    fn floor_end_is_capped() {
        use super::{
            FLOOR_CELLS, FLOOR_TERM_CAP_MS, MAX_SEND_OVERLAP_MS, OLD_SEND_MS, OVERLAP_MS, floor_end,
        };

        let capacity = u64::try_from(secmp_proto::link::QUEUE_CAPACITY).unwrap_or(0);
        let depth = u64::from(crate::scheduler::params::Params::default().max_in_flight);
        assert_eq!(
            FLOOR_CELLS,
            capacity.saturating_add(depth).saturating_add(2)
        );
        assert_eq!(FLOOR_CELLS, 132);
        assert_eq!(MAX_SEND_OVERLAP_MS, 48 * 3_600_000 + 60_000);
        assert_eq!(FLOOR_TERM_CAP_MS, 25 * 3_600_000);
        const { assert!(MAX_SEND_OVERLAP_MS > OLD_SEND_MS) };
        let fallback = OLD_SEND_MS.saturating_sub(OVERLAP_MS.0);
        assert_eq!(
            FLOOR_TERM_CAP_MS.saturating_add(fallback),
            MAX_SEND_OVERLAP_MS
        );
        let (max, cap) = (MAX_SEND_OVERLAP_MS, FLOOR_TERM_CAP_MS);
        assert_eq!(floor_end(10, 0, Some(80_000)), 10_560_010);
        assert_eq!(floor_end(10, 5, Some(80_000)), 10_560_015);
        assert_eq!(
            floor_end(3, 5, Some(681_818)),
            89_999_984,
            "one interval below the term's cap"
        );
        assert_eq!(
            floor_end(3, 5, Some(681_819)),
            cap.saturating_add(8),
            "above it"
        );
        assert_eq!(floor_end(7, 11, None), cap.saturating_add(18));
        assert_eq!(floor_end(0, 0, Some(u64::MAX)), cap);
        assert_eq!(floor_end(0, fallback, Some(u64::MAX)), max, "the fallback");
        assert_eq!(
            floor_end(0, fallback.saturating_add(1), Some(u64::MAX)),
            max,
            "a larger share is cut"
        );
        assert_eq!(floor_end(0, u64::MAX, Some(1)), max);
        assert_eq!(floor_end(u64::MAX, 0, Some(1)), u64::MAX);
    }

    /// SE-149 (Q264, Q266; B17c verification R1 M-2; spec §10.6 (4)): the floor moves with the drawn share by exactly that
    /// share at every interval — below, at and far above the term's cap, unknown, and for every mode and n up to 1000 —
    /// so the end stays uniform over the draw's 23 h and is never at a fixed distance from the switch.
    #[test]
    fn floor_end_keeps_the_draw_at_every_interval() {
        use super::{cell_interval_ms, floor_end};
        use crate::scheduler::params::{Mode, Params};

        let p = Params::default();
        let mut intervals = vec![
            Some(10_000),
            Some(80_000),
            Some(681_818),
            Some(681_819),
            Some(1_309_500),
            Some(10_000_000),
            Some(u64::MAX),
            None,
        ];
        for mode in [Mode::Strict, Mode::Balanced, Mode::LowBw] {
            for n in [1_u64, 21, 42, 62, 124, 1_000] {
                intervals.push(cell_interval_ms(&p, mode, 80_000, n));
            }
        }
        for interval in intervals {
            let low = floor_end(1_000, 0, interval);
            for blur in [1_u64, 41_400_000, 82_800_000] {
                assert_eq!(
                    floor_end(1_000, blur, interval).checked_sub(low),
                    Some(blur),
                    "{interval:?} {blur}"
                );
            }
        }
    }

    /// `from + blur + span`.
    #[cfg(feature = "kat")]
    const fn end_of(from: u64, blur: u64, span: u64) -> u64 {
        from.saturating_add(blur).saturating_add(span)
    }

    /// The floor `from + blur + FLOOR_CELLS · interval`.
    #[cfg(feature = "kat")]
    const fn floor_of(from: u64, blur: u64, interval: u64) -> u64 {
        end_of(from, blur, FLOOR_CELLS.saturating_mul(interval))
    }

    /// The (until, from, blur) of the old send queue `q` in overlap, if it has a floor (a switch of this process).
    #[cfg(feature = "kat")]
    fn retiring_of(hub: &Hub<ManualClock, Fixed>, q: QueueId) -> Option<(u64, u64, u64)> {
        hub.retiring_sends
            .iter()
            .find(|r| r.queue == q)
            .and_then(|r| r.floor.map(|f| (r.until, f.from, f.blur)))
    }

    /// The end (monotonic) of the old send queue `q` in overlap, with or without a floor.
    #[cfg(feature = "kat")]
    fn end_at(hub: &Hub<ManualClock, Fixed>, q: QueueId) -> Option<u64> {
        hub.retiring_sends
            .iter()
            .find(|r| r.queue == q)
            .map(|r| r.until)
    }

    /// Whether the actions taken since the last call remove `q`.
    #[cfg(feature = "kat")]
    fn removes(hub: &mut Hub<ManualClock, Fixed>, q: QueueId) -> bool {
        hub.take_actions()
            .iter()
            .any(|x| matches!(x, Action::Remove { queue } if *queue == q))
    }

    /// The old send queues of `on_b` in overlap: X (the first, 10 s) and A (`sid` 9, 80 s).
    #[cfg(feature = "kat")]
    fn x_and_a(
        hub: &Hub<ManualClock, Fixed>,
        contact: ContactId,
    ) -> Result<(QueueId, QueueId), crate::testutil::E> {
        let (a, _) = hub.sends_of(contact).ok_or("sends")?;
        let x = hub
            .retiring_sends
            .iter()
            .map(|r| r.queue)
            .find(|q| *q != a)
            .ok_or("X")?;
        Ok((x, a))
    }

    /// SE-142 (Q264, Q265; spec §10.1, §10.6 (4)): Strict mode, no `KeyChange`. At the switch the end is the draw (`from + u`,
    /// `blur = u − 1 h`); the first tick raises A (80 s) to `from + blur + 132 · 80 s` — the draw shifted by 132 · 80 s − 1 h,
    /// never a fixed distance from the switch — and keeps X (10 s; 132 · 10 s is below 1 h) at its draw; A's row names the
    /// new end, the row it replaced is gone; the tick 1 ms before keeps A, the tick at it removes A and its row.
    #[test]
    #[cfg(feature = "kat")]
    fn switch_floor_shifts_the_drawn_end() -> R {
        big(|| {
            let (mut sc, _guest, contact) = on_b("hub-fl-sw", 191)?;
            let hub = &mut sc.invitee;
            let (x, a) = x_and_a(hub, contact)?;
            let (xu, xf, xb) = retiring_of(hub, x).ok_or("X retires")?;
            let (au, af, ab) = retiring_of(hub, a).ok_or("A retires")?;
            assert_eq!(
                (xu, au),
                (end_of(xf, xb, OVERLAP_MS.0), end_of(af, ab, OVERLAP_MS.0)),
                "the draws"
            );
            hub.tick(hub.core.clock.mono_ms());
            let a_end = floor_of(af, ab, 80_000);
            assert_eq!(
                retiring_of(hub, a).map(|r| r.0),
                Some(a_end),
                "Q264: A's floor"
            );
            assert_eq!(
                a_end.saturating_sub(au),
                FLOOR_CELLS
                    .saturating_mul(80_000)
                    .saturating_sub(OVERLAP_MS.0),
                "the draw, shifted"
            );
            assert_eq!(
                retiring_of(hub, x).map(|r| r.0),
                Some(xu),
                "X keeps its draw"
            );
            let base = hub.unix_base();
            let rows = overlaps_of(hub, contact)?;
            let of_a: Vec<u64> = rows
                .iter()
                .filter(|r| r.0 == [9; 16])
                .map(|r| r.2)
                .collect();
            assert_eq!(
                of_a,
                vec![base.saturating_add(a_end)],
                "Q265: A's one row names its floor"
            );
            hub.tick(a_end.saturating_sub(1));
            assert!(!removes(hub, a), "1 ms before");
            hub.tick(a_end);
            assert!(removes(hub, a), "at the floor");
            assert!(
                !overlaps_of(hub, contact)?.iter().any(|r| r.0 == [9; 16]),
                "A's row goes"
            );
            Ok(())
        })
    }

    /// SE-143 (Q264; spec §10.2): the floor follows the mode and the send queues on the link at every tick and never
    /// shortens an end. Balanced, n = 3 (X, A, B): A (80 s) 100 s, X (10 s) 30 s; a route C (n = 4): A 110 s, X 40 s, B (now
    /// in overlap, 80 s) 110 s from its own switch; Low-bandwidth: A 180 s, X 120 s; Strict again: nothing shorter; direct
    /// transport in Strict mode counts as Balanced.
    #[test]
    #[cfg(feature = "kat")]
    fn floor_follows_the_mode_and_a_growing_link() -> R {
        use crate::scheduler::params::Mode;

        big(|| {
            let (mut sc, _guest, contact) = on_b("hub-fl-n", 193)?;
            let (x, a) = x_and_a(&sc.invitee, contact)?;
            let (_, xf, xb) = retiring_of(&sc.invitee, x).ok_or("X")?;
            let (_, af, ab) = retiring_of(&sc.invitee, a).ok_or("A")?;
            let at = |hub: &Hub<ManualClock, Fixed>, q| retiring_of(hub, q).map(|r| r.0);
            let hub = &mut sc.invitee;
            hub.core.settings.mode = Mode::Balanced;
            hub.tick(hub.core.clock.mono_ms());
            assert_eq!(at(hub, a), Some(floor_of(af, ab, 100_000)), "A, n = 3");
            assert_eq!(at(hub, x), Some(floor_of(xf, xb, 30_000)), "X, n = 3");
            let b = hub.send_ids.get(&contact.0).copied().ok_or("B")?;
            send_route(&mut sc, 7, ms(40))?;
            let hub = &mut sc.invitee;
            hub.pump()?;
            let (bu, bf, bb) = retiring_of(hub, b).ok_or("B retires")?;
            assert_eq!(bu, end_of(bf, bb, OVERLAP_MS.0), "B's draw");
            hub.tick(hub.core.clock.mono_ms());
            assert_eq!(at(hub, a), Some(floor_of(af, ab, 110_000)), "A, n = 4");
            assert_eq!(at(hub, x), Some(floor_of(xf, xb, 40_000)), "X, n = 4");
            assert_eq!(at(hub, b), Some(floor_of(bf, bb, 110_000)), "B, n = 4");
            hub.core.settings.mode = Mode::LowBw;
            hub.tick(hub.core.clock.mono_ms());
            assert_eq!(at(hub, a), Some(floor_of(af, ab, 180_000)), "A, Low-bw");
            assert_eq!(at(hub, x), Some(floor_of(xf, xb, 120_000)), "X, Low-bw");
            let high = (at(hub, x), at(hub, a), at(hub, b));
            hub.core.settings.mode = Mode::Strict;
            hub.tick(hub.core.clock.mono_ms());
            assert_eq!((at(hub, x), at(hub, a), at(hub, b)), high, "never shorter");
            let base = hub.unix_base();
            let rows = overlaps_of(hub, contact)?;
            let of_a: Vec<u64> = rows
                .iter()
                .filter(|r| r.0 == [9; 16])
                .map(|r| r.2)
                .collect();
            assert_eq!(
                of_a,
                vec![base.saturating_add(floor_of(af, ab, 180_000))],
                "one row, the latest end"
            );

            let (mut sc, _guest, contact) = on_b("hub-fl-direct", 195)?;
            let hub = &mut sc.invitee;
            let (_, a) = x_and_a(hub, contact)?;
            let (_, af, ab) = retiring_of(hub, a).ok_or("A")?;
            hub.core.view.direct = true;
            hub.tick(hub.core.clock.mono_ms());
            assert_eq!(
                at(hub, a),
                Some(floor_of(af, ab, 100_000)),
                "direct: Balanced"
            );
            Ok(())
        })
    }

    /// SE-144 (Q265; CLAUDE.md §1.7): a floor is used only once its row is durable — a failed write leaves A's end and its
    /// row as they were, and the next tick writes it; a queue in overlap without an overlap row is never lengthened.
    #[test]
    #[cfg(feature = "kat")]
    fn floor_waits_for_its_row() -> R {
        big(|| {
            let (mut sc, _guest, contact) = on_b("hub-fl-row", 197)?;
            let hub = &mut sc.invitee;
            let (_, a) = x_and_a(hub, contact)?;
            let (au, af, ab) = retiring_of(hub, a).ok_or("A")?;
            let base = hub.unix_base();
            let ghost = hub.alloc_send();
            hub.send_targets.insert(ghost, (hub.config.relay, [77; 16]));
            hub.send_periods.insert(ghost, 80_000);
            let mono = hub.core.clock.mono_ms();
            hub.retiring_sends.push(Retiring {
                queue: ghost,
                until: mono.saturating_add(1_000),
                floor: Some(Anchor {
                    from: mono,
                    blur: 0,
                }),
            });
            secmp_store::kat::fail_at(secmp_store::kat::FailAt(1));
            hub.tick(mono);
            assert_eq!(
                retiring_of(hub, a).map(|r| r.0),
                Some(au),
                "the write failed: A's end stays"
            );
            let rows = overlaps_of(hub, contact)?;
            let of_a: Vec<u64> = rows
                .iter()
                .filter(|r| r.0 == [9; 16])
                .map(|r| r.2)
                .collect();
            assert_eq!(of_a, vec![base.saturating_add(au)], "and its row");
            hub.tick(mono);
            let a_end = floor_of(af, ab, 80_000);
            assert_eq!(
                retiring_of(hub, a).map(|r| r.0),
                Some(a_end),
                "written at the next tick"
            );
            assert_eq!(
                retiring_of(hub, ghost).map(|r| r.0),
                Some(mono.saturating_add(1_000)),
                "no row: no floor"
            );
            hub.tick(mono.saturating_add(1_000));
            assert!(removes(hub, ghost), "it ends at its end");
            Ok(())
        })
    }

    /// SE-145 (Q267 revised, option (a); B17c verification R1 B-1; spec §11.3): two old send queues a restart a minute
    /// later registers again (rows of `sid` 22 and 23, 20 s, ends 5 s and 7 s ahead) keep exactly their stored ends —
    /// no floor, no common instant, no fixed distance from the restart: the first tick changes neither end nor row; the
    /// tick 1 ms before each end keeps it, the tick at it removes that queue, and its row, only.
    #[test]
    #[cfg(feature = "kat")]
    fn restart_keeps_the_stored_ends() -> R {
        use crate::clock::Clock as _;
        use crate::sessions::actor::OverlapRoute;

        big(|| {
            let (sc, guest, contact) = on_b("hub-fl-rs", 199)?;
            drop(sc);
            guest.clock.advance_ms(60_000);
            let now = guest.clock.unix_secs().saturating_mul(1_000);
            let store = guest.profile.store();
            for (sid, ahead) in [(22_u8, 5_000_u64), (23, 7_000)] {
                let row = OverlapRoute {
                    sid: [sid; 16],
                    seed: SecretBytes::from_slice(&[sid; 32])?,
                    period: Period::S20,
                    until_ms: now.saturating_add(ahead),
                    newest: 0,
                    unknown: false,
                }
                .row();
                store
                    .lock()
                    .map_err(|_| "lock")?
                    .txn(|tx| secmp_store::sessions::insert_pending_control(tx, contact.0, &row))?;
            }
            drop(store);
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 900)?;
            let added = add_sends(&mut again);
            let (q22, q23) = (
                queue_of(&added, 22).ok_or("22")?,
                queue_of(&added, 23).ok_or("23")?,
            );
            let mono = again.core.clock.mono_ms();
            assert!(mono >= 60_000, "the restart is a minute later");
            let (e22, e23) = (mono.saturating_add(5_000), mono.saturating_add(7_000));
            let rows_of =
                |hub: &Hub<ManualClock, Fixed>| -> Result<Vec<(Id, u64)>, crate::testutil::E> {
                    Ok(overlaps_of(hub, contact)?
                        .iter()
                        .filter(|r| r.0 == [22; 16] || r.0 == [23; 16])
                        .map(|r| (r.0, r.2))
                        .collect())
                };
            let stored = rows_of(&again)?;
            again.tick(mono);
            assert_eq!(
                (end_at(&again, q22), end_at(&again, q23)),
                (Some(e22), Some(e23)),
                "Q267: the stored ends, not a common instant"
            );
            assert_eq!(
                (retiring_of(&again, q22), retiring_of(&again, q23)),
                (None, None),
                "no floor after a restart"
            );
            assert_eq!(rows_of(&again)?, stored, "no row rewritten");
            again.tick(e22.saturating_sub(1));
            assert!(!removes(&mut again, q22), "1 ms before 22's end");
            again.tick(e22);
            let gone = again.take_actions();
            let gone = |q: QueueId| {
                gone.iter()
                    .any(|x| matches!(x, Action::Remove { queue } if *queue == q))
            };
            assert_eq!(
                (gone(q22), gone(q23)),
                (true, false),
                "22 at its end, 23 not"
            );
            again.tick(e23.saturating_sub(1));
            assert!(!removes(&mut again, q23), "1 ms before 23's end");
            again.tick(e23);
            assert!(removes(&mut again, q23), "23 at its end");
            assert_eq!(rows_of(&again)?, Vec::new(), "their rows go");
            Ok(())
        })
    }

    /// SE-146 (Q265): three rows of one `sid` (22; ends 5 s, 9 s and 3 s ahead, in `ord` order, as a crash between the
    /// write of a lengthened row and the delete of the row it replaces leaves them) register it once, until the latest end.
    #[test]
    #[cfg(feature = "kat")]
    fn restart_takes_the_latest_end_of_a_sid() -> R {
        use crate::clock::Clock as _;
        use crate::sessions::actor::OverlapRoute;

        big(|| {
            let (sc, guest, contact) = on_b("hub-fl-max", 201)?;
            drop(sc);
            let now = guest.clock.unix_secs().saturating_mul(1_000);
            let store = guest.profile.store();
            for ahead in [5_000_u64, 9_000, 3_000] {
                let row = OverlapRoute {
                    sid: [22; 16],
                    seed: SecretBytes::from_slice(&[22; 32])?,
                    period: Period::S20,
                    until_ms: now.saturating_add(ahead),
                    newest: 0,
                    unknown: false,
                }
                .row();
                store
                    .lock()
                    .map_err(|_| "lock")?
                    .txn(|tx| secmp_store::sessions::insert_pending_control(tx, contact.0, &row))?;
            }
            drop(store);
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 900)?;
            let added = add_sends(&mut again);
            assert_eq!(
                added.iter().filter(|(_, s)| *s == [22; 16]).count(),
                1,
                "once"
            );
            let q = queue_of(&added, 22).ok_or("22")?;
            let mono = again.core.clock.mono_ms();
            assert_eq!(
                end_at(&again, q),
                Some(mono.saturating_add(9_000)),
                "the latest end"
            );
            Ok(())
        })
    }

    /// SE-148 (Q264; B17c verification R1): the floor of a switch counts from the switch on the monotonic clock — B (80 s)
    /// switched two hours after the start: its `from` is that time, its draw and its floor `from + blur + 132 · 80 s` are
    /// measured from it; the tick 1 ms before keeps B, the tick at it removes B.
    #[test]
    #[cfg(feature = "kat")]
    fn switch_floor_counts_from_the_switch() -> R {
        use crate::clock::Clock as _;

        big(|| {
            let (mut sc, _guest, contact) = on_b("hub-fl-at", 215)?;
            sc.invitee.core.clock.advance_ms(2 * 3_600_000);
            let at = sc.invitee.core.clock.mono_ms();
            assert!(at >= 2 * 3_600_000, "two hours on");
            let b = sc.invitee.send_ids.get(&contact.0).copied().ok_or("B")?;
            send_route(&mut sc, 7, ms(40))?;
            let hub = &mut sc.invitee;
            hub.pump()?;
            let (bu, bf, bb) = retiring_of(hub, b).ok_or("B retires")?;
            assert_eq!(bf, at, "from = the switch");
            assert_eq!(bu, end_of(at, bb, OVERLAP_MS.0), "the draw from the switch");
            hub.tick(at);
            let end = floor_of(at, bb, 80_000);
            assert_eq!(
                retiring_of(hub, b).map(|r| r.0),
                Some(end),
                "Q264: the floor from the switch"
            );
            hub.tick(end.saturating_sub(1));
            assert!(!removes(hub, b), "1 ms before");
            hub.tick(end);
            assert!(removes(hub, b), "at the floor");
            Ok(())
        })
    }

    /// SE-150 (Q267 revised, option (a); B17c verification R1 M-1): A (80 s, Strict) switched and raised to its floor in
    /// one process; then 30 restarts two hours apart: every restart that registers A registers it until exactly the end
    /// its row kept (the floor from the switch, Q265), rewrites no row, and once that end has passed no restart registers
    /// A again — restarts never keep an old queue beyond its stored end.
    #[test]
    #[cfg(feature = "kat")]
    fn restarts_do_not_extend_an_old_queue() -> R {
        use crate::clock::Clock as _;

        big(|| {
            let (mut sc, mut guest, contact) = on_b("hub-fl-loop", 211)?;
            let hub = &mut sc.invitee;
            let (_, a) = x_and_a(hub, contact)?;
            let (_, af, ab) = retiring_of(hub, a).ok_or("A")?;
            hub.tick(hub.core.clock.mono_ms());
            let stored = hub.unix_base().saturating_add(floor_of(af, ab, 80_000));
            let rows_of_a =
                |hub: &Hub<ManualClock, Fixed>| -> Result<Vec<u64>, crate::testutil::E> {
                    Ok(overlaps_of(hub, contact)?
                        .iter()
                        .filter(|r| r.0 == [9; 16])
                        .map(|r| r.2)
                        .collect())
                };
            assert_eq!(
                rows_of_a(hub)?,
                vec![stored],
                "Q265: the floor from the switch is stored"
            );
            drop(sc);
            let (mut registered, mut ended) = (0_u32, false);
            for _ in 0..30_u32 {
                guest.clock.advance_ms(2 * 3_600_000);
                guest = guest.reopen()?;
                let mut again = hub_over(&guest, "guest", 900)?;
                let Some(a2) = queue_of(&add_sends(&mut again), 9) else {
                    assert!(
                        again.core.now_ms() >= stored,
                        "A goes only once its end has passed"
                    );
                    ended = true;
                    break;
                };
                registered = registered.saturating_add(1);
                let mono = again.core.clock.mono_ms();
                again.tick(mono);
                assert_eq!(
                    end_at(&again, a2).map(|e| again.unix_base().saturating_add(e)),
                    Some(stored),
                    "restart {registered}: exactly the stored end"
                );
                assert_eq!(
                    rows_of_a(&again)?,
                    vec![stored],
                    "restart {registered}: no row rewritten"
                );
                drop(again);
            }
            assert!(
                ended,
                "A is not registered after its stored end ({registered} restarts registered it)"
            );
            assert!(registered >= 1, "the first restart registers A");
            Ok(())
        })
    }

    /// SE-151 (Q264; B17c finalizer): the floor comes before the drop — A's first tick after its switch at its drawn end
    /// (`from + blur + 1 h`) raises A to its floor and keeps it; the tick at the floor removes it.
    #[test]
    #[cfg(feature = "kat")]
    fn switch_floor_comes_before_the_drop() -> R {
        big(|| {
            let (mut sc, _guest, contact) = on_b("hub-fl-first", 217)?;
            let hub = &mut sc.invitee;
            let (_, a) = x_and_a(hub, contact)?;
            let (au, af, ab) = retiring_of(hub, a).ok_or("A")?;
            hub.tick(au);
            assert!(!removes(hub, a), "the floor comes first");
            let a_end = floor_of(af, ab, 80_000);
            assert_eq!(end_at(hub, a), Some(a_end), "A's floor");
            hub.tick(a_end);
            assert!(removes(hub, a), "at the floor");
            Ok(())
        })
    }

    /// SE-152 (Q264; B17c verification R2, hand mutant V24): the floor reaches the old send queue of a second contact,
    /// whose conversation is not the first one the hub holds: its queue 17 (80 s, Strict) is raised from its draw to
    /// `from + blur + 132 · 80 s`.
    #[test]
    #[cfg(feature = "kat")]
    fn second_contact_gets_its_floor() -> R {
        big(|| {
            let (mut sc, guest, _first) = on_b("hub-r2-two", 331)?;
            // the first contact's overlaps end first, so the second scene's steps see only their own queues (as SE-84)
            sc.invitee.tick(ms(200_000));
            let mut sc2 = scene(party("hub-r2-two-h2", 335)?, &guest)?;
            core::mem::swap(&mut sc2.invitee, &mut sc.invitee);
            sc2.invitee.take_actions();
            step_invite(&mut sc2)?;
            step_accept(&mut sc2)?;
            step_handshake(&mut sc2)?;
            step_reply(&mut sc2)?;
            let second = sc2.contact;
            assert_eq!(
                sc2.invitee.core.index.get(&second.0).copied(),
                Some(1),
                "the second conversation"
            );
            sc2.invitee.take_actions();
            for (n, now) in [(17_u8, 50), (18, 60)] {
                send_route(&mut sc2, n, ms(now))?;
                sc2.invitee.pump()?;
            }
            let hub = &mut sc2.invitee;
            let old = hub.previous_sends.get(&second.0).copied().ok_or("17")?;
            let (u, f, b) = retiring_of(hub, old).ok_or("17 retires")?;
            assert_eq!(u, end_of(f, b, OVERLAP_MS.0), "the draw");
            hub.tick(hub.core.clock.mono_ms());
            assert_eq!(
                retiring_of(hub, old).map(|r| r.0),
                Some(floor_of(f, b, 80_000)),
                "Q264: the second contact's floor"
            );
            Ok(())
        })
    }

    /// SE-153 (Q266, Q267; B17c verification R2, hand mutant V26): a restart registers an end further ahead than
    /// `OLD_SEND_MS` — up to `MAX_SEND_OVERLAP_MS` — until exactly that end (rows of `sid` 22 and 23: `OLD_SEND_MS` + 1 ms
    /// and `MAX_SEND_OVERLAP_MS` ahead).
    #[test]
    #[cfg(feature = "kat")]
    fn restart_keeps_an_end_beyond_a_day() -> R {
        use crate::clock::Clock as _;
        use crate::sessions::actor::OverlapRoute;

        big(|| {
            let (sc, guest, contact) = on_b("hub-r2-far", 341)?;
            drop(sc);
            let now = guest.clock.unix_secs().saturating_mul(1_000);
            let far = [
                (22_u8, OLD_SEND_MS.saturating_add(1)),
                (23, MAX_SEND_OVERLAP_MS),
            ];
            let store = guest.profile.store();
            for (sid, ahead) in far {
                let row = OverlapRoute {
                    sid: [sid; 16],
                    seed: SecretBytes::from_slice(&[sid; 32])?,
                    period: Period::S20,
                    until_ms: now.saturating_add(ahead),
                    newest: 0,
                    unknown: false,
                }
                .row();
                store
                    .lock()
                    .map_err(|_| "lock")?
                    .txn(|tx| secmp_store::sessions::insert_pending_control(tx, contact.0, &row))?;
            }
            drop(store);
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 909)?;
            let added = add_sends(&mut again);
            let mono = again.core.clock.mono_ms();
            for (sid, ahead) in far {
                let q = queue_of(&added, sid).ok_or("registered")?;
                assert_eq!(
                    end_at(&again, q),
                    Some(mono.saturating_add(ahead)),
                    "{sid}: exactly its end"
                );
            }
            Ok(())
        })
    }
}
