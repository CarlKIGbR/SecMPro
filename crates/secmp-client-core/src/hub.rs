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

/// CAP (Q268, OPEN-M7-B-29 (1)): the most old send queues one contact holds in send overlap — switched in this process or
/// registered again at a restart. A `RouteUpdate` to a new physical queue that would make one more is not registered: the
/// contact keeps its queue (Q236 skip), nothing is drawn or sealed, only the current route is written back, nothing is
/// remembered; a later `RouteUpdate` (or the same one sent again) registers once one of its old queues has ended. A peer
/// that follows `docs/03` sends at most 4 within the longest overlap (Q269); 6 leaves a margin of 2. It bounds the
/// contact's send queues to 7 and its overlap rows to 6, so a hostile contact adds at most 7 to the n of every floor.
pub const MAX_SEND_OVERLAPS: usize = 6;

/// B17c (Q264): an old send queue in overlap. Its end is `max(drawn end, from + blur + min(FLOOR_CELLS · I, cap))`, I the
/// longest interval between two cells of the queue in the current mode with the send queues on its link now
/// ([`cell_interval_ms`]); the end only grows, and a longer one is used only after its row is durable (Q265).
struct Retiring {
    /// The queue.
    queue: QueueId,
    /// CAP (Q268): the contact it was switched away from; its old queues count toward [`MAX_SEND_OVERLAPS`].
    contact: i64,
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
    /// queue keeps holding (fail closed); and only a physical queue not registered already (spec §10.2, Q236), and at most
    /// [`MAX_SEND_OVERLAPS`] per contact, in `ord` order (Q270). The set of
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
            // CAP (Q270): no more than the cap again — a row beyond it (a replayed or an older store) is not registered: it
            // goes at the next preparation and a marker of its `sid` keeps holding (fail closed); the open never fails on it
            if self.overlaps_held(contact) >= MAX_SEND_OVERLAPS {
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
                contact: contact.0,
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
    /// which must not give that queue a second sender (spec §10.2, Q236); so is a route to a new queue while the contact
    /// holds [`MAX_SEND_OVERLAPS`] old send queues in overlap (Q268).
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
        // CAP (Q268): a switch would put one more old queue into overlap — at the cap the route is not registered, before
        // any registration, draw, seal or row write; the contact keeps its queue and the stored routes follow it (as Q236)
        if self.send_ids.contains_key(&contact.0)
            && self.overlaps_held(contact) >= MAX_SEND_OVERLAPS
        {
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
                contact: contact.0,
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

    /// CAP (Q268): how many old send queues `contact` holds in send overlap now.
    fn overlaps_held(&self, contact: ContactId) -> usize {
        self.retiring_sends
            .iter()
            .filter(|r| r.contact == contact.0)
            .count()
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
                contact: contact.0,
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

    /// CAP: the `RouteUpdate`s the receive commits of `contact` stored since the last pump, registered as the pump does
    /// but without its closing write of the current route (so the refusal's own write is what the store shows).
    #[cfg(feature = "kat")]
    fn register_taken(hub: &mut Hub<ManualClock, Fixed>, contact: ContactId) -> R {
        let at = *hub.core.index.get(&contact.0).ok_or("index")?;
        let routes = hub
            .core
            .convs
            .get_mut(at)
            .ok_or("conversation")?
            .persist_mut()
            .take_routes();
        for bytes in &routes {
            hub.register_route(contact, at, bytes)?;
        }
        Ok(())
    }

    /// CAP: `on_b`, then routes of `sid` 40, 41, … (80 s), one pump each, until the contact (the hub's only one) holds
    /// `held` old send queues in overlap; also the next `sid`.
    #[cfg(feature = "kat")]
    fn filled(
        label: &str,
        seed: u64,
        held: usize,
    ) -> Result<(Scene, Fixture, ContactId, u8), crate::testutil::E> {
        let (mut sc, guest, contact) = on_b(label, seed)?;
        let mut sid = 40_u8;
        for now in 40..60_u64 {
            if sc.invitee.retiring_sends.len() >= held {
                break;
            }
            send_route(&mut sc, sid, ms(now))?;
            sc.invitee.pump()?;
            assert_eq!(
                sids(&mut sc.invitee),
                [[sid; 16]],
                "{sid} registers below the cap"
            );
            sid = sid.checked_add(1).ok_or("sid")?;
        }
        assert_eq!(sc.invitee.retiring_sends.len(), held, "the setup");
        Ok((sc, guest, contact, sid))
    }

    /// The (queue, end) of every old send queue in overlap.
    #[cfg(feature = "kat")]
    fn ends_of(hub: &Hub<ManualClock, Fixed>) -> Vec<(QueueId, u64)> {
        hub.retiring_sends
            .iter()
            .map(|r| (r.queue, r.until))
            .collect()
    }

    /// SE-154 (Q268, Q270; OPEN-M7-B-29 (1)): at cap − 1 a route registers and the contact holds `MAX_SEND_OVERLAPS` old
    /// send queues; at the cap a route to a new queue — and the next one (cap + 1), and the first sent again — registers
    /// nothing: no action, the contact keeps its queue, every end, every overlap row and n stay, the stored route is the
    /// current one (written back by the refusal itself). The tick at the earliest end removes that queue and starts none;
    /// the refused route sent again then registers, as the next queue id.
    #[test]
    #[cfg(feature = "kat")]
    fn cap_refuses_a_route_at_the_cap() -> R {
        big(|| {
            let (mut sc, _guest, contact, sid) =
                filled("cap-at", 401, MAX_SEND_OVERLAPS.saturating_sub(1))?;
            send_route(&mut sc, sid, ms(60))?;
            sc.invitee.pump()?;
            assert_eq!(sids(&mut sc.invitee), [[sid; 16]], "cap − 1: registers");
            let hub = &mut sc.invitee;
            assert_eq!(hub.retiring_sends.len(), MAX_SEND_OVERLAPS, "at the cap");
            hub.tick(hub.core.clock.mono_ms());
            hub.take_actions();
            let current = hub.sends_of(contact).ok_or("sends")?;
            let ends = ends_of(hub);
            let rows = overlaps_of(hub, contact)?;
            let n = hub.send_targets.len();
            let last = hub.next_send;
            let (r1, r2) = (
                sid.checked_add(1).ok_or("sid")?,
                sid.checked_add(2).ok_or("sid")?,
            );
            for (refused, now) in [(r1, 61), (r2, 62), (r1, 63)] {
                send_route(&mut sc, refused, ms(now))?;
                let hub = &mut sc.invitee;
                register_taken(hub, contact)?;
                assert!(hub.take_actions().is_empty(), "{refused}: no action");
                assert_eq!(
                    hub.sends_of(contact),
                    Some(current),
                    "{refused}: the same queues"
                );
                assert_eq!(ends_of(hub), ends, "{refused}: every end stays");
                assert_eq!(overlaps_of(hub, contact)?, rows, "{refused}: the rows stay");
                assert_eq!(hub.send_targets.len(), n, "{refused}: n stays");
                assert_eq!(
                    stored_sid(hub, contact)?,
                    Some([sid; 16]),
                    "{refused}: the stored route is the current one"
                );
            }
            let hub = &mut sc.invitee;
            let (first, end) = ends.iter().copied().min_by_key(|e| e.1).ok_or("an end")?;
            hub.tick(end);
            let actions = hub.take_actions();
            assert_eq!(
                actions
                    .iter()
                    .filter(|a| matches!(a, Action::Remove { .. }))
                    .count(),
                1,
                "one queue ends"
            );
            assert!(
                actions
                    .iter()
                    .any(|a| matches!(a, Action::Remove { queue } if *queue == first)),
                "the earliest"
            );
            assert_eq!(added_send(&actions), None, "nothing starts at the end");
            send_route(&mut sc, r1, ms(64))?;
            sc.invitee.pump()?;
            assert_eq!(
                add_sends(&mut sc.invitee),
                vec![(
                    QueueId(SEND_BASE.saturating_add(last.saturating_add(1))),
                    [r1; 16]
                )],
                "sent again below the cap: registers as the next queue"
            );
            assert_eq!(sc.invitee.retiring_sends.len(), MAX_SEND_OVERLAPS);
            Ok(())
        })
    }

    /// SE-155 (Q268; criterion 6): the cap is per contact. A second contact (conversation 1) beside the first: the first
    /// registers `MAX_SEND_OVERLAPS` routes and is then refused; the second still registers, and the first stays refused.
    #[test]
    #[cfg(feature = "kat")]
    fn cap_is_per_contact() -> R {
        big(|| {
            let (mut sc, guest, first) = on_b("cap-two", 403)?;
            // the first contact's overlaps end, so the second scene's steps see only their own queues (as SE-152)
            sc.invitee.tick(ms(200_000));
            let mut sc2 = scene(party("cap-two-h2", 411)?, &guest)?;
            core::mem::swap(&mut sc2.invitee, &mut sc.invitee);
            sc2.invitee.take_actions();
            step_invite(&mut sc2)?;
            step_accept(&mut sc2)?;
            step_handshake(&mut sc2)?;
            step_reply(&mut sc2)?;
            let second = sc2.contact;
            let hub = &mut sc2.invitee;
            hub.take_actions();
            let at1 = *hub.core.index.get(&first.0).ok_or("first")?;
            let at2 = *hub.core.index.get(&second.0).ok_or("second")?;
            assert_eq!((at1, at2), (0, 1), "two conversations");
            let mut sid = 70_u8;
            for _ in 0..MAX_SEND_OVERLAPS {
                hub.register_route(first, at1, &route_body(sid, Period::S80)?)?;
                assert_eq!(sids(hub), [[sid; 16]], "first: {sid} below its cap");
                sid = sid.checked_add(1).ok_or("sid")?;
            }
            hub.register_route(first, at1, &route_body(sid, Period::S80)?)?;
            assert_eq!(sids(hub), Vec::<Id>::new(), "first: at its cap");
            let other = sid.checked_add(1).ok_or("sid")?;
            hub.register_route(second, at2, &route_body(other, Period::S80)?)?;
            assert_eq!(sids(hub), [[other; 16]], "second: registers");
            hub.register_route(first, at1, &route_body(sid, Period::S80)?)?;
            assert_eq!(sids(hub), Vec::<Id>::new(), "first: still at its cap");
            Ok(())
        })
    }

    /// The overlap row of `sid` (20 s) ending `ahead` ms after `now`, written into `contact`'s store as at a switch.
    #[cfg(feature = "kat")]
    fn put_overlap(guest: &Fixture, contact: ContactId, sid: u8, until: u64) -> R {
        let row = crate::sessions::actor::OverlapRoute {
            sid: [sid; 16],
            seed: SecretBytes::from_slice(&[sid; 32])?,
            period: Period::S20,
            until_ms: until,
            newest: 0,
            unknown: false,
        }
        .row();
        guest
            .profile
            .store()
            .lock()
            .map_err(|_| "lock")?
            .txn(|tx| secmp_store::sessions::insert_pending_control(tx, contact.0, &row))?;
        Ok(())
    }

    /// SE-156 (Q270; criterion 5, D-B85/D-B79 class): a store with more overlap rows than the cap (`on_b`'s and
    /// `MAX_SEND_OVERLAPS` more, every end ahead): the open succeeds, registers B and the first `MAX_SEND_OVERLAPS` rows in
    /// `ord` order, and the rows beyond the cap go at the first preparation.
    #[test]
    #[cfg(feature = "kat")]
    fn restart_registers_at_most_the_cap() -> R {
        use crate::clock::Clock as _;

        big(|| {
            let (sc, guest, contact) = on_b("cap-excess", 407)?;
            let before: Vec<Id> = overlaps_of(&sc.invitee, contact)?
                .iter()
                .map(|r| r.0)
                .collect();
            drop(sc);
            let now = guest.clock.unix_secs().saturating_mul(1_000);
            let mut rows = before.clone();
            for i in 0..u8::try_from(MAX_SEND_OVERLAPS).map_err(|_| "cap")? {
                let sid = 50_u8.saturating_add(i);
                put_overlap(
                    &guest,
                    contact,
                    sid,
                    now.saturating_add(10_000).saturating_add(u64::from(i)),
                )?;
                rows.push([sid; 16]);
            }
            assert!(rows.len() > MAX_SEND_OVERLAPS, "more rows than the cap");
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 911)?;
            let added: Vec<Id> = add_sends(&mut again).into_iter().map(|(_, s)| s).collect();
            let kept: Vec<Id> = rows.iter().copied().take(MAX_SEND_OVERLAPS).collect();
            let mut want = vec![[4; 16]];
            want.extend(kept.iter().copied());
            assert_eq!(added, want, "B and the first rows up to the cap");
            assert_eq!(again.retiring_sends.len(), MAX_SEND_OVERLAPS);
            let (_, b2) = again.sends_of(contact).ok_or("sends")?;
            on(&mut again, b2, ms(10), 1)?;
            assert_eq!(
                overlaps_of(&again, contact)?
                    .iter()
                    .map(|r| r.0)
                    .collect::<Vec<_>>(),
                kept,
                "the rows beyond the cap go"
            );
            Ok(())
        })
    }

    /// SE-157 (Q268, Q270): a contact at the cap restarts: its `MAX_SEND_OVERLAPS` old queues are registered again and
    /// count — a route to a new queue then registers nothing.
    #[test]
    #[cfg(feature = "kat")]
    fn restart_at_the_cap_refuses_a_new_route() -> R {
        big(|| {
            let (sc, guest, contact, sid) = filled("cap-restart", 409, MAX_SEND_OVERLAPS)?;
            drop(sc);
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 913)?;
            assert_eq!(
                add_sends(&mut again).len(),
                MAX_SEND_OVERLAPS.saturating_add(1)
            );
            assert_eq!(again.retiring_sends.len(), MAX_SEND_OVERLAPS, "all again");
            let at = *again.core.index.get(&contact.0).ok_or("index")?;
            again.register_route(contact, at, &route_body(sid, Period::S80)?)?;
            assert_eq!(
                sids(&mut again),
                Vec::<Id>::new(),
                "at the cap after the restart"
            );
            Ok(())
        })
    }

    /// SE-158 (Q268; criterion 2): the cap with a held `KeyChange` (`kc_on_b_then_c`: B's copy holds): the contact is
    /// filled to the cap, then a route is refused — the `KeyChange` is still live, its markers and the overlap rows are
    /// unchanged, no marker names the refused queue, and every end stays.
    #[test]
    #[cfg(feature = "kat")]
    fn cap_keeps_a_held_key_change() -> R {
        big(|| {
            let (mut sc, _guest, contact) = kc_on_b_then_c("cap-kc", 415)?;
            let hub = &mut sc.invitee;
            let at = *hub.core.index.get(&contact.0).ok_or("index")?;
            let mut sid = 80_u8;
            for _ in 0..MAX_SEND_OVERLAPS {
                if hub.retiring_sends.len() >= MAX_SEND_OVERLAPS {
                    break;
                }
                hub.register_route(contact, at, &route_body(sid, Period::S80)?)?;
                sid = sid.checked_add(1).ok_or("sid")?;
            }
            assert_eq!(hub.retiring_sends.len(), MAX_SEND_OVERLAPS, "at the cap");
            hub.take_actions();
            let tags = crate::sessions::tests::control_tags(&hub.profile_store(), contact.0)?;
            let ends = ends_of(hub);
            assert!(kc_live(hub, contact), "held before");
            hub.register_route(contact, at, &route_body(sid, Period::S80)?)?;
            assert!(hub.take_actions().is_empty(), "refused");
            assert!(kc_live(hub, contact), "still held");
            let after = crate::sessions::tests::control_tags(&hub.profile_store(), contact.0)?;
            assert_eq!(after, tags, "rows and markers unchanged");
            assert!(
                !after.1.contains(&[sid; 16]),
                "no marker names the refused queue"
            );
            assert_eq!(ends_of(hub), ends, "every end stays");
            Ok(())
        })
    }

    /// SE-159 (Q270; criterion 2, 5): rows beyond the cap at an open, among them B's — written after `MAX_SEND_OVERLAPS`
    /// other rows, its copy of the `KeyChange` not counted away: B is not registered again, its row goes and its marker
    /// stays, the `KeyChange` holds after the copy on C is counted (fail closed); the open itself succeeds.
    #[test]
    #[cfg(feature = "kat")]
    fn restart_beyond_the_cap_holds_the_key_change() -> R {
        use crate::clock::Clock as _;

        big(|| {
            let (mut sc, guest, contact) = on_b("cap-kc-excess", 417)?;
            let now = guest.clock.unix_secs().saturating_mul(1_000);
            for i in 0..u8::try_from(MAX_SEND_OVERLAPS).map_err(|_| "cap")? {
                put_overlap(
                    &guest,
                    contact,
                    60_u8.saturating_add(i),
                    now.saturating_add(7_200_000),
                )?;
            }
            // as `kc_on_b_then_c`: the `KeyChange` relayed on B, then the route C — B's row after the rows above
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
            let rows: Vec<Id> = overlaps_of(hub, contact)?.iter().map(|r| r.0).collect();
            assert_eq!(rows.last(), Some(&[4; 16]), "B's row is the last");
            assert!(rows.len() > MAX_SEND_OVERLAPS, "more rows than the cap");
            drop(sc);
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 919)?;
            let added = add_sends(&mut again);
            assert_eq!(queue_of(&added, 4), None, "Q270: B is beyond the cap");
            assert_eq!(again.retiring_sends.len(), MAX_SEND_OVERLAPS, "the cap");
            let c2 = queue_of(&added, 7).ok_or("C")?;
            for i in 0..4_u64 {
                on(
                    &mut again,
                    c2,
                    ms(200_u64.saturating_add(i)),
                    300_u64.saturating_add(i),
                )?;
            }
            for i in 0..3_u64 {
                on(
                    &mut again,
                    c2,
                    ms(210_u64.saturating_add(i)),
                    600_u64.saturating_add(i),
                )?;
            }
            assert!(kc_live(&again, contact), "B's copy holds");
            assert!(
                !overlaps_of(&again, contact)?.iter().any(|r| r.0 == [4; 16]),
                "B's row goes"
            );
            assert!(
                crate::sessions::tests::control_tags(&again.profile_store(), contact.0)?
                    .1
                    .contains(&[4; 16]),
                "B's marker stays"
            );
            Ok(())
        })
    }

    /// SE-160 (Q268): a contact without a send queue (no current registration) is not capped — its first route adds no
    /// old queue, so it registers even while `MAX_SEND_OVERLAPS` old queues of the contact are in overlap.
    #[test]
    #[cfg(feature = "kat")]
    fn first_route_is_not_capped() -> R {
        big(|| {
            let (mut sc, _guest, contact, sid) = filled("cap-first", 421, MAX_SEND_OVERLAPS)?;
            let hub = &mut sc.invitee;
            let at = *hub.core.index.get(&contact.0).ok_or("index")?;
            hub.send_ids.remove(&contact.0);
            hub.send_routes.remove(&contact.0);
            hub.register_route(contact, at, &route_body(sid, Period::S80)?)?;
            assert_eq!(sids(hub), [[sid; 16]], "the first route registers");
            assert_eq!(
                hub.retiring_sends.len(),
                MAX_SEND_OVERLAPS,
                "no old queue added"
            );
            Ok(())
        })
    }

    /// SE-161 (Q268, Q271; criteria 4, 6): thirty routes to new queues, one every 30 minutes with a tick, at two timing
    /// seeds (the draws decide when an old queue ends): a route registers exactly when the contact holds fewer than
    /// `MAX_SEND_OVERLAPS` old queues — both refusals and registrations after a refusal occur; the contact never holds more, its send queues (n on the link, one contact) never
    /// exceed `MAX_SEND_OVERLAPS + 1`; a tick beyond the longest overlap leaves the current queue alone.
    #[test]
    #[cfg(feature = "kat")]
    fn cap_bounds_the_send_queues_at_any_draw() -> R {
        big(|| {
            for (label, seed) in [("cap-n-a", 5_u64), ("cap-n-b", 0x5eed_c0de_0bad_f00d)] {
                let (mut sc, _guest, contact) = on_b(label, 423)?;
                let hub = &mut sc.invitee;
                hub.seed_timing_kat(seed);
                let at = *hub.core.index.get(&contact.0).ok_or("index")?;
                let mut refused = 0_usize;
                let mut late = 0_usize;
                for i in 0..30_u8 {
                    let held = hub.retiring_sends.len();
                    hub.register_route(
                        contact,
                        at,
                        &route_body(100_u8.saturating_add(i), Period::S80)?,
                    )?;
                    let added = sids(hub).len();
                    assert_eq!(
                        added,
                        usize::from(held < MAX_SEND_OVERLAPS),
                        "{label} {i}: held {held}"
                    );
                    if added == 0 {
                        refused = refused.saturating_add(1);
                    } else if refused > 0 {
                        late = late.saturating_add(1);
                    }
                    assert!(
                        hub.retiring_sends.len() <= MAX_SEND_OVERLAPS,
                        "{label} {i}: the cap"
                    );
                    assert!(
                        hub.send_targets.len() <= MAX_SEND_OVERLAPS.saturating_add(1),
                        "{label} {i}: n"
                    );
                    hub.core.clock.advance_ms(1_800_000);
                    hub.tick(hub.core.clock.mono_ms());
                }
                assert!(
                    refused > 0 && late > 0,
                    "{label}: refused {refused}, registered after a refusal {late}"
                );
                hub.core.clock.advance_ms(MAX_SEND_OVERLAP_MS);
                hub.tick(hub.core.clock.mono_ms());
                assert!(
                    hub.retiring_sends.is_empty(),
                    "{label}: every overlap ended"
                );
                assert_eq!(hub.send_targets.len(), 1, "{label}: the current queue");
            }
            Ok(())
        })
    }

    /// SE-162 (Q268; criterion 1): a refused route draws nothing — after it, the next switch draws what it would have
    /// drawn without it (the cap comes before the draw; one timing seed for both runs).
    #[test]
    #[cfg(feature = "kat")]
    fn refused_route_draws_nothing() -> R {
        big(|| {
            let mut blurs = Vec::new();
            for (label, refuse) in [("cap-draw-a", false), ("cap-draw-b", true)] {
                let (mut sc, _guest, contact) = on_b(label, 425)?;
                let hub = &mut sc.invitee;
                hub.seed_timing_kat(77);
                let at = *hub.core.index.get(&contact.0).ok_or("index")?;
                let mut sid = 110_u8;
                for _ in 0..MAX_SEND_OVERLAPS {
                    if hub.retiring_sends.len() >= MAX_SEND_OVERLAPS {
                        break;
                    }
                    hub.register_route(contact, at, &route_body(sid, Period::S80)?)?;
                    sid = sid.checked_add(1).ok_or("sid")?;
                }
                assert_eq!(
                    hub.retiring_sends.len(),
                    MAX_SEND_OVERLAPS,
                    "{label}: at the cap"
                );
                if refuse {
                    hub.register_route(contact, at, &route_body(140, Period::S80)?)?;
                }
                let end = ends_of(hub).iter().map(|e| e.1).min().ok_or("an end")?;
                hub.tick(end.saturating_add(FLOOR_TERM_CAP_MS));
                hub.take_actions();
                let (_, current) = hub.sends_of(contact).ok_or("sends")?;
                hub.register_route(contact, at, &route_body(141, Period::S80)?)?;
                assert_eq!(sids(hub), [[141; 16]], "{label}: registers");
                blurs.push(retiring_of(hub, current).map(|r| r.2).ok_or("blur")?);
            }
            assert_eq!(blurs.first(), blurs.get(1), "the same draw");
            Ok(())
        })
    }

    /// SE-163 (Q269): the cap leaves a margin of 2 over the rotations the specification asks of a peer within the longest
    /// overlap: the invitation queue's retirement (`docs/03` §6.6 step 4, §10.6 (5)) or the 30-day rotation (`docs/02`
    /// §4.3) — 30 days apart, so at most one of them — and a rotation to a larger period (§10.2) at most `|PERIODS| − 1`
    /// times.
    #[test]
    fn cap_leaves_a_margin_over_the_spec() {
        use super::{MAX_SEND_OVERLAPS, Period};

        let honest = Period::ALL.len();
        assert_eq!(honest, 4, "1 + (|PERIODS| − 1)");
        assert_eq!(MAX_SEND_OVERLAPS, honest.saturating_add(2));
    }

    /// SE-164 (Q268, Q242, D-B107; verifier R1): the cap reached inside one pump — of two new routes the first registers
    /// and the second meets the cap, and the store ends on the first (the queue sent to); a refused route and then a
    /// stale one (B, in overlap: the Q236 skip) in one pump register nothing and keep the store; a crash after the
    /// receive commit of a refused route (no pump): the restart registers that stored route as the current queue and the
    /// six old queues again — the queue sent to before has no row and is not registered, the send queues stay seven.
    #[test]
    #[cfg(feature = "kat")]
    fn cap_inside_one_pump_and_a_crash_after_a_refusal() -> R {
        big(|| {
            let (mut sc, guest, contact, sid) =
                filled("cap-v1", 431, MAX_SEND_OVERLAPS.saturating_sub(1))?;
            let r1 = sid;
            let r2 = r1.checked_add(1).ok_or("sid")?;
            let r3 = r2.checked_add(1).ok_or("sid")?;
            let r4 = r3.checked_add(1).ok_or("sid")?;
            send_route(&mut sc, r1, ms(60))?;
            send_route(&mut sc, r2, ms(61))?;
            sc.invitee.pump()?;
            assert_eq!(
                sids(&mut sc.invitee),
                [[r1; 16]],
                "the first registers, the second meets the cap"
            );
            assert_eq!(
                sc.invitee.retiring_sends.len(),
                MAX_SEND_OVERLAPS,
                "at the cap"
            );
            assert_eq!(
                stored_sid(&sc.invitee, contact)?,
                Some([r1; 16]),
                "Q242: the store ends on the queue sent to"
            );
            let n = sc.invitee.send_targets.len();
            assert_eq!(n, MAX_SEND_OVERLAPS.saturating_add(1), "seven send queues");
            send_route(&mut sc, r3, ms(62))?;
            send_route(&mut sc, 4, ms(63))?;
            sc.invitee.pump()?;
            assert_eq!(
                sids(&mut sc.invitee),
                Vec::<Id>::new(),
                "refused, then skipped"
            );
            assert_eq!(sc.invitee.retiring_sends.len(), MAX_SEND_OVERLAPS);
            assert_eq!(sc.invitee.send_targets.len(), n, "n stays");
            assert_eq!(
                stored_sid(&sc.invitee, contact)?,
                Some([r1; 16]),
                "the store stays"
            );
            send_route(&mut sc, r4, ms(64))?;
            assert_eq!(
                stored_sid(&sc.invitee, contact)?,
                Some([r4; 16]),
                "the receive commit stored the route the cap will refuse"
            );
            drop(sc);
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 931)?;
            let added = sids(&mut again);
            assert_eq!(
                added.first(),
                Some(&[r4; 16]),
                "D-B107: the stored route is current"
            );
            assert!(
                !added.contains(&[r1; 16]),
                "the queue sent to before has no row"
            );
            assert_eq!(
                added.len(),
                MAX_SEND_OVERLAPS.saturating_add(1),
                "seven again"
            );
            assert_eq!(again.retiring_sends.len(), MAX_SEND_OVERLAPS);
            Ok(())
        })
    }

    /// SE-165 (Q268; verifier R1): at the cap the relay's `ERR_NOQUEUE` for the current queue and for an old one starts
    /// and ends nothing and frees no slot (a lost old queue counts until its end); a route to a new queue stays refused
    /// 1 ms before the earliest end and at that end before the tick drops it (the queue still carries cells); the tick at
    /// that end removes exactly that queue, the route then registers, and the next one is refused again.
    #[test]
    #[cfg(feature = "kat")]
    fn cap_holds_through_queue_loss_until_an_end() -> R {
        big(|| {
            let (mut sc, _guest, contact, sid) = filled("cap-v2", 433, MAX_SEND_OVERLAPS)?;
            let hub = &mut sc.invitee;
            let at = *hub.core.index.get(&contact.0).ok_or("index")?;
            hub.tick(hub.core.clock.mono_ms());
            hub.take_actions();
            let (old, current) = hub.sends_of(contact).ok_or("sends")?;
            hub.queue_lost(current);
            hub.queue_lost(old);
            assert!(
                hub.take_actions().is_empty(),
                "a loss starts and ends nothing"
            );
            assert_eq!(
                hub.retiring_sends.len(),
                MAX_SEND_OVERLAPS,
                "a lost queue counts"
            );
            hub.register_route(contact, at, &route_body(sid, Period::S80)?)?;
            assert_eq!(sids(hub), Vec::<Id>::new(), "refused after the loss");
            let (first, end) = ends_of(hub)
                .into_iter()
                .min_by_key(|e| e.1)
                .ok_or("an end")?;
            hub.tick(end.saturating_sub(1));
            assert!(hub.take_actions().is_empty(), "1 ms before: nothing ends");
            hub.register_route(contact, at, &route_body(sid, Period::S80)?)?;
            assert_eq!(sids(hub), Vec::<Id>::new(), "1 ms before: still refused");
            let late = end.saturating_sub(hub.core.clock.mono_ms());
            hub.core.clock.advance_ms(late);
            hub.register_route(contact, at, &route_body(sid, Period::S80)?)?;
            assert_eq!(
                sids(hub),
                Vec::<Id>::new(),
                "past its end but not dropped yet: still counted"
            );
            hub.tick(end);
            let actions = hub.take_actions();
            assert_eq!(
                actions
                    .iter()
                    .filter(|a| matches!(a, Action::Remove { .. }))
                    .count(),
                1,
                "one queue ends"
            );
            assert!(
                actions
                    .iter()
                    .any(|a| matches!(a, Action::Remove { queue } if *queue == first)),
                "the earliest"
            );
            hub.register_route(contact, at, &route_body(sid, Period::S80)?)?;
            assert_eq!(sids(hub), [[sid; 16]], "a slot is free: registers");
            assert_eq!(hub.retiring_sends.len(), MAX_SEND_OVERLAPS);
            let next = sid.checked_add(1).ok_or("sid")?;
            hub.register_route(contact, at, &route_body(next, Period::S80)?)?;
            assert_eq!(sids(hub), Vec::<Id>::new(), "at the cap again");
            Ok(())
        })
    }

    /// SE-171 (Q270, Q265; verifier R1): at a restart a row whose end passed takes no slot and two rows of one `sid` (a
    /// lengthened end and the row it replaces) take one: the old queues registered are the first `MAX_SEND_OVERLAPS`
    /// distinct `sid`s with an end ahead, in `ord` order; the next distinct one is beyond the cap and spends no queue id.
    #[test]
    #[cfg(feature = "kat")]
    fn restart_counts_each_sid_once_toward_the_cap() -> R {
        use crate::clock::Clock as _;

        big(|| {
            let (sc, guest, contact) = on_b("cap-v3", 435)?;
            let mut distinct: Vec<Id> = Vec::new();
            for (s, ..) in overlaps_of(&sc.invitee, contact)? {
                if !distinct.contains(&s) {
                    distinct.push(s);
                }
            }
            drop(sc);
            let now = guest.clock.unix_secs().saturating_mul(1_000);
            put_overlap(&guest, contact, 59, now.saturating_sub(1_000))?;
            put_overlap(&guest, contact, 50, now.saturating_add(10_000))?;
            put_overlap(&guest, contact, 50, now.saturating_add(20_000))?;
            distinct.push([50; 16]);
            let mut sid = 51_u8;
            while distinct.len() <= MAX_SEND_OVERLAPS {
                put_overlap(&guest, contact, sid, now.saturating_add(30_000))?;
                distinct.push([sid; 16]);
                sid = sid.checked_add(1).ok_or("sid")?;
            }
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 935)?;
            let mut want = vec![[4; 16]];
            want.extend(distinct.iter().copied().take(MAX_SEND_OVERLAPS));
            assert_eq!(
                sids(&mut again),
                want,
                "B and the first distinct sids up to the cap"
            );
            assert_eq!(again.retiring_sends.len(), MAX_SEND_OVERLAPS);
            assert_eq!(
                usize::try_from(again.next_send).map_err(|_| "id")?,
                want.len(),
                "a row beyond the cap spends no queue id"
            );
            Ok(())
        })
    }

    /// SE-172 (Q268, Q270; criterion 6; verifier R1): two contacts, each counted alone, live and across a restart. The
    /// first holds `MAX_SEND_OVERLAPS − 1` old queues, the second switches once: the first's next route still registers
    /// (the other contact's old queue is not counted) and the one after it is refused. A restart registers every old
    /// queue of both contacts again (the cap is per contact at the open too); the second then registers exactly up to its
    /// own cap and the first is refused; the first without a current queue is not capped while the second has one.
    #[test]
    #[cfg(feature = "kat")]
    fn cap_counts_each_contact_alone_across_a_restart() -> R {
        big(|| {
            let (mut sc, guest, first) = on_b("cap-v4", 437)?;
            sc.invitee.tick(ms(200_000));
            let mut sc2 = scene(party("cap-v4-h2", 441)?, &guest)?;
            core::mem::swap(&mut sc2.invitee, &mut sc.invitee);
            sc2.invitee.take_actions();
            step_invite(&mut sc2)?;
            step_accept(&mut sc2)?;
            step_handshake(&mut sc2)?;
            step_reply(&mut sc2)?;
            let second = sc2.contact;
            let hub = &mut sc2.invitee;
            hub.take_actions();
            let at1 = *hub.core.index.get(&first.0).ok_or("first")?;
            let at2 = *hub.core.index.get(&second.0).ok_or("second")?;
            let base = hub.retiring_sends.len();
            let mut sid = 150_u8;
            for _ in 1..MAX_SEND_OVERLAPS {
                hub.register_route(first, at1, &route_body(sid, Period::S80)?)?;
                assert_eq!(sids(hub), [[sid; 16]], "first: {sid} below its cap");
                sid = sid.checked_add(1).ok_or("sid")?;
            }
            hub.register_route(second, at2, &route_body(sid, Period::S80)?)?;
            assert_eq!(sids(hub), [[sid; 16]], "second: switches");
            let theirs = base.saturating_add(1);
            assert!(
                theirs < MAX_SEND_OVERLAPS,
                "the setup: the second below its cap"
            );
            sid = sid.checked_add(1).ok_or("sid")?;
            hub.register_route(first, at1, &route_body(sid, Period::S80)?)?;
            assert_eq!(
                sids(hub),
                [[sid; 16]],
                "first: the second's old queue not counted"
            );
            sid = sid.checked_add(1).ok_or("sid")?;
            hub.register_route(first, at1, &route_body(sid, Period::S80)?)?;
            assert_eq!(sids(hub), Vec::<Id>::new(), "first: at its cap");
            // the pump's closing write (the routes above were registered without a pump)
            hub.store_current_route(second)?;
            drop(sc2);
            drop(sc);
            let guest = guest.reopen()?;
            let mut again = hub_over(&guest, "guest", 937)?;
            again.take_actions();
            assert_eq!(
                again.retiring_sends.len(),
                MAX_SEND_OVERLAPS.saturating_add(theirs),
                "every old queue of both contacts again"
            );
            let at1 = *again.core.index.get(&first.0).ok_or("first")?;
            let at2 = *again.core.index.get(&second.0).ok_or("second")?;
            let mut more = 0_usize;
            for _ in 0..MAX_SEND_OVERLAPS {
                sid = sid.checked_add(1).ok_or("sid")?;
                again.register_route(second, at2, &route_body(sid, Period::S80)?)?;
                if sids(&mut again).is_empty() {
                    break;
                }
                more = more.saturating_add(1);
            }
            assert_eq!(
                more,
                MAX_SEND_OVERLAPS.saturating_sub(theirs),
                "second: up to its own cap after the restart"
            );
            sid = sid.checked_add(1).ok_or("sid")?;
            again.register_route(first, at1, &route_body(sid, Period::S80)?)?;
            assert_eq!(
                sids(&mut again),
                Vec::<Id>::new(),
                "first: at its cap after the restart"
            );
            again.send_ids.remove(&first.0);
            again.send_routes.remove(&first.0);
            again.register_route(first, at1, &route_body(sid, Period::S80)?)?;
            assert_eq!(
                sids(&mut again),
                [[sid; 16]],
                "first: no current queue, not capped beside the second"
            );
            Ok(())
        })
    }

    /// SE-173 (Q268, Q248; ADR-060 (2); verifier R2): a refused route touches no `KeyChange` marker — after a refusal at
    /// the cap the contact's `KeyChange` relayed on the queue it is sent to writes its marker for that queue's `sid`, not
    /// for the refused route's, and the refused `sid` appears in no marker or overlap row.
    #[test]
    #[cfg(feature = "kat")]
    fn refused_route_leaves_the_marker_on_the_sent_queue() -> R {
        big(|| {
            let (mut sc, _guest, contact, sid) = filled("cap-v5", 443, MAX_SEND_OVERLAPS)?;
            let hub = &mut sc.invitee;
            let at = *hub.core.index.get(&contact.0).ok_or("index")?;
            let current = *hub.send_ids.get(&contact.0).ok_or("current")?;
            let sent_to = sid.checked_sub(1).ok_or("sid")?;
            hub.take_actions();
            hub.register_route(contact, at, &route_body(sid, Period::S80)?)?;
            assert!(hub.take_actions().is_empty(), "refused at the cap");
            assert!(matches!(
                hub.core_mut().handle(Request::RotateIdentity)?,
                Response::IdentityRotated(_)
            ));
            for i in 0..4_u64 {
                on(
                    hub,
                    current,
                    ms(70_u64.saturating_add(i)),
                    i.saturating_add(1),
                )?;
            }
            let (_, markers) =
                crate::sessions::tests::control_tags(&hub.profile_store(), contact.0)?;
            assert!(
                markers.contains(&[sent_to; 16]),
                "the marker names the queue sent to"
            );
            assert!(
                !markers.contains(&[sid; 16]),
                "no marker names the refused queue"
            );
            assert!(
                !overlaps_of(hub, contact)?.iter().any(|r| r.0 == [sid; 16]),
                "no overlap row names the refused queue"
            );
            Ok(())
        })
    }

    /// SE-174 (Q268, Q271; verifier R2): the cap bounds send queues only — at the cap our own rotation of the contact's
    /// receive queue (`Request::Rotate`) still registers its new receive queue, and the cap is unchanged.
    #[test]
    #[cfg(feature = "kat")]
    fn cap_leaves_our_own_rotation_alone() -> R {
        big(|| {
            let (mut sc, _guest, contact, _) = filled("cap-v6", 445, MAX_SEND_OVERLAPS)?;
            let hub = &mut sc.invitee;
            hub.take_actions();
            assert!(matches!(
                hub.core_mut()
                    .handle(Request::Rotate { contact, relay: 1 })?,
                Response::Rotated(true)
            ));
            hub.pump()?;
            let added = hub
                .take_actions()
                .iter()
                .filter(|a| matches!(a, Action::AddRecv { .. }))
                .count();
            assert_eq!(added, 1, "the new receive queue registers at the cap");
            assert_eq!(hub.retiring_sends.len(), MAX_SEND_OVERLAPS, "the cap stays");
            Ok(())
        })
    }

    /// SE-175 (Q268; verifier R3): a refused route leaves the queue sent to as it was — a message relayed there is not
    /// sent again, its `T_RS` and its period stay those of that queue, though the refused route names another period.
    #[test]
    #[cfg(feature = "kat")]
    fn refused_route_leaves_the_current_queue_as_it_was() -> R {
        big(|| {
            let (mut sc, _guest, contact, sid) = filled("cap-v7", 447, MAX_SEND_OVERLAPS)?;
            let hub = &mut sc.invitee;
            let at = *hub.core.index.get(&contact.0).ok_or("index")?;
            let current = *hub.send_ids.get(&contact.0).ok_or("current")?;
            let Response::Sent(id) = hub.core_mut().handle(Request::Send {
                contact,
                kind: 1,
                payload: secmp_crypto::Zeroizing::new(b"held".to_vec()),
                expire_after: 0,
            })?
            else {
                return Err("sent".into());
            };
            let state = |hub: &Hub<ManualClock, Fixed>| {
                hub.core.convs.get(at).and_then(|c| c.outbox().state(&id))
            };
            for i in 0..8_u64 {
                if matches!(state(hub), Some(MsgState::Relayed(_))) {
                    break;
                }
                on(
                    hub,
                    current,
                    ms(70_u64.saturating_add(i)),
                    i.saturating_add(1),
                )?;
            }
            let relayed = state(hub);
            assert!(
                matches!(relayed, Some(MsgState::Relayed(_))),
                "the setup: relayed on the queue sent to"
            );
            let t_rs = |hub: &Hub<ManualClock, Fixed>| {
                hub.core
                    .convs
                    .get(at)
                    .map(crate::sessions::actor::Conversation::receipt_timeout_ms_kat)
            };
            assert_eq!(
                t_rs(hub),
                Some(crate::sessions::actor::receipt_timeout_ms(80_000)),
                "the setup"
            );
            hub.take_actions();
            hub.register_route(contact, at, &route_body(sid, Period::S10)?)?;
            assert!(hub.take_actions().is_empty(), "refused at the cap");
            assert_eq!(state(hub), relayed, "the relayed message is not sent again");
            assert_eq!(
                t_rs(hub),
                Some(crate::sessions::actor::receipt_timeout_ms(80_000)),
                "T_RS of the queue sent to"
            );
            assert_eq!(
                hub.send_periods.get(&current).copied(),
                Some(80_000),
                "the period of the queue sent to"
            );
            Ok(())
        })
    }

    /// SE-176 (Q268; verifier R3): the cap counts the contact's old send queues only — however many receive queues the hub
    /// holds (here more than the cap), a route below the cap registers.
    #[test]
    #[cfg(feature = "kat")]
    fn cap_counts_no_receive_queue() -> R {
        big(|| {
            let (mut sc, _guest, _, sid) = filled("cap-v8", 449, 2)?;
            let seed = SecretBytes::from_slice(&[7; 32])?;
            for q in 0..=MAX_SEND_OVERLAPS {
                let q = u32::try_from(q).map_err(|_| "q")?;
                sc.invitee.register_recv(
                    RelayId(1),
                    QueueId(70_000_u32.saturating_add(q)),
                    &seed,
                    80_000,
                );
            }
            assert!(
                sc.invitee.recv_periods.len() > MAX_SEND_OVERLAPS,
                "the setup: more receive queues than the cap"
            );
            sc.invitee.take_actions();
            send_route(&mut sc, sid, ms(70))?;
            sc.invitee.pump()?;
            assert_eq!(
                sids(&mut sc.invitee),
                [[sid; 16]],
                "below the cap: registers"
            );
            Ok(())
        })
    }

    /// SE-177 (Q268, Q271; verifier R3): at the cap our own rotation also retires the receive queue it replaces (its
    /// `QUEUE_DEL` reaches the scheduler), and a peer's route to a new queue after it is still refused.
    #[test]
    #[cfg(feature = "kat")]
    fn our_rotation_at_the_cap_retires_the_old_receive_queue() -> R {
        big(|| {
            let (mut sc, _guest, contact, sid) = filled("cap-v9", 451, MAX_SEND_OVERLAPS)?;
            let at = *sc.invitee.core.index.get(&contact.0).ok_or("index")?;
            let old = sc
                .invitee
                .core
                .convs
                .get(at)
                .and_then(|c| c.recv_queues_kat().0)
                .ok_or("receive queue")?;
            sc.invitee.take_actions();
            assert!(matches!(
                sc.invitee
                    .core_mut()
                    .handle(Request::Rotate { contact, relay: 1 })?,
                Response::Rotated(true)
            ));
            sc.invitee.pump()?;
            let actions = sc.invitee.take_actions();
            assert_eq!(
                queue_dels(&actions, old).len(),
                1,
                "the replaced receive queue is retired at the cap"
            );
            send_route(&mut sc, sid, ms(70))?;
            sc.invitee.pump()?;
            assert_eq!(
                sids(&mut sc.invitee),
                Vec::<Id>::new(),
                "a route after the rotation: still refused"
            );
            Ok(())
        })
    }

    /// SE-178: what `look` compares, one labelled part per line.
    #[cfg(feature = "kat")]
    type Parts = Vec<(String, String)>;

    /// SE-178: the actions `actions` hold, written out (every field, seeds included).
    #[cfg(feature = "kat")]
    fn spelled(actions: &[Action]) -> Vec<String> {
        actions
            .iter()
            .map(|a| match a {
                Action::AddRecv {
                    queue,
                    relay,
                    seed,
                    period_ms,
                } => format!(
                    "AddRecv {queue:?} {relay:?} {:?} {period_ms}",
                    seed.expose_secret()
                ),
                Action::AddSend {
                    queue,
                    relay,
                    sid,
                    seed,
                    period_ms,
                } => format!(
                    "AddSend {queue:?} {relay:?} {sid:?} {:?} {period_ms}",
                    seed.expose_secret()
                ),
                Action::Remove { queue } => format!("Remove {queue:?}"),
                Action::Control(op) => format!("Control {op:?}"),
            })
            .collect()
    }

    /// SE-178: every row of every table of `hub`'s store as the store holds it (integers and text as they are, a blob — sealed
    /// under a fresh nonce at every write — by its length), each table's rows sorted.
    #[cfg(feature = "kat")]
    fn raw_rows(hub: &Hub<ManualClock, Fixed>, out: &mut Parts) -> R {
        let store = hub.profile_store();
        let s = store.lock().map_err(|_| "lock")?;
        let conn = s.connection_kat();
        let mut names = Vec::new();
        {
            let mut stmt =
                conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")?;
            let mut rows = stmt.query(())?;
            while let Some(row) = rows.next()? {
                names.push(row.get::<usize, String>(0)?);
            }
        }
        for name in names {
            let mut stmt = conn.prepare(&format!("SELECT * FROM \"{name}\""))?;
            let columns = stmt.column_count();
            let mut lines = Vec::new();
            let mut rows = stmt.query(())?;
            while let Some(row) = rows.next()? {
                let mut line = Vec::new();
                for i in 0..columns {
                    let cell = if let Ok(v) = row.get::<usize, Option<i64>>(i) {
                        format!("{v:?}")
                    } else if let Ok(v) = row.get::<usize, Option<String>>(i) {
                        format!("{v:?}")
                    } else {
                        let v = row.get::<usize, Option<Vec<u8>>>(i)?;
                        format!("blob {:?}", v.map(|b| b.len()))
                    };
                    line.push(cell);
                }
                lines.push(line.join(" "));
            }
            lines.sort();
            out.push((format!("store raw {name}"), format!("{lines:?}")));
        }
        Ok(())
    }

    /// SE-178: the hub's and the core's fields, labelled; also the next draw of both timing streams (the same draw is then
    /// taken in both worlds).
    #[cfg(feature = "kat")]
    fn look_hub(hub: &mut Hub<ManualClock, Fixed>, out: &mut Parts) {
        let mut put = |label: &str, value: String| out.push((label.to_string(), value));
        put("hub.registered", format!("{:?}", hub.registered));
        put("hub.send_ids", format!("{:?}", hub.send_ids));
        let routes: Vec<_> = hub
            .send_routes
            .iter()
            .map(|(c, r)| (*c, r.to_vec()))
            .collect();
        put("hub.send_routes", format!("{routes:?}"));
        let retiring: Vec<_> = hub
            .retiring_sends
            .iter()
            .map(|r| {
                let floor = r.floor.map(|a| (a.from, a.blur));
                (r.queue, r.contact, r.until, floor)
            })
            .collect();
        put("hub.retiring_sends", format!("{retiring:?}"));
        put("hub.send_periods", format!("{:?}", hub.send_periods));
        put("hub.send_targets", format!("{:?}", hub.send_targets));
        put("hub.previous_sends", format!("{:?}", hub.previous_sends));
        put("hub.next_send", format!("{}", hub.next_send));
        put("hub.recv_periods", format!("{:?}", hub.recv_periods));
        put("hub.inv_queues", format!("{:?}", hub.inv_queues));
        put("hub.waiting", format!("{:?}", hub.waiting));
        put("hub.next_expiry", format!("{:?}", hub.next_expiry));
        put("hub.actions", format!("{:?}", spelled(&hub.actions)));
        let (draws, next) = (hub.rng.draws(), hub.rng.uniform(0, u64::MAX - 1).ok());
        put("hub.rng", format!("{draws} {next:?}"));
        let core = &mut hub.core;
        let (draws, next) = (core.rng.draws(), core.rng.uniform(0, u64::MAX - 1).ok());
        put("core.rng", format!("{draws} {next:?}"));
        put("core.index", format!("{:?}", core.index));
        put("core.events", format!("{:?}", core.events));
        put("core.settings", format!("{:?}", core.settings));
        put("core.view", format!("{:?}", core.view));
        put("core.ops", format!("{:?}", core.ops));
        put("core.routes_changed", format!("{:?}", core.routes_changed));
        put("core.rotated", format!("{}", core.rotated.len()));
        put(
            "core.rotation_period",
            format!("{:?}", core.rotation_period),
        );
        put(
            "core.clock",
            format!("{} {}", core.clock.mono_ms(), core.clock.unix_secs()),
        );
    }

    /// SE-178: what each conversation shows (every accessor the test module has), labelled by its contact.
    #[cfg(feature = "kat")]
    fn look_conversations(hub: &Hub<ManualClock, Fixed>, out: &mut Parts) -> R {
        for (contact, at) in &hub.core.index {
            let c = hub.core.convs.get(*at).ok_or("conversation")?;
            let overlaps: Vec<_> = c
                .overlaps_read()
                .map_err(|_| "overlaps")?
                .iter()
                .map(|o| {
                    let seed = o.seed.expose_secret().to_vec();
                    (o.sid, seed, o.period, o.until_ms, o.newest, o.unknown)
                })
                .collect();
            let received: Vec<_> = c
                .received()
                .iter()
                .map(|r| format!("{:?} {:?}", r.msg_id, r.payload.to_vec()))
                .collect();
            out.push((
                format!("conversation {contact}"),
                format!(
                    "send {:?} recv {:?} t_rs {} receipts {} kc {} successions {} overlaps {overlaps:?} durable {:?} \
                     received {received:?} partials {} discarded {} receipts_due {} pending_real {} mapped {} digests {:?} \
                     controls {} trust {:?} awaiting {} may_send {:?}",
                    c.send_queues_kat(),
                    c.recv_queues_kat(),
                    c.receipt_timeout_ms_kat(),
                    c.send_receipts_kat(),
                    c.key_change_in_flight(),
                    c.successions_pending(),
                    c.durable(),
                    c.partials(),
                    c.discarded(),
                    c.receipts_due(),
                    c.has_pending_real(),
                    c.mapped_cells(),
                    c.message_key_digests_kat(),
                    c.live_controls_test(),
                    c.trust(),
                    c.awaiting_first_reply(),
                    c.may_send_real(),
                ),
            ));
        }
        Ok(())
    }

    /// SE-178: the store opened — every contact row, and per contact its routes and queues, its session rows, its pending
    /// controls (overlap rows and markers among them), its handshake and previous identity, its outbox, its history ids.
    #[cfg(feature = "kat")]
    fn look_store(hub: &Hub<ManualClock, Fixed>, out: &mut Parts) -> R {
        let store = hub.profile_store();
        let s = store.lock().map_err(|_| "lock")?;
        let mut put = |label: String, value: String| out.push((label, value));
        for c in s.contacts()? {
            put(
                format!("store contact {}", c.id),
                format!(
                    "{:?} {:?} {} {:?} {} {:?}",
                    c.iks, c.fingerprint, c.verified, c.display_name, c.state, c.profile
                ),
            );
        }
        for contact in hub.core.index.keys() {
            let routes = s.contact_routes(*contact)?.map(|r| r.to_vec());
            let queues = s.contact_queues(*contact)?.map(|r| r.to_vec());
            put(
                format!("store routes and queues {contact}"),
                format!("{routes:?} {queues:?}"),
            );
            let session = s.session_rows(*contact)?.map(|r| {
                let skipped: Vec<_> = r.skipped.iter().map(|(o, e)| (*o, e.to_vec())).collect();
                let (inbox, trust) = (r.inbox.map(|v| v.to_vec()), r.trust.map(|v| v.to_vec()));
                format!("{:?} {skipped:?} {inbox:?} {trust:?}", r.fixed.to_vec())
            });
            put(format!("store session {contact}"), format!("{session:?}"));
            let controls: Vec<_> = s
                .pending_controls(*contact)?
                .iter()
                .map(|(o, r)| (*o, r.to_vec()))
                .collect();
            put(
                format!("store pending controls {contact}"),
                format!("{controls:?}"),
            );
            let handshake = s.handshake(*contact)?.map(|v| v.to_vec());
            let previous = s.previous_identity(*contact)?.map(|v| v.to_vec());
            put(
                format!("store handshake and previous identity {contact}"),
                format!("{handshake:?} {previous:?}"),
            );
            let outbox: Vec<_> = s
                .outbox_rows(*contact)?
                .iter()
                .map(|o| {
                    format!(
                        "{:?} {} {} {} {:?} {} {:?} {} {:?}",
                        o.msg_id,
                        o.seq,
                        o.kind,
                        o.expire_after,
                        o.payload.to_vec(),
                        o.queued_ms,
                        o.first_relayed_ms,
                        o.state,
                        o.cell_id
                    )
                })
                .collect();
            put(format!("store outbox {contact}"), format!("{outbox:?}"));
            put(
                format!("store delivered {contact}"),
                format!("{:?}", s.delivered_ids(*contact)?),
            );
        }
        Ok(())
    }

    /// SE-178: everything of `hub` the test module reaches, labelled: `look_hub`, `look_conversations`, `look_store` and
    /// `raw_rows`.
    #[cfg(feature = "kat")]
    fn look(hub: &mut Hub<ManualClock, Fixed>) -> Result<Parts, crate::testutil::E> {
        let mut out: Parts = Vec::new();
        look_hub(hub, &mut out);
        look_conversations(hub, &mut out)?;
        look_store(hub, &mut out)?;
        raw_rows(hub, &mut out)?;
        Ok(out)
    }

    /// SE-178: one cell prepared on every send queue the hub knows, in queue order, at `now`, each relayed as cell `id`:
    /// what each queue sends next (the plan, the outbox, the controls, the entropy) — a digest of each cell.
    #[cfg(feature = "kat")]
    fn probe(hub: &mut Hub<ManualClock, Fixed>, now: u64, id: u64) -> Vec<String> {
        use std::hash::{Hash as _, Hasher as _};

        let queues: Vec<QueueId> = hub.send_targets.keys().copied().collect();
        let mut out = Vec::new();
        for q in queues {
            match hub.prepare_cell(q, now) {
                Ok(Some(p)) => {
                    let mut h = std::hash::DefaultHasher::new();
                    p.cell.as_bytes().hash(&mut h);
                    out.push(format!("{q:?} {:x}", h.finish()));
                    hub.relayed(q, p.token, id);
                }
                Ok(None) => out.push(format!("{q:?} none")),
                Err(_) => out.push(format!("{q:?} error")),
            }
        }
        out
    }

    /// SE-178: `a` and `b` equal part by part. The message names the step and the part that differs and nothing that
    /// depends on the run (a signed row, written out, is as wide as the hedged signature's random bytes make it).
    #[cfg(feature = "kat")]
    fn same(step: &str, a: &Parts, b: &Parts) {
        let labels = |p: &Parts| p.iter().map(|(l, _)| l.clone()).collect::<Vec<_>>();
        assert_eq!(labels(a), labels(b), "SE-178 {step}: the same parts");
        for ((label, x), (_, y)) in a.iter().zip(b) {
            assert!(x == y, "SE-178 {step}: {label} differs");
        }
    }

    /// SE-178: the world from `seed` — two contacts, each at the cap: the first through `RouteUpdate`s, its `KeyChange`
    /// (`RotateIdentity`) held on the old queue B (as `kc_on_b_then_c`); the second through routes registered without a
    /// cell, its copy of the `KeyChange` planned and unmarked on its current queue; an open invitation of the guest that
    /// expires at `T0` + 1 s; every timing stream seeded. Also the guest's fixture and the next `sid`.
    #[cfg(feature = "kat")]
    fn cap_world(
        seed: u64,
    ) -> Result<(Scene, Fixture, ContactId, ContactId, u8), crate::testutil::E> {
        let guest = party("cap-w-g", seed.wrapping_add(2))?;
        let mut sc = scene(party("cap-w-h", seed)?, &guest)?;
        sc.inviter.seed_timing_kat(seed);
        sc.invitee.seed_timing_kat(seed.wrapping_add(1));
        step_invite(&mut sc)?;
        step_accept(&mut sc)?;
        step_handshake(&mut sc)?;
        step_reply(&mut sc)?;
        let first = sc.contact;
        // the second contact (as SE-155), its scene's hub over the same guest swapped in
        let mut sc2 = scene(party("cap-w-h2", seed.wrapping_add(4))?, &guest)?;
        sc2.inviter.seed_timing_kat(seed.wrapping_add(5));
        core::mem::swap(&mut sc2.invitee, &mut sc.invitee);
        sc2.invitee.take_actions();
        step_invite(&mut sc2)?;
        step_accept(&mut sc2)?;
        step_handshake(&mut sc2)?;
        step_reply(&mut sc2)?;
        let second = sc2.contact;
        core::mem::swap(&mut sc2.invitee, &mut sc.invitee);
        drop(sc2);
        sc.invitee.take_actions();
        for (n, now) in [(9_u8, 20), (4, 30)] {
            send_route(&mut sc, n, ms(now))?;
            sc.invitee.pump()?;
        }
        // the `KeyChange` held on B (as `kc_on_b_then_c`); the second contact's copy stays pending
        let hub = &mut sc.invitee;
        let b = *hub.send_ids.get(&first.0).ok_or("B")?;
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
        let c = *hub.send_ids.get(&first.0).ok_or("C")?;
        for i in 0..4_u64 {
            on(hub, c, ms(90_u64.saturating_add(i)), i.saturating_add(1))?;
        }
        on(hub, c, ms(100), 261)?;
        on(hub, c, ms(101), 262)?;
        let mut sid = 40_u8;
        for now in 110..120_u64 {
            if sc.invitee.overlaps_held(first) >= MAX_SEND_OVERLAPS {
                break;
            }
            send_route(&mut sc, sid, ms(now))?;
            sc.invitee.pump()?;
            sid = sid.saturating_add(1);
        }
        // the second contact to its own cap too, without a cell: its `KeyChange` stays planned, unmarked, on its queue
        let hub = &mut sc.invitee;
        let at2 = *hub.core.index.get(&second.0).ok_or("second")?;
        for other in 20..30_u8 {
            if hub.overlaps_held(second) >= MAX_SEND_OVERLAPS {
                break;
            }
            hub.register_route(second, at2, &route_body(other, Period::S40)?)?;
        }
        hub.store_current_route(second)?;
        // an open invitation that expires after the open and before the refusal (`refuse` moves the clocks past it with no
        // tick between): only a tick retires it, never a refusal (verifier R5)
        hub.invite(T0.saturating_add(1))?;
        hub.take_actions();
        assert!(kc_live(&sc.invitee, first), "the setup: the KeyChange held");
        assert_eq!(
            (
                sc.invitee.overlaps_held(first),
                sc.invitee.overlaps_held(second)
            ),
            (MAX_SEND_OVERLAPS, MAX_SEND_OVERLAPS),
            "the setup: both at the cap"
        );
        // spare queues for the rotations after the fork (the two handshakes took the pool's)
        crate::invitations::SparePool::new(guest.profile.store()).fill(
            RelayId(1),
            3,
            &mut entropy(seed.wrapping_add(1003)),
        )?;
        Ok((sc, guest, first, second, sid))
    }

    /// SE-178: a copy of the closed profile directory `from` in `to`, file by file.
    #[cfg(feature = "kat")]
    fn copy_dir(from: &std::path::Path, to: &std::path::Path) -> R {
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            let target = to.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                std::fs::create_dir_all(&target)?;
                copy_dir(&entry.path(), &target)?;
            } else {
                std::fs::copy(entry.path(), &target)?;
            }
        }
        Ok(())
    }

    /// SE-178: the guest's hub over the profile in `dir` (as `hub_over`, randomness by `seed`), its timing streams seeded.
    #[cfg(feature = "kat")]
    fn hub_in(
        dir: &std::path::Path,
        unlocked: &secmp_store::wrap::Unlocked,
        clock: &ManualClock,
        seed: u64,
    ) -> Result<Hub<ManualClock, Fixed>, crate::testutil::E> {
        let profile = crate::profile::Profile::open_with(dir, unlocked)?;
        let mut count = 0_u64;
        let core = Core::with_profile(profile, clock.clone(), move || {
            count = count.saturating_add(1);
            Fixed(entropy(seed.saturating_add(count)))
        })?;
        let mut hub = Hub::new(
            core,
            HubConfig {
                relay: RelayId(1),
                inv_period: Period::S10,
                reply_period: Period::S10,
                profile: wire_profile("guest")?,
            },
        )?;
        hub.seed_timing_kat(seed.wrapping_add(1));
        Ok(hub)
    }

    /// SE-178: the same in both worlds after the fork — a message relayed and one queued on the first contact's current
    /// queue; our rotation of the second pumped (its `RouteUpdate` pending beside its `KeyChange`).
    #[cfg(feature = "kat")]
    fn traffic(hub: &mut Hub<ManualClock, Fixed>, first: ContactId, second: ContactId) -> R {
        for text in [&b"relayed"[..], &b"queued"[..]] {
            let Response::Sent(id) = hub.core_mut().handle(Request::Send {
                contact: first,
                kind: 1,
                payload: secmp_crypto::Zeroizing::new(text.to_vec()),
                expire_after: 0,
            })?
            else {
                return Err("sent".into());
            };
            if text != &b"relayed"[..] {
                continue;
            }
            let current = *hub.send_ids.get(&first.0).ok_or("current")?;
            let at = *hub.core.index.get(&first.0).ok_or("first")?;
            for i in 0..8_u64 {
                if matches!(
                    hub.core.convs.get(at).and_then(|c| c.outbox().state(&id)),
                    Some(MsgState::Relayed(_))
                ) {
                    break;
                }
                on(
                    hub,
                    current,
                    ms(130_u64.saturating_add(i)),
                    300_u64.saturating_add(i),
                )?;
            }
        }
        assert!(matches!(
            hub.core_mut().handle(Request::Rotate {
                contact: second,
                relay: 1
            })?,
            Response::Rotated(true)
        ));
        hub.pump()?;
        Ok(())
    }

    /// SE-178: the inviter's `RouteUpdate` of the relay queue `n` (10 s, a period no queue of the world has) sealed in one
    /// cell at `now` (as `send_route`).
    #[cfg(feature = "kat")]
    fn route_cell(
        inviter: &mut Hub<ManualClock, Fixed>,
        host_send: QueueId,
        n: u8,
        now: u64,
    ) -> Result<Cell, crate::testutil::E> {
        let at = *inviter.core.index.get(&1).ok_or("host index")?;
        let routes = RouteUpdateBody::decode(&route_body(n, Period::S10)?)?.routes;
        inviter
            .core
            .convs
            .get_mut(at)
            .ok_or("host conversation")?
            .queue_route_update(routes);
        Ok(inviter
            .prepare_cell(host_send, now)
            .map_err(|_| "prepare")?
            .ok_or("cell")?
            .cell)
    }

    /// SE-178: the two worlds of the test, opened from the same bytes, with the inviter of the first contact.
    #[cfg(feature = "kat")]
    struct Twins {
        /// The inviter's profile (kept open while its hub lives).
        _host: Fixture,
        inviter: Hub<ManualClock, Fixed>,
        host_send: QueueId,
        reply_queue: QueueId,
        dirs: [secmp_store::kat::TempDir; 2],
        clocks: [ManualClock; 2],
        unlocked: secmp_store::wrap::Unlocked,
        first: ContactId,
        second: ContactId,
        next: u8,
    }

    #[cfg(feature = "kat")]
    impl Twins {
        /// Both worlds' hubs opened again (a restart), by `seed`, and their open's actions compared.
        fn open(
            &self,
            seed: u64,
            step: &str,
        ) -> Result<[Hub<ManualClock, Fixed>; 2], crate::testutil::E> {
            let [d0, d1] = &self.dirs;
            let [c0, c1] = &self.clocks;
            let mut a = hub_in(d0.path(), &self.unlocked, c0, seed)?;
            let mut b = hub_in(d1.path(), &self.unlocked, c1, seed)?;
            assert_eq!(
                spelled(&a.take_actions()),
                spelled(&b.take_actions()),
                "SE-178 {step}: actions"
            );
            same(step, &look(&mut a)?, &look(&mut b)?);
            Ok([a, b])
        }
    }

    /// SE-178: the world of `sc` and `guest` closed and its profile directory copied: the twins, not opened yet.
    #[cfg(feature = "kat")]
    fn fork(
        sc: Scene,
        guest: Fixture,
        first: ContactId,
        second: ContactId,
        next: u8,
    ) -> Result<Twins, crate::testutil::E> {
        let Scene {
            host,
            inviter,
            invitee,
            host_send,
            reply_queue,
            ..
        } = sc;
        drop(invitee);
        let Fixture {
            dir,
            unlocked,
            profile,
            clock,
        } = guest;
        drop(profile);
        let copy = secmp_store::kat::TempDir::new("cap-fork")?;
        copy_dir(dir.path(), copy.path())?;
        let clock_b = ManualClock::new(T0);
        clock_b.set_ms(clock.mono_ms());
        Ok(Twins {
            _host: host,
            inviter,
            host_send,
            reply_queue,
            dirs: [dir, copy],
            clocks: [clock, clock_b],
            unlocked,
            first,
            second,
            next,
        })
    }

    /// SE-178: `a` and `b` the same (`look`), and the next cell of every send queue the same (`probe` at `now`, ids `id`).
    #[cfg(feature = "kat")]
    fn alike(
        step: &str,
        a: &mut Hub<ManualClock, Fixed>,
        b: &mut Hub<ManualClock, Fixed>,
        now: u64,
        id: u64,
    ) -> R {
        same(step, &look(a)?, &look(b)?);
        assert_eq!(
            probe(a, ms(now), id),
            probe(b, ms(now), id),
            "SE-178 {step}: the next cells"
        );
        Ok(())
    }

    /// SE-178: the refusal in A and nothing but the write-back in B — the first contact's route by a cell of the inviter
    /// (B: the same cell, its routes taken from the hub), the second's given to the hub directly (B: none) — with the
    /// guest's invitation expired and no tick since.
    #[cfg(feature = "kat")]
    fn refuse(
        t: &mut Twins,
        a: &mut Hub<ManualClock, Fixed>,
        b: &mut Hub<ManualClock, Fixed>,
    ) -> R {
        // the guest's invitation expired (`cap_world`), no tick since: a refusal must not retire it
        let [c0, c1] = &t.clocks;
        c0.set_ms(1_000);
        c1.set_ms(1_000);
        assert!(
            a.next_expiry
                .is_some_and(|at| a.core.clock.unix_secs() >= at),
            "SE-178 refusal: an invitation expired, not retired"
        );
        assert_eq!(a.waiting.len(), 1, "SE-178 refusal: an accept waiting");
        let cell = route_cell(&mut t.inviter, t.host_send, t.next, ms(150))?;
        for w in [&mut *a, &mut *b] {
            assert_eq!(
                w.deliver(t.reply_queue, 0, 1, &cell),
                Ok(Delivered::Committed),
                "the route"
            );
        }
        a.pump()?;
        let at = *b.core.index.get(&t.first.0).ok_or("index")?;
        let taken = b
            .core
            .convs
            .get_mut(at)
            .ok_or("conversation")?
            .persist_mut()
            .take_routes();
        assert_eq!(taken.len(), 1, "B: the route taken from the hub");
        b.store_current_route(t.first)?;
        b.pump()?;
        let at2 = *a.core.index.get(&t.second.0).ok_or("second")?;
        a.register_route(t.second, at2, &route_body(t.next, Period::S10)?)?;
        a.store_current_route(t.second)?;
        b.store_current_route(t.second)?;
        let acts = spelled(&a.take_actions());
        assert!(acts.is_empty(), "SE-178 refusal: no action");
        assert_eq!(acts, spelled(&b.take_actions()), "SE-178 refusal: actions");
        Ok(())
    }

    /// SE-178: at the cap, time passes to the earliest end of an old queue of the first contact registered at the open and
    /// the tick drops it; then a route to a new queue registers — first the refused route sent again — in both; repeated
    /// (verifier R5) until the first contact is at the cap with only old queues switched in this process, each with its
    /// floor and its period (a queue registered at the open has neither), so that at the second refusal its oldest old
    /// queue is one of them. The last `sid` used is `t.next`.
    #[cfg(feature = "kat")]
    fn end_and_again(
        t: &mut Twins,
        a: &mut Hub<ManualClock, Fixed>,
        b: &mut Hub<ManualClock, Fixed>,
    ) -> R {
        for round in 0..16_u64 {
            // the earliest end of an old queue registered at the open
            let opened = a
                .retiring_sends
                .iter()
                .filter(|r| r.contact == t.first.0 && r.floor.is_none())
                .map(|r| r.until)
                .min();
            let at_cap = a.overlaps_held(t.first) >= MAX_SEND_OVERLAPS;
            if opened.is_none() && at_cap {
                break;
            }
            if let (true, Some(end)) = (at_cap, opened) {
                let [c0, c1] = &t.clocks;
                c0.set_ms(end);
                c1.set_ms(end);
                a.tick(end);
                b.tick(end);
                let acts = spelled(&a.take_actions());
                assert!(!acts.is_empty(), "SE-178 end: a queue ends");
                assert_eq!(acts, spelled(&b.take_actions()), "SE-178 end: actions");
            }
            if round == 0 {
                alike("end", a, b, 170, 410)?;
            } else {
                t.next = t.next.checked_add(1).ok_or("sid")?;
            }
            let cell = route_cell(
                &mut t.inviter,
                t.host_send,
                t.next,
                ms(180_u64.saturating_add(round)),
            )?;
            for w in [&mut *a, &mut *b] {
                assert_eq!(
                    w.deliver(t.reply_queue, 0, round.saturating_add(2), &cell),
                    Ok(Delivered::Committed),
                    "the route again"
                );
                w.pump()?;
            }
            let acts = spelled(&a.take_actions());
            assert_eq!(
                acts.iter().filter(|x| x.starts_with("AddSend")).count(),
                1,
                "SE-178 later route: registers"
            );
            assert_eq!(
                acts,
                spelled(&b.take_actions()),
                "SE-178 later route: actions"
            );
        }
        assert!(
            a.overlaps_held(t.first) == MAX_SEND_OVERLAPS
                && a.retiring_sends
                    .iter()
                    .filter(|r| r.contact == t.first.0)
                    .all(|r| r.floor.is_some() && a.send_periods.contains_key(&r.queue)),
            "SE-178 later routes: at the cap, every old queue switched in this process"
        );
        alike("later route", a, b, 190, 420)
    }

    /// SE-178: a second refusal of the first contact, at the cap again (after the later routes) and now holding only old
    /// queues switched in this process — each with its floor anchored at the switch and its period, which a queue registered
    /// at the open does not have (verifier R5): the refusal in A, the same cell with nothing but the write-back in B.
    #[cfg(feature = "kat")]
    fn refuse_again(
        t: &mut Twins,
        a: &mut Hub<ManualClock, Fixed>,
        b: &mut Hub<ManualClock, Fixed>,
    ) -> R {
        assert!(
            a.retiring_sends
                .iter()
                .any(|r| r.contact == t.first.0 && r.floor.is_some()),
            "SE-178 second refusal: an old queue with its floor"
        );
        let n = t.next.checked_add(1).ok_or("sid")?;
        let cell = route_cell(&mut t.inviter, t.host_send, n, ms(199))?;
        for w in [&mut *a, &mut *b] {
            assert_eq!(
                w.deliver(t.reply_queue, 0, 20, &cell),
                Ok(Delivered::Committed),
                "the second refused route"
            );
        }
        a.pump()?;
        let at = *b.core.index.get(&t.first.0).ok_or("index")?;
        let taken = b
            .core
            .convs
            .get_mut(at)
            .ok_or("conversation")?
            .persist_mut()
            .take_routes();
        assert_eq!(taken.len(), 1, "B: the second route taken from the hub");
        b.store_current_route(t.first)?;
        b.pump()?;
        let acts = spelled(&a.take_actions());
        assert!(acts.is_empty(), "SE-178 second refusal: no action");
        assert_eq!(
            acts,
            spelled(&b.take_actions()),
            "SE-178 second refusal: actions"
        );
        alike("second refusal", a, b, 195, 425)
    }

    /// SE-178: our rotation of the first contact at its cap, in both: its new receive queue and the replaced one's
    /// `QUEUE_DEL`, the same actions.
    #[cfg(feature = "kat")]
    fn rotate_first(
        first: ContactId,
        a: &mut Hub<ManualClock, Fixed>,
        b: &mut Hub<ManualClock, Fixed>,
    ) -> R {
        assert_eq!(
            a.overlaps_held(first),
            MAX_SEND_OVERLAPS,
            "SE-178 rotation: at the cap"
        );
        let at1 = *a.core.index.get(&first.0).ok_or("first")?;
        let replaced = a
            .core
            .convs
            .get(at1)
            .and_then(|c| c.recv_queues_kat().0)
            .ok_or("receive queue")?;
        for w in [&mut *a, &mut *b] {
            assert!(matches!(
                w.core_mut().handle(Request::Rotate {
                    contact: first,
                    relay: 1
                })?,
                Response::Rotated(true)
            ));
            w.pump()?;
        }
        let rotated = a.take_actions();
        let added = rotated
            .iter()
            .filter(|x| matches!(x, Action::AddRecv { .. }))
            .count();
        assert_eq!(
            (added, queue_dels(&rotated, replaced).len()),
            (1, 1),
            "SE-178 rotation: its receive queue and the replaced one's QUEUE_DEL at the cap"
        );
        assert_eq!(
            spelled(&rotated),
            spelled(&b.take_actions()),
            "SE-178 rotation: actions"
        );
        alike("rotation", a, b, 200, 430)
    }

    /// SE-178, restart part: the store of one contact with `MAX_SEND_OVERLAPS` overlap rows, closed and copied, the copy
    /// given 2 rows more; also the contact and the 2 rows' `sid`s.
    #[cfg(feature = "kat")]
    fn beyond_the_cap() -> Result<(Twins, ContactId, Vec<Id>), crate::testutil::E> {
        use crate::clock::Clock as _;

        let guest = party("cap-x-g", 473)?;
        let mut sc = scene(party("cap-x-h", 471)?, &guest)?;
        sc.inviter.seed_timing_kat(471);
        sc.invitee.seed_timing_kat(472);
        step_invite(&mut sc)?;
        step_accept(&mut sc)?;
        step_handshake(&mut sc)?;
        step_reply(&mut sc)?;
        let contact = sc.contact;
        for (n, now) in [(9_u8, 20), (4, 30)] {
            send_route(&mut sc, n, ms(now))?;
            sc.invitee.pump()?;
        }
        let held = overlaps_of(&sc.invitee, contact)?.len();
        let now = guest.clock.unix_secs().saturating_mul(1_000);
        let row = |sid: u8| -> Result<Zeroizing<Vec<u8>>, crate::testutil::E> {
            Ok(crate::sessions::actor::OverlapRoute {
                sid: [sid; 16],
                seed: SecretBytes::from_slice(&[sid; 32])?,
                period: Period::S20,
                until_ms: now.saturating_add(10_000).saturating_add(u64::from(sid)),
                newest: 0,
                unknown: false,
            }
            .row())
        };
        let mut sid = 50_u8;
        for _ in held..MAX_SEND_OVERLAPS {
            let r = row(sid)?;
            guest
                .profile
                .store()
                .lock()
                .map_err(|_| "lock")?
                .txn(|tx| secmp_store::sessions::insert_pending_control(tx, contact.0, &r))?;
            sid = sid.checked_add(1).ok_or("sid")?;
        }
        let mut t = fork(sc, guest, contact, contact, sid)?;
        let mut beyond = Vec::new();
        let more = crate::profile::Profile::open_with(t.dirs[1].path(), &t.unlocked)?;
        for _ in 0..2 {
            let r = row(t.next)?;
            more.store()
                .lock()
                .map_err(|_| "lock")?
                .txn(|tx| secmp_store::sessions::insert_pending_control(tx, contact.0, &r))?;
            beyond.push([t.next; 16]);
            t.next = t.next.checked_add(1).ok_or("sid")?;
        }
        Ok((t, contact, beyond))
    }

    /// SE-178 (Q268, Q270; verifier R4): a refusal changes nothing but the stored route. One world (`cap_world`: two
    /// contacts, the first at the cap with its `KeyChange` held on an old queue) is closed and its store copied — two
    /// worlds A and B from the same bytes (the hedged signature of the `KeyChange` draws from the OS, so two builds would
    /// differ in it) — both opened and given the same traffic (`traffic`). A receives a `RouteUpdate` to a new queue with
    /// another period (refused at the cap) and the hub is given one for the second contact; B receives the same cell, but
    /// its routes never reach the hub, and the second's never comes — only the current routes are written back, as the
    /// pump's closing write. Everything the test module reaches (`look`: the hub's fields, the core's, each conversation's
    /// observable state, the store opened and raw; `probe`: the next cell of every send queue) is equal after it and after
    /// each later step — time to the first's earliest end and its tick, the refused route sent again (now registered) and
    /// new routes until every old queue of the first contact was switched in this process, a second refusal (verifier R5:
    /// now with only such old queues, each with its floor and its period), our rotation of the first contact (at the cap
    /// again: its new receive queue and the replaced one's `QUEUE_DEL`), a restart. The first refusal comes with an
    /// invitation of the guest expired and not yet retired (no tick since) and an accept waiting for its `LINK_GET`
    /// (verifier R5). Restart part: a store with `MAX_SEND_OVERLAPS` + 2 overlap rows of one contact against the same store
    /// with only the first `MAX_SEND_OVERLAPS`: the open is the same in actions and state but for the 2 rows read and not
    /// registered (`overlaps_read`, their store rows), which the first preparation deletes; then everything is equal.
    #[test]
    #[cfg(feature = "kat")]
    fn a_refusal_changes_nothing_but_the_stored_route() -> R {
        big(|| {
            let (sc, guest, first, second, next) = cap_world(461)?;
            let mut twins = fork(sc, guest, first, second, next)?;
            let [mut a, mut b] = twins.open(463, "open")?;
            // an invitation the guest is accepting, its `LINK_GET` not back (memory only): a refusal must not forget it
            let uri = twins.inviter.invite(T0.saturating_add(DAY))?.uri;
            a.begin_accept(&uri)?;
            b.begin_accept(&uri)?;
            traffic(&mut a, twins.first, twins.second)?;
            traffic(&mut b, twins.first, twins.second)?;
            assert_eq!(
                spelled(&a.take_actions()),
                spelled(&b.take_actions()),
                "SE-178 setup: actions"
            );
            same("setup", &look(&mut a)?, &look(&mut b)?);
            refuse(&mut twins, &mut a, &mut b)?;
            alike("refusal", &mut a, &mut b, 160, 400)?;
            end_and_again(&mut twins, &mut a, &mut b)?;
            refuse_again(&mut twins, &mut a, &mut b)?;
            rotate_first(twins.first, &mut a, &mut b)?;
            drop((a, b));
            let [mut a, mut b] = twins.open(465, "restart")?;
            assert_eq!(
                probe(&mut a, ms(210), 440),
                probe(&mut b, ms(210), 440),
                "SE-178 restart: the next cells"
            );
            drop((a, b, twins));
            // the restart part: the cap + 2 overlap rows of one contact against the cap only
            let (twins, contact, beyond) = beyond_the_cap()?;
            let [d0, d1] = &twins.dirs;
            let [c0, c1] = &twins.clocks;
            let mut capped = hub_in(d0.path(), &twins.unlocked, c0, 475)?;
            let mut over = hub_in(d1.path(), &twins.unlocked, c1, 475)?;
            assert_eq!(
                spelled(&over.take_actions()),
                spelled(&capped.take_actions()),
                "SE-178 open beyond the cap: actions"
            );
            // before the first preparation the 2 rows beyond the cap are read and not registered: their only trace
            let traces = [
                format!("conversation {}", contact.0),
                format!("store pending controls {}", contact.0),
                "store raw sessions".to_string(),
            ];
            let rest = |p: Parts| {
                p.into_iter()
                    .filter(|(l, _)| !traces.contains(l))
                    .collect::<Parts>()
            };
            same(
                "open beyond the cap",
                &rest(look(&mut over)?),
                &rest(look(&mut capped)?),
            );
            let read = |h: &Hub<ManualClock, Fixed>| {
                h.core
                    .convs
                    .get(0)
                    .and_then(|x| x.overlaps_read().ok())
                    .map(|v| v.iter().map(|o| o.sid).collect::<Vec<_>>())
            };
            assert_eq!(
                (read(&over), read(&capped)),
                (Some(beyond), Some(Vec::new())),
                "SE-178 open beyond the cap: the 2 rows read, not registered"
            );
            let (_, current) = over.sends_of(contact).ok_or("sends")?;
            on(&mut over, current, ms(10), 1)?;
            on(&mut capped, current, ms(10), 1)?;
            assert_eq!(
                spelled(&over.take_actions()),
                spelled(&capped.take_actions()),
                "SE-178 first preparation beyond the cap: actions"
            );
            same(
                "first preparation beyond the cap",
                &look(&mut over)?,
                &look(&mut capped)?,
            );
            Ok(())
        })
    }
}
