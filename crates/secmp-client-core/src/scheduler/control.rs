// SPDX-License-Identifier: AGPL-3.0-or-later
//! `ControlOps` (spec §10.6 (2), `docs/02` §4.4): `QUEUE_NEW`, `QUEUE_DEL`, `LINK_PUT` and owner-status `LINK_GET` each
//! run on their own isolated one-shot link, delayed by `U[1 min, 60 min]` from any related operation — except where a
//! user is waiting (the invitee's consuming `LINK_GET`, the inviter's `LINK_PUT`), which start at once.
//!
//! This module decides *when*; the host runs the operation (it owns the keys and the link data). Delays come from the
//! timing randomness only (CO-08).

use crate::scheduler::core::backoff::reconnect_delay;
use crate::scheduler::params::{CONNECT_TIMEOUT_MS, Params};
use crate::scheduler::types::{ControlKind, OpId, QueueId, RelayId};
use crate::timing::{TimingRng, Unavailable};

/// When an operation starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum When {
    /// A user is waiting: now.
    Prompt,
    /// `U[1 min, 60 min]` after the latest related operation (or now).
    Delayed,
    /// At this monotonic time (re-creation after `ERR_NOQUEUE`, spec §9.1: its own delay, drawn by the caller).
    At(u64),
    /// After a `FETCH` of this queue that held no present cell, then `U[1 min, 60 min]` (the `QUEUE_DEL` of a retired
    /// queue, §10.6 (4), Q163, Q194): [`ControlOps::schedule_after_empty_fetch`].
    AfterEmptyFetch(QueueId),
    /// As [`When::AfterEmptyFetch`], but only a `FETCH` at or after this monotonic time counts: the queue is fetched through
    /// its overlap period `U[1 h, 24 h]` first (a rotated queue, an invitation queue replaced by the first reply, §10.6 (4)
    /// and (5)).
    AfterEmptyFetchFrom(QueueId, u64),
}

struct Op {
    id: OpId,
    kind: ControlKind,
    relay: RelayId,
    /// The correlation this operation belongs to (a queue, an invitation, a contact), chosen by the host.
    related: u64,
    due: u64,
    /// The delay drawn for a [`When::Delayed`] operation (again at an answer, or at its empty `FETCH`): it never starts before the latest related start plus this delay (spec §10.6 (2): `U[1 min, 60 min]` from any related operation, whenever that one actually ran) — a retry after a link failure neither, its own failed start included (EXT3b-1 (i), Q304). `None` for an operation a user waits for until it is answered: an answered operation is re-queued with a drawn delay (`ControlOps::answered`) and keeps it as its floor after a later link failure.
    delay: Option<u64>,
    running: bool,
    failures: u32,
    closed_before: u32,
    /// The queue whose `FETCH` must first answer with no present cell (Q163, Q194): the operation does not start, and has no
    /// time, until [`ControlOps::note_empty_fetch`] reports it.
    awaiting: Option<QueueId>,
    /// The earliest monotonic time at which an empty `FETCH` of `awaiting` counts (the end of the overlap period).
    not_before: u64,
}

/// What to queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpSpec {
    /// What to run.
    pub kind: ControlKind,
    /// On which relay.
    pub relay: RelayId,
    /// The correlation the operation belongs to (a queue, an invitation, a contact), chosen by the host.
    pub related: u64,
    /// When it starts.
    pub when: When,
}

/// An operation that is due.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DueOp {
    /// The operation.
    pub id: OpId,
    /// What to run.
    pub kind: ControlKind,
    /// On which relay.
    pub relay: RelayId,
    /// The admission time: the `now` of [`ControlOps::take_due`] (HB-64, EXT3d-1).
    pub at: u64,
}

/// The queue of control operations.
#[derive(Default)]
pub struct ControlOps {
    ops: Vec<Op>,
    /// The start of the latest operation per correlation.
    last_start: Vec<(u64, u64)>,
}

impl ControlOps {
    /// No operation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ops: Vec::new(),
            last_start: Vec::new(),
        }
    }

    /// Operations waiting or running.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.ops.len()
    }

    /// Whether nothing waits.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Whether a `QUEUE_DEL` of `queue` waits or runs (Q201).
    #[must_use]
    pub fn queue_del_pending(&self, queue: crate::scheduler::types::QueueId) -> bool {
        self.ops
            .iter()
            .any(|o| o.kind == ControlKind::QueueDel(queue))
    }

    /// Drop the `QUEUE_DEL`s and the `QUEUE_NEW`s of `queue`: the queue is gone from the schedule, there is nothing left to
    /// delete (Q201) and nothing to re-create (a pending re-create of a removed queue would make the host mint a spare for it).
    pub fn drop_queue_ops(&mut self, queue: crate::scheduler::types::QueueId) {
        self.ops.retain(|o| {
            o.kind != ControlKind::QueueDel(queue) && o.kind != ControlKind::QueueNew(queue)
        });
    }

    /// The operation a new `kind` on `relay` joins instead of being queued (Q304, EXT3b-4): one `LINK_PUT` chain and one owner-status `LINK_GET` chain per link data. A new operation joins only a WAITING one of its kind: one requested while its kind runs is queued (never two WAITING through this path; a link's life after `prepare` lasts up to `CONNECT_TIMEOUT_MS`; `prepare` and `commit` are outside that limit (HB-62 (3)), so the bound of three or four assumes a bounded `prepare`; delayed starts are 60 s apart, so two can run at once, and `answered`/`failed` re-queue without joining — at most three or four operations of one kind, link data and relay, HB-61) — a put that succeeds after the relay lost its state must not swallow the re-put the owner answer asked for (EXT3c-2). `None` for every other kind.
    #[must_use]
    pub fn coalesced(&self, kind: ControlKind, relay: RelayId) -> Option<OpId> {
        let joins = |o: &Op| {
            matches!(kind, ControlKind::LinkPut(_) | ControlKind::LinkGetOwner(_)) && !o.running
        };
        self.ops
            .iter()
            .find(|o| o.kind == kind && o.relay == relay && joins(o))
            .map(|o| o.id)
    }

    /// What `id` runs, while it waits or runs.
    #[must_use]
    pub fn kind_of(&self, id: OpId) -> Option<ControlKind> {
        self.ops.iter().find(|o| o.id == id).map(|o| o.kind)
    }

    /// The monotonic time at which `id` may start, while it waits (a related start that came later has pushed a
    /// delayed operation back).
    #[must_use]
    pub fn due_of(&self, id: OpId) -> Option<u64> {
        self.ops
            .iter()
            .find(|o| o.id == id && o.awaiting.is_none())
            .map(|o| self.start_not_before(o))
    }

    /// Queue an operation. A delayed one starts `U[1 min, 60 min]` after `max(now, the latest start or due time of an
    /// operation with the same `related`)`: related operations never run within a minute of each other.
    ///
    /// A `LINK_PUT` or owner-status `LINK_GET` that [`ControlOps::coalesced`] names is not queued (Q304).
    ///
    /// # Errors
    /// [`Unavailable`] without randomness.
    pub fn schedule(
        &mut self,
        params: &Params,
        rng: &mut TimingRng,
        id: OpId,
        now: u64,
        spec: OpSpec,
    ) -> Result<(), Unavailable> {
        // Q304 (EXT3b-4): one put chain and one owner-query chain per link data; joining draws nothing (Q301)
        if self.coalesced(spec.kind, spec.relay).is_some() {
            return Ok(());
        }
        let OpSpec {
            kind,
            relay,
            related,
            when,
        } = spec;
        if let When::AfterEmptyFetch(queue) = when {
            return self.schedule_after_empty_fetch(id, spec, queue);
        }
        if let When::AfterEmptyFetchFrom(queue, from) = when {
            return self.schedule_after_empty_fetch_from(id, spec, queue, from);
        }
        let mut delay = None;
        let due = match when {
            When::Prompt | When::AfterEmptyFetch(_) | When::AfterEmptyFetchFrom(..) => now,
            When::At(t) => t,
            When::Delayed => {
                let (at, drawn) = self.delayed_due(params, rng, related, now)?;
                delay = Some(drawn);
                at
            }
        };
        self.ops.push(Op {
            id,
            kind,
            relay,
            related,
            due,
            delay,
            running: false,
            failures: 0,
            closed_before: 0,
            awaiting: None,
            not_before: 0,
        });
        Ok(())
    }

    /// The due time and the drawn delay of a [`When::Delayed`] operation of `related` queued at `now`: `U[1 min, 60 min]`
    /// after the latest of `now` and the start or due time of any operation with the same `related` (spec §10.6 (2)).
    fn delayed_due(
        &self,
        params: &Params,
        rng: &mut TimingRng,
        related: u64,
        now: u64,
    ) -> Result<(u64, u64), Unavailable> {
        let started = self
            .last_start
            .iter()
            .filter(|(r, _)| *r == related)
            .map(|(_, t)| *t);
        let waiting = self
            .ops
            .iter()
            .filter(|o| o.related == related)
            .map(|o| o.due);
        let base = started.chain(waiting).fold(now, u64::max);
        let (lo, hi) = params.control_delay_ms;
        let drawn = rng.uniform(lo, hi)?;
        Ok((base.saturating_add(drawn), drawn))
    }

    /// [`ControlOps::schedule`] of a [`When::Delayed`] operation whose delay `drawn` (`params.control_delay_ms`) the caller drew
    /// before it changed anything (Q301: a failed draw changes nothing); `spec.when` is not read. It cannot fail.
    pub fn schedule_drawn(&mut self, id: OpId, now: u64, spec: OpSpec, drawn: u64) {
        // Q304 (EXT3b-4): one put chain and one owner-query chain per link data; joining draws nothing (Q301)
        if self.coalesced(spec.kind, spec.relay).is_some() {
            return;
        }
        let started = self
            .last_start
            .iter()
            .filter(|(r, _)| *r == spec.related)
            .map(|(_, t)| *t);
        let waiting = self
            .ops
            .iter()
            .filter(|o| o.related == spec.related)
            .map(|o| o.due);
        let base = started.chain(waiting).fold(now, u64::max);
        self.ops.push(Op {
            id,
            kind: spec.kind,
            relay: spec.relay,
            related: spec.related,
            due: base.saturating_add(drawn),
            delay: Some(drawn),
            running: false,
            failures: 0,
            closed_before: 0,
            awaiting: None,
            not_before: 0,
        });
    }

    /// Queue `spec` (a `QUEUE_DEL` of `queue`, §10.6 (4)) behind an empty `FETCH` (Q163, Q194; D-B11): it waits, with no
    /// time of its own, until the core reports a `FETCH` of `queue` that held no present cell
    /// ([`ControlOps::note_empty_fetch`]); then its `U[1 min, 60 min]` delay (§10.6 (2)) starts. One implementation for
    /// every retirement: an expired invitation, a rotated queue, a consumed invitation's queue.
    ///
    /// # Errors
    /// [`Unavailable`] never here (the delay is drawn when the empty `FETCH` is seen); the signature follows
    /// [`ControlOps::schedule`].
    pub fn schedule_after_empty_fetch(
        &mut self,
        id: OpId,
        spec: OpSpec,
        queue: QueueId,
    ) -> Result<(), Unavailable> {
        self.schedule_after_empty_fetch_from(id, spec, queue, 0)
    }

    /// [`ControlOps::schedule_after_empty_fetch`] where only an empty `FETCH` at or after `from` (monotonic ms) counts: the
    /// overlap period of a rotated or replaced queue, `U[1 h, 24 h]` (§10.6 (4)), drawn once when the queue is retired.
    ///
    /// # Errors
    /// As [`ControlOps::schedule_after_empty_fetch`].
    pub fn schedule_after_empty_fetch_from(
        &mut self,
        id: OpId,
        spec: OpSpec,
        queue: QueueId,
        from: u64,
    ) -> Result<(), Unavailable> {
        self.ops.push(Op {
            id,
            kind: spec.kind,
            relay: spec.relay,
            related: spec.related,
            due: u64::MAX,
            delay: None,
            running: false,
            failures: 0,
            closed_before: 0,
            awaiting: Some(queue),
            not_before: from,
        });
        Ok(())
    }

    /// A `FETCH` of `queue` returned no present cell at `now`: the operations that waited for it start their delay
    /// `U[1 min, 60 min]` from `max(now, the latest related start)`; when an operation of the same correlation runs, from
    /// `now + CONNECT_TIMEOUT_MS` — its command may still leave until then (EXT3c-1, M7-S9b). Without randomness they keep
    /// waiting (fail closed: nothing is deleted without its delay).
    pub fn note_empty_fetch(
        &mut self,
        params: &Params,
        rng: &mut TimingRng,
        queue: QueueId,
        now: u64,
    ) {
        for i in 0..self.ops.len() {
            let Some(op) = self.ops.get(i) else { break };
            if op.awaiting != Some(queue) || now < op.not_before {
                continue;
            }
            let related = op.related;
            let running = self.ops.iter().any(|o| o.related == related && o.running);
            let floor = if running {
                now.saturating_add(CONNECT_TIMEOUT_MS)
            } else {
                now
            };
            let started = self
                .last_start
                .iter()
                .filter(|(r, _)| *r == related)
                .map(|(_, t)| *t)
                .fold(floor, u64::max);
            let (lo, hi) = params.control_delay_ms;
            let Ok(drawn) = rng.uniform(lo, hi) else {
                continue;
            };
            if let Some(op) = self.ops.get_mut(i) {
                op.awaiting = None;
                op.delay = Some(drawn);
                op.due = started.saturating_add(drawn);
            }
        }
    }

    /// Whether `id` still waits for an empty `FETCH`.
    #[must_use]
    pub fn awaits_empty_fetch(&self, id: OpId) -> bool {
        self.ops.iter().any(|o| o.id == id && o.awaiting.is_some())
    }

    /// When `op` may start: its due time, and for a delayed operation not before the latest related start plus its drawn
    /// delay (a related operation that started later than planned pushes it back).
    fn start_not_before(&self, op: &Op) -> u64 {
        let rebased = op.delay.and_then(|d| {
            self.last_start
                .iter()
                .filter(|(r, _)| *r == op.related)
                .map(|(_, t)| t.saturating_add(d))
                .max()
        });
        rebased.map_or(op.due, |t| t.max(op.due))
    }

    /// The earliest time a waiting operation may start.
    #[must_use]
    pub fn next_due(&self) -> Option<u64> {
        self.ops
            .iter()
            .filter(|o| !o.running && o.awaiting.is_none())
            .map(|o| self.start_not_before(o))
            .min()
    }

    /// The operations that may start at `now`, in queue order; they are marked running. Of several delayed operations
    /// of one correlation that are overdue together, one starts per call: the others are rebased on its start.
    pub fn take_due(&mut self, now: u64) -> Vec<DueOp> {
        let mut out = Vec::new();
        for i in 0..self.ops.len() {
            let Some(op) = self.ops.get(i) else { break };
            if op.running || op.awaiting.is_some() || self.start_not_before(op) > now {
                continue;
            }
            let related = op.related;
            out.push(DueOp {
                id: op.id,
                kind: op.kind,
                relay: op.relay,
                at: now,
            });
            if let Some(op) = self.ops.get_mut(i) {
                op.running = true;
            }
            match self.last_start.iter_mut().find(|(r, _)| *r == related) {
                Some((_, t)) => *t = (*t).max(now),
                None => self.last_start.push((related, now)),
            }
        }
        out
    }

    /// The link was up and no answer was committed (Q300 phase rule, M7-S4d: a relay `ERR` of any code, an unfitting answer, the link closed, the timeout): it waits again exactly as a fresh
    /// [`When::Delayed`] operation of its correlation (the answered attempt is a related operation, spec §10.6 (2)), also
    /// when it first ran at once; the drawn delay is kept, so a later related start pushes it back. No cap, no growing
    /// back-off (HB-61).
    ///
    /// # Errors
    /// [`Unavailable`] without randomness.
    pub fn answered(
        &mut self,
        params: &Params,
        rng: &mut TimingRng,
        id: OpId,
        now: u64,
    ) -> Result<(), Unavailable> {
        let Some(related) = self.ops.iter().find(|o| o.id == id).map(|o| o.related) else {
            return Ok(());
        };
        let (due, drawn) = self.delayed_due(params, rng, related, now)?;
        if let Some(op) = self.ops.iter_mut().find(|o| o.id == id) {
            op.failures = op.failures.saturating_add(1);
            op.closed_before = 0;
            op.due = due;
            op.delay = Some(drawn);
            op.running = false;
        }
        Ok(())
    }

    /// The operation succeeded: it is gone (it ran exactly once).
    pub fn done(&mut self, id: OpId) {
        self.ops.retain(|o| o.id != id);
    }

    /// The operation's link failed before it could run: it is attempted again after the back-off of `closed_before`
    /// consecutive closes before `RELAYINFO` (LR-03), never dropped (CO-06); a delayed one keeps its drawn delay, so it also starts no earlier than the latest related start — its own failed one included — plus that delay (spec §10.6 (2), EXT3b-1 (i), Q304).
    ///
    /// # Errors
    /// [`Unavailable`] without randomness.
    pub fn failed(
        &mut self,
        params: &Params,
        rng: &mut TimingRng,
        id: OpId,
        now: u64,
        closed_before_relayinfo: bool,
    ) -> Result<(), Unavailable> {
        let Some(op) = self.ops.iter_mut().find(|o| o.id == id) else {
            return Ok(());
        };
        op.failures = op.failures.saturating_add(1);
        op.closed_before = if closed_before_relayinfo {
            op.closed_before.saturating_add(1)
        } else {
            0
        };
        op.due = now.saturating_add(reconnect_delay(params, rng, op.closed_before)?);
        op.running = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(kind: ControlKind, related: u64, when: When) -> OpSpec {
        OpSpec {
            kind,
            relay: RelayId(0),
            related,
            when,
        }
    }

    /// B-4 killers (`ControlOps::note_empty_fetch`, Q194): the delay of a `QUEUE_DEL` starts from the latest start of an
    /// operation of its own correlation — not of another one — and from now when there is none.
    #[test]
    fn empty_fetch_delay_starts_from_its_own_correlation() -> Result<(), Unavailable> {
        let params = Params::default();
        let mut rng = TimingRng::seeded(5);
        let mut ops = ControlOps::new();
        // another correlation started late
        ops.schedule(
            &params,
            &mut rng,
            OpId(1),
            10_000_000,
            spec(ControlKind::QueueNew(QueueId(1)), 1, When::Prompt),
        )?;
        assert_eq!(ops.take_due(10_000_000).len(), 1);
        // an operation of correlation 2 waits for an empty `FETCH` of queue 2
        ops.schedule(
            &params,
            &mut rng,
            OpId(2),
            0,
            spec(
                ControlKind::QueueDel(QueueId(2)),
                2,
                When::AfterEmptyFetch(QueueId(2)),
            ),
        )?;
        assert!(ops.awaits_empty_fetch(OpId(2)));
        assert_eq!(ops.due_of(OpId(2)), None);
        // a `FETCH` of another queue arms nothing
        ops.note_empty_fetch(&params, &mut rng, QueueId(3), 1_000);
        assert!(ops.awaits_empty_fetch(OpId(2)));
        ops.note_empty_fetch(&params, &mut rng, QueueId(2), 1_000);
        let due = ops.due_of(OpId(2)).ok_or(Unavailable)?;
        assert!((1_000 + 60_000..=1_000 + 3_600_000).contains(&due), "{due}");
        // the same correlation started later: the delay follows that start
        ops.schedule(
            &params,
            &mut rng,
            OpId(3),
            0,
            spec(
                ControlKind::QueueDel(QueueId(4)),
                1,
                When::AfterEmptyFetch(QueueId(4)),
            ),
        )?;
        ops.note_empty_fetch(&params, &mut rng, QueueId(4), 2_000);
        let due = ops.due_of(OpId(3)).ok_or(Unavailable)?;
        assert!(
            (10_000_000 + 60_000..=10_000_000 + 3_600_000).contains(&due),
            "{due}"
        );
        Ok(())
    }

    /// The least difference of consecutive start times of `starts` (in start order; `u64::MAX` for fewer than two).
    fn min_gap(starts: &[(OpId, u64)]) -> u64 {
        starts
            .iter()
            .zip(starts.iter().skip(1))
            .map(|(a, b)| b.1.saturating_sub(a.1))
            .min()
            .unwrap_or(u64::MAX)
    }

    /// A put and an owner query of link data 7, both due 60 000 ms after the latest related start or due (`schedule_drawn` at 0), the put started at 60 000 ms (T1, T2).
    fn put_and_query() -> ControlOps {
        let mut ops = ControlOps::new();
        ops.schedule_drawn(
            OpId(1),
            0,
            spec(ControlKind::LinkPut(7), 7, When::Delayed),
            60_000,
        );
        ops.schedule_drawn(
            OpId(2),
            0,
            spec(ControlKind::LinkGetOwner(7), 7, When::Delayed),
            60_000,
        );
        let started = ops.take_due(60_000).len();
        assert_eq!(started, 1);
        ops
    }

    /// T1 — EXT3b-1 (i) (V-EXT3b-1 T1; spec §10.6 (2)): a delayed operation whose link failed before it was up keeps its drawn delay: its retry starts at least a minute after a related operation that started meanwhile (500 seeds).
    #[test]
    fn link_failed_retry_keeps_related_spacing() -> Result<(), Unavailable> {
        let params = Params::default();
        for seed in 0..500_u64 {
            let (mut rng, mut ops) = (TimingRng::seeded(seed), put_and_query());
            ops.failed(&params, &mut rng, OpId(1), 60_001, false)?;
            let mut starts = Vec::new();
            for _ in 0..20 {
                let Some(t) = ops.next_due() else { break };
                starts.extend(ops.take_due(t).into_iter().map(|d| (d.id, t)));
            }
            assert_eq!(starts.len(), 2, "seed {seed}: {starts:?}");
            assert!(min_gap(&starts) >= 60_000, "seed {seed}: {starts:?}");
        }
        Ok(())
    }

    /// T2 — EXT3b-1 (i) (V-EXT3b-1 T2): as T1, the put's link closing before `RELAYINFO` twice (the back-off cap grows to 360 s): no two starts of the link data, its failed ones included, are less than a minute apart.
    #[test]
    fn link_failed_retries_keep_spacing_after_closes() -> Result<(), Unavailable> {
        let params = Params::default();
        for seed in 0..500_u64 {
            let (mut rng, mut ops) = (TimingRng::seeded(seed), put_and_query());
            ops.failed(&params, &mut rng, OpId(1), 60_001, true)?;
            let mut starts = vec![(OpId(1), 60_000)];
            for _ in 0..20 {
                if starts.len() >= 4 {
                    break;
                }
                let Some(t) = ops.next_due() else { break };
                for d in ops.take_due(t) {
                    starts.push((d.id, t));
                    if d.id == OpId(1) && starts.iter().filter(|s| s.0 == OpId(1)).count() == 2 {
                        ops.failed(&params, &mut rng, OpId(1), t.saturating_add(1), true)?;
                    }
                }
            }
            assert_eq!(starts.len(), 4, "seed {seed}: {starts:?}");
            assert!(min_gap(&starts) >= 60_000, "seed {seed}: {starts:?}");
        }
        Ok(())
    }

    /// UA1 — Q304 (EXT3b-4; V-EXT3b-34 T4-1): a `LINK_PUT` of a link data that has one WAITING joins it — nothing is queued and nothing is drawn (Q301), also without randomness; one requested while the put runs is queued (S9, EXT3c-2); another link data is its own chain.
    #[test]
    fn link_put_joins_only_a_waiting_put() -> Result<(), Unavailable> {
        let params = Params::default();
        let (mut rng, mut none, mut ops) = (
            TimingRng::seeded(43),
            TimingRng::failing(),
            ControlOps::new(),
        );
        let put = |n: u32, when| spec(ControlKind::LinkPut(n), u64::from(n), when);
        ops.schedule(&params, &mut rng, OpId(1), 0, put(7, When::Delayed))?;
        let due = ops.due_of(OpId(1)).ok_or(Unavailable)?;
        assert_eq!(ops.take_due(due).len(), 1);
        ops.answered(&params, &mut rng, OpId(1), due.saturating_add(1_000))?;
        ops.schedule(
            &params,
            &mut none,
            OpId(2),
            due.saturating_add(2_000),
            put(7, When::Delayed),
        )?;
        assert_eq!((ops.len(), ops.kind_of(OpId(2))), (1, None), "waiting");
        let again = ops.due_of(OpId(1)).ok_or(Unavailable)?;
        assert_eq!(ops.take_due(again).len(), 1);
        ops.schedule(&params, &mut none, OpId(3), again, put(7, When::Prompt))?;
        assert_eq!(
            (ops.len(), ops.kind_of(OpId(3))),
            (2, Some(ControlKind::LinkPut(7))),
            "running: queued"
        );
        ops.schedule(&params, &mut rng, OpId(4), again, put(8, When::Delayed))?;
        assert_eq!(ops.len(), 3, "another link data");
        Ok(())
    }

    /// S9 — Q304 (A) (EXT3c-2): a `LINK_PUT` requested while the link data's put RUNS is queued; when the running one ends done, the queued one is still there and due.
    #[test]
    fn reput_requested_while_a_put_runs_is_queued() -> Result<(), Unavailable> {
        let params = Params::default();
        let (mut rng, mut ops) = (TimingRng::seeded(44), ControlOps::new());
        let put = spec(ControlKind::LinkPut(7), 7, When::Delayed);
        ops.schedule(&params, &mut rng, OpId(1), 0, put)?;
        let due = ops.due_of(OpId(1)).ok_or(Unavailable)?;
        assert_eq!(ops.take_due(due).len(), 1);
        ops.schedule(&params, &mut rng, OpId(2), due.saturating_add(1_000), put)?;
        assert_eq!(
            (ops.len(), ops.kind_of(OpId(2))),
            (2, Some(ControlKind::LinkPut(7)))
        );
        ops.done(OpId(1));
        assert_eq!(ops.len(), 1);
        let d = ops.due_of(OpId(2)).ok_or(Unavailable)?;
        assert!(d >= due.saturating_add(61_000), "due {d}");
        Ok(())
    }

    /// S9b — spec §10.6 (2), Q304 (EXT3c-1): an operation that waited for an empty `FETCH` and is armed while an operation of its correlation RUNS counts its delay from `now + CONNECT_TIMEOUT_MS` — the running one may still send its command until then; with none running, from `now` or the latest related start, as before; an operation of another correlation does not move it.
    #[test]
    fn deletion_armed_while_a_related_operation_runs_waits_out_the_attempt()
    -> Result<(), Unavailable> {
        let params = Params {
            control_delay_ms: (60_000, 60_000),
            ..Params::default()
        };
        // the second operation's due time after the first (`first`, correlation 7) started at `t0`, the deletion of `q` was
        // queued at `t0 + 1 000` and armed at `t0 + 2 000`; `finish` ends the first before the arming
        let armed =
            |first: (ControlKind, u64), finish: bool| -> Result<(Option<u64>, u64), Unavailable> {
                let (mut rng, mut ops, q) = (TimingRng::seeded(45), ControlOps::new(), QueueId(5));
                let (kind, related) = first;
                ops.schedule(
                    &params,
                    &mut rng,
                    OpId(1),
                    0,
                    spec(kind, related, When::Delayed),
                )?;
                let t0 = ops.due_of(OpId(1)).ok_or(Unavailable)?;
                assert_eq!(ops.take_due(t0).len(), 1);
                let del = spec(ControlKind::QueueDel(q), 7, When::AfterEmptyFetch(q));
                ops.schedule(&params, &mut rng, OpId(2), t0.saturating_add(1_000), del)?;
                if finish {
                    ops.done(OpId(1));
                }
                ops.note_empty_fetch(&params, &mut rng, q, t0.saturating_add(2_000));
                Ok((ops.due_of(OpId(2)), t0))
            };
        let (due, t0) = armed((ControlKind::LinkPut(7), 7), false)?;
        let running = t0.saturating_add(2_000 + 120_000 + 60_000);
        assert_eq!(due, Some(running), "c) a put runs");
        let (due, t0) = armed((ControlKind::LinkPut(7), 7), true)?;
        assert_eq!(due, Some(t0.saturating_add(2_000 + 60_000)), "d) done");
        let (due, t0) = armed((ControlKind::LinkGetOwner(7), 7), false)?;
        assert_eq!(
            due,
            Some(t0.saturating_add(2_000 + 120_000 + 60_000)),
            "e) a query runs"
        );
        let (due, t0) = armed((ControlKind::LinkPut(8), 8), false)?;
        assert_eq!(
            due,
            Some(t0.saturating_add(2_000 + 60_000)),
            "f) an unrelated operation runs"
        );
        Ok(())
    }

    /// UA2 — Q304 (EXT3b-4; V-EXT3b-34 T4-2): with an owner query and a `LINK_PUT` of one link data waiting, ten more puts and a second query add nothing; a query that runs does not absorb its successor.
    #[test]
    fn owner_query_joins_only_a_waiting_query() -> Result<(), Unavailable> {
        let params = Params::default();
        let (mut rng, mut ops) = (TimingRng::seeded(44), ControlOps::new());
        let (query, put) = (
            spec(ControlKind::LinkGetOwner(7), 7, When::Delayed),
            spec(ControlKind::LinkPut(7), 7, When::Delayed),
        );
        ops.schedule(&params, &mut rng, OpId(1), 0, query)?;
        for id in 2..=12_u64 {
            ops.schedule(&params, &mut rng, OpId(id), 0, put)?;
        }
        ops.schedule(&params, &mut rng, OpId(13), 0, query)?;
        assert_eq!(ops.len(), 2);
        let at = ops.due_of(OpId(1)).ok_or(Unavailable)?;
        let started: Vec<OpId> = ops.take_due(at).iter().map(|o| o.id).collect();
        assert_eq!(started, vec![OpId(1)]);
        ops.schedule(&params, &mut rng, OpId(14), at, query)?;
        assert_eq!(ops.len(), 3, "the successor of a running query is queued");
        Ok(())
    }

    /// Q301 sweep: `schedule_drawn` with the delay the caller drew queues exactly what `schedule` of a `When::Delayed`
    /// operation queues, also behind a waiting related operation and after the first one started.
    #[test]
    fn schedule_drawn_is_the_delayed_schedule() -> Result<(), Unavailable> {
        let params = Params::default();
        let (lo, hi) = params.control_delay_ms;
        let (mut a, mut b) = (ControlOps::new(), ControlOps::new());
        let (mut by_rng, mut drawn) = (TimingRng::seeded(9), TimingRng::seeded(9));
        for n in 1..=2_u64 {
            let s = spec(ControlKind::QueueNew(QueueId(1)), 7, When::Delayed);
            a.schedule(&params, &mut by_rng, OpId(n), 0, s)?;
            b.schedule_drawn(OpId(n), 0, s, drawn.uniform(lo, hi)?);
            assert_eq!(a.due_of(OpId(n)), b.due_of(OpId(n)));
        }
        let d = a.due_of(OpId(1)).ok_or(Unavailable)?;
        assert_eq!(a.take_due(d), b.take_due(d));
        assert_eq!(a.due_of(OpId(2)), b.due_of(OpId(2)));
        let d2 = a.due_of(OpId(2)).ok_or(Unavailable)?;
        assert_eq!(a.take_due(d2), b.take_due(d2));
        let s = spec(ControlKind::QueueNew(QueueId(1)), 7, When::Delayed);
        a.schedule(&params, &mut by_rng, OpId(3), 0, s)?;
        b.schedule_drawn(OpId(3), 0, s, drawn.uniform(lo, hi)?);
        assert_eq!(a.due_of(OpId(3)), b.due_of(OpId(3)));
        Ok(())
    }

    /// Q300 (EXT3-4; spec §10.6 (2)): an answered operation, here a prompt one, is due again `U[1 min, 60 min]` after the
    /// latest related start or due time and never overtakes a waiting related one.
    #[test]
    fn answered_error_redues_through_control_delay() -> Result<(), Unavailable> {
        let params = Params::default();
        for seed in 0..200_u64 {
            let mut rng = TimingRng::seeded(seed);
            let mut ops = ControlOps::new();
            ops.schedule(
                &params,
                &mut rng,
                OpId(1),
                0,
                spec(ControlKind::LinkPut(7), 7, When::Prompt),
            )?;
            assert_eq!(ops.take_due(0).len(), 1, "seed {seed}");
            ops.answered(&params, &mut rng, OpId(1), 1_000)?;
            let due = ops.due_of(OpId(1)).ok_or(Unavailable)?;
            assert!(
                (61_000..=3_601_000).contains(&due),
                "seed {seed}: due {due}"
            );
            assert!(
                ops.take_due(due.saturating_sub(1)).is_empty(),
                "seed {seed}: early"
            );
            assert_eq!(ops.take_due(due).len(), 1, "seed {seed}: at due");
            ops.schedule(
                &params,
                &mut rng,
                OpId(2),
                due,
                spec(ControlKind::LinkGetOwner(7), 7, When::Delayed),
            )?;
            let query = ops.due_of(OpId(2)).ok_or(Unavailable)?;
            ops.answered(&params, &mut rng, OpId(1), due.saturating_add(1_000))?;
            let again = ops.due_of(OpId(1)).ok_or(Unavailable)?;
            assert!(
                again >= query.saturating_add(60_000),
                "seed {seed}: again {again}, query {query}"
            );
            assert_eq!(
                ops.take_due(query).first().map(|o| o.id),
                Some(OpId(2)),
                "seed {seed}: the waiting query starts first"
            );
            // M7-S4d (XREVIEW-M7-S4 S4-2 (ii)): the drawn delay is kept — a related start after the answer pushes the
            // answered operation back
            ops.schedule(
                &params,
                &mut rng,
                OpId(3),
                again.saturating_sub(1),
                spec(ControlKind::LinkPut(8), 7, When::Prompt),
            )?;
            let first: Vec<OpId> = ops
                .take_due(again.saturating_sub(1))
                .iter()
                .map(|o| o.id)
                .collect();
            assert_eq!(
                first,
                vec![OpId(3)],
                "seed {seed}: the related prompt op starts"
            );
            let pushed = ops.due_of(OpId(1)).ok_or(Unavailable)?;
            assert!(
                pushed > again,
                "seed {seed}: pushed {pushed}, again {again}"
            );
        }
        Ok(())
    }

    /// EXT3d-1 (HB-64, T8): `take_due(now)` names `now` as the admission time of every operation it takes.
    #[test]
    fn take_due_reports_admission_time() -> Result<(), Unavailable> {
        let params = Params::default();
        let mut rng = TimingRng::seeded(8);
        let mut ops = ControlOps::new();
        ops.schedule(
            &params,
            &mut rng,
            OpId(1),
            100,
            spec(ControlKind::LinkPut(1), 1, When::At(5_000)),
        )?;
        assert!(ops.take_due(4_999).is_empty());
        let due = ops.take_due(7_321);
        assert_eq!(due.len(), 1);
        assert_eq!(due.first().map(|d| d.at), Some(7_321));
        Ok(())
    }
}
