// SPDX-License-Identifier: AGPL-3.0-or-later
//! The pure decisions of the scheduler core, small enough for Kani (K-01…K-03, K-C1…K-C6, SC-06…SC-09) and free of
//! I/O, store and codec.

use crate::scheduler::types::{Delivered, SourceError};

/// The most fetched cells above its acknowledgement a recv-queue keeps track of (OQ-20). An honest relay answers a
/// `FETCH` with the lowest cells above the acknowledgement, at most `F_M` = 8 (spec §10.2), so the ledger holds at most
/// eight; the bound only keeps a misbehaving relay from growing it.
pub const RECEIVED_MAX: usize = 64;

/// The fetched cells of a recv-queue above its acknowledgement, ascending by id, each with whether its decision is
/// committed (OQ-20, OPEN-M7-08 A; spec §9.3, CLAUDE.md §1.7). A fixed array of `N` slots, no heap (the Kani harnesses
/// run it with a small `N`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received<const N: usize> {
    ids: [u64; N],
    committed: [bool; N],
    len: usize,
    /// The lowest fetched id that could not be recorded (the ledger was full): the acknowledgement stays below it until
    /// it is recorded.
    floor: Option<u64>,
}

impl<const N: usize> Received<N> {
    /// Nothing fetched.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ids: [0; N],
            committed: [false; N],
            len: 0,
            floor: None,
        }
    }

    /// The recorded ids.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Nothing recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn position(&self, id: u64) -> Option<usize> {
        self.ids.iter().take(self.len).position(|x| *x == id)
    }

    /// `id` is recorded and its decision committed.
    #[must_use]
    pub fn is_committed(&self, id: u64) -> bool {
        self.position(id)
            .and_then(|at| self.committed.get(at))
            .is_some_and(|c| *c)
    }

    /// A recorded decision is not committed yet.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.committed.iter().take(self.len).any(|c| !*c)
    }

    /// Record the fetched `id` with whether its decision is committed (a recorded id stays committed once it is). `false`
    /// if the ledger is full: nothing is recorded, and the acknowledgement stays below `id` until it is.
    pub fn record(&mut self, id: u64, committed: bool) -> bool {
        if let Some(at) = self.position(id) {
            if let Some(c) = self.committed.get_mut(at) {
                *c |= committed;
            }
            return true;
        }
        let Some(grown) = self.len.checked_add(1).filter(|g| *g <= N) else {
            self.floor = Some(self.floor.map_or(id, |f| f.min(id)));
            return false;
        };
        let at = self
            .ids
            .iter()
            .take(self.len)
            .position(|x| *x > id)
            .unwrap_or(self.len);
        let Some(next) = at.checked_add(1) else {
            return false;
        };
        // the ids from `at` on move up one slot (`grown ≤ N`: the last one fits)
        self.ids.copy_within(at..self.len, next);
        self.committed.copy_within(at..self.len, next);
        if let (Some(slot), Some(c)) = (self.ids.get_mut(at), self.committed.get_mut(at)) {
            *slot = id;
            *c = committed;
        }
        self.len = grown;
        if self.floor == Some(id) {
            self.floor = None;
        }
        true
    }

    /// The decision of the recorded `id` is committed now (a later completion). `false` if `id` is not recorded.
    pub fn commit(&mut self, id: u64) -> bool {
        match self.position(id).and_then(|at| self.committed.get_mut(at)) {
            Some(c) => {
                *c = true;
                true
            }
            None => false,
        }
    }

    /// The acknowledgement after `acked`: the highest recorded id `h` such that every recorded id up to `h` is committed
    /// (and `h` is below the floor); the entries up to it are dropped. `acked` itself if the oldest is not committed.
    pub fn advance(&mut self, acked: u64) -> u64 {
        let mut new = acked;
        let mut done = 0_usize;
        for (id, committed) in self.ids.iter().zip(&self.committed).take(self.len) {
            if !*committed || self.floor.is_some_and(|f| *id >= f) {
                break;
            }
            new = *id;
            done = done.saturating_add(1);
        }
        self.ids.copy_within(done..self.len, 0);
        self.committed.copy_within(done..self.len, 0);
        self.len = self.len.saturating_sub(done);
        new
    }
}

impl<const N: usize> Default for Received<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// The receive side of one recv-queue (OQ-20, OPEN-M7-08 A): its cumulative acknowledgement, its generation and the
/// cells fetched above the acknowledgement. The acknowledgement is the highest committed prefix of what was fetched
/// (persist-before-ack, CLAUDE.md §1.7): a cell is acknowledged only once it and every fetched cell below it are
/// committed. A re-creation of the queue (spec §9.1) starts a new generation, and a response asked in an older one
/// changes nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecvLedger<const N: usize> {
    acked: u64,
    generation: u64,
    received: Received<N>,
}

impl<const N: usize> RecvLedger<N> {
    /// A new queue: nothing acknowledged, generation 0.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            acked: 0,
            generation: 0,
            received: Received::new(),
        }
    }

    /// The cumulative acknowledgement (spec §9.3): every cell at or below it is decided and committed.
    #[must_use]
    pub const fn acked(&self) -> u64 {
        self.acked
    }

    /// The generation a request is asked in.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// A fetched cell's decision is not committed yet (the next `FETCH` waits for it until its lead, OPEN-M6-13).
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.received.has_pending()
    }

    /// The fetched cells above the acknowledgement.
    #[must_use]
    pub const fn received(&self) -> &Received<N> {
        &self.received
    }

    /// The cells of a response asked in generation `asked`, in the relay's order: every cell above the acknowledgement
    /// whose decision is not committed yet goes to `deliver` in this one pass (OPEN-M7-08 A: "the core hands every present
    /// cell of a response to the worker at once"); a storage failure stops the pass (the rest comes again); then the
    /// acknowledgement moves to the highest committed prefix. A response of an older generation changes nothing
    /// (`false`).
    pub fn take<C>(
        &mut self,
        asked: u64,
        cells: impl IntoIterator<Item = (u64, C)>,
        mut deliver: impl FnMut(u64, C) -> Result<Delivered, SourceError>,
    ) -> bool {
        if asked != self.generation {
            return false;
        }
        for (id, cell) in cells {
            // at or below the acknowledgement, or committed: decided already (a re-fetch, spec §9.3)
            if id <= self.acked || self.received.is_committed(id) {
                continue;
            }
            let outcome = deliver(id, cell);
            let committed = matches!(outcome, Ok(Delivered::Committed));
            if !self.received.record(id, committed) || outcome.is_err() {
                break;
            }
        }
        self.acked = self.received.advance(self.acked);
        true
    }

    /// The decision of the fetched `id` is committed now (the worker finished it): the acknowledgement moves to the
    /// highest committed prefix. An id that is not recorded (another generation's, or decided already) changes nothing.
    pub fn committed(&mut self, id: u64) {
        if self.received.commit(id) {
            self.acked = self.received.advance(self.acked);
        }
    }

    /// The queue is re-created (spec §9.1): the relay numbers its cells from 1 again; a new generation begins with
    /// nothing acknowledged and nothing fetched.
    pub fn recreate(&mut self) {
        self.acked = 0;
        self.received = Received::new();
        self.generation = self.generation.wrapping_add(1);
    }
}

impl<const N: usize> Default for RecvLedger<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// The response to a request asked for `queue` in `generation` (SC-07): it goes to the recv-queue of that id among
/// `queues`, if that queue still exists — a removed queue's response finds none, and a re-added queue has a new id — and
/// changes it only in that generation ([`RecvLedger::take`]). `false` if it changed nothing.
pub fn take_response<'a, Q: PartialEq, C, const N: usize>(
    queues: impl IntoIterator<Item = (Q, &'a mut RecvLedger<N>)>,
    queue: &Q,
    generation: u64,
    cells: impl IntoIterator<Item = (u64, C)>,
    deliver: impl FnMut(u64, C) -> Result<Delivered, SourceError>,
) -> bool {
    match queues.into_iter().find(|(q, _)| q == queue) {
        Some((_, ledger)) => ledger.take(generation, cells, deliver),
        None => false,
    }
}

/// What the cell source's answer for a send slot leaves to build (persist-before-send, spec §7.5, CLAUDE.md §1.7): the
/// cell if it is ready and its new state was committed; nothing if it is not ready or not persisted — then no frame is
/// built for the slot (SC-08).
#[must_use]
pub fn sendable<T>(answer: Result<Option<T>, SourceError>) -> Option<T> {
    answer.ok().flatten()
}

/// The queue a Balanced slot sends to (spec §10.2): the first queue, from the round-robin pointer `rr`, whose previous
/// `SEND` is at least `P_q` before the slot `slot_ms` (or that was never sent to). `None`: nothing is due, the slot
/// carries a `PING`. `queues` is `(last_send_ms, period_ms)` in the fixed round-robin order.
#[must_use]
pub fn rr_select(rr: usize, queues: &[(Option<u64>, u64)], slot_ms: u64) -> Option<usize> {
    let n = queues.len();
    if n == 0 {
        return None;
    }
    for step in 0..n {
        let at = rr.checked_add(step)?.checked_rem(n)?;
        let (last, period) = queues.get(at).copied()?;
        let due = last.is_none_or(|l| slot_ms.checked_sub(l).is_some_and(|d| d >= period));
        if due {
            return Some(at);
        }
    }
    None
}

/// The choice of a Balanced slot (spec §10.2, SC-09): the index of the queue its `SEND` goes to ([`rr_select`] from the
/// round-robin position `rr`) and the position after it, which the `SEND` commits once it is written — or `None`, a
/// `PING`. Only the schedule enters: the positions, the previous `SEND`s and the slot.
#[must_use]
pub fn send_choice(
    rr: usize,
    queues: &[(Option<u64>, u64)],
    slot_ms: u64,
) -> Option<(usize, usize)> {
    let at = rr_select(rr, queues, slot_ms)?;
    let next = at
        .checked_add(1)
        .and_then(|n| n.checked_rem(queues.len()))
        .unwrap_or(0);
    Some((at, next))
}

/// The time of tick `k`: `t_up + k·period` (K-03). `None` on overflow — never wraps.
#[must_use]
pub fn tick_time(t_up: u64, k: u32, period_ms: u64) -> Option<u64> {
    u64::from(k).checked_mul(period_ms)?.checked_add(t_up)
}

/// The round-robin position the next `SEND` preparation starts from (FIN2-1): the successor the newest still-unwritten
/// `SEND` will commit, else the committed position `committed`. Whether a write completed before or after the
/// preparation never changes the answer. `unwritten` holds, oldest first, each handed-out frame's id and the position it
/// commits when it is completely written (a `SEND`), or `None`.
#[must_use]
pub fn reserved_rr<F>(unwritten: &[(F, Option<usize>)], committed: usize) -> usize {
    unwritten
        .iter()
        .rev()
        .find_map(|(_, n)| *n)
        .unwrap_or(committed)
}

/// A frame is handed to the driver: its id and its commit (the position after a `SEND`, `None` for any other frame) join
/// the ledger. Nothing is committed here (A′: the rotation advances only when a write completes).
pub fn hand_out<F>(unwritten: &mut Vec<(F, Option<usize>)>, frame: F, commits: Option<usize>) {
    unwritten.push((frame, commits));
}

/// The driver reports frame `frame` completely written; frames complete in hand-out order, so it must be the oldest
/// handed-out one: a `SEND`'s position is committed into `rr`. `false` — and nothing changes — on an empty ledger (a
/// report for a frame that was never handed out) or for any other id (a duplicate report, FINAL3 (e)).
pub fn complete_oldest<F: PartialEq>(
    unwritten: &mut Vec<(F, Option<usize>)>,
    rr: &mut usize,
    frame: &F,
) -> bool {
    // a `Vec`, not a `VecDeque`: the ledger holds at most `unwritten_max` entries, and the shift is the cost of nothing
    if unwritten.first().is_none_or(|(oldest, _)| oldest != frame) {
        return false;
    }
    if let (_, Some(n)) = unwritten.remove(0) {
        *rr = n;
    }
    true
}

/// Whether a tick that hands out `adding` frames keeps a ledger of `len` entries within `max` (`unwritten_max`).
#[must_use]
pub const fn ledger_admits(len: usize, adding: usize, max: usize) -> bool {
    len.saturating_add(adding) <= max
}

/// The most frames a link may hold handed out and not yet reported written (`UNWRITTEN_MAX`): a tick carries at most two
/// frames (`SEND` and `FETCH`), and at most `max_in_flight` ticks are outstanding (spec §10.3, `Flight`), so a driver that
/// reports its writes keeps the ledger within `2 · max_in_flight`. A tick that would pass it tears the link down with
/// `Reason::InFlight` — the driver rule "a write still pending at the next tick closes the link" in the core's terms.
#[must_use]
pub fn unwritten_max(max_in_flight: u8) -> usize {
    usize::from(max_in_flight).saturating_mul(2)
}

/// A request whose response is outstanding, as the in-flight rule sees it: the tick it was written at.
pub trait Ticked {
    /// The tick (`k` of the link).
    fn tick(&self) -> u32;
}

impl Ticked for u8 {
    fn tick(&self) -> u32 {
        u32::from(*self)
    }
}

/// The most ticks a link may have outstanding (spec §10.3: "a third tick with two outstanding tears the link down"): the
/// bound of [`InFlight`], whatever larger `max_in_flight` a caller asks for.
pub const IN_FLIGHT_TICKS: u8 = 2;

/// The most requests outstanding on a link: two ticks of at most two requests (a `SEND` and a `FETCH`).
pub const IN_FLIGHT_REQS: usize = 4;

/// The requests of an up link whose responses are outstanding, oldest first, with the count of their ticks (spec §10.3):
/// the transitions `World::tick` makes (a due tick is admitted, its one or two requests join) and `Scheduler::on_frame`
/// makes (a response completes the oldest request; its tick is answered once no request of it is left). A teardown drops
/// it with the up-state; the next connection starts a new one (SC-06). A fixed array of [`IN_FLIGHT_REQS`] slots, no heap:
/// a `Vec` or a `VecDeque` of symbolic length does not finish under Kani over eight transitions (M7 B-SC measurement).
pub struct InFlight<R> {
    flight: Flight,
    reqs: [Option<R>; IN_FLIGHT_REQS],
    len: usize,
}

impl<R: Ticked> InFlight<R> {
    /// Nothing outstanding; at most `max` ticks allowed, and never more than [`IN_FLIGHT_TICKS`].
    #[must_use]
    pub fn new(max: u8) -> Self {
        Self {
            flight: Flight::new(max.min(IN_FLIGHT_TICKS)),
            reqs: core::array::from_fn(|_| None),
            len: 0,
        }
    }

    /// Ticks outstanding.
    #[must_use]
    pub const fn count(&self) -> u8 {
        self.flight.count()
    }

    /// A tick is due: `false` — and nothing changes — if `max` ticks are outstanding (the caller tears the link down
    /// before it writes anything).
    #[must_use]
    pub const fn admit(&mut self) -> bool {
        self.flight.on_tick()
    }

    /// A request of the admitted tick is written. `false` if all [`IN_FLIGHT_REQS`] slots are taken (not reachable: at
    /// most two admitted ticks of at most two requests); the request is then not held, and its response does not match
    /// the oldest request — the link is torn down (`Reason::Rejected`, fail closed).
    #[must_use]
    pub fn push(&mut self, req: R) -> bool {
        let Some(slot) = self.reqs.get_mut(self.len) else {
            return false;
        };
        *slot = Some(req);
        self.len = self.len.saturating_add(1);
        true
    }

    /// The oldest outstanding request (the one the next response answers).
    #[must_use]
    pub fn front(&self) -> Option<&R> {
        self.iter().next()
    }

    /// The outstanding requests, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &R> {
        self.reqs.iter().take(self.len).flatten()
    }

    /// The response of the oldest request is complete: it leaves (the younger ones move up a slot), and its tick is
    /// answered once no request of that tick is left.
    pub fn complete(&mut self) -> Option<R> {
        if self.len == 0 {
            return None;
        }
        let req = self.reqs.first_mut()?.take()?;
        self.reqs.rotate_left(1);
        self.len = self.len.saturating_sub(1);
        if !self.iter().any(|o| o.tick() == req.tick()) {
            self.flight.on_response();
        }
        Some(req)
    }

    /// The link is torn down: every outstanding request is handed back, oldest first.
    pub fn drain(&mut self) -> impl Iterator<Item = R> + '_ {
        self.len = 0;
        self.reqs.iter_mut().filter_map(Option::take)
    }
}

/// Ticks whose responses are outstanding (spec §10.3): a third tick with two outstanding tears the link down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flight {
    count: u8,
    max: u8,
}

impl Flight {
    /// No tick outstanding; at most `max` allowed.
    #[must_use]
    pub const fn new(max: u8) -> Self {
        Self { count: 0, max }
    }

    /// Ticks outstanding.
    #[must_use]
    pub const fn count(&self) -> u8 {
        self.count
    }

    /// A tick is due: `false` (and nothing changes) if `max` ticks are already outstanding — the caller tears the link
    /// down before writing anything.
    #[must_use]
    pub const fn on_tick(&mut self) -> bool {
        if self.count >= self.max {
            return false;
        }
        self.count = self.count.saturating_add(1);
        true
    }

    /// The responses of the oldest outstanding tick are complete.
    pub const fn on_response(&mut self) {
        self.count = self.count.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rr_walks_from_the_pointer_and_pings_when_nothing_is_due() {
        let q = [(Some(0), 10), (None, 40), (Some(5), 40)];
        assert_eq!(rr_select(0, &q, 10), Some(0));
        assert_eq!(rr_select(1, &q, 10), Some(1));
        assert_eq!(rr_select(2, &q, 10), Some(0));
        let none = [(Some(0), 10), (Some(5), 40)];
        assert_eq!(rr_select(0, &none, 5), None);
        assert_eq!(rr_select(0, &[], 5), None);
    }

    /// SC-09 (unit): the choice of a Balanced slot and the position after it, wrapping at the end of the order.
    #[test]
    fn send_choice_names_the_queue_and_the_next_position() {
        let q = [(Some(0), 10), (None, 40), (Some(5), 40)];
        assert_eq!(send_choice(0, &q, 10), Some((0, 1)));
        assert_eq!(send_choice(2, &q, 10), Some((0, 1)));
        assert_eq!(send_choice(1, &q, 10), Some((1, 2)));
        let last = [(Some(0), 40), (Some(0), 40), (None, 40)];
        assert_eq!(send_choice(0, &last, 10), Some((2, 0)), "wraps");
        assert_eq!(send_choice(0, &[(Some(0), 10)], 5), None);
    }

    #[test]
    fn tick_time_never_wraps() {
        assert_eq!(tick_time(5, 3, 10), Some(35));
        assert_eq!(tick_time(u64::MAX, 1, 10), None);
        assert_eq!(tick_time(0, u32::MAX, u64::MAX), None);
    }

    #[test]
    fn unwritten_max_is_twice_the_ticks_in_flight() {
        assert_eq!(unwritten_max(2), 4);
        assert_eq!(unwritten_max(0), 0);
        assert_eq!(unwritten_max(u8::MAX), 510);
    }

    /// What a test cell source answers for one fetched id.
    fn answer(c: u8) -> Result<Delivered, SourceError> {
        match c {
            b'C' => Ok(Delivered::Committed),
            b'P' => Ok(Delivered::Pending),
            _ => Err(SourceError),
        }
    }

    /// `take` over `(id, answer)` pairs; returns the ids handed to the cell source.
    fn take<const N: usize>(l: &mut RecvLedger<N>, asked: u64, cells: &[(u64, u8)]) -> Vec<u64> {
        let mut handed = Vec::new();
        let applied = l.take(asked, cells.iter().copied(), |id, c| {
            handed.push(id);
            answer(c)
        });
        assert_eq!(applied, asked == l.generation());
        handed
    }

    /// SC-02 (unit): commits in the order 1, 3, 2 — the acknowledgement is 1, stays 1 after 3, and is 3 once 2 is
    /// committed; every present cell is handed over in one pass.
    #[test]
    fn ack_is_the_highest_committed_prefix() {
        let mut l: RecvLedger<8> = RecvLedger::new();
        assert_eq!(
            take(&mut l, 0, &[(1, b'P'), (2, b'P'), (3, b'P')]),
            [1, 2, 3]
        );
        assert_eq!(l.acked(), 0);
        assert!(l.has_pending());
        l.committed(1);
        assert_eq!(l.acked(), 1);
        l.committed(3);
        assert_eq!(l.acked(), 1, "3 is committed, 2 is not");
        l.committed(2);
        assert_eq!(l.acked(), 3);
        assert!(!l.has_pending());
        assert!(l.received().is_empty());
        // a report for a cell the ledger does not hold changes nothing
        l.committed(9);
        assert_eq!(l.acked(), 3);
    }

    /// A re-fetch: cells at or below the acknowledgement and committed cells are not handed over again; pending ones are
    /// (the facade dedups its jobs); synchronous commits acknowledge at once; ids may have gaps.
    #[test]
    fn refetch_hands_over_only_what_is_not_committed() {
        let mut l: RecvLedger<8> = RecvLedger::new();
        assert_eq!(
            take(&mut l, 0, &[(2, b'C'), (4, b'P'), (7, b'C')]),
            [2, 4, 7]
        );
        assert_eq!(l.acked(), 2, "4 is pending");
        assert_eq!(
            take(&mut l, 0, &[(2, b'C'), (4, b'P'), (7, b'C'), (8, b'C')]),
            [4, 8]
        );
        assert_eq!(l.acked(), 2);
        assert_eq!(take(&mut l, 0, &[(4, b'C'), (7, b'C'), (8, b'C')]), [4]);
        assert_eq!(l.acked(), 8);
    }

    /// A storage failure stops the pass: the failed cell blocks the acknowledgement, the rest of the response is not handed
    /// over; the next response hands it over again.
    #[test]
    fn a_storage_failure_stops_the_pass_and_blocks_the_ack() {
        let mut l: RecvLedger<8> = RecvLedger::new();
        assert_eq!(take(&mut l, 0, &[(1, b'C'), (2, b'E'), (3, b'C')]), [1, 2]);
        assert_eq!(l.acked(), 1);
        assert!(l.has_pending());
        assert_eq!(take(&mut l, 0, &[(2, b'C'), (3, b'C')]), [2, 3]);
        assert_eq!(l.acked(), 3);
    }

    /// SC-07 (unit): a response asked in an older generation changes nothing; the re-creation starts from nothing.
    #[test]
    fn an_old_generation_changes_nothing() {
        let mut l: RecvLedger<8> = RecvLedger::new();
        assert_eq!(take(&mut l, 0, &[(1, b'C'), (2, b'P')]), [1, 2]);
        l.recreate();
        assert_eq!((l.acked(), l.generation()), (0, 1));
        assert!(l.received().is_empty());
        let before = l.clone();
        assert!(take(&mut l, 0, &[(1, b'C'), (5, b'C')]).is_empty());
        assert_eq!(l, before);
        // the old generation's pending cell 2 is not held any more
        l.committed(2);
        assert_eq!(l, before);
        assert_eq!(take(&mut l, 1, &[(1, b'C')]), [1]);
        assert_eq!(l.acked(), 1);
    }

    /// SC-07 (unit): a response goes to the queue of its id, in its generation; a removed queue's response finds none.
    #[test]
    fn take_response_finds_the_queue_and_its_generation() {
        let (mut a, mut b): (RecvLedger<4>, RecvLedger<4>) = (RecvLedger::new(), RecvLedger::new());
        let deliver = |_: u64, (): ()| Ok(Delivered::Committed);
        assert!(take_response(
            [(1_u32, &mut a), (2, &mut b)],
            &2,
            0,
            [(5, ())],
            deliver
        ));
        assert_eq!((a.acked(), b.acked()), (0, 5));
        assert!(!take_response([(1_u32, &mut a)], &2, 0, [(6, ())], deliver));
        assert!(!take_response([(1_u32, &mut a)], &1, 1, [(6, ())], deliver));
        assert_eq!((a.acked(), b.acked()), (0, 5));
    }

    /// SC-08 (unit): only a persisted cell is sent.
    #[test]
    fn only_a_persisted_cell_is_sendable() {
        assert_eq!(sendable(Ok(Some(3))), Some(3));
        assert_eq!(sendable::<u8>(Ok(None)), None);
        assert_eq!(sendable::<u8>(Err(SourceError)), None);
    }

    /// The ledger bound: a full ledger records nothing more and keeps the acknowledgement below the first id it could not
    /// record, until that id is recorded.
    #[test]
    fn a_full_ledger_keeps_the_ack_below_what_it_could_not_record() {
        let mut r: Received<2> = Received::new();
        assert!(r.record(5, true));
        assert!(r.record(9, false));
        assert!(!r.record(7, true), "full");
        assert_eq!(r.len(), 2);
        assert_eq!(r.advance(0), 5);
        assert!(r.commit(9));
        assert_eq!(r.advance(5), 5, "9 is above the unrecorded 7");
        assert!(r.record(7, true));
        assert_eq!(r.advance(5), 9);
        assert!(r.is_empty());
        // insertion keeps the ids ascending; a recorded id stays committed
        assert!(r.record(12, false));
        assert!(r.record(11, true));
        assert!(r.record(11, false));
        assert!(r.is_committed(11) && !r.is_committed(12));
        assert_eq!(r.advance(10), 11);
        assert!(!r.commit(11), "dropped");
        assert_eq!(Received::<2>::default(), Received::<2>::new());
        assert_eq!(RecvLedger::<2>::default(), RecvLedger::<2>::new());
    }

    /// SC-06 (unit): the in-flight count is the number of ticks with an outstanding request — a tick of two requests is
    /// answered by its second response; a third tick is refused; a teardown hands every request back.
    #[test]
    fn in_flight_counts_ticks_not_requests() {
        let mut f: InFlight<u8> = InFlight::new(2);
        assert!(f.admit());
        assert!(f.push(1));
        assert!(f.push(1));
        assert!(f.admit());
        assert!(f.push(2));
        assert!(!f.admit(), "a third tick");
        assert_eq!(f.count(), 2);
        assert_eq!(f.front(), Some(&1));
        assert_eq!(f.complete(), Some(1));
        assert_eq!(f.count(), 2, "the second request of tick 1 is outstanding");
        assert_eq!(f.complete(), Some(1));
        assert_eq!(f.count(), 1);
        assert_eq!(f.iter().copied().collect::<Vec<_>>(), [2]);
        assert_eq!(f.drain().collect::<Vec<_>>(), [2]);
        assert_eq!(f.complete(), None);
        assert_eq!(f.front(), None);
        assert_eq!(Ticked::tick(&7_u8), 7);
        // four slots: a fifth request is refused; a larger max is clamped to two ticks
        let mut g: InFlight<u8> = InFlight::new(9);
        assert!(g.admit() && g.admit() && !g.admit());
        assert!((1..=4).all(|t| g.push(t)));
        assert!(!g.push(5));
        assert_eq!(g.iter().copied().collect::<Vec<_>>(), [1, 2, 3, 4]);
    }

    #[test]
    fn flight_allows_two() {
        let mut f = Flight::new(2);
        assert!(f.on_tick());
        assert!(f.on_tick());
        assert!(!f.on_tick());
        assert_eq!(f.count(), 2);
        f.on_response();
        assert!(f.on_tick());
        f.on_response();
        f.on_response();
        f.on_response();
        assert_eq!(f.count(), 0);
    }
}
