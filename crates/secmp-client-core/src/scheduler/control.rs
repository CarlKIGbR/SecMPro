// SPDX-License-Identifier: AGPL-3.0-or-later
//! `ControlOps` (spec §10.6 (2), `docs/02` §4.4): `QUEUE_NEW`, `QUEUE_DEL`, `LINK_PUT` and owner-status `LINK_GET` each
//! run on their own isolated one-shot link, delayed by `U[1 min, 60 min]` from any related operation — except where a
//! user is waiting (the invitee's consuming `LINK_GET`, the inviter's `LINK_PUT`), which start at once.
//!
//! This module decides *when*; the host runs the operation (it owns the keys and the link data). Delays come from the
//! timing randomness only (CO-08).

use crate::scheduler::core::backoff::reconnect_delay;
use crate::scheduler::params::Params;
use crate::scheduler::types::{ControlKind, OpId, RelayId};
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
}

struct Op {
    id: OpId,
    kind: ControlKind,
    relay: RelayId,
    /// The correlation this operation belongs to (a queue, an invitation, a contact), chosen by the host.
    related: u64,
    due: u64,
    /// The delay drawn for a [`When::Delayed`] operation, until it first starts: it never starts before the latest
    /// related start plus this delay (spec §10.6 (2): `U[1 min, 60 min]` from any related operation, whenever that one
    /// actually ran). `None` for an operation a user waits for or that has its own time, and once it has started.
    delay: Option<u64>,
    running: bool,
    failures: u32,
    closed_before: u32,
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
            .find(|o| o.id == id)
            .map(|o| self.start_not_before(o))
    }

    /// Queue an operation. A delayed one starts `U[1 min, 60 min]` after `max(now, the latest start or due time of an
    /// operation with the same `related`)`: related operations never run within a minute of each other.
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
        let OpSpec {
            kind,
            relay,
            related,
            when,
        } = spec;
        let mut delay = None;
        let due = match when {
            When::Prompt => now,
            When::At(t) => t,
            When::Delayed => {
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
                delay = Some(drawn);
                base.saturating_add(drawn)
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
        });
        Ok(())
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
            .filter(|o| !o.running)
            .map(|o| self.start_not_before(o))
            .min()
    }

    /// The operations that may start at `now`, in queue order; they are marked running. Of several delayed operations
    /// of one correlation that are overdue together, one starts per call: the others are rebased on its start.
    pub fn take_due(&mut self, now: u64) -> Vec<DueOp> {
        let mut out = Vec::new();
        for i in 0..self.ops.len() {
            let Some(op) = self.ops.get(i) else { break };
            if op.running || self.start_not_before(op) > now {
                continue;
            }
            let related = op.related;
            out.push(DueOp {
                id: op.id,
                kind: op.kind,
                relay: op.relay,
            });
            if let Some(op) = self.ops.get_mut(i) {
                op.running = true;
                // a retry after a failure follows the back-off, not the correlation delay
                op.delay = None;
            }
            match self.last_start.iter_mut().find(|(r, _)| *r == related) {
                Some((_, t)) => *t = (*t).max(now),
                None => self.last_start.push((related, now)),
            }
        }
        out
    }

    /// The operation succeeded: it is gone (it ran exactly once).
    pub fn done(&mut self, id: OpId) {
        self.ops.retain(|o| o.id != id);
    }

    /// The operation's link failed before it could run: it is attempted again after the back-off of `closed_before`
    /// consecutive closes before `RELAYINFO` (LR-03), never dropped (CO-06).
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
