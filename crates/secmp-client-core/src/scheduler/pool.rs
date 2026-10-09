// SPDX-License-Identifier: AGPL-3.0-or-later
//! `QueuePool` (spec §10.6 (3)): at least two pre-created, spare recv-queues per relay, so that creating or accepting an
//! invitation never needs a `QUEUE_NEW` at that moment. A spare queue is fetched at its period like any queue (so it
//! never reaches `QUEUE_IDLE_TTL`); the creations are control operations with their own delays.
//!
//! This module only counts and remembers; the [`crate::scheduler::core::Scheduler`] queues the control operations and
//! registers the created queues.

use crate::scheduler::types::{QueueId, RelayId};

struct PoolRelay {
    relay: RelayId,
    spares: Vec<QueueId>,
    pending: Vec<QueueId>,
}

/// The spare queues of every managed relay.
pub struct QueuePool {
    target: usize,
    relays: Vec<PoolRelay>,
}

impl QueuePool {
    /// A pool that keeps `target` spares per managed relay.
    #[must_use]
    pub const fn new(target: usize) -> Self {
        Self {
            target,
            relays: Vec::new(),
        }
    }

    /// Keep spares on `relay` from now on.
    pub fn manage(&mut self, relay: RelayId) {
        if !self.relays.iter().any(|r| r.relay == relay) {
            self.relays.push(PoolRelay {
                relay,
                spares: Vec::new(),
                pending: Vec::new(),
            });
        }
    }

    /// The relays that are short of spares, with the number of creations missing (spares and creations under way
    /// counted).
    #[must_use]
    pub fn missing(&self) -> Vec<(RelayId, usize)> {
        self.relays
            .iter()
            .filter_map(|r| {
                let have = r.spares.len().saturating_add(r.pending.len());
                let need = self.target.saturating_sub(have);
                (need > 0).then_some((r.relay, need))
            })
            .collect()
    }

    /// A creation was queued for `queue`.
    pub fn creating(&mut self, relay: RelayId, queue: QueueId) {
        if let Some(r) = self.relays.iter_mut().find(|r| r.relay == relay) {
            r.pending.push(queue);
        }
    }

    /// The creation of `queue` succeeded: it is a spare. Returns its relay.
    pub fn created(&mut self, queue: QueueId) -> Option<RelayId> {
        let r = self.relays.iter_mut().find(|r| r.pending.contains(&queue))?;
        r.pending.retain(|q| *q != queue);
        r.spares.push(queue);
        Some(r.relay)
    }

    /// Hand out the oldest spare of `relay`.
    pub fn take(&mut self, relay: RelayId) -> Option<QueueId> {
        let r = self.relays.iter_mut().find(|r| r.relay == relay)?;
        if r.spares.is_empty() {
            None
        } else {
            Some(r.spares.remove(0))
        }
    }

    /// Spares on `relay`.
    #[must_use]
    pub fn spares(&self, relay: RelayId) -> usize {
        self.relays
            .iter()
            .find(|r| r.relay == relay)
            .map_or(0, |r| r.spares.len())
    }

    /// The relay whose creation of `queue` is under way.
    #[must_use]
    pub fn pending_relay(&self, queue: QueueId) -> Option<RelayId> {
        self.relays
            .iter()
            .find(|r| r.pending.contains(&queue))
            .map(|r| r.relay)
    }

    /// Whether `queue` is a spare.
    #[must_use]
    pub fn is_spare(&self, queue: QueueId) -> bool {
        self.relays.iter().any(|r| r.spares.contains(&queue))
    }
}
