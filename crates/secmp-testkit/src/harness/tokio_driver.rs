// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The parts the tokio driver (`secmp_client_core::scheduler::run`) needs in a test (TEST-SPEC-M6 AD-10, the driver
//! obligations, the tokio repeats of AI-01…AI-06): a one-relay [`TestDirectory`], deterministic [`TestHandshakes`], a
//! [`TestControl`] runner that mirrors the virtual driver's control operations, and a [`CostedWorker`] that models the
//! cost of the cell source in virtual time (`tokio::time::pause`): a job's result arrives after its modelled cost.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use secmp_client_core::scheduler::run::{
    ControlEffect, ControlRunner, Directory, HandshakeEntropy, Job, JobDone, Worker,
};
use secmp_client_core::scheduler::types::{ControlKind, OpId, RelayId};
use secmp_crypto::SecretBytes;
use secmp_proto::link::ids::AccessKey;
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::inv::RelayRef;
use secmp_transport::driver::{AsyncQueueTransport, AsyncRelayQueueTransport, ProviderStream};
use secmp_transport::{Error as TransportError, LinkGetMode, RecvCap};

use super::driver::{Convs, Costs, LinkMaterial};
use super::entropy::EntropyPool;

/// One relay, `RelayId(0)`.
pub struct TestDirectory {
    relay: RelayRef,
    access: AccessKey,
}

impl TestDirectory {
    /// The directory of one relay.
    #[must_use]
    pub const fn new(relay: RelayRef, access: AccessKey) -> Self {
        Self { relay, access }
    }
}

impl Directory for TestDirectory {
    fn relay(&self, relay: RelayId) -> Option<&RelayRef> {
        (relay == RelayId(0)).then_some(&self.relay)
    }

    fn access_key(&self, relay: RelayId) -> Option<&AccessKey> {
        (relay == RelayId(0)).then_some(&self.access)
    }
}

/// Handshake randomness from a deterministic stream: connection `k` draws the `k`-th block.
pub struct TestHandshakes {
    pool: EntropyPool,
}

impl TestHandshakes {
    /// The handshakes of the stream (`suite`, `index`).
    #[must_use]
    pub fn new(suite: &str, index: u32) -> Self {
        Self {
            pool: EntropyPool::new(suite, index),
        }
    }
}

impl HandshakeEntropy for TestHandshakes {
    type E = FixedEntropy;

    fn next(&mut self) -> FixedEntropy {
        FixedEntropy::new(&self.pool.bytes(1 << 13))
    }
}

/// The key material the control runner needs (as the virtual driver's `Material` and `LinkMaterial`).
#[derive(Default)]
pub struct ControlMaterial {
    /// `(recv seed, send seed)` by queue id.
    pub queues: BTreeMap<u32, ([u8; 32], [u8; 32])>,
    /// Link data by number.
    pub links: BTreeMap<u32, LinkMaterial>,
    /// Owner-status answers: link data, present, consumed.
    pub link_status: Vec<(u32, bool, bool)>,
    /// Control operations completed, with their kind.
    pub done: Vec<ControlKind>,
}

/// The control runner (as the virtual driver's `run_control`); queue seeds of new pool queues come from `seeds`.
pub struct TestControl {
    access: AccessKey,
    seeds: Mutex<EntropyPool>,
    /// The material and what the operations reported.
    pub material: Arc<Mutex<ControlMaterial>>,
}

impl TestControl {
    /// A runner with the relay's access key; new queue seeds from the stream (`suite`, `index`).
    #[must_use]
    pub fn new(access: AccessKey, suite: &str, index: u32) -> Self {
        Self {
            access,
            seeds: Mutex::new(EntropyPool::new(suite, index)),
            material: Arc::new(Mutex::new(ControlMaterial::default())),
        }
    }
}

fn seed32(bytes: &[u8; 32]) -> SecretBytes<32> {
    SecretBytes::from_slice(bytes).unwrap()
}

impl ControlRunner for TestControl {
    async fn run<S: ProviderStream>(
        &self,
        _op: OpId,
        kind: ControlKind,
        relay: RelayId,
        t: &mut AsyncRelayQueueTransport<S>,
    ) -> Result<ControlEffect, TransportError> {
        let effect = match kind {
            ControlKind::QueueNew(queue) => {
                let known = self.material.lock().unwrap().queues.get(&queue.0).copied();
                let (recv, send) = known.unwrap_or_else(|| {
                    let mut pool = self.seeds.lock().unwrap();
                    let m: ([u8; 32], [u8; 32]) = (
                        pool.bytes(32).try_into().unwrap(),
                        pool.bytes(32).try_into().unwrap(),
                    );
                    self.material.lock().unwrap().queues.insert(queue.0, m);
                    m
                });
                let (rc, _) = t
                    .create_queue(&seed32(&recv), &seed32(&send), &self.access)
                    .await?;
                ControlEffect::PoolQueueReady(queue, rc)
            }
            ControlKind::QueueDel(queue) => {
                let (recv, _) = *self
                    .material
                    .lock()
                    .unwrap()
                    .queues
                    .get(&queue.0)
                    .ok_or(TransportError::Invalid)?;
                let cap = RecvCap::from_seed(&seed32(&recv))?;
                t.delete_queue(&cap).await?;
                ControlEffect::None
            }
            ControlKind::LinkPut(n) => {
                let (ld, owner, blob, one_time, expires) = {
                    let m = self.material.lock().unwrap();
                    let l = m.links.get(&n).ok_or(TransportError::Invalid)?;
                    (
                        l.ld_id,
                        l.owner_seed,
                        l.blob.clone(),
                        l.one_time,
                        l.expires_bucket,
                    )
                };
                let blob = <secmp_proto::wire::inv::LinkBlob as secmp_proto::Decode>::decode(&blob)
                    .map_err(|_| TransportError::Invalid)?;
                t.put_link_data(ld, &seed32(&owner), &blob, one_time, expires, &self.access)
                    .await?;
                ControlEffect::None
            }
            ControlKind::LinkGetOwner(n) => {
                let (ld, owner) = {
                    let m = self.material.lock().unwrap();
                    let l = m.links.get(&n).ok_or(TransportError::Invalid)?;
                    (l.ld_id, l.owner_seed)
                };
                let owner = seed32(&owner);
                let got = t
                    .get_link_data(ld, LinkGetMode::OwnerStatus(&owner))
                    .await?;
                self.material
                    .lock()
                    .unwrap()
                    .link_status
                    .push((n, got.present, got.consumed));
                ControlEffect::OwnerStatus {
                    relay,
                    ld: n,
                    present: got.present,
                    consumed: got.consumed,
                    expired: false,
                }
            }
            ControlKind::LinkGetConsume(n) => {
                let ld = {
                    let m = self.material.lock().unwrap();
                    m.links.get(&n).ok_or(TransportError::Invalid)?.ld_id
                };
                t.get_link_data(ld, LinkGetMode::Consume).await?;
                ControlEffect::None
            }
        };
        self.material.lock().unwrap().done.push(kind);
        Ok(effect)
    }
}

/// One job the costed worker ran: virtual start, end, kind (`P` prepare real, `p` prepare dummy, `-` prepare not
/// ready, `D` deliver, `N` notification).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobRecord {
    /// When the worker took the job.
    pub start: u64,
    /// When its result went back to the driver.
    pub end: u64,
    /// What it was.
    pub kind: u8,
}

/// The worker of the tests: runs each job on the shared conversations and returns its result after the job's modelled
/// cost in virtual time (VD-M6-A-13: a real cell 20 ms, a dummy 1 ms, a received cell 5 ms in the AI repeats).
pub struct CostedWorker {
    convs: Arc<Mutex<Convs>>,
    costs: Costs,
    clock: secmp_client_core::clock::TokioClock,
    /// The modelled work done in all (virtual milliseconds).
    pub work_total: Arc<AtomicU64>,
    /// Every job, in order.
    pub log: Arc<Mutex<Vec<JobRecord>>>,
    /// Hold the preparation of cells back: a `Prepare` is "not ready".
    pub block_prepare: Arc<std::sync::atomic::AtomicBool>,
}

impl CostedWorker {
    /// A worker over `convs` with `costs`.
    #[must_use]
    pub fn new(
        convs: Arc<Mutex<Convs>>,
        costs: Costs,
        clock: secmp_client_core::clock::TokioClock,
    ) -> Self {
        Self {
            convs,
            costs,
            clock,
            work_total: Arc::new(AtomicU64::new(0)),
            log: Arc::new(Mutex::new(Vec::new())),
            block_prepare: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

impl Worker for CostedWorker {
    async fn run(&mut self, job: Job) -> JobDone {
        use secmp_client_core::clock::Clock;
        let start = self.clock.mono_ms();
        let (done, cost, kind) = {
            let mut convs = self.convs.lock().unwrap();
            match &job {
                Job::Prepare { queue, .. } => {
                    if self.block_prepare.load(Ordering::SeqCst) {
                        (
                            JobDone::Prepared {
                                queue: *queue,
                                cell: Ok(None),
                            },
                            0,
                            b'-',
                        )
                    } else {
                        let real = convs.pending_real(*queue);
                        let done = job.apply(&mut *convs);
                        let made = matches!(
                            done,
                            JobDone::Prepared {
                                cell: Ok(Some(_)),
                                ..
                            }
                        );
                        let (cost, kind) = match (made, real) {
                            (false, _) => (0, b'-'),
                            (true, true) => (self.costs.prepare_real, b'P'),
                            (true, false) => (self.costs.prepare_dummy, b'p'),
                        };
                        (done, cost, kind)
                    }
                }
                Job::Deliver { .. } => (job.apply(&mut *convs), self.costs.receive, b'D'),
                _ => (job.apply(&mut *convs), 0, b'N'),
            }
        };
        if cost > 0 {
            tokio::time::sleep(Duration::from_millis(cost)).await;
        }
        self.work_total.fetch_add(cost, Ordering::SeqCst);
        self.log.lock().unwrap().push(JobRecord {
            start,
            end: self.clock.mono_ms(),
            kind,
        });
        done
    }
}
