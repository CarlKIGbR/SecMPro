// SPDX-License-Identifier: AGPL-3.0-or-later
//! The host runtime (M7 Phase C, `docs/02` §4.4): the pieces a host needs to run the client for real — the store-backed
//! [`Hub`] behind a mutex as the scheduler's cell source, the tokio [`Driver`] over the transport providers (Tor, or direct
//! TLS only when the user chose it, spec §8.1, CLAUDE.md §1.5), the control runner that carries out the hub's one-shot
//! operations, and the loop that connects them. A host (`secmp-cli`) gets a [`Client`] to call and a [`Serve`] to run.
//!
//! **What the loop does.** It runs the driver in chunks of [`CHUNK_MS`]; between two chunks, under the hub's lock, it works
//! on what the sessions delivered ([`Hub::pump`]), lets time pass for the hub ([`Hub::tick`]), takes the hub's actions and
//! the core's control operations and hands them to the scheduler (as the testkit's `VirtualDriver` does), forwards the
//! events and answers the queued calls. A call never runs inside a chunk and reaches the scheduler only through actions: the
//! frames a client emits depend on the mode, the periods, the set of links and the phases fixed at link start — never on
//! what the user types (spec §10.1). Cells are prepared and persisted only by the driver's worker (`prepare_cell`,
//! `deliver`: persist-before-send and persist-before-ack, CLAUDE.md §1.7).
//!
//! **The spare pool (D4′).** The stored spares (`relays.pool`) are the scheduler pool's: adopted at start, created by the
//! scheduler's own delayed `QUEUE_NEW` (spec §10.6 (2), (3)), their seeds made durable by [`Hub::pool_material`] before the
//! request leaves; an invitation or a rotation hands a named spare out ([`Action::TakeSpare`]).

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use secmp_crypto::{SecretBytes, Zeroizing};
use secmp_proto::link::ids::AccessKey;
use secmp_proto::wire::inv::{LinkBlob, Profile as WireProfile, RelayRef};
use secmp_proto::wire::{Id, Period};
use secmp_proto::{Decode as _, Encode as _};
use secmp_transport::driver::{AsyncQueueTransport, AsyncRelayQueueTransport, ProviderStream};
use secmp_transport::tls::TlsProvider;
use secmp_transport::tor::arti;
use secmp_transport::{Error as TransportError, LinkGetMode, RecvCap};
use tokio::sync::{mpsc, oneshot};

use crate::api::{ContactId, Core, Error, Event, Request, Response, Stamped};
use crate::clock::{Clock, SystemClock, TokioClock};
use crate::hub::{Action, Hub, HubConfig};
use crate::profile::Profile;
use crate::scheduler::core::Scheduler;
use crate::scheduler::params::{Mode, Params};
use crate::scheduler::run::{
    BlockingWorker, ControlEffect, ControlRunner, Directory, Driver, Only, OsHandshakes, Providers,
};
use crate::scheduler::types::{
    CellSource, CellToken, ControlKind, Delivered, OpId, PreparedCell, QueueId, RelayId,
    SendFailure, SourceError, Transport,
};
use crate::sessions::actor::{EntropySource as _, OsSource};
use crate::timing::TimingRng;

/// The step of the loop: how long the driver runs between two visits to the hub (spec §10.1 does not depend on it).
pub const CHUNK_MS: u64 = 1_000;

/// The relay rows a profile may hold that the runtime looks for.
const RELAY_ROWS: u32 = 16;

/// What the host chose.
pub struct RuntimeConfig {
    /// Direct TLS instead of Tor: only on the user's explicit request (spec §5.3, §8.1). Implies Balanced.
    pub direct: bool,
    /// The name presented to a contact in a handshake (not stored).
    pub name: String,
}

/// What a host asks of the runtime.
#[non_exhaustive]
pub enum Call {
    /// A request of the core's API.
    Core(Request),
    /// Issue an invitation that expires in `expires_s` seconds.
    InviteCreate {
        /// Seconds from now (at most 30 days, spec §5.2).
        expires_s: u64,
    },
    /// Accept the invitation `uri`.
    InviteAccept {
        /// The URI (a secret).
        uri: Zeroizing<String>,
    },
    /// Shut the runtime down.
    Quit,
}

impl core::fmt::Debug for Call {
    /// The variant name only (CLAUDE.md §1.6).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Core(_) => "Core",
            Self::InviteCreate { .. } => "InviteCreate",
            Self::InviteAccept { .. } => "InviteAccept",
            Self::Quit => "Quit",
        })
    }
}

/// The answer to a [`Call`].
#[non_exhaustive]
pub enum Answer {
    /// The answer of the core.
    Core(Response),
    /// The invitation issued (a secret).
    Invitation {
        /// Its URI.
        uri: Zeroizing<String>,
    },
    /// The accept is under way: [`Event::ContactAdded`] or [`Event::InviteFailed`] follows.
    Accepting,
    /// The pool has no spare queue (spec §10.6 (3)): the first spares of a profile are created at random times after its
    /// first open, so an invitation has to wait for them.
    PoolEmpty,
    /// The runtime has shut down.
    Closed,
}

impl core::fmt::Debug for Answer {
    /// The variant name only (CLAUDE.md §1.6).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Core(_) => "Core",
            Self::Invitation { .. } => "Invitation",
            Self::Accepting => "Accepting",
            Self::PoolEmpty => "PoolEmpty",
            Self::Closed => "Closed",
        })
    }
}

/// What the runtime reports besides answers.
#[derive(Debug)]
#[non_exhaustive]
pub enum Notice {
    /// An event of the core.
    Event(Stamped),
    /// The hub could not work on what the sessions delivered (the store); the next chunk tries again (RJ semantics).
    Unavailable,
    /// The scheduler refused something the hub asked for (a queue it could not add or hand out); the queue stays as it was.
    Refused,
    /// The loop has stopped for good (no randomness: fail closed, nothing more is sent); no [`Answer::Closed`] follows.
    Stopped,
}

/// Whether `Call::Core` may carry `request`: the loop runs a call between two chunks of the schedule, under the hub's lock, so
/// only requests that take milliseconds are admitted (CLAUDE.md §1.4). `Request::Export` runs Argon2id (`PROFILE`, 256 MiB)
/// and writes a file under the store's lock: refused here (`Error::Unsupported`); a host exports off the loop.
/// Exhaustive on purpose: a new `Request` variant must be classified.
#[must_use]
pub const fn admitted(request: &Request) -> bool {
    match request {
        Request::Contacts
        | Request::SafetyNumber { .. }
        | Request::Verify { .. }
        | Request::Settings
        | Request::RelayView { .. }
        | Request::Send { .. }
        | Request::Message { .. }
        | Request::Reveal { .. }
        | Request::Rotate { .. }
        | Request::ResetSession { .. }
        | Request::Remove { .. }
        | Request::SetSettings(_)
        | Request::RotateIdentity => true,
        Request::Export { .. } => false,
    }
}

/// What a take of a spare came to.
#[derive(Debug, PartialEq, Eq)]
enum TakeStep {
    /// Handed out.
    Done,
    /// The spare's `QUEUE_NEW` is still running: its registration follows, the hand-out then (no cap: it ends with the
    /// creation).
    Retry,
    /// The scheduler refused, or does not hold the queue and is not creating it: nobody is waiting for it any more.
    Refused,
}

fn take_step(
    result: Result<Option<QueueId>, crate::scheduler::core::SchedError>,
    pending: bool,
) -> TakeStep {
    match result {
        Ok(Some(_)) => TakeStep::Done,
        Ok(None) if pending => TakeStep::Retry,
        Ok(None) | Err(_) => TakeStep::Refused,
    }
}

/// The scheduler view the core is left with at the start: what the hub keeps of the recv-queue periods (`Hub::sync_view`,
/// the rate bound of a rotation, spec §10.2) and the transport the user chose.
fn start_view<C: Clock, S: crate::sessions::actor::EntropySource>(
    core: &mut Core<C, S>,
    direct: bool,
) {
    core.view.direct = direct;
}

/// A `SetSettings` and what it means for the scheduler: the settings are stored, then a changed mode is set on the scheduler
/// (direct implies Balanced); a refusal (the recv-queues do not fit the mode, spec §10.2) is the call's error and the settings
/// are put back — the store and the scheduler never disagree. `store` stores and returns the previous settings, `restore` puts
/// them back.
fn switch_settings<S: CellSource>(
    sched: &mut Scheduler,
    (now, source): (u64, &mut S),
    new: crate::settings::Settings,
    store: impl FnOnce(crate::settings::Settings) -> Result<crate::settings::Settings, Error>,
    restore: impl FnOnce(crate::settings::Settings),
) -> Result<Vec<crate::scheduler::types::Output>, Error> {
    let previous = store(new)?;
    if previous.mode == new.mode {
        return Ok(Vec::new());
    }
    sched.set_mode(now, new.mode, source).map_err(|_| {
        restore(previous);
        Error::Unsupported
    })
}

type Envelope = (Call, oneshot::Sender<Result<Answer, Error>>);

/// A cheap handle that sends calls to the runtime's loop (several tasks of a host may each hold one).
#[derive(Clone)]
pub struct Caller(mpsc::UnboundedSender<Envelope>);

impl Caller {
    /// Send a call and wait for its one answer (it comes between two chunks of the loop, at most [`CHUNK_MS`] later).
    ///
    /// # Errors
    /// The call's refusal; [`Error::Unavailable`] if the loop has ended.
    pub async fn call(&self, call: Call) -> Result<Answer, Error> {
        let (reply, answer) = oneshot::channel();
        self.0.send((call, reply)).map_err(|_| Error::Unavailable)?;
        answer.await.map_err(|_| Error::Unavailable)?
    }
}

/// The handle of a host: calls go to the runtime's loop, notices come back on a stream.
pub struct Client {
    calls: Caller,
    notices: mpsc::UnboundedReceiver<Notice>,
}

impl Client {
    /// Send a call and wait for its one answer (see [`Caller::call`]).
    ///
    /// # Errors
    /// As [`Caller::call`].
    pub async fn call(&self, call: Call) -> Result<Answer, Error> {
        self.calls.call(call).await
    }

    /// A handle for sending calls from another task while this one waits for notices.
    #[must_use]
    pub fn caller(&self) -> Caller {
        self.calls.clone()
    }

    /// The next notice, in the order the runtime raised them; `None` once the loop has ended and the stream is drained.
    pub async fn next_event(&mut self) -> Option<Notice> {
        self.notices.recv().await
    }
}

/// The loop of a runtime: await [`Serve::run`] on the runtime that [`start`] was called in.
pub struct Serve(Pin<Box<dyn Future<Output = ()>>>);

impl Serve {
    /// Run until a [`Call::Quit`] (or the [`Client`] is dropped), then shut the driver down.
    pub async fn run(self) {
        self.0.await;
    }
}

// ---- the relay reference ------------------------------------------------------------------------------------------------

fn unhex(s: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| {
        char::from(c)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|p| match p {
            [hi, lo] => Some((digit(*hi)? << 4) | digit(*lo)?),
            _ => None,
        })
        .collect()
}

/// Read the text of a relay reference file: `relay_ref = <hex RelayRef>` and `access_key = <hex 32 bytes>`, one per line;
/// `#` starts a comment.
///
/// # Errors
/// [`Error::Unavailable`] for a line that is not hex, a reference that does not decode, or a missing or short key.
pub fn read_relay_ref(text: &str) -> Result<(RelayRef, AccessKey), Error> {
    let (mut relay, mut access) = (None, None);
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let bytes = Zeroizing::new(unhex(value.trim()).ok_or(Error::Unavailable)?);
        match key.trim() {
            "relay_ref" => relay = RelayRef::decode(&bytes).ok(),
            "access_key" => access = SecretBytes::<32>::from_slice(&bytes).ok(),
            _ => {}
        }
    }
    match (relay, access) {
        (Some(r), Some(a)) => Ok((r, a)),
        _ => Err(Error::Unavailable),
    }
}

/// Create the profile in `dir` under `passphrase` (the `PROFILE` Argon2id cost); with `relay` (the text of a relay reference
/// file, [`read_relay_ref`]) the relay is recorded as relay 1.
///
/// # Errors
/// [`Error::Unavailable`] for a directory that holds a profile, a relay reference that does not read, or a store that cannot
/// be written.
pub fn create_profile(dir: &Path, passphrase: &[u8], relay: Option<&str>) -> Result<(), Error> {
    let relay = relay.map(read_relay_ref).transpose()?;
    let mut source = OsSource::default();
    let profile = Profile::create(dir, passphrase, &SystemClock::new(), source.entropy())?;
    if let Some((relay, access)) = relay {
        profile.add_relay(&relay, &access)?;
    }
    Ok(())
}

// ---- the parts ----------------------------------------------------------------------------------------------------------

type RtHub = Hub<TokioClock, OsSource>;

/// The hub behind a mutex, as the cell source of the worker and the scheduler's own calls. A lock that cannot be taken (a
/// panic elsewhere) fails closed: nothing is prepared, nothing committed or acknowledged.
#[derive(Clone)]
struct SharedHub(Arc<Mutex<RtHub>>);

impl CellSource for SharedHub {
    fn prepare_cell(
        &mut self,
        queue: QueueId,
        now: u64,
    ) -> Result<Option<PreparedCell>, SourceError> {
        self.0
            .lock()
            .map_err(|_| SourceError)?
            .prepare_cell(queue, now)
    }

    fn relayed(&mut self, queue: QueueId, token: CellToken, cell_id: u64) {
        if let Ok(mut hub) = self.0.lock() {
            hub.relayed(queue, token, cell_id);
        }
    }

    fn evicted(&mut self, queue: QueueId, cell_id: u64) {
        if let Ok(mut hub) = self.0.lock() {
            hub.evicted(queue, cell_id);
        }
    }

    fn send_failed(&mut self, queue: QueueId, token: CellToken, why: SendFailure) {
        if let Ok(mut hub) = self.0.lock() {
            hub.send_failed(queue, token, why);
        }
    }

    fn discard(&mut self, queue: QueueId, token: CellToken) {
        if let Ok(mut hub) = self.0.lock() {
            hub.discard(queue, token);
        }
    }

    fn queue_lost(&mut self, queue: QueueId) {
        if let Ok(mut hub) = self.0.lock() {
            hub.queue_lost(queue);
        }
    }

    fn deliver(
        &mut self,
        queue: QueueId,
        generation: u64,
        cell_id: u64,
        cell: &secmp_proto::wire::cell::Cell,
    ) -> Result<Delivered, SourceError> {
        self.0
            .lock()
            .map_err(|_| SourceError)?
            .deliver(queue, generation, cell_id, cell)
    }
}

/// The relays of the profile: where they are and what credential each needs (the store's relay rows).
struct HostDirectory {
    relays: BTreeMap<u32, (RelayRef, Option<AccessKey>)>,
}

impl HostDirectory {
    fn load(hub: &RtHub) -> Result<Self, Error> {
        let store = hub.profile_store();
        let store = store.lock().map_err(|_| Error::Unavailable)?;
        let mut relays = BTreeMap::new();
        for id in 1..=RELAY_ROWS {
            let Some(encoded) = store.relay_ref(i64::from(id))? else {
                continue;
            };
            let relay = RelayRef::decode(&encoded)?;
            let access = store
                .relay_access_key(i64::from(id))?
                .and_then(|k| SecretBytes::<32>::from_slice(&k).ok());
            relays.insert(id, (relay, access));
        }
        Ok(Self { relays })
    }
}

impl Directory for HostDirectory {
    fn relay(&self, relay: RelayId) -> Option<&RelayRef> {
        self.relays.get(&relay.0).map(|(r, _)| r)
    }

    fn access_key(&self, relay: RelayId) -> Option<&AccessKey> {
        self.relays.get(&relay.0).and_then(|(_, a)| a.as_ref())
    }
}

/// The control runner: the key material of the one-shot operations comes from the hub (the store).
struct HostControl {
    hub: Arc<Mutex<RtHub>>,
    access: Option<AccessKey>,
    /// The link data the user is accepting: number → `ld_id` (the consuming `LINK_GET` names it).
    consuming: Arc<Mutex<BTreeMap<u32, Id>>>,
}

impl HostControl {
    /// Run `f` on the hub, off the I/O threads (the store and the crypto block); a lock that cannot be taken or a result of
    /// `None` fails the operation.
    async fn with_hub<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut RtHub) -> Option<T> + Send + 'static,
    ) -> Result<T, TransportError> {
        let hub = Arc::clone(&self.hub);
        tokio::task::spawn_blocking(move || f(&mut *hub.lock().ok()?))
            .await
            .ok()
            .flatten()
            .ok_or(TransportError::Invalid)
    }

    /// A spare the scheduler's pool creates, or a queue re-created after `ERR_NOQUEUE` (spec §9.1).
    async fn queue_new<S: ProviderStream>(
        &self,
        queue: QueueId,
        access: &AccessKey,
        t: &mut AsyncRelayQueueTransport<S>,
    ) -> Result<ControlEffect, TransportError> {
        // a queue the hub knows uses its stored seeds; a new spare gets its seeds made durable now, before the request is
        // written (D4′)
        let (recv, send) = self
            .with_hub(move |hub| match hub.queue_material(queue) {
                Some((recv, Some(send))) => Some((recv, send)),
                Some((_, None)) => None,
                None => hub.pool_material(queue),
            })
            .await?;
        let (cap, _) = t.create_queue(&recv, &send, access).await?;
        Ok(ControlEffect::PoolQueueReady(queue, cap))
    }

    async fn queue_del<S: ProviderStream>(
        &self,
        queue: QueueId,
        t: &mut AsyncRelayQueueTransport<S>,
    ) -> Result<ControlEffect, TransportError> {
        let recv = self
            .with_hub(move |hub| hub.queue_material(queue).map(|(recv, _)| recv))
            .await?;
        let cap = RecvCap::from_seed(&recv)?;
        // a queue the relay does not have (the `QUEUE_DEL` ran, the host did not record it) is deleted all the same
        match t.delete_queue(&cap).await {
            Ok(()) | Err(TransportError::NoQueue) => {}
            Err(e) => return Err(e),
        }
        self.with_hub(move |hub| hub.queue_deleted(queue).ok())
            .await?;
        Ok(ControlEffect::None)
    }

    /// The consuming `LINK_GET` of an invitation the user is accepting: the accept, then the contact (or the refusal).
    async fn link_get_consume<S: ProviderStream>(
        &self,
        n: u32,
        t: &mut AsyncRelayQueueTransport<S>,
    ) -> Result<ControlEffect, TransportError> {
        let ld = self
            .consuming
            .lock()
            .map_err(|_| TransportError::Invalid)?
            .get(&n)
            .copied()
            .ok_or(TransportError::Invalid)?;
        let got = t.get_link_data(ld, LinkGetMode::Consume).await?;
        let blob = got
            .blob
            .as_ref()
            .map(|b| b.encode().map(|v| v.to_vec()))
            .transpose()
            .map_err(|_| TransportError::Invalid)?;
        if let Ok(mut consuming) = self.consuming.lock() {
            consuming.remove(&n);
        }
        self.with_hub(move |hub| {
            if let Err(e) = hub.link_consumed(n, blob.as_deref()) {
                let reason = match e {
                    Error::Invitation(r) => r,
                    _ => crate::api::InviteReject::Invalid,
                };
                hub.core_mut().raise(Event::InviteFailed(reason));
            }
            Some(())
        })
        .await?;
        Ok(ControlEffect::None)
    }
}

impl ControlRunner for HostControl {
    async fn run<S: ProviderStream>(
        &self,
        _op: OpId,
        kind: ControlKind,
        relay: RelayId,
        t: &mut AsyncRelayQueueTransport<S>,
    ) -> Result<ControlEffect, TransportError> {
        let access = self.access.as_ref().ok_or(TransportError::Invalid)?;
        match kind {
            ControlKind::QueueNew(queue) => self.queue_new(queue, access, t).await,
            ControlKind::QueueDel(queue) => self.queue_del(queue, t).await,
            ControlKind::LinkPut(n) => {
                let args = self.with_hub(move |hub| hub.link_put_args(n).ok()).await?;
                let blob = LinkBlob::decode(&args.blob).map_err(|_| TransportError::Invalid)?;
                let bucket =
                    u32::try_from(args.expires / 3_600).map_err(|_| TransportError::Invalid)?;
                t.put_link_data(args.ld_id, &args.owner_seed, &blob, true, bucket, access)
                    .await?;
                Ok(ControlEffect::None)
            }
            ControlKind::LinkGetOwner(n) => {
                let args = self.with_hub(move |hub| hub.link_put_args(n).ok()).await?;
                let got = t
                    .get_link_data(args.ld_id, LinkGetMode::OwnerStatus(&args.owner_seed))
                    .await?;
                Ok(ControlEffect::OwnerStatus {
                    relay,
                    ld: n,
                    present: got.present,
                    consumed: got.consumed,
                    expired: false,
                })
            }
            ControlKind::LinkGetConsume(n) => self.link_get_consume(n, t).await,
        }
    }
}

// ---- the loop -----------------------------------------------------------------------------------------------------------

/// A spare to hand out that the scheduler did not hold yet.
struct Take {
    queue: QueueId,
    period_ms: u64,
}

struct Engine<P: Providers> {
    sched: Scheduler,
    driver:
        Driver<P, HostDirectory, HostControl, OsHandshakes, BlockingWorker<SharedHub>, TokioClock>,
    hub: SharedHub,
    clock: TokioClock,
    relay: RelayId,
    calls: mpsc::UnboundedReceiver<Envelope>,
    notices: mpsc::UnboundedSender<Notice>,
    consuming: Arc<Mutex<BTreeMap<u32, Id>>>,
    known: BTreeSet<i64>,
    takes: Vec<Take>,
}

/// What the hub and the core ask of the scheduler after a visit.
struct Visit {
    actions: Vec<Action>,
    ops: Vec<crate::scheduler::control::OpSpec>,
}

impl<P: Providers> Engine<P> {
    /// One visit to the hub under its lock: what the sessions delivered, time, new contacts, and what it asks for.
    fn visit(&mut self) -> Visit {
        let now = self.clock.mono_ms();
        let Ok(mut hub) = self.hub.0.lock() else {
            let _ = self.notices.send(Notice::Unavailable);
            return Visit {
                actions: Vec::new(),
                ops: Vec::new(),
            };
        };
        if hub.pump().is_err() {
            let _ = self.notices.send(Notice::Unavailable);
        }
        hub.tick(now);
        // a contact that appeared (the invitee's accept, the inviter's accepted handshake) is announced once
        let now_known: BTreeSet<i64> = hub.core().contact_ids().collect();
        for id in now_known.difference(&self.known) {
            hub.core_mut().raise(Event::ContactAdded(ContactId(*id)));
        }
        self.known = now_known;
        let actions = hub.take_actions();
        let ops = hub.core_mut().take_ops();
        for event in hub.core_mut().take_events() {
            let _ = self.notices.send(Notice::Event(event));
        }
        Visit { actions, ops }
    }

    fn apply(&mut self, visit: Visit) {
        for action in visit.actions {
            self.apply_action(action);
        }
        let now = self.clock.mono_ms();
        for op in visit.ops {
            let _ = self
                .sched
                .schedule_control(now, op.kind, op.relay, op.related, op.when);
        }
    }

    fn apply_action(&mut self, action: Action) {
        let now = self.clock.mono_ms();
        let relay = self.relay;
        let mut source = self.hub.clone();
        let result = match action {
            Action::AddRecv {
                queue,
                relay,
                seed,
                period_ms,
            } => self
                .sched
                .add_recv_queue_seed(now, queue, relay, &seed, period_ms),
            Action::AddSend {
                queue,
                relay,
                sid,
                seed,
                period_ms,
            } => self
                .sched
                .add_send_queue_route(now, queue, relay, (sid, &seed), period_ms),
            Action::Control(spec) => self
                .sched
                .schedule_control(now, spec.kind, spec.relay, spec.related, spec.when)
                .map(|_| ()),
            Action::Remove { queue } => self
                .sched
                .remove_queue(now, queue, &mut source)
                .and_then(|outs| self.driver.submit(&mut self.sched, outs)),
            Action::TakeSpare { queue, period_ms } => {
                self.take(now, relay, (queue, period_ms), &mut source);
                Ok(())
            }
        };
        // a queue that is known already (a restart registers what the hub registered before) is no error; any other refusal
        // leaves the queue as it was and is reported
        if result.is_err_and(|e| e != crate::scheduler::core::SchedError::DuplicateQueue) {
            let _ = self.notices.send(Notice::Refused);
        }
    }

    fn take(
        &mut self,
        now: u64,
        relay: RelayId,
        (queue, period_ms): (QueueId, u64),
        source: &mut SharedHub,
    ) {
        let pending = self.sched.pool_pending(queue);
        let result = self
            .sched
            .take_pool_queue_id(now, relay, queue, period_ms, source);
        let (taken, outs) = match result {
            Ok((taken, outs)) => (Ok(taken), outs),
            Err(e) => (Err(e), Vec::new()),
        };
        match take_step(taken, pending) {
            TakeStep::Done => {
                if self.driver.submit(&mut self.sched, outs).is_err() {
                    let _ = self.notices.send(Notice::Refused);
                }
            }
            TakeStep::Retry => self.takes.push(Take { queue, period_ms }),
            TakeStep::Refused => {
                let _ = self.notices.send(Notice::Refused);
            }
        }
    }

    fn retry_takes(&mut self) {
        let now = self.clock.mono_ms();
        let relay = self.relay;
        let mut source = self.hub.clone();
        for t in core::mem::take(&mut self.takes) {
            self.take(now, relay, (t.queue, t.period_ms), &mut source);
        }
    }

    /// A `SetSettings`: stored under the hub's lock, the mode change handed to the scheduler outside it (its calls reach the
    /// cell source, which takes the lock).
    fn set_settings(&mut self, new: crate::settings::Settings) -> Result<Answer, Error> {
        let hub = Arc::clone(&self.hub.0);
        let (now, mut source) = (self.clock.mono_ms(), self.hub.clone());
        let outs = switch_settings(
            &mut self.sched,
            (now, &mut source),
            new,
            |new| {
                let mut hub = hub.lock().map_err(|_| Error::Unavailable)?;
                let previous = hub.core().settings;
                hub.core_mut().handle(Request::SetSettings(new))?;
                Ok(previous)
            },
            |previous| {
                if let Ok(mut hub) = hub.lock() {
                    let store = hub.profile_store();
                    let _ = previous.save(&store);
                    hub.core_mut().settings = previous;
                }
            },
        )?;
        self.driver
            .submit(&mut self.sched, outs)
            .map_err(|_| Error::Unavailable)?;
        Ok(Answer::Core(Response::Done))
    }

    /// One call, under the hub's lock.
    fn answer(&mut self, call: Call) -> Result<Answer, Error> {
        if let Call::Core(request) = &call
            && !admitted(request)
        {
            return Err(Error::Unsupported);
        }
        if let Call::Core(Request::SetSettings(new)) = call {
            return self.set_settings(new);
        }
        let mut hub = self.hub.0.lock().map_err(|_| Error::Unavailable)?;
        match call {
            Call::Core(request) => hub.core_mut().handle(request).map(Answer::Core),
            Call::InviteCreate { expires_s } => {
                if hub.spares()? == 0 {
                    return Ok(Answer::PoolEmpty);
                }
                let expires = hub.core().clock().unix_secs().saturating_add(expires_s);
                let issued = hub.invite(expires)?;
                Ok(Answer::Invitation { uri: issued.uri })
            }
            Call::InviteAccept { uri } => {
                // a URI that does not parse is refused before anything else
                crate::invitations::uri_link_data(&uri)?;
                if hub.spares()? == 0 {
                    return Ok(Answer::PoolEmpty);
                }
                let (ld_id, n) = hub.begin_accept(&uri)?;
                self.consuming
                    .lock()
                    .map_err(|_| Error::Unavailable)?
                    .insert(n, ld_id);
                Ok(Answer::Accepting)
            }
            Call::Quit => Ok(Answer::Closed),
        }
    }

    async fn run(mut self) {
        loop {
            let until = self.clock.mono_ms().saturating_add(CHUNK_MS);
            if self.driver.run_until(&mut self.sched, until).await.is_err() {
                // no randomness: fail closed, nothing more is sent
                let _ = self.notices.send(Notice::Stopped);
                break;
            }
            self.retry_takes();
            let visit = self.visit();
            self.apply(visit);
            let mut quit = None;
            while let Ok((call, reply)) = self.calls.try_recv() {
                if matches!(call, Call::Quit) {
                    quit = Some(reply);
                    break;
                }
                let _ = reply.send(self.answer(call));
            }
            let visit = self.visit();
            self.apply(visit);
            if let Some(reply) = quit {
                let _ = self.driver.shutdown(&mut self.sched);
                self.driver.release_unused();
                let _ = reply.send(Ok(Answer::Closed));
                break;
            }
            if self.calls.is_closed() {
                let _ = self.driver.shutdown(&mut self.sched);
                self.driver.release_unused();
                break;
            }
        }
    }
}

/// Everything but the providers, which differ by transport.
fn engine<P: Providers>(
    providers: P,
    hub: Hub<TokioClock, OsSource>,
    direct: bool,
    clock: TokioClock,
    channels: (
        mpsc::UnboundedReceiver<Envelope>,
        mpsc::UnboundedSender<Notice>,
    ),
) -> Result<Serve, Error> {
    let directory = HostDirectory::load(&hub)?;
    let relay = RelayId(1);
    let access = directory
        .relays
        .get(&relay.0)
        .and_then(|(_, a)| a.as_ref())
        .and_then(|a| SecretBytes::<32>::from_slice(a.expose_secret()).ok());
    let have_relay = directory.relays.contains_key(&relay.0);
    let mode = match (hub.core().settings.mode, direct) {
        (Mode::Strict, true) => Mode::Balanced,
        (mode, _) => mode,
    };
    let shared = SharedHub(Arc::new(Mutex::new(hub)));
    let consuming = Arc::new(Mutex::new(BTreeMap::new()));
    let control = HostControl {
        hub: Arc::clone(&shared.0),
        access,
        consuming: Arc::clone(&consuming),
    };
    let driver = Driver::new(
        Arc::new(providers),
        Arc::new(directory),
        Arc::new(control),
        OsHandshakes,
        BlockingWorker::new(shared.clone()),
        Arc::new(clock),
    );
    let sched = Scheduler::new(Params::default(), mode, TimingRng::os());
    let (calls, notices) = channels;
    let mut engine = Engine {
        sched,
        driver,
        hub: shared.clone(),
        clock,
        relay,
        calls,
        notices,
        consuming,
        known: BTreeSet::new(),
        takes: Vec::new(),
    };
    {
        let mut hub = shared.0.lock().map_err(|_| Error::Unavailable)?;
        start_view(hub.core_mut(), direct);
        engine.known = hub.core().contact_ids().collect();
    }
    let now = clock.mono_ms();
    if direct {
        let mut source = shared.clone();
        let outs = engine
            .sched
            .set_direct(now, true, &mut source)
            .map_err(|_| Error::Unavailable)?;
        engine
            .driver
            .submit(&mut engine.sched, outs)
            .map_err(|_| Error::Unavailable)?;
    }
    // the stored spares are the scheduler pool's (D4′): adopted as created, the ids floored above them, the missing ones
    // scheduled with the random delay of spec §10.6 (2)
    let start = shared
        .0
        .lock()
        .map_err(|_| Error::Unavailable)?
        .bridge_pool()?;
    engine.sched.floor_queue_ids(start.floor);
    for (queue, seed) in &start.spares {
        let cap = RecvCap::from_seed(seed).map_err(|_| Error::Unavailable)?;
        engine
            .sched
            .adopt_pool_queue(now, start.relay, *queue, cap)
            .map_err(|_| Error::Unavailable)?;
    }
    if have_relay {
        engine
            .sched
            .manage_pool(now, start.relay)
            .map_err(|_| Error::Unavailable)?;
    }
    let visit = engine.visit();
    engine.apply(visit);
    Ok(Serve(Box::pin(engine.run())))
}

/// Open the profile in `dir` under `passphrase` and make the runtime: a [`Client`] to call and the [`Serve`] loop to run. Call
/// it inside a tokio runtime (the clock and, over Tor, Arti start tasks).
///
/// Over Tor (the default) a Tor that is not ready means no link connects and nothing else is tried; with `cfg.direct` the
/// links are direct TLS to the relay's pinned endpoint and the mode is at least Balanced (spec §10.2).
///
/// # Errors
/// [`Error::Unlock`] for a wrong passphrase; [`Error::Transport`] if Tor cannot be started; [`Error::Unavailable`] for a
/// profile that does not open or a profile another process holds.
pub fn start(dir: &Path, passphrase: &[u8], cfg: RuntimeConfig) -> Result<(Client, Serve), Error> {
    let clock = TokioClock::new(SystemClock::new().unix_secs());
    let core = Core::open(dir, passphrase, clock, OsSource::default)?;
    let RuntimeConfig { direct, name } = cfg;
    let profile = WireProfile::new(&name, None).map_err(|_| Error::Unsupported)?;
    let hub = Hub::new(
        core,
        HubConfig {
            relay: RelayId(1),
            inv_period: Period::S10,
            reply_period: Period::S10,
            profile,
        },
    )?;
    let (calls, inbox) = mpsc::unbounded_channel();
    let (notices_tx, notices) = mpsc::unbounded_channel();
    let channels = (inbox, notices_tx);
    let serve = if direct {
        let providers = Only::new(TlsProvider::new(), Transport::Direct);
        engine(providers, hub, true, clock, channels)?
    } else {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let provider = arti::start(dir, tx).map_err(|_| Error::Transport)?;
        // Arti's status follower stops when nobody listens: keep the stream drained
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        engine(
            Only::new(provider, Transport::Tor),
            hub,
            false,
            clock,
            channels,
        )?
    };
    Ok((
        Client {
            calls: Caller(calls),
            notices,
        },
        serve,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::fmt::Write as _;

    use secmp_proto::wire::inv::Onion;

    fn text(access: &str) -> Result<String, Box<dyn std::error::Error>> {
        let relay = RelayRef {
            relay_fp: [1; 32],
            onion: Onion::from_pubkey(&[2; 32]),
            akc: [3; 32],
            direct: None,
        };
        let mut hex = String::new();
        for b in relay.encode()?.iter() {
            write!(hex, "{b:02x}")?;
        }
        Ok(format!(
            "# a relay\nrelay_ref = {hex}\naccess_key = {access}\n"
        ))
    }

    /// M7-C1 (A4): the relay reference file's `relay_ref` and a 32-byte `access_key` are read; a missing, short or
    /// non-hex key, or a reference that does not decode, is refused.
    #[test]
    fn relay_ref_file_is_read_strictly() -> Result<(), Box<dyn std::error::Error>> {
        let good = text(&"07".repeat(32))?;
        let (relay, access) = read_relay_ref(&good)?;
        assert_eq!(relay.relay_fp, [1; 32]);
        assert_eq!(access.expose_secret(), &[7; 32]);
        for bad in [
            text(&"07".repeat(31))?,
            text("zz")?,
            text(&"07".repeat(33))?,
            good.replace("relay_ref", "relay_rex"),
            good.replace("access_key", "access_kex"),
            "relay_ref = 00\naccess_key = 00\n".to_owned(),
            String::new(),
        ] {
            assert!(read_relay_ref(&bad).is_err(), "{bad:?}");
        }
        Ok(())
    }

    /// M7-C1b (C1-1): `admitted` is an allowlist over every `Request`: only `Export` (Argon2id and a file under the store's
    /// lock, on the loop) is refused.
    #[test]
    fn admitted_is_an_allowlist() {
        let contact = ContactId(1);
        let secret = || Zeroizing::new(b"x".to_vec());
        let all = [
            (Request::Contacts, true),
            (Request::SafetyNumber { contact }, true),
            (
                Request::Verify {
                    contact,
                    digits: String::new(),
                },
                true,
            ),
            (
                Request::Send {
                    contact,
                    kind: 1,
                    payload: secret(),
                    expire_after: 0,
                },
                true,
            ),
            (
                Request::Message {
                    contact,
                    msg_id: [0; 16],
                },
                true,
            ),
            (
                Request::Reveal {
                    contact,
                    msg_id: [0; 16],
                },
                true,
            ),
            (Request::Rotate { contact, relay: 1 }, true),
            (Request::RotateIdentity, true),
            (Request::ResetSession { contact }, true),
            (Request::Remove { contact }, true),
            (Request::Settings, true),
            (
                Request::SetSettings(crate::settings::Settings::default()),
                true,
            ),
            (Request::RelayView { direct: true }, true),
            (
                Request::Export {
                    path: std::path::PathBuf::from("x"),
                    passphrase: secret(),
                    confirm: true,
                    force: true,
                },
                false,
            ),
        ];
        for (request, want) in &all {
            assert_eq!(admitted(request), *want, "{request:?}");
        }
    }

    /// M7-C1b (C1-4): the outcomes of a take; a spare still being created is retried however often it was asked.
    #[test]
    fn take_step_outcomes() {
        use crate::scheduler::core::SchedError;

        assert_eq!(
            take_step(Err(SchedError::UnknownQueue), true),
            TakeStep::Refused
        );
        assert_eq!(
            take_step(Err(SchedError::RateBound), false),
            TakeStep::Refused
        );
        assert_eq!(take_step(Ok(Some(QueueId(1))), false), TakeStep::Done);
        for _ in 0..10_000 {
            assert_eq!(take_step(Ok(None), true), TakeStep::Retry);
        }
        assert_eq!(take_step(Ok(None), false), TakeStep::Refused);
    }

    #[cfg(feature = "kat")]
    type TestCore = Core<crate::clock::ManualClock, crate::testutil::Fixed>;

    #[cfg(feature = "kat")]
    fn core_of(
        label: &str,
        seed: u64,
    ) -> Result<(crate::testutil::Fixture, TestCore), Box<dyn std::error::Error>> {
        use crate::testutil::{Fixed, entropy};

        let fx = crate::sessions::tests::party(label, seed)?;
        let core = Core::with_profile(fx.profile.clone(), fx.clock.clone(), move || {
            Fixed(entropy(seed))
        })?;
        Ok((fx, core))
    }

    /// M7-C1b (C1-3): the start sets only `direct` on the core's view; the periods the hub keeps stay.
    #[cfg(feature = "kat")]
    #[test]
    fn start_view_keeps_hub_periods() -> Result<(), Box<dyn std::error::Error>> {
        let (_fx, mut core) = core_of("rt-view", 91)?;
        core.view.recv_periods_ms = vec![10_000, 80_000];
        start_view(&mut core, true);
        assert!(core.view.direct);
        assert_eq!(core.view.recv_periods_ms, [10_000, 80_000]);
        Ok(())
    }

    /// A cell source that never has a cell.
    #[cfg(feature = "kat")]
    struct NoCells;

    #[cfg(feature = "kat")]
    impl CellSource for NoCells {
        fn prepare_cell(
            &mut self,
            _: QueueId,
            _: u64,
        ) -> Result<Option<PreparedCell>, SourceError> {
            Ok(None)
        }
        fn relayed(&mut self, _: QueueId, _: CellToken, _: u64) {}
        fn evicted(&mut self, _: QueueId, _: u64) {}
        fn send_failed(&mut self, _: QueueId, _: CellToken, _: SendFailure) {}
        fn discard(&mut self, _: QueueId, _: CellToken) {}
        fn queue_lost(&mut self, _: QueueId) {}
        fn deliver(
            &mut self,
            _: QueueId,
            _: u64,
            _: u64,
            _: &secmp_proto::wire::cell::Cell,
        ) -> Result<Delivered, SourceError> {
            Err(SourceError)
        }
    }

    /// M7-C1b (C1-3, spec §10.2): a mode the recv-queues do not fit (two queues at 10 s: 16 ≤ 32 in Balanced, 48 > 32 in
    /// Low-bandwidth) is refused by the scheduler; the call's error is returned and the settings read back are the previous
    /// ones, in memory and in the store.
    #[cfg(feature = "kat")]
    #[test]
    fn mode_change_refused_restores_settings() -> Result<(), Box<dyn std::error::Error>> {
        use std::cell::RefCell;

        use crate::settings::Settings;

        let (fx, core) = core_of("rt-mode", 92)?;
        let core = RefCell::new(core);
        let balanced = Settings {
            mode: Mode::Balanced,
            ..Settings::default()
        };
        core.borrow_mut().handle(Request::SetSettings(balanced))?;
        let mut sched = Scheduler::new(Params::default(), Mode::Balanced, TimingRng::os());
        for n in 1..=2_u8 {
            let cap = RecvCap::from_seed(&SecretBytes::from_slice(&[n; 32])?)?;
            sched.add_recv_queue(0, RelayId(1), cap, 10_000)?;
        }
        let store_new = |new: Settings| {
            let mut core = core.borrow_mut();
            let previous = core.settings;
            core.handle(Request::SetSettings(new))?;
            Ok(previous)
        };
        let low = Settings {
            mode: Mode::LowBw,
            ..Settings::default()
        };
        let refused = switch_settings(&mut sched, (0, &mut NoCells), low, store_new, |previous| {
            let mut core = core.borrow_mut();
            let _ = previous.save(&fx.profile.store());
            core.settings = previous;
        });
        assert_eq!(refused.err(), Some(Error::Unsupported));
        assert_eq!(core.borrow().settings, balanced);
        assert_eq!(
            Settings::load(&fx.profile.store())?,
            balanced,
            "the store too"
        );
        assert_eq!(sched.effective_mode(), Mode::Balanced);
        // a mode that fits is stored and set
        let strict = Settings {
            mode: Mode::Strict,
            ..Settings::default()
        };
        let ok = switch_settings(&mut sched, (0, &mut NoCells), strict, store_new, |_| {});
        assert!(ok.is_ok());
        assert_eq!(sched.effective_mode(), Mode::Strict);
        assert_eq!(core.borrow().settings, strict);
        Ok(())
    }
}
