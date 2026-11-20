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

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex, TryLockError};

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
    consume_outcome, link_put_outcome,
};
use crate::scheduler::types::{
    CellSource, CellToken, ControlKind, Delivered, OpId, Output, PreparedCell, QueueId, RelayId,
    SendFailure, SourceError, Transport,
};
use crate::sessions::actor::{EntropySource as _, OsSource};
use crate::settings::Settings;
use crate::timing::TimingRng;

/// The step of the loop: how long the driver runs between two visits to the hub (spec §10.1 does not depend on it).
pub const CHUNK_MS: u64 = 1_000;

/// The relay rows a profile may hold that the runtime looks for.
const RELAY_ROWS: u32 = 16;

/// The most queued calls one hub job answers in one hold of the hub's lock (M7-S8, Q303; EXT3b-2 (a)); the rest stay queued, in
/// order, for the next job, at most one chunk later. The CLI sends at most 2 calls per job (one `input` line, one
/// `event_line`); 8 leaves a library host room and bounds a hold to 8 calls' cost — a `Request::Send` is ≈ 2 fsyncs.
const MAX_JOB_CALLS: usize = 8;

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
    /// Write the backup file (CS-3.5): the rows are read on the loop, the key derivation and the file are written off it
    /// (`Call::Core(Request::Export)` stays refused, [`admitted`]).
    Export {
        /// The file to create.
        path: std::path::PathBuf,
        /// The backup passphrase (a secret).
        passphrase: Zeroizing<Vec<u8>>,
        /// The user's confirmation (CS-3.5).
        confirm: bool,
        /// Also into a cloud-synchronised folder.
        force: bool,
    },
    /// The runtime's own numbers ([`StatusView`]).
    Status,
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
            Self::Export { .. } => "Export",
            Self::Status => "Status",
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
    /// The runtime's numbers.
    Status(StatusView),
    /// The runtime has shut down.
    Closed,
}

/// What `Call::Status` answers: the numbers of the runtime (no id, no key).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusView {
    /// The scheduler's effective mode.
    pub mode: Mode,
    /// Direct TLS instead of Tor.
    pub direct: bool,
    /// The links the scheduler holds (at the start of the call's job).
    pub links: usize,
    /// The contacts.
    pub contacts: usize,
    /// The spare queues of the pool.
    pub spares: usize,
}

impl core::fmt::Debug for Answer {
    /// The variant name only (CLAUDE.md §1.6).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Core(_) => "Core",
            Self::Invitation { .. } => "Invitation",
            Self::Accepting => "Accepting",
            Self::PoolEmpty => "PoolEmpty",
            Self::Status(_) => "Status",
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
    /// creation). Or the scheduler had no randomness (Q301): nothing changed, tried again.
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
        // Q301: a failed draw changed nothing (the spare is still in the pool): the hand-out is tried again at the next boundary
        Err(crate::scheduler::core::SchedError::Unavailable) => TakeStep::Retry,
        Ok(None) | Err(_) => TakeStep::Refused,
    }
}

/// Queue `spec` on the scheduler (spec §10.6 (2)); without randomness nothing changed (Q301) and it is kept in `kept`, queued again at the next boundary (EXT3b-3, Q304; as a take, `TakeStep::Retry`). Any other refusal is returned.
fn schedule_or_keep(
    sched: &mut Scheduler,
    now: u64,
    spec: crate::scheduler::control::OpSpec,
    kept: &mut Vec<crate::scheduler::control::OpSpec>,
) -> Result<(), crate::scheduler::core::SchedError> {
    match sched.schedule_control(now, spec.kind, spec.relay, spec.related, spec.when) {
        Ok(_) => Ok(()),
        Err(crate::scheduler::core::SchedError::Unavailable) => {
            kept.push(spec);
            Ok(())
        }
        Err(e) => Err(e),
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

/// Step 1 of a `SetSettings` (C2-2; spec §10.2): a changed mode is set on the scheduler first, before anything is stored. A
/// refusal (the recv-queues do not fit the mode) is the call's error `Unsupported`, a failed draw `Unavailable` (Q301), and
/// nothing is stored, nothing changed.
fn mode_step<S: CellSource>(
    sched: &mut Scheduler,
    (now, source): (u64, &mut S),
    previous: Mode,
    new: Mode,
) -> Result<Vec<Output>, Error> {
    if previous == new {
        return Ok(Vec::new());
    }
    sched.set_mode(now, new, source).map_err(|e| match e {
        // Q301: no randomness — nothing changed, and not a refusal of the mode
        crate::scheduler::core::SchedError::Unavailable => Error::Unavailable,
        _ => Error::Unsupported,
    })
}

/// Step 3: the save of the settings (the hub job) failed: one `Notice::Refused`, and the mode to go back to (`None` if the
/// mode was not changed or the save worked). The scheduler is never left in a mode the store does not hold unless the
/// revert is refused — then the mode is a valid one and the next open reads the store's.
fn after_save(
    saved: bool,
    (previous, new): (Mode, Mode),
    notices: &mpsc::UnboundedSender<Notice>,
) -> Option<Mode> {
    if saved {
        return None;
    }
    let _ = notices.send(Notice::Refused);
    (previous != new).then_some(previous)
}

/// The revert of [`after_save`].
fn apply_revert<S: CellSource>(
    sched: &mut Scheduler,
    (now, source): (u64, &mut S),
    previous: Mode,
) -> Result<Vec<Output>, crate::scheduler::core::SchedError> {
    sched.set_mode(now, previous, source)
}

/// Step 1 of a `SetSettings` from the scheduler's own mode (C2f-1): `None` while the backlog is not empty (a revert may be
/// waiting: nothing is touched and the call stays where it is); else the mode the scheduler was in and the result of
/// [`mode_step`] — `sched_mode` is re-read from [`Scheduler::mode`] after the step.
/// **Invariant (Q301):** after every [`settings_step`] and [`revert_step`], `sched_mode == sched.mode()`; a failed draw
/// changes nothing.
fn settings_step<S: CellSource>(
    sched: &mut Scheduler,
    sched_mode: &mut Mode,
    backlog_empty: bool,
    (now, source): (u64, &mut S),
    new: Mode,
) -> Option<(Mode, Result<Vec<Output>, Error>)> {
    if !backlog_empty {
        return None;
    }
    let previous = *sched_mode;
    let result = mode_step(sched, (now, source), previous, new);
    // Q301 (invariant): `sched_mode` is the scheduler's own mode after every step — set, refused or failed
    *sched_mode = sched.mode();
    Some((previous, result))
}

/// The revert of a failed save: `Ok(outputs)` when the scheduler is back on `previous` (`sched_mode` is set to it;
/// the caller submits the outputs); `Err(())` on a refusal, after a second `Notice::Refused`; `sched_mode` then keeps
/// the mode the scheduler is in.
fn revert_step<S: CellSource>(
    sched: &mut Scheduler,
    sched_mode: &mut Mode,
    (now, source): (u64, &mut S),
    previous: Mode,
    notices: &mpsc::UnboundedSender<Notice>,
) -> Result<Vec<Output>, ()> {
    let result = apply_revert(sched, (now, source), previous);
    // Q301 (invariant): as in `settings_step`
    *sched_mode = sched.mode();
    if let Ok(outs) = result {
        Ok(outs)
    } else {
        let _ = notices.send(Notice::Refused);
        Err(())
    }
}

/// What the loop could not do yet because the hub's lock was busy (the worker holds it for one transaction), and what has to
/// wait behind it: kept in order, retried first at the next boundary (C2-8).
enum Pending {
    Action(Action),
    Op(crate::scheduler::control::OpSpec),
    Revert(Mode),
}

/// Whether applying `p` calls the cell source (the hub).
const fn needs_hub(p: &Pending) -> bool {
    matches!(
        p,
        Pending::Action(Action::Remove { .. } | Action::TakeSpare { .. }) | Pending::Revert(_)
    )
}

/// The deferred work of the loop, in order. Nothing is applied behind an item that cannot be applied yet.
struct Backlog<A>(VecDeque<A>);

impl<A> Backlog<A> {
    fn push(&mut self, a: A) {
        self.0.push_back(a);
    }

    /// Apply the items in order: one that `needs_hub` is applied only if `hub` can be locked without waiting (`apply` gets the
    /// guarded value), else this stops and the rest stays. A poisoned lock is `Err` (fail closed: the rest is dropped).
    fn drain<M>(
        &mut self,
        hub: &Mutex<M>,
        needs_hub: impl Fn(&A) -> bool,
        mut apply: impl FnMut(A, Option<&mut M>),
    ) -> Result<(), ()> {
        while let Some(front) = self.0.front() {
            if needs_hub(front) {
                match hub.try_lock() {
                    Ok(mut guard) => {
                        if let Some(a) = self.0.pop_front() {
                            apply(a, Some(&mut *guard));
                        }
                    }
                    Err(TryLockError::WouldBlock) => return Ok(()),
                    Err(TryLockError::Poisoned(_)) => {
                        self.0.clear();
                        return Err(());
                    }
                }
            } else if let Some(a) = self.0.pop_front() {
                apply(a, None);
            }
        }
        Ok(())
    }
}

type Reply = oneshot::Sender<Result<Answer, Error>>;
type Envelope = (Call, Reply);

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

/// The bytes of the hex string `s`, in one zeroizing allocation of exactly their length (CLAUDE.md §1.6; review L34-2 (a):
/// the access key is never in a buffer that grew or that is dropped unwiped); `None` for an odd length or a non-hex digit.
fn unhex(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let digit = |c: u8| {
        char::from(c)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() / 2));
    for p in s.as_bytes().chunks(2) {
        match p {
            [hi, lo] => out.push((digit(*hi)? << 4) | digit(*lo)?),
            _ => return None,
        }
    }
    Some(out)
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
        let bytes = unhex(value.trim()).ok_or(Error::Unavailable)?;
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

/// The contacts of the profile in `dir`, offline (no runtime, no network): the profile is opened and closed.
///
/// # Errors
/// [`Error::Unlock`] for a wrong passphrase; [`Error::Unavailable`] for a profile that does not open or one another process
/// holds.
pub fn list_contacts(
    dir: &Path,
    passphrase: &[u8],
) -> Result<Vec<crate::contacts::Contact>, Error> {
    let mut core = Core::open(dir, passphrase, SystemClock::new(), OsSource::default)?;
    match core.handle(Request::Contacts)? {
        Response::Contacts(contacts) => Ok(contacts),
        _ => Err(Error::Unavailable),
    }
}

/// Restore the backup file `backup` into a new profile in `dir` under `passphrase` (CS-3.5; [`Core::restore`]); returns the
/// number of contacts it holds, each to be invited again.
///
/// # Errors
/// As [`Core::restore`].
pub fn import_profile(
    dir: &Path,
    passphrase: &[u8],
    backup: &Path,
    backup_passphrase: &[u8],
) -> Result<usize, Error> {
    let mut core = Core::restore(
        dir,
        passphrase,
        backup,
        backup_passphrase,
        SystemClock::new(),
        OsSource::default,
    )?;
    // the restored contacts have no session: they are the store's contacts, not the core's index
    match core.handle(Request::Contacts)? {
        Response::Contacts(contacts) => Ok(contacts.len()),
        _ => Err(Error::Unavailable),
    }
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
}

/// The material of a control operation, from the hub before its one-shot link opens (Q300; EXT3-1 Repro B).
enum ControlPrepared {
    /// A queue to create: its id and its recipient and sender seeds.
    QueueNew(QueueId, SecretBytes<32>, SecretBytes<32>),
    /// A queue to delete: its id and its recipient capability, derived before the link opens (M7-S4d).
    QueueDel(QueueId, RecvCap),
    /// A `LINK_PUT`: its arguments, its decoded blob and its expiry bucket, decoded before the link opens (M7-S4d).
    LinkPut(crate::invitations::LinkPutArgs, LinkBlob, u32),
    /// An owner-status `LINK_GET`: the link-data number and the arguments.
    LinkGetOwner(u32, crate::invitations::LinkPutArgs),
    /// A consuming `LINK_GET`: the link-data number and its `ld_id`.
    LinkGetConsume(u32, Id),
}

/// What the relay answered, committed to the hub after the link is closed (Q300; CLAUDE.md §1.7: done only after the
/// commit).
enum ControlAnswer {
    /// Nothing for the hub: the effect for the scheduler.
    Effect(ControlEffect),
    /// The queue was deleted on the relay (or was already gone).
    QueueDeleted(QueueId),
    /// The owner status of link data `n`.
    OwnerStatus(u32, crate::invitations::OwnerStatus),
    /// The link data `n` was consumed: its blob, `None` if it was gone.
    Consumed(u32, Option<Vec<u8>>),
    /// The consuming `LINK_GET` of link data `n` ended with no answer committed after its link was up — a relay `ERR` or any other end (Q300 phase rule, M7-S4d; `ControlRunner::unanswered`): the accept ends.
    AcceptFailed(u32),
}

impl ControlRunner for HostControl {
    type Prepared = ControlPrepared;
    type Answer = ControlAnswer;

    async fn prepare(
        &self,
        _op: OpId,
        kind: ControlKind,
        _relay: RelayId,
    ) -> Result<Option<ControlPrepared>, TransportError> {
        self.access.as_ref().ok_or(TransportError::Invalid)?;
        match kind {
            // a spare the scheduler's pool creates, or a queue re-created after `ERR_NOQUEUE` (spec §9.1)
            ControlKind::QueueNew(queue) => {
                // a queue the hub knows uses its stored seeds; a new spare gets its seeds made durable now, before the
                // request is written (D4′)
                let (recv, send) = self
                    .with_hub(move |hub| match hub.queue_material(queue) {
                        Some((recv, Some(send))) => Some((recv, send)),
                        Some((_, None)) => None,
                        None => hub.pool_material(queue),
                    })
                    .await?;
                Ok(Some(ControlPrepared::QueueNew(queue, recv, send)))
            }
            ControlKind::QueueDel(queue) => {
                let recv = self
                    .with_hub(move |hub| hub.queue_material(queue).map(|(recv, _)| recv))
                    .await?;
                // Q300 (M7-S4d, S4-3): the capability is derived before the link opens; a local failure opens no link
                let cap = RecvCap::from_seed(&recv)?;
                Ok(Some(ControlPrepared::QueueDel(queue, cap)))
            }
            ControlKind::LinkPut(n) => {
                // Q298 (S2-1): checked when the operation runs; an invitation that is no longer offered ends it before a
                // link opens (HB-55); a store error is retried
                let Some(args) = self.with_hub(move |hub| hub.put_args(n).ok()).await? else {
                    return Ok(None);
                };
                // Q300 (M7-S4d, S4-3): the blob and the expiry bucket are decoded before the link opens; a local failure opens
                // no link (link failed, CO-06's back-off; nothing reaches the relay)
                let blob = LinkBlob::decode(&args.blob).map_err(|_| TransportError::Invalid)?;
                let bucket =
                    u32::try_from(args.expires / 3_600).map_err(|_| TransportError::Invalid)?;
                Ok(Some(ControlPrepared::LinkPut(args, blob, bucket)))
            }
            ControlKind::LinkGetOwner(n) => {
                // Q300 (EXT3-4): the put's gates again when the query runs; an ineligible query ends before a link opens
                let args = self
                    .with_hub(move |hub| hub.owner_query_args(n).ok())
                    .await?;
                Ok(args.map(|args| ControlPrepared::LinkGetOwner(n, args)))
            }
            ControlKind::LinkGetConsume(n) => {
                // an accept that is no longer waiting has nothing to consume
                let ld = self
                    .consuming
                    .lock()
                    .map_err(|_| TransportError::Invalid)?
                    .get(&n)
                    .copied();
                Ok(ld.map(|ld| ControlPrepared::LinkGetConsume(n, ld)))
            }
        }
    }

    async fn run<S: ProviderStream>(
        &self,
        prepared: ControlPrepared,
        t: &mut AsyncRelayQueueTransport<S>,
    ) -> Result<ControlAnswer, TransportError> {
        let access = self.access.as_ref().ok_or(TransportError::Invalid)?;
        match prepared {
            ControlPrepared::QueueNew(queue, recv, send) => {
                let (cap, _) = t.create_queue(&recv, &send, access).await?;
                Ok(ControlAnswer::Effect(ControlEffect::PoolQueueReady(
                    queue, cap,
                )))
            }
            ControlPrepared::QueueDel(queue, cap) => {
                // a queue the relay does not have (the `QUEUE_DEL` ran, the host did not record it) is deleted all the same
                match t.delete_queue(&cap).await {
                    Ok(()) | Err(TransportError::NoQueue) => {}
                    Err(e) => return Err(e),
                }
                Ok(ControlAnswer::QueueDeleted(queue))
            }
            ControlPrepared::LinkPut(args, blob, bucket) => {
                // Q299 (F1-1; spec §9.4): `ERR_EXISTS` is done, never retried; the owner-status chain sees the real state
                link_put_outcome(
                    t.put_link_data(args.ld_id, &args.owner_seed, &blob, true, bucket, access)
                        .await,
                )?;
                Ok(ControlAnswer::Effect(ControlEffect::None))
            }
            ControlPrepared::LinkGetOwner(n, args) => {
                let got = t
                    .get_link_data(args.ld_id, LinkGetMode::OwnerStatus(&args.owner_seed))
                    .await?;
                Ok(ControlAnswer::OwnerStatus(
                    n,
                    crate::invitations::OwnerStatus {
                        present: got.present,
                        consumed: got.consumed,
                    },
                ))
            }
            ControlPrepared::LinkGetConsume(n, ld) => {
                // Q300 (EXT3-4): a relay `ERR` ends the accept; it is not retried
                let Some(got) = consume_outcome(t.get_link_data(ld, LinkGetMode::Consume).await)?
                else {
                    return Ok(ControlAnswer::AcceptFailed(n));
                };
                let blob = got
                    .blob
                    .as_ref()
                    .map(|b| b.encode().map(|v| v.to_vec()))
                    .transpose()
                    .map_err(|_| TransportError::Invalid)?;
                Ok(ControlAnswer::Consumed(n, blob))
            }
        }
    }

    async fn commit(&self, answer: ControlAnswer) -> Result<ControlEffect, TransportError> {
        match answer {
            ControlAnswer::Effect(effect) => Ok(effect),
            ControlAnswer::QueueDeleted(queue) => {
                self.with_hub(move |hub| hub.queue_deleted(queue).ok())
                    .await?;
                Ok(ControlEffect::None)
            }
            ControlAnswer::OwnerStatus(n, status) => {
                // the hub commits what it learned before the operation is done (CLAUDE.md §1.7) and queues the re-put
                // (§9.7 (1)) and the next query (Q297)
                self.with_hub(move |hub| hub.owner_status(n, status).ok())
                    .await?;
                Ok(ControlEffect::None)
            }
            ControlAnswer::Consumed(n, blob) => {
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
            ControlAnswer::AcceptFailed(n) => {
                if let Ok(mut consuming) = self.consuming.lock() {
                    consuming.remove(&n);
                }
                self.with_hub(move |hub| {
                    hub.accept_failed(n);
                    Some(())
                })
                .await?;
                Ok(ControlEffect::None)
            }
        }
    }

    async fn unanswered(&self, kind: ControlKind) -> bool {
        match kind {
            // Q300 (M7-S4d): the relay may have consumed — the accept ends, as for an answered consume, never retried (a
            // consumption the client never saw is HB-22's window)
            ControlKind::LinkGetConsume(n) => {
                self.commit(ControlAnswer::AcceptFailed(n)).await.is_ok()
            }
            _ => false,
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
    direct: bool,
    takes: Vec<Take>,
    /// Control operations the scheduler could not queue for want of randomness: queued again at the next boundary (EXT3b-3).
    unscheduled: Vec<crate::scheduler::control::OpSpec>,
    /// What waits for the hub's lock ([`Backlog`]).
    backlog: Backlog<Pending>,
    /// The mode last set on the scheduler (a mode step or a revert that worked); a `SetSettings` steps from it.
    sched_mode: Mode,
    /// The mode change of the settings job in flight: (previous, new).
    inflight: Option<(Mode, Mode)>,
}

/// What the hub and the core ask of the scheduler after a visit.
#[derive(Default)]
struct Visit {
    actions: Vec<Action>,
    ops: Vec<crate::scheduler::control::OpSpec>,
}

/// One visit to the hub (under its lock): what the sessions delivered, time, new contacts, and what it asks for.
fn visit_hub(
    hub: &mut RtHub,
    now: u64,
    known: &mut BTreeSet<i64>,
    notices: &mpsc::UnboundedSender<Notice>,
) -> Visit {
    if hub.pump().is_err() {
        let _ = notices.send(Notice::Unavailable);
    }
    hub.tick(now);
    // a contact that appeared (the invitee's accept, the inviter's accepted handshake) is announced once
    let now_known: BTreeSet<i64> = hub.core().contact_ids().collect();
    for id in now_known.difference(known) {
        hub.core_mut().raise(Event::ContactAdded(ContactId(*id)));
    }
    *known = now_known;
    let actions = hub.take_actions();
    let ops = hub.core_mut().take_ops();
    for event in hub.core_mut().take_events() {
        let _ = notices.send(Notice::Event(event));
    }
    Visit { actions, ops }
}

/// What a hub job needs besides the hub: the scheduler's numbers at its start (the `Status` call), the accepts in progress
/// and the stream of notices.
struct JobCtx {
    status: (Mode, bool, usize),
    consuming: Arc<Mutex<BTreeMap<u32, Id>>>,
    clock: TokioClock,
    notices: mpsc::UnboundedSender<Notice>,
}

/// The settings change of a call whose mode step is done (C2-2): the job saves it.
struct SettingsJob {
    new: Settings,
    previous: Mode,
    reply: Reply,
}

/// What a hub job is given to do, in this order.
struct JobWork {
    settings: Option<SettingsJob>,
    calls: Vec<Envelope>,
}

/// How a settings job ended: the loop reverts the mode if the save failed.
struct SettingsOutcome {
    saved: Result<(), Error>,
    previous: Mode,
    new: Mode,
}

/// What a finished hub job hands back to the loop.
struct JobDone {
    visit: Visit,
    known: BTreeSet<i64>,
    settings: Option<SettingsOutcome>,
}

/// A hub job (B0): one visit, the settings write and the calls in front of the queue that need only the hub, answered in
/// order, and a second visit for what they raised. It runs on the blocking pool with the hub's lock held; the loop goes on with
/// the schedule meanwhile and applies the result at a chunk boundary (CLAUDE.md §1.4).
fn hub_job(
    hub: &Mutex<RtHub>,
    ctx: &JobCtx,
    work: JobWork,
    known: &mut BTreeSet<i64>,
) -> (Visit, Option<SettingsOutcome>) {
    let JobWork { settings, calls } = work;
    let Ok(mut hub) = hub.lock() else {
        let _ = ctx.notices.send(Notice::Unavailable);
        for (_, reply) in calls {
            let _ = reply.send(Err(Error::Unavailable));
        }
        let outcome = settings.map(|s| {
            let _ = s.reply.send(Err(Error::Unavailable));
            SettingsOutcome {
                saved: Err(Error::Unavailable),
                previous: s.previous,
                new: s.new.mode,
            }
        });
        return (Visit::default(), outcome);
    };
    let mut visit = visit_hub(&mut hub, ctx.clock.mono_ms(), known, &ctx.notices);
    let mut outcome = None;
    if let Some(s) = settings {
        // the store and the hub; `handle` sets the settings only after the save
        let saved = hub
            .core_mut()
            .handle(Request::SetSettings(s.new))
            .map(|_| ());
        let _ = s.reply.send(match &saved {
            Ok(()) => Ok(Answer::Core(Response::Done)),
            Err(_) => Err(Error::Unavailable),
        });
        outcome = Some(SettingsOutcome {
            saved,
            previous: s.previous,
            new: s.new.mode,
        });
    }
    if !calls.is_empty() {
        for (call, reply) in calls {
            match call {
                Call::Export {
                    path,
                    passphrase,
                    confirm,
                    force,
                } => export_in_job(&hub, (path, passphrase, confirm, force), reply),
                call => {
                    let _ = reply.send(answer_hub(&mut hub, ctx, call));
                }
            }
        }
        let after = visit_hub(&mut hub, ctx.clock.mono_ms(), known, &ctx.notices);
        visit.actions.extend(after.actions);
        visit.ops.extend(after.ops);
    }
    (visit, outcome)
}

/// An export (C2-1; M7-S6, Q302): under the hub's lock, which the job holds, only `Core::export_snapshot`; the history, the key
/// derivation and the file on the blocking pool, which sends the reply — neither the loop nor `SharedHub::prepare_cell` or
/// `SharedHub::deliver` waits for the history (CLAUDE.md §1.4).
fn export_in_job(
    hub: &RtHub,
    (path, passphrase, confirm, force): (std::path::PathBuf, Zeroizing<Vec<u8>>, bool, bool),
    reply: Reply,
) {
    #[cfg(feature = "kat")]
    hooks::hold_handle();
    match hub.core().export_snapshot(confirm, force, &path) {
        Err(e) => {
            let _ = reply.send(Err(e));
        }
        Ok(pending) => {
            let store = hub.profile_store();
            drop(tokio::task::spawn_blocking(move || {
                let written = pending.finish(&store).and_then(|snapshot| {
                    snapshot.write(&passphrase, secmp_store::wrap::Argon2Params::PROFILE)
                });
                let answer = match written {
                    Ok(()) => Ok(Answer::Core(Response::Done)),
                    Err(e) => Err(Error::from(e)),
                };
                let _ = reply.send(answer);
            }));
        }
    }
}

/// Whether a call is answered by a hub job; the others (`SetSettings`: its mode step is the loop's; `Quit`) are the loop's.
const fn is_hub_call(call: &Call) -> bool {
    match call {
        Call::Core(Request::SetSettings(_)) | Call::Quit => false,
        Call::Core(_)
        | Call::Export { .. }
        | Call::InviteCreate { .. }
        | Call::InviteAccept { .. }
        | Call::Status => true,
    }
}

/// The calls at the front of `pending` that need only the hub, in their order, at most [`MAX_JOB_CALLS`] (M7-S8, Q303).
fn job_calls(pending: &mut VecDeque<Envelope>) -> Vec<Envelope> {
    let mut calls = Vec::new();
    while calls.len() < MAX_JOB_CALLS && pending.front().is_some_and(|(call, _)| is_hub_call(call))
    {
        calls.extend(pending.pop_front());
    }
    calls
}

/// One call of a hub job, under the hub's lock.
fn answer_hub(hub: &mut RtHub, ctx: &JobCtx, call: Call) -> Result<Answer, Error> {
    match call {
        Call::Core(request) => {
            if !admitted(&request) {
                return Err(Error::Unsupported);
            }
            #[cfg(feature = "kat")]
            hooks::hold_handle();
            hub.core_mut().handle(request).map(Answer::Core)
        }
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
            ctx.consuming
                .lock()
                .map_err(|_| Error::Unavailable)?
                .insert(n, ld_id);
            Ok(Answer::Accepting)
        }
        Call::Status => {
            let (mode, direct, links) = ctx.status;
            Ok(Answer::Status(StatusView {
                mode,
                direct,
                links,
                contacts: hub.core().contact_ids().count(),
                spares: hub.spares()?,
            }))
        }
        Call::Export { .. } | Call::Quit => Err(Error::Unsupported),
    }
}

/// What the loop has to do itself with the front of the queue.
enum LoopCall {
    /// Nothing: the hub job takes the front.
    None,
    /// A `Quit`: the reply to send after the shutdown.
    Quit(Reply),
    /// A `SetSettings` whose mode step is done: the hub job saves it.
    Settings(SettingsJob),
}

/// What the loop is waiting for: the hub job on the blocking pool.
type Job = tokio::task::JoinHandle<JobDone>;

impl<P: Providers> Engine<P> {
    /// One visit to the hub on the loop (the start and the end, when no job runs).
    fn visit(&mut self) -> Visit {
        let now = self.clock.mono_ms();
        let Ok(mut hub) = self.hub.0.lock() else {
            let _ = self.notices.send(Notice::Unavailable);
            return Visit::default();
        };
        visit_hub(&mut hub, now, &mut self.known, &self.notices)
    }

    /// Start the hub job: the settings write, if the mode step of a `SetSettings` was done, and the calls at the front of
    /// `pending` that need only the hub, in their order, at most [`MAX_JOB_CALLS`] (Q303).
    fn start_job(
        &mut self,
        pending: &mut VecDeque<Envelope>,
        settings: Option<SettingsJob>,
    ) -> Job {
        let calls = job_calls(pending);
        self.inflight = settings.as_ref().map(|s| (s.previous, s.new.mode));
        let ctx = JobCtx {
            status: (
                self.sched.effective_mode(),
                self.direct,
                self.sched.links().len(),
            ),
            consuming: Arc::clone(&self.consuming),
            clock: self.clock,
            notices: self.notices.clone(),
        };
        let hub = Arc::clone(&self.hub.0);
        let mut known = self.known.clone();
        tokio::task::spawn_blocking(move || {
            let (visit, settings) = hub_job(&hub, &ctx, JobWork { settings, calls }, &mut known);
            JobDone {
                visit,
                known,
                settings,
            }
        })
    }

    /// A finished job: what it saw is applied, a failed save has its mode reverted (the next drain); a job that panicked leaves
    /// `known` as it was and a mode change in flight is reverted.
    fn finish_job(&mut self, done: Result<JobDone, tokio::task::JoinError>) {
        let inflight = self.inflight.take();
        if let Ok(done) = done {
            self.known = done.known;
            if let Some(o) = done.settings {
                let saved = o.saved.is_ok();
                if let Some(back) = after_save(saved, (o.previous, o.new), &self.notices) {
                    self.backlog.push(Pending::Revert(back));
                }
            }
            self.apply(done.visit);
        } else {
            let _ = self.notices.send(Notice::Unavailable);
            if let Some((previous, new)) = inflight
                && previous != new
            {
                self.backlog.push(Pending::Revert(previous));
            }
            self.drain_backlog();
        }
    }

    /// What the hub and the core asked: in order, behind what is still deferred.
    fn apply(&mut self, visit: Visit) {
        for action in visit.actions {
            self.backlog.push(Pending::Action(action));
        }
        for op in visit.ops {
            self.backlog.push(Pending::Op(op));
        }
        self.drain_backlog();
    }

    /// Apply the deferred work in order; what needs the hub waits (without waiting) while the worker holds its lock.
    fn drain_backlog(&mut self) {
        let hub = Arc::clone(&self.hub.0);
        let mut backlog = core::mem::replace(&mut self.backlog, Backlog(VecDeque::new()));
        let result = backlog.drain(&hub, needs_hub, |p, guard| self.apply_pending(p, guard));
        if result.is_err() {
            let _ = self.notices.send(Notice::Unavailable);
        }
        self.backlog = backlog;
    }

    fn apply_pending(&mut self, p: Pending, hub: Option<&mut RtHub>) {
        let now = self.clock.mono_ms();
        match p {
            Pending::Action(action) => self.apply_action(action, hub),
            Pending::Op(op) => {
                let _ = schedule_or_keep(&mut self.sched, now, op, &mut self.unscheduled);
            }
            Pending::Revert(previous) => {
                if let Some(source) = hub
                    && let Ok(outs) = revert_step(
                        &mut self.sched,
                        &mut self.sched_mode,
                        (now, source),
                        previous,
                        &self.notices,
                    )
                {
                    let _ = self.driver.submit(&mut self.sched, outs);
                }
            }
        }
    }

    fn apply_action(&mut self, action: Action, hub: Option<&mut RtHub>) {
        let now = self.clock.mono_ms();
        let relay = self.relay;
        let result = match (action, hub) {
            (
                Action::AddRecv {
                    queue,
                    relay,
                    seed,
                    period_ms,
                },
                _,
            ) => self
                .sched
                .add_recv_queue_seed(now, queue, relay, &seed, period_ms),
            (
                Action::AddSend {
                    queue,
                    relay,
                    sid,
                    seed,
                    period_ms,
                },
                _,
            ) => self
                .sched
                .add_send_queue_route(now, queue, relay, (sid, &seed), period_ms),
            (Action::Control(spec), _) => {
                schedule_or_keep(&mut self.sched, now, spec, &mut self.unscheduled)
            }
            (Action::Remove { queue }, Some(source)) => self
                .sched
                .remove_queue(now, queue, source)
                .and_then(|outs| self.driver.submit(&mut self.sched, outs)),
            (Action::TakeSpare { queue, period_ms }, Some(source)) => {
                self.take(now, relay, (queue, period_ms), source);
                Ok(())
            }
            // `needs_hub` keeps these from running without the hub
            (Action::Remove { .. } | Action::TakeSpare { .. }, None) => Ok(()),
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
        source: &mut RtHub,
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

    /// The control operations the scheduler could not queue for want of randomness, once more (EXT3b-3, Q304); one attempt each per boundary.
    fn retry_controls(&mut self) {
        let now = self.clock.mono_ms();
        for spec in core::mem::take(&mut self.unscheduled) {
            let _ = schedule_or_keep(&mut self.sched, now, spec, &mut self.unscheduled);
        }
    }

    /// The takes that wait for a spare's creation, again; without the hub's lock (the worker has it) they stay for the next
    /// boundary.
    fn retry_takes(&mut self) {
        if self.takes.is_empty() {
            return;
        }
        let hub = Arc::clone(&self.hub.0);
        let mut guard = match hub.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return,
            Err(TryLockError::Poisoned(_)) => {
                self.takes.clear();
                let _ = self.notices.send(Notice::Unavailable);
                return;
            }
        };
        let (now, relay) = (self.clock.mono_ms(), self.relay);
        for t in core::mem::take(&mut self.takes) {
            self.take(now, relay, (t.queue, t.period_ms), &mut guard);
        }
    }

    /// The calls that are the loop's, at the front of `pending`: a `Quit`, and the mode step of a `SetSettings` (the
    /// scheduler's; the write is the hub job's, which then takes it).
    fn loop_calls(&mut self, pending: &mut VecDeque<Envelope>) -> LoopCall {
        loop {
            match pending.front() {
                Some((Call::Quit, _)) => {
                    return pending
                        .pop_front()
                        .map_or(LoopCall::None, |(_, reply)| LoopCall::Quit(reply));
                }
                Some((Call::Core(Request::SetSettings(new)), _)) => {
                    let new = *new;
                    // behind a waiting revert (or any deferred work) the call waits, in order
                    if !self.backlog.0.is_empty() {
                        return LoopCall::None;
                    }
                    let hub = Arc::clone(&self.hub.0);
                    let now = self.clock.mono_ms();
                    let stepped = match hub.try_lock() {
                        Ok(mut guard) => settings_step(
                            &mut self.sched,
                            &mut self.sched_mode,
                            true,
                            (now, &mut *guard),
                            new.mode,
                        ),
                        Err(TryLockError::WouldBlock) => return LoopCall::None,
                        Err(TryLockError::Poisoned(_)) => {
                            let _ = self.notices.send(Notice::Unavailable);
                            Some((self.sched_mode, Err(Error::Unavailable)))
                        }
                    };
                    let Some((previous, outs)) = stepped else {
                        return LoopCall::None;
                    };
                    let Some((_, reply)) = pending.pop_front() else {
                        return LoopCall::None;
                    };
                    match outs {
                        Err(e) => {
                            let _ = reply.send(Err(e));
                        }
                        Ok(outs) => {
                            if self.driver.submit(&mut self.sched, outs).is_ok() {
                                return LoopCall::Settings(SettingsJob {
                                    new,
                                    previous,
                                    reply,
                                });
                            }
                            // the mode is set but the links could not follow: back, and the call fails
                            let _ = self.notices.send(Notice::Refused);
                            if previous != new.mode {
                                self.backlog.push(Pending::Revert(previous));
                            }
                            let _ = reply.send(Err(Error::Unavailable));
                        }
                    }
                }
                _ => return LoopCall::None,
            }
        }
    }

    /// The loop keeps only the schedule: the driver in chunks, the actions and operations the hub asked for, the takes. What
    /// needs the hub (`visit`, the calls) runs as one hub job at a time on the blocking pool while the chunks go on; its
    /// result is applied at the next chunk boundary and the next job starts when a call or a visit is due (B0).
    async fn run(mut self) {
        let mut pending: VecDeque<Envelope> = VecDeque::new();
        let mut job: Option<Job> = None;
        loop {
            let until = self.clock.mono_ms().saturating_add(CHUNK_MS);
            if self.driver.run_until(&mut self.sched, until).await.is_err() {
                // no randomness: fail closed, nothing more is sent
                let _ = self.notices.send(Notice::Stopped);
                break;
            }
            #[cfg(feature = "kat")]
            hooks::note_chunk();
            while let Ok(envelope) = self.calls.try_recv() {
                pending.push_back(envelope);
            }
            if job.as_ref().is_some_and(Job::is_finished)
                && let Some(done) = job.take()
            {
                self.finish_job(done.await);
            }
            // work that takes the hub's lock on the loop waits for the job
            if job.is_none() {
                self.drain_backlog();
                self.retry_takes();
                self.retry_controls();
                let settings = match self.loop_calls(&mut pending) {
                    LoopCall::Quit(reply) => {
                        let visit = self.visit();
                        self.apply(visit);
                        let _ = self.driver.shutdown(&mut self.sched);
                        self.driver.release_unused();
                        let _ = reply.send(Ok(Answer::Closed));
                        break;
                    }
                    LoopCall::Settings(settings) => Some(settings),
                    LoopCall::None => None,
                };
                job = Some(self.start_job(&mut pending, settings));
            }
            if self.calls.is_closed() && pending.is_empty() {
                if let Some(running) = job.take() {
                    self.finish_job(running.await);
                }
                let _ = self.driver.shutdown(&mut self.sched);
                self.driver.release_unused();
                break;
            }
        }
    }
}

/// Test hooks (feature `kat`): what the runtime tests of the testkit and of this crate observe or hold.
#[cfg(feature = "kat")]
pub mod hooks {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Milliseconds the next `Core::handle` of a call is held (taken by it; 0: none).
    pub static HOLD_HANDLE_MS: AtomicU64 = AtomicU64::new(0);
    /// The chunks the loop has run.
    pub static CHUNKS: AtomicU64 = AtomicU64::new(0);

    pub(super) fn hold_handle() {
        let ms = HOLD_HANDLE_MS.swap(0, Ordering::SeqCst);
        if ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }

    pub(super) fn note_chunk() {
        CHUNKS.fetch_add(1, Ordering::SeqCst);
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
        direct,
        takes: Vec::new(),
        unscheduled: Vec::new(),
        backlog: Backlog(VecDeque::new()),
        sched_mode: mode,
        inflight: None,
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
    // EXT3b-3 (Q304): the open's registrations (the contacts' recv-queues) first, so `World::room_for` counts them
    let visit = engine.visit();
    engine.apply(visit);
    if have_relay {
        engine
            .sched
            .manage_pool(now, start.relay)
            .map_err(|_| Error::Unavailable)?;
    }
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

/// The stack of the threads that run a [`Host`]'s engine (as the CLI's: the handshake and the ratchet keep large frames, and
/// the main thread of a Windows process has 1 MiB).
const HOST_STACK: usize = 64 << 20;

/// A runtime on threads of its own, for a host that has no async runtime (the desktop UI): [`spawn_host`] runs [`start`] and
/// the loop there; calls go in without blocking the caller, answers and notices come back to closures.
pub struct Host {
    runtime: tokio::runtime::Handle,
    caller: Caller,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// Open the profile in `dir` under `passphrase` and run its runtime on a thread of its own ([`start`] and [`Serve::run`]);
/// every [`Notice`] goes to `on_notice`, on the runtime's threads. **The call blocks** until the runtime has started or
/// failed (the profile's key derivation runs inside it); call it from a thread that may wait. Its own copy of the passphrase
/// is dropped (zeroised) as soon as the runtime has started.
///
/// # Errors
/// As [`start`]; [`Error::Unavailable`] if a thread or the runtime cannot be made.
pub fn spawn_host(
    dir: &Path,
    passphrase: &[u8],
    cfg: RuntimeConfig,
    on_notice: impl Fn(Notice) + Send + 'static,
) -> Result<Host, Error> {
    let dir = dir.to_path_buf();
    let passphrase = Zeroizing::new(passphrase.to_vec());
    let (ready, started) = std::sync::mpsc::channel();
    let thread = std::thread::Builder::new()
        .stack_size(HOST_STACK)
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(HOST_STACK)
                .build()
            else {
                let _ = ready.send(Err(Error::Unavailable));
                return;
            };
            runtime.block_on(async move {
                let started = start(&dir, &passphrase, cfg);
                // the passphrase is not needed once the runtime has started (or failed to)
                drop(passphrase);
                let (mut client, serve) = match started {
                    Ok(parts) => parts,
                    Err(e) => {
                        let _ = ready.send(Err(e));
                        return;
                    }
                };
                let _ = ready.send(Ok((tokio::runtime::Handle::current(), client.caller())));
                let notices = tokio::spawn(async move {
                    while let Some(notice) = client.next_event().await {
                        on_notice(notice);
                    }
                });
                serve.run().await;
                let _ = notices.await;
            });
        })
        .map_err(|_| Error::Unavailable)?;
    match started.recv() {
        Ok(Ok((runtime, caller))) => Ok(Host {
            runtime,
            caller,
            thread: Some(thread),
        }),
        Ok(Err(e)) => {
            let _ = thread.join();
            Err(e)
        }
        Err(_) => Err(Error::Unavailable),
    }
}

impl Host {
    /// Send `call` to the loop and return at once; `reply` runs, on the runtime's threads, with its one answer (see
    /// [`Caller::call`]).
    pub fn call(&self, call: Call, reply: impl FnOnce(Result<Answer, Error>) + Send + 'static) {
        let caller = self.caller.clone();
        self.runtime
            .spawn(async move { reply(caller.call(call).await) });
    }
}

impl Drop for Host {
    /// Shut the loop down (`Call::Quit`) and wait for its thread.
    fn drop(&mut self) {
        let caller = self.caller.clone();
        let (done, finished) = std::sync::mpsc::channel();
        self.runtime.spawn(async move {
            let _ = caller.call(Call::Quit).await;
            let _ = done.send(());
        });
        let _ = finished.recv();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
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

    /// M7-S3 (L34-2 (a); CLAUDE.md §1.6): `unhex` decodes into one allocation of exactly the decoded length and refuses an
    /// odd length or a non-hex digit.
    #[test]
    fn unhex_is_one_exact_allocation() -> Result<(), Box<dyn std::error::Error>> {
        for n in [1_u8, 31, 32, 33, 100] {
            let bytes: Vec<u8> = (0..n).collect();
            let mut text = String::new();
            for b in &bytes {
                write!(text, "{b:02x}")?;
            }
            let got = unhex(&text).ok_or("unhex refused valid hex")?;
            assert_eq!(got.as_slice(), bytes.as_slice());
            assert_eq!(got.capacity(), got.len(), "{n} bytes");
        }
        assert!(unhex("0").is_none());
        assert!(unhex("0g").is_none());
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

    /// M7-C2 (B; CLAUDE.md §1.4): `Call::Export` is a hub job: the snapshot under the hub lock the job holds, the key and the file on the blocking pool —
    /// while the write is held on a barrier (the `kat` hook of `Snapshot::write`) a `Call::Core(Request::Contacts)` is
    /// answered; then the export completes: the file exists, `0600`.
    #[cfg(feature = "kat")]
    #[test]
    fn export_does_not_stall_the_loop() -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::atomic::Ordering;
        use std::sync::{Arc, Barrier};

        let dir = secmp_store::kat::TempDir::new("rt-export")?;
        let profile = dir.path().join("profile");
        std::fs::create_dir_all(&profile)?;
        create_profile(&profile, b"correct horse", None)?;
        let target = dir.path().join("backup.smpb");
        let barrier = Arc::new(Barrier::new(2));
        *secmp_store::backup::WRITE_BARRIER
            .lock()
            .map_err(|_| "barrier")? = Some(Arc::clone(&barrier));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let local = tokio::task::LocalSet::new();
        local.block_on(&runtime, async {
            let cfg = RuntimeConfig {
                direct: true,
                name: "rt-export".to_owned(),
            };
            let (client, serve) = start(&profile, b"correct horse", cfg)?;
            let serving = tokio::task::spawn_local(serve.run());
            let caller = client.caller();
            let path = target.clone();
            hooks::HOLD_HANDLE_MS.store(3_000, Ordering::SeqCst);
            let export = tokio::task::spawn_local(async move {
                caller
                    .call(Call::Export {
                        path,
                        passphrase: Zeroizing::new(b"backup horse".to_vec()),
                        confirm: true,
                        force: true,
                    })
                    .await
            });
            // the export is queued first
            tokio::task::yield_now().await;
            // C2-1: the snapshot is taken in the hub job: held for 3 s, the loop's chunks go on
            let chunks = hooks::CHUNKS.load(Ordering::SeqCst);
            let contacts = client.call(Call::Core(Request::Contacts)).await;
            let advanced = hooks::CHUNKS.load(Ordering::SeqCst).saturating_sub(chunks);
            assert!(
                advanced >= 2,
                "{advanced} chunks ran while the snapshot was held"
            );
            assert!(
                matches!(contacts, Ok(Answer::Core(_))),
                "answered meanwhile"
            );
            assert!(!export.is_finished(), "the write is still held");
            assert!(!target.exists());
            // release the write
            tokio::task::spawn_blocking(move || barrier.wait()).await?;
            let done = export.await?;
            assert!(matches!(done, Ok(Answer::Core(Response::Done))));
            assert!(target.exists());
            let closed = client.call(Call::Quit).await;
            assert!(matches!(closed, Ok(Answer::Closed)));
            serving.await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&target)?.permissions().mode() & 0o777,
                0o600
            );
        }
        Ok(())
    }

    /// M7-S6: the `msg_id` of history row `i` of [`held_export`].
    #[cfg(feature = "kat")]
    fn history_id(i: u16) -> [u8; 16] {
        let [hi, lo] = i.to_be_bytes();
        [hi, lo, 0x5e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    /// M7-S6: what [`held_export`] started.
    #[cfg(feature = "kat")]
    struct HeldExport {
        hub: Arc<Mutex<RtHub>>,
        barrier: Arc<std::sync::Barrier>,
        answer: oneshot::Receiver<Result<Answer, Error>>,
        target: std::path::PathBuf,
        job: tokio::task::JoinHandle<()>,
        dir: secmp_store::kat::TempDir,
    }

    /// M7-S6 (Q302): contact 1 and `n` received messages, the hub behind the runtime's lock, and an export run as the runtime runs it
    /// (`hub_job` on the blocking pool), held inside its history read (`HISTORY_HOLD`); one more `barrier.wait()` releases it.
    #[cfg(feature = "kat")]
    fn held_export(
        runtime: &tokio::runtime::Runtime,
        label: &str,
        n: u16,
    ) -> Result<HeldExport, Box<dyn std::error::Error>> {
        use secmp_proto::Encode as _;
        let dir = secmp_store::kat::TempDir::new(label)?;
        let profile = dir.path().join("profile");
        std::fs::create_dir_all(&profile)?;
        create_profile(&profile, b"correct horse", None)?;
        let clock = TokioClock::new(SystemClock::new().unix_secs());
        let core = Core::open(&profile, b"correct horse", clock, OsSource::default)?;
        let config = HubConfig {
            relay: RelayId(1),
            inv_period: Period::S10,
            reply_period: Period::S10,
            profile: WireProfile::new("rt-s6", None)?,
        };
        let hub = Hub::new(core, config)?;
        let sig = secmp_crypto::HybridSigningKey::from_seeds(&[1; 32], &[2; 32])?;
        let peer = secmp_proto::prekeys::IdentityKeys::from_parts(
            sig,
            secmp_proto::prekeys::IkDhSecret::from_bytes(&[3; 32])?,
        )?;
        let iks = peer.public().encode()?.to_vec();
        let bob = WireProfile::new("Bob", None)?.encode()?;
        hub.profile_store().lock().map_err(|_| "store")?.txn(|tx| {
            let contact = secmp_store::contacts::Contact {
                id: 1,
                iks: &iks,
                fingerprint: b"peer fingerprint",
                display_name: Some("Bob"),
                verified: false,
                routes: None,
                queues: None,
                state: secmp_store::contacts::STATE_ACTIVE,
                profile: Some(bob.as_slice()),
            };
            secmp_store::contacts::put_contact(tx, &contact)?;
            for i in 0..n {
                secmp_store::sessions::insert_delivered(
                    tx,
                    1,
                    &history_id(i),
                    1,
                    b"a row of the history",
                    1_000,
                    0,
                )?;
            }
            Ok(())
        })?;
        let (hub, barrier) = (
            Arc::new(Mutex::new(hub)),
            Arc::new(std::sync::Barrier::new(2)),
        );
        *secmp_store::backup::HISTORY_HOLD
            .lock()
            .map_err(|_| "hold")? = Some(Arc::clone(&barrier));
        let (target, (reply, answer), (notices, _)) = (
            dir.path().join("backup.smpb"),
            oneshot::channel(),
            mpsc::unbounded_channel(),
        );
        let ctx = JobCtx {
            status: (Mode::Strict, false, 0),
            consuming: Arc::new(Mutex::new(BTreeMap::new())),
            clock,
            notices,
        };
        let export = Call::Export {
            path: target.clone(),
            passphrase: Zeroizing::new(b"backup horse".to_vec()),
            confirm: true,
            force: true,
        };
        let work = JobWork {
            settings: None,
            calls: vec![(export, reply)],
        };
        let shared = Arc::clone(&hub);
        let job = runtime.spawn_blocking(move || {
            let _ = hub_job(&shared, &ctx, work, &mut BTreeSet::new());
        });
        barrier.wait(); // the export is inside the history read
        Ok(HeldExport {
            hub,
            barrier,
            answer,
            target,
            job,
            dir,
        })
    }

    /// M7-S6 (EXT3-1 Repro A; Q302; CLAUDE.md §1.4): while an export of 2 000 messages is held inside its history read, the
    /// worker's cell source and the store answer within 500 ms.
    #[cfg(feature = "kat")]
    #[test]
    fn export_snapshot_does_not_hold_the_hub_lock() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let held = {
            let _enter = runtime.enter();
            held_export(&runtime, "s6-lock", 2_000)?
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let hub = Arc::clone(&held.hub);
        let probe = std::thread::spawn(move || {
            let _ = SharedHub(Arc::clone(&hub)).prepare_cell(QueueId(1), 0);
            let store = hub.lock().map(|h| h.profile_store());
            let found = store
                .ok()
                .and_then(|s| s.lock().ok().map(|s| s.has_message(1, &[0xee; 16]).is_ok()));
            let _ = tx.send(found == Some(true));
        });
        let prompt = rx.recv_timeout(std::time::Duration::from_millis(500));
        held.barrier.wait();
        let _ = probe.join();
        runtime.block_on(held.job)?;
        let done = runtime.block_on(held.answer)?;
        assert!(
            matches!(prompt, Ok(true)),
            "the cell source waited for the export's history read: {prompt:?}"
        );
        assert!(matches!(done, Ok(Answer::Core(Response::Done))));
        assert!(held.target.exists());
        Ok(())
    }

    /// M7-S6 (EXT3-1 Repro A; Q302; CLAUDE.md §1.4); wording M7-S8 (EXT3b-6). No session, link or scheduler is set up and
    /// `prepare_cell(QueueId(1), …)` returns no cell: the test proves the responsiveness of the cell source's lock while an
    /// export is held 25 s (> 2 `P_q`) in its history read — three `SharedHub::prepare_cell` calls issued at the deadlines of a
    /// `P_q` = 10 s period each return before the next deadline (counted by hand: a later return would be an `Overrun` of a
    /// send link, `World::tick`, OPEN-M6-13) and are issued on time: 0 overruns, 0 late. That a Strict send link survives
    /// follows only together with the scheduler's prepare-after-tick order (spec §10.1), which this test does not run.
    #[cfg(feature = "kat")]
    #[test]
    fn send_link_survives_export_hold_longer_than_period() -> Result<(), Box<dyn std::error::Error>>
    {
        const P_MS: u64 = 10_000;
        const HOLD_MS: u64 = 25_000;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let held = {
            let _enter = runtime.enter();
            held_export(&runtime, "s6-period", 2_000)?
        };
        let clock = SystemClock::new();
        let mut cells = SharedHub(Arc::clone(&held.hub));
        let ticker = std::thread::spawn(move || {
            let mut ticks = Vec::new();
            for k in 0..3_u64 {
                let at = k.saturating_mul(P_MS);
                while clock.mono_ms() < at {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                let issued = clock.mono_ms();
                let _ = cells.prepare_cell(QueueId(1), issued);
                ticks.push((issued, clock.mono_ms()));
            }
            ticks
        });
        std::thread::sleep(std::time::Duration::from_millis(HOLD_MS));
        held.barrier.wait();
        let ticks = ticker.join().map_err(|_| "ticker")?;
        runtime.block_on(held.job)?;
        let done = runtime.block_on(held.answer)?;
        assert!(matches!(done, Ok(Answer::Core(Response::Done))));
        let overruns = ticks
            .iter()
            .zip(0_u64..)
            .filter(|&(&(_, ready), k)| ready > k.saturating_add(1).saturating_mul(P_MS))
            .count();
        let late = ticks
            .iter()
            .zip(0_u64..)
            // 2 s: the hold sits on a blocking thread in real time; a loaded runner must not flake (overruns are asserted exactly)
            .filter(|&(&(issued, _), k)| issued.abs_diff(k.saturating_mul(P_MS)) > 2_000)
            .count();
        assert_eq!(ticks.len(), 3, "{ticks:?}");
        assert_eq!(overruns, 0, "{ticks:?}");
        assert_eq!(late, 0, "{ticks:?}");
        Ok(())
    }

    /// M7-S6 (EXT3-1 Repro A; Q302; CLAUDE.md §1.4): a message committed and one deleted while the export reads its history
    /// neither wait nor change the snapshot — the history at the export's start (deleted row in, new row out) — and the file
    /// imports.
    #[cfg(feature = "kat")]
    #[test]
    fn export_commit_during_history_read_is_out_and_imports()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let held = {
            let _enter = runtime.enter();
            held_export(&runtime, "s6-point", 3)?
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let hub = Arc::clone(&held.hub);
        let writer = std::thread::spawn(move || {
            let ok = hub
                .lock()
                .ok()
                .and_then(|h| {
                    let store = h.profile_store();
                    let mut s = store.lock().ok()?;
                    let put = s.txn(|tx| {
                        secmp_store::sessions::insert_delivered(
                            tx,
                            1,
                            &[0xc0; 16],
                            1,
                            b"during",
                            1_000,
                            0,
                        )
                    });
                    let del = s.delete_message(1, &history_id(0));
                    Some(put.is_ok() && del.is_ok())
                })
                .unwrap_or(false);
            let _ = tx.send(ok);
        });
        let prompt = rx.recv_timeout(std::time::Duration::from_millis(500));
        held.barrier.wait();
        let _ = writer.join();
        runtime.block_on(held.job)?;
        let done = runtime.block_on(held.answer)?;
        assert!(
            matches!(prompt, Ok(true)),
            "the commit waited for the export's history read: {prompt:?}"
        );
        assert!(matches!(done, Ok(Answer::Core(Response::Done))));
        let live = held.hub.lock().map_err(|_| "hub")?.profile_store();
        let rows = live
            .lock()
            .map_err(|_| "store")?
            .connection_kat()
            .query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))?;
        assert_eq!(rows, 3);
        let restored = held.dir.path().join("restored");
        std::fs::create_dir_all(&restored)?;
        let core = Core::restore(
            &restored,
            b"restored horse",
            &held.target,
            b"backup horse",
            SystemClock::new(),
            OsSource::default,
        )?;
        let store = core.profile_store();
        let store = store.lock().map_err(|_| "store")?;
        let count = |sql: &str, id: Option<&[u8]>| -> Result<i64, Box<dyn std::error::Error>> {
            let conn = store.connection_kat();
            Ok(match id {
                None => conn.query_row(sql, [], |r| r.get::<_, i64>(0))?,
                Some(id) => conn.query_row(sql, [id], |r| r.get::<_, i64>(0))?,
            })
        };
        assert_eq!(count("SELECT count(*) FROM messages", None)?, 3);
        let sql = "SELECT count(*) FROM messages WHERE msg_id = ?1";
        assert_eq!(count(sql, Some(history_id(0).as_slice()))?, 1);
        assert_eq!(count(sql, Some([0xc0_u8; 16].as_slice()))?, 0);
        Ok(())
    }

    /// M7-S8: what [`job_hub`] builds — the profile's directory, the hub behind the runtime's lock, and the clock.
    #[cfg(feature = "kat")]
    type JobHub = (secmp_store::kat::TempDir, Arc<Mutex<RtHub>>, TokioClock);

    /// M7-S8: a profile with no contact, its hub behind the runtime's lock, and its clock (built as [`held_export`] builds them).
    #[cfg(feature = "kat")]
    fn job_hub(label: &str) -> Result<JobHub, Box<dyn std::error::Error>> {
        let dir = secmp_store::kat::TempDir::new(label)?;
        let profile = dir.path().join("profile");
        std::fs::create_dir_all(&profile)?;
        create_profile(&profile, b"correct horse", None)?;
        let clock = TokioClock::new(SystemClock::new().unix_secs());
        let core = Core::open(&profile, b"correct horse", clock, OsSource::default)?;
        let config = HubConfig {
            relay: RelayId(1),
            inv_period: Period::S10,
            reply_period: Period::S10,
            profile: WireProfile::new("rt-s8", None)?,
        };
        let hub = Hub::new(core, config)?;
        Ok((dir, Arc::new(Mutex::new(hub)), clock))
    }

    /// M7-S8 (EXT3b-2 (a); Q303; CLAUDE.md §1.4): of `MAX_JOB_CALLS` + 2 queued hub calls one job takes and answers
    /// `MAX_JOB_CALLS`; the other 2 stay queued, in order and unanswered, while the cell source takes the hub's lock between
    /// the two jobs; the next job answers them.
    #[cfg(feature = "kat")]
    #[test]
    fn hub_job_answers_at_most_max_job_calls() -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::atomic::Ordering;
        use tokio::sync::oneshot::error::TryRecvError;
        const EXTRA: usize = 2;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (_dir, hub, clock) = {
            let _enter = runtime.enter();
            job_hub("s8-cap")?
        };
        let ctx = || JobCtx {
            status: (Mode::Strict, false, 0),
            consuming: Arc::new(Mutex::new(BTreeMap::new())),
            clock,
            notices: mpsc::unbounded_channel().0,
        };
        let mut pending: VecDeque<Envelope> = VecDeque::new();
        let mut answers = Vec::new();
        for _ in 0..MAX_JOB_CALLS.saturating_add(EXTRA) {
            let (reply, answer) = oneshot::channel();
            pending.push_back((Call::Core(Request::Contacts), reply));
            answers.push(answer);
        }
        let first = job_calls(&mut pending);
        assert_eq!((first.len(), pending.len()), (MAX_JOB_CALLS, EXTRA));
        // the first call of the first job is held 2 s; the job holds the hub's lock meanwhile
        hooks::HOLD_HANDLE_MS.store(2_000, Ordering::SeqCst);
        let (shared, job_ctx) = (Arc::clone(&hub), ctx());
        let job1 = runtime.spawn_blocking(move || {
            let work = JobWork {
                settings: None,
                calls: first,
            };
            let _ = hub_job(&shared, &job_ctx, work, &mut BTreeSet::new());
        });
        std::thread::sleep(std::time::Duration::from_millis(200));
        let (tx, rx) = std::sync::mpsc::channel();
        let probe_hub = Arc::clone(&hub);
        let probe = std::thread::spawn(move || {
            let _ = SharedHub(probe_hub).prepare_cell(QueueId(1), 0);
            let _ = tx.send(());
        });
        runtime.block_on(job1)?;
        // between the jobs
        let between = rx.recv_timeout(std::time::Duration::from_millis(5_000));
        probe.join().map_err(|_| "probe")?;
        assert!(
            between.is_ok(),
            "the cell source did not get the lock between the jobs: {between:?}"
        );
        for (i, answer) in answers.iter_mut().enumerate() {
            if i < MAX_JOB_CALLS {
                assert!(
                    matches!(
                        answer.try_recv(),
                        Ok(Ok(Answer::Core(Response::Contacts(_))))
                    ),
                    "call {i}: answered by the first job"
                );
            } else {
                assert!(
                    matches!(answer.try_recv(), Err(TryRecvError::Empty)),
                    "call {i}: still queued"
                );
            }
        }
        let second = job_calls(&mut pending);
        assert_eq!((second.len(), pending.len()), (EXTRA, 0));
        let (shared, job_ctx) = (Arc::clone(&hub), ctx());
        let job2 = runtime.spawn_blocking(move || {
            let work = JobWork {
                settings: None,
                calls: second,
            };
            let _ = hub_job(&shared, &job_ctx, work, &mut BTreeSet::new());
        });
        runtime.block_on(job2)?;
        for (i, answer) in answers.iter_mut().enumerate().skip(MAX_JOB_CALLS) {
            assert!(
                matches!(
                    answer.try_recv(),
                    Ok(Ok(Answer::Core(Response::Contacts(_))))
                ),
                "call {i}: answered by the second job"
            );
        }
        Ok(())
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

    /// Q301 sweep (EXT3-2): a take whose scheduler draw failed changed nothing and is tried again; a refusal is not.
    #[test]
    fn take_step_retries_a_failed_draw() {
        use crate::scheduler::core::SchedError;

        assert_eq!(
            take_step(Err(SchedError::Unavailable), false),
            TakeStep::Retry
        );
        assert_eq!(
            take_step(Err(SchedError::Unavailable), true),
            TakeStep::Retry
        );
        assert_eq!(
            take_step(Err(SchedError::BadPeriod), false),
            TakeStep::Refused
        );
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

    /// A scheduler in Balanced with two recv-queues at 10 s (16 ≤ 32 in Balanced and Strict, 48 > 32 in Low-bandwidth).
    #[cfg(feature = "kat")]
    fn two_queues() -> Result<Scheduler, Box<dyn std::error::Error>> {
        let mut sched = Scheduler::new(Params::default(), Mode::Balanced, TimingRng::os());
        for n in 1..=2_u8 {
            let cap = RecvCap::from_seed(&SecretBytes::from_slice(&[n; 32])?)?;
            sched.add_recv_queue(0, RelayId(1), cap, 10_000)?;
        }
        Ok(sched)
    }

    /// M7-C1b (C1-3, spec §10.2) as reordered by C-2f: a mode the recv-queues do not fit is refused by the scheduler in the
    /// mode step, before anything is stored: the call's error is `Unsupported`, the scheduler, the settings in memory and the
    /// store stay as they were; a mode that fits is set.
    #[cfg(feature = "kat")]
    #[test]
    fn mode_change_refused_restores_settings() -> Result<(), Box<dyn std::error::Error>> {
        use crate::settings::Settings;

        let (fx, mut core) = core_of("rt-mode", 92)?;
        let balanced = Settings {
            mode: Mode::Balanced,
            ..Settings::default()
        };
        core.handle(Request::SetSettings(balanced))?;
        let mut sched = two_queues()?;
        let refused = mode_step(&mut sched, (0, &mut NoCells), Mode::Balanced, Mode::LowBw);
        assert_eq!(refused.err(), Some(Error::Unsupported));
        assert_eq!(core.settings, balanced);
        assert_eq!(
            Settings::load(&fx.profile.store())?,
            balanced,
            "nothing stored"
        );
        assert_eq!(sched.effective_mode(), Mode::Balanced);
        // a mode that fits is set (stored by the job afterwards); an unchanged one touches nothing
        assert!(mode_step(&mut sched, (0, &mut NoCells), Mode::Balanced, Mode::Strict).is_ok());
        assert_eq!(sched.effective_mode(), Mode::Strict);
        assert!(mode_step(&mut sched, (0, &mut NoCells), Mode::Strict, Mode::Strict).is_ok());
        Ok(())
    }

    /// SE-192 (C2-2; C-2f): the mode is set first; when the save fails the scheduler goes back to the previous mode, the call
    /// fails and exactly one `Notice::Refused` is sent; a save that works sends nothing and reverts nothing.
    #[cfg(feature = "kat")]
    #[test]
    fn settings_save_failure_reverts_mode() -> Result<(), Box<dyn std::error::Error>> {
        let mut sched = two_queues()?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let modes = (Mode::Balanced, Mode::Strict);
        mode_step(&mut sched, (0, &mut NoCells), modes.0, modes.1)?;
        assert_eq!(sched.effective_mode(), Mode::Strict);
        // the save worked: nothing to revert, nothing sent
        assert_eq!(after_save(true, modes, &tx), None);
        assert!(rx.try_recv().is_err());
        // the save failed
        let back = after_save(false, modes, &tx);
        assert_eq!(back, Some(Mode::Balanced));
        apply_revert(&mut sched, (0, &mut NoCells), Mode::Balanced)?;
        assert_eq!(sched.effective_mode(), Mode::Balanced);
        assert!(matches!(rx.try_recv(), Ok(Notice::Refused)));
        assert!(rx.try_recv().is_err(), "exactly one notice");
        // a save that failed without a mode change: the notice, no revert
        assert_eq!(after_save(false, (Mode::Strict, Mode::Strict), &tx), None);
        assert!(matches!(rx.try_recv(), Ok(Notice::Refused)));
        Ok(())
    }

    /// SE-194 (C2f-1; C-2g): a revert the scheduler refuses leaves it in the new mode; the next request for the old mode steps
    /// from the scheduler's own mode (a step is tried and refused), where stepping from the stored mode would have saved
    /// without a step and left the wire in the other mode.
    #[cfg(feature = "kat")]
    #[test]
    fn refused_revert_then_same_request_steps_the_scheduler()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut sched = two_queues()?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut sched_mode = Mode::Balanced;
        let stepped = settings_step(
            &mut sched,
            &mut sched_mode,
            true,
            (0, &mut NoCells),
            Mode::Strict,
        );
        assert!(matches!(stepped, Some((Mode::Balanced, Ok(_)))));
        assert_eq!(sched.effective_mode(), Mode::Strict);
        assert_eq!(sched_mode, Mode::Strict);
        assert_eq!(
            after_save(false, (Mode::Balanced, Mode::Strict), &tx),
            Some(Mode::Balanced)
        );
        assert!(matches!(rx.try_recv(), Ok(Notice::Refused)));
        // three more recv-queues at 10 s: Strict takes them, Balanced would be 5 × 8 = 40 > 32
        for n in 3..=5_u8 {
            let cap = RecvCap::from_seed(&SecretBytes::from_slice(&[n; 32])?)?;
            sched.add_recv_queue(0, RelayId(1), cap, 10_000)?;
        }
        let reverted = revert_step(
            &mut sched,
            &mut sched_mode,
            (0, &mut NoCells),
            Mode::Balanced,
            &tx,
        );
        assert!(reverted.is_err());
        assert_eq!(sched.effective_mode(), Mode::Strict);
        assert_eq!(sched_mode, Mode::Strict);
        assert!(matches!(rx.try_recv(), Ok(Notice::Refused)), "a second one");
        assert!(rx.try_recv().is_err(), "two in all");
        // the same request again: a step is attempted and refused
        let again = settings_step(
            &mut sched,
            &mut sched_mode,
            true,
            (0, &mut NoCells),
            Mode::Balanced,
        );
        assert!(matches!(
            again,
            Some((Mode::Strict, Err(Error::Unsupported)))
        ));
        assert_eq!(sched.effective_mode(), Mode::Strict);
        // a save of Strict leaves store and scheduler on Strict, with no step
        let same = settings_step(
            &mut sched,
            &mut sched_mode,
            true,
            (0, &mut NoCells),
            Mode::Strict,
        );
        assert!(matches!(same, Some((Mode::Strict, Ok(v))) if v.is_empty()));
        Ok(())
    }

    /// SE-195 (C2f-1; C-2g): a `SetSettings` waits while a revert is pending (the call stays in line, nothing is touched);
    /// after the revert it steps from the mode the scheduler is in.
    #[cfg(feature = "kat")]
    #[test]
    fn settings_wait_for_a_pending_revert() -> Result<(), Box<dyn std::error::Error>> {
        let mut sched = two_queues()?;
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut sched_mode = Mode::Balanced;
        let first = settings_step(
            &mut sched,
            &mut sched_mode,
            true,
            (0, &mut NoCells),
            Mode::Strict,
        );
        assert!(matches!(first, Some((Mode::Balanced, Ok(_)))));
        let mut backlog = Backlog(VecDeque::new());
        if let Some(back) = after_save(false, (Mode::Balanced, Mode::Strict), &tx) {
            backlog.push(Pending::Revert(back));
        }
        assert_eq!(backlog.0.len(), 1);
        let held = settings_step(
            &mut sched,
            &mut sched_mode,
            backlog.0.is_empty(),
            (0, &mut NoCells),
            Mode::Strict,
        );
        assert!(held.is_none());
        assert_eq!(sched.effective_mode(), Mode::Strict);
        assert_eq!(sched_mode, Mode::Strict);
        // the revert is applied
        assert!(matches!(
            backlog.0.pop_front(),
            Some(Pending::Revert(Mode::Balanced))
        ));
        let reverted = revert_step(
            &mut sched,
            &mut sched_mode,
            (0, &mut NoCells),
            Mode::Balanced,
            &tx,
        );
        assert!(reverted.is_ok());
        assert_eq!(sched.effective_mode(), Mode::Balanced);
        assert!(backlog.0.is_empty());
        let next = settings_step(
            &mut sched,
            &mut sched_mode,
            backlog.0.is_empty(),
            (0, &mut NoCells),
            Mode::Strict,
        );
        assert!(matches!(next, Some((Mode::Balanced, Ok(_)))));
        assert_eq!(sched.effective_mode(), Mode::Strict);
        Ok(())
    }

    /// Q301 (EXT3-2): a mode step whose phase draw fails is `Unavailable` (not a refusal of the mode) and changes nothing —
    /// the scheduler, `sched_mode` and the links stay on the old mode, and the same request, with randomness, works.
    #[cfg(feature = "kat")]
    #[test]
    fn settings_step_failed_draw_then_old_mode_keeps_scheduler_in_step()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::scheduler::core::LinkKind;

        let mut sched = Scheduler::new(
            Params::default(),
            Mode::Strict,
            TimingRng::failing_after(5, 2),
        );
        for n in 1..=2_u8 {
            let cap = RecvCap::from_seed(&SecretBytes::from_slice(&[n; 32])?)?;
            sched.add_recv_queue(0, RelayId(1), cap, 10_000)?;
        }
        let mut sched_mode = Mode::Strict;
        let failed = settings_step(
            &mut sched,
            &mut sched_mode,
            true,
            (0, &mut NoCells),
            Mode::Balanced,
        );
        assert!(matches!(
            failed,
            Some((Mode::Strict, Err(Error::Unavailable)))
        ));
        assert_eq!(
            (sched.effective_mode(), sched.mode(), sched_mode),
            (Mode::Strict, Mode::Strict, Mode::Strict)
        );
        let kinds: Vec<LinkKind> = sched.links().iter().map(|l| l.kind).collect();
        assert_eq!(kinds, [LinkKind::Recv, LinkKind::Recv]);
        let same = settings_step(
            &mut sched,
            &mut sched_mode,
            true,
            (0, &mut NoCells),
            Mode::Strict,
        );
        assert!(matches!(same, Some((Mode::Strict, Ok(v))) if v.is_empty()));
        assert_eq!(sched.effective_mode(), Mode::Strict);
        Ok(())
    }

    /// T3-3 — EXT3b-3 (V-EXT3b-34 T3-3): a control operation the scheduler cannot queue for want of randomness is kept and nothing is queued; the next attempt with randomness queues it.
    #[test]
    fn unscheduled_control_op_is_kept_for_the_next_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::scheduler::control::{OpSpec, When};
        let mut sched = Scheduler::new(Params::default(), Mode::Strict, TimingRng::seeded(7));
        sched.set_control_rng(TimingRng::failing());
        let spec = OpSpec {
            kind: ControlKind::LinkGetOwner(5),
            relay: RelayId(1),
            related: 5,
            when: When::Delayed,
        };
        let mut kept = Vec::new();
        schedule_or_keep(&mut sched, 0, spec, &mut kept)?;
        assert_eq!((kept.clone(), sched.next_deadline()), (vec![spec], None));
        sched.set_control_rng(TimingRng::seeded(8));
        for again in core::mem::take(&mut kept) {
            schedule_or_keep(&mut sched, 1, again, &mut kept)?;
        }
        assert!(kept.is_empty());
        assert!(
            sched
                .next_deadline()
                .is_some_and(|t| (60_001..=3_600_001).contains(&t))
        );
        Ok(())
    }

    /// SE-193 (C2-8; C-2f; C-2g: no clock): the loop-side drain returns while another thread holds the hub's mutex (the
    /// holder releases only after the drain's result is in) and defers what needs the hub — and everything behind it, in
    /// order; once the lock is free the deferred item is applied next, then the rest.
    #[test]
    fn loop_side_hub_access_never_waits() {
        use std::sync::mpsc as std_mpsc;

        let hub = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let mut backlog = Backlog(VecDeque::new());
        for item in ["add", "remove", "add2"] {
            backlog.push(item);
        }
        let needs = |a: &&str| *a == "remove";
        let (held_tx, held_rx) = std_mpsc::channel();
        let (release_tx, release_rx) = std_mpsc::channel::<()>();
        let holder = {
            let hub = Arc::clone(&hub);
            std::thread::spawn(move || {
                let _guard = hub.lock();
                let _ = held_tx.send(());
                let _ = release_rx.recv();
            })
        };
        assert!(held_rx.recv().is_ok());
        let mut applied = Vec::new();
        let first = backlog.drain(&hub, needs, |a, _| applied.push(a));
        assert_eq!(first, Ok(()));
        assert_eq!(applied, ["add"], "the item behind the busy one waits too");
        assert_eq!(backlog.0.len(), 2);
        assert!(release_tx.send(()).is_ok());
        assert!(holder.join().is_ok());
        let second = backlog.drain(&hub, needs, |a, guard| {
            if let Some(guard) = guard {
                guard.push(a);
            }
            applied.push(a);
        });
        assert_eq!(second, Ok(()));
        assert_eq!(applied, ["add", "remove", "add2"], "in order");
        assert_eq!(
            hub.lock().map(|g| g.clone()).unwrap_or_default(),
            ["remove"]
        );
        assert!(backlog.0.is_empty());
    }
}
