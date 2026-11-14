// SPDX-License-Identifier: AGPL-3.0-or-later
//! The error and the events of the client core's request/response API (`docs/02` §4). One uniform error for the whole
//! crate surface that the UI sees: no variant carries a field with an id, a secret or a message of a lower layer
//! (CLAUDE.md §4). The request/response methods themselves are B-4…B-7; part 1 defines the names the rows of B-1…B-3 use.

use core::fmt;
use std::collections::BTreeMap;
use std::sync::Arc;

use secmp_crypto::Zeroizing;
use secmp_proto::tr::content::Trust;
use secmp_proto::wire::cell::ControlCode;
use tokio::sync::{mpsc, oneshot};

use crate::clock::Clock;
use crate::contacts::Contacts;
use crate::outbox::StoreOutbox;
use crate::persist::{SharedStore, StorePersist};
use crate::profile::Profile;
use crate::relay_view;
use crate::scheduler::params::{Mode, Params};
use crate::scheduler::types::{QueueId, RelayId};
use crate::sessions::actor::{Conversations, EntropySource, Refusal, SessionEvent};
use crate::sessions::{self, StoreConversation};
use crate::settings::{DeliveredReceipts, Settings};
use crate::timing::TimingRng;

/// A contact (the row id; also the id of its session).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContactId(pub i64);

/// Why an invitation was refused (spec §5.5, TEST-SPEC IN-12): the class is computed locally from the invitation and the
/// opened link data, shown to the user, never logged and never sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InviteReject {
    /// `now ≥ expires`.
    Expired,
    /// The version byte of the invitation or its kind byte is not the one this build speaks.
    Unsupported,
    /// The inviter's identity in the link data is not the one the invitation names.
    Mismatch,
    /// Anything else: a malformed invitation, a link data that does not open, a bundle that does not verify.
    Invalid,
}

impl fmt::Display for InviteReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Expired => "invitation expired",
            Self::Unsupported => "invitation not supported",
            Self::Mismatch => "invitation does not match link data",
            Self::Invalid => "invitation invalid",
        })
    }
}

/// The error of the `Api`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The profile could not be unlocked (uniform: a wrong passphrase, a file that is no profile).
    Unlock,
    /// The store or the environment could not complete the operation; nothing was changed.
    Unavailable,
    /// The contact does not take real messages (it removed us, or its identity changed and is not verified again).
    Blocked,
    /// The session is frozen (an invalid key change, spec §7.7); only a reset (spec §7.8) helps.
    Frozen,
    /// A session reset was requested (either side, spec §7.8); real messages wait for a new invitation.
    ResetRequested,
    /// The contact is not verified and the operation needs it.
    Unverified,
    /// The contact came from a restored backup and must be invited again.
    ReinviteRequired,
    /// The operation needs the user's confirmation first.
    ConfirmRequired,
    /// An export path inside a cloud-synchronised folder.
    CloudFolder,
    /// Not supported by this build.
    Unsupported,
    /// An invitation was refused.
    Invitation(InviteReject),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unlock => f.write_str("the profile could not be unlocked"),
            Self::Unavailable => f.write_str("unavailable"),
            Self::Blocked => f.write_str("the contact does not accept messages"),
            Self::Frozen => f.write_str("the session is frozen"),
            Self::ResetRequested => f.write_str("a session reset was requested"),
            Self::Unverified => f.write_str("the contact is not verified"),
            Self::ReinviteRequired => f.write_str("the contact must be invited again"),
            Self::ConfirmRequired => f.write_str("confirmation required"),
            Self::CloudFolder => f.write_str("the path is inside a cloud-synchronised folder"),
            Self::Unsupported => f.write_str("not supported"),
            Self::Invitation(r) => r.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

impl From<secmp_store::Error> for Error {
    fn from(e: secmp_store::Error) -> Self {
        match e {
            secmp_store::Error::Unlock => Self::Unlock,
            secmp_store::Error::Unsupported | secmp_store::Error::TooNew => Self::Unsupported,
            secmp_store::Error::ConfirmRequired => Self::ConfirmRequired,
            secmp_store::Error::CloudFolder => Self::CloudFolder,
            _ => Self::Unavailable,
        }
    }
}

impl From<secmp_proto::Error> for Error {
    /// A protocol refusal on the client's own data (never on untrusted input, which has its own mapping) is the
    /// environment's failure from the caller's point of view.
    fn from(_: secmp_proto::Error) -> Self {
        Self::Unavailable
    }
}

impl From<secmp_crypto::Error> for Error {
    /// As for [`secmp_proto::Error`]: a failure of the client's own keys or of the environment.
    fn from(_: secmp_crypto::Error) -> Self {
        Self::Unavailable
    }
}

/// An event for the user interface (no secret in any field; `Debug` prints the variant name only, Q206).
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A handshake presented the identity of an existing contact (ADR-044 (f), O-29): the new contact `new` was created,
    /// unverified, beside `existing`; nothing was merged.
    DuplicateIdentity {
        /// The contact that already held the identity.
        existing: ContactId,
        /// The contact the handshake created.
        new: ContactId,
    },
    /// An invitation was consumed by someone else: the owner status says used, no handshake came before `expires`.
    InvitationUsedElsewhere,
    /// An unconsumed invitation was retired (Q164, SE-09); `id` is its link-data number.
    InvitationRetired {
        /// The invitation.
        id: u32,
        /// Why.
        reason: RetireReason,
    },
    /// A queue rotation did not start: it would exceed the rate bound or the 32 entries of a `FETCH_MULTI` (spec §10.2), or
    /// the pool has no spare queue.
    RotationDeferred(ContactId),
    /// A message arrived from `contact` (a view-once is held in memory, locked until the contact is verified).
    MessageReceived {
        /// The sender.
        contact: ContactId,
        /// The message.
        msg_id: [u8; 16],
        /// `AppMessage.kind`.
        kind: u8,
    },
    /// The contact announced new routes (spec §9.8).
    RoutesChanged(ContactId),
    /// The contact's identity changed (a verified `KeyChange`, spec §7.7): verify the new safety number.
    KeyChanged(ContactId),
    /// A `KeyChange` did not verify: the session is frozen (spec §7.7).
    KeyChangeInvalid(ContactId),
    /// The contact removed us (`Control{1}`, ADR-054 item 4).
    ContactRemoved(ContactId),
    /// A session reset was requested (`Control{2}`): issue a new invitation (spec §7.8).
    ResetRequested(ContactId),
    /// A message was relayed and no receipt came within `T_RS` (OQ-19; not re-sent).
    NotConfirmed {
        /// The recipient.
        contact: ContactId,
        /// The message.
        msg_id: [u8; 16],
    },
    /// A view-once queued by an earlier run was lost with it (it was in memory only, ST-17).
    ViewOnceLost([u8; 16]),
    /// An identity succession towards the contact has been pending for 24 h, or two or more are pending (ADR-060 (6),
    /// Q246): the contact has not fetched the earlier `KeyChange` yet. Nothing is skipped or given up.
    SuccessionPending(ContactId),
}

impl core::fmt::Debug for Event {
    /// The variant name only: no id, no message id (CLAUDE.md §4 logging; Q206).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::DuplicateIdentity { .. } => "DuplicateIdentity",
            Self::InvitationUsedElsewhere => "InvitationUsedElsewhere",
            Self::InvitationRetired { .. } => "InvitationRetired",
            Self::RotationDeferred(_) => "RotationDeferred",
            Self::MessageReceived { .. } => "MessageReceived",
            Self::RoutesChanged(_) => "RoutesChanged",
            Self::KeyChanged(_) => "KeyChanged",
            Self::KeyChangeInvalid(_) => "KeyChangeInvalid",
            Self::ContactRemoved(_) => "ContactRemoved",
            Self::ResetRequested(_) => "ResetRequested",
            Self::NotConfirmed { .. } => "NotConfirmed",
            Self::ViewOnceLost(_) => "ViewOnceLost",
            Self::SuccessionPending(_) => "SuccessionPending",
        })
    }
}

/// The length of a field in a redacting `Debug` (`<7 bytes>`): never its bytes (Q206, CLAUDE.md §1.6).
struct Len(usize);

impl core::fmt::Debug for Len {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "<{} bytes>", self.0)
    }
}

/// Why an invitation was retired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetireReason {
    /// The user rotated the identity (spec §7.7; Q164).
    IdentityRotated,
}

// ---------------------------------------------------------------------------------------------------------------------
// The request/response API (docs/02 §4.1, §6): the UI's only way into the core. `Api` is the handle (a `tokio::sync` request
// channel and an event stream); `Core` owns the profile, the sessions and the clock and answers one request at a time.
// Nothing here wakes, adds or removes a slot of the schedule (spec §10.1): a request changes outbox, trust and store state
// only; a refused one changes nothing. The Api names no store type and no secret in its public surface (AP-02).
// ---------------------------------------------------------------------------------------------------------------------

/// The Unix time in milliseconds the clock stamps an event with, and the id of a message (16 random bytes).
pub type MessageId = [u8; 16];

/// An event with the time of the clock it was raised at (AP-07: only the injected clock).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stamped {
    /// Unix milliseconds.
    pub at_ms: u64,
    /// What happened.
    pub event: Event,
}

/// What a request asks of the core (`Debug` prints the variant name and the lengths of its byte fields only, Q206).
#[non_exhaustive]
pub enum Request {
    /// The contacts.
    Contacts,
    /// The 60-digit safety number of a contact (spec §6.7).
    SafetyNumber {
        /// The contact.
        contact: ContactId,
    },
    /// Verify a contact by the digits the user typed.
    Verify {
        /// The contact.
        contact: ContactId,
        /// The digits (spaces ignored).
        digits: String,
    },
    /// Queue a message.
    Send {
        /// The contact.
        contact: ContactId,
        /// `AppMessage.kind`.
        kind: u8,
        /// The payload.
        payload: Zeroizing<Vec<u8>>,
        /// `expire_after` in seconds (0: never).
        expire_after: u32,
    },
    /// Show a received view-once.
    Reveal {
        /// The contact.
        contact: ContactId,
        /// The message.
        msg_id: MessageId,
    },
    /// Rotate the recv-queue of a contact (spec §10.6 (4)).
    Rotate {
        /// The contact.
        contact: ContactId,
        /// The relay whose pool provides the new queue.
        relay: u32,
    },
    /// Rotate the user's identity (spec §7.7). Never refused because of another contact (ADR-060 (4), Q244): towards a
    /// contact whose earlier `KeyChange` is still live the new one waits behind it ([`Event::SuccessionPending`]).
    RotateIdentity,
    /// Ask a contact for a new session (spec §7.8).
    ResetSession {
        /// The contact.
        contact: ContactId,
    },
    /// Remove a contact (`Control{ContactRemoved}`, spec §7.6, ADR-054 item 4): the peer is told, real messages stop, the
    /// slots keep carrying dummies.
    Remove {
        /// The contact.
        contact: ContactId,
    },
    /// The settings.
    Settings,
    /// Replace the settings.
    SetSettings(Settings),
    /// "What the relay can see" (spec §11.3).
    RelayView {
        /// Direct (non-Tor) transport.
        direct: bool,
    },
    /// Write the backup file, on the user's explicit request only (CS-3.5).
    Export {
        /// Where.
        path: std::path::PathBuf,
        /// The backup passphrase.
        passphrase: Zeroizing<Vec<u8>>,
        /// The user confirmed.
        confirm: bool,
        /// The user accepts a cloud-synchronised folder.
        force: bool,
    },
}

/// The answer to a [`Request`] (`Debug` as for [`Request`]).
#[non_exhaustive]
pub enum Response {
    /// The contacts.
    Contacts(Vec<crate::contacts::Contact>),
    /// The safety number.
    SafetyNumber(String),
    /// Whether the digits matched (the contact is verified then).
    Verified(bool),
    /// The id of the queued message.
    Sent(MessageId),
    /// The payload of a view-once.
    Revealed(Zeroizing<Vec<u8>>),
    /// Whether the rotation started (else `Event::RotationDeferred`).
    Rotated(bool),
    /// The new fingerprint.
    IdentityRotated([u8; 32]),
    /// The settings.
    Settings(Settings),
    /// The lines of the page.
    RelayView(Vec<&'static str>),
    /// Done.
    Done,
}

impl core::fmt::Debug for Request {
    /// The variant name and the byte lengths: no payload, passphrase, digits, path or id (Q206).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Contacts => f.write_str("Contacts"),
            Self::SafetyNumber { .. } => f.write_str("SafetyNumber"),
            Self::Verify { digits, .. } => f
                .debug_struct("Verify")
                .field("digits", &Len(digits.len()))
                .finish_non_exhaustive(),
            Self::Send { payload, .. } => f
                .debug_struct("Send")
                .field("payload", &Len(payload.len()))
                .finish_non_exhaustive(),
            Self::Reveal { .. } => f.write_str("Reveal"),
            Self::Rotate { .. } => f.write_str("Rotate"),
            Self::RotateIdentity => f.write_str("RotateIdentity"),
            Self::ResetSession { .. } => f.write_str("ResetSession"),
            Self::Remove { .. } => f.write_str("Remove"),
            Self::Settings => f.write_str("Settings"),
            Self::SetSettings(_) => f.write_str("SetSettings"),
            Self::RelayView { .. } => f.write_str("RelayView"),
            Self::Export { passphrase, .. } => f
                .debug_struct("Export")
                .field("passphrase", &Len(passphrase.len()))
                .finish_non_exhaustive(),
        }
    }
}

impl core::fmt::Debug for Response {
    /// The variant name and the byte lengths: no plaintext, safety number, fingerprint or contact (Q206).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Contacts(_) => f.write_str("Contacts"),
            Self::SafetyNumber(digits) => f
                .debug_tuple("SafetyNumber")
                .field(&Len(digits.len()))
                .finish(),
            Self::Verified(_) => f.write_str("Verified"),
            Self::Sent(_) => f.write_str("Sent"),
            Self::Revealed(payload) => f
                .debug_tuple("Revealed")
                .field(&Len(payload.len()))
                .finish(),
            Self::Rotated(_) => f.write_str("Rotated"),
            Self::IdentityRotated(_) => f.write_str("IdentityRotated"),
            Self::Settings(_) => f.write_str("Settings"),
            Self::RelayView(_) => f.write_str("RelayView"),
            Self::Done => f.write_str("Done"),
        }
    }
}

/// What the scheduler tells the core about its recv-queues: the rate bound of a rotation counts every one (spec §10.2).
#[derive(Clone, Debug, Default)]
pub struct SchedulerView {
    /// Direct (non-Tor) transport, which implies Balanced.
    pub direct: bool,
    /// The periods (ms) of every recv-queue, those in overlap included.
    pub recv_periods_ms: Vec<u64>,
}

/// The core behind the [`Api`]: one profile, its sessions, the clock.
pub struct Core<C: Clock, S: EntropySource> {
    pub(crate) profile: Profile,
    pub(crate) store: SharedStore,
    pub(crate) clock: C,
    pub(crate) make_source: Box<dyn FnMut() -> S>,
    pub(crate) convs: Conversations<StoreOutbox, StorePersist, S>,
    pub(crate) index: BTreeMap<i64, usize>,
    pub(crate) events: Vec<Stamped>,
    pub(crate) settings: Settings,
    pub(crate) view: SchedulerView,
    pub(crate) rng: TimingRng,
    pub(crate) ops: Vec<crate::scheduler::control::OpSpec>,
    /// The contacts whose routes changed since the hub last looked (the hub moves the send queue).
    pub(crate) routes_changed: Vec<ContactId>,
    /// The rotations that started since the hub last looked (the hub registers the new queue).
    pub(crate) rotated: Vec<RotationDone>,
    /// The period of the queue a rotation makes current.
    pub(crate) rotation_period: secmp_proto::wire::Period,
}

/// A rotation that started: the queue the scheduler fetches from now on.
pub(crate) struct RotationDone {
    pub(crate) relay: RelayId,
    pub(crate) queue: QueueId,
    pub(crate) recv_seed: secmp_crypto::SecretBytes<32>,
    pub(crate) period: secmp_proto::wire::Period,
    pub(crate) retire_op: Option<crate::scheduler::control::OpSpec>,
}

impl<C: Clock, S: EntropySource> Core<C, S> {
    /// Open the profile in `dir` under `passphrase`.
    ///
    /// # Errors
    /// [`Error::Unlock`] — uniformly — for a wrong passphrase (or none); [`Error::Unavailable`] otherwise: a directory that
    /// holds no profile, a profile another process holds, a store that does not open (PR-03; VERIFY-B4 P1 m-4). Nothing is
    /// written then.
    pub fn open(
        dir: &std::path::Path,
        passphrase: &[u8],
        clock: C,
        make_source: impl FnMut() -> S + 'static,
    ) -> Result<Self, Error> {
        let unlocked = secmp_store::wrap::unlock(dir, passphrase)?;
        Self::with_profile(Profile::open_with(dir, &unlocked)?, clock, make_source)
    }

    /// [`Core::open`] accepting `accept` as the key-derivation cost (feature `kat`, tests only).
    ///
    /// # Errors
    /// As [`Core::open`].
    #[cfg(feature = "kat")]
    pub fn open_kat(
        dir: &std::path::Path,
        passphrase: &[u8],
        accept: secmp_store::wrap::Argon2Params,
        clock: C,
        make_source: impl FnMut() -> S + 'static,
    ) -> Result<Self, Error> {
        let unlocked = secmp_store::wrap::unlock_kat(dir, passphrase, accept)?;
        Self::with_profile(Profile::open_with(dir, &unlocked)?, clock, make_source)
    }

    /// Restore a backup into a new profile in `dir` (CS-3.5; only on the user's request): the identity, the settings and the
    /// messages of the file; every contact must be invited again (`Error::ReinviteRequired` on a send, BK-03); fresh
    /// signed and one-time prekeys — new key material, none of the source's (Q197).
    ///
    /// # Errors
    /// [`Error::Unlock`] — uniformly — for a file that is no backup under `backup_passphrase`; [`Error::Unavailable`]
    /// otherwise. Nothing of the file is written on any error.
    pub fn restore(
        dir: &std::path::Path,
        passphrase: &[u8],
        backup: &std::path::Path,
        backup_passphrase: &[u8],
        clock: C,
        make_source: impl FnMut() -> S + 'static,
    ) -> Result<Self, Error> {
        let unlocked = secmp_store::wrap::create(dir, passphrase)?;
        let mut store = secmp_store::Store::open_unlocked(dir, &unlocked)?;
        let now_ms = clock.unix_secs().saturating_mul(1_000);
        secmp_store::backup::import(&mut store, backup, backup_passphrase, now_ms)?;
        Self::after_restore(store, clock, make_source)
    }

    /// [`Core::restore`] accepting `accept` as the key-derivation cost of both files (feature `kat`, tests only).
    ///
    /// # Errors
    /// As [`Core::restore`].
    #[cfg(feature = "kat")]
    pub fn restore_kat(
        dir: &std::path::Path,
        passphrase: &[u8],
        backup: &std::path::Path,
        backup_passphrase: &[u8],
        accept: secmp_store::wrap::Argon2Params,
        clock: C,
        make_source: impl FnMut() -> S + 'static,
    ) -> Result<Self, Error> {
        let unlocked = secmp_store::wrap::create_kat(dir, passphrase, accept)?;
        let mut store = secmp_store::Store::open_unlocked(dir, &unlocked)?;
        let now_ms = clock.unix_secs().saturating_mul(1_000);
        secmp_store::backup::import_kat(&mut store, backup, backup_passphrase, accept, now_ms)?;
        Self::after_restore(store, clock, make_source)
    }

    fn after_restore(
        store: secmp_store::Store,
        clock: C,
        mut make_source: impl FnMut() -> S + 'static,
    ) -> Result<Self, Error> {
        let profile = Profile::from_store(Arc::new(std::sync::Mutex::new(store)));
        let mut source = make_source();
        profile.maintain(&clock, source.entropy())?;
        profile.fill_opks(1, source.entropy())?;
        Self::with_profile(profile, clock, make_source)
    }

    /// The core of an open profile: the settings, the sessions of every contact that has one, and — after a restart — the
    /// view-once messages the last run lost (`Event::ViewOnceLost`, ST-17).
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be read.
    pub fn with_profile(
        profile: Profile,
        clock: C,
        make_source: impl FnMut() -> S + 'static,
    ) -> Result<Self, Error> {
        let store = profile.store();
        let settings = Settings::load(&store)?;
        let mut core = Self {
            profile,
            store,
            clock,
            make_source: Box::new(make_source),
            convs: Conversations::default(),
            index: BTreeMap::new(),
            events: Vec::new(),
            settings,
            view: SchedulerView::default(),
            rng: TimingRng::os(),
            ops: Vec::new(),
            routes_changed: Vec::new(),
            rotated: Vec::new(),
            rotation_period: secmp_proto::wire::Period::S80,
        };
        let lost = core
            .store
            .lock()
            .map_err(|_| Error::Unavailable)?
            .take_view_once_lost()?;
        for id in lost {
            core.raise(Event::ViewOnceLost(id));
        }
        for contact in sessions::ready_contacts(&core.store)? {
            core.open_session(contact)?;
        }
        Ok(core)
    }

    /// Queue a `KeyChange` the test built (possibly one that does not verify, spec §7.7): tests only.
    ///
    /// # Errors
    /// [`Error::Unavailable`] for an unknown contact or without randomness.
    #[cfg(feature = "kat")]
    pub fn queue_key_change_kat(
        &mut self,
        contact: ContactId,
        body: secmp_proto::wire::cell::KeyChangeBody,
    ) -> Result<(), Error> {
        self.session(contact)?
            .queue_key_change(body)
            .map_err(|_| Error::Unavailable)
    }

    /// Seed the timing randomness of the core (the overlap of a rotation): tests only, for runs that repeat.
    #[cfg(feature = "kat")]
    pub fn seed_timing_kat(&mut self, seed: u64) {
        self.rng = TimingRng::seeded(seed);
    }

    /// The profile's store, shared with the sessions (a test reads rows through it).
    #[must_use]
    pub(crate) fn profile_store(&self) -> SharedStore {
        Arc::clone(&self.store)
    }

    /// The clock the core stamps with.
    #[must_use]
    pub const fn clock(&self) -> &C {
        &self.clock
    }

    pub(crate) fn now_ms(&self) -> u64 {
        self.clock.unix_secs().saturating_mul(1_000)
    }

    pub(crate) fn raise(&mut self, event: Event) {
        let at_ms = self.now_ms();
        self.events.push(Stamped { at_ms, event });
    }

    pub(crate) fn contacts(&self) -> Result<Contacts, Error> {
        Ok(Contacts::new(
            Arc::clone(&self.store),
            self.profile.fingerprint()?,
        ))
    }

    pub(crate) fn open_session(&mut self, contact: ContactId) -> Result<(), Error> {
        let base = self.now_ms().saturating_sub(self.clock.mono_ms());
        let mut conversation =
            sessions::open_conversation(&self.store, contact, (self.make_source)(), base)?;
        conversation.set_send_receipts(self.receipts_for(conversation.trust()));
        // `T_RS` of the queue the contact is sent to (SE-13b, Q210 d)
        if let Some(period_ms) = sessions::send_period_ms(&self.store, contact)? {
            conversation
                .set_receipt_timeout_ms(crate::sessions::actor::receipt_timeout_ms(period_ms));
        }
        let at = self.convs.add(conversation);
        self.index.insert(contact.0, at);
        Ok(())
    }

    const fn receipts_for(&self, trust: Trust) -> bool {
        match self.settings.delivered_receipts {
            DeliveredReceipts::Off => false,
            DeliveredReceipts::All => true,
            DeliveredReceipts::VerifiedOnly => matches!(trust, Trust::Verified),
        }
    }

    /// The conversation of `contact`; [`Error::ReinviteRequired`] if it has none because it came from a backup.
    fn session(&mut self, contact: ContactId) -> Result<&mut StoreConversation<S>, Error> {
        let Some(at) = self.index.get(&contact.0).copied() else {
            self.contacts()?.check_send(contact)?;
            return Err(Error::Unavailable);
        };
        self.convs.get_mut(at).ok_or(Error::Unavailable)
    }

    /// The sessions (the tests of this module deliver cells by hand).
    #[cfg(test)]
    pub(crate) const fn conversations_mut(
        &mut self,
    ) -> &mut Conversations<StoreOutbox, StorePersist, S> {
        &mut self.convs
    }

    /// The scheduler's recv-queues, as the rate bound of a rotation sees them.
    pub fn set_scheduler_view(&mut self, view: SchedulerView) {
        self.view = view;
    }

    /// The control operations the requests asked for since the last call (the driver schedules them).
    pub fn take_ops(&mut self) -> Vec<crate::scheduler::control::OpSpec> {
        core::mem::take(&mut self.ops)
    }

    /// The events raised since the last call, oldest first.
    pub fn take_events(&mut self) -> Vec<Stamped> {
        core::mem::take(&mut self.events)
    }

    /// Take what the sessions delivered since the last call: received messages go to the history (a view-once is held in
    /// memory), the session events become [`Event`]s. The driver calls this after its receive commits.
    ///
    /// # Errors
    /// [`Error::Unavailable`] if the store cannot be written.
    pub fn pump(&mut self) -> Result<(), Error> {
        let now = self.now_ms();
        let contacts: Vec<(i64, usize)> = self.index.iter().map(|(c, i)| (*c, *i)).collect();
        for (id, at) in contacts {
            let contact = ContactId(id);
            let Some(conversation) = self.convs.get_mut(at) else {
                continue;
            };
            let session_events = conversation.take_events();
            let received = conversation.take_received();
            for event in session_events {
                let event = self.session_event(contact, &event)?;
                self.raise(event);
            }
            for (msg_id, kind) in sessions::store_received(&self.store, contact, received, now)? {
                self.raise(Event::MessageReceived {
                    contact,
                    msg_id,
                    kind,
                });
            }
        }
        Ok(())
    }

    fn session_event(&mut self, contact: ContactId, event: &SessionEvent) -> Result<Event, Error> {
        Ok(match event {
            SessionEvent::Routes(_) => {
                self.routes_changed.push(contact);
                Event::RoutesChanged(contact)
            }
            // the new identity was committed with the cell (Q210 a)
            SessionEvent::KeyChanged(_) => Event::KeyChanged(contact),
            SessionEvent::KeyChangeInvalid => Event::KeyChangeInvalid(contact),
            SessionEvent::ContactRemoved => {
                self.contacts()?.on_control(
                    contact,
                    &secmp_proto::wire::cell::ControlBody {
                        code: ControlCode::ContactRemoved,
                        arg: Zeroizing::new(Vec::new()),
                    },
                )?;
                Event::ContactRemoved(contact)
            }
            SessionEvent::ResetRequested => Event::ResetRequested(contact),
            SessionEvent::NotConfirmed(msg_id) => Event::NotConfirmed {
                contact,
                msg_id: *msg_id,
            },
            SessionEvent::SuccessionPending => Event::SuccessionPending(contact),
        })
    }

    /// Answer one request; the events it raised follow in [`Core::take_events`].
    ///
    /// # Errors
    /// The request's refusal; nothing was changed then.
    pub fn handle(&mut self, request: Request) -> Result<Response, Error> {
        let answer = match request {
            Request::Contacts => Response::Contacts(self.contacts()?.list()?),
            Request::SafetyNumber { contact } => {
                Response::SafetyNumber(self.contacts()?.safety_number(contact)?.as_str().to_owned())
            }
            Request::Verify { contact, digits } => self.verify(contact, &digits)?,
            Request::Send {
                contact,
                kind,
                payload,
                expire_after,
            } => {
                let (now, contacts) = (self.now_ms(), self.contacts()?);
                let store = Arc::clone(&self.store);
                let conversation = self.session(contact)?;
                Response::Sent(sessions::queue_message(
                    &store,
                    &contacts,
                    conversation,
                    contact,
                    &sessions::Outgoing {
                        kind,
                        payload: &payload,
                        expire_after,
                    },
                    now,
                )?)
            }
            Request::Reveal { contact, msg_id } => {
                let (now, store) = (self.now_ms(), Arc::clone(&self.store));
                let conversation = self.session(contact)?;
                Response::Revealed(sessions::reveal(&store, conversation, &msg_id, now)?)
            }
            Request::Rotate { contact, relay } => self.rotate(contact, RelayId(relay))?,
            Request::RotateIdentity => self.rotate_identity()?,
            Request::ResetSession { contact } => {
                let store = Arc::clone(&self.store);
                let conversation = self.session(contact)?;
                // the block is durable before the request is planned (Q210 b)
                sessions::block_session(&store, conversation, contact, Refusal::Reset)?;
                Response::Done
            }
            Request::Remove { contact } => {
                let store = Arc::clone(&self.store);
                let conversation = self.session(contact)?;
                sessions::block_session(&store, conversation, contact, Refusal::Removed)?;
                self.contacts()?.on_control(
                    contact,
                    &secmp_proto::wire::cell::ControlBody {
                        code: ControlCode::ContactRemoved,
                        arg: Zeroizing::new(Vec::new()),
                    },
                )?;
                Response::Done
            }
            Request::Settings => Response::Settings(self.settings),
            Request::SetSettings(settings) => {
                settings.save(&self.store)?;
                self.settings = settings;
                Response::Done
            }
            Request::RelayView { direct } => {
                Response::RelayView(relay_view::relay_view(self.settings.mode, direct))
            }
            Request::Export {
                path,
                passphrase,
                confirm,
                force,
            } => {
                secmp_store::backup::export(
                    &*self.store.lock().map_err(|_| Error::Unavailable)?,
                    &path,
                    &passphrase,
                    confirm,
                    force,
                )?;
                Response::Done
            }
        };
        self.pump()?;
        Ok(answer)
    }

    /// `Request::Verify`: with a session the contact flag and the trust are written in one transaction
    /// (`sessions::set_verified`), so a frozen session refuses both — [`Error::Frozen`], the contact stays unverified (Q205).
    fn verify(&mut self, contact: ContactId, digits: &str) -> Result<Response, Error> {
        if !self.index.contains_key(&contact.0) {
            return Ok(Response::Verified(
                self.contacts()?.confirm_digits(contact, digits)?,
            ));
        }
        let ok = self.contacts()?.digits_match(contact, digits)?;
        if ok {
            let store = Arc::clone(&self.store);
            let receipts = self.settings.delivered_receipts;
            let conversation = self.session(contact)?;
            sessions::set_verified(&store, conversation, contact)?;
            conversation.set_send_receipts(!matches!(receipts, DeliveredReceipts::Off));
        }
        Ok(Response::Verified(ok))
    }

    fn rotate(&mut self, contact: ContactId, relay: RelayId) -> Result<Response, Error> {
        Ok(Response::Rotated(self.rotate_contact(contact, relay)?))
    }

    /// Rotate the recv-queue of `contact` onto a pooled queue of `relay` (spec §10.6 (4)): on success the `RouteUpdate` is
    /// queued on the session, the previous queue is in overlap and a [`RotationDone`] is left for the hub to register with
    /// the scheduler; otherwise `Event::RotationDeferred`. Returns whether the rotation started.
    pub(crate) fn rotate_contact(
        &mut self,
        contact: ContactId,
        relay: RelayId,
    ) -> Result<bool, Error> {
        let (now, store) = (self.now_ms(), Arc::clone(&self.store));
        let old_queue = {
            let s = store.lock().map_err(|_| Error::Unavailable)?;
            match s.contact_queues(contact.0)? {
                Some(bytes) => sessions::rotation::QueueSet::decode(&bytes)?
                    .entries
                    .last()
                    .map(|e| QueueId(e.queue)),
                None => None,
            }
        };
        let mode = if self.view.direct && matches!(self.settings.mode, Mode::Strict) {
            Mode::Balanced
        } else {
            self.settings.mode
        };
        let params = Params::default();
        let periods = self.view.recv_periods_ms.clone();
        let at = *self.index.get(&contact.0).ok_or(Error::Unavailable)?;
        let conversation = self.convs.get_mut(at).ok_or(Error::Unavailable)?;
        let outcome = sessions::rotation::rotate(
            &store,
            conversation,
            &sessions::rotation::RotateRequest {
                contact,
                relay,
                period: self.rotation_period,
                mode,
                params: &params,
                recv_periods_ms: &periods,
                old_queue,
                unix_base_ms: now.saturating_sub(self.clock.mono_ms()),
            },
            now,
            &mut self.rng,
        )?;
        match outcome {
            sessions::rotation::Rotated::Started {
                queue,
                recv_seed,
                retire_op,
                ..
            } => {
                if let Some(conversation) = self.convs.get_mut(at) {
                    conversation.rotate_recv_queue(queue);
                }
                self.rotated.push(RotationDone {
                    relay,
                    queue,
                    recv_seed,
                    period: self.rotation_period,
                    retire_op,
                });
                Ok(true)
            }
            sessions::rotation::Rotated::Deferred(event) => {
                self.raise(event);
                Ok(false)
            }
        }
    }

    fn rotate_identity(&mut self) -> Result<Response, Error> {
        // no profile-wide refusal (ADR-060 (4), Q244, OPEN-M7-B-17): each contact gets its `KeyChange`, signed now by the
        // current identity, and a conversation plans only the head of its chain — a link waits while a copy of the one
        // before it may still reach the peer (ADR-058: one previous identity), so one stuck contact holds back only itself
        let mut source = (self.make_source)();
        let ready: Vec<(i64, usize)> = self.index.iter().map(|(c, i)| (*c, *i)).collect();
        let sessions: Vec<i64> = ready.iter().map(|(c, _)| *c).collect();
        let rotation = self
            .profile
            .rotate_identity(&sessions, &self.clock, source.entropy())?;
        // the `KeyChange`s are durable with the identity (Q210 c); here they are planned
        for (((_, at), body), ord) in ready
            .into_iter()
            .zip(rotation.key_changes)
            .zip(rotation.pending)
        {
            if let Some(conversation) = self.convs.get_mut(at) {
                // a plan failure keeps the content and answers Ok (Q240); this `?` stops only at an encode error of the
                // body, which the profile has just built (known, unchanged): every row is committed already and the
                // next open plans the contacts after this one
                conversation
                    .queue_pending(ord, crate::sessions::actor::PendingControl::KeyChange(body))
                    .map_err(|_| Error::Unavailable)?;
            }
        }
        let maintained =
            crate::invitations::retirement(&rotation.retired, Some(RetireReason::IdentityRotated));
        for event in maintained.events {
            self.raise(event);
        }
        self.ops.extend(maintained.ops);
        Ok(Response::IdentityRotated(rotation.fingerprint))
    }
}

type Envelope = (Request, oneshot::Sender<Result<Response, Error>>);

/// The handle of the UI: requests go over a `tokio::sync` channel to the core's task, answers come back on a `oneshot`,
/// events on a stream (`docs/02` §4.1).
pub struct Api {
    requests: mpsc::Sender<Envelope>,
    events: mpsc::UnboundedReceiver<Stamped>,
}

/// The task that runs a [`Core`]: await it on the runtime (or a `LocalSet`) next to the UI.
pub type Serve = core::pin::Pin<Box<dyn core::future::Future<Output = ()>>>;

impl Api {
    /// The handle and the task of `core`.
    #[must_use]
    pub fn new<C: Clock + 'static, S: EntropySource + 'static>(
        mut core: Core<C, S>,
    ) -> (Self, Serve) {
        let (requests, mut inbox) = mpsc::channel::<Envelope>(32);
        let (events_tx, events) = mpsc::unbounded_channel();
        let serve = async move {
            // events of the open (a view-once lost in the last run) come first
            for event in core.take_events() {
                let _ = events_tx.send(event);
            }
            while let Some((request, reply)) = inbox.recv().await {
                let answer = core.handle(request);
                for event in core.take_events() {
                    let _ = events_tx.send(event);
                }
                let _ = reply.send(answer);
            }
        };
        (Self { requests, events }, Box::pin(serve))
    }

    /// Send a request and wait for its one answer.
    ///
    /// # Errors
    /// The request's refusal; [`Error::Unavailable`] if the core's task is gone.
    pub async fn call(&self, request: Request) -> Result<Response, Error> {
        let (reply, answer) = oneshot::channel();
        self.requests
            .send((request, reply))
            .await
            .map_err(|_| Error::Unavailable)?;
        answer.await.map_err(|_| Error::Unavailable)?
    }

    /// The next event, in the order the core raised them; `None` once the core's task has ended and the stream is drained.
    pub async fn next_event(&mut self) -> Option<Stamped> {
        self.events.recv().await
    }

    /// An event already raised, if any.
    pub fn try_event(&mut self) -> Option<Stamped> {
        self.events.try_recv().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::future::Future;

    #[cfg(feature = "kat")]
    use crate::scheduler::outbox::Outbox as _;
    #[cfg(feature = "kat")]
    use crate::sessions::tests::{R, World, big, deliver, ms, next, route, text, world};
    #[cfg(feature = "kat")]
    use crate::testutil::{E, Fixed, T0, entropy};

    /// A current-thread runtime with a `LocalSet` for the core's task.
    #[cfg(feature = "kat")]
    fn run<F: Future>(f: F) -> Result<F::Output, E> {
        let rt = tokio::runtime::Builder::new_current_thread().build()?;
        Ok(rt.block_on(f))
    }

    /// The entropy of the next conversation or operation: a new stream for each call.
    #[cfg(feature = "kat")]
    fn sources(seed: u64) -> impl FnMut() -> Fixed {
        let mut n = 0_u64;
        move || {
            n = n.saturating_add(1);
            Fixed(entropy(seed.saturating_add(n)))
        }
    }

    /// A `Send` of `text` as `kind`.
    #[cfg(feature = "kat")]
    fn send(contact: ContactId, kind: u8, text: &[u8]) -> Request {
        Request::Send {
            contact,
            kind,
            payload: Zeroizing::new(text.to_vec()),
            expire_after: 0,
        }
    }

    /// The row count of `table` in the store.
    #[cfg(feature = "kat")]
    fn rows(store: &SharedStore, table: &str) -> Result<i64, E> {
        let s = store.lock().map_err(|_| "lock")?;
        Ok(s.connection_kat()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?)
    }

    /// AP-01 (`docs/02:84`, F9, ST-17): every request kind once gets one response, over `tokio::sync` channels; the events
    /// come in the order they were raised — here the `ViewOnceLost` of the previous run and the session events of two cells
    /// the peer sent before the first request (a route update, a message); a refused outbox insert (F9) is an error
    /// response and queues nothing.
    #[cfg(feature = "kat")]
    #[test]
    fn request_response_and_events() -> R {
        big(|| {
            let World {
                guest, mut h, g, ..
            } = world("ap01", 71)?;
            // the previous run queued a view-once and ended: its id is reported lost
            guest
                .profile
                .store()
                .lock()
                .map_err(|_| "lock")?
                .queue_view_once([0x44; 16], b"gone")?;
            drop(g);
            let guest = guest.reopen()?;
            let store = guest.profile.store();
            let mut core =
                Core::with_profile(guest.profile.clone(), guest.clock.clone(), sources(900))?;
            // the peer's first reply and a message reach the guest's session
            h.queue_route_update(vec![route(1)?]);
            let reply = next(&mut h, ms(4))?;
            h.outbox_mut().enqueue(text(9, 6), 0);
            let message = next(&mut h, ms(14))?;
            let conv = core.conversations_mut().get_mut(0).ok_or("conversation")?;
            deliver(conv, &reply)?;
            deliver(conv, &message)?;
            run(async move {
                let (mut api, serve) = Api::new(core);
                let _: &mpsc::Sender<Envelope> = &api.requests;
                let local = tokio::task::LocalSet::new();
                local.spawn_local(serve);
                local.run_until(requests(&mut api, &store)).await
            })??;
            Ok(())
        })
    }

    /// F9: the store refuses the outbox row — an error response, nothing queued, no history row.
    #[cfg(feature = "kat")]
    async fn refused_outbox_insert(api: &mut Api, store: &SharedStore, contact: ContactId) -> R {
        let (outbox, history) = (rows(store, "outbox")?, rows(store, "messages")?);
        let trigger = "CREATE TRIGGER refuse BEFORE INSERT ON outbox \
                       BEGIN SELECT RAISE(ABORT, 'refused'); END";
        store
            .lock()
            .map_err(|_| "lock")?
            .connection_kat()
            .execute_batch(trigger)?;
        assert!(matches!(
            api.call(send(contact, 1, b"refused")).await,
            Err(Error::Unavailable)
        ));
        store
            .lock()
            .map_err(|_| "lock")?
            .connection_kat()
            .execute_batch("DROP TRIGGER refuse")?;
        assert_eq!(
            (rows(store, "outbox")?, rows(store, "messages")?),
            (outbox, history)
        );
        Ok(())
    }

    /// The requests of AP-01, one of each kind.
    #[cfg(feature = "kat")]
    async fn requests(api: &mut Api, store: &SharedStore) -> R {
        let Response::Contacts(list) = api.call(Request::Contacts).await? else {
            return Err("contacts".into());
        };
        let contact = list.first().ok_or("contact")?.id;
        assert_eq!(list.len(), 1);
        let Response::SafetyNumber(number) = api.call(Request::SafetyNumber { contact }).await?
        else {
            return Err("safety number".into());
        };
        assert_eq!(number.chars().filter(char::is_ascii_digit).count(), 60);
        let wrong = Request::Verify {
            contact,
            digits: "1".into(),
        };
        assert!(matches!(api.call(wrong).await?, Response::Verified(false)));
        let right = Request::Verify {
            contact,
            digits: number,
        };
        assert!(matches!(api.call(right).await?, Response::Verified(true)));
        // sends: text; kind 2 is unsupported (SE-20); a view-once to the verified contact
        let Response::Sent(id) = api.call(send(contact, 1, b"hello")).await? else {
            return Err("sent".into());
        };
        assert!(matches!(
            api.call(send(contact, 2, b"x")).await,
            Err(Error::Unsupported)
        ));
        let Response::Sent(vo) = api.call(send(contact, 3, b"once")).await? else {
            return Err("sent view-once".into());
        };
        assert_ne!(id, vo);
        refused_outbox_insert(api, store, contact).await?;
        let unknown = Request::Reveal {
            contact,
            msg_id: [0x55; 16],
        };
        assert!(matches!(api.call(unknown).await, Err(Error::Unavailable)));
        // rotation, settings, relay view, export without confirmation, identity rotation, reset
        let rotate = Request::Rotate { contact, relay: 1 };
        assert!(matches!(api.call(rotate).await?, Response::Rotated(true)));
        let Response::Settings(mut settings) = api.call(Request::Settings).await? else {
            return Err("settings".into());
        };
        settings.mode = crate::scheduler::params::Mode::Balanced;
        assert!(matches!(
            api.call(Request::SetSettings(settings)).await?,
            Response::Done
        ));
        let Response::RelayView(lines) = api.call(Request::RelayView { direct: false }).await?
        else {
            return Err("relay view".into());
        };
        assert_eq!(lines.len(), 6);
        let export = Request::Export {
            path: std::env::temp_dir().join("secmp-ap01-never"),
            passphrase: Zeroizing::new(b"x".to_vec()),
            confirm: false,
            force: false,
        };
        assert!(matches!(
            api.call(export).await,
            Err(Error::ConfirmRequired)
        ));
        assert!(matches!(
            api.call(Request::RotateIdentity).await?,
            Response::IdentityRotated(_)
        ));
        assert!(matches!(
            api.call(Request::ResetSession { contact }).await?,
            Response::Done
        ));
        assert!(matches!(
            api.call(send(contact, 1, b"after")).await,
            Err(Error::ResetRequested)
        ));
        // removing the contact: the peer is told, real sends are refused
        assert!(matches!(
            api.call(Request::Remove { contact }).await?,
            Response::Done
        ));
        assert!(matches!(
            api.call(send(contact, 1, b"gone")).await,
            Err(Error::Blocked)
        ));
        // the events, in order
        let mut events = Vec::new();
        while let Some(e) = api.try_event() {
            events.push(e.event);
        }
        let want = [
            Event::ViewOnceLost([0x44; 16]),
            Event::RoutesChanged(contact),
            Event::MessageReceived {
                contact,
                msg_id: [9; 16],
                kind: 1,
            },
        ];
        assert_eq!(events, want);
        Ok(())
    }

    /// PR-08 through the wiring (OPEN-M7-B-8; §7.6 Control code 1, ADR-054 item 4): the peer removes the contact; the core
    /// marks it removed (`Event::ContactRemoved`, state `Removed`), a send is `Err(Blocked)`, and the schedule is as it was —
    /// the session prepares one cell for every slot before and after (the removed contact's slots carry dummies), nothing
    /// real is pending, and no slot appears or disappears (Δ = 0).
    #[cfg(feature = "kat")]
    #[test]
    fn contact_removed_keeps_schedule() -> R {
        big(|| {
            let World {
                guest, mut h, g, ..
            } = world("pr08", 91)?;
            drop(g);
            let mut core =
                Core::with_profile(guest.profile.clone(), guest.clock.clone(), sources(930))?;
            let slots = |core: &mut Core<_, Fixed>, from: u64| -> Result<usize, E> {
                let conv = core.conversations_mut().get_mut(0).ok_or("conversation")?;
                let mut n = 0;
                for k in 0..5 {
                    if conv.prepare_direct(ms(from + 10 * k)).is_ok() {
                        n += 1;
                    }
                }
                assert!(!conv.has_pending_real());
                Ok(n)
            };
            let before = slots(&mut core, 0)?;
            // the host's first reply, then the removal
            h.queue_route_update(vec![route(1)?]);
            let reply = next(&mut h, ms(4))?;
            h.queue_control(secmp_proto::wire::cell::ControlCode::ContactRemoved);
            let removal = next(&mut h, ms(14))?;
            let conv = core.conversations_mut().get_mut(0).ok_or("conversation")?;
            deliver(conv, &reply)?;
            deliver(conv, &removal)?;
            core.pump()?;
            let events: Vec<Event> = core.take_events().into_iter().map(|s| s.event).collect();
            assert_eq!(
                events,
                [
                    Event::RoutesChanged(ContactId(1)),
                    Event::ContactRemoved(ContactId(1))
                ]
            );
            let Response::Contacts(list) = core.handle(Request::Contacts)? else {
                return Err("contacts".into());
            };
            assert_eq!(
                list.first().map(|c| c.state),
                Some(crate::contacts::ContactState::Removed)
            );
            let refused = core.handle(Request::Send {
                contact: ContactId(1),
                kind: 1,
                payload: Zeroizing::new(b"x".to_vec()),
                expire_after: 0,
            });
            assert!(matches!(refused, Err(Error::Blocked)));
            assert_eq!(slots(&mut core, 100)?, before, "Δ = 0 slots");
            assert_eq!(before, 5);
            Ok(())
        })
    }

    /// AP-03 (§11.3 `docs/03:717-725`, Q156): the page lists items 1–5 of §11.3 word for word — read from the spec file —
    /// in every mode; Balanced, Low-bandwidth and direct add the grouping sentence (`docs/03:662`), direct the IP-exposure
    /// sentence (`docs/03:231`); nothing else, and Strict without direct has nothing added.
    #[test]
    fn relay_view_lists_11_3() {
        use crate::relay_view::{GROUPING, IP_EXPOSURE, LEAKAGE, relay_view};

        let spec = include_str!("../../../docs/03-protocol-spec.md").replace("\r\n", "\n");
        let section = spec
            .split("### 11.3 Accepted leakage")
            .nth(1)
            .and_then(|s| s.split("\n---").next())
            .unwrap_or_default();
        let items: Vec<&str> = section
            .lines()
            .filter_map(|l| {
                let (n, rest) = l.split_once(". ")?;
                n.chars().all(|c| c.is_ascii_digit()).then_some(rest)
            })
            .collect();
        assert_eq!(items, LEAKAGE, "verbatim from the spec");
        assert!(spec.contains(GROUPING) && spec.contains(IP_EXPOSURE));
        let five = LEAKAGE.to_vec();
        let with = |extra: &[&'static str]| [five.clone(), extra.to_vec()].concat();
        for (mode, direct, want) in [
            (Mode::Strict, false, with(&[])),
            (Mode::Balanced, false, with(&[GROUPING])),
            (Mode::LowBw, false, with(&[GROUPING])),
            (Mode::Strict, true, with(&[GROUPING, IP_EXPOSURE])),
            (Mode::Balanced, true, with(&[GROUPING, IP_EXPOSURE])),
            (Mode::LowBw, true, with(&[GROUPING, IP_EXPOSURE])),
        ] {
            assert_eq!(relay_view(mode, direct), want, "{mode:?} direct={direct}");
        }
    }

    /// AP-07 (CLAUDE.md §4 time): every event is stamped by the injected clock — a `ManualClock` here — and the product
    /// source of the module reads no real clock (the `SystemTime::now` gate stands).
    #[cfg(feature = "kat")]
    #[test]
    fn clock_injected() -> R {
        big(|| {
            let World { guest, g, .. } = world("ap07", 73)?;
            drop(g);
            let clock = guest.clock.clone();
            let mut core = Core::with_profile(guest.profile.clone(), clock.clone(), sources(910))?;
            core.raise(Event::KeyChanged(ContactId(1)));
            clock.advance_ms(7_000);
            core.raise(Event::KeyChangeInvalid(ContactId(1)));
            clock.advance_ms(86_400_000);
            core.raise(Event::ResetRequested(ContactId(1)));
            let t0 = T0 * 1_000;
            let stamps: Vec<u64> = core.take_events().iter().map(|e| e.at_ms).collect();
            assert_eq!(stamps, [t0, t0 + 7_000, t0 + 86_407_000]);
            let source = include_str!("api.rs").replace("\r\n", "\n");
            let product = source
                .split("#[cfg(test)]\nmod tests")
                .next()
                .unwrap_or_default();
            // spelled in parts so that the wall-clock scan (m6_driver) does not count this line
            for real in [
                concat!("System", "Time::now"),
                concat!("Insta", "nt::now"),
                "chrono",
            ] {
                assert!(!product.contains(real), "{real}");
            }
            Ok(())
        })
    }

    /// BK-03, `Api` half (CS-3.5; Q142, Q197): a profile with one-time prekeys and a contact is exported and imported into a
    /// fresh profile; the contact needs a new invitation (`Api.send` → `ReinviteRequired`, no session is opened), and the
    /// prekeys the restored profile makes are new key material — no secret equals one of the source's.
    #[cfg(feature = "kat")]
    #[test]
    fn restore_requires_reinvite_api() -> R {
        use secmp_store::profile::KIND_OPK;
        use secmp_store::wrap::Argon2Params;

        big(|| {
            let World { guest, g, .. } = world("ap-bk03", 75)?;
            drop(g);
            guest.profile.fill_opks(3, &mut entropy(75))?;
            let source = guest.profile.store();
            let old: Vec<Vec<u8>> = {
                let s = source.lock().map_err(|_| "lock")?;
                let mut secrets = Vec::new();
                for row in s.prekeys(KIND_OPK)? {
                    secrets.push(s.prekey_secret(KIND_OPK, row.id)?.ok_or("opk")?.to_vec());
                }
                secrets
            };
            assert!(old.len() >= 3);
            let file = guest.dir.path().join("export.secmpbackup");
            secmp_store::backup::export_kat(
                &*source.lock().map_err(|_| "lock")?,
                &file,
                b"backup pass",
                Argon2Params::kat_small(),
            )?;
            let fresh = secmp_store::kat::TempDir::new("ap-bk03-fresh")?;
            let mut core = Core::restore_kat(
                fresh.path(),
                b"new pass",
                &file,
                b"backup pass",
                Argon2Params::kat_small(),
                guest.clock.clone(),
                sources(920),
            )?;
            let Response::Contacts(list) = core.handle(Request::Contacts)? else {
                return Err("contacts".into());
            };
            assert_eq!(list.len(), 1);
            assert_eq!(
                list.first().map(|c| c.state),
                Some(crate::contacts::ContactState::ReinviteRequired)
            );
            let send = core.handle(Request::Send {
                contact: ContactId(1),
                kind: 1,
                payload: Zeroizing::new(b"hi".to_vec()),
                expire_after: 0,
            });
            assert!(matches!(send, Err(Error::ReinviteRequired)));
            let restored = core.profile.store();
            let s = restored.lock().map_err(|_| "lock")?;
            let fresh_opks = s.prekeys(KIND_OPK)?;
            assert!(!fresh_opks.is_empty(), "fresh prekeys");
            for row in fresh_opks {
                let secret = s.prekey_secret(KIND_OPK, row.id)?.ok_or("opk")?.to_vec();
                assert!(!old.contains(&secret), "no secret of the source");
            }
            assert!(!s.prekeys(secmp_store::profile::KIND_SPK)?.is_empty());
            Ok(())
        })
    }

    /// Q210 d (VERIFY-B4 P1 M-4; SE-13b, spec §10.4): through the `Api` — the session opened by the core has `T_RS` of the
    /// queue it sends to; a message to the verified contact is relayed, no receipt comes, and when the clock passes `T_RS`
    /// `Event::NotConfirmed` is raised for it once.
    #[cfg(feature = "kat")]
    #[test]
    fn not_confirmed_fires_after_t_rs() -> R {
        use crate::sessions::actor::T_RS_MIN_MS;

        big(|| {
            let World {
                guest, mut h, g, ..
            } = world("q210d", 93)?;
            drop(g);
            let clock = guest.clock.clone();
            let mut core = Core::with_profile(guest.profile.clone(), clock.clone(), sources(960))?;
            // the handshake cells, then the host's first reply: real sends may start
            h.queue_route_update(vec![route(1)?]);
            let reply = next(&mut h, ms(4))?;
            {
                let conv = core.conversations_mut().get_mut(0).ok_or("conversation")?;
                for i in 0..3 {
                    conv.prepare_direct(ms(i)).map_err(|_| "handshake")?;
                }
                deliver(conv, &reply)?;
            }
            let Response::SafetyNumber(digits) = core.handle(Request::SafetyNumber {
                contact: ContactId(1),
            })?
            else {
                return Err("safety number".into());
            };
            let verified = core.handle(Request::Verify {
                contact: ContactId(1),
                digits,
            })?;
            assert!(matches!(verified, Response::Verified(true)));
            let Response::Sent(id) = core.handle(send(ContactId(1), 1, b"are you there"))? else {
                return Err("sent".into());
            };
            core.take_events();
            clock.set_ms(ms(10));
            let at = clock.mono_ms();
            let not_confirmed = |core: &mut Core<_, Fixed>, now: u64| -> Result<usize, E> {
                let conv = core.conversations_mut().get_mut(0).ok_or("conversation")?;
                conv.prepare_direct(now).map_err(|_| "prepare")?;
                core.pump()?;
                Ok(core
                    .take_events()
                    .iter()
                    .filter(|e| {
                        e.event
                            == Event::NotConfirmed {
                                contact: ContactId(1),
                                msg_id: id,
                            }
                    })
                    .count())
            };
            {
                let conv = core.conversations_mut().get_mut(0).ok_or("conversation")?;
                let prepared = conv.prepare_direct(at).map_err(|_| "message")?;
                conv.relayed_direct(prepared.token, 9);
            }
            clock.set_ms(ms(10).saturating_add(T_RS_MIN_MS).saturating_sub(1));
            assert_eq!(not_confirmed(&mut core, clock.mono_ms())?, 0, "before T_RS");
            clock.set_ms(ms(10).saturating_add(T_RS_MIN_MS));
            assert_eq!(not_confirmed(&mut core, clock.mono_ms())?, 1, "at T_RS");
            clock.set_ms(ms(20).saturating_add(T_RS_MIN_MS));
            assert_eq!(not_confirmed(&mut core, clock.mono_ms())?, 0, "once");
            Ok(())
        })
    }

    /// Q210 f (VERIFY-B4 P1 M-6, hand mutant M2): `Api.send` asks the trust — after a verified key change it is
    /// `Err(Blocked)`, after a forged one (frozen) `Err(Frozen)`; nothing is queued either time.
    #[cfg(feature = "kat")]
    #[test]
    fn send_refused_after_key_change() -> R {
        use secmp_proto::prekeys::IdentityKeys;
        use secmp_proto::tr::Entropy as _;

        big(|| {
            for (forged, want) in [(false, Error::Blocked), (true, Error::Frozen)] {
                let w = world("api-kc", 95 + u64::from(forged))?;
                let (host, guest) = (w.host, w.guest);
                drop((w.h, w.g));
                let mut host_core =
                    Core::with_profile(host.profile.clone(), host.clock.clone(), sources(970))?;
                let mut guest_core =
                    Core::with_profile(guest.profile.clone(), guest.clock.clone(), sources(980))?;
                let new = IdentityKeys::generate(&mut entropy(907))?;
                let signer = if forged {
                    entropy(909).hybrid_signing_key()?
                } else {
                    host.profile.signing_key()?
                };
                let body = secmp_proto::tr::content::key_change_body(&signer, new.public())?;
                host_core.queue_key_change_kat(ContactId(1), body)?;
                for at in 0..6 {
                    let cell = next(
                        host_core.conversations_mut().get_mut(0).ok_or("host")?,
                        ms(at),
                    )?;
                    deliver(
                        guest_core.conversations_mut().get_mut(0).ok_or("guest")?,
                        &cell,
                    )?;
                }
                guest_core.pump()?;
                let store = guest.profile.store();
                let before = rows(&store, "outbox")?;
                let sent = guest_core.handle(send(ContactId(1), 1, b"held"));
                assert_eq!(sent.err(), Some(want), "forged {forged}");
                assert_eq!(rows(&store, "outbox")?, before, "nothing queued");
            }
            Ok(())
        })
    }

    /// C1-4 a (VERIFY-DELTA-B4c part 1): `Request::Verify` of a contact that is not in `Core.index` (no loaded session) whose
    /// stored trust is `Frozen` is refused with `Err(Frozen)` and the contact flag is not written — the unguarded
    /// `contacts.verified` writer is gone (Q205).
    #[cfg(feature = "kat")]
    #[test]
    fn verify_without_session_keeps_stored_frozen() -> R {
        use secmp_store::sessions::{TRUST_FROZEN, update_trust};

        big(|| {
            let w = world("api-vf", 97)?;
            let host = w.host;
            drop((w.h, w.g));
            let store = host.profile.store();
            store
                .lock()
                .map_err(|_| "lock")?
                .txn(|tx| update_trust(tx, 1, Some(TRUST_FROZEN), None))?;
            let mut core =
                Core::with_profile(host.profile.clone(), host.clock.clone(), sources(990))?;
            core.index.remove(&1);
            let Response::SafetyNumber(digits) = core.handle(Request::SafetyNumber {
                contact: ContactId(1),
            })?
            else {
                return Err("safety number".into());
            };
            let verified = core.handle(Request::Verify {
                contact: ContactId(1),
                digits,
            });
            assert_eq!(verified.err(), Some(Error::Frozen));
            drop(core);
            let reopened =
                Core::with_profile(host.profile.clone(), host.clock.clone(), sources(991))?;
            let s = reopened.store.lock().map_err(|_| "lock")?;
            let rows = s.contacts()?;
            let row = rows.iter().find(|c| c.id == 1).ok_or("contact")?;
            assert!(!row.verified, "the contact stays unverified");
            Ok(())
        })
    }

    /// B-4c killer (`<Event as Debug>::fmt`, Q206): an event prints its variant's name and nothing of its fields.
    #[test]
    fn event_debug_names_the_variant_only() {
        assert_eq!(
            format!("{:?}", Event::KeyChanged(ContactId(7))),
            "KeyChanged"
        );
        let received = Event::MessageReceived {
            contact: ContactId(7),
            msg_id: [0xab; 16],
            kind: 1,
        };
        assert_eq!(format!("{received:?}"), "MessageReceived");
        assert_eq!(
            format!(
                "{:?}",
                Event::InvitationRetired {
                    id: 99,
                    reason: RetireReason::IdentityRotated
                }
            ),
            "InvitationRetired"
        );
        assert_eq!(
            format!("{:?}", Event::ViewOnceLost([1; 16])),
            "ViewOnceLost"
        );
    }

    /// Q206 (VERIFY-B4 P1 B-2, probe P3; CLAUDE.md §1.6): the `Debug` of a request or a response that carries a passphrase,
    /// a message or a view-once prints neither its bytes (as numbers) nor its text — the variant and the length only.
    #[test]
    fn debug_redacts_secrets() {
        let secret = |s: &str| Zeroizing::new(s.as_bytes().to_vec());
        let shown = [
            format!(
                "{:?}",
                Request::Export {
                    path: std::path::PathBuf::from("/tmp/x"),
                    passphrase: secret("hunter2"),
                    confirm: true,
                    force: false,
                }
            ),
            format!(
                "{:?}",
                Request::Send {
                    contact: ContactId(1),
                    kind: 1,
                    payload: secret("attack at dawn"),
                    expire_after: 0,
                }
            ),
            format!("{:?}", Response::Revealed(secret("secret view"))),
        ];
        for (text, out) in ["hunter2", "attack at dawn", "secret view"]
            .into_iter()
            .zip(&shown)
        {
            let numbers = text
                .bytes()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            assert!(!out.contains(text), "{out}");
            assert!(!out.contains(&numbers), "{out}");
            let first_two = numbers.split(", ").take(2).collect::<Vec<_>>().join(", ");
            assert!(!out.contains(&format!("[{first_two}")), "{out}");
        }
        assert_eq!(shown[0], "Export { passphrase: <7 bytes>, .. }");
        assert_eq!(shown[2], "Revealed(<11 bytes>)");
    }

    /// The `Display` texts are fixed and carry no detail; `Mismatch` is the text IN-12 pins.
    #[test]
    fn errors_display_fixed_text() {
        assert_eq!(
            InviteReject::Mismatch.to_string(),
            "invitation does not match link data"
        );
        assert_eq!(
            Error::Invitation(InviteReject::Expired).to_string(),
            "invitation expired"
        );
        assert_eq!(
            Error::Unlock.to_string(),
            "the profile could not be unlocked"
        );
        assert_eq!(Error::from(secmp_store::Error::TooNew), Error::Unsupported);
        assert_eq!(Error::from(secmp_store::Error::Unlock), Error::Unlock);
        assert_eq!(
            Error::from(secmp_store::Error::Unavailable),
            Error::Unavailable
        );
        assert_eq!(
            Error::from(secmp_store::Error::ConfirmRequired),
            Error::ConfirmRequired
        );
        assert_eq!(
            Error::from(secmp_store::Error::CloudFolder),
            Error::CloudFolder
        );
        assert_eq!(
            Error::from(secmp_store::Error::Unsupported),
            Error::Unsupported
        );
    }

    /// B-4…B-7 killers (`Core::receipts_for`, `verify`): delivery receipts follow the setting — off, for verified contacts
    /// only, for all — when a session is opened, and verifying a contact turns them on unless they are off.
    #[cfg(feature = "kat")]
    #[test]
    fn receipts_follow_the_setting_and_the_verification() -> R {
        big(|| {
            for (n, (setting, at_open, after_verify)) in [
                (DeliveredReceipts::Off, false, false),
                (DeliveredReceipts::VerifiedOnly, false, true),
                (DeliveredReceipts::All, true, true),
            ]
            .into_iter()
            .enumerate()
            {
                let w = world("api-receipts", 81 + u64::try_from(n)?)?;
                let store = w.guest.profile.store();
                let guest = w.guest;
                drop((w.h, w.g));
                let mut settings = Settings::load(&store)?;
                settings.delivered_receipts = setting;
                settings.save(&store)?;
                let mut core =
                    Core::with_profile(guest.profile.clone(), guest.clock.clone(), sources(910))?;
                let receipts = |core: &mut Core<_, Fixed>| {
                    core.conversations_mut()
                        .get(0)
                        .map(super::super::sessions::actor::Conversation::send_receipts_kat)
                };
                assert_eq!(receipts(&mut core), Some(at_open), "{setting:?} at open");
                let Response::SafetyNumber(digits) = core.handle(Request::SafetyNumber {
                    contact: ContactId(1),
                })?
                else {
                    return Err("safety number".into());
                };
                let wrong = core.handle(Request::Verify {
                    contact: ContactId(1),
                    digits: "1".into(),
                })?;
                assert!(matches!(wrong, Response::Verified(false)));
                assert_eq!(
                    receipts(&mut core),
                    Some(at_open),
                    "{setting:?}: a wrong number changes nothing"
                );
                let right = core.handle(Request::Verify {
                    contact: ContactId(1),
                    digits,
                })?;
                assert!(matches!(right, Response::Verified(true)));
                assert_eq!(
                    receipts(&mut core),
                    Some(after_verify),
                    "{setting:?} after the verification"
                );
            }
            Ok(())
        })
    }

    /// B-4…B-7 killers (`set_scheduler_view`, `rotate_contact`; SE-04): the rate bound sees the recv-queues the scheduler
    /// reports — in Balanced mode and in direct mode, which implies it, not in Strict mode — and `take_ops` hands over the
    /// retirement of the invitation an identity rotation retired, once.
    #[cfg(feature = "kat")]
    #[test]
    fn rotation_sees_the_scheduler_and_identity_rotation_leaves_ops() -> R {
        use crate::scheduler::params::Mode;

        big(|| {
            let w = world("api-view", 83)?;
            let guest = w.guest;
            drop((w.h, w.g));
            let mut core =
                Core::with_profile(guest.profile.clone(), guest.clock.clone(), sources(920))?;
            let rotate = |core: &mut Core<_, Fixed>| {
                core.handle(Request::Rotate {
                    contact: ContactId(1),
                    relay: 1,
                })
            };
            let full = |direct| SchedulerView {
                direct,
                recv_periods_ms: vec![10_000; 4],
            };
            // Strict, not direct: no bound
            core.set_scheduler_view(full(false));
            assert!(matches!(rotate(&mut core)?, Response::Rotated(true)));
            // Strict and direct: Balanced, four queues at 10 s are full
            core.set_scheduler_view(full(true));
            assert!(matches!(rotate(&mut core)?, Response::Rotated(false)));
            // Balanced, full: deferred; Balanced, empty view: starts
            let mut settings = core.handle(Request::Settings).map(|r| match r {
                Response::Settings(s) => s,
                _ => Settings::default(),
            })?;
            settings.mode = Mode::Balanced;
            core.handle(Request::SetSettings(settings))?;
            core.set_scheduler_view(full(false));
            assert!(matches!(rotate(&mut core)?, Response::Rotated(false)));
            core.set_scheduler_view(SchedulerView::default());
            assert!(matches!(rotate(&mut core)?, Response::Rotated(true)));
            let deferred = core
                .take_events()
                .iter()
                .filter(|e| matches!(e.event, Event::RotationDeferred(_)))
                .count();
            assert_eq!(deferred, 2);
            // an open invitation is retired by the identity rotation: its QUEUE_DEL is left for the driver
            let w = world("api-ops", 85)?;
            let (host, _) = (w.host, w.guest);
            drop((w.h, w.g));
            let (_issued, _cells) = crate::sessions::tests::pending_handshake(&host, 87)?;
            let mut core =
                Core::with_profile(host.profile.clone(), host.clock.clone(), sources(930))?;
            assert!(core.take_ops().is_empty());
            let rotated = core.handle(Request::RotateIdentity)?;
            assert!(matches!(rotated, Response::IdentityRotated(_)));
            let ops = core.take_ops();
            assert!(
                ops.iter()
                    .any(|op| matches!(op.kind, crate::scheduler::types::ControlKind::QueueDel(_))),
                "{} ops",
                ops.len()
            );
            assert!(core.take_ops().is_empty(), "handed over once");
            Ok(())
        })
    }

    /// SE-34 (re-dictated by Q244, ADR-060 (4); was Q222, OPEN-M7-B-12): a second identity rotation while the
    /// `KeyChange` of the first is in flight is taken (`IdentityRotated`, a new fingerprint, a second row) and its
    /// `KeyChange` waits behind the first; once the first has left its eviction window, its row is gone, the second is the
    /// head, and a third rotation adds a row again.
    #[cfg(feature = "kat")]
    #[test]
    fn second_rotation_waits_behind_the_live_key_change() -> R {
        big(|| {
            let w = world("api-kc-guard", 941)?;
            let host = w.host;
            drop((w.h, w.g, w.guest));
            let mut core =
                Core::with_profile(host.profile.clone(), host.clock.clone(), sources(941))?;
            let Response::IdentityRotated(fp1) = core.handle(Request::RotateIdentity)? else {
                return Err("rotated".into());
            };
            let Response::IdentityRotated(fp2) = core.handle(Request::RotateIdentity)? else {
                return Err("Q244: a live KeyChange refuses no rotation".into());
            };
            assert_ne!(fp1, fp2);
            assert_eq!(host.profile.fingerprint()?, fp2);
            assert_eq!(control_rows(&host)?, 2);
            let conv = core.convs.get_mut(0).ok_or("conversation")?;
            assert_eq!(conv.successions_pending(), 2);
            for i in 0..4_u64 {
                let p = conv.prepare_direct(ms(10 + i)).map_err(|_| "prepare")?;
                conv.relayed_direct(p.token, 1 + i);
            }
            let dummy = conv.prepare_direct(ms(20)).map_err(|_| "prepare")?;
            conv.relayed_direct(dummy.token, 300);
            conv.prepare_direct(ms(21)).map_err(|_| "prepare")?;
            assert_eq!(conv.successions_pending(), 1, "the first has left");
            assert_eq!(control_rows(&host)?, 1);
            assert!(matches!(
                core.handle(Request::RotateIdentity)?,
                Response::IdentityRotated(_)
            ));
            assert_eq!(control_rows(&host)?, 2);
            Ok(())
        })
    }

    /// The pending control rows of contact 1 in `host`'s store.
    #[cfg(feature = "kat")]
    fn control_rows(host: &crate::testutil::Fixture) -> Result<usize, E> {
        Ok(host
            .profile
            .store()
            .lock()
            .map_err(|_| "lock")?
            .pending_controls(1)?
            .len())
    }

    /// SE-69 (re-dictated by Q244; was Q240, EXT2c-1): a restart after the `KeyChange`'s last `OK_SEND` but inside its
    /// eviction window keeps its row; the core opened again takes a second rotation, whose `KeyChange` waits behind the
    /// first one read back from its row (two pending, the fingerprint the new one).
    #[cfg(feature = "kat")]
    #[test]
    fn restart_in_the_window_keeps_the_chain() -> R {
        big(|| {
            let w = world("api-kc-q240", 943)?;
            let host = w.host;
            drop((w.h, w.g, w.guest));
            let mut core =
                Core::with_profile(host.profile.clone(), host.clock.clone(), sources(943))?;
            let Response::IdentityRotated(fp1) = core.handle(Request::RotateIdentity)? else {
                return Err("rotated".into());
            };
            let conv = core.convs.get_mut(0).ok_or("conversation")?;
            for i in 0..4_u64 {
                let p = conv.prepare_direct(ms(10 + i)).map_err(|_| "prepare")?;
                conv.relayed_direct(p.token, 1 + i);
            }
            conv.prepare_direct(ms(20)).map_err(|_| "prepare")?;
            assert_eq!(
                control_rows(&host)?,
                1,
                "Q240: the row outlives the last OK_SEND"
            );
            drop(core);
            let mut again =
                Core::with_profile(host.profile.clone(), host.clock.clone(), sources(944))?;
            let Response::IdentityRotated(fp2) = again.handle(Request::RotateIdentity)? else {
                return Err("Q244: rotated after the restart".into());
            };
            assert_ne!(fp1, fp2);
            assert_eq!(
                again
                    .convs
                    .get(0)
                    .map(crate::sessions::actor::Conversation::successions_pending),
                Some(2),
                "Q244: the second waits behind the first, read back from its row"
            );
            Ok(())
        })
    }

    /// SE-89 (Q244, ADR-060 (4); EXT2c-6, OPEN-M7-B-17): a contact whose `KeyChange` is still live (contact 1: nothing
    /// sent) does not hold back the profile: a second rotation is taken, contact 2 — whose first `KeyChange` has left its
    /// window — gets the second at once, and its peer accepts it under the identity of the first (two `KeyChanged`);
    /// contact 1 keeps both, in order, and the core raises `SuccessionPending` for contact 1 only.
    #[cfg(feature = "kat")]
    #[test]
    fn rotation_is_not_held_back_by_a_pending_contact() -> R {
        use crate::sessions::tests::{connect, party};

        big(|| {
            let w = world("api-chain-1", 947)?;
            let host = w.host;
            drop((w.h, w.g, w.guest));
            let other = party("api-chain-2", 951)?;
            let link = connect(&host, &other, 953)?;
            assert_eq!(link.contact, ContactId(2));
            let mut g2 = link.g;
            drop(link.h);
            let mut core =
                Core::with_profile(host.profile.clone(), host.clock.clone(), sources(956))?;
            let (one, two) = (
                *core.index.get(&1).ok_or("contact 1")?,
                *core.index.get(&2).ok_or("contact 2")?,
            );
            let Response::IdentityRotated(fp1) = core.handle(Request::RotateIdentity)? else {
                return Err("rotated".into());
            };
            let changed = |g: &mut crate::sessions::StoreConversation<Fixed>| {
                g.take_events()
                    .iter()
                    .filter(|e| matches!(e, crate::sessions::actor::SessionEvent::KeyChanged(_)))
                    .count()
            };
            let conv = core.convs.get_mut(two).ok_or("conversation 2")?;
            for i in 0..4_u64 {
                let p = conv.prepare_direct(ms(10 + i)).map_err(|_| "prepare")?;
                conv.relayed_direct(p.token, 1 + i);
                deliver(&mut g2, &p.cell)?;
            }
            let dummy = conv.prepare_direct(ms(20)).map_err(|_| "prepare")?;
            conv.relayed_direct(dummy.token, 300);
            deliver(&mut g2, &dummy.cell)?;
            deliver(&mut g2, &next(conv, ms(21))?)?;
            assert_eq!(conv.successions_pending(), 0);
            assert_eq!(changed(&mut g2), 1);
            assert!(
                core.convs
                    .get(one)
                    .is_some_and(crate::sessions::actor::Conversation::key_change_in_flight)
            );
            let Response::IdentityRotated(fp2) = core.handle(Request::RotateIdentity)? else {
                return Err("Q244: contact 1 holds back no rotation".into());
            };
            assert_ne!(fp1, fp2);
            let conv = core.convs.get_mut(two).ok_or("conversation 2")?;
            for i in 0..4_u64 {
                deliver(&mut g2, &next(conv, ms(30 + i))?)?;
            }
            assert_eq!(changed(&mut g2), 1, "contact 2 gets the second at once");
            assert_eq!(
                g2.trust(),
                secmp_proto::tr::content::Trust::KeyChanged,
                "not frozen"
            );
            let conv = core.convs.get_mut(one).ok_or("conversation 1")?;
            assert_eq!(conv.successions_pending(), 2);
            next(conv, ms(40))?;
            core.pump()?;
            let warned: Vec<ContactId> = core
                .take_events()
                .iter()
                .filter_map(|e| match e.event {
                    Event::SuccessionPending(c) => Some(c),
                    _ => None,
                })
                .collect();
            assert_eq!(warned, [ContactId(1)]);
            Ok(())
        })
    }

    /// SE-70 (Q240): once the `KeyChange` has left its eviction window its row is gone; a restart then plans no
    /// `KeyChange` (nothing is sent again) and a second rotation is taken, with exactly its own row.
    #[cfg(feature = "kat")]
    #[test]
    fn restart_after_the_window_resends_nothing_and_rotates() -> R {
        big(|| {
            let w = world("api-kc-q240b", 945)?;
            let host = w.host;
            drop((w.h, w.g, w.guest));
            let mut core =
                Core::with_profile(host.profile.clone(), host.clock.clone(), sources(945))?;
            core.handle(Request::RotateIdentity)?;
            let conv = core.convs.get_mut(0).ok_or("conversation")?;
            for i in 0..4_u64 {
                let p = conv.prepare_direct(ms(10 + i)).map_err(|_| "prepare")?;
                conv.relayed_direct(p.token, 1 + i);
            }
            let dummy = conv.prepare_direct(ms(20)).map_err(|_| "prepare")?;
            conv.relayed_direct(dummy.token, 261);
            conv.prepare_direct(ms(21)).map_err(|_| "prepare")?;
            assert_eq!(control_rows(&host)?, 0, "the row goes at the window's end");
            drop(core);
            let mut again =
                Core::with_profile(host.profile.clone(), host.clock.clone(), sources(946))?;
            assert!(
                !again
                    .convs
                    .get(0)
                    .is_some_and(crate::sessions::actor::Conversation::key_change_in_flight),
                "nothing is sent again"
            );
            assert!(matches!(
                again.handle(Request::RotateIdentity)?,
                Response::IdentityRotated(_)
            ));
            assert_eq!(control_rows(&host)?, 1);
            Ok(())
        })
    }

    /// B-4…B-7 killers (`Core::queue_key_change_kat`, `seed_timing_kat`; `Api::next_event`): a key change the test forged
    /// reaches the peer, whose session freezes — `KeyChangeInvalid` — and the events come out of the stream in order.
    #[cfg(feature = "kat")]
    #[test]
    fn forged_key_change_freezes_and_events_stream() -> R {
        use secmp_proto::prekeys::IdentityKeys;
        use secmp_proto::tr::Entropy as _;

        big(|| {
            let w = world("api-forged", 89)?;
            let (host, guest) = (w.host, w.guest);
            drop((w.h, w.g));
            let mut host_core =
                Core::with_profile(host.profile.clone(), host.clock.clone(), sources(940))?;
            let mut guest_core =
                Core::with_profile(guest.profile.clone(), guest.clock.clone(), sources(950))?;
            host_core.seed_timing_kat(3);
            assert_eq!(
                host_core.rng.uniform(1, 1_000),
                TimingRng::seeded(3).uniform(1, 1_000)
            );
            let forger = entropy(903).hybrid_signing_key()?;
            let new = IdentityKeys::generate(&mut entropy(905))?;
            let body = secmp_proto::tr::content::key_change_body(&forger, new.public())?;
            host_core.queue_key_change_kat(ContactId(1), body)?;
            for at in 0..6 {
                let cell = next(
                    host_core.conversations_mut().get_mut(0).ok_or("host")?,
                    ms(at),
                )?;
                deliver(
                    guest_core.conversations_mut().get_mut(0).ok_or("guest")?,
                    &cell,
                )?;
            }
            guest_core.pump()?;
            let events = guest_core.take_events();
            assert!(
                events
                    .iter()
                    .any(|e| e.event == Event::KeyChangeInvalid(ContactId(1))),
                "{events:?}"
            );
            // the stream hands the events over, oldest first
            guest_core.raise(Event::ResetRequested(ContactId(1)));
            guest_core.raise(Event::KeyChanged(ContactId(1)));
            let (mut api, serve) = Api::new(guest_core);
            let local = tokio::task::LocalSet::new();
            local.spawn_local(serve);
            let rt = tokio::runtime::Builder::new_current_thread().build()?;
            let got = rt.block_on(local.run_until(async {
                let first = api.next_event().await;
                let second = api.next_event().await;
                (first, second)
            }));
            assert_eq!(
                (got.0.map(|s| s.event), got.1.map(|s| s.event)),
                (
                    Some(Event::ResetRequested(ContactId(1))),
                    Some(Event::KeyChanged(ContactId(1)))
                )
            );
            Ok(())
        })
    }
}
