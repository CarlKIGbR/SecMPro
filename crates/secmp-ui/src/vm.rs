// SPDX-License-Identifier: AGPL-3.0-or-later
//! The view models: plain data the screens show and the state machine that turns the user's input into requests of the
//! [`bridge`](crate::bridge) and the bridge's responses into the next state. Nothing here touches the core, the store or a key;
//! it knows ids (as numbers) and enums only. Every method returns at once — an answer arrives later as a [`Response`].

use secmp_client_core::Zeroizing;

use slint::Image;

use crate::bridge::{Bridge, CoreEvent, LinkReport, Refused, Request, Response};
use crate::convo::{Body, Chat, HISTORY_PAGE, OutState, Warning, clock_text};
use crate::locale::{self, Lang, key};
use crate::qr::Matrix;

/// The screens of part 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    /// No profile yet: create one.
    Onboarding,
    /// A profile exists: unlock it.
    Unlock,
    /// The contact list of the open profile.
    Contacts,
    /// Issue and accept invitations.
    Invitations,
    /// The messages of one contact.
    Conversation,
    /// The safety number of that contact.
    Safety,
    /// The settings and the profile actions.
    Settings,
    /// The actions on one contact.
    Options,
    /// The engine has stopped: nothing is shown but the message.
    Stopped,
}

/// Whether the display is known to be protected against capture (docs/04 CS-1.2, CS-1.18). The model starts
/// [`Locked`](Self::Locked); no content is shown until the state changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    /// The platform confirmed the exclusion from capture.
    Verified,
    /// Only partly protected (blur, view-once): content is shown, a view-once is not revealed. Set by nothing before M9.
    Partial,
    /// Not verified (or not possible on this platform yet): contact names and everything later are not shown.
    Locked,
    /// The user chose, for this process only, to show content on an unprotected display (CS-1.9). Never persisted.
    Overridden,
}

/// The scheduler mode a user picks (spec §10.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeChoice {
    /// Strict.
    Strict,
    /// Balanced.
    Balanced,
    /// Low bandwidth.
    LowBw,
}

impl ModeChoice {
    /// The modes in the order the choice lists them.
    pub const ALL: [Self; 3] = [Self::Strict, Self::Balanced, Self::LowBw];

    /// The mode at `index` of [`Self::ALL`]; an index out of range is Strict (the default).
    #[must_use]
    pub fn from_index(index: i32) -> Self {
        usize::try_from(index)
            .ok()
            .and_then(|i| Self::ALL.get(i).copied())
            .unwrap_or(Self::Strict)
    }

    /// The position of the mode in [`Self::ALL`].
    #[must_use]
    pub const fn index(self) -> i32 {
        match self {
            Self::Strict => 0,
            Self::Balanced => 1,
            Self::LowBw => 2,
        }
    }

    /// The key of the mode's name in the locale tables.
    #[must_use]
    pub const fn name_key(self) -> &'static str {
        match self {
            Self::Strict => key::MODE_STRICT,
            Self::Balanced => key::MODE_BALANCED,
            Self::LowBw => key::MODE_LOWBW,
        }
    }
}

/// How long the message history is kept (CS-3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionChoice {
    /// Forever (the default).
    Keep,
    /// Delete messages older than this many days.
    Days(u32),
}

impl RetentionChoice {
    /// The choices the list offers besides a value the store holds that is not among them.
    pub const OFFERED: [Self; 5] = [
        Self::Keep,
        Self::Days(7),
        Self::Days(30),
        Self::Days(90),
        Self::Days(365),
    ];
}

/// Whom delivery receipts are sent to (spec §10.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptChoice {
    /// Nobody.
    Off,
    /// Verified contacts only (the default).
    VerifiedOnly,
    /// Every contact.
    All,
}

impl ReceiptChoice {
    /// The choices in the order the list shows them.
    pub const ALL: [Self; 3] = [Self::Off, Self::VerifiedOnly, Self::All];

    /// The key of the choice's name in the locale tables.
    #[must_use]
    pub const fn name_key(self) -> &'static str {
        match self {
            Self::Off => key::RECEIPTS_OFF,
            Self::VerifiedOnly => key::RECEIPTS_VERIFIED,
            Self::All => key::RECEIPTS_ALL,
        }
    }
}

/// The settings the UI shows and changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettingsView {
    /// The scheduler mode.
    pub mode: ModeChoice,
    /// How long the history is kept.
    pub retention: RetentionChoice,
    /// Delivery receipts.
    pub delivered: ReceiptChoice,
    /// Read receipts.
    pub read_receipts: bool,
}

/// What a contact or profile action did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionKind {
    /// The session keys were rotated.
    Rotate,
    /// A new session was asked for.
    Reset,
    /// The contact was removed.
    Remove,
    /// The identity was rotated.
    Identity,
    /// The backup was written.
    Export,
}

/// How the engine is doing, as far as the UI knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Engine {
    /// Answering.
    Working,
    /// It reported that it could not finish something just now (a transient notice).
    Notice,
    /// The bridge's thread is gone.
    Down,
}

/// What the connection line says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Link {
    Connecting,
    Connected,
    Unavailable,
}

/// An action the user asked for and has not confirmed yet: nothing is sent before the confirm click.
enum Confirm {
    Rotate(i64),
    Reset(i64),
    Remove(i64),
    Identity,
    Export {
        path: String,
        pass: Zeroizing<Vec<u8>>,
    },
    Mode(ModeChoice),
}

/// Why the last request did not go through. Wrong passphrase and damaged store are one case on purpose ([`Failure::Unlock`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The two passphrase fields differ.
    PassphraseMismatch,
    /// The passphrase is empty.
    PassphraseEmpty,
    /// The profile name is not usable as a directory name.
    NameInvalid,
    /// The profile could not be created.
    Create,
    /// The profile did not unlock, whatever the reason.
    Unlock,
    /// The bridge's queue is full.
    Busy,
    /// The engine or the bridge's thread is gone.
    Stopped,
    /// The profile was created, but the chosen mode was not stored.
    ModeNotSaved,
    /// No invitation can be issued yet (the pool has no spare queue).
    InvitePoolEmpty,
    /// An invitation could not be issued.
    InviteCreate,
    /// An invitation was refused, whatever the reason (malformed, truncated, used, expired: one message).
    InviteAccept,
    /// The core refused a message.
    Send(SendReason),
    /// A view-once could not be revealed.
    Reveal,
    /// The core gave no safety number.
    Safety,
    /// The verification did not go through (the digits did not match, or the core refused).
    Verify,
    /// The earlier messages could not be read.
    History,
    /// The settings could not be read or stored.
    Settings,
    /// A contact or profile action was refused.
    Action,
    /// The backup could not be written.
    Export,
    /// The backup folder is synchronised to a cloud service.
    ExportCloud,
    /// The path or the passphrase of the backup is missing.
    ExportInput,
}

/// Why the core refused a message, as far as the user is told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendReason {
    /// Empty, too long or not plain text.
    Unsupported,
    /// The contact is blocked until its safety number is verified again.
    Blocked,
    /// The session is frozen.
    Frozen,
    /// The contact has to be invited again.
    Reinvite,
    /// Anything else.
    Other,
}

impl Failure {
    /// The key of the message in the locale tables.
    #[must_use]
    pub const fn message_key(self) -> &'static str {
        match self {
            Self::PassphraseMismatch => key::ERROR_MISMATCH,
            Self::PassphraseEmpty => key::ERROR_EMPTY_PASS,
            Self::NameInvalid => key::ERROR_NAME,
            Self::Create => key::ERROR_CREATE,
            Self::Unlock => key::ERROR_UNLOCK,
            Self::Busy => key::ERROR_BUSY,
            Self::Stopped => key::ERROR_STOPPED,
            Self::ModeNotSaved => key::ONBOARDING_MODE_NOT_SAVED,
            Self::InvitePoolEmpty => key::ERROR_INVITE_POOL_EMPTY,
            Self::InviteCreate => key::ERROR_INVITE_CREATE,
            Self::InviteAccept => key::ERROR_INVITE_ACCEPT,
            Self::Send(SendReason::Unsupported) => key::ERROR_SEND_UNSUPPORTED,
            Self::Send(SendReason::Blocked) => key::ERROR_SEND_BLOCKED,
            Self::Send(SendReason::Frozen) => key::ERROR_SEND_FROZEN,
            Self::Send(SendReason::Reinvite) => key::ERROR_SEND_REINVITE,
            Self::Send(SendReason::Other) => key::ERROR_SEND_OTHER,
            Self::Reveal => key::ERROR_REVEAL,
            Self::Safety => key::ERROR_SAFETY,
            Self::Verify => key::ERROR_VERIFY,
            Self::History => key::ERROR_HISTORY,
            Self::Settings => key::ERROR_SETTINGS,
            Self::Action => key::ERROR_ACTION,
            Self::Export => key::ERROR_EXPORT,
            Self::ExportCloud => key::ERROR_EXPORT_CLOUD,
            Self::ExportInput => key::ERROR_EXPORT_INPUT,
        }
    }
}

/// The state of a contact as a row shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowState {
    /// Sends and receives.
    Active,
    /// Has to be invited again.
    ReinviteRequired,
    /// Removed this client.
    Removed,
}

/// A contact as the list shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactRow {
    /// The contact's id.
    pub id: i64,
    /// The name the contact gave itself; empty if it gave none.
    pub name: String,
    /// The start of the fingerprint in hex, to tell two contacts of one name apart.
    pub key: String,
    /// The user has verified the safety number.
    pub verified: bool,
    /// The state.
    pub state: RowState,
}

/// What the contacts screen shows for one row, in the language of the interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowText {
    /// The name, or the placeholder for none.
    pub name: String,
    /// The key start.
    pub key: String,
    /// The verification state or, for a contact that cannot be written to, why.
    pub status: String,
    /// Whether the row is verified.
    pub verified: bool,
}

/// What the conversation screen shows for one message, in the language of the interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MsgText {
    /// The text, or the placeholder of a view-once.
    pub text: String,
    /// Who, when and how far it got.
    pub meta: String,
    /// Whether it was received.
    pub incoming: bool,
    /// Whether the row is a view-once the user may hold to reveal.
    pub hold: bool,
}

/// How long a view-once stays on the screen at most, in seconds, however long the user holds it (CS-1.14).
pub const REVEAL_MAX_S: u64 = 20;

/// The longest profile name (it names a directory and is the name shown in a handshake).
pub const NAME_MAX: usize = 32;

/// Whether `name` is usable as a profile name: 1 to [`NAME_MAX`] ASCII letters, digits, `-` or `_`.
#[must_use]
pub fn name_is_valid(name: &str) -> bool {
    (1..=NAME_MAX).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Whether two secrets are the same, without stopping at the first difference.
fn same_secret(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= usize::from(x ^ y);
    }
    diff == 0
}

/// The state of the window.
pub struct Vm {
    lang: Lang,
    screen: Screen,
    profile: String,
    contacts: Vec<ContactRow>,
    relay_lines: Vec<String>,
    failure: Option<Failure>,
    busy: bool,
    engine: Engine,
    invite: InviteState,
    chat: Chat,
    protection: Protection,
    settings: Option<SettingsView>,
    confirm: Option<Confirm>,
    notice: Option<&'static str>,
    status: Option<LinkReport>,
    profile_open: bool,
    reported: Option<Protection>,
}

/// What the invitation screen holds. The URI is a capability: it lives in a zeroising buffer, is shown as content only and is
/// dropped when the screen is left; its code is made once when the URI arrives.
#[derive(Default)]
struct InviteState {
    uri: Option<Zeroizing<String>>,
    qr: Option<Image>,
    accepting: bool,
    notice: Option<&'static str>,
}

impl Vm {
    /// A model that starts on `screen`; `profile` is the name of the existing profile on the unlock screen.
    #[must_use]
    pub fn new(lang: Lang, screen: Screen, profile: &str) -> Self {
        Self {
            lang,
            screen,
            profile: profile.to_owned(),
            contacts: Vec::new(),
            relay_lines: Vec::new(),
            failure: None,
            busy: false,
            engine: Engine::Working,
            invite: InviteState::default(),
            chat: Chat::default(),
            protection: Protection::Locked,
            settings: None,
            confirm: None,
            notice: None,
            status: None,
            profile_open: false,
            reported: None,
        }
    }

    /// The protection state of the display.
    #[must_use]
    pub const fn protection(&self) -> Protection {
        self.protection
    }

    /// Record what the platform check found (`Verified` after a confirmed exclusion, `Locked` for every other outcome).
    pub fn set_protection(&mut self, protection: Protection) {
        self.protection = protection;
        self.protection_changed();
    }

    /// What follows from a change of the protection state: a reveal is never kept on a display that is not verified.
    fn protection_changed(&mut self) {
        if self.protection != Protection::Verified {
            self.chat.release();
        }
    }

    /// Tell the core what the display state is, once per change and only while a profile is open (CS-1.18: the core can be
    /// asked what the UI reported). A full queue leaves it for the next answer.
    pub fn sync_display(&mut self, bridge: &Bridge) {
        if !self.profile_open || self.reported == Some(self.protection) {
            return;
        }
        if bridge
            .submit(Request::SetDisplayState(self.protection))
            .is_ok()
        {
            self.reported = Some(self.protection);
        }
    }

    /// Whether content (names, keys, later messages) may be rendered.
    #[must_use]
    pub const fn content_visible(&self) -> bool {
        !matches!(self.protection, Protection::Locked)
    }

    /// Whether the per-session override of CS-1.9 is offered: only while locked, and only on Linux (M8 has none elsewhere).
    #[cfg(target_os = "linux")]
    #[must_use]
    pub const fn override_available(&self) -> bool {
        matches!(self.protection, Protection::Locked)
    }

    /// The per-session override of CS-1.9 is not offered on this platform.
    #[cfg(not(target_os = "linux"))]
    #[must_use]
    pub const fn override_available(&self) -> bool {
        false
    }

    /// The user chose to show content on an unprotected display for this process. Held in memory only: nothing is written,
    /// and no file, flag or environment variable can set it.
    #[cfg(target_os = "linux")]
    pub fn override_session(&mut self) {
        if self.override_available() {
            self.protection = Protection::Overridden;
            self.protection_changed();
        }
    }

    /// The key of the indicator line in the locale tables.
    #[must_use]
    pub const fn indicator_key(&self) -> &'static str {
        match self.protection {
            Protection::Verified => key::INDICATOR_PROTECTED,
            Protection::Partial => key::INDICATOR_PARTIAL,
            Protection::Locked => key::INDICATOR_LOCKED,
            Protection::Overridden => key::INDICATOR_OVERRIDDEN,
        }
    }

    /// The language of the interface.
    #[must_use]
    pub const fn lang(&self) -> Lang {
        self.lang
    }

    /// The screen to show.
    #[must_use]
    pub const fn screen(&self) -> Screen {
        self.screen
    }

    /// The profile named on the unlock screen.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Whether a request is under way.
    #[must_use]
    pub const fn busy(&self) -> bool {
        self.busy
    }

    /// The contact rows, as the core listed them last.
    #[must_use]
    pub fn contacts(&self) -> &[ContactRow] {
        &self.contacts
    }

    /// The lines of "what the relay can see" for the chosen mode.
    #[must_use]
    pub fn relay_lines(&self) -> &[String] {
        &self.relay_lines
    }

    /// The banner for a transient engine notice, or empty.
    #[must_use]
    pub fn unavailable_text(&self) -> &'static str {
        if self.engine == Engine::Notice {
            locale::text(self.lang, key::ENGINE_UNAVAILABLE)
        } else {
            ""
        }
    }

    /// The message of the last failure, in the language of the interface; the same text for every cause of
    /// [`Failure::Unlock`].
    #[must_use]
    pub fn error_text(&self) -> &'static str {
        self.failure
            .map_or("", |f| locale::text(self.lang, f.message_key()))
    }

    /// The rows as the contacts screen shows them.
    #[must_use]
    pub fn rows(&self) -> Vec<RowText> {
        if !self.content_visible() {
            // fail closed: one placeholder line, whatever the number of contacts (the count is content)
            return vec![RowText {
                name: locale::text(self.lang, key::CONTENT_LOCKED).to_owned(),
                key: String::new(),
                status: String::new(),
                verified: false,
            }];
        }
        self.contacts
            .iter()
            .map(|c| RowText {
                name: if c.name.is_empty() {
                    locale::text(self.lang, key::CONTACTS_UNNAMED).to_owned()
                } else {
                    c.name.clone()
                },
                key: c.key.clone(),
                status: locale::text(
                    self.lang,
                    match (c.state, c.verified) {
                        (RowState::ReinviteRequired, _) => key::CONTACTS_REINVITE,
                        (RowState::Removed, _) => key::CONTACTS_REMOVED,
                        (RowState::Active, true) => key::CONTACTS_VERIFIED,
                        (RowState::Active, false) => key::CONTACTS_UNVERIFIED,
                    },
                )
                .to_owned(),
                verified: c.verified && c.state == RowState::Active,
            })
            .collect()
    }

    /// Queue `request`; a refusal is the failure the screen shows (a full queue is [`Failure::Busy`]). Returns whether it
    /// was queued; the failure of an earlier request is not cleared here.
    fn submit(&mut self, bridge: &Bridge, request: Request) -> bool {
        match bridge.submit(request) {
            Ok(()) => true,
            Err(Refused::Full) => {
                self.failure = Some(Failure::Busy);
                false
            }
            Err(Refused::Stopped) => {
                self.failure = Some(Failure::Stopped);
                false
            }
        }
    }

    /// A request the user made that is answered later: the previous failure and notice are gone, the screen is busy until the
    /// answer comes.
    fn begin(&mut self, bridge: &Bridge, request: Request) {
        self.failure = None;
        self.notice = None;
        self.busy = self.submit(bridge, request);
    }

    /// The user opens the invitation screen from the contact list.
    pub fn open_invitations(&mut self) {
        if self.screen == Screen::Contacts {
            self.failure = None;
            self.screen = Screen::Invitations;
        }
    }

    /// The user leaves the screen they are on (for the contact list, from the safety number for the conversation); what the
    /// screen held is dropped (the invitation URI, the revealed text and the digits are zeroised).
    pub fn leave(&mut self) {
        match self.screen {
            Screen::Invitations => {
                self.invite = InviteState::default();
                self.failure = None;
                self.screen = Screen::Contacts;
            }
            Screen::Conversation => {
                self.chat.close();
                self.failure = None;
                self.screen = Screen::Contacts;
            }
            Screen::Safety => {
                self.chat.close_safety();
                self.failure = None;
                self.screen = Screen::Conversation;
            }
            Screen::Settings => {
                self.confirm = None;
                self.notice = None;
                self.failure = None;
                self.screen = Screen::Contacts;
            }
            Screen::Options => {
                self.confirm = None;
                self.notice = None;
                self.failure = None;
                self.screen = Screen::Conversation;
            }
            Screen::Onboarding | Screen::Unlock | Screen::Contacts | Screen::Stopped => {}
        }
    }

    /// The user asks for an invitation.
    pub fn create_invitation(&mut self, bridge: &Bridge) {
        if self.busy || self.screen != Screen::Invitations {
            return;
        }
        self.invite.uri = None;
        self.invite.qr = None;
        self.invite.notice = None;
        self.failure = None;
        self.busy = self.submit(bridge, Request::InviteCreate);
    }

    /// The user asks to accept the invitation `uri` they pasted; an empty field is refused like any other bad invitation.
    pub fn accept_invitation(&mut self, bridge: &Bridge, uri: &str) {
        if self.busy || self.screen != Screen::Invitations || !self.content_visible() {
            return;
        }
        self.invite.notice = None;
        let uri = Zeroizing::new(uri.trim().to_owned());
        if uri.is_empty() {
            self.invite.accepting = false;
            self.failure = Some(Failure::InviteAccept);
            return;
        }
        // "Accepting…" shows from the submit on, whatever the answer will be: a refusal at once looks like one that comes later
        self.invite.accepting = true;
        self.failure = None;
        self.busy = self.submit(bridge, Request::InviteAccept(uri));
        if !self.busy {
            self.invite.accepting = false;
        }
    }

    /// Whether the invitation field takes text: content is visible and nothing is under way.
    #[must_use]
    pub const fn invite_input_enabled(&self) -> bool {
        self.content_visible() && !self.busy
    }

    /// Whether an invitation URI is held (it is dropped when the screen is left).
    #[must_use]
    pub const fn invitation_held(&self) -> bool {
        self.invite.uri.is_some()
    }

    /// The invitation as text: empty if there is none, the placeholder while content is locked.
    #[must_use]
    pub fn invite_text(&self) -> String {
        match &self.invite.uri {
            None => String::new(),
            Some(_) if !self.content_visible() => {
                locale::text(self.lang, key::CONTENT_LOCKED).to_owned()
            }
            Some(uri) => uri.as_str().to_owned(),
        }
    }

    /// Whether the invitation may be copied (there is one and content is visible).
    #[must_use]
    pub const fn invite_copyable(&self) -> bool {
        self.invite.uri.is_some() && self.content_visible()
    }

    /// The QR code of the invitation (made once when the invitation arrived), only while content is visible.
    #[must_use]
    pub const fn invite_qr(&self) -> Option<&Image> {
        if self.content_visible() {
            self.invite.qr.as_ref()
        } else {
            None
        }
    }

    /// The status line of the invitation screen, or empty.
    #[must_use]
    pub fn invite_status(&self) -> &'static str {
        let key = if self.invite.accepting {
            Some(key::INVITE_ACCEPTING)
        } else {
            self.invite.notice
        };
        key.map_or("", |k| locale::text(self.lang, k))
    }

    /// The user opens the conversation of the contact in row `index` of the list (never while content is locked); the latest
    /// page of its history is asked for the first time it is opened.
    pub fn open_contact(&mut self, bridge: &Bridge, index: usize) {
        if self.screen != Screen::Contacts || !self.content_visible() {
            return;
        }
        let Some(id) = self.contacts.get(index).map(|row| row.id) else {
            return;
        };
        self.chat.open_contact(id);
        self.failure = None;
        self.notice = None;
        self.screen = Screen::Conversation;
        if self.chat.history_first(id) {
            self.ask_history(bridge, id, None);
        }
    }

    /// Ask for a page of the history of `contact`; a refusal is shown and the page may be asked for again.
    fn ask_history(&mut self, bridge: &Bridge, contact: i64, before: Option<i64>) {
        let request = Request::History {
            contact,
            before,
            limit: HISTORY_PAGE,
        };
        if !self.submit(bridge, request) {
            self.chat.history_failed(contact);
        }
    }

    /// The user scrolled to the top of the conversation (or asked): the next page of older messages.
    pub fn load_earlier(&mut self, bridge: &Bridge) {
        if self.screen != Screen::Conversation || !self.content_visible() {
            return;
        }
        let Some(contact) = self.chat.open() else {
            return;
        };
        if self.chat.history_first(contact) {
            self.ask_history(bridge, contact, None);
        } else if let Some(cursor) = self.chat.history_older(contact) {
            self.ask_history(bridge, contact, Some(cursor));
        }
    }

    /// Whether the conversation has older messages to ask for.
    #[must_use]
    pub fn conv_more(&self) -> bool {
        self.screen == Screen::Conversation
            && self.content_visible()
            && self.chat.open().is_some_and(|c| self.chat.history_more(c))
    }

    /// The row of the contact whose conversation is open.
    fn open_row(&self) -> Option<&ContactRow> {
        let id = self.chat.open()?;
        self.contacts.iter().find(|c| c.id == id)
    }

    /// Whether the input of the conversation takes text: the contact can be written to, nothing froze the conversation, and
    /// content is visible.
    #[must_use]
    pub fn conv_input_enabled(&self) -> bool {
        self.screen == Screen::Conversation
            && self.content_visible()
            && !self.busy
            && self.chat.open().is_some_and(|id| !self.chat.frozen(id))
            && self
                .open_row()
                .is_some_and(|row| row.state == RowState::Active)
    }

    /// The user sends `text`; the core takes it as it is. Returns whether the request was made (the field is emptied when the
    /// core's answer comes, not before).
    pub fn send(&mut self, bridge: &Bridge, text: &str) -> bool {
        if text.is_empty() || !self.conv_input_enabled() {
            return false;
        }
        let Some(contact) = self.chat.open() else {
            return false;
        };
        let text = Zeroizing::new(text.to_owned());
        self.chat.sending(contact, text.clone());
        self.failure = None;
        if !self.submit(bridge, Request::Send { contact, text }) {
            self.chat.send_refused();
            return false;
        }
        self.busy = true;
        true
    }

    /// The user holds the view-once in row `index` of the conversation: it is asked for only on a display verified as
    /// protected (CS-1.14) — never while locked or on the user's override.
    ///
    /// `now_ms` is the model's clock: the 20 seconds of CS-1.14 run from the press that starts the reveal, a second press while
    /// it runs changes nothing.
    pub fn reveal_press(&mut self, bridge: &Bridge, index: usize, now_ms: u64) {
        if self.protection != Protection::Verified
            || self.screen != Screen::Conversation
            || self.chat.revealing()
        {
            return;
        }
        let Some(contact) = self.chat.open() else {
            return;
        };
        let Some(msg_id) = self.chat.sealed(contact, index) else {
            return;
        };
        self.chat.hold(contact, msg_id, now_ms);
        if !self.submit(bridge, Request::Reveal { contact, msg_id }) {
            self.chat.release();
            self.failure = Some(Failure::Reveal);
        }
    }

    /// The user let go of the view-once: the revealed text is dropped.
    pub fn reveal_release(&mut self) {
        self.chat.release();
    }

    /// The model's clock moved to `now_ms`: a reveal that has run for 20 seconds ends. Returns whether it did.
    pub fn tick(&mut self, now_ms: u64) -> bool {
        if self.chat.reveal_expired(now_ms) {
            self.chat.release();
            return true;
        }
        false
    }

    /// The window lost the focus: a reveal under way ends (CS-1.14).
    pub fn focus_lost(&mut self) {
        self.chat.release();
    }

    /// Whether a reveal is under way or showing.
    #[must_use]
    pub const fn revealing(&self) -> bool {
        self.chat.revealing()
    }

    /// The user opens the safety number of the contact of the conversation.
    pub fn open_safety(&mut self, bridge: &Bridge) {
        if self.screen != Screen::Conversation || !self.content_visible() {
            return;
        }
        let Some(contact) = self.chat.open() else {
            return;
        };
        self.chat.release();
        self.chat.close_safety();
        self.failure = None;
        // a refused request keeps the user on the conversation, with the failure shown there
        if self.submit(bridge, Request::SafetyNumber(contact)) {
            self.screen = Screen::Safety;
        }
    }

    /// The user opens the actions on the contact of the conversation (never while content is locked).
    pub fn open_options(&mut self) {
        if self.screen != Screen::Conversation || !self.content_visible() {
            return;
        }
        self.chat.release();
        self.failure = None;
        self.notice = None;
        self.confirm = None;
        self.screen = Screen::Options;
    }

    /// The user marks the contact as verified by the digits on the screen.
    pub fn verify(&mut self, bridge: &Bridge) {
        if self.busy || self.screen != Screen::Safety || !self.content_visible() {
            return;
        }
        let (Some(contact), Some(digits)) = (self.chat.open(), self.chat.digits().cloned()) else {
            return;
        };
        self.chat.verify_submitted(contact);
        self.failure = None;
        self.busy = self.submit(bridge, Request::Verify { contact, digits });
        if !self.busy {
            self.chat.verify_refused();
        }
    }

    /// The title of the conversation: the contact's name (the placeholder while content is locked).
    #[must_use]
    pub fn conv_title(&self) -> String {
        if !self.content_visible() {
            return locale::text(self.lang, key::CONTENT_LOCKED).to_owned();
        }
        self.open_row()
            .map(|row| {
                if row.name.is_empty() {
                    locale::text(self.lang, key::CONTACTS_UNNAMED).to_owned()
                } else {
                    row.name.clone()
                }
            })
            .unwrap_or_default()
    }

    /// The banners of the open contact (and the hint of a frozen conversation), in the language of the interface.
    #[must_use]
    pub fn conv_banners(&self) -> Vec<&'static str> {
        if !self.content_visible() {
            return Vec::new();
        }
        let Some(contact) = self.chat.open() else {
            return Vec::new();
        };
        let mut banners: Vec<&'static str> = self
            .chat
            .warnings(contact)
            .into_iter()
            .map(|w| locale::text(self.lang, w.key()))
            .collect();
        // what the contact record keeps survives a restart
        match self.open_row().map(|row| row.state) {
            Some(RowState::ReinviteRequired) => {
                banners.push(locale::text(self.lang, key::BANNER_REINVITE));
            }
            Some(RowState::Removed) => banners.push(locale::text(self.lang, key::BANNER_REMOVED)),
            Some(RowState::Active) | None => {}
        }
        if self.chat.frozen(contact) {
            banners.push(locale::text(self.lang, key::CONV_FROZEN));
        }
        banners
    }

    /// The messages of the open conversation as rows; one placeholder line while content is locked.
    #[must_use]
    pub fn conv_rows(&self) -> Vec<MsgText> {
        let text = |k: &'static str| locale::text(self.lang, k).to_owned();
        if !self.content_visible() {
            return vec![MsgText {
                text: text(key::CONTENT_LOCKED),
                meta: String::new(),
                incoming: false,
                hold: false,
            }];
        }
        let Some(contact) = self.chat.open() else {
            return Vec::new();
        };
        self.chat
            .messages(contact)
            .iter()
            .map(|m| {
                let (body, hold) = match &m.body {
                    Body::Pending => (text(key::WORKING), false),
                    Body::Text(t) => (t.as_str().to_owned(), false),
                    // the hold area stays while the text shows, so that the release reaches it
                    Body::Sealed if self.protection == Protection::Verified => {
                        (text(key::MSG_VIEW_ONCE), true)
                    }
                    Body::Sealed => (text(key::MSG_VIEW_ONCE_LOCKED), false),
                    Body::Viewed => match self.chat.shown(&m.id) {
                        Some(shown) => (shown.to_owned(), true),
                        None => (text(key::MSG_VIEW_ONCE_VIEWED), false),
                    },
                    Body::Lost => (text(key::MSG_VIEW_ONCE_LOST), false),
                    Body::Unsupported => (text(key::MSG_UNSUPPORTED), false),
                    Body::Unavailable => (text(key::MSG_UNAVAILABLE), false),
                };
                let mut meta = vec![text(if m.incoming {
                    key::MSG_IN
                } else {
                    key::MSG_OUT
                })];
                if let Some(at) = m.at_ms {
                    meta.push(clock_text(at) + " " + locale::text(self.lang, key::MSG_UTC));
                }
                if let Some(state) = m.state.filter(|_| !m.incoming) {
                    meta.push(text(state.key()));
                }
                MsgText {
                    text: body,
                    meta: meta.join(" · "),
                    incoming: m.incoming,
                    hold,
                }
            })
            .collect()
    }

    /// The safety number as text: empty if the screen holds none, the placeholder while content is locked.
    #[must_use]
    pub fn safety_text(&self) -> String {
        match self.chat.digits() {
            None => String::new(),
            Some(_) if !self.content_visible() => {
                locale::text(self.lang, key::CONTENT_LOCKED).to_owned()
            }
            Some(digits) => digits.as_str().to_owned(),
        }
    }

    /// The QR code of the safety number (made once when the number arrived), only while content is visible.
    #[must_use]
    pub const fn safety_qr(&self) -> Option<&Image> {
        if self.content_visible() {
            self.chat.digits_qr()
        } else {
            None
        }
    }

    /// Whether "mark verified" is offered: there are digits, content is visible and the contact was not verified just now.
    #[must_use]
    pub fn safety_can_verify(&self) -> bool {
        self.chat.digits().is_some() && self.content_visible() && !self.chat.just_verified()
    }

    /// The status line of the safety number screen, or empty.
    #[must_use]
    pub fn safety_status(&self) -> &'static str {
        if self.chat.just_verified() {
            locale::text(self.lang, key::SAFETY_VERIFIED)
        } else {
            ""
        }
    }

    /// The user asks for the relay's view of `mode` (the onboarding screen shows it before a profile exists).
    pub fn show_relay_view(&mut self, bridge: &Bridge, mode: ModeChoice) {
        self.submit(bridge, Request::RelayView(mode));
    }

    /// The user asks to create the profile `name` under the passphrase `pass` (typed twice) in `mode`.
    pub fn create(
        &mut self,
        bridge: &Bridge,
        name: &str,
        pass: &str,
        again: &str,
        mode: ModeChoice,
    ) {
        if self.busy {
            return;
        }
        let pass = Zeroizing::new(pass.as_bytes().to_vec());
        let again = Zeroizing::new(again.as_bytes().to_vec());
        if !name_is_valid(name) {
            self.failure = Some(Failure::NameInvalid);
        } else if pass.is_empty() {
            self.failure = Some(Failure::PassphraseEmpty);
        } else if !same_secret(&pass, &again) {
            self.failure = Some(Failure::PassphraseMismatch);
        } else {
            name.clone_into(&mut self.profile);
            let request = Request::Create {
                name: name.to_owned(),
                pass,
                mode,
            };
            self.failure = None;
            self.busy = self.submit(bridge, request);
        }
    }

    /// The user asks to unlock the existing profile under the passphrase `pass`.
    pub fn unlock(&mut self, bridge: &Bridge, pass: &str) {
        if self.busy {
            return;
        }
        let request = Request::Unlock {
            name: self.profile.clone(),
            pass: Zeroizing::new(pass.as_bytes().to_vec()),
        };
        self.failure = None;
        self.busy = self.submit(bridge, request);
    }

    /// The user opens the settings from the contact list.
    pub fn open_settings(&mut self, bridge: &Bridge) {
        if self.screen != Screen::Contacts {
            return;
        }
        self.failure = None;
        self.notice = None;
        self.confirm = None;
        self.screen = Screen::Settings;
        self.submit(bridge, Request::Settings);
    }

    /// The settings as the screen shows them: what the core holds, with the mode the user picked and has not confirmed yet.
    #[must_use]
    pub fn settings_shown(&self) -> Option<SettingsView> {
        self.settings.map(|s| match self.confirm {
            Some(Confirm::Mode(mode)) => SettingsView { mode, ..s },
            _ => s,
        })
    }

    /// Whether the settings controls take input.
    #[must_use]
    pub const fn settings_enabled(&self) -> bool {
        self.settings.is_some() && !self.busy
    }

    /// The retention choices of the list: the ones offered, and the stored value if it is none of them.
    #[must_use]
    pub fn retention_options(&self) -> Vec<RetentionChoice> {
        let mut options = RetentionChoice::OFFERED.to_vec();
        if let Some(s) = self.settings
            && !options.contains(&s.retention)
        {
            options.push(s.retention);
        }
        options
    }

    /// The names of the retention choices, in the language of the interface.
    #[must_use]
    pub fn retention_names(&self) -> Vec<String> {
        self.retention_options()
            .into_iter()
            .map(|choice| match choice {
                RetentionChoice::Keep => locale::text(self.lang, key::RETENTION_KEEP).to_owned(),
                RetentionChoice::Days(n) => {
                    locale::text(self.lang, key::RETENTION_DAYS).replace("{n}", &n.to_string())
                }
            })
            .collect()
    }

    /// The position of the retention shown in [`Self::retention_options`].
    #[must_use]
    pub fn retention_index(&self) -> i32 {
        self.settings
            .and_then(|s| {
                self.retention_options()
                    .iter()
                    .position(|c| *c == s.retention)
            })
            .and_then(|at| i32::try_from(at).ok())
            .unwrap_or(0)
    }

    /// The position of the delivery receipts shown.
    #[must_use]
    pub fn delivered_index(&self) -> i32 {
        self.settings
            .and_then(|s| ReceiptChoice::ALL.iter().position(|c| *c == s.delivered))
            .and_then(|at| i32::try_from(at).ok())
            .unwrap_or(0)
    }

    /// Store `new` as the settings (shown at once; a refusal reads them again).
    fn store_settings(&mut self, bridge: &Bridge, new: SettingsView) {
        self.settings = Some(new);
        self.begin(bridge, Request::SetSettings(new));
    }

    /// The user picks the traffic mode at `index`: the relay's view of that mode is listed and a confirm click is asked for;
    /// nothing is stored before it.
    pub fn pick_mode(&mut self, bridge: &Bridge, index: i32) {
        if self.screen != Screen::Settings || !self.settings_enabled() {
            return;
        }
        let mode = ModeChoice::from_index(index);
        self.failure = None;
        self.notice = None;
        self.confirm = if self.settings.is_some_and(|s| s.mode == mode) {
            None
        } else {
            Some(Confirm::Mode(mode))
        };
        self.submit(bridge, Request::RelayView(mode));
    }

    /// The user picks the retention at `index` of [`Self::retention_options`].
    pub fn pick_retention(&mut self, bridge: &Bridge, index: i32) {
        let options = self.retention_options();
        let (Some(current), Some(choice)) = (
            self.settings,
            usize::try_from(index)
                .ok()
                .and_then(|at| options.get(at).copied()),
        ) else {
            return;
        };
        if self.screen == Screen::Settings && self.settings_enabled() && current.retention != choice
        {
            self.store_settings(
                bridge,
                SettingsView {
                    retention: choice,
                    ..current
                },
            );
        }
    }

    /// The user picks the delivery receipts at `index` of [`ReceiptChoice::ALL`].
    pub fn pick_delivered(&mut self, bridge: &Bridge, index: i32) {
        let (Some(current), Some(choice)) = (
            self.settings,
            usize::try_from(index)
                .ok()
                .and_then(|at| ReceiptChoice::ALL.get(at).copied()),
        ) else {
            return;
        };
        if self.screen == Screen::Settings && self.settings_enabled() && current.delivered != choice
        {
            self.store_settings(
                bridge,
                SettingsView {
                    delivered: choice,
                    ..current
                },
            );
        }
    }

    /// The user switches the read receipts.
    pub fn set_read_receipts(&mut self, bridge: &Bridge, on: bool) {
        if let Some(current) = self.settings
            && self.screen == Screen::Settings
            && self.settings_enabled()
            && current.read_receipts != on
        {
            self.store_settings(
                bridge,
                SettingsView {
                    read_receipts: on,
                    ..current
                },
            );
        }
    }

    /// The contact of the open options screen.
    fn options_contact(&self) -> Option<i64> {
        (self.screen == Screen::Options && self.content_visible())
            .then(|| self.chat.open())
            .flatten()
    }

    /// The user asks to rotate the session keys of the contact: a confirm click follows, nothing is sent yet.
    pub fn ask_rotate(&mut self) {
        if let Some(contact) = self.options_contact() {
            self.ask(Confirm::Rotate(contact));
        }
    }

    /// The user asks to reset the session with the contact (as above).
    pub fn ask_reset(&mut self) {
        if let Some(contact) = self.options_contact() {
            self.ask(Confirm::Reset(contact));
        }
    }

    /// The user asks to remove the contact (as above).
    pub fn ask_remove(&mut self) {
        if let Some(contact) = self.options_contact() {
            self.ask(Confirm::Remove(contact));
        }
    }

    /// The user asks to rotate their identity: a warning and a confirm click follow.
    pub fn ask_identity(&mut self) {
        if self.screen == Screen::Settings {
            self.ask(Confirm::Identity);
        }
    }

    /// The user asks to export a backup to `path` under `passphrase`: a confirm click follows. The passphrase is held in a
    /// zeroising buffer until then.
    pub fn ask_export(&mut self, path: &str, passphrase: &str) {
        if self.screen != Screen::Settings {
            return;
        }
        let pass = Zeroizing::new(passphrase.as_bytes().to_vec());
        if path.trim().is_empty() || pass.is_empty() {
            self.failure = Some(Failure::ExportInput);
            return;
        }
        self.ask(Confirm::Export {
            path: path.trim().to_owned(),
            pass,
        });
    }

    fn ask(&mut self, confirm: Confirm) {
        if self.busy {
            return;
        }
        self.failure = None;
        self.notice = None;
        self.confirm = Some(confirm);
    }

    /// The question the user is asked to confirm, or empty.
    #[must_use]
    pub fn confirm_text(&self) -> &'static str {
        let key = match self.confirm {
            None => return "",
            Some(Confirm::Rotate(_)) => key::CONFIRM_ROTATE,
            Some(Confirm::Reset(_)) => key::CONFIRM_RESET,
            Some(Confirm::Remove(_)) => key::CONFIRM_REMOVE,
            Some(Confirm::Identity) => key::CONFIRM_IDENTITY,
            Some(Confirm::Export { .. }) => key::CONFIRM_EXPORT,
            Some(Confirm::Mode(_)) => key::CONFIRM_MODE,
        };
        locale::text(self.lang, key)
    }

    /// The user clicked "Confirm": the action is sent now, for the first time.
    pub fn confirm(&mut self, bridge: &Bridge) {
        if self.busy {
            return;
        }
        let Some(pending) = self.confirm.take() else {
            return;
        };
        match pending {
            Confirm::Rotate(contact) => self.begin(bridge, Request::Rotate(contact)),
            Confirm::Reset(contact) => self.begin(bridge, Request::ResetSession(contact)),
            Confirm::Remove(contact) => self.begin(bridge, Request::Remove(contact)),
            Confirm::Identity => self.begin(bridge, Request::RotateIdentity),
            Confirm::Export { path, pass } => self.begin(
                bridge,
                Request::Export {
                    path,
                    passphrase: pass,
                },
            ),
            Confirm::Mode(mode) => {
                if let Some(current) = self.settings {
                    self.store_settings(bridge, SettingsView { mode, ..current });
                }
            }
        }
    }

    /// The user clicked "Cancel": nothing was sent, nothing is.
    pub fn cancel(&mut self, bridge: &Bridge) {
        let was_mode = matches!(self.confirm, Some(Confirm::Mode(_)));
        self.confirm = None;
        if was_mode && let Some(current) = self.settings {
            // the list shows the mode in force again
            self.submit(bridge, Request::RelayView(current.mode));
        }
    }

    /// The notice of the last action ("Done."), or empty.
    #[must_use]
    pub fn notice_text(&self) -> &'static str {
        self.notice.map_or("", |k| locale::text(self.lang, k))
    }

    /// Ask the core about the connection (the shell does it every few seconds while a profile is open).
    pub fn poll_status(&mut self, bridge: &Bridge) {
        if !self.profile_open {
            return;
        }
        match bridge.submit(Request::Status) {
            // a poll that finds the queue full is skipped; the next one asks again
            Ok(()) | Err(Refused::Full) => {}
            Err(Refused::Stopped) => self.engine = Engine::Down,
        }
    }

    /// The connection line: the transport, and connected, connecting or unavailable. No address, no counter.
    #[must_use]
    pub fn status_text(&self) -> String {
        let Some(report) = self.status else {
            return String::new();
        };
        if !self.profile_open {
            return String::new();
        }
        let link = if self.engine != Engine::Working {
            Link::Unavailable
        } else if report.connected {
            Link::Connected
        } else {
            Link::Connecting
        };
        let transport = if report.direct {
            key::STATUS_DIRECT
        } else {
            key::STATUS_TOR
        };
        let state = match link {
            Link::Connected => key::STATUS_CONNECTED,
            Link::Connecting => key::STATUS_CONNECTING,
            Link::Unavailable => key::STATUS_UNAVAILABLE,
        };
        format!(
            "{}: {}",
            locale::text(self.lang, transport),
            locale::text(self.lang, state)
        )
    }

    /// The profile is open (`mode_not_saved`: the mode chosen at creation was not stored).
    fn opened(&mut self, bridge: &Bridge, mode_not_saved: bool) {
        self.busy = false;
        self.profile_open = true;
        self.reported = None;
        self.screen = Screen::Contacts;
        self.failure = None;
        if self.submit(bridge, Request::Contacts) && mode_not_saved {
            self.failure = Some(Failure::ModeNotSaved);
        }
        self.poll_status(bridge);
    }

    /// A request did not go through.
    fn failed(&mut self, failure: Failure, bridge: &Bridge) {
        self.busy = false;
        match failure {
            Failure::InviteAccept => self.invite.accepting = false,
            Failure::Send(reason) => {
                // what the core persists of a session shows when a send is refused: a frozen or blocked session is frozen here
                // too (and stays so after a restart), until the contact is verified again
                if let Some(contact) = self.chat.send_refused() {
                    match reason {
                        SendReason::Frozen => self.chat.warn(contact, Warning::KeyChangeInvalid),
                        SendReason::Blocked => self.chat.warn(contact, Warning::KeyChanged),
                        _ => {}
                    }
                }
            }
            Failure::Reveal => self.chat.release(),
            Failure::Verify => self.chat.verify_refused(),
            Failure::Settings => {
                // what the core holds is shown again
                self.confirm = None;
                self.settings = None;
                self.submit(bridge, Request::Settings);
            }
            _ => {}
        }
        self.failure = Some(failure);
    }

    /// Take one response (or event) of the bridge.
    pub fn apply(&mut self, response: Response, bridge: &Bridge) {
        // an answer means the engine is working; a notice does not say so
        if !matches!(response, Response::Event(_)) && self.engine == Engine::Notice {
            self.engine = Engine::Working;
        }
        match response {
            Response::Opened => self.opened(bridge, false),
            Response::OpenedModeNotSaved => self.opened(bridge, true),
            Response::NotOpened => {
                // the profile exists: unlock it instead of creating it again
                self.busy = false;
                self.screen = Screen::Unlock;
                self.failure = Some(Failure::Unlock);
            }
            Response::Failed(failure) => self.failed(failure, bridge),
            Response::Sent { contact, msg_id } => {
                self.busy = false;
                self.failure = None;
                if self.chat.sent(contact, msg_id) {
                    // the time (and the history's copy of the text) come from the core
                    self.submit(bridge, Request::Load { contact, msg_id });
                }
            }
            Response::Message {
                contact,
                msg_id,
                at_ms,
                text,
            } => self.chat.loaded(contact, msg_id, at_ms, text),
            Response::MessageMissing { contact, msg_id } => self.chat.missing(contact, msg_id),
            Response::History {
                contact,
                limit,
                items,
                ..
            } => self.chat.history_arrived(contact, limit, items),
            Response::HistoryFailed(contact) => {
                self.chat.history_failed(contact);
                self.failure = Some(Failure::History);
            }
            Response::Revealed {
                contact,
                msg_id,
                text,
            } => self.chat.revealed(contact, msg_id, text),
            Response::SafetyNumber { contact, digits } => {
                if self.screen == Screen::Safety && self.chat.open() == Some(contact) {
                    self.chat.set_digits(digits);
                }
            }
            Response::Verified { contact, ok } => {
                self.busy = false;
                if ok {
                    self.failure = None;
                    self.chat.verified(contact);
                    self.submit(bridge, Request::Contacts);
                } else {
                    self.chat.verify_refused();
                    self.failure = Some(Failure::Verify);
                }
            }
            Response::Contacts(rows) => self.contacts = rows,
            Response::RelayView(lines) => self.relay_lines = lines,
            Response::Settings(settings) => {
                self.busy = false;
                self.settings = Some(settings);
                if self.screen == Screen::Settings && self.confirm.is_none() {
                    self.submit(bridge, Request::RelayView(settings.mode));
                }
            }
            Response::ActionDone(kind) => {
                self.busy = false;
                self.failure = None;
                self.notice = Some(if kind == ActionKind::Identity {
                    key::ACTION_IDENTITY_DONE
                } else {
                    key::ACTION_DONE
                });
                if kind == ActionKind::Remove {
                    self.submit(bridge, Request::Contacts);
                }
            }
            Response::Status(report) => self.status = Some(report),
            Response::Display(_) => {}
            Response::Invitation(uri) => {
                self.busy = false;
                self.failure = None;
                self.invite.qr = Matrix::of(&uri).map(|m| m.image());
                self.invite.uri = Some(uri);
                self.invite.notice = None;
            }
            Response::Accepting => {
                self.busy = false;
                self.failure = None;
                self.invite.accepting = true;
                self.invite.notice = None;
            }
            Response::Event(event) => self.apply_event(event, bridge),
        }
        self.sync_display(bridge);
    }

    /// Take one event of the core.
    fn apply_event(&mut self, event: CoreEvent, bridge: &Bridge) {
        match event {
            CoreEvent::Unavailable => self.engine = Engine::Notice,
            CoreEvent::Stopped => {
                self.busy = false;
                self.screen = Screen::Stopped;
                self.profile_open = false;
                self.contacts.clear();
                self.invite = InviteState::default();
                self.chat.clear();
                self.settings = None;
                self.confirm = None;
                self.failure = Some(Failure::Stopped);
            }
            CoreEvent::MessageReceived {
                contact,
                msg_id,
                kind,
                at_ms,
            } => {
                if self.chat.received(contact, msg_id, kind, at_ms) {
                    self.submit(bridge, Request::Load { contact, msg_id });
                }
            }
            CoreEvent::Relayed(contact, msg_id) => {
                self.chat.state(contact, msg_id, OutState::Relayed);
            }
            CoreEvent::Delivered(contact, msg_id) => {
                self.chat.state(contact, msg_id, OutState::Delivered);
            }
            CoreEvent::NotConfirmed(contact, msg_id) => {
                self.chat.state(contact, msg_id, OutState::NotConfirmed);
                self.chat.warn(contact, Warning::NotConfirmed);
            }
            CoreEvent::ViewOnceLost(msg_id) => {
                // a view-once of an earlier run has no placeholder in this one: nothing to replace
                self.chat.lost(&msg_id);
            }
            CoreEvent::KeyChangeInvalid(contact) => {
                self.chat.warn(contact, Warning::KeyChangeInvalid);
            }
            CoreEvent::ResetRequested(contact) => {
                self.chat.warn(contact, Warning::ResetRequested);
            }
            CoreEvent::DuplicateIdentity { existing, new } => {
                self.chat.warn(existing, Warning::DuplicateIdentity);
                self.chat.warn(new, Warning::DuplicateIdentity);
            }
            CoreEvent::SuccessionPending(contact) => {
                self.chat.warn(contact, Warning::SuccessionPending);
            }
            CoreEvent::RotationDeferred(contact) => {
                self.chat.warn(contact, Warning::RotationDeferred);
            }
            CoreEvent::InviteFailed => {
                // one message for every class of refusal
                self.invite.accepting = false;
                self.failure = Some(Failure::InviteAccept);
            }
            CoreEvent::InvitationRetired => {
                self.invite.uri = None;
                self.invite.qr = None;
                self.invite.notice = Some(key::INVITE_RETIRED);
            }
            CoreEvent::InvitationUsedElsewhere => {
                self.invite.uri = None;
                self.invite.qr = None;
                self.invite.notice = Some(key::INVITE_USED_ELSEWHERE);
            }
            event @ (CoreEvent::ContactAdded(_)
            | CoreEvent::ContactRemoved(_)
            | CoreEvent::KeyChanged(_)) => {
                match event {
                    CoreEvent::ContactAdded(_) => {
                        self.invite.accepting = false;
                        self.invite.notice = Some(key::INVITE_CONTACT_ADDED);
                    }
                    CoreEvent::KeyChanged(contact) => {
                        self.chat.warn(contact, Warning::KeyChanged);
                        self.key_changed_on_safety_screen(bridge, contact);
                    }
                    _ => {}
                }
                if matches!(
                    self.screen,
                    Screen::Contacts
                        | Screen::Invitations
                        | Screen::Conversation
                        | Screen::Safety
                        | Screen::Options
                ) {
                    // the list is read again
                    self.submit(bridge, Request::Contacts);
                }
            }
        }
    }

    /// The identity of the contact whose safety number is on the screen changed: the number shown is wrong now, so it is dropped
    /// and the new one is asked for.
    fn key_changed_on_safety_screen(&mut self, bridge: &Bridge, contact: i64) {
        if self.screen == Screen::Safety && self.chat.open() == Some(contact) {
            self.chat.clear_digits();
            self.submit(bridge, Request::SafetyNumber(contact));
        }
    }
}
