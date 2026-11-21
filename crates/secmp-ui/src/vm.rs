// SPDX-License-Identifier: AGPL-3.0-or-later
//! The view models: plain data the screens show and the state machine that turns the user's input into requests of the
//! [`bridge`](crate::bridge) and the bridge's responses into the next state. Nothing here touches the core, the store or a key;
//! it knows ids (as numbers) and enums only. Every method returns at once — an answer arrives later as a [`Response`].

use secmp_client_core::Zeroizing;

use crate::bridge::{Bridge, CoreEvent, Refused, Request, Response};
use crate::convo::{Body, Chat, OutState, Warning, clock_text};
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
    /// The engine has stopped: nothing is shown but the message.
    Stopped,
}

/// Whether the display is known to be protected against capture (docs/04 CS-1.2, CS-1.18). The model starts
/// [`Locked`](Self::Locked); no content is shown until the state changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    /// The platform confirmed the exclusion from capture.
    Verified,
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
    unavailable: bool,
    invite: InviteState,
    chat: Chat,
    protection: Protection,
}

/// What the invitation screen holds. The URI is a capability: it lives in a zeroising buffer, is shown as content only and is
/// dropped when the screen is left.
#[derive(Default)]
struct InviteState {
    uri: Option<Zeroizing<String>>,
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
            unavailable: false,
            invite: InviteState::default(),
            chat: Chat::default(),
            protection: Protection::Locked,
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
        }
    }

    /// The key of the indicator line in the locale tables.
    #[must_use]
    pub const fn indicator_key(&self) -> &'static str {
        match self.protection {
            Protection::Verified => key::INDICATOR_PROTECTED,
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
        if self.unavailable {
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

    fn submit(&mut self, bridge: &Bridge, request: Request) {
        self.failure = match bridge.submit(request) {
            Ok(()) => None,
            Err(Refused::Full) => Some(Failure::Busy),
            Err(Refused::Stopped) => Some(Failure::Stopped),
        };
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
            Screen::Onboarding | Screen::Unlock | Screen::Contacts | Screen::Stopped => {}
        }
    }

    /// The user asks for an invitation.
    pub fn create_invitation(&mut self, bridge: &Bridge) {
        if self.busy || self.screen != Screen::Invitations {
            return;
        }
        self.invite.uri = None;
        self.invite.notice = None;
        self.submit(bridge, Request::InviteCreate);
        self.busy = self.failure.is_none();
    }

    /// The user asks to accept the invitation `uri` they pasted; an empty field is refused like any other bad invitation.
    pub fn accept_invitation(&mut self, bridge: &Bridge, uri: &str) {
        if self.busy || self.screen != Screen::Invitations {
            return;
        }
        self.invite.notice = None;
        let uri = Zeroizing::new(uri.trim().to_owned());
        if uri.is_empty() {
            self.failure = Some(Failure::InviteAccept);
            return;
        }
        self.submit(bridge, Request::InviteAccept(uri));
        self.busy = self.failure.is_none();
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

    /// The QR code of the invitation, only while content is visible.
    #[must_use]
    pub fn invite_qr(&self) -> Option<Matrix> {
        match &self.invite.uri {
            Some(uri) if self.content_visible() => Matrix::of(uri),
            _ => None,
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

    /// The user opens the conversation of the contact in row `index` of the list (never while content is locked).
    pub fn open_contact(&mut self, index: usize) {
        if self.screen != Screen::Contacts || !self.content_visible() {
            return;
        }
        if let Some(row) = self.contacts.get(index) {
            self.chat.open_contact(row.id);
            self.failure = None;
            self.screen = Screen::Conversation;
        }
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
        self.submit(bridge, Request::Send { contact, text });
        if self.failure.is_some() {
            self.chat.send_refused();
            return false;
        }
        self.busy = true;
        true
    }

    /// The user holds the view-once in row `index` of the conversation: it is asked for only on a display verified as
    /// protected (CS-1.14) — never while locked or on the user's override.
    pub fn reveal_press(&mut self, bridge: &Bridge, index: usize) {
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
        self.chat.hold(contact, msg_id);
        if bridge.submit(Request::Reveal { contact, msg_id }).is_err() {
            self.chat.release();
            self.failure = Some(Failure::Reveal);
        }
    }

    /// The user let go of the view-once, or the 20 seconds ran out: the revealed text is dropped.
    pub fn reveal_release(&mut self) {
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
        self.screen = Screen::Safety;
        let _ = bridge.submit(Request::SafetyNumber(contact));
    }

    /// The user marks the contact as verified by the digits on the screen.
    pub fn verify(&mut self, bridge: &Bridge) {
        if self.busy || self.screen != Screen::Safety || !self.content_visible() {
            return;
        }
        let (Some(contact), Some(digits)) = (self.chat.open(), self.chat.digits().cloned()) else {
            return;
        };
        self.submit(bridge, Request::Verify { contact, digits });
        self.busy = self.failure.is_none();
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
        let Some(contact) = self.chat.open() else {
            return Vec::new();
        };
        let mut banners: Vec<&'static str> = self
            .chat
            .warnings(contact)
            .into_iter()
            .map(|w| locale::text(self.lang, w.key()))
            .collect();
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
                if !m.incoming {
                    meta.push(text(m.state.key()));
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

    /// The QR code of the safety number, only while content is visible.
    #[must_use]
    pub fn safety_qr(&self) -> Option<Matrix> {
        match self.chat.digits() {
            Some(digits) if self.content_visible() => Matrix::of(digits),
            _ => None,
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
        // not an error of the form: a full queue leaves the lines as they were
        let _ = bridge.submit(Request::RelayView(mode));
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
            self.submit(bridge, request);
            self.busy = self.failure.is_none();
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
        self.submit(bridge, request);
        self.busy = self.failure.is_none();
    }

    /// Take one response (or event) of the bridge.
    pub fn apply(&mut self, response: Response, bridge: &Bridge) {
        // an answer means the engine is working; a notice does not say so
        if !matches!(response, Response::Event(_)) {
            self.unavailable = false;
        }
        match response {
            Response::Opened => {
                self.busy = false;
                self.failure = None;
                self.screen = Screen::Contacts;
                self.submit(bridge, Request::Contacts);
            }
            Response::OpenedModeNotSaved => {
                self.busy = false;
                self.screen = Screen::Contacts;
                self.submit(bridge, Request::Contacts);
                if self.failure.is_none() {
                    self.failure = Some(Failure::ModeNotSaved);
                }
            }
            Response::NotOpened => {
                // the profile exists: unlock it instead of creating it again
                self.busy = false;
                self.screen = Screen::Unlock;
                self.failure = Some(Failure::Unlock);
            }
            Response::Failed(failure) => {
                self.busy = false;
                match failure {
                    Failure::InviteAccept => self.invite.accepting = false,
                    Failure::Send(_) => self.chat.send_refused(),
                    Failure::Reveal => self.chat.release(),
                    _ => {}
                }
                self.failure = Some(failure);
            }
            Response::Sent { contact, msg_id } => {
                self.busy = false;
                self.failure = None;
                if self.chat.sent(contact, msg_id) {
                    // the time (and the history's copy of the text) come from the core; a full queue leaves the time out
                    let _ = bridge.submit(Request::Load { contact, msg_id });
                }
            }
            Response::Message {
                contact,
                msg_id,
                at_ms,
                text,
            } => self.chat.loaded(contact, msg_id, at_ms, text),
            Response::MessageMissing { contact, msg_id } => self.chat.missing(contact, msg_id),
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
                    let _ = bridge.submit(Request::Contacts);
                } else {
                    self.failure = Some(Failure::Verify);
                }
            }
            Response::Contacts(rows) => self.contacts = rows,
            Response::RelayView(lines) => self.relay_lines = lines,
            Response::Invitation(uri) => {
                self.busy = false;
                self.failure = None;
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
    }

    /// Take one event of the core.
    fn apply_event(&mut self, event: CoreEvent, bridge: &Bridge) {
        match event {
            CoreEvent::Unavailable => self.unavailable = true,
            CoreEvent::Stopped => {
                self.busy = false;
                self.screen = Screen::Stopped;
                self.contacts.clear();
                self.invite = InviteState::default();
                self.chat.clear();
                self.failure = Some(Failure::Stopped);
            }
            CoreEvent::MessageReceived {
                contact,
                msg_id,
                kind,
                at_ms,
            } => {
                if self.chat.received(contact, msg_id, kind, at_ms) {
                    let _ = bridge.submit(Request::Load { contact, msg_id });
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
                self.invite.notice = Some(key::INVITE_RETIRED);
            }
            CoreEvent::InvitationUsedElsewhere => {
                self.invite.uri = None;
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
                    CoreEvent::KeyChanged(contact) => self.chat.warn(contact, Warning::KeyChanged),
                    _ => {}
                }
                if matches!(
                    self.screen,
                    Screen::Contacts | Screen::Invitations | Screen::Conversation | Screen::Safety
                ) {
                    // the list is read again; a full queue means a read is already waiting
                    let _ = bridge.submit(Request::Contacts);
                }
            }
        }
    }
}
