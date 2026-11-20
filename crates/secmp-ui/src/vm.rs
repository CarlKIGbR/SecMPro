// SPDX-License-Identifier: AGPL-3.0-or-later
//! The view models: plain data the screens show and the state machine that turns the user's input into requests of the
//! [`bridge`](crate::bridge) and the bridge's responses into the next state. Nothing here touches the core, the store or a key;
//! it knows ids (as numbers) and enums only. Every method returns at once — an answer arrives later as a [`Response`].

use secmp_client_core::Zeroizing;

use crate::bridge::{Bridge, CoreEvent, Refused, Request, Response};
use crate::locale::{self, Lang, key};

/// The screens of part 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    /// No profile yet: create one.
    Onboarding,
    /// A profile exists: unlock it.
    Unlock,
    /// The contact list of the open profile.
    Contacts,
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
    protection: Protection,
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

    /// Whether the per-session override of CS-1.9 is offered: only while locked, and not on Windows (where M8 has none).
    #[must_use]
    pub const fn override_available(&self) -> bool {
        !cfg!(windows) && matches!(self.protection, Protection::Locked)
    }

    /// The user chose to show content on an unprotected display for this process. Held in memory only: nothing is written,
    /// and no file, flag or environment variable can set it.
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
            // fail closed: one placeholder per row, nothing of the contact
            return self
                .contacts
                .iter()
                .map(|_| RowText {
                    name: locale::text(self.lang, key::CONTENT_LOCKED).to_owned(),
                    key: String::new(),
                    status: String::new(),
                    verified: false,
                })
                .collect();
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
        match response {
            Response::Opened => {
                self.busy = false;
                self.failure = None;
                self.screen = Screen::Contacts;
                self.submit(bridge, Request::Contacts);
            }
            Response::NotOpened => {
                // the profile exists: unlock it instead of creating it again
                self.busy = false;
                self.screen = Screen::Unlock;
                self.failure = Some(Failure::Unlock);
            }
            Response::Failed(failure) => {
                self.busy = false;
                self.failure = Some(failure);
            }
            Response::Contacts(rows) => self.contacts = rows,
            Response::RelayView(lines) => self.relay_lines = lines,
            Response::Event(CoreEvent::Stopped) => {
                self.busy = false;
                self.screen = Screen::Stopped;
                self.contacts.clear();
                self.failure = Some(Failure::Stopped);
            }
            Response::Event(
                CoreEvent::ContactAdded(_)
                | CoreEvent::ContactRemoved(_)
                | CoreEvent::KeyChanged(_),
            ) => {
                if self.screen == Screen::Contacts {
                    // the list is read again; a full queue means a read is already waiting
                    let _ = bridge.submit(Request::Contacts);
                }
            }
        }
    }
}
