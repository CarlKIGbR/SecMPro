// SPDX-License-Identifier: AGPL-3.0-or-later
//! The [`Backend`] over the real client core: profiles live in directories under one root, a profile is created with the
//! functions `secmp-cli` uses and opened on a runtime of its own ([`spawn_host`]), and everything the UI shows is copied out
//! into view-model data. No key, no store handle and no core type leaves this module.

use std::path::PathBuf;
use std::sync::mpsc::channel;

use secmp_client_core::Zeroizing;
use secmp_client_core::api::runtime::{
    Answer, Call, Host, Notice, RuntimeConfig, create_profile, spawn_host,
};
use secmp_client_core::api::{
    Contact, ContactId, ContactState, DisplayState, Error, Event, Mode, Request, Response,
};
use secmp_client_core::relay_view::relay_view;
use secmp_client_core::settings::{DeliveredReceipts, Retention, Settings};

use crate::bridge::{
    Backend, CoreEvent, HistoryItem, LinkReport, MsgId, Request as UiRequest,
    Response as UiResponse, Sink,
};
use crate::convo::KIND_TEXT;
use crate::vm::{
    ActionKind, ContactRow, Failure, ModeChoice, Protection, ReceiptChoice, RetentionChoice,
    RowState, SendReason, SettingsView, name_is_valid,
};

/// How many hex digits of the fingerprint a row shows.
const KEY_DIGITS: usize = 16;

/// How long an invitation the UI issues stays open, as for `secmp-cli invite create` (spec §5.2 allows 30 days at most).
const INVITE_LIFETIME_S: u64 = 86_400;

/// The core's mode of the user's choice.
pub(crate) const fn mode_of(choice: ModeChoice) -> Mode {
    match choice {
        ModeChoice::Strict => Mode::Strict,
        ModeChoice::Balanced => Mode::Balanced,
        ModeChoice::LowBw => Mode::LowBw,
    }
}

/// The mode the UI shows for the core's.
const fn choice_of(mode: Mode) -> ModeChoice {
    match mode {
        Mode::Strict => ModeChoice::Strict,
        Mode::Balanced => ModeChoice::Balanced,
        Mode::LowBw => ModeChoice::LowBw,
    }
}

/// The settings as the UI shows them.
const fn view_of(s: &Settings) -> SettingsView {
    SettingsView {
        mode: choice_of(s.mode),
        retention: match s.retention {
            Retention::Keep => RetentionChoice::Keep,
            Retention::Days(d) => RetentionChoice::Days(d),
        },
        delivered: match s.delivered_receipts {
            DeliveredReceipts::Off => ReceiptChoice::Off,
            DeliveredReceipts::VerifiedOnly => ReceiptChoice::VerifiedOnly,
            DeliveredReceipts::All => ReceiptChoice::All,
        },
        read_receipts: s.read_receipts,
    }
}

/// The core's settings for what the UI shows.
const fn settings_of(v: &SettingsView) -> Settings {
    Settings {
        mode: mode_of(v.mode),
        retention: match v.retention {
            RetentionChoice::Keep => Retention::Keep,
            RetentionChoice::Days(d) => Retention::Days(d),
        },
        delivered_receipts: match v.delivered {
            ReceiptChoice::Off => DeliveredReceipts::Off,
            ReceiptChoice::VerifiedOnly => DeliveredReceipts::VerifiedOnly,
            ReceiptChoice::All => DeliveredReceipts::All,
        },
        read_receipts: v.read_receipts,
    }
}

/// The core's display state for the UI's protection state (CS-1.18).
const fn display_of(p: Protection) -> DisplayState {
    match p {
        Protection::Verified => DisplayState::Protected,
        Protection::Partial => DisplayState::PartiallyProtected,
        Protection::Locked => DisplayState::Locked,
        Protection::Overridden => DisplayState::Overridden,
    }
}

/// The protection state for the core's display state.
const fn protection_of(d: DisplayState) -> Protection {
    match d {
        DisplayState::Protected => Protection::Verified,
        DisplayState::PartiallyProtected => Protection::Partial,
        DisplayState::Locked => Protection::Locked,
        DisplayState::Overridden => Protection::Overridden,
    }
}

/// The relay whose spare pool a rotation takes its queue from: the profile's first (as `secmp-cli rotate`).
const ROTATE_RELAY: u32 = 1;

/// The row a contact is shown as.
fn row_of(contact: &Contact) -> ContactRow {
    let key = contact.display_key();
    ContactRow {
        id: contact.id.0,
        name: contact.display_name.clone().unwrap_or_default(),
        key: key.get(..KEY_DIGITS).unwrap_or(&key).to_owned(),
        verified: contact.verified,
        state: match contact.state {
            ContactState::Active => RowState::Active,
            ContactState::ReinviteRequired => RowState::ReinviteRequired,
            ContactState::Removed => RowState::Removed,
        },
    }
}

/// The event of the UI's list for a notice of the runtime, if the list cares.
fn event_of(notice: &Notice) -> Option<CoreEvent> {
    let stamped = match notice {
        Notice::Event(stamped) => stamped,
        // the loop ended or could not work: the UI shows nothing more (fail closed)
        Notice::Stopped => return Some(CoreEvent::Stopped),
        Notice::Unavailable => return Some(CoreEvent::Unavailable),
        _ => return None,
    };
    match stamped.event {
        Event::ContactAdded(ContactId(id)) => Some(CoreEvent::ContactAdded(id)),
        Event::ContactRemoved(ContactId(id)) => Some(CoreEvent::ContactRemoved(id)),
        Event::KeyChanged(ContactId(id)) => Some(CoreEvent::KeyChanged(id)),
        // the class of a refusal is never shown (spec §5.5): one event for all
        Event::InviteFailed(_) => Some(CoreEvent::InviteFailed),
        Event::InvitationRetired { .. } => Some(CoreEvent::InvitationRetired),
        Event::InvitationUsedElsewhere => Some(CoreEvent::InvitationUsedElsewhere),
        Event::MessageReceived {
            contact: ContactId(contact),
            msg_id,
            kind,
        } => Some(CoreEvent::MessageReceived {
            contact,
            msg_id,
            kind,
            at_ms: stamped.at_ms,
        }),
        Event::Relayed {
            contact: ContactId(contact),
            msg_id,
        } => Some(CoreEvent::Relayed(contact, msg_id)),
        Event::Delivered {
            contact: ContactId(contact),
            msg_id,
        } => Some(CoreEvent::Delivered(contact, msg_id)),
        Event::NotConfirmed {
            contact: ContactId(contact),
            msg_id,
        } => Some(CoreEvent::NotConfirmed(contact, msg_id)),
        Event::ViewOnceLost(msg_id) => Some(CoreEvent::ViewOnceLost(msg_id)),
        Event::KeyChangeInvalid(ContactId(id)) => Some(CoreEvent::KeyChangeInvalid(id)),
        Event::ResetRequested(ContactId(id)) => Some(CoreEvent::ResetRequested(id)),
        Event::DuplicateIdentity {
            existing: ContactId(existing),
            new: ContactId(new),
        } => Some(CoreEvent::DuplicateIdentity { existing, new }),
        Event::SuccessionPending(ContactId(id)) => Some(CoreEvent::SuccessionPending(id)),
        Event::RotationDeferred(ContactId(id)) => Some(CoreEvent::RotationDeferred(id)),
        _ => None,
    }
}

/// The text of a payload: the core only delivers UTF-8 (SE-20), anything else is shown with replacement characters.
fn text_of(payload: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(String::from_utf8_lossy(payload).into_owned())
}

/// What the core said about a refused send, as far as the user is told.
fn send_reason(error: Error) -> SendReason {
    match error {
        Error::Unsupported => SendReason::Unsupported,
        Error::Blocked | Error::Unverified => SendReason::Blocked,
        Error::Frozen => SendReason::Frozen,
        Error::ReinviteRequired | Error::ResetRequested => SendReason::Reinvite,
        _ => SendReason::Other,
    }
}

/// Send `call` and wait for its answer on this (the bridge's) thread.
fn ask(host: &Host, call: Call) -> Result<Answer, Error> {
    let (reply, answer) = channel();
    host.call(call, move |result| {
        let _ = reply.send(result);
    });
    answer.recv().map_err(|_| Error::Unavailable)?
}

/// The backend of the application.
pub struct CoreBackend {
    root: PathBuf,
    direct: bool,
    host: Option<Host>,
}

impl CoreBackend {
    /// A backend whose profiles are the directories of `root`; over Tor unless `direct` (the user's explicit choice, spec §5.3).
    #[must_use]
    pub const fn new(root: PathBuf, direct: bool) -> Self {
        Self {
            root,
            direct,
            host: None,
        }
    }

    fn open(&mut self, name: &str, pass: &[u8], events: &Sink) -> Result<(), Error> {
        let events = events.clone();
        let host = spawn_host(
            &self.root.join(name),
            pass,
            RuntimeConfig {
                direct: self.direct,
                name: name.to_owned(),
            },
            move |notice| {
                if let Some(event) = event_of(&notice) {
                    events(UiResponse::Event(event));
                }
            },
        )?;
        self.host = Some(host);
        Ok(())
    }

    fn create(&mut self, name: &str, pass: &[u8], mode: ModeChoice, events: &Sink) -> UiResponse {
        if !name_is_valid(name) {
            return UiResponse::Failed(Failure::NameInvalid);
        }
        if std::fs::create_dir_all(&self.root).is_err()
            || create_profile(&self.root.join(name), pass, None).is_err()
        {
            return UiResponse::Failed(Failure::Create);
        }
        // from here the profile exists: a failure to open it leads to the unlock screen, not to "could not be created"
        if self.open(name, pass, events).is_err() {
            return UiResponse::NotOpened;
        }
        let settings = Settings {
            mode: mode_of(mode),
            ..Settings::default()
        };
        let set = self
            .host
            .as_ref()
            .map(|host| ask(host, Call::Core(Request::SetSettings(settings))));
        if let Some(Ok(_)) = set {
            UiResponse::Opened
        } else {
            // the profile is open and runs in the default mode (Strict); the user is told the choice was not stored
            UiResponse::OpenedModeNotSaved
        }
    }

    fn invite_create(&self) -> UiResponse {
        let Some(host) = &self.host else {
            return UiResponse::Failed(Failure::InviteCreate);
        };
        match ask(
            host,
            Call::InviteCreate {
                expires_s: INVITE_LIFETIME_S,
            },
        ) {
            Ok(Answer::Invitation { uri }) => UiResponse::Invitation(uri),
            Ok(Answer::PoolEmpty) => UiResponse::Failed(Failure::InvitePoolEmpty),
            _ => UiResponse::Failed(Failure::InviteCreate),
        }
    }

    /// The accept is under way once the core took it; every refusal, here or later as an event, is one failure.
    fn invite_accept(&self, uri: Zeroizing<String>) -> UiResponse {
        let Some(host) = &self.host else {
            return UiResponse::Failed(Failure::InviteAccept);
        };
        match ask(host, Call::InviteAccept { uri }) {
            Ok(Answer::Accepting) => UiResponse::Accepting,
            _ => UiResponse::Failed(Failure::InviteAccept),
        }
    }

    /// One request of the core's API; every failure, and any answer that is not the core's, is [`Error::Unavailable`].
    fn core(&self, request: Request) -> Result<Response, Error> {
        let host = self.host.as_ref().ok_or(Error::Unavailable)?;
        match ask(host, Call::Core(request))? {
            Answer::Core(response) => Ok(response),
            _ => Err(Error::Unavailable),
        }
    }

    fn send(&self, contact: i64, text: &Zeroizing<String>) -> UiResponse {
        let request = Request::Send {
            contact: ContactId(contact),
            kind: KIND_TEXT,
            payload: Zeroizing::new(text.as_bytes().to_vec()),
            expire_after: 0,
        };
        match self.core(request) {
            Ok(Response::Sent(msg_id)) => UiResponse::Sent { contact, msg_id },
            Err(error) => UiResponse::Failed(Failure::Send(send_reason(error))),
            Ok(_) => UiResponse::Failed(Failure::Send(SendReason::Other)),
        }
    }

    /// A message of the history.
    fn load(&self, contact: i64, msg_id: MsgId) -> UiResponse {
        let request = Request::Message {
            contact: ContactId(contact),
            msg_id,
        };
        match self.core(request) {
            Ok(Response::Message { ts_ms, payload, .. }) => UiResponse::Message {
                contact,
                msg_id,
                at_ms: ts_ms,
                text: text_of(&payload),
            },
            _ => UiResponse::MessageMissing { contact, msg_id },
        }
    }

    /// A page of the history, newest first. Only a text has its payload shown; a view-once never has one.
    fn history(&self, contact: i64, before: Option<i64>, limit: u16) -> UiResponse {
        let request = Request::History {
            contact: ContactId(contact),
            before,
            limit,
        };
        match self.core(request) {
            Ok(Response::History(entries)) => UiResponse::History {
                contact,
                before,
                limit,
                items: entries
                    .into_iter()
                    .map(|e| HistoryItem {
                        cursor: e.cursor,
                        msg_id: e.msg_id,
                        incoming: e.incoming,
                        kind: e.kind,
                        at_ms: e.ts_ms,
                        text: (e.kind == KIND_TEXT).then(|| text_of(&e.payload)),
                    })
                    .collect(),
            },
            _ => UiResponse::HistoryFailed(contact),
        }
    }

    fn settings(&self) -> UiResponse {
        match self.core(Request::Settings) {
            Ok(Response::Settings(s)) => UiResponse::Settings(view_of(&s)),
            _ => UiResponse::Failed(Failure::Settings),
        }
    }

    /// Store the settings; the answer is what the core holds afterwards.
    fn set_settings(&self, view: &SettingsView) -> UiResponse {
        match self.core(Request::SetSettings(settings_of(view))) {
            Ok(Response::Done) => self.settings(),
            _ => UiResponse::Failed(Failure::Settings),
        }
    }

    /// A contact or profile action; every refusal is one failure.
    fn action(&self, request: Request, kind: ActionKind) -> UiResponse {
        match (self.core(request), kind) {
            (Ok(Response::Rotated(true)), ActionKind::Rotate)
            | (Ok(Response::Done), ActionKind::Reset | ActionKind::Remove)
            | (Ok(Response::IdentityRotated(_)), ActionKind::Identity) => {
                UiResponse::ActionDone(kind)
            }
            // a rotation the core put off is told as an event (a banner); here it did not go through
            _ => UiResponse::Failed(Failure::Action),
        }
    }

    /// Write the backup the user confirmed. The key derivation and the file are written off the core's loop.
    fn export(&self, path: String, passphrase: Zeroizing<Vec<u8>>) -> UiResponse {
        let Some(host) = &self.host else {
            return UiResponse::Failed(Failure::Export);
        };
        let call = Call::Export {
            path: PathBuf::from(path),
            passphrase,
            confirm: true,
            force: false,
        };
        match ask(host, call) {
            Ok(Answer::Core(Response::Done)) => UiResponse::ActionDone(ActionKind::Export),
            Err(Error::CloudFolder) => UiResponse::Failed(Failure::ExportCloud),
            _ => UiResponse::Failed(Failure::Export),
        }
    }

    /// The connection as the user sees it: the transport, and whether a link is up.
    fn status(&self) -> UiResponse {
        let down = LinkReport {
            direct: self.direct,
            connected: false,
        };
        let Some(host) = &self.host else {
            return UiResponse::Status(down);
        };
        match ask(host, Call::Status) {
            Ok(Answer::Status(view)) => UiResponse::Status(LinkReport {
                direct: view.direct,
                connected: view.links > 0,
            }),
            _ => UiResponse::Status(down),
        }
    }

    fn set_display(&self, protection: Protection) -> UiResponse {
        match self.core(Request::SetDisplayState(display_of(protection))) {
            Ok(Response::Done) => UiResponse::Display(protection),
            _ => UiResponse::Event(CoreEvent::Unavailable),
        }
    }

    fn display(&self) -> UiResponse {
        match self.core(Request::DisplayState) {
            Ok(Response::DisplayState(d)) => UiResponse::Display(protection_of(d)),
            _ => UiResponse::Event(CoreEvent::Unavailable),
        }
    }

    fn reveal(&self, contact: i64, msg_id: MsgId) -> UiResponse {
        let request = Request::Reveal {
            contact: ContactId(contact),
            msg_id,
        };
        match self.core(request) {
            Ok(Response::Revealed(payload)) => UiResponse::Revealed {
                contact,
                msg_id,
                text: text_of(&payload),
            },
            _ => UiResponse::Failed(Failure::Reveal),
        }
    }

    fn safety_number(&self, contact: i64) -> UiResponse {
        match self.core(Request::SafetyNumber {
            contact: ContactId(contact),
        }) {
            Ok(Response::SafetyNumber(digits)) => UiResponse::SafetyNumber {
                contact,
                digits: Zeroizing::new(digits),
            },
            _ => UiResponse::Failed(Failure::Safety),
        }
    }

    fn verify(&self, contact: i64, digits: &Zeroizing<String>) -> UiResponse {
        let request = Request::Verify {
            contact: ContactId(contact),
            digits: digits.as_str().to_owned(),
        };
        match self.core(request) {
            Ok(Response::Verified(ok)) => UiResponse::Verified { contact, ok },
            _ => UiResponse::Failed(Failure::Verify),
        }
    }

    fn contacts(&self) -> UiResponse {
        let Some(host) = &self.host else {
            return UiResponse::Contacts(Vec::new());
        };
        match ask(host, Call::Core(Request::Contacts)) {
            Ok(Answer::Core(Response::Contacts(list))) => {
                UiResponse::Contacts(list.iter().map(row_of).collect())
            }
            _ => UiResponse::Contacts(Vec::new()),
        }
    }
}

impl Backend for CoreBackend {
    fn handle(&mut self, request: UiRequest, events: &Sink) -> UiResponse {
        match request {
            UiRequest::Create { name, pass, mode } => self.create(&name, &pass, mode, events),
            UiRequest::Unlock { name, pass } => {
                // a wrong passphrase, a damaged store and a profile another process holds are one answer
                if name_is_valid(&name) && self.open(&name, &pass, events).is_ok() {
                    UiResponse::Opened
                } else {
                    UiResponse::Failed(Failure::Unlock)
                }
            }
            UiRequest::Contacts => self.contacts(),
            UiRequest::InviteCreate => self.invite_create(),
            UiRequest::InviteAccept(uri) => self.invite_accept(uri),
            UiRequest::Send { contact, text } => self.send(contact, &text),
            UiRequest::Load { contact, msg_id } => self.load(contact, msg_id),
            UiRequest::Reveal { contact, msg_id } => self.reveal(contact, msg_id),
            UiRequest::SafetyNumber(contact) => self.safety_number(contact),
            UiRequest::Verify { contact, digits } => self.verify(contact, &digits),
            UiRequest::History {
                contact,
                before,
                limit,
            } => self.history(contact, before, limit),
            UiRequest::Settings => self.settings(),
            UiRequest::SetSettings(view) => self.set_settings(&view),
            UiRequest::Rotate(contact) => self.action(
                Request::Rotate {
                    contact: ContactId(contact),
                    relay: ROTATE_RELAY,
                },
                ActionKind::Rotate,
            ),
            UiRequest::ResetSession(contact) => self.action(
                Request::ResetSession {
                    contact: ContactId(contact),
                },
                ActionKind::Reset,
            ),
            UiRequest::Remove(contact) => self.action(
                Request::Remove {
                    contact: ContactId(contact),
                },
                ActionKind::Remove,
            ),
            UiRequest::RotateIdentity => self.action(Request::RotateIdentity, ActionKind::Identity),
            UiRequest::Export { path, passphrase } => self.export(path, passphrase),
            UiRequest::Status => self.status(),
            UiRequest::SetDisplayState(protection) => self.set_display(protection),
            UiRequest::DisplayState => self.display(),
            UiRequest::RelayView(mode) => UiResponse::RelayView(
                relay_view(mode_of(mode), self.direct)
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use secmp_client_core::api::{InviteReject, Stamped};

    fn contact(id: i64, state: ContactState, verified: bool) -> Contact {
        Contact {
            id: ContactId(id),
            fingerprint: [0xAB; 32],
            verified,
            display_name: Some("Ann".to_owned()),
            state,
        }
    }

    /// Every contact state of the core has its row state; name, verification and a key prefix of the fixed length carry over.
    #[test]
    fn row_of_maps_every_contact_state() {
        for (state, want) in [
            (ContactState::Active, RowState::Active),
            (ContactState::ReinviteRequired, RowState::ReinviteRequired),
            (ContactState::Removed, RowState::Removed),
        ] {
            let row = row_of(&contact(7, state, true));
            assert_eq!(row.state, want);
            assert_eq!(row.id, 7);
            assert_eq!(row.name, "Ann");
            assert!(row.verified);
            assert_eq!(row.key, "abababababababab");
        }
        let mut nameless = contact(1, ContactState::Active, false);
        nameless.display_name = None;
        assert_eq!(row_of(&nameless).name, "");
    }

    /// The contact events and the loop's end map to the UI's events; others do not.
    #[test]
    fn event_of_maps_contact_events() {
        let at = |event| Notice::Event(Stamped { at_ms: 0, event });
        assert_eq!(
            event_of(&at(Event::ContactAdded(ContactId(3)))),
            Some(CoreEvent::ContactAdded(3))
        );
        assert_eq!(
            event_of(&at(Event::ContactRemoved(ContactId(4)))),
            Some(CoreEvent::ContactRemoved(4))
        );
        assert_eq!(
            event_of(&at(Event::KeyChanged(ContactId(5)))),
            Some(CoreEvent::KeyChanged(5))
        );
        assert_eq!(
            event_of(&at(Event::InvitationUsedElsewhere)),
            Some(CoreEvent::InvitationUsedElsewhere)
        );
        assert_eq!(
            event_of(&at(Event::InviteFailed(InviteReject::Expired))),
            Some(CoreEvent::InviteFailed)
        );
        assert_eq!(event_of(&at(Event::RoutesChanged(ContactId(1)))), None);
        assert_eq!(event_of(&Notice::Stopped), Some(CoreEvent::Stopped));
        assert_eq!(event_of(&Notice::Unavailable), Some(CoreEvent::Unavailable));
        assert_eq!(event_of(&Notice::Refused), None);
    }
}
