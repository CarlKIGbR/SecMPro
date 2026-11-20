// SPDX-License-Identifier: AGPL-3.0-or-later
//! The [`Backend`] over the real client core: profiles live in directories under one root, a profile is created with the
//! functions `secmp-cli` uses and opened on a runtime of its own ([`spawn_host`]), and everything the UI shows is copied out
//! into view-model data. No key, no store handle and no core type leaves this module.

use std::path::PathBuf;
use std::sync::mpsc::channel;

use secmp_client_core::api::runtime::{
    Answer, Call, Host, Notice, RuntimeConfig, create_profile, spawn_host,
};
use secmp_client_core::api::{
    Contact, ContactId, ContactState, Error, Event, Mode, Request, Response,
};
use secmp_client_core::relay_view::relay_view;
use secmp_client_core::settings::Settings;

use crate::bridge::{Backend, CoreEvent, Request as UiRequest, Response as UiResponse, Sink};
use crate::vm::{ContactRow, Failure, ModeChoice, RowState, name_is_valid};

/// How many hex digits of the fingerprint a row shows.
const KEY_DIGITS: usize = 16;

/// The core's mode of the user's choice.
const fn mode_of(choice: ModeChoice) -> Mode {
    match choice {
        ModeChoice::Strict => Mode::Strict,
        ModeChoice::Balanced => Mode::Balanced,
        ModeChoice::LowBw => Mode::LowBw,
    }
}

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
        Notice::Stopped | Notice::Unavailable => return Some(CoreEvent::Stopped),
        _ => return None,
    };
    match stamped.event {
        Event::ContactAdded(ContactId(id)) => Some(CoreEvent::ContactAdded(id)),
        Event::ContactRemoved(ContactId(id)) => Some(CoreEvent::ContactRemoved(id)),
        Event::KeyChanged(ContactId(id)) => Some(CoreEvent::KeyChanged(id)),
        _ => None,
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
            // the mode was not stored: close the runtime, the profile is unlocked by the user (default mode Strict)
            self.host = None;
            UiResponse::NotOpened
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

    use secmp_client_core::api::Stamped;

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
        assert_eq!(event_of(&at(Event::InvitationUsedElsewhere)), None);
        assert_eq!(event_of(&Notice::Stopped), Some(CoreEvent::Stopped));
        assert_eq!(event_of(&Notice::Unavailable), Some(CoreEvent::Stopped));
        assert_eq!(event_of(&Notice::Refused), None);
    }
}
