// SPDX-License-Identifier: AGPL-3.0-or-later
//! The data of a conversation as the model keeps it: the messages of this run (the core has no list of the history, only a
//! message by its id), the state of an outgoing message and the warnings of a contact. Plain data and pure functions; the
//! texts are content and live in zeroising buffers.

use std::collections::{BTreeMap, BTreeSet};

use secmp_client_core::Zeroizing;

use crate::bridge::MsgId;
use crate::locale::key;

/// `AppMessage.kind` of a text.
pub const KIND_TEXT: u8 = 1;

/// `AppMessage.kind` of a view-once text.
pub const KIND_VIEW_ONCE: u8 = 3;

/// How far an outgoing message got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutState {
    /// Queued in the core.
    Queued,
    /// Relayed (`Event::Relayed`).
    Relayed,
    /// Acknowledged by the contact (`Event::Delivered`).
    Delivered,
    /// Relayed, but no receipt came in time (`Event::NotConfirmed`).
    NotConfirmed,
}

impl OutState {
    /// The key of the state's name in the locale tables.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Queued => key::MSG_STATE_QUEUED,
            Self::Relayed => key::MSG_STATE_RELAYED,
            Self::Delivered => key::MSG_STATE_DELIVERED,
            Self::NotConfirmed => key::MSG_STATE_NOT_CONFIRMED,
        }
    }

    /// The state after `next` was reported: a delivered message stays delivered, whatever arrives later.
    #[must_use]
    pub const fn then(self, next: Self) -> Self {
        match self {
            Self::Delivered => Self::Delivered,
            _ => next,
        }
    }
}

/// What a message shows.
pub enum Body {
    /// The text is being read from the core.
    Pending,
    /// A text.
    Text(Zeroizing<String>),
    /// A view-once that was not shown yet.
    Sealed,
    /// A view-once that was shown (or asked for): it is gone.
    Viewed,
    /// A view-once that was lost with the run that held it.
    Lost,
    /// A kind of message this version does not show.
    Unsupported,
    /// The core has no such message in its history.
    Unavailable,
}

/// One message of a conversation.
pub struct Message {
    /// The id.
    pub id: MsgId,
    /// Whether it was received (else sent).
    pub incoming: bool,
    /// When, once the core said.
    pub at_ms: Option<u64>,
    /// What it shows.
    pub body: Body,
    /// The state of an outgoing message.
    pub state: OutState,
}

/// What can be wrong with a contact, shown as a banner on its conversation until the user acts (CS-1.18, spec §7.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Warning {
    /// The contact's identity changed: verify the new safety number.
    KeyChanged,
    /// A key change did not verify: the session is frozen.
    KeyChangeInvalid,
    /// The contact asked for a new session.
    ResetRequested,
    /// The contact has an identity another contact already holds.
    DuplicateIdentity,
    /// A message was relayed and no receipt came.
    NotConfirmed,
    /// An identity succession towards the contact is pending.
    SuccessionPending,
    /// A queue rotation was deferred.
    RotationDeferred,
}

impl Warning {
    /// The key of the banner's text in the locale tables.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::KeyChanged => key::WARN_KEY_CHANGED,
            Self::KeyChangeInvalid => key::WARN_KEY_CHANGE_INVALID,
            Self::ResetRequested => key::WARN_RESET_REQUESTED,
            Self::DuplicateIdentity => key::WARN_DUPLICATE_IDENTITY,
            Self::NotConfirmed => key::WARN_NOT_CONFIRMED,
            Self::SuccessionPending => key::WARN_SUCCESSION_PENDING,
            Self::RotationDeferred => key::WARN_ROTATION_DEFERRED,
        }
    }

    /// Whether the conversation takes no input until the contact is verified again.
    #[must_use]
    pub const fn freezes(self) -> bool {
        matches!(self, Self::KeyChanged | Self::KeyChangeInvalid)
    }
}

/// The time of day (UTC) of `ms` Unix milliseconds as `HH:MM`.
#[must_use]
pub fn clock_text(ms: u64) -> String {
    let minutes = ms / 60_000;
    let (hours, minutes) = ((minutes / 60) % 24, minutes % 60);
    format!("{hours:02}:{minutes:02}")
}

/// A reveal under way or showing: the user holds the message, the text is here for as long as they do.
struct Reveal {
    contact: i64,
    id: MsgId,
    text: Option<Zeroizing<String>>,
}

/// The conversations of this run, the warnings of the contacts and the state of the reveal and the safety number screens.
#[derive(Default)]
pub struct Chat {
    open: Option<i64>,
    convs: BTreeMap<i64, Vec<Message>>,
    warnings: BTreeMap<i64, BTreeSet<Warning>>,
    // states reported before the answer that names the message came (events and answers travel on different threads)
    early: Vec<(i64, MsgId, OutState)>,
    pending_send: Option<(i64, Zeroizing<String>)>,
    reveal: Option<Reveal>,
    digits: Option<Zeroizing<String>>,
    verified: bool,
}

impl Chat {
    /// The contact whose conversation (or safety number) is open.
    #[must_use]
    pub const fn open(&self) -> Option<i64> {
        self.open
    }

    /// Open the conversation of `contact`.
    pub fn open_contact(&mut self, contact: i64) {
        self.open = Some(contact);
    }

    /// Leave the conversation: the open contact, the reveal and the safety number are dropped (the texts are zeroised); the
    /// messages of the run and the warnings stay.
    pub fn close(&mut self) {
        self.open = None;
        self.reveal = None;
        self.close_safety();
    }

    /// Leave the safety number screen: the digits are dropped.
    pub fn close_safety(&mut self) {
        self.digits = None;
        self.verified = false;
    }

    /// Drop everything (the engine stopped).
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// The messages of `contact`, oldest first.
    #[must_use]
    pub fn messages(&self, contact: i64) -> &[Message] {
        self.convs.get(&contact).map_or(&[], Vec::as_slice)
    }

    fn list(&mut self, contact: i64) -> &mut Vec<Message> {
        self.convs.entry(contact).or_default()
    }

    fn find(&mut self, contact: i64, id: &MsgId) -> Option<&mut Message> {
        self.convs
            .get_mut(&contact)
            .and_then(|list| list.iter_mut().find(|m| m.id == *id))
    }

    /// Remember the text of the message being sent to `contact`.
    pub fn sending(&mut self, contact: i64, text: Zeroizing<String>) {
        self.pending_send = Some((contact, text));
    }

    /// Forget the message being sent (it was refused).
    pub fn send_refused(&mut self) {
        self.pending_send = None;
    }

    /// The core queued the message being sent: it joins the conversation. Returns whether it did.
    pub fn sent(&mut self, contact: i64, id: MsgId) -> bool {
        let Some((to, text)) = self.pending_send.take() else {
            return false;
        };
        if to != contact {
            return false;
        }
        let state = self
            .early
            .iter()
            .position(|(c, m, _)| *c == contact && *m == id)
            .map(|at| self.early.swap_remove(at).2)
            .map_or(OutState::Queued, |early| OutState::Queued.then(early));
        self.list(contact).push(Message {
            id,
            incoming: false,
            at_ms: None,
            body: Body::Text(text),
            state,
        });
        true
    }

    /// A message arrived. Returns whether its text is to be read from the core.
    pub fn received(&mut self, contact: i64, id: MsgId, kind: u8, at_ms: u64) -> bool {
        if self.find(contact, &id).is_some() {
            return false;
        }
        let (body, read) = match kind {
            KIND_TEXT => (Body::Pending, true),
            KIND_VIEW_ONCE => (Body::Sealed, false),
            _ => (Body::Unsupported, false),
        };
        self.list(contact).push(Message {
            id,
            incoming: true,
            at_ms: Some(at_ms),
            body,
            state: OutState::Queued,
        });
        read
    }

    /// An outgoing message reached `state`.
    pub fn state(&mut self, contact: i64, id: MsgId, state: OutState) {
        if let Some(message) = self.find(contact, &id) {
            message.state = message.state.then(state);
        } else {
            // the answer that names the message has not come yet
            self.early.push((contact, id, state));
        }
    }

    /// The core gave the text and the time of a message.
    pub fn loaded(&mut self, contact: i64, id: MsgId, at_ms: u64, text: Zeroizing<String>) {
        if let Some(message) = self.find(contact, &id) {
            message.at_ms = Some(at_ms);
            if matches!(message.body, Body::Pending) {
                message.body = Body::Text(text);
            }
        }
    }

    /// The core has no such message.
    pub fn missing(&mut self, contact: i64, id: MsgId) {
        if let Some(message) = self.find(contact, &id)
            && matches!(message.body, Body::Pending)
        {
            message.body = Body::Unavailable;
        }
    }

    /// A view-once was lost with the run that held it; returns whether this run had a placeholder for it.
    pub fn lost(&mut self, id: &MsgId) -> bool {
        let mut found = false;
        for list in self.convs.values_mut() {
            for message in list.iter_mut().filter(|m| m.id == *id) {
                message.body = Body::Lost;
                found = true;
            }
        }
        found
    }

    /// Whether the message `index` of `contact` is a view-once that was not shown.
    #[must_use]
    pub fn sealed(&self, contact: i64, index: usize) -> Option<MsgId> {
        self.messages(contact)
            .get(index)
            .filter(|m| m.incoming && matches!(m.body, Body::Sealed))
            .map(|m| m.id)
    }

    /// The user holds the message `id` of `contact`: a reveal starts, nothing is shown before the core's answer.
    pub fn hold(&mut self, contact: i64, id: MsgId) {
        self.reveal = Some(Reveal {
            contact,
            id,
            text: None,
        });
    }

    /// The user let go (or the time ran out): the shown text is dropped.
    pub fn release(&mut self) {
        self.reveal = None;
    }

    /// Whether a reveal is under way or showing.
    #[must_use]
    pub const fn revealing(&self) -> bool {
        self.reveal.is_some()
    }

    /// The core gave the text of a view-once: it is shown if the user still holds it; the message is gone either way.
    pub fn revealed(&mut self, contact: i64, id: MsgId, text: Zeroizing<String>) {
        if let Some(message) = self.find(contact, &id) {
            message.body = Body::Viewed;
        }
        if let Some(reveal) = self
            .reveal
            .as_mut()
            .filter(|r| r.contact == contact && r.id == id)
        {
            reveal.text = Some(text);
        }
    }

    /// The text being revealed for message `id`, if the user holds it.
    #[must_use]
    pub fn shown(&self, id: &MsgId) -> Option<&str> {
        self.reveal
            .as_ref()
            .filter(|r| r.id == *id)
            .and_then(|r| r.text.as_deref())
            .map(String::as_str)
    }

    /// A warning on `contact`.
    pub fn warn(&mut self, contact: i64, warning: Warning) {
        self.warnings.entry(contact).or_default().insert(warning);
    }

    /// The warnings of `contact`, in a fixed order.
    #[must_use]
    pub fn warnings(&self, contact: i64) -> Vec<Warning> {
        self.warnings
            .get(&contact)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Whether `contact`'s conversation takes no input until it is verified again.
    #[must_use]
    pub fn frozen(&self, contact: i64) -> bool {
        self.warnings
            .get(&contact)
            .is_some_and(|set| set.iter().any(|w| w.freezes()))
    }

    /// `contact` was verified again: what froze the conversation is cleared.
    pub fn verified(&mut self, contact: i64) {
        if let Some(set) = self.warnings.get_mut(&contact) {
            set.retain(|w| !w.freezes());
        }
        self.verified = true;
    }

    /// Whether the user verified the contact on the safety number screen just now.
    #[must_use]
    pub const fn just_verified(&self) -> bool {
        self.verified
    }

    /// The core gave the safety number.
    pub fn set_digits(&mut self, digits: Zeroizing<String>) {
        self.digits = Some(digits);
    }

    /// The safety number, if the screen holds it.
    #[must_use]
    pub fn digits(&self) -> Option<&Zeroizing<String>> {
        self.digits.as_ref()
    }
}
