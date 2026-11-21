// SPDX-License-Identifier: AGPL-3.0-or-later
//! The data of a conversation as the model keeps it: the messages of this run and the pages of the history the core read from
//! the store, the state of an outgoing message and the warnings of a contact. Plain data and pure functions; the texts are
//! content and live in zeroising buffers.

use std::collections::BTreeMap;

use secmp_client_core::Zeroizing;
use slint::Image;

use crate::bridge::{HistoryItem, MsgId};
use crate::locale::key;
use crate::qr::Matrix;
use crate::vm::REVEAL_MAX_S;

/// `AppMessage.kind` of a text.
pub const KIND_TEXT: u8 = 1;

/// `AppMessage.kind` of a view-once text.
pub const KIND_VIEW_ONCE: u8 = 3;

/// How many states reported before the answer that names their message the model keeps (the oldest is dropped).
pub const EARLY_MAX: usize = 256;

/// How many messages one page of the history asks for.
pub const HISTORY_PAGE: u16 = 50;

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
    /// The state of an outgoing message of this run (the history does not keep it).
    pub state: Option<OutState>,
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

/// The date and time (UTC) of `ms` Unix milliseconds as `YYYY-MM-DD HH:MM` (the caller adds the label "UTC": there is no
/// time-zone source in M8).
#[must_use]
pub fn clock_text(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rest) = (secs / 86_400, secs % 86_400);
    let (hours, minutes) = (rest / 3600, (rest % 3600) / 60);
    let (year, month, day) = civil(days);
    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}")
}

/// The proleptic Gregorian date of `days` since 1970-01-01 (the civil-from-days algorithm; saturating, never panics).
fn civil(days: u64) -> (u64, u64, u64) {
    let z = days.saturating_add(719_468);
    let (era, doe) = (z / 146_097, z % 146_097);
    let yoe = doe
        .saturating_sub(doe / 1460)
        .saturating_add(doe / 36_524)
        .saturating_sub(doe / 146_096)
        / 365;
    let year = yoe.saturating_add(era.saturating_mul(400));
    let doy = doe.saturating_sub(
        yoe.saturating_mul(365)
            .saturating_add(yoe / 4)
            .saturating_sub(yoe / 100),
    );
    let mp = doy.saturating_mul(5).saturating_add(2) / 153;
    let day = doy
        .saturating_sub(mp.saturating_mul(153).saturating_add(2) / 5)
        .saturating_add(1);
    let month = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let year = if month <= 2 {
        year.saturating_add(1)
    } else {
        year
    };
    (year, month, day)
}

/// A reveal under way or showing: the user holds the message, the text is here for as long as they do.
struct Reveal {
    contact: i64,
    id: MsgId,
    text: Option<Zeroizing<String>>,
    /// The model clock's reading when the reveal began (the 20 s run from here, never from a later press).
    started_ms: u64,
}

/// How far the history of one contact is loaded.
#[derive(Default)]
struct Hist {
    loaded: bool,
    loading: bool,
    exhausted: bool,
    oldest: Option<i64>,
}

/// The conversations of this run, the warnings of the contacts and the state of the reveal and the safety number screens.
#[derive(Default)]
pub struct Chat {
    open: Option<i64>,
    convs: BTreeMap<i64, Vec<Message>>,
    /// Per contact, each warning with the epoch of its last raising.
    warnings: BTreeMap<i64, BTreeMap<Warning, u64>>,
    /// Per contact, a counter every warning event increments.
    epochs: BTreeMap<i64, u64>,
    /// The contact a `Verify` was submitted for and its epoch at the time.
    verify_at: Option<(i64, u64)>,
    // states reported before the answer that names the message came (events and answers travel on different threads)
    early: Vec<(i64, MsgId, OutState)>,
    pending_send: Option<(i64, Zeroizing<String>)>,
    reveal: Option<Reveal>,
    digits: Option<Zeroizing<String>>,
    digits_qr: Option<Image>,
    verified: bool,
    hist: BTreeMap<i64, Hist>,
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

    /// Leave the safety number screen: the digits and their code are dropped.
    pub fn close_safety(&mut self) {
        self.clear_digits();
    }

    /// Drop the safety number shown (and the verification state of the screen).
    pub fn clear_digits(&mut self) {
        self.digits = None;
        self.digits_qr = None;
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

    /// Whether the first page of the history of `contact` is to be asked for now (marks it as under way).
    pub fn history_first(&mut self, contact: i64) -> bool {
        let hist = self.hist.entry(contact).or_default();
        if hist.loaded || hist.loading {
            return false;
        }
        hist.loading = true;
        true
    }

    /// The cursor of the page of older messages to ask for now, if there is one (marks it as under way).
    pub fn history_older(&mut self, contact: i64) -> Option<i64> {
        let hist = self.hist.get_mut(&contact)?;
        if !hist.loaded || hist.loading || hist.exhausted {
            return None;
        }
        hist.loading = true;
        hist.oldest
    }

    /// Whether older messages may still be asked for.
    #[must_use]
    pub fn history_more(&self, contact: i64) -> bool {
        self.hist
            .get(&contact)
            .is_some_and(|h| h.loaded && !h.exhausted)
    }

    /// A request for a page was refused or failed: it may be asked again.
    pub fn history_failed(&mut self, contact: i64) {
        if let Some(hist) = self.hist.get_mut(&contact) {
            hist.loading = false;
        }
    }

    /// A page of the history came (newest first, `limit` asked for): its messages join the conversation before the ones the
    /// model has; a message the model already holds (this run's) stays as it is.
    pub fn history_arrived(&mut self, contact: i64, limit: u16, items: Vec<HistoryItem>) {
        let hist = self.hist.entry(contact).or_default();
        hist.loading = false;
        hist.loaded = true;
        hist.exhausted = items.len() < usize::from(limit);
        if let Some(last) = items.last() {
            hist.oldest = Some(last.cursor);
        }
        let list = self.convs.entry(contact).or_default();
        let mut older: Vec<Message> = Vec::new();
        for item in items.into_iter().rev() {
            if list
                .iter()
                .any(|m| m.id == item.msg_id && m.incoming == item.incoming)
            {
                continue;
            }
            let body = match (item.kind, item.text) {
                (KIND_TEXT, Some(text)) => Body::Text(text),
                (KIND_TEXT, None) => Body::Unavailable,
                // a view-once is never in the history with a payload; whatever row says so is gone
                (KIND_VIEW_ONCE, _) => Body::Viewed,
                _ => Body::Unsupported,
            };
            older.push(Message {
                id: item.msg_id,
                incoming: item.incoming,
                at_ms: Some(item.at_ms),
                body,
                state: None,
            });
        }
        older.append(list);
        *list = older;
    }

    /// Remember the text of the message being sent to `contact`.
    pub fn sending(&mut self, contact: i64, text: Zeroizing<String>) {
        self.pending_send = Some((contact, text));
    }

    /// Forget the message being sent (it was refused); the contact it was for.
    pub fn send_refused(&mut self) -> Option<i64> {
        self.pending_send.take().map(|(contact, _)| contact)
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
            state: Some(state),
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
            state: None,
        });
        read
    }

    /// An outgoing message reached `state`.
    pub fn state(&mut self, contact: i64, id: MsgId, state: OutState) {
        if let Some(message) = self.find(contact, &id) {
            message.state = Some(message.state.map_or(state, |s| s.then(state)));
        } else {
            // the answer that names the message has not come yet
            if self.early.len() >= EARLY_MAX {
                self.early.remove(0);
            }
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

    /// The user holds the message `id` of `contact` at `now_ms` of the model's clock: a reveal starts, nothing is shown before
    /// the core's answer. A reveal under way is not touched (its 20 seconds are not extended).
    pub fn hold(&mut self, contact: i64, id: MsgId, now_ms: u64) {
        if self.reveal.is_none() {
            self.reveal = Some(Reveal {
                contact,
                id,
                text: None,
                started_ms: now_ms,
            });
        }
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

    /// Whether the reveal under way has run for [`REVEAL_MAX_S`] seconds at `now_ms`.
    #[must_use]
    pub fn reveal_expired(&self, now_ms: u64) -> bool {
        self.reveal.as_ref().is_some_and(|r| {
            now_ms.saturating_sub(r.started_ms) >= REVEAL_MAX_S.saturating_mul(1000)
        })
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

    /// A warning on `contact`: every warning event moves the contact's epoch on.
    pub fn warn(&mut self, contact: i64, warning: Warning) {
        let epoch = self.epochs.entry(contact).or_insert(0);
        *epoch = epoch.saturating_add(1);
        let at = *epoch;
        self.warnings
            .entry(contact)
            .or_default()
            .insert(warning, at);
    }

    /// The warnings of `contact`, in a fixed order.
    #[must_use]
    pub fn warnings(&self, contact: i64) -> Vec<Warning> {
        self.warnings
            .get(&contact)
            .map(|set| set.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Whether `contact`'s conversation takes no input until it is verified again.
    #[must_use]
    pub fn frozen(&self, contact: i64) -> bool {
        self.warnings
            .get(&contact)
            .is_some_and(|set| set.keys().any(|w| w.freezes()))
    }

    /// A `Verify` for `contact` is submitted: the answer clears the warnings raised up to now, no later one.
    pub fn verify_submitted(&mut self, contact: i64) {
        let epoch = self.epochs.get(&contact).copied().unwrap_or(0);
        self.verify_at = Some((contact, epoch));
    }

    /// The `Verify` submitted was not confirmed: nothing is cleared.
    pub fn verify_refused(&mut self) {
        self.verify_at = None;
    }

    /// `contact` was verified (the answer to the `Verify` submitted): what froze the conversation up to the epoch recorded then
    /// is cleared; a key change that came after the submit stays.
    pub fn verified(&mut self, contact: i64) {
        let upto = match self.verify_at.take() {
            Some((to, epoch)) if to == contact => epoch,
            _ => 0,
        };
        if let Some(set) = self.warnings.get_mut(&contact) {
            set.retain(|w, at| !(w.freezes() && *at <= upto));
        }
        self.verified = !self.frozen(contact);
    }

    /// Whether the user verified the contact on the safety number screen just now.
    #[must_use]
    pub const fn just_verified(&self) -> bool {
        self.verified
    }

    /// The core gave the safety number; its code is made once, here.
    pub fn set_digits(&mut self, digits: Zeroizing<String>) {
        self.digits_qr = Matrix::of(&digits).map(|m| m.image());
        self.digits = Some(digits);
    }

    /// The safety number, if the screen holds it.
    #[must_use]
    pub fn digits(&self) -> Option<&Zeroizing<String>> {
        self.digits.as_ref()
    }

    /// The code of the safety number, made once when the number arrived.
    #[must_use]
    pub const fn digits_qr(&self) -> Option<&Image> {
        self.digits_qr.as_ref()
    }
}
