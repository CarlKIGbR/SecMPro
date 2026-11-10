// SPDX-License-Identifier: AGPL-3.0-or-later
//! The durable sessions (`docs/02:102`, CS-3.7): one set of `sessions` rows per contact, keyed by the contact's id. Part 1
//! of Phase B writes the rows of a new session inside the accept transaction of an invitation ([`write_initial`]); the
//! session actor that drives them (B-4…B-7) moves here with its `Conversation`.

pub mod actor;
pub mod rotation;

use secmp_crypto::{HybridVerifyingKey, Zeroizing};
use secmp_proto::Decode as _;
use secmp_proto::tr::Entropy as _;
use secmp_proto::tr::RatchetState;
use secmp_proto::tr::content::{Trust, ik_sig};
use secmp_proto::wire::cell::AppKind;
use secmp_proto::wire::cell::ControlCode;
use secmp_proto::wire::inv::IksPublic;
use secmp_store::Tx;
use secmp_store::sessions::{
    init_trust, insert_pending_control, insert_skipped, put_fixed, trust_row, update_trust,
};

use crate::api::{ContactId, Error};
use crate::contacts::Contacts;
use crate::outbox::StoreOutbox;
use crate::persist::{SharedStore, StorePersist};
use crate::scheduler::outbox::{MsgId, OutMessage, Outbox as _, trust_code};
use actor::{
    Conversation, EntropySource, PendingControl, Received, Refusal, block_code, block_of,
    initial_parts,
};

/// A conversation over the profile store: the session's rows, the contact's outbox.
pub type StoreConversation<S> = Conversation<StoreOutbox, StorePersist, S>;

/// The trust of its stored code.
#[must_use]
pub const fn trust_of(code: u8) -> Option<Trust> {
    match code {
        0 => Some(Trust::Unverified),
        1 => Some(Trust::Verified),
        2 => Some(Trust::KeyChanged),
        3 => Some(Trust::Frozen),
        _ => None,
    }
}

/// The contact's `IK_sig` (the key a `KeyChange` is verified under, §7.7), from the identity the contact row holds.
///
/// # Errors
/// [`Error::Unavailable`] if there is no such contact or its identity does not decode.
pub fn peer_key(store: &SharedStore, contact: ContactId) -> Result<HybridVerifyingKey, Error> {
    Ok(ik_sig(&peer_identity(store, contact)?)?)
}

/// The identity (`IKSPublic`) the contact row of `contact` holds (ADR-058: a `KeyChange` naming it and signed by the
/// previous `IK_sig` is the accepted succession again).
///
/// # Errors
/// [`Error::Unavailable`] if there is no such contact or its identity does not decode.
pub fn peer_identity(store: &SharedStore, contact: ContactId) -> Result<IksPublic, Error> {
    let s = store.lock().map_err(|_| Error::Unavailable)?;
    let row = s
        .contacts()?
        .into_iter()
        .find(|c| c.id == contact.0)
        .ok_or(Error::Unavailable)?;
    Ok(IksPublic::decode(&row.iks)?)
}

/// The user verified the safety number of `contact` (spec §6.7): the contact and the session are verified, in one store
/// transaction; a held message goes out with the next slots. A frozen session stays frozen (Q205): the store's guarded
/// trust writer refuses, and nothing is written — the contact stays unverified.
///
/// # Errors
/// [`Error::Frozen`] if the session is frozen (in memory or in the store); [`Error::Unavailable`] if the store cannot be
/// written.
pub fn set_verified<S: EntropySource>(
    store: &SharedStore,
    conversation: &mut StoreConversation<S>,
    contact: ContactId,
) -> Result<(), Error> {
    if matches!(conversation.trust(), Trust::Frozen) {
        return Err(Error::Frozen);
    }
    let mut s = store.lock().map_err(|_| Error::Unavailable)?;
    let written = s.txn(|tx| {
        update_trust(tx, contact.0, Some(trust_code(Trust::Verified)), None)?;
        secmp_store::contacts::set_contact_verified(tx, contact.0, true)
    });
    if written.is_err() {
        return Err(trust_write_refusal(&s, contact)?);
    }
    drop(s);
    conversation.set_trust(Trust::Verified);
    Ok(())
}

/// The error for a refused trust write: [`Error::Frozen`] if the stored trust is `Frozen` (the store's guard), else
/// [`Error::Unavailable`].
///
/// # Errors
/// [`Error::Unavailable`] if the trust row cannot be read or does not decode.
pub(crate) fn trust_write_refusal(
    store: &secmp_store::Store,
    contact: ContactId,
) -> Result<Error, Error> {
    let (_, row) = store.inbox_trust(contact.0)?;
    let stored = row.as_deref().map(|r| trust_row(r)).transpose()?;
    Ok(match stored {
        Some((code, _)) if trust_of(code) == Some(Trust::Frozen) => Error::Frozen,
        _ => Error::Unavailable,
    })
}

/// Block real sends on the session of `contact` and tell the peer (`Removed`: `Control{1}`, `Reset`: `Control{2}`;
/// Q210 b, c): in one store transaction the block byte of the trust row — set and never cleared — and the `Control` as a
/// pending control content; then both in memory (the `Control` goes out on a coming slot, its row with its send commit).
///
/// # Errors
/// [`Error::Unavailable`] if the store cannot be written or `block` is not a block (nothing changes).
pub fn block_session<S: EntropySource>(
    store: &SharedStore,
    conversation: &mut StoreConversation<S>,
    contact: ContactId,
    block: Refusal,
) -> Result<(), Error> {
    let byte = block_code(block).ok_or(Error::Unavailable)?;
    let code = match block {
        Refusal::Removed => ControlCode::ContactRemoved,
        _ => ControlCode::SessionResetRequest,
    };
    let control = PendingControl::Control(code)
        .encode()
        .map_err(|_| Error::Unavailable)?;
    let ord = store.lock().map_err(|_| Error::Unavailable)?.txn(|tx| {
        update_trust(tx, contact.0, None, Some(byte))?;
        insert_pending_control(tx, contact.0, &control)
    })?;
    conversation.restore_block(Some(block));
    conversation
        .queue_pending(ord, PendingControl::Control(code))
        .map_err(|_| Error::Unavailable)
}

/// The period in ms of the queue `contact` sends to (its first route of a known kind), if it has one: `T_RS` is a function
/// of it (spec §10.4, Q210 d).
///
/// # Errors
/// [`Error::Unavailable`] if the store cannot be read or the routes do not decode.
pub fn send_period_ms(store: &SharedStore, contact: ContactId) -> Result<Option<u64>, Error> {
    use secmp_proto::wire::cell::{RouteDescriptor, RouteUpdateBody};

    let routes = store
        .lock()
        .map_err(|_| Error::Unavailable)?
        .contact_routes(contact.0)?;
    let Some(bytes) = routes else {
        return Ok(None);
    };
    Ok(RouteUpdateBody::decode(&bytes)?
        .routes
        .iter()
        .find_map(|r| match r {
            RouteDescriptor::RelayQueue(q) => {
                Some(u64::from(q.period_s.seconds()).saturating_mul(1_000))
            }
            RouteDescriptor::Unknown { .. } => None,
        }))
}

/// The largest text the `Api` takes: 16 KiB (ADR-054 item 3; inline attachments are kind 1 of at most 64 fragments).
pub const MESSAGE_MAX: usize = 16_384;

/// What the application sends.
pub struct Outgoing<'a> {
    /// `AppMessage.kind`.
    pub kind: u8,
    /// The payload.
    pub payload: &'a [u8],
    /// `expire_after` in seconds (0: never).
    pub expire_after: u32,
}

/// Queue a message for `contact` (`Api.send`, spec §10.4, §7.6; O-27): the one entry through which the application's
/// content reaches a session. Nothing here wakes, adds or removes a slot — a refusal leaves the schedule as it was (the
/// slots keep carrying dummies, spec §10.1), and an accepted message only changes the outbox and the history.
///
/// Refusals, before anything is queued: [`Error::Unsupported`] for kinds 2, 4, 5, 6, an unknown kind, or a text that is
/// empty, longer than [`MESSAGE_MAX`], not UTF-8 or contains U+0000 (ADR-054 items 1, 3); [`Error::Blocked`] for a removed contact or a changed identity that is not verified again;
/// [`Error::ReinviteRequired`]; [`Error::Frozen`]; [`Error::ResetRequested`]; [`Error::Unverified`] for a view-once
/// (kind 3) to a contact that is not verified.
///
/// # Errors
/// As above; [`Error::Unavailable`] if the store refused the outbox row or the history row (F9: the message is not queued).
pub fn queue_message<S: EntropySource>(
    store: &SharedStore,
    contacts: &Contacts,
    conversation: &mut StoreConversation<S>,
    contact: ContactId,
    message: &Outgoing<'_>,
    now_ms: u64,
) -> Result<MsgId, Error> {
    let Outgoing {
        kind,
        payload,
        expire_after,
    } = *message;
    let kind = AppKind::ALL
        .into_iter()
        .find(|k| k.byte() == kind)
        .ok_or(Error::Unsupported)?;
    if !actor::app_payload_ok(kind, payload) {
        return Err(Error::Unsupported);
    }
    contacts.check_send(contact)?;
    match conversation.may_send_real() {
        Ok(()) | Err(Refusal::AwaitingReply) => {}
        Err(Refusal::Trust) => {
            return Err(if matches!(conversation.trust(), Trust::Frozen) {
                Error::Frozen
            } else {
                Error::Blocked
            });
        }
        Err(Refusal::Removed) => return Err(Error::Blocked),
        Err(Refusal::Reset) => return Err(Error::ResetRequested),
    }
    let view_once = matches!(kind, AppKind::ViewOnceText);
    if view_once && !matches!(conversation.trust(), Trust::Verified) {
        return Err(Error::Unverified);
    }
    let msg_id: MsgId = *conversation
        .source_mut()
        .entropy()
        .secret::<16>()
        .map_err(|_| Error::Unavailable)?
        .expose_secret();
    // the history first (a view-once is never written): an outbox that refuses takes the row back
    if !view_once {
        store
            .lock()
            .map_err(|_| Error::Unavailable)?
            .insert_message(&secmp_store::messages::NewMessage {
                contact_id: contact.0,
                msg_id,
                direction: secmp_store::messages::Direction::Out,
                kind: kind.byte(),
                ts_ms: now_ms,
                expire_after,
                payload,
            })?;
    }
    let queued = conversation.outbox_mut().enqueue_durable(
        OutMessage {
            msg_id,
            kind,
            expire_after,
            payload: Zeroizing::new(payload.to_vec()),
        },
        now_ms,
    );
    if !queued {
        if !view_once {
            let _ = store
                .lock()
                .map_err(|_| Error::Unavailable)?
                .delete_message(contact.0, &msg_id);
        }
        return Err(Error::Unavailable);
    }
    Ok(msg_id)
}

/// The application takes the messages a conversation delivered: a view-once is held in memory (never written, even when
/// the contact is not verified — `reveal` refuses then, O-27, CS-1.14); every other message goes to the history. Returns
/// each message's id and kind byte.
///
/// # Errors
/// [`Error::Unavailable`] if the history cannot be written (the messages already taken are not lost: the failing one and
/// those after it are returned to nobody — the store is the application's, a retry is its decision).
pub fn store_received(
    store: &SharedStore,
    contact: ContactId,
    received: Vec<Received>,
    now_ms: u64,
) -> Result<Vec<(MsgId, u8)>, Error> {
    let mut out = Vec::with_capacity(received.len());
    let mut s = store.lock().map_err(|_| Error::Unavailable)?;
    for r in received {
        if matches!(r.kind, AppKind::ViewOnceText) {
            s.hold_received_view_once(r.msg_id, &r.payload);
        } else {
            s.insert_message(&secmp_store::messages::NewMessage {
                contact_id: contact.0,
                msg_id: r.msg_id,
                direction: secmp_store::messages::Direction::In,
                kind: r.kind.byte(),
                ts_ms: now_ms,
                expire_after: 0,
                payload: &r.payload,
            })?;
        }
        out.push((r.msg_id, r.kind.byte()));
    }
    Ok(out)
}

/// Show a received view-once (`Api.reveal`, O-27): only for a verified contact — from an unverified one it stays held,
/// locked — and for 20 s after the first reveal; it is never written.
///
/// # Errors
/// [`Error::Unverified`] unless the contact is verified; [`Error::Unavailable`] if it is not (or no longer) held.
pub fn reveal<S: EntropySource>(
    store: &SharedStore,
    conversation: &StoreConversation<S>,
    msg_id: &MsgId,
    now_ms: u64,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !matches!(conversation.trust(), Trust::Verified) {
        return Err(Error::Unverified);
    }
    store
        .lock()
        .map_err(|_| Error::Unavailable)?
        .reveal_view_once(msg_id, now_ms)
        .ok_or(Error::Unavailable)
}

/// The contacts whose queues may enter the scheduler: those with a durable session (SE-16, Q165) — for a responder after
/// the accept commit, for an initiator after its state and handshake cells were persisted and released. A contact row
/// without session rows (a restored contact, BK-03) is not ready.
///
/// # Errors
/// [`Error::Unavailable`] if the store cannot be read.
pub fn ready_contacts(store: &SharedStore) -> Result<Vec<ContactId>, Error> {
    let s = store.lock().map_err(|_| Error::Unavailable)?;
    let mut out = Vec::new();
    for c in s.contacts()? {
        if s.session_rows(c.id)?.is_some() {
            out.push(ContactId(c.id));
        }
    }
    Ok(out)
}

/// Open the conversation of `contact` from its durable rows (CS-3.7): the ratchet state, the reassembly state, the trust,
/// the outbox, and — for an initiator that has not heard from the responder — the three handshake cells as persisted;
/// `source` is its randomness, `unix_base` the Unix time at monotonic 0. A restart is this call.
///
/// # Errors
/// [`Error::Unavailable`] if the contact has no session or a row does not open.
pub fn open_conversation<S: EntropySource>(
    store: &SharedStore,
    contact: ContactId,
    source: S,
    unix_base: u64,
) -> Result<StoreConversation<S>, Error> {
    let persist = StorePersist::open(std::sync::Arc::clone(store), contact.0)
        .map_err(|_| Error::Unavailable)?;
    let parts = persist
        .load()
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::Unavailable)?;
    let (inbox, row) = persist.load_inbox_trust().map_err(|_| Error::Unavailable)?;
    // `trust code ‖ block`, strictly (Q210 b); no row: a session before its first trust write
    let (trust, block) = match row.as_deref().map(|r| trust_row(r)).transpose()? {
        Some((code, block)) => (
            trust_of(code).ok_or(Error::Unavailable)?,
            block_of(block).ok_or(Error::Unavailable)?,
        ),
        None => (Trust::Unverified, None),
    };
    let outbox = StoreOutbox::open(std::sync::Arc::clone(store), contact.0)
        .map_err(|_| Error::Unavailable)?;
    let history = persist.delivered_ids().map_err(|_| Error::Unavailable)?;
    let peer = peer_key(store, contact)?;
    let mut conversation = Conversation::from_parts(
        &parts,
        inbox.as_deref().map(Vec::as_slice),
        trust,
        (outbox, persist, source),
        peer,
        unix_base,
    )
    .map_err(|_| Error::Unavailable)?;
    conversation.seed_seen(history);
    conversation.restore_block(block);
    // the identity before the last accepted key change (ADR-058): a read or open error fails the open like every other
    // part; a row that does not decode or whose `IK_sig` does not load is treated as absent (fail closed: a repeat
    // freezes)
    let previous = store
        .lock()
        .map_err(|_| Error::Unavailable)?
        .previous_identity(contact.0)?
        .and_then(|row| IksPublic::decode(&row).ok())
        .and_then(|iks| ik_sig(&iks).ok());
    conversation.set_peer_identity(peer_identity(store, contact)?, previous);
    // the control contents whose effect is durable and that were not sealed yet (Q210 c)
    let pending = store
        .lock()
        .map_err(|_| Error::Unavailable)?
        .pending_controls(contact.0)?;
    for (ord, row) in pending {
        let content = PendingControl::decode(&row).map_err(|_| Error::Unavailable)?;
        conversation
            .queue_pending(ord, content)
            .map_err(|_| Error::Unavailable)?;
    }
    let cells = store
        .lock()
        .map_err(|_| Error::Unavailable)?
        .handshake(contact.0)?;
    if let Some(bytes) = cells {
        let cells = secmp_proto::hx::PersistedCells::from_bytes(&bytes)?.into_cells();
        conversation.queue_handshake(&cells);
    }
    Ok(conversation)
}

/// Write the session of the accepted handshake `state` as `session` (the contact's id) into the caller's transaction: the
/// fixed part, one row per skipped entry (a responder's first state has none) and the trust, which is `Unverified` — the
/// contact of a handshake is stored unverified (§6.6) — through the guarded writer onto a session without a trust row
/// (Q205). The reassembly state is empty and has no row.
///
/// # Errors
/// [`secmp_store::Error::Unavailable`] if the state does not serialise, an entry is malformed (Q175), the session has a
/// trust row already or a statement fails.
pub(crate) fn write_initial(
    tx: &mut Tx<'_>,
    session: i64,
    state: &RatchetState,
) -> secmp_store::Result<()> {
    let parts = initial_parts(state).map_err(|_| secmp_store::Error::Unavailable)?;
    write_initial_parts(tx, session, &parts)
}

/// [`write_initial`] for a state already in its parts (an initiator's, as `HandshakeCells::release` hands it over).
///
/// # Errors
/// As [`write_initial`].
pub(crate) fn write_initial_parts(
    tx: &mut Tx<'_>,
    session: i64,
    parts: &secmp_proto::tr::RatchetParts,
) -> secmp_store::Result<()> {
    put_fixed(tx, session, &parts.fixed)?;
    for (ord, entry) in (0_i64..).zip(&parts.skipped) {
        insert_skipped(tx, session, ord, entry)?;
    }
    init_trust(tx, session, trust_code(Trust::Unverified))
}

#[cfg(test)]
pub(crate) mod tests;
