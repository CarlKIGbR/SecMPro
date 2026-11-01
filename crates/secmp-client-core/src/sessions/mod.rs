// SPDX-License-Identifier: AGPL-3.0-or-later
//! The durable sessions (`docs/02:102`, CS-3.7): one set of `sessions` rows per contact, keyed by the contact's id. Part 1
//! of Phase B writes the rows of a new session inside the accept transaction of an invitation ([`write_initial`]); the
//! session actor that drives them (B-4…B-7) moves here with its `Conversation`.

pub mod actor;
pub mod rotation;

use secmp_crypto::HybridVerifyingKey;
use secmp_proto::Decode as _;
use secmp_proto::tr::RatchetState;
use secmp_proto::tr::content::{Trust, ik_sig};
use secmp_proto::wire::inv::IksPublic;
use secmp_store::Tx;
use secmp_store::sessions::{insert_skipped, put_fixed, put_trust};

use crate::api::{ContactId, Error};
use crate::outbox::StoreOutbox;
use crate::persist::{SharedStore, StorePersist};
use crate::scheduler::outbox::trust_code;
use actor::{Conversation, EntropySource, initial_parts};

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
    let s = store.lock().map_err(|_| Error::Unavailable)?;
    let row = s
        .contacts()?
        .into_iter()
        .find(|c| c.id == contact.0)
        .ok_or(Error::Unavailable)?;
    Ok(ik_sig(&IksPublic::decode(&row.iks)?)?)
}

/// A verified key change was announced (`SessionEvent::KeyChanged`, spec §7.7): the contact takes the new identity — the
/// row, the fingerprint, unverified — and the session verifies later key changes under the new `IK_sig`. The trust of the
/// session (`KeyChanged`) was committed with the cell; real sends stay held until the new safety number is verified.
///
/// # Errors
/// [`Error::Unavailable`] if the store cannot be written.
pub fn accept_key_change<S: EntropySource>(
    store: &SharedStore,
    conversation: &mut StoreConversation<S>,
    contact: ContactId,
    new: &IksPublic,
) -> Result<(), Error> {
    use secmp_proto::Encode as _;

    let iks = new.encode()?;
    let fp = secmp_proto::prekeys::fingerprint_of(new)?;
    store
        .lock()
        .map_err(|_| Error::Unavailable)?
        .txn(|tx| secmp_store::contacts::put_contact_identity(tx, contact.0, &iks, &fp))?;
    conversation.set_peer(ik_sig(new)?);
    Ok(())
}

/// The user verified the safety number of `contact` (spec §6.7): the contact and the session are verified, in one store
/// transaction; a held message goes out with the next slots. A frozen session stays frozen.
///
/// # Errors
/// [`Error::Unavailable`] if the store cannot be written.
pub fn set_verified<S: EntropySource>(
    store: &SharedStore,
    conversation: &mut StoreConversation<S>,
    contact: ContactId,
) -> Result<(), Error> {
    store.lock().map_err(|_| Error::Unavailable)?.txn(|tx| {
        secmp_store::contacts::set_contact_verified(tx, contact.0, true)?;
        put_trust(tx, contact.0, &[trust_code(Trust::Verified)])
    })?;
    conversation.set_trust(Trust::Verified);
    Ok(())
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
    let (inbox, trust) = persist.load_inbox_trust().map_err(|_| Error::Unavailable)?;
    let trust = match trust.as_ref().map(|t| t.first()) {
        Some(Some(code)) => trust_of(*code).ok_or(Error::Unavailable)?,
        _ => Trust::Unverified,
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
/// contact of a handshake is stored unverified (§6.6). The reassembly state is empty and has no row.
///
/// # Errors
/// [`secmp_store::Error::Unavailable`] if the state does not serialise, an entry is malformed (Q175) or a statement fails.
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
    put_trust(tx, session, &[trust_code(Trust::Unverified)])
}

#[cfg(test)]
pub(crate) mod tests;
