// SPDX-License-Identifier: AGPL-3.0-or-later
//! The durable sessions (`docs/02:102`, CS-3.7): one set of `sessions` rows per contact, keyed by the contact's id. Part 1
//! of Phase B writes the rows of a new session inside the accept transaction of an invitation ([`write_initial`]); the
//! session actor that drives them (B-4…B-7) moves here with its `Conversation`.

pub mod actor;

use secmp_proto::tr::RatchetState;
use secmp_proto::tr::content::Trust;
use secmp_store::Tx;
use secmp_store::sessions::{insert_skipped, put_fixed, put_trust};

use crate::scheduler::outbox::trust_code;
use actor::initial_parts;

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
    put_fixed(tx, session, &parts.fixed)?;
    for (ord, entry) in (0_i64..).zip(&parts.skipped) {
        insert_skipped(tx, session, ord, entry)?;
    }
    put_trust(tx, session, &[trust_code(Trust::Unverified)])
}
