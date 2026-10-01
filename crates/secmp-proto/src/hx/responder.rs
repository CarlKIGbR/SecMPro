// SPDX-License-Identifier: AGPL-3.0-or-later
//! The responder of SecMP-HX (spec §6.5 grouping, §6.6 steps 1–4): the inviter's side.
//!
//! **Atomicity.** Everything `accept` computes lives on working copies; the only side effect is the OPK deletion of
//! step 4, which is the last operation. Every rejection therefore leaves the store, the record and the caller's
//! state as they were, and "log nothing identifying" (§6.6 step 3) holds because nothing here logs.
//!
//! **One uniform error.** Every rejection of untrusted input is [`Error::Rejected`], whichever check failed;
//! [`Error::Unavailable`] occurs only if the ratchet's sending half could not draw randomness after the
//! `first_msg` MAC verified (the caller neither acknowledges nor deletes anything and retries).

use secmp_crypto::{Caead, ConstantTimeEq, Label, MlKem1024Ct, SecretBytes, Zeroizing};

use super::derive::{Shared, TranscriptInputs, k_id, session_key, transcript};
use super::{ResponderKeys, dh_checked};
use crate::codec::{Decode, Encode};
use crate::error::{Error, Result};
use crate::inv::derive_k_inv;
use crate::prekeys::{InvitationRecord, PrekeyStore};
use crate::sizes::{HANDSHAKE_CHUNK_LEN, HANDSHAKE_CHUNKS, NONCE_LEN};
use crate::tr::{Entropy, RatchetState};
use crate::wire::Id;
use crate::wire::cell::{Cell, ContentBody, RouteDescriptor};
use crate::wire::hx::{HandshakeCellPlaintext, Inner, Outer};
use crate::wire::inv::{IksPublic, Profile};

/// At most this many partially received envelopes are held while grouping; the oldest is evicted (ADR-044 (c)).
pub const MAX_PARTIAL_GROUPS: usize = 8;

/// What a successful [`Responder::accept`] yields (§6.6 step 4).
pub struct Accepted {
    /// The ratchet state after decrypting `first_msg` (§7.4): the responder side of the session. It holds none
    /// of the prekey secrets: the DH step replaced `SPK_dh` and `RPK_kem` (CLAUDE.md §1.3).
    pub state: RatchetState,
    /// `IKSPublic_I`: the contact is stored as **unverified**.
    pub peer: IksPublic,
    /// The initiator's reply routes from `first_msg`'s Handshake content, byte-identical to what it sent (§6.5).
    pub routes: Vec<RouteDescriptor>,
    /// The initiator's profile from the Handshake content.
    pub profile: Profile,
}

/// The responder (the inviter).
pub struct Responder;

/// The chunks received so far for one `init_id`, of any chunk type `C` (the responder stores the 4006-byte chunks;
/// the Kani harnesses of the grouping and of `drive` use a small stand-in, which is why they are generic).
pub(crate) struct Group<K, C> {
    pub(crate) init_id: K,
    pub(crate) chunks: [Option<C>; 3],
}

impl<K, C> Group<K, C> {
    pub(crate) fn complete(&self) -> bool {
        self.chunks.iter().all(Option::is_some)
    }
}

/// Add chunk `i` (< 3) of `init_id` (§6.5, ADR-044 (c)): a duplicate `(init_id, i)` is ignored whatever its bytes
/// (identical: nothing to do; differing: first-seen wins); a new `init_id` evicts the oldest partial group once
/// [`MAX_PARTIAL_GROUPS`] are held. Returns the index of the group if it is now complete.
pub(crate) fn insert<K: PartialEq, C>(
    groups: &mut Vec<Group<K, C>>,
    init_id: K,
    i: usize,
    chunk: C,
    max_groups: usize,
) -> Option<usize> {
    if i >= 3 {
        return None;
    }
    let at = if let Some(at) = groups.iter().position(|g| g.init_id == init_id) {
        at
    } else {
        if groups.len() >= max_groups {
            groups.remove(0);
        }
        groups.push(Group {
            init_id,
            chunks: [None, None, None],
        });
        groups.len().checked_sub(1)?
    };
    let group = groups.get_mut(at)?;
    let slot = group.chunks.get_mut(i)?;
    if slot.is_none() {
        *slot = Some(chunk);
    }
    group.complete().then_some(at)
}

/// The driver of §6.5 and §6.6 step 4 over already opened chunks `(init_id, i, chunk)`, in fetch order: group them
/// ([`insert`]); for each group that completes, in the order of completion, `process` it (§6.6 steps 1–3, reading
/// the store); the first group `process` accepts is the session: the OPK is deleted — the only call of
/// `delete_opk`, after `process` succeeded — and `process`'s value returned. A group `process` rejects is discarded
/// and the OPK kept; later groups are still processed. If none is accepted the result is [`Error::Rejected`];
/// [`Error::Unavailable`] from `process` is passed up at once. A failing `delete_opk` rejects, the OPK kept.
pub(crate) fn drive<K: PartialEq, C, T, S: PrekeyStore>(
    items: impl IntoIterator<Item = (K, usize, C)>,
    store: &mut S,
    opk_id: u32,
    mut process: impl FnMut(&Group<K, C>, &S) -> Result<T>,
) -> Result<T> {
    let mut groups: Vec<Group<K, C>> = Vec::new();
    for (init_id, i, chunk) in items {
        let Some(done) = insert(&mut groups, init_id, i, chunk, MAX_PARTIAL_GROUPS) else {
            continue;
        };
        let group = groups.remove(done);
        match process(&group, &*store) {
            Ok(accepted) => {
                // step 4: delete the OPK — the last operation; a failure keeps it and rejects
                store.delete_opk(opk_id).map_err(|_| Error::Rejected)?;
                return Ok(accepted);
            }
            Err(Error::Unavailable) => return Err(Error::Unavailable),
            // a rejected complete group is discarded; the OPK is kept (§6.6 step 3)
            Err(_) => {}
        }
    }
    Err(Error::Rejected)
}

impl Responder {
    /// §6.5 and §6.6: trial-open every cell of `cells` (the cells fetched from the invitation queue and retained
    /// for it) with `K_inv`; ignore what does not open or parse; group the chunks by `init_id`; for each group that
    /// completes, in the order of completion, run steps 1–3 — and on the first group that passes, step 4: delete
    /// the OPK, and return the session.
    ///
    /// `record` is the invitation's record (§5.2). Expiry is the record lifecycle's: the caller offers only
    /// unexpired records ([`crate::prekeys::MemoryPrekeyStore::offered_records`], ADR-044 (d)).
    ///
    /// A group that completes but is rejected is discarded and the OPK kept; later groups are still processed. If
    /// no group passes, the result is [`Error::Rejected`], whether `cells` held garbage only, an incomplete group
    /// or a bad envelope.
    ///
    /// # Errors
    /// The uniform [`Error::Rejected`]; [`Error::Unavailable`] as described in the module documentation. The store
    /// is unchanged on every error.
    pub fn accept(
        cells: &[Cell],
        record: &InvitationRecord,
        store: &mut impl PrekeyStore,
        own_keys: &ResponderKeys<'_>,
        entropy: &mut impl Entropy,
    ) -> Result<Accepted> {
        let k_inv = derive_k_inv(&record.ld_id, &record.link_key)?;
        let ad_cell = [Label::HxInitcell.as_bytes(), record.ld_id.as_slice()].concat();
        // trial-open every cell with K_inv; anything that does not open or parse is ignored (garbage may come from
        // the relay or an invitation thief; it is never fatal)
        let opened = cells.iter().filter_map(|cell| {
            let p = open_cell(&k_inv, &ad_cell, cell)?;
            Some((p.init_id, usize::from(p.i), p.chunk))
        });
        drive(opened, store, record.opk_id, |group, store| {
            process(group, record, store, own_keys, entropy)
        })
    }
}

/// `CAEAD.Open(K_inv, N_i, "SecMP-HX/1 initcell" ‖ ld_id, …)` and the `HandshakeCellPlaintext` decoder (`total` = 3,
/// `i` ≤ 2). `None` for a cell that does not open or parse.
fn open_cell(k_inv: &SecretBytes<32>, ad: &[u8], cell: &Cell) -> Option<HandshakeCellPlaintext> {
    let (n, com_ct) = cell.as_bytes().split_first_chunk::<NONCE_LEN>()?;
    let plaintext = Caead::open(k_inv, n, ad, com_ct).ok()?;
    HandshakeCellPlaintext::decode(&plaintext).ok()
}

/// §6.6 steps 1–3 on a complete group; no side effect.
fn process(
    group: &Group<Id, Box<[u8; HANDSHAKE_CHUNK_LEN]>>,
    record: &InvitationRecord,
    store: &impl PrekeyStore,
    own_keys: &ResponderKeys<'_>,
    entropy: &mut impl Entropy,
) -> Result<Accepted> {
    // Padded = chunk_0 ‖ chunk_1 ‖ chunk_2
    let mut padded = Zeroizing::new(Vec::with_capacity(
        HANDSHAKE_CHUNK_LEN.saturating_mul(usize::from(HANDSHAKE_CHUNKS)),
    ));
    for chunk in &group.chunks {
        padded.extend_from_slice(chunk.as_deref().ok_or(Error::Rejected)?);
    }

    // step 1: parse Outer (padding, version, low-order EK_I); `spk_id`/`opk_id` are this invitation's; the SPK is
    // retained and the OPK unused
    let outer = Outer::decode(&padded)?;
    if outer.spk_id != record.spk_id || outer.opk_id != record.opk_id {
        return Err(Error::Rejected);
    }
    let spk = store.spk(outer.spk_id).ok_or(Error::Rejected)?;
    let opk = store.opk(outer.opk_id).ok_or(Error::Rejected)?;

    // step 2: DH3, DH4, ss_spk, ss_opk -> K_id; open inner_ct
    let ek = outer.ek_i.as_bytes();
    let dh3 = dh_checked(spk.dh_secret(), ek)?;
    let dh4 = dh_checked(opk.dh_secret(), ek)?;
    let kem_signed = spk
        .kem_secret()
        .decapsulate(&MlKem1024Ct::from_bytes(outer.ct_spk.as_slice())?);
    let kem_onetime = opk
        .kem_secret()
        .decapsulate(&MlKem1024Ct::from_bytes(outer.ct_opk.as_slice())?);
    let k_id = k_id(
        &record.ld_id,
        &record.link_key,
        &dh3,
        &kem_signed,
        &dh4,
        &kem_onetime,
    )?;
    let ad_inner = [Label::HxInner.as_bytes(), record.ld_id.as_slice()].concat();
    let com_ct = [outer.inner_ct.com.as_slice(), outer.inner_ct.ct.as_slice()].concat();
    let inner_bytes = Caead::open(&k_id, &outer.inner_ct.n2, &ad_inner, &com_ct)?;
    // IKSPublic_I decodable with `ik_dh` not low-order; `first_msg` is a 4096-byte cell
    let inner = Inner::decode(&inner_bytes)?;
    // ADR-044 (f): a reflected identity is rejected
    let reflected = inner.iks.encode()?.ct_eq(&own_keys.iks.encode()?);
    if bool::from(reflected) {
        return Err(Error::Rejected);
    }

    // step 3: DH1, DH2, transcript, SK; TR responder (§7.2); decrypt first_msg (§7.4)
    let dh1 = dh_checked(spk.dh_secret(), inner.iks.ik_dh.as_bytes())?;
    let dh2 = dh_checked(own_keys.ik_dh.secret(), ek)?;
    let spk_dh = spk.dh_public()?;
    let spk_kem = spk.kem_public()?;
    let rpk_kem = spk.rpk_public()?;
    let opk_dh = opk.dh_public()?;
    let opk_kem = opk.kem_public()?;
    let transcript = transcript(&TranscriptInputs {
        iks_r: own_keys.iks,
        spk_id: outer.spk_id,
        spk_dh: &spk_dh,
        spk_kem: &spk_kem,
        rpk_kem: &rpk_kem,
        opk_id: outer.opk_id,
        opk_dh: &opk_dh,
        opk_kem: &opk_kem,
        iks_i: &inner.iks,
        ek_i: &outer.ek_i,
        ct_spk: &outer.ct_spk,
        ct_opk: &outer.ct_opk,
        ld_id: &record.ld_id,
    })?;
    let sk = session_key(
        &Shared {
            dh1,
            dh2,
            dh3,
            dh4,
            ss_spk: kem_signed,
            ss_opk: kem_onetime,
        },
        &transcript,
    )?;
    let state = RatchetState::init_responder(&sk, &transcript, spk.dh_copy()?, spk.rpk_copy()?)?;
    let opened = state
        .decrypt_with(inner.first_msg.as_bytes(), entropy)
        .map_err(|refused| refused.error())?;
    // ADR-044 (e): the first message carries n = 0 and pn = 0
    if opened.header_counters() != (0, 0) {
        return Err(Error::Rejected);
    }
    let (state, plaintext) = opened
        .commit(|_| Ok::<(), Error>(()))
        .map_err(|_: Error| Error::Rejected)?;
    // §6.5 / §6.6 step 3: the content must be a Handshake (caps = 0 and a non-empty route list are the decoder's)
    let ContentBody::Handshake(handshake) = plaintext.content()?.body else {
        return Err(Error::Rejected);
    };
    // ADR-044 (e): at least one route of a known kind
    if !handshake
        .routes
        .iter()
        .any(|r| matches!(r, RouteDescriptor::RelayQueue(_)))
    {
        return Err(Error::Rejected);
    }
    Ok(Accepted {
        state,
        peer: inner.iks,
        routes: handshake.routes,
        profile: handshake.profile,
    })
}
