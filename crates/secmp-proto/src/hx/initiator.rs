// SPDX-License-Identifier: AGPL-3.0-or-later
//! The initiator of SecMP-HX (spec §6.4, §6.5): the invitee's side.

use secmp_crypto::{Caead, Label, SecretBytes, X25519Secret};

use super::derive::{Shared, TranscriptInputs, k_id, session_key, transcript};
use super::{HandshakeCells, InitiatorKeys, copy_route, dh_checked};
use crate::codec::{Decode, Encode};
use crate::error::{Error, Result};
use crate::inv::{InviteeAccepted, derive_k_inv};
use crate::keys::X25519Pk;
use crate::sizes::{COM_LEN, HANDSHAKE_CHUNK_LEN, HANDSHAKE_CHUNKS, HASH_LEN, MLKEM1024_CT_LEN};
use crate::tr::{Entropy, RatchetState};
use crate::wire::cell::{Cell, Content, ContentBody, HandshakeBody, RouteDescriptor};
use crate::wire::hx::{HandshakeCell, HandshakeCellPlaintext, Inner, InnerCt, Outer};
use crate::wire::inv::{InvitationV1, LinkDataV1, Profile};

/// The initiator (the invitee).
pub struct Initiator;

/// What §6.4 yields, before the envelope.
struct Agreement {
    ek_pk: X25519Pk,
    ct_spk: [u8; MLKEM1024_CT_LEN],
    ct_opk: [u8; MLKEM1024_CT_LEN],
    transcript: [u8; HASH_LEN],
    sk: SecretBytes<32>,
    k_id: SecretBytes<32>,
}

/// §6.4 on the bundle: `EK_I`, the two encapsulations, `DH1`…`DH4`, transcript, `SK`, `K_id`. `EK_I`'s secret is
/// local to this function and zeroized when it returns (ADR-044 (b)).
fn agree(
    invitation: &InvitationV1,
    link_data: &LinkDataV1,
    own_keys: &InitiatorKeys<'_>,
    entropy: &mut impl Entropy,
) -> Result<Agreement> {
    let bundle = &link_data.bundle;
    let iks_r = &link_data.inviter_iks;
    let ek: X25519Secret = entropy.x25519()?;
    let ek_pk = X25519Pk::from_bytes(ek.public_key().as_bytes())?;

    // (ct_spk, ss_spk) = ML-KEM-1024.Encaps(SPK_kem_R); (ct_opk, ss_opk) = ML-KEM-1024.Encaps(OPK_kem_R)
    let kem_signed = secmp_crypto::MlKem1024Ek::from_bytes(bundle.spk_kem.as_bytes())?;
    let kem_onetime = secmp_crypto::MlKem1024Ek::from_bytes(bundle.opk_kem.as_bytes())?;
    let (ct_signed, ss_signed) = entropy.encaps1024(&kem_signed)?;
    let (ct_onetime, ss_onetime) = entropy.encaps1024(&kem_onetime)?;

    // DH1..DH4, every one checked non-zero (§6.4)
    let dh1 = dh_checked(own_keys.ik_dh.secret(), bundle.spk_dh.as_bytes())?;
    let dh2 = dh_checked(&ek, iks_r.ik_dh.as_bytes())?;
    let dh3 = dh_checked(&ek, bundle.spk_dh.as_bytes())?;
    let dh4 = dh_checked(&ek, bundle.opk_dh.as_bytes())?;

    let transcript = transcript(&TranscriptInputs {
        iks_r,
        spk_id: bundle.spk_id,
        spk_dh: &bundle.spk_dh,
        spk_kem: &bundle.spk_kem,
        rpk_kem: &bundle.rpk_kem,
        opk_id: bundle.opk_id,
        opk_dh: &bundle.opk_dh,
        opk_kem: &bundle.opk_kem,
        iks_i: own_keys.iks,
        ek_i: &ek_pk,
        ct_spk: ct_signed.as_bytes(),
        ct_opk: ct_onetime.as_bytes(),
        ld_id: &invitation.ld_id,
    })?;
    let k_id = k_id(
        &invitation.ld_id,
        &invitation.link_key,
        &dh3,
        &ss_signed,
        &dh4,
        &ss_onetime,
    )?;
    let sk = session_key(
        &Shared {
            dh1,
            dh2,
            dh3,
            dh4,
            ss_spk: ss_signed,
            ss_opk: ss_onetime,
        },
        &transcript,
    )?;
    Ok(Agreement {
        ek_pk,
        ct_spk: *ct_signed.as_bytes(),
        ct_opk: *ct_onetime.as_bytes(),
        transcript,
        sk,
        k_id,
    })
}

/// `CAEAD.Seal(key, nonce, ad, plaintext)` split into `(COM, ct ‖ tag)`.
fn seal_split(
    key: &SecretBytes<32>,
    nonce: secmp_crypto::Nonce24,
    ad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; COM_LEN], Vec<u8>)> {
    let com_ct = Caead::seal(key, nonce, ad, plaintext)?;
    let (com, ct) = com_ct
        .split_first_chunk::<COM_LEN>()
        .ok_or(Error::Rejected)?;
    Ok((*com, ct.to_vec()))
}

/// §6.5: `Inner`, `inner_ct`, `Outer`, the padding, `init_id` and the three cells.
fn seal_envelope(
    invitation: &InvitationV1,
    link_data: &LinkDataV1,
    own_keys: &InitiatorKeys<'_>,
    agreement: &Agreement,
    first_msg: Cell,
    entropy: &mut impl Entropy,
) -> Result<[Cell; 3]> {
    let bundle = &link_data.bundle;
    let ld_id = invitation.ld_id.as_slice();
    let k_inv = derive_k_inv(&invitation.ld_id, &invitation.link_key)?;

    // Inner = IKSPublic_I ‖ first_msg; inner_ct = N2 ‖ CAEAD.Seal(K_id, N2, "SecMP-HX/1 inner" ‖ ld_id, Inner)
    let inner = Inner {
        iks: own_keys.iks.clone(),
        first_msg,
    }
    .encode()?;
    let nonce_inner = entropy.nonce()?;
    let nonce_inner_bytes = *nonce_inner.as_bytes();
    let (com, ct) = seal_split(
        &agreement.k_id,
        nonce_inner,
        &[Label::HxInner.as_bytes(), ld_id].concat(),
        &inner,
    )?;
    let inner_ct = InnerCt {
        n2: nonce_inner_bytes,
        com,
        ct: crate::codec::boxed(&ct)?,
    };

    // Outer = ver ‖ EK_I ‖ spk_id ‖ opk_id ‖ ct_spk ‖ ct_opk ‖ inner_ct, padded to 3 × 4006
    let padded = Outer {
        ek_i: agreement.ek_pk,
        spk_id: bundle.spk_id,
        opk_id: bundle.opk_id,
        ct_spk: Box::new(agreement.ct_spk),
        ct_opk: Box::new(agreement.ct_opk),
        inner_ct,
    }
    .encode()?;

    // init_id = random 16 B; cell_i = N_i ‖ CAEAD.Seal(K_inv, N_i, "SecMP-HX/1 initcell" ‖ ld_id,
    //                                    init_id ‖ i ‖ 0x03 ‖ Padded[i·4006 .. (i+1)·4006])
    let init_id: [u8; 16] = *entropy.secret::<16>()?.expose_secret();
    let ad_cell = [Label::HxInitcell.as_bytes(), ld_id].concat();
    let (chunks, _) = padded.as_chunks::<HANDSHAKE_CHUNK_LEN>();
    let mut cells = Vec::with_capacity(usize::from(HANDSHAKE_CHUNKS));
    for (i, chunk) in (0..HANDSHAKE_CHUNKS).zip(chunks) {
        let plaintext = HandshakeCellPlaintext {
            init_id,
            i,
            chunk: Box::new(*chunk),
        }
        .encode()?;
        let nonce_cell = entropy.nonce()?;
        let nonce_cell_bytes = *nonce_cell.as_bytes();
        let (com, ct) = seal_split(&k_inv, nonce_cell, &ad_cell, &plaintext)?;
        let cell = HandshakeCell {
            n: nonce_cell_bytes,
            com,
            ct: crate::codec::boxed(&ct)?,
        };
        cells.push(Cell::decode(&cell.encode()?)?);
    }
    let [c0, c1, c2]: [Cell; 3] = cells.try_into().map_err(|_| Error::Rejected)?;
    Ok([c0, c1, c2])
}

impl Initiator {
    /// §6.4–§6.5 and §7.2–§7.3: from the result of the invitee's checks (§5.5 steps 1, 3, 4:
    /// [`crate::inv::invitee_check`] — the only way to obtain an [`InviteeAccepted`]), derive `SK`, `K_id` and `K_inv`, initialise the ratchet as initiator, encrypt
    /// the Handshake Content (`profile`, `caps = 0`, `reply_routes`) as `first_msg` (`seq` 1, `ts` = `now`), seal
    /// `Inner`, `Outer` and the three cells. Returns the cells and the post-`first_msg` ratchet state; the caller
    /// persists both before any cell leaves the process ([`HandshakeCells::release`]).
    ///
    /// No signing key is a parameter: the envelope contains no signature by the initiator (§6.6). `EK_I`'s secret
    /// is zeroized at the end of `agree`, before the ratchet is initialised and anything is sealed (ADR-044 (b)); the state holds none of it.
    ///
    /// Randomness is drawn in this order: `EK_I`; `Encaps` randomness for `SPK_kem` and for `OPK_kem`; the ratchet
    /// initialisation (`dh_s`, `kem_s`, `Encaps` randomness); the `first_msg` header nonce; `N2`; `init_id`;
    /// `N_0`, `N_1`, `N_2`.
    ///
    /// # Errors
    /// [`Error::Rejected`] if an input is refused (a zero X25519 output, an undecodable route, a Content beyond
    /// its bound); [`Error::Unavailable`] without randomness or locked memory. Nothing is sent or persisted.
    pub fn start<E: Entropy>(
        accepted: &InviteeAccepted,
        own_keys: &InitiatorKeys<'_>,
        reply_routes: &[RouteDescriptor],
        profile: &Profile,
        now: u64,
        entropy: &mut E,
    ) -> Result<(HandshakeCells, RatchetState)> {
        let (invitation, link_data) = (accepted.invitation(), accepted.link_data());
        let bundle = &link_data.bundle;
        let agreement = agree(invitation, link_data, own_keys, entropy)?;

        // §7.2 initiator, then §7.3 Encrypt of the Handshake Content (the first message of the ratchet)
        let state = RatchetState::init_initiator_with(
            &agreement.sk,
            &agreement.transcript,
            &bundle.spk_dh,
            &bundle.rpk_kem,
            entropy,
        )?;
        let content = Content {
            seq: 1,
            ts: now,
            body: ContentBody::Handshake(HandshakeBody {
                profile: profile.clone(),
                routes: reply_routes
                    .iter()
                    .map(copy_route)
                    .collect::<Result<Vec<_>>>()?,
            }),
        };
        let sealed = state
            .encrypt_with(&content, entropy)
            .map_err(|refused| refused.error())?;
        // the state is persisted by the caller together with the cells (`HandshakeCells::release`)
        let (state, first_msg) = sealed
            .persist(|_| Ok::<(), Error>(()))
            .map_err(|_: Error| Error::Rejected)?;

        let cells = seal_envelope(
            invitation, link_data, own_keys, &agreement, first_msg, entropy,
        )?;
        Ok((HandshakeCells::new(cells, &state)?, state))
    }
}
