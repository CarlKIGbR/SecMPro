// SPDX-License-Identifier: AGPL-3.0-or-later
//! The key derivation of SecMP-HX (spec §6.4): the transcript, `SK` and `K_id`.
//!
//! Every function here is a direct transcription of the §6.4 formulas; nothing is optional and nothing is
//! derived from anything the spec does not list (CLAUDE.md §5).

use secmp_crypto::{Label, SecretBytes, hkdf, sha256};

use crate::codec::{Encode, Zeroizing};
use crate::error::Result;
use crate::keys::{MlKem768Ek, MlKem1024Ek, X25519Pk};
use crate::sizes::{HASH_LEN, MLKEM1024_CT_LEN};
use crate::wire::Id;
use crate::wire::inv::IksPublic;

/// The thirteen components of the transcript (§6.4), in the order of the formula.
pub struct TranscriptInputs<'a> {
    /// `IKSPublic_R`.
    pub iks_r: &'a IksPublic,
    /// `spk_id`.
    pub spk_id: u32,
    /// `SPK_dh_R`.
    pub spk_dh: &'a X25519Pk,
    /// `SPK_kem_R`.
    pub spk_kem: &'a MlKem1024Ek,
    /// `RPK_kem_R`.
    pub rpk_kem: &'a MlKem768Ek,
    /// `opk_id`.
    pub opk_id: u32,
    /// `OPK_dh_R`.
    pub opk_dh: &'a X25519Pk,
    /// `OPK_kem_R`.
    pub opk_kem: &'a MlKem1024Ek,
    /// `IKSPublic_I`.
    pub iks_i: &'a IksPublic,
    /// `EK_I`.
    pub ek_i: &'a X25519Pk,
    /// `ct_spk`.
    pub ct_spk: &'a [u8; MLKEM1024_CT_LEN],
    /// `ct_opk`.
    pub ct_opk: &'a [u8; MLKEM1024_CT_LEN],
    /// `ld_id`.
    pub ld_id: &'a Id,
}

/// `transcript = SHA-256("SecMP-HX/1 transcript" ‖ encode(IKSPublic_R) ‖ spk_id ‖ SPK_dh_R ‖ SHA-256(SPK_kem_R) ‖
/// SHA-256(RPK_kem_R) ‖ opk_id ‖ OPK_dh_R ‖ SHA-256(OPK_kem_R) ‖ encode(IKSPublic_I) ‖ EK_I ‖ SHA-256(ct_spk) ‖
/// SHA-256(ct_opk) ‖ ld_id)` (spec §6.4); `spk_id` and `opk_id` are u32 big-endian.
///
/// # Errors
/// [`crate::Error::Rejected`] only if an identity has no encoding (never for decoded or generated ones).
pub fn transcript(t: &TranscriptInputs<'_>) -> Result<[u8; HASH_LEN]> {
    let iks_r = t.iks_r.encode()?;
    let iks_i = t.iks_i.encode()?;
    let kem_signed = sha256(&[t.spk_kem.as_bytes()]);
    let kem_ratchet = sha256(&[t.rpk_kem.as_bytes()]);
    let kem_onetime = sha256(&[t.opk_kem.as_bytes()]);
    let ct_signed = sha256(&[t.ct_spk]);
    let ct_onetime = sha256(&[t.ct_opk]);
    Ok(sha256(&[
        Label::HxTranscript.as_bytes(),
        &iks_r,
        &t.spk_id.to_be_bytes(),
        t.spk_dh.as_bytes(),
        &kem_signed,
        &kem_ratchet,
        &t.opk_id.to_be_bytes(),
        t.opk_dh.as_bytes(),
        &kem_onetime,
        &iks_i,
        t.ek_i.as_bytes(),
        &ct_signed,
        &ct_onetime,
        t.ld_id,
    ]))
}

/// The six secrets of the key agreement (§6.4); `DH1`…`DH4` are already checked non-zero by the X25519 operation.
pub struct Shared {
    /// `X25519(IK_dh_I, SPK_dh_R)`.
    pub dh1: SecretBytes<32>,
    /// `X25519(EK_I, IK_dh_R)`.
    pub dh2: SecretBytes<32>,
    /// `X25519(EK_I, SPK_dh_R)`.
    pub dh3: SecretBytes<32>,
    /// `X25519(EK_I, OPK_dh_R)`.
    pub dh4: SecretBytes<32>,
    /// ML-KEM-1024 shared secret of `SPK_kem_R`.
    pub ss_spk: SecretBytes<32>,
    /// ML-KEM-1024 shared secret of `OPK_kem_R`.
    pub ss_opk: SecretBytes<32>,
}

/// `SK = HKDF-SHA-256(salt = 0^32, IKM = 0xFF^32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4 ‖ ss_spk ‖ ss_opk,
/// info = "SecMP-HX/1 sk" ‖ transcript, L = 32)` (spec §6.4).
///
/// # Errors
/// [`crate::Error::Rejected`] only if the KDF refuses its length (never).
pub fn session_key(s: &Shared, transcript: &[u8; HASH_LEN]) -> Result<SecretBytes<32>> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + 6 * 32));
    ikm.extend_from_slice(&[0xff; 32]);
    for part in [&s.dh1, &s.dh2, &s.dh3, &s.dh4, &s.ss_spk, &s.ss_opk] {
        ikm.extend_from_slice(part.expose_secret());
    }
    Ok(hkdf::<32>(&[0; 32], &ikm, Label::HxSk, &[transcript])?)
}

/// `K_id = HKDF-SHA-256(salt = ld_id, IKM = link_key ‖ DH3 ‖ ss_spk ‖ DH4 ‖ ss_opk, info = "SecMP-HX/1 idkey",
/// L = 32)` (spec §6.4). `DH1` and `DH2` are not inputs: the responder computes `K_id` before it knows
/// `IKSPublic_I`.
///
/// # Errors
/// [`crate::Error::Rejected`] only if the KDF refuses its length (never).
pub fn k_id(
    ld_id: &Id,
    link_key: &SecretBytes<32>,
    dh3: &SecretBytes<32>,
    kem_signed: &SecretBytes<32>,
    dh4: &SecretBytes<32>,
    kem_onetime: &SecretBytes<32>,
) -> Result<SecretBytes<32>> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(5 * 32));
    for part in [link_key, dh3, kem_signed, dh4, kem_onetime] {
        ikm.extend_from_slice(part.expose_secret());
    }
    Ok(hkdf::<32>(ld_id, &ikm, Label::HxIdkey, &[])?)
}
