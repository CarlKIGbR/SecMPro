// SPDX-License-Identifier: AGPL-3.0-or-later
//! The key schedule of the SecMP-LINK handshake (spec §8.3), shared by the client and the relay. Each function is
//! one line of the spec:
//!
//! ```text
//! h0  = SHA-256("SecMP-LINK/1 h0" ‖ ver ‖ u32be(kid) ‖ relay_fp ‖ e_c ‖ SHA-256(ek_c) ‖ pk_e1 ‖ SHA-256(ct_kem))
//! ck1 = HKDF-Extract(salt = h0, IKM = ss1);   mac1 = HMAC-SHA-256(ck1, "SecMP-LINK/1 hs1")
//! h1  = SHA-256(h0 ‖ mac1 ‖ e_r ‖ SHA-256(ct_c))
//! ck2 = HKDF-Extract(salt = h1, IKM = ck1 ‖ ss2);   mac2 = HMAC-SHA-256(ck2, "SecMP-LINK/1 hs2")
//! (k_c2r ‖ k_r2c ‖ sess_id) = HKDF-Expand(ck2, "SecMP-LINK/1 keys", 80)
//! ```

use secmp_crypto::{Label, SecretBytes, Zeroizing, hkdf_expand, hkdf_extract, hmac_sha256, sha256};

use crate::keys::{MlKem768Ek, X25519Pk};
use crate::link::{Error, Result};
use crate::sizes::{HASH_LEN, MLKEM768_CT_LEN, MLKEM1024_CT_LEN, PROTO_VER};
use crate::wire::Id;

/// The fields of `HS1` that `h0` binds.
pub(crate) struct Hs1Fields<'a> {
    pub kid: u32,
    pub relay_fp: &'a [u8; HASH_LEN],
    pub e_c: &'a X25519Pk,
    pub ek_c: &'a MlKem768Ek,
    pub pk_e1: &'a X25519Pk,
    pub ct_kem: &'a [u8; MLKEM1024_CT_LEN],
}

/// `h0` (spec §8.3).
pub(crate) fn h0(f: &Hs1Fields<'_>) -> [u8; HASH_LEN] {
    sha256(&[
        Label::LinkH0.as_bytes(),
        &[PROTO_VER],
        &f.kid.to_be_bytes(),
        f.relay_fp,
        f.e_c.as_bytes(),
        &sha256(&[f.ek_c.as_bytes()]),
        f.pk_e1.as_bytes(),
        &sha256(&[f.ct_kem]),
    ])
}

/// `(ck1, mac1)` from `h0` and `ss1` (spec §8.3).
pub(crate) fn chain1(
    h0: &[u8; HASH_LEN],
    ss1: &SecretBytes<32>,
) -> Result<(SecretBytes<32>, [u8; HASH_LEN])> {
    let ck1 = hkdf_extract(h0, ss1.expose_secret())?;
    let mac1 = hmac_sha256(ck1.expose_secret(), Label::LinkHs1, &[])?;
    Ok((ck1, mac1))
}

/// `h1` (spec §8.3).
pub(crate) fn h1(
    h0: &[u8; HASH_LEN],
    mac1: &[u8; HASH_LEN],
    e_r: &X25519Pk,
    ct_c: &[u8; MLKEM768_CT_LEN],
) -> [u8; HASH_LEN] {
    sha256(&[h0, mac1, e_r.as_bytes(), &sha256(&[ct_c])])
}

/// `(ck2, mac2)` from `h1`, `ck1` and `ss2` (spec §8.3).
pub(crate) fn chain2(
    h1: &[u8; HASH_LEN],
    ck1: &SecretBytes<32>,
    ss2: &SecretBytes<32>,
) -> Result<(SecretBytes<32>, [u8; HASH_LEN])> {
    // IKM = ck1 ‖ ss2, in a buffer that is wiped on drop
    let mut ikm = Zeroizing::new([0_u8; 64]);
    let (head, tail) = ikm.split_at_mut(32);
    head.copy_from_slice(ck1.expose_secret());
    tail.copy_from_slice(ss2.expose_secret());
    let ck2 = hkdf_extract(h1, ikm.as_slice())?;
    let mac2 = hmac_sha256(ck2.expose_secret(), Label::LinkHs2, &[])?;
    Ok((ck2, mac2))
}

/// The link keys of spec §8.3.
pub(crate) struct LinkKeys {
    pub k_c2r: SecretBytes<32>,
    pub k_r2c: SecretBytes<32>,
    pub sess_id: Id,
}

/// `(k_c2r ‖ k_r2c ‖ sess_id) = HKDF-Expand(PRK = ck2, "SecMP-LINK/1 keys", 80)`, split 32/32/16.
pub(crate) fn link_keys(ck2: &SecretBytes<32>) -> Result<LinkKeys> {
    let okm = hkdf_expand::<80>(ck2.expose_secret(), Label::LinkKeys, &[])?;
    let bytes = okm.expose_secret();
    let (c2r, rest) = bytes.split_first_chunk::<32>().ok_or(Error::Rejected)?;
    let (r2c, sess) = rest.split_first_chunk::<32>().ok_or(Error::Rejected)?;
    let sess_id: Id = sess.try_into().map_err(|_| Error::Rejected)?;
    Ok(LinkKeys {
        k_c2r: SecretBytes::from_slice(c2r)?,
        k_r2c: SecretBytes::from_slice(r2c)?,
        sess_id,
    })
}
