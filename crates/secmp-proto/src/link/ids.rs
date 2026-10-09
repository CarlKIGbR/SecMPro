// SPDX-License-Identifier: AGPL-3.0-or-later
//! Derived identifiers and the access token (spec §5.3, §8.2, §9.1, §9.6; Appendix A labels).
//!
//! - `relay_fp = SHA-256("SecMP-LINK/1 relay-fp" ‖ relay_sig_pk)` (§8.2)
//! - `akc = SHA-256("SecMP-Q/1 akc" ‖ relay_access_key)` (§5.3)
//! - `rid = SHA-256("SecMP-Q/1 rid" ‖ recv_pk)[0..16]`, `sid = SHA-256("SecMP-Q/1 sid" ‖ recv_pk ‖ send_pk)[0..16]`
//!   (§9.1)
//! - `token = HMAC-SHA-256(relay_access_key, "SecMP-Q/1 token" ‖ sess_id ‖ u32be(cmd_seq))` (§9.6)

use secmp_crypto::{Choice, Label, SecretBytes, hmac_sha256, hmac_sha256_verify, sha256};

use crate::error::{Error, Result};
use crate::keys::Ed25519Pk;
use crate::sizes::HASH_LEN;
use crate::wire::Id;

/// The relay access key (spec §9.6): 32 random bytes the operator distributes to its users.
pub type AccessKey = SecretBytes<32>;

/// `relay_fp` of the relay's long-term signing key (spec §8.2).
#[must_use]
pub fn relay_fp(relay_sig_pk: &Ed25519Pk) -> [u8; HASH_LEN] {
    sha256(&[Label::LinkRelayFp.as_bytes(), relay_sig_pk.as_bytes()])
}

/// The access-key commitment `akc` (spec §5.3, §9.6).
#[must_use]
pub fn akc(access_key: &AccessKey) -> [u8; HASH_LEN] {
    sha256(&[Label::QAkc.as_bytes(), access_key.expose_secret()])
}

fn truncated(digest: &[u8; HASH_LEN]) -> Result<Id> {
    digest.first_chunk::<16>().copied().ok_or(Error::Rejected)
}

/// The recipient id of a queue (spec §9.1).
///
/// # Errors
/// None in practice (a SHA-256 digest has 16 leading bytes).
pub fn rid(recv_pk: &Ed25519Pk) -> Result<Id> {
    truncated(&sha256(&[Label::QRid.as_bytes(), recv_pk.as_bytes()]))
}

/// The sender id of a queue (spec §9.1).
///
/// # Errors
/// None in practice.
pub fn sid(recv_pk: &Ed25519Pk, send_pk: &Ed25519Pk) -> Result<Id> {
    truncated(&sha256(&[
        Label::QSid.as_bytes(),
        recv_pk.as_bytes(),
        send_pk.as_bytes(),
    ]))
}

/// The access token of one command (spec §9.6): bound to the link (`sess_id`) and to the command's own `cmd_seq`.
///
/// # Errors
/// None in practice (HMAC accepts every key length).
pub fn token(access_key: &AccessKey, sess_id: &Id, cmd_seq: u32) -> Result<[u8; HASH_LEN]> {
    Ok(hmac_sha256(
        access_key.expose_secret(),
        Label::QToken,
        &[sess_id, &cmd_seq.to_be_bytes()],
    )?)
}

/// Whether `received` is the token of this link and `cmd_seq`, as a [`Choice`] (constant-time comparison; the
/// relay's `ERR_TOKEN` decision, spec §9.6).
///
/// # Errors
/// None in practice.
pub fn token_verify(
    access_key: &AccessKey,
    sess_id: &Id,
    cmd_seq: u32,
    received: &[u8; HASH_LEN],
) -> Result<Choice> {
    Ok(hmac_sha256_verify(
        access_key.expose_secret(),
        Label::QToken,
        &[sess_id, &cmd_seq.to_be_bytes()],
        received,
    )?)
}
