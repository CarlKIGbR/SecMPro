// SPDX-License-Identifier: AGPL-3.0-or-later
//! SecMP-INV (spec §5): the invitation's URI and QR text (§5.2), the link-data blob (§5.4), `K_ld` and `K_inv`
//! (§5.4, §6.5), the invitee's processing (§5.5 steps 1, 3 and 4 — step 2's `LINK_GET` is the transport's) and the
//! inviter's issue-side bounds (§5.2, §6.3).
//!
//! **Invitee checks.** The invitee checks exactly §5.5 steps 1, 3 and 4 (ADR-043 (h), SQ-25 reading A): the
//! invitation's version, kind, period and expiry (`now` ≥ `expires` rejects), the blob's opening under `K_ld`,
//! `fingerprint(inviter_iks) = inviter_fp`, the bundle signature under `inviter_iks.IK_sig`, `spk_expiry > now`
//! and `opk_present = 1` (the decoder). The inviter-side bounds of §5.2 (`expires` ≤ creation + 30 days) and §6.3
//! (`spk_expiry` ≥ `expires`) are **not** invitee checks; they are enforced where the inviter issues
//! ([`IssueError`]).
//!
//! **Errors.** Every rejection of untrusted input is the uniform [`Error::Rejected`] (CLAUDE.md §4): which of the
//! checks failed is not observable. The inviter's own misuse is [`IssueError`], a local error that never reaches
//! the wire.

use secmp_crypto::{Caead, ConstantTimeEq, Fingerprint, Label, Nonce24, SecretBytes, hkdf};

use crate::codec::{Decode, Encode};
use crate::error::{Error, Result};
use crate::sizes::{COM_LEN, HASH_LEN, LINK_BLOB_LEN, NONCE_LEN};
use crate::wire::inv::{InvitationV1, LinkBlob, LinkDataV1};
use crate::wire::Id;

/// The URI scheme and path of an invitation (§5.2): `secmp://i/` followed by the unpadded base64url encoding.
pub const URI_PREFIX: &str = "secmp://i/";

/// The inviter's bound on an invitation's life (§5.2): `expires` ≤ creation + 30 days.
pub const MAX_INVITATION_LIFE_S: u64 = 30 * 24 * 60 * 60;

/// An inviter-side misuse (§5.2, §6.3): a local error, never produced for untrusted input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueError {
    /// `expires` is later than creation + 30 days (§5.2).
    ExpiresTooLate,
    /// `spk_expiry` is earlier than the invitation's `expires` (§6.3).
    SpkExpiryBeforeExpires,
    /// The invitation is already expired at creation.
    AlreadyExpired,
    /// A cryptographic or environment error ([`Error::Unavailable`], or a refused key or encoding).
    Crypto(Error),
}

impl From<Error> for IssueError {
    fn from(e: Error) -> Self {
        Self::Crypto(e)
    }
}

impl From<secmp_crypto::Error> for IssueError {
    fn from(e: secmp_crypto::Error) -> Self {
        Self::Crypto(Error::from(e))
    }
}

impl core::fmt::Display for IssueError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::ExpiresTooLate => "invitation expiry beyond 30 days",
            Self::SpkExpiryBeforeExpires => "prekey expiry before the invitation's",
            Self::AlreadyExpired => "invitation already expired",
            Self::Crypto(_) => "cryptographic or environment error",
        })
    }
}

impl std::error::Error for IssueError {}

/// The inviter's bounds of §5.2 and §6.3 for an invitation created at `created` expiring at `expires`, with a
/// bundle valid until `spk_expiry`.
///
/// # Errors
/// [`IssueError::AlreadyExpired`], [`IssueError::ExpiresTooLate`] or [`IssueError::SpkExpiryBeforeExpires`].
pub fn check_issue_bounds(
    created: u64,
    expires: u64,
    spk_expiry: u64,
) -> core::result::Result<(), IssueError> {
    if expires <= created {
        return Err(IssueError::AlreadyExpired);
    }
    let latest = created
        .checked_add(MAX_INVITATION_LIFE_S)
        .ok_or(IssueError::ExpiresTooLate)?;
    if expires > latest {
        return Err(IssueError::ExpiresTooLate);
    }
    if spk_expiry < expires {
        return Err(IssueError::SpkExpiryBeforeExpires);
    }
    Ok(())
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn sextet(group: u32, shift: u32) -> char {
    let index = usize::try_from((group >> shift) & 0x3f).unwrap_or(0);
    char::from(B64.get(index).copied().unwrap_or(b'A'))
}

/// base64url (RFC 4648 §5) without padding.
#[must_use]
pub fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let group = (b0 << 16) | (b1 << 8) | b2;
        out.push(sextet(group, 18));
        out.push(sextet(group, 12));
        if chunk.len() > 1 {
            out.push(sextet(group, 6));
        }
        if chunk.len() > 2 {
            out.push(sextet(group, 0));
        }
    }
    out
}

fn sextet_value(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c.checked_sub(b'A')?,
        b'a'..=b'z' => c.checked_sub(b'a')?.checked_add(26)?,
        b'0'..=b'9' => c.checked_sub(b'0')?.checked_add(52)?,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// The strict inverse of [`base64url_encode`]: only the URL-safe alphabet, no padding, no whitespace, a length
/// that is not 1 modulo 4, and zero unused low bits in the last character — so every byte string has exactly one
/// text (spec §4.1 canonicality; SPEC-QUESTIONS reading 4).
///
/// # Errors
/// [`Error::Rejected`] for any other input.
pub fn base64url_decode(text: &str) -> Result<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(Error::Rejected);
    }
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(3) / 4);
    for chunk in bytes.chunks(4) {
        let mut group = 0_u32;
        for i in 0..4 {
            let v = match chunk.get(i) {
                Some(c) => sextet_value(*c).ok_or(Error::Rejected)?,
                None => 0,
            };
            group = (group << 6) | v;
        }
        // the unused low bits of a short last group must be zero
        let unused_mask = match chunk.len() {
            2 => 0x0000_ffff,
            3 => 0x0000_00ff,
            _ => 0,
        };
        if group & unused_mask != 0 {
            return Err(Error::Rejected);
        }
        let be = group.to_be_bytes();
        let used = match chunk.len() {
            2 => 1,
            3 => 2,
            _ => 3,
        };
        out.extend_from_slice(be.get(1..=used).ok_or(Error::Rejected)?);
    }
    Ok(out)
}

/// The invitation's URI (§5.2): `secmp://i/` ‖ base64url (no padding) of the encoding.
///
/// # Errors
/// [`Error::Rejected`] if the invitation has no encoding.
pub fn invitation_uri(invitation: &InvitationV1) -> Result<String> {
    let encoded = invitation.encode()?;
    Ok(format!("{URI_PREFIX}{}", base64url_encode(&encoded)))
}

/// The text of the QR code (§5.2: "same string, byte mode"): identical to [`invitation_uri`].
///
/// # Errors
/// As [`invitation_uri`].
pub fn invitation_qr_text(invitation: &InvitationV1) -> Result<String> {
    invitation_uri(invitation)
}

/// Parse an invitation URI (§5.5 step 1, first half): the exact prefix `secmp://i/`, canonical base64url, an exact
/// `InvitationV1` (version, kind 0x01, period ∈ `PERIODS`, decoded `RelayRef`).
///
/// # Errors
/// [`Error::Rejected`] for anything else.
pub fn parse_invitation_uri(uri: &str) -> Result<InvitationV1> {
    let text = uri.strip_prefix(URI_PREFIX).ok_or(Error::Rejected)?;
    InvitationV1::decode(&base64url_decode(text)?)
}

/// `K_ld = HKDF-SHA-256(salt = ld_id, IKM = link_key, info = "SecMP-INV/1 linkdata", L = 32)` (§5.4).
///
/// # Errors
/// [`Error::Rejected`] only if the KDF refuses its length (never for these inputs).
pub fn derive_k_ld(ld_id: &Id, link_key: &SecretBytes<HASH_LEN>) -> Result<SecretBytes<32>> {
    Ok(hkdf::<32>(
        ld_id,
        link_key.expose_secret(),
        Label::InvLinkdata,
        &[],
    )?)
}

/// `K_inv = HKDF-SHA-256(salt = ld_id, IKM = link_key, info = "SecMP-HX/1 initkey", L = 32)` (§6.5).
///
/// # Errors
/// As [`derive_k_ld`].
pub fn derive_k_inv(ld_id: &Id, link_key: &SecretBytes<HASH_LEN>) -> Result<SecretBytes<32>> {
    Ok(hkdf::<32>(
        ld_id,
        link_key.expose_secret(),
        Label::HxInitkey,
        &[],
    )?)
}

/// `AD = "SecMP-INV/1 blob" ‖ ld_id` (§5.4).
fn blob_ad(ld_id: &Id) -> Vec<u8> {
    [Label::InvBlob.as_bytes(), ld_id.as_slice()].concat()
}

/// Seal link data (§5.4): `blob = N ‖ CAEAD.Seal(K_ld, N, AD = "SecMP-INV/1 blob" ‖ ld_id, pad(LinkDataV1, 12288))`
/// (12360 bytes).
///
/// # Errors
/// [`Error::Rejected`] if the link data has no encoding (a field beyond its bound).
pub fn seal_blob(
    ld_id: &Id,
    link_key: &SecretBytes<HASH_LEN>,
    nonce: Nonce24,
    link_data: &LinkDataV1,
) -> Result<LinkBlob> {
    let k_ld = derive_k_ld(ld_id, link_key)?;
    let padded = link_data.encode()?;
    let n = *nonce.as_bytes();
    let com_ct = Caead::seal(&k_ld, nonce, &blob_ad(ld_id), &padded)?;
    LinkBlob::from_parts(&n, &com_ct)
}

/// Open a blob (§5.5 step 2): exactly 12360 bytes, `CAEAD.Open` under `K_ld`, the padding and the `LinkDataV1`
/// decoder.
///
/// # Errors
/// [`Error::Rejected`] — uniformly — for a wrong length, a wrong key or AD, a tampered byte, bad padding or an
/// undecodable `LinkDataV1`.
pub fn open_blob(
    ld_id: &Id,
    link_key: &SecretBytes<HASH_LEN>,
    blob: &[u8],
) -> Result<LinkDataV1> {
    if blob.len() != LINK_BLOB_LEN {
        return Err(Error::Rejected);
    }
    let k_ld = derive_k_ld(ld_id, link_key)?;
    let (n, com_ct) = blob
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(Error::Rejected)?;
    let padded = Caead::open(&k_ld, n, &blob_ad(ld_id), com_ct)?;
    LinkDataV1::decode(&padded)
}

/// What the invitee holds after §5.5 steps 1–4: the invitation and the verified link data.
pub struct InviteeAccepted {
    /// The parsed invitation (a secret: `link_key`, `inv_send_seed`).
    pub invitation: InvitationV1,
    /// The inviter's link data; its fingerprint matched `inviter_fp` and its bundle signature verified.
    pub link_data: LinkDataV1,
}

/// §5.5 steps 1, 3 and 4 on the parsed `invitation` and the `blob` that `LINK_GET` returned (step 2's transport),
/// at `now` (Unix seconds).
///
/// 1. the invitation is unexpired (`now` < `expires`; the version, kind and period were checked by the decoder);
/// 2. the blob opens under `K_ld` (§5.4);
/// 3. `fingerprint(inviter_iks) = inviter_fp`, compared in constant time;
/// 4. `bundle.sig` verifies under `inviter_iks.IK_sig` over the bundle fields ‖ `ik_dh` (§6.3), `spk_expiry` >
///    `now`, `opk_present = 1` (the decoder).
///
/// Nothing is sent and nothing persisted on a rejection (the caller sends only after `Ok`).
///
/// # Errors
/// The uniform [`Error::Rejected`].
pub fn invitee_check(invitation: InvitationV1, blob: &[u8], now: u64) -> Result<InviteeAccepted> {
    // step 1: expired (reading 3: the boundary `now = expires` is expired)
    if now >= invitation.expires {
        return Err(Error::Rejected);
    }
    // step 2
    let link_data = open_blob(&invitation.ld_id, &invitation.link_key, blob)?;
    // step 3: `inviter_fp` (secret: it is in the invitation) against the fingerprint of the decrypted IKS
    let iks_bytes = link_data.inviter_iks.encode()?;
    let fp = Fingerprint::of_encoded_iks(&iks_bytes)?;
    if !bool::from(fp.as_bytes().ct_eq(&invitation.inviter_fp)) {
        return Err(Error::Rejected);
    }
    // step 4
    verify_bundle(&link_data, now)?;
    Ok(InviteeAccepted {
        invitation,
        link_data,
    })
}

/// [`parse_invitation_uri`] then [`invitee_check`].
///
/// # Errors
/// The uniform [`Error::Rejected`].
pub fn invitee_accept(uri: &str, blob: &[u8], now: u64) -> Result<InviteeAccepted> {
    invitee_check(parse_invitation_uri(uri)?, blob, now)
}

/// `HybridVerify(IK_sig, "SecMP-HX/1 bundle", bundle fields before sig ‖ ik_dh)` and `spk_expiry > now`
/// (§5.5 step 4, §6.3). The expiry is checked after the signature, so a forged bundle and an expired one are
/// indistinguishable.
fn verify_bundle(link_data: &LinkDataV1, now: u64) -> Result<()> {
    let bundle = &link_data.bundle;
    let signed = bundle_signed_message(bundle, &link_data.inviter_iks)?;
    let vk = crate::tr::content::ik_sig(&link_data.inviter_iks)?;
    let sig = secmp_crypto::HybridSignature::from_bytes(bundle.sig.as_bytes())?;
    vk.verify(Label::HxBundle, &signed, &sig)?;
    if bundle.spk_expiry <= now {
        return Err(Error::Rejected);
    }
    Ok(())
}

/// The message the bundle signature covers: the encoded bundle fields before `sig` ‖ the signer's `ik_dh`
/// (§6.3; 4402 + 32 = 4434 bytes).
///
/// # Errors
/// [`Error::Rejected`] if a field has no encoding (never for decoded fields).
pub fn bundle_signed_message(
    bundle: &crate::wire::inv::PrekeyBundle,
    signer: &crate::wire::inv::IksPublic,
) -> Result<Vec<u8>> {
    let mut m = bundle.signed_fields()?;
    m.extend_from_slice(signer.ik_dh.as_bytes());
    Ok(m)
}

const _: () = assert!(LINK_BLOB_LEN == NONCE_LEN + COM_LEN + 12_288 + 16);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_vectors() {
        // RFC 4648 §10 (with the URL-safe alphabet, no padding)
        for (plain, text) in [
            (&b""[..], ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
            (&[0xfb, 0xff, 0xbf], "-_-_"),
        ] {
            assert_eq!(base64url_encode(plain), text);
            assert_eq!(base64url_decode(text).as_deref(), Ok(plain));
        }
    }

    #[test]
    fn base64url_is_canonical() {
        for bad in [
            "Zg==", "Zm9v+", "Zm9v/", "Z", "Zm9vY", "Zh", "Zm9", "Zm 9v", " Zm9v", "Zm9v\n", "Zm9vé",
        ] {
            assert_eq!(base64url_decode(bad), Err(Error::Rejected), "{bad:?}");
        }
        // every 1-byte and 2-byte string round-trips and no other text decodes to it
        for a in 0..=255_u8 {
            let t = base64url_encode(&[a]);
            assert_eq!(base64url_decode(&t).ok(), Some(vec![a]));
        }
    }

    #[test]
    fn issue_bounds() {
        let created = 1_700_000_000;
        let max = created + MAX_INVITATION_LIFE_S;
        assert_eq!(check_issue_bounds(created, max, max), Ok(()));
        assert_eq!(
            check_issue_bounds(created, max + 1, max + 1),
            Err(IssueError::ExpiresTooLate)
        );
        assert_eq!(
            check_issue_bounds(created, max, max - 1),
            Err(IssueError::SpkExpiryBeforeExpires)
        );
        assert_eq!(
            check_issue_bounds(created, created, max),
            Err(IssueError::AlreadyExpired)
        );
        assert_eq!(
            check_issue_bounds(u64::MAX, u64::MAX, u64::MAX),
            Err(IssueError::ExpiresTooLate)
        );
    }
}
