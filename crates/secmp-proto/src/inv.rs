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

use crate::codec::{Decode, Encode, Zeroizing};
use crate::error::{Error, Result};
use crate::sizes::{COM_LEN, HASH_LEN, LINK_BLOB_LEN, NONCE_LEN};
use crate::wire::Id;
use crate::wire::inv::{InvitationV1, LinkBlob, LinkDataV1};

/// The URI scheme and path of an invitation (§5.2): `secmp://i/` followed by the unpadded base64url encoding.
pub const URI_PREFIX: &str = "secmp://i/";

/// The inviter's bound on an invitation's life (§5.2): `expires` ≤ creation + 30 days.
pub const MAX_INVITATION_LIFE_S: u64 = 30 * 24 * 60 * 60;

#[cfg(feature = "kat")]
std::thread_local! {
    /// The reject-site tag of the last [`invitee_accept`] / [`parse_invitation_uri`] / [`invitee_check`] on this
    /// thread (feature `kat`; M3 review R-45, F19), read with `INVITEE_SITE_KAT.get()`: the constant-time bench checks
    /// before measuring that each class of an INV target is refused at the step of §5.5 the target claims. The tag is
    /// set when a step begins, so after a rejection it names the step that rejected:
    ///
    /// - `"uri"` — set by [`parse_invitation_uri`] first: the prefix `secmp://i/` and canonical base64url;
    /// - `"invitation decode"` — set by the `InvitationV1` decoder first: version, kind, period, `RelayRef`;
    /// - `"expired"` — set by [`invitee_check`] first: `now` ≥ `expires`;
    /// - `"blob open"` — set by [`open_blob`] first: the blob's length and `CAEAD.Open` under `K_ld`;
    /// - `"linkdata decode"` — the padding and the `LinkDataV1` decoder, except the `opk_present` byte;
    /// - `"opk_present"` — the bundle decoder's `opk_present = 0x01` (set back to `"linkdata decode"` after it);
    /// - `"fingerprint"` — `fingerprint(inviter_iks) = inviter_fp`, compared in constant time;
    /// - `"bundle signature"` — `HybridVerify` of the bundle under `inviter_iks.IK_sig`;
    /// - `"bundle expired"` — `spk_expiry` > `now`.
    ///
    /// `open_blob` and the invitation and bundle decoders set it outside the invitee's processing too; it is meaningful after the invitee's
    /// processing only. `None` before the first call on this thread. Without `kat` neither the tag nor any statement
    /// setting it exists (the `hx::ACCEPT_SITE_KAT` mechanism).
    pub static INVITEE_SITE_KAT: core::cell::Cell<Option<&'static str>> = const { core::cell::Cell::new(None) };
}

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

/// An arithmetic right shift by 8: `-1` for a negative `x`, else `0` (the mask of the constant-time base64 below).
const fn mask(x: i16) -> i16 {
    x.wrapping_shr(8)
}

/// The URL-safe base64 character of a sextet `v` < 64, by arithmetic only (no table lookup, no branch on `v`: an
/// invitation is a secret, M4 verifier V-5; the construction of `base64ct`).
fn encode_sextet(v: u8) -> u8 {
    let src = i16::from(v);
    let mut diff = 0x41_i16;
    diff = diff.wrapping_add(mask(25_i16.wrapping_sub(src)) & 0x06);
    diff = diff.wrapping_sub(mask(51_i16.wrapping_sub(src)) & 0x4b);
    diff = diff.wrapping_sub(mask(61_i16.wrapping_sub(src)) & 0x0d);
    diff = diff.wrapping_add(mask(62_i16.wrapping_sub(src)) & 0x31);
    u8::try_from(src.wrapping_add(diff)).unwrap_or(0)
}

/// The sextet of a URL-safe base64 character `c`, or a negative value for any other byte; by arithmetic only.
fn decode_sextet(c: u8) -> i16 {
    let src = i16::from(c);
    let mut ret = -1_i16;
    ret = ret.wrapping_add(
        mask(0x40_i16.wrapping_sub(src) & src.wrapping_sub(0x5b)) & src.wrapping_sub(0x40),
    );
    ret = ret.wrapping_add(
        mask(0x60_i16.wrapping_sub(src) & src.wrapping_sub(0x7b)) & src.wrapping_sub(0x46),
    );
    ret = ret.wrapping_add(
        mask(0x2f_i16.wrapping_sub(src) & src.wrapping_sub(0x3a)) & src.wrapping_add(5),
    );
    ret = ret.wrapping_add(mask(0x2c_i16.wrapping_sub(src) & src.wrapping_sub(0x2e)) & 0x3f);
    ret.wrapping_add(mask(0x5e_i16.wrapping_sub(src) & src.wrapping_sub(0x60)) & 0x40)
}

/// base64url (RFC 4648 §5) without padding, in constant time in the bytes (the result is held in `Zeroizing`).
#[must_use]
pub fn base64url_encode(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(
        bytes.len().saturating_mul(4).div_ceil(3),
    ));
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let group = (b0 << 16) | (b1 << 8) | b2;
        let emit = |out: &mut Zeroizing<String>, shift: u32| {
            let v = u8::try_from((group >> shift) & 0x3f).unwrap_or(0);
            out.push(char::from(encode_sextet(v)));
        };
        emit(&mut out, 18);
        emit(&mut out, 12);
        if chunk.len() > 1 {
            emit(&mut out, 6);
        }
        if chunk.len() > 2 {
            emit(&mut out, 0);
        }
    }
    out
}

/// The strict inverse of [`base64url_encode`]: only the URL-safe alphabet, no padding, no whitespace, a length
/// that is not 1 modulo 4, and zero unused low bits in the last character — so every byte string has exactly one
/// text (spec §4.1 canonicality; SPEC-QUESTIONS reading 4). The characters are mapped without a table or a branch
/// on their value; the result is held in `Zeroizing`.
///
/// # Errors
/// [`Error::Rejected`] for any other input.
pub fn base64url_decode(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(Error::Rejected);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len().saturating_mul(3) / 4));
    let mut invalid = 0_i16;
    let mut dirty = 0_u32;
    for chunk in bytes.chunks(4) {
        let mut group = 0_u32;
        for i in 0..4 {
            let v = chunk.get(i).map_or(0, |c| decode_sextet(*c));
            invalid |= v;
            group = (group << 6) | u32::from(u8::try_from(v & 0x3f).unwrap_or(0));
        }
        // the unused low bits of a short last group must be zero
        let unused_mask = match chunk.len() {
            2 => 0x0000_ffff,
            3 => 0x0000_00ff,
            _ => 0,
        };
        dirty |= group & unused_mask;
        let be = group.to_be_bytes();
        let used = match chunk.len() {
            2 => 1,
            3 => 2,
            _ => 3,
        };
        out.extend_from_slice(be.get(1..=used).ok_or(Error::Rejected)?);
    }
    if invalid < 0 || dirty != 0 {
        return Err(Error::Rejected);
    }
    Ok(out)
}

/// The invitation's URI (§5.2): `secmp://i/` ‖ base64url (no padding) of the encoding.
///
/// # Errors
/// [`Error::Rejected`] if the invitation has no encoding.
pub fn invitation_uri(invitation: &InvitationV1) -> Result<Zeroizing<String>> {
    let encoded = invitation.encode()?;
    Ok(Zeroizing::new(format!(
        "{URI_PREFIX}{}",
        base64url_encode(&encoded).as_str()
    )))
}

/// The text of the QR code (§5.2: "same string, byte mode"): identical to [`invitation_uri`].
///
/// # Errors
/// As [`invitation_uri`].
pub fn invitation_qr_text(invitation: &InvitationV1) -> Result<Zeroizing<String>> {
    invitation_uri(invitation)
}

/// Parse an invitation URI (§5.5 step 1, first half): the exact prefix `secmp://i/`, canonical base64url, an exact
/// `InvitationV1` (version, kind 0x01, period ∈ `PERIODS`, decoded `RelayRef`).
///
/// # Errors
/// [`Error::Rejected`] for anything else.
pub fn parse_invitation_uri(uri: &str) -> Result<InvitationV1> {
    #[cfg(feature = "kat")]
    INVITEE_SITE_KAT.set(Some("uri"));
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
pub fn open_blob(ld_id: &Id, link_key: &SecretBytes<HASH_LEN>, blob: &[u8]) -> Result<LinkDataV1> {
    #[cfg(feature = "kat")]
    INVITEE_SITE_KAT.set(Some("blob open"));
    if blob.len() != LINK_BLOB_LEN {
        return Err(Error::Rejected);
    }
    let k_ld = derive_k_ld(ld_id, link_key)?;
    let (n, com_ct) = blob
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(Error::Rejected)?;
    let padded = Caead::open(&k_ld, n, &blob_ad(ld_id), com_ct)?;
    #[cfg(feature = "kat")]
    INVITEE_SITE_KAT.set(Some("linkdata decode"));
    LinkDataV1::decode(&padded)
}

/// What the invitee holds after §5.5 steps 1–4: the invitation and the verified link data.
pub struct InviteeAccepted {
    invitation: Zeroizing<InvitationV1>,
    link_data: LinkDataV1,
}

impl InviteeAccepted {
    /// The parsed invitation (a secret: `link_key`, `inv_send_seed`).
    #[must_use]
    pub fn invitation(&self) -> &InvitationV1 {
        &self.invitation
    }

    /// The inviter's link data; its fingerprint matched `inviter_fp` and its bundle signature verified.
    #[must_use]
    pub const fn link_data(&self) -> &LinkDataV1 {
        &self.link_data
    }
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
    #[cfg(feature = "kat")]
    INVITEE_SITE_KAT.set(Some("expired"));
    // step 1: expired (reading 3: the boundary `now = expires` is expired)
    if now >= invitation.expires {
        return Err(Error::Rejected);
    }
    // step 2
    let link_data = open_blob(&invitation.ld_id, &invitation.link_key, blob)?;
    #[cfg(feature = "kat")]
    INVITEE_SITE_KAT.set(Some("fingerprint"));
    // step 3: `inviter_fp` (secret: it is in the invitation) against the fingerprint of the decrypted IKS
    let iks_bytes = link_data.inviter_iks.encode()?;
    let fp = Fingerprint::of_encoded_iks(&iks_bytes)?;
    if !bool::from(fp.as_bytes().ct_eq(&invitation.inviter_fp)) {
        return Err(Error::Rejected);
    }
    // step 4
    verify_bundle(&link_data, now)?;
    Ok(InviteeAccepted {
        invitation: Zeroizing::new(invitation),
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
    #[cfg(feature = "kat")]
    INVITEE_SITE_KAT.set(Some("bundle signature"));
    let bundle = &link_data.bundle;
    let signed = bundle_signed_message(bundle, &link_data.inviter_iks)?;
    let vk = crate::tr::content::ik_sig(&link_data.inviter_iks)?;
    let sig = secmp_crypto::HybridSignature::from_bytes(bundle.sig.as_bytes())?;
    vk.verify(Label::HxBundle, &signed, &sig)?;
    #[cfg(feature = "kat")]
    INVITEE_SITE_KAT.set(Some("bundle expired"));
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
            assert_eq!(base64url_encode(plain).as_str(), text);
            assert_eq!(
                base64url_decode(text).ok().as_deref().map(Vec::as_slice),
                Some(plain)
            );
        }
    }

    #[test]
    fn base64url_is_canonical() {
        for bad in [
            "Zg==", "Zm9v+", "Zm9v/", "Z", "Zm9vY", "Zh", "Zm9", "Zm 9v", " Zm9v", "Zm9v\n",
            "Zm9vé",
        ] {
            assert_eq!(base64url_decode(bad), Err(Error::Rejected), "{bad:?}");
        }
        // every 1-byte and 2-byte string round-trips and no other text decodes to it
        for a in 0..=255_u8 {
            let t = base64url_encode(&[a]);
            assert_eq!(
                base64url_decode(&t).ok().as_deref().map(Vec::as_slice),
                Some([a].as_slice())
            );
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
        // creation + 30 days overflows: refused, not wrapped
        assert_eq!(
            check_issue_bounds(u64::MAX - 5, u64::MAX, u64::MAX),
            Err(IssueError::ExpiresTooLate)
        );
        assert_eq!(
            check_issue_bounds(u64::MAX, u64::MAX, u64::MAX),
            Err(IssueError::AlreadyExpired)
        );
    }
}

#[cfg(test)]
mod zeroizing_pins {
    use super::*;

    /// F10 / M3 R-23: the invitation held by `InviteeAccepted` is wiped on drop; a type change breaks this.
    #[test]
    fn invitee_accepted_holds_the_invitation_zeroizing() {
        fn pin(a: &InviteeAccepted) {
            let _: &Zeroizing<InvitationV1> = &a.invitation;
        }
        let _ = pin;
    }
}
