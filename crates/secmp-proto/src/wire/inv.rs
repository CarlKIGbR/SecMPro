// SPDX-License-Identifier: AGPL-3.0-or-later
//! D.3 — invitation, relay reference, link data (spec §5.2–5.4, §6.2–6.3; rev 2.3):
//!
//! - `RelayRef.onion` is a v3 onion address `PUBKEY[32] ‖ CHECKSUM[2] ‖ VERSION[1]` with VERSION 0x03 and
//!   `CHECKSUM = SHA3-256(".onion checksum" ‖ PUBKEY ‖ VERSION)[0..2]` (spec §5.3, Tor rend-spec-v3 §6); PUBKEY is
//!   not otherwise checked.
//! - `RelayRef.direct`: `host` 1..=253 bytes, each in 0x21..=0x7E, `port` ≠ 0 (D.3, rev 2.3).
//! - `InvitationV1.kind` is 0x01 (one-time); 0x02 (multi-use) is reserved and rejects like every other value.
//! - `Profile.name` is strict UTF-8 of at most 64 bytes; `PrekeyBundle.opk_present` must be 0x01 (spec §6.3).
//! - `LinkDataV1` is padded to 12288 bytes; `LinkBlob` is opaque (length only).

use core::num::NonZeroU16;

use secmp_crypto::{SecretBytes, Zeroize};

use crate::codec::{
    Decode, Encode, Reader, Writer, Zeroizing, boxed, decode_padded, encode_padded,
};
use crate::error::{Error, Result};
use crate::keys::{Ed25519Pk, HybridSig, MlKem768Ek, MlKem1024Ek, X25519Pk};
use crate::sizes::{
    AEAD_TAG_LEN, COM_LEN, HASH_LEN, HOST_MAX, LINK_BLOB_CT_LEN, LINKDATA_PADDED_LEN,
    MLDSA65_PK_LEN, NAME_MAX, NONCE_LEN, ONION_LEN,
};
use crate::wire::{Id, Period, read_ver, write_ver};

/// The Tor onion-address checksum prefix (rend-spec-v3 §6; cited by spec §5.3 — Tor's constant, not a SecMP label).
const ONION_CHECKSUM_PREFIX: &[u8] = b".onion checksum";
/// The v3 onion-address version byte.
const ONION_VERSION: u8 = 0x03;

/// A v3 onion service identity (the decoded 56-character address, spec §5.3).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Onion([u8; ONION_LEN]);

impl Onion {
    /// The address with these 35 bytes.
    ///
    /// # Errors
    /// [`Error::Rejected`] unless 35 bytes with VERSION 0x03 and a valid CHECKSUM.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let onion: [u8; ONION_LEN] = bytes.try_into().map_err(|_| Error::Rejected)?;
        let (pubkey, rest) = onion.split_at_checked(32).ok_or(Error::Rejected)?;
        let (checksum, version) = rest.split_at_checked(2).ok_or(Error::Rejected)?;
        if version != [ONION_VERSION] {
            return Err(Error::Rejected);
        }
        let expected = secmp_crypto::sha3_256(&[ONION_CHECKSUM_PREFIX, pubkey, version]);
        if expected.get(..2) != Some(checksum) {
            return Err(Error::Rejected);
        }
        Ok(Self(onion))
    }

    /// The address of the v3 onion service with this Ed25519 public key.
    #[must_use]
    pub fn from_pubkey(pubkey: &[u8; 32]) -> Self {
        let checksum = secmp_crypto::sha3_256(&[ONION_CHECKSUM_PREFIX, pubkey, &[ONION_VERSION]]);
        let mut onion = [0_u8; ONION_LEN];
        for (o, b) in onion
            .iter_mut()
            .zip(pubkey.iter().chain(checksum.iter().take(2)))
        {
            *o = *b;
        }
        if let Some(v) = onion.last_mut() {
            *v = ONION_VERSION;
        }
        Self(onion)
    }

    /// The 35 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ONION_LEN] {
        &self.0
    }
}

/// `RelayRef.direct.host`: 1..=253 bytes, each in 0x21..=0x7E (a DNS name or an IP literal; rev 2.3).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Host(crate::codec::Zeroizing<Vec<u8>>);

impl Host {
    /// The host with these bytes.
    ///
    /// # Errors
    /// [`Error::Rejected`] unless 1..=253 printable, non-space ASCII bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if (1..=HOST_MAX).contains(&bytes.len()) && bytes.iter().all(|b| (0x21..=0x7e).contains(b))
        {
            Ok(Self(crate::codec::Zeroizing::new(bytes.to_vec())))
        } else {
            Err(Error::Rejected)
        }
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Zeroize for Host {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// `RelayRef.direct = host_len u16 ‖ host ‖ port u16 ‖ spki_sha256[32]` (direct TLS mode, spec §8.1).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct Direct {
    /// Host name or IP literal.
    pub host: Host,
    /// TCP port, never 0.
    pub port: NonZeroU16,
    /// Pinned SHA-256 of the relay's TLS SPKI.
    pub spki_sha256: [u8; HASH_LEN],
}

/// `RelayRef = ver ‖ relay_fp[32] ‖ onion[35] ‖ akc[32] ‖ direct_present u8 ‖ [direct]` (spec §5.3).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct RelayRef {
    /// `SHA-256("SecMP-LINK/1 relay-fp" ‖ relay_sig_pk)`.
    pub relay_fp: [u8; HASH_LEN],
    /// The relay's onion service (required).
    pub onion: Onion,
    /// Access-key commitment.
    pub akc: [u8; HASH_LEN],
    /// Direct TLS endpoint, if offered.
    pub direct: Option<Direct>,
}

impl Zeroize for RelayRef {
    fn zeroize(&mut self) {
        self.relay_fp.zeroize();
        self.onion.0.zeroize();
        self.akc.zeroize();
        if let Some(d) = &mut self.direct {
            d.host.zeroize();
            d.spki_sha256.zeroize();
        }
    }
}

/// A decoded or rejected `RelayRef` is wiped when it goes out of scope (M4 review R-61).
impl Drop for RelayRef {
    fn drop(&mut self) {
        self.zeroize();
        #[cfg(test)]
        crate::wire::wipe_log::note("RelayRef");
    }
}

/// `SecretBytes` has no in-place wipe: a zero value replaces the seed, and the old allocation is wiped by its own
/// `Drop`. (`from_slice` fails only on a wrong length, which `HASH_LEN` is not.)
pub(crate) fn wipe_seed(seed: &mut SecretBytes<HASH_LEN>) {
    if let Ok(zero) = SecretBytes::from_slice(&[0; HASH_LEN]) {
        *seed = zero;
    }
}

impl Encode for RelayRef {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        write_ver(w);
        w.bytes(&self.relay_fp);
        w.bytes(self.onion.as_bytes());
        w.bytes(&self.akc);
        w.flag(self.direct.is_some());
        if let Some(d) = &self.direct {
            w.prefixed_u16(d.host.as_bytes())?;
            w.u16(d.port.get());
            w.bytes(&d.spki_sha256);
        }
        Ok(())
    }
}

impl Decode for RelayRef {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        read_ver(r)?;
        let relay_fp = r.array()?;
        let onion = Onion::from_bytes(r.take(ONION_LEN)?)?;
        let akc = r.array()?;
        let direct = if r.flag()? {
            Some(Direct {
                host: Host::from_bytes(r.prefixed_u16()?)?,
                port: NonZeroU16::new(r.u16()?).ok_or(Error::Rejected)?,
                spki_sha256: r.array()?,
            })
        } else {
            None
        };
        Ok(Self {
            relay_fp,
            onion,
            akc,
            direct,
        })
    }
}

/// `InvitationV1.kind` of a one-time invitation (the only kind in v1).
const INVITATION_ONE_TIME: u8 = 0x01;

/// `InvitationV1 = ver ‖ kind u8 (0x01) ‖ RelayRef ‖ ld_id[16] ‖ link_key[32] ‖ inviter_fp[32] ‖ inv_sid[16] ‖
/// inv_send_seed[32] ‖ inv_period_s u16 ‖ expires u64` (spec §5.2). An invitation is a secret: `link_key` and
/// `inv_send_seed` are held as `SecretBytes`.
pub struct InvitationV1 {
    /// The inviter's relay.
    pub relay: RelayRef,
    /// Link-data id.
    pub ld_id: Id,
    /// Link-data key (never sent to the relay).
    pub link_key: SecretBytes<HASH_LEN>,
    /// Fingerprint of the inviter's IKS.
    pub inviter_fp: [u8; HASH_LEN],
    /// Sender id of the invitation queue.
    pub inv_sid: Id,
    /// Ed25519 seed of the invitation queue's sender key.
    pub inv_send_seed: SecretBytes<HASH_LEN>,
    /// The invitation queue's period.
    pub inv_period_s: Period,
    /// Unix seconds.
    pub expires: u64,
}

/// Wiped explicitly, by `Zeroizing<InvitationV1>` (held so by [`crate::inv::InviteeAccepted`]) and, since R-61, by its
/// own `Drop` (so a rejected invitation is wiped too): the relay reference, the ids and both seeds.
impl Zeroize for InvitationV1 {
    fn zeroize(&mut self) {
        self.relay.zeroize();
        self.ld_id.zeroize();
        wipe_seed(&mut self.link_key);
        self.inviter_fp.zeroize();
        self.inv_sid.zeroize();
        wipe_seed(&mut self.inv_send_seed);
        self.expires = 0;
    }
}

impl Drop for InvitationV1 {
    fn drop(&mut self) {
        self.zeroize();
        #[cfg(test)]
        crate::wire::wipe_log::note("InvitationV1");
    }
}

impl Encode for InvitationV1 {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        write_ver(w);
        w.u8(INVITATION_ONE_TIME);
        self.relay.encode_to(w)?;
        w.bytes(&self.ld_id);
        w.bytes(self.link_key.expose_secret());
        w.bytes(&self.inviter_fp);
        w.bytes(&self.inv_sid);
        w.bytes(self.inv_send_seed.expose_secret());
        self.inv_period_s.encode_to(w)?;
        w.u64(self.expires);
        Ok(())
    }
}

impl Decode for InvitationV1 {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        // feature `kat`: the invitee's reject-site tag (`inv::INVITEE_SITE_KAT`)
        #[cfg(feature = "kat")]
        crate::inv::INVITEE_SITE_KAT.set(Some("invitation decode"));
        read_ver(r)?;
        // one-time only; 0x02 (multi-use) is reserved and v1 clients MUST reject it (spec §5.2)
        r.expect(INVITATION_ONE_TIME)?;
        Ok(Self {
            relay: RelayRef::decode_from(r)?,
            ld_id: r.array()?,
            link_key: SecretBytes::from_slice(r.take(HASH_LEN)?)?,
            inviter_fp: r.array()?,
            inv_sid: r.array()?,
            inv_send_seed: SecretBytes::from_slice(r.take(HASH_LEN)?)?,
            inv_period_s: Period::decode_from(r)?,
            expires: r.u64()?,
        })
    }
}

/// `Profile = name_len u8 ‖ name (UTF-8, ≤ 64) ‖ avatar_present u8 ‖ [avatar_sha256[32]]` (D.3).
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Profile {
    /// Held wiped-on-drop: it comes out of a decrypted Handshake (M3 review F10). Not a secret in the comparison
    /// sense (display name), so `PartialEq` below compares the strings.
    name: Zeroizing<String>,
    /// SHA-256 of the avatar, if any.
    pub avatar_sha256: Option<[u8; HASH_LEN]>,
}

impl Profile {
    /// A profile; `name` is at most 64 bytes (possibly empty).
    ///
    /// # Errors
    /// [`Error::Rejected`] if `name` is longer than 64 bytes.
    pub fn new(name: &str, avatar_sha256: Option<[u8; HASH_LEN]>) -> Result<Self> {
        if name.len() > NAME_MAX {
            return Err(Error::Rejected);
        }
        Ok(Self {
            name: Zeroizing::new(name.to_owned()),
            avatar_sha256,
        })
    }

    /// The display name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

// display data; variable-time comparison is acceptable (reviewer 2026-10-01)
impl PartialEq for Profile {
    fn eq(&self, other: &Self) -> bool {
        *self.name == *other.name && self.avatar_sha256 == other.avatar_sha256
    }
}

impl Eq for Profile {}

impl Encode for Profile {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        if self.name.len() > NAME_MAX {
            return Err(Error::Rejected);
        }
        w.prefixed_u8(self.name.as_bytes())?;
        w.flag(self.avatar_sha256.is_some());
        if let Some(a) = &self.avatar_sha256 {
            w.bytes(a);
        }
        Ok(())
    }
}

impl Decode for Profile {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        let name = r.prefixed_u8()?;
        if name.len() > NAME_MAX {
            return Err(Error::Rejected);
        }
        // strict UTF-8 (RFC 3629: no overlong forms, no surrogates, nothing above U+10FFFF)
        let name = core::str::from_utf8(name).map_err(|_| Error::Rejected)?;
        let avatar_sha256 = if r.flag()? { Some(r.array()?) } else { None };
        Ok(Self {
            name: Zeroizing::new(name.to_owned()),
            avatar_sha256,
        })
    }
}

/// `IKSPublic = ver ‖ ik_ed25519[32] ‖ ik_mldsa65[1952] ‖ ik_dh[32]` (2017 B, spec §6.2).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct IksPublic {
    /// Ed25519 half of `IK_sig`.
    pub ik_ed25519: Ed25519Pk,
    /// ML-DSA-65 half of `IK_sig` (opaque at decode: `pkDecode` cannot fail for this length).
    pub ik_mldsa65: Box<[u8; MLDSA65_PK_LEN]>,
    /// `IK_dh`.
    pub ik_dh: X25519Pk,
}

impl Encode for IksPublic {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        write_ver(w);
        self.ik_ed25519.encode_to(w)?;
        w.bytes(self.ik_mldsa65.as_slice());
        self.ik_dh.encode_to(w)
    }
}

impl Decode for IksPublic {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        read_ver(r)?;
        Ok(Self {
            ik_ed25519: Ed25519Pk::decode_from(r)?,
            ik_mldsa65: r.boxed()?,
            ik_dh: X25519Pk::decode_from(r)?,
        })
    }
}

/// `PrekeyBundle = ver ‖ spk_id u32 ‖ spk_dh[32] ‖ spk_kem[1568] ‖ rpk_kem[1184] ‖ spk_expiry u64 ‖ opk_present u8
/// (0x01) ‖ opk_id u32 ‖ opk_dh[32] ‖ opk_kem[1568] ‖ sig[3373]` (7775 B, spec §6.3). v1 requires the OPK, so
/// `opk_present` is not a field: it is written as 0x01 and anything else rejects.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct PrekeyBundle {
    /// Signed-prekey id.
    pub spk_id: u32,
    /// Signed prekey, X25519.
    pub spk_dh: X25519Pk,
    /// Signed prekey, ML-KEM-1024.
    pub spk_kem: MlKem1024Ek,
    /// Ratchet prekey, ML-KEM-768.
    pub rpk_kem: MlKem768Ek,
    /// Unix seconds.
    pub spk_expiry: u64,
    /// One-time prekey id.
    pub opk_id: u32,
    /// One-time prekey, X25519.
    pub opk_dh: X25519Pk,
    /// One-time prekey, ML-KEM-1024.
    pub opk_kem: MlKem1024Ek,
    /// `HybridSign(IK_sig, "SecMP-HX/1 bundle", all preceding fields ‖ ik_dh)` — verified at use.
    pub sig: HybridSig,
}

impl Encode for PrekeyBundle {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        write_ver(w);
        w.u32(self.spk_id);
        self.spk_dh.encode_to(w)?;
        self.spk_kem.encode_to(w)?;
        self.rpk_kem.encode_to(w)?;
        w.u64(self.spk_expiry);
        w.u8(1);
        w.u32(self.opk_id);
        self.opk_dh.encode_to(w)?;
        self.opk_kem.encode_to(w)?;
        self.sig.encode_to(w)
    }
}

impl Decode for PrekeyBundle {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        read_ver(r)?;
        let spk_id = r.u32()?;
        let spk_dh = X25519Pk::decode_from(r)?;
        let spk_kem = MlKem1024Ek::decode_from(r)?;
        let rpk_kem = MlKem768Ek::decode_from(r)?;
        let spk_expiry = r.u64()?;
        // `opk_present` MUST be 0x01 in v1 (spec §6.3)
        #[cfg(feature = "kat")]
        crate::inv::INVITEE_SITE_KAT.set(Some("opk_present"));
        r.expect(1)?;
        #[cfg(feature = "kat")]
        crate::inv::INVITEE_SITE_KAT.set(Some("linkdata decode"));
        Ok(Self {
            spk_id,
            spk_dh,
            spk_kem,
            rpk_kem,
            spk_expiry,
            opk_id: r.u32()?,
            opk_dh: X25519Pk::decode_from(r)?,
            opk_kem: MlKem1024Ek::decode_from(r)?,
            sig: HybridSig::decode_from(r)?,
        })
    }
}

impl PrekeyBundle {
    /// The encoded fields before `sig` (the bundle signature covers them followed by `ik_dh`, spec §6.3).
    ///
    /// # Errors
    /// None in practice (every field has a fixed width).
    pub fn signed_fields(&self) -> Result<Vec<u8>> {
        let all = self.encode()?;
        let n = crate::sizes::PREKEY_BUNDLE_LEN
            .checked_sub(crate::sizes::HYBRID_SIG_LEN)
            .ok_or(Error::Rejected)?;
        Ok(all.get(..n).ok_or(Error::Rejected)?.to_vec())
    }
}

/// `LinkDataV1 = ver ‖ IKSPublic ‖ PrekeyBundle ‖ Profile ‖ created u64 → pad to 12288` (spec §5.4).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub struct LinkDataV1 {
    /// The inviter's identity.
    pub inviter_iks: IksPublic,
    /// The inviter's prekeys.
    pub bundle: PrekeyBundle,
    /// The inviter's profile.
    pub profile: Profile,
    /// Unix seconds.
    pub created: u64,
}

/// `LinkDataV1` without its padding.
struct LinkDataFields<'a>(&'a LinkDataV1);

impl Encode for LinkDataFields<'_> {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        let l = self.0;
        write_ver(w);
        l.inviter_iks.encode_to(w)?;
        l.bundle.encode_to(w)?;
        l.profile.encode_to(w)?;
        w.u64(l.created);
        Ok(())
    }
}

struct LinkDataDecoded(LinkDataV1);

impl Decode for LinkDataDecoded {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        read_ver(r)?;
        Ok(Self(LinkDataV1 {
            inviter_iks: IksPublic::decode_from(r)?,
            bundle: PrekeyBundle::decode_from(r)?,
            profile: Profile::decode_from(r)?,
            created: r.u64()?,
        }))
    }
}

impl Encode for LinkDataV1 {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        w.bytes(&encode_padded(&LinkDataFields(self), LINKDATA_PADDED_LEN)?);
        Ok(())
    }
}

impl Decode for LinkDataV1 {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(decode_padded::<LinkDataDecoded>(r.take(LINKDATA_PADDED_LEN)?, LINKDATA_PADDED_LEN)?.0)
    }
}

/// `LinkBlob = N[24] ‖ COM[32] ‖ ct[12288 + 16]` (12360 B, opaque: length only).
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct LinkBlob {
    /// CAEAD nonce.
    pub n: [u8; NONCE_LEN],
    /// CAEAD commitment.
    pub com: [u8; COM_LEN],
    /// XChaCha20-Poly1305 ciphertext of the padded `LinkDataV1` with its tag.
    pub ct: Box<[u8; LINK_BLOB_CT_LEN]>,
}

impl Encode for LinkBlob {
    fn encode_to(&self, w: &mut Writer) -> Result<()> {
        w.bytes(&self.n);
        w.bytes(&self.com);
        w.bytes(self.ct.as_slice());
        Ok(())
    }
}

impl Decode for LinkBlob {
    fn decode_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            n: r.array()?,
            com: r.array()?,
            ct: r.boxed()?,
        })
    }
}

impl LinkBlob {
    /// A blob from its three parts (`COM ‖ ct` as `CAEAD.Seal` returns it follows `N`).
    ///
    /// # Errors
    /// [`Error::Rejected`] on wrong lengths.
    pub fn from_parts(n: &[u8], com_ct: &[u8]) -> Result<Self> {
        let (com, ct) = com_ct.split_at_checked(COM_LEN).ok_or(Error::Rejected)?;
        Ok(Self {
            n: n.try_into().map_err(|_| Error::Rejected)?,
            com: com.try_into().map_err(|_| Error::Rejected)?,
            ct: boxed(ct)?,
        })
    }
}

const _: () = assert!(LINK_BLOB_CT_LEN == LINKDATA_PADDED_LEN + AEAD_TAG_LEN);

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::wire::testutil::{
        ed25519, ek768, ek1024, exact_fit, hybrid_sig, round_trip, round_trip_bytes, x25519,
    };

    pub(crate) fn iks(seed: u8) -> Result<IksPublic> {
        Ok(IksPublic {
            ik_ed25519: ed25519(seed)?,
            ik_mldsa65: Box::new([seed; MLDSA65_PK_LEN]),
            ik_dh: x25519(seed)?,
        })
    }

    pub(crate) fn relay_ref(direct: bool) -> Result<RelayRef> {
        Ok(RelayRef {
            relay_fp: [1; 32],
            onion: Onion::from_pubkey(ed25519(2)?.as_bytes()),
            akc: [3; 32],
            direct: if direct {
                Some(Direct {
                    host: Host::from_bytes(b"relay.example.org")?,
                    port: NonZeroU16::new(443).ok_or(Error::Rejected)?,
                    spki_sha256: [4; 32],
                })
            } else {
                None
            },
        })
    }

    /// RFC 4648 base32 (lowercase, no padding), for onion addresses.
    fn base32(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let (mut acc, mut bits) = (0_u32, 0_u32);
        for c in s.bytes() {
            let v = match c {
                b'a'..=b'z' => c.checked_sub(b'a'),
                b'2'..=b'7' => c.checked_sub(b'2').and_then(|v| v.checked_add(26)),
                _ => None,
            }
            .unwrap_or_default();
            acc = (acc << 5) | u32::from(v);
            bits = bits.saturating_add(5);
            if bits >= 8 {
                bits = bits.saturating_sub(8);
                out.push(u8::try_from((acc >> bits) & 0xff).unwrap_or_default());
            }
        }
        out
    }

    #[test]
    fn onion_checksum_and_version() -> Result<()> {
        // a published v3 address (DuckDuckGo's onion service), checksum per rend-spec-v3 §6
        let ddg = base32("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad");
        assert_eq!(ddg.len(), ONION_LEN);
        let parsed = Onion::from_bytes(&ddg)?;
        let pubkey: [u8; 32] = ddg
            .get(..32)
            .and_then(|p| p.try_into().ok())
            .unwrap_or_default();
        assert_eq!(Onion::from_pubkey(&pubkey), parsed);
        let o = Onion::from_pubkey(&[7; 32]);
        assert_eq!(Onion::from_bytes(o.as_bytes())?, o);
        let mut bad_version = *o.as_bytes();
        bad_version[34] = 0x02;
        assert!(Onion::from_bytes(&bad_version).is_err());
        let mut bad_checksum = *o.as_bytes();
        bad_checksum[32] ^= 1;
        assert!(Onion::from_bytes(&bad_checksum).is_err());
        assert!(Onion::from_bytes(&o.as_bytes()[..34]).is_err());
        Ok(())
    }

    #[test]
    fn relay_ref_with_and_without_direct() -> Result<()> {
        let bytes = round_trip(&relay_ref(false)?)?;
        assert_eq!(bytes.len(), crate::sizes::RELAYREF_NO_DIRECT_LEN);
        exact_fit::<RelayRef>(&bytes);
        let bytes = round_trip(&relay_ref(true)?)?;
        assert_eq!(bytes.len(), 154);
        exact_fit::<RelayRef>(&bytes);
        let mut max = relay_ref(true)?;
        if let Some(d) = &mut max.direct {
            d.host = Host::from_bytes(&[b'a'; 253])?;
            d.port = NonZeroU16::MAX;
        }
        assert_eq!(round_trip(&max)?.len(), 390);
        for host in [&b""[..], &[b'a'; 254][..], b"a b", b"a\x7f", b"\x80"] {
            assert!(Host::from_bytes(host).is_err());
        }
        Ok(())
    }

    #[test]
    fn invitation() -> Result<()> {
        let inv = InvitationV1 {
            relay: relay_ref(false)?,
            ld_id: [5; 16],
            link_key: SecretBytes::from_slice(&[6; 32])?,
            inviter_fp: [7; 32],
            inv_sid: [8; 16],
            inv_send_seed: SecretBytes::from_slice(&[9; 32])?,
            inv_period_s: Period::S80,
            expires: u64::MAX,
        };
        // review C1: the encoding carries `link_key` and `inv_send_seed` and is a `Zeroizing<Vec<u8>>`
        let encoded: secmp_crypto::Zeroizing<Vec<u8>> = inv.encode()?;
        assert!(encoded.windows(32).any(|w| w == [6; 32]));
        assert!(encoded.windows(32).any(|w| w == [9; 32]));
        let bytes = round_trip_bytes(&inv)?;
        assert_eq!(bytes.len(), crate::sizes::INVITATION_NO_DIRECT_LEN);
        exact_fit::<InvitationV1>(&bytes);
        for kind in [0_u8, 2, 3, 0xff] {
            let mut b = bytes.clone();
            if let Some(k) = b.get_mut(1) {
                *k = kind;
            }
            assert!(InvitationV1::decode(&b).is_err(), "kind {kind}");
        }
        Ok(())
    }

    #[test]
    fn profile_names() -> Result<()> {
        for name in ["", "Zoë Ångström 李雷 🙂", &"a".repeat(64)] {
            for avatar in [None, Some([1; 32])] {
                let p = Profile::new(name, avatar)?;
                assert_eq!(p.name(), name);
                let bytes = round_trip(&p)?;
                assert_eq!(Profile::decode(&bytes)?.name(), name);
                exact_fit::<Profile>(&bytes);
            }
        }
        assert!(Profile::new(&"a".repeat(65), None).is_err());
        for bad in [
            &[0xff][..],
            &[0xc0, 0xaf],
            &[0xed, 0xa0, 0x80],
            &[0xf4, 0x90, 0x80, 0x80],
        ] {
            let mut w = Writer::new();
            w.prefixed_u8(bad)?;
            w.u8(0);
            assert!(Profile::decode(&w.into_bytes()).is_err());
        }
        Ok(())
    }

    /// M4 PR run 37127247911 (R-96): `Profile::eq` compares the name and the avatar hash, both — a one-byte change of
    /// either, and a missing avatar, make two profiles differ (kills `eq -> true` and `&& -> ||`).
    #[test]
    fn profile_eq_distinguishes_name_and_avatar() -> Result<()> {
        let alice = Profile::new("alice", Some([1; 32]))?;
        assert_eq!(alice, Profile::new("alice", Some([1; 32]))?);
        assert_ne!(alice, Profile::new("alicf", Some([1; 32]))?);
        assert_ne!(alice, Profile::new("alice", Some([2; 32]))?);
        assert_ne!(alice, Profile::new("alice", None)?);
        assert_eq!(Profile::new("", None)?, Profile::new("", None)?);
        Ok(())
    }

    fn bundle() -> Result<PrekeyBundle> {
        Ok(PrekeyBundle {
            spk_id: 1,
            spk_dh: x25519(2)?,
            spk_kem: ek1024(3)?,
            rpk_kem: ek768(4)?,
            spk_expiry: 5,
            opk_id: 6,
            opk_dh: x25519(7)?,
            opk_kem: ek1024(8)?,
            sig: hybrid_sig(9)?,
        })
    }

    #[test]
    fn iks_bundle_link_data_blob() -> Result<()> {
        let i = round_trip(&iks(1)?)?;
        assert_eq!(i.len(), crate::sizes::IKS_PUBLIC_LEN);
        exact_fit::<IksPublic>(&i);
        let b = round_trip(&bundle()?)?;
        assert_eq!(b.len(), crate::sizes::PREKEY_BUNDLE_LEN);
        exact_fit::<PrekeyBundle>(&b);
        assert_eq!(bundle()?.signed_fields()?.len(), 7775 - 3373);
        let mut no_opk = b.clone();
        if let Some(p) = no_opk.get_mut(1 + 4 + 32 + 1568 + 1184 + 8) {
            *p = 0;
        }
        assert!(PrekeyBundle::decode(&no_opk).is_err());
        let ld = LinkDataV1 {
            inviter_iks: iks(2)?,
            bundle: bundle()?,
            profile: Profile::new("inviter", Some([3; 32]))?,
            created: 4,
        };
        let bytes = round_trip(&ld)?;
        assert_eq!(bytes.len(), LINKDATA_PADDED_LEN);
        exact_fit::<LinkDataV1>(&bytes);
        let blob = LinkBlob::from_parts(&[1; 24], &[2; COM_LEN + LINK_BLOB_CT_LEN])?;
        assert_eq!(round_trip(&blob)?.len(), crate::sizes::LINK_BLOB_LEN);
        Ok(())
    }

    /// M2 review F9: the largest `LinkDataV1` (a 64-byte name and an avatar hash) has 9899 bytes of fields, so its
    /// padding marker sits at offset 9899 of the 12288 bytes — the bound `sizes` asserts at compile time.
    #[test]
    fn largest_link_data_fits_its_padding() -> Result<()> {
        let ld = LinkDataV1 {
            inviter_iks: iks(5)?,
            bundle: bundle()?,
            profile: Profile::new(&"a".repeat(64), Some([6; 32]))?,
            created: u64::MAX,
        };
        let bytes = round_trip(&ld)?;
        assert_eq!(bytes.len(), LINKDATA_PADDED_LEN);
        assert_eq!(bytes.get(9898), Some(&0xff), "the last byte of `created`");
        assert_eq!(bytes.get(9899), Some(&0x80), "the marker");
        assert!(
            bytes
                .get(9900..)
                .unwrap_or_default()
                .iter()
                .all(|b| *b == 0)
        );
        Ok(())
    }
}
