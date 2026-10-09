// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay's side of the SecMP-LINK handshake (spec §8.2–§8.3): its identity and static keys ([`RelayKeys`]),
//! `RELAYINFO`, and the responder as a typestate chain
//!
//! ```text
//! accept(keys) ──► AwaitHello ──on_hello──► AwaitHs1 ──on_hs1──► (HS2, Link)
//!                                (RELAYINFO)              (mac1 verified first)
//! ```
//!
//! A failed check is [`Error::Rejected`] and consumes the state: the caller emits nothing further and closes the
//! connection (spec §8.5, "teardown"). `HS2` randomness (`sk_er`, `m2`) is drawn only after `mac1` has verified
//! (reading OPEN-2). The relay keeps no HS1 replay cache: a replayed `HS1` is answered as a new handshake (spec §8.3,
//! ADR-048 (c)).

use secmp_crypto::{
    ConstantTimeEq, Ed25519SigningKey, HybridKem768PublicKey, HybridKem1024Ciphertext,
    HybridKem1024SecretKey, Label, MlKem768Ek as CryptoEk768, MlKem1024Ct, MlKem1024Dk,
    X25519Public, X25519Secret,
};

use crate::codec::{Decode, Encode};
use crate::keys::{Ed25519Pk, Ed25519Sig, MlKem1024Ek, X25519Pk};
use crate::link::handshake::{self, Hs1Fields};
use crate::link::ids::{AccessKey, akc, relay_fp};
use crate::link::{Error, Link, Result};
use crate::sizes::HASH_LEN;
use crate::tr::Entropy;
use crate::wire::record::{Hello, Hs1, Hs2, RelayInfoRecord, RelayInfoV1};

#[cfg(feature = "kat")]
std::thread_local! {
    /// Signing operations of [`RelayKeys::relay_info`] on this thread (feature `kat`; M05 review R-144): one per
    /// `RELAYINFO`, none for a placeholder.
    pub static SIGN_CALLS_KAT: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// The relay's long-term signing identity, the static key pair of one key generation `kid` and the access key
/// (spec §8.2, §9.6).
pub struct RelayKeys {
    sig: Ed25519SigningKey,
    sig_pk: Ed25519Pk,
    kid: u32,
    kem: HybridKem1024SecretKey,
    dh_pk: X25519Pk,
    kem_ek: MlKem1024Ek,
    access_key: AccessKey,
}

impl RelayKeys {
    /// The keys from their secrets: `relay_sig`, `relay_dh` and `relay_kem` (held as a seed) of generation `kid`.
    ///
    /// # Errors
    /// [`Error::Rejected`] if a derived public key is refused by the §4.1 rules (not reachable for honest keys).
    pub fn new(
        sig: Ed25519SigningKey,
        dh: X25519Secret,
        kem: MlKem1024Dk,
        access_key: AccessKey,
        kid: u32,
    ) -> Result<Self> {
        let sig_pk = Ed25519Pk::from_bytes(sig.verifying_key().as_bytes())?;
        let kem = HybridKem1024SecretKey::from_parts(dh, kem);
        let public = kem.public_key();
        Ok(Self {
            sig,
            sig_pk,
            kid,
            dh_pk: X25519Pk::from_bytes(public.pk_dh().as_bytes())?,
            kem_ek: MlKem1024Ek::from_bytes(public.ek().as_bytes())?,
            kem,
            access_key,
        })
    }

    /// The key generation announced in `RELAYINFO`.
    #[must_use]
    pub const fn kid(&self) -> u32 {
        self.kid
    }

    /// `relay_sig_pk`.
    #[must_use]
    pub const fn sig_pk(&self) -> &Ed25519Pk {
        &self.sig_pk
    }

    /// `relay_fp` (spec §8.2).
    #[must_use]
    pub fn fp(&self) -> [u8; HASH_LEN] {
        relay_fp(&self.sig_pk)
    }

    /// `akc` of the configured access key (spec §5.3).
    #[must_use]
    pub fn akc(&self) -> [u8; HASH_LEN] {
        akc(&self.access_key)
    }

    /// The access key (the executor verifies tokens with it, spec §9.6).
    #[must_use]
    pub const fn access_key(&self) -> &AccessKey {
        &self.access_key
    }

    /// `RelayInfoV1` for this generation, valid until `valid_until` (Unix seconds), signed with `relay_sig`
    /// (spec §8.2). Deterministic: the same inputs give the same bytes.
    ///
    /// # Errors
    /// [`Error::Rejected`] only if the signature fails the encoding rules (not reachable for an honest signer).
    pub fn relay_info(&self, valid_until: u64) -> Result<RelayInfoV1> {
        // the signature covers every field before `sig`: build the value with a constant filler in the `sig` field (not a
        // signature, no signing operation; M05 review R-144), take its signed prefix, sign once, rebuild
        let placeholder = Ed25519Sig::from_bytes(&[0x01; 64])?;
        let unsigned = RelayInfoV1 {
            relay_sig_pk: self.sig_pk,
            kid: self.kid,
            relay_dh_pk: self.dh_pk,
            relay_kem_ek: self.kem_ek.clone(),
            akc: self.akc(),
            valid_until,
            sig: placeholder,
        };
        let message = [
            Label::LinkRelayinfo.as_bytes(),
            unsigned.signed_fields()?.as_slice(),
        ]
        .concat();
        #[cfg(feature = "kat")]
        SIGN_CALLS_KAT.with(|c| c.set(c.get().saturating_add(1)));
        Ok(RelayInfoV1 {
            sig: Ed25519Sig::from_bytes(&self.sig.sign(&message))?,
            ..unsigned
        })
    }

    /// The `RELAYINFO` record (spec §8.2, D.1) for this generation.
    ///
    /// # Errors
    /// As [`RelayKeys::relay_info`].
    pub fn relay_info_record(&self, valid_until: u64) -> Result<Vec<u8>> {
        let record = RelayInfoRecord {
            relay_info: self.relay_info(valid_until)?,
        };
        Ok(record.encode()?.to_vec())
    }
}

/// Marker: every secret field (`relay_sig`, the static pair of `kid`, the access key) wipes its memory on drop.
impl secmp_crypto::ZeroizeOnDrop for RelayKeys {}

/// A connection that has not sent anything yet: waiting for `HELLO`; the relay holds one key generation.
#[must_use]
pub const fn accept(keys: &RelayKeys) -> AwaitHello<'_> {
    AwaitHello {
        ring: core::slice::from_ref(keys),
    }
}

/// As [`accept`] for a relay that holds several key generations during a rotation (spec §8.2 "overlapping
/// validity"): `ring` in ascending `kid` order; `RELAYINFO` announces the last (newest) generation, and `HS1` may
/// name any generation of the ring. An empty ring answers no `HELLO`.
#[must_use]
pub const fn accept_ring(ring: &[RelayKeys]) -> AwaitHello<'_> {
    AwaitHello { ring }
}

/// The relay before `HELLO`.
pub struct AwaitHello<'k> {
    ring: &'k [RelayKeys],
}

impl<'k> AwaitHello<'k> {
    /// Process `HELLO` and answer with the current `RELAYINFO` record (spec §8.2): every `HELLO` is answered, no
    /// matter who sent it.
    ///
    /// # Errors
    /// [`Error::Rejected`] if `record` is not exactly a `HELLO` record, or the ring is empty.
    pub fn on_hello(self, record: &[u8], valid_until: u64) -> Result<(Vec<u8>, AwaitHs1<'k>)> {
        Hello::decode(record)?;
        let current = self.ring.last().ok_or(Error::Rejected)?;
        let info = current.relay_info_record(valid_until)?;
        Ok((info, AwaitHs1 { ring: self.ring }))
    }
}

/// The relay after `RELAYINFO`: waiting for `HS1`.
pub struct AwaitHs1<'k> {
    ring: &'k [RelayKeys],
}

impl AwaitHs1<'_> {
    /// Process `HS1` and answer with the `HS2` record and the established [`Link`] (spec §8.3).
    ///
    /// The decoder carries the §4.1 obligations on `e_c`, `pk_e1` and `ek_c`; `kid` must be a generation held;
    /// `Decaps` binds the relay's own static keys into the combiner; `mac1` is compared in constant time **before**
    /// the relay draws anything. Then `sk_er` and `m2` are drawn for `HybridKEM-768.Encaps((e_c, ek_c))`.
    ///
    /// # Errors
    /// [`Error::Rejected`] for any failed check (no randomness drawn); [`Error::Unavailable`] if randomness or
    /// locked memory is unavailable.
    pub fn on_hs1(self, record: &[u8], entropy: &mut impl Entropy) -> Result<(Vec<u8>, Link)> {
        let hs1 = Hs1::decode(record)?;
        // the kid is public (it is in the cleartext record): a plain lookup
        let keys = self
            .ring
            .iter()
            .find(|k| k.kid == hs1.kid)
            .ok_or(Error::Rejected)?;
        let ct1 = HybridKem1024Ciphertext::new(
            X25519Public::from_bytes_checked(hs1.pk_e1.as_bytes())?,
            MlKem1024Ct::from_bytes(hs1.ct_kem.as_slice())?,
        );
        let ss1 = keys.kem.decapsulate(&ct1)?;
        let fp = keys.fp();
        let h0 = handshake::h0(&Hs1Fields {
            kid: hs1.kid,
            relay_fp: &fp,
            e_c: &hs1.e_c,
            ek_c: &hs1.ek_c,
            pk_e1: &hs1.pk_e1,
            ct_kem: &hs1.ct_kem,
        });
        let (ck1, mac1) = handshake::chain1(&h0, &ss1)?;
        // spec §8.3: mac1 in constant time, before the relay answers or draws anything (spec §8.5)
        if !bool::from(mac1.ct_eq(&hs1.mac1)) {
            return Err(Error::Rejected);
        }

        let pk_c = HybridKem768PublicKey::new(
            X25519Public::from_bytes_checked(hs1.e_c.as_bytes())?,
            CryptoEk768::from_bytes(hs1.ek_c.as_bytes())?,
        );
        let (ct2, ss2) = entropy.hybrid_encaps768(&pk_c)?;
        let e_r = X25519Pk::from_bytes(ct2.pk_e().as_bytes())?;
        let ct_c = Box::new(*ct2.ct().as_bytes());
        let h1 = handshake::h1(&h0, &mac1, &e_r, &ct_c);
        let (ck2, mac2) = handshake::chain2(&h1, &ck1, &ss2)?;
        let link_keys = handshake::link_keys(&ck2)?;
        let record = Hs2 { e_r, ct_c, mac2 }.encode()?.to_vec();
        #[cfg(feature = "kat")]
        let trace = crate::link::HandshakeTrace {
            ss1: *ss1.expose_secret(),
            h0,
            ck1: *ck1.expose_secret(),
            mac1,
            ss2: *ss2.expose_secret(),
            h1,
            ck2: *ck2.expose_secret(),
            mac2,
            k_c2r: *link_keys.k_c2r.expose_secret(),
            k_r2c: *link_keys.k_r2c.expose_secret(),
            sess_id: link_keys.sess_id,
        };
        let link = Link::relay(link_keys);
        #[cfg(feature = "kat")]
        let link = link.with_trace(trace);
        Ok((record, link))
    }
}
