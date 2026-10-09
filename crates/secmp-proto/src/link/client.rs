// SPDX-License-Identifier: AGPL-3.0-or-later
//! The client's side of the SecMP-LINK handshake (spec §8.2–§8.3), a typestate chain:
//!
//! ```text
//! start ──► AwaitRelayInfo ──on_relayinfo──► AwaitHs2 ──on_hs2──► Link
//!   (HELLO)                    (HS1)                       (HS2 verified)
//! ```
//!
//! The client is anonymous (§8.3): `start` takes the relay's pinned `relay_fp`, an optional access key and the time,
//! and no long-term secret. The `RELAYINFO` of each link is used for that link only and never cached (§8.2): no
//! function takes a stored `RelayInfo`. Every failure is the one [`Error::Rejected`] and consumes the state (spec
//! §8.5, reading OPEN-2): no [`Link`], no key and no further record leave a failed handshake.

use secmp_crypto::{
    ConstantTimeEq, Ed25519VerifyingKey, HybridKem768SecretKey, HybridKem1024PublicKey, Label,
    MlKem768Ct, MlKem1024Ek, SecretBytes, X25519Public, hmac_sha256_verify,
};

use crate::codec::{Decode, Encode};
use crate::keys::{MlKem768Ek, X25519Pk};
use crate::link::handshake::{self, Hs1Fields};
use crate::link::ids::{AccessKey, akc};
use crate::link::{Error, Link, MAX_VALIDITY_SECS, Result};
use crate::sizes::HASH_LEN;
use crate::tr::Entropy;
use crate::wire::record::{Hello, Hs1, Hs2, RelayInfoRecord};

/// Begin a link: the `HELLO` record to send and the state that awaits `RELAYINFO`.
///
/// `pinned_fp` is the relay's `relay_fp` from its `RelayRef`; `access_key` is the key the client holds, if any (the
/// `akc` of `RELAYINFO` is checked only then, spec §8.2, ADR-048 (a)); `now` is Unix seconds.
///
/// # Errors
/// None in practice (`HELLO` always encodes).
pub fn start(
    pinned_fp: [u8; HASH_LEN],
    access_key: Option<&AccessKey>,
    now: u64,
) -> Result<(Vec<u8>, AwaitRelayInfo)> {
    let hello = Hello.encode()?.to_vec();
    Ok((
        hello,
        AwaitRelayInfo {
            pinned_fp,
            akc: access_key.map(akc),
            now,
        },
    ))
}

/// The client after `HELLO`: waiting for `RELAYINFO`.
pub struct AwaitRelayInfo {
    pinned_fp: [u8; HASH_LEN],
    akc: Option<[u8; HASH_LEN]>,
    now: u64,
}

impl AwaitRelayInfo {
    /// Process the `RELAYINFO` record (spec §8.2) and answer with the `HS1` record (spec §8.3).
    ///
    /// Checks, in this order: the record and `RelayInfoV1` decoders with the §4.1 obligations; strict Ed25519 of
    /// `sig` under `"SecMP-LINK/1 relayinfo" ‖` the 1677 bytes before it; `relay_fp` equals the pinned value;
    /// `valid_until ≥ now`; `valid_until − now ≤ 60 days`; `akc` if the client holds an access key. Then the client
    /// draws `e_c_sk`, `ek_c_seed`, and for `HybridKEM-1024.Encaps((relay_dh_pk, relay_kem_ek))` `sk_e1` and `m1`
    /// (reading OPEN-1).
    ///
    /// # Errors
    /// [`Error::Rejected`] for any failed check; [`Error::Unavailable`] if randomness or locked memory is
    /// unavailable.
    pub fn on_relayinfo(
        self,
        record: &[u8],
        entropy: &mut impl Entropy,
    ) -> Result<(Vec<u8>, AwaitHs2)> {
        let info = RelayInfoRecord::decode(record)?.relay_info;
        // sig = Ed25519(relay_sig, "SecMP-LINK/1 relayinfo" ‖ all preceding fields), strict (§3.5)
        let signed = [
            Label::LinkRelayinfo.as_bytes(),
            info.signed_fields()?.as_slice(),
        ]
        .concat();
        Ed25519VerifyingKey::from_bytes(info.relay_sig_pk.as_bytes())?
            .verify(&signed, info.sig.as_bytes())?;
        if !bool::from(super::ids::relay_fp(&info.relay_sig_pk).ct_eq(&self.pinned_fp)) {
            return Err(Error::Rejected);
        }
        if info.valid_until < self.now {
            return Err(Error::Rejected);
        }
        // `valid_until ≥ now` holds: the subtraction cannot underflow
        if info
            .valid_until
            .checked_sub(self.now)
            .is_none_or(|d| d > MAX_VALIDITY_SECS)
        {
            return Err(Error::Rejected);
        }
        if let Some(mine) = &self.akc
            && !bool::from(mine.ct_eq(&info.akc))
        {
            return Err(Error::Rejected);
        }

        let relay_pk = HybridKem1024PublicKey::new(
            X25519Public::from_bytes_checked(info.relay_dh_pk.as_bytes())?,
            MlKem1024Ek::from_bytes(info.relay_kem_ek.as_bytes())?,
        );
        // draws, in the order of reading OPEN-1: e_c_sk, ek_c_seed, sk_e1, m1
        let e_c_sk = entropy.x25519()?;
        let dk_c = entropy.mlkem768()?;
        let (ct1, ss1) = entropy.hybrid_encaps1024(&relay_pk)?;
        let kem_c = HybridKem768SecretKey::from_parts(e_c_sk, dk_c);
        let pk_c = kem_c.public_key();
        let dh_pub = X25519Pk::from_bytes(pk_c.pk_dh().as_bytes())?;
        let kem_pub = MlKem768Ek::from_bytes(pk_c.ek().as_bytes())?;
        let pk_e1 = X25519Pk::from_bytes(ct1.pk_e().as_bytes())?;
        let ct_kem = Box::new(*ct1.ct().as_bytes());

        let relay_fp = self.pinned_fp;
        let h0 = handshake::h0(&Hs1Fields {
            kid: info.kid,
            relay_fp: &relay_fp,
            e_c: &dh_pub,
            ek_c: &kem_pub,
            pk_e1: &pk_e1,
            ct_kem: &ct_kem,
        });
        let (ck1, mac1) = handshake::chain1(&h0, &ss1)?;
        let hs1 = Hs1 {
            kid: info.kid,
            e_c: dh_pub,
            ek_c: kem_pub,
            pk_e1,
            ct_kem,
            mac1,
        };
        let record = hs1.encode()?.to_vec();
        #[cfg(feature = "kat")]
        let trace = crate::link::HandshakeTrace {
            ss1: *ss1.expose_secret(),
            h0,
            ck1: *ck1.expose_secret(),
            mac1,
            ..crate::link::HandshakeTrace::default()
        };
        Ok((
            record,
            AwaitHs2 {
                kem_c,
                h0,
                ck1,
                mac1,
                #[cfg(feature = "kat")]
                trace,
            },
        ))
    }
}

/// The client after `HS1`: waiting for `HS2`.
pub struct AwaitHs2 {
    kem_c: HybridKem768SecretKey,
    h0: [u8; HASH_LEN],
    ck1: SecretBytes<32>,
    mac1: [u8; HASH_LEN],
    #[cfg(feature = "kat")]
    trace: crate::link::HandshakeTrace,
}

impl AwaitHs2 {
    /// Process the `HS2` record (spec §8.3): the decoder (a low-order `e_r` is refused), `HybridKEM-768.Decaps`,
    /// `h1`, `ck2`, then `mac2` compared in constant time; the keys are derived only if it verifies.
    ///
    /// # Errors
    /// [`Error::Rejected`] for any failed check.
    pub fn on_hs2(self, record: &[u8]) -> Result<Link> {
        let hs2 = Hs2::decode(record)?;
        let ct = secmp_crypto::HybridKem768Ciphertext::new(
            X25519Public::from_bytes_checked(hs2.e_r.as_bytes())?,
            MlKem768Ct::from_bytes(hs2.ct_c.as_slice())?,
        );
        let ss2 = self.kem_c.decapsulate(&ct)?;
        let h1 = handshake::h1(&self.h0, &self.mac1, &hs2.e_r, &hs2.ct_c);
        let (ck2, mac2) = handshake::chain2(&h1, &self.ck1, &ss2)?;
        let verified = hmac_sha256_verify(ck2.expose_secret(), Label::LinkHs2, &[], &hs2.mac2)?;
        if !bool::from(verified) {
            return Err(Error::Rejected);
        }
        let keys = handshake::link_keys(&ck2)?;
        #[cfg(feature = "kat")]
        let trace = crate::link::HandshakeTrace {
            ss2: *ss2.expose_secret(),
            h1,
            ck2: *ck2.expose_secret(),
            mac2,
            k_c2r: *keys.k_c2r.expose_secret(),
            k_r2c: *keys.k_r2c.expose_secret(),
            sess_id: keys.sess_id,
            ..self.trace.clone()
        };
        #[cfg(not(feature = "kat"))]
        let _ = mac2;
        let link = Link::client(keys);
        #[cfg(feature = "kat")]
        let link = link.with_trace(trace);
        Ok(link)
    }

    /// The values computed so far (vectors and tests only).
    #[cfg(feature = "kat")]
    #[must_use]
    pub const fn trace_kat(&self) -> &crate::link::HandshakeTrace {
        &self.trace
    }
}
