// SPDX-License-Identifier: AGPL-3.0-or-later
//! The SecMP-TR key derivations of spec §7.2, exactly:
//!
//! ```text
//! (RK ‖ HK_A ‖ NHK_B) = HKDF-SHA-256(salt = 0^32, IKM = SK, info = "SecMP-TR/1 init", L = 96)
//! KDF_RK(rk, ikm)     = HKDF-SHA-256(salt = rk, IKM = ikm, info = "SecMP-TR/1 rk", L = 96) → (rk', ck, nhk)
//! KDF_CK(ck)          = (ck' = HMAC-SHA-256(ck, 0x02), mk = HMAC-SHA-256(ck, 0x01))
//! ```
//!
//! The `ikm` of every `KDF_RK` call is `X25519(dh_s, dh_r) ‖ ss_pq` (§7.2 initiator, §7.4 `DHRatchet`, both
//! halves), so [`kdf_rk`] takes the two 32-byte secrets and concatenates them itself, in a zeroizing buffer.
//! [`kdf_ck`] runs up to 2^21 times for one received message in a fast-forward (spec §7.4 note (a)), so it keys
//! HMAC once and finishes a copy of the keyed state for each of the two outputs.

use hmac::digest::FixedOutput;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::kdf::hkdf;
use crate::label::Label;
use crate::secret::SecretBytes;

/// `okm[0..32] ‖ okm[32..64] ‖ okm[64..96]` as three keys, in the order the spec's left-hand side lists them.
fn thirds(okm: &SecretBytes<96>) -> Result<(SecretBytes<32>, SecretBytes<32>, SecretBytes<32>)> {
    let (a, rest) = okm
        .expose_secret()
        .split_first_chunk::<32>()
        .ok_or(Error::Rejected)?;
    let (b, c) = rest.split_first_chunk::<32>().ok_or(Error::Rejected)?;
    Ok((
        SecretBytes::from_slice(a)?,
        SecretBytes::from_slice(b)?,
        SecretBytes::from_slice(c)?,
    ))
}

/// Spec §7.2 initialisation: `(RK, HK_A, NHK_B)` from the handshake secret `SK`.
///
/// # Errors
/// None in practice (the lengths are fixed); kept fallible like every derivation.
pub fn tr_init(
    sk: &SecretBytes<32>,
) -> Result<(SecretBytes<32>, SecretBytes<32>, SecretBytes<32>)> {
    // (RK ‖ HK_A ‖ NHK_B) = HKDF-SHA-256(salt = 0^32, IKM = SK, info = "SecMP-TR/1 init", L = 96)
    let okm = hkdf::<96>(&[0; 32], sk.expose_secret(), Label::TrInit, &[])?;
    thirds(&okm)
}

/// Spec §7.2 `KDF_RK(rk, dh ‖ ss)` → `(rk', ck, nhk)`, where `dh` is the X25519 output and `ss` the ML-KEM-768
/// shared secret of the step (§7.2 initiator; §7.4 `DHRatchet`, receiving and sending half).
///
/// # Errors
/// None in practice (the lengths are fixed); kept fallible like every derivation.
pub fn kdf_rk(
    rk: &SecretBytes<32>,
    dh: &SecretBytes<32>,
    ss: &SecretBytes<32>,
) -> Result<(SecretBytes<32>, SecretBytes<32>, SecretBytes<32>)> {
    // IKM = dh ‖ ss, in a buffer that is wiped on drop
    let mut ikm = SecretBytes::<64>::zero();
    let (ikm_dh, ikm_ss) = ikm
        .expose_secret_mut()
        .split_first_chunk_mut::<32>()
        .ok_or(Error::Rejected)?;
    ikm_dh.copy_from_slice(dh.expose_secret());
    ikm_ss.copy_from_slice(ss.expose_secret());
    // HKDF-SHA-256(salt = rk, IKM = ikm, info = "SecMP-TR/1 rk", L = 96)
    let okm = hkdf::<96>(rk.expose_secret(), ikm.expose_secret(), Label::TrRk, &[])?;
    thirds(&okm)
}

/// Spec §7.2 `KDF_CK(ck)` → `(ck', mk)` with `ck' = HMAC-SHA-256(ck, 0x02)` and `mk = HMAC-SHA-256(ck, 0x01)`.
///
/// # Errors
/// None in practice (HMAC accepts every key length); kept fallible like every derivation.
pub fn kdf_ck(ck: &SecretBytes<32>) -> Result<(SecretBytes<32>, SecretBytes<32>)> {
    // key HMAC once; each output finishes its own copy of the keyed state (spec §7.4 note (a): fast-forward)
    let keyed = <Hmac<Sha256> as KeyInit>::new_from_slice(ck.expose_secret())
        .map_err(|_| Error::Rejected)?;
    let mut next = keyed.clone();
    let mut mk = keyed;
    next.update(&[0x02]);
    mk.update(&[0x01]);
    let mut ck_out = SecretBytes::<32>::zero();
    let mut mk_out = SecretBytes::<32>::zero();
    next.finalize_into(ck_out.expose_secret_mut().into());
    mk.finalize_into(mk_out.expose_secret_mut().into());
    Ok((ck_out, mk_out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;
    use crate::test_util::{hex, unhex};

    fn key(b: u8) -> Result<SecretBytes<32>> {
        SecretBytes::from_slice(&[b; 32])
    }

    /// HMAC-SHA-256 composed by hand from SHA-256 (RFC 2104): `H((K ⊕ opad) ‖ H((K ⊕ ipad) ‖ m))`, for keys of at
    /// most one block (every key here is 32 bytes).
    fn manual_hmac(k: &[u8], m: &[u8]) -> [u8; 32] {
        assert!(k.len() <= 64, "keys longer than a block are hashed first");
        let mut block = [0_u8; 64];
        for (b, x) in block.iter_mut().zip(k) {
            *b = *x;
        }
        let ipad: Vec<u8> = block.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = block.iter().map(|b| b ^ 0x5c).collect();
        let inner = sha256(&[&ipad, m]);
        sha256(&[&opad, &inner])
    }

    /// HKDF-SHA-256 (RFC 5869) composed from [`manual_hmac`]: `PRK = HMAC(salt, IKM)`, `T(i) = HMAC(PRK, T(i−1) ‖
    /// info ‖ i)`, OKM = `T(1) ‖ T(2) ‖ T(3)` (96 bytes).
    fn manual_hkdf_96(salt: &[u8], ikm: &[u8], info: &[u8]) -> Vec<u8> {
        let prk = manual_hmac(salt, ikm);
        let mut okm = Vec::new();
        let mut t: Vec<u8> = Vec::new();
        for i in 1_u8..=3 {
            t = manual_hmac(&prk, &[&t[..], info, &[i]].concat()).to_vec();
            okm.extend_from_slice(&t);
        }
        okm
    }

    fn cat(k: &(SecretBytes<32>, SecretBytes<32>, SecretBytes<32>)) -> Vec<u8> {
        [
            &k.0.expose_secret()[..],
            &k.1.expose_secret()[..],
            &k.2.expose_secret()[..],
        ]
        .concat()
    }

    /// The hand-made HMAC is HMAC: RFC 4231 test cases 1–4 (keys of 20, 4, 20 and 25 bytes).
    #[test]
    fn manual_hmac_matches_rfc4231() {
        let cases: [(Vec<u8>, Vec<u8>, &str); 4] = [
            (
                vec![0x0b; 20],
                b"Hi There".to_vec(),
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                vec![0xaa; 20],
                vec![0xdd; 50],
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                unhex("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap_or_default(),
                vec![0xcd; 50],
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            ),
        ];
        for (k, m, expected) in cases {
            assert_eq!(hex(&manual_hmac(&k, &m)), expected);
        }
    }

    /// `tr_init` = HKDF(salt = 0^32, IKM = SK, info = "SecMP-TR/1 init", L = 96), split `RK ‖ HK_A ‖ NHK_B` in
    /// that order — recomputed independently.
    #[test]
    fn tr_init_matches_manual_composition() -> Result<()> {
        for sk in [[0x11_u8; 32], [0; 32], [0xff; 32]] {
            let keys = tr_init(&SecretBytes::from_slice(&sk)?)?;
            let expected = manual_hkdf_96(&[0; 32], &sk, b"SecMP-TR/1 init");
            assert_eq!(hex(&cat(&keys)), hex(&expected));
            assert_eq!(
                keys.0.expose_secret().as_slice(),
                expected.get(..32).unwrap_or_default(),
                "RK first"
            );
            assert_eq!(
                keys.2.expose_secret().as_slice(),
                expected.get(64..).unwrap_or_default(),
                "NHK_B last"
            );
        }
        Ok(())
    }

    /// `kdf_rk(rk, dh, ss)` = HKDF(salt = rk, IKM = dh ‖ ss, info = "SecMP-TR/1 rk", L = 96) split `rk' ‖ ck ‖ nhk`
    /// — recomputed independently; the IKM order is `dh` then `ss`.
    #[test]
    fn kdf_rk_matches_manual_composition() -> Result<()> {
        let (rk, dh, ss) = ([0x21_u8; 32], [0x42_u8; 32], [0x63_u8; 32]);
        let keys = kdf_rk(
            &SecretBytes::from_slice(&rk)?,
            &SecretBytes::from_slice(&dh)?,
            &SecretBytes::from_slice(&ss)?,
        )?;
        let expected = manual_hkdf_96(&rk, &[dh, ss].concat(), b"SecMP-TR/1 rk");
        assert_eq!(hex(&cat(&keys)), hex(&expected));
        let swapped = kdf_rk(
            &SecretBytes::from_slice(&rk)?,
            &SecretBytes::from_slice(&ss)?,
            &SecretBytes::from_slice(&dh)?,
        )?;
        assert_ne!(
            cat(&swapped),
            cat(&keys),
            "dh and ss are not interchangeable"
        );
        Ok(())
    }

    /// `kdf_ck(ck)` = (HMAC(ck, 0x02), HMAC(ck, 0x01)) in that order — recomputed with the hand-made HMAC.
    #[test]
    fn kdf_ck_matches_manual_hmac() -> Result<()> {
        for ck in [[0x5a_u8; 32], [0; 32], [0xff; 32]] {
            let (next, mk) = kdf_ck(&SecretBytes::from_slice(&ck)?)?;
            assert_eq!(hex(next.expose_secret()), hex(&manual_hmac(&ck, &[0x02])));
            assert_eq!(hex(mk.expose_secret()), hex(&manual_hmac(&ck, &[0x01])));
        }
        Ok(())
    }

    /// The outputs are distinct and depend on every input: the three thirds differ; each input of `kdf_rk` changes
    /// every output; a chain step never repeats a key.
    #[test]
    fn outputs_are_distinct_and_bound_to_every_input() -> Result<()> {
        let (a, b, c) = tr_init(&key(1)?)?;
        assert_ne!(a.expose_secret(), b.expose_secret());
        assert_ne!(b.expose_secret(), c.expose_secret());
        assert_ne!(a.expose_secret(), c.expose_secret());
        let base = kdf_rk(&key(1)?, &key(2)?, &key(3)?)?;
        for other in [
            kdf_rk(&key(9)?, &key(2)?, &key(3)?)?,
            kdf_rk(&key(1)?, &key(9)?, &key(3)?)?,
            kdf_rk(&key(1)?, &key(2)?, &key(9)?)?,
        ] {
            assert_ne!(base.0.expose_secret(), other.0.expose_secret());
            assert_ne!(base.1.expose_secret(), other.1.expose_secret());
            assert_ne!(base.2.expose_secret(), other.2.expose_secret());
        }
        // tr_init and kdf_rk are separated by their labels: the same 32-byte IKM half gives other keys
        let (rk, ck, nhk) = kdf_rk(&SecretBytes::from_slice(&[0; 32])?, &key(1)?, &key(1)?)?;
        assert_ne!(rk.expose_secret(), a.expose_secret());
        assert_ne!(ck.expose_secret(), b.expose_secret());
        assert_ne!(nhk.expose_secret(), c.expose_secret());
        let (ck1, mk1) = kdf_ck(&key(4)?)?;
        let (ck2, mk2) = kdf_ck(&ck1)?;
        assert_ne!(ck1.expose_secret(), mk1.expose_secret());
        assert_ne!(mk1.expose_secret(), mk2.expose_secret());
        assert_ne!(ck2.expose_secret(), ck1.expose_secret());
        assert_ne!(ck1.expose_secret(), key(4)?.expose_secret());
        Ok(())
    }
}
