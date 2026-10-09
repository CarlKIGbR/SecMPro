// SPDX-License-Identifier: AGPL-3.0-or-later
//! HKDF-Extract and HMAC-SHA-256 as the SecMP-LINK handshake and the SecMP-Q access token use them (spec §3 table
//! "KDF / MAC", §8.3 `ck1`/`mac1`/`ck2`/`mac2`, §9.6 `token`).
//!
//! - [`hkdf_extract`] is `PRK = HMAC-SHA-256(salt, IKM)` (RFC 5869 §2.2); the PRK is a secret chain key
//!   ([`SecretBytes`]) that [`crate::hkdf_expand`] and [`hmac_sha256`] take as their key.
//! - [`hmac_sha256`] and [`hmac_sha256_verify`] follow the label discipline of spec §3: the MAC input is a label of
//!   Appendix A followed by the call site's context bytes without framing. The verdict of the verification is a
//!   [`Choice`]; the comparison of the two tags is `subtle`'s (CLAUDE.md §5).

use hmac::digest::FixedOutput;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};

use crate::error::{Error, Result};
use crate::label::Label;
use crate::secret::SecretBytes;

/// The length of an HMAC-SHA-256 tag.
pub const MAC_LEN: usize = 32;

/// `HMAC-SHA-256(key, parts[0] ‖ parts[1] ‖ …)`.
fn hmac_parts(key: &[u8], parts: &[&[u8]]) -> Result<Hmac<Sha256>> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| Error::Rejected)?;
    for p in parts {
        mac.update(p);
    }
    Ok(mac)
}

/// `HKDF-Extract(salt, ikm)` (RFC 5869 §2.2): `HMAC-SHA-256(salt, ikm)`, the pseudo-random key of the SecMP-LINK
/// handshake chain (spec §8.3 `ck1 = HKDF-Extract(salt = h0, IKM = ss1)`, `ck2 = HKDF-Extract(salt = h1, IKM = ck1 ‖
/// ss2)`). An empty salt equals `0^32`.
///
/// # Errors
/// None in practice (HMAC accepts every key length); kept fallible like every derivation.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Result<SecretBytes<32>> {
    let mac = hmac_parts(salt, &[ikm])?;
    let mut prk = SecretBytes::<32>::zero();
    mac.finalize_into(prk.expose_secret_mut().into());
    Ok(prk)
}

/// `HMAC-SHA-256(key, label ‖ context[0] ‖ context[1] ‖ …)`.
///
/// # Errors
/// None in practice (HMAC accepts every key length); kept fallible like every derivation.
pub fn hmac_sha256(key: &[u8], label: Label, context: &[&[u8]]) -> Result<[u8; MAC_LEN]> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| Error::Rejected)?;
    mac.update(label.as_bytes());
    for c in context {
        mac.update(c);
    }
    Ok(mac.finalize().into_bytes().into())
}

/// Whether `tag` is `HMAC-SHA-256(key, label ‖ context…)`, as a [`Choice`]: the tag is always computed and
/// compared in constant time, whatever the outcome.
///
/// # Errors
/// None in practice (as [`hmac_sha256`]).
pub fn hmac_sha256_verify(
    key: &[u8],
    label: Label,
    context: &[&[u8]],
    tag: &[u8; MAC_LEN],
) -> Result<Choice> {
    let expected = hmac_sha256(key, label, context)?;
    Ok(expected.as_slice().ct_eq(tag.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{hex, unhex};

    /// RFC 5869 A.1: the PRK of the basic test case.
    #[test]
    fn extract_matches_rfc5869_a1() -> Result<()> {
        let salt = unhex("000102030405060708090a0b0c").ok_or(Error::Rejected)?;
        let prk = hkdf_extract(&salt, &[0x0b; 22])?;
        assert_eq!(
            hex(prk.expose_secret()),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        Ok(())
    }

    /// RFC 5869 A.3: zero-length salt equals `0^32`.
    #[test]
    fn extract_matches_rfc5869_a3_and_empty_salt_is_zero_salt() -> Result<()> {
        let prk = hkdf_extract(&[], &[0x0b; 22])?;
        assert_eq!(
            hex(prk.expose_secret()),
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        );
        let zero = hkdf_extract(&[0; 32], &[0x0b; 22])?;
        assert_eq!(prk.expose_secret(), zero.expose_secret());
        Ok(())
    }

    /// RFC 4231 test cases 1 and 2 through the keyed state the labelled MAC is built on.
    #[test]
    fn hmac_matches_rfc4231() -> Result<()> {
        let t1: [u8; 32] = hmac_parts(&[0x0b; 20], &[b"Hi There"])?
            .finalize()
            .into_bytes()
            .into();
        assert_eq!(
            hex(&t1),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        let t2: [u8; 32] = hmac_parts(b"Jefe", &[b"what do ya want ", b"for nothing?"])?
            .finalize()
            .into_bytes()
            .into();
        assert_eq!(
            hex(&t2),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        Ok(())
    }

    #[test]
    fn labelled_mac_is_hmac_over_label_then_context_unframed() -> Result<()> {
        let key = [7_u8; 32];
        let a = hmac_sha256(&key, Label::LinkHs1, &[b"ab", b"c"])?;
        let b = hmac_sha256(&key, Label::LinkHs1, &[b"abc"])?;
        let by_hand: [u8; 32] = hmac_parts(&key, &[b"SecMP-LINK/1 hs1", b"abc"])?
            .finalize()
            .into_bytes()
            .into();
        assert_eq!(a, b);
        assert_eq!(a, by_hand);
        assert_ne!(a, hmac_sha256(&key, Label::LinkHs2, &[b"abc"])?);
        assert_ne!(a, hmac_sha256(&[8; 32], Label::LinkHs1, &[b"abc"])?);
        Ok(())
    }

    #[test]
    fn verify_accepts_only_the_tag() -> Result<()> {
        let key = [9_u8; 32];
        let tag = hmac_sha256(&key, Label::QToken, &[b"x"])?;
        assert!(bool::from(hmac_sha256_verify(
            &key,
            Label::QToken,
            &[b"x"],
            &tag
        )?));
        for i in [0, 15, 31] {
            let mut bad = tag;
            if let Some(b) = bad.get_mut(i) {
                *b ^= 1;
            }
            assert!(!bool::from(hmac_sha256_verify(
                &key,
                Label::QToken,
                &[b"x"],
                &bad
            )?));
        }
        assert!(!bool::from(hmac_sha256_verify(
            &key,
            Label::QToken,
            &[b"y"],
            &tag
        )?));
        Ok(())
    }
}
