// SPDX-License-Identifier: AGPL-3.0-or-later
//! Plain XChaCha20-Poly1305 (spec §3 table, "AEAD (headers, frames, …)": 24-byte nonce, 16-byte tag) for the uses
//! the spec leaves without the committing wrapper: ratchet headers (§7.3 `hdr_ct = XChaCha20-Poly1305.Seal(hk_s,
//! hdr_nonce, AD, encode(header))`, §7.4, §7.5) and link frames (§8.4). Their keys come from an authenticated
//! handshake, so no commitment is needed (§3.4, last sentence); every other AEAD use is [`crate::Caead`].
//!
//! - [`Aead::seal`] returns `C ‖ tag` (`|P| + 16` bytes) and consumes the nonce.
//! - [`Aead::open`] returns the plaintext in a zeroizing buffer, or the uniform [`Error::Rejected`].
//! - [`Aead::open_ct`] is the opening for trial decryption (spec §7.4 header keys, CLAUDE.md §5): the verdict is a
//!   [`Choice`], and after the AEAD call nothing depends on it — `out` is written in either case (the plaintext,
//!   or zeros selected with [`ConditionallySelectable`]). The AEAD itself verifies the tag before it decrypts
//!   (test `the_aead_verifies_before_it_decrypts`), so an opening costs one keystream pass more than a rejection;
//!   a trial decryption that opens under *every* candidate key (spec §7.4) therefore does the same total work
//!   whichever key opens.

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroizing;

use crate::caead::{AEAD_TAG_LEN, NONCE_LEN};
use crate::error::{Error, Result};
use crate::nonce::Nonce24;
use crate::secret::SecretBytes;

/// The keyed AEAD.
fn cipher(k: &SecretBytes<32>) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(k.expose_secret().into())
}

/// Plain XChaCha20-Poly1305 (spec §3 table; ratchet headers §7.3/§7.5, link frames §8.4). No commitment (§3.4).
pub struct Aead;

impl Aead {
    /// `XChaCha20-Poly1305.Seal(K, N, AD, P)` → `C ‖ tag` (`|P| + 16` bytes). The nonce is consumed; transmit
    /// `nonce.as_bytes()`, read before.
    ///
    /// # Errors
    /// [`Error::Rejected`] only if the AEAD refuses the length (more than 2^38 bytes; unreachable in practice).
    pub fn seal(k: &SecretBytes<32>, nonce: Nonce24, ad: &[u8], p: &[u8]) -> Result<Vec<u8>> {
        let n = nonce.into_bytes();
        let mut out = Vec::with_capacity(p.len().saturating_add(AEAD_TAG_LEN));
        out.extend_from_slice(p);
        let tag = cipher(k)
            .encrypt_inout_detached(&XNonce::from(n), ad, out.as_mut_slice().into())
            .map_err(|_| Error::Rejected)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// `XChaCha20-Poly1305.Open(K, N, AD, C ‖ tag)`; the plaintext is zeroized on drop.
    ///
    /// # Errors
    /// [`Error::Rejected`] — uniformly — if `c` is shorter than a tag or the tag does not verify.
    pub fn open(
        k: &SecretBytes<32>,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        c: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let tag_at = c.len().checked_sub(AEAD_TAG_LEN).ok_or(Error::Rejected)?;
        let (ct, tag) = c.split_at(tag_at);
        let tag = Tag::try_from(tag).map_err(|_| Error::Rejected)?;
        let mut buf = Zeroizing::new(ct.to_vec());
        cipher(k)
            .decrypt_inout_detached(&XNonce::from(*nonce), ad, buf.as_mut_slice().into(), &tag)
            .map_err(|_| Error::Rejected)?;
        Ok(buf)
    }

    /// Constant-work opening for trial decryption (spec §7.4; CLAUDE.md §5): opens `c = C ‖ tag` into `out` and
    /// returns whether the tag verified, as a [`Choice`].
    ///
    /// - If `c.len() != out.len() + 16` it returns `Choice(0)` and leaves `out` untouched (lengths are public: a
    ///   header has exactly one length, spec §7.5).
    /// - Otherwise `out` receives the plaintext if the tag verified and zeros if it did not; the zeros are selected
    ///   byte by byte with [`ConditionallySelectable`], so after the AEAD call there is no branch on the outcome.
    ///
    /// The caller combines the result with its other `Choice`s and converts to `bool` once, at its final decision
    /// (docs/06 §9).
    #[must_use]
    pub fn open_ct(
        k: &SecretBytes<32>,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        c: &[u8],
        out: &mut [u8],
    ) -> Choice {
        let Some((ct, tag)) = c.split_at_checked(out.len()) else {
            return Choice::from(0);
        };
        let Ok(tag) = Tag::try_from(tag) else {
            return Choice::from(0);
        };
        out.copy_from_slice(ct);
        let opened = cipher(k)
            .decrypt_inout_detached(&XNonce::from(*nonce), ad, (&mut *out).into(), &tag)
            .is_ok();
        let ok = Choice::from(u8::from(opened));
        // a rejected tag leaves the ciphertext in `out`: replace it by zeros without branching on the verdict
        let rejected = !ok;
        for b in out.iter_mut() {
            b.conditional_assign(&0, rejected);
        }
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{hex, unhex};

    fn key(b: u8) -> Result<SecretBytes<32>> {
        SecretBytes::from_slice(&[b; 32])
    }

    /// draft-irtf-cfrg-xchacha-03 §A.3.1 (`AEAD_XChaCha20_Poly1305`); the same bytes are Wycheproof
    /// `xchacha20_poly1305_test.json` tcId 1 ("draft-arciszewski-xchacha-02", the draft's earlier name).
    const A31_KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const A31_IV: &str = "404142434445464748494a4b4c4d4e4f5051525354555657";
    const A31_AAD: &str = "50515253c0c1c2c3c4c5c6c7";
    const A31_PLAINTEXT: &[u8] =
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for \
the future, sunscreen would be it.";
    const A31_CT: &str = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3\
a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921\
f9664c97637da9768812f615c68b13b52e";
    const A31_TAG: &str = "c0875924c1c7987947deafd8780acf49";

    struct A31 {
        key: SecretBytes<32>,
        nonce: [u8; NONCE_LEN],
        aad: Vec<u8>,
        sealed: Vec<u8>,
    }

    fn a31() -> Result<A31> {
        let nonce: [u8; NONCE_LEN] = unhex(A31_IV)
            .unwrap_or_default()
            .try_into()
            .map_err(|_| Error::Rejected)?;
        let mut sealed = unhex(A31_CT).unwrap_or_default();
        sealed.extend_from_slice(&unhex(A31_TAG).unwrap_or_default());
        Ok(A31 {
            key: SecretBytes::from_slice(&unhex(A31_KEY).unwrap_or_default())?,
            nonce,
            aad: unhex(A31_AAD).unwrap_or_default(),
            sealed,
        })
    }

    #[test]
    fn draft_xchacha_a31_opens() -> Result<()> {
        let v = a31()?;
        assert_eq!(A31_PLAINTEXT.len(), 114);
        assert_eq!(v.sealed.len(), 114 + AEAD_TAG_LEN);
        let opened = Aead::open(&v.key, &v.nonce, &v.aad, &v.sealed)?;
        assert_eq!(opened.as_slice(), A31_PLAINTEXT);
        let mut out = [0xaa_u8; 114];
        let ok = Aead::open_ct(&v.key, &v.nonce, &v.aad, &v.sealed, &mut out);
        assert!(bool::from(ok));
        assert_eq!(&out[..], A31_PLAINTEXT);
        Ok(())
    }

    /// Sealing with the vector's fixed nonce needs `Nonce24::from_bytes_kat` (feature `kat`).
    #[cfg(feature = "kat")]
    #[test]
    fn draft_xchacha_a31_seals() -> Result<()> {
        let v = a31()?;
        let sealed = Aead::seal(
            &v.key,
            Nonce24::from_bytes_kat(v.nonce),
            &v.aad,
            A31_PLAINTEXT,
        )?;
        assert_eq!(hex(&sealed), hex(&v.sealed));
        Ok(())
    }

    /// `seal` is the pinned crate's XChaCha20-Poly1305 with the tag appended (a random nonce), and `open`/`open_ct`
    /// invert it.
    #[test]
    fn seal_is_the_crate_aead_and_round_trips() -> Result<()> {
        let n = Nonce24::random()?;
        let nb = *n.as_bytes();
        let sealed = Aead::seal(&key(9)?, n, b"assoc", b"payload")?;
        assert_eq!(sealed.len(), 7 + AEAD_TAG_LEN);
        let aead = XChaCha20Poly1305::new_from_slice(&[9; 32]).map_err(|_| Error::Rejected)?;
        let mut buf = b"payload".to_vec();
        let tag = aead
            .encrypt_inout_detached(&XNonce::from(nb), b"assoc", buf.as_mut_slice().into())
            .map_err(|_| Error::Rejected)?;
        buf.extend_from_slice(&tag);
        assert_eq!(hex(&sealed), hex(&buf));
        assert_eq!(
            Aead::open(&key(9)?, &nb, b"assoc", &sealed)?.as_slice(),
            b"payload"
        );
        let mut out = [0_u8; 7];
        assert!(bool::from(Aead::open_ct(
            &key(9)?,
            &nb,
            b"assoc",
            &sealed,
            &mut out
        )));
        assert_eq!(&out, b"payload");
        Ok(())
    }

    /// The empty plaintext seals to the tag alone and opens to nothing; its tag is still checked.
    #[test]
    fn empty_plaintext() -> Result<()> {
        let n = Nonce24::random()?;
        let nb = *n.as_bytes();
        let sealed = Aead::seal(&key(1)?, n, b"ad", b"")?;
        assert_eq!(sealed.len(), AEAD_TAG_LEN);
        assert!(Aead::open(&key(1)?, &nb, b"ad", &sealed)?.is_empty());
        assert!(bool::from(Aead::open_ct(
            &key(1)?,
            &nb,
            b"ad",
            &sealed,
            &mut []
        )));
        let mut bad = sealed.clone();
        if let Some(b) = bad.first_mut() {
            *b ^= 1;
        }
        assert_eq!(
            Aead::open(&key(1)?, &nb, b"ad", &bad).err(),
            Some(Error::Rejected)
        );
        assert!(!bool::from(Aead::open_ct(
            &key(1)?,
            &nb,
            b"ad",
            &bad,
            &mut []
        )));
        Ok(())
    }

    /// Asserts that `c` is rejected by `open` and by `open_ct`, and that `open_ct` leaves `out` all zero (a
    /// ciphertext of the right length) or untouched (any other length).
    fn assert_rejected(
        k: &SecretBytes<32>,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        c: &[u8],
        what: &str,
    ) {
        assert_eq!(
            Aead::open(k, nonce, ad, c).err(),
            Some(Error::Rejected),
            "{what}"
        );
        let mut out = [0xaa_u8; 32];
        let ok = Aead::open_ct(k, nonce, ad, c, &mut out);
        assert!(!bool::from(ok), "{what}");
        if Some(c.len()) == out.len().checked_add(AEAD_TAG_LEN) {
            assert_eq!(out, [0; 32], "{what}: out is zeroed");
        } else {
            assert_eq!(out, [0xaa; 32], "{what}: out is untouched");
        }
    }

    /// Every failure is the same rejection: a flipped bit in the ciphertext or the tag, a wrong key, nonce or AD,
    /// truncation, extension, an input shorter than a tag.
    #[test]
    fn every_failure_is_the_same_rejection() -> Result<()> {
        let n = Nonce24::random()?;
        let nb = *n.as_bytes();
        let k = key(2)?;
        let sealed = Aead::seal(&k, n, b"ad", &[7; 32])?;
        assert_eq!(sealed.len(), 48);
        for (i, what) in [
            (0, "ciphertext, first byte"),
            (31, "ciphertext, last byte"),
            (32, "tag, first byte"),
            (47, "tag, last byte"),
        ] {
            let mut bad = sealed.clone();
            if let Some(b) = bad.get_mut(i) {
                *b ^= 1;
            }
            assert_rejected(&k, &nb, b"ad", &bad, what);
        }
        assert_rejected(&k, &nb, b"aD", &sealed, "AD");
        assert_rejected(&k, &nb, b"", &sealed, "empty AD");
        assert_rejected(&key(3)?, &nb, b"ad", &sealed, "key");
        let mut other = nb;
        other[23] ^= 0x80;
        assert_rejected(&k, &other, b"ad", &sealed, "nonce");
        let short = sealed.split_last().map_or(&[][..], |(_, r)| r);
        assert_rejected(&k, &nb, b"ad", short, "truncated");
        let mut long = sealed.clone();
        long.push(0);
        assert_rejected(&k, &nb, b"ad", &long, "extended");
        assert_rejected(
            &k,
            &nb,
            b"ad",
            sealed.get(..15).unwrap_or_default(),
            "15 bytes",
        );
        assert_rejected(&k, &nb, b"ad", &[], "empty");
        // a wrong-length input whose own tag is valid: a 31-byte plaintext sealed and opened into 32 bytes
        let n = Nonce24::random()?;
        let nb31 = *n.as_bytes();
        let sealed31 = Aead::seal(&k, n, b"ad", &[7; 31])?;
        assert!(Aead::open(&k, &nb31, b"ad", &sealed31).is_ok());
        let mut out = [0xaa_u8; 32];
        assert!(!bool::from(Aead::open_ct(
            &k, &nb31, b"ad", &sealed31, &mut out
        )));
        assert_eq!(out, [0xaa; 32], "a valid ciphertext of another length");
        Ok(())
    }

    /// `open_ct` with an `out` that does not match the ciphertext length (too short, too long) returns 0 and
    /// leaves `out` untouched, even for an authentic ciphertext.
    #[test]
    fn open_ct_needs_the_exact_out_length() -> Result<()> {
        let n = Nonce24::random()?;
        let nb = *n.as_bytes();
        let k = key(4)?;
        let sealed = Aead::seal(&k, n, b"", &[5; 20])?;
        let mut short = [0xaa_u8; 19];
        assert!(!bool::from(Aead::open_ct(
            &k, &nb, b"", &sealed, &mut short
        )));
        assert_eq!(short, [0xaa; 19]);
        let mut long = [0xaa_u8; 21];
        assert!(!bool::from(Aead::open_ct(&k, &nb, b"", &sealed, &mut long)));
        assert_eq!(long, [0xaa; 21]);
        let mut all = [0xaa_u8; 36];
        assert!(!bool::from(Aead::open_ct(&k, &nb, b"", &sealed, &mut all)));
        assert_eq!(all, [0xaa; 36]);
        let mut exact = [0xaa_u8; 20];
        assert!(bool::from(Aead::open_ct(&k, &nb, b"", &sealed, &mut exact)));
        assert_eq!(exact, [5; 20]);
        Ok(())
    }

    /// The property the module documentation relies on: the pinned `chacha20poly1305` checks the tag before it
    /// applies the keystream, so a rejected opening leaves the ciphertext in the buffer (which `open_ct` then
    /// replaces by zeros).
    #[test]
    fn the_aead_verifies_before_it_decrypts() -> Result<()> {
        let n = Nonce24::random()?;
        let nb = *n.as_bytes();
        let sealed = Aead::seal(&key(6)?, n, b"", &[0x33; 64])?;
        let (ct, tag) = sealed.split_at(64);
        let mut tag = Tag::try_from(tag).map_err(|_| Error::Rejected)?;
        if let Some(b) = tag.first_mut() {
            *b ^= 1;
        }
        let mut buf = ct.to_vec();
        let r = cipher(&key(6)?).decrypt_inout_detached(
            &XNonce::from(nb),
            b"",
            buf.as_mut_slice().into(),
            &tag,
        );
        assert!(r.is_err());
        assert_eq!(buf, ct, "the buffer still holds the ciphertext");
        Ok(())
    }
}
