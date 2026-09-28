// SPDX-License-Identifier: AGPL-3.0-or-later
//! HKDF-SHA-256 (RFC 5869) with the label discipline of spec §3: every `info` begins with a label of Appendix A,
//! followed by the call site's context bytes without framing. The helpers take a [`Label`], so no other `info`
//! can be formed.

use core::iter;

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::label::Label;
use crate::secret::SecretBytes;

/// The largest HKDF-SHA-256 output (255 · 32 bytes, RFC 5869 §2.3).
pub const HKDF_MAX_LEN: usize = 8160;

fn expand_into(hk: &Hkdf<Sha256>, label: Label, context: &[&[u8]], okm: &mut [u8]) -> Result<()> {
    let info: Vec<&[u8]> = iter::once(label.as_bytes())
        .chain(context.iter().copied())
        .collect();
    hk.expand_multi_info(&info, okm)
        .map_err(|_| Error::Rejected)
}

/// `HKDF-SHA-256(salt, ikm, info = label ‖ context[0] ‖ context[1] ‖ …, L)`. An empty `salt` equals
/// `0^32` (RFC 5869 §2.2), which is how the spec's `salt = 0^32` call sites are written.
///
/// # Errors
/// [`Error::Rejected`] if `L` exceeds [`HKDF_MAX_LEN`].
pub fn hkdf<const L: usize>(
    salt: &[u8],
    ikm: &[u8],
    label: Label,
    context: &[&[u8]],
) -> Result<SecretBytes<L>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = SecretBytes::<L>::zero();
    expand_into(&hk, label, context, okm.expose_secret_mut())?;
    Ok(okm)
}

/// `HKDF-Expand(PRK = prk, info = label ‖ context…, L)` without the extract step (spec §3.4 CAEAD, §8.3).
///
/// # Errors
/// [`Error::Rejected`] if `prk` is shorter than 32 bytes or `L` exceeds [`HKDF_MAX_LEN`].
pub fn hkdf_expand<const L: usize>(
    prk: &[u8],
    label: Label,
    context: &[&[u8]],
) -> Result<SecretBytes<L>> {
    let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| Error::Rejected)?;
    let mut okm = SecretBytes::<L>::zero();
    expand_into(&hk, label, context, okm.expose_secret_mut())?;
    Ok(okm)
}

/// Variable-length HKDF for known-answer tests and the `hkdf-labels` vector suite (feature `kat`):
/// `expand_only = false` is [`hkdf`], `true` is [`hkdf_expand`] with `PRK = ikm` (then `salt` must be empty).
///
/// # Errors
/// [`Error::Rejected`] as for [`hkdf`] / [`hkdf_expand`], or if `expand_only` is set with a non-empty salt.
#[cfg(feature = "kat")]
pub fn hkdf_kat(
    salt: &[u8],
    ikm: &[u8],
    label: Label,
    extra_info: &[u8],
    len: usize,
    expand_only: bool,
) -> Result<Vec<u8>> {
    let hk = if expand_only {
        if !salt.is_empty() {
            return Err(Error::Rejected);
        }
        Hkdf::<Sha256>::from_prk(ikm).map_err(|_| Error::Rejected)?
    } else {
        Hkdf::<Sha256>::new(Some(salt), ikm)
    };
    let mut okm = vec![0; len];
    expand_into(&hk, label, &[extra_info], &mut okm)?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::hex;

    #[test]
    fn empty_salt_equals_zero_salt() -> Result<()> {
        let a = hkdf::<76>(&[], b"ikm", Label::TrMsgkeys, &[])?;
        let b = hkdf::<76>(&[0; 32], b"ikm", Label::TrMsgkeys, &[])?;
        assert_eq!(a.expose_secret(), b.expose_secret());
        Ok(())
    }

    #[test]
    fn info_is_label_then_context_unframed() -> Result<()> {
        let a = hkdf::<32>(b"s", b"k", Label::HxSk, &[b"ab", b"c"])?;
        let b = hkdf::<32>(b"s", b"k", Label::HxSk, &[b"abc"])?;
        let c = hkdf::<32>(b"s", b"k", Label::HxSk, &[])?;
        let d = hkdf::<32>(b"s", b"k", Label::HxIdkey, &[b"abc"])?;
        assert_eq!(a.expose_secret(), b.expose_secret());
        assert_ne!(a.expose_secret(), c.expose_secret());
        assert_ne!(a.expose_secret(), d.expose_secret());
        Ok(())
    }

    /// RFC 5869 A.1 with the info replaced by a label: recomputed with an independent composition of HMAC
    /// (extract, then T(1) = HMAC(PRK, info ‖ 0x01)).
    #[test]
    fn matches_manual_hmac_composition() -> Result<()> {
        use hmac::{Hmac, KeyInit, Mac};
        let salt = [0x0b_u8; 13];
        let ikm = [0x0c_u8; 22];
        let mut ext =
            <Hmac<Sha256> as KeyInit>::new_from_slice(&salt).map_err(|_| Error::Rejected)?;
        ext.update(&ikm);
        let prk: [u8; 32] = ext.finalize().into_bytes().into();
        let mut t1 =
            <Hmac<Sha256> as KeyInit>::new_from_slice(&prk).map_err(|_| Error::Rejected)?;
        t1.update(Label::TrRk.as_bytes());
        t1.update(b"ctx");
        t1.update(&[1]);
        let t1: [u8; 32] = t1.finalize().into_bytes().into();
        let okm = hkdf::<32>(&salt, &ikm, Label::TrRk, &[b"ctx"])?;
        assert_eq!(hex(okm.expose_secret()), hex(&t1));
        let okm2 = hkdf_expand::<32>(&prk, Label::TrRk, &[b"ctx"])?;
        assert_eq!(okm2.expose_secret(), &t1);
        Ok(())
    }

    #[test]
    fn length_limits() {
        assert!(hkdf::<HKDF_MAX_LEN>(b"", b"", Label::HxSk, &[]).is_ok());
        assert_eq!(
            hkdf::<{ HKDF_MAX_LEN + 1 }>(b"", b"", Label::HxSk, &[]).err(),
            Some(Error::Rejected)
        );
        assert_eq!(
            hkdf_expand::<32>(&[0; 31], Label::Commit, &[]).err(),
            Some(Error::Rejected)
        );
        assert!(hkdf_expand::<64>(&[0; 32], Label::Commit, &[&[0; 24]]).is_ok());
    }
}
