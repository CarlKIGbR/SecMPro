// SPDX-License-Identifier: AGPL-3.0-or-later
//! Argon2id (RFC 9106 §3, version 0x13) over the `argon2` crate (ADR-055). A primitive wrapper only: no store key
//! hierarchy, no labels and no parameter choice live here (those are ADR-053 and `secmp-store`'s). The output is a
//! [`SecretBytes`]; every failure of the underlying crate — an out-of-range parameter, a salt that is too short or too
//! long, an oversized secret or associated datum — is the one uniform [`Error::Rejected`] (CLAUDE.md §4).
//!
//! The working memory (`m_kib` KiB) is allocated zeroed and freed by the `argon2` crate; the block matrix is not zeroized
//! on drop (the crate zeroizes the initial hash and, in `finalize`, `blockhash`/`blockhash_bytes`), a property recorded with
//! the vet record of `argon2` (ADR-051 Am. 7).

use ::argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};

use crate::error::{Error, Result};
use crate::secret::SecretBytes;

/// Argon2id v0x13 with no secret and no associated data: `Argon2id(P = password, S = salt, p, T = L, m = m_kib KiB,
/// t, v = 0x13)` (RFC 9106 §3.1).
///
/// # Errors
/// [`Error::Rejected`] for any parameter outside the RFC 9106 §3.2 ranges (`m` < 8·`p` KiB, `t` = 0, `p` = 0, `L` < 4,
/// a salt shorter than 8 bytes, …).
pub fn argon2id<const L: usize>(
    password: &[u8],
    salt: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
) -> Result<SecretBytes<L>> {
    derive::<L>(password, salt, m_kib, t, p, &[], &[])
}

/// As [`argon2id`], with the optional secret value `K` and associated data `X` of RFC 9106 §3.1.
///
/// # Errors
/// [`Error::Rejected`] as for [`argon2id`], or if `ad` exceeds 32 bytes or `secret` the crate's limit.
pub fn argon2id_with_secret_and_ad<const L: usize>(
    password: &[u8],
    salt: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
    secret: &[u8],
    ad: &[u8],
) -> Result<SecretBytes<L>> {
    derive::<L>(password, salt, m_kib, t, p, secret, ad)
}

fn derive<const L: usize>(
    password: &[u8],
    salt: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
    secret: &[u8],
    ad: &[u8],
) -> Result<SecretBytes<L>> {
    let mut builder = ParamsBuilder::new();
    builder.m_cost(m_kib).t_cost(t).p_cost(p).output_len(L);
    if !ad.is_empty() {
        builder.data(AssociatedData::new(ad).map_err(|_| Error::Rejected)?);
    }
    let params = builder.build().map_err(|_| Error::Rejected)?;
    let ctx = if secret.is_empty() {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    } else {
        Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params)
            .map_err(|_| Error::Rejected)?
    };
    let mut out = SecretBytes::<L>::zero();
    ctx.hash_password_into(password, salt, out.expose_secret_mut())
        .map_err(|_| Error::Rejected)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::hex;

    /// TEST-SPEC-M7 ST-08, RFC 9106 §5.3 (Argon2id test vector): m = 32 KiB, t = 3, p = 4, T = 32, password 32 × 0x01,
    /// salt 16 × 0x02, secret 8 × 0x03, associated data 12 × 0x04.
    #[test]
    fn rfc9106_argon2id_vector() -> Result<()> {
        let tag = argon2id_with_secret_and_ad::<32>(
            &[0x01; 32],
            &[0x02; 16],
            32,
            3,
            4,
            &[0x03; 8],
            &[0x04; 12],
        )?;
        assert_eq!(
            hex(tag.expose_secret()),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
        // the secret and the associated data are part of the input: without either the tag is another one
        let no_ad =
            argon2id_with_secret_and_ad::<32>(&[0x01; 32], &[0x02; 16], 32, 3, 4, &[0x03; 8], &[])?;
        let no_secret = argon2id_with_secret_and_ad::<32>(
            &[0x01; 32],
            &[0x02; 16],
            32,
            3,
            4,
            &[],
            &[0x04; 12],
        )?;
        let neither = argon2id::<32>(&[0x01; 32], &[0x02; 16], 32, 3, 4)?;
        assert_ne!(no_ad.expose_secret(), tag.expose_secret());
        assert_ne!(no_secret.expose_secret(), tag.expose_secret());
        assert_ne!(neither.expose_secret(), tag.expose_secret());
        Ok(())
    }

    /// `argon2id` is the case of an empty secret and empty associated data, and every input and parameter moves the tag
    /// (so no constant or truncated result passes).
    #[test]
    fn argon2id_is_the_empty_secret_and_ad_case_and_every_input_counts() -> Result<()> {
        let base = argon2id::<32>(b"password", &[0x02; 16], 32, 2, 2)?;
        let same = argon2id_with_secret_and_ad::<32>(b"password", &[0x02; 16], 32, 2, 2, &[], &[])?;
        assert_eq!(base.expose_secret(), same.expose_secret());
        assert_ne!(base.expose_secret(), &[0_u8; 32]);
        let short = argon2id::<16>(b"password", &[0x02; 16], 32, 2, 2)?;
        assert_ne!(
            short.expose_secret().as_slice(),
            base.expose_secret().get(..16).unwrap_or_default()
        );
        for (what, other) in [
            (
                "password",
                argon2id::<32>(b"passwore", &[0x02; 16], 32, 2, 2)?,
            ),
            ("salt", argon2id::<32>(b"password", &[0x03; 16], 32, 2, 2)?),
            ("m", argon2id::<32>(b"password", &[0x02; 16], 40, 2, 2)?),
            ("t", argon2id::<32>(b"password", &[0x02; 16], 32, 3, 2)?),
            ("p", argon2id::<32>(b"password", &[0x02; 16], 32, 2, 1)?),
        ] {
            assert_ne!(base.expose_secret(), other.expose_secret(), "{what}");
        }
        Ok(())
    }

    /// Parameters outside RFC 9106 §3.2 are the uniform rejection: `m` below 8·`p` KiB, `t` = 0, `p` = 0, a salt of 7
    /// bytes, an output of 3 bytes, associated data of 33 bytes.
    #[test]
    fn argon2id_rejects_out_of_range_params() {
        let pw = [0x01_u8; 8];
        let salt = [0x02_u8; 16];
        assert!(argon2id::<32>(&pw, &salt, 32, 1, 4).is_ok());
        assert!(
            argon2id::<32>(&pw, &salt, 8, 1, 1).is_ok(),
            "m = 8 p is the minimum"
        );
        for (what, r) in [
            ("m < 8p", argon2id::<32>(&pw, &salt, 31, 1, 4)),
            ("m = 0", argon2id::<32>(&pw, &salt, 0, 1, 1)),
            ("t = 0", argon2id::<32>(&pw, &salt, 32, 0, 4)),
            ("p = 0", argon2id::<32>(&pw, &salt, 32, 1, 0)),
            ("salt 7 B", argon2id::<32>(&pw, &salt[..7], 32, 1, 4)),
        ] {
            assert_eq!(r.err(), Some(Error::Rejected), "{what}");
        }
        assert_eq!(
            argon2id::<3>(&pw, &salt, 32, 1, 4).err(),
            Some(Error::Rejected),
            "output 3 B"
        );
        let long_ad = argon2id_with_secret_and_ad::<32>(&pw, &salt, 32, 1, 4, &[], &[0x04; 33]);
        assert_eq!(long_ad.err(), Some(Error::Rejected), "ad 33 B");
    }
}
