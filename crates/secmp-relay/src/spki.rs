// SPDX-License-Identifier: AGPL-3.0-or-later
//! The pin of the direct listener's certificate (`docs/05` §7, spec D.3 `spki_sha256`; OPEN-M6-09 A; TEST-SPEC-M6
//! TLS-15): SHA-256 of the DER of the certificate's `SubjectPublicKeyInfo`, which clients compare against
//! `RelayRef.direct.spki_sha256`. `secmp-relay spki <cert.der>` prints it. No TLS crate is needed for this, so the
//! command is part of the default (std-only) build.
//!
//! The DER walk is the same as the client's (`secmp_transport::tls::spki_of`; the relay may not depend on the
//! transport crate, `docs/02` §3); the testkit cross-checks the two on generated and mutated certificates.

use secmp_proto::sizes::HASH_LEN;

/// One DER element: (tag, the whole element, its content, the bytes after it).
type Tlv<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

/// One DER element at the start of `input`. Definite lengths only, at most three length bytes, minimal length
/// encoding, single-byte tags; anything else is `None`.
fn tlv(input: &[u8]) -> Option<Tlv<'_>> {
    let (&tag, after_tag) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, after_len) = after_tag.split_first()?;
    let (len, len_bytes) = if first < 0x80 {
        (usize::from(first), 0_usize)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 3 {
            return None;
        }
        let bytes = after_len.get(..n)?;
        let mut len = 0_usize;
        for b in bytes {
            len = len.checked_mul(256)?.checked_add(usize::from(*b))?;
        }
        // DER: the shortest form (no leading zero byte, long form only from 128 on)
        if bytes.first() == Some(&0) || len < 0x80 {
            return None;
        }
        (len, n)
    };
    let header = len_bytes.checked_add(2)?;
    let total = header.checked_add(len)?;
    let element = input.get(..total)?;
    let content = element.get(header..)?;
    let rest = input.get(total..)?;
    Some((tag, element, content, rest))
}

/// The DER of the `SubjectPublicKeyInfo` of an X.509 certificate (RFC 5280 §4.1: the seventh element of
/// `tbsCertificate` when `version` is present, the sixth otherwise); `None` unless `cert` is exactly one well-formed
/// certificate up to that field.
#[must_use]
pub fn spki_of(cert: &[u8]) -> Option<&[u8]> {
    let (0x30, _, certificate, []) = tlv(cert)? else {
        return None;
    };
    let (0x30, _, tbs, _) = tlv(certificate)? else {
        return None;
    };
    let mut rest = tbs;
    // [0] EXPLICIT version, optional
    if rest.first() == Some(&0xa0) {
        rest = tlv(rest)?.3;
    }
    // serialNumber INTEGER, signature AlgorithmIdentifier, issuer Name, validity, subject Name
    for want in [0x02_u8, 0x30, 0x30, 0x30, 0x30] {
        let (tag, _, _, next) = tlv(rest)?;
        if tag != want {
            return None;
        }
        rest = next;
    }
    let (0x30, spki, _, _) = tlv(rest)? else {
        return None;
    };
    Some(spki)
}

/// The pin of `cert`: SHA-256 of its SPKI DER; `None` if `cert` is not a certificate [`spki_of`] can read.
#[must_use]
pub fn pin_of(cert: &[u8]) -> Option<[u8; HASH_LEN]> {
    spki_of(cert).map(|spki| secmp_crypto::sha256(&[spki]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let n = content.len();
        let mut out = vec![tag];
        if n < 0x80 {
            out.push(u8::try_from(n).unwrap_or(0));
        } else if n < 0x100 {
            out.extend([0x81, u8::try_from(n).unwrap_or(0)]);
        } else {
            out.extend([
                0x82,
                u8::try_from(n >> 8).unwrap_or(0),
                u8::try_from(n & 0xff).unwrap_or(0),
            ]);
        }
        out.extend_from_slice(content);
        out
    }

    fn seq(parts: &[&[u8]]) -> Vec<u8> {
        der(0x30, &parts.concat())
    }

    /// An Ed25519 certificate's structure (the walk does not verify the signature).
    fn cert(version: bool) -> (Vec<u8>, Vec<u8>) {
        let alg = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
        let name = seq(&[&der(
            0x31,
            &seq(&[&[0x06, 0x03, 0x55, 0x04, 0x03], &der(0x0c, b"relay")]),
        )]);
        let validity = seq(&[&der(0x17, b"200101000000Z"), &der(0x17, b"491231235959Z")]);
        let spki = seq(&[&alg, &der(0x03, &[[0_u8].as_slice(), &[0x42; 32]].concat())]);
        let mut tbs: Vec<&[u8]> = Vec::new();
        let v = der(0xa0, &[0x02, 0x01, 0x02]);
        if version {
            tbs.push(&v);
        }
        let serial = [0x02, 0x01, 0x01];
        tbs.extend([serial.as_slice(), &alg, &name, &validity, &name, &spki]);
        let tbs = seq(&tbs);
        let sig = der(0x03, &[0_u8; 65]);
        (seq(&[&tbs, &alg, &sig]), spki)
    }

    #[test]
    fn spki_is_found_with_and_without_version() {
        for version in [true, false] {
            let (c, spki) = cert(version);
            assert_eq!(spki_of(&c), Some(spki.as_slice()));
            assert_eq!(pin_of(&c), Some(secmp_crypto::sha256(&[&spki])));
        }
    }

    #[test]
    fn malformed_certificates_have_no_pin() {
        let (c, _) = cert(true);
        // trailing bytes, truncation at every length, a non-minimal length, a multi-byte tag
        let mut trailing = c.clone();
        trailing.push(0);
        assert_eq!(spki_of(&trailing), None);
        for n in 0..c.len() {
            assert_eq!(spki_of(c.get(..n).unwrap_or_default()), None, "{n}");
        }
        assert_eq!(tlv(&[0x30, 0x81, 0x05, 0, 0, 0, 0, 0]), None);
        assert_eq!(tlv(&[0x30, 0x82, 0x00, 0x80]), None);
        assert_eq!(tlv(&[0x1f, 0x00]), None);
        assert_eq!(tlv(&[0x30, 0x84, 0, 0, 0, 1, 0]), None);
        assert_eq!(tlv(&[0x30, 0x80]), None);
        assert_eq!(
            tlv(&[0x30, 0x00]),
            Some((0x30, [0x30, 0].as_slice(), [].as_slice(), [].as_slice()))
        );
        assert_eq!(pin_of(b""), None);
    }

    /// The length forms at their bounds: short form up to 127, long form from 128 on, `0x80` (BER's indefinite form)
    /// refused even with 128 bytes after it, three length bytes the most (65 536 content bytes pass, a four-byte length
    /// of 16 MiB does not).
    #[test]
    fn tlv_length_forms_at_their_bounds() {
        let short = [&[0x04, 0x7f][..], &[0; 0x7f]].concat();
        assert_eq!(tlv(&short).map(|t| t.2.len()), Some(0x7f));
        let long = [&[0x04, 0x81, 0x80][..], &[0; 0x80]].concat();
        assert_eq!(tlv(&long).map(|t| t.2.len()), Some(0x80));
        let indefinite = [&[0x04, 0x80][..], &[0; 0x80]].concat();
        assert_eq!(tlv(&indefinite), None);
        let three = [&[0x04, 0x83, 0x01, 0x00, 0x00][..], &vec![0; 0x1_0000]].concat();
        assert_eq!(tlv(&three).map(|t| t.2.len()), Some(0x1_0000));
        let four = [
            &[0x04, 0x84, 0x01, 0x00, 0x00, 0x00][..],
            &vec![0; 0x100_0000],
        ]
        .concat();
        assert_eq!(tlv(&four), None);
    }
}
