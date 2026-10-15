// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Test certificates of the direct-mode rows (TEST-SPEC-M6 TLS-01…TLS-15): Ed25519 X.509 v3 certificates and their
//! PKCS#8 keys built in code (no `rcgen`, OPEN-M6-09 A; no `openssl` at test time), signed with `secmp-crypto`'s
//! Ed25519. No TLS crate is needed to build them; the TLS fixtures of `secmp-transport` load them into rustls.

use secmp_crypto::Ed25519SigningKey;

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(u8::try_from(n).unwrap());
    } else if n < 0x100 {
        out.extend([0x81, u8::try_from(n).unwrap()]);
    } else {
        out.extend([
            0x82,
            u8::try_from(n >> 8).unwrap(),
            u8::try_from(n & 0xff).unwrap(),
        ]);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    der(0x30, &parts.concat())
}

/// `AlgorithmIdentifier { id-Ed25519 }` (RFC 8410).
const ED25519_ALG: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

fn name(cn: &str) -> Vec<u8> {
    let atv = seq(&[&[0x06, 0x03, 0x55, 0x04, 0x03], &der(0x0c, cn.as_bytes())]);
    seq(&[&der(0x31, &atv)])
}

/// A certificate's validity window, as `UTCTime` strings (`YYMMDDHHMMSSZ`).
#[derive(Clone, Copy, Debug)]
pub struct Validity {
    /// `notBefore`.
    pub not_before: &'static str,
    /// `notAfter`.
    pub not_after: &'static str,
}

/// 2020 to 2049: valid at any test date.
pub const VALID: Validity = Validity {
    not_before: "200101000000Z",
    not_after: "491231235959Z",
};
/// Ended in 2002.
pub const EXPIRED: Validity = Validity {
    not_before: "010101000000Z",
    not_after: "021231235959Z",
};
/// Starts in 2045.
pub const NOT_YET: Validity = Validity {
    not_before: "450101000000Z",
    not_after: "491231235959Z",
};

/// An Ed25519 key of a fixture (a fixed seed).
pub struct FixtureKey {
    seed: [u8; 32],
}

impl FixtureKey {
    /// The key of `seed`.
    #[must_use]
    pub const fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    fn signing(&self) -> Ed25519SigningKey {
        Ed25519SigningKey::from_seed(&self.seed).unwrap()
    }

    /// The raw public key.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        *self.signing().verifying_key().as_bytes()
    }

    /// The `SubjectPublicKeyInfo` DER (what the pin hashes).
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn spki(&self) -> Vec<u8> {
        seq(&[
            &ED25519_ALG,
            &der(0x03, &[&[0_u8][..], &self.public()].concat()),
        ])
    }

    /// The pin: SHA-256 of the SPKI DER.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn pin(&self) -> [u8; 32] {
        secmp_crypto::sha256(&[&self.spki()])
    }

    /// The PKCS#8 DER of the key (RFC 8410 §7).
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn pkcs8(&self) -> Vec<u8> {
        seq(&[
            &[0x02, 0x01, 0x00],
            &ED25519_ALG,
            &der(0x04, &der(0x04, &self.seed)),
        ])
    }
}

/// An X.509 v3 certificate for `subject`'s key with common name and DNS name `cn`, signed by `issuer` (whose name is
/// `issuer_cn`), valid over `validity`; `ca` adds `basicConstraints cA`.
///
/// # Panics
/// On a violated harness invariant: a test failure, never a production path.
#[must_use]
pub fn certificate(
    subject: &FixtureKey,
    cn: &str,
    issuer: &FixtureKey,
    issuer_cn: &str,
    validity: Validity,
    ca: bool,
    serial: u8,
) -> Vec<u8> {
    certificate_padded(
        subject,
        issuer,
        (cn, issuer_cn),
        validity,
        (ca, serial),
        None,
    )
}

/// A self-signed certificate of `key` of exactly `len` bytes (EXTB-7), padded with a non-critical private extension
/// (OID 1.3.6.1.4.1.55555.1, an OCTET STRING of zeros); `None` if no padding reaches `len` exactly.
///
/// # Panics
/// On a violated harness invariant: a test failure, never a production path.
#[must_use]
pub fn self_signed_of_len(key: &FixtureKey, cn: &str, len: usize) -> Option<Vec<u8>> {
    (0..len).find_map(|extra| {
        let c = certificate_padded(key, key, (cn, cn), VALID, (false, 1), Some(extra));
        (c.len() == len).then_some(c)
    })
}

/// [`certificate`] with an optional padding extension of `padding` bytes; `names` = (subject, issuer) common names,
/// `kind` = (`ca`, serial).
fn certificate_padded(
    subject: &FixtureKey,
    issuer: &FixtureKey,
    names: (&str, &str),
    validity: Validity,
    kind: (bool, u8),
    padding: Option<usize>,
) -> Vec<u8> {
    let ((cn, issuer_cn), (ca, serial)) = (names, kind);
    let version = der(0xa0, &[0x02, 0x01, 0x02]);
    let validity = seq(&[
        &der(0x17, validity.not_before.as_bytes()),
        &der(0x17, validity.not_after.as_bytes()),
    ]);
    // subjectAltName dNSName = cn; basicConstraints for a CA
    let san = seq(&[
        &[0x06, 0x03, 0x55, 0x1d, 0x11],
        &der(0x04, &seq(&[&der(0x82, cn.as_bytes())])),
    ]);
    let mut exts = vec![san];
    if ca {
        exts.push(seq(&[
            &[0x06, 0x03, 0x55, 0x1d, 0x13],
            &[0x01, 0x01, 0xff],
            &der(0x04, &seq(&[&[0x01, 0x01, 0xff]])),
        ]));
    }
    if let Some(extra) = padding {
        exts.push(seq(&[
            &[
                0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xb2, 0x03, 0x01,
            ],
            &der(0x04, &vec![0_u8; extra]),
        ]));
    }
    let exts: Vec<&[u8]> = exts.iter().map(Vec::as_slice).collect();
    let extensions = der(0xa3, &seq(&exts));
    let tbs = seq(&[
        &version,
        &[0x02, 0x01, serial],
        &ED25519_ALG,
        &name(issuer_cn),
        &validity,
        &name(cn),
        &subject.spki(),
        &extensions,
    ]);
    let sig = issuer.signing().sign(&tbs);
    seq(&[
        &tbs,
        &ED25519_ALG,
        &der(0x03, &[&[0_u8][..], sig.as_ref()].concat()),
    ])
}

/// A self-signed certificate of `key` for `cn`.
///
/// # Panics
/// On a violated harness invariant: a test failure, never a production path.
#[must_use]
pub fn self_signed(key: &FixtureKey, cn: &str, validity: Validity) -> Vec<u8> {
    certificate(key, cn, key, cn, validity, false, 1)
}
