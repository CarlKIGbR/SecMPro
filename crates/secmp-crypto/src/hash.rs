// SPDX-License-Identifier: AGPL-3.0-or-later
//! SHA-256 and SHA3-256 over concatenated parts (spec §3: SHA-256; SHA3-256 in the KEM combiner). Outputs that
//! are secret are written straight into a [`SecretBytes`].

use sha2::{Digest, Sha256};
use sha3::Sha3_256;

use crate::secret::SecretBytes;

/// SHA-256 of `parts[0] ‖ parts[1] ‖ …`.
#[must_use]
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// SHA3-256 of `parts[0] ‖ parts[1] ‖ …`.
#[must_use]
pub fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// SHA3-256 of `parts[0] ‖ parts[1] ‖ …` when the result is a secret (the `HybridKEM` combiner, spec §3.2).
pub(crate) fn sha3_256_secret(parts: &[&[u8]]) -> SecretBytes<32> {
    let mut h = Sha3_256::new();
    for p in parts {
        h.update(p);
    }
    let mut out = SecretBytes::<32>::zero();
    h.finalize_into(out.expose_secret_mut().into());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::hex;

    #[test]
    fn sha256_fips180_vectors() {
        assert_eq!(
            hex(&sha256(&[b"abc"])),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(&[])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // parts are concatenated without framing
        assert_eq!(sha256(&[b"a", b"", b"bc"]), sha256(&[b"abc"]));
    }

    #[test]
    fn sha3_256_fips202_vectors() {
        assert_eq!(
            hex(&sha3_256(&[b"abc"])),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            hex(&sha3_256(&[])),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            sha3_256_secret(&[b"ab", b"c"]).expose_secret(),
            &sha3_256(&[b"abc"])
        );
    }
}
