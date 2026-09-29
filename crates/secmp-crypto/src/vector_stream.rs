// SPDX-License-Identifier: AGPL-3.0-or-later
//! The per-case input stream of `vectors/SCHEMA.md` §2 (feature `kat`): `seed_i = SHA-256("SecMP-vectors/1" ‖
//! suite ‖ u32be(i))`, `stream_i = SHAKE-256(seed_i)`, consumed front to back. For the vector generators of the
//! crates that may not use cryptographic crates themselves (`secmp-proto`, M2); never a source of real keys.

use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::hash::sha256;
use crate::label::Label;

/// `stream_i` of a vector suite.
pub struct VectorStream(sha3::Shake256Reader);

impl VectorStream {
    /// `stream_i` of `suite` (the suite name, e.g. `"encodings"`).
    #[must_use]
    pub fn new(suite: &str, i: u32) -> Self {
        let seed = sha256(&[
            Label::Vectors.as_bytes(),
            suite.as_bytes(),
            &i.to_be_bytes(),
        ]);
        let mut h = Shake256::default();
        h.update(&seed);
        Self(h.finalize_xof())
    }

    /// The next `n` bytes.
    #[must_use]
    pub fn take(&mut self, n: usize) -> Vec<u8> {
        let mut out = vec![0; n];
        self.0.read(&mut out);
        out
    }

    /// The next `N` bytes as an array.
    #[must_use]
    pub fn arr<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0; N];
        self.0.read(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stream is SHAKE-256 of the SCHEMA §2 seed, read in any chunking.
    #[test]
    fn matches_the_schema_rule_and_chunking() {
        let mut a = VectorStream::new("encodings", 1);
        let mut b = VectorStream::new("encodings", 1);
        let whole = a.take(64);
        let mut parts = b.arr::<10>().to_vec();
        parts.extend(b.take(54));
        assert_eq!(whole, parts);
        let seed = sha256(&[b"SecMP-vectors/1", b"encodings", &1_u32.to_be_bytes()]);
        let mut h = Shake256::default();
        h.update(&seed);
        let mut expected = [0_u8; 64];
        h.finalize_xof().read(&mut expected);
        assert_eq!(whole, expected);
        assert_ne!(
            VectorStream::new("encodings", 2).take(8),
            whole.get(..8).unwrap_or_default()
        );
    }
}
