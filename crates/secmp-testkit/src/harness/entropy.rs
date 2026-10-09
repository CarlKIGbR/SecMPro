// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Deterministic randomness of the harness (feature `kat`): one pool per actor, filled from the SCHEMA §2 stream
//! (`VectorStream`, SHA3-256 counter mode) of the actor's own suite name, so that the same scenario draws the same
//! bytes in every run (H-10) and no actor's draws move another's.

use secmp_crypto::VectorStream;
use secmp_proto::tr::FixedEntropy;

/// Bytes drawn from the stream per refill.
const REFILL: usize = 2 << 20;
/// A call that needs more than this many bytes at once gets a fresh refill first.
const LOW_WATER: usize = 512 << 10;

/// An [`FixedEntropy`] that refills itself from a deterministic stream when it runs low. The unused tail of a
/// refill is dropped, which is still deterministic: the refill points depend only on the draws made.
pub struct EntropyPool {
    stream: VectorStream,
    entropy: FixedEntropy,
}

impl EntropyPool {
    /// The pool of the stream (`suite`, `index`).
    #[must_use]
    pub fn new(suite: &str, index: u32) -> Self {
        let mut stream = VectorStream::new(suite, index);
        let entropy = FixedEntropy::new(&stream.take(REFILL));
        Self { stream, entropy }
    }

    /// The randomness, refilled first if less than 512 KiB is left.
    pub fn get(&mut self) -> &mut FixedEntropy {
        if self.entropy.remaining() < LOW_WATER {
            self.entropy = FixedEntropy::new(&self.stream.take(REFILL));
        }
        &mut self.entropy
    }

    /// `n` bytes from the stream itself (a seed or an id the scenario chooses), not from the entropy source: they
    /// do not move the draws of the protocol code.
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        self.stream.take(n)
    }
}
