// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Where a `two-clients` actor gets its randomness: the deterministic streams of the harness on the `mem` transport (a
//! run is reproducible), the operating system's on every real transport (keys of a run that talks to a real relay are
//! never a function of a name).

use secmp_client_core::scheduler::conversation::{EntropySource, OsSource};
use secmp_client_core::scheduler::run::{HandshakeEntropy, OsHandshakes};
use secmp_client_core::timing::TimingRng;
use secmp_crypto::SecretBytes;

use crate::harness::{EntropyPool, TestHandshakes};

/// One actor's randomness (the content entropy of its conversations and set-up, its link handshakes, its timing).
pub trait Rand: EntropySource<E: Send> + Send + 'static {
    /// The randomness of the link handshakes.
    type Hs: HandshakeEntropy;

    /// The actor `label` (`index` distinguishes runs of one label; the operating system ignores both).
    fn actor(label: &str, index: u32) -> Self;

    /// A fresh 32-byte seed (a queue seed).
    fn seed(&mut self) -> SecretBytes<32>;

    /// The handshake randomness of the actor.
    fn handshakes(label: &str, index: u32) -> Self::Hs;

    /// The timing stream of the actor (`seed` is used by the deterministic streams only).
    fn timing(seed: u64) -> TimingRng;
}

impl Rand for EntropyPool {
    type Hs = TestHandshakes;

    fn actor(label: &str, index: u32) -> Self {
        Self::new(label, index)
    }

    fn seed(&mut self) -> SecretBytes<32> {
        SecretBytes::from_slice(&self.bytes(32)).unwrap()
    }

    fn handshakes(label: &str, index: u32) -> TestHandshakes {
        TestHandshakes::new(label, index)
    }

    fn timing(seed: u64) -> TimingRng {
        TimingRng::seeded(seed)
    }
}

impl Rand for OsSource {
    type Hs = OsHandshakes;

    fn actor(_label: &str, _index: u32) -> Self {
        Self::new()
    }

    fn seed(&mut self) -> SecretBytes<32> {
        SecretBytes::random().unwrap()
    }

    fn handshakes(_label: &str, _index: u32) -> OsHandshakes {
        OsHandshakes
    }

    fn timing(_seed: u64) -> TimingRng {
        TimingRng::os()
    }
}
