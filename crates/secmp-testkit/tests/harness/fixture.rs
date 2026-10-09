// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared set-up of the harness tests: a relay with one connected client, seeds, blobs and a scripted relay.

use secmp_crypto::SecretBytes;
use secmp_proto::Decode;
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::inv::LinkBlob;
use secmp_testkit::harness::{ClientId, EntropyPool, Harness, HarnessConfig, HarnessStream};
use secmp_transport::RelayQueueTransport;

use crate::scripted::{self, Script, Scripted};

/// A harness with client `a`, connected.
pub struct Rig {
    pub h: Harness,
    pub a: ClientId,
}

pub fn rig() -> Rig {
    let mut h = Harness::new(HarnessConfig::default());
    let a = h.add_client();
    h.connect(a).unwrap();
    Rig { h, a }
}

impl Rig {
    /// The link of client `c` and its randomness.
    pub fn link(
        &mut self,
        c: ClientId,
    ) -> (&mut RelayQueueTransport<HarnessStream>, &mut FixedEntropy) {
        self.h.client(c).link().unwrap()
    }

    /// Two fresh seeds from client `c`'s stream: (recipient key, sender key).
    pub fn seeds(&mut self, c: ClientId) -> (SecretBytes<32>, SecretBytes<32>) {
        let client = self.h.client(c);
        (client.seed(), client.seed())
    }
}

/// A 12 360-byte link blob of one repeated byte.
pub fn blob(fill: u8) -> LinkBlob {
    LinkBlob::decode(&[fill; 12_360]).unwrap()
}

/// A transport connected to a scripted relay, the scripted relay's handle and its identity.
pub fn scripted(script: Script) -> (RelayQueueTransport<Scripted>, Scripted, scripted::Identity) {
    let relay = Scripted::new(script);
    let id = scripted::identity();
    let mut entropy = EntropyPool::new("scripted-client", 0);
    let transport = RelayQueueTransport::connect(
        relay.clone(),
        id.fp,
        Some(&id.access),
        scripted::T0,
        entropy.get(),
    )
    .unwrap();
    (transport, relay, id)
}
