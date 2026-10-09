// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Mode 3 of the `hx_accept_structured` fuzz target (M5, M4 review R-44): a fuzzed padded `Content` encrypted as the
//! initiator's `first_msg` from the fixture's post-init TR state, so that the checks behind the decryption (spec §6.6
//! step 3: counters `n = 0, pn = 0`, the `Handshake` type, `caps = 0`, a non-empty list with a known route) are
//! reached by more than the honest input.
//!
//! The fixture of `hx_fixture.rs` keeps only the state after `first_msg`; the state before it is re-derived here from
//! the same constant draws, with the public derivation functions of `secmp_proto::hx` (`transcript`, `session_key`),
//! and checked against the honest envelope (`Mode3::get` asserts that encrypting the honest Content reproduces the
//! honest `first_msg` byte for byte).

use std::sync::OnceLock;

use secmp_crypto::{MlKem1024Ek, SecretBytes, Zeroizing, sha256};
use secmp_proto::Encode;
use secmp_proto::codec::pad;
use secmp_proto::hx::{Shared, TranscriptInputs, session_key, transcript};
use secmp_proto::inv::invitee_accept;
use secmp_proto::keys::X25519Pk;
use secmp_proto::prekeys::IdentityKeys;
use secmp_proto::sizes::{BODY_LEN, CELL_LEN};
use secmp_proto::tr::{FixedEntropy, RatchetState};
use secmp_proto::wire::Period;
use secmp_proto::wire::cell::{
    Cell, Content, ContentBody, HandshakeBody, RelayQueue, RouteDescriptor,
};
use secmp_proto::wire::inv::{Onion, Profile, RelayRef};

use crate::hx_fixture::{Fixture, NOW, PADDED_LEN};

/// The initiator's `RatchetStateV1` before `first_msg`, and the honest padded Content.
pub struct Mode3 {
    state: Zeroizing<Vec<u8>>,
    /// The honest padded Content (1710 B), which reproduces the honest envelope.
    pub honest_content: Vec<u8>,
    /// The header nonce of `first_msg` (24 B of the fixture's `start` draws).
    nonce: Vec<u8>,
    /// `IKSPublic_I` (the first `INNER_LEN - CELL_LEN` bytes of the honest `Inner`).
    iks_i: Vec<u8>,
}

fn constant(label: &str, n: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(n));
    let mut i = 0_u32;
    while out.len() < n {
        out.extend_from_slice(&sha256(&[label.as_bytes(), &i.to_be_bytes()]));
        i = i.checked_add(1).unwrap();
    }
    out.truncate(n);
    out
}

fn relay_ref(seed: u8) -> RelayRef {
    RelayRef {
        relay_fp: [seed; 32],
        onion: Onion::from_pubkey(&[seed.wrapping_add(1); 32]),
        akc: [seed.wrapping_add(2); 32],
        direct: None,
    }
}

impl Mode3 {
    pub fn get() -> &'static Self {
        static MODE3: OnceLock<Mode3> = OnceLock::new();
        MODE3.get_or_init(Self::build)
    }

    fn build() -> Self {
        let f = Fixture::get();
        let invitee_draws = constant("hx-fuzz invitee", 96);
        let invitee = IdentityKeys::generate(&mut FixedEntropy::new(&invitee_draws)).unwrap();
        // `IK_dh_I` is the last of the identity's draws (hybrid signing key 64 B, then the X25519 secret)
        let ik_dh = secmp_crypto::X25519Secret::from_bytes(&invitee_draws[64..96]).unwrap();
        let accepted = invitee_accept(&f.uri, &f.blob, NOW).unwrap();
        let link_data = accepted.link_data();
        let bundle = &link_data.bundle;
        let keys = invitee.initiator_keys();
        assert_eq!(ik_dh.public_key().as_bytes(), keys.iks.ik_dh.as_bytes());
        // the draws of `Initiator::start`: EK_I 32, m_spk 32, m_opk 32, ratchet (dh_s 32, kem_s 64, m 32), nonce 24
        let draws = constant("hx-fuzz start", 360);
        let ek = secmp_crypto::X25519Secret::from_bytes(&draws[..32]).unwrap();
        let ek_pk = X25519Pk::from_bytes(ek.public_key().as_bytes()).unwrap();
        let encaps = |ek_bytes: &[u8], m: &[u8]| {
            MlKem1024Ek::from_bytes(ek_bytes)
                .unwrap()
                .encapsulate_kat(m.try_into().unwrap())
        };
        let (_, ss_spk) = encaps(bundle.spk_kem.as_bytes(), &draws[32..64]);
        let (_, ss_opk) = encaps(bundle.opk_kem.as_bytes(), &draws[64..96]);
        let ct_spk: [u8; 1568] = f.outer_head[41..1609].try_into().unwrap();
        let ct_opk: [u8; 1568] = f.outer_head[1609..3177].try_into().unwrap();
        let dh = |secret: &secmp_crypto::X25519Secret, peer: &[u8]| {
            secret
                .diffie_hellman(&secmp_crypto::X25519Public::from_bytes(peer).unwrap())
                .unwrap()
        };
        let shared = Shared {
            dh1: dh(&ik_dh, bundle.spk_dh.as_bytes()),
            dh2: dh(&ek, link_data.inviter_iks.ik_dh.as_bytes()),
            dh3: dh(&ek, bundle.spk_dh.as_bytes()),
            dh4: dh(&ek, bundle.opk_dh.as_bytes()),
            ss_spk,
            ss_opk,
        };
        let transcript = transcript(&TranscriptInputs {
            iks_r: &link_data.inviter_iks,
            spk_id: bundle.spk_id,
            spk_dh: &bundle.spk_dh,
            spk_kem: &bundle.spk_kem,
            rpk_kem: &bundle.rpk_kem,
            opk_id: bundle.opk_id,
            opk_dh: &bundle.opk_dh,
            opk_kem: &bundle.opk_kem,
            iks_i: keys.iks,
            ek_i: &ek_pk,
            ct_spk: &ct_spk,
            ct_opk: &ct_opk,
            ld_id: &accepted.invitation().ld_id,
        })
        .unwrap();
        let sk: SecretBytes<32> = session_key(&shared, &transcript).unwrap();
        let state = RatchetState::init_initiator_with(
            &sk,
            &transcript,
            &bundle.spk_dh,
            &bundle.rpk_kem,
            &mut FixedEntropy::new(&draws[96..224]),
        )
        .unwrap();
        let honest_content = Content {
            seq: 1,
            ts: NOW + 1,
            body: ContentBody::Handshake(HandshakeBody {
                profile: Profile::new("alice", None).unwrap(),
                routes: vec![RouteDescriptor::RelayQueue(RelayQueue {
                    relay: relay_ref(20),
                    sid: [23; 16],
                    send_seed: SecretBytes::from_slice(&[24; 32]).unwrap(),
                    period_s: Period::S20,
                })],
            }),
        }
        .encode()
        .unwrap()
        .to_vec();
        assert_eq!(honest_content.len(), BODY_LEN);
        let mode3 = Self {
            state: state.to_bytes().unwrap(),
            honest_content,
            nonce: draws[224..248].to_vec(),
            iks_i: f.inner[..f.inner.len() - CELL_LEN].to_vec(),
        };
        // the re-derived state reproduces the honest `first_msg` (the last cell of the honest `Inner`)
        let honest_cell = mode3.first_msg(&mode3.honest_content);
        assert_eq!(
            honest_cell.as_bytes().as_slice(),
            &f.inner[f.inner.len() - CELL_LEN..]
        );
        mode3
    }

    /// `first_msg`: the 4096-byte cell of `body` (any 1710 bytes) from the pre-`first_msg` state.
    fn first_msg(&self, body: &[u8]) -> Cell {
        RatchetState::from_bytes(&self.state)
            .unwrap()
            .encrypt_padded_kat(body, &mut FixedEntropy::new(&self.nonce))
            .map_err(|refused| refused.error())
            .unwrap()
            .persist(|_| Ok::<(), ()>(()))
            .unwrap()
            .1
    }

    /// The `Padded` of the envelope whose `first_msg` carries `body` (1710 bytes), for `Fixture::cells_of`.
    pub fn padded(&self, f: &Fixture, body: &[u8]) -> Vec<u8> {
        let inner = [
            self.iks_i.as_slice(),
            self.first_msg(body).as_bytes().as_slice(),
        ]
        .concat();
        let outer = [f.outer_head.as_slice(), &f.inner_ct(&inner)].concat();
        let padded = pad(&outer, PADDED_LEN).unwrap().to_vec();
        padded
    }
}
