// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The fixed SecMP-HX handshake of the `hx_accept_*` and `inv_linkdata` fuzz targets (M4), built deterministically:
//! every key, nonce and id comes from `FixedEntropy` over constant bytes (SHA-256 of a label and a counter), so the
//! inviter's identity, store, invitation, the honest cells and the keys `K_inv` and `K_id` are the same in every run
//! and on every machine.
//!
//! The fixture holds what the structured target needs to re-seal a mutated envelope the way an invitation holder
//! (who knows `K_inv`) or the initiator (who knows `K_id`) could: the padded `Outer` of the honest handshake
//! (12018 B), the honest `Inner` (6113 B), `K_inv`, `K_id`, and the pieces of the honest `Outer`.

use std::sync::OnceLock;

use secmp_crypto::{
    Caead, Label, MlKem1024Ek, Nonce24, SecretBytes, X25519Public, X25519Secret, Zeroizing, sha256,
};
use secmp_proto::Encode;
use secmp_proto::codec::unpad;
use secmp_proto::hx::{self, Initiator};
use secmp_proto::inv::{derive_k_inv, invitation_uri, invitee_accept};
use secmp_proto::prekeys::{IdentityKeys, InvitationRecord, IssueParams, MemoryPrekeyStore};
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::Period;
use secmp_proto::wire::cell::{Cell, RelayQueue, RouteDescriptor};
use secmp_proto::wire::inv::{Onion, Profile, RelayRef};

/// The randomness of the responder's DH step (X25519 secret 32, ML-KEM-768 seed 64, `Encaps` 32).
pub const STEP_RANDOMNESS: usize = 128;
/// `Padded` (3 × 4006) and `Inner` (2017 + 4096).
pub const PADDED_LEN: usize = 12_018;
pub const INNER_LEN: usize = 6_113;
/// `now` of the invitee's checks and of the handshake.
pub const NOW: u64 = 1_700_000_100;

pub struct Fixture {
    pub inviter: IdentityKeys,
    pub store: MemoryPrekeyStore,
    pub record: InvitationRecord,
    pub uri: String,
    pub blob: Vec<u8>,
    /// The three honest cells.
    pub cells: Vec<Cell>,
    pub k_inv: SecretBytes<32>,
    pub k_id: SecretBytes<32>,
    /// The honest `Padded` and `Inner`.
    pub padded: Vec<u8>,
    pub inner: Vec<u8>,
    /// The honest `Outer` fields before `inner_ct` (3177 B), whose `ek_I`, ids and ciphertexts the targets keep.
    pub outer_head: Vec<u8>,
    /// The randomness of the responder's DH step.
    pub step: Vec<u8>,
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

impl Fixture {
    pub fn get() -> &'static Self {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(Self::build)
    }

    fn build() -> Self {
        let inviter = IdentityKeys::generate(&mut FixedEntropy::new(&constant("hx-fuzz inviter", 96))).unwrap();
        let invitee = IdentityKeys::generate(&mut FixedEntropy::new(&constant("hx-fuzz invitee", 96))).unwrap();
        let mut store = MemoryPrekeyStore::starting_at(7, 42);
        let issued = store
            .issue_invitation(
                &inviter,
                IssueParams {
                    relay: relay_ref(10),
                    inv_period: Period::S20,
                    profile: Profile::new("bob", None).unwrap(),
                    now: 1_700_000_000,
                    expires: 1_702_592_000,
                    spk_expiry: 1_702_592_000,
                },
                &mut FixedEntropy::new(&constant("hx-fuzz issue", 600)),
            )
            .unwrap();
        let uri = invitation_uri(&issued.invitation).unwrap().to_string();
        let blob = issued.blob.encode().unwrap().to_vec();
        let record = store.record(&issued.invitation.ld_id).unwrap().duplicate().unwrap();
        let accepted = invitee_accept(&uri, &blob, NOW).unwrap();
        let route = RouteDescriptor::RelayQueue(RelayQueue {
            relay: relay_ref(20),
            sid: [23; 16],
            send_seed: SecretBytes::from_slice(&[24; 32]).unwrap(),
            period_s: Period::S20,
        });
        // start's draws: EK_I 32, m_spk 32, m_opk 32, then the ratchet (dh_s 32, kem_s 64, m 32), header nonce 24,
        // N2 24, init_id 16, N_0..N_2
        let draws = constant("hx-fuzz start", 360);
        let (hc, _state) = Initiator::start(
            &accepted,
            &invitee.initiator_keys(),
            &[route],
            &Profile::new("alice", None).unwrap(),
            NOW + 1,
            &mut FixedEntropy::new(&draws),
        )
        .unwrap();
        let cells = hc.release(|_, _| Ok::<(), ()>(())).unwrap().to_vec();
        // K_id from the initiator's values: DH3 = EK × SPK_dh, DH4 = EK × OPK_dh, ss_spk and ss_opk from the
        // encapsulation randomness
        let bundle = &accepted.link_data().bundle;
        let ek = X25519Secret::from_bytes(&draws[..32]).unwrap();
        let pk = |b: &[u8]| X25519Public::from_bytes(b).unwrap();
        let dh3 = ek.diffie_hellman(&pk(bundle.spk_dh.as_bytes())).unwrap();
        let dh4 = ek.diffie_hellman(&pk(bundle.opk_dh.as_bytes())).unwrap();
        let m_spk: [u8; 32] = draws[32..64].try_into().unwrap();
        let m_opk: [u8; 32] = draws[64..96].try_into().unwrap();
        let (_, ss_spk) = MlKem1024Ek::from_bytes(bundle.spk_kem.as_bytes()).unwrap().encapsulate_kat(&m_spk);
        let (_, ss_opk) = MlKem1024Ek::from_bytes(bundle.opk_kem.as_bytes()).unwrap().encapsulate_kat(&m_opk);
        let k_id = hx::k_id(&record.ld_id, &record.link_key, &dh3, &ss_spk, &dh4, &ss_opk).unwrap();
        let k_inv = derive_k_inv(&record.ld_id, &record.link_key).unwrap();
        // the honest Padded, Outer and Inner by opening what start sealed
        let ad_cell = [Label::HxInitcell.as_bytes(), record.ld_id.as_slice()].concat();
        let mut padded = Vec::new();
        for c in &cells {
            let (n, rest) = c.as_bytes().split_at(24);
            let pt = Caead::open(&k_inv, n.try_into().unwrap(), &ad_cell, rest).unwrap();
            padded.extend_from_slice(&pt[18..]);
        }
        assert_eq!(padded.len(), PADDED_LEN);
        let outer = unpad(&padded, PADDED_LEN).unwrap().to_vec();
        let (outer_head, inner_ct) = outer.split_at(3177);
        let ad_inner = [Label::HxInner.as_bytes(), record.ld_id.as_slice()].concat();
        let (n2, rest) = inner_ct.split_at(24);
        let inner = Caead::open(&k_id, n2.try_into().unwrap(), &ad_inner, rest).unwrap().to_vec();
        assert_eq!(inner.len(), INNER_LEN);
        Self {
            inviter,
            store,
            record,
            uri,
            blob,
            cells,
            k_inv,
            k_id,
            padded,
            inner,
            outer_head: outer_head.to_vec(),
            step: constant("hx-fuzz step", STEP_RANDOMNESS).to_vec(),
        }
    }

    /// A nonce from SHA-256 of a label and the input (deterministic: the targets seal many inputs).
    fn nonce(label: &str, input: &[u8]) -> Nonce24 {
        let h = sha256(&[label.as_bytes(), input]);
        Nonce24::from_bytes_kat(h[..24].try_into().unwrap())
    }

    /// `inner_ct = N2 ‖ CAEAD.Seal(K_id, N2, "SecMP-HX/1 inner" ‖ ld_id, inner)` for any 6113-byte `inner`.
    pub fn inner_ct(&self, inner: &[u8]) -> Vec<u8> {
        assert_eq!(inner.len(), INNER_LEN);
        let nonce = Self::nonce("inner", inner);
        let n = *nonce.as_bytes();
        let ad = [Label::HxInner.as_bytes(), self.record.ld_id.as_slice()].concat();
        [n.as_slice(), &Caead::seal(&self.k_id, nonce, &ad, inner).unwrap()].concat()
    }

    /// The three cells of any `Padded` (12018 B) under `K_inv` and `init_id` = the first 16 bytes of its hash.
    pub fn cells_of(&self, padded: &[u8]) -> Vec<Cell> {
        assert_eq!(padded.len(), PADDED_LEN);
        let init_id: [u8; 16] = sha256(&[b"init_id", padded])[..16].try_into().unwrap();
        let ad = [Label::HxInitcell.as_bytes(), self.record.ld_id.as_slice()].concat();
        padded
            .chunks_exact(4006)
            .zip(0_u8..)
            .map(|(chunk, i)| {
                let plaintext = [init_id.as_slice(), &[i, 3], chunk].concat();
                let nonce = Self::nonce("cell", &plaintext);
                let n = *nonce.as_bytes();
                let sealed = Caead::seal(&self.k_inv, nonce, &ad, &plaintext).unwrap();
                Cell::from_bytes(&[n.as_slice(), &sealed].concat()).unwrap()
            })
            .collect()
    }

    /// `bytes` cut or zero-padded to `n`.
    pub fn fit(bytes: &[u8], n: usize) -> Vec<u8> {
        let mut v = vec![0_u8; n];
        let k = bytes.len().min(n);
        v[..k].copy_from_slice(&bytes[..k]);
        v
    }
}
