// SPDX-License-Identifier: AGPL-3.0-or-later
//! SecMP-INV/HX property tests (TEST-SPEC-M4 (c) P1 … P11), on generators built from `rand` (ADR-040), as the TR and
//! encodings properties: a `StdRng` seeded from the master seed — [`DEFAULT_SEED`], or the decimal `u64` in
//! `SECMP_PROPTEST_SEED` if set and not empty — so a failure is reproducible; the seed (as
//! `SECMP_PROPTEST_SEED=<n>`) and the case index are in every assertion message. No shrinking.
//!
//! A *run* is a whole random handshake through the library's public API: a fresh inviter identity, prekey store and
//! invitation (`MemoryPrekeyStore::issue_invitation`), the invitee's checks (`invitee_accept`), `Initiator::start`
//! with a random profile and route list, and the three cells; all randomness comes from `FixedEntropy` buffers
//! filled from the run's RNG. The properties then act on the cells (`Responder::accept` on mutated or extended
//! lists) and on the states.

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

use secmp_crypto::{Caead, Label, SecretBytes, X25519Secret, Zeroizing};
use secmp_proto::codec::{Decode, Encode};
use secmp_proto::hx::{self, HandshakeCells, Initiator, Responder, Shared, TranscriptInputs};
use secmp_proto::inv::{
    InviteeAccepted, invitation_uri, invitee_accept, open_blob, parse_invitation_uri,
};
use secmp_proto::keys::{MlKem768Ek, MlKem1024Ek, X25519Pk};
use secmp_proto::prekeys::{
    IdentityKeys, InvitationRecord, IssueParams, MemoryPrekeyStore, PrekeyStore,
};
use secmp_proto::tr::{FixedEntropy, RatchetState};
use secmp_proto::wire::cell::{Cell, RelayQueue, RouteDescriptor};
use secmp_proto::wire::hx::{HandshakeCellPlaintext, Inner, Outer};
use secmp_proto::wire::inv::{InvitationV1, IksPublic, LinkDataV1, Profile};
use secmp_proto::wire::Period;
use secmp_proto::Error;

use crate::fixture::relay_ref;
use crate::hx_gen::harness::{self, CREATED, EXPIRES, NOW, PADDED_LEN, cell_plaintext, cell_raw};
use crate::hx_gen::tr_digest::fields;

/// The master seed when `SECMP_PROPTEST_SEED` is not set.
const DEFAULT_SEED: u64 = 0x5ec3_2d00_0000_0004;
/// Runs per property.
const CASES: usize = 6;

fn master_seed() -> u64 {
    let raw = match std::env::var("SECMP_PROPTEST_SEED") {
        Err(std::env::VarError::NotPresent) => return DEFAULT_SEED,
        other => other.map_err(|e| format!("SECMP_PROPTEST_SEED: {e}")).unwrap(),
    };
    if raw.trim().is_empty() {
        return DEFAULT_SEED;
    }
    raw.trim()
        .parse()
        .map_err(|e| format!("SECMP_PROPTEST_SEED={raw:?} is not a decimal u64: {e}"))
        .unwrap()
}

fn rng_for(tag: u64) -> StdRng {
    StdRng::seed_from_u64(master_seed() ^ tag.wrapping_mul(0x9e37_79b9_7f4a_7c15))
}

fn random_bytes(rng: &mut StdRng, n: usize) -> Vec<u8> {
    let mut v = vec![0_u8; n];
    rng.fill(v.as_mut_slice());
    v
}

/// One random handshake.
struct Run {
    seed: u64,
    inviter: IdentityKeys,
    invitee: IdentityKeys,
    store: MemoryPrekeyStore,
    record: InvitationRecord,
    accepted: InviteeAccepted,
    uri: String,
    blob: Vec<u8>,
    routes: Vec<Vec<u8>>,
    profile: Profile,
    cells: Vec<Vec<u8>>,
    state_i: RatchetState,
    step: Vec<u8>,
    k_inv: SecretBytes<32>,
}

/// Random routes: at least one of a known kind, unknown kinds (2..=255) with random blobs, within the Content bound.
fn random_routes(rng: &mut StdRng, profile_len: usize) -> Vec<Vec<u8>> {
    let budget = 1689 - profile_len - 4 - 1;
    loop {
        let count = rng.random_range(1..=8_usize);
        let mut routes: Vec<Vec<u8>> = Vec::new();
        for k in 0..count {
            let known = k == 0 || rng.random_bool(0.5);
            let r = if known {
                RouteDescriptor::RelayQueue(RelayQueue {
                    relay: relay_ref(rng.random()),
                    sid: rng.random(),
                    send_seed: SecretBytes::from_slice(&random_bytes(rng, 32)).unwrap(),
                    period_s: Period::ALL[rng.random_range(0..4_usize)],
                })
            } else {
                RouteDescriptor::Unknown {
                    kind: rng.random_range(2..=255_u8),
                    blob: Zeroizing::new({
                        let len = rng.random_range(0..=120_usize);
                        random_bytes(rng, len)
                    }),
                }
            };
            routes.push(r.encode().unwrap().to_vec());
        }
        // the first is known; shuffle one unknown to the front half of the time
        if rng.random_bool(0.5) {
            routes.reverse();
        }
        if routes.iter().map(Vec::len).sum::<usize>() <= budget {
            return routes;
        }
    }
}

fn random_profile(rng: &mut StdRng) -> Profile {
    let len = rng.random_range(0..=64_usize);
    let name: String = (0..len).map(|_| char::from(rng.random_range(b'a'..=b'z'))).collect();
    let avatar = rng.random_bool(0.5).then(|| rng.random::<[u8; 32]>());
    Profile::new(&name, avatar).unwrap()
}

fn make_run(seed: u64) -> Run {
    let mut rng = StdRng::seed_from_u64(seed);
    let inviter = IdentityKeys::generate(&mut FixedEntropy::new(&random_bytes(&mut rng, 96))).unwrap();
    let invitee = IdentityKeys::generate(&mut FixedEntropy::new(&random_bytes(&mut rng, 96))).unwrap();
    let mut store = MemoryPrekeyStore::starting_at(rng.random_range(1..1000), rng.random_range(1..1000));
    let issued = store
        .issue_invitation(
            &inviter,
            IssueParams {
                relay: relay_ref(rng.random()),
                inv_period: Period::ALL[rng.random_range(0..4_usize)],
                profile: random_profile(&mut rng),
                now: CREATED,
                expires: EXPIRES,
                spk_expiry: EXPIRES,
            },
            &mut FixedEntropy::new(&random_bytes(&mut rng, 600)),
        )
        .unwrap();
    let uri = invitation_uri(&issued.invitation).unwrap();
    let blob = issued.blob.encode().unwrap().to_vec();
    let record = store.record(&issued.invitation.ld_id).unwrap().duplicate().unwrap();
    let accepted = invitee_accept(&uri, &blob, NOW).unwrap();
    let profile = random_profile(&mut rng);
    let routes = random_routes(&mut rng, profile.encode().unwrap().len());
    let descriptors: Vec<RouteDescriptor> = routes.iter().map(|r| RouteDescriptor::decode(r).unwrap()).collect();
    let (cells, state_i) = Initiator::start(
        &accepted.invitation,
        &accepted.link_data,
        &invitee.initiator_keys(),
        &descriptors,
        &profile,
        NOW + 1,
        &mut FixedEntropy::new(&random_bytes(&mut rng, 600)),
    )
    .unwrap();
    let cells = cells.release(|_| Ok::<(), ()>(())).unwrap().iter().map(|c| c.as_bytes().to_vec()).collect();
    let k_inv = harness::k_inv(&record.ld_id, record.link_key.expose_secret());
    Run {
        seed,
        inviter,
        invitee,
        store,
        record,
        accepted,
        uri,
        blob,
        routes,
        profile,
        cells,
        state_i,
        step: random_bytes(&mut rng, 128),
        k_inv,
    }
}

impl Run {
    fn accept(&self, store: &mut MemoryPrekeyStore, cells: &[Vec<u8>]) -> Result<hx::Accepted, Error> {
        let cells: Vec<Cell> = cells.iter().map(|c| Cell::from_bytes(c).unwrap()).collect();
        Responder::accept(
            &cells,
            &self.record,
            store,
            &self.inviter.responder_keys(),
            &mut FixedEntropy::new(&self.step),
        )
    }

    /// A copy of the run's store as the inviter issued it.
    fn fresh_store(&self) -> MemoryPrekeyStore {
        self.store.duplicate_kat().unwrap()
    }

    fn assert_rejected(&self, cells: &[Vec<u8>], what: &str) {
        let mut store = self.fresh_store();
        let before = store.digest_kat();
        let r = self.accept(&mut store, cells);
        assert_eq!(r.err(), Some(Error::Rejected), "SECMP_PROPTEST_SEED={} run {}: {what}", master_seed(), self.seed);
        assert_eq!(store.digest_kat(), before, "{what}: store unchanged (P6)");
        assert!(store.opk(self.record.opk_id).is_some(), "{what}: OPK kept");
    }

    /// The padded `Outer` recovered by opening the honest cells under `K_inv`.
    fn padded(&self) -> Vec<u8> {
        let ad = [Label::HxInitcell.as_bytes(), self.record.ld_id.as_slice()].concat();
        let mut padded = Vec::new();
        for c in &self.cells {
            let (n, rest) = c.split_at(24);
            let pt = Caead::open(&self.k_inv, n.try_into().unwrap(), &ad, rest).unwrap();
            padded.extend_from_slice(&pt[18..]);
        }
        assert_eq!(padded.len(), PADDED_LEN);
        padded
    }

    /// Cells of `padded` under `init_id` with nonces from `rng`.
    fn reseal(&self, rng: &mut StdRng, init_id: [u8; 16], padded: &[u8]) -> Vec<Vec<u8>> {
        (0..3_u8)
            .map(|i| {
                let k = usize::from(i);
                cell_raw(
                    &self.k_inv,
                    &self.record.ld_id,
                    &random_bytes(rng, 24),
                    &cell_plaintext(&init_id, i, 3, &padded[k * 4006..(k + 1) * 4006]),
                )
            })
            .collect()
    }
}

fn runs(tag: u64) -> impl Iterator<Item = Run> {
    let mut rng = rng_for(tag);
    (0..CASES).map(move |_| make_run(rng.random()))
}

// ---- P1 ---------------------------------------------------------------------------------------------------------

#[test]
fn prop_handshake_complementary_states() {
    for run in runs(1) {
        let ctx = format!("SECMP_PROPTEST_SEED={} run {}", master_seed(), run.seed);
        let mut store = run.fresh_store();
        let accepted = run.accept(&mut store, &run.cells).unwrap_or_else(|e| panic!("{ctx}: {e}"));
        let (i, r) = (fields(&run.state_i), fields(&accepted.state));
        // sb = transcript on both sides
        assert_eq!(i.sb_rk_dh_s[..32], r.sb_rk_dh_s[..32], "{ctx}: R.sb = I.sb");
        // R.hk_r = I.hk_s = HK_A; R.ck_r = I.ck_s
        assert_eq!(r.keys[3], i.keys[2], "{ctx}: R.hk_r = I.hk_s");
        assert_eq!(r.keys[1], i.keys[0], "{ctx}: R.ck_r = I.ck_s");
        assert!(r.keys[3].is_some() && r.keys[1].is_some());
        // R.n_r = I.n_s = 1
        assert_eq!((i.n_s, r.n_r), (1, 1), "{ctx}: n_s = n_r = 1");
        // R.dh_r = I.dh_s.pk; R.kem_r = I.kem_s.ek; R.last_ct_r = I.ct_s
        let i_dh_pk = X25519Secret::from_bytes(&i.sb_rk_dh_s[64..96]).unwrap().public_key();
        assert_eq!(r.dh_r.as_deref(), Some(i_dh_pk.as_bytes().as_slice()), "{ctx}: R.dh_r = I.dh_s.pk");
        let i_kem_pk = secmp_crypto::MlKem768Dk::from_seed(&i.kem_s_seed).unwrap().encapsulation_key();
        assert_eq!(r.kem[0].as_deref(), Some(i_kem_pk.as_bytes().as_slice()), "{ctx}: R.kem_r = I.kem_s.ek");
        assert_eq!(r.kem[1], i.kem[2], "{ctx}: R.last_ct_r = I.ct_s");
        // R.hk_s = I.nhk_r = NHK_B; R.nhk_r = I.nhk_s
        assert_eq!(r.keys[2], i.keys[5], "{ctx}: R.hk_s = I.nhk_r");
        assert_eq!(r.keys[5], i.keys[4], "{ctx}: R.nhk_r = I.nhk_s");
        // the states are complementary, not identical
        assert_ne!(accepted.state.to_bytes().unwrap().to_vec(), run.state_i.to_bytes().unwrap().to_vec());
        // R -> I and a second I -> R message decrypt
        let sealed = accepted.state.encrypt(&secmp_proto::tr::content::dummy()).map_err(|r| r.error()).unwrap();
        let (r_state, reply) = sealed.persist(|_| Ok::<(), ()>(())).unwrap();
        let opened = run
            .state_i
            .decrypt(reply.as_bytes())
            .map_err(|r| r.error())
            .unwrap_or_else(|e| panic!("{ctx}: I decrypts R's reply: {e}"));
        let (i_state, _) = opened.commit(|_| Ok::<(), ()>(())).unwrap();
        let second = i_state.encrypt(&secmp_proto::tr::content::dummy()).map_err(|r| r.error()).unwrap();
        let (_, cell) = second.persist(|_| Ok::<(), ()>(())).unwrap();
        r_state
            .decrypt(cell.as_bytes())
            .map_err(|r| r.error())
            .unwrap_or_else(|e| panic!("{ctx}: R decrypts the second I message: {e}"));
    }
}

// ---- P2, P3, P4, P5, P6 -----------------------------------------------------------------------------------------

#[test]
fn prop_opk_consumed_exactly_once() {
    for (k, run) in runs(2).enumerate() {
        let mut rng = rng_for(200 + k as u64);
        let ctx = format!("SECMP_PROPTEST_SEED={} run {}", master_seed(), run.seed);
        // a second valid envelope of the same invitation (another initiator)
        let other = IdentityKeys::generate(&mut FixedEntropy::new(&random_bytes(&mut rng, 96))).unwrap();
        let descriptors: Vec<RouteDescriptor> =
            run.routes.iter().map(|r| RouteDescriptor::decode(r).unwrap()).collect();
        let (b, _) = Initiator::start(
            &run.accepted.invitation,
            &run.accepted.link_data,
            &other.initiator_keys(),
            &descriptors,
            &run.profile,
            NOW + 2,
            &mut FixedEntropy::new(&random_bytes(&mut rng, 600)),
        )
        .unwrap();
        let cells_b: Vec<Vec<u8>> = b.release(|_| Ok::<(), ()>(())).unwrap().iter().map(|c| c.as_bytes().to_vec()).collect();
        // bogus complete groups (valid cells, undecodable Outer) under up to 3 other init_ids
        let padded = run.padded();
        let mut bogus_groups = Vec::new();
        for _ in 0..3 {
            let mut bad = padded.clone();
            let at = rng.random_range(0..9362_usize);
            bad[at] ^= 0x55;
            let init_id: [u8; 16] = rng.random();
            bogus_groups.push(run.reseal(&mut rng, init_id, &bad));
        }
        let mut store = run.fresh_store();
        let opk_id = run.record.opk_id;
        let mut consumed = false;
        for call in 0..4 {
            // up to 12 cells drawn from the pool, in random order, with duplicates
            let mut pool: Vec<(Vec<u8>, Option<(bool, usize)>)> = Vec::new();
            for (i, c) in run.cells.iter().enumerate() {
                pool.push((c.clone(), Some((true, i))));
            }
            for (i, c) in cells_b.iter().enumerate() {
                pool.push((c.clone(), Some((false, i))));
            }
            for g in &bogus_groups {
                for c in g {
                    pool.push((c.clone(), None));
                }
            }
            for c in crate::build::garbage(rng.random_range(0..1000), 3) {
                pool.push((c, None));
            }
            let n = rng.random_range(0..=12_usize);
            let chosen: Vec<_> = (0..n).map(|_| pool[rng.random_range(0..pool.len())].clone()).collect();
            let has = |is_a: bool| (0..3).all(|i| chosen.iter().any(|(_, t)| *t == Some((is_a, i))));
            let expected = !consumed && (has(true) || has(false));
            let before = store.digest_kat();
            let cells: Vec<Vec<u8>> = chosen.into_iter().map(|(c, _)| c).collect();
            let result = run.accept(&mut store, &cells);
            assert_eq!(result.is_ok(), expected, "{ctx} call {call}: Ok iff an untampered complete envelope was delivered and the OPK is unused");
            if result.is_ok() {
                assert!(store.opk(opk_id).is_none(), "{ctx}: the OPK is gone after Ok");
                assert_ne!(store.digest_kat(), before);
                consumed = true;
            } else {
                assert_eq!(store.digest_kat(), before, "{ctx} call {call}: Reject leaves the store unchanged (P6)");
            }
        }
    }
}

#[test]
fn prop_garbage_never_changes_outcome_or_state() {
    for (k, run) in runs(3).enumerate() {
        let mut rng = rng_for(300 + k as u64);
        let ctx = format!("SECMP_PROPTEST_SEED={} run {}", master_seed(), run.seed);
        let mut base_store = run.fresh_store();
        let base = run.accept(&mut base_store, &run.cells).unwrap();
        let base_state = base.state.to_bytes().unwrap().to_vec();
        // any number of random cells at any positions
        let mut cells = run.cells.clone();
        for g in crate::build::garbage(rng.random(), rng.random_range(1..=20_usize)) {
            let at = rng.random_range(0..=cells.len());
            cells.insert(at, g);
        }
        let mut store = run.fresh_store();
        let again = run.accept(&mut store, &cells).unwrap_or_else(|e| panic!("{ctx}: {e}"));
        assert_eq!(again.state.to_bytes().unwrap().to_vec(), base_state, "{ctx}: the returned state is unchanged by garbage");
        assert_eq!(store.digest_kat(), base_store.digest_kat(), "{ctx}: the store after Ok is the same");
        // with no honest group: Reject, store unchanged
        let only_garbage = crate::build::garbage(rng.random(), rng.random_range(0..=12_usize));
        run.assert_rejected(&only_garbage, "garbage only");
    }
}

#[test]
fn prop_cell_byte_flip_rejects_or_is_ignored() {
    for (k, run) in runs(4).enumerate() {
        let mut rng = rng_for(400 + k as u64);
        for _ in 0..24 {
            let (cell, at) = (rng.random_range(0..3_usize), rng.random_range(0..4096_usize));
            let mut cells = run.cells.clone();
            cells[cell][at] ^= 1 << rng.random_range(0..8_u32);
            run.assert_rejected(&cells, &format!("cell {cell} byte {at}"));
        }
    }
}

#[test]
fn prop_resealed_padded_flip_rejects() {
    for (k, run) in runs(5).enumerate() {
        let mut rng = rng_for(500 + k as u64);
        let padded = run.padded();
        for _ in 0..24 {
            let at = rng.random_range(0..PADDED_LEN);
            let mut bad = padded.clone();
            bad[at] ^= 1 << rng.random_range(0..8_u32);
            let init_id: [u8; 16] = rng.random();
            let cells = run.reseal(&mut rng, init_id, &bad);
            run.assert_rejected(&cells, &format!("Padded byte {at}"));
        }
        // the structural bytes
        for at in [0, 1, 32, 33, 37, 41, 1609, 3177, 9361, 9362, 9363, PADDED_LEN - 1] {
            let mut bad = padded.clone();
            bad[at] ^= 1;
            run.assert_rejected(&run.reseal(&mut rng, [7; 16], &bad), &format!("Padded byte {at}"));
        }
    }
}

#[test]
fn prop_reject_is_transactional() {
    // P6 is asserted inside P2 (call by call), P3 and P4/P5 (`assert_rejected` compares the store digest). This test
    // adds the explicit statement for a rejection after the TR step (a valid envelope of another invitee's key)
    for run in runs(6) {
        let mut store = run.fresh_store();
        let before = store.digest_kat();
        let mut cells = run.cells.clone();
        cells.reverse();
        // reversed order is still a complete group: accepted; the digest then differs by exactly the OPK
        run.accept(&mut store, &cells).unwrap();
        assert_ne!(store.digest_kat(), before);
        assert!(store.opk(run.record.opk_id).is_none());
        // and a second delivery rejects without touching anything
        let after = store.digest_kat();
        assert_eq!(run.accept(&mut store, &cells).err(), Some(Error::Rejected));
        assert_eq!(store.digest_kat(), after);
    }
}

// ---- P7 ---------------------------------------------------------------------------------------------------------

#[test]
fn prop_stored_routes_equal_sent_routes() {
    for run in runs(7) {
        let ctx = format!("SECMP_PROPTEST_SEED={} run {}", master_seed(), run.seed);
        let mut store = run.fresh_store();
        let a = run.accept(&mut store, &run.cells).unwrap();
        let stored: Vec<Vec<u8>> = a.routes.iter().map(|r| r.encode().unwrap().to_vec()).collect();
        assert_eq!(stored, run.routes, "{ctx}: R's routes are byte-identical to I's, in order");
        assert_eq!(a.profile.encode().unwrap().to_vec(), run.profile.encode().unwrap().to_vec(), "{ctx}: profile");
        assert!(a.routes.iter().any(|r| matches!(r, RouteDescriptor::RelayQueue(_))));
    }
}

// ---- P8, P9 -----------------------------------------------------------------------------------------------------

#[test]
fn prop_transcript_component_sensitivity() {
    for (k, run) in runs(8).enumerate() {
        let mut rng = rng_for(800 + k as u64);
        let ctx = format!("SECMP_PROPTEST_SEED={} run {}", master_seed(), run.seed);
        let link = &run.accepted.link_data;
        let other = IdentityKeys::generate(&mut FixedEntropy::new(&random_bytes(&mut rng, 96))).unwrap();
        let ek = X25519Pk::from_bytes(X25519Secret::from_bytes(&random_bytes(&mut rng, 32)).unwrap().public_key().as_bytes()).unwrap();
        let ct_spk: [u8; 1568] = rng.random::<[u8; 32]>().iter().cycle().take(1568).copied().collect::<Vec<u8>>().try_into().unwrap();
        let ct_opk: [u8; 1568] = ct_spk.map(|b| b ^ 0x5a);
        let kem1024 = |seed: u8| {
            MlKem1024Ek::from_bytes(secmp_crypto::MlKem1024Dk::from_seed(&[seed; 64]).unwrap().encapsulation_key().as_bytes()).unwrap()
        };
        let rpk2 = MlKem768Ek::from_bytes(secmp_crypto::MlKem768Dk::from_seed(&random_bytes(&mut rng, 64)).unwrap().encapsulation_key().as_bytes()).unwrap();
        let ld_id: [u8; 16] = rng.random();
        let base = |t: &mut Vec<(&'static str, [u8; 32])>, label, iks_r: &IksPublic, spk_id, spk_dh: &X25519Pk, spk_kem: &MlKem1024Ek, rpk: &MlKem768Ek, opk_id, opk_dh: &X25519Pk, opk_kem: &MlKem1024Ek, iks_i: &IksPublic, ek_i: &X25519Pk, c1: &[u8; 1568], c2: &[u8; 1568], ld: &[u8; 16]| {
            let tr = hx::transcript(&TranscriptInputs { iks_r, spk_id, spk_dh, spk_kem, rpk_kem: rpk, opk_id, opk_dh, opk_kem, iks_i, ek_i, ct_spk: c1, ct_opk: c2, ld_id: ld }).unwrap();
            t.push((label, tr));
        };
        let b = &link.bundle;
        let mut results: Vec<(&'static str, [u8; 32])> = Vec::new();
        let (iks_r, iks_i) = (link.inviter_iks.clone(), IksPublic::decode(&run.invitee.public().encode().unwrap()).unwrap());
        let other_iks = other.public().clone();
        let x2 = other.public().ik_dh;
        let k2 = kem1024(0x21);
        let ids = (b.spk_id, b.opk_id);
        base(&mut results, "base", &iks_r, ids.0, &b.spk_dh, &b.spk_kem, &b.rpk_kem, ids.1, &b.opk_dh, &b.opk_kem, &iks_i, &ek, &ct_spk, &ct_opk, &run.record.ld_id);
        base(&mut results, "IKS_R", &other_iks, ids.0, &b.spk_dh, &b.spk_kem, &b.rpk_kem, ids.1, &b.opk_dh, &b.opk_kem, &iks_i, &ek, &ct_spk, &ct_opk, &run.record.ld_id);
        base(&mut results, "spk_id", &iks_r, ids.0.wrapping_add(1), &b.spk_dh, &b.spk_kem, &b.rpk_kem, ids.1, &b.opk_dh, &b.opk_kem, &iks_i, &ek, &ct_spk, &ct_opk, &run.record.ld_id);
        base(&mut results, "SPK_dh", &iks_r, ids.0, &x2, &b.spk_kem, &b.rpk_kem, ids.1, &b.opk_dh, &b.opk_kem, &iks_i, &ek, &ct_spk, &ct_opk, &run.record.ld_id);
        base(&mut results, "SPK_kem", &iks_r, ids.0, &b.spk_dh, &k2, &b.rpk_kem, ids.1, &b.opk_dh, &b.opk_kem, &iks_i, &ek, &ct_spk, &ct_opk, &run.record.ld_id);
        base(&mut results, "RPK_kem", &iks_r, ids.0, &b.spk_dh, &b.spk_kem, &rpk2, ids.1, &b.opk_dh, &b.opk_kem, &iks_i, &ek, &ct_spk, &ct_opk, &run.record.ld_id);
        base(&mut results, "opk_id", &iks_r, ids.0, &b.spk_dh, &b.spk_kem, &b.rpk_kem, ids.1.wrapping_add(1), &b.opk_dh, &b.opk_kem, &iks_i, &ek, &ct_spk, &ct_opk, &run.record.ld_id);
        base(&mut results, "OPK_dh", &iks_r, ids.0, &b.spk_dh, &b.spk_kem, &b.rpk_kem, ids.1, &x2, &b.opk_kem, &iks_i, &ek, &ct_spk, &ct_opk, &run.record.ld_id);
        base(&mut results, "OPK_kem", &iks_r, ids.0, &b.spk_dh, &b.spk_kem, &b.rpk_kem, ids.1, &b.opk_dh, &k2, &iks_i, &ek, &ct_spk, &ct_opk, &run.record.ld_id);
        base(&mut results, "IKS_I", &iks_r, ids.0, &b.spk_dh, &b.spk_kem, &b.rpk_kem, ids.1, &b.opk_dh, &b.opk_kem, &other_iks, &ek, &ct_spk, &ct_opk, &run.record.ld_id);
        base(&mut results, "EK_I", &iks_r, ids.0, &b.spk_dh, &b.spk_kem, &b.rpk_kem, ids.1, &b.opk_dh, &b.opk_kem, &iks_i, &x2, &ct_spk, &ct_opk, &run.record.ld_id);
        base(&mut results, "ct_spk", &iks_r, ids.0, &b.spk_dh, &b.spk_kem, &b.rpk_kem, ids.1, &b.opk_dh, &b.opk_kem, &iks_i, &ek, &ct_opk, &ct_opk, &run.record.ld_id);
        base(&mut results, "ct_opk", &iks_r, ids.0, &b.spk_dh, &b.spk_kem, &b.rpk_kem, ids.1, &b.opk_dh, &b.opk_kem, &iks_i, &ek, &ct_spk, &ct_spk, &run.record.ld_id);
        base(&mut results, "ld_id", &iks_r, ids.0, &b.spk_dh, &b.spk_kem, &b.rpk_kem, ids.1, &b.opk_dh, &b.opk_kem, &iks_i, &ek, &ct_spk, &ct_opk, &ld_id);
        assert_eq!(results.len(), 14, "the base and the thirteen components");
        let shared = || Shared {
            dh1: SecretBytes::from_slice(&[1; 32]).unwrap(),
            dh2: SecretBytes::from_slice(&[2; 32]).unwrap(),
            dh3: SecretBytes::from_slice(&[3; 32]).unwrap(),
            dh4: SecretBytes::from_slice(&[4; 32]).unwrap(),
            ss_spk: SecretBytes::from_slice(&[5; 32]).unwrap(),
            ss_opk: SecretBytes::from_slice(&[6; 32]).unwrap(),
        };
        let (_, base_t) = results[0];
        let base_sk = hx::session_key(&shared(), &base_t).unwrap();
        for (name, t) in &results[1..] {
            assert_ne!(*t, base_t, "{ctx}: the transcript changes with {name}");
            assert_ne!(hx::session_key(&shared(), t).unwrap().expose_secret(), base_sk.expose_secret(), "{ctx}: SK changes with {name}");
        }
    }
}

#[test]
fn prop_k_id_input_set() {
    let mut rng = rng_for(9);
    for case in 0..CASES * 4 {
        let ctx = format!("SECMP_PROPTEST_SEED={} case {case}", master_seed());
        let secret = |rng: &mut StdRng| SecretBytes::<32>::from_slice(&random_bytes(rng, 32)).unwrap();
        let ld_id: [u8; 16] = rng.random();
        let (link, dh3, ss_spk, dh4, ss_opk) =
            (secret(&mut rng), secret(&mut rng), secret(&mut rng), secret(&mut rng), secret(&mut rng));
        let k = |ld: &[u8; 16], l: &SecretBytes<32>, d3: &SecretBytes<32>, s1: &SecretBytes<32>, d4: &SecretBytes<32>, s2: &SecretBytes<32>| {
            hx::k_id(ld, l, d3, s1, d4, s2).unwrap()
        };
        let base = k(&ld_id, &link, &dh3, &ss_spk, &dh4, &ss_opk);
        // the independent harness agrees
        let h = harness::k_id(&ld_id, link.expose_secret(), dh3.expose_secret(), ss_spk.expose_secret(), dh4.expose_secret(), ss_opk.expose_secret());
        assert_eq!(base.expose_secret(), h.expose_secret(), "{ctx}: library = harness");
        let mut ld2 = ld_id;
        ld2[rng.random_range(0..16_usize)] ^= 1;
        let (l2, d32, s12, d42, s22) = (secret(&mut rng), secret(&mut rng), secret(&mut rng), secret(&mut rng), secret(&mut rng));
        for (name, other) in [
            ("ld_id", k(&ld2, &link, &dh3, &ss_spk, &dh4, &ss_opk)),
            ("link_key", k(&ld_id, &l2, &dh3, &ss_spk, &dh4, &ss_opk)),
            ("DH3", k(&ld_id, &link, &d32, &ss_spk, &dh4, &ss_opk)),
            ("ss_spk", k(&ld_id, &link, &dh3, &s12, &dh4, &ss_opk)),
            ("DH4", k(&ld_id, &link, &dh3, &ss_spk, &d42, &ss_opk)),
            ("ss_opk", k(&ld_id, &link, &dh3, &ss_spk, &dh4, &s22)),
        ] {
            assert_ne!(base.expose_secret(), other.expose_secret(), "{ctx}: K_id changes with {name}");
        }
        // and does not depend on IKSPublic_I, DH1 or DH2: the function has no such parameters, and the session
        // key (which does) is a different value
        let sk = hx::session_key(
            &Shared { dh1: secret(&mut rng), dh2: secret(&mut rng), dh3: SecretBytes::from_slice(dh3.expose_secret()).unwrap(), dh4: SecretBytes::from_slice(dh4.expose_secret()).unwrap(), ss_spk: SecretBytes::from_slice(ss_spk.expose_secret()).unwrap(), ss_opk: SecretBytes::from_slice(ss_opk.expose_secret()).unwrap() },
            &[7; 32],
        )
        .unwrap();
        assert_ne!(sk.expose_secret(), base.expose_secret());
    }
}

// ---- P10, P11 ---------------------------------------------------------------------------------------------------

#[test]
fn prop_inv_hx_canonical() {
    for run in runs(10) {
        let ctx = format!("SECMP_PROPTEST_SEED={} run {}", master_seed(), run.seed);
        // InvitationV1 and its URI
        let inv_bytes = run.accepted.invitation.encode().unwrap();
        assert_eq!(InvitationV1::decode(&inv_bytes).unwrap().encode().unwrap(), inv_bytes, "{ctx}: InvitationV1");
        let parsed = parse_invitation_uri(&run.uri).unwrap();
        assert_eq!(invitation_uri(&parsed).unwrap(), run.uri, "{ctx}: URI");
        // LinkDataV1 (padded)
        let padded = run.accepted.link_data.encode().unwrap();
        assert_eq!(LinkDataV1::decode(&padded).unwrap().encode().unwrap(), padded, "{ctx}: LinkDataV1");
        // Outer (padded), Inner, HandshakeCellPlaintext
        let outer_padded = run.padded();
        let outer = Outer::decode(&outer_padded).unwrap();
        assert_eq!(outer.encode().unwrap().to_vec(), outer_padded, "{ctx}: Outer");
        let ad = [Label::HxInitcell.as_bytes(), run.record.ld_id.as_slice()].concat();
        for c in &run.cells {
            let (n, rest) = c.split_at(24);
            let pt = Caead::open(&run.k_inv, n.try_into().unwrap(), &ad, rest).unwrap();
            let decoded = HandshakeCellPlaintext::decode(&pt).unwrap();
            assert_eq!(decoded.encode().unwrap().to_vec(), pt.to_vec(), "{ctx}: HandshakeCellPlaintext");
        }
        // Inner: the invitee's IKSPublic and a cell-sized value
        let inner = Inner {
            iks: IksPublic::decode(&run.invitee.public().encode().unwrap()).unwrap(),
            first_msg: Cell::from_bytes(&[0x42; 4096]).unwrap(),
        };
        let inner_bytes = inner.encode().unwrap();
        assert_eq!(Inner::decode(&inner_bytes).unwrap().encode().unwrap(), inner_bytes, "{ctx}: Inner");
        // HandshakeCells persistence
        let hc = HandshakeCells::from_bytes(&run.cells.concat()).unwrap();
        assert_eq!(hc.to_bytes().to_vec(), run.cells.concat(), "{ctx}: HandshakeCells");
    }
}

#[test]
fn prop_blob_flip_rejects() {
    for (k, run) in runs(11).enumerate() {
        let mut rng = rng_for(1100 + k as u64);
        for _ in 0..24 {
            let at = rng.random_range(0..run.blob.len());
            let mut blob = run.blob.clone();
            blob[at] ^= 1 << rng.random_range(0..8_u32);
            assert_eq!(
                invitee_accept(&run.uri, &blob, NOW).err(),
                Some(Error::Rejected),
                "SECMP_PROPTEST_SEED={} run {}: blob byte {at}",
                master_seed(),
                run.seed
            );
        }
        for at in [0, 23, 24, 55, 56, run.blob.len() - 17, run.blob.len() - 16, run.blob.len() - 1] {
            let mut blob = run.blob.clone();
            blob[at] ^= 1;
            assert_eq!(invitee_accept(&run.uri, &blob, NOW).err(), Some(Error::Rejected), "blob byte {at}");
        }
        // control
        assert!(open_blob(&run.record.ld_id, &run.record.link_key, &run.blob).is_ok());
    }
}
