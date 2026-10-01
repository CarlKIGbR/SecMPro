// SPDX-License-Identifier: AGPL-3.0-or-later
//! `Responder::accept` and `Initiator::start`: the accepting paths, the grouping rules of ADR-044 (c), the
//! single-use OPK, the structural review-focus checks (TEST-SPEC-M4 (a), (b) grouping rows N-31 … N-33, N-37 …
//! N-39, N-59, N-66, N-67, N-71, and (e)).

use secmp_crypto::SecretBytes;
use secmp_proto::codec::{Decode, Encode};
use secmp_proto::hx::{HandshakeCells, Initiator, InitiatorKeys, Shared, TranscriptInputs};
use secmp_proto::keys::{MlKem768Ek, MlKem1024Ek, X25519Pk};
use secmp_proto::prekeys::{MemoryPrekeyStore, PrekeyStore};
use secmp_proto::tr::{FixedEntropy, RatchetState};
use secmp_proto::wire::cell::RouteDescriptor;
use secmp_proto::wire::hx::{Inner, Outer};
use secmp_proto::wire::inv::{IksPublic, LinkDataV1, Profile};
use secmp_proto::{Error, hx};

use crate::build::{garbage, random_bytes};
use crate::hx_gen::harness::{
    self, CREATED, NOW, OFF_INNER_CT, OPK_ID, SPK_ID, cell_plaintext, cell_raw,
};
use crate::hx_gen::tr_digest::digest;
use crate::scenario::{Lib, fixed};

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// `v[i]`, cloned.
fn at(v: &[Vec<u8>], i: usize) -> Vec<u8> {
    v.get(i).unwrap().clone()
}

/// `v[i..]`, cloned.
fn tail(v: &[Vec<u8>], i: usize) -> Vec<Vec<u8>> {
    v.get(i..).unwrap().to_vec()
}

/// The first two cells of `v`.
fn first_two(v: &[Vec<u8>]) -> Vec<Vec<u8>> {
    v.get(..2).unwrap().to_vec()
}

/// Overwrite `buf[at .. at + src.len()]` with `src`.
fn put(buf: &mut [u8], at: usize, src: &[u8]) {
    buf.get_mut(at..)
        .unwrap()
        .get_mut(..src.len())
        .unwrap()
        .copy_from_slice(src);
}

type StartFn = fn(
    &secmp_proto::wire::inv::InvitationV1,
    &LinkDataV1,
    &InitiatorKeys<'_>,
    &[RouteDescriptor],
    &Profile,
    u64,
    &mut FixedEntropy,
) -> Result<(HandshakeCells, RatchetState), Error>;

/// `accept` on a fresh store; the result and the store.
fn accept_fresh(lib: &Lib, cells: &[Vec<u8>]) -> (Result<hx::Accepted, Error>, MemoryPrekeyStore) {
    let mut store = lib.store();
    let r = lib.accept(&mut store, cells);
    (r, store)
}

fn accepted_ok(lib: &Lib, cells: &[Vec<u8>], what: &str) -> hx::Accepted {
    let (r, store) = accept_fresh(lib, cells);
    let accepted = r.map_err(|e| format!("{what}: {e}")).unwrap();
    assert!(
        !store.opk_ids().contains(&OPK_ID),
        "{what}: the OPK is deleted on success"
    );
    accepted
}

// ---- controls of the builders: the accepting counterpart of every rejecting row ------------------------------

#[test]
fn builders_reproduce_an_accepted_envelope() {
    let lib = Lib::new();
    let h = lib.honest();
    // the full builder with the scenario's initiator and Content is the honest envelope
    assert_eq!(
        lib.full_envelope(&lib.w.i, &lib.honest_content_padded(), None),
        h
    );
    // every re-sealing builder with honest content is accepted
    let first_msg = lib.w.b6.first_msg.clone();
    for (what, cells) in [
        (
            "reseal of the honest Outer",
            lib.reseal(&lib.w.b6.outer, 31),
        ),
        ("outer_variant (no change)", lib.outer_variant(32, |_| {})),
        (
            "inner_variant (honest Inner)",
            lib.inner_variant(33, &lib.honest_inner()),
        ),
        (
            "first_msg_variant (honest first_msg)",
            lib.first_msg_variant(34, &first_msg),
        ),
        (
            "content_variant (honest Content)",
            lib.content_variant(35, &lib.honest_content_padded()),
        ),
        (
            "first_msg with counters 0/0",
            lib.first_msg_variant(36, &lib.first_msg_with_counters(0, 0, 36)),
        ),
        (
            "handshake with the route",
            lib.content_variant(37, &lib.handshake_with_routes(&[lib.route()])),
        ),
        (
            "handshake with an unknown route and the route",
            lib.content_variant(
                38,
                &lib.handshake_with_routes(&[lib.unknown_route(), lib.route()]),
            ),
        ),
    ] {
        accepted_ok(&lib, &cells, what);
    }
    // the reflection control: the same construction for another initiator identity is accepted
    let other = lib.other_identity(0x50);
    let accepted = accepted_ok(
        &lib,
        &lib.full_envelope(&other, &lib.honest_content_padded(), None),
        "other initiator",
    );
    assert_eq!(accepted.peer.encode().unwrap().to_vec(), other.iks_bytes);
}

// ---- (a) positives ---------------------------------------------------------------------------------------------

#[test]
fn accept_garbage_interleaved_succeeds() {
    let lib = Lib::new();
    let h = lib.honest();
    let g = |tag, n| garbage(tag, n);
    // random cells before, between and after the three chunks
    let cells = [
        g(1, 2),
        vec![at(&h, 0)],
        g(2, 3),
        vec![at(&h, 1)],
        g(3, 1),
        vec![at(&h, 2)],
        g(4, 4),
    ]
    .concat();
    let a = accepted_ok(&lib, &cells, "interleaved garbage");
    assert_eq!(a.peer.encode().unwrap().to_vec(), lib.w.i.iks_bytes);
    // a complete foreign group of an invitation holder placed after the honest group
    let foreign = lib.outer_variant(40, |o| *o.get_mut(OFF_INNER_CT + 10).unwrap() ^= 1);
    accepted_ok(
        &lib,
        &[h.clone(), foreign].concat(),
        "foreign group after the honest one",
    );
}

#[test]
fn group_rejected_then_other_init_id_accepts() {
    let lib = Lib::new();
    let h = lib.honest();
    // a complete group that is rejected (inner tag flipped) comes first: it is discarded, the OPK is kept, and the
    // honest group, with another init_id, is processed
    let bad = lib.outer_variant(41, |o| *o.last_mut().unwrap() ^= 1);
    let mut store = lib.store();
    let before = store.digest_kat();
    // first alone: rejected, OPK kept
    assert_eq!(lib.accept(&mut store, &bad).err(), Some(Error::Rejected));
    assert_eq!(store.digest_kat(), before);
    // together: Ok, and only now is the OPK deleted
    let accepted = lib.accept(&mut store, &[bad, h].concat()).unwrap();
    assert!(!store.opk_ids().contains(&OPK_ID));
    assert_eq!(accepted.profile.name(), "alice");
}

#[test]
fn accept_with_retained_previous_spk_succeeds() {
    let lib = Lib::new();
    // a store with SPK 7 (created at CREATED), its OPK and record, rotated eight days later: SPK 8 is current and
    // generation 7 is retained because the unexpired invitation references it (§6.1)
    let mut store = lib.store();
    let later = CREATED + 8 * 24 * 3600;
    assert_eq!(
        store
            .rotate_if_due(later, &mut FixedEntropy::new(&random_bytes(1, 160)))
            .unwrap(),
        SPK_ID + 1
    );
    assert_eq!(store.spk_ids(), vec![SPK_ID, SPK_ID + 1]);
    assert!(
        store.retire_expired(later).is_empty(),
        "the invitation has not expired"
    );
    assert_eq!(
        store.spk_ids(),
        vec![SPK_ID, SPK_ID + 1],
        "generation 7 is retained while referenced"
    );
    lib.accept(&mut store, &lib.honest()).unwrap();
    assert!(!store.opk_ids().contains(&OPK_ID));
}

#[test]
fn accept_with_rotated_out_spk_rejects_and_keeps_opk() {
    let lib = Lib::new();
    // a store that no longer holds generation 7 (rotated out and not retained), with OPK 42 as before
    let mut store = MemoryPrekeyStore::starting_at(SPK_ID + 1, OPK_ID);
    let mut e = FixedEntropy::new(
        &[
            random_bytes(2, 160),
            lib.w.r_seed.get(96 + 160..).unwrap().to_vec(),
        ]
        .concat(),
    );
    store.create_spk(CREATED, &mut e).unwrap();
    store.issue_opk(&mut e).unwrap();
    assert_eq!(store.spk_ids(), vec![SPK_ID + 1]);
    let before = store.digest_kat();
    // the envelope names spk_id 7 and the record does too
    let r = lib.accept(&mut store, &lib.honest());
    assert_eq!(r.err(), Some(Error::Rejected));
    assert_eq!(store.digest_kat(), before);
    assert!(store.opk_ids().contains(&OPK_ID));
}

// ---- grouping (§6.5, ADR-044 (c)) ------------------------------------------------------------------------------

fn bogus_chunk(lib: &Lib, i: u8, tag: u8) -> Vec<u8> {
    cell_raw(
        &lib.w.k_inv,
        &lib.w.inv.ld_id,
        &[tag; 24],
        &cell_plaintext(&lib.w.b6.init_id, i, 3, &[tag; 4006]),
    )
}

#[test]
fn accept_bad_total_or_index_cell_ignored() {
    let lib = Lib::new();
    let h = lib.honest();
    let chunk = harness::chunk_of(&lib.w.b6.outer, 0);
    let bad_total = cell_raw(
        &lib.w.k_inv,
        &lib.w.inv.ld_id,
        &[51; 24],
        &cell_plaintext(&[51; 16], 0, 2, &chunk),
    );
    let bad_index = cell_raw(
        &lib.w.k_inv,
        &lib.w.inv.ld_id,
        &[52; 24],
        &cell_plaintext(&[52; 16], 3, 3, &chunk),
    );
    for (what, bad) in [("total 2", bad_total), ("index 3", bad_index)] {
        accepted_ok(
            &lib,
            &[vec![bad.clone()], h.clone()].concat(),
            &format!("{what} before"),
        );
        accepted_ok(
            &lib,
            &[h.clone(), vec![bad.clone()]].concat(),
            &format!("{what} after"),
        );
        accepted_ok(
            &lib,
            &[vec![at(&h, 0), bad], tail(&h, 1)].concat(),
            &format!("{what} between"),
        );
    }
}

#[test]
fn accept_cell_of_other_invitation_ignored() {
    let lib = Lib::new();
    let h = lib.honest();
    let chunk = harness::chunk_of(&lib.w.b6.outer, 1);
    // a cell under another invitation's K_inv
    let mut other_key = lib.w.inv.link_key;
    *other_key.first_mut().unwrap() ^= 1;
    let other_k_inv = harness::k_inv(&lib.w.inv.ld_id, &other_key);
    let foreign_key = cell_raw(
        &other_k_inv,
        &lib.w.inv.ld_id,
        &[53; 24],
        &cell_plaintext(&lib.w.b6.init_id, 1, 3, &chunk),
    );
    // a cell whose AD names another ld_id
    let mut other_ld = lib.w.inv.ld_id;
    *other_ld.first_mut().unwrap() ^= 1;
    let foreign_ad = cell_raw(
        &lib.w.k_inv,
        &other_ld,
        &[54; 24],
        &cell_plaintext(&lib.w.b6.init_id, 1, 3, &chunk),
    );
    for (what, bad) in [
        ("another K_inv", foreign_key),
        ("another ld_id", foreign_ad),
    ] {
        // placed where the honest chunk 1 is missing: the group cannot complete from it ...
        let cells = vec![at(&h, 0), bad.clone(), at(&h, 2)];
        lib.assert_rejected(&cells, what);
        // ... and next to the honest group it changes nothing
        accepted_ok(&lib, &[vec![bad], h.clone()].concat(), what);
    }
}

#[test]
fn group_duplicate_chunk_differing_first_seen_wins() {
    let lib = Lib::new();
    let h = lib.honest();
    let bogus = bogus_chunk(&lib, 1, 55);
    // the later duplicate is discarded: the honest chunk 1 came first
    accepted_ok(
        &lib,
        &[at(&h, 0), at(&h, 1), bogus.clone(), at(&h, 2)],
        "bogus after the honest chunk",
    );
    accepted_ok(
        &lib,
        &[h.clone(), vec![bogus.clone()]].concat(),
        "bogus after the whole group",
    );
    // the bogus chunk first: it is the one kept, the group completes with it and is rejected (OPK kept)
    lib.assert_rejected(&[vec![bogus], h].concat(), "bogus before the honest chunk");
}

#[test]
fn group_duplicate_chunk_identical_ignored() {
    let lib = Lib::new();
    let h = lib.honest();
    let doubled: Vec<Vec<u8>> = h.iter().flat_map(|c| [c.clone(), c.clone()]).collect();
    accepted_ok(&lib, &doubled, "every cell twice");
    accepted_ok(&lib, &[h.clone(), h.clone()].concat(), "the group twice");
    accepted_ok(
        &lib,
        &[vec![at(&h, 0), at(&h, 0), at(&h, 0)], tail(&h, 1)].concat(),
        "chunk 0 three times",
    );
}

#[test]
fn group_partial_store_bound_8_evicts_oldest() {
    let lib = Lib::new();
    let partial = |k: u8| lib.reseal(&lib.w.b6.outer, k + 1);
    // nine partial groups (chunks 0 and 1), then the missing chunk of the oldest
    let mut cells: Vec<Vec<u8>> = (0..9).flat_map(|k| first_two(&partial(k))).collect();
    cells.push(at(&partial(0), 2));
    lib.assert_rejected(&cells, "the oldest of nine partial groups is evicted");
    // control: eight partial groups, the missing chunk of the oldest completes it
    let mut cells: Vec<Vec<u8>> = (0..8).flat_map(|k| first_two(&partial(k))).collect();
    cells.push(at(&partial(0), 2));
    accepted_ok(&lib, &cells, "eight partial groups are held");
    // and the second oldest of nine is still held
    let mut cells: Vec<Vec<u8>> = (0..9).flat_map(|k| first_two(&partial(k))).collect();
    cells.push(at(&partial(1), 2));
    accepted_ok(&lib, &cells, "the second oldest of nine survives");
}

// ---- the OPK (§6.6 step 1, step 4) -----------------------------------------------------------------------------

#[test]
fn accept_wrong_opk_id_rejects_and_keeps_opk() {
    let lib = Lib::new();
    // another live OPK in the store (another invitation's), and an envelope that names it
    let mut store = lib.store();
    let other = store
        .issue_opk(&mut FixedEntropy::new(&random_bytes(3, 96)))
        .unwrap();
    assert_eq!(other, OPK_ID + 1);
    let before = store.digest_kat();
    let cells = lib.outer_variant(60, |o| {
        put(o, harness::OFF_OPK_ID, &other.to_be_bytes());
    });
    assert_eq!(lib.accept(&mut store, &cells).err(), Some(Error::Rejected));
    assert_eq!(store.digest_kat(), before, "both OPKs untouched");
    assert_eq!(store.opk_ids(), vec![OPK_ID, other]);
    // an unknown id is the table's N-37 row
}

#[test]
fn accept_used_opk_rejects() {
    let lib = Lib::new();
    let mut store = lib.store();
    store.delete_opk(OPK_ID).unwrap();
    let before = store.digest_kat();
    assert_eq!(
        lib.accept(&mut store, &lib.honest()).err(),
        Some(Error::Rejected)
    );
    assert_eq!(store.digest_kat(), before);
}

#[test]
fn accept_replayed_envelope_rejects_after_success() {
    let lib = Lib::new();
    let h = lib.honest();
    let mut store = lib.store();
    let accepted = lib.accept(&mut store, &h).unwrap();
    let session = accepted.state.to_bytes().unwrap().to_vec();
    let after = store.digest_kat();
    // the same three cells, and the retransmitted copies
    for cells in [h.clone(), [h.clone(), h.clone()].concat()] {
        assert_eq!(lib.accept(&mut store, &cells).err(), Some(Error::Rejected));
        assert_eq!(store.digest_kat(), after, "store unchanged by the replay");
    }
    assert_eq!(
        accepted.state.to_bytes().unwrap().to_vec(),
        session,
        "the first session is unaffected"
    );
}

#[test]
fn accept_success_deletes_exactly_that_opk() {
    let lib = Lib::new();
    let mut store = lib.store();
    store
        .issue_opk(&mut FixedEntropy::new(&random_bytes(4, 96)))
        .unwrap();
    let mut reference = lib.store();
    reference
        .issue_opk(&mut FixedEntropy::new(&random_bytes(4, 96)))
        .unwrap();
    reference.delete_opk(OPK_ID).unwrap();
    lib.accept(&mut store, &lib.honest()).unwrap();
    assert_eq!(store.opk_ids(), vec![OPK_ID + 1]);
    assert_eq!(store.spk_ids(), vec![SPK_ID]);
    assert_eq!(
        store.digest_kat(),
        reference.digest_kat(),
        "SPK, RPK, the other OPK and the record unchanged"
    );
}

#[test]
fn retransmitted_handshake_cells_after_success_are_tr_rejects() {
    let lib = Lib::new();
    let accepted = accepted_ok(&lib, &lib.honest(), "honest");
    let mut state = accepted.state;
    for cell in lib.honest() {
        let before = state.to_bytes().unwrap().to_vec();
        let refused = state
            .decrypt(&cell)
            .err()
            .expect("a handshake cell is not a TR cell of the session");
        assert_eq!(refused.error(), Error::Rejected);
        state = refused.into_state();
        assert_eq!(
            state.to_bytes().unwrap().to_vec(),
            before,
            "the session state is unchanged"
        );
    }
}

// ---- results: routes, state, identity ------------------------------------------------------------------------------

#[test]
fn accept_stored_routes_equal_first_msg_routes() {
    let lib = Lib::new();
    let a = accepted_ok(&lib, &lib.honest(), "honest");
    // byte-identical to what the initiator put in first_msg, and no other source
    let routes: Vec<Vec<u8>> = a
        .routes
        .iter()
        .map(|r: &RouteDescriptor| r.encode().unwrap().to_vec())
        .collect();
    assert_eq!(routes, vec![lib.route()]);
    assert_eq!(
        a.profile.encode().unwrap().to_vec(),
        harness::profile_bytes("alice", Some(lib.w.b6.avatar))
    );
    // a different route in first_msg is what is stored (not the one of the unaffected scenario)
    let other = lib.other_route();
    let a = accepted_ok(
        &lib,
        &lib.content_variant(61, &lib.handshake_with_routes(std::slice::from_ref(&other))),
        "other route",
    );
    assert_eq!(a.routes.first().unwrap().encode().unwrap().to_vec(), other);
}

#[test]
fn accept_state_holds_no_prekey_secret() {
    let lib = Lib::new();
    let a = accepted_ok(&lib, &lib.honest(), "honest");
    let state = a.state.to_bytes().unwrap().to_vec();
    let keys = &lib.w.keys;
    for (name, secret) in [
        ("SPK_dh", keys.spk_dh.expose_secret().to_vec()),
        ("SPK_kem", keys.spk_kem.expose_seed().to_vec()),
        ("RPK_kem", keys.rpk_kem.expose_seed().to_vec()),
        ("OPK_dh", keys.opk_dh.expose_secret().to_vec()),
        ("OPK_kem", keys.opk_kem.expose_seed().to_vec()),
    ] {
        assert!(
            !contains(&state, &secret),
            "the returned state holds the {name} secret"
        );
    }
}

#[test]
fn initiator_start_output_and_state_contain_no_ek_secret() {
    let lib = Lib::new();
    let e = &lib.w.b6.entropy;
    let ek_sk = e.get(..32).unwrap().to_vec();
    let accepted = secmp_proto::inv::invitee_accept(&lib.w.uri, &lib.w.blob, NOW).unwrap();
    let route = RouteDescriptor::decode(&lib.route()).unwrap();
    let (cells, state) = Initiator::start(
        &accepted.invitation,
        &accepted.link_data,
        &lib.i_id.initiator_keys(),
        &[route],
        &Profile::new("alice", Some(lib.w.b6.avatar)).unwrap(),
        1_700_000_001,
        &mut FixedEntropy::new(e),
    )
    .unwrap();
    // structural: the outputs are `HandshakeCells` and `RatchetState`, neither has an EK field; by content: the
    // serialised state and the cells do not contain the scalar (nor its clamped form)
    let state_bytes = state.to_bytes().unwrap().to_vec();
    let cell_bytes = cells.to_bytes().to_vec();
    let mut clamped = ek_sk.clone();
    *clamped.first_mut().unwrap() &= 0xf8;
    *clamped.last_mut().unwrap() &= 0x7f;
    *clamped.last_mut().unwrap() |= 0x40;
    for secret in [&ek_sk, &clamped] {
        assert!(
            !contains(&state_bytes, secret),
            "the persisted initiator state holds EK_I"
        );
        assert!(!contains(&cell_bytes, secret), "the cells hold EK_I");
    }
    // the matching public key is in the cells' plaintext only (sealed): not visible in the ciphertext either
    assert!(!contains(&cell_bytes, &lib.w.b6.a.ek_pk));
}

#[test]
fn initiator_takes_no_signing_key() {
    // type level: `start`'s parameters are the invitation, the verified link data, `InitiatorKeys`, routes, profile,
    // a time and the randomness source; `InitiatorKeys` has exactly the two fields `iks` (public) and `ik_dh` (the
    // X25519 identity secret) — the literal below stops compiling if a signing key is added to it
    let lib = Lib::new();
    let keys = InitiatorKeys {
        iks: lib.i_id.public(),
        ik_dh: lib.i_id.ik_dh(),
    };
    let start: StartFn = Initiator::start::<FixedEntropy>;
    std::hint::black_box((keys, start));
}

#[test]
fn envelope_has_no_signature() {
    let lib = Lib::new();
    let w = &lib.w;
    // Inner is exactly IKSPublic ‖ Cell (2017 + 4096), Outer exactly the §6.5 fields
    let inner = Inner::decode(&w.b6.inner).unwrap();
    assert_eq!(inner.encode().unwrap().len(), 2017 + 4096);
    assert_eq!(w.b6.inner.len(), 2017 + 4096);
    assert_eq!(w.b6.outer.len(), 1 + 32 + 4 + 4 + 1568 + 1568 + 6185);
    let padded = secmp_proto::codec::pad(&w.b6.outer, 12_018).unwrap();
    let outer = Outer::decode(&padded).unwrap();
    assert_eq!(outer.encode().unwrap().to_vec(), padded.to_vec());
    // and a signature-sized tail does not fit: the initiator's randomness is exactly the case-6 draws
    // (`hybridsign_not_called_by_initiator` below)
}

#[test]
fn hybridsign_not_called_by_initiator() {
    let lib = Lib::new();
    // `HybridSign` is reachable only through `Entropy::sign`, which reads 32 bytes of ML-DSA hedge from the
    // derandomised source: `start` consumes exactly its documented draws (the vector run asserts the same), so it
    // never signs
    let accepted = secmp_proto::inv::invitee_accept(&lib.w.uri, &lib.w.blob, NOW).unwrap();
    let mut e = FixedEntropy::new(&lib.w.b6.entropy);
    let route = RouteDescriptor::decode(&lib.route()).unwrap();
    Initiator::start(
        &accepted.invitation,
        &accepted.link_data,
        &lib.i_id.initiator_keys(),
        &[route],
        &Profile::new("alice", Some(lib.w.b6.avatar)).unwrap(),
        1_700_000_001,
        &mut e,
    )
    .unwrap();
    assert_eq!(e.remaining(), 0);
    // with 32 extra bytes available they stay unread
    let mut extra = lib.w.b6.entropy.clone();
    extra.extend_from_slice(&[0xab; 32]);
    let mut e = FixedEntropy::new(&extra);
    let route = RouteDescriptor::decode(&lib.route()).unwrap();
    Initiator::start(
        &accepted.invitation,
        &accepted.link_data,
        &lib.i_id.initiator_keys(),
        &[route],
        &Profile::new("alice", Some(lib.w.b6.avatar)).unwrap(),
        1_700_000_001,
        &mut e,
    )
    .unwrap();
    assert_eq!(e.remaining(), 32, "no signing draw");
}

#[test]
fn initiator_cells_persisted_with_state() {
    let lib = Lib::new();
    let accepted = secmp_proto::inv::invitee_accept(&lib.w.uri, &lib.w.blob, NOW).unwrap();
    let route = RouteDescriptor::decode(&lib.route()).unwrap();
    let (cells, state) = Initiator::start(
        &accepted.invitation,
        &accepted.link_data,
        &lib.i_id.initiator_keys(),
        &[route],
        &Profile::new("alice", Some(lib.w.b6.avatar)).unwrap(),
        1_700_000_001,
        &mut FixedEntropy::new(&lib.w.b6.entropy),
    )
    .unwrap();
    // a failing persist releases nothing
    let failed = HandshakeCells::from_bytes(&cells.to_bytes())
        .unwrap()
        .release(|_| Err::<(), &str>("disk full"));
    assert_eq!(failed.err(), Some("disk full"));
    // the cells and the state are persisted before any cell is handed out
    let state_bytes = state.to_bytes().unwrap().to_vec();
    let mut durable: Option<Vec<u8>> = None;
    let released = cells
        .release(|bytes| {
            durable = Some(bytes.to_vec());
            Ok::<(), ()>(())
        })
        .unwrap();
    let durable = durable.expect("persist was called before the release");
    assert_eq!(durable.len(), 3 * 4096);
    assert_eq!(released.len(), 3);
    for (cell, chunk) in released.iter().zip(durable.chunks(4096)) {
        assert_eq!(cell.as_bytes().as_slice(), chunk);
    }
    // after a restart: the persisted bytes restore both, and they are the honest ones
    let restored = RatchetState::from_bytes(&state_bytes).unwrap();
    assert_eq!(digest(&restored), digest(&state));
    assert_eq!(durable, lib.honest().concat());
}

#[test]
fn initiator_retry_resends_identical_cells() {
    let lib = Lib::new();
    let persisted = lib.honest().concat();
    // a retry restores the persisted cells and re-sends them byte-identical: no sealing, no randomness (the
    // restoring functions take no entropy source)
    for _ in 0..3 {
        let again = HandshakeCells::from_bytes(&persisted).unwrap();
        let sent = again
            .release(|b| {
                if b == persisted.as_slice() {
                    Ok(())
                } else {
                    Err(())
                }
            })
            .unwrap();
        let joined: Vec<u8> = sent.iter().flat_map(|c| c.as_bytes().to_vec()).collect();
        assert_eq!(joined, persisted);
    }
    assert_eq!(
        HandshakeCells::from_bytes(persisted.get(..8191).unwrap()).err(),
        Some(Error::Rejected)
    );
    assert_eq!(
        HandshakeCells::from_bytes(&[persisted.clone(), vec![0]].concat()).err(),
        Some(Error::Rejected)
    );
}

// ---- (e) review focus: transcript, K_id ------------------------------------------------------------------------------

struct Parts {
    iks_r: IksPublic,
    iks_i: IksPublic,
    spk_dh: X25519Pk,
    spk_kem: MlKem1024Ek,
    rpk_kem: MlKem768Ek,
    opk_dh: X25519Pk,
    opk_kem: MlKem1024Ek,
    ek_i: X25519Pk,
    ct_spk: [u8; 1568],
    ct_opk: [u8; 1568],
    ld_id: [u8; 16],
    spk_id: u32,
    opk_id: u32,
}

fn parts(lib: &Lib) -> Parts {
    let w = &lib.w;
    let link: LinkDataV1 = secmp_proto::inv::open_blob(
        &w.inv.ld_id,
        &SecretBytes::from_slice(&w.inv.link_key).unwrap(),
        &w.blob,
    )
    .unwrap();
    Parts {
        iks_r: link.inviter_iks.clone(),
        iks_i: IksPublic::decode(&w.i.iks_bytes).unwrap(),
        spk_dh: link.bundle.spk_dh,
        spk_kem: link.bundle.spk_kem.clone(),
        rpk_kem: link.bundle.rpk_kem.clone(),
        opk_dh: link.bundle.opk_dh,
        opk_kem: link.bundle.opk_kem.clone(),
        ek_i: X25519Pk::from_bytes(&w.b6.a.ek_pk).unwrap(),
        ct_spk: w.b6.a.ct_spk.clone().try_into().unwrap(),
        ct_opk: w.b6.a.ct_opk.clone().try_into().unwrap(),
        ld_id: w.inv.ld_id,
        spk_id: SPK_ID,
        opk_id: OPK_ID,
    }
}

fn lib_transcript(p: &Parts) -> [u8; 32] {
    hx::transcript(&TranscriptInputs {
        iks_r: &p.iks_r,
        spk_id: p.spk_id,
        spk_dh: &p.spk_dh,
        spk_kem: &p.spk_kem,
        rpk_kem: &p.rpk_kem,
        opk_id: p.opk_id,
        opk_dh: &p.opk_dh,
        opk_kem: &p.opk_kem,
        iks_i: &p.iks_i,
        ek_i: &p.ek_i,
        ct_spk: &p.ct_spk,
        ct_opk: &p.ct_opk,
        ld_id: &p.ld_id,
    })
    .unwrap()
}

#[test]
fn transcript_matches_independent_concatenation() {
    let lib = Lib::new();
    let p = parts(&lib);
    // the test code's own concatenation (hx_harness::transcript: plain SHA-256 over the thirteen components)
    assert_eq!(lib_transcript(&p), lib.w.b6.a.transcript);
    let kem = |ek: &[u8]| ek.to_vec();
    let independent = harness::transcript([
        &lib.w.r.iks_bytes,
        &SPK_ID.to_be_bytes(),
        p.spk_dh.as_bytes(),
        &kem(p.spk_kem.as_bytes()),
        &kem(p.rpk_kem.as_bytes()),
        &OPK_ID.to_be_bytes(),
        p.opk_dh.as_bytes(),
        &kem(p.opk_kem.as_bytes()),
        &lib.w.i.iks_bytes,
        p.ek_i.as_bytes(),
        &p.ct_spk,
        &p.ct_opk,
        &p.ld_id,
    ]);
    assert_eq!(lib_transcript(&p), independent);
}

#[test]
fn transcript_iks_encoded_2017_bytes() {
    let lib = Lib::new();
    let p = parts(&lib);
    assert_eq!(p.iks_r.encode().unwrap().len(), 2017);
    assert_eq!(p.iks_i.encode().unwrap().len(), 2017);
}

/// Eight of the thirteen single-component mutations of the transcript inputs (§6.4).
fn mutations(lib: &Lib) -> Vec<(&'static str, Parts)> {
    let other = lib.other_identity(0x71);
    let other_iks = IksPublic::decode(&other.iks_bytes).unwrap();
    let other_x = X25519Pk::from_bytes(other.iks.ik_dh.as_bytes()).unwrap();
    let other_kem1024 = {
        let p = parts(lib);
        // a second valid ML-KEM-1024 key: the OPK's key as the SPK, and vice versa
        (p.opk_kem, p.spk_kem)
    };
    let alt_rpk = MlKem768Ek::from_bytes(
        secmp_crypto::MlKem768Dk::from_seed(&[0x33; 64])
            .unwrap()
            .encapsulation_key()
            .as_bytes(),
    )
    .unwrap();
    vec![
        (
            "IKSPublic_R",
            Parts {
                iks_r: other_iks.clone(),
                ..parts(lib)
            },
        ),
        (
            "SPK_dh",
            Parts {
                spk_dh: other_x,
                ..parts(lib)
            },
        ),
        (
            "SPK_kem",
            Parts {
                spk_kem: other_kem1024.0.clone(),
                ..parts(lib)
            },
        ),
        (
            "RPK_kem",
            Parts {
                rpk_kem: alt_rpk,
                ..parts(lib)
            },
        ),
        (
            "OPK_dh",
            Parts {
                opk_dh: other_x,
                ..parts(lib)
            },
        ),
        (
            "OPK_kem",
            Parts {
                opk_kem: other_kem1024.1.clone(),
                ..parts(lib)
            },
        ),
        (
            "IKSPublic_I",
            Parts {
                iks_i: other_iks,
                ..parts(lib)
            },
        ),
        (
            "EK_I",
            Parts {
                ek_i: other_x,
                ..parts(lib)
            },
        ),
    ]
}

/// The other five single-component mutations of the transcript inputs (§6.4).
fn scalar_mutations(lib: &Lib, base: &Parts) -> Vec<(&'static str, Parts)> {
    let flip = |mut b: [u8; 1568]| {
        b[0] ^= 1;
        b
    };
    vec![
        (
            "spk_id",
            Parts {
                spk_id: SPK_ID + 1,
                ..parts(lib)
            },
        ),
        (
            "opk_id",
            Parts {
                opk_id: OPK_ID + 1,
                ..parts(lib)
            },
        ),
        (
            "ct_spk",
            Parts {
                ct_spk: flip(base.ct_spk),
                ..parts(lib)
            },
        ),
        (
            "ct_opk",
            Parts {
                ct_opk: flip(base.ct_opk),
                ..parts(lib)
            },
        ),
        (
            "ld_id",
            Parts {
                ld_id: [0x5a; 16],
                ..parts(lib)
            },
        ),
    ]
}

#[test]
fn transcript_each_component_changes_sk() {
    let lib = Lib::new();
    let base = parts(&lib);
    let a = &lib.w.b6.a;
    let shared = || Shared {
        dh1: SecretBytes::from_slice(&a.dh[0]).unwrap(),
        dh2: SecretBytes::from_slice(&a.dh[1]).unwrap(),
        dh3: SecretBytes::from_slice(&a.dh[2]).unwrap(),
        dh4: SecretBytes::from_slice(&a.dh[3]).unwrap(),
        ss_spk: SecretBytes::from_slice(&a.ss_spk).unwrap(),
        ss_opk: SecretBytes::from_slice(&a.ss_opk).unwrap(),
    };
    let base_t = lib_transcript(&base);
    let base_sk = hx::session_key(&shared(), &base_t).unwrap();
    let mut mutations = mutations(&lib);
    mutations.extend(scalar_mutations(&lib, &base));
    assert_eq!(mutations.len(), 13);
    for (name, mutated) in &mutations {
        let t = lib_transcript(mutated);
        assert_ne!(t, base_t, "the transcript changes with {name}");
        let sk = hx::session_key(&shared(), &t).unwrap();
        assert_ne!(
            sk.expose_secret(),
            base_sk.expose_secret(),
            "SK changes with {name}"
        );
    }
}

#[test]
fn k_id_matches_spec_hkdf() {
    let lib = Lib::new();
    let a = &lib.w.b6.a;
    let secret = |b: &[u8]| SecretBytes::<32>::from_slice(b).unwrap();
    let link_key = secret(&lib.w.inv.link_key);
    let k = hx::k_id(
        &lib.w.inv.ld_id,
        &link_key,
        &secret(&a.dh[2]),
        &secret(&a.ss_spk),
        &secret(&a.dh[3]),
        &secret(&a.ss_opk),
    )
    .unwrap();
    // salt = ld_id, IKM = link_key ‖ DH3 ‖ ss_spk ‖ DH4 ‖ ss_opk, info = "SecMP-HX/1 idkey", L = 32
    let ikm = [
        lib.w.inv.link_key.as_slice(),
        &a.dh[2],
        &a.ss_spk,
        &a.dh[3],
        &a.ss_opk,
    ]
    .concat();
    let expected =
        secmp_crypto::hkdf::<32>(&lib.w.inv.ld_id, &ikm, secmp_crypto::Label::HxIdkey, &[])
            .unwrap();
    assert_eq!(k.expose_secret(), expected.expose_secret());
    assert_eq!(
        k.expose_secret().as_slice(),
        a.k_id.expose_secret().as_slice()
    );
    assert_eq!(secmp_crypto::Label::HxIdkey.as_bytes(), b"SecMP-HX/1 idkey");
}

#[test]
fn k_id_derived_before_initiator_identity() {
    let lib = Lib::new();
    let a = &lib.w.b6.a;
    let secret = |b: &[u8]| SecretBytes::<32>::from_slice(b).unwrap();
    // `hx::k_id` takes no identity and no DH1/DH2: it is a function of ld_id, link_key, DH3, ss_spk, DH4, ss_opk
    let k = |dh3: &[u8], ss_spk: &[u8], dh4: &[u8], ss_opk: &[u8], link: &[u8]| {
        hx::k_id(
            &lib.w.inv.ld_id,
            &secret(link),
            &secret(dh3),
            &secret(ss_spk),
            &secret(dh4),
            &secret(ss_opk),
        )
        .unwrap()
    };
    let base = k(
        &a.dh[2],
        &a.ss_spk,
        &a.dh[3],
        &a.ss_opk,
        &lib.w.inv.link_key,
    );
    let flipped = |v: &Vec<u8>| {
        let mut x = v.clone();
        *x.first_mut().unwrap() ^= 1;
        x
    };
    let mut link = lib.w.inv.link_key;
    link[0] ^= 1;
    assert_ne!(
        base.expose_secret(),
        k(
            &flipped(&a.dh[2]),
            &a.ss_spk,
            &a.dh[3],
            &a.ss_opk,
            &lib.w.inv.link_key
        )
        .expose_secret(),
        "DH3"
    );
    assert_ne!(
        base.expose_secret(),
        k(
            &a.dh[2],
            &flipped(&a.ss_spk),
            &a.dh[3],
            &a.ss_opk,
            &lib.w.inv.link_key
        )
        .expose_secret(),
        "ss_spk"
    );
    assert_ne!(
        base.expose_secret(),
        k(
            &a.dh[2],
            &a.ss_spk,
            &flipped(&a.dh[3]),
            &a.ss_opk,
            &lib.w.inv.link_key
        )
        .expose_secret(),
        "DH4"
    );
    assert_ne!(
        base.expose_secret(),
        k(
            &a.dh[2],
            &a.ss_spk,
            &a.dh[3],
            &flipped(&a.ss_opk),
            &lib.w.inv.link_key
        )
        .expose_secret(),
        "ss_opk"
    );
    assert_ne!(
        base.expose_secret(),
        k(&a.dh[2], &a.ss_spk, &a.dh[3], &a.ss_opk, &link).expose_secret(),
        "link_key"
    );
    // R computes the same K_id from its own secrets before it has parsed IKSPublic_I: an envelope whose Inner has an
    // undecodable IKS but a correct K_id reaches the inner decoder (and is rejected there), see `accept_inner_*`
}

#[test]
fn k_inv_k_ld_k_id_distinct() {
    let lib = Lib::new();
    let w = &lib.w;
    let keys = [
        w.k_ld.expose_secret(),
        w.k_inv.expose_secret(),
        w.b6.a.k_id.expose_secret(),
    ];
    assert_ne!(keys[0], keys[1]);
    assert_ne!(keys[0], keys[2]);
    assert_ne!(keys[1], keys[2]);
    assert_eq!(
        secmp_crypto::Label::InvLinkdata.as_bytes(),
        b"SecMP-INV/1 linkdata"
    );
    assert_eq!(
        secmp_crypto::Label::HxInitkey.as_bytes(),
        b"SecMP-HX/1 initkey"
    );
    assert_eq!(secmp_crypto::Label::HxIdkey.as_bytes(), b"SecMP-HX/1 idkey");
    let _ = (fixed(&[]), CREATED);
}
