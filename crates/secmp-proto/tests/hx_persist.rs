// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! The bytes `HandshakeCells::release` hands to `persist` (persist-before-send, V-6, M3 review F13): exactly the
//! three released cells and the serialised initiator state. OS randomness and no feature `kat`, so that the
//! mutation gate (which builds `secmp-proto` without `kat`) runs it: `HandshakeCells::to_bytes` and `join_cells`
//! are otherwise checked only by the `kat`-gated `hx` suite (M4-6, PR run 36930469555: 9 missed mutants).

use secmp_crypto::SecretBytes;
use secmp_proto::Encode;
use secmp_proto::hx::{HandshakeCells, Initiator, PersistedCells, Responder};
use secmp_proto::inv::{invitation_uri, invitee_accept};
use secmp_proto::prekeys::{
    IdentityKeys, InvitationRecord, IssueParams, Issued, MemoryPrekeyStore,
};
use secmp_proto::tr::{Entropy, OsEntropy, RatchetState};
use secmp_proto::wire::Period;
use secmp_proto::wire::cell::{Cell, RelayQueue, RouteDescriptor};
use secmp_proto::wire::inv::{Onion, Profile, RelayRef};

const CREATED: u64 = 1_700_000_000;
const NOW: u64 = 1_700_000_100;
const EXPIRES: u64 = 1_702_592_000;

fn relay_ref(seed: u8) -> RelayRef {
    RelayRef {
        relay_fp: [seed; 32],
        onion: Onion::from_pubkey(&[seed.wrapping_add(1); 32]),
        akc: [seed.wrapping_add(2); 32],
        direct: None,
    }
}

fn route(seed: u8) -> RouteDescriptor {
    RouteDescriptor::RelayQueue(RelayQueue {
        relay: relay_ref(seed),
        sid: [seed.wrapping_add(3); 16],
        send_seed: SecretBytes::from_slice(&[seed.wrapping_add(4); 32]).unwrap(),
        period_s: Period::S20,
    })
}

/// The inviter: identity, prekey store and one issued invitation with its URI.
struct Inviter {
    identity: IdentityKeys,
    store: MemoryPrekeyStore,
    issued: Issued,
    uri: String,
}

impl Inviter {
    fn new(entropy: &mut impl Entropy) -> Self {
        let identity = IdentityKeys::generate(entropy).unwrap();
        let mut store = MemoryPrekeyStore::default();
        let issued = store
            .issue_invitation(
                &identity,
                IssueParams {
                    relay: relay_ref(10),
                    inv_period: Period::S20,
                    profile: Profile::new("bob", None).unwrap(),
                    now: CREATED,
                    expires: EXPIRES,
                    spk_expiry: EXPIRES,
                },
                entropy,
            )
            .unwrap();
        let uri = invitation_uri(&issued.invitation).unwrap().to_string();
        Self {
            identity,
            store,
            issued,
            uri,
        }
    }

    fn record(&self) -> &InvitationRecord {
        self.store.record(&self.issued.invitation.ld_id).unwrap()
    }
}

struct Run {
    inviter: Inviter,
    guest: IdentityKeys,
    cells: HandshakeCells,
    state: RatchetState,
}

fn run() -> Run {
    let mut rng = OsEntropy;
    let inviter = Inviter::new(&mut rng);
    let guest = IdentityKeys::generate(&mut rng).unwrap();
    let blob = inviter.issued.blob.encode().unwrap();
    let accepted = invitee_accept(&inviter.uri, blob.as_slice(), NOW).unwrap();
    let (cells, state) = Initiator::start(
        &accepted,
        &guest.initiator_keys(),
        &[route(20)],
        &Profile::new("alice", Some([9; 32])).unwrap(),
        NOW + 1,
        &mut rng,
    )
    .unwrap();
    Run {
        inviter,
        guest,
        cells,
        state,
    }
}

fn concat(cells: &[Cell; 3]) -> Vec<u8> {
    cells.iter().flat_map(|c| c.as_bytes().to_vec()).collect()
}

#[test]
fn release_persists_exactly_the_three_cells() {
    let r = run();
    let mut captured: Option<(Vec<u8>, Vec<u8>)> = None;
    let released = r
        .cells
        .release(&r.state, |cells_bytes, state_bytes| {
            captured = Some((cells_bytes.to_vec(), state_bytes.to_vec()));
            Ok::<(), secmp_proto::Error>(())
        })
        .unwrap();
    let (cells_bytes, state_bytes) = captured.unwrap();
    assert_eq!(cells_bytes.len(), 3 * 4096);
    let [a, b, c] = &released;
    let expected: Vec<u8> = [a.as_bytes().as_slice(), b.as_bytes(), c.as_bytes()].concat();
    assert_eq!(cells_bytes, expected);
    assert!(!state_bytes.is_empty());
    let restored = RatchetState::from_bytes(&state_bytes).unwrap();
    assert_eq!(
        restored.to_bytes().unwrap().as_slice(),
        state_bytes.as_slice()
    );
    assert_eq!(
        r.state.to_bytes().unwrap().as_slice(),
        state_bytes.as_slice()
    );
    let persisted = PersistedCells::from_bytes(&cells_bytes).unwrap();
    assert_eq!(persisted.to_bytes().as_slice(), cells_bytes.as_slice());
    assert_eq!(concat(&persisted.into_cells()), cells_bytes);
}

#[test]
fn persisted_cells_are_accepted_by_the_responder() {
    let mut r = run();
    let mut persisted_bytes = Vec::new();
    let released = r
        .cells
        .release(&r.state, |cells_bytes, _| {
            persisted_bytes = cells_bytes.to_vec();
            Ok::<(), secmp_proto::Error>(())
        })
        .unwrap();
    // the retry path: what comes back from the store is what was released
    let restored = PersistedCells::from_bytes(&persisted_bytes)
        .unwrap()
        .into_cells();
    assert_eq!(concat(&restored), concat(&released));
    let record = r.inviter.record().duplicate().unwrap();
    let accepted = Responder::accept(
        &restored,
        &record,
        &mut r.inviter.store,
        &r.inviter.identity.responder_keys(),
        &mut OsEntropy,
    )
    .unwrap();
    assert_eq!(
        accepted.peer.encode().unwrap(),
        r.guest.public().encode().unwrap()
    );
    assert_eq!(accepted.profile.name(), "alice");
    assert_eq!(accepted.routes.len(), 1);
    assert_eq!(
        accepted
            .routes
            .first()
            .unwrap()
            .encode()
            .unwrap()
            .as_slice(),
        route(20).encode().unwrap().as_slice()
    );
}

#[test]
fn release_hands_persist_the_same_bytes_it_returns() {
    let r = run();
    let mut calls = 0_u32;
    let mut captured = Vec::new();
    let released = r
        .cells
        .release(&r.state, |cells_bytes, _| {
            calls += 1;
            captured = cells_bytes.to_vec();
            Ok::<(), secmp_proto::Error>(())
        })
        .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(captured, concat(&released));
    assert!(captured.iter().any(|&b| b != 0));
}

/// M4 review C-8 (R-22): `release` persists the initiator state as it is at release time. After `start`, one dummy is
/// sealed with the returned state and persisted (`n_s` 1 → 2); `release(&state, …)` then hands `persist` the
/// serialisation of that live state — not the one right after `start`, which would roll `n_s` back and make a restart
/// reuse the message key of the dummy.
#[test]
fn release_persists_the_state_at_release_time() {
    let r = run();
    let after_start = r.state.to_bytes().unwrap().to_vec();
    let sealed = r
        .state
        .encrypt(&secmp_proto::tr::content::dummy())
        .map_err(|refused| refused.error())
        .unwrap();
    let (state, _dummy) = sealed
        .persist(|_| Ok::<(), secmp_proto::Error>(()))
        .unwrap();
    let at_release = state.to_bytes().unwrap().to_vec();
    assert_ne!(at_release, after_start, "the dummy advanced the state");
    let mut persisted = None;
    r.cells
        .release(&state, |_, state_bytes| {
            persisted = Some(state_bytes.to_vec());
            Ok::<(), secmp_proto::Error>(())
        })
        .unwrap();
    let persisted = persisted.unwrap();
    assert_eq!(persisted, at_release);
    assert_ne!(persisted, after_start);
    assert_eq!(
        RatchetState::from_bytes(&persisted)
            .unwrap()
            .to_bytes()
            .unwrap()
            .as_slice(),
        at_release.as_slice()
    );
}
