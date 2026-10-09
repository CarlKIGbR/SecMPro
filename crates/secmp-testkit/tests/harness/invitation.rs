// SPDX-License-Identifier: AGPL-3.0-or-later
//! H-02 (invitation and handshake over the relay) and H-09 (the scenario API is public): the whole of §5.5, §6.4–6.6
//! and §9.4 between two harness clients, through `pub` items of `secmp_testkit::harness` only.

use secmp_crypto::SecretBytes;
use secmp_proto::Encode;
use secmp_proto::hx::{Initiator, Responder};
use secmp_proto::inv::{invitation_uri, invitee_check, parse_invitation_uri};
use secmp_proto::keys::Ed25519Pk;
use secmp_proto::link::ids::akc;
use secmp_proto::prekeys::{
    IdentityKeys, InvitationRecord, IssueParams, Issued, MemoryPrekeyStore,
};
use secmp_proto::tr::RatchetState;
use secmp_proto::wire::Period;
use secmp_proto::wire::cell::{Cell, RelayQueue, RouteDescriptor};
use secmp_proto::wire::inv::{Onion, Profile, RelayRef};
use secmp_relay::HourBucket;
use secmp_testkit::harness::{ClientId, Harness, HarnessConfig, Side};
use secmp_transport::{LinkGetMode, QueueTransport, RecvCap, SendCap};

use crate::scenarios::pair;

/// What the invitation scenario observed.
pub struct Outcome {
    /// `(present, consumed)` of the owner-status query after the invitee consumed the link data.
    pub owner_status: (bool, bool),
    /// The inviter learned the invitee's profile name.
    pub invitee_name: String,
    /// Text the inviter sent to the invitee through the route in the invitee's Handshake, as the invitee received it.
    pub greeting: Vec<String>,
}

fn public_key(seed: &SecretBytes<32>) -> Ed25519Pk {
    let key = secmp_crypto::Ed25519SigningKey::from_seed(seed.expose_secret()).unwrap();
    Ed25519Pk::from_bytes(key.verifying_key().as_bytes()).unwrap()
}

/// The inviter: identity, prekey store, the invitation with its record, the pooled invitation queue.
struct Inviter {
    identity: IdentityKeys,
    store: MemoryPrekeyStore,
    issued: Issued,
    record: InvitationRecord,
    invitation_queue: RecvCap,
}

fn relay_ref(harness: &Harness) -> RelayRef {
    RelayRef {
        relay_fp: harness.relay_fp(),
        onion: Onion::from_pubkey(&[0x33; 32]),
        akc: akc(&harness.access_key()),
        direct: None,
    }
}

/// Stage 1 — the inviter issues an invitation, publishes its link data (`LINK_PUT`) and creates the pooled
/// invitation queue from the keys the record holds.
fn issue(harness: &mut Harness, alice: ClientId) -> Inviter {
    let token = harness.access_key();
    let now = harness.clock().unix();
    let relay = relay_ref(harness);
    let identity = IdentityKeys::generate(harness.client(alice).entropy()).unwrap();
    let mut store = MemoryPrekeyStore::default();
    let expires = now.saturating_add(7 * 86_400);
    let params = IssueParams {
        relay,
        inv_period: Period::S20,
        profile: Profile::new("alice", None).unwrap(),
        now,
        expires,
        spk_expiry: expires,
    };
    let issued = store
        .issue_invitation(&identity, params, harness.client(alice).entropy())
        .unwrap();
    let record = store
        .record(&issued.invitation.ld_id)
        .unwrap()
        .duplicate()
        .unwrap();
    let bucket = HourBucket::from_unix_secs(expires).0;
    let (link, _) = harness.client(alice).link().unwrap();
    link.put_link_data(
        issued.invitation.ld_id,
        &record.owner_seed,
        &issued.blob,
        true,
        bucket,
        &token,
    )
    .unwrap();
    let (invitation_queue, invitation_send) = link
        .create_queue(
            &record.invq_recv_seed,
            &issued.invitation.inv_send_seed,
            &token,
        )
        .unwrap();
    // the invitation names the queue the relay derived (spec §5.2, §9.1; ADR-048 (m))
    assert_eq!(invitation_send.sid(), &issued.invitation.inv_sid);
    Inviter {
        identity,
        store,
        issued,
        record,
        invitation_queue,
    }
}

/// The invitee after its three handshake cells are on the relay.
struct Invitee {
    state: RatchetState,
    reply_queue: RecvCap,
    route_sid: [u8; 16],
}

/// Stage 2 — the invitee consumes the link data, runs the checks of §5.5, builds its reply route from a pool queue
/// and sends the three handshake cells to the invitation queue.
fn respond_to(harness: &mut Harness, bob: ClientId, inviter: &Inviter) -> Invitee {
    let token = harness.access_key();
    let now = harness.clock().unix();
    let uri = invitation_uri(&inviter.issued.invitation).unwrap();
    let parsed = parse_invitation_uri(&uri).unwrap();
    let (link, _) = harness.client(bob).link().unwrap();
    let got = link
        .get_link_data(parsed.ld_id, LinkGetMode::Consume)
        .unwrap();
    assert!(got.present && !got.consumed);
    let blob_bytes = got.blob.unwrap().encode().unwrap();
    let accepted = invitee_check(parsed, &blob_bytes, now).unwrap();
    let identity = IdentityKeys::generate(harness.client(bob).entropy()).unwrap();
    // the reply queue and the route that names it (spec §9.8: the sid is derived)
    let (recv_seed, send_seed) = (harness.client(bob).seed(), harness.client(bob).seed());
    let relay = relay_ref(harness);
    let (link, rng) = harness.client(bob).link().unwrap();
    let (reply_queue, _) = link.create_queue(&recv_seed, &send_seed, &token).unwrap();
    let route = RelayQueue::derived(
        relay,
        &public_key(&recv_seed),
        SecretBytes::from_slice(send_seed.expose_secret()).unwrap(),
        Period::S20,
    )
    .unwrap();
    let route_sid = route.sid;
    let (handshake, state) = Initiator::start(
        &accepted,
        &identity.initiator_keys(),
        &[RouteDescriptor::RelayQueue(route)],
        &Profile::new("bob", None).unwrap(),
        now,
        rng,
    )
    .unwrap();
    let cells: [Cell; 3] = handshake
        .release(&state, |_, _| Ok::<(), secmp_proto::Error>(()))
        .unwrap();
    let to_invitation = SendCap::from_route(
        inviter.issued.invitation.inv_sid,
        &inviter.issued.invitation.inv_send_seed,
    )
    .unwrap();
    for cell in &cells {
        link.send(&to_invitation, cell).unwrap();
    }
    Invitee {
        state,
        reply_queue,
        route_sid,
    }
}

/// Stage 3 — the inviter fetches the cells, accepts the handshake, reads the owner status, and answers through the
/// invitee's route; the invitee decrypts with the state its initiator kept.
fn accept_and_answer(
    harness: &mut Harness,
    alice: ClientId,
    bob: ClientId,
    mut host: Inviter,
    guest: Invitee,
) -> Outcome {
    let token = harness.access_key();
    let (link, rng) = harness.client(alice).link().unwrap();
    let fetched: Vec<Cell> = link
        .fetch(&host.invitation_queue, 0)
        .unwrap()
        .into_iter()
        .map(|(_, cell)| cell)
        .collect();
    assert_eq!(fetched.len(), 3, "the three handshake cells");
    let accepted = Responder::accept(
        &fetched,
        &host.record,
        &mut host.store,
        &host.identity.responder_keys(),
        rng,
    )
    .unwrap();
    assert_eq!(accepted.profile.name(), "bob");
    let status = link
        .get_link_data(
            host.issued.invitation.ld_id,
            LinkGetMode::OwnerStatus(&host.record.owner_seed),
        )
        .unwrap();
    let route = match accepted.routes.first() {
        Some(RouteDescriptor::RelayQueue(queue)) => {
            SendCap::from_route(queue.sid, &queue.send_seed).unwrap()
        }
        other => unreachable!("a RelayQueue route, got {}", other.is_some()),
    };
    assert_eq!(route.sid(), &guest.route_sid);
    let (alice_recv_seed, alice_send_seed) =
        (harness.client(alice).seed(), harness.client(alice).seed());
    let (link, rng) = harness.client(alice).link().unwrap();
    let (alice_recv, _) = link
        .create_queue(&alice_recv_seed, &alice_send_seed, &token)
        .unwrap();
    let mut side_alice = Side::new(accepted.state, alice_recv, route);
    let mut side_bob = Side::new(
        guest.state,
        guest.reply_queue,
        SendCap::from_route([0; 16], &alice_send_seed).unwrap(),
    );
    side_alice.send_text(link, rng, b"hello bob").unwrap();
    let (link, rng) = harness.client(bob).link().unwrap();
    side_bob.drain(link, rng).unwrap();
    Outcome {
        owner_status: (status.present, status.consumed),
        invitee_name: accepted.profile.name().to_owned(),
        greeting: side_bob
            .received()
            .iter()
            .map(|payload| String::from_utf8(payload.clone()).unwrap())
            .collect(),
    }
}

/// A (the inviter) issues an invitation and publishes its link data; B (the invitee) consumes it, checks it and sends
/// the three handshake cells to the invitation queue; A fetches, accepts, and answers through B's route.
pub fn run(harness: &mut Harness, alice: ClientId, bob: ClientId) -> Outcome {
    let host = issue(harness, alice);
    let guest = respond_to(harness, bob, &host);
    accept_and_answer(harness, alice, bob, host, guest)
}

/// H-02: the invitation and the handshake over the relay, end to end.
#[test]
fn harness_invitation_and_handshake_over_relay() {
    let mut harness = Harness::new(HarnessConfig::default());
    let (alice, bob) = (harness.add_client(), harness.add_client());
    harness.connect(alice).unwrap();
    harness.connect(bob).unwrap();
    let out = run(&mut harness, alice, bob);
    assert_eq!(out.owner_status, (false, true), "consumed by B");
    assert_eq!(out.invitee_name, "bob");
    assert_eq!(out.greeting, vec!["hello bob".to_owned()]);
}

/// H-09: M6's `two-clients` can drive the scenario API — the invitation of H-02 and the exchange of H-03 compile and
/// pass written in `tests/` against `pub` items only.
#[test]
fn harness_scenario_api_is_public_for_two_clients() {
    let mut harness = Harness::new(HarnessConfig::default());
    let (alice, bob) = (harness.add_client(), harness.add_client());
    harness.connect(alice).unwrap();
    harness.connect(bob).unwrap();
    let out = run(&mut harness, alice, bob);
    assert_eq!(out.owner_status, (false, true));
    let mut world = pair(HarnessConfig::default());
    world.exchange(20);
    let (at_alice, at_bob) = world.delivered();
    assert_eq!((at_alice.len(), at_bob.len()), (20, 20));
    assert_eq!(
        world.h.client(world.a).captures().len(),
        1,
        "one connection per client"
    );
}
