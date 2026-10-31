// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tests of `invitations` (TEST-SPEC-M7 IN-01…IN-04, IN-09…IN-13, IN-18, IN-19, IN-21 and the differential test of the
//! issue). The module is plain `cfg(test)`; each item that needs the `kat` entropy and the test key is gated inside.

#[cfg(feature = "kat")]
use secmp_proto::inv::{base64url_encode, invitation_uri, parse_invitation_uri};
#[cfg(feature = "kat")]
use secmp_proto::tr::FixedEntropy;

#[cfg(feature = "kat")]
use super::*;
#[cfg(feature = "kat")]
use crate::testutil::{DAY, E, Fixture, T0, entropy, relay_ref, stream, wire_profile};

#[cfg(feature = "kat")]
type R = Result<(), E>;

/// An invitation that expires ten days on.
#[cfg(feature = "kat")]
fn request(relay: u32) -> Result<IssueRequest, E> {
    Ok(IssueRequest {
        relay: RelayId(relay),
        inv_period: Period::S10,
        profile: wire_profile("inviter")?,
        expires: T0 + 10 * DAY,
    })
}

/// The inviter (relay 1, `pool` spare queues) and its entropy.
#[cfg(feature = "kat")]
fn inviter(label: &str, seed: u64, pool: usize) -> Result<(Fixture, FixedEntropy), E> {
    let mut e = entropy(seed);
    let fx = Fixture::new(label, &mut e)?;
    fx.add_relay(1, pool, &mut entropy(seed.wrapping_add(1000)))?;
    Ok((fx, e))
}

/// The pool of relay 1, as stored.
#[cfg(feature = "kat")]
fn pool_of(fx: &Fixture) -> Result<PoolBlob, E> {
    let store = fx.profile.store();
    let s = store.lock().map_err(|_| "lock")?;
    Ok(PoolBlob::read(&s, RelayId(1))?)
}

/// The record of `ld_id`, opened.
#[cfg(feature = "kat")]
fn record_of(fx: &Fixture, ld_id: &Id) -> Result<Stored, E> {
    let store = fx.profile.store();
    let s = store.lock().map_err(|_| "lock")?;
    Ok(load(&s, ld_id)?.ok_or("record")?.stored)
}

/// IN-01 (F-14, R-143; §5.2 `docs/03:211`, ADR-048 (m), §10.6 (3) `:695`): an invitation created with two spare queues is
/// issued on the oldest — its `inv_sid` is `SHA-256("SecMP-Q/1 sid" ‖ recv_pk ‖ send_pk)[0..16]` of that queue's keys and
/// its `inv_send_seed` the queue's sender seed — the call issues no `QUEUE_NEW`, and the one control operation it asks for
/// is the `LINK_PUT`, at once, on a one-shot link (a user waits).
#[cfg(feature = "kat")]
#[test]
fn uses_pool_queue() -> R {
    use crate::scheduler::control::ControlOps;
    use crate::scheduler::params::Params;
    use crate::scheduler::types::OpId;
    use crate::timing::TimingRng;

    let (fx, mut e) = inviter("in01", 1, 2)?;
    let pool = pool_of(&fx)?;
    assert_eq!(pool.queues.len(), 2);
    let first = pool.queues.first().ok_or("pool")?;
    let (recv_pk, send_pk) = (
        ed25519_pk_of(&first.recv_seed)?,
        ed25519_pk_of(&first.send_seed)?,
    );

    let invitations = Invitations::new(fx.profile.clone());
    let issued = invitations.issue(&request(1)?, &fx.clock, &mut e)?;
    assert_eq!(issued.invitation.inv_sid, sid(&recv_pk, &send_pk)?);
    assert_eq!(
        issued.invitation.inv_send_seed.expose_secret(),
        first.send_seed.expose_secret()
    );
    let record = record_of(&fx, &issued.invitation.ld_id)?;
    assert_eq!(record.queue, first.queue);
    assert_eq!(record.relay, RelayId(1));
    assert_eq!(
        record.record.invq_recv_seed.expose_secret(),
        first.recv_seed.expose_secret()
    );
    let after = pool_of(&fx)?;
    assert_eq!(after.queues.len(), 1, "the invitation took one spare queue");
    assert_eq!(after.queues.first().map(|q| q.queue), Some(QueueId(2)));

    // no QUEUE_NEW: the one operation is the LINK_PUT, due at once
    let n = link_data_n(&issued.invitation.ld_id);
    assert_eq!(issued.ops.len(), 1);
    let op = issued.ops.first().ok_or("op")?;
    assert_eq!(op.kind, ControlKind::LinkPut(n));
    assert_eq!(op.when, When::Prompt);
    let mut queue = ControlOps::new();
    let mut rng = TimingRng::seeded(1);
    queue.schedule(&Params::default(), &mut rng, OpId(1), 5_000, *op)?;
    assert_eq!(queue.due_of(OpId(1)), Some(5_000));
    let due = queue.take_due(5_000);
    assert_eq!(due.len(), 1);
    assert!(
        due.iter()
            .all(|d| matches!(d.kind, ControlKind::LinkPut(_)))
    );
    assert_eq!(rng.draws(), 0, "a prompt operation draws no delay");
    Ok(())
}

/// IN-02 (F-14; §9.2 `docs/03:597`): two profiles with different identities, spare queues from the same entropy seed, issue
/// invitations on the same queue — the queue's keys, `inv_sid` and `inv_send_seed` are identical: no identity key enters
/// the queue's keys.
#[cfg(feature = "kat")]
#[test]
fn queue_keys_independent_of_iks() -> R {
    let (fx_a, mut ea) = inviter("in02a", 21, 2)?;
    let (fx_b, mut eb) = inviter("in02b", 22, 2)?;
    // the pool entropy is derived from the seed (`inviter`): make it the same for both
    let same = |fx: &Fixture| -> Result<(), E> {
        let store = fx.profile.store();
        let mut s = store.lock().map_err(|_| "lock")?;
        s.txn(|tx| secmp_store::profile::put_relay_pool(tx, 1, None))?;
        drop(s);
        crate::invitations::SparePool::new(fx.profile.store()).fill(
            RelayId(1),
            2,
            &mut entropy(555),
        )?;
        Ok(())
    };
    same(&fx_a)?;
    same(&fx_b)?;
    assert_ne!(
        fx_a.profile.fingerprint()?,
        fx_b.profile.fingerprint()?,
        "different identities"
    );

    let a = Invitations::new(fx_a.profile.clone()).issue(&request(1)?, &fx_a.clock, &mut ea)?;
    let b = Invitations::new(fx_b.profile.clone()).issue(&request(1)?, &fx_b.clock, &mut eb)?;
    assert_eq!(a.invitation.inv_sid, b.invitation.inv_sid);
    assert_eq!(
        a.invitation.inv_send_seed.expose_secret(),
        b.invitation.inv_send_seed.expose_secret()
    );
    let (ra, rb) = (
        record_of(&fx_a, &a.invitation.ld_id)?,
        record_of(&fx_b, &b.invitation.ld_id)?,
    );
    assert_eq!(
        ra.record.invq_recv_pk()?.as_bytes(),
        rb.record.invq_recv_pk()?.as_bytes()
    );
    assert_eq!(ra.queue, rb.queue);
    assert_ne!(
        a.invitation.ld_id, b.invitation.ld_id,
        "the invitations themselves differ"
    );
    Ok(())
}

/// IN-03 (R-67 [O-01]; §5.2 `docs/03:211`): after an issue and a reopen the record holds `ld_id`, `link_key`, the owner
/// key, the invitation queue's recipient key, `spk_id`/`opk_id` and `expires`; the secret fields are sealed (the ST-12 rule:
/// the column is the plaintext plus 72 bytes and holds none of its secrets).
#[cfg(feature = "kat")]
#[test]
fn record_fields_persisted_sealed() -> R {
    use secmp_store::kat::contains;
    use secmp_store::seal::SEAL_OVERHEAD;

    let (fx, mut e) = inviter("in03", 3, 1)?;
    let issued = Invitations::new(fx.profile.clone()).issue(&request(1)?, &fx.clock, &mut e)?;
    let ld_id = issued.invitation.ld_id;
    let fx = fx.reopen()?;
    let stored = record_of(&fx, &ld_id)?;
    let r = &stored.record;
    assert_eq!(r.ld_id, ld_id);
    assert_eq!(
        r.link_key.expose_secret(),
        issued.invitation.link_key.expose_secret()
    );
    assert_eq!((r.spk_id, r.opk_id, r.expires), (1, 1, T0 + 10 * DAY));
    assert_eq!(
        r.owner_pk()?.as_bytes(),
        ed25519_pk_of(&r.owner_seed)?.as_bytes()
    );
    assert_eq!(
        r.invq_recv_pk()?.as_bytes(),
        ed25519_pk_of(&r.invq_recv_seed)?.as_bytes()
    );
    assert_eq!(stored.blob.as_ref().map(|b| b.len()), Some(LINK_BLOB_LEN));

    // sealed at rest
    let store = fx.profile.store();
    let s = store.lock().map_err(|_| "lock")?;
    let raw: Vec<u8> = s.connection_kat().query_row(
        "SELECT record FROM invitations WHERE ld_id = ?1",
        [&ld_id[..]],
        |row| row.get(0),
    )?;
    assert_eq!(raw.len(), stored.encode().len() + SEAL_OVERHEAD);
    for (name, secret) in [
        ("link_key", r.link_key.expose_secret().as_slice()),
        ("owner_seed", r.owner_seed.expose_secret().as_slice()),
        (
            "invq_recv_seed",
            r.invq_recv_seed.expose_secret().as_slice(),
        ),
        (
            "blob",
            stored
                .blob
                .as_ref()
                .and_then(|b| b.get(..64))
                .ok_or("blob")?,
        ),
    ] {
        assert!(!contains(&raw, secret), "{name} inside the column");
    }
    Ok(())
}

/// IN-04 (§5.2 `docs/03:209`): an invitation issued without a direct endpoint is `secmp://i/` and 322 characters (332 in
/// all), and parses back to the same `InvitationV1`.
#[cfg(feature = "kat")]
#[test]
fn uri_roundtrip() -> R {
    let (fx, mut e) = inviter("in04", 4, 1)?;
    let issued = Invitations::new(fx.profile.clone()).issue(&request(1)?, &fx.clock, &mut e)?;
    assert!(relay_ref().direct.is_none());
    assert!(issued.uri.starts_with("secmp://i/"));
    assert_eq!(issued.uri.len(), 332);
    assert_eq!(issued.uri.len() - "secmp://i/".len(), 322);
    let parsed = parse_invitation_uri(&issued.uri)?;
    assert_eq!(*parsed.encode()?, *issued.invitation.encode()?);
    assert_eq!(parsed.ld_id, issued.invitation.ld_id);
    assert_eq!(*invitation_uri(&parsed)?, *issued.uri);
    Ok(())
}

/// The invitee side: a second profile with relay 1 and `pool` spare queues.
#[cfg(feature = "kat")]
fn invitee(label: &str, seed: u64, pool: usize) -> Result<(Fixture, FixedEntropy), E> {
    inviter(label, seed, pool)
}

/// The three handshake cells of `invitee` accepting `issued`, as released to the relay.
#[cfg(feature = "kat")]
fn handshake(invitee: &Fixture, e: &mut FixedEntropy, issued: &Issuance) -> Result<[Cell; 3], E> {
    let profile = wire_profile("invitee")?;
    let start = Invitations::new(invitee.profile.clone()).accept_invitation(
        &issued.uri,
        &issued.blob.encode()?,
        &AcceptRequest {
            relay: RelayId(1),
            reply_period: Period::S10,
            profile: &profile,
        },
        &invitee.clock,
        e,
    )?;
    Ok(start
        .cells
        .release(&start.state, |_, _| Ok::<(), secmp_proto::Error>(()))?)
}

/// A garbage cell: 4096 bytes that open under no key.
#[cfg(feature = "kat")]
fn garbage(seed: u64) -> Result<Cell, E> {
    Ok(Cell::from_bytes(&stream(seed, CELL_LEN))?)
}

/// IN-09 (RT-1; `docs/07:149`, `responder.rs:21`): 30 garbage cells over three fetches, then one more — after each step the
/// retained cells are the newest 24 (their ids checked), and each fetch is acknowledged up to its newest cell.
#[cfg(feature = "kat")]
#[test]
fn unclassified_cells_capped_24() -> R {
    let (fx, mut e) = inviter("in09", 9, 1)?;
    let invitations = Invitations::new(fx.profile.clone());
    let ld_id = invitations
        .issue(&request(1)?, &fx.clock, &mut e)?
        .invitation
        .ld_id;
    let mut all: Vec<u64> = Vec::new();
    for (round, ids) in [
        (1_u64, 1..=10_u64),
        (2, 11..=20),
        (3, 21..=30),
        (4, 31..=31),
    ] {
        let fetched: Vec<(u64, Cell)> = ids
            .map(|id| Ok((id, garbage(id.wrapping_mul(7919))?)))
            .collect::<Result<_, E>>()?;
        all.extend(fetched.iter().map(|(id, _)| *id));
        let out = invitations.process_round(&ld_id, &fetched, &fx.clock, &mut e)?;
        assert_eq!(
            out.ack_through,
            fetched.last().map(|(id, _)| *id),
            "round {round}"
        );
        assert!(out.accepted.is_none() && out.events.is_empty() && out.ops.is_empty());
        let want: Vec<u64> = all.iter().rev().take(24).rev().copied().collect();
        assert_eq!(invitations.retained_ids(&ld_id)?, want, "round {round}");
    }
    assert_eq!(
        invitations.retained_ids(&ld_id)?,
        (8..=31).collect::<Vec<u64>>()
    );
    assert_eq!(accept_calls_kat(), 4);
    Ok(())
}

/// IN-10 (RT-1; `docs/07:149`): a complete valid group among garbage is accepted — one contact, the OPK gone, the invitation
/// consumed, the retained cells cleared — and the next fetch round, which brings the group's cells again, does not call
/// `accept`, retains nothing and presents the group to no one.
#[cfg(feature = "kat")]
#[test]
fn complete_group_spent_after_one_accept() -> R {
    let (fx, mut e) = inviter("in10", 15, 1)?;
    let (peer, mut pe) = invitee("in10-peer", 17, 2)?;
    let invitations = Invitations::new(fx.profile.clone());
    let issued = invitations.issue(&request(1)?, &fx.clock, &mut e)?;
    let ld_id = issued.invitation.ld_id;
    let cells = handshake(&peer, &mut pe, &issued)?;
    let replay: Vec<Cell> = cells
        .iter()
        .map(|c| Cell::from_bytes(c.as_bytes()))
        .collect::<Result<_, _>>()?;
    let [c0, c1, c2] = cells;

    let fetched = vec![
        (1, garbage(101)?),
        (2, garbage(102)?),
        (3, c0),
        (4, garbage(103)?),
        (5, c1),
        (6, c2),
        (7, garbage(104)?),
    ];
    let before = accept_calls_kat();
    let out = invitations.process_round(&ld_id, &fetched, &fx.clock, &mut e)?;
    assert_eq!(accept_calls_kat(), before + 1);
    assert_eq!(out.accepted, Some(ContactId(1)));
    assert_eq!(out.ack_through, Some(7));
    assert!(out.events.is_empty());
    {
        let store = fx.profile.store();
        let s = store.lock().map_err(|_| "lock")?;
        assert_eq!(s.contacts()?.len(), 1);
        let rows = s.invitations()?;
        assert_eq!(
            rows.first().map(|r| r.status),
            Some(secmp_store::profile::INVITATION_CONSUMED)
        );
        assert!(
            s.prekeys(KIND_OPK)?.iter().all(|r| r.id != 1),
            "the OPK of the invitation is gone"
        );
        assert!(
            s.invitation_retained(&ld_id)?.is_none(),
            "nothing retained after the accept"
        );
        assert!(s.session_rows(1)?.is_some(), "the session exists");
    }
    assert_eq!(invitations.retained_ids(&ld_id)?, Vec::<u64>::new());

    // the next round: the group's cells arrive again (the relay re-delivers; a thief replays them) — nothing is decided
    let mut again: Vec<(u64, Cell)> = (8..).zip(replay).collect();
    again.push((11, garbage(105)?));
    let out = invitations.process_round(&ld_id, &again, &fx.clock, &mut e)?;
    assert_eq!(accept_calls_kat(), before + 1, "accept is not called again");
    assert!(out.accepted.is_none());
    assert_eq!(out.ack_through, Some(11));
    assert_eq!(invitations.retained_ids(&ld_id)?, Vec::<u64>::new());
    {
        let store = fx.profile.store();
        let s = store.lock().map_err(|_| "lock")?;
        assert_eq!(s.contacts()?.len(), 1, "still one contact");
    }
    Ok(())
}

/// IN-11 (R-69; ADR-044 (d), `docs/03:354`, `prekeys.rs:585`): a record that expires at `t` reaches `accept` in the step at
/// `t − 1` and not in the step at `t + 1`, where the invitation is retired instead: its queue's `QUEUE_DEL` is asked for,
/// delayed `U[1 min, 60 min]` through `ControlOps`, and the record, its one-time prekey and its row are gone.
#[cfg(feature = "kat")]
#[test]
fn accept_only_offered_records() -> R {
    use crate::scheduler::control::ControlOps;
    use crate::scheduler::params::Params;
    use crate::scheduler::types::OpId;
    use crate::timing::TimingRng;

    let (fx, mut e) = inviter("in11", 19, 1)?;
    let invitations = Invitations::new(fx.profile.clone());
    let mut req = request(1)?;
    req.expires = T0 + 100;
    let issued = invitations.issue(&req, &fx.clock, &mut e)?;
    let ld_id = issued.invitation.ld_id;

    fx.clock.set_ms(99_000);
    let step = invitations.process_round(&ld_id, &[(1, garbage(1)?)], &fx.clock, &mut e)?;
    assert_eq!(accept_calls_kat(), 1, "offered at t − 1");
    assert!(step.ops.is_empty() && step.accepted.is_none());

    fx.clock.set_ms(101_000);
    let step = invitations.process_round(&ld_id, &[(2, garbage(2)?)], &fx.clock, &mut e)?;
    assert_eq!(
        accept_calls_kat(),
        1,
        "not offered at t + 1: accept is not called"
    );
    assert_eq!(step.ack_through, None);
    let op = step.ops.first().ok_or("QUEUE_DEL")?;
    assert_eq!(step.ops.len(), 1);
    assert_eq!(op.kind, ControlKind::QueueDel(QueueId(1)));
    assert_eq!((op.relay, op.when), (RelayId(1), When::Delayed));
    let mut queue = ControlOps::new();
    let mut rng = TimingRng::seeded(11);
    let now = fx.clock.mono_ms();
    queue.schedule(&Params::default(), &mut rng, OpId(1), now, *op)?;
    let due = queue.due_of(OpId(1)).ok_or("due")?;
    assert!(
        (now + 60_000..=now + 3_600_000).contains(&due),
        "U[1 min, 60 min]: {}",
        due - now
    );
    let store = fx.profile.store();
    let s = store.lock().map_err(|_| "lock")?;
    assert!(s.invitations()?.is_empty(), "the record is retired");
    assert!(
        s.prekeys(KIND_OPK)?.iter().all(|r| r.id != 1),
        "with its one-time prekey"
    );
    Ok(())
}

/// The URI of `bytes` as the invitee is given it.
#[cfg(feature = "kat")]
fn uri_of(bytes: &[u8]) -> String {
    format!("secmp://i/{}", base64url_encode(bytes).as_str())
}

/// IN-12 (§5.5 `docs/03:252-259`, Q154): expired, a kind byte 0x02, a fingerprint that is not the link data's, a flipped
/// bundle signature, and the valid invitation give `Expired`, `Unsupported`, `Mismatch`, `Invalid` and `Ok`; the
/// `Mismatch` text is "invitation does not match link data".
#[cfg(feature = "kat")]
#[test]
fn invitee_checks_5_5() -> R {
    let (fx, mut e) = inviter("in12", 23, 1)?;
    let issued = Invitations::new(fx.profile.clone()).issue(&request(1)?, &fx.clock, &mut e)?;
    let blob = issued.blob.encode()?;
    let uri = issued.uri.as_str();
    let now = T0 + 1;
    let class = |uri: &str, blob: &[u8], now: u64| check_invitation(uri, blob, now).err();

    assert_eq!(
        class(uri, &blob, issued.invitation.expires),
        Some(InviteReject::Expired)
    );

    let mut bytes =
        secmp_proto::inv::base64url_decode(uri.strip_prefix("secmp://i/").ok_or("prefix")?)?
            .to_vec();
    *bytes.get_mut(1).ok_or("kind byte")? = 0x02;
    assert_eq!(
        class(&uri_of(&bytes), &blob, now),
        Some(InviteReject::Unsupported)
    );
    *bytes.get_mut(1).ok_or("kind byte")? = 0x01;
    *bytes.first_mut().ok_or("version byte")? = 0x02;
    assert_eq!(
        class(&uri_of(&bytes), &blob, now),
        Some(InviteReject::Invalid),
        "version byte"
    );
    assert_eq!(
        class("secmp://i/", &blob, now),
        Some(InviteReject::Invalid),
        "no bytes"
    );
    assert_eq!(
        class("https://example.org/", &blob, now),
        Some(InviteReject::Invalid),
        "prefix"
    );

    let mut other = parse_invitation_uri(uri)?;
    other.inviter_fp = [0x5a; 32];
    let mismatch = class(&invitation_uri(&other)?, &blob, now);
    assert_eq!(mismatch, Some(InviteReject::Mismatch));
    assert_eq!(
        mismatch.map(|m| m.to_string()).as_deref(),
        Some("invitation does not match link data")
    );
    assert_eq!(
        class(uri, blob.get(..blob.len() - 1).ok_or("blob")?, now),
        Some(InviteReject::Invalid),
        "blob length"
    );

    // a bundle whose signature is flipped (the blob re-sealed under the same key)
    let invitation = parse_invitation_uri(uri)?;
    let mut data = secmp_proto::inv::open_blob(&invitation.ld_id, &invitation.link_key, &blob)?;
    let mut sig = data.bundle.sig.as_bytes().to_vec();
    *sig.last_mut().ok_or("sig")? ^= 1;
    data.bundle.sig = HybridSig::from_bytes(&sig)?;
    let flipped =
        secmp_proto::inv::seal_blob(&invitation.ld_id, &invitation.link_key, e.nonce()?, &data)?
            .encode()?;
    assert_eq!(class(uri, &flipped, now), Some(InviteReject::Invalid));

    assert!(check_invitation(uri, &blob, now).is_ok());
    Ok(())
}

/// IN-13 (§5.5 step 5 `docs/03:256`): the invitee accepting an invitation takes its reply route from its own spare queues —
/// the oldest of the two — and asks for no `QUEUE_NEW`: the pool shrinks by one, nothing else changes.
#[cfg(feature = "kat")]
#[test]
fn invitee_reply_queue_from_pool() -> R {
    let (fx, mut e) = inviter("in13", 25, 1)?;
    let (peer, mut pe) = invitee("in13-peer", 27, 2)?;
    let issued = Invitations::new(fx.profile.clone()).issue(&request(1)?, &fx.clock, &mut e)?;
    let before = pool_of(&peer)?;
    assert_eq!(before.queues.len(), 2);
    let profile = wire_profile("invitee")?;
    let start = Invitations::new(peer.profile.clone()).accept_invitation(
        &issued.uri,
        &issued.blob.encode()?,
        &AcceptRequest {
            relay: RelayId(1),
            reply_period: Period::S10,
            profile: &profile,
        },
        &peer.clock,
        &mut pe,
    )?;
    assert_eq!(
        Some(start.reply_queue),
        before.queues.first().map(|q| q.queue)
    );
    let after = pool_of(&peer)?;
    assert_eq!(after.queues.len(), 1, "one spare queue taken, none created");
    assert_eq!(
        after.queues.first().map(|q| q.queue),
        before.queues.get(1).map(|q| q.queue)
    );
    // an invitation that is refused takes no queue
    let refused = Invitations::new(peer.profile.clone()).accept_invitation(
        &issued.uri,
        issued.blob.encode()?.get(1..).ok_or("blob")?,
        &AcceptRequest {
            relay: RelayId(1),
            reply_period: Period::S10,
            profile: &profile,
        },
        &peer.clock,
        &mut pe,
    );
    assert_eq!(
        refused.err(),
        Some(Error::Invitation(InviteReject::Invalid))
    );
    assert_eq!(pool_of(&peer)?.queues.len(), 1);
    Ok(())
}

/// IN-18 (§5.2 `docs/03:213`): an owner status of "consumed" with no handshake before `expires` shows
/// `Event::InvitationUsedElsewhere` — once.
#[cfg(feature = "kat")]
#[test]
fn used_by_someone_else() -> R {
    let (fx, mut e) = inviter("in18", 29, 1)?;
    let invitations = Invitations::new(fx.profile.clone());
    let ld_id = invitations
        .issue(&request(1)?, &fx.clock, &mut e)?
        .invitation
        .ld_id;
    let ops = invitations.on_owner_status(
        &ld_id,
        OwnerStatus {
            present: false,
            consumed: true,
        },
        &fx.clock,
    )?;
    assert!(ops.is_empty(), "a consumed link data is not put again");
    fx.at_day(5);
    assert_eq!(
        invitations.maintain(&fx.clock)?,
        Maintained::default(),
        "before `expires`"
    );
    fx.at_day(11);
    let done = invitations.maintain(&fx.clock)?;
    assert_eq!(done.events, [Event::InvitationUsedElsewhere]);
    assert_eq!(done.ops.len(), 1, "the queue is retired");
    assert_eq!(
        invitations.maintain(&fx.clock)?,
        Maintained::default(),
        "once"
    );
    Ok(())
}

/// IN-19 (§9.7 (1) `docs/03:630`): an owner status of "not present, not consumed" before `expires` (the relay restarted)
/// asks for the identical `LINK_PUT` — the same `ld_id` and the same 12 360-byte blob, read from the sealed record, never
/// sealed again — on a one-shot link, delayed `U[1 min, 60 min]` (no user waits).
#[cfg(feature = "kat")]
#[test]
fn reissue_link_put_after_relay_restart() -> R {
    use crate::scheduler::control::ControlOps;
    use crate::scheduler::params::Params;
    use crate::scheduler::types::OpId;
    use crate::timing::TimingRng;

    let (fx, mut e) = inviter("in19", 31, 1)?;
    let invitations = Invitations::new(fx.profile.clone());
    let issued = invitations.issue(&request(1)?, &fx.clock, &mut e)?;
    let n = link_data_n(&issued.invitation.ld_id);
    let first = invitations.link_put_args(n)?;
    assert_eq!(*first.blob, *issued.blob.encode()?);

    let draws_before = secmp_store::kat::store_txn_commits();
    let ops = invitations.on_owner_status(
        &issued.invitation.ld_id,
        OwnerStatus {
            present: false,
            consumed: false,
        },
        &fx.clock,
    )?;
    assert_eq!(
        secmp_store::kat::store_txn_commits(),
        draws_before,
        "nothing is rewritten"
    );
    let op = ops.first().ok_or("LINK_PUT")?;
    assert_eq!(
        (ops.len(), op.kind, op.when),
        (1, ControlKind::LinkPut(n), When::Delayed)
    );
    let mut queue = ControlOps::new();
    queue.schedule(
        &Params::default(),
        &mut TimingRng::seeded(3),
        OpId(1),
        0,
        *op,
    )?;
    let due = queue.due_of(OpId(1)).ok_or("due")?;
    assert!((60_000..=3_600_000).contains(&due), "{due}");

    let again = invitations.link_put_args(n)?;
    assert_eq!(again.ld_id, first.ld_id);
    assert_eq!(*again.blob, *first.blob);
    assert_eq!(again.owner_pk.as_bytes(), first.owner_pk.as_bytes());
    assert_eq!(again.blob.len(), 12_360);

    // present (the normal case) and an unknown link data change nothing
    let present = invitations.on_owner_status(
        &issued.invitation.ld_id,
        OwnerStatus {
            present: true,
            consumed: false,
        },
        &fx.clock,
    )?;
    assert!(present.is_empty());
    assert_eq!(
        invitations.link_put_args(n ^ 1).err(),
        Some(Error::Unavailable)
    );
    Ok(())
}

/// IN-21 (CS-2.2 note `docs/04:45`; O-36): the `link_key` is in memory only during a step — one opened record while the
/// step runs, none after it, whether the step is an issue, a `LINK_PUT` read, an owner status or a fetch round — and sealed
/// at rest (IN-03).
#[cfg(feature = "kat")]
#[test]
fn link_key_lifetime() -> R {
    let (fx, mut e) = inviter("in21", 33, 1)?;
    let invitations = Invitations::new(fx.profile.clone());
    assert_eq!(live_records_kat(), 0);
    reset_live_peak_kat();
    let issued = invitations.issue(&request(1)?, &fx.clock, &mut e)?;
    assert_eq!(live_records_kat(), 0, "after the issue");
    let ld_id = issued.invitation.ld_id;
    let n = link_data_n(&ld_id);

    for (name, step) in [
        ("link_put_args", 0),
        ("owner status", 1),
        ("fetch round", 2),
        ("retire", 3),
    ] {
        reset_live_peak_kat();
        match step {
            0 => {
                invitations.link_put_args(n)?;
            }
            1 => {
                let status = OwnerStatus {
                    present: true,
                    consumed: false,
                };
                invitations.on_owner_status(&ld_id, status, &fx.clock)?;
            }
            2 => {
                invitations.process_round(&ld_id, &[(1, garbage(1)?)], &fx.clock, &mut e)?;
            }
            _ => {
                invitations.maintain(&fx.clock)?;
            }
        }
        assert_eq!(live_records_kat(), 0, "after the {name}");
        if step < 3 {
            assert_eq!(
                live_records_peak_kat(),
                1,
                "the record is open during the {name}"
            );
        }
    }
    // sealed at rest: the column holds no byte of the key
    let store = fx.profile.store();
    let s = store.lock().map_err(|_| "lock")?;
    let raw: Vec<u8> =
        s.connection_kat()
            .query_row("SELECT record FROM invitations", [], |row| row.get(0))?;
    assert!(!secmp_store::kat::contains(
        &raw,
        issued.invitation.link_key.expose_secret()
    ));
    Ok(())
}

/// The issue equals the issue of `MemoryPrekeyStore::issue_invitation_on` (Q147 (i)): with the same entropy stream and the
/// same spare queue, the sealed link data, the invitation and its URI are byte for byte those of the reference — the
/// product assembles the bundle and the invitation from the persisted prekeys because `MemoryPrekeyStore` cannot be
/// loaded from them (D-B6).
#[cfg(feature = "kat")]
#[test]
fn issue_equals_issue_invitation_on() -> R {
    use secmp_proto::prekeys::{IdentityKeys, IssueParams, MemoryPrekeyStore, PoolQueueSeeds};

    let bytes = stream(77, 1 << 21);
    // the product: identity, signed prekey 1 and one-time prekey 1 at creation, then the issue
    let mut e1 = FixedEntropy::new(&bytes);
    let fx = Fixture::new("diff", &mut e1)?;
    fx.add_relay(1, 1, &mut entropy(901))?;
    let queue = pool_of(&fx)?.queues.remove(0);
    let issued = Invitations::new(fx.profile.clone()).issue(&request(1)?, &fx.clock, &mut e1)?;

    // the reference: the same stream — identity, signed prekey (`create_spk`), then `issue_invitation_on` draws the
    // one-time prekey and everything after it
    let mut e2 = FixedEntropy::new(&bytes);
    let identity = IdentityKeys::generate(&mut e2)?;
    let mut reference = MemoryPrekeyStore::default();
    reference.create_spk(T0, &mut e2)?;
    let expires = T0 + 10 * DAY;
    let want = reference.issue_invitation_on(
        &identity,
        IssueParams {
            relay: relay_ref(),
            inv_period: Period::S10,
            profile: wire_profile("inviter")?,
            now: T0,
            expires,
            spk_expiry: expires,
        },
        PoolQueueSeeds {
            invq_recv_seed: SecretBytes::from_slice(queue.recv_seed.expose_secret())?,
            inv_send_seed: SecretBytes::from_slice(queue.send_seed.expose_secret())?,
        },
        &mut e2,
    );
    let want = want.map_err(|_| "reference issue")?;
    assert_eq!(*issued.blob.encode()?, *want.blob.encode()?);
    assert_eq!(*issued.invitation.encode()?, *want.invitation.encode()?);
    assert_eq!(*issued.uri, *invitation_uri(&want.invitation)?);
    Ok(())
}
