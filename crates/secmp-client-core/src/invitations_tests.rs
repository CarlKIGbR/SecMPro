// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tests of `invitations` (TEST-SPEC-M7 IN-01…IN-04, IN-09…IN-13, IN-18, IN-19, IN-21 and the differential test of the
//! issue). The module is plain `cfg(test)`; each item that needs the `kat` entropy and the test key is gated inside.

#[cfg(feature = "kat")]
use secmp_proto::inv::{base64url_encode, invitation_uri, parse_invitation_uri};
#[cfg(feature = "kat")]
use secmp_proto::keys::HybridSig;
#[cfg(feature = "kat")]
use secmp_proto::link::ids::sid;
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
    // the sender key and the period of the invitation queue (Q199): what the invitation advertises
    assert_eq!(
        stored.inv_send_seed.expose_secret(),
        issued.invitation.inv_send_seed.expose_secret()
    );
    assert_eq!(
        stored.inv_period_s,
        issued.invitation.inv_period_s.seconds()
    );
    let entry = stored.entry()?;
    assert_eq!(
        (entry.relay, entry.queue, entry.period_s, entry.retire_at_ms),
        (1, 1, 10, None)
    );
    assert_eq!(entry.seed.expose_secret(), r.invq_recv_seed.expose_secret());
    assert_eq!(
        entry.send_seed.as_ref().map(|s| *s.expose_secret()),
        Some(*issued.invitation.inv_send_seed.expose_secret())
    );

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
            "inv_send_seed",
            stored.inv_send_seed.expose_secret().as_slice(),
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
    Ok(start.cells)
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
    assert_eq!(
        out.ack_through, None,
        "cells of a consumed record are session cells (Q193)"
    );
    assert_eq!(out.to_session, vec![8, 9, 10, 11]);
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
    assert_eq!(
        (op.relay, op.when),
        (RelayId(1), When::AfterEmptyFetch(QueueId(1)))
    );
    let mut queue = ControlOps::new();
    let mut rng = TimingRng::seeded(11);
    let now = fx.clock.mono_ms();
    queue.schedule(&Params::default(), &mut rng, OpId(1), now, *op)?;
    // nothing before the queue has been fetched empty
    assert!(queue.awaits_empty_fetch(OpId(1)));
    assert!(queue.take_due(u64::MAX).is_empty());
    queue.note_empty_fetch(&Params::default(), &mut rng, QueueId(1), now);
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

/// OPEN-M7-B-5 (red first on the tree that took the pool queue in its own transaction before `Initiator::start`: the pool
/// shrank although the start failed): an accept that fails in `Initiator::start` (the entropy is too short for it) takes no
/// queue from the pool and writes no contact, session or handshake row.
#[cfg(feature = "kat")]
#[test]
fn accept_failure_keeps_pool_queue() -> R {
    let (fx, mut e) = inviter("b5", 41, 1)?;
    let (peer, mut pe) = invitee("b5-peer", 43, 2)?;
    let issued = Invitations::new(fx.profile.clone()).issue(&request(1)?, &fx.clock, &mut e)?;
    let before = pool_of(&peer)?;
    assert_eq!(before.queues.len(), 2);
    let profile = wire_profile("invitee")?;
    let failed = Invitations::new(peer.profile.clone()).accept_invitation(
        &issued.uri,
        &issued.blob.encode()?,
        &AcceptRequest {
            relay: RelayId(1),
            reply_period: Period::S10,
            profile: &profile,
        },
        &peer.clock,
        &mut FixedEntropy::new(&[]),
    );
    assert!(failed.is_err(), "the start needs randomness");
    let after = pool_of(&peer)?;
    assert_eq!(
        after.queues.iter().map(|q| q.queue).collect::<Vec<_>>(),
        before.queues.iter().map(|q| q.queue).collect::<Vec<_>>(),
        "the pool is unchanged"
    );
    let contacts =
        crate::contacts::Contacts::new(peer.profile.store(), peer.profile.fingerprint()?);
    assert!(contacts.list()?.is_empty(), "no contact row");

    drop(contacts);
    // the success half (Q200): the contact, its reply queue's entry and the session are there after a reopen
    let reply_queue = before.queues.first().ok_or("pool 0")?;
    let start = Invitations::new(peer.profile.clone()).accept_invitation(
        &issued.uri,
        &issued.blob.encode()?,
        &AcceptRequest {
            relay: RelayId(1),
            reply_period: Period::S20,
            profile: &profile,
        },
        &peer.clock,
        &mut pe,
    )?;
    assert_eq!(start.reply_queue, reply_queue.queue);
    let peer = peer.reopen()?;
    let store = peer.profile.store();
    let s = store.lock().map_err(|_| "lock")?;
    let rows = s.contacts()?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows.first().map(|c| c.id), Some(start.contact.0));
    let set = QueueSet::decode(&s.contact_queues(start.contact.0)?.ok_or("queues")?)?;
    let [entry] = set.entries.as_slice() else {
        return Err("one entry".into());
    };
    assert_eq!(entry.queue, reply_queue.queue.0);
    assert_eq!(
        entry.seed.expose_secret(),
        reply_queue.recv_seed.expose_secret()
    );
    assert_eq!(
        entry.send_seed.as_ref().map(|k| *k.expose_secret()),
        Some(*reply_queue.send_seed.expose_secret())
    );
    assert_eq!((entry.period_s, entry.retire_at_ms), (20, None));
    assert!(s.contact_routes(start.contact.0)?.is_some());
    assert_eq!(
        PoolBlob::read(&s, RelayId(1))?.queues.len(),
        1,
        "the queue left the pool in the same transaction"
    );
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

/// The issue equals the issue of `MemoryPrekeyStore::issue_invitation_on` (Q147 (i), Q189): with the same entropy stream
/// and the same spare queue, the sealed link data, the invitation, its URI and the stored `InvitationRecord` are byte for
/// byte those of the reference — on the three paths of the product: a one-time prekey of the pool reused, none
/// unreferenced (`opk_is_new`: drawn in the issue), and the signed prekey rotated inside the issue (clock at day 8). The
/// rotation runs on the `opk_is_new` path: the reference draws the new generation before the one-time prekey, which the
/// product does only when it draws the one-time prekey in the issue.
#[cfg(feature = "kat")]
#[test]
fn issue_equals_issue_invitation_on() -> R {
    diff_case("diff", 0, false)?;
    diff_case("diff-new", 0, true)?;
    diff_case("diff-rot", 8, true)
}

/// One case of [`issue_equals_issue_invitation_on`]: the issue on day `day`; `opk_new` deletes the one-time prekey of the
/// profile's creation first, so that the issue draws one.
#[cfg(feature = "kat")]
fn diff_case(label: &str, day: u64, opk_new: bool) -> R {
    use secmp_proto::prekeys::{IdentityKeys, IssueParams, MemoryPrekeyStore, PoolQueueSeeds};

    let bytes = stream(77, 1 << 21);
    // the product: identity, signed prekey 1 and one-time prekey 1 at creation, then the issue
    let mut e1 = FixedEntropy::new(&bytes);
    let fx = Fixture::new(label, &mut e1)?;
    fx.add_relay(1, 1, &mut entropy(901))?;
    if opk_new {
        let store = fx.profile.store();
        let mut s = store.lock().map_err(|_| "lock")?;
        s.txn(|tx| delete_prekey(tx, KIND_OPK, 1))?;
    }
    fx.at_day(day);
    let queue = pool_of(&fx)?.queues.remove(0);
    let issued = Invitations::new(fx.profile.clone()).issue(&request(1)?, &fx.clock, &mut e1)?;
    let record = {
        let store = fx.profile.store();
        let s = store.lock().map_err(|_| "lock")?;
        let loaded = load(&s, &issued.invitation.ld_id)?.ok_or("record")?;
        loaded.stored.record.to_bytes()
    };

    // the reference: the same stream — identity, signed prekey (`create_spk`), the one-time prekey of the creation if the
    // product drew it again, then `issue_invitation_on` rotates if due, draws the one-time prekey and everything after it
    let mut e2 = FixedEntropy::new(&bytes);
    let identity = IdentityKeys::generate(&mut e2)?;
    let mut reference = MemoryPrekeyStore::default();
    reference.create_spk(T0, &mut e2)?;
    if opk_new {
        OpkSecrets::generate(0, &mut e2)?;
    }
    let expires = T0 + 10 * DAY;
    let want = reference.issue_invitation_on(
        &identity,
        IssueParams {
            relay: relay_ref(),
            inv_period: Period::S10,
            profile: wire_profile("inviter")?,
            now: T0.saturating_add(day.saturating_mul(DAY)),
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
    let want_record = reference
        .record(&want.invitation.ld_id)
        .ok_or("reference record")?;
    assert_eq!(*issued.blob.encode()?, *want.blob.encode()?, "{label}");
    assert_eq!(
        *issued.invitation.encode()?,
        *want.invitation.encode()?,
        "{label}"
    );
    assert_eq!(*issued.uri, *invitation_uri(&want.invitation)?, "{label}");
    assert_eq!(*record, *want_record.to_bytes(), "{label}");
    if day > 0 {
        assert_eq!(want_record.spk_id, 2, "{label}: rotated in the issue");
    }
    Ok(())
}

/// IN-08 (review focus "OPK deletion" `docs/07:147`; §6.6 step 4 `:351`): in a successful accept the OPK row delete and
/// the record's status update are statements of the same store transaction as the session insert (`kat::txn_log`); and
/// `commit_accept` of the staged prekeys refuses a record that names another OPK, or another invitation, and stages
/// nothing then.
#[cfg(feature = "kat")]
#[test]
fn opk_and_record_in_one_txn() -> R {
    let (fx, mut e) = inviter("in08", 35, 1)?;
    let (peer, mut pe) = invitee("in08-peer", 37, 2)?;
    let invitations = Invitations::new(fx.profile.clone());
    let issued = invitations.issue(&request(1)?, &fx.clock, &mut e)?;
    let ld_id = issued.invitation.ld_id;
    let [c0, c1, c2] = handshake(&peer, &mut pe, &issued)?;

    // a record that names another OPK is refused; the right one stages (and writes nothing)
    {
        let store = fx.profile.store();
        let s = store.lock().map_err(|_| "lock")?;
        let stored = load(&s, &ld_id)?.ok_or("record")?.stored;
        let opk_id = stored.record.opk_id;
        let mut staged = StagedPrekeys::load(&s, &stored.record)?;
        assert_eq!(
            staged.commit_accept(opk_id + 1, &ld_id),
            Err(secmp_proto::Error::Rejected)
        );
        assert_eq!(
            staged.commit_accept(opk_id, &[0; 16]),
            Err(secmp_proto::Error::Rejected)
        );
        assert_eq!(staged.delete_opk(99), Err(secmp_proto::Error::Rejected));
        assert!(!staged.staged());
        assert_eq!(staged.commit_accept(opk_id, &ld_id), Ok(()));
        assert!(staged.staged() && staged.opk(opk_id).is_none());
        assert_eq!(
            s.prekeys(KIND_OPK)?.len(),
            2,
            "the store itself is untouched"
        );
    }

    secmp_store::kat::reset_counters();
    let out = invitations.process_round(&ld_id, &[(1, c0), (2, c1), (3, c2)], &fx.clock, &mut e)?;
    assert_eq!(out.accepted, Some(ContactId(1)));
    let log = secmp_store::kat::txn_log();
    let seq_of = |table: &str, verb: &str| -> Vec<u64> {
        log.iter()
            .filter(|(_, t, v)| *t == table && *v == verb)
            .map(|(s, _, _)| *s)
            .collect()
    };
    let opk = seq_of("prekeys", "delete");
    let record = seq_of("invitations", "update");
    let session = seq_of("sessions", "insert");
    assert_eq!(opk.len(), 1);
    assert!(!record.is_empty() && !session.is_empty());
    assert!(
        record
            .iter()
            .chain(&session)
            .all(|s| Some(s) == opk.first()),
        "{log:?}"
    );

    Ok(())
}

/// Killers (B-1…B-3 mutants of `link_data_n`, `Cursor::finish`, `SparePool`, the live counters): the id of a link data is
/// the big-endian first four bytes of its `ld_id`; a record or a pool with a trailing byte does not decode; the pool
/// counts, hands out the oldest and writes nothing when it is full already; the live counters follow the opened records.
#[cfg(feature = "kat")]
#[test]
fn killers_pool_and_counters() -> R {
    assert_eq!(
        link_data_n(&[1, 2, 3, 4, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9]),
        0x0102_0304
    );
    assert_eq!(link_data_n(&[0; 16]), 0);

    let (fx, mut e) = inviter("killers", 39, 3)?;
    let pool = SparePool::new(fx.profile.store());
    assert_eq!(
        (pool.len(RelayId(1))?, pool.is_empty(RelayId(1))?),
        (3, false)
    );
    assert_eq!(pool.len(RelayId(2))?, 0);
    assert!(pool.is_empty(RelayId(2))?);
    let commits = secmp_store::kat::store_txn_commits();
    assert_eq!(pool.fill(RelayId(1), 3, &mut e)?, 0, "full already");
    assert_eq!(
        secmp_store::kat::store_txn_commits(),
        commits,
        "nothing is written"
    );
    assert_eq!(pool.fill(RelayId(1), 4, &mut e)?, 1);
    let first = pool.take(RelayId(1))?.ok_or("take")?;
    assert_eq!(first.queue, QueueId(1));
    assert_eq!(pool.len(RelayId(1))?, 3);
    assert_eq!(pool.take(RelayId(2))?.map(|q| q.queue), None);

    // trailing bytes
    let mut long = PoolBlob::empty().encode()?.to_vec();
    long.push(0);
    assert!(PoolBlob::decode(&long).is_err());
    let blob = {
        let store = fx.profile.store();
        let s = store.lock().map_err(|_| "lock")?;
        s.relay_pool(1)?.ok_or("pool")?.to_vec()
    };
    assert!(PoolBlob::decode(&blob).is_ok());
    assert!(PoolBlob::decode(&[blob.clone(), vec![0]].concat()).is_err());
    assert!(Cursor::new(&[1]).finish().is_err());
    assert!(Cursor::new(&[]).finish().is_ok());

    // the live counters
    assert_eq!(live_records_kat(), 0);
    reset_live_peak_kat();
    assert_eq!(live_records_peak_kat(), 0);
    let invitations = Invitations::new(fx.profile.clone());
    let a = invitations.issue(&request(1)?, &fx.clock, &mut e)?;
    let b = invitations.issue(&request(1)?, &fx.clock, &mut e)?;
    reset_live_peak_kat();
    {
        let store = fx.profile.store();
        let s = store.lock().map_err(|_| "lock")?;
        let first = load(&s, &a.invitation.ld_id)?.ok_or("a")?;
        assert_eq!((live_records_kat(), live_records_peak_kat()), (1, 1));
        let second = load(&s, &b.invitation.ld_id)?.ok_or("b")?;
        assert_eq!((live_records_kat(), live_records_peak_kat()), (2, 2));
        drop(first);
        assert_eq!((live_records_kat(), live_records_peak_kat()), (1, 2));
        drop(second);
    }
    assert_eq!(live_records_kat(), 0);
    assert_eq!(live_records_peak_kat(), 2);
    reset_live_peak_kat();
    assert_eq!(live_records_peak_kat(), 0, "reset to the number alive now");

    // two invitations on one profile: distinct link data, distinct one-time prekeys (the first is referenced)
    let (ra, rb) = (
        record_of(&fx, &a.invitation.ld_id)?,
        record_of(&fx, &b.invitation.ld_id)?,
    );
    assert_ne!(ra.record.opk_id, rb.record.opk_id);
    assert_ne!(ra.queue, rb.queue);
    assert_eq!(
        rb.record.spk_id, ra.record.spk_id,
        "one signed prekey for both"
    );
    Ok(())
}

/// Killers (rounds, the cap of a round, retained cells, routes and queues of the contact): the retained cells are the
/// cells that were fetched, byte for byte; more than 152 distinct cells in a round are refused; the contact's routes
/// and queues hold what the accept wrote; the owner status of a consumed invitation changes nothing.
#[cfg(feature = "kat")]
#[test]
fn killers_rounds_and_contact() -> R {
    let (fx, mut e) = inviter("killers2", 41, 1)?;
    let (peer, mut pe) = invitee("killers2-peer", 43, 2)?;
    let invitations = Invitations::new(fx.profile.clone());
    let issued = invitations.issue(&request(1)?, &fx.clock, &mut e)?;
    let ld_id = issued.invitation.ld_id;
    let status = |present, consumed| OwnerStatus { present, consumed };

    // retained cells are the fetched ones
    invitations.process_round(
        &ld_id,
        &[(1, garbage(1)?), (2, garbage(2)?)],
        &fx.clock,
        &mut e,
    )?;
    {
        let store = fx.profile.store();
        let s = store.lock().map_err(|_| "lock")?;
        let kept = decode_retained(
            s.invitation_retained(&ld_id)?
                .as_ref()
                .map(|z| z.as_slice()),
        )?;
        assert_eq!(kept.iter().map(|(i, _)| *i).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(
            kept.first().map(|(_, c)| c.as_bytes().to_vec()),
            Some(garbage(1)?.as_bytes().to_vec())
        );
        assert_eq!(
            kept.get(1).map(|(_, c)| c.as_bytes().to_vec()),
            Some(garbage(2)?.as_bytes().to_vec())
        );
    }

    // the cap of a round: 24 retained and 128 fetched are decided, 129 fetched are refused
    let many = |from: u64, n: u64| -> Result<Vec<(u64, Cell)>, E> {
        (from..from + n).map(|i| Ok((i, garbage(i)?))).collect()
    };
    let fill = invitations.process_round(&ld_id, &many(50, 40)?, &fx.clock, &mut e)?;
    assert_eq!(fill.ack_through, Some(89));
    assert_eq!(invitations.retained_ids(&ld_id)?.len(), 24);
    let ok = invitations.process_round(&ld_id, &many(100, 128)?, &fx.clock, &mut e)?;
    assert_eq!(
        ok.ack_through,
        Some(227),
        "24 retained and 128 fetched: 152, the cap"
    );
    assert_eq!(
        invitations
            .process_round(&ld_id, &many(300, 129)?, &fx.clock, &mut e)
            .err(),
        Some(Error::Unavailable),
        "24 retained and 129 fetched"
    );

    // the accept: the routes and the queues the contact row holds
    let cells = handshake(&peer, &mut pe, &issued)?;
    let record = record_of(&fx, &ld_id)?;
    let fetched: Vec<(u64, Cell)> = (1000..).zip(cells).collect();
    let out = invitations.process_round(&ld_id, &fetched, &fx.clock, &mut e)?;
    assert_eq!(out.accepted, Some(ContactId(1)));
    {
        let store = fx.profile.store();
        let s = store.lock().map_err(|_| "lock")?;
        let queues = s.contact_queues(1)?.ok_or("queues")?;
        // `contacts.queues` is a `QueueSet` since B-4 (rotation): the invitation queue, current, made current at accept time
        let set = crate::sessions::rotation::QueueSet::decode(&queues)?;
        assert_eq!(set.rotated_ms, fx.clock.unix_secs() * 1000);
        assert_eq!(set.entries.len(), 1);
        let first = set.entries.first().ok_or("entry")?;
        assert_eq!(
            first.seed.expose_secret(),
            record.record.invq_recv_seed.expose_secret()
        );
        assert_eq!(first.retire_at_ms, None);
        let routes = s.contact_routes(1)?.ok_or("routes")?;
        assert_eq!(routes.first(), Some(&1));
        assert!(routes.len() > 100, "a route descriptor follows the count");
    }
    // the owner status of a consumed invitation changes nothing
    assert!(
        invitations
            .on_owner_status(&ld_id, status(false, false), &fx.clock)?
            .is_empty()
    );
    assert!(
        invitations
            .on_owner_status(&ld_id, status(false, true), &fx.clock)?
            .is_empty()
    );
    // the consumed invitation expires: retired without an OPK delete (the accept deleted it) and without an operation
    fx.at_day(11);
    assert_eq!(invitations.maintain(&fx.clock)?, Maintained::default());
    Ok(())
}

/// Killers (an expired invitation): the owner status of an expired, still open invitation asks for nothing; a round past
/// `expires` returns the retirement's events and operation and acknowledges nothing.
#[cfg(feature = "kat")]
#[test]
fn killers_expired_invitation() -> R {
    let (fx, mut e) = inviter("killers3", 45, 1)?;
    let invitations = Invitations::new(fx.profile.clone());
    let issued = invitations.issue(&request(1)?, &fx.clock, &mut e)?;
    let ld_id = issued.invitation.ld_id;
    let consumed = OwnerStatus {
        present: false,
        consumed: true,
    };
    invitations.on_owner_status(&ld_id, consumed, &fx.clock)?;
    fx.at_day(11);
    let gone = OwnerStatus {
        present: false,
        consumed: false,
    };
    assert!(
        invitations
            .on_owner_status(&ld_id, gone, &fx.clock)?
            .is_empty(),
        "expired: not put again"
    );
    let round = invitations.process_round(&ld_id, &[(1, garbage(1)?)], &fx.clock, &mut e)?;
    assert_eq!(round.events, [Event::InvitationUsedElsewhere]);
    assert_eq!(round.ops.len(), 1);
    assert_eq!(round.ack_through, None);
    Ok(())
}

/// Q190 (killer of `StagedPrekeys::commit_accept`, `||` → `&&` before `self.opk`): a second `commit_accept` on the same
/// staging names the same record and OPK, but the OPK is already staged for deletion — it is refused.
#[cfg(feature = "kat")]
#[test]
fn commit_accept_twice_is_rejected() -> R {
    let (fx, mut e) = inviter("q190-twice", 51, 1)?;
    let issued = Invitations::new(fx.profile.clone()).issue(&request(1)?, &fx.clock, &mut e)?;
    let ld_id = issued.invitation.ld_id;
    let store = fx.profile.store();
    let s = store.lock().map_err(|_| "lock")?;
    let stored = load(&s, &ld_id)?.ok_or("record")?.stored;
    let opk_id = stored.record.opk_id;
    let mut staged = StagedPrekeys::load(&s, &stored.record)?;
    assert_eq!(staged.commit_accept(opk_id, &ld_id), Ok(()));
    assert_eq!(
        staged.commit_accept(opk_id, &ld_id),
        Err(secmp_proto::Error::Rejected)
    );
    Ok(())
}

/// Q190 (killer of the version guard of `check_invitation`, Q154): with a version byte 0x02 **and** a kind byte 0x02 the
/// class is `Invalid` — the version is checked before the kind.
#[cfg(feature = "kat")]
#[test]
fn check_invitation_refuses_bad_version_before_kind() -> R {
    let (fx, mut e) = inviter("q190-ver", 53, 1)?;
    let issued = Invitations::new(fx.profile.clone()).issue(&request(1)?, &fx.clock, &mut e)?;
    let blob = issued.blob.encode()?;
    let text = issued.uri.strip_prefix("secmp://i/").ok_or("prefix")?;
    let mut bytes = secmp_proto::inv::base64url_decode(text)?.to_vec();
    *bytes.first_mut().ok_or("version byte")? = 0x02;
    *bytes.get_mut(1).ok_or("kind byte")? = 0x02;
    assert_eq!(
        check_invitation(&uri_of(&bytes), &blob, T0 + 1).err(),
        Some(InviteReject::Invalid)
    );
    Ok(())
}

/// Q192 (IN-21, Q173): the consumed path of `on_owner_status` opens the record through `load` — counted while it lives,
/// one record at a time, none alive after the step.
#[cfg(feature = "kat")]
#[test]
fn live_counter_counts_owner_status_open() -> R {
    let (fx, mut e) = inviter("q192-live", 55, 1)?;
    let invitations = Invitations::new(fx.profile.clone());
    let ld_id = invitations
        .issue(&request(1)?, &fx.clock, &mut e)?
        .invitation
        .ld_id;
    reset_live_peak_kat();
    let consumed = OwnerStatus {
        present: false,
        consumed: true,
    };
    assert!(
        invitations
            .on_owner_status(&ld_id, consumed, &fx.clock)?
            .is_empty()
    );
    assert_eq!(live_records_peak_kat(), 1);
    assert_eq!(live_records_kat(), 0);
    let store = fx.profile.store();
    let s = store.lock().map_err(|_| "lock")?;
    let loaded = load(&s, &ld_id)?.ok_or("record")?;
    assert_eq!(loaded.stored.flags & FLAG_CONSUMED_SEEN, FLAG_CONSUMED_SEEN);
    Ok(())
}

/// Q192: `decide` checks the record's status and expiry again under the lock it decides under. Called directly with a
/// complete valid handshake: (a) on a record consumed after `process_round`'s check would have passed, `accept` is not
/// called and no contact is made; (b) with the clock past `expires`, `accept` is not called and nothing is acknowledged.
#[cfg(feature = "kat")]
#[test]
fn decide_rechecks_status_after_lock() -> R {
    // (a) consumed between the check and the decision
    let (fx, mut e) = inviter("q192-consumed", 57, 1)?;
    let (peer, mut pe) = invitee("q192-consumed-peer", 59, 2)?;
    let invitations = Invitations::new(fx.profile.clone());
    let issued = invitations.issue(&request(1)?, &fx.clock, &mut e)?;
    let ld_id = issued.invitation.ld_id;
    let [c0, c1, c2] = handshake(&peer, &mut pe, &issued)?;
    {
        let store = fx.profile.store();
        let mut s = store.lock().map_err(|_| "lock")?;
        s.txn(|tx| set_invitation_status(tx, &ld_id, INVITATION_CONSUMED))?;
    }
    let before = accept_calls_kat();
    let fetched = [(1, c0), (2, c1), (3, c2)];
    let out = invitations.decide(&ld_id, &fetched, Some(3), &fx.clock, &mut e)?;
    assert_eq!(accept_calls_kat(), before, "consumed: accept is not called");
    assert!(out.accepted.is_none());
    assert_eq!(
        out.ack_through, None,
        "consumed: nothing is acknowledged by the invitation path (Q193)"
    );
    assert_eq!(
        out.to_session,
        vec![1, 2, 3],
        "consumed: the cells go to the session path, which decides and acknowledges them"
    );
    {
        let store = fx.profile.store();
        let s = store.lock().map_err(|_| "lock")?;
        assert!(s.contacts()?.is_empty(), "no contact");
    }

    // (b) expired between the check and the decision
    let (fx, mut e) = inviter("q192-expired", 61, 1)?;
    let (peer, mut pe) = invitee("q192-expired-peer", 63, 2)?;
    let invitations = Invitations::new(fx.profile.clone());
    let issued = invitations.issue(&request(1)?, &fx.clock, &mut e)?;
    let ld_id = issued.invitation.ld_id;
    let [c0, c1, c2] = handshake(&peer, &mut pe, &issued)?;
    fx.at_day(11);
    let before = accept_calls_kat();
    let fetched = [(1, c0), (2, c1), (3, c2)];
    let out = invitations.decide(&ld_id, &fetched, Some(3), &fx.clock, &mut e)?;
    assert_eq!(accept_calls_kat(), before, "expired: accept is not called");
    assert_eq!(out.ack_through, None);
    assert!(out.accepted.is_none());
    Ok(())
}

/// Q193 (`docs/03:351`, §6.6 step 4; OPEN-M7-B-6; red first: `out.ack_through.is_none()` on the tree that acknowledged and
/// dropped, `left: Some(..)`): after the record is consumed, the cells that arrive on its invitation queue are TR cells of
/// the session — the round hands them to the session (`to_session`), acknowledges nothing itself, and the session's receive
/// path decrypts, commits and so decides them; none is dropped unprocessed.
#[cfg(feature = "kat")]
#[test]
fn consumed_queue_cells_reach_session() -> R {
    use crate::sessions::tests::{Link, big, connect, deliver, next, party};

    big(|| {
        let host = party("q193-h", 71)?;
        let guest = party("q193-g", 73)?;
        let Link {
            mut h,
            mut g,
            ld_id,
            ..
        } = connect(&host, &guest, 400)?;
        let invitations = Invitations::new(host.profile.clone());
        // the guest sent its three handshake cells (consumed by the accept); then TR cells reach the consumed invitation queue
        for i in 1..=3_u64 {
            next(&mut g, i.saturating_mul(1_000))?;
        }
        let fetched: Vec<(u64, Cell)> = (10..12_u64)
            .map(|id| Ok((id, next(&mut g, id.saturating_mul(1_000))?)))
            .collect::<Result<_, E>>()?;
        let before = accept_calls_kat();
        let out = invitations.process_round(&ld_id, &fetched, &host.clock, &mut entropy(402))?;
        assert!(
            out.ack_through.is_none(),
            "the invitation path acknowledges nothing"
        );
        assert_eq!(out.to_session, vec![10, 11]);
        assert_eq!(accept_calls_kat(), before, "accept is not called");
        // the session path decides them: decrypted and committed, then they count as acknowledged
        for (_, cell) in &fetched {
            deliver(&mut h, cell)?;
        }
        assert_eq!(h.discarded(), 0, "both were cells of the session");
        let _ = &mut g;
        Ok(())
    })
}

/// Q194 / OPEN-M7-B-7 (D-B11; Q163; red first: on the tree where the `QUEUE_DEL` was merely `Delayed` it was due at once, so
/// `awaits_empty_fetch` is false): the `QUEUE_DEL` of an expired invitation's queue is queued behind an empty `FETCH` — a
/// `FETCH` that still holds a cell does not release it, the first one that holds none does, and its `U[1 min, 60 min]`
/// delay runs from that `FETCH`.
#[cfg(feature = "kat")]
#[test]
fn expired_queue_del_after_empty_fetch() -> R {
    use crate::scheduler::control::ControlOps;
    use crate::scheduler::params::Params;
    use crate::scheduler::types::OpId;
    use crate::timing::TimingRng;

    let (fx, mut e) = inviter("q194", 75, 1)?;
    let invitations = Invitations::new(fx.profile.clone());
    let mut req = request(1)?;
    req.expires = T0 + 100;
    invitations.issue(&req, &fx.clock, &mut e)?;
    fx.clock.set_ms(101_000);
    let ops = invitations.maintain(&fx.clock)?.ops;
    let op = ops.first().ok_or("QUEUE_DEL")?;
    let (params, mut rng) = (Params::default(), TimingRng::seeded(13));
    let mut queue = ControlOps::new();
    queue.schedule(&params, &mut rng, OpId(1), 5_000, *op)?;
    assert!(queue.awaits_empty_fetch(OpId(1)));
    // a FETCH of another queue, then the queue's own FETCH that still held a cell (no report): nothing is due
    queue.note_empty_fetch(&params, &mut rng, QueueId(9), 6_000);
    assert!(queue.take_due(u64::MAX).is_empty());
    assert_eq!(queue.next_due(), None);
    // the FETCH with no present cell
    queue.note_empty_fetch(&params, &mut rng, QueueId(1), 70_000);
    assert!(!queue.awaits_empty_fetch(OpId(1)));
    let due = queue.due_of(OpId(1)).ok_or("due")?;
    assert!(
        (70_000 + 60_000..=70_000 + 3_600_000).contains(&due),
        "{due}"
    );
    assert!(queue.take_due(70_000 + 59_999).is_empty());
    assert_eq!(queue.take_due(due).len(), 1);
    Ok(())
}

/// B-4 killers (`Invitations::open_queues`, `queue_of`, `SparePool::seeds`): the pool lists its spare queues with their ids
/// and seeds, oldest first; an issued invitation takes the oldest; the open invitations list their queues (a consumed one
/// does not, but `queue_of` still finds it).
#[cfg(feature = "kat")]
#[test]
fn open_queues_and_pool_seeds() -> R {
    use secmp_store::profile::{INVITATION_CONSUMED, set_invitation_status};

    let (fx, mut e) = inviter("oq", 55, 3)?;
    let invitations = Invitations::new(fx.profile.clone());
    let pool = SparePool::new(fx.profile.store());
    let before = pool.seeds(RelayId(1))?;
    assert_eq!(before.len(), 3);
    assert!(invitations.open_queues()?.is_empty());
    let first = invitations.issue(&request(1)?, &fx.clock, &mut e)?;
    let second = invitations.issue(&request(1)?, &fx.clock, &mut e)?;
    let open = invitations.open_queues()?;
    assert_eq!(open.len(), 2);
    let (a, b) = (open.first().ok_or("a")?, open.get(1).ok_or("b")?);
    let wanted = [
        (&first.invitation.ld_id, before.first().ok_or("pool 0")?),
        (&second.invitation.ld_id, before.get(1).ok_or("pool 1")?),
    ];
    for (found, (ld_id, (queue, recv, _send))) in [a, b].into_iter().zip(wanted) {
        assert_eq!(&found.ld_id, ld_id);
        assert_eq!(found.relay, RelayId(1));
        assert_eq!(found.queue, *queue);
        assert_eq!(found.recv_seed.expose_secret(), recv);
        assert_eq!(found.n, link_data_n(ld_id));
    }
    assert_eq!(pool.seeds(RelayId(1))?.len(), 1);
    // consumed: not open, still found by `queue_of`
    {
        let store = fx.profile.store();
        let mut s = store.lock().map_err(|_| "lock")?;
        s.txn(|tx| set_invitation_status(tx, &first.invitation.ld_id, INVITATION_CONSUMED))?;
    }
    let open = invitations.open_queues()?;
    assert_eq!(open.len(), 1);
    assert_eq!(open.first().map(|q| q.ld_id), Some(second.invitation.ld_id));
    let consumed = invitations.queue_of(&first.invitation.ld_id)?;
    assert_eq!(consumed.queue, before.first().ok_or("pool 0")?.0);
    assert!(invitations.queue_of(&[0xee; 16]).is_err());
    Ok(())
}

// EXTB1 review reproductions; no product changes.
#[cfg(feature = "kat")]
mod extb1_review {
    #![forbid(unsafe_code)]
    use super::*;
    use secmp_crypto::ConstantTimeEq as _;

    // Enumerate every persisted recipient-key container written by this module.
    // Compare public keys only; never print or compare secret seeds.
    fn has_recipient(fx: &Fixture, want: &Ed25519Pk) -> Result<bool, E> {
        let store = fx.profile.store();
        let s = store.lock().map_err(|_| "lock")?;
        for q in PoolBlob::read(&s, RelayId(1))?.queues {
            if ed25519_pk_of(&q.recv_seed)?.as_bytes() == want.as_bytes() {
                return Ok(true);
            }
        }
        for row in s.invitations()? {
            let record = load(&s, &ld_id_of(&row.ld_id)?)?.ok_or("record")?;
            if record.stored.record.invq_recv_pk()?.as_bytes() == want.as_bytes() {
                return Ok(true);
            }
        }
        for contact in s.contacts()? {
            if let Some(bytes) = s.contact_queues(contact.id)? {
                for entry in QueueSet::decode(&bytes)?.entries {
                    if ed25519_pk_of(&entry.seed)?.as_bytes() == want.as_bytes() {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    #[test]
    fn extb1_successful_invitee_keeps_reply_recipient() -> R {
        let (host, mut he) = inviter("extb1-host", 201, 2)?;
        let (peer, mut pe) = invitee("extb1-peer", 203, 2)?;
        let issued =
            Invitations::new(host.profile.clone()).issue(&request(1)?, &host.clock, &mut he)?;
        let (queue_id, recv_pk) = {
            let pool = pool_of(&peer)?;
            let q = pool.queues.first().ok_or("queue")?;
            (q.queue, ed25519_pk_of(&q.recv_seed)?)
        };
        assert!(has_recipient(&peer, &recv_pk)?);
        let profile = wire_profile("peer")?;
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
        assert_eq!(start.reply_queue, queue_id);
        // InviteeStart has only cells, RatchetState and QueueId; no recv capability.
        let peer = peer.reopen()?;
        assert!(
            has_recipient(&peer, &recv_pk)?,
            "successful accept lost the recipient key of its advertised reply queue"
        );
        Ok(())
    }

    #[test]
    fn extb1_issue_preserves_invitation_period() -> R {
        let (a, mut ea) = inviter("extb1-period-a", 207, 2)?;
        let (b, mut eb) = inviter("extb1-period-b", 207, 2)?;
        let mut slow = request(1)?;
        slow.inv_period = Period::S80;
        let ia = Invitations::new(a.profile.clone()).issue(&request(1)?, &a.clock, &mut ea)?;
        let ib = Invitations::new(b.profile.clone()).issue(&slow, &b.clock, &mut eb)?;
        assert_ne!(ia.invitation.inv_period_s, ib.invitation.inv_period_s);
        let ra = record_of(&a, &ia.invitation.ld_id)?.encode();
        let rb = record_of(&b, &ib.invitation.ld_id)?.encode();
        // Constant-time comparison avoids comparing the records' secrets with ==.
        assert!(
            !bool::from(ra.as_slice().ct_eq(rb.as_slice())),
            "S10 and S80 invitations have identical persisted records; restart cannot recover their period"
        );
        Ok(())
    }

    #[test]
    fn extb1_issue_preserves_queue_sender_key() -> R {
        let (a, mut ea) = inviter("extb1-sender-a", 209, 2)?;
        let (b, mut eb) = inviter("extb1-sender-b", 209, 2)?;
        let mut pool = pool_of(&b)?;
        pool.queues.first_mut().ok_or("queue")?.send_seed = entropy(211).secret::<32>()?;
        {
            let store = b.profile.store();
            let mut s = store.lock().map_err(|_| "lock")?;
            let bytes = pool.encode()?;
            s.txn(|tx| put_relay_pool(tx, 1, Some(&bytes)))?;
        }
        drop(pool);
        let ia = Invitations::new(a.profile.clone()).issue(&request(1)?, &a.clock, &mut ea)?;
        let ib = Invitations::new(b.profile.clone()).issue(&request(1)?, &b.clock, &mut eb)?;
        assert_ne!(ia.invitation.inv_sid, ib.invitation.inv_sid);
        let ra = record_of(&a, &ia.invitation.ld_id)?.encode();
        let rb = record_of(&b, &ib.invitation.ld_id)?.encode();
        let pa = pool_of(&a)?.encode()?;
        let pb = pool_of(&b)?.encode()?;
        assert!(bool::from(pa.as_slice().ct_eq(pb.as_slice())));
        assert!(
            !bool::from(ra.as_slice().ct_eq(rb.as_slice())),
            "different sender keys/sids have identical remaining pools and invitation records"
        );
        Ok(())
    }
}
