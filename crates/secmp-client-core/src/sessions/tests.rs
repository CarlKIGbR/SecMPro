// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tests of `sessions` (TEST-SPEC-M7 SE-*, IN-15, IN-16). The module is plain `cfg(test)`; each item that needs the `kat`
//! entropy and the test key is gated inside.

#[cfg(feature = "kat")]
#[cfg(feature = "kat")]
use secmp_proto::wire::Period;
#[cfg(feature = "kat")]
use secmp_proto::wire::cell::{AppKind, Cell};

#[cfg(feature = "kat")]
use super::*;
#[cfg(feature = "kat")]
use crate::invitations::{AcceptRequest, Invitations, IssueRequest};
#[cfg(feature = "kat")]
use crate::scheduler::outbox::{OutMessage, Outbox};
#[cfg(feature = "kat")]
use crate::scheduler::types::RelayId;
#[cfg(feature = "kat")]
use crate::sessions::actor::{Refusal, SessionEvent, T_RS_MIN_MS, counters, receipt_timeout_ms};
#[cfg(feature = "kat")]
use crate::testutil::{DAY, E, Fixed, Fixture, T0, entropy, relay_ref, wire_profile};

#[cfg(feature = "kat")]
type R = Result<(), E>;

/// Two profiles with an accepted invitation between them and the conversation of each (the host is the inviter).
#[cfg(feature = "kat")]
pub(crate) struct World {
    pub(crate) host: Fixture,
    pub(crate) guest: Fixture,
    pub(crate) h: StoreConversation<Fixed>,
    pub(crate) g: StoreConversation<Fixed>,
}

#[cfg(feature = "kat")]
pub(crate) fn party(label: &str, seed: u64) -> Result<Fixture, E> {
    let mut e = entropy(seed);
    let fx = Fixture::new(label, &mut e)?;
    fx.add_relay(1, 3, &mut entropy(seed.wrapping_add(1000)))?;
    Ok(fx)
}

/// The invitation of `host`, accepted by `guest`, decided by `host`: both sides have their session and their
/// conversation (host side first, with the contacts' ids on the two sides); the guest's three handshake cells have not
/// been sent as TR cells (they were handed over directly). `seed` seeds the entropy of the four actors.
#[cfg(feature = "kat")]
pub(crate) fn connect(
    host: &Fixture,
    guest: &Fixture,
    seed: u64,
) -> Result<
    (
        StoreConversation<Fixed>,
        StoreConversation<Fixed>,
        ContactId,
    ),
    E,
> {
    let mut he = entropy(seed.wrapping_add(10));
    let mut ge = entropy(seed.wrapping_add(12));
    let invitations = Invitations::new(host.profile.clone());
    let issued = invitations.issue(
        &IssueRequest {
            relay: RelayId(1),
            inv_period: Period::S10,
            profile: wire_profile("host")?,
            expires: T0 + 10 * DAY,
        },
        &host.clock,
        &mut he,
    )?;
    let profile = wire_profile("guest")?;
    let start = Invitations::new(guest.profile.clone()).accept_invitation(
        &issued.uri,
        &secmp_proto::Encode::encode(&issued.blob)?,
        &AcceptRequest {
            relay: RelayId(1),
            reply_period: Period::S10,
            profile: &profile,
        },
        &guest.clock,
        &mut ge,
    )?;
    let fetched: Vec<(u64, Cell)> = (1..).zip(start.cells).collect();
    let round =
        invitations.process_round(&issued.invitation.ld_id, &fetched, &host.clock, &mut he)?;
    let contact = round.accepted.ok_or("accepted")?;
    let h = open_conversation(
        &host.profile.store(),
        contact,
        Fixed(entropy(seed.wrapping_add(20))),
        T0,
    )?;
    let g = open_conversation(
        &guest.profile.store(),
        start.contact,
        Fixed(entropy(seed.wrapping_add(22))),
        T0,
    )?;
    Ok((h, g, contact))
}

/// An open invitation of `host` and the three handshake cells of a new guest that accepted it (not yet decided by the
/// host).
#[cfg(feature = "kat")]
pub(crate) fn pending_handshake(
    host: &Fixture,
    seed: u64,
) -> Result<(crate::invitations::Issuance, [Cell; 3]), E> {
    let issued = Invitations::new(host.profile.clone()).issue(
        &IssueRequest {
            relay: RelayId(1),
            inv_period: Period::S10,
            profile: wire_profile("host")?,
            expires: T0 + 10 * DAY,
        },
        &host.clock,
        &mut entropy(seed),
    )?;
    let guest = party(&format!("pending-{seed}"), seed.wrapping_add(7))?;
    let start = Invitations::new(guest.profile.clone()).accept_invitation(
        &issued.uri,
        &secmp_proto::Encode::encode(&issued.blob)?,
        &AcceptRequest {
            relay: RelayId(1),
            reply_period: Period::S10,
            profile: &wire_profile("pending")?,
        },
        &guest.clock,
        &mut entropy(seed.wrapping_add(9)),
    )?;
    Ok((issued, start.cells))
}

/// A host and a guest with an accepted invitation between them.
#[cfg(feature = "kat")]
pub(crate) fn world(label: &str, seed: u64) -> Result<World, E> {
    let host = party(&format!("{label}-h"), seed)?;
    let guest = party(&format!("{label}-g"), seed.wrapping_add(2))?;
    let (h, g, contact) = connect(&host, &guest, seed)?;
    assert_eq!(contact, ContactId(1));
    Ok(World { host, guest, h, g })
}

/// Run `f` on a thread with a big stack: a debug build of the post-quantum operations of the first steps of a session
/// (ML-DSA signing, ML-KEM key generation) needs more than the 2 MiB of a test thread.
#[cfg(feature = "kat")]
pub(crate) fn big<F: FnOnce() -> R + Send + 'static>(f: F) -> R {
    let done = std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || f().map_err(|e| e.to_string()))?
        .join()
        .map_err(|_| "the test panicked")?;
    Ok(done?)
}

/// `n` seconds in ms.
#[cfg(feature = "kat")]
pub(crate) const fn ms(n: u64) -> u64 {
    n.saturating_mul(1_000)
}

/// The next cell of `c` at `now_ms`.
#[cfg(feature = "kat")]
pub(crate) fn next<S: actor::EntropySource>(
    c: &mut StoreConversation<S>,
    now_ms: u64,
) -> Result<Cell, E> {
    Ok(c.prepare_direct(now_ms)
        .map_err(|_| format!("prepare at {now_ms}"))?
        .cell)
}

/// Decide `cell` at `c`.
#[cfg(feature = "kat")]
pub(crate) fn deliver<S: actor::EntropySource>(
    c: &mut StoreConversation<S>,
    cell: &Cell,
) -> Result<(), E> {
    c.deliver_direct(cell).map_err(|_| "deliver")?;
    Ok(())
}

/// A route of the relay queue `n`.
#[cfg(feature = "kat")]
pub(crate) fn route(n: u8) -> Result<secmp_proto::wire::cell::RouteDescriptor, E> {
    use secmp_proto::wire::cell::{RelayQueue, RouteDescriptor};
    Ok(RouteDescriptor::RelayQueue(RelayQueue {
        relay: relay_ref(),
        sid: [n; 16],
        send_seed: secmp_crypto::SecretBytes::from_slice(&[n; 32])?,
        period_s: Period::S20,
    }))
}

/// A text message of `n`.
#[cfg(feature = "kat")]
pub(crate) fn text(n: u8, len: usize) -> OutMessage {
    OutMessage {
        msg_id: [n; 16],
        kind: AppKind::Text,
        expire_after: 0,
        payload: vec![n; len].into(),
    }
}

/// SE-16 (Q165; `docs/03:342`): a contact's queues enter the scheduler only once its session exists and is durable — a
/// contact row without session rows is not ready; after the accept (responder) or the persisted start (initiator) it is.
#[cfg(feature = "kat")]
#[test]
fn scheduler_entry_after_first_step() -> R {
    big(|| {
        let fx = party("se16", 3)?;
        // a contact without a session
        let peer = {
            use secmp_proto::prekeys::IdentityKeys;
            IdentityKeys::generate(&mut entropy(5))?
        };
        let contacts =
            crate::contacts::Contacts::new(fx.profile.store(), fx.profile.fingerprint()?);
        let (id, _) = contacts.add_from_handshake(peer.public(), &wire_profile("p")?, None)?;
        assert_eq!(
            ready_contacts(&fx.profile.store())?,
            Vec::<ContactId>::new()
        );
        assert_eq!(
            open_conversation(&fx.profile.store(), id, Fixed(entropy(1)), T0).err(),
            Some(Error::Unavailable)
        );
        // both sides of an accepted invitation are ready
        let w = world("se16w", 7)?;
        assert_eq!(ready_contacts(&w.host.profile.store())?, [ContactId(1)]);
        assert_eq!(ready_contacts(&w.guest.profile.store())?, [ContactId(1)]);
        Ok(())
    })
}

/// SE-17 (F29): with the trust `Frozen` real content is refused at the one send entry — a queued message waits, the cell
/// is a dummy — and the only seal site is `Conversation::seal`.
#[cfg(feature = "kat")]
#[test]
fn may_send_real_single_entry() -> R {
    big(|| {
        let mut w = world("se17", 11)?;
        w.h.outbox_mut().enqueue(text(1, 20), 0);
        assert_eq!(w.h.may_send_real(), Ok(()));
        w.h.set_trust(secmp_proto::tr::content::Trust::KeyChanged);
        assert_eq!(w.h.may_send_real(), Err(Refusal::Trust));
        let cell = next(&mut w.h, 0)?;
        deliver(&mut w.g, &cell)?;
        assert!(w.g.received().is_empty(), "a dummy, not the message");
        assert_eq!(w.h.outbox().waiting(), 1, "the message waits");
        w.h.set_trust(secmp_proto::tr::content::Trust::Unverified);
        let cell = next(&mut w.h, 1_000)?;
        deliver(&mut w.g, &cell)?;
        assert_eq!(w.g.received().len(), 1, "released with the trust");
        assert_eq!(counters::encrypt_sites(), ["Conversation::seal"]);
        // a frozen session stays frozen (§7.7): no call releases it
        w.h.set_trust(secmp_proto::tr::content::Trust::Frozen);
        w.h.set_trust(secmp_proto::tr::content::Trust::Verified);
        assert_eq!(w.h.may_send_real(), Err(Refusal::Trust));
        Ok(())
    })
}

/// IN-15 (§6.5 `docs/03:342`): an initiator with three real messages queued before the first reply sends its three handshake
/// cells, byte for byte as persisted, then only dummies; after the first reply is decrypted the three go out.
#[cfg(feature = "kat")]
#[test]
fn initiator_only_dummies_until_first_reply() -> R {
    big(|| {
        let mut w = world("in15", 13)?;
        assert!(w.g.awaiting_first_reply());
        for n in 1..=3 {
            w.g.outbox_mut().enqueue(text(n, 10), 0);
        }
        // the three handshake cells are the persisted ones
        let persisted = {
            let store = w.guest.profile.store();
            let s = store.lock().map_err(|_| "lock")?;
            s.handshake(1)?.ok_or("cells")?.to_vec()
        };
        let mut sent = Vec::new();
        for i in 0..3 {
            sent.extend_from_slice(next(&mut w.g, ms(i))?.as_bytes());
        }
        assert_eq!(sent, persisted, "byte-identical to part 4");
        // then dummies: the host decrypts them and delivers nothing
        for i in 3..8 {
            let cell = next(&mut w.g, ms(i))?;
            deliver(&mut w.h, &cell)?;
        }
        assert!(w.h.received().is_empty());
        assert_eq!(w.g.outbox().waiting(), 3, "the three wait");
        // the first reply (a route update) is decrypted: the part-4 cells go and the three are sent
        w.h.queue_route_update(vec![route(1)?]);
        let reply = next(&mut w.h, 9_000)?;
        deliver(&mut w.g, &reply)?;
        assert!(!w.g.awaiting_first_reply());
        assert!(
            w.guest
                .profile
                .store()
                .lock()
                .map_err(|_| "lock")?
                .handshake(1)?
                .is_none()
        );
        for i in 0..3 {
            let cell = next(&mut w.g, ms(10).saturating_add(ms(i)))?;
            deliver(&mut w.h, &cell)?;
        }
        assert_eq!(w.h.received().len(), 3);
        Ok(())
    })
}

/// SE-01 (§9.8 `docs/03:648`): a `RouteUpdate` with a route of kind 0x01 and one of the unknown kind 0x7E leaves the
/// contact the 0x01 route only, persisted (sealed) with the receive commit.
#[cfg(feature = "kat")]
#[test]
fn route_update_applied() -> R {
    big(|| {
        use secmp_proto::Encode as _;
        use secmp_proto::wire::cell::{RelayQueue, RouteDescriptor};

        let mut w = world("se01", 17)?;
        let rq = RelayQueue {
            relay: relay_ref(),
            sid: [4; 16],
            send_seed: secmp_crypto::SecretBytes::from_slice(&[5; 32])?,
            period_s: Period::S20,
        };
        let want = RouteDescriptor::RelayQueue(RelayQueue {
            relay: relay_ref(),
            sid: [4; 16],
            send_seed: secmp_crypto::SecretBytes::from_slice(&[5; 32])?,
            period_s: Period::S20,
        })
        .encode()?;
        w.h.queue_route_update(vec![
            RouteDescriptor::RelayQueue(rq),
            RouteDescriptor::Unknown {
                kind: 0x7E,
                blob: secmp_crypto::Zeroizing::new(vec![9; 20]),
            },
        ]);
        let cell = next(&mut w.h, 0)?;
        deliver(&mut w.g, &cell)?;
        let events = w.g.take_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(events.first(), Some(SessionEvent::Routes(r)) if r.len() == 1));
        let stored = {
            let store = w.guest.profile.store();
            let s = store.lock().map_err(|_| "lock")?;
            s.contact_routes(1)?.ok_or("routes")?.to_vec()
        };
        assert_eq!(stored, [&[1_u8][..], &want[..]].concat());
        Ok(())
    })
}

/// A world after the first reply: the guest has heard from the host (its part-4 cells are gone).
#[cfg(feature = "kat")]
pub(crate) fn established(label: &str, seed: u64) -> Result<World, E> {
    let mut w = world(label, seed)?;
    for i in 0..3 {
        next(&mut w.g, ms(i))?;
    }
    w.h.queue_route_update(vec![route(1)?]);
    let reply = next(&mut w.h, 4_000)?;
    deliver(&mut w.g, &reply)?;
    assert!(!w.g.awaiting_first_reply());
    // the reply's route update is an event of its own (IN-16)
    assert!(matches!(
        w.g.take_events().as_slice(),
        [SessionEvent::Routes(_)]
    ));
    Ok(w)
}

/// SE-20 (OQ-11; §7.6 Fragment `docs/03:501`; ADR-054 item 3): a text of 16 KiB (kind 1) goes in at most 64 fragments and
/// is delivered byte for byte. (`Api.send` of kind 2 is refused at the `Api`, AP-01.)
#[cfg(feature = "kat")]
#[test]
fn inline_attachment_64k() -> R {
    big(|| {
        let mut w = established("se20", 23)?;
        let payload: Vec<u8> = (0..16_384_u32)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect();
        w.g.outbox_mut().enqueue(
            OutMessage {
                msg_id: [7; 16],
                kind: AppKind::Text,
                expire_after: 0,
                payload: payload.clone().into(),
            },
            0,
        );
        let mut cells = 0_u32;
        while w.h.received().is_empty() {
            let cell = next(&mut w.g, 10_000 + ms(u64::from(cells)))?;
            deliver(&mut w.h, &cell)?;
            cells += 1;
            assert!(cells <= 64, "at most 64 fragments");
        }
        assert!(cells >= 2, "fragmented");
        let got = w.h.received().first().ok_or("received")?;
        assert_eq!(got.payload.as_slice(), payload.as_slice());
        Ok(())
    })
}

/// SE-12 [O-09] (§10.4): a delivered message is receipted — `Receipt{delivered}`, in a slot — to a verified contact; to an
/// unverified one (receipts off) the slot carries a dummy and the sender's message stays `Relayed`; never a `read` receipt.
#[cfg(feature = "kat")]
#[test]
fn receipts_defaults() -> R {
    big(|| {
        use crate::scheduler::outbox::MsgState;

        for verified in [true, false] {
            let mut w = established(if verified { "se12v" } else { "se12u" }, 29)?;
            w.h.set_send_receipts(verified);
            w.g.outbox_mut().enqueue(text(5, 12), 0);
            let prepared = w.g.prepare_direct(10_000).map_err(|_| "prepare")?;
            w.g.relayed_direct(prepared.token, 77);
            deliver(&mut w.h, &prepared.cell)?;
            assert_eq!(w.h.received().len(), 1);
            let answer = next(&mut w.h, 11_000)?;
            deliver(&mut w.g, &answer)?;
            let state = w.g.outbox().state(&[5; 16]);
            if verified {
                assert_eq!(state, Some(MsgState::Delivered));
            } else {
                assert_eq!(
                    state,
                    Some(MsgState::Relayed(77)),
                    "no receipt to an unverified contact"
                );
            }
        }
        Ok(())
    })
}

/// SE-13b [O-07] (re-dictated Q159, D-B4): a message relayed at `t` and not receipted is not re-sent; at `t` + `T_RS` the
/// session reports `NotConfirmed(msg_id)` once.
#[cfg(feature = "kat")]
#[test]
fn unconfirmed_after_receipt_timeout() -> R {
    big(|| {
        let mut w = established("se13b", 31)?;
        let t_rs = T_RS_MIN_MS;
        w.g.set_receipt_timeout_ms(t_rs);
        w.g.outbox_mut().enqueue(text(6, 8), 0);
        let prepared = w.g.prepare_direct(10_000).map_err(|_| "prepare")?;
        w.g.relayed_direct(prepared.token, 5);
        w.g.take_events();
        // one cell short of the timeout: nothing
        let _ = next(&mut w.g, 10_000 + t_rs - 1)?;
        assert!(w.g.take_events().is_empty());
        let _ = next(&mut w.g, 10_000 + t_rs)?;
        let events = w.g.take_events();
        assert!(matches!(events.as_slice(), [SessionEvent::NotConfirmed(id)] if *id == [6; 16]));
        // once, and no re-send: the message is still relayed, no new copy waits
        let _ = next(&mut w.g, 10_000 + t_rs + 10_000)?;
        assert!(w.g.take_events().is_empty());
        assert_eq!(w.g.outbox().waiting(), 0);
        assert_eq!(T_RS_MIN_MS, 86_400_000);
        assert_eq!(
            receipt_timeout_ms(10_000),
            86_400_000,
            "2 * 128 * 10 s = 42.7 min: the 24 h floor"
        );
        assert_eq!(receipt_timeout_ms(80_000), 86_400_000);
        assert_eq!(
            receipt_timeout_ms(400_000),
            102_400_000,
            "a longer period raises it"
        );
        Ok(())
    })
}

/// SE-15 [O-35] (F30): `Control{2}` sent — also from a `Frozen` session — reaches the peer as `ResetRequested`; the peer
/// refuses real sends from then on (dummies go on).
#[cfg(feature = "kat")]
#[test]
fn session_reset_request() -> R {
    big(|| {
        let mut w = established("se15", 37)?;
        w.h.set_trust(secmp_proto::tr::content::Trust::Frozen);
        assert_eq!(w.h.may_send_real(), Err(Refusal::Trust));
        w.h.queue_control(secmp_proto::wire::cell::ControlCode::SessionResetRequest);
        let cell = next(&mut w.h, 5_000)?;
        deliver(&mut w.g, &cell)?;
        let events = w.g.take_events();
        assert!(matches!(events.as_slice(), [SessionEvent::ResetRequested]));
        assert_eq!(w.g.may_send_real(), Err(Refusal::Reset));
        w.g.outbox_mut().enqueue(text(8, 4), 0);
        let dummy = next(&mut w.g, 6_000)?;
        deliver(&mut w.h, &dummy).ok();
        assert_eq!(w.g.outbox().waiting(), 1, "the real message is refused");
        Ok(())
    })
}

/// The key change of `host` to a new identity, signed by the old `IK_sig` (or by `signer` instead), as fragments.
#[cfg(feature = "kat")]
fn key_change(w: &mut World, other_signer: bool) -> Result<secmp_proto::wire::inv::IksPublic, E> {
    use secmp_proto::prekeys::IdentityKeys;
    use secmp_proto::tr::content::key_change_body;

    let new = IdentityKeys::generate(&mut entropy(901))?;
    let old = w.host.profile.signing_key()?;
    let signer = if other_signer {
        IdentityKeys::generate(&mut entropy(903))?;
        secmp_proto::tr::Entropy::hybrid_signing_key(&mut entropy(903))?
    } else {
        old
    };
    w.h.queue_key_change(key_change_body(&signer, new.public())?)
        .map_err(|_| "queue")?;
    Ok(new.public().clone())
}

/// Deliver all planned cells of `from` to `to` (at most `n`).
#[cfg(feature = "kat")]
fn flush(from: &mut StoreConversation<Fixed>, to: &mut StoreConversation<Fixed>, n: u64) -> R {
    for i in 0..n {
        let cell = next(from, ms(20).saturating_add(ms(i)))?;
        deliver(to, &cell)?;
    }
    Ok(())
}

/// SE-06 [O-28] (§7.7): a valid `KeyChange`, fragmented and signed by the old `IK_sig`, makes the contact `KeyChanged`:
/// the event carries the new identity, real sends are held — a queued message waits, the slots carry dummies.
/// SE-07: after the new safety number is verified, the held message goes out.
#[cfg(feature = "kat")]
#[test]
fn key_change_blocks_sending() -> R {
    big(|| {
        let mut w = established("se06", 41)?;
        let new = key_change(&mut w, false)?;
        w.g.outbox_mut().enqueue(text(9, 6), 0);
        flush(&mut w.h, &mut w.g, 4)?;
        let events = w.g.take_events();
        assert!(matches!(events.as_slice(), [SessionEvent::KeyChanged(iks)] if **iks == new));
        assert_eq!(w.g.may_send_real(), Err(Refusal::Trust));
        // the held message is not sealed: dummies only
        flush(&mut w.g, &mut w.h, 3)?;
        assert!(w.h.received().is_empty());
        assert_eq!(w.g.outbox().waiting(), 1);
        // the contact takes the new identity, unverified; verifying it releases the message (SE-07)
        accept_key_change(&w.guest.profile.store(), &mut w.g, ContactId(1), &new)?;
        let contacts =
            crate::contacts::Contacts::new(w.guest.profile.store(), w.guest.profile.fingerprint()?);
        assert!(!contacts.get(ContactId(1))?.verified);
        assert_eq!(
            contacts.get(ContactId(1))?.fingerprint,
            secmp_proto::prekeys::fingerprint_of(&new)?
        );
        set_verified(&w.guest.profile.store(), &mut w.g, ContactId(1))?;
        assert_eq!(w.g.may_send_real(), Ok(()));
        flush(&mut w.g, &mut w.h, 2)?;
        assert_eq!(w.h.received().len(), 1);
        Ok(())
    })
}

/// SE-08 (§7.7): a `KeyChange` that does not verify — signed by another key — freezes the session: `KeyChangeInvalid`; no
/// call un-freezes it (`set_trust`, `set_verified`).
#[cfg(feature = "kat")]
#[test]
fn invalid_key_change_freezes() -> R {
    big(|| {
        let mut w = established("se08", 43)?;
        key_change(&mut w, true)?;
        flush(&mut w.h, &mut w.g, 4)?;
        let events = w.g.take_events();
        assert!(matches!(
            events.as_slice(),
            [SessionEvent::KeyChangeInvalid]
        ));
        assert_eq!(w.g.may_send_real(), Err(Refusal::Trust));
        set_verified(&w.guest.profile.store(), &mut w.g, ContactId(1))?;
        w.g.set_trust(secmp_proto::tr::content::Trust::Verified);
        assert_eq!(w.g.may_send_real(), Err(Refusal::Trust), "still frozen");
        // nothing more is delivered
        w.h.outbox_mut().enqueue(text(3, 5), 0);
        flush(&mut w.h, &mut w.g, 2)?;
        assert!(w.g.received().is_empty());
        Ok(())
    })
}
