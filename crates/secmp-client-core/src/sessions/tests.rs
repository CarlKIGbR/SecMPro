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
use crate::contacts::Contacts;
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
pub(crate) type R = Result<(), E>;

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
pub(crate) fn connect(host: &Fixture, guest: &Fixture, seed: u64) -> Result<Link, E> {
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
    Ok(Link {
        h,
        g,
        contact,
        ld_id: issued.invitation.ld_id,
    })
}

/// What [`connect`] made.
#[cfg(feature = "kat")]
pub(crate) struct Link {
    pub(crate) h: StoreConversation<Fixed>,
    pub(crate) g: StoreConversation<Fixed>,
    /// The host's contact.
    pub(crate) contact: ContactId,
    /// The consumed invitation.
    pub(crate) ld_id: [u8; 16],
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
    let Link { h, g, contact, .. } = connect(&host, &guest, seed)?;
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

/// The `rotate` request of the host's contact 1 on relay 1.
#[cfg(feature = "kat")]
fn rotate_request<'a>(
    params: &'a crate::scheduler::params::Params,
    periods: &'a [u64],
) -> rotation::RotateRequest<'a> {
    rotation::RotateRequest {
        contact: ContactId(1),
        relay: RelayId(1),
        period: Period::S80,
        mode: crate::scheduler::params::Mode::Balanced,
        params,
        recv_periods_ms: periods,
    }
}

/// The contact's queue set as stored.
#[cfg(feature = "kat")]
fn queue_set(fx: &Fixture) -> Result<rotation::QueueSet, E> {
    let store = fx.profile.store();
    let s = store.lock().map_err(|_| "lock")?;
    let bytes = s.contact_queues(1)?.ok_or("queues")?;
    Ok(rotation::QueueSet::decode(&bytes)?)
}

/// SE-04 (§10.2 `docs/03:662`): in Balanced mode a rotation that would exceed `Σ 1/P_q ≤ F_M / (2·T)` or the 32 entries of a
/// `FETCH_MULTI` does not start — queues in overlap count — and `Event::RotationDeferred` says so; the pool and the contact's
/// queues are untouched and the schedule carries no `RouteUpdate`. One entry short of the limits it starts.
#[cfg(feature = "kat")]
#[test]
fn rotation_respects_rate_bound() -> R {
    use crate::scheduler::params::{Mode, Params};
    use crate::timing::TimingRng;

    let p = Params::default();
    // the pure rule: Σ at 31 entries of 80 s = 31 of 32
    let at80 = vec![80_000_u64; 31];
    assert!(rotation::rotation_fits(&p, Mode::Balanced, &at80, 80_000));
    assert!(
        !rotation::rotation_fits(&p, Mode::Balanced, &at80, 40_000),
        "Σ 33 > 32"
    );
    assert!(
        !rotation::rotation_fits(&p, Mode::Balanced, &[80_000; 32], 80_000),
        "33 entries"
    );
    assert!(rotation::rotation_fits(
        &p,
        Mode::Strict,
        &[10_000; 100],
        10_000
    ));
    assert!(rotation::rotation_fits(
        &p,
        Mode::LowBw,
        &[40_000; 4],
        40_000
    ));
    assert!(!rotation::rotation_fits(
        &p,
        Mode::LowBw,
        &[40_000; 5],
        40_000
    ));

    big(|| {
        let p = Params::default();
        let mut w = established("se04", 51)?;
        let store = w.host.profile.store();
        let pool = crate::invitations::SparePool::new(store.clone());
        let before = (pool.len(RelayId(1))?, queue_set(&w.host)?.encode()?);
        let mut rng = TimingRng::seeded(5);
        let full = [80_000_u64; 32];
        let out = rotation::rotate(
            &store,
            &mut w.h,
            &rotate_request(&p, &full),
            1_000,
            &mut rng,
        )?;
        assert!(matches!(
            out,
            rotation::Rotated::Deferred(crate::api::Event::RotationDeferred(ContactId(1)))
        ));
        assert_eq!(pool.len(RelayId(1))?, before.0, "no queue taken");
        assert_eq!(
            *queue_set(&w.host)?.encode()?,
            *before.1,
            "queues untouched"
        );
        // the schedule is untouched: the slot carries a dummy, not a RouteUpdate
        let cell = next(&mut w.h, 20_000)?;
        deliver(&mut w.g, &cell)?;
        assert!(w.g.take_events().is_empty());
        // one entry short of the limits: it starts
        let short = [80_000_u64; 31];
        let out = rotation::rotate(
            &store,
            &mut w.h,
            &rotate_request(&p, &short),
            2_000,
            &mut rng,
        )?;
        assert!(matches!(out, rotation::Rotated::Started { .. }));
        Ok(())
    })
}

/// SE-05 (`docs/02:115`): a contact's queue is rotated after 30 days and on demand — one rotation each: a pooled queue is
/// taken, the previous queue is in overlap for `U[1 h, 24 h]`, and one `RouteUpdate` with the new queue reaches the peer.
#[cfg(feature = "kat")]
#[test]
fn rotation_every_30_days_or_on_demand() -> R {
    use crate::scheduler::params::Params;
    use crate::timing::TimingRng;

    big(|| {
        let p = Params::default();
        let mut w = established("se05", 53)?;
        let store = w.host.profile.store();
        let pool = crate::invitations::SparePool::new(store.clone());
        let mut rng = TimingRng::seeded(7);
        let first = queue_set(&w.host)?;
        assert_eq!(first.entries.len(), 1);
        let t0 = first.rotated_ms;
        let day = 24 * 3_600_000_u64;
        assert!(!first.due(t0 + 30 * day - 1), "day 30 minus a millisecond");
        assert!(first.due(t0 + 30 * day), "day 30");
        let pool_before = pool.len(RelayId(1))?;
        // due: one rotation
        let now = t0 + 30 * day;
        let periods = [80_000_u64];
        let out = rotation::rotate(
            &store,
            &mut w.h,
            &rotate_request(&p, &periods),
            now,
            &mut rng,
        )?;
        let rotation::Rotated::Started { retire_at_ms, .. } = out else {
            return Err("started".into());
        };
        assert!((now + 3_600_000..=now + day).contains(&retire_at_ms));
        let set = queue_set(&w.host)?;
        assert_eq!(set.entries.len(), 2);
        assert_eq!(set.rotated_ms, now);
        assert_eq!(
            set.entries.first().and_then(|e| e.retire_at_ms),
            Some(retire_at_ms)
        );
        assert!(set.entries.last().is_some_and(|e| e.retire_at_ms.is_none()));
        assert!(!set.due(now + 1), "not due again");
        assert_eq!(pool.len(RelayId(1))?, pool_before - 1);
        // the peer receives exactly one RouteUpdate
        let cell = next(&mut w.h, ms(100))?;
        deliver(&mut w.g, &cell)?;
        assert!(matches!(
            w.g.take_events().as_slice(),
            [SessionEvent::Routes(routes)] if routes.len() == 1
        ));
        let cell = next(&mut w.h, ms(110))?;
        deliver(&mut w.g, &cell)?;
        assert!(w.g.take_events().is_empty(), "one RouteUpdate per rotation");
        // on demand, a day later: one more
        let out = rotation::rotate(
            &store,
            &mut w.h,
            &rotate_request(&p, &periods),
            now + day,
            &mut rng,
        )?;
        assert!(matches!(out, rotation::Rotated::Started { .. }));
        assert_eq!(queue_set(&w.host)?.entries.len(), 3);
        assert_eq!(pool.len(RelayId(1))?, pool_before - 2);
        Ok(())
    })
}

/// `contacts.queues` ([`rotation::QueueSet`]) is total and canonical: a set round-trips; a flag other than 0 or 1, a deadline
/// on the current queue, none on an old one, a wrong length and an empty set are refused.
#[cfg(feature = "kat")]
#[test]
fn queue_set_codec_is_canonical() -> R {
    use secmp_crypto::SecretBytes;

    let seed = |b: u8| SecretBytes::<32>::from_slice(&[b; 32]);
    let set = rotation::QueueSet {
        rotated_ms: 77,
        entries: vec![
            rotation::QueueEntry {
                seed: seed(1)?,
                retire_at_ms: Some(99),
            },
            rotation::QueueEntry {
                seed: seed(2)?,
                retire_at_ms: None,
            },
        ],
    };
    let bytes = set.encode()?;
    assert_eq!(bytes.len(), 1 + 8 + 2 * 41);
    let back = rotation::QueueSet::decode(&bytes)?;
    assert_eq!(*back.encode()?, *bytes);
    // damaged forms
    let mut flag = bytes.to_vec();
    *flag.get_mut(9 + 32).ok_or("flag")? = 2;
    assert!(rotation::QueueSet::decode(&flag).is_err());
    let mut zero_flag_deadline = bytes.to_vec();
    *zero_flag_deadline.get_mut(9 + 41 + 32).ok_or("flag")? = 0;
    *zero_flag_deadline.get_mut(9 + 41 + 40).ok_or("at")? = 5;
    assert!(rotation::QueueSet::decode(&zero_flag_deadline).is_err());
    let mut last_old = bytes.to_vec();
    *last_old.get_mut(9 + 41 + 32).ok_or("flag")? = 1;
    assert!(
        rotation::QueueSet::decode(&last_old).is_err(),
        "the newest queue is current"
    );
    let mut first_current = bytes.to_vec();
    *first_current.get_mut(9 + 32).ok_or("flag")? = 0;
    *first_current.get_mut(9 + 40).ok_or("at")? = 0;
    assert!(
        rotation::QueueSet::decode(&first_current).is_err(),
        "an old queue has a deadline"
    );
    assert!(rotation::QueueSet::decode(bytes.get(..bytes.len() - 1).ok_or("cut")?).is_err());
    let mut long = bytes.to_vec();
    long.push(0);
    assert!(rotation::QueueSet::decode(&long).is_err());
    assert!(rotation::QueueSet::decode(&[]).is_err());
    assert!(rotation::QueueSet::decode(&[0; 9]).is_err(), "no entry");
    Ok(())
}

/// The row count of `table`.
#[cfg(feature = "kat")]
fn rows(fx: &Fixture, table: &str) -> Result<i64, E> {
    let store = fx.profile.store();
    let s = store.lock().map_err(|_| "lock")?;
    Ok(s.connection_kat()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?)
}

/// SE-10 [O-27] (`docs/07:147`): `send` of a view-once (kind 3) to an unverified contact is refused with
/// `Err(Unverified)` — the outbox, the history and the schedule are as they were (the next slot carries a dummy); to a
/// verified contact it is accepted, held in memory only (no `outbox` row, no `messages` row, ST-17) and goes out in a slot.
#[cfg(feature = "kat")]
#[test]
fn view_once_refused_for_unverified() -> R {
    big(|| {
        let mut w = established("se10", 61)?;
        let store = w.guest.profile.store();
        let contacts = Contacts::new(store.clone(), w.guest.profile.fingerprint()?);
        let vo = Outgoing {
            kind: AppKind::ViewOnceText.byte(),
            payload: b"burn after reading",
            expire_after: 0,
        };
        let refused = queue_message(&store, &contacts, &mut w.g, ContactId(1), &vo, ms(5));
        assert_eq!(refused, Err(Error::Unverified));
        assert_eq!(w.g.outbox().waiting(), 0);
        assert_eq!(
            (rows(&w.guest, "outbox")?, rows(&w.guest, "messages")?),
            (0, 0)
        );
        // the schedule is unchanged: a slot carries a dummy, which the peer decides without a message
        let dummy = next(&mut w.g, ms(10))?;
        deliver(&mut w.h, &dummy)?;
        assert!(w.h.received().is_empty());

        set_verified(&store, &mut w.g, ContactId(1))?;
        let id = queue_message(&store, &contacts, &mut w.g, ContactId(1), &vo, ms(20))?;
        assert_eq!(w.g.outbox().waiting(), 1);
        assert_eq!(
            (rows(&w.guest, "outbox")?, rows(&w.guest, "messages")?),
            (0, 0)
        );
        assert!(
            store
                .lock()
                .map_err(|_| "lock")?
                .outgoing_view_once(&id)
                .is_some(),
            "held in memory"
        );
        let cell = next(&mut w.g, ms(30))?;
        deliver(&mut w.h, &cell)?;
        assert_eq!(w.h.received().len(), 1);
        assert_eq!(w.h.received().first().map(|r| r.msg_id), Some(id));
        Ok(())
    })
}

/// SE-11 [O-27] (CS-1.14): a view-once received from an unverified contact is held in memory and locked — `reveal` is
/// `Err(Unverified)` — and is never written (no `messages` row); after the contact is verified `reveal` shows it, once
/// the 20 s window has started.
#[cfg(feature = "kat")]
#[test]
fn view_once_from_unverified_locked() -> R {
    big(|| {
        let mut w = established("se11", 63)?;
        let (gstore, hstore) = (w.guest.profile.store(), w.host.profile.store());
        let contacts = Contacts::new(gstore.clone(), w.guest.profile.fingerprint()?);
        set_verified(&gstore, &mut w.g, ContactId(1))?;
        let id = queue_message(
            &gstore,
            &contacts,
            &mut w.g,
            ContactId(1),
            &Outgoing {
                kind: AppKind::ViewOnceText.byte(),
                payload: b"for your eyes",
                expire_after: 0,
            },
            ms(5),
        )?;
        let cell = next(&mut w.g, ms(10))?;
        deliver(&mut w.h, &cell)?;
        let got = w.h.take_received();
        assert_eq!(
            store_received(&hstore, ContactId(1), got, ms(11))?,
            [(id, 3)]
        );
        assert_eq!(rows(&w.host, "messages")?, 0, "never written");
        assert!(
            hstore
                .lock()
                .map_err(|_| "lock")?
                .view_once_held(&id, ms(12))
        );
        assert_eq!(reveal(&hstore, &w.h, &id, ms(12)), Err(Error::Unverified));
        // still held, still locked
        assert!(
            hstore
                .lock()
                .map_err(|_| "lock")?
                .view_once_held(&id, ms(13))
        );
        set_verified(&hstore, &mut w.h, ContactId(1))?;
        let shown = reveal(&hstore, &w.h, &id, ms(14))?;
        assert_eq!(&**shown, b"for your eyes");
        assert_eq!(rows(&w.host, "messages")?, 0);
        Ok(())
    })
}
