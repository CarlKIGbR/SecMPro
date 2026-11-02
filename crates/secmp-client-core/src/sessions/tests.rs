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
    let round = invitations.process_round(
        &issued.invitation.ld_id,
        crate::testutil::round_on(&invitations, &issued.invitation.ld_id)?,
        &fetched,
        &host.clock,
        &mut he,
    )?;
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
        invitation_queue: round.invitation_queue,
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
    /// The relay and the queue of the consumed invitation.
    pub(crate) invitation_queue: Option<(RelayId, crate::scheduler::types::QueueId)>,
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
        // Q210 d: a confirmation is awaited from a verified contact only
        w.g.set_trust(secmp_proto::tr::content::Trust::Verified);
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

/// SE-06/SE-08 through the `Api` (VERIFY-B4 P1 M-6; Q210 f): a core over `fx`'s profile answers a `Send` to contact 1
/// with `want`, and no outbox row is written.
#[cfg(feature = "kat")]
fn api_send_refused(fx: &Fixture, seed: u64, want: Error) -> R {
    use crate::api::{Core, Request};

    let store = fx.profile.store();
    let outbox = |store: &SharedStore| -> Result<i64, E> {
        let s = store.lock().map_err(|_| "lock")?;
        Ok(s.connection_kat()
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))?)
    };
    let before = outbox(&store)?;
    let mut core = Core::with_profile(fx.profile.clone(), fx.clock.clone(), core_sources(seed))?;
    let sent = core.handle(Request::Send {
        contact: ContactId(1),
        kind: 1,
        payload: Zeroizing::new(b"held".to_vec()),
        expire_after: 0,
    });
    assert_eq!(sent.err(), Some(want));
    drop(core);
    assert_eq!(outbox(&store)?, before, "nothing queued");
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
        // `Api.send` is `Err(Blocked)`, nothing queued (Q210 f)
        api_send_refused(&w.guest, 42, Error::Blocked)?;
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
        // `Api.send` is `Err(Frozen)`, nothing queued (Q210 f)
        api_send_refused(&w.guest, 44, Error::Frozen)?;
        assert_eq!(
            set_verified(&w.guest.profile.store(), &mut w.g, ContactId(1)).err(),
            Some(Error::Frozen)
        );
        w.g.set_trust(secmp_proto::tr::content::Trust::Verified);
        assert_eq!(w.g.may_send_real(), Err(Refusal::Trust), "still frozen");
        // nothing more is delivered
        w.h.outbox_mut().enqueue(text(3, 5), 0);
        flush(&mut w.h, &mut w.g, 2)?;
        assert!(w.g.received().is_empty());
        // Q205: from the rows, too — the session reopens frozen
        let World { guest, g, .. } = w;
        drop(g);
        let g = open_conversation(&guest.profile.store(), ContactId(1), Fixed(entropy(44)), T0)?;
        assert_eq!(g.trust(), secmp_proto::tr::content::Trust::Frozen);
        assert_eq!(g.may_send_real(), Err(Refusal::Trust));
        Ok(())
    })
}

/// The entropy of the conversations a test core opens.
#[cfg(feature = "kat")]
fn core_sources(seed: u64) -> impl FnMut() -> Fixed {
    let mut n = 0_u64;
    move || {
        n = n.saturating_add(1);
        Fixed(entropy(seed.saturating_add(n)))
    }
}

/// Q205 (VERIFY-B4 P1 B-1, probe P1; SE-08, spec §7.7): `Frozen` is durable — `set_verified` on a frozen session leaves
/// the stored trust `Frozen` (the session reopens frozen) and is `Err(Frozen)`; `Api` `Verify` with the right digits is
/// `Err(Frozen)` and the contact stays unverified, also after a restart.
#[cfg(feature = "kat")]
#[test]
fn frozen_survives_verify_and_reopen() -> R {
    use crate::api::{Core, Request, Response};
    use secmp_proto::tr::content::Trust;

    big(|| {
        let mut w = established("q205", 45)?;
        key_change(&mut w, true)?;
        flush(&mut w.h, &mut w.g, 4)?;
        assert!(matches!(
            w.g.take_events().as_slice(),
            [SessionEvent::KeyChangeInvalid]
        ));
        let World { guest, mut g, .. } = w;
        let store = guest.profile.store();
        let refused = set_verified(&store, &mut g, ContactId(1));
        drop(g);
        let g = open_conversation(&store, ContactId(1), Fixed(entropy(46)), T0)?;
        assert_eq!(g.trust(), Trust::Frozen);
        assert_eq!(refused.err(), Some(Error::Frozen));
        drop(g);
        let contacts = Contacts::new(store.clone(), guest.profile.fingerprint()?);
        assert!(!contacts.get(ContactId(1))?.verified);
        // through the `Api`
        let mut core =
            Core::with_profile(guest.profile.clone(), guest.clock.clone(), core_sources(47))?;
        let Response::SafetyNumber(digits) = core.handle(Request::SafetyNumber {
            contact: ContactId(1),
        })?
        else {
            return Err("safety number".into());
        };
        let verify = core.handle(Request::Verify {
            contact: ContactId(1),
            digits,
        });
        assert_eq!(verify.err(), Some(Error::Frozen));
        drop((core, contacts, store));
        let guest = guest.reopen()?;
        let store = guest.profile.store();
        let contacts = Contacts::new(store.clone(), guest.profile.fingerprint()?);
        assert!(
            !contacts.get(ContactId(1))?.verified,
            "unverified after the restart"
        );
        let g = open_conversation(&store, ContactId(1), Fixed(entropy(48)), T0)?;
        assert_eq!(g.trust(), Trust::Frozen, "frozen after the restart");
        Ok(())
    })
}

/// Q210 b (VERIFY-B4 P1 M-3, probe P2; SE-15): the block is durable — a received `Control{SessionResetRequest}` is
/// committed with its cell and the session reopens refusing real sends (`Reset`); a `Request::Remove` through the core
/// leaves the host's session `Removed` after a restart.
#[cfg(feature = "kat")]
#[test]
fn reset_request_survives_reopen() -> R {
    use crate::api::{Core, Request};

    big(|| {
        let mut w = established("q210b", 49)?;
        w.h.queue_control(secmp_proto::wire::cell::ControlCode::SessionResetRequest);
        let cell = next(&mut w.h, 5_000)?;
        deliver(&mut w.g, &cell)?;
        assert!(matches!(
            w.g.take_events().as_slice(),
            [SessionEvent::ResetRequested]
        ));
        let World { host, guest, h, g } = w;
        drop((h, g));
        let conv = open_conversation(&guest.profile.store(), ContactId(1), Fixed(entropy(50)), T0)?;
        assert_eq!(conv.may_send_real(), Err(Refusal::Reset));
        let mut core =
            Core::with_profile(host.profile.clone(), host.clock.clone(), core_sources(51))?;
        core.handle(Request::Remove {
            contact: ContactId(1),
        })?;
        drop(core);
        let conv = open_conversation(&host.profile.store(), ContactId(1), Fixed(entropy(52)), T0)?;
        assert_eq!(conv.may_send_real(), Err(Refusal::Removed));
        Ok(())
    })
}

/// Q210 a (VERIFY-B4 P1 M-2; SE-21's crash-fixture form, spec §7.7, CLAUDE.md §1.7): the new identity of a verified
/// `KeyChange` is written in the receive commit of the cell that completes it. With a fault on the identity write (an SQL
/// trigger) nothing of the receive is durable — the session's fixed part, the trust and the contact are as before and the
/// cell is not decided; without it the same cell commits, and after a reopen the contact has the new fingerprint,
/// unverified, and the session the trust `KeyChanged`.
#[cfg(feature = "kat")]
#[test]
fn key_change_identity_commits_with_receive() -> R {
    use secmp_proto::tr::content::Trust;

    big(|| {
        let mut w = established("q210a", 53)?;
        let new = key_change(&mut w, false)?;
        let store = w.guest.profile.store();
        let fingerprint = |store: &SharedStore| -> Result<[u8; 32], E> {
            let contacts = Contacts::new(store.clone(), w.guest.profile.fingerprint()?);
            Ok(contacts.get(ContactId(1))?.fingerprint)
        };
        let old_fp = fingerprint(&store)?;
        let trust_before = w.g.trust();
        let trigger = "CREATE TRIGGER refuse_identity BEFORE UPDATE OF iks ON contacts \
                       BEGIN SELECT RAISE(ABORT, 'refused'); END";
        store
            .lock()
            .map_err(|_| "lock")?
            .connection_kat()
            .execute_batch(trigger)?;
        let durable = |store: &SharedStore| -> Result<(Vec<u8>, Option<Vec<u8>>), E> {
            let s = store.lock().map_err(|_| "lock")?;
            let fixed = s.session_rows(1)?.ok_or("rows")?.fixed.to_vec();
            Ok((fixed, s.inbox_trust(1)?.1.map(|t| t.to_vec())))
        };
        let mut refused = None;
        for i in 0..8 {
            let cell = next(&mut w.h, ms(20).saturating_add(ms(i)))?;
            let before = durable(&store)?;
            if w.g.deliver_direct(&cell).is_err() {
                // the cell that completes the key change: nothing of its receive is durable
                assert_eq!(durable(&store)?, before, "the receive is not durable");
                assert_eq!(fingerprint(&store)?, old_fp);
                refused = Some(cell);
                break;
            }
        }
        assert!(
            refused.is_some(),
            "the receive commit of the completing cell writes the identity: the fault refuses it"
        );
        let cell = refused.ok_or("no cell completed the key change")?;
        assert_eq!(w.g.trust(), trust_before, "in memory: as before");
        store
            .lock()
            .map_err(|_| "lock")?
            .connection_kat()
            .execute_batch("DROP TRIGGER refuse_identity")?;
        // the same cell again: decided now
        deliver(&mut w.g, &cell)?;
        assert!(matches!(
            w.g.take_events().as_slice(),
            [SessionEvent::KeyChanged(iks)] if **iks == new
        ));
        let World { guest, g, .. } = w;
        drop(g);
        let g = open_conversation(&store, ContactId(1), Fixed(entropy(54)), T0)?;
        assert_eq!(g.trust(), Trust::KeyChanged);
        let contacts = Contacts::new(store.clone(), guest.profile.fingerprint()?);
        let contact = contacts.get(ContactId(1))?;
        assert_eq!(
            contact.fingerprint,
            secmp_proto::prekeys::fingerprint_of(&new)?
        );
        assert!(!contact.verified);
        Ok(())
    })
}

/// Q210 c (VERIFY-B4 P1 M-3; R-ROT-1): pending control content is durable with the commit that makes its effect durable —
/// a rotation's `RouteUpdate`, a removal's `Control{1}` and an identity rotation's `KeyChange` — and re-planned when the
/// session opens again: after a restart before any slot each reaches the peer, and the send commit of its last cell takes
/// its row.
#[cfg(feature = "kat")]
#[test]
fn pending_control_content_survives_restart() -> R {
    use crate::api::{Core, Request};

    big(|| {
        let World { host, h, mut g, .. } = world("q210c", 55)?;
        drop(h);
        let store = host.profile.store();
        let pending = |store: &SharedStore| -> Result<usize, E> {
            Ok(store.lock().map_err(|_| "lock")?.pending_controls(1)?.len())
        };
        // one request through the core, then the process ends before any slot; the session opens from its rows and sends
        let mut run = |request: Request, seed: u64| -> Result<Vec<SessionEvent>, E> {
            let mut core =
                Core::with_profile(host.profile.clone(), host.clock.clone(), core_sources(seed))?;
            core.handle(request)?;
            drop(core);
            assert_eq!(pending(&store)?, 1, "durable with its effect");
            let mut h = open_conversation(&store, ContactId(1), Fixed(entropy(seed)), T0)?;
            for i in 0..6 {
                let cell = next(&mut h, ms(seed.saturating_mul(10).saturating_add(i)))?;
                deliver(&mut g, &cell)?;
            }
            assert_eq!(
                pending(&store)?,
                0,
                "the last cell's send commit took the row"
            );
            Ok(g.take_events())
        };
        let rotated = run(
            Request::Rotate {
                contact: ContactId(1),
                relay: 1,
            },
            60,
        )?;
        assert!(matches!(rotated.as_slice(), [SessionEvent::Routes(_)]));
        let identity = run(Request::RotateIdentity, 61)?;
        assert!(
            matches!(identity.as_slice(), [SessionEvent::KeyChanged(_)]),
            "the KeyChange of the identity rotation"
        );
        let removed = run(
            Request::Remove {
                contact: ContactId(1),
            },
            62,
        )?;
        assert!(matches!(removed.as_slice(), [SessionEvent::ContactRemoved]));
        Ok(())
    })
}

/// Q210 e (VERIFY-B4 P1 M-8; SE-17, §7.7): the single entry is asked per cell — a message whose fragments were planned
/// before the trust became `KeyChanged` is not sealed any further: its fragments leave the plan, the message waits in the
/// outbox, the slots carry dummies, and the peer receives nothing of it.
#[cfg(feature = "kat")]
#[test]
fn planned_fragments_held_after_freeze() -> R {
    use secmp_proto::tr::content::Trust;

    big(|| {
        let mut w = established("q210e", 57)?;
        w.h.outbox_mut().enqueue(text(4, 16_000), 0);
        // the first fragment goes out: the others are planned
        let cell = next(&mut w.h, ms(5))?;
        deliver(&mut w.g, &cell)?;
        assert!(w.h.has_pending_real());
        w.h.set_trust(Trust::KeyChanged);
        for i in 0..70_u64 {
            let cell = next(&mut w.h, ms(6).saturating_add(ms(i)))?;
            deliver(&mut w.g, &cell)?;
        }
        assert!(
            w.g.received().is_empty(),
            "nothing of the message after the change"
        );
        assert_eq!(w.h.outbox().waiting(), 1, "the message is held");
        Ok(())
    })
}

/// Q210 e (VERIFY-B4 P1 M-8; IN-15): control content obeys `awaiting_first_reply` — an initiator's control content waits
/// behind the handshake cells until the responder's first reply is decrypted (only dummies before it), then goes out.
#[cfg(feature = "kat")]
#[test]
fn control_content_waits_for_first_reply() -> R {
    big(|| {
        let mut w = world("q210w", 59)?;
        assert!(w.g.awaiting_first_reply());
        w.g.queue_control(secmp_proto::wire::cell::ControlCode::SessionResetRequest);
        for i in 0..3 {
            next(&mut w.g, ms(i))?;
        }
        for i in 3..8 {
            let cell = next(&mut w.g, ms(i))?;
            deliver(&mut w.h, &cell)?;
        }
        assert!(
            w.h.take_events().is_empty(),
            "only dummies before the first reply"
        );
        w.h.queue_route_update(vec![route(1)?]);
        let reply = next(&mut w.h, ms(9))?;
        deliver(&mut w.g, &reply)?;
        assert!(!w.g.awaiting_first_reply());
        let cell = next(&mut w.g, ms(10))?;
        deliver(&mut w.h, &cell)?;
        assert!(matches!(
            w.h.take_events().as_slice(),
            [SessionEvent::ResetRequested]
        ));
        Ok(())
    })
}

/// Q210 c: the row of a pending control content is `tag u8 ‖ body` in the wire encodings and decodes strictly — each kind
/// round-trips; an empty row, an unknown tag, a `Control` with an argument and a body with a trailing byte are refused.
#[cfg(feature = "kat")]
#[test]
fn pending_control_codec_is_strict() -> R {
    use crate::sessions::actor::PendingControl;
    use secmp_proto::wire::cell::{ControlBody, ControlCode, RouteUpdateBody};

    let routes = PendingControl::Routes(RouteUpdateBody {
        routes: vec![route(3)?],
    })
    .encode()
    .map_err(|_| "routes")?;
    assert_eq!(routes.first(), Some(&1));
    assert!(
        matches!(PendingControl::decode(&routes), Ok(PendingControl::Routes(b)) if b.routes.len() == 1)
    );
    let control = PendingControl::Control(ControlCode::SessionResetRequest)
        .encode()
        .map_err(|_| "control")?;
    assert_eq!(control.as_slice(), [2, 2, 0, 0]);
    assert!(matches!(
        PendingControl::decode(&control),
        Ok(PendingControl::Control(ControlCode::SessionResetRequest))
    ));
    let with_arg = ControlBody {
        code: ControlCode::ContactRemoved,
        arg: Zeroizing::new(vec![7]),
    };
    let mut bad = vec![2];
    bad.extend_from_slice(&secmp_proto::Encode::encode(&with_arg)?);
    let mut trailing = routes.to_vec();
    trailing.push(0);
    for row in [&[][..], &[9, 0], &bad, &trailing] {
        assert!(PendingControl::decode(row).is_err(), "{row:?}");
    }
    Ok(())
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
        old_queue: None,
        unix_base_ms: 0,
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

/// `contacts.queues` ([`rotation::QueueSet`]) is total and canonical: a set round-trips; a flag other than the two bits, a
/// deadline on the current queue, none on an old one, a period outside `PERIODS`, a sender seed that is there without its
/// flag, a wrong length and an empty set are refused.
#[cfg(feature = "kat")]
#[test]
fn queue_set_codec_is_canonical() -> R {
    use secmp_crypto::SecretBytes;

    const E0: usize = 9;
    const LEN: usize = 83;
    let seed = |b: u8| SecretBytes::<32>::from_slice(&[b; 32]);
    let entry = |queue: u32, b: u8, send: bool, retire: Option<u64>| -> Result<_, E> {
        Ok(rotation::QueueEntry {
            relay: 1,
            queue,
            seed: seed(b)?,
            send_seed: send.then(|| seed(b + 1)).transpose()?,
            period_s: 20,
            retire_at_ms: retire,
        })
    };
    let set = rotation::QueueSet {
        rotated_ms: 77,
        entries: vec![entry(4, 1, false, Some(99))?, entry(5, 2, true, None)?],
    };
    let bytes = set.encode()?;
    assert_eq!(bytes.len(), E0 + 2 * LEN);
    let back = rotation::QueueSet::decode(&bytes)?;
    assert_eq!(*back.encode()?, *bytes);
    assert_eq!(back.entries.first().map(|e| e.queue), Some(4));
    assert!(back.entries.first().is_some_and(|e| e.send_seed.is_none()));
    assert!(back.entries.get(1).is_some_and(|e| e.send_seed.is_some()));
    let damaged = |at: usize, v: u8| -> Result<Vec<u8>, E> {
        let mut b = bytes.to_vec();
        *b.get_mut(at).ok_or("offset")? = v;
        Ok(b)
    };
    let first = E0;
    let second = E0 + LEN;
    // flags of the first entry: bit 0 deadline, bit 1 sender seed known
    assert!(
        rotation::QueueSet::decode(&damaged(first + 74, 0b100 | 1)?).is_err(),
        "unknown bit"
    );
    assert!(
        rotation::QueueSet::decode(&damaged(first + 74, 0)?).is_err(),
        "old queue without a deadline"
    );
    assert!(
        rotation::QueueSet::decode(&damaged(first + 40, 7)?).is_err(),
        "seed without its flag"
    );
    assert!(
        rotation::QueueSet::decode(&damaged(second + 74, 0b10 | 1)?).is_err(),
        "current queue with a deadline"
    );
    assert!(
        rotation::QueueSet::decode(&damaged(second + 75 + 7, 5)?).is_err(),
        "deadline bytes without the flag"
    );
    assert!(
        rotation::QueueSet::decode(&damaged(first + 73, 21)?).is_err(),
        "period"
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

/// IN-16 (D-C2-1; §6.6 step 4 `docs/03:351`, §10.6 (4), (5) `:696-697`): after the responder accepted a handshake, its first
/// reply is a `RouteUpdate` with a queue from its pool (the pool shrinks by one, no `QUEUE_NEW`), the invitation queue is
/// kept for `U[1 h, 24 h]` and then retired with a `QUEUE_DEL` that waits for a `FETCH` without a present cell — an empty
/// `FETCH` inside the window does not count — and then runs `U[1 min, 60 min]` later.
#[cfg(feature = "kat")]
#[test]
fn first_reply_carries_route_update() -> R {
    use crate::scheduler::control::{ControlOps, OpSpec, When};
    use crate::scheduler::params::{Mode, Params};
    use crate::scheduler::types::{ControlKind, OpId, QueueId};
    use crate::timing::TimingRng;

    big(|| {
        let host = party("in16-h", 81)?;
        let guest = party("in16-g", 83)?;
        let Link {
            mut h,
            mut g,
            contact,
            invitation_queue,
            ..
        } = connect(&host, &guest, 81)?;
        let (relay, old) = invitation_queue.ok_or("invitation queue")?;
        let store = host.profile.store();
        let pool = crate::invitations::SparePool::new(store.clone());
        let before = pool.len(relay)?;
        let (params, mut rng) = (Params::default(), TimingRng::seeded(11));
        let base = T0 * 1_000;
        let request = rotation::RotateRequest {
            contact,
            relay,
            period: Period::S20,
            mode: Mode::Strict,
            params: &params,
            recv_periods_ms: &[],
            old_queue: Some(old),
            unix_base_ms: base,
        };
        let started = rotation::rotate(&store, &mut h, &request, base, &mut rng)?;
        let rotation::Rotated::Started {
            retire_at_ms,
            retire_op: Some(op),
            ..
        } = started
        else {
            return Err("started with a retirement".into());
        };
        assert_eq!(pool.len(relay)?, before - 1, "a pool queue, no QUEUE_NEW");
        assert!((base + 3_600_000..=base + 86_400_000).contains(&retire_at_ms));
        let from = retire_at_ms - base;
        assert_eq!(
            op,
            OpSpec {
                kind: ControlKind::QueueDel(old),
                relay,
                related: u64::from(old.0),
                when: When::AfterEmptyFetchFrom(old, from),
            }
        );
        // the invitation queue is in overlap, the pool queue is current
        let set = queue_set(&host)?;
        assert_eq!(set.entries.len(), 2);
        assert_eq!(
            set.entries.first().and_then(|e| e.retire_at_ms),
            Some(retire_at_ms)
        );

        // the first reply is the RouteUpdate, with the pool queue (period 20 s)
        for i in 0..3 {
            next(&mut g, ms(i))?;
        }
        let reply = next(&mut h, ms(4))?;
        deliver(&mut g, &reply)?;
        assert!(!g.awaiting_first_reply());
        let events = g.take_events();
        let [SessionEvent::Routes(routes)] = events.as_slice() else {
            return Err("one Routes event".into());
        };
        let [secmp_proto::wire::cell::RouteDescriptor::RelayQueue(q)] = routes.as_slice() else {
            return Err("one relay queue".into());
        };
        assert_eq!(q.period_s, Period::S20);

        // the QUEUE_DEL waits: not within the window, then for an empty FETCH, then its delay
        let mut ops = ControlOps::new();
        ops.schedule(&params, &mut rng, OpId(1), 0, op)?;
        assert!(ops.awaits_empty_fetch(OpId(1)));
        ops.note_empty_fetch(&params, &mut rng, old, from - 1);
        assert!(
            ops.awaits_empty_fetch(OpId(1)),
            "an empty FETCH inside the window"
        );
        ops.note_empty_fetch(&params, &mut rng, QueueId(9_999), from);
        assert!(ops.awaits_empty_fetch(OpId(1)), "another queue's");
        ops.note_empty_fetch(&params, &mut rng, old, from);
        assert!(!ops.awaits_empty_fetch(OpId(1)));
        let due = ops.due_of(OpId(1)).ok_or("due")?;
        assert!((from + 60_000..=from + 3_600_000).contains(&due));
        Ok(())
    })
}

/// B-4 killers (`trust_of`): the stored trust codes 0…3 are the four trusts, anything else is none; the row is `code ‖
/// block` (Q210 b), two bytes, decoded strictly by the store.
#[cfg(feature = "kat")]
#[test]
fn trust_codes_map_to_trusts() {
    use secmp_proto::tr::content::Trust;
    use secmp_store::sessions::trust_row;
    assert_eq!(trust_row(&[3, 2]), Ok((3, 2)));
    assert!(trust_row(&[3]).is_err() && trust_row(&[3, 2, 0]).is_err());
    assert_eq!(trust_of(0), Some(Trust::Unverified));
    assert_eq!(trust_of(1), Some(Trust::Verified));
    assert_eq!(trust_of(2), Some(Trust::KeyChanged));
    assert_eq!(trust_of(3), Some(Trust::Frozen));
    assert_eq!(trust_of(4), None);
    for trust in [
        Trust::Unverified,
        Trust::Verified,
        Trust::KeyChanged,
        Trust::Frozen,
    ] {
        assert_eq!(
            trust_of(crate::scheduler::outbox::trust_code(trust)),
            Some(trust)
        );
    }
}

/// B-4 killers (`queue_message`, `open_conversation`): a text of exactly `MESSAGE_MAX` bytes is taken and one byte more is
/// `Unsupported`; the trust a session was verified with is the trust it is opened with again.
#[cfg(feature = "kat")]
#[test]
fn message_limit_and_reopened_trust() -> R {
    big(|| {
        let mut w = established("se-lim", 47)?;
        let store = w.guest.profile.store();
        let contacts = Contacts::new(store.clone(), w.guest.profile.fingerprint()?);
        let payload = vec![b'x'; MESSAGE_MAX];
        let fits = Outgoing {
            kind: 1,
            payload: &payload,
            expire_after: 0,
        };
        assert!(queue_message(&store, &contacts, &mut w.g, ContactId(1), &fits, ms(5)).is_ok());
        let long = vec![b'x'; MESSAGE_MAX + 1];
        let over = Outgoing {
            kind: 1,
            payload: &long,
            expire_after: 0,
        };
        assert_eq!(
            queue_message(&store, &contacts, &mut w.g, ContactId(1), &over, ms(6)),
            Err(Error::Unsupported)
        );
        // verified, then opened again from the rows: still verified
        set_verified(&store, &mut w.g, ContactId(1))?;
        let again = open_conversation(&store, ContactId(1), Fixed(entropy(88)), T0)?;
        assert_eq!(again.trust(), secmp_proto::tr::content::Trust::Verified);
        Ok(())
    })
}

/// B-4 killer (`Conversation::set_peer`, `accept_key_change`): after the first key change is accepted, a second one signed by
/// the identity it announced verifies — the session verifies under the new `IK_sig`.
#[cfg(feature = "kat")]
#[test]
fn second_key_change_verifies_under_the_new_key() -> R {
    use secmp_proto::prekeys::IdentityKeys;
    use secmp_proto::tr::content::key_change_body;

    big(|| {
        let mut w = established("se06b", 49)?;
        let first = key_change(&mut w, false)?;
        flush(&mut w.h, &mut w.g, 4)?;
        assert!(matches!(
            w.g.take_events().as_slice(),
            [SessionEvent::KeyChanged(_)]
        ));
        accept_key_change(&w.guest.profile.store(), &mut w.g, ContactId(1), &first)?;
        // the identity of `key_change` (stream 901) signs the next one
        let signer = secmp_proto::tr::Entropy::hybrid_signing_key(&mut entropy(901))?;
        let newer = IdentityKeys::generate(&mut entropy(907))?;
        w.h.queue_key_change(key_change_body(&signer, newer.public())?)
            .map_err(|_| "queue")?;
        flush(&mut w.h, &mut w.g, 4)?;
        let events = w.g.take_events();
        assert!(
            matches!(events.as_slice(), [SessionEvent::KeyChanged(iks)] if **iks == *newer.public()),
            "the second key change is accepted under the first new key"
        );
        Ok(())
    })
}

/// B-4 killer (`note_unconfirmed`, SE-13b): a contact that gets no receipts from us is not asked about them — no
/// `NotConfirmed` after `T_RS` when receipts are off.
#[cfg(feature = "kat")]
#[test]
fn no_unconfirmed_report_without_receipts() -> R {
    big(|| {
        let mut w = established("se13c", 51)?;
        w.g.set_receipt_timeout_ms(T_RS_MIN_MS);
        w.g.set_send_receipts(false);
        w.g.outbox_mut().enqueue(text(6, 8), 0);
        let prepared = w.g.prepare_direct(10_000).map_err(|_| "prepare")?;
        w.g.relayed_direct(prepared.token, 5);
        w.g.take_events();
        let _ = next(&mut w.g, 10_000 + T_RS_MIN_MS)?;
        let _ = next(&mut w.g, 10_000 + T_RS_MIN_MS + 10_000)?;
        assert!(w.g.take_events().is_empty());
        Ok(())
    })
}
