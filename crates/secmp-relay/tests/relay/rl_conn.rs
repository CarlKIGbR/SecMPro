// SPDX-License-Identifier: AGPL-3.0-or-later
//! Relay obligations at the connection and the link (TEST-SPEC-M5 (b5) and (b3); spec §8.2–§8.5, §9.7 items 6
//! and 7): one link per connection (RL-12), the frame-rate and handshake-rate limits (RL-13, RL-14; ADR-048 (p),
//! OPEN-M5-02), the graceful drain (RL-15, OPEN-M5-09 A), `keygen` and load (RL-16), the static-key rotation
//! (RL-17, OPEN-M5-10 A), `akc` (RL-19), fresh dummies in the draw order of reading R5-7 (RL-20), the
//! `HELLO`→`HS1` timeout (RL-22), and the unknown request opcodes (F-11).

use std::path::Path;

use secmp_crypto::sha256;
use secmp_proto::Decode as _;
use secmp_proto::link::ids::AccessKey;
use secmp_proto::link::{MAX_VALIDITY_SECS, client};
use secmp_proto::tr::{FixedEntropy, OsEntropy};
use secmp_proto::wire::frame::{CellrContext, Request};
use secmp_proto::wire::record::{Hs1, RelayInfoRecord};
use secmp_relay::clock::wall_clock_unix_secs;
use secmp_relay::event::NullSink;
use secmp_relay::keys::{DEFAULT_VALIDITY_SECS, KeyFile};
use secmp_relay::rate::RateLimit;
use secmp_relay::{Connection, Limits, Now, Outcome, Output, Relay};

use crate::d2::{OP_SKEY, msg_queue_new, queue_new_req};
use crate::fixture::{
    Bench, Client, EXPIRES, FRAME, HELLO, Key, NOW, RelayFx, VALID_UNTIL, at, client_entropy, flip,
    hex, lots, now, reference, relay_hs_entropy, rid_of, sid_of,
};
use crate::rl_util::{
    BLOB, CELL, Drive, RELAYINFO_RECORD, V, Wire, add, cells, copy_key, distinct_bytes, flags,
    fresh_dir, hello, identity, key_file, linkr, load, one_time, pair, presents, strip, view,
};

/// What a teardown writes: nothing, and the connection closes (spec §8.5).
const fn closed() -> Output {
    Output {
        bytes: Vec::new(),
        close: true,
    }
}

/// The suite's wall clock with the monotonic clock at `ms`.
const fn mono(ms: u64) -> Now {
    Now {
        unix_secs: NOW,
        mono_ms: ms,
    }
}

/// The wall clock at `unix_secs`, the monotonic clock at 0.
const fn wall(unix_secs: u64) -> Now {
    Now {
        unix_secs,
        mono_ms: 0,
    }
}

/// RL-12 `relay_one_link_per_connection`: after `HS2` the connection reads only 4352-byte units, so a `HELLO` — the
/// start of a unit the next frame completes, a `HELLO` padded to a unit, a `HELLO` with a whole second handshake —
/// fails to open as a frame: teardown, nothing emitted, the store unchanged, no draw (spec §9.7 item 7, D.1).
#[test]
fn relay_one_link_per_connection() {
    let fx = RelayFx::case1();
    let relay = fx.relay(Limits::vectors());
    let mut w = Wire::link_a(&relay, &fx, now());
    assert_eq!(
        w.go(now(), &mut lots(), |_, s| Client::ping(s)),
        vec![V::Ok],
        "the link serves"
    );
    let (digest, mut e) = (relay.store_digest_kat(), lots());
    let left = e.remaining();
    let out = w.conn.on_bytes(&HELLO, now(), &mut e);
    assert_eq!(
        out,
        Output::default(),
        "RL-12: a HELLO is read as the start of a unit"
    );
    let next = w.client.seal(&Client::ping(2));
    assert_eq!(
        w.conn.on_bytes(&next, now(), &mut e),
        closed(),
        "RL-12: teardown"
    );
    assert!(
        w.conn.is_closed() && w.conn.executor().is_none(),
        "RL-12: the link is gone"
    );
    assert_eq!(
        w.conn.on_bytes(&next, now(), &mut e),
        closed(),
        "RL-12: nothing after the teardown"
    );
    // a second handshake: HELLO and an honest HS1 for this relay
    let info = relay
        .keys()
        .newest()
        .unwrap()
        .0
        .relay_info_record(VALID_UNTIL)
        .unwrap();
    let (_, st) = client::start(fx.relay_fp, Some(&fx.access()), NOW).unwrap();
    let (hs1, _) = st.on_relayinfo(&info, &mut client_entropy()).unwrap();
    let mut padded = HELLO.to_vec();
    padded.resize(FRAME, 0);
    let mut second = [HELLO.as_slice(), &hs1].concat();
    second.resize(FRAME, 0);
    for (name, unit) in [("a HELLO unit", padded), ("HELLO + HS1", second)] {
        let mut w = Wire::link_a(&relay, &fx, now());
        assert_eq!(
            w.conn.on_bytes(&unit, now(), &mut e),
            closed(),
            "RL-12: {name}: teardown"
        );
        assert!(w.conn.is_closed(), "RL-12: {name}: closed");
    }
    assert_eq!(relay.store_digest_kat(), digest, "RL-12: store unchanged");
    assert_eq!(e.remaining(), left, "RL-12: no draw");
}

/// RL-13 `relay_frame_rate_limit`: with the per-link limit of OPEN-M5-02 (burst 8 request frames, refill 1 per
/// second), a PING, a FETCH, a `LINK_PUT` and an `SKEY` over the rate are each answered with exactly one ERR 7 frame
/// — the `LINK_PUT`'s after its third frame, also when only that frame is over —, are not executed (store
/// unchanged), and their `cmd_seq` is recorded: a later request with it is stale (ERR 6) (spec §9.7 item 7, D.2;
/// ADR-048 (p)). The over-rate `SKEY` (`rl13_over_rate_skey_is_err_7_and_records_cmd_seq`, M05 review R-139/C-10,
/// H-4): rate (ERR 7), not the `SKEY` row's ERR 6, for a fresh `cmd_seq` over the rate — the D.2 exceptions override
/// the `SKEY` table row; a stale `cmd_seq` is ERR 6 before the rate, also for `SKEY` (owner erratum (d), §8.5/D.2
/// precedence; OPEN-M5-decided clarification 2026-10-09).
#[test]
fn relay_frame_rate_limit() {
    let mut d = Drive::new(Limits::defaults());
    let limit = RateLimit {
        burst: 8,
        per_sec: 1,
    };
    assert_eq!(
        d.b.relay.limits().link_rate,
        Some(limit),
        "the OPEN-M5-02 default"
    );
    let (r, s) = pair(1, 2);
    let (owner, blob) = (Key::of(3), distinct_bytes(3, BLOB));
    let t0 = mono(0);
    d.go(t0, |c, n| c.queue_new(n, &r, &s));
    d.go(t0, |c, n| c.send(n, &r, &s, &[1; CELL]));
    d.go(t0, |c, n| c.send(n, &r, &s, &[2; CELL]));
    for _ in 0..5 {
        assert_eq!(
            d.go(t0, |_, n| Client::ping(n)),
            vec![V::Ok],
            "within the burst"
        );
    }
    let before = d.b.digest();
    let ping = d.go(t0, |_, n| Client::ping(n));
    assert_eq!(
        ping,
        vec![V::Err(7)],
        "RL-13: PING over the rate: one ERR 7"
    );
    let ping_seq = d.b.exec.last_cmd_seq();
    let fetch = d.go(t0, |c, n| c.fetch(n, &r, 1));
    assert_eq!(
        fetch,
        vec![V::Err(7)],
        "RL-13: FETCH over the rate: one ERR 7, not F CELLR frames"
    );
    let fetch_seq = d.b.exec.last_cmd_seq();
    let put = d.put(t0, &one_time(&[0x13; 16], EXPIRES, &owner, &blob));
    assert_eq!(
        put,
        vec![V::Err(7)],
        "RL-13: LINK_PUT over the rate: one ERR 7 after frame 3"
    );
    let put_seq = d.b.exec.last_cmd_seq();
    let over = skey(&mut d, t0);
    assert_eq!(
        over,
        vec![V::Err(7)],
        "RL-13 (C-10) rl13_over_rate_skey_is_err_7_and_records_cmd_seq: SKEY over the rate: one ERR 7"
    );
    let skey_seq = d.b.exec.last_cmd_seq();
    assert_eq!(
        (ping_seq, fetch_seq, put_seq, skey_seq),
        (9, 10, 11, 12),
        "RL-13: the cmd_seqs are recorded (C-10: the SKEY's too)"
    );
    assert_eq!(
        d.b.digest(),
        before,
        "RL-13: not executed (cell 1 kept, no link data; C-10: the SKEY changed nothing)"
    );
    for (i, seq) in [ping_seq, fetch_seq, put_seq, skey_seq]
        .into_iter()
        .enumerate()
    {
        let t = mono(times_ms(add(1, u64::try_from(i).unwrap())));
        let stale = d.b.run(&Client::ping(seq), t, &mut lots());
        assert_eq!(
            stale.frames().iter().map(view).collect::<Vec<_>>(),
            vec![(seq, V::Err(6))],
            "RL-13: a later request with a recorded cmd_seq is stale (C-10 \
             rl13_over_rate_skey_is_err_7_and_records_cmd_seq: also the SKEY's)"
        );
    }
    // only the third frame over the rate: two tokens left when the LINK_PUT starts
    let t1 = mono(20_000);
    for _ in 0..6 {
        assert_eq!(d.go(t1, |_, n| Client::ping(n)), vec![V::Ok]);
    }
    let put = d.put(t1, &one_time(&[0x14; 16], EXPIRES, &owner, &blob));
    assert_eq!(
        put,
        vec![V::Err(7)],
        "RL-13: the third frame over the rate: one ERR 7 after it"
    );
    assert_eq!(d.b.digest(), before, "RL-13: not executed");
    // within the rate again: served
    let t2 = mono(40_000);
    let put = d.put(t2, &one_time(&[0x14; 16], EXPIRES, &owner, &blob));
    assert_eq!(
        put,
        vec![V::Ok],
        "RL-13: within the rate the LINK_PUT is executed"
    );
    let fetch = d.go(t2, |c, n| c.fetch(n, &r, 1));
    assert_eq!(
        presents(&fetch),
        vec![(1, 2), (0, 0), (0, 0), (0, 0)],
        "RL-13: the FETCH is executed"
    );
}

/// An `SKEY` (`0x02 ‖ cmd_seq`; no request type, reading OPEN-6, D.2) for the next `cmd_seq` at `t`: the views of
/// its answer (each frame echoes the `cmd_seq`).
fn skey(d: &mut Drive, t: Now) -> Vec<V> {
    let s = d.seq.bump();
    let frame =
        d.b.client
            .seal_payload(&[&[OP_SKEY][..], &s.to_be_bytes()].concat());
    let frames = match d.b.unit(&frame, t, &mut lots()) {
        Outcome::Respond(frames) => Some(frames),
        Outcome::Pending | Outcome::Teardown => None,
    }
    .expect("the SKEY is answered");
    let views = frames
        .iter()
        .map(|f| view(&d.b.client.open(f.as_slice(), CellrContext::Fetch)))
        .collect();
    strip(s, views)
}

/// `secs` seconds in milliseconds.
fn times_ms(secs: u64) -> u64 {
    secs.checked_mul(1000).unwrap()
}

/// RL-14 `relay_handshake_rate_limit`: with the listener's `HELLO` limit of OPEN-M5-02 (burst 16, refill 4 per
/// second) the 17th `HELLO` at one instant closes its connection before `RELAYINFO` (nothing emitted); one more is
/// answered a quarter second later; without the limit every `HELLO` is answered (spec §9.7 item 7; ADR-048 (p)).
#[test]
fn relay_handshake_rate_limit() {
    let fx = RelayFx::case1();
    let relay = fx.relay(Limits::defaults());
    let info = relay
        .keys()
        .newest()
        .unwrap()
        .0
        .relay_info_record(VALID_UNTIL)
        .unwrap();
    assert_eq!(info.len(), RELAYINFO_RECORD);
    let answered = Output {
        bytes: info.clone(),
        close: false,
    };
    let mut e = lots();
    let left = e.remaining();
    let mut hello_at = |relay: &Relay, ms: u64| {
        let mut conn = Connection::accept(relay, mono(ms)).unwrap();
        let out = conn.on_bytes(&HELLO, mono(ms), &mut e);
        assert_eq!(
            conn.is_closed(),
            out.close,
            "a close is a closed connection"
        );
        out
    };
    for i in 0..16 {
        assert_eq!(
            hello_at(&relay, 0),
            answered,
            "RL-14: HELLO {i} within the burst"
        );
    }
    assert_eq!(
        hello_at(&relay, 0),
        closed(),
        "RL-14: over the rate: closed before RELAYINFO"
    );
    assert_eq!(
        hello_at(&relay, 249),
        closed(),
        "RL-14: no token before 250 ms"
    );
    assert_eq!(
        hello_at(&relay, 250),
        answered,
        "RL-14: one token after 250 ms"
    );
    assert_eq!(hello_at(&relay, 250), closed(), "RL-14: and only one");
    let open = fx.relay(Limits::vectors());
    for i in 0..64 {
        assert_eq!(
            hello_at(&open, 0),
            answered,
            "RL-14: no limit configured: HELLO {i} answered"
        );
    }
    assert_eq!(e.remaining(), left, "RL-14: HELLO draws nothing");
}

/// RL-15 `relay_graceful_drain`: once the drain has started, a `QUEUE_NEW` that would create state and `LINK_PUT`
/// (after its third frame) answer ERR 2 with the store unchanged, SEND and FETCH on the open link are served, a new
/// connection is refused, and the drain is finished `drain_secs` (60) after its start (`docs/02` §5.1; OPEN-M5-09
/// A). An identical `QUEUE_NEW` (same keys, existing queue: no new state) answers `OK_QUEUE_NEW` with the store
/// unchanged also during the drain, as at the budget limit (Q-07), and its token is checked first: with a bad token
/// it is ERR 1 (`rl15_drain_identical_queue_new_answers_ok`; OPEN-M5-09 clarification 2026-10-09, M05 review
/// R-119/C-10).
#[test]
fn relay_graceful_drain() {
    let mut d = Drive::new(Limits::vectors());
    let (r, s) = pair(1, 2);
    let (owner, blob) = (Key::of(3), distinct_bytes(5, BLOB));
    d.go(now(), |c, n| c.queue_new(n, &r, &s));
    assert_eq!(
        d.go(now(), |c, n| c.send(n, &r, &s, &[1; CELL])),
        vec![V::Send(1, None)]
    );
    assert!(d.b.relay.accepts_connections() && !d.b.relay.draining());
    let start = at(0, 1_000);
    d.b.relay.start_drain(start);
    assert!(d.b.relay.draining(), "RL-15: draining");
    let before = d.b.digest();
    let (r2, s2) = pair(3, 4);
    let qn = d.go(start, |c, n| c.queue_new(n, &r2, &s2));
    assert_eq!(qn, vec![V::Err(2)], "RL-15: QUEUE_NEW ERR 2");
    let put = d.put(start, &one_time(&[0x15; 16], EXPIRES, &owner, &blob));
    assert_eq!(
        put,
        vec![V::Err(2)],
        "RL-15: LINK_PUT ERR 2 after its third frame"
    );
    assert_eq!(d.b.digest(), before, "RL-15: no new state");
    let same = d.go(start, |c, n| c.queue_new(n, &r, &s));
    assert_eq!(
        same,
        vec![V::QueueNew(rid_of(&r.pk), sid_of(&r.pk, &s.pk))],
        "RL-15 (C-10) rl15_drain_identical_queue_new_answers_ok: an identical QUEUE_NEW answers OK_QUEUE_NEW"
    );
    assert_eq!(
        d.b.digest(),
        before,
        "RL-15 (C-10) rl15_drain_identical_queue_new_answers_ok: store unchanged"
    );
    let bad_token = d.go(start, |c, n| {
        let token: [u8; 32] = flip(&c.token(n), 0).try_into().unwrap();
        let sig = r.sign(&msg_queue_new(&c.sess_id(), n, &r, &s, &token));
        queue_new_req(n, &r, &s, token, sig)
    });
    assert_eq!(
        bad_token,
        vec![V::Err(1)],
        "RL-15 (C-10) rl15_drain_identical_queue_new_answers_ok: the identical QUEUE_NEW with a bad token is ERR 1"
    );
    assert_eq!(
        d.b.digest(),
        before,
        "RL-15 (C-10) rl15_drain_identical_queue_new_answers_ok: bad token, store unchanged"
    );
    let sent = d.go(start, |c, n| c.send(n, &r, &s, &[2; CELL]));
    assert_eq!(sent, vec![V::Send(2, None)], "RL-15: SEND served");
    let fetched = d.go(start, |c, n| c.fetch(n, &r, 0));
    assert_eq!(
        presents(&fetched),
        vec![(1, 1), (1, 2), (0, 0), (0, 0)],
        "RL-15: FETCH served"
    );
    assert_eq!(
        d.go(start, |_, n| Client::ping(n)),
        vec![V::Ok],
        "RL-15: PING served"
    );
    assert!(
        Connection::accept(&d.b.relay, start).is_none(),
        "RL-15: a new connection is refused"
    );
    assert!(
        !d.b.relay.accepts_connections(),
        "RL-15: the listener refuses"
    );
    d.b.relay.start_drain(at(0, 30_000));
    assert!(
        !d.b.relay.drain_finished(at(0, 60_999)),
        "RL-15: still draining before drain_secs"
    );
    assert!(
        d.b.relay.drain_finished(at(0, 61_000)),
        "RL-15: finished drain_secs after the (first) start"
    );
}

/// A client pinned to the relay's `relay_fp` completes the handshake through a connection at `t` and is served a
/// PING (its `RELAYINFO` verifies: signature, `relay_fp`, validity, `akc`); returns `valid_until − now`.
fn accepted(relay: &Relay, t: Now) -> u64 {
    let (_, rec) = hello(relay, t, &mut OsEntropy);
    let info = RelayInfoRecord::decode(&rec).unwrap().relay_info;
    let (fp, access) = identity(relay);
    let mut w = Wire::connect(relay, fp, &access, t, &mut OsEntropy, &mut OsEntropy);
    assert_eq!(w.go(t, &mut OsEntropy, |_, s| Client::ping(s)), vec![V::Ok]);
    info.valid_until.checked_sub(t.unix_secs).unwrap()
}

/// RL-16 `relay_keygen_then_load_same_identity`: a key file written by `keygen` loads to the same identity —
/// `relay_sig_pk`, `relay_fp`, kid 1 and its static keys (the `RELAYINFO` bytes are equal) —, its `RELAYINFO`
/// verifies at a client, and `valid_until − now` ≤ 5 184 000 (exactly 60 days accepted, more refused); the
/// `secmp-relay keygen` command does the same (spec §8.2 `:532`, `:539`; OPEN-4; `docs/05` §6).
#[test]
fn relay_keygen_then_load_same_identity() {
    let dir = fresh_dir("rl16");
    let path = dir.join("relay-keys");
    let generated = KeyFile::generate(NOW, DEFAULT_VALIDITY_SECS).unwrap();
    generated.write_new(&path).unwrap();
    assert!(
        generated.write_new(&path).is_err(),
        "RL-16: keygen never overwrites"
    );
    let loaded = KeyFile::read(&path).unwrap();
    assert_eq!(
        loaded.encode().unwrap().as_slice(),
        generated.encode().unwrap().as_slice(),
        "RL-16: the same secrets"
    );
    let (g, l) = (generated.ring().unwrap(), loaded.ring().unwrap());
    let ((gk, gu), (lk, lu)) = (g.newest().unwrap(), l.newest().unwrap());
    assert_eq!(
        gk.sig_pk().as_bytes(),
        lk.sig_pk().as_bytes(),
        "RL-16: relay_sig_pk"
    );
    assert_eq!(gk.fp(), lk.fp(), "RL-16: relay_fp");
    assert_eq!(
        (gk.kid(), l.kids(), gu),
        (1, vec![1], lu),
        "RL-16: kid 1, its validity"
    );
    assert_eq!(
        gk.relay_info_record(gu).unwrap(),
        lk.relay_info_record(lu).unwrap(),
        "RL-16: the same static keys, akc and signature"
    );
    let relay = Relay::new(l, Limits::vectors(), Box::new(NullSink), now());
    assert_eq!(
        accepted(&relay, now()),
        DEFAULT_VALIDITY_SECS,
        "RL-16: 45 days"
    );
    let max = KeyFile::generate(NOW, MAX_VALIDITY_SECS)
        .unwrap()
        .ring()
        .unwrap();
    let relay = Relay::new(max, Limits::vectors(), Box::new(NullSink), now());
    assert_eq!(
        accepted(&relay, now()),
        5_184_000,
        "RL-16: exactly 60 days is accepted"
    );
    assert!(
        KeyFile::generate(NOW, add(MAX_VALIDITY_SECS, 1)).is_err(),
        "RL-16: not beyond 60 days"
    );
    cli_keygen(&dir);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `secmp-relay keygen --out <file>` (wall clock): prints the `relay_fp` of the file it wrote, which loads and serves.
fn cli_keygen(dir: &Path) {
    let path = dir.join("cli-keys");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_secmp-relay"))
        .arg("keygen")
        .arg("--out")
        .arg(&path)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "RL-16: secmp-relay keygen succeeds");
    let ring = KeyFile::read(&path).unwrap().ring().unwrap();
    let fp = ring.newest().unwrap().0.fp();
    let printed = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        printed,
        format!("relay_fp {}\n", hex(&fp)),
        "RL-16: keygen prints relay_fp"
    );
    let relay = Relay::new(ring, Limits::vectors(), Box::new(NullSink), now());
    let ahead = accepted(&relay, wall(wall_clock_unix_secs()));
    assert!(
        ahead <= DEFAULT_VALIDITY_SECS,
        "RL-16: valid_until − now ≤ the 45-day default"
    );
}

/// RL-17 `relay_rotate_static_overlap`: `rotate-static` adds generation kid + 1 and keeps `relay_sig`; `RELAYINFO`
/// announces the new kid; an `HS1` naming the old kid is accepted through its `valid_until` and torn down after it
/// (nothing emitted, no draw); the next rotation drops the old generation (spec §8.2 `:539`; OPEN-M5-10 A).
#[test]
fn relay_rotate_static_overlap() {
    let old_validity = 864_000; // 10 days
    let until1 = add(NOW, old_validity);
    let rotated_at = add(NOW, 3600);
    let mut f = KeyFile::generate(NOW, old_validity).unwrap();
    let fp = f.ring().unwrap().newest().unwrap().0.fp();
    assert_eq!(
        f.rotate(rotated_at, DEFAULT_VALIDITY_SECS).unwrap(),
        2,
        "RL-17: kid + 1"
    );
    let ring = f.ring().unwrap();
    assert_eq!(ring.kids(), vec![1, 2], "RL-17: both generations held");
    let (newest, until2) = ring.newest().unwrap();
    assert_eq!(until2, add(rotated_at, DEFAULT_VALIDITY_SECS));
    assert_eq!(newest.fp(), fp, "RL-17: relay_fp is stable");
    assert!(
        ring.usable(1, until1) && !ring.usable(1, add(until1, 1)),
        "RL-17: kid 1 through until1"
    );
    let old_info = ring
        .ring()
        .first()
        .unwrap()
        .relay_info_record(until1)
        .unwrap();
    let access = copy_key(newest.access_key());
    let relay = Relay::new(
        ring,
        Limits::vectors(),
        Box::new(NullSink),
        wall(rotated_at),
    );
    let (_, rec) = hello(&relay, wall(rotated_at), &mut OsEntropy);
    let info = RelayInfoRecord::decode(&rec).unwrap().relay_info;
    assert_eq!(
        (info.kid, info.valid_until),
        (2, until2),
        "RL-17: RELAYINFO announces kid 2"
    );
    let old = OldKid {
        relay: &relay,
        info: &old_info,
        fp,
        access: &access,
        client_now: until1,
    };
    assert!(
        old.hs1(wall(rotated_at)),
        "RL-17: HS1 of kid 1 accepted during the overlap"
    );
    assert!(
        old.hs1(wall(until1)),
        "RL-17: HS1 of kid 1 accepted at its valid_until"
    );
    assert!(
        !old.hs1(wall(add(until1, 1))),
        "RL-17: HS1 of kid 1 torn down after its valid_until"
    );
    let after = wall(add(until1, 1));
    let mut w = Wire::connect(&relay, fp, &access, after, &mut OsEntropy, &mut OsEntropy);
    assert_eq!(
        w.go(after, &mut OsEntropy, |_, s| Client::ping(s)),
        vec![V::Ok],
        "RL-17: kid 2 serves"
    );
    assert_eq!(f.rotate(add(until1, 1), DEFAULT_VALIDITY_SECS).unwrap(), 3);
    assert_eq!(
        f.ring().unwrap().kids(),
        vec![2, 3],
        "RL-17: kid 1 dropped after its valid_until"
    );
}

/// A client that holds the old generation's `RELAYINFO` (read at `client_now`).
struct OldKid<'a> {
    relay: &'a Relay,
    info: &'a [u8],
    fp: [u8; 32],
    access: &'a AccessKey,
    client_now: u64,
}

impl OldKid<'_> {
    /// An `HS1` naming the old kid on a new connection at `t`: whether the link is established and serves a PING;
    /// a refusal must be a teardown that emits nothing and draws nothing.
    fn hs1(&self, t: Now) -> bool {
        let (mut conn, _) = hello(self.relay, t, &mut OsEntropy);
        let (_, st) = client::start(self.fp, Some(self.access), self.client_now).unwrap();
        let (hs1, wait) = st.on_relayinfo(self.info, &mut OsEntropy).unwrap();
        assert_eq!(Hs1::decode(&hs1).unwrap().kid, 1, "the HS1 names kid 1");
        let mut e = lots();
        let left = e.remaining();
        let out = conn.on_bytes(&hs1, t, &mut e);
        if out.close {
            assert_eq!(out, closed(), "a teardown emits nothing");
            assert_eq!(e.remaining(), left, "a teardown draws nothing");
            return false;
        }
        let mut client = Client::new(wait.on_hs2(&out.bytes).unwrap(), copy_key(self.access));
        let ping = client.seal(&Client::ping(1));
        let out = conn.on_bytes(&ping, t, &mut e);
        assert_eq!(
            view(&client.open(&out.bytes, CellrContext::Fetch)),
            (1, V::Ok)
        );
        true
    }
}

/// RL-19 `relay_akc_matches_access_key`: the `akc` of `RELAYINFO` is SHA-256("SecMP-Q/1 akc" ‖ access key) of the
/// configured access key — for the suite's relay (= `link-0001`'s `akc`) and for a generated key file — and
/// another access key gives another `akc` (spec §8.2, §5.3, §9.6).
#[test]
fn relay_akc_matches_access_key() {
    let akc_of = |relay: &Relay| {
        let (_, rec) = hello(relay, now(), &mut OsEntropy);
        RelayInfoRecord::decode(&rec).unwrap().relay_info.akc
    };
    let fx = RelayFx::case1();
    let suite = akc_of(&fx.relay(Limits::vectors()));
    let expected = sha256(&[b"SecMP-Q/1 akc".as_slice(), fx.access_key.as_slice()]);
    assert_eq!(suite, expected, "RL-19: akc of the configured access key");
    assert_eq!(
        suite.to_vec(),
        reference().case(1).output("akc"),
        "RL-19: = link-0001 akc"
    );
    let dir = fresh_dir("rl19");
    let path = key_file(&dir, DEFAULT_VALIDITY_SECS);
    let relay = load(&path, Limits::vectors(), now());
    let (_, access) = identity(&relay);
    let generated = akc_of(&relay);
    let from_file = sha256(&[
        b"SecMP-Q/1 akc".as_slice(),
        access.expose_secret().as_slice(),
    ]);
    assert_eq!(
        generated, from_file,
        "RL-19: akc of a generated key file's access key"
    );
    assert_ne!(generated, suite, "RL-19: another access key, another akc");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The relay's draws, front to back, and the position the test expects them at.
struct Tape {
    bytes: Vec<u8>,
    at: usize,
    e: FixedEntropy,
}

impl Tape {
    fn new(n: usize) -> Self {
        let bytes = distinct_bytes(0xd0, n);
        Self {
            e: FixedEntropy::new(&bytes),
            bytes,
            at: 0,
        }
    }

    /// The next `n` bytes the relay must draw.
    fn next(&mut self, n: usize) -> Vec<u8> {
        let end = self.at.checked_add(n).unwrap();
        let v = self.bytes.get(self.at..end).unwrap().to_vec();
        self.at = end;
        v
    }

    /// The next `k` cells.
    fn cells(&mut self, k: usize) -> Vec<Vec<u8>> {
        (0..k).map(|_| self.next(CELL)).collect()
    }

    /// Exactly the expected draws happened.
    fn check(&self, what: &str) {
        let left = self.bytes.len().checked_sub(self.at).unwrap();
        assert_eq!(
            self.e.remaining(),
            left,
            "RL-20: {what}: exactly these draws"
        );
    }
}

/// RL-20 `relay_dummies_are_fresh_randomness`: every dummy is fresh randomness — two FETCH answers with dummies and two
/// absent `LINK_GET`s give different dummies — drawn in response-frame order per reading R5-7 (an error frame's cell
/// before the dummies; `FETCH_MULTI` one cell per error frame in request order, then the dummies; a consume-mode
/// `LINK_GET` draws only when it returns no blob, owner status always) (spec §9.3 `:605`, `:609`).
#[test]
fn relay_dummies_are_fresh_randomness() {
    let mut d = Drive::new(Limits::vectors());
    let (r, sender) = pair(1, 2);
    let (ghost_a, ghost_b) = (Key::of(8), Key::of(9));
    d.go(now(), |c, n| c.queue_new(n, &r, &sender));
    let mut tape = Tape::new(200_000);
    let first = cells(&d.go_with(now(), &mut tape.e, |c, n| c.fetch(n, &r, 0)));
    assert_eq!(first, tape.cells(4), "RL-20: FETCH dummies in frame order");
    let second = cells(&d.go_with(now(), &mut tape.e, |c, n| c.fetch(n, &r, 0)));
    assert_eq!(second, tape.cells(4), "RL-20: the second FETCH draws anew");
    let mut all: Vec<&Vec<u8>> = first.iter().chain(&second).collect();
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 8, "RL-20: the dummies of two FETCHes differ");
    let err = d.go_with(now(), &mut tape.e, |c, n| c.fetch(n, &ghost_a, 0));
    assert_eq!(presents(&err), vec![(2, 0), (0, 0), (0, 0), (0, 0)]);
    assert_eq!(
        cells(&err),
        tape.cells(4),
        "RL-20: the error frame's cell first, then the dummies"
    );
    let stored = vec![0x42; CELL];
    d.go_with(now(), &mut tape.e, |c, n| c.send(n, &r, &sender, &stored));
    tape.check("SEND");
    let one = d.go_with(now(), &mut tape.e, |c, n| c.fetch(n, &r, 0));
    let want: Vec<Vec<u8>> = [vec![stored], tape.cells(3)].concat();
    assert_eq!(
        cells(&one),
        want,
        "RL-20: the dummies after the stored cell"
    );
    let multi = d.go_with(now(), &mut tape.e, |c, n| {
        let entries = vec![
            c.fetch_entry(n, &ghost_a, 0),
            c.fetch_entry(n, &r, 1),
            c.fetch_entry(n, &ghost_b, 0),
        ];
        Client::fetch_multi(n, entries)
    });
    let errors = [(2, rid_of(&ghost_a.pk)), (2, rid_of(&ghost_b.pk))];
    assert!(
        multi
            .iter()
            .zip(errors)
            .all(|(v, (p, rid))| matches!(v, V::Cellr(q, x, 0, _) if *q == p && *x == rid))
    );
    assert_eq!(
        cells(&multi),
        tape.cells(8),
        "RL-20: FETCH_MULTI: the error cells, then the dummies"
    );
    dummy_blobs(&mut d, &mut tape);
    tape.check("all");
    fresh_from_the_os(&mut d, &r);
}

/// RL-20, `LINK_GET`: two absent ones give two fresh dummy blobs; a consume that returns the blob draws nothing;
/// owner status draws a dummy blob also for a present entry.
fn dummy_blobs(d: &mut Drive, tape: &mut Tape) {
    let (owner, blob) = (Key::of(3), distinct_bytes(0x20, BLOB));
    let absent = [0x2a; 16];
    let x = linkr(&d.go_with(now(), &mut tape.e, |_, n| {
        Client::link_get_consume(n, &absent)
    }));
    assert_eq!(
        x,
        (false, false, tape.next(BLOB)),
        "RL-20: a dummy blob of 12360 drawn bytes"
    );
    let y = linkr(&d.go_with(now(), &mut tape.e, |_, n| {
        Client::link_get_consume(n, &absent)
    }));
    assert_eq!(
        y,
        (false, false, tape.next(BLOB)),
        "RL-20: the second absent LINK_GET draws anew"
    );
    assert_ne!(x.2, y.2, "RL-20: the dummy blobs differ");
    let ld_id = [0x2b; 16];
    assert_eq!(
        d.put(now(), &one_time(&ld_id, EXPIRES, &owner, &blob)),
        vec![V::Ok]
    );
    let status = linkr(&d.go_with(now(), &mut tape.e, |c, n| {
        c.link_get_owner(n, &ld_id, &owner)
    }));
    assert_eq!(
        status,
        (true, false, tape.next(BLOB)),
        "RL-20: owner status draws a dummy blob"
    );
    let got = linkr(&d.go_with(now(), &mut tape.e, |_, n| {
        Client::link_get_consume(n, &ld_id)
    }));
    assert_eq!(got, (true, false, blob), "RL-20: the blob itself");
    tape.check("a consume that returns the blob");
    let status = d.go_with(now(), &mut tape.e, |c, n| {
        c.link_get_owner(n, &ld_id, &owner)
    });
    assert_eq!(flags(&status), (false, true));
    assert_eq!(
        linkr(&status).2,
        tape.next(BLOB),
        "RL-20: owner status of a marker draws a dummy blob"
    );
}

/// RL-20 with the relay's production randomness (`OsEntropy`, as the server runs it): two FETCH answers with dummies
/// differ.
fn fresh_from_the_os(d: &mut Drive, r: &Key) {
    let fetch = |d: &mut Drive| {
        let seq = d.seq.bump();
        let req = d.b.client.fetch(seq, r, 0);
        let frame = d.b.client.seal(&req);
        let frames = match d.b.exec.on_unit(&d.b.relay, &frame, now(), &mut OsEntropy) {
            Outcome::Respond(frames) => Some(frames),
            Outcome::Pending | Outcome::Teardown => None,
        }
        .expect("RL-20: the FETCH is answered");
        let views: Vec<V> = frames
            .iter()
            .map(|f| view(&d.b.client.open(f.as_slice(), CellrContext::Fetch)).1)
            .collect();
        cells(&views)
    };
    let (x, y) = (fetch(d), fetch(d));
    assert_eq!((x.len(), y.len()), (4, 4), "RL-20: four frames each");
    assert!(
        x.iter().all(|c| !y.contains(c)),
        "RL-20: OS-drawn dummies differ between FETCHes"
    );
}

/// RL-22 `relay_hello_to_hs1_timeout`: a connection whose `HELLO` was answered but whose `HS1` is not complete
/// within 30 s (virtual clock) is closed with nothing emitted and no draw; the control, an `HS1` completed at 29 s,
/// establishes the link, which then outlives the bound; the same bound runs from accept to `HELLO` (spec §9.7 item
/// 7; OPEN-M5-02 values).
#[test]
fn relay_hello_to_hs1_timeout() {
    let fx = RelayFx::case1();
    let relay = fx.relay(Limits::defaults());
    assert_eq!(
        relay.limits().hello_timeout_ms,
        30_000,
        "the OPEN-M5-02 value"
    );
    let hs1 = |info: &[u8]| {
        let (_, st) = client::start(fx.relay_fp, Some(&fx.access()), NOW).unwrap();
        st.on_relayinfo(info, &mut client_entropy()).unwrap()
    };
    let mut e = lots();
    let left = e.remaining();
    let (mut conn, info) = hello(&relay, mono(0), &mut e);
    let (record, _) = hs1(&info);
    let (head, tail) = record.split_at_checked(1000).unwrap();
    assert_eq!(
        conn.on_bytes(head, mono(10_000), &mut e),
        Output::default(),
        "a partial HS1"
    );
    assert_eq!(
        conn.on_tick(mono(29_999)),
        Output::default(),
        "RL-22: waiting before 30 s"
    );
    assert_eq!(
        conn.on_tick(mono(30_000)),
        closed(),
        "RL-22: no complete HS1 within 30 s: closed"
    );
    assert_eq!(
        conn.on_bytes(tail, mono(30_000), &mut e),
        closed(),
        "RL-22: nothing emitted"
    );
    let (mut conn, info) = hello(&relay, mono(100_000), &mut e);
    let (record, _) = hs1(&info);
    assert_eq!(
        conn.on_bytes(&record, mono(130_000), &mut e),
        closed(),
        "RL-22: HS1 at 30 s is late"
    );
    assert_eq!(e.remaining(), left, "RL-22: no draw");
    // control: HS1 complete at 29 s
    let (mut conn, info) = hello(&relay, mono(200_000), &mut e);
    let (record, wait) = hs1(&info);
    let (head, tail) = record.split_at_checked(2000).unwrap();
    assert_eq!(
        conn.on_bytes(head, mono(210_000), &mut e),
        Output::default()
    );
    let out = conn.on_bytes(tail, mono(229_000), &mut relay_hs_entropy());
    assert!(
        !out.close,
        "RL-22: control: HS1 complete at 29 s is answered"
    );
    let mut client = Client::new(wait.on_hs2(&out.bytes).unwrap(), fx.access());
    let ping = client.seal(&Client::ping(1));
    let out = conn.on_bytes(&ping, mono(300_000), &mut e);
    let answer = view(&client.open(&out.bytes, CellrContext::Fetch));
    assert_eq!(
        answer,
        (1, V::Ok),
        "RL-22: control: the link outlives the bound"
    );
    let mut quiet = Connection::accept(&relay, mono(400_000)).unwrap();
    assert_eq!(quiet.on_tick(mono(429_999)), Output::default());
    assert_eq!(
        quiet.on_tick(mono(430_000)),
        closed(),
        "RL-22: no HELLO within 30 s: closed"
    );
}

/// A request frame plaintext of F-11: raw payload bytes, or a request.
enum Unit<'a> {
    Raw(Vec<u8>),
    Req(&'a Request),
}

/// F-11 `relay_unknown_request_opcode_tears_down`: request opcodes 0x0A (F12), 0x00, 0x80 and 0xFF, and 0x7F
/// (`CONT`) with no `LINK_PUT` pending (F10), tear the link down — nothing emitted; the frame counters, the
/// recorded `cmd_seq`, the store and the draws unchanged —, while the control 0x02 (`SKEY`) is answered with one
/// ERR 6 (E21) and its `cmd_seq` recorded (D.2 `:816-828`; spec §8.5; OPEN-6).
#[test]
fn relay_unknown_request_opcode_tears_down() {
    let (owner, blob) = (Key::of(5), distinct_bytes(0xf1, BLOB));
    let [_, cont1, cont2] = Bench::vectors()
        .client
        .link_put(7, &one_time(&[0xf1; 16], EXPIRES, &owner, &blob));
    let raw = |op: u8, fields: &[u8]| Unit::Raw([&[op, 0, 0, 0, 7][..], fields].concat());
    let cases = [
        ("0x0A", raw(0x0a, &[])),
        ("0x0A with fields", raw(0x0a, &[0x55; 100])),
        ("0x00", raw(0x00, &[])),
        ("0x80", raw(0x80, &[])),
        ("0xFF", raw(0xff, &[])),
        ("0x7F idx 1, nothing pending", Unit::Req(&cont1)),
        ("0x7F idx 2, nothing pending", Unit::Req(&cont2)),
    ];
    for (name, unit) in cases {
        let mut b = Bench::vectors();
        assert!(
            matches!(b.go(&Client::ping(1)).frames().as_slice(), [_]),
            "a link with history"
        );
        let (post, digest, mut e) = (b.link_post(), b.digest(), lots());
        let left = e.remaining();
        let frame = match unit {
            Unit::Raw(p) => b.client.seal_payload(&p),
            Unit::Req(r) => b.client.seal(r),
        };
        assert!(
            matches!(b.unit(&frame, now(), &mut e), Outcome::Teardown),
            "F-11: {name}: teardown"
        );
        assert_eq!(
            b.link_post(),
            post,
            "F-11: {name}: counters and cmd_seq unchanged"
        );
        assert_eq!(
            (b.digest(), e.remaining()),
            (digest, left),
            "F-11: {name}: store and draws unchanged"
        );
    }
    let mut b = Bench::vectors();
    let frame = b.client.seal_payload(&[0x02, 0, 0, 0, 9]);
    let frames = match b.unit(&frame, now(), &mut lots()) {
        Outcome::Respond(frames) => Some(frames),
        Outcome::Pending | Outcome::Teardown => None,
    }
    .expect("F-11: the control SKEY is answered");
    let views: Vec<(u32, V)> = frames
        .iter()
        .map(|f| view(&b.client.open(f.as_slice(), CellrContext::Fetch)))
        .collect();
    assert_eq!(views, vec![(9, V::Err(6))], "F-11: control SKEY: one ERR 6");
    assert_eq!(b.link_post(), (1, 1, 9), "F-11: SKEY's cmd_seq is recorded");
}
