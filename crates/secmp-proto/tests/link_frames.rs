// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! F-01…F-10, F-12 and P-01…P-05: frames (spec §8.4), the response decoder and the properties (TEST-SPEC-M5 (b); `docs/reviews/M05-planning/TEST-SPEC-M5.md`).

#[path = "link/fixture.rs"]
mod fixture;

use fixture::{NOW, VALID_UNTIL, at, client_draws, flip, honest_links, reference, relay_draws};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use secmp_crypto::{
    Aead, Ed25519SigningKey, Label, MlKem1024Dk, Nonce24, SecretBytes, X25519Secret, sha256,
};
use secmp_proto::codec::pad;
use secmp_proto::keys::Ed25519Pk;
use secmp_proto::link::relay::RelayKeys;
use secmp_proto::link::{self, Error, LINK_MAX_FRAMES, Link, ids};
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::frame::CellrContext;

const FRAME: usize = 4352;
const PLAIN: usize = 4336;

fn kb(k: &[u8; 32]) -> SecretBytes<32> {
    SecretBytes::from_slice(k).unwrap()
}

/// The independent frame of spec §8.4 over an already padded plaintext.
fn indep_seal_padded(key: &[u8; 32], ctr: u64, sess_id: &[u8], padded: &[u8]) -> Vec<u8> {
    let nonce = [&[0_u8; 16][..], &ctr.to_be_bytes()].concat();
    let nonce: [u8; 24] = nonce.try_into().unwrap();
    let ad = [Label::LinkFrame.as_bytes(), sess_id].concat();
    Aead::seal(&kb(key), Nonce24::from_bytes_kat(nonce), &ad, padded).unwrap()
}

fn indep_seal(key: &[u8; 32], ctr: u64, sess_id: &[u8], payload: &[u8]) -> Vec<u8> {
    let padded = pad(payload, PLAIN).unwrap();
    indep_seal_padded(key, ctr, sess_id, &padded)
}

fn pattern(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap().wrapping_add(salt))
        .collect()
}

/// `(sender, receiver)` of direction `d`: 0 = client to relay, 1 = relay to client.
fn directed(d: usize) -> (Link, Link) {
    let (c, r) = honest_links();
    if d == 0 { (c, r) } else { (r, c) }
}

fn rejected<T>(r: Result<T, Error>) -> bool {
    r.err() == Some(Error::Rejected)
}

#[test]
fn link_frame_seal_matches_independent_aead() {
    for d in 0..2 {
        for len in [0_usize, 5, 4314, 4335] {
            let (mut tx, mut rx) = directed(d);
            let key = *tx.keys_kat().0;
            let sess = *tx.sess_id();
            for ctr in 0_u64..2 {
                let payload = pattern(len, u8::try_from(ctr).unwrap());
                let frame = tx.seal(&payload).unwrap();
                assert_eq!(frame.len(), FRAME);
                assert_eq!(
                    frame.as_slice(),
                    indep_seal(&key, ctr, &sess, &payload).as_slice(),
                    "d {d} len {len} ctr {ctr}"
                );
                let opened = rx.open(frame.as_slice()).unwrap();
                assert_eq!(opened.payload(), payload.as_slice());
                assert_eq!(opened.counter(), ctr);
            }
        }
    }
}

#[test]
fn link_frame_unit_length_rejected_before_aead() {
    for d in 0..2 {
        let (mut tx, mut rx) = directed(d);
        let good = tx.seal(b"x").unwrap();
        for len in [0_usize, 1, 4335, 4351, 4353, 8704] {
            let unit = vec![0_u8; len];
            assert!(rejected(rx.open(&unit)), "d {d} len {len}");
            assert!(rejected(rx.open_unit(&unit)));
            assert_eq!(rx.aead_open_attempts_kat(), 0, "d {d} len {len}");
            assert_eq!(rx.recv_counter(), Some(0));
        }
        // a truncated and an extended honest frame
        let mut longer = good.to_vec();
        longer.push(0);
        assert!(rejected(rx.open(&longer)));
        assert!(rejected(rx.open(good.get(..4351).unwrap())));
        assert_eq!(rx.aead_open_attempts_kat(), 0);
        assert!(rx.open(good.as_slice()).is_ok());
        assert_eq!(rx.aead_open_attempts_kat(), 1);
    }
}

#[test]
fn link_frame_counter_strict_plus_one() {
    for d in 0..2 {
        let (mut tx, mut rx) = directed(d);
        let f0 = tx.seal(b"zero").unwrap();
        let f1 = tx.seal(b"one").unwrap();
        let f2 = tx.seal(b"two").unwrap();
        // skip
        assert!(rejected(rx.open(f1.as_slice())), "skip d {d}");
        assert!(rejected(rx.open(f2.as_slice())));
        assert_eq!(rx.recv_counter(), Some(0));
        assert_eq!(rx.open(f0.as_slice()).unwrap().payload(), b"zero");
        // replay
        assert!(rejected(rx.open(f0.as_slice())), "replay d {d}");
        assert_eq!(rx.recv_counter(), Some(1));
        assert_eq!(rx.open(f1.as_slice()).unwrap().payload(), b"one");
        assert!(rejected(rx.open(f1.as_slice())));
        assert!(rejected(rx.open(f0.as_slice())));
        assert_eq!(rx.open(f2.as_slice()).unwrap().payload(), b"two");
        assert_eq!(rx.recv_counter(), Some(3));
    }
}

#[test]
fn link_frame_flip_rejects() {
    for d in 0..2 {
        for pos in [0_usize, 4335, 4336, 4351] {
            let (mut tx, mut rx) = directed(d);
            let f = tx.seal(b"flip me").unwrap();
            assert!(
                rejected(rx.open(&flip(f.as_slice(), pos))),
                "d {d} pos {pos}"
            );
            assert_eq!(rx.recv_counter(), Some(0));
            assert!(rx.open(f.as_slice()).is_ok());
        }
    }
}

#[test]
fn link_frame_direction_and_link_binding() {
    let (mut c, mut r) = honest_links();
    let (mut c_b, mut r_b) = {
        let mut rng = StdRng::seed_from_u64(master_seed() ^ 0xb);
        handshake(&mut rng)
    };
    let fc = c.seal(b"c2r").unwrap();
    let fr = r.seal(b"r2c").unwrap();
    // reflected
    assert!(rejected(c.open(fc.as_slice())));
    assert!(rejected(r.open(fr.as_slice())));
    // another link, same counter
    let fcb = c_b.seal(b"c2r").unwrap();
    let frb = r_b.seal(b"r2c").unwrap();
    assert!(rejected(r.open(fcb.as_slice())));
    assert!(rejected(c.open(frb.as_slice())));
    // AD with a flipped sess_id (otherwise honest keys and counter)
    let bad_sess = flip(c.sess_id(), 0);
    let padded = pad(b"c2r", PLAIN).unwrap();
    let ck = *c.keys_kat().0;
    let rk = *r.keys_kat().0;
    assert!(rejected(
        r.open(&indep_seal_padded(&ck, 0, &bad_sess, &padded))
    ));
    assert!(rejected(
        c.open(&indep_seal_padded(&rk, 0, &bad_sess, &padded))
    ));
    // the control: the independent frame with the right sess_id opens
    assert!(
        r.open(&indep_seal_padded(&ck, 0, c.sess_id(), &padded))
            .is_ok()
    );
    assert!(
        c.open(&indep_seal_padded(&rk, 0, c.sess_id(), &padded))
            .is_ok()
    );
    assert_eq!(r.recv_counter(), Some(1));
    assert_eq!(c.recv_counter(), Some(1));
    assert_ne!(c.sess_id(), c_b.sess_id());
}

#[test]
fn link_frame_failed_open_changes_nothing() {
    for d in 0..2_usize {
        let (mut tx, mut rx) = directed(d);
        let (mut tx_b, _rx_b) = {
            let mut rng = StdRng::seed_from_u64(master_seed() ^ 0xc ^ u64::try_from(d).unwrap());
            let (c, r) = handshake(&mut rng);
            if d == 0 { (c, r) } else { (r, c) }
        };
        let key = *tx.keys_kat().0;
        let sess = *tx.sess_id();
        let own_send_key = *rx.keys_kat().0; // the receiver's send key: a reflected frame
        let honest = tx.seal(b"honest").unwrap();
        let next = tx.seal(b"next").unwrap();
        let bad: Vec<(&str, Vec<u8>)> = vec![
            ("len 0", vec![]),
            ("len 4351", vec![0; 4351]),
            ("len 4353", vec![0; 4353]),
            ("len 8704", vec![0; 8704]),
            ("skip", next.to_vec()),
            ("flip ct", flip(honest.as_slice(), 0)),
            ("flip tag", flip(honest.as_slice(), 4351)),
            ("reflected", indep_seal(&own_send_key, 0, &sess, b"honest")),
            (
                "other sess",
                indep_seal(&key, 0, &flip(&sess, 0), b"honest"),
            ),
            ("other link", tx_b.seal(b"honest").unwrap().to_vec()),
            (
                "no 0x80",
                indep_seal_padded(&key, 0, &sess, &pattern(PLAIN, 1)),
            ),
            ("all zero", indep_seal_padded(&key, 0, &sess, &[0; PLAIN])),
        ];
        for (name, unit) in &bad {
            assert!(rejected(rx.open(unit)), "{name} d {d}");
            assert!(rejected(rx.open_unit(unit)), "{name} d {d}");
            assert!(rejected(rx.open_request(unit)), "{name} d {d}");
            assert_eq!(rx.recv_counter(), Some(0), "{name} d {d}");
            assert_eq!(tx.send_counter(), Some(2), "{name} d {d}");
        }
        assert!(rx.open(honest.as_slice()).is_ok(), "d {d}");
        assert_eq!(rx.recv_counter(), Some(1));
        assert!(rx.open(next.as_slice()).is_ok());
        assert_eq!(rx.recv_counter(), Some(2));
    }
}

#[test]
fn link_frame_padding_rules() {
    for d in 0..2 {
        let (mut tx, mut rx) = directed(d);
        let key = *tx.keys_kat().0;
        let sess = *tx.sess_id();
        // seal: 4335 ok, 4336 too long, nothing moves
        assert!(tx.seal(&pattern(4335, 3)).is_ok());
        assert_eq!(tx.send_counter(), Some(1));
        assert_eq!(
            tx.seal(&pattern(4336, 3)).err(),
            Some(Error::PayloadTooLong)
        );
        assert_eq!(tx.send_counter(), Some(1));
        // open
        let mut non_zero_after = vec![0_u8; PLAIN];
        *non_zero_after.first_mut().unwrap() = 0x01;
        *non_zero_after.get_mut(1).unwrap() = 0x80;
        *non_zero_after.last_mut().unwrap() = 0x01;
        let mut last_7f = vec![0_u8; PLAIN];
        *last_7f.last_mut().unwrap() = 0x7f;
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("no 0x80", pattern(PLAIN, 1)),
            ("non-zero after 0x80", non_zero_after),
            ("all zero", vec![0; PLAIN]),
            ("last byte 0x7f", last_7f),
        ];
        for (name, padded) in &cases {
            let unit = indep_seal_padded(&key, 0, &sess, padded);
            assert!(rejected(rx.open(&unit)), "{name} d {d}");
            assert_eq!(rx.recv_counter(), Some(0), "{name} d {d}");
        }
        // control: 0x80 alone (empty payload)
        let mut empty = vec![0_u8; PLAIN];
        *empty.first_mut().unwrap() = 0x80;
        let o = rx.open(&indep_seal_padded(&key, 0, &sess, &empty)).unwrap();
        assert!(o.payload().is_empty());
    }
}

#[test]
fn link_frame_counter_overflow_aborts() {
    // sealing at u64::MAX: the relay end has no LINK_MAX_FRAMES check
    let (mut c, mut r) = honest_links();
    r.set_send_counter_kat(u64::MAX);
    c.set_recv_counter_kat(u64::MAX);
    let f = r.seal(b"last").unwrap();
    assert_eq!(r.send_counter(), None);
    assert_eq!(r.seal(b"more").err(), Some(Error::CounterOverflow));
    assert_eq!(r.send_counter(), None);
    assert_eq!(c.open(f.as_slice()).unwrap().payload(), b"last");
    assert_eq!(c.recv_counter(), None);
    let before = c.aead_open_attempts_kat();
    assert_eq!(c.open(&[0_u8; FRAME]).err(), Some(Error::CounterOverflow));
    assert_eq!(
        c.open_response(&[0_u8; FRAME], CellrContext::Fetch).err(),
        Some(Error::CounterOverflow)
    );
    assert_eq!(c.aead_open_attempts_kat(), before, "nothing opened");
    // opening at u64::MAX on the relay end (c2r)
    let (c, mut r) = honest_links();
    r.set_recv_counter_kat(u64::MAX);
    let key = *c.keys_kat().0;
    let sess = *c.sess_id();
    let unit = indep_seal(&key, u64::MAX, &sess, b"c2r last");
    assert_eq!(r.open(&unit).unwrap().payload(), b"c2r last");
    assert_eq!(r.recv_counter(), None);
    let before = r.aead_open_attempts_kat();
    assert_eq!(r.open(&unit).err(), Some(Error::CounterOverflow));
    assert_eq!(r.aead_open_attempts_kat(), before);
    // the client end at u64::MAX: refused as NewLinkRequired (LINK_MAX_FRAMES is checked first); nothing sealed
    let (mut c, _r) = honest_links();
    c.set_send_counter_kat(u64::MAX);
    assert_eq!(c.seal(b"x").err(), Some(Error::NewLinkRequired));
    assert_eq!(c.send_counter(), Some(u64::MAX));
}

#[test]
fn link_client_refuses_seal_beyond_link_max_frames() {
    assert_eq!(LINK_MAX_FRAMES, 1 << 20);
    let last = LINK_MAX_FRAMES - 1;
    // c2r
    let (mut c, mut r) = honest_links();
    c.set_send_counter_kat(last);
    r.set_recv_counter_kat(last);
    let f = c.seal(b"last c2r").unwrap();
    assert_eq!(c.send_counter(), Some(LINK_MAX_FRAMES));
    assert_eq!(c.seal(b"next").err(), Some(Error::NewLinkRequired));
    assert_eq!(c.send_counter(), Some(LINK_MAX_FRAMES));
    assert_eq!(r.open(f.as_slice()).unwrap().payload(), b"last c2r");
    // r2c
    let (mut c, mut r) = honest_links();
    r.set_send_counter_kat(last);
    c.set_recv_counter_kat(last);
    let f = r.seal(b"last r2c").unwrap();
    assert_eq!(c.open(f.as_slice()).unwrap().payload(), b"last r2c");
    assert_eq!(c.recv_counter(), Some(LINK_MAX_FRAMES));
    assert_eq!(c.seal(b"next").err(), Some(Error::NewLinkRequired));
    assert_eq!(c.send_counter(), Some(0), "nothing sealed");
    // the relay does not check
    r.set_send_counter_kat(LINK_MAX_FRAMES);
    r.set_recv_counter_kat(LINK_MAX_FRAMES);
    assert!(r.seal(b"relay does not check").is_ok());
}

/// `op ‖ cmd_seq ‖ fields` (the payload `Link::seal` pads).
fn raw(op: u8, seq: u32, fields: &[u8]) -> Vec<u8> {
    [&[op][..], &seq.to_be_bytes(), fields].concat()
}

#[test]
fn link_client_response_decode_failure_rejects() {
    let bad: Vec<(&str, Vec<u8>)> = vec![
        ("op 0x01 (request)", raw(0x01, 7, &[0; 100])),
        ("op 0x00", raw(0x00, 7, &[])),
        ("op 0x85", raw(0x85, 7, &[])),
        ("op 0x7f (request CONT)", raw(0x7f, 7, &[1; 4101])),
        ("trailing data after OK", raw(0x80, 7, &[1])),
        ("truncated OK_SEND", raw(0x82, 7, &[0; 5])),
        ("unknown ERR code", raw(0x8f, 7, &[0x7f])),
    ];
    for (name, payload) in &bad {
        let (mut c, mut r) = honest_links();
        let unit = r.seal(payload).unwrap();
        assert!(
            rejected(c.open_response(unit.as_slice(), CellrContext::Fetch)),
            "{name}"
        );
        assert_eq!(c.recv_counter(), Some(0), "{name}");
        // the link layer accepted the unit; only the decoder refused it, and nothing was consumed
        assert!(c.open_unit(unit.as_slice()).is_ok(), "{name}");
        let ok = r.seal(&raw(0x80, 9, &[])).unwrap();
        assert!(
            rejected(c.open_response(ok.as_slice(), CellrContext::Fetch)),
            "{name}: next counter"
        );
        assert_eq!(c.recv_counter(), Some(0));
        assert!(
            c.open_response(unit.as_slice(), CellrContext::Fetch)
                .is_err()
        );
    }
    // bad padding
    let (mut c, r) = honest_links();
    let key = *r.keys_kat().0;
    let sess = *r.sess_id();
    for (name, padded) in [
        ("no 0x80", pattern(PLAIN, 1)),
        ("all zero", vec![0_u8; PLAIN]),
    ] {
        let unit = indep_seal_padded(&key, 0, &sess, &padded);
        assert!(
            rejected(c.open_response(&unit, CellrContext::Fetch)),
            "{name}"
        );
        assert_eq!(c.recv_counter(), Some(0));
    }
    // the control: an OK response at counter 0 decodes
    let unit = indep_seal(&key, 0, &sess, &raw(0x80, 3, &[]));
    assert!(c.open_response(&unit, CellrContext::Fetch).is_ok());
    assert_eq!(c.recv_counter(), Some(1));
}

fn cellr(present: u8, rid: u8, cell_id: u64) -> Vec<u8> {
    let fields = [
        &[present][..],
        &[rid; 16],
        &cell_id.to_be_bytes(),
        &[0x55; 4096],
    ]
    .concat();
    raw(0x83, 5, &fields)
}

fn linkr(present: u8, consumed: u8) -> Vec<u8> {
    raw(0x84, 5, &[&[present, consumed][..], &[0x66; 4160]].concat())
}

fn resp_cont(idx: u8) -> Vec<u8> {
    raw(0xff, 5, &[&[idx][..], &[0x77; 4100]].concat())
}

fn ok_send(evicted_present: u8, evicted_id: u64) -> Vec<u8> {
    raw(
        0x82,
        5,
        &[
            &9_u64.to_be_bytes()[..],
            &[evicted_present],
            &evicted_id.to_be_bytes(),
        ]
        .concat(),
    )
}

fn open_one(payload: &[u8], ctx: CellrContext) -> Result<(), Error> {
    let (mut c, mut r) = honest_links();
    let unit = r.seal(payload).unwrap();
    let res = c.open_response(unit.as_slice(), ctx).map(|_| ());
    let expected = if res.is_ok() { Some(1) } else { Some(0) };
    assert_eq!(c.recv_counter(), expected, "counter moves only on success");
    res
}

#[test]
fn link_client_response_value_rules_reject() {
    use CellrContext::{Fetch, FetchMulti};
    let rejects: Vec<(&str, Vec<u8>, CellrContext)> = vec![
        ("OK_SEND evicted_present 0, id != 0", ok_send(0, 1), Fetch),
        ("OK_SEND evicted_present 2", ok_send(2, 0), Fetch),
        ("CELLR present 5", cellr(5, 0, 0), Fetch),
        ("CELLR present 5 (multi)", cellr(5, 1, 0), FetchMulti),
        ("CELLR present 0 with rid", cellr(0, 1, 0), Fetch),
        ("CELLR present 0 with cell_id", cellr(0, 0, 1), Fetch),
        (
            "CELLR present 0 with rid (multi)",
            cellr(0, 1, 0),
            FetchMulti,
        ),
        (
            "CELLR present 0 with cell_id (multi)",
            cellr(0, 0, 1),
            FetchMulti,
        ),
        ("CELLR FETCH present 1 with rid", cellr(1, 1, 3), Fetch),
        ("CELLR present 2 with cell_id", cellr(2, 1, 1), FetchMulti),
        ("CELLR present 3 with cell_id", cellr(3, 1, 1), FetchMulti),
        ("CELLR present 4 with cell_id", cellr(4, 1, 1), FetchMulti),
        (
            "CELLR present 2 with cell_id (fetch)",
            cellr(2, 0, 1),
            Fetch,
        ),
        ("LINKR present 2", linkr(2, 0), Fetch),
        ("LINKR consumed 2", linkr(1, 2), Fetch),
        ("CONT idx 0", resp_cont(0), Fetch),
        ("CONT idx 3", resp_cont(3), Fetch),
    ];
    for (name, payload, ctx) in &rejects {
        assert_eq!(open_one(payload, *ctx), Err(Error::Rejected), "{name}");
    }
    let accepts: Vec<(&str, Vec<u8>, CellrContext)> = vec![
        ("OK_SEND none", ok_send(0, 0), Fetch),
        ("OK_SEND some", ok_send(1, 4), Fetch),
        ("CELLR dummy", cellr(0, 0, 0), Fetch),
        ("CELLR cell fetch", cellr(1, 0, 3), Fetch),
        ("CELLR cell multi with rid", cellr(1, 1, 3), FetchMulti),
        ("CELLR error 2 with rid", cellr(2, 1, 0), FetchMulti),
        ("CELLR error 4 with rid", cellr(4, 1, 0), Fetch),
        ("LINKR 1/0", linkr(1, 0), Fetch),
        ("LINKR 0/1", linkr(0, 1), Fetch),
        ("CONT idx 1", resp_cont(1), Fetch),
        ("CONT idx 2", resp_cont(2), Fetch),
    ];
    for (name, payload, ctx) in &accepts {
        assert_eq!(open_one(payload, *ctx), Ok(()), "{name}");
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Properties (rand-based, as tr_properties.rs): SECMP_PROPTEST_SEED / SECMP_PROPTEST_CASES.

const DEFAULT_SEED: u64 = 0x5ec3_2d00_0000_0005;

fn env_number<T: core::str::FromStr>(name: &str) -> Option<T> {
    let raw = std::env::var(name).ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    Some(raw.parse().unwrap_or_else(|_| std::process::abort()))
}

fn master_seed() -> u64 {
    env_number("SECMP_PROPTEST_SEED").unwrap_or(DEFAULT_SEED)
}

fn cases(default: u32) -> u32 {
    env_number("SECMP_PROPTEST_CASES").unwrap_or(default)
}

fn rand_vec(rng: &mut StdRng, n: usize) -> Vec<u8> {
    let mut v = vec![0_u8; n];
    rng.fill(v.as_mut_slice());
    v
}

/// A complete handshake with random relay secrets, access key, kid and entropy.
fn handshake(rng: &mut StdRng) -> (Link, Link) {
    let access = rand_vec(rng, 32);
    let keys = RelayKeys::new(
        Ed25519SigningKey::from_seed(&rand_vec(rng, 32)).unwrap(),
        X25519Secret::from_bytes(&rand_vec(rng, 32)).unwrap(),
        MlKem1024Dk::from_seed(&rand_vec(rng, 64)).unwrap(),
        SecretBytes::from_slice(&access).unwrap(),
        rng.random::<u32>(),
    )
    .unwrap();
    let client_len = client_draws(reference().case(3)).len();
    let relay_len = relay_draws(reference().case(4)).len();
    let mut ent_c = FixedEntropy::new(&rand_vec(rng, client_len));
    let mut ent_r = FixedEntropy::new(&rand_vec(rng, relay_len));
    let access = SecretBytes::from_slice(&access).unwrap();
    let (hello, st) = link::client::start(keys.fp(), Some(&access), NOW).unwrap();
    let (info, st_r) = link::relay::accept(&keys)
        .on_hello(&hello, VALID_UNTIL)
        .unwrap();
    let (hs1, wait) = st.on_relayinfo(&info, &mut ent_c).unwrap();
    let (hs2, relay_link) = st_r.on_hs1(&hs1, &mut ent_r).unwrap();
    let client_link = wait.on_hs2(&hs2).unwrap();
    (client_link, relay_link)
}

#[test]
fn prop_link_handshake_agrees() {
    let seed = master_seed();
    let mut rng = StdRng::seed_from_u64(seed);
    for case in 0..cases(8) {
        let ctx = format!("SECMP_PROPTEST_SEED={seed} case {case}");
        let (c, r) = handshake(&mut rng);
        let (tc, tr) = (c.trace_kat().clone(), r.trace_kat().clone());
        assert_eq!(tc.ss1, tr.ss1, "{ctx}");
        assert_eq!(tc.ck1, tr.ck1, "{ctx}");
        assert_eq!(tc.ss2, tr.ss2, "{ctx}");
        assert_eq!(tc.ck2, tr.ck2, "{ctx}");
        assert_eq!(tc.k_c2r, tr.k_c2r, "{ctx}");
        assert_eq!(tc.k_r2c, tr.k_r2c, "{ctx}");
        assert_eq!(tc.sess_id, tr.sess_id, "{ctx}");
        assert_ne!(tc.k_c2r, tc.k_r2c, "{ctx}");
        assert_eq!(c.sess_id(), &tc.sess_id, "{ctx}");
        assert_eq!(r.sess_id(), &tr.sess_id, "{ctx}");
        assert_eq!(c.keys_kat().0, &tc.k_c2r, "{ctx}");
        assert_eq!(c.keys_kat().1, &tc.k_r2c, "{ctx}");
        assert_eq!(r.keys_kat().0, &tc.k_r2c, "{ctx}");
        assert_eq!(r.keys_kat().1, &tc.k_c2r, "{ctx}");
        // and the frame layer works end to end
        let (mut c, mut r) = (c, r);
        let f = c.seal(b"agree").unwrap();
        assert_eq!(r.open(f.as_slice()).unwrap().payload(), b"agree", "{ctx}");
        let f = r.seal(b"agree").unwrap();
        assert_eq!(c.open(f.as_slice()).unwrap().payload(), b"agree", "{ctx}");
    }
}

#[test]
fn prop_frame_roundtrip_any_payload() {
    let seed = master_seed() ^ 2;
    let mut rng = StdRng::seed_from_u64(seed);
    for case in 0..cases(24) {
        let ctx = format!("SECMP_PROPTEST_SEED={seed} case {case}");
        let len = match case {
            0 => 0,
            1 => 4335,
            _ => rng.random_range(0..=4335_usize),
        };
        let payload = rand_vec(&mut rng, len);
        let d = rng.random_range(0..2_usize);
        let (mut tx, mut rx) = directed(d);
        let (s0, r0) = (tx.send_counter().unwrap(), rx.recv_counter().unwrap());
        let f = tx.seal(&payload).unwrap();
        assert_eq!(f.len(), FRAME, "{ctx}");
        assert_eq!(tx.send_counter(), s0.checked_add(1), "{ctx}");
        let o = rx.open(f.as_slice()).unwrap();
        assert_eq!(o.payload(), payload.as_slice(), "{ctx}");
        assert_eq!(rx.recv_counter(), r0.checked_add(1), "{ctx}");
    }
}

#[test]
fn prop_frame_single_byte_flip_rejects() {
    let seed = master_seed() ^ 3;
    let mut rng = StdRng::seed_from_u64(seed);
    for case in 0..cases(60) {
        let ctx = format!("SECMP_PROPTEST_SEED={seed} case {case}");
        let d = rng.random_range(0..2_usize);
        let (mut tx, mut rx) = directed(d);
        let len = rng.random_range(0..=4335_usize);
        let payload = rand_vec(&mut rng, len);
        let f = tx.seal(&payload).unwrap();
        let pos = rng.random_range(0..FRAME);
        let mask = rng.random_range(1..=255_u8);
        let mut bad = f.to_vec();
        *bad.get_mut(pos).unwrap() ^= mask;
        assert!(rejected(rx.open(&bad)), "{ctx} pos {pos} mask {mask}");
        assert_eq!(rx.recv_counter(), Some(0), "{ctx}");
        assert_eq!(rx.open(f.as_slice()).unwrap().payload(), payload.as_slice());
    }
}

#[test]
fn prop_frame_sequence_tampering_rejects() {
    let seed = master_seed() ^ 4;
    let mut rng = StdRng::seed_from_u64(seed);
    for case in 0..cases(40) {
        let ctx = format!("SECMP_PROPTEST_SEED={seed} case {case}");
        let d = rng.random_range(0..2_usize);
        let (mut tx, mut rx) = directed(d);
        let n = rng.random_range(3..=8_usize);
        let mut frames: Vec<Vec<u8>> = Vec::new();
        for _ in 0..n {
            let len = rng.random_range(0..=64_usize);
            let p = rand_vec(&mut rng, len);
            frames.push(tx.seal(&p).unwrap().to_vec());
        }
        // i < n - 1, so every kind leaves an out-of-place unit
        let i = rng.random_range(0..n.checked_sub(1).unwrap());
        let kind = rng.random_range(0..3_u8);
        let mut delivered = frames.clone();
        match kind {
            0 => {
                delivered.remove(i);
            }
            1 => delivered.insert(i, frames.get(i).unwrap().clone()),
            _ => delivered.swap(i, i.checked_add(1).unwrap()),
        }
        let first = delivered
            .iter()
            .zip(frames.iter())
            .position(|(a, b)| a != b);
        assert!(first.is_some(), "{ctx}: no out-of-place unit");
        for (k, unit) in delivered.iter().enumerate() {
            if Some(k) == first {
                assert!(rejected(rx.open(unit)), "{ctx} kind {kind} i {i} k {k}");
                assert_eq!(rx.recv_counter(), u64::try_from(k).ok(), "{ctx}");
                break;
            }
            assert!(rx.open(unit).is_ok(), "{ctx} kind {kind} i {i} k {k}");
        }
    }
}

#[test]
fn prop_q_ids_are_derived() {
    let seed = master_seed() ^ 5;
    let mut rng = StdRng::seed_from_u64(seed);
    let pk = |rng: &mut StdRng| {
        let sk = Ed25519SigningKey::from_seed(&rand_vec(rng, 32)).unwrap();
        Ed25519Pk::from_bytes(sk.verifying_key().as_bytes()).unwrap()
    };
    for case in 0..cases(64) {
        let ctx = format!("SECMP_PROPTEST_SEED={seed} case {case}");
        let (pk_r, pk_s) = (pk(&mut rng), pk(&mut rng));
        let rid = sha256(&[b"SecMP-Q/1 rid", pk_r.as_bytes()]);
        let sid = sha256(&[b"SecMP-Q/1 sid", pk_r.as_bytes(), pk_s.as_bytes()]);
        assert_eq!(
            ids::rid(&pk_r).unwrap().as_slice(),
            at(&rid, 0, 16),
            "{ctx}"
        );
        assert_eq!(
            ids::sid(&pk_r, &pk_s).unwrap().as_slice(),
            at(&sid, 0, 16),
            "{ctx}"
        );
        assert_ne!(
            ids::sid(&pk_r, &pk_s).unwrap(),
            ids::sid(&pk_s, &pk_r).unwrap()
        );
    }
}
