// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! C-01…C-22: the client handshake (spec §8.2–§8.3) (TEST-SPEC-M5 (b); `docs/reviews/M05-planning/TEST-SPEC-M5.md`).

#[path = "link/fixture.rs"]
mod fixture;

use fixture::{
    Hs1Parts, LOW_ORDER_8, NOW, RelayFx, VALID_UNTIL, add, at, ck1_mac1, client_draws,
    client_entropy, client_hs1, flip, from, h0_of, h1, h2, honest_links, hs1_record, patch,
    reference, relay_answer, ri, unhex,
};
use secmp_crypto::{Ed25519SigningKey, Label, MlKem1024Dk, SecretBytes, X25519Secret, sha256};
use secmp_proto::link::client::AwaitHs2;
use secmp_proto::link::ids::AccessKey;
use secmp_proto::link::relay::RelayKeys;
use secmp_proto::link::{self, Error};
use secmp_proto::tr::FixedEntropy;

// ---------------------------------------------------------------------------------------------------------------
// helpers

/// The type of `client::start`: pinned fingerprint, optional access key, clock; no long-term secret.
type StartFn =
    fn([u8; 32], Option<&AccessKey>, u64) -> link::Result<(Vec<u8>, link::client::AwaitRelayInfo)>;

/// 60 days in seconds.
const SIXTY_DAYS: u64 = 5_184_000;

/// A RELAYINFO input of the client: the record, the pinned fingerprint and the client clock.
struct RiCase {
    name: String,
    rec: Vec<u8>,
    pinned: [u8; 32],
    now: u64,
}

impl RiCase {
    fn new(fx: &RelayFx, name: impl Into<String>, rec: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            rec,
            pinned: fx.relay_fp,
            now: NOW,
        }
    }
}

/// Run the client up to `on_relayinfo` with the honest draws; returns the result and the unused entropy bytes.
fn run_ri(c: &RiCase, access: Option<&AccessKey>) -> (link::Result<(Vec<u8>, AwaitHs2)>, usize) {
    let (_hello, st) = link::client::start(c.pinned, access, c.now).unwrap();
    let mut entropy = client_entropy();
    let r = st.on_relayinfo(&c.rec, &mut entropy);
    (r, entropy.remaining())
}

fn assert_ri_rejects(c: &RiCase, access: Option<&AccessKey>) {
    let (r, _left) = run_ri(c, access);
    assert!(
        matches!(r, Err(Error::Rejected)),
        "{}: RELAYINFO must be Rejected (access key held: {})",
        c.name,
        access.is_some()
    );
}

/// Rejected both without and with the (matching) access key.
fn assert_ri_rejects_both(fx: &RelayFx, c: &RiCase) {
    assert_ri_rejects(c, None);
    assert_ri_rejects(c, Some(&fx.access()));
    let _ = fx;
}

fn assert_ri_accepts(c: &RiCase, access: Option<&AccessKey>) {
    let (r, left) = run_ri(c, access);
    assert!(r.is_ok(), "{}: RELAYINFO must be accepted", c.name);
    assert_eq!(left, 0, "{}: the accepted handshake drew 160 B", c.name);
}

/// `rec_relayinfo` with `new` written at `off`, re-signed under `relay_sig`.
fn resigned_patch(fx: &RelayFx, off: usize, new: &[u8]) -> Vec<u8> {
    fx.resigned(|r| *r = patch(r, off, new))
}

/// `rec_relayinfo` with `valid_until := v`, re-signed.
fn with_valid_until(fx: &RelayFx, v: u64) -> Vec<u8> {
    resigned_patch(fx, ri::VALID_UNTIL, &v.to_be_bytes())
}

/// `rec` signed under `seed` over `prefix ‖ rec[3..1680]` (a different label or no label).
fn sign_custom(seed: &[u8], prefix: &[u8], rec: &[u8]) -> Vec<u8> {
    let msg = [prefix, at(rec, 3, 1677)].concat();
    let sig = Ed25519SigningKey::from_seed(seed).unwrap().sign(&msg);
    patch(rec, ri::SIG, &sig)
}

/// The honest HS2 record of `link-0004` for the honest client of `link-0003`.
fn honest_hs2() -> Vec<u8> {
    reference().case(4).output("rec_hs2")
}

/// The client after `HS1` (honest draws), no access key.
fn awaiting_hs2(fx: &RelayFx) -> AwaitHs2 {
    client_hs1(fx, &fx.rec_relayinfo, None).unwrap().1
}

/// Whether `on_hs2` of a fresh honest client rejects `rec` with exactly `Rejected`.
fn hs2_rejected(fx: &RelayFx, rec: &[u8]) -> bool {
    matches!(awaiting_hs2(fx).on_hs2(rec), Err(Error::Rejected))
}

/// A little-endian 256-bit value as 32 bytes: `p + delta` for `delta` in {-1, 0, 1} (`p = 2^255 - 19`).
fn p_plus(delta: i8) -> [u8; 32] {
    let mut b = [0xff_u8; 32];
    *b.last_mut().unwrap() = 0x7f;
    *b.first_mut().unwrap() = match delta {
        -1 => 0xec,
        0 => 0xed,
        _ => 0xee,
    };
    b
}

/// The low-order set of X25519 (spec §4.1 (a)): u ∈ {0, 1, p − 1, the two order-8 points}, plus u + p for u ∈ {0, 1},
/// each also with bit 255 set.
fn low_order_values() -> Vec<[u8; 32]> {
    let mut one = [0_u8; 32];
    *one.first_mut().unwrap() = 1;
    let partner: [u8; 32] =
        unhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157")
            .try_into()
            .unwrap();
    let base = [
        [0_u8; 32],
        one,
        p_plus(-1),
        LOW_ORDER_8,
        partner,
        p_plus(0),
        p_plus(1),
    ];
    let mut all = Vec::new();
    for v in base {
        all.push(v);
        let mut hi = v;
        *hi.last_mut().unwrap() |= 0x80;
        all.push(hi);
    }
    all
}

/// The 8 small-order Ed25519 encodings, y ≥ p, and a y that is not on the curve.
fn bad_ed25519_points() -> Vec<(String, Vec<u8>)> {
    let small = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    ];
    let mut out: Vec<(String, Vec<u8>)> = small
        .iter()
        .map(|h| (format!("small-order {}", &h[..8]), unhex(h)))
        .collect();
    out.push(("y = p".into(), p_plus(0).to_vec()));
    out.push((
        "y = 2^255 - 1".into(),
        [vec![0xff; 31], vec![0x7f]].concat(),
    ));
    // y = 2: x^2 = 3 / (2^2 d + 1) is a non-residue (checked offline): not on the curve
    out.push(("y = 2 (off curve)".into(), {
        let mut y = vec![0_u8; 32];
        *y.first_mut().unwrap() = 2;
        y
    }));
    out
}

/// `s + L` for a 32-byte little-endian `s` (the non-canonical `S` of an Ed25519 signature).
fn add_group_order(s: &[u8]) -> Vec<u8> {
    let l = unhex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let mut carry = 0_u16;
    let mut out = Vec::new();
    for (a, b) in s.iter().zip(l.iter()) {
        let sum = u16::from(*a)
            .checked_add(u16::from(*b))
            .unwrap()
            .checked_add(carry)
            .unwrap();
        out.push(u8::try_from(sum & 0xff).unwrap());
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "S + L < 2^256");
    out
}

// ---------------------------------------------------------------------------------------------------------------
// mutant sets (shared by the row tests and C-22)

fn c02_cases(fx: &RelayFx) -> Vec<RiCase> {
    let rec = &fx.rec_relayinfo;
    assert_eq!(rec.len(), 1744);
    let mut v: Vec<(String, Vec<u8>)> = Vec::new();
    for l in [1741_u16, 1743] {
        v.push((format!("len field {l}"), patch(rec, 0, &l.to_be_bytes())));
    }
    for t in [0x01_u8, 0x03, 0x04] {
        v.push((format!("type {t:#04x}"), patch(rec, 2, &[t])));
    }
    // body - 1 byte / body + 1 byte, with the length field consistent and inconsistent
    let short = rec.get(..1743).unwrap().to_vec();
    let long = [rec.as_slice(), &[0_u8]].concat();
    v.push((
        "body -1, len consistent".into(),
        patch(&short, 0, &1741_u16.to_be_bytes()),
    ));
    v.push(("body -1, len unchanged".into(), short));
    v.push((
        "body +1, len consistent".into(),
        patch(&long, 0, &1743_u16.to_be_bytes()),
    ));
    v.push(("body +1, len unchanged".into(), long));
    v.push(("empty".into(), Vec::new()));
    v.push(("len only".into(), rec.get(..2).unwrap().to_vec()));
    v.into_iter()
        .map(|(n, r)| RiCase::new(fx, format!("C-02 {n}"), r))
        .collect()
}

fn c03_cases(fx: &RelayFx) -> Vec<RiCase> {
    [0x00_u8, 0x02, 0xff]
        .into_iter()
        .map(|ver| {
            RiCase::new(
                fx,
                format!("C-03 ver {ver:#04x} re-signed"),
                resigned_patch(fx, ri::VER, &[ver]),
            )
        })
        .collect()
}

fn c04_cases(fx: &RelayFx) -> Vec<RiCase> {
    bad_ed25519_points()
        .into_iter()
        .map(|(n, pt)| {
            RiCase::new(
                fx,
                format!("C-04 relay_sig_pk {n}"),
                resigned_patch(fx, ri::SIG_PK, &pt),
            )
        })
        .collect()
}

fn c05_cases(fx: &RelayFx) -> Vec<RiCase> {
    let rec = &fx.rec_relayinfo;
    let sig = at(rec, ri::SIG, 64);
    let s_plus_l = add_group_order(at(sig, 32, 32));
    let mut v = vec![(
        "S := S + L".to_owned(),
        patch(rec, add(ri::SIG, 32), &s_plus_l),
    )];
    for (n, r) in [
        (
            "R := identity (small order)",
            unhex("01")
                .into_iter()
                .chain([0_u8; 31])
                .collect::<Vec<u8>>(),
        ),
        (
            "R := order-2 point",
            unhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ),
        (
            "R := order-8 point",
            unhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        ),
        ("R with y = p", p_plus(0).to_vec()),
        (
            "R with y = 2^255 - 1",
            [vec![0xff; 31], vec![0x7f]].concat(),
        ),
    ] {
        v.push((n.to_owned(), patch(rec, ri::SIG, &r)));
    }
    v.into_iter()
        .map(|(n, r)| RiCase::new(fx, format!("C-05 sig {n}"), r))
        .collect()
}

fn c06_cases(fx: &RelayFx) -> Vec<RiCase> {
    low_order_values()
        .into_iter()
        .map(|u| {
            RiCase::new(
                fx,
                format!("C-06 relay_dh_pk {}", fixture::hex(&u)),
                resigned_patch(fx, ri::DH_PK, &u),
            )
        })
        .collect()
}

fn c07_cases(fx: &RelayFx) -> Vec<RiCase> {
    vec![RiCase::new(
        fx,
        "C-07 relay_kem_ek bytes 0-2 := ff ff ff",
        resigned_patch(fx, ri::KEM_EK, &[0xff; 3]),
    )]
}

fn c08_cases(fx: &RelayFx) -> Vec<RiCase> {
    let rec = &fx.rec_relayinfo;
    let mut v = Vec::new();
    for (name, off) in [
        ("ver", ri::VER),
        ("relay_sig_pk", ri::SIG_PK),
        ("kid", ri::KID),
        ("kid last byte", add(ri::KID, 3)),
        ("relay_dh_pk", ri::DH_PK),
        ("relay_dh_pk last byte", add(ri::DH_PK, 31)),
        ("relay_kem_ek", ri::KEM_EK),
        ("relay_kem_ek last byte", add(ri::KEM_EK, 1567)),
        ("akc", ri::AKC),
        ("akc last byte", add(ri::AKC, 31)),
        ("valid_until", ri::VALID_UNTIL),
        ("valid_until last byte", add(ri::VALID_UNTIL, 7)),
    ] {
        v.push((format!("flip {name} after signing"), flip(rec, off)));
    }
    v.push((
        "sig over the 1677 bytes without the label".into(),
        sign_custom(&fx.sig_seed, &[], rec),
    ));
    v.push((
        "sig with label \"SecMP-LINK/1 relay-fp\"".into(),
        sign_custom(&fx.sig_seed, Label::LinkRelayFp.as_bytes(), rec),
    ));
    v.push(("flip sig byte 32 (I1)".into(), flip(rec, add(ri::SIG, 32))));
    v.push(("flip sig byte 0".into(), flip(rec, ri::SIG)));
    v.push(("flip sig byte 63".into(), flip(rec, add(ri::SIG, 63))));
    v.into_iter()
        .map(|(n, r)| RiCase::new(fx, format!("C-08 {n}"), r))
        .collect()
}

/// A RELAYINFO validly signed by another `relay_sig` key (valid under its own fingerprint).
fn other_relay_record(fx: &RelayFx) -> (Vec<u8>, [u8; 32]) {
    let seed = [0x07_u8; 32];
    let pk = Ed25519SigningKey::from_seed(&seed)
        .unwrap()
        .verifying_key()
        .as_bytes()
        .to_vec();
    let body = patch(&fx.rec_relayinfo, ri::SIG_PK, &pk);
    let rec = sign_custom(&seed, Label::LinkRelayinfo.as_bytes(), &body);
    let fp = sha256(&[Label::LinkRelayFp.as_bytes(), &pk]);
    (rec, fp)
}

fn c09_cases(fx: &RelayFx) -> Vec<RiCase> {
    let mut flipped = RiCase::new(fx, "C-09 pinned fp flipped (I2)", fx.rec_relayinfo.clone());
    flipped.pinned = flip(&fx.relay_fp, 0).try_into().unwrap();
    let (other, _fp) = other_relay_record(fx);
    vec![
        flipped,
        RiCase::new(
            fx,
            "C-09 RelayInfo validly signed by another relay_sig",
            other,
        ),
    ]
}

/// `(case, accepted)` for the validity boundaries of C-10.
fn c10_table(fx: &RelayFx) -> Vec<(RiCase, bool)> {
    let days61 = NOW.checked_add(61 * 86_400).unwrap();
    [
        ("valid_until = now", NOW, true),
        (
            "valid_until = now - 1 (I3)",
            NOW.checked_sub(1).unwrap(),
            false,
        ),
        (
            "valid_until = now + 5 184 000 (I8)",
            NOW.checked_add(SIXTY_DAYS).unwrap(),
            true,
        ),
        (
            "valid_until = now + 5 184 001",
            NOW.checked_add(SIXTY_DAYS + 1).unwrap(),
            false,
        ),
        ("valid_until = now + 61 d (I7)", days61, false),
        ("valid_until = u64::MAX", u64::MAX, false),
    ]
    .into_iter()
    .map(|(n, v, ok)| {
        (
            RiCase::new(fx, format!("C-10 {n}"), with_valid_until(fx, v)),
            ok,
        )
    })
    .collect()
}

/// `akc` of the honest record replaced by `akc`, re-signed.
fn with_akc(fx: &RelayFx, akc: &[u8]) -> Vec<u8> {
    resigned_patch(fx, ri::AKC, akc)
}

fn c11_reject_cases(fx: &RelayFx) -> Vec<RiCase> {
    let akc = fx.akc;
    let mut v = vec![
        ("flip akc byte 0", with_akc(fx, &flip(&akc, 0))),
        ("flip akc byte 31", with_akc(fx, &flip(&akc, 31))),
        (
            "akc of another key",
            with_akc(fx, &sha256(&[Label::QAkc.as_bytes(), &[0x55_u8; 32]])),
        ),
        ("akc := zeros", with_akc(fx, &[0_u8; 32])),
    ];
    // the file's I4
    v.push((
        "I4 (link-0055)",
        reference().case(55).input("rec_relayinfo"),
    ));
    v.into_iter()
        .map(|(n, r)| RiCase::new(fx, format!("C-11 {n}"), r))
        .collect()
}

fn c17_cases() -> Vec<(String, Vec<u8>)> {
    let rec = honest_hs2();
    [0_usize, 15, 31]
        .into_iter()
        .map(|i| {
            (
                format!("C-17 flip mac2 byte {i}"),
                flip(&rec, add(h2::MAC2, i)),
            )
        })
        .collect()
}

fn c18_cases() -> Vec<(String, Vec<u8>)> {
    let rec = honest_hs2();
    let mut base_point = [0_u8; 32];
    *base_point.first_mut().unwrap() = 9;
    vec![
        (
            "C-18 e_r := X25519 base point (another valid point)".to_owned(),
            patch(&rec, h2::E_R, &base_point),
        ),
        ("C-18 flip e_r byte 0".to_owned(), flip(&rec, h2::E_R)),
        (
            "C-18 flip ct_c byte 0 (T2)".to_owned(),
            flip(&rec, h2::CT_C),
        ),
        (
            "C-18 flip ct_c byte 1087".to_owned(),
            flip(&rec, add(h2::CT_C, 1087)),
        ),
    ]
}

fn c19_cases() -> Vec<(String, Vec<u8>)> {
    let rec = honest_hs2();
    low_order_values()
        .into_iter()
        .map(|u| {
            (
                format!("C-19 e_r {}", fixture::hex(&u)),
                patch(&rec, h2::E_R, &u),
            )
        })
        .collect()
}

fn c20_cases() -> Vec<(String, Vec<u8>)> {
    let rec = honest_hs2();
    assert_eq!(rec.len(), 1156);
    let mut v: Vec<(String, Vec<u8>)> = Vec::new();
    for l in [1153_u16, 1155] {
        v.push((
            format!("C-20 len field {l}"),
            patch(&rec, 0, &l.to_be_bytes()),
        ));
    }
    for t in [0x01_u8, 0x03, 0x05] {
        v.push((format!("C-20 type {t:#04x}"), patch(&rec, 2, &[t])));
    }
    v.push(("C-20 ver 0x02 (T4)".to_owned(), patch(&rec, h2::VER, &[2])));
    v.push(("C-20 ver 0x00".to_owned(), patch(&rec, h2::VER, &[0])));
    let short = rec.get(..1155).unwrap().to_vec();
    let long = [rec.as_slice(), &[0_u8]].concat();
    v.push((
        "C-20 body -1, len consistent".to_owned(),
        patch(&short, 0, &1153_u16.to_be_bytes()),
    ));
    v.push(("C-20 body -1, len unchanged".to_owned(), short));
    v.push((
        "C-20 body +1, len consistent".to_owned(),
        patch(&long, 0, &1155_u16.to_be_bytes()),
    ));
    v.push(("C-20 body +1, len unchanged".to_owned(), long));
    v.push(("C-20 empty".to_owned(), Vec::new()));
    v
}

/// The honest HS2 of a second handshake whose client draws differ (other `e_c`, other `ek_c`).
fn second_handshake(fx: &RelayFx) -> (Vec<u8>, Vec<u8>, AwaitHs2, Vec<u8>) {
    let draws = patch(&client_draws(reference().case(3)), 0, &[0x42_u8; 32]);
    let (_hello, st) = link::client::start(fx.relay_fp, None, NOW).unwrap();
    let (rec_hs1, wait2) = st
        .on_relayinfo(&fx.rec_relayinfo, &mut FixedEntropy::new(&draws))
        .unwrap();
    let (rec_hs2, _relay_link) = relay_answer(fx, &rec_hs1).unwrap();
    (rec_hs1, rec_hs2, wait2, draws)
}

// ---------------------------------------------------------------------------------------------------------------
// tests

/// C-01 `client_hello_record_bytes`.
#[test]
fn client_hello_record_bytes() {
    let fx = RelayFx::case1();
    let (hello, _st) = link::client::start(fx.relay_fp, None, NOW).unwrap();
    assert_eq!(hello, unhex("0007015345434d5001"), "HELLO bytes");
    assert_eq!(hello.len(), 9);
    assert_eq!(
        hello,
        vec![0x00, 0x07, 0x01, 0x53, 0x45, 0x43, 0x4d, 0x50, 0x01]
    );
    // identical with and without an access key; equal to the file's link-0002
    let access = fx.access();
    let (hello2, _st) = link::client::start(fx.relay_fp, Some(&access), NOW).unwrap();
    assert_eq!(hello2, hello, "HELLO does not depend on the access key");
    assert_eq!(
        reference().case(2).output("rec_hello"),
        hello,
        "link-0002 rec_hello"
    );
}

/// C-02 `client_relayinfo_record_shape_rejects`.
#[test]
fn client_relayinfo_record_shape_rejects() {
    let fx = RelayFx::case1();
    let cases = c02_cases(&fx);
    assert!(cases.len() >= 10);
    for c in &cases {
        assert_ri_rejects_both(&fx, c);
    }
}

/// C-03 `client_relayinfo_ver_rejects`.
#[test]
fn client_relayinfo_ver_rejects() {
    let fx = RelayFx::case1();
    for c in &c03_cases(&fx) {
        assert_ri_rejects_both(&fx, c);
    }
    // I5 (link-0056) as the file has it
    let i5 = RiCase::new(
        &fx,
        "I5 link-0056",
        reference().case(56).input("rec_relayinfo"),
    );
    assert_ri_rejects_both(&fx, &i5);
    // control: ver 0x01 re-signed is accepted
    let ok = RiCase::new(&fx, "ver 0x01 control", resigned_patch(&fx, ri::VER, &[1]));
    assert_ri_accepts(&ok, None);
}

/// C-04 `client_relayinfo_bad_sig_pk_rejects`.
#[test]
fn client_relayinfo_bad_sig_pk_rejects() {
    let fx = RelayFx::case1();
    let cases = c04_cases(&fx);
    assert_eq!(cases.len(), 11);
    for c in &cases {
        assert_ri_rejects_both(&fx, c);
    }
}

/// C-05 `client_relayinfo_bad_sig_encoding_rejects`.
#[test]
fn client_relayinfo_bad_sig_encoding_rejects() {
    let fx = RelayFx::case1();
    let cases = c05_cases(&fx);
    assert_eq!(cases.len(), 6);
    for c in &cases {
        assert_ri_rejects_both(&fx, c);
    }
}

/// C-06 `client_relayinfo_low_order_dh_rejects`.
#[test]
fn client_relayinfo_low_order_dh_rejects() {
    let fx = RelayFx::case1();
    let cases = c06_cases(&fx);
    assert_eq!(cases.len(), 14);
    for c in &cases {
        assert_ri_rejects_both(&fx, c);
    }
    // I6 (link-0057)
    let i6 = RiCase::new(
        &fx,
        "I6 link-0057",
        reference().case(57).input("rec_relayinfo"),
    );
    assert_ri_rejects_both(&fx, &i6);
}

/// C-07 `client_relayinfo_kem_ek_modulus_rejects`.
#[test]
fn client_relayinfo_kem_ek_modulus_rejects() {
    let fx = RelayFx::case1();
    for c in &c07_cases(&fx) {
        assert_ri_rejects_both(&fx, c);
    }
}

/// C-08 `client_relayinfo_signature_binds_every_field`.
#[test]
fn client_relayinfo_signature_binds_every_field() {
    let fx = RelayFx::case1();
    // controls: the same custom-signing helper with the right label reproduces the honest record
    assert_eq!(
        sign_custom(
            &fx.sig_seed,
            Label::LinkRelayinfo.as_bytes(),
            &fx.rec_relayinfo
        ),
        fx.rec_relayinfo,
        "helper control"
    );
    let cases = c08_cases(&fx);
    assert_eq!(cases.len(), 17);
    for c in &cases {
        assert_ri_rejects_both(&fx, c);
    }
    // I1 (link-0052)
    let i1 = RiCase::new(
        &fx,
        "I1 link-0052",
        reference().case(52).input("rec_relayinfo"),
    );
    assert_ri_rejects_both(&fx, &i1);
}

/// C-09 `client_relayinfo_fp_mismatch_rejects`.
#[test]
fn client_relayinfo_fp_mismatch_rejects() {
    let fx = RelayFx::case1();
    for c in &c09_cases(&fx) {
        assert_ri_rejects_both(&fx, c);
    }
    // I2 (link-0053): the file's pinned value
    let c = reference().case(53);
    let mut i2 = RiCase::new(&fx, "I2 link-0053", c.input("rec_relayinfo"));
    i2.pinned = c.input("relay_fp").try_into().unwrap();
    assert_ri_rejects_both(&fx, &i2);
    // control: the other relay's record is accepted when its own fingerprint is pinned
    let (other, fp) = other_relay_record(&fx);
    let mut ok = RiCase::new(&fx, "other relay, own pin", other);
    ok.pinned = fp;
    assert_ri_accepts(&ok, None);
}

/// C-10 `client_relayinfo_validity_boundaries`.
#[test]
fn client_relayinfo_validity_boundaries() {
    let fx = RelayFx::case1();
    let table = c10_table(&fx);
    assert_eq!(table.len(), 6);
    for (c, accept) in &table {
        for access in [None, Some(&fx.access())] {
            if *accept {
                assert_ri_accepts(c, access);
            } else {
                assert_ri_rejects(c, access);
            }
        }
    }
    // the file's I3 (link-0054, expired), I7 (link-0058, too long), I8 (link-0059, exactly 60 d)
    let i3 = RiCase::new(
        &fx,
        "I3 link-0054",
        reference().case(54).input("rec_relayinfo"),
    );
    let i7 = RiCase::new(
        &fx,
        "I7 link-0058",
        reference().case(58).input("rec_relayinfo"),
    );
    let i8 = RiCase::new(
        &fx,
        "I8 link-0059",
        reference().case(59).input("rec_relayinfo"),
    );
    assert_ri_rejects_both(&fx, &i3);
    assert_ri_rejects_both(&fx, &i7);
    assert_ri_accepts(&i8, None);
    // the same record with another client clock: 60 d + 1 s before valid_until rejects, 60 d accepts
    let mut early = RiCase::new(
        &fx,
        "now = valid_until - 60 d - 1",
        fx.rec_relayinfo.clone(),
    );
    early.now = VALID_UNTIL - SIXTY_DAYS - 1;
    assert_ri_rejects_both(&fx, &early);
    early.now = VALID_UNTIL - SIXTY_DAYS;
    assert_ri_accepts(&early, None);
}

/// C-11 `client_relayinfo_akc_with_access_key`.
#[test]
fn client_relayinfo_akc_with_access_key() {
    let fx = RelayFx::case1();
    let access = fx.access();
    // akc = SHA-256("SecMP-Q/1 akc" ‖ k), computed in the test
    let expect = sha256(&[Label::QAkc.as_bytes(), &fx.access_key]);
    assert_eq!(fx.akc, expect, "akc of the file");
    assert_eq!(
        at(&fx.rec_relayinfo, ri::AKC, 32),
        expect,
        "akc in the record"
    );
    let honest = RiCase::new(&fx, "honest", fx.rec_relayinfo.clone());
    assert_ri_accepts(&honest, Some(&access));
    for c in &c11_reject_cases(&fx) {
        assert_ri_rejects(c, Some(&access));
    }
    // a different access key rejects the honest record
    let other: AccessKey = SecretBytes::from_slice(&[0x55_u8; 32]).unwrap();
    assert_ri_rejects(&honest, Some(&other));
}

/// C-12 `client_relayinfo_akc_without_access_key_not_checked` [O-1].
#[test]
fn client_relayinfo_akc_without_access_key_not_checked() {
    let fx = RelayFx::case1();
    for akc in [
        [0xaa_u8; 32],
        [0_u8; 32],
        flip(&fx.akc, 0).try_into().unwrap(),
    ] {
        let c = RiCase::new(&fx, "C-12 arbitrary akc", with_akc(&fx, &akc));
        assert_ri_accepts(&c, None);
    }
    // I4 (link-0055): rejected only with a key
    let i4 = RiCase::new(
        &fx,
        "I4 link-0055",
        reference().case(55).input("rec_relayinfo"),
    );
    assert_ri_accepts(&i4, None);
    assert_ri_rejects(&i4, Some(&fx.access()));
}

/// C-13 `client_relayinfo_not_cached_across_links`.
#[test]
fn client_relayinfo_not_cached_across_links() {
    let fx = RelayFx::case1();
    // the second RELAYINFO: kid 2 and new static keys under the same signing identity
    let keys2 = RelayKeys::new(
        Ed25519SigningKey::from_seed(&fx.sig_seed).unwrap(),
        X25519Secret::from_bytes(&[0x11_u8; 32]).unwrap(),
        MlKem1024Dk::from_seed(&[0x22_u8; 64]).unwrap(),
        fx.access(),
        2,
    )
    .unwrap();
    let keys_kid2_old_statics = fx.keys_with_kid(2);
    let rec2 = keys2.relay_info_record(VALID_UNTIL).unwrap();
    assert_ne!(rec2, fx.rec_relayinfo);
    assert_eq!(keys2.fp(), fx.relay_fp, "same relay_sig, same pinned fp");
    assert_eq!(
        at(
            &keys_kid2_old_statics
                .relay_info_record(VALID_UNTIL)
                .unwrap(),
            ri::KID,
            4
        ),
        2_u32.to_be_bytes(),
        "keys_with_kid(2) carries kid 2"
    );

    // first link against the first RELAYINFO
    let (hs1_a, wait_a) = client_hs1(&fx, &fx.rec_relayinfo, None).unwrap();
    // second link, same client draws, against the second RELAYINFO
    let (hs1_b, wait_b) = client_hs1(&fx, &rec2, None).unwrap();
    assert_eq!(at(&hs1_a, h1::KID, 4), 1_u32.to_be_bytes());
    assert_eq!(
        at(&hs1_b, h1::KID, 4),
        2_u32.to_be_bytes(),
        "second HS1 carries kid 2"
    );
    // the client's own ephemerals repeat (same draws), the encapsulation to the new statics does not
    assert_eq!(at(&hs1_a, h1::E_C, 32), at(&hs1_b, h1::E_C, 32));
    assert_ne!(at(&hs1_a, h1::CT_KEM, 1568), at(&hs1_b, h1::CT_KEM, 1568));
    assert_eq!(
        at(&hs1_a, h1::PK_E1, 32),
        at(&hs1_b, h1::PK_E1, 32),
        "pk_e1 is the draw-derived ephemeral"
    );

    // the second HS1 encapsulates to the new keys: only a relay holding them answers; the old relay refuses
    assert!(
        relay_answer(&fx, &hs1_b).is_err(),
        "old statics cannot open HS1 #2"
    );
    let (_info, st) = link::relay::accept(&keys2)
        .on_hello(&unhex("0007015345434d5001"), VALID_UNTIL)
        .unwrap();
    let (rec_hs2, relay_link) = st.on_hs1(&hs1_b, &mut fixture::relay_entropy()).unwrap();
    let client_link = wait_b.on_hs2(&rec_hs2).unwrap();
    assert_eq!(client_link.sess_id(), relay_link.sess_id());
    // and the first link is untouched by the second
    let (rec_hs2_a, relay_link_a) = relay_answer(&fx, &hs1_a).unwrap();
    let client_link_a = wait_a.on_hs2(&rec_hs2_a).unwrap();
    assert_eq!(client_link_a.sess_id(), relay_link_a.sess_id());
    assert_ne!(client_link_a.sess_id(), client_link.sess_id());
}

/// C-14 `client_unexpected_record_type_rejects`.
#[test]
fn client_unexpected_record_type_rejects() {
    let fx = RelayFx::case1();
    let hello = unhex("0007015345434d5001");
    let rec_hs1 = reference().case(3).output("rec_hs1");
    let rec_hs2 = honest_hs2();
    // awaiting RELAYINFO: HELLO, HS1, HS2
    for (n, rec) in [("HELLO", &hello), ("HS1", &rec_hs1), ("HS2", &rec_hs2)] {
        let c = RiCase::new(&fx, format!("C-14 awaiting RELAYINFO got {n}"), rec.clone());
        assert_ri_rejects_both(&fx, &c);
    }
    // awaiting HS2: RELAYINFO, HS1 (and HELLO)
    for (n, rec) in [
        ("RELAYINFO", &fx.rec_relayinfo),
        ("HS1", &rec_hs1),
        ("HELLO", &hello),
    ] {
        assert!(hs2_rejected(&fx, rec), "C-14 awaiting HS2 got {n}");
    }
    // control: the right records are accepted
    let (client, relay) = honest_links();
    assert_eq!(client.sess_id(), relay.sess_id());
}

/// C-15 `client_takes_no_long_term_secret`.
#[test]
fn client_takes_no_long_term_secret() {
    // type level: `start` takes the pinned fingerprint, an optional access key and the clock; nothing else
    let start_fn: StartFn = link::client::start;
    assert!(start_fn(RelayFx::case1().relay_fp, None, NOW).is_ok());
    let fx = RelayFx::case1();
    // draws over one handshake: exactly 32 + 64 + 32 + 32 B
    let draws = client_draws(reference().case(3));
    assert_eq!(draws.len(), 160);
    let mut entropy = FixedEntropy::new(&draws);
    assert_eq!(entropy.remaining(), 160);
    let (_hello, st) = link::client::start(fx.relay_fp, None, NOW).unwrap();
    let (_rec, wait) = st.on_relayinfo(&fx.rec_relayinfo, &mut entropy).unwrap();
    assert_eq!(
        entropy.remaining(),
        0,
        "32 + 64 + 32 + 32 B drawn, nothing more"
    );
    // with surplus bytes only 160 are consumed
    let mut more = FixedEntropy::new(&[draws.as_slice(), &[0_u8; 17]].concat());
    let (_h, st) = link::client::start(fx.relay_fp, None, NOW).unwrap();
    let _ = st.on_relayinfo(&fx.rec_relayinfo, &mut more).unwrap();
    assert_eq!(more.remaining(), 17);
    // short entropy: the handshake fails (Unavailable, not a verdict on received bytes)
    let mut short = FixedEntropy::new(draws.get(..159).unwrap());
    let (_h, st) = link::client::start(fx.relay_fp, None, NOW).unwrap();
    assert!(matches!(
        st.on_relayinfo(&fx.rec_relayinfo, &mut short),
        Err(Error::Unavailable)
    ));
    // HS2 processing draws nothing (`on_hs2` takes no entropy) and yields the link
    let link = wait.on_hs2(&honest_hs2()).unwrap();
    assert_eq!(
        link.sess_id(),
        reference().case(4).output("sess_id").as_slice()
    );
}

/// C-16 `client_hs1_matches_independent_derivation`.
#[test]
fn client_hs1_matches_independent_derivation() {
    let fx = RelayFx::case1();
    let (rec, wait) = client_hs1(&fx, &fx.rec_relayinfo, None).unwrap();
    assert_eq!(rec.len(), 2856);
    // body offsets of the row (record offsets minus the 3-byte len ‖ type prefix)
    assert_eq!(
        [
            h1::VER,
            h1::KID,
            h1::E_C,
            h1::EK_C,
            h1::PK_E1,
            h1::CT_KEM,
            h1::MAC1,
            h1::LEN
        ]
        .map(|o| o - 3),
        [0, 1, 5, 37, 1221, 1253, 2821, 2853]
    );
    assert_eq!(
        at(&rec, 0, 3),
        [0x0b, 0x26, 0x03],
        "len 2854 (type + 2853 body) ‖ type 0x03"
    );
    assert_eq!(rec.get(h1::VER), Some(&1));
    let parts = Hs1Parts {
        kid: u32::from_be_bytes(at(&rec, h1::KID, 4).try_into().unwrap()),
        relay_fp: fx.relay_fp,
        e_c: at(&rec, h1::E_C, 32).to_vec(),
        ek_c: at(&rec, h1::EK_C, 1184).to_vec(),
        pk_e1: at(&rec, h1::PK_E1, 32).to_vec(),
        ct_kem: at(&rec, h1::CT_KEM, 1568).to_vec(),
    };
    assert_eq!(parts.kid, 1);
    // ss1, h0, ck1 from the kat trace; h0, ck1, mac1 recomputed with secmp-crypto primitives
    let trace = wait.trace_kat();
    let h0 = h0_of(&parts);
    assert_eq!(h0, trace.h0, "h0");
    let (ck1, mac1) = ck1_mac1(&h0, &trace.ss1);
    assert_eq!(ck1.expose_secret(), &trace.ck1, "ck1");
    assert_eq!(mac1, trace.mac1, "mac1");
    assert_eq!(at(&rec, h1::MAC1, 32), mac1, "mac1 in the record");
    assert_eq!(hs1_record(&parts, &mac1, 1), rec, "whole record");
    assert_eq!(rec, reference().case(3).output("rec_hs1"), "link-0003");
    // the hash trails of the row: the h0 preimage is 180 B (asserted inside h0_of)
    assert_eq!(from(&rec, h1::MAC1).len(), 32);
}

/// C-17 `client_hs2_mac2_flip_rejects`.
#[test]
fn client_hs2_mac2_flip_rejects() {
    let fx = RelayFx::case1();
    let cases = c17_cases();
    assert_eq!(cases.len(), 3);
    for (n, rec) in &cases {
        assert!(hs2_rejected(&fx, rec), "{n}");
    }
    // T1 (link-0071)
    assert!(
        hs2_rejected(&fx, &reference().case(71).input("rec_hs2")),
        "T1"
    );
    // control: the honest record is accepted
    assert!(awaiting_hs2(&fx).on_hs2(&honest_hs2()).is_ok());
}

/// C-18 `client_hs2_tampered_field_rejects`.
#[test]
fn client_hs2_tampered_field_rejects() {
    let fx = RelayFx::case1();
    for (n, rec) in &c18_cases() {
        assert!(hs2_rejected(&fx, rec), "{n}");
    }
    // T2 (link-0072)
    assert!(
        hs2_rejected(&fx, &reference().case(72).input("rec_hs2")),
        "T2"
    );
}

/// C-19 `client_hs2_low_order_e_r_rejects`.
#[test]
fn client_hs2_low_order_e_r_rejects() {
    let fx = RelayFx::case1();
    let cases = c19_cases();
    assert_eq!(cases.len(), 14);
    for (n, rec) in &cases {
        assert!(hs2_rejected(&fx, rec), "{n}");
    }
    // T3 (link-0073)
    assert!(
        hs2_rejected(&fx, &reference().case(73).input("rec_hs2")),
        "T3"
    );
}

/// C-20 `client_hs2_record_shape_rejects`.
#[test]
fn client_hs2_record_shape_rejects() {
    let fx = RelayFx::case1();
    for (n, rec) in &c20_cases() {
        assert!(hs2_rejected(&fx, rec), "{n}");
    }
    // T4 (link-0074)
    assert!(
        hs2_rejected(&fx, &reference().case(74).input("rec_hs2")),
        "T4"
    );
}

/// C-21 `client_hs2_of_other_handshake_rejects`.
#[test]
fn client_hs2_of_other_handshake_rejects() {
    let fx = RelayFx::case1();
    let (hs1_2, hs2_2, wait2, draws2) = second_handshake(&fx);
    let (hs1_1, _wait1) = client_hs1(&fx, &fx.rec_relayinfo, None).unwrap();
    assert_ne!(draws2, client_draws(reference().case(3)));
    assert_ne!(
        at(&hs1_1, h1::E_C, 32),
        at(&hs1_2, h1::E_C, 32),
        "other e_c"
    );
    assert_ne!(hs2_2, honest_hs2());
    // the second HS2 is honest for the second client ...
    assert!(
        wait2.on_hs2(&hs2_2).is_ok(),
        "honest HS2 of handshake 2 opens handshake 2"
    );
    // ... and Rejected by the first
    assert!(hs2_rejected(&fx, &hs2_2), "HS2 of another handshake");
    // symmetric: the first HS2 is rejected by the second client
    let (_rec, wait2b, ..) = {
        let (_h, st) = link::client::start(fx.relay_fp, None, NOW).unwrap();
        let (r, w) = st
            .on_relayinfo(&fx.rec_relayinfo, &mut FixedEntropy::new(&draws2))
            .unwrap();
        (r, w)
    };
    assert!(matches!(wait2b.on_hs2(&honest_hs2()), Err(Error::Rejected)));
}

/// C-22 `client_rejection_leaves_no_link`.
#[test]
fn client_rejection_leaves_no_link() {
    let fx = RelayFx::case1();
    let access = fx.access();
    // every RELAYINFO reject of C-02…C-11 (with the access key held) and the file's I1…I8 rejects
    let mut ri_cases: Vec<RiCase> = Vec::new();
    ri_cases.extend(c02_cases(&fx));
    ri_cases.extend(c03_cases(&fx));
    ri_cases.extend(c04_cases(&fx));
    ri_cases.extend(c05_cases(&fx));
    ri_cases.extend(c06_cases(&fx));
    ri_cases.extend(c07_cases(&fx));
    ri_cases.extend(c08_cases(&fx));
    ri_cases.extend(c09_cases(&fx));
    ri_cases.extend(
        c10_table(&fx)
            .into_iter()
            .filter(|(_, ok)| !ok)
            .map(|(c, _)| c),
    );
    ri_cases.extend(c11_reject_cases(&fx));
    for n in 52..=58 {
        let c = reference().case(n);
        let mut rc = RiCase::new(&fx, format!("link-{n:04}"), c.input("rec_relayinfo"));
        if c.inputs.contains_key("relay_fp") {
            rc.pinned = c.input("relay_fp").try_into().unwrap();
        }
        ri_cases.push(rc);
    }
    assert!(ri_cases.len() > 80);
    for c in &ri_cases {
        // the failing call consumes the state (moved in) and returns an error, not a link: the HS1 record,
        // the handshake state and every key are dropped inside the call
        let (r, _left) = run_ri(c, Some(&access));
        assert_eq!(r.err(), Some(Error::Rejected), "{}", c.name);
    }
    // a fresh handshake afterwards still works
    let (client, relay) = honest_links();
    assert_eq!(client.sess_id(), relay.sess_id());

    // every HS2 reject of C-17…C-20, the file's T1…T4 and the HS2 of another handshake (C-21)
    let mut hs2_cases: Vec<(String, Vec<u8>)> = Vec::new();
    hs2_cases.extend(c17_cases());
    hs2_cases.extend(c18_cases());
    hs2_cases.extend(c19_cases());
    hs2_cases.extend(c20_cases());
    for n in 71..=74 {
        hs2_cases.push((format!("link-{n:04}"), reference().case(n).input("rec_hs2")));
    }
    hs2_cases.push(("C-21".into(), second_handshake(&fx).1));
    assert!(hs2_cases.len() > 30);
    for (n, rec) in &hs2_cases {
        let wait = awaiting_hs2(&fx);
        assert_eq!(wait.on_hs2(rec).err(), Some(Error::Rejected), "{n}");
    }
    let (client, relay) = honest_links();
    assert_eq!(client.sess_id(), relay.sess_id());
    // the awaiting-HS2 state of a rejected HS2 is gone; a client must start over, and the new one works
    let (rec_hs1, wait) = client_hs1(&fx, &fx.rec_relayinfo, None).unwrap();
    let (rec_hs2, _relay_link) = relay_answer(&fx, &rec_hs1).unwrap();
    assert!(wait.on_hs2(&rec_hs2).is_ok());
}
