// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! `StateDigestV1` of the `tr` vector suite (`vectors/SCHEMA-4.9-tr.md`). It is the suite's comparison construct,
//! not the persistence format, so it lives in the test crate: [`fields`] parses the documented `RatchetStateV1`
//! encoding (`RatchetState::to_bytes`, M3 plan D5) field by field and [`digest`] hashes the SCHEMA-4.9 preimage.
//!
//! Shared by the replay test `tests/tr_vectors.rs` and the generator `tests/common/tr.rs` (the `gen-tr` example and
//! the `tr_generator` test).

use secmp_crypto::sha256;
use secmp_proto::tr::RatchetState;

/// The digest's ASCII label (SCHEMA-4.9, SQ-24; no terminator).
const LABEL: &[u8] = b"SecMP-TR/1 state-digest";

/// Lowercase hex.
pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// The fields of a state (spec §7.1), read from its `RatchetStateV1` encoding in encoding order.
pub struct StateFields {
    /// `sb`, `rk`, `dh_s.sk` (the 32 raw bytes as drawn).
    pub sb_rk_dh_s: Vec<u8>,
    /// `dh_r`.
    pub dh_r: Option<Vec<u8>>,
    /// `kem_s.seed` (`d ‖ z`).
    pub kem_s_seed: Vec<u8>,
    /// `kem_r`, `last_ct_r`, `ct_s`.
    pub kem: [Option<Vec<u8>>; 3],
    /// `ck_s`, `ck_r`, `hk_s`, `hk_r`, `nhk_s`, `nhk_r`.
    pub keys: [Option<Vec<u8>>; 6],
    /// `n_s`, `n_r`, `pn`.
    pub n_s: u32,
    /// See [`StateFields::n_s`].
    pub n_r: u32,
    /// See [`StateFields::n_s`].
    pub pn: u32,
    /// The skipped entries `hk[32] ‖ u32be(n) ‖ mk[32]`, in insertion order.
    pub skipped: Vec<Vec<u8>>,
}

/// A cursor over the `RatchetStateV1` encoding.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let (head, tail) = self
            .0
            .split_at_checked(n)
            .expect("RatchetStateV1 too short");
        self.0 = tail;
        head
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().unwrap())
    }

    /// A presence byte and, if present, `n` bytes.
    fn opt(&mut self, n: usize) -> Option<Vec<u8>> {
        let flag = self.take(1).first().copied().unwrap();
        assert!(flag <= 1, "presence byte {flag}");
        (flag == 1).then(|| self.take(n).to_vec())
    }
}

/// The fields of `state`, parsed from `RatchetStateV1` (`fmt 0x01 ‖ sb ‖ rk ‖ dh_s.sk ‖ opt(dh_r) ‖ kem_s.seed ‖
/// opt(kem_r) ‖ opt(last_ct_r) ‖ opt(ct_s) ‖ opt(ck_s) … opt(nhk_r) ‖ n_s ‖ n_r ‖ pn ‖ count u16 ‖ entries`).
pub fn fields(state: &RatchetState) -> StateFields {
    let encoded = state.to_bytes().unwrap();
    let mut c = Cursor(&encoded);
    assert_eq!(c.take(1), [1], "RatchetStateV1 format byte");
    let sb_rk_dh_s = c.take(96).to_vec();
    let dh_r = c.opt(32);
    let kem_s_seed = c.take(64).to_vec();
    let kem = [c.opt(1184), c.opt(1088), c.opt(1088)];
    let keys = [
        c.opt(32),
        c.opt(32),
        c.opt(32),
        c.opt(32),
        c.opt(32),
        c.opt(32),
    ];
    let (n_s, n_r, pn) = (c.u32(), c.u32(), c.u32());
    let count = u16::from_be_bytes(c.take(2).try_into().unwrap());
    let skipped = (0..count).map(|_| c.take(68).to_vec()).collect();
    assert!(c.0.is_empty(), "RatchetStateV1 fully consumed");
    StateFields {
        sb_rk_dh_s,
        dh_r,
        kem_s_seed,
        kem,
        keys,
        n_s,
        n_r,
        pn,
        skipped,
    }
}

/// `opt(None) = 0x00`, `opt(Some(x)) = 0x01 ‖ x`.
fn opt(pre: &mut Vec<u8>, x: Option<&Vec<u8>>) {
    match x {
        None => pre.push(0),
        Some(x) => {
            pre.push(1);
            pre.extend_from_slice(x);
        }
    }
}

/// `StateDigestV1` (SCHEMA-4.9) in lowercase hex: SHA-256 of `"SecMP-TR/1 state-digest" ‖ sb ‖ rk ‖ dh_s.sk ‖
/// opt(dh_r) ‖ kem_s.seed ‖ opt(kem_r) ‖ opt(last_ct_r) ‖ opt(ct_s) ‖ opt(ck_s) ‖ opt(ck_r) ‖ opt(hk_s) ‖ opt(hk_r) ‖
/// opt(nhk_s) ‖ opt(nhk_r) ‖ u32be(n_s) ‖ u32be(n_r) ‖ u32be(pn) ‖ u32be(|skipped|) ‖ (hk ‖ u32be(n) ‖ mk)*`.
pub fn digest(state: &RatchetState) -> String {
    let f = fields(state);
    let mut pre = LABEL.to_vec();
    pre.extend_from_slice(&f.sb_rk_dh_s);
    opt(&mut pre, f.dh_r.as_ref());
    pre.extend_from_slice(&f.kem_s_seed);
    for x in f.kem.iter().chain(&f.keys) {
        opt(&mut pre, x.as_ref());
    }
    let count = u32::try_from(f.skipped.len()).unwrap();
    for n in [f.n_s, f.n_r, f.pn, count] {
        pre.extend_from_slice(&n.to_be_bytes());
    }
    for e in &f.skipped {
        pre.extend_from_slice(e);
    }
    hex(&sha256(&[&pre]))
}
