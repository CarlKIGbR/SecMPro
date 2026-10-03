// SPDX-License-Identifier: AGPL-3.0-or-later
//! `Responder::accept`: grouping (§6.5), steps 1–3 of §6.6 and what a rejection leaves behind (TEST-SPEC-M4 (a),
//! N-26 … N-57, N-66 … N-71).
//!
//! Every negative row builds its cells with the independent harness (re-sealed under `K_inv` and, for the inner
//! layer, `K_id`), runs `accept` on a fresh store and asserts three things (`Lib::assert_rejected`,
//! `"…_and_keeps_opk"`): the uniform `Rejected`, a store whose digest (SPK generations, RPK, every OPK, the records) is
//! unchanged, and the OPK still held; rows that name a check also assert its reject site (`Lib::assert_rejected_at`).
//! The fourth and fifth — no `delete_opk`/`commit_accept` call and no draw of randomness that a rejection could have
//! caused (the entropy handed in is exactly the DH-step randomness) — are asserted for every row by N-60: over the
//! shared table (`table`) by `accept_reject_is_uniform_and_transactional`, over the rejecting rows outside it by
//! `accept_every_rejecting_row_counts_no_delete_and_no_draw` (M4 review C-15). `secmp-proto` has no logging
//! dependency, so "log nothing identifying" holds structurally.

use secmp_crypto::{SecretBytes, X25519Secret};
use secmp_proto::Error;
use secmp_proto::hx::ACCEPT_SITE_KAT;
use secmp_proto::tr::{FixedEntropy, OsEntropy};

use crate::accept_ok::{at, bogus_chunk, first_two};
use crate::build::random_bytes;
use crate::build::{garbage, handshake_body, raw_content};
use crate::hx_gen::harness::{
    self, OFF_CT_OPK, OFF_CT_SPK, OFF_EK, OFF_INNER_CT, OFF_OPK_ID, OFF_SPK_ID,
};
use crate::layout::{IKS_DH, IKS_ED, low_order_values};
use crate::scenario::Lib;

fn flip(mut b: Vec<u8>, at: usize) -> Vec<u8> {
    *b.get_mut(at).unwrap() ^= 1;
    b
}

/// Overwrite `buf[at .. at + src.len()]` with `src`.
fn put(buf: &mut [u8], at: usize, src: &[u8]) {
    buf.get_mut(at..)
        .unwrap()
        .get_mut(..src.len())
        .unwrap()
        .copy_from_slice(src);
}

/// One negative scenario: the row, a description, and the cells handed to `accept`.
type Entry = (&'static str, String, Vec<Vec<u8>>);

fn entry(row: &'static str, what: impl Into<String>, cells: Vec<Vec<u8>>) -> Entry {
    (row, what.into(), cells)
}

/// N-26 … N-30: grouping.
fn table_grouping(lib: &Lib) -> Vec<Entry> {
    let h = lib.honest();
    let w = &lib.w;
    let mut t: Vec<Entry> = Vec::new();

    // N-26: two of three chunks (each pair), single cells, nothing
    for (x, y) in [(0, 1), (0, 2), (1, 2)] {
        t.push(entry(
            "N-26",
            format!("chunks {x} and {y}"),
            vec![h.get(x).unwrap().clone(), h.get(y).unwrap().clone()],
        ));
    }
    for (x, c) in h.iter().take(3).enumerate() {
        t.push(entry("N-26", format!("chunk {x} only"), vec![c.clone()]));
    }
    t.push(entry("N-26", "no cells", vec![]));

    // N-27: garbage only
    for (n, tag) in [(3, 1), (12, 2)] {
        t.push(entry("N-27", format!("{n} random cells"), garbage(tag, n)));
    }

    // N-28: a flipped byte of cell i in N, COM, ct, tag: the cell is ignored, no complete group remains
    for i in 0..3 {
        for (part, at) in [("N", 5), ("COM", 30), ("ct", 100), ("tag", 4095)] {
            let mut cells = h.clone();
            let c = cells.get_mut(i).unwrap();
            *c = flip(std::mem::take(c), at);
            t.push(entry("N-28", format!("cell {i}, {part}"), cells));
        }
    }

    // N-29: chunks 0, 1 of envelope A and chunk 2 of envelope B (same invitation)
    let (ea, eb) = (lib.reseal(&w.b6.outer, 1), lib.reseal(&w.b6.outer, 2));
    let (a0, a1, a2) = (ea.first().unwrap(), ea.get(1).unwrap(), ea.get(2).unwrap());
    let (b1, b2) = (eb.get(1).unwrap(), eb.get(2).unwrap());
    t.push(entry(
        "N-29",
        "A0 A1 B2",
        vec![a0.clone(), a1.clone(), b2.clone()],
    ));
    t.push(entry(
        "N-29",
        "A0 B1 A2",
        vec![a0.clone(), b1.clone(), a2.clone()],
    ));

    // N-30: chunk 2 of another envelope re-sealed under A's init_id (a splice; the Outer fails to open)
    let other_outer = flip(w.b6.outer.clone(), OFF_INNER_CT + 6000);
    let spliced = harness::cell_raw(
        &w.k_inv,
        &w.inv.ld_id,
        &[9; 24],
        &harness::cell_plaintext(&[1; 16], 2, 3, &harness::chunk_of(&other_outer, 2)),
    );
    t.push(entry(
        "N-30",
        "A0 A1 B2 under A's init_id",
        vec![a0.clone(), a1.clone(), spliced],
    ));
    t
}

/// N-34 … N-44: the Outer layer.
fn table_outer(lib: &Lib) -> Vec<Entry> {
    let w = &lib.w;
    let mut t: Vec<Entry> = Vec::new();

    // N-34: Outer padding
    let mut no_marker = vec![0_u8; 12_018];
    put(&mut no_marker, 0, &w.b6.outer);
    t.push(entry("N-34", "no 0x80", lib.reseal_padded(&no_marker, 3)));
    let mut dirty = secmp_proto::codec::pad(&w.b6.outer, 12_018)
        .unwrap()
        .to_vec();
    *dirty.last_mut().unwrap() = 1;
    t.push(entry(
        "N-34",
        "non-zero after 0x80",
        lib.reseal_padded(&dirty, 3),
    ));

    // N-35: Outer ver
    t.push(entry(
        "N-35",
        "ver 0x02",
        lib.outer_variant(4, |o| *o.get_mut(0).unwrap() = 2),
    ));

    // N-36: spk_id; N-37: opk_id unknown
    t.push(entry(
        "N-36",
        "spk_id 8",
        lib.outer_variant(5, |o| put(o, OFF_SPK_ID, &8_u32.to_be_bytes())),
    ));
    t.push(entry(
        "N-37",
        "opk_id 43 (unknown)",
        lib.outer_variant(6, |o| put(o, OFF_OPK_ID, &43_u32.to_be_bytes())),
    ));

    // N-40: low-order ek_I (the Outer decoder, before any DH)
    for (k, v) in low_order_values().iter().enumerate() {
        t.push(entry(
            "N-40",
            format!("ek_I low order #{k}"),
            lib.outer_variant(7, |o| put(o, OFF_EK, v)),
        ));
    }

    // N-42 … N-44: another valid ek_I, flipped ct_spk, flipped ct_opk (implicit rejection: K_id differs)
    let other_ek = *X25519Secret::from_bytes(&[0x42; 32])
        .unwrap()
        .public_key()
        .as_bytes();
    t.push(entry(
        "N-42",
        "another valid ek_I",
        lib.outer_variant(8, |o| put(o, OFF_EK, &other_ek)),
    ));
    t.push(entry(
        "N-43",
        "ct_spk byte flipped",
        lib.outer_variant(9, |o| *o.get_mut(OFF_CT_SPK + 5).unwrap() ^= 1),
    ));
    t.push(entry(
        "N-44",
        "ct_opk byte flipped",
        lib.outer_variant(10, |o| *o.get_mut(OFF_CT_OPK + 5).unwrap() ^= 1),
    ));
    t
}

/// N-45 … N-52: the Inner layer and the first message.
fn table_inner(lib: &Lib) -> Vec<Entry> {
    let w = &lib.w;
    let a = &w.b6.a;
    let mut t: Vec<Entry> = Vec::new();

    // N-45: inner_ct under the K_id of another link_key; AD with another ld_id
    let mut other_link_key = w.inv.link_key;
    *other_link_key.first_mut().unwrap() ^= 1;
    let wrong_k_id = harness::k_id(
        &w.inv.ld_id,
        &other_link_key,
        a.dh.get(2).unwrap(),
        &a.ss_spk,
        a.dh.get(3).unwrap(),
        &a.ss_opk,
    );
    let ict = harness::inner_ct(&wrong_k_id, &w.inv.ld_id, &[11; 24], &w.b6.inner);
    t.push(entry(
        "N-45",
        "K_id of another link_key",
        lib.reseal(&lib.outer_of(&ict), 11),
    ));
    let mut other_ld = w.inv.ld_id;
    *other_ld.first_mut().unwrap() ^= 1;
    let ict = harness::inner_ct(&a.k_id, &other_ld, &[12; 24], &w.b6.inner);
    t.push(entry(
        "N-45",
        "AD with another ld_id",
        lib.reseal(&lib.outer_of(&ict), 12),
    ));

    // N-46: inner_ct tampered (COM, a ct byte, the tag), outer re-sealed under K_inv
    let ict = harness::inner_ct(&a.k_id, &w.inv.ld_id, &[13; 24], &w.b6.inner);
    for (part, at) in [
        ("COM", 30),
        ("ct", 100),
        ("tag", ict.len().saturating_sub(1)),
    ] {
        t.push(entry(
            "N-46",
            format!("inner_ct {part}"),
            lib.reseal(&lib.outer_of(&flip(ict.clone(), at)), 13),
        ));
    }

    // N-47, N-48: Inner's IKSPublic_I (decoder), re-sealed under the right K_id
    let first_msg = &w.b6.first_msg;
    for (k, v) in low_order_values().iter().enumerate() {
        let mut iks = w.i.iks_bytes.clone();
        put(&mut iks, IKS_DH, v);
        t.push(entry(
            "N-47",
            format!("IKS ik_dh low order #{k}"),
            lib.inner_variant(14, &lib.inner_with(&iks, first_msg)),
        ));
    }
    let mut identity_point = [0_u8; 32];
    *identity_point.first_mut().unwrap() = 1;
    let mut y_ge_p = [0xff_u8; 32];
    *y_ge_p.last_mut().unwrap() = 0x7f;
    for (name, bytes) in [("identity point", identity_point), ("y >= p", y_ge_p)] {
        let mut iks = w.i.iks_bytes.clone();
        put(&mut iks, IKS_ED, &bytes);
        t.push(entry(
            "N-48",
            format!("ik_ed25519 {name}"),
            lib.inner_variant(15, &lib.inner_with(&iks, first_msg)),
        ));
    }
    let mut iks = w.i.iks_bytes.clone();
    *iks.first_mut().unwrap() = 2;
    t.push(entry(
        "N-48",
        "IKS ver 0x02",
        lib.inner_variant(15, &lib.inner_with(&iks, first_msg)),
    ));

    // N-49: another valid IKSPublic in Inner, first_msg unchanged (transcript, DH1 and SK change)
    let other = lib.other_identity(0x50);
    t.push(entry(
        "N-49",
        "substituted initiator identity",
        lib.inner_variant(16, &lib.inner_with(&other.iks_bytes, first_msg)),
    ));

    // N-50: header sealed under a key other than HK_A
    let wrong_hk = SecretBytes::<32>::from_slice(&[0x99; 32]).unwrap();
    t.push(entry(
        "N-50",
        "header under another key",
        lib.first_msg_variant(17, &lib.first_msg_header_under(first_msg, &wrong_hk)),
    ));

    // N-51: body tag flipped (vector R8)
    t.push(entry(
        "N-51",
        "body tag",
        lib.first_msg_variant(18, &flip(first_msg.clone(), 4095)),
    ));
    t.push(entry(
        "N-51",
        "body byte",
        lib.first_msg_variant(18, &flip(first_msg.clone(), 3000)),
    ));

    // N-52: first_msg encrypted for another sb
    let mut other_sb = a.transcript;
    *other_sb.first_mut().unwrap() ^= 1;
    t.push(entry(
        "N-52",
        "different sb",
        lib.full_envelope(&w.i, &lib.honest_content_padded(), Some(other_sb)),
    ));
    t
}

/// N-53 … N-70: the Content layer.
fn table_content(lib: &Lib) -> Vec<Entry> {
    let w = &lib.w;
    let mut t: Vec<Entry> = Vec::new();

    // N-53: Content undecodable (padding, version)
    t.push(entry(
        "N-53",
        "no padding marker",
        lib.content_variant(19, &[0_u8; 1710]),
    ));
    t.push(entry(
        "N-53",
        "Content ver 0x02",
        lib.content_variant(
            19,
            &raw_content(2, 1, &handshake_body(lib, 0, &[lib.route()])),
        ),
    ));
    let mut dirty_content = lib.honest_content_padded();
    *dirty_content.get_mut(1709).unwrap() = 1;
    t.push(entry(
        "N-53",
        "non-zero after the marker",
        lib.content_variant(19, &dirty_content),
    ));

    // N-54: not a Handshake
    t.push(entry(
        "N-54",
        "Batch",
        lib.content_variant(20, &lib.batch_content()),
    ));
    t.push(entry(
        "N-54",
        "Dummy",
        lib.content_variant(20, &lib.dummy_content()),
    ));

    // N-55: caps = 1; N-56: zero routes
    t.push(entry(
        "N-55",
        "caps 1",
        lib.content_variant(
            21,
            &raw_content(1, 1, &handshake_body(lib, 1, &[lib.route()])),
        ),
    ));
    t.push(entry(
        "N-55",
        "caps 0x80",
        lib.content_variant(
            21,
            &raw_content(1, 1, &handshake_body(lib, 0x80, &[lib.route()])),
        ),
    ));
    t.push(entry(
        "N-56",
        "route count 0",
        lib.content_variant(22, &raw_content(1, 1, &handshake_body(lib, 0, &[]))),
    ));

    // N-57: reflection (a complete, cryptographically valid envelope whose initiator is R itself)
    t.push(entry(
        "N-57",
        "IKSPublic_I = IKSPublic_R",
        lib.full_envelope(&w.r, &lib.honest_content_padded(), None),
    ));

    // N-68, N-69: first_msg header n, pn
    t.push(entry(
        "N-68",
        "n = 1",
        lib.first_msg_variant(23, &lib.first_msg_with_counters(1, 0, 23)),
    ));
    t.push(entry(
        "N-68",
        "n = 7",
        lib.first_msg_variant(23, &lib.first_msg_with_counters(7, 0, 23)),
    ));
    t.push(entry(
        "N-69",
        "pn = 5",
        lib.first_msg_variant(24, &lib.first_msg_with_counters(0, 5, 24)),
    ));

    // N-70: routes, none of a known kind
    t.push(entry(
        "N-70",
        "one route of kind 0x02",
        lib.content_variant(25, &lib.handshake_with_routes(&[lib.unknown_route()])),
    ));
    t.push(entry(
        "N-70",
        "two routes of kind 0x02",
        lib.content_variant(
            25,
            &lib.handshake_with_routes(&[lib.unknown_route(), lib.unknown_route()]),
        ),
    ));
    t
}

/// Every standard negative scenario of N-26 … N-57 and N-66 … N-70, with the standard store.
fn table(lib: &Lib) -> Vec<Entry> {
    let mut t = table_grouping(lib);
    t.extend(table_outer(lib));
    t.extend(table_inner(lib));
    t.extend(table_content(lib));
    t
}

fn check_row(row: &str) {
    let lib = Lib::new();
    let entries: Vec<Entry> = table(&lib).into_iter().filter(|e| e.0 == row).collect();
    assert!(!entries.is_empty(), "{row} has entries");
    for (row, what, cells) in entries {
        lib.assert_rejected(&cells, &format!("{row} {what}"));
    }
}

/// [`check_row`] with the reject site (M4 review C-15, R-31): every entry of `row` is rejected at `site`.
fn check_row_at(row: &str, site: &str) {
    let lib = Lib::new();
    let entries: Vec<Entry> = table(&lib).into_iter().filter(|e| e.0 == row).collect();
    assert!(!entries.is_empty(), "{row} has entries");
    for (_, _, cells) in entries {
        lib.assert_rejected_at(&cells, site);
    }
}

/// M4 review C-15 (R-31): the check a row names is the one that rejects, not a backstop behind it — N-40 (a low-order
/// `EK_I`) at the `Outer` decoder ("outer"), N-47 and N-48 (the `IKSPublic_I` of `Inner`) at the `Inner` decoder
/// ("inner checks").
#[test]
fn accept_reject_sites_name_the_check_that_rejects() {
    check_row_at("N-40", "outer");
    check_row_at("N-47", "inner checks");
    check_row_at("N-48", "inner checks");
}

#[test]
fn accept_two_of_three_chunks_rejects_and_keeps_opk() {
    check_row("N-26");
}

#[test]
fn accept_garbage_only_rejects_and_keeps_opk() {
    check_row("N-27");
}

#[test]
fn accept_tampered_chunk_rejects_and_keeps_opk() {
    check_row("N-28");
}

#[test]
fn accept_mixed_init_id_chunks_rejects_and_keeps_opk() {
    check_row("N-29");
}

#[test]
fn accept_spliced_chunk_same_init_id_rejects_and_keeps_opk() {
    check_row("N-30");
}

#[test]
fn accept_outer_bad_padding_rejects_and_keeps_opk() {
    check_row("N-34");
}

#[test]
fn accept_outer_wrong_ver_rejects_and_keeps_opk() {
    check_row("N-35");
}

#[test]
fn accept_wrong_spk_id_rejects_and_keeps_opk() {
    check_row("N-36");
}

#[test]
fn accept_low_order_ek_i_rejects_and_keeps_opk() {
    check_row_at("N-40", "outer");
}

#[test]
fn accept_tampered_ek_i_rejects_and_keeps_opk() {
    check_row("N-42");
}

#[test]
fn accept_tampered_ct_spk_rejects_and_keeps_opk() {
    check_row("N-43");
}

#[test]
fn accept_tampered_ct_opk_rejects_and_keeps_opk() {
    check_row("N-44");
}

#[test]
fn accept_inner_wrong_k_id_rejects_and_keeps_opk() {
    check_row("N-45");
}

#[test]
fn accept_inner_tampered_rejects_and_keeps_opk() {
    check_row("N-46");
}

#[test]
fn accept_inner_iks_low_order_ik_dh_rejects_and_keeps_opk() {
    check_row_at("N-47", "inner checks");
}

#[test]
fn accept_inner_iks_bad_ed25519_rejects_and_keeps_opk() {
    check_row_at("N-48", "inner checks");
}

#[test]
fn accept_substituted_initiator_identity_rejects_and_keeps_opk() {
    check_row("N-49");
}

#[test]
fn accept_first_msg_bad_header_rejects_and_keeps_opk() {
    check_row("N-50");
}

#[test]
fn accept_first_msg_bad_body_mac_rejects_and_keeps_opk() {
    check_row("N-51");
}

#[test]
fn accept_first_msg_wrong_sb_rejects_and_keeps_opk() {
    check_row("N-52");
}

#[test]
fn accept_first_msg_content_undecodable_rejects_and_keeps_opk() {
    check_row("N-53");
}

#[test]
fn accept_first_msg_not_handshake_rejects_and_keeps_opk() {
    check_row("N-54");
}

#[test]
fn accept_first_msg_caps_nonzero_rejects_and_keeps_opk() {
    check_row("N-55");
}

/// ADR-043 (g): `first_msg` must decrypt to a Handshake with `caps = 0`; caps = 1 and caps = 0x80 reject (N-55).
#[test]
fn accept_handshake_caps_nonzero_rejects_and_keeps_opk() {
    check_row("N-55");
}

#[test]
fn accept_first_msg_zero_routes_rejects_and_keeps_opk() {
    check_row("N-56");
}

#[test]
fn accept_reflected_own_iks_rejects_and_keeps_opk() {
    check_row("N-57");
}

#[test]
fn accept_first_msg_n_nonzero_rejects_and_keeps_opk() {
    check_row("N-68");
}

#[test]
fn accept_first_msg_pn_nonzero_rejects_and_keeps_opk() {
    check_row("N-69");
}

#[test]
fn accept_handshake_without_known_route_rejects_and_keeps_opk() {
    check_row("N-70");
}

/// A store that counts `delete_opk` and `commit_accept` calls (each deletes the OPK) and delegates to the in-memory
/// store (N-60).
struct Counting {
    inner: secmp_proto::prekeys::MemoryPrekeyStore,
    deletes: usize,
}

impl secmp_proto::prekeys::PrekeyStore for Counting {
    fn spk(&self, id: u32) -> Option<&secmp_proto::prekeys::SpkGeneration> {
        self.inner.spk(id)
    }
    fn opk(&self, id: u32) -> Option<&secmp_proto::prekeys::OpkSecrets> {
        self.inner.opk(id)
    }
    fn delete_opk(&mut self, id: u32) -> secmp_proto::Result<()> {
        self.deletes = self.deletes.saturating_add(1);
        self.inner.delete_opk(id)
    }
    fn commit_accept(&mut self, opk_id: u32, ld_id: &[u8; 16]) -> secmp_proto::Result<()> {
        self.deletes = self.deletes.saturating_add(1);
        self.inner.commit_accept(opk_id, ld_id)
    }
}

/// A store whose `commit_accept` cannot be made durable (M4 review C-12): it counts the call, returns
/// `Unavailable` and changes nothing; everything else is the in-memory store's.
struct Failing {
    inner: secmp_proto::prekeys::MemoryPrekeyStore,
    commits: usize,
}

impl secmp_proto::prekeys::PrekeyStore for Failing {
    fn spk(&self, id: u32) -> Option<&secmp_proto::prekeys::SpkGeneration> {
        self.inner.spk(id)
    }
    fn opk(&self, id: u32) -> Option<&secmp_proto::prekeys::OpkSecrets> {
        self.inner.opk(id)
    }
    fn delete_opk(&mut self, id: u32) -> secmp_proto::Result<()> {
        self.inner.delete_opk(id)
    }
    fn commit_accept(&mut self, _opk_id: u32, _ld_id: &[u8; 16]) -> secmp_proto::Result<()> {
        self.commits = self.commits.saturating_add(1);
        Err(Error::Unavailable)
    }
}

/// M4 review C-12 (R-26): a `commit_accept` that cannot be made durable is `Unavailable`, not `Rejected` — honest
/// cells, the store refuses to make the commit durable: `accept` returns `Unavailable` after exactly one commit call,
/// the inner store is unchanged and the OPK kept. A refused commit stays `Rejected` (`commit_accept_rejects_*` in
/// `store.rs`).
#[test]
fn accept_commit_unavailable_is_unavailable_and_changes_nothing() {
    use secmp_proto::hx::Responder;
    use secmp_proto::wire::cell::Cell;
    let lib = Lib::new();
    let mut store = Failing {
        inner: lib.store(),
        commits: 0,
    };
    let before = store.inner.digest_kat();
    let cells: Vec<Cell> = lib
        .honest()
        .iter()
        .map(|c| Cell::from_bytes(c).unwrap())
        .collect();
    let result = Responder::accept(
        &cells,
        &lib.record(),
        &mut store,
        &lib.r_id.responder_keys(),
        &mut FixedEntropy::new(&lib.w.step),
    );
    assert_eq!(result.err(), Some(Error::Unavailable));
    assert_eq!(store.commits, 1, "the one commit, after steps 1-3 passed");
    assert_eq!(store.inner.digest_kat(), before, "the store is unchanged");
    assert!(
        store.inner.opk_ids().contains(&harness::OPK_ID),
        "the OPK is kept"
    );
}

/// N-60: every row above through one function: one error value, the store digest unchanged, the OPK kept, and the
/// counting store sees no `delete_opk` call.
#[test]
fn accept_reject_is_uniform_and_transactional() {
    use secmp_proto::hx::Responder;
    use secmp_proto::wire::cell::Cell;

    let lib = Lib::new();
    let entries = table(&lib);
    assert!(
        entries.len() > 60,
        "the table covers every standard row ({} entries)",
        entries.len()
    );
    let mut errors = std::collections::BTreeSet::new();
    for (row, what, cells) in &entries {
        let mut store = Counting {
            inner: lib.store(),
            deletes: 0,
        };
        let before = store.inner.digest_kat();
        let cells: Vec<Cell> = cells.iter().map(|c| Cell::from_bytes(c).unwrap()).collect();
        let mut entropy = FixedEntropy::new(&lib.w.step);
        let result = Responder::accept(
            &cells,
            &lib.record(),
            &mut store,
            &lib.r_id.responder_keys(),
            &mut entropy,
        );
        let error = result.err();
        assert_eq!(error, Some(Error::Rejected), "{row} {what}");
        errors.insert(format!("{error:?}"));
        assert_eq!(store.deletes, 0, "{row} {what}: no delete");
        assert_eq!(
            store.inner.digest_kat(),
            before,
            "{row} {what}: store digest"
        );
        // §6.6 step 3: no draw before the first message is decrypted; if it decrypted, the DH step's working copy
        // drew its 128 bytes (ref reading 11) and the rejection came from a later check
        let left = entropy.remaining();
        assert!(
            left == lib.w.step.len() || left == 0,
            "{row} {what}: a rejection draws nothing, or one whole DH step ({left} left)"
        );
    }
    assert_eq!(errors.len(), 1, "one error value for every reject site");
    // the Ok path deletes exactly once
    let mut store = Counting {
        inner: lib.store(),
        deletes: 0,
    };
    let cells: Vec<Cell> = lib
        .honest()
        .iter()
        .map(|c| Cell::from_bytes(c).unwrap())
        .collect();
    Responder::accept(
        &cells,
        &lib.record(),
        &mut store,
        &lib.r_id.responder_keys(),
        &mut FixedEntropy::new(&lib.w.step),
    )
    .unwrap();
    assert_eq!(store.deletes, 1);
}

/// M4 review C-15 (R-33): the N-60 assertions — `Rejected`, no `delete_opk`/`commit_accept` call, the store digest
/// unchanged, and no draw (`remaining()` is the whole DH-step stream: every row here rejects before the first message
/// is decrypted) — over the rejecting rows outside `table()`: N-32, N-33, N-67, N-37 with a live OPK, N-38, N-39,
/// N-71, and N-41 through `Responder::accept` (a low-order input of DH1–DH4: `EK_I` and `IKSPublic_I.ik_dh`; the
/// decoders refuse it before any DH, the helper's own check is the unit test of the same name).
#[test]
fn accept_every_rejecting_row_counts_no_delete_and_no_draw() {
    use secmp_proto::hx::Responder;
    use secmp_proto::prekeys::MemoryPrekeyStore;
    use secmp_proto::wire::cell::Cell;
    let lib = Lib::new();
    let h = lib.honest();
    let check = |inner: MemoryPrekeyStore, cells: &[Vec<u8>], what: &str| {
        let mut store = Counting { inner, deletes: 0 };
        let before = store.inner.digest_kat();
        let cells: Vec<Cell> = cells.iter().map(|c| Cell::from_bytes(c).unwrap()).collect();
        let mut entropy = FixedEntropy::new(&lib.w.step);
        let result = Responder::accept(
            &cells,
            &lib.record(),
            &mut store,
            &lib.r_id.responder_keys(),
            &mut entropy,
        );
        assert_eq!(result.err(), Some(Error::Rejected), "{what}");
        assert_eq!(store.deletes, 0, "{what}: no delete");
        assert_eq!(store.inner.digest_kat(), before, "{what}: store digest");
        // every row here rejects before the first message is decrypted: nothing is drawn (delta review VD2-4)
        assert_eq!(
            entropy.remaining(),
            lib.w.step.len(),
            "{what}: a rejection draws nothing"
        );
    };
    // N-32: chunk 1 under another invitation's K_inv, or with another ld_id in the AD
    let chunk = harness::chunk_of(&lib.w.b6.outer, 1);
    let mut other_key = lib.w.inv.link_key;
    *other_key.first_mut().unwrap() ^= 1;
    let other_k_inv = harness::k_inv(&lib.w.inv.ld_id, &other_key);
    let plaintext = harness::cell_plaintext(&lib.w.b6.init_id, 1, 3, &chunk);
    let mut other_ld = lib.w.inv.ld_id;
    *other_ld.first_mut().unwrap() ^= 1;
    for (what, bad) in [
        (
            "N-32 another K_inv",
            harness::cell_raw(&other_k_inv, &lib.w.inv.ld_id, &[53; 24], &plaintext),
        ),
        (
            "N-32 another ld_id",
            harness::cell_raw(&lib.w.k_inv, &other_ld, &[54; 24], &plaintext),
        ),
    ] {
        check(lib.store(), &[at(&h, 0), bad, at(&h, 2)], what);
    }
    // N-33: a differing duplicate of chunk 1 first
    check(
        lib.store(),
        &[vec![bogus_chunk(&lib, 1, 55)], h.clone()].concat(),
        "N-33 bogus before the honest chunk",
    );
    // N-67: nine partial groups, then the missing chunk of the evicted oldest
    let partial = |k: u8| lib.reseal(&lib.w.b6.outer, k + 1);
    let mut cells: Vec<Vec<u8>> = (0..9).flat_map(|k| first_two(&partial(k))).collect();
    cells.push(at(&partial(0), 2));
    check(lib.store(), &cells, "N-67 the oldest of nine is evicted");
    // N-37: the opk_id of another live OPK
    let mut store = lib.store();
    let other = store
        .issue_opk(&mut FixedEntropy::new(&random_bytes(3, 96)))
        .unwrap();
    let cells = lib.outer_variant(60, |o| put(o, OFF_OPK_ID, &other.to_be_bytes()));
    check(store, &cells, "N-37 another live OPK");
    // N-38: the OPK was consumed
    let mut store = lib.store();
    secmp_proto::prekeys::PrekeyStore::delete_opk(&mut store, harness::OPK_ID).unwrap();
    check(store, &h, "N-38 used OPK");
    // N-39: after a success, the same cells and the retransmitted copies
    for (what, cells) in [
        ("N-39 the same cells", h.clone()),
        ("N-39 retransmitted copies", [h.clone(), h.clone()].concat()),
    ] {
        let mut store = lib.store();
        lib.accept(&mut store, &h).unwrap();
        check(store, &cells, what);
    }
    // N-71: the SPK generation was rotated out
    let mut store = MemoryPrekeyStore::starting_at(harness::SPK_ID + 1, harness::OPK_ID);
    let mut e = FixedEntropy::new(
        &[
            random_bytes(2, 160),
            lib.w.r_seed.get(96 + 160..).unwrap().to_vec(),
        ]
        .concat(),
    );
    store.create_spk(harness::CREATED, &mut e).unwrap();
    store.issue_opk(&mut e).unwrap();
    check(store, &h, "N-71 rotated-out SPK");
    // N-41 through accept: every low-order value as EK_I (DH2–DH4) and as IKSPublic_I.ik_dh (DH1)
    for v in low_order_values() {
        check(
            lib.store(),
            &lib.outer_variant(7, |o| put(o, OFF_EK, &v)),
            "N-41 low-order EK_I",
        );
        let mut iks = lib.w.i.iks_bytes.clone();
        put(&mut iks, IKS_DH, &v);
        check(
            lib.store(),
            &lib.inner_variant(14, &lib.inner_with(&iks, &lib.w.b6.first_msg)),
            "N-41 low-order ik_dh",
        );
    }
}

/// The reject site of `accept` on `cells` against a store that also holds SPK generation 8 and OPK 43 (so that the
/// ids of N-36/N-37 name keys that exist: only the §6.6 step 1 comparison with the record's ids can refuse them
/// there, and a refusal anywhere later names a different site).
fn reject_site_with_extra_keys(lib: &Lib, cells: &[Vec<u8>]) -> &'static str {
    let mut store = lib.store();
    assert_eq!(store.create_spk(harness::CREATED, &mut OsEntropy), Ok(8));
    assert_eq!(store.issue_opk(&mut OsEntropy), Ok(43));
    let before = store.digest_kat();
    assert_eq!(lib.accept(&mut store, cells).err(), Some(Error::Rejected));
    assert_eq!(store.digest_kat(), before, "the store is unchanged");
    ACCEPT_SITE_KAT.get().unwrap()
}

#[test]
fn accept_wrong_spk_id_rejects_at_the_id_check() {
    let lib = Lib::new();
    // spk_id 8 (held), opk_id correct
    let cells = lib.outer_variant(5, |o| put(o, OFF_SPK_ID, &8_u32.to_be_bytes()));
    assert_eq!(reject_site_with_extra_keys(&lib, &cells), "outer");
}

#[test]
fn accept_wrong_opk_id_rejects_at_the_id_check() {
    let lib = Lib::new();
    // opk_id 43 (held), spk_id correct
    let cells = lib.outer_variant(6, |o| put(o, OFF_OPK_ID, &43_u32.to_be_bytes()));
    assert_eq!(reject_site_with_extra_keys(&lib, &cells), "outer");
}
