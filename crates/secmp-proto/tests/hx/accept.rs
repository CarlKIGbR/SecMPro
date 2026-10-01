// SPDX-License-Identifier: AGPL-3.0-or-later
//! `Responder::accept`: grouping (§6.5), steps 1–3 of §6.6 and what a rejection leaves behind (TEST-SPEC-M4 (a),
//! N-26 … N-57, N-66 … N-71).
//!
//! Every negative row builds its cells with the independent harness (re-sealed under `K_inv` and, for the inner
//! layer, `K_id`), runs `accept` on a fresh store and asserts the *same* four things (`"…_and_keeps_opk"`): the
//! uniform `Rejected`, a store whose digest (SPK generations, RPK, every OPK, the records) is unchanged, the OPK
//! still held, and no draw of randomness that a rejection could have caused (the entropy handed in is exactly the
//! DH-step randomness; a rejection never consumes it — `secmp-proto` has no logging dependency, so "log nothing
//! identifying" holds structurally). The rows share one table (`table`) so that N-60 can run all of them.

use secmp_crypto::{SecretBytes, X25519Secret};
use secmp_proto::tr::FixedEntropy;

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
    check_row("N-40");
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
    check_row("N-47");
}

#[test]
fn accept_inner_iks_bad_ed25519_rejects_and_keeps_opk() {
    check_row("N-48");
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

/// N-60: every row above through one function: one error value, the store digest unchanged, the OPK kept, and the
/// counting store sees no `delete_opk` call.
#[test]
fn accept_reject_is_uniform_and_transactional() {
    use secmp_proto::Error;
    use secmp_proto::hx::Responder;
    use secmp_proto::prekeys::PrekeyStore;
    use secmp_proto::wire::cell::Cell;

    /// A store that counts `delete_opk` calls and delegates to the in-memory store.
    struct Counting {
        inner: secmp_proto::prekeys::MemoryPrekeyStore,
        deletes: usize,
    }
    impl PrekeyStore for Counting {
        fn spk(&self, id: u32) -> Option<&secmp_proto::prekeys::SpkGeneration> {
            self.inner.spk(id)
        }
        fn opk(&self, id: u32) -> Option<&secmp_proto::prekeys::OpkSecrets> {
            self.inner.opk(id)
        }
        fn delete_opk(&mut self, id: u32) -> secmp_proto::Result<()> {
            self.deletes += 1;
            self.inner.delete_opk(id)
        }
    }

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
