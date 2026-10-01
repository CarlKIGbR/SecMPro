// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! `Responder::accept` (spec §6.5, §6.6) on a list of cells against the fixture handshake
//! (`fuzz/common/hx_fixture.rs`): the first byte is the number of cells (modulo 13, at most 12); each cell is a
//! selector byte followed, for selector 3 (modulo 4), by 4096 raw bytes (zero-filled if the input ends); selectors
//! 0–2 name the fixture's honest cell 0, 1 or 2 — so the fuzzer can place the honest cells anywhere among raw ones.
//!
//! Invariants: no panic; `Ok` only if all three honest cells are in the list (nothing else opens under `K_inv`),
//! and then exactly the OPK is gone from the store; every `Err` is the uniform `Rejected` and leaves the store
//! digest unchanged with the OPK in place.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::Error;
use secmp_proto::hx::Responder;
use secmp_proto::prekeys::PrekeyStore;
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::cell::Cell;

#[path = "../common/hx_fixture.rs"]
mod hx_fixture;

use hx_fixture::Fixture;

fuzz_target!(|data: &[u8]| {
    let f = Fixture::get();
    let Some((count, mut rest)) = data.split_first() else {
        return;
    };
    let mut cells: Vec<Cell> = Vec::new();
    for _ in 0..(count % 13) {
        let Some((selector, tail)) = rest.split_first() else {
            break;
        };
        rest = tail;
        if selector % 4 < 3 {
            cells.push(f.cells[usize::from(selector % 4)].clone());
        } else {
            let raw = Fixture::fit(rest, 4096);
            rest = &rest[rest.len().min(4096)..];
            cells.push(Cell::from_bytes(&raw).unwrap());
        }
    }
    let mut store = f.store.duplicate_kat().unwrap();
    let before = store.digest_kat();
    let mut entropy = FixedEntropy::new(&f.step);
    match Responder::accept(
        &cells,
        &f.record,
        &mut store,
        &f.inviter.responder_keys(),
        &mut entropy,
    ) {
        Ok(_) => {
            for honest in &f.cells {
                assert!(cells.iter().any(|c| c.as_bytes() == honest.as_bytes()));
            }
            assert!(store.opk(f.record.opk_id).is_none());
            let mut reference = f.store.duplicate_kat().unwrap();
            reference.delete_opk(f.record.opk_id).unwrap();
            assert_eq!(store.digest_kat(), reference.digest_kat());
        }
        Err(e) => {
            assert_eq!(e, Error::Rejected);
            assert_eq!(store.digest_kat(), before);
            assert!(store.opk(f.record.opk_id).is_some());
        }
    }
});
