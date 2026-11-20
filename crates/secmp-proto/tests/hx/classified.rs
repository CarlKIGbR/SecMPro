// SPDX-License-Identifier: AGPL-3.0-or-later
//! `Responder::accept_classified` (Q147 (iii)): the result of `accept` and the cells the call spent (review RT-1) —
//! every chunk of a complete group processed in the call, accepted or rejected; nothing after `Unavailable` (delta
//! review VD2-7).

use secmp_proto::Error;
use secmp_proto::hx::{Accepted, Responder, Spent};
use secmp_proto::prekeys::{MemoryPrekeyStore, OpkSecrets, PrekeyStore, SpkGeneration};
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::cell::Cell;

use crate::accept_ok::at;
use crate::build::garbage;
use crate::hx_gen::harness::{OFF_SPK_ID, OPK_ID};
use crate::scenario::Lib;

/// `accept_classified` on `cells` with the honest DH-step randomness.
fn classify(
    lib: &Lib,
    store: &mut impl PrekeyStore,
    cells: &[Vec<u8>],
) -> (secmp_proto::Result<Accepted>, Spent) {
    let cells: Vec<Cell> = cells.iter().map(|c| Cell::from_bytes(c).unwrap()).collect();
    Responder::accept_classified(
        &cells,
        &lib.record(),
        store,
        &lib.r_id.responder_keys(),
        &mut FixedEntropy::new(&lib.w.step),
    )
}

/// A complete group that opens under `K_inv` but is rejected at §6.6 step 1 (`spk_id` 8, N-36), `init_id` `[5; 16]`.
fn rejected_group(lib: &Lib) -> Vec<Vec<u8>> {
    lib.outer_variant(5, |o| {
        o.get_mut(OFF_SPK_ID..)
            .unwrap()
            .get_mut(..4)
            .unwrap()
            .copy_from_slice(&8_u32.to_be_bytes());
    })
}

/// A valid group among garbage: accepted; the group's three cells are spent, the garbage is not.
#[test]
fn classified_valid_group_among_garbage_spends_the_group() {
    let lib = Lib::new();
    let h = lib.honest();
    let g = garbage(7, 3);
    let cells = vec![
        at(&g, 0),
        at(&h, 0),
        at(&g, 1),
        at(&h, 1),
        at(&h, 2),
        at(&g, 2),
    ];
    let mut store = lib.store();
    let (result, spent) = classify(&lib, &mut store, &cells);
    assert!(result.is_ok());
    assert_eq!(spent.indices(), &[1, 3, 4]);
    // `accept` is the same call without the classification
    assert!(lib.accept(&mut lib.store(), &cells).is_ok());
}

/// A rejected complete group is spent with the call's `Rejected`; before an honest group both are spent and the call
/// accepts; a duplicate chunk the group ignored (first-seen wins) is not spent.
#[test]
fn classified_rejected_group_is_spent() {
    let lib = Lib::new();
    let bad = rejected_group(&lib);
    let h = lib.honest();
    let mut store = lib.store();
    let before = store.digest_kat();
    let (result, spent) = classify(&lib, &mut store, &bad);
    assert_eq!(result.err(), Some(Error::Rejected));
    assert_eq!(spent.indices(), &[0, 1, 2]);
    assert_eq!(store.digest_kat(), before, "the store is unchanged");

    let cells = [
        bad.clone(),
        vec![at(&h, 0), at(&h, 0)],
        vec![at(&h, 1), at(&h, 2)],
    ]
    .concat();
    let (result, spent) = classify(&lib, &mut lib.store(), &cells);
    assert!(result.is_ok());
    assert_eq!(
        spent.indices(),
        &[0, 1, 2, 3, 5, 6],
        "index 4 is the ignored duplicate"
    );
}

/// A partial group (two of three chunks) is not spent: it is retained for the next call.
#[test]
fn classified_partial_group_is_not_spent() {
    let lib = Lib::new();
    let h = lib.honest();
    let mut store = lib.store();
    let (result, spent) = classify(&lib, &mut store, &[at(&h, 0), at(&h, 2)]);
    assert_eq!(result.err(), Some(Error::Rejected));
    assert!(spent.indices().is_empty());
    let (result, spent) = classify(&lib, &mut store, &garbage(8, 4));
    assert_eq!(result.err(), Some(Error::Rejected));
    assert_eq!(spent, Spent::default(), "garbage is never spent");
}

/// A store whose `commit_accept` cannot be made durable (M4 review C-12); everything else is the in-memory store's.
struct Failing(MemoryPrekeyStore);

impl PrekeyStore for Failing {
    fn spk(&self, id: u32) -> Option<&SpkGeneration> {
        self.0.spk(id)
    }
    fn opk(&self, id: u32) -> Option<&OpkSecrets> {
        self.0.opk(id)
    }
    fn delete_opk(&mut self, id: u32) -> secmp_proto::Result<()> {
        self.0.delete_opk(id)
    }
    fn commit_accept(&mut self, _opk_id: u32, _ld_id: &[u8; 16]) -> secmp_proto::Result<()> {
        Err(Error::Unavailable)
    }
}

/// VD2-7: after `Unavailable` nothing is spent — not the accepted group whose commit failed, nor a rejected group
/// processed before it; the caller retries the same cells.
#[test]
fn classified_unavailable_spends_nothing() {
    let lib = Lib::new();
    let cells = [rejected_group(&lib), lib.honest()].concat();
    let mut store = Failing(lib.store());
    let (result, spent) = classify(&lib, &mut store, &cells);
    assert_eq!(result.err(), Some(Error::Unavailable));
    assert!(spent.indices().is_empty());
    assert!(store.0.opk_ids().contains(&OPK_ID), "the OPK is kept");
    // the retry on a durable store accepts and spends all six
    let (result, spent) = classify(&lib, &mut store.0, &cells);
    assert!(result.is_ok());
    assert_eq!(spent.indices(), &[0, 1, 2, 3, 4, 5]);
}
