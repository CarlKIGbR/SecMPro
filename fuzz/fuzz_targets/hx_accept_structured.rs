// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! `Responder::accept` on envelopes the fuzzer shapes, re-sealed by the harness with the fixture's `K_inv` (and
//! `K_id`) so that the input reaches the checks behind the trial opening (spec §6.6 steps 1–3; random cells never
//! open under `K_inv`). The first byte selects the mode (modulo 3); the rest is cut or zero-padded to the size:
//!
//! - 0: `Padded` (12018 B), sealed into three cells under `K_inv`: the `Outer` decoder, padding, version.
//! - 1: `Inner` (6113 B), sealed under `K_id` into the honest `Outer`, padded, sealed under `K_inv`: `IKSPublic_I`,
//!   `first_msg` and the TR decryption.
//! - 2: the first 3177 bytes of `Outer` (version, `ek_I`, ids, `ct_spk`, `ct_opk`) in front of the honest `inner_ct`
//!   (re-sealed): the id checks, the DH operations and `K_id`.
//!
//! Invariants: no panic; every `Err` is the uniform `Rejected` and leaves the store digest unchanged with the OPK in
//! place; an `Ok` (only for an input that reproduces the honest envelope's content) leaves exactly the OPK deleted.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::Error;
use secmp_proto::codec::pad;
use secmp_proto::hx::Responder;
use secmp_proto::prekeys::PrekeyStore;
use secmp_proto::tr::FixedEntropy;

#[path = "../common/hx_fixture.rs"]
mod hx_fixture;

use hx_fixture::{Fixture, INNER_LEN, PADDED_LEN};

fuzz_target!(|data: &[u8]| {
    let f = Fixture::get();
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let padded = match selector % 3 {
        0 => Fixture::fit(rest, PADDED_LEN),
        1 => {
            let inner_ct = f.inner_ct(&Fixture::fit(rest, INNER_LEN));
            let outer = [f.outer_head.as_slice(), &inner_ct].concat();
            pad(&outer, PADDED_LEN).unwrap().to_vec()
        }
        _ => {
            let inner_ct = f.inner_ct(&f.inner);
            let outer = [Fixture::fit(rest, f.outer_head.len()).as_slice(), &inner_ct].concat();
            pad(&outer, PADDED_LEN).unwrap().to_vec()
        }
    };
    let cells = f.cells_of(&padded);
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
