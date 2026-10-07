// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! `Responder::accept` on envelopes the fuzzer shapes, re-sealed by the harness with the fixture's `K_inv` (and
//! `K_id`) so that the input reaches the checks behind the trial opening (spec §6.6 steps 1–3; random cells never
//! open under `K_inv`). The first byte selects the mode (modulo 4); the rest is cut or zero-padded to the size:
//!
//! - 0: `Padded` (12018 B), sealed into three cells under `K_inv`: the `Outer` decoder, padding, version.
//! - 1: `Inner` (6113 B), sealed under `K_id` into the honest `Outer`, padded, sealed under `K_inv`: `IKSPublic_I`,
//!   `first_msg` and the TR decryption.
//! - 2: the first 3177 bytes of `Outer` (version, `ek_I`, ids, `ct_spk`, `ct_opk`) in front of the honest `inner_ct`
//!   (re-sealed): the id checks, the DH operations and `K_id`.
//! - 3 (M5, M4 review R-44): the rest, cut or zero-padded to 1710 B, is a padded `Content` that the harness encrypts
//!   as `first_msg` from the initiator's post-init TR state (`fuzz/common/hx_mode3.rs`), behind the honest
//!   `IKSPublic_I` and `Outer` head, all re-sealed: it reaches the rejects of step 3 behind the decryption (padding,
//!   `Content` decoder, type, `caps`, known route). The honest padded Content is the seed.
//!
//! Invariants: no panic; every `Err` is the uniform `Rejected` and leaves the store digest unchanged with the OPK in
//! place; an `Ok` (only for an input that reproduces the honest envelope's content; in mode 3 exactly for a `Content`
//! that decodes as a `Handshake` with a relay-queue route) leaves exactly the OPK deleted and the record consumed.
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::Error;
use secmp_proto::codec::pad;
use secmp_proto::hx::Responder;
use secmp_proto::prekeys::PrekeyStore;
use secmp_proto::tr::FixedEntropy;

#[path = "../common/hx_fixture.rs"]
mod hx_fixture;
#[path = "../common/hx_mode3.rs"]
mod hx_mode3;

use hx_fixture::{Fixture, INNER_LEN, PADDED_LEN};
use hx_mode3::Mode3;
use secmp_proto::Decode;
use secmp_proto::sizes::BODY_LEN;
use secmp_proto::wire::cell::{Content, ContentBody, RouteDescriptor};

/// Mode 3: whether the step-3 content rules (§6.5, §6.6 step 3) accept this padded `Content`, decided with the
/// decoders alone.
fn content_accepted(body: &[u8]) -> bool {
    matches!(
        Content::decode(body),
        Ok(Content { body: ContentBody::Handshake(h), .. })
            if h.routes.iter().any(|r| matches!(r, RouteDescriptor::RelayQueue(_)))
    )
}

fuzz_target!(|data: &[u8]| {
    let f = Fixture::get();
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let mut accepted_by_content = None;
    let padded = match selector % 4 {
        3 => {
            let body = Fixture::fit(rest, BODY_LEN);
            accepted_by_content = Some(content_accepted(&body));
            Mode3::get().padded(f, &body)
        }
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
            assert_ne!(accepted_by_content, Some(false));
            let mut reference = f.store.duplicate_kat().unwrap();
            reference
                .commit_accept(f.record.opk_id, &f.record.ld_id)
                .unwrap();
            assert_eq!(store.digest_kat(), reference.digest_kat());
        }
        Err(e) => {
            assert_eq!(e, Error::Rejected);
            assert_ne!(accepted_by_content, Some(true));
            assert_eq!(store.digest_kat(), before);
            assert!(store.opk(f.record.opk_id).is_some());
        }
    }
});
