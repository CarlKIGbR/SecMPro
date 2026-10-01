// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! SecMP-TR `Decrypt` (spec §7.4) on a fixed receiver state (`fuzz/common/tr_fixture.rs`: a current receiving
//! chain, a next header key and three skipped keys under two distinct header keys), from a fresh decoding of its
//! `RatchetStateV1` for every input. The first byte selects the mode (modulo 5):
//!
//! - 0: the rest is the received cell, any length.
//! - 1–4: the rest is a header plaintext, zero-padded or cut to `HEADER_LEN` (2314), sealed under one of the
//!   receiver's header keys with the nonce and body of an undelivered honest cell (`Fixture::sealed`):
//!   1 `hk_r` (the current chain), 2 `nhk_r` (a DH step), 3 `hk_r` = the header key of the skipped entry
//!   `(hk_A2, 0)`, 4 the old chain's header key (skipped entry `(hk_A1, 1)`). Such headers open, so the input
//!   reaches header decoding, the skipped-key lookup, the KEM-constancy and new-ratchet-key checks,
//!   `skip_message_keys` and the body MAC (which verifies only for the honest header: its AD binds the header
//!   ciphertext).
//!
//! Invariants: no panic; a refusal is the uniform `Rejected` (never `Unavailable`: every call gets the randomness of
//! a DH step's sending half), draws none of that randomness, and hands back the state byte-identical; an accepted
//! cell's committed state is the state's own encoding, and it decodes and re-encodes to itself.
//!
//! A header with a large `pn`/`n` (up to `MAX_FF` = 2^20 beyond `n_r`) makes the receiver derive that many chain
//! keys, twice on a DH step: legitimate §7.4 behaviour that takes up to seconds per input; the gates run libFuzzer
//! with a per-input timeout above that (`fuzz/README.md`).
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_crypto::Zeroizing;
use secmp_proto::Error;
use secmp_proto::tr::RatchetState;

#[path = "../common/tr_fixture.rs"]
mod tr_fixture;

use tr_fixture::Fixture;

fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let fixture = Fixture::get();
    let mode = usize::from(selector % 5);
    let cell = if mode == 0 {
        rest.to_vec()
    } else {
        fixture.sealed(mode, rest)
    };
    let state = RatchetState::from_bytes(&fixture.receiver).unwrap();
    let mut entropy = Fixture::step_entropy();
    let supplied = entropy.remaining();
    match state.decrypt_with(&cell, &mut entropy) {
        Ok(opened) => {
            let mut committed = Zeroizing::new(Vec::new());
            let (state, _plaintext) = opened
                .commit(|bytes| {
                    committed.extend_from_slice(bytes);
                    Ok::<(), Error>(())
                })
                .unwrap();
            let encoded = state.to_bytes().unwrap();
            assert_eq!(encoded.as_slice(), committed.as_slice());
            let decoded = RatchetState::from_bytes(&encoded).unwrap();
            assert_eq!(decoded.to_bytes().unwrap().as_slice(), encoded.as_slice());
        }
        Err(refused) => {
            let (state, error) = refused.into_parts();
            assert_eq!(error, Error::Rejected);
            // a rejection draws no randomness (M3 plan D2, review C4)
            assert_eq!(entropy.remaining(), supplied);
            assert_eq!(
                state.to_bytes().unwrap().as_slice(),
                fixture.receiver.as_slice()
            );
        }
    }
});
