// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FZ-04 (M5): `Link::open` on an established link (the relay's end of the fixed honest handshake of
//! `fuzz/common/link_fixture.rs`, kept across inputs). Invariants: no panic; every `Err` is the uniform `Rejected`
//! and leaves the receive counter unchanged; a unit of another length than 4352 B is rejected before the AEAD (no
//! open attempt, `aead_open_attempts_kat`); an `Ok` advances the counter by exactly one and a replay of the same unit
//! is rejected.
//!
//! The first byte selects the mode (modulo 5); the harness keeps the client's send counter equal to the relay's
//! receive counter before every input:
//!
//! - 0 raw: the rest is the unit, of any length (an `Ok` is possible only for a unit the client sealed).
//! - 1 honest: the rest (cut to 4335 bytes) is sealed by the client and opened by the relay; must be `Ok` and the
//!   payload must come back; a replay of the same frame must be rejected.
//! - 2 tampered: bytes 0–1 are a position (modulo 4352), byte 2 an xor mask (0 counts as 1), the rest (cut to 4335)
//!   is the payload of a frame whose byte at the position is xored with the mask: must be rejected.
//! - 3 counter skew: bytes 0–1: bit 15 the direction, bits 0–9 the distance minus one; the rest is the payload of a
//!   frame sealed under the expected counter shifted by that distance (forwards, or backwards if possible): must be
//!   rejected.
//! - 4 wrong direction: the rest is sealed by the relay itself and opened by the relay: must be rejected.
#![no_main]

use std::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use secmp_proto::link::{Error, Link};
use secmp_proto::sizes::FRAME_LEN;

#[path = "../common/link_fixture.rs"]
mod link_fixture;

use link_fixture::{Bytes, Fixture};

const MAX_PAYLOAD: usize = 4335;

thread_local! {
    static LINKS: RefCell<Option<(Link, Link)>> = const { RefCell::new(None) };
}

fn payload_of(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len().min(MAX_PAYLOAD)]
}

/// `relay.open(unit)`: the rejection invariants, then (on `Ok`) the counter step and the replay.
fn open(relay: &mut Link, unit: &[u8], expect_ok: Option<bool>) -> bool {
    let before = relay.recv_counter();
    let attempts = relay.aead_open_attempts_kat();
    let result = relay.open(unit);
    let ok = match &result {
        Ok(_) => {
            assert_eq!(unit.len(), FRAME_LEN);
            assert_eq!(relay.recv_counter(), before.and_then(|c| c.checked_add(1)));
            true
        }
        Err(e) => {
            assert_eq!(*e, Error::Rejected);
            assert_eq!(relay.recv_counter(), before);
            if unit.len() != FRAME_LEN {
                assert_eq!(relay.aead_open_attempts_kat(), attempts);
            }
            false
        }
    };
    if let Some(expected) = expect_ok {
        assert_eq!(ok, expected);
    }
    ok
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    LINKS.with(|cell| {
        let mut slot = cell.borrow_mut();
        let (client, relay) = slot.get_or_insert_with(|| Fixture::get().honest_links());
        client.set_send_counter_kat(relay.recv_counter().unwrap());
        let mut b = Bytes(rest);
        let mut renew = false;
        match selector % 5 {
            0 => {
                open(relay, rest, None);
            }
            1 => {
                let payload = payload_of(rest);
                // the client refuses to seal beyond LINK_MAX_FRAMES: start a new link then
                match client.seal(payload) {
                    Ok(frame) => {
                        let counter = relay.recv_counter().unwrap();
                        assert!(open(relay, &*frame, Some(true)));
                        assert_eq!(relay.recv_counter(), Some(counter + 1));
                        assert!(!open(relay, &*frame, Some(false)));
                    }
                    Err(e) => {
                        assert_eq!(e, Error::NewLinkRequired);
                        renew = true;
                    }
                }
            }
            2 => {
                let at = usize::from(b.u16()) % FRAME_LEN;
                let mask = b.u8().max(1);
                if let Ok(frame) = client.seal(payload_of(b.0)) {
                    let mut unit = frame.to_vec();
                    unit[at] ^= mask;
                    open(relay, &unit, Some(false));
                } else {
                    renew = true;
                }
            }
            3 => {
                let k = b.u16();
                let distance = u64::from(k & 0x3ff) + 1;
                let counter = relay.recv_counter().unwrap();
                let skewed = if k & 0x8000 == 0 {
                    counter.checked_add(distance)
                } else {
                    counter.checked_sub(distance)
                };
                if let Some(skewed) = skewed {
                    client.set_send_counter_kat(skewed);
                    if let Ok(frame) = client.seal(payload_of(b.0)) {
                        open(relay, &*frame, Some(false));
                    } else {
                        renew = true;
                    }
                }
            }
            _ => {
                if let Ok(frame) = relay.seal(payload_of(rest)) {
                    open(relay, &*frame, Some(false));
                }
            }
        }
        if renew {
            *slot = None;
        }
    });
});
