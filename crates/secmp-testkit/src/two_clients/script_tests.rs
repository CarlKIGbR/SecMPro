// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Unit tests of the script's messages (TC-04's generator) and the hex helpers of the files.

use super::cli::Script;
use super::run::{hex, msg_id, payload, unhex};

#[test]
fn payloads_are_seeded_and_cover_the_range() {
    let script = Script {
        messages: 100,
        size_min: 1,
        size_max: 65_535,
        seed: 11,
        interval_s: 0,
    };
    let sizes: Vec<usize> = (0..100).map(|i| payload(&script, 0, i).len()).collect();
    assert!(sizes.iter().all(|n| (1..=65_535).contains(n)));
    assert!(*sizes.iter().min().unwrap() < 8_000, "{sizes:?}");
    assert!(*sizes.iter().max().unwrap() > 50_000, "{sizes:?}");
    // the same script gives the same bytes; the other direction and the other seed give other bytes
    assert_eq!(payload(&script, 0, 5), payload(&script, 0, 5));
    assert_ne!(payload(&script, 0, 5), payload(&script, 1, 5));
    let other = Script { seed: 12, ..script };
    assert_ne!(payload(&script, 0, 5), payload(&other, 0, 5));
    // a one-size script
    let fixed = Script {
        size_min: 40,
        size_max: 40,
        ..script
    };
    assert!((0..20).all(|i| payload(&fixed, 1, i).len() == 40));
}

#[test]
fn message_ids_are_distinct_per_direction_and_ordinal() {
    let mut ids = std::collections::BTreeSet::new();
    for dir in 0..2 {
        for idx in 0..500 {
            assert!(ids.insert(msg_id(dir, idx)));
        }
    }
}

#[test]
fn hex_round_trip_and_refusals() {
    let bytes = [0x00, 0x7f, 0x80, 0xff, 0x10];
    assert_eq!(unhex(&hex(&bytes)).unwrap(), bytes);
    assert_eq!(hex(&[0xab, 0x01]), "ab01");
    for bad in ["a", "zz", "0g", "abc"] {
        assert!(unhex(bad).is_none(), "{bad}");
    }
}
