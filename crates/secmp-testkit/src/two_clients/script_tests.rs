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
        start_s: 0,
        bursts: 0,
        burst_size: 20,
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

#[test]
fn the_schedule_of_the_active_hour() {
    // AI-07: an idle hour, then 120 messages 30 s apart and 10 bursts of 20, one every 360 s from 180 s after the start
    let s = Script {
        messages: 120 + 200,
        size_min: 1,
        size_max: 1_000,
        seed: 1,
        interval_s: 30,
        start_s: 3_600,
        bursts: 10,
        burst_size: 20,
    };
    assert_eq!(s.enqueue_at_ms(0), 3_600_000);
    assert_eq!(s.enqueue_at_ms(119), 3_600_000 + 119 * 30_000);
    assert_eq!(s.enqueue_at_ms(120), 3_600_000 + 180_000);
    assert_eq!(s.enqueue_at_ms(139), 3_600_000 + 180_000);
    assert_eq!(s.enqueue_at_ms(140), 3_600_000 + 540_000);
    assert_eq!(s.enqueue_at_ms(319), 3_600_000 + 180_000 + 9 * 360_000);
    // every message falls in the active hour
    assert!((0..320).all(|i| (3_600_000..7_200_000).contains(&s.enqueue_at_ms(i))));
}
