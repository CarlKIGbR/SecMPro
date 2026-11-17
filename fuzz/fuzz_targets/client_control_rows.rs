// SPDX-License-Identifier: AGPL-3.0-or-later
//! FZ-05 `client_control_rows` (M7 FZ; OPEN-M7-B-29 (2), D-B94; CLAUDE.md §1.8, §2.4): the decoders of the rows of a
//! session's CONTROL part, which `open_conversation` reads back from the store and classifies with `control_row_of`
//! (`sessions/mod.rs`, a row that does not decode fails the open, Q251, Q255) — `marker_of` (tag 4, Q248), `overlap_of`
//! (tag 5, Q252) and `PendingControl::decode` (tags 1–3), with their encoders `marker_row`, `OverlapRoute::row` and
//! `PendingControl::encode`. No store, no crypto: the functions see the row's bytes only.
//!
//! Input: `mode u8 ‖ rest`.
//! - Even mode: `rest` is a CONTROL row.
//! - Odd mode: `rest` gives the fields of a marker, an overlap, a `Control` and a `RouteUpdate` (zeros once it is
//!   exhausted), then one edit; the four rows are encoded, checked against their byte layout and decoded back, and each
//!   is checked as a row before and after the edit (set, xor, drop the last byte, append a byte).
//!
//! Every row: no panic; the tag dispatch — `marker_of` is none exactly for a row not of tag 4 (the empty row included),
//! `overlap_of` exactly for a row not of tag 5, `PendingControl::decode` refuses every tag but 1, 2, 3 — so at most one
//! decoder accepts; the field rules restated from the bytes (a marker is 25 bytes with a non-negative `ord`; an overlap
//! is 68 bytes with a period of `PERIODS` = {10, 20, 40, 80} and a flag 0 or 1; a `Control` row is `2 ‖ code 1|2 ‖ 0 0`);
//! whatever a decoder accepts re-encodes to exactly the row (canonical) and names the fields at their offsets
//! (big-endian); and the class `control_row_of` gives the row — the function `open_conversation` classifies every row
//! with (marker, overlap, content, or a failed open), with the payload of the row's decoder — is the one these rules give
//! and the one the leaf decoders give in the reverse order (a differential check against an independent restatement).
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_client_core::sessions::actor::{
    ControlRow, OverlapRoute, PendingControl, control_row_of, marker_of, marker_row, overlap_of,
};
use secmp_crypto::{SecretBytes, Zeroizing};
use secmp_proto::wire::Period;
use secmp_proto::wire::cell::{ControlCode, KeyChangeBody, RouteDescriptor, RouteUpdateBody};
use secmp_proto::{Decode as _, Encode as _};

/// The class of a row at an open (`open_conversation`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    Marker,
    Overlap,
    Content,
    /// The open fails (`Error::Unavailable`).
    Fails,
}

/// The class the product gives the row at an open: `control_row_of`, which `open_conversation` calls; an error fails the
/// open. Its payload must be what the decoder of the row's tag returns.
fn open_class(row: &[u8]) -> Class {
    match control_row_of(row) {
        Ok(ControlRow::Marker { key_change, sid }) => {
            assert_eq!(
                marker_of(row),
                Ok(Some((key_change, sid))),
                "the marker of the row"
            );
            Class::Marker
        }
        Ok(ControlRow::Overlap(route)) => {
            assert_eq!(route.row().as_slice(), row, "the overlap of the row");
            Class::Overlap
        }
        Ok(ControlRow::Pending(content)) => {
            let again = content.encode().expect("an accepted content encodes");
            assert_eq!(again.as_slice(), row, "the content of the row");
            Class::Content
        }
        Err(_) => Class::Fails,
    }
}

/// The independent oracle: the three leaf decoders in the reverse order.
fn reverse_class(row: &[u8]) -> Class {
    if PendingControl::decode(row).is_ok() {
        return Class::Content;
    }
    match overlap_of(row) {
        Err(_) => return Class::Fails,
        Ok(Some(_)) => return Class::Overlap,
        Ok(None) => {}
    }
    match marker_of(row) {
        Ok(Some(_)) => Class::Marker,
        _ => Class::Fails,
    }
}

fn be_u64(row: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(row.get(at..at + 8)?.try_into().ok()?))
}

/// Every property of one row.
fn check_row(row: &[u8]) {
    let tag = row.first().copied();
    let marker = marker_of(row);
    let overlap = overlap_of(row);
    let content = PendingControl::decode(row);
    // the tag dispatch
    assert_eq!(
        matches!(marker, Ok(None)),
        tag != Some(4),
        "marker_of: none exactly off tag 4"
    );
    assert_eq!(
        matches!(overlap, Ok(None)),
        tag != Some(5),
        "overlap_of: none exactly off tag 5"
    );
    if !matches!(tag, Some(1..=3)) {
        assert!(
            content.is_err(),
            "PendingControl::decode accepts only tags 1, 2, 3"
        );
    }
    // the field rules, restated from the bytes
    let marker_ok = tag == Some(4) && row.len() == 25 && row.get(1).is_some_and(|b| *b < 0x80);
    let period = row.get(49..51).map(|p| u16::from_be_bytes([p[0], p[1]]));
    let overlap_ok = tag == Some(5)
        && row.len() == 68
        && period.is_some_and(|p| [10, 20, 40, 80].contains(&p))
        && row.get(67).is_some_and(|f| *f <= 1);
    assert_eq!(
        matches!(marker, Ok(Some(_))),
        marker_ok,
        "marker field rules"
    );
    assert_eq!(
        matches!(overlap, Ok(Some(_))),
        overlap_ok,
        "overlap field rules"
    );
    if tag == Some(2) {
        let control_ok = row.len() == 4
            && matches!(row.get(1), Some(1 | 2))
            && row.get(2..4) == Some(&[0, 0][..]);
        assert_eq!(
            content.is_ok(),
            control_ok,
            "a Control row is 2 ‖ code ‖ 0 0"
        );
    }
    // at most one decoder accepts
    let accepted = [
        matches!(marker, Ok(Some(_))),
        matches!(overlap, Ok(Some(_))),
        content.is_ok(),
    ];
    assert!(
        accepted.iter().filter(|a| **a).count() <= 1,
        "two decoders accept one row"
    );
    // canonical, and the fields at their offsets
    if let Ok(Some((ord, sid))) = &marker {
        assert_eq!(marker_row(*ord, sid), row, "a marker re-encodes to its row");
        assert_eq!(
            Some(ord.to_be_bytes().as_slice()),
            row.get(1..9),
            "ord, big-endian"
        );
        assert_eq!(Some(sid.as_slice()), row.get(9..25), "sid");
    }
    if let Ok(Some(r)) = &overlap {
        assert_eq!(r.row().as_slice(), row, "an overlap re-encodes to its row");
        assert_eq!(Some(r.sid.as_slice()), row.get(1..17), "sid");
        assert_eq!(
            Some(r.seed.expose_secret().as_slice()),
            row.get(17..49),
            "seed"
        );
        assert_eq!(Some(r.period.seconds()), period, "period, big-endian");
        assert_eq!(Some(r.until_ms), be_u64(row, 51), "until_ms, big-endian");
        assert_eq!(Some(r.newest), be_u64(row, 59), "newest, big-endian");
        assert_eq!(Some(u8::from(r.unknown)), row.get(67).copied(), "flag");
    }
    if let Ok(c) = &content {
        let again = c.encode().expect("an accepted content encodes");
        assert_eq!(again.as_slice(), row, "a content re-encodes to its row");
    }
    // the class at an open
    let class = open_class(row);
    let want = match tag {
        Some(4) if marker_ok => Class::Marker,
        Some(5) if overlap_ok => Class::Overlap,
        Some(1..=3) if content.is_ok() => Class::Content,
        _ => Class::Fails,
    };
    assert_eq!(class, want, "the class at an open");
    assert_eq!(
        reverse_class(row),
        class,
        "the order of the decoders does not matter"
    );
    // the body of a content row: tag 1 a `RouteUpdateBody`, tag 3 a `KeyChangeBody`, by the wire decoders alone
    match (tag, row.get(1..)) {
        (Some(1), Some(body)) => assert_eq!(
            content.is_ok(),
            RouteUpdateBody::decode(body).is_ok(),
            "a RouteUpdate row is 1 ‖ RouteUpdateBody"
        ),
        (Some(3), Some(body)) => assert_eq!(
            content.is_ok(),
            KeyChangeBody::decode(body).is_ok(),
            "a KeyChange row is 3 ‖ KeyChangeBody"
        ),
        _ => {}
    }
}

/// The input's bytes, zeros once they are exhausted.
struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0; N];
        let n = N.min(self.0.len());
        out[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        out
    }
    fn u8(&mut self) -> u8 {
        self.take::<1>()[0]
    }
}

/// The edit of the odd mode: 0 none, 1 set a byte, 2 xor a byte, 3 drop the last byte, 4 append a byte.
fn edit(row: &[u8], op: u8, at: u16, value: u8) -> Vec<u8> {
    let mut out = row.to_vec();
    let at = usize::from(at) % out.len().max(1);
    match op % 5 {
        1 => {
            if let Some(b) = out.get_mut(at) {
                *b = value;
            }
        }
        2 => {
            if let Some(b) = out.get_mut(at) {
                *b ^= value;
            }
        }
        3 => {
            out.pop();
        }
        4 => out.push(value),
        _ => {}
    }
    out
}

fn structured(rest: &[u8]) {
    let mut b = Bytes(rest);
    let sid: [u8; 16] = b.take();
    let seed: [u8; 32] = b.take();
    let period = Period::ALL[usize::from(b.u8()) % Period::ALL.len()];
    let until_ms = u64::from_be_bytes(b.take());
    let newest = u64::from_be_bytes(b.take());
    let unknown = b.u8() & 1 == 1;
    let ord = i64::from_be_bytes(b.take());
    let code = if b.u8() & 1 == 0 {
        ControlCode::ContactRemoved
    } else {
        ControlCode::SessionResetRequest
    };
    let kind = b.u8();
    let blob_len = usize::from(u16::from_be_bytes(b.take())) % 64;
    let blob: Vec<u8> = (0..blob_len).map(|_| b.u8()).collect();
    let (op, at, value) = (b.u8(), u16::from_be_bytes(b.take()), b.u8());

    // a marker: `4 ‖ ord ‖ sid`; decodes back exactly for a non-negative `ord`
    let m = marker_row(ord, &sid);
    let want = [&[4][..], &ord.to_be_bytes(), &sid].concat();
    assert_eq!(m, want, "marker layout");
    if ord >= 0 {
        assert_eq!(marker_of(&m), Ok(Some((ord, sid))), "marker round trip");
    } else {
        assert!(marker_of(&m).is_err(), "a negative ord is refused");
    }
    // an overlap: `5 ‖ sid ‖ seed ‖ period ‖ until ‖ newest ‖ flag`, 68 bytes
    let route = OverlapRoute {
        sid,
        seed: SecretBytes::from_slice(&seed).expect("32 bytes"),
        period,
        until_ms,
        newest,
        unknown,
    };
    let o = route.row();
    let want = [
        &[5][..],
        &sid,
        &seed,
        &period.seconds().to_be_bytes(),
        &until_ms.to_be_bytes(),
        &newest.to_be_bytes(),
        &[u8::from(unknown)],
    ]
    .concat();
    assert_eq!(o.as_slice(), want.as_slice(), "overlap layout");
    let back = overlap_of(&o).expect("an overlap decodes").expect("tag 5");
    assert!(
        back.sid == sid
            && back.seed.expose_secret() == &seed
            && back.period == period
            && back.until_ms == until_ms
            && back.newest == newest
            && back.unknown == unknown,
        "overlap round trip"
    );
    // a `Control` without an argument: `2 ‖ code ‖ 0 0`
    let c = PendingControl::Control(code)
        .encode()
        .expect("a Control encodes");
    let byte = if code == ControlCode::ContactRemoved {
        1
    } else {
        2
    };
    assert_eq!(c.as_slice(), [2, byte, 0, 0], "Control layout");
    assert!(
        matches!(PendingControl::decode(&c), Ok(PendingControl::Control(back)) if back == code),
        "Control round trip"
    );
    // a `RouteUpdate` of one route of another kind than 1: `1 ‖ body`
    let kind = if kind == 1 { 2 } else { kind };
    let routes = PendingControl::Routes(RouteUpdateBody {
        routes: vec![RouteDescriptor::Unknown {
            kind,
            blob: Zeroizing::new(blob.clone()),
        }],
    });
    let r = routes.encode().expect("a RouteUpdate encodes");
    let body = RouteUpdateBody {
        routes: vec![RouteDescriptor::Unknown {
            kind,
            blob: Zeroizing::new(blob.clone()),
        }],
    }
    .encode()
    .expect("a body encodes");
    assert_eq!(
        r.as_slice(),
        [&[1][..], &body].concat().as_slice(),
        "RouteUpdate layout"
    );
    match PendingControl::decode(&r) {
        Ok(PendingControl::Routes(got)) => assert!(
            matches!(got.routes.as_slice(), [RouteDescriptor::Unknown { kind: k, blob: g }] if *k == kind && g.as_slice() == blob.as_slice()),
            "RouteUpdate round trip"
        ),
        _ => panic!("a RouteUpdate decodes as one"),
    }
    for row in [m.as_slice(), o.as_slice(), c.as_slice(), r.as_slice()] {
        check_row(row);
        check_row(&edit(row, op, at, value));
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 1 == 0 {
        check_row(rest);
    } else {
        structured(rest);
    }
});
