// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The D.5 cell, header, content and body decoders of `secmp-proto` on arbitrary bytes: never panic, and whatever
//! they accept re-encodes to exactly its input (total, exact-fit, canonical: docs/06 §4). The first byte selects
//! the decoder: 0 `Cell`, 1 `HeaderV1`, 2 `Content`, 3 `AppMessage`, 4 `BatchBody`, 5 `Fragment`,
//! 6 `FragmentPayload`, 7 `RouteDescriptor`, 8 `RelayQueue`, 9 `RouteUpdateBody`, 10 `HandshakeBody`,
//! 11 `KeyChangeBody`, 12 `ReceiptBody`, 13 `ControlBody` (modulo 14).
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::wire::cell::{
    AppMessage, BatchBody, Cell, Content, ControlBody, Fragment, FragmentPayload, HandshakeBody,
    HeaderV1, KeyChangeBody, ReceiptBody, RelayQueue, RouteDescriptor, RouteUpdateBody,
};
use secmp_proto::{Decode, Encode};

/// Decode as `T`; an accepted input re-encodes to itself.
fn canonical<T: Decode + Encode>(bytes: &[u8]) {
    if let Ok(v) = T::decode(bytes) {
        assert_eq!(v.encode().unwrap().as_slice(), bytes);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, bytes)) = data.split_first() else {
        return;
    };
    match selector % 14 {
        0 => canonical::<Cell>(bytes),
        1 => canonical::<HeaderV1>(bytes),
        2 => canonical::<Content>(bytes),
        3 => canonical::<AppMessage>(bytes),
        4 => canonical::<BatchBody>(bytes),
        5 => canonical::<Fragment>(bytes),
        6 => canonical::<FragmentPayload>(bytes),
        7 => canonical::<RouteDescriptor>(bytes),
        8 => canonical::<RelayQueue>(bytes),
        9 => canonical::<RouteUpdateBody>(bytes),
        10 => canonical::<HandshakeBody>(bytes),
        11 => canonical::<KeyChangeBody>(bytes),
        12 => canonical::<ReceiptBody>(bytes),
        _ => canonical::<ControlBody>(bytes),
    }
});
