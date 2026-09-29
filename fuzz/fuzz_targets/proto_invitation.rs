// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The D.3 invitation and link-data decoders of `secmp-proto` on arbitrary bytes: never panic, and whatever they
//! accept re-encodes to exactly its input (total, exact-fit, canonical: docs/06 §4). The first byte selects the
//! decoder: 0 `RelayRef`, 1 `InvitationV1`, 2 `Profile`, 3 `LinkDataV1`, 4 `LinkBlob`, 5 `IKSPublic`,
//! 6 `PrekeyBundle` (modulo 7).
#![no_main]

use libfuzzer_sys::fuzz_target;
use secmp_proto::wire::inv::{
    IksPublic, InvitationV1, LinkBlob, LinkDataV1, PrekeyBundle, Profile, RelayRef,
};
use secmp_proto::{Decode, Encode};

/// Decode as `T`; an accepted input re-encodes to itself.
fn canonical<T: Decode + Encode>(bytes: &[u8]) {
    if let Ok(v) = T::decode(bytes) {
        assert_eq!(v.encode().unwrap(), bytes);
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, bytes)) = data.split_first() else {
        return;
    };
    match selector % 7 {
        0 => canonical::<RelayRef>(bytes),
        1 => canonical::<InvitationV1>(bytes),
        2 => canonical::<Profile>(bytes),
        3 => canonical::<LinkDataV1>(bytes),
        4 => canonical::<LinkBlob>(bytes),
        5 => canonical::<IksPublic>(bytes),
        _ => canonical::<PrekeyBundle>(bytes),
    }
});
