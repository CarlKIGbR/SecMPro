// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]
//! M2 review C4: the libFuzzer `-max_len` table `FUZZ_MAX_LEN` of `xtask/src/expect.rs` holds, per fuzz target, the
//! largest valid input plus one byte. This test reads the table (as the ct bench reads its parameters) and
//! recomputes every entry from `sizes.rs`, the `secmp-crypto` constants and live encodings, so the table cannot
//! drift from the structures it bounds.

use secmp_crypto::{MLDSA65_PK_LEN, MLDSA65_SIG_LEN, MSG_SEALED_LEN, Zeroizing};
use secmp_proto::sizes::{
    CELL_LEN, ED25519_PK_LEN, ED25519_SIG_LEN, FRAME_PLAINTEXT_LEN, HS1_LEN, HYBRID_SIG_LEN,
    LINK_BLOB_LEN, MAX_MSG_BYTES, MLKEM1024_CT_LEN, MLKEM1024_EK_LEN, NAME_MAX, NONCE_LEN,
    OUTER_PADDED_LEN, PREKEY_BUNDLE_LEN, X25519_PK_LEN,
};
use secmp_proto::wire::cell::{Cell, HandshakeBody, RouteDescriptor};
use secmp_proto::wire::inv::Profile;
use secmp_proto::wire::signed;
use secmp_proto::{Encode, Error};

const EXPECT_RS: &str = include_str!("../../../xtask/src/expect.rs");

/// The largest `u8` length (the `ad_len` and `ctx_len` bytes of the M1 targets).
const U8_MAX_LEN: usize = 255;

/// `("name", 12_345),` lines of `FUZZ_MAX_LEN`.
fn table() -> Vec<(String, usize)> {
    EXPECT_RS
        .lines()
        .skip_while(|l| !l.starts_with("pub(crate) const FUZZ_MAX_LEN"))
        .skip(1)
        .take_while(|l| !l.starts_with("];"))
        .filter_map(|l| {
            let (name, n) = l.trim().strip_prefix("(\"")?.split_once("\", ")?;
            let n = n.strip_suffix("),")?.replace('_', "").parse().ok()?;
            Some((name.to_owned(), n))
        })
        .collect()
}

fn sum(parts: &[usize]) -> usize {
    parts.iter().fold(0, |a, b| a.saturating_add(*b))
}

#[test]
fn fuzz_max_len_is_the_largest_valid_input_plus_one() -> Result<(), Error> {
    // the largest `HandshakeBody`: a 64-byte name with an avatar, one route of an unknown kind with a full blob
    let handshake = HandshakeBody {
        profile: Profile::new(&"a".repeat(NAME_MAX), Some([0; 32]))?,
        routes: vec![RouteDescriptor::Unknown {
            kind: 2,
            blob: Zeroizing::new(vec![0; MAX_MSG_BYTES]),
        }],
    }
    .encode()?
    .len();
    // the largest Ed25519-signed message: D.6 `SEND` (it carries a whole cell)
    let send = signed::send(&[0; 16], 0, &[0; 16], &Cell::from_bytes(&[0; CELL_LEN])?).len();
    let bundle_message = sum(&[
        PREKEY_BUNDLE_LEN.saturating_sub(HYBRID_SIG_LEN),
        X25519_PK_LEN,
    ]);
    let expected: [(&str, usize); 12] = [
        // mode, nonce, ad_len, AD, `COM ‖ C` of a LinkBlob
        (
            "caead_open",
            sum(&[
                1,
                NONCE_LEN,
                1,
                U8_MAX_LEN,
                LINK_BLOB_LEN.saturating_sub(NONCE_LEN),
            ]),
        ),
        (
            "ed25519_verify",
            sum(&[ED25519_PK_LEN, ED25519_SIG_LEN, send]),
        ),
        (
            "hybrid_sign_verify",
            sum(&[1, 1, HYBRID_SIG_LEN, bundle_message]),
        ),
        (
            "mldsa65_verify",
            sum(&[
                1,
                MLDSA65_PK_LEN.max(sum(&[1, U8_MAX_LEN, MLDSA65_SIG_LEN])),
            ]),
        ),
        (
            "mlkem_parse",
            sum(&[1, MLKEM1024_EK_LEN.max(MLKEM1024_CT_LEN)]),
        ),
        ("msg_open", sum(&[1, 1, U8_MAX_LEN, MSG_SEALED_LEN])),
        (
            "x25519_dh",
            sum(&[X25519_PK_LEN, X25519_PK_LEN, X25519_PK_LEN]),
        ),
        ("proto_cell", sum(&[1, handshake])),
        ("proto_frames", sum(&[1, FRAME_PLAINTEXT_LEN])),
        ("proto_handshake", sum(&[1, OUTER_PADDED_LEN])),
        ("proto_invitation", sum(&[1, LINK_BLOB_LEN])),
        // selector, record `len` u16, type byte, HS1 fields
        ("proto_records", sum(&[1, 2, 1, HS1_LEN])),
    ];
    assert_eq!(handshake, 65_642);
    assert_eq!(send, 4_146);
    let table = table();
    assert_eq!(table.len(), expected.len(), "{table:?}");
    for (name, largest) in expected {
        let entry = table.iter().find(|(n, _)| n == name).map(|(_, v)| *v);
        assert_eq!(entry, Some(sum(&[largest, 1])), "{name}");
    }
    Ok(())
}
