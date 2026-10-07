// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]
//! M2 review C4: the libFuzzer `-max_len` table `FUZZ_MAX_LEN` of `xtask/src/expect.rs` holds, per fuzz target, the
//! largest valid input plus one byte. This test reads the table (as the ct bench reads its parameters) and
//! recomputes every entry from `sizes.rs`, the `secmp-crypto` constants and live encodings, so the table cannot
//! drift from the structures it bounds.

use secmp_crypto::{MLDSA65_PK_LEN, MLDSA65_SIG_LEN, MSG_SEALED_LEN, Zeroizing};
use secmp_proto::sizes::{
    CELL_LEN, CONTENT_BODY_MAX, ED25519_PK_LEN, ED25519_SIG_LEN, FRAGMENT_HEADER_LEN, FRAME_LEN,
    FRAME_PLAINTEXT_LEN, HANDSHAKE_CELL_PT_LEN, HEADER_LEN, HOST_MAX, HS1_LEN, HYBRID_SIG_LEN,
    ID_LEN, INNER_LEN, LINK_BLOB_LEN, LINKDATA_PADDED_LEN, MAX_MSG_BYTES, MLKEM1024_CT_LEN,
    MLKEM1024_EK_LEN, NAME_MAX, NONCE_LEN, OUTER_PADDED_LEN, PREKEY_BUNDLE_LEN, RELAYINFO_LEN,
    X25519_PK_LEN,
};
use secmp_proto::tr::RatchetState;
use secmp_proto::tr::content::Inbox;
use secmp_proto::wire::Period;
use secmp_proto::wire::cell::{Cell, HandshakeBody, RouteDescriptor};
use secmp_proto::wire::inv::{Direct, Host, InvitationV1, Onion, Profile, RelayRef};
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

/// The URI length of the largest invitation: a `direct` endpoint with a 253-byte host; the URI is the prefix and the
/// unpadded base64url of the encoding.
fn largest_invitation_uri_len() -> Result<usize, Error> {
    let invitation = InvitationV1 {
        relay: RelayRef {
            relay_fp: [0; 32],
            onion: Onion::from_pubkey(&[0; 32]),
            akc: [0; 32],
            direct: Some(Direct {
                host: Host::from_bytes(&vec![b'a'; HOST_MAX])?,
                port: core::num::NonZeroU16::MIN,
                spki_sha256: [0; 32],
            }),
        },
        ld_id: [0; 16],
        link_key: secmp_crypto::SecretBytes::from_slice(&[0; 32])?,
        inviter_fp: [0; 32],
        inv_sid: [0; 16],
        inv_send_seed: secmp_crypto::SecretBytes::from_slice(&[0; 32])?,
        inv_period_s: Period::S10,
        expires: 0,
    };
    Ok(secmp_proto::inv::invitation_uri(&invitation)?.len())
}

/// The SecMP-LINK/Q targets (M5, Phase A).
fn link_entries() -> [(&'static str, usize); 6] {
    [
        // selector, record `len` u16, type byte, then the HS1 fields (the largest record)
        ("link_records", sum(&[1, 2, 1, HS1_LEN])),
        // selector, flag byte, then the RELAYINFO record (`len`, type, `RelayInfoV1`) of the raw mode
        ("link_client_handshake", sum(&[1, 1, 2, 1, RELAYINFO_LEN])),
        ("link_relay_handshake", sum(&[1, 2, 1, HS1_LEN])),
        // selector, then a unit (the raw mode; the others take at most 4339)
        ("link_frame_open", sum(&[1, FRAME_LEN])),
        // selector / mode byte, then a frame plaintext
        ("q_request_decode", sum(&[1, FRAME_PLAINTEXT_LEN])),
        ("q_response_decode", sum(&[1, FRAME_PLAINTEXT_LEN])),
    ]
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
    // the largest `InboxV1` with one message of one chunk: fmt, count 1, msg_id, total 2, present 1, idx 0, a
    // maximal chunk (the Content body limit minus the fragment header) — decoded and re-encoded live
    let chunk = CONTENT_BODY_MAX.saturating_sub(FRAGMENT_HEADER_LEN);
    let chunk_len = u16::try_from(chunk).map_err(|_| Error::Rejected)?;
    let inbox_bytes = [
        &[1_u8, 1][..],
        &[0; ID_LEN],
        &[0, 2, 1, 0, 0],
        &chunk_len.to_be_bytes(),
        &vec![7; chunk],
    ]
    .concat();
    let inbox = Inbox::from_bytes(&inbox_bytes)?.to_bytes()?.len();
    let uri = largest_invitation_uri_len()?;
    let expected: Vec<(&str, usize)> = [
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
        // the URI of the largest invitation
        ("inv_uri", uri),
        // mode, then an opened `LinkDataV1` (mode 0) or a blob (mode 1)
        (
            "inv_linkdata",
            sum(&[1, LINKDATA_PADDED_LEN.max(LINK_BLOB_LEN)]),
        ),
        ("hx_outer", OUTER_PADDED_LEN),
        ("hx_inner", INNER_LEN),
        ("hx_cell_plaintext", HANDSHAKE_CELL_PT_LEN),
        // count, then 12 cells of selector 3 ‖ 4096 raw bytes
        ("hx_accept_raw", sum(&[1, 12 * (1 + 4096)])),
        // selector, then `Padded`, `Inner` or the `Outer` head (the fields before `inner_ct`)
        (
            "hx_accept_structured",
            sum(&[1, OUTER_PADDED_LEN.max(INNER_LEN)]),
        ),
        ("proto_cell", sum(&[1, handshake])),
        ("proto_frames", sum(&[1, FRAME_PLAINTEXT_LEN])),
        ("proto_handshake", sum(&[1, OUTER_PADDED_LEN])),
        ("proto_invitation", sum(&[1, LINK_BLOB_LEN])),
        // selector, record `len` u16, type byte, HS1 fields
        ("proto_records", sum(&[1, 2, 1, HS1_LEN])),
        // mode, then a cell (mode 0) or a header plaintext (modes 1–4)
        ("tr_decrypt", sum(&[1, CELL_LEN.max(HEADER_LEN)])),
        // selector, then `RatchetStateV1` or `InboxV1`
        (
            "tr_state",
            sum(&[1, RatchetState::MAX_ENCODED_LEN.max(inbox)]),
        ),
    ]
    .into_iter()
    .chain(link_entries())
    .collect();
    assert_eq!(handshake, 65_642);
    assert_eq!(send, 4_146);
    assert_eq!(inbox, 1_694);
    assert_eq!(uri, 717);
    assert_eq!(RatchetState::MAX_ENCODED_LEN, 38_585);
    let table = table();
    assert_eq!(table.len(), expected.len(), "{table:?}");
    for (name, largest) in expected {
        let entry = table.iter().find(|(n, _)| n == name).map(|(_, v)| *v);
        assert_eq!(entry, Some(sum(&[largest, 1])), "{name}");
    }
    Ok(())
}
