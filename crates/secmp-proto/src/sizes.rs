// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sizes of spec Appendix B and §4.2, each re-derived at compile time from its Appendix D field list, and the
//! primitive sizes checked against `secmp-crypto`. A wrong constant or field list is a compile error.

/// The sum of field widths, or `usize::MAX` on overflow (which fails every assertion below).
const fn sum(mut parts: &[usize]) -> usize {
    let mut acc: usize = 0;
    while let Some((first, rest)) = parts.split_first() {
        acc = match acc.checked_add(*first) {
            Some(v) => v,
            None => return usize::MAX,
        };
        parts = rest;
    }
    acc
}

/// `PROTO_VER` (spec §4.2): the value of every `ver` field.
pub const PROTO_VER: u8 = 0x01;

/// X25519 public key.
pub const X25519_PK_LEN: usize = 32;
/// Ed25519 public key.
pub const ED25519_PK_LEN: usize = 32;
/// Ed25519 signature `R ‖ S`.
pub const ED25519_SIG_LEN: usize = 64;
/// ML-KEM-768 encapsulation key.
pub const MLKEM768_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext.
pub const MLKEM768_CT_LEN: usize = 1088;
/// ML-KEM-1024 encapsulation key.
pub const MLKEM1024_EK_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext.
pub const MLKEM1024_CT_LEN: usize = 1568;
/// ML-DSA-65 public key.
pub const MLDSA65_PK_LEN: usize = 1952;
/// ML-DSA-65 signature.
pub const MLDSA65_SIG_LEN: usize = 3309;
/// `HybridSig` = Ed25519 ‖ ML-DSA-65 (spec §3.5).
pub const HYBRID_SIG_LEN: usize = sum(&[ED25519_SIG_LEN, MLDSA65_SIG_LEN]);
/// 16-byte identifiers (`rid`, `sid`, `ld_id`, `msg_id`, `init_id`, `sess_id`).
pub const ID_LEN: usize = 16;
/// 32-byte values (hashes, tokens, MACs, seeds, keys).
pub const HASH_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag.
pub const AEAD_TAG_LEN: usize = 16;
/// CAEAD commitment (spec §3.4).
pub const COM_LEN: usize = 32;
/// v3 onion address `PUBKEY ‖ CHECKSUM ‖ VERSION` (spec §5.3).
pub const ONION_LEN: usize = sum(&[32, 2, 1]);

/// `IKSPublic` (App. B 2017).
pub const IKS_PUBLIC_LEN: usize = sum(&[1, ED25519_PK_LEN, MLDSA65_PK_LEN, X25519_PK_LEN]);
/// `PrekeyBundle` (App. B 7775).
pub const PREKEY_BUNDLE_LEN: usize = sum(&[
    1,
    4,
    X25519_PK_LEN,
    MLKEM1024_EK_LEN,
    MLKEM768_EK_LEN,
    8,
    1,
    4,
    X25519_PK_LEN,
    MLKEM1024_EK_LEN,
    HYBRID_SIG_LEN,
]);
/// `LinkDataV1` padded (App. B 12288).
pub const LINKDATA_PADDED_LEN: usize = 12_288;
/// `LinkBlob` (App. B 12360).
pub const LINK_BLOB_LEN: usize = sum(&[NONCE_LEN, COM_LEN, LINKDATA_PADDED_LEN, AEAD_TAG_LEN]);
/// The CAEAD ciphertext inside a `LinkBlob`.
pub const LINK_BLOB_CT_LEN: usize = sum(&[LINKDATA_PADDED_LEN, AEAD_TAG_LEN]);

/// `HeaderV1` (App. B 2314).
pub const HEADER_LEN: usize = sum(&[1, 1, X25519_PK_LEN, 4, 4, MLKEM768_EK_LEN, MLKEM768_CT_LEN]);
/// `hdr_ct` (App. B 2330).
pub const HDR_CT_LEN: usize = sum(&[HEADER_LEN, AEAD_TAG_LEN]);
/// `BODY_LEN` (spec §4.2): the padded `Content`.
pub const BODY_LEN: usize = 1710;
/// The `MsgEncrypt` tag.
pub const BODY_TAG_LEN: usize = 32;
/// `CELL_SIZE` (App. B 4096).
pub const CELL_LEN: usize = sum(&[NONCE_LEN, HDR_CT_LEN, BODY_LEN, BODY_TAG_LEN]);
/// `FRAME_SIZE` (App. B 4352).
pub const FRAME_LEN: usize = 4352;
/// Frame plaintext (App. B 4336).
pub const FRAME_PLAINTEXT_LEN: usize = 4336;
/// `Content` fields before the body: `ver ‖ type ‖ seq ‖ ts ‖ body_len`.
pub const CONTENT_HEADER_LEN: usize = sum(&[1, 1, 8, 8, 2]);
/// The largest `Content.body` (spec §7.6: ≤ 1689): the padded content minus its header and the marker.
pub const CONTENT_BODY_MAX: usize = 1689;
/// `KeyChange` body (spec §7.6: 5390, always fragmented).
pub const KEYCHANGE_BODY_LEN: usize = sum(&[IKS_PUBLIC_LEN, HYBRID_SIG_LEN]);
/// `Fragment` fields before the chunk.
pub const FRAGMENT_HEADER_LEN: usize = sum(&[ID_LEN, 2, 2]);

/// Handshake `Outer` (App. B 9362).
pub const OUTER_LEN: usize = sum(&[
    1,
    X25519_PK_LEN,
    4,
    4,
    MLKEM1024_CT_LEN,
    MLKEM1024_CT_LEN,
    INNER_CT_LEN,
]);
/// One handshake chunk (spec §6.5).
pub const HANDSHAKE_CHUNK_LEN: usize = 4006;
/// `Outer` padded to three chunks (App. B 12018).
pub const OUTER_PADDED_LEN: usize = sum(&[
    HANDSHAKE_CHUNK_LEN,
    HANDSHAKE_CHUNK_LEN,
    HANDSHAKE_CHUNK_LEN,
]);
/// `Inner = IKSPublic ‖ first_msg` (6113).
pub const INNER_LEN: usize = sum(&[IKS_PUBLIC_LEN, CELL_LEN]);
/// `inner_ct` (6185).
pub const INNER_CT_LEN: usize = sum(&[NONCE_LEN, COM_LEN, INNER_LEN, AEAD_TAG_LEN]);
/// The CAEAD ciphertext inside `inner_ct`.
pub const INNER_CT_CT_LEN: usize = sum(&[INNER_LEN, AEAD_TAG_LEN]);
/// `init_id ‖ i ‖ total ‖ chunk` (4024).
pub const HANDSHAKE_CELL_PT_LEN: usize = sum(&[ID_LEN, 1, 1, HANDSHAKE_CHUNK_LEN]);
/// A handshake cell (4096).
pub const HANDSHAKE_CELL_LEN: usize =
    sum(&[NONCE_LEN, COM_LEN, HANDSHAKE_CELL_PT_LEN, AEAD_TAG_LEN]);
/// The CAEAD ciphertext inside a handshake cell.
pub const HANDSHAKE_CELL_CT_LEN: usize = sum(&[HANDSHAKE_CELL_PT_LEN, AEAD_TAG_LEN]);
/// The chunk count of a handshake envelope (spec §6.5).
pub const HANDSHAKE_CHUNKS: u8 = 3;

/// `RelayInfoV1` (App. B 1741).
pub const RELAYINFO_LEN: usize = sum(&[
    1,
    ED25519_PK_LEN,
    4,
    X25519_PK_LEN,
    MLKEM1024_EK_LEN,
    HASH_LEN,
    8,
    ED25519_SIG_LEN,
]);
/// HS1 without its record type byte (App. B 2853).
pub const HS1_LEN: usize = sum(&[
    1,
    4,
    X25519_PK_LEN,
    MLKEM768_EK_LEN,
    X25519_PK_LEN,
    MLKEM1024_CT_LEN,
    HASH_LEN,
]);
/// HS2 without its record type byte (App. B 1153).
pub const HS2_LEN: usize = sum(&[1, X25519_PK_LEN, MLKEM768_CT_LEN, HASH_LEN]);
/// The HELLO record body `0x01 ‖ "SECMP" ‖ ver` (D.1: 7).
pub const HELLO_BODY_LEN: usize = sum(&[1, 5, 1]);

/// `blob_part` of `LINK_PUT`/`LINKR` frame 1 (D.2).
pub const BLOB_PART_LEN: usize = 4160;
/// `data` of a CONT frame (D.2).
pub const CONT_DATA_LEN: usize = 4100;

/// `RelayRef` without `direct` (101).
pub const RELAYREF_NO_DIRECT_LEN: usize = sum(&[1, HASH_LEN, ONION_LEN, HASH_LEN, 1]);
/// `InvitationV1` without `direct` (App. B 241).
pub const INVITATION_NO_DIRECT_LEN: usize = sum(&[
    1,
    1,
    RELAYREF_NO_DIRECT_LEN,
    ID_LEN,
    HASH_LEN,
    HASH_LEN,
    ID_LEN,
    HASH_LEN,
    2,
    8,
]);

/// `Profile.name` at most 64 bytes (D.3).
pub const NAME_MAX: usize = 64;
/// `RelayRef.direct.host` 1..=253 bytes (D.3, rev 2.3).
pub const HOST_MAX: usize = 253;
/// `FETCH_MULTI` 1..=32 entries (D.2).
pub const FETCH_MULTI_MAX: usize = 32;
/// Fragment `total` 2..=64 (D.5, rev 2.3).
pub const FRAGMENT_TOTAL_MIN: u16 = 2;
/// Fragment `total` 2..=64 (D.5, rev 2.3).
pub const FRAGMENT_TOTAL_MAX: u16 = 64;
/// `MAX_MSG_BYTES` (spec §4.2).
pub const MAX_MSG_BYTES: usize = 65_535;

// ---- Appendix B -----------------------------------------------------------------------------------------------
const _: () = assert!(HYBRID_SIG_LEN == 3373);
const _: () = assert!(IKS_PUBLIC_LEN == 2017);
const _: () = assert!(PREKEY_BUNDLE_LEN == 7775);
const _: () = assert!(LINK_BLOB_LEN == 12_360);
const _: () = assert!(HEADER_LEN == 2314 && HDR_CT_LEN == 2330);
const _: () = assert!(CELL_LEN == 4096);
const _: () = assert!(sum(&[FRAME_PLAINTEXT_LEN, AEAD_TAG_LEN]) == FRAME_LEN);
const _: () = assert!(sum(&[CELL_LEN, 240]) == FRAME_PLAINTEXT_LEN);
const _: () =
    assert!(OUTER_LEN == 9362 && OUTER_PADDED_LEN == 12_018 && OUTER_LEN < OUTER_PADDED_LEN);
const _: () = assert!(INNER_LEN == 6113 && INNER_CT_LEN == 6185);
const _: () = assert!(HANDSHAKE_CELL_PT_LEN == 4024 && HANDSHAKE_CELL_LEN == 4096);
const _: () = assert!(RELAYINFO_LEN == 1741 && HS1_LEN == 2853 && HS2_LEN == 1153);
const _: () = assert!(HELLO_BODY_LEN == 7);
const _: () = assert!(INVITATION_NO_DIRECT_LEN == 241 && RELAYREF_NO_DIRECT_LEN == 101);
// spec §4.2 / §7.6: the largest body leaves room for the header and the padding marker
const _: () = assert!(sum(&[CONTENT_HEADER_LEN, CONTENT_BODY_MAX, 1]) == BODY_LEN);
const _: () = assert!(KEYCHANGE_BODY_LEN == 5390 && KEYCHANGE_BODY_LEN > CONTENT_BODY_MAX);
// D.2: the blob travels in three frames; every frame's fields leave room for the marker
const _: () = assert!(sum(&[BLOB_PART_LEN, CONT_DATA_LEN, CONT_DATA_LEN]) == LINK_BLOB_LEN);
const _: () = assert!(
    sum(&[
        1,
        4,
        ID_LEN,
        1,
        4,
        ED25519_PK_LEN,
        HASH_LEN,
        ED25519_SIG_LEN,
        BLOB_PART_LEN
    ]) < FRAME_PLAINTEXT_LEN
);
const _: () = assert!(sum(&[1, 4, ID_LEN, CELL_LEN, ED25519_SIG_LEN]) < FRAME_PLAINTEXT_LEN);
const _: () = assert!(sum(&[1, 4, 1, ID_LEN, 8, CELL_LEN]) < FRAME_PLAINTEXT_LEN);
const _: () = assert!(sum(&[1, 4, 1, CONT_DATA_LEN]) < FRAME_PLAINTEXT_LEN);
// FETCH_MULTI with 32 entries: 1 + 4 + 1 + 32 × 88 = 2822
const _: () = assert!(
    sum(&[
        6, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88, 88,
        88, 88, 88, 88, 88, 88, 88, 88, 88, 88
    ]) == 2822
);
const _: () = assert!(sum(&[ID_LEN, 8, ED25519_SIG_LEN]) == 88);

// ---- agreement with secmp-crypto ------------------------------------------------------------------------------
const _: () = assert!(X25519_PK_LEN == secmp_crypto::X25519_LEN);
const _: () = assert!(ED25519_PK_LEN == secmp_crypto::ED25519_PK_LEN);
const _: () = assert!(ED25519_SIG_LEN == secmp_crypto::ED25519_SIG_LEN);
const _: () = assert!(MLKEM768_EK_LEN == secmp_crypto::MLKEM768_EK_LEN);
const _: () = assert!(MLKEM768_CT_LEN == secmp_crypto::MLKEM768_CT_LEN);
const _: () = assert!(MLKEM1024_EK_LEN == secmp_crypto::MLKEM1024_EK_LEN);
const _: () = assert!(MLKEM1024_CT_LEN == secmp_crypto::MLKEM1024_CT_LEN);
const _: () = assert!(MLDSA65_PK_LEN == secmp_crypto::MLDSA65_PK_LEN);
const _: () = assert!(MLDSA65_SIG_LEN == secmp_crypto::MLDSA65_SIG_LEN);
const _: () = assert!(HYBRID_SIG_LEN == secmp_crypto::HYBRID_SIG_LEN);
const _: () = assert!(IKS_PUBLIC_LEN == secmp_crypto::IKS_PUBLIC_LEN);
const _: () = assert!(BODY_LEN == secmp_crypto::BODY_LEN);
const _: () = assert!(NONCE_LEN == secmp_crypto::NONCE_LEN);
const _: () = assert!(COM_LEN == secmp_crypto::COM_LEN);
const _: () = assert!(AEAD_TAG_LEN == secmp_crypto::AEAD_TAG_LEN);
const _: () = assert!(BODY_TAG_LEN == secmp_crypto::MSG_TAG_LEN);
const _: () = assert!(sum(&[BODY_LEN, BODY_TAG_LEN]) == secmp_crypto::MSG_SEALED_LEN);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sum_saturates_to_max_on_overflow() {
        assert_eq!(sum(&[]), 0);
        assert_eq!(sum(&[1, 2, 3]), 6);
        assert_eq!(sum(&[usize::MAX, 1]), usize::MAX);
    }
}
