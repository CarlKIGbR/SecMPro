// SPDX-License-Identifier: AGPL-3.0-or-later
//! Byte offsets of the structures the negative tests patch (spec §5.2, §5.4, §6.2, §6.3, §6.5).

/// `InvitationV1` (241 B): `ver ‖ kind ‖ RelayRef (101) ‖ ld_id ‖ link_key ‖ inviter_fp ‖ inv_sid ‖ inv_send_seed ‖
/// inv_period_s ‖ expires`.
pub const INV_VER: usize = 0;
pub const INV_KIND: usize = 1;
pub const INV_FP: usize = 2 + 101 + 16 + 32;
pub const INV_PERIOD: usize = 241 - 8 - 2;
pub const INV_EXPIRES: usize = 241 - 8;

/// `IKSPublic` (2017 B): `ver ‖ ik_ed25519 ‖ ik_mldsa65 ‖ ik_dh`.
pub const IKS_ED: usize = 1;
pub const IKS_DH: usize = 2017 - 32;

/// `PrekeyBundle` (7775 B).
pub const B_SPK_ID: usize = 1;
pub const B_SPK_DH: usize = 5;
pub const B_SPK_KEM: usize = 37;
pub const B_RPK_KEM: usize = 37 + 1568;
pub const B_SPK_EXPIRY: usize = 37 + 1568 + 1184;
pub const B_OPK_PRESENT: usize = B_SPK_EXPIRY + 8;
pub const B_OPK_ID: usize = B_OPK_PRESENT + 1;
pub const B_OPK_DH: usize = B_OPK_ID + 4;
pub const B_OPK_KEM: usize = B_OPK_DH + 32;
pub const B_SIG: usize = 7775 - 3373;

/// Low-order X25519 `u` values and non-canonical encodings of them (spec §4.1 (a), RFC 7748 §5): 0, 1, `p − 1`,
/// the two points of order 8, `p` (≡ 0), `p + 1` (≡ 1) and 0 with bit 255 set.
pub fn low_order_values() -> Vec<[u8; 32]> {
    let mut p = [0xff_u8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    let mut p_minus_1 = p;
    p_minus_1[0] = 0xec;
    let mut p_plus_1 = p;
    p_plus_1[0] = 0xee;
    let mut one = [0_u8; 32];
    one[0] = 1;
    let mut zero_high = [0_u8; 32];
    zero_high[31] = 0x80;
    let order8_a = super::hx_gen::harness::LOW_ORDER_8;
    let order8_b: [u8; 32] = [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ];
    vec![
        [0; 32], one, p_minus_1, order8_a, order8_b, p, p_plus_1, zero_high,
    ]
}
