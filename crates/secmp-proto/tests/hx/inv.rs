// SPDX-License-Identifier: AGPL-3.0-or-later
//! SecMP-INV: the invitation text and the invitee's checks (TEST-SPEC-M4 (a) INV rows and N-1 … N-23; spec §5.2,
//! §5.4, §5.5).
//!
//! The invitee's functions take no entropy and perform no I/O, so "sends nothing" and "no RNG draw after the reject
//! site" hold by construction: a rejection is an `Err(Rejected)` and the only way to a handshake is `Initiator::start`
//! with the returned `InviteeAccepted`.

use secmp_crypto::{Caead, Label, Nonce24};
use secmp_proto::codec::pad;
use secmp_proto::inv::{
    base64url_decode, derive_k_inv, derive_k_ld, invitation_qr_text,
    invitation_uri, invitee_accept, parse_invitation_uri,
};
use secmp_proto::wire::inv::InvitationV1;
use secmp_proto::{Decode, Encode, Error};

use crate::hx_gen::harness::{
    self, EXPIRES, LOW_ORDER_8, NOW, bundle_bytes, bundle_fields, identity, sign_fields,
};
use crate::layout::*;
use crate::scenario::Lib;

fn rejects(lib: &Lib, uri: &str, blob: &[u8], what: &str) {
    assert_eq!(lib.invitee(uri, blob).err(), Some(Error::Rejected), "{what}");
}

fn accepts(lib: &Lib, uri: &str, blob: &[u8], what: &str) {
    assert_eq!(lib.invitee(uri, blob).err(), None, "{what}");
}

fn flip(mut b: Vec<u8>, at: usize) -> Vec<u8> {
    b[at] ^= 1;
    b
}

// ---- (a) positive INV tests ---------------------------------------------------------------------------------

#[test]
fn inv_uri_roundtrip() {
    let lib = Lib::new();
    let invitation = InvitationV1::decode(&lib.w.invitation).unwrap();
    let uri = invitation_uri(&invitation).unwrap();
    assert!(uri.starts_with("secmp://i/"));
    assert_eq!(uri, lib.w.uri);
    assert_eq!(uri.len(), 332, "10 + ceil(241 * 4 / 3)");
    let back = parse_invitation_uri(&uri).unwrap();
    assert_eq!(back.encode().unwrap().to_vec(), lib.w.invitation);
    // no padding, URL-safe alphabet only
    assert!(uri[10..].bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
}

#[test]
fn inv_qr_text_equals_uri() {
    let lib = Lib::new();
    let invitation = InvitationV1::decode(&lib.w.invitation).unwrap();
    assert_eq!(
        invitation_qr_text(&invitation).unwrap(),
        invitation_uri(&invitation).unwrap()
    );
}

#[test]
fn inv_blob_len_and_keys() {
    let lib = Lib::new();
    assert_eq!(lib.w.blob.len(), 12_360);
    // K_ld and K_inv equal the HKDF of the spec with the exact labels
    let invitation = InvitationV1::decode(&lib.w.invitation).unwrap();
    let k_ld = derive_k_ld(&invitation.ld_id, &invitation.link_key).unwrap();
    let k_inv = derive_k_inv(&invitation.ld_id, &invitation.link_key).unwrap();
    let expected_ld = secmp_crypto::hkdf::<32>(
        &lib.w.inv.ld_id,
        &lib.w.inv.link_key,
        Label::InvLinkdata,
        &[],
    )
    .unwrap();
    let expected_inv = secmp_crypto::hkdf::<32>(
        &lib.w.inv.ld_id,
        &lib.w.inv.link_key,
        Label::HxInitkey,
        &[],
    )
    .unwrap();
    assert_eq!(k_ld.expose_secret(), expected_ld.expose_secret());
    assert_eq!(k_inv.expose_secret(), expected_inv.expose_secret());
    assert_eq!(Label::InvLinkdata.as_bytes(), b"SecMP-INV/1 linkdata");
    assert_eq!(Label::HxInitkey.as_bytes(), b"SecMP-HX/1 initkey");
    assert_ne!(k_ld.expose_secret(), k_inv.expose_secret());
    // the harness's own blob seals to the same bytes
    assert_eq!(lib.blob_of(&lib.w.linkdata, 1).len(), 12_360);
}

// ---- N-1 … N-6: the invitation -----------------------------------------------------------------------------

#[test]
fn invitee_uri_wrong_prefix_rejects() {
    let lib = Lib::new();
    let tail = &lib.w.uri[10..];
    for bad in [
        format!("secmp://I/{tail}"),
        format!("secmp:/i/{tail}"),
        format!(" secmp://i/{tail}"),
        format!("secmp://i{tail}"),
        format!("SECMP://i/{tail}"),
        format!("secmp://i/ {tail}"),
        tail.to_owned(),
    ] {
        rejects(&lib, &bad, &lib.w.blob, &bad[..14.min(bad.len())]);
    }
    accepts(&lib, &lib.w.uri, &lib.w.blob, "control");
}

#[test]
fn invitee_uri_noncanonical_base64_rejects() {
    let lib = Lib::new();
    let tail = lib.w.uri[10..].to_owned();
    // `=` padding (241 B is not a multiple of 3: one pad char would be added)
    for bad in [
        format!("secmp://i/{tail}="),
        format!("secmp://i/{}+{}", &tail[..5], &tail[6..]),
        format!("secmp://i/{}/{}", &tail[..5], &tail[6..]),
        // length ≡ 1 (mod 4)
        format!("secmp://i/{tail}A"),
        format!("secmp://i/{}", &tail[..tail.len() - 1]),
    ] {
        rejects(&lib, &bad, &lib.w.blob, "non-canonical text");
    }
    // non-zero unused low bits in the last character: 241 B = 80 · 3 + 1, so the last of 322 characters carries 6 data
    // bits of which only the top 2 are used; of the 64 possible last characters exactly the 4 whose low 4 bits are
    // zero are canonical
    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let prefix = &tail[..tail.len() - 1];
    let mut canonical = 0;
    for (value, c) in ALPHABET.chars().enumerate() {
        let text = format!("{prefix}{c}");
        let ok = base64url_decode(&text).is_ok();
        assert_eq!(ok, value % 16 == 0, "last character {c}");
        canonical += usize::from(ok);
        let uri = format!("secmp://i/{text}");
        assert_eq!(parse_invitation_uri(&uri).is_ok(), ok, "uri with last character {c}");
    }
    assert_eq!(canonical, 4);
    assert_eq!(base64url_decode("Zh").err(), Some(Error::Rejected));
    assert_eq!(base64url_decode("Zm9vYg=").err(), Some(Error::Rejected));
}

#[test]
fn invitee_invitation_wrong_ver_rejects() {
    let lib = Lib::new();
    let mut inv = lib.w.invitation.clone();
    inv[INV_VER] = 2;
    rejects(&lib, &lib.uri_of(&inv), &lib.w.blob, "ver 0x02");
    // vector V3 (hx-0011): the same mutation
}

#[test]
fn invitee_invitation_kind_not_one_time_rejects() {
    let lib = Lib::new();
    for kind in [0x02_u8, 0x00, 0x03] {
        let mut inv = lib.w.invitation.clone();
        inv[INV_KIND] = kind;
        rejects(&lib, &lib.uri_of(&inv), &lib.w.blob, &format!("kind {kind:#04x}"));
    }
}

#[test]
fn invitee_invitation_bad_period_rejects() {
    let lib = Lib::new();
    for period in [0_u16, 9, 15, 30, 160, 0xffff] {
        let mut inv = lib.w.invitation.clone();
        inv[INV_PERIOD..INV_PERIOD + 2].copy_from_slice(&period.to_be_bytes());
        rejects(&lib, &lib.uri_of(&inv), &lib.w.blob, &format!("period {period}"));
    }
}

#[test]
fn invitee_expired_invitation_rejects() {
    let lib = Lib::new();
    let with_expiry = |e: u64| {
        let mut inv = lib.w.invitation.clone();
        inv[INV_EXPIRES..].copy_from_slice(&e.to_be_bytes());
        lib.uri_of(&inv)
    };
    // reading 3: `now` = `expires` is expired
    assert_eq!(
        invitee_accept(&with_expiry(NOW), &lib.w.blob, NOW).err(),
        Some(Error::Rejected),
        "now = expires"
    );
    assert_eq!(
        invitee_accept(&with_expiry(NOW - 1), &lib.w.blob, NOW).err(),
        Some(Error::Rejected),
        "now = expires + 1 (vector V1: expires = now − 1)"
    );
    assert!(
        invitee_accept(&with_expiry(NOW + 1), &lib.w.blob, NOW).is_ok(),
        "control: now = expires − 1"
    );
}

// ---- N-7 … N-10: the blob ------------------------------------------------------------------------------------

#[test]
fn invitee_blob_wrong_link_key_rejects() {
    let lib = Lib::new();
    let mut wrong = lib.w.inv.link_key;
    wrong[0] ^= 1;
    let k = harness::k_ld(&lib.w.inv.ld_id, &wrong);
    let blob = harness::blob(&k, &lib.w.inv.ld_id, &[3; 24], &lib.w.linkdata);
    rejects(&lib, &lib.w.uri, &blob, "K_ld from a flipped link_key (vector V8)");
}

#[test]
fn invitee_blob_wrong_ld_id_ad_rejects() {
    let lib = Lib::new();
    let mut other = lib.w.inv.ld_id;
    other[0] ^= 1;
    // right key, AD names another ld_id
    let blob = harness::blob(&lib.w.k_ld, &other, &[4; 24], &lib.w.linkdata);
    rejects(&lib, &lib.w.uri, &blob, "AD with another ld_id");
}

#[test]
fn invitee_blob_tampered_rejects() {
    let lib = Lib::new();
    // N = 0..24, COM = 24..56, ct = 56..12344, tag = 12344..12360
    for at in [0_usize, 23, 24, 55, 56, 5000, 12_343, 12_344, 12_359] {
        rejects(&lib, &lib.w.uri, &flip(lib.w.blob.clone(), at), &format!("flip byte {at}"));
    }
    let mut longer = lib.w.blob.clone();
    longer.push(0);
    rejects(&lib, &lib.w.uri, &longer, "length 12361");
    rejects(
        &lib,
        &lib.w.uri,
        &lib.w.blob[..lib.w.blob.len() - 1],
        "length 12359",
    );
    rejects(&lib, &lib.w.uri, &[], "empty blob");
}

#[test]
fn invitee_linkdata_bad_padding_rejects() {
    let lib = Lib::new();
    let seal = |padded: &[u8]| {
        let ad = [Label::InvBlob.as_bytes(), lib.w.inv.ld_id.as_slice()].concat();
        let sealed = Caead::seal(&lib.w.k_ld, Nonce24::from_bytes_kat([5; 24]), &ad, padded).unwrap();
        [[5_u8; 24].as_slice(), sealed.as_slice()].concat()
    };
    let good = pad(&lib.w.linkdata, 12_288).unwrap().to_vec();
    accepts(&lib, &lib.w.uri, &seal(&good), "control: correct padding");
    // no 0x80 after the fields: zeros only
    let mut no_marker = good.clone();
    no_marker[lib.w.linkdata.len()] = 0;
    rejects(&lib, &lib.w.uri, &seal(&no_marker), "no 0x80 marker");
    // a non-zero byte after the marker
    let mut dirty = good.clone();
    dirty[12_287] = 1;
    rejects(&lib, &lib.w.uri, &seal(&dirty), "non-zero byte after the marker");
    // all zero
    rejects(&lib, &lib.w.uri, &seal(&[0; 12_288]), "all zero");
}

// ---- N-11 … N-14: fingerprint and signature ------------------------------------------------------------------

#[test]
fn invitee_wrong_fingerprint_rejects_and_sends_nothing() {
    let lib = Lib::new();
    for at in [INV_FP, INV_FP + 31] {
        let inv = flip(lib.w.invitation.clone(), at);
        rejects(&lib, &lib.uri_of(&inv), &lib.w.blob, &format!("inviter_fp byte {}", at - INV_FP));
    }
}

#[test]
fn invitee_substituted_inviter_iks_rejects() {
    let lib = Lib::new();
    // another valid identity, and a bundle validly signed by it; the invitation keeps the original inviter_fp
    let other = identity(&[0x61; 32], &[0x62; 32], &[0x63; 32]);
    let bundle = bundle_bytes(&other, &lib.w.keys, EXPIRES, 1, &[7; 32]);
    let linkdata = lib.linkdata_of(&other.iks_bytes, &bundle);
    rejects(&lib, &lib.w.uri, &lib.blob_of(&linkdata, 6), "substituted IKS");
    // control: the same link data with the matching fingerprint is accepted
    let mut inv = lib.w.invitation.clone();
    inv[INV_FP..INV_FP + 32].copy_from_slice(&other.fp);
    accepts(&lib, &lib.uri_of(&inv), &lib.blob_of(&linkdata, 6), "control: matching fingerprint");
}

fn bundle_variant(lib: &Lib, mutate: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut b = lib.w.bundle.clone();
    mutate(&mut b);
    b
}

fn reject_bundle(lib: &Lib, bundle: &[u8], what: &str) {
    let linkdata = lib.linkdata_of(&lib.w.r.iks_bytes, bundle);
    rejects(lib, &lib.w.uri, &lib.blob_of(&linkdata, 8), what);
}

#[test]
fn invitee_bundle_bad_sig_ed25519_rejects() {
    let lib = Lib::new();
    // bit 0 of byte 0 of the signature: the Ed25519 R, still a valid encoding (vector V9)
    reject_bundle(&lib, &bundle_variant(&lib, |b| b[B_SIG] ^= 1), "Ed25519 R bit flipped");
}

#[test]
fn invitee_bundle_bad_sig_mldsa_rejects() {
    let lib = Lib::new();
    // the ML-DSA half starts after the 64-byte Ed25519 signature (vector V5: last byte)
    for at in [B_SIG + 64, B_SIG + 64 + 1000, 7774] {
        reject_bundle(&lib, &bundle_variant(&lib, |b| b[at] ^= 1), &format!("ML-DSA byte {at}"));
    }
}

// ---- N-15 … N-22: the bundle ----------------------------------------------------------------------------------

#[test]
fn invitee_bundle_field_tampered_rejects() {
    let lib = Lib::new();
    // after signing, flip a bit of a signed field (the blob is re-sealed)
    for (name, at) in [
        ("spk_kem", B_SPK_KEM + 100),
        ("rpk_kem", B_RPK_KEM + 100),
        ("opk_dh", B_OPK_DH),
        ("spk_expiry", B_SPK_EXPIRY + 7),
        ("opk_id", B_OPK_ID + 3),
        ("spk_id", B_SPK_ID + 3),
        ("spk_dh", B_SPK_DH),
    ] {
        reject_bundle(&lib, &bundle_variant(&lib, |b| b[at] ^= 1), name);
    }
}

#[test]
fn invitee_bundle_signed_over_other_ik_dh_rejects() {
    let lib = Lib::new();
    let other_dh = identity(&lib.w.r_seed[..32], &lib.w.r_seed[32..64], &[0x77; 32]);
    let fields = bundle_fields(&lib.w.keys, EXPIRES, 1);
    let bundle = sign_fields(
        &lib.w.r,
        &fields,
        other_dh.iks.ik_dh.as_bytes(),
        &[9; 32],
        Label::HxBundle,
    );
    reject_bundle(&lib, &bundle, "signature over fields ‖ a different ik_dh");
    // control: over the right ik_dh
    let good = sign_fields(&lib.w.r, &fields, lib.w.r.iks.ik_dh.as_bytes(), &[9; 32], Label::HxBundle);
    let linkdata = lib.linkdata_of(&lib.w.r.iks_bytes, &good);
    accepts(&lib, &lib.w.uri, &lib.blob_of(&linkdata, 8), "control");
}

#[test]
fn invitee_bundle_wrong_label_rejects() {
    let lib = Lib::new();
    let fields = bundle_fields(&lib.w.keys, EXPIRES, 1);
    let bundle = sign_fields(
        &lib.w.r,
        &fields,
        lib.w.r.iks.ik_dh.as_bytes(),
        &[9; 32],
        Label::TrKeychange,
    );
    reject_bundle(&lib, &bundle, "signed with \"SecMP-TR/1 keychange\"");
}

#[test]
fn invitee_bundle_expired_rejects() {
    let lib = Lib::new();
    let signed = |spk_expiry: u64| bundle_bytes(&lib.w.r, &lib.w.keys, spk_expiry, 1, &[10; 32]);
    reject_bundle(&lib, &signed(NOW - 1), "spk_expiry = now − 1 (vector V6)");
    reject_bundle(&lib, &signed(NOW), "spk_expiry = now (boundary rejects)");
    let linkdata = lib.linkdata_of(&lib.w.r.iks_bytes, &signed(NOW + 1));
    accepts(&lib, &lib.w.uri, &lib.blob_of(&linkdata, 8), "control: spk_expiry = now + 1");
}

#[test]
fn invitee_bundle_without_opk_rejects() {
    let lib = Lib::new();
    // opk_present = 0, validly signed (vector V7): the PrekeyBundle decoder rejects it
    let bundle = bundle_bytes(&lib.w.r, &lib.w.keys, EXPIRES, 0, &[11; 32]);
    let linkdata = lib.linkdata_of(&lib.w.r.iks_bytes, &bundle);
    let padded = pad(&linkdata, 12_288).unwrap();
    assert!(!lib.decodes(&padded), "the decoder refuses opk_present = 0");
    rejects(&lib, &lib.w.uri, &lib.blob_of(&linkdata, 8), "opk_present = 0");
    // any other value as well
    for present in [2_u8, 0xff] {
        let bundle = bundle_bytes(&lib.w.r, &lib.w.keys, EXPIRES, present, &[11; 32]);
        let linkdata = lib.linkdata_of(&lib.w.r.iks_bytes, &bundle);
        rejects(&lib, &lib.w.uri, &lib.blob_of(&linkdata, 8), "opk_present ≠ 1");
    }
}

/// Re-sign `fields` (patched) so that only the decoder, not the signature, can be what rejects.
fn resigned(lib: &Lib, patch: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut fields = bundle_fields(&lib.w.keys, EXPIRES, 1);
    patch(&mut fields);
    sign_fields(&lib.w.r, &fields, lib.w.r.iks.ik_dh.as_bytes(), &[12; 32], Label::HxBundle)
}

#[test]
fn invitee_low_order_x25519_rejects() {
    let lib = Lib::new();
    for value in low_order_values() {
        for (name, at) in [("spk_dh", B_SPK_DH), ("opk_dh", B_OPK_DH)] {
            let bundle = resigned(&lib, |f| f[at..at + 32].copy_from_slice(&value));
            reject_bundle(&lib, &bundle, &format!("{name} = {}", harness::hex(&value)));
        }
        // ik_dh of the IKS (the blob's IKS and the fingerprint follow: re-pin the invitation to it)
        let mut iks = lib.w.r.iks_bytes.clone();
        iks[IKS_DH..IKS_DH + 32].copy_from_slice(&value);
        let linkdata = lib.linkdata_of(&iks, &lib.w.bundle);
        rejects(&lib, &lib.w.uri, &lib.blob_of(&linkdata, 8), "ik_dh low order");
    }
    assert!(low_order_values().contains(&LOW_ORDER_8));
}

#[test]
fn invitee_kem_modulus_rejects() {
    let lib = Lib::new();
    // a 12-bit coefficient ≥ q = 3329 (here 4095) fails the FIPS 203 §7.2 modulus check
    for (name, at) in [("spk_kem", B_SPK_KEM), ("rpk_kem", B_RPK_KEM), ("opk_kem", B_OPK_KEM)] {
        let bundle = resigned(&lib, |f| f[at..at + 3].copy_from_slice(&[0xff, 0xff, 0xff]));
        reject_bundle(&lib, &bundle, name);
    }
}

#[test]
fn invitee_bad_ed25519_identity_rejects() {
    let lib = Lib::new();
    // small-order point (the identity, y = 1) and y ≥ p
    let mut identity_point = [0_u8; 32];
    identity_point[0] = 1;
    let mut y_ge_p = [0xff_u8; 32];
    y_ge_p[31] = 0x7f;
    for (name, bytes) in [("identity point", identity_point), ("y ≥ p", y_ge_p)] {
        let mut iks = lib.w.r.iks_bytes.clone();
        iks[IKS_ED..IKS_ED + 32].copy_from_slice(&bytes);
        let linkdata = lib.linkdata_of(&iks, &lib.w.bundle);
        rejects(&lib, &lib.w.uri, &lib.blob_of(&linkdata, 8), name);
    }
}

// ---- N-23: SQ-25 reading A -----------------------------------------------------------------------------------

#[test]
fn invitee_does_not_check_inviter_bounds() {
    let lib = Lib::new();
    // `expires` beyond creation + 30 days (the invitation has no creation time; the link data has `created`)
    let mut inv = lib.w.invitation.clone();
    inv[INV_EXPIRES..].copy_from_slice(&(NOW + 90 * 24 * 3600).to_be_bytes());
    accepts(&lib, &lib.uri_of(&inv), &lib.w.blob, "expires > created + 30 d is accepted");
    // `spk_expiry` < the invitation's `expires` (but > now)
    let bundle = bundle_bytes(&lib.w.r, &lib.w.keys, NOW + 10, 1, &[13; 32]);
    let linkdata = lib.linkdata_of(&lib.w.r.iks_bytes, &bundle);
    accepts(&lib, &lib.w.uri, &lib.blob_of(&linkdata, 8), "spk_expiry < expires is accepted");
}

fn low_order_values() -> Vec<[u8; 32]> {
    crate::layout::low_order_values()
}
