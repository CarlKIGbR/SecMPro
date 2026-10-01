// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! An independent construction of SecMP-INV/HX from the spec and `vectors/SCHEMA-4.10-hx.md` (§5.4, §6.3–§6.5),
//! written without the library's `inv`, `hx` or `prekeys` modules: raw byte layouts and the `secmp-crypto`
//! primitives only. It generates the `hx` vector suite (`hx_gen.rs`) and re-seals the manipulated envelopes of the
//! negative tests, so that the tests compare the library against a second composition of the same spec text.
//!
//! The library types used here are the wire structures of Appendix D (decoders) and `RatchetState` (SecMP-TR).

use secmp_crypto::{
    Caead, Fingerprint, HybridSigningKey, Label, MlKem768Dk, MlKem1024Dk, Nonce24,
    SecretBytes, X25519Public, X25519Secret, hkdf, sha256,
};
use secmp_proto::codec::{pad, unpad};
use secmp_proto::keys::{Ed25519Pk, MlKem768Ek, X25519Pk};
use secmp_proto::sizes::{BODY_LEN, CELL_LEN};
use secmp_proto::tr::{FixedEntropy, RatchetState};
use secmp_proto::wire::cell::{Content, ContentBody, HandshakeBody, RouteDescriptor};
use secmp_proto::wire::inv::{IksPublic, Profile};
use secmp_proto::Encode;

pub const CREATED: u64 = 1_700_000_000;
pub const NOW: u64 = 1_700_000_100;
pub const EXPIRES: u64 = 1_702_592_000;
pub const SPK_ID: u32 = 7;
pub const OPK_ID: u32 = 42;

pub const OUTER_LEN: usize = 9362;
pub const PADDED_LEN: usize = 12_018;
pub const CHUNK: usize = 4006;
pub const IKS_LEN: usize = 2017;
pub const INNER_LEN: usize = IKS_LEN + CELL_LEN;
pub const INNER_CT_LEN: usize = 6185;
/// Offsets inside `Outer` (spec §6.5).
pub const OFF_EK: usize = 1;
pub const OFF_SPK_ID: usize = 33;
pub const OFF_OPK_ID: usize = 37;
pub const OFF_CT_SPK: usize = 41;
pub const OFF_CT_OPK: usize = 1609;
pub const OFF_INNER_CT: usize = 3177;

/// An order-8 X25519 point (`e0eb…b800`), a low-order public value.
pub const LOW_ORDER_8: [u8; 32] = [
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
    0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
];

pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// An identity from its seeds: `IK_sig` = Ed25519 `ed` ‖ ML-DSA-65 `KeyGen_internal(xi)`, `IK_dh` = `dh`.
pub struct Identity {
    pub sig: HybridSigningKey,
    pub dh: X25519Secret,
    pub iks: IksPublic,
    /// `encode(IKSPublic)`, 2017 bytes.
    pub iks_bytes: Vec<u8>,
    /// `fingerprint(IKSPublic)`.
    pub fp: [u8; 32],
}

pub fn identity(xi: &[u8], ed: &[u8], dh: &[u8]) -> Identity {
    let sig = HybridSigningKey::from_seeds(ed, xi).unwrap();
    let dh = X25519Secret::from_bytes(dh).unwrap();
    let vk = sig.verifying_key();
    let iks = IksPublic {
        ik_ed25519: Ed25519Pk::from_bytes(vk.ed25519()).unwrap(),
        ik_mldsa65: Box::new(*vk.mldsa65()),
        ik_dh: X25519Pk::from_bytes(dh.public_key().as_bytes()).unwrap(),
    };
    let iks_bytes = iks.encode().unwrap().to_vec();
    assert_eq!(iks_bytes.len(), IKS_LEN);
    let fp = *Fingerprint::of_encoded_iks(&iks_bytes).unwrap().as_bytes();
    Identity {
        sig,
        dh,
        iks,
        iks_bytes,
        fp,
    }
}

/// The responder's prekeys from their seeds (spec §6.1).
pub struct Prekeys {
    pub spk_dh: X25519Secret,
    pub spk_kem: MlKem1024Dk,
    pub rpk_kem: MlKem768Dk,
    pub opk_dh: X25519Secret,
    pub opk_kem: MlKem1024Dk,
}

/// The bundle fields before `sig` (§6.3, 4402 B) with `spk_expiry` and `opk_present`.
pub fn bundle_fields(keys: &Prekeys, spk_expiry: u64, opk_present: u8) -> Vec<u8> {
    let mut b = vec![0x01];
    b.extend_from_slice(&SPK_ID.to_be_bytes());
    b.extend_from_slice(keys.spk_dh.public_key().as_bytes());
    b.extend_from_slice(keys.spk_kem.encapsulation_key().as_bytes());
    b.extend_from_slice(keys.rpk_kem.encapsulation_key().as_bytes());
    b.extend_from_slice(&spk_expiry.to_be_bytes());
    b.push(opk_present);
    b.extend_from_slice(&OPK_ID.to_be_bytes());
    b.extend_from_slice(keys.opk_dh.public_key().as_bytes());
    b.extend_from_slice(keys.opk_kem.encapsulation_key().as_bytes());
    assert_eq!(b.len(), 7775 - 3373);
    b
}

/// `fields ‖ HybridSign(signer, label, fields ‖ ik_dh)`, ML-DSA hedged with `rnd`.
pub fn sign_fields(
    signer: &Identity,
    fields: &[u8],
    ik_dh: &[u8],
    rnd: &[u8; 32],
    label: Label,
) -> Vec<u8> {
    let message = [fields, ik_dh].concat();
    let sig = signer.sig.sign_kat(label, &message, rnd).unwrap();
    [fields, sig.as_bytes().as_slice()].concat()
}

/// The bundle bytes (§6.3, 7775 B) with `spk_expiry`, `opk_present` and the signature over the encoded fields
/// before `sig` ‖ `ik_dh` of `signer`, hedged with `rnd`.
pub fn bundle_bytes(
    signer: &Identity,
    keys: &Prekeys,
    spk_expiry: u64,
    opk_present: u8,
    rnd: &[u8; 32],
) -> Vec<u8> {
    let b = sign_fields(
        signer,
        &bundle_fields(keys, spk_expiry, opk_present),
        signer.iks.ik_dh.as_bytes(),
        rnd,
        Label::HxBundle,
    );
    assert_eq!(b.len(), 7775);
    b
}

pub fn profile_bytes(name: &str, avatar: Option<[u8; 32]>) -> Vec<u8> {
    Profile::new(name, avatar).unwrap().encode().unwrap().to_vec()
}

/// `LinkDataV1` without padding: `ver ‖ IKSPublic ‖ bundle ‖ Profile ‖ created` (§5.4).
pub fn linkdata_bytes(iks: &[u8], bundle: &[u8], profile: &[u8], created: u64) -> Vec<u8> {
    let mut l = vec![0x01];
    l.extend_from_slice(iks);
    l.extend_from_slice(bundle);
    l.extend_from_slice(profile);
    l.extend_from_slice(&created.to_be_bytes());
    l
}

pub fn k_ld(ld_id: &[u8; 16], link_key: &[u8; 32]) -> SecretBytes<32> {
    hkdf::<32>(ld_id, link_key, Label::InvLinkdata, &[]).unwrap()
}

pub fn k_inv(ld_id: &[u8; 16], link_key: &[u8; 32]) -> SecretBytes<32> {
    hkdf::<32>(ld_id, link_key, Label::HxInitkey, &[]).unwrap()
}

pub fn nonce(n: &[u8]) -> Nonce24 {
    Nonce24::from_bytes_kat(n.try_into().unwrap())
}

/// `blob = N ‖ CAEAD.Seal(K_ld, N, "SecMP-INV/1 blob" ‖ ld_id, pad(linkdata, 12288))` (12360 B).
pub fn blob(k_ld: &SecretBytes<32>, ld_id: &[u8; 16], n: &[u8], linkdata: &[u8]) -> Vec<u8> {
    let padded = pad(linkdata, 12_288).unwrap();
    let ad = [Label::InvBlob.as_bytes(), ld_id.as_slice()].concat();
    let sealed = Caead::seal(k_ld, nonce(n), &ad, &padded).unwrap();
    let out = [n, sealed.as_slice()].concat();
    assert_eq!(out.len(), 12_360);
    out
}

/// The transcript of §6.4 by plain concatenation of the thirteen components, in the order of the formula: `IKS_R`,
/// `spk_id` (u32 BE), `SPK_dh`, `SPK_kem`, `RPK_kem`, `opk_id` (u32 BE), `OPK_dh`, `OPK_kem`, `IKS_I`, `EK_I`,
/// `ct_spk`, `ct_opk`, `ld_id`; the three KEM keys and the two ciphertexts are hashed first.
pub fn transcript(c: [&[u8]; 13]) -> [u8; 32] {
    let h = |x: &[u8]| sha256(&[x]);
    sha256(&[
        b"SecMP-HX/1 transcript",
        c[0],
        c[1],
        c[2],
        &h(c[3]),
        &h(c[4]),
        c[5],
        c[6],
        &h(c[7]),
        c[8],
        c[9],
        &h(c[10]),
        &h(c[11]),
        c[12],
    ])
}

/// `SK = HKDF(0^32, 0xFF^32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4 ‖ ss_spk ‖ ss_opk, "SecMP-HX/1 sk" ‖ transcript, 32)`.
pub fn sk(parts: [&[u8]; 6], transcript: &[u8; 32]) -> SecretBytes<32> {
    let ikm = [&[0xff_u8; 32][..], parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]].concat();
    hkdf::<32>(&[0; 32], &ikm, Label::HxSk, &[transcript]).unwrap()
}

/// `K_id = HKDF(ld_id, link_key ‖ DH3 ‖ ss_spk ‖ DH4 ‖ ss_opk, "SecMP-HX/1 idkey", 32)`.
pub fn k_id(
    ld_id: &[u8; 16],
    link_key: &[u8; 32],
    dh3: &[u8],
    ss_spk: &[u8],
    dh4: &[u8],
    ss_opk: &[u8],
) -> SecretBytes<32> {
    let ikm = [link_key.as_slice(), dh3, ss_spk, dh4, ss_opk].concat();
    hkdf::<32>(ld_id, &ikm, Label::HxIdkey, &[]).unwrap()
}

/// `inner_ct = N2 ‖ CAEAD.Seal(K_id, N2, "SecMP-HX/1 inner" ‖ ld_id, inner)` (6185 B).
pub fn inner_ct(k_id: &SecretBytes<32>, ld_id: &[u8; 16], n2: &[u8], inner: &[u8]) -> Vec<u8> {
    assert_eq!(inner.len(), INNER_LEN);
    let ad = [Label::HxInner.as_bytes(), ld_id.as_slice()].concat();
    let out = [n2, Caead::seal(k_id, nonce(n2), &ad, inner).unwrap().as_slice()].concat();
    assert_eq!(out.len(), INNER_CT_LEN);
    out
}

/// `Outer` unpadded (9362 B): `ver ‖ ek ‖ spk_id ‖ opk_id ‖ ct_spk ‖ ct_opk ‖ inner_ct`.
pub fn outer(
    ek: &[u8],
    spk_id: u32,
    opk_id: u32,
    ct_spk: &[u8],
    ct_opk: &[u8],
    inner_ct: &[u8],
) -> Vec<u8> {
    let mut o = vec![0x01];
    o.extend_from_slice(ek);
    o.extend_from_slice(&spk_id.to_be_bytes());
    o.extend_from_slice(&opk_id.to_be_bytes());
    o.extend_from_slice(ct_spk);
    o.extend_from_slice(ct_opk);
    o.extend_from_slice(inner_ct);
    assert_eq!(o.len(), OUTER_LEN);
    o
}

/// One handshake cell: `N ‖ CAEAD.Seal(K_inv, N, "SecMP-HX/1 initcell" ‖ ld_id, plaintext)` (4096 B) for the
/// plaintext `init_id ‖ i ‖ total ‖ chunk`.
pub fn cell_raw(k_inv: &SecretBytes<32>, ld_id: &[u8; 16], n: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let ad = [Label::HxInitcell.as_bytes(), ld_id.as_slice()].concat();
    let out = [n, Caead::seal(k_inv, nonce(n), &ad, plaintext).unwrap().as_slice()].concat();
    assert_eq!(out.len(), 4096);
    out
}

/// The plaintext of chunk `i` of `padded` with the given `i` and `total` bytes.
pub fn cell_plaintext(init_id: &[u8; 16], i: u8, total: u8, chunk: &[u8]) -> Vec<u8> {
    assert_eq!(chunk.len(), CHUNK);
    [init_id.as_slice(), &[i, total], chunk].concat()
}

/// The three cells of `outer` (unpadded) under `init_id` and the nonces.
pub fn cells(
    k_inv: &SecretBytes<32>,
    ld_id: &[u8; 16],
    init_id: &[u8; 16],
    nonces: [&[u8]; 3],
    outer: &[u8],
) -> [Vec<u8>; 3] {
    let padded = pad(outer, PADDED_LEN).unwrap();
    let chunk = |i: usize| &padded[i * CHUNK..(i + 1) * CHUNK];
    let make = |i: usize| {
        let i8 = u8::try_from(i).unwrap();
        cell_raw(k_inv, ld_id, nonces[i], &cell_plaintext(init_id, i8, 3, chunk(i)))
    };
    [make(0), make(1), make(2)]
}

/// The padded chunk `i` of `outer`.
pub fn chunk_of(outer: &[u8], i: usize) -> Vec<u8> {
    let padded = pad(outer, PADDED_LEN).unwrap();
    padded[i * CHUNK..(i + 1) * CHUNK].to_vec()
}

/// A Handshake Content as the unpadded bytes (§7.6, D.5) and its encoding.
pub fn handshake_content(
    profile: Profile,
    routes: Vec<RouteDescriptor>,
    seq: u64,
    ts: u64,
) -> Content {
    Content {
        seq,
        ts,
        body: ContentBody::Handshake(HandshakeBody { profile, routes }),
    }
}

pub fn unpadded_content(c: &Content) -> Vec<u8> {
    unpad(&c.encode().unwrap(), BODY_LEN).unwrap().to_vec()
}

/// What §6.4 gives the initiator from its seeds.
pub struct Agreement {
    pub ek_pk: [u8; 32],
    pub dh: [Vec<u8>; 4],
    pub ct_spk: Vec<u8>,
    pub ss_spk: Vec<u8>,
    pub ct_opk: Vec<u8>,
    pub ss_opk: Vec<u8>,
    pub transcript: [u8; 32],
    pub sk: SecretBytes<32>,
    pub k_id: SecretBytes<32>,
}

/// The inputs of [`agree`].
pub struct AgreeIn<'a> {
    pub i: &'a Identity,
    pub r: &'a Identity,
    pub keys: &'a Prekeys,
    pub ld_id: &'a [u8; 16],
    pub link_key: &'a [u8; 32],
    pub ek_sk: &'a [u8],
    pub m_spk: &'a [u8; 32],
    pub m_opk: &'a [u8; 32],
}

/// §6.4 for the initiator against the responder and its prekeys, from `ek_sk`, `m_spk`, `m_opk`.
pub fn agree(x: &AgreeIn<'_>) -> Agreement {
    let (i, r, keys) = (x.i, x.r, x.keys);
    let ek = X25519Secret::from_bytes(x.ek_sk).unwrap();
    let ek_pk = *ek.public_key().as_bytes();
    let (ct_spk, ss_spk) = keys.spk_kem.encapsulation_key().encapsulate_kat(x.m_spk);
    let (ct_opk, ss_opk) = keys.opk_kem.encapsulation_key().encapsulate_kat(x.m_opk);
    let pk = |s: &X25519Secret| X25519Public::from_bytes(s.public_key().as_bytes()).unwrap();
    let dh1 = i.dh.diffie_hellman(&pk(&keys.spk_dh)).unwrap();
    let dh2 = ek.diffie_hellman(&pk(&r.dh)).unwrap();
    let dh3 = ek.diffie_hellman(&pk(&keys.spk_dh)).unwrap();
    let dh4 = ek.diffie_hellman(&pk(&keys.opk_dh)).unwrap();
    let tr = transcript([
        &r.iks_bytes,
        &SPK_ID.to_be_bytes(),
        keys.spk_dh.public_key().as_bytes(),
        keys.spk_kem.encapsulation_key().as_bytes(),
        keys.rpk_kem.encapsulation_key().as_bytes(),
        &OPK_ID.to_be_bytes(),
        keys.opk_dh.public_key().as_bytes(),
        keys.opk_kem.encapsulation_key().as_bytes(),
        &i.iks_bytes,
        &ek_pk,
        ct_spk.as_bytes(),
        ct_opk.as_bytes(),
        x.ld_id,
    ]);
    let sk_value = sk(
        [
            dh1.expose_secret(),
            dh2.expose_secret(),
            dh3.expose_secret(),
            dh4.expose_secret(),
            ss_spk.expose_secret(),
            ss_opk.expose_secret(),
        ],
        &tr,
    );
    let k_id_value = k_id(
        x.ld_id,
        x.link_key,
        dh3.expose_secret(),
        ss_spk.expose_secret(),
        dh4.expose_secret(),
        ss_opk.expose_secret(),
    );
    Agreement {
        ek_pk,
        dh: [
            dh1.expose_secret().to_vec(),
            dh2.expose_secret().to_vec(),
            dh3.expose_secret().to_vec(),
            dh4.expose_secret().to_vec(),
        ],
        ct_spk: ct_spk.as_bytes().to_vec(),
        ss_spk: ss_spk.expose_secret().to_vec(),
        ct_opk: ct_opk.as_bytes().to_vec(),
        ss_opk: ss_opk.expose_secret().to_vec(),
        transcript: tr,
        sk: sk_value,
        k_id: k_id_value,
    }
}

/// A fixed-entropy source from the concatenation of `parts`.
pub fn fixed(parts: &[&[u8]]) -> FixedEntropy {
    FixedEntropy::new(&parts.concat())
}

/// The TR initiator state of §7.2 from the agreement (`dh_s_sk` ‖ `kem_s_seed` ‖ `m_tr`).
pub fn tr_initiator(
    a: &Agreement,
    keys: &Prekeys,
    dh_s_sk: &[u8],
    kem_s_seed: &[u8],
    m_tr: &[u8],
) -> RatchetState {
    let spk_dh = X25519Pk::from_bytes(keys.spk_dh.public_key().as_bytes()).unwrap();
    let rpk = MlKem768Ek::from_bytes(keys.rpk_kem.encapsulation_key().as_bytes()).unwrap();
    let mut e = fixed(&[dh_s_sk, kem_s_seed, m_tr]);
    let state = RatchetState::init_initiator_with(&a.sk, &a.transcript, &spk_dh, &rpk, &mut e).unwrap();
    assert_eq!(e.remaining(), 0);
    state
}

/// R's initial TR state (§7.2) from the agreement values.
pub fn tr_responder(sk: &SecretBytes<32>, transcript: &[u8; 32], keys: &Prekeys) -> RatchetState {
    RatchetState::init_responder(
        sk,
        transcript,
        X25519Secret::from_bytes(keys.spk_dh.expose_secret()).unwrap(),
        MlKem768Dk::from_seed(keys.rpk_kem.expose_seed()).unwrap(),
    )
    .unwrap()
}

/// A snapshot of a state (`RatchetState` is not `Clone`).
pub fn snapshot(state: &RatchetState) -> RatchetState {
    RatchetState::from_bytes(&state.to_bytes().unwrap()).unwrap()
}
