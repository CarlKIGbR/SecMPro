// SPDX-License-Identifier: AGPL-3.0-or-later
//! Unit and negative tests of SecMP-TR (M3 plan step 7, and the coverage of steps 3–5), grouped by prefix:
//!
//! 1. `reject_*` — every rejection path of spec §7.4.
//! 2. `encrypt_*` — the refusals of §7.3 and the persist-before-send / persist-before-ack closures (plan D4).
//! 3. `unavailable_*` — `Unavailable` on decrypt (plan D1, D2).
//! 4. `ratchet_*` — header-key rotation, KEM material, steps, `pn`, skipped keys and their bounds (§7.2–§7.4),
//!    dummies; the two `ratchet_fast_forward_*` tests derive 2^20 chain keys each (seconds, not milliseconds).
//! 5. `state_*` — the persistence encoding `RatchetStateV1` (`state.rs`, plan D5).
//! 6. `content_*` — the content layer (§7.6, §7.7; plan D6, D7).
//!
//! Every refusal is checked for the uniform error — `Rejected`, or `Unavailable` where plan D1 says so — **and**
//! for a byte-identical state (`to_bytes()` before and after); every rejected cell is also checked to draw no
//! randomness (the source fails on its first draw and counts the calls, plan D2). Manipulated cells are built by
//! hand from §7.3 and §7.5 with the ratchet's internal keys, so that each differs from an accepted cell in exactly
//! the fault under test (the message key is the one the receiver derives, unless a test says otherwise), and each
//! negative test has a positive control: the same construction without the fault is accepted.

use secmp_crypto::{
    Aead, ConstantTimeEq, Fingerprint, HybridSigningKey, HybridVerifyingKey, Label, MlKem768Ct,
    MlKem768Dk, MsgEncrypt, Nonce24, SecretBytes, X25519Public, X25519Secret, Zeroizing, kdf_ck,
    kdf_rk, tr_init,
};

use super::content::{self, Delivery, Inbox, MAX_PARTIALS, Trust};
use super::entropy::TestEntropy;
use super::state::SkippedKey;
use super::{MAX_FF, MAX_SKIPPED, Plaintext, RatchetState, SKIP_WINDOW};
use crate::codec::{Decode, Encode, pad};
use crate::error::{Error, Result};
use crate::keys::{Ed25519Pk, HybridSig, MlKem768Ek, X25519Pk};
use crate::sizes::{
    BODY_LEN, BODY_TAG_LEN, CELL_LEN, ED25519_SIG_LEN, HDR_CT_LEN, HEADER_LEN, HYBRID_SIG_LEN,
    IKS_PUBLIC_LEN, MLKEM768_CT_LEN, NONCE_LEN, sum,
};
use crate::wire::cell::{
    AppKind, AppMessage, BatchBody, Content, ContentBody, ControlBody, ControlCode, Fragment,
    FragmentPayload, HandshakeBody, HeaderV1, KeyChangeBody, ReceiptBody, ReceiptKind,
    RouteDescriptor, RouteUpdateBody,
};
use crate::wire::inv::{IksPublic, Profile};
use crate::wire::testutil::{ek768, x25519};

// ------------------------------------------------------------------------------------------------ helpers

/// The session binding of the test sessions.
const SB: [u8; 32] = [7; 32];
/// Another session binding.
const OTHER_SB: [u8; 32] = [8; 32];

/// `HeaderV1` offsets (§7.5): `ver ‖ flags ‖ dh_pk[32] ‖ pn u32 ‖ n u32 ‖ ek_pq[1184] ‖ ct_pq[1088]`.
const H_VER: usize = 0;
const H_FLAGS: usize = 1;
const H_DH: usize = 2;
const H_EK: usize = 42;
const H_CT: usize = 1226;
const _: () = assert!(sum(&[H_CT, MLKEM768_CT_LEN]) == HEADER_LEN);

/// Cell offsets (§7.5): `hdr_nonce[24] ‖ hdr_ct[2330] ‖ body_ct[1710] ‖ tag[32]`.
const C_BODY: usize = sum(&[NONCE_LEN, HDR_CT_LEN]);
const C_TAG: usize = sum(&[C_BODY, BODY_LEN]);
/// The last byte of a cell (of its body tag).
const C_LAST: usize = 4095;
const _: () = assert!(
    sum(&[C_TAG, BODY_TAG_LEN]) == CELL_LEN
        && sum(&[C_LAST, 1]) == CELL_LEN
        && C_BODY == 2354
        && C_TAG == 4064
);

/// Low-order X25519 u-coordinates (spec §4.1 (a)): 1 and p − 1 (0 is `[0; 32]`).
const U_ONE: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const U_P_MINUS_ONE: [u8; 32] = [
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// A session (§7.2) from `sk`: the initiator with session binding `sb_a`, the responder with `sb_b`.
fn session_with(
    sk: &SecretBytes<32>,
    sb_a: &[u8; 32],
    sb_b: &[u8; 32],
) -> Result<(RatchetState, RatchetState)> {
    let spk = X25519Secret::generate()?;
    let rpk = MlKem768Dk::generate()?;
    let spk_pub = X25519Pk::from_bytes(spk.public_key().as_bytes())?;
    let rpk_ek = MlKem768Ek::from_bytes(rpk.encapsulation_key().as_bytes())?;
    let a = RatchetState::init_initiator(sk, sb_a, &spk_pub, &rpk_ek)?;
    let b = RatchetState::init_responder(sk, sb_b, spk, rpk)?;
    Ok((a, b))
}

/// A fresh session with binding [`SB`].
fn session() -> Result<(RatchetState, RatchetState)> {
    session_with(&SecretBytes::random()?, &SB, &SB)
}

/// An `AppMessage` identified by `seq` (its `msg_id` and payload).
fn message(seq: u64) -> AppMessage {
    let mut msg_id = [0_u8; 16];
    put(&mut msg_id, 8, &seq.to_be_bytes());
    AppMessage {
        msg_id,
        kind: AppKind::Text,
        expire_after: 0,
        payload: Zeroizing::new(seq.to_be_bytes().to_vec()),
    }
}

/// A one-message Batch identified by `seq`.
fn text(seq: u64) -> Content {
    Content {
        seq,
        ts: seq,
        body: ContentBody::Batch(BatchBody {
            messages: vec![message(seq)],
        }),
    }
}

/// The `seq` of a decrypted Content.
fn seq(pt: &Plaintext) -> Result<u64> {
    Ok(pt.content()?.seq)
}

/// Overwrite `buf` from `at` on with `bytes` (clipped at its end).
fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
    for (dst, src) in buf.iter_mut().skip(at).zip(bytes) {
        *dst = *src;
    }
}

/// Flip bit 0 of `buf[at]`.
fn flip(buf: &mut [u8], at: usize) {
    if let Some(b) = buf.get_mut(at) {
        *b ^= 1;
    }
}

/// `bytes` with bit 0 of byte `at` flipped.
fn flipped(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    flip(&mut out, at);
    out
}

/// A copy of `bytes` with `with` written at `at` (the length is kept).
fn overwrite(bytes: &[u8], at: usize, with: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(bytes.to_vec());
    let end = at.checked_add(with.len()).ok_or(Error::Rejected)?;
    out.get_mut(at..end)
        .ok_or(Error::Rejected)?
        .copy_from_slice(with);
    Ok(out)
}

/// A copy of a present key.
fn key(k: Option<&SecretBytes<32>>) -> Result<SecretBytes<32>> {
    Ok(SecretBytes::from_slice(
        k.ok_or(Error::Rejected)?.expose_secret(),
    )?)
}

/// Whether `a` is present and equal to `b` (a constant-time comparison; the test reads the verdict).
fn same(a: Option<&SecretBytes<32>>, b: &SecretBytes<32>) -> bool {
    a.is_some_and(|a| bool::from(a.ct_eq(b)))
}

/// A copy of a state through its persistence encoding (the state has no `Clone`).
fn copy(s: &RatchetState) -> Result<RatchetState> {
    RatchetState::from_bytes(&s.to_bytes()?)
}

/// `encrypt` and persist; the bytes handed to the persistence closure are the returned state's encoding (D4).
fn send(s: RatchetState, c: &Content) -> Result<(RatchetState, Vec<u8>)> {
    let mut persisted = Vec::new();
    let (s, cell) = s.encrypt(c).map_err(|r| r.error())?.persist(|bytes| {
        persisted = bytes.to_vec();
        Ok::<(), Error>(())
    })?;
    assert_eq!(persisted, *s.to_bytes()?, "persist-before-send");
    Ok((s, cell.as_bytes().to_vec()))
}

/// `decrypt` and commit; the bytes handed to the commit closure are the returned state's encoding (D4).
fn recv(s: RatchetState, cell: &[u8]) -> Result<(RatchetState, Plaintext)> {
    let mut committed = Vec::new();
    let (s, pt) = s.decrypt(cell).map_err(|r| r.error())?.commit(|bytes| {
        committed = bytes.to_vec();
        Ok::<(), Error>(())
    })?;
    assert_eq!(committed, *s.to_bytes()?, "persist-before-ack");
    Ok((s, pt))
}

/// `recv` and the `seq` of the Content.
fn recv_seq(s: RatchetState, cell: &[u8]) -> Result<(RatchetState, u64)> {
    let (s, pt) = recv(s, cell)?;
    Ok((s, seq(&pt)?))
}

/// `from` sends `c`, `to` decrypts exactly `c`'s padded encoding.
fn exchange(
    from: RatchetState,
    to: RatchetState,
    c: &Content,
) -> Result<(RatchetState, RatchetState)> {
    let (from, cell) = send(from, c)?;
    let (to, pt) = recv(to, &cell)?;
    assert_eq!(pt.as_bytes().as_slice(), c.encode()?.as_slice());
    Ok((from, to))
}

/// `decrypt_with(cell, entropy)` is refused with `expected` and hands back the byte-identical state.
fn refused(
    s: RatchetState,
    cell: &[u8],
    entropy: &mut TestEntropy,
    expected: Error,
    what: &str,
) -> Result<RatchetState> {
    let before = s.to_bytes()?;
    let refusal = s.decrypt_with(cell, entropy).err();
    assert!(refusal.is_some(), "{what}: accepted");
    let (s, error) = refusal.ok_or(Error::Rejected)?.into_parts();
    assert_eq!(error, expected, "{what}");
    assert_eq!(*s.to_bytes()?, *before, "{what}: the state changed");
    Ok(s)
}

/// `decrypt` refuses `cell` with the uniform `Rejected`, draws no randomness, and leaves the state byte-identical.
fn rejects(s: RatchetState, cell: &[u8], what: &str) -> Result<RatchetState> {
    let mut entropy = TestEntropy::failing_after(0);
    let s = refused(s, cell, &mut entropy, Error::Rejected, what)?;
    assert_eq!(entropy.calls, 0, "{what}: a rejection drew randomness");
    Ok(s)
}

/// The header the sender's next `encrypt` writes (§7.3).
fn header_of(s: &RatchetState) -> Result<HeaderV1> {
    Ok(HeaderV1 {
        dh_pk: s.dh_s.pk,
        pn: s.pn,
        n: s.n_s,
        ek_pq: s.kem_s.ek.clone(),
        ct_pq: Box::new(*s.ct_s.as_ref().ok_or(Error::Rejected)?.as_bytes()),
    })
}

/// A cell built by hand (§7.3, §7.5): `header` (any bytes) sealed under `hk` with `AD = "SecMP-TR/1 hdr" ‖
/// sb_hdr`, `body` (any bytes) under `mk` with `AD = "SecMP-TR/1 body" ‖ sb_body ‖ hdr_nonce ‖ hdr_ct`.
fn seal_cell(
    hk: &SecretBytes<32>,
    sb_hdr: &[u8; 32],
    sb_body: &[u8; 32],
    header: &[u8],
    mk: SecretBytes<32>,
    body: &[u8],
) -> Result<Vec<u8>> {
    let nonce = Nonce24::random()?;
    let hdr_nonce = *nonce.as_bytes();
    let hdr_ad = [Label::TrHdr.as_bytes(), sb_hdr.as_slice()].concat();
    let hdr_ct = Aead::seal(hk, nonce, &hdr_ad, header)?;
    let body_ad = [
        Label::TrBody.as_bytes(),
        sb_body.as_slice(),
        hdr_nonce.as_slice(),
        &hdr_ct,
    ]
    .concat();
    let body_ct = MsgEncrypt::seal(mk, &body_ad, body)?;
    Ok([hdr_nonce.as_slice(), &hdr_ct, &body_ct].concat())
}

/// [`seal_cell`] with binding [`SB`], `header` encoded and `c` padded.
fn seal(
    hk: &SecretBytes<32>,
    header: &HeaderV1,
    mk: SecretBytes<32>,
    c: &Content,
) -> Result<Vec<u8>> {
    seal_cell(hk, &SB, &SB, &header.encode()?, mk, &c.encode()?)
}

/// §7.3 by hand on the sender's state: its next header with `edit` applied to the encoding, sealed under `hk_s`,
/// and `body` (1710 bytes) under its next message key; `ck_s` and `n_s` advance as in `encrypt`.
fn forge(s: &mut RatchetState, edit: impl FnOnce(&mut [u8]), body: &[u8]) -> Result<Vec<u8>> {
    let mut header = header_of(s)?.encode()?;
    edit(header.as_mut_slice());
    let (ck, mk) = kdf_ck(s.ck_s.as_ref().ok_or(Error::Rejected)?)?;
    let cell = seal_cell(
        s.hk_s.as_ref().ok_or(Error::Rejected)?,
        &s.sb,
        &s.sb,
        &header,
        mk,
        body,
    )?;
    s.ck_s = Some(ck);
    s.n_s = s.n_s.checked_add(1).ok_or(Error::Rejected)?;
    Ok(cell)
}

/// The sender loses its next `k` messages: `k` chain steps, as `k` encrypts whose cells never arrive (encrypt
/// changes nothing else); their message keys.
fn advance(s: &mut RatchetState, k: u32) -> Result<Vec<SecretBytes<32>>> {
    let mut lost = Vec::new();
    for _ in 0..k {
        let (ck, mk) = kdf_ck(s.ck_s.as_ref().ok_or(Error::Rejected)?)?;
        s.ck_s = Some(ck);
        s.n_s = s.n_s.checked_add(1).ok_or(Error::Rejected)?;
        lost.push(mk);
    }
    Ok(lost)
}

/// The cell `k` positions after the sender state `start` (a copy of it is advanced and encrypts).
fn message_at(start: &RatchetState, k: u32) -> Result<Vec<u8>> {
    let mut s = copy(start)?;
    advance(&mut s, k)?;
    let position = u64::from(s.n_s);
    Ok(send(s, &text(position))?.1)
}

/// The header of `cell`, opened under `hk` with binding [`SB`].
fn header_in(hk: &SecretBytes<32>, cell: &[u8]) -> Result<HeaderV1> {
    let (nonce, rest) = cell
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(Error::Rejected)?;
    let hdr_ct = rest.get(..HDR_CT_LEN).ok_or(Error::Rejected)?;
    let ad = [Label::TrHdr.as_bytes(), SB.as_slice()].concat();
    HeaderV1::decode(&Aead::open(hk, nonce, &ad, hdr_ct)?)
}

/// The message key after `steps` chain steps from `ck` (§7.2 `KDF_CK`).
fn mk_after(ck: &SecretBytes<32>, steps: u32) -> Result<SecretBytes<32>> {
    let mut ck = key(Some(ck))?;
    for _ in 0..steps {
        ck = kdf_ck(&ck)?.0;
    }
    Ok(kdf_ck(&ck)?.1)
}

/// The message key the receiver derives for position `n` of its current chain (§7.4, `step = false`).
fn chain_mk(r: &RatchetState, n: u32) -> Result<SecretBytes<32>> {
    mk_after(
        r.ck_r.as_ref().ok_or(Error::Rejected)?,
        n.checked_sub(r.n_r).ok_or(Error::Rejected)?,
    )
}

/// The new receiving chain key of a DH step with `header` (§7.4 `DHRatchet`, receiving half).
fn step_ck(r: &RatchetState, header: &HeaderV1) -> Result<SecretBytes<32>> {
    let dh = r
        .dh_s
        .sk
        .diffie_hellman(&X25519Public::from_bytes(header.dh_pk.as_bytes())?)?;
    let ss = r
        .kem_s
        .dk
        .decapsulate(&MlKem768Ct::from_bytes(header.ct_pq.as_slice())?);
    Ok(kdf_rk(&r.rk, &dh, &ss)?.1)
}

/// The message key the receiver derives for a DH-step `header`.
fn step_mk(r: &RatchetState, header: &HeaderV1) -> Result<SecretBytes<32>> {
    mk_after(&step_ck(r, header)?, header.n)
}

/// A fresh X25519 public key.
fn fresh_dh() -> Result<X25519Pk> {
    X25519Pk::from_bytes(X25519Secret::generate()?.public_key().as_bytes())
}

/// A DH-step header from a new ratchet key: a fresh `dh_pk`, a valid `ek_pq`, any `ct_pq`.
fn new_step_header(pn: u32, n: u32) -> Result<HeaderV1> {
    Ok(HeaderV1 {
        dh_pk: fresh_dh()?,
        pn,
        n,
        ek_pq: ek768(9)?,
        ct_pq: Box::new([5; MLKEM768_CT_LEN]),
    })
}

/// A and B, where B holds one skipped key of A's first chain while both are on later chains: A's first message
/// (`lost`, returned) did not arrive, its second did; B answered, A stepped and sent once more.
fn old_skipped() -> Result<(RatchetState, RatchetState, Vec<u8>)> {
    let (a, b) = session()?;
    let (a, lost) = send(a, &text(0))?;
    let (a, b) = exchange(a, b, &text(1))?;
    let (b, a) = exchange(b, a, &text(100))?;
    let (a, b) = exchange(a, b, &text(2))?;
    assert_eq!(b.skipped.len(), 1);
    assert!(!same(
        b.hk_r.as_ref(),
        &b.skipped.front().ok_or(Error::Rejected)?.hk
    ));
    Ok((a, b, lost))
}

/// The header key and message key of the first skipped entry.
fn front_entry(s: &RatchetState) -> Result<(SecretBytes<32>, SecretBytes<32>)> {
    let e = s.skipped.front().ok_or(Error::Rejected)?;
    Ok((key(Some(&e.hk))?, key(Some(&e.mk))?))
}

/// 4096 random bytes.
fn random_cell() -> Result<Vec<u8>> {
    let mut cell = Vec::with_capacity(CELL_LEN);
    while cell.len() < CELL_LEN {
        cell.extend_from_slice(SecretBytes::<32>::random()?.expose_secret());
    }
    Ok(cell)
}

// ------------------------------------------------------------------------------ 1. rejections of §7.4

/// A cell of any length but 4096 bytes (§7.5).
#[test]
fn reject_cell_length() -> Result<()> {
    let (a, b) = session()?;
    let (_, cell) = send(a, &text(1))?;
    let mut longer = cell.clone();
    longer.push(0);
    let mut b = b;
    for len in [0, 1, NONCE_LEN, C_BODY, C_LAST] {
        let short = cell.get(..len).ok_or(Error::Rejected)?;
        b = rejects(b, short, &format!("length {len}"))?;
    }
    let b = rejects(b, &longer, "length 4097")?;
    let (_, got) = recv_seq(b, &cell)?;
    assert_eq!(got, 1, "control: the 4096-byte cell");
    Ok(())
}

/// Random bytes, a damaged nonce or header, and a cell of another session open under no candidate key; then the
/// undamaged cell is accepted.
fn no_key_opens(s: RatchetState, honest: &[u8], foreign: &[u8]) -> Result<RatchetState> {
    let mut s = s;
    for (what, cell) in [
        ("random bytes", random_cell()?),
        ("another session's key", foreign.to_vec()),
        ("hdr_nonce damaged", flipped(honest, 0)),
        ("hdr_ct damaged", flipped(honest, NONCE_LEN)),
        (
            "header tag damaged",
            flipped(honest, C_BODY.saturating_sub(1)),
        ),
    ] {
        s = rejects(s, &cell, what)?;
    }
    Ok(recv(s, honest)?.0)
}

/// No header key: a fresh responder (only `nhk_r`; the absent `hk_r` is masked) and a responder that tries two
/// skipped header keys of old chains, `hk_r` and `nhk_r`.
#[test]
fn reject_no_header_key() -> Result<()> {
    let (other, _) = session()?;
    let (other, foreign_first) = send(other, &text(90))?;
    let (_, foreign_later) = send(other, &text(91))?;
    // fresh
    let (a, fresh) = session()?;
    let (_, first) = send(a, &text(0))?;
    no_key_opens(fresh, &first, &foreign_first)?;
    // two old chains with skipped keys
    let (a, b, _) = old_skipped()?;
    let (a, _) = send(a, &text(3))?;
    let (a, b) = exchange(a, b, &text(4))?;
    let (b, a) = exchange(b, a, &text(101))?;
    let (a, b) = exchange(a, b, &text(5))?;
    let hk_r = key(b.hk_r.as_ref())?;
    assert_eq!(b.skipped.len(), 2);
    assert!(b.skipped.iter().all(|e| !bool::from(e.hk.ct_eq(&hk_r))));
    let (_, honest) = send(a, &text(6))?;
    no_key_opens(b, &honest, &foreign_later)?;
    Ok(())
}

/// The session binding is in the header AD (a responder with another transcript opens nothing) and in the body AD.
#[test]
fn reject_wrong_session_binding() -> Result<()> {
    let sk = SecretBytes::random()?;
    let (a, b) = session_with(&sk, &SB, &OTHER_SB)?;
    let (_, cell) = send(a, &text(1))?;
    rejects(b, &cell, "another transcript")?;
    // on a chain, a cell built with another binding in one of the two ADs
    let (a, b) = session()?;
    let (a, b) = exchange(a, b, &text(0))?;
    let hk = key(a.hk_s.as_ref())?;
    let header = header_of(&a)?.encode()?;
    let body = text(1).encode()?;
    let cell = seal_cell(&hk, &OTHER_SB, &SB, &header, chain_mk(&b, 1)?, &body)?;
    let b = rejects(b, &cell, "header AD")?;
    let cell = seal_cell(&hk, &SB, &OTHER_SB, &header, chain_mk(&b, 1)?, &body)?;
    let b = rejects(b, &cell, "body AD")?;
    let cell = seal_cell(&hk, &SB, &SB, &header, chain_mk(&b, 1)?, &body)?;
    assert_eq!(recv_seq(b, &cell)?.1, 1, "control");
    Ok(())
}

/// An absent key is never a candidate: a header sealed under the all-zero key that stands in for an absent `hk_r`
/// does not open (plan D3) — at the responder before its first step and the initiator before its first reply.
/// And a responder before any chain rejects a header under a key it does not hold yet.
#[test]
fn reject_absent_and_unknown_keys() -> Result<()> {
    let (a, b) = session()?;
    assert!(a.hk_r.is_none() && b.hk_r.is_none());
    let zero = SecretBytes::<32>::from_slice(&[0; 32])?;
    let header = header_of(&a)?;
    let ck_s = key(a.ck_s.as_ref())?;
    let cell = seal(&zero, &header, mk_after(&ck_s, 0)?, &text(1))?;
    let b = rejects(b, &cell, "responder: the dummy key")?;
    let a = rejects(a, &cell, "initiator: the dummy key")?;
    // keys the responder lacks: A's next sending header key, a random key
    let nhk_s = key(a.nhk_s.as_ref())?;
    let b = rejects(
        b,
        &seal(&nhk_s, &header, mk_after(&ck_s, 0)?, &text(1))?,
        "A's nhk_s",
    )?;
    let random = SecretBytes::random()?;
    let b = rejects(
        b,
        &seal(&random, &header, mk_after(&ck_s, 0)?, &text(1))?,
        "random key",
    )?;
    // control: the same header and body under HK_A
    let hk_a = key(a.hk_s.as_ref())?;
    let cell = seal(&hk_a, &header, mk_after(&ck_s, 0)?, &text(1))?;
    assert_eq!(recv_seq(b, &cell)?.1, 1, "control");
    Ok(())
}

/// An edit of an encoded header.
type HeaderEdit = fn(&mut [u8]);

/// Headers that open but do not decode (§7.5 `ver` = 1, `flags` = 0; §4.1 (a) `dh_pk` not of low order, (c)
/// `ek_pq` passes the modulus check), as edits of an honest header.
fn undecodable_edits() -> [(&'static str, HeaderEdit); 8] {
    [
        ("flags 1", |h| put(h, H_FLAGS, &[1])),
        ("flags 0x80", |h| put(h, H_FLAGS, &[0x80])),
        ("ver 0", |h| put(h, H_VER, &[0])),
        ("ver 2", |h| put(h, H_VER, &[2])),
        ("dh_pk 0", |h| put(h, H_DH, &[0; 32])),
        ("dh_pk 1", |h| put(h, H_DH, &U_ONE)),
        ("dh_pk p - 1", |h| put(h, H_DH, &U_P_MINUS_ONE)),
        ("ek_pq modulus", |h| put(h, H_EK, &[0xff; 3])),
    ]
}

/// Header decoding on the DH-step path (the responder's first message: `nhk_r` opens it).
#[test]
fn reject_undecodable_header_on_the_step_path() -> Result<()> {
    let (a, b) = session()?;
    let body = text(1).encode()?;
    let mut b = b;
    for (what, edit) in undecodable_edits() {
        let mut sender = copy(&a)?;
        b = rejects(b, &forge(&mut sender, edit, &body)?, what)?;
    }
    let mut a = a;
    let control = forge(&mut a, |_| {}, &body)?;
    let (b, got) = recv_seq(b, &control)?;
    assert_eq!(got, 1, "control");
    assert!(b.skipped.is_empty());
    Ok(())
}

/// Header decoding on the current chain (`hk_r` opens it; no skipped key takes part).
#[test]
fn reject_undecodable_header_on_the_chain_path() -> Result<()> {
    let (a, b) = session()?;
    let (a, b) = exchange(a, b, &text(0))?;
    assert!(b.skipped.is_empty());
    let body = text(1).encode()?;
    let mut b = b;
    for (what, edit) in undecodable_edits() {
        let mut sender = copy(&a)?;
        b = rejects(b, &forge(&mut sender, edit, &body)?, what)?;
    }
    let mut a = a;
    let control = forge(&mut a, |_| {}, &body)?;
    assert_eq!(recv_seq(b, &control)?.1, 1, "control");
    Ok(())
}

/// Header decoding under a skipped key (reference reading 3: `Open()` includes decoding) — a key of an old chain,
/// and a skipped key of the current chain (which is also `hk_r`).
#[test]
fn reject_undecodable_header_under_a_skipped_key() -> Result<()> {
    let (_, b, lost) = old_skipped()?;
    let (hk, _) = front_entry(&b)?;
    let header = header_in(&hk, &lost)?;
    let body = text(0).encode()?;
    let mut b = b;
    for (what, edit) in undecodable_edits() {
        let mut bytes = header.encode()?;
        edit(bytes.as_mut_slice());
        let (_, mk) = front_entry(&b)?;
        b = rejects(b, &seal_cell(&hk, &SB, &SB, &bytes, mk, &body)?, what)?;
    }
    let (_, mk) = front_entry(&b)?;
    let control = seal(&hk, &header, mk, &text(0))?;
    assert_eq!(recv_seq(b, &control)?.1, 0, "control: an old chain");
    // the current chain: position 0 lost, position 1 delivered
    let (a, b) = session()?;
    let start = copy(&a)?;
    let (a, _) = send(a, &text(0))?;
    let (_, b) = exchange(a, b, &text(1))?;
    assert!(same(b.hk_r.as_ref(), &front_entry(&b)?.0));
    let mut b = b;
    for (what, edit) in undecodable_edits() {
        let mut sender = copy(&start)?;
        b = rejects(b, &forge(&mut sender, edit, &body)?, what)?;
    }
    let mut sender = copy(&start)?;
    let control = forge(&mut sender, |_| {}, &body)?;
    assert_eq!(recv_seq(b, &control)?.1, 0, "control: the current chain");
    Ok(())
}

/// A DH step whose `pn` lies below the receiver's `n_r` on the old chain is a stale counter: §7.4
/// `skip_message_keys(header.pn)` rejects `until < n_r` before `DHRatchet` (honest body under the step's message
/// key, so only `pn` decides); the control `pn = n_r` is accepted (M3 review C4, R-10). Run once on 2026-10-01 with
/// the hand mutant `select::skip_plan(self.n_r, header.pn.max(self.n_r))` in `RatchetState::open_step`
/// (`ratchet.rs:638` at `665e84e`), which survives every other TR test and the vectors: this test fails on it — the
/// mutated decrypt passes the body MAC and reaches the step's sending half, so the refusal is `Unavailable` (from
/// the zero-budget test entropy) instead of `Rejected` (assertion message `pn = n_r - 1`, `left: Unavailable`) — and
/// passes again without it.
#[test]
fn reject_step_with_pn_below_n_r() -> Result<()> {
    let (a, b) = session()?;
    let (a, b) = exchange(a, b, &text(0))?;
    let (_, b) = exchange(a, b, &text(1))?;
    assert_eq!(b.n_r, 2);
    let nhk_r = key(b.nhk_r.as_ref())?;
    let below = b.n_r.checked_sub(1).ok_or(Error::Rejected)?;
    let mut header = new_step_header(below, 0)?;
    let cell = seal(&nhk_r, &header, step_mk(&b, &header)?, &text(2))?;
    let b = rejects(b, &cell, "pn = n_r - 1")?;
    header.pn = b.n_r;
    let cell = seal(&nhk_r, &header, step_mk(&b, &header)?, &text(2))?;
    let (b, got) = recv_seq(b, &cell)?;
    assert_eq!(got, 2, "control: pn = n_r");
    assert_eq!((b.pn, b.n_r), (0, 1), "the step was taken");
    Ok(())
}

/// A DH step must carry a new ratchet key (`header.dh_pk == dh_r` rejects); the control differs only in `dh_pk`.
#[test]
fn reject_step_that_repeats_the_ratchet_key() -> Result<()> {
    let (a, b) = session()?;
    let (a, b) = exchange(a, b, &text(0))?;
    let nhk_r = key(b.nhk_r.as_ref())?;
    let mut header = header_of(&a)?;
    header.pn = b.n_r;
    header.n = 0;
    assert_eq!(Some(header.dh_pk), b.dh_r);
    let cell = seal(&nhk_r, &header, step_mk(&b, &header)?, &text(1))?;
    let b = rejects(b, &cell, "dh_pk == dh_r")?;
    header.dh_pk = fresh_dh()?;
    let cell = seal(&nhk_r, &header, step_mk(&b, &header)?, &text(1))?;
    let (b, got) = recv_seq(b, &cell)?;
    assert_eq!(got, 1, "control");
    assert_eq!(b.dh_r, Some(header.dh_pk));
    Ok(())
}

/// KEM constancy on a message that is not a step: `ek_pq` changed, `ct_pq` changed, both (honest body).
#[test]
fn reject_kem_material_that_changes_within_a_chain() -> Result<()> {
    let (a, b) = session()?;
    let (a, b) = exchange(a, b, &text(0))?;
    let hk = key(a.hk_s.as_ref())?;
    let other_ek = ek768(3)?;
    let mut b = b;
    for (what, ek, ct) in [
        ("ek_pq", true, false),
        ("ct_pq", false, true),
        ("both", true, true),
    ] {
        let mut header = header_of(&a)?;
        if ek {
            header.ek_pq = other_ek.clone();
        }
        if ct {
            flip(header.ct_pq.as_mut_slice(), 1000);
        }
        let cell = seal(&hk, &header, chain_mk(&b, header.n)?, &text(1))?;
        b = rejects(b, &cell, what)?;
    }
    let header = header_of(&a)?;
    let cell = seal(&hk, &header, chain_mk(&b, header.n)?, &text(1))?;
    assert_eq!(recv_seq(b, &cell)?.1, 1, "control");
    Ok(())
}

/// A replay below `n_r` on the current chain (`skip_message_keys`: `until < n_r`).
#[test]
fn reject_replay_on_the_current_chain() -> Result<()> {
    let (a, b) = session()?;
    let (a, m0) = send(a, &text(0))?;
    let (a, m1) = send(a, &text(1))?;
    let (_, m2) = send(a, &text(2))?;
    let mut b = b;
    for cell in [&m0, &m1, &m2] {
        b = recv(b, cell)?.0;
    }
    for (what, cell) in [("n_r - 1", &m2), ("n_r - 2", &m1), ("n_r - 3", &m0)] {
        b = rejects(b, cell, what)?;
    }
    Ok(())
}

/// A replay of a consumed skipped key: on the current chain, and on an old chain with and without other keys left
/// under its header key.
#[test]
fn reject_replay_of_a_consumed_skipped_key() -> Result<()> {
    let (a, b) = session()?;
    let (a, m0) = send(a, &text(0))?;
    let (_, b) = exchange(a, b, &text(1))?;
    let (b, _) = recv(b, &m0)?;
    rejects(b, &m0, "current chain")?;
    // old chain: two skipped keys under A's first header key
    let (a, b) = session()?;
    let (a, m0) = send(a, &text(0))?;
    let (a, m1) = send(a, &text(1))?;
    let (a, b) = exchange(a, b, &text(2))?;
    let (b, a) = exchange(b, a, &text(100))?;
    let (_, b) = exchange(a, b, &text(3))?;
    let (b, _) = recv(b, &m0)?;
    let b = rejects(b, &m0, "old chain, its header key still in skipped")?;
    let (b, _) = recv(b, &m1)?;
    assert!(b.skipped.is_empty());
    rejects(b, &m1, "old chain, its header key gone")?;
    Ok(())
}

/// A gap over `MAX_FF`, the cheap cases (rejected before anything is derived): `n` on the current chain and on a
/// step's new chain (bodies under the key of the next expected position, not of `n`), `pn` on a step's old chain
/// (honest body). The exact bound with honest bodies both ways: `ratchet_fast_forward_*`.
#[test]
fn reject_gap_over_max_ff() -> Result<()> {
    let (a, b) = session()?;
    let (a, b) = exchange(a, b, &text(0))?;
    let over = b
        .n_r
        .checked_add(MAX_FF)
        .and_then(|n| n.checked_add(1))
        .ok_or(Error::Rejected)?;
    let hk = key(a.hk_s.as_ref())?;
    let mut header = header_of(&a)?;
    header.n = over;
    let cell = seal(&hk, &header, chain_mk(&b, 1)?, &text(1))?;
    let b = rejects(b, &cell, "chain n")?;
    let nhk_r = key(b.nhk_r.as_ref())?;
    let header = new_step_header(over, 0)?;
    let cell = seal(&nhk_r, &header, step_mk(&b, &header)?, &text(2))?;
    let mut b = rejects(b, &cell, "step pn")?;
    for n in [MAX_FF.saturating_add(1), u32::MAX] {
        let header = new_step_header(b.n_r, n)?;
        let mut zero = header.clone();
        zero.n = 0;
        let cell = seal(&nhk_r, &header, step_mk(&b, &zero)?, &text(3))?;
        b = rejects(b, &cell, "step n")?;
    }
    // control: a step with a gap of 3 on the old chain stores those 3 keys
    let header = new_step_header(b.n_r.saturating_add(3), 0)?;
    let cell = seal(&nhk_r, &header, step_mk(&b, &header)?, &text(4))?;
    let (b, got) = recv_seq(b, &cell)?;
    assert_eq!(got, 4, "control");
    let positions: Vec<u32> = b.skipped.iter().map(|e| e.n).collect();
    assert_eq!(positions, [1, 2, 3]);
    Ok(())
}

/// `n_r` at `u32::MAX`: `n_r += 1` overflows (the cell is built with the internal chain key); one position below,
/// the same construction is accepted.
#[test]
fn reject_n_r_overflow() -> Result<()> {
    let (a, b) = session()?;
    let (a, mut b) = exchange(a, b, &text(0))?;
    let hk = key(a.hk_s.as_ref())?;
    let mut header = header_of(&a)?;
    b.n_r = u32::MAX.saturating_sub(1);
    header.n = b.n_r;
    let cell = seal(&hk, &header, chain_mk(&b, header.n)?, &text(1))?;
    let (b, got) = recv_seq(b, &cell)?;
    assert_eq!(got, 1, "control");
    assert_eq!(b.n_r, u32::MAX);
    header.n = u32::MAX;
    let cell = seal(&hk, &header, chain_mk(&b, header.n)?, &text(2))?;
    rejects(b, &cell, "n_r += 1 overflows")?;
    Ok(())
}

/// Body MAC failures (the body or its tag damaged) after the header opened: on the step path (after the receiving
/// half: nothing applied, no randomness drawn), on the current chain (also after a fast-forward: nothing stored) and
/// under a skipped key (which stays).
#[test]
fn reject_body_mac_failure() -> Result<()> {
    let (a, b) = session()?;
    let (a, m0) = send(a, &text(0))?;
    let (a, m1) = send(a, &text(1))?;
    let (a, m2) = send(a, &text(2))?;
    let (a, _) = send(a, &text(3))?;
    let (_, m4) = send(a, &text(4))?;
    let damage = [C_BODY, sum(&[C_BODY, 1000]), C_TAG, C_LAST];
    let mut b = b;
    for at in damage {
        b = rejects(b, &flipped(&m1, at), "step")?;
    }
    b = recv(b, &m1)?.0;
    for (what, cell) in [
        ("chain", &m2),
        ("chain after a gap", &m4),
        ("skipped key", &m0),
    ] {
        for at in damage {
            b = rejects(b, &flipped(cell, at), what)?;
        }
    }
    assert_eq!(b.skipped.len(), 1, "the skipped key stays");
    for (cell, expected) in [(&m0, 0), (&m2, 2), (&m4, 4)] {
        let (next, got) = recv_seq(b, cell)?;
        assert_eq!(got, expected, "control");
        b = next;
    }
    Ok(())
}

/// A later step (with a `pn` fast-forward on the old chain) whose body MAC fails, and a step whose `ct_pq` was
/// changed — the step derives another chain key, so the body MAC fails (§7.4 note (b)).
#[test]
fn reject_step_with_a_wrong_body_or_ct_pq() -> Result<()> {
    let (a, b) = session()?;
    let body = text(0).encode()?;
    let mut sender = copy(&a)?;
    let b = rejects(
        b,
        &forge(&mut sender, |h| flip(h, H_CT), &body)?,
        "first step: ct_pq",
    )?;
    let (a, b) = exchange(a, b, &text(0))?;
    let (a, _) = send(a, &text(1))?;
    let (b, a) = exchange(b, a, &text(100))?;
    let mut sender = copy(&a)?;
    let ct_changed = forge(&mut sender, |h| flip(h, H_CT), &text(2).encode()?)?;
    let (_, cell) = send(a, &text(2))?;
    let mut b = rejects(b, &ct_changed, "later step: ct_pq")?;
    for at in [C_BODY, C_TAG, C_LAST] {
        b = rejects(b, &flipped(&cell, at), "later step: body")?;
    }
    let (b, got) = recv_seq(b, &cell)?;
    assert_eq!(got, 2, "control");
    assert_eq!(b.skipped.len(), 1, "the pn fast-forward stored position 1");
    Ok(())
}

/// Defence in depth: the branches that no reachable state takes (`from_bytes` refuses such shapes, the ratchet never
/// builds them) fail closed on an in-memory state built by hand — `hk_r` without the rest of its receiving chain on
/// the chain path, `nhk_r` without `nhk_s` on the step path.
#[test]
fn reject_unreachable_shapes_fail_closed() -> Result<()> {
    let (a, b) = session()?;
    let (a, mut b) = exchange(a, b, &text(0))?;
    let (_, cell) = send(a, &text(1))?;
    b.last_ct_r = None;
    rejects(b, &cell, "chain path without last_ct_r")?;
    let (a, mut b) = session()?;
    let (_, cell) = send(a, &text(0))?;
    b.nhk_s = None;
    rejects(b, &cell, "step path without nhk_s")?;
    Ok(())
}

/// `rejects`, and the `kat` reject-site tag names `site`.
#[cfg(feature = "kat")]
fn rejects_at(s: RatchetState, cell: &[u8], site: &str) -> Result<RatchetState> {
    let s = rejects(s, cell, site)?;
    assert_eq!(super::DECRYPT_SITE_KAT.get(), Some(site));
    Ok(s)
}

/// Feature `kat` (M3 review R-45, F19; WEISUNG M4-4 Part E): each reject site of §7.4 sets its tag
/// (`DECRYPT_SITE_KAT`), on one cell each — the names the constant-time bench's pre-checks claim; the body MAC on the
/// step, chain and skipped paths.
#[cfg(feature = "kat")]
#[test]
fn reject_sites_are_tagged() -> Result<()> {
    // the step path (B's first message), then the chain path at n_r = 1
    let (a, b) = session()?;
    let (_, first) = send(copy(&a)?, &text(0))?;
    let b = rejects_at(b, &flipped(&first, C_LAST), "body MAC")?;
    let (a, b) = exchange(a, b, &text(0))?;
    let (a1, m1) = send(copy(&a)?, &text(1))?;
    let b = rejects_at(b, m1.get(..C_LAST).ok_or(Error::Rejected)?, "cell length")?;
    let b = rejects_at(b, &random_cell()?, "header: no key opened")?;
    let mut sender = copy(&a)?;
    let undecodable = forge(&mut sender, |h| put(h, H_FLAGS, &[1]), &text(1).encode()?)?;
    let b = rejects_at(b, &undecodable, "header decode")?;
    let mut header = header_of(&a)?;
    flip(header.ct_pq.as_mut_slice(), 1000);
    let changed = seal(&key(a.hk_s.as_ref())?, &header, chain_mk(&b, 1)?, &text(1))?;
    let b = rejects_at(b, &changed, "kem constancy")?;
    let b = rejects_at(b, &flipped(&m1, C_LAST), "body MAC")?;
    let (b, _) = recv(b, &m1)?;
    let b = rejects_at(b, &m1, "counter rule")?;
    // a step under nhk_r that repeats the ratchet key
    let mut header = header_of(&a1)?;
    header.pn = b.n_r;
    header.n = 0;
    let repeated = seal(
        &key(b.nhk_r.as_ref())?,
        &header,
        step_mk(&b, &header)?,
        &text(2),
    )?;
    rejects_at(b, &repeated, "dh_pk")?;
    // skipped keys (hk_1, 0) and (hk_1, 1) of an old chain: the body MAC under one; a replay of the consumed other
    let (a, b) = session()?;
    let (a, m0) = send(a, &text(0))?;
    let (a, m1) = send(a, &text(1))?;
    let (a, b) = exchange(a, b, &text(2))?;
    let (b, a) = exchange(b, a, &text(100))?;
    let (_, b) = exchange(a, b, &text(3))?;
    let b = rejects_at(b, &flipped(&m1, C_LAST), "body MAC")?;
    let (b, _) = recv(b, &m0)?;
    rejects_at(b, &m0, "skipped: (hk, n) not stored")?;
    // the Content decoder (outside the transaction): an accepted cell whose padded body is no Content
    let (a, b) = session()?;
    let (_, cell) = a
        .encrypt_padded_kat(&[0xff; BODY_LEN], &mut super::OsEntropy)
        .map_err(|r| r.error())?
        .persist(|_| Ok::<(), Error>(()))?;
    let (_, pt) = recv(b, cell.as_bytes())?;
    assert_eq!(pt.content().err(), Some(Error::Rejected));
    assert_eq!(super::DECRYPT_SITE_KAT.get(), Some("body decode"));
    Ok(())
}

// ----------------------------------------------------------------------------- 2. encrypt refusals

/// `encrypt_with` is refused with `expected` and hands back the byte-identical state.
fn encrypt_refused(
    s: RatchetState,
    c: &Content,
    entropy: &mut TestEntropy,
    expected: Error,
    what: &str,
) -> Result<RatchetState> {
    let before = s.to_bytes()?;
    let refusal = s.encrypt_with(c, entropy).err();
    assert!(refusal.is_some(), "{what}: sealed");
    let refusal = refusal.ok_or(Error::Rejected)?;
    assert_eq!(refusal.error(), expected, "{what}");
    let s = refusal.into_state();
    assert_eq!(*s.to_bytes()?, *before, "{what}: the state changed");
    Ok(s)
}

/// A responder before its first step has no sending chain (real and dummy contents alike).
#[test]
fn encrypt_without_a_sending_chain() -> Result<()> {
    let (a, b) = session()?;
    let mut entropy = TestEntropy::failing_after(1);
    let b = encrypt_refused(b, &text(1), &mut entropy, Error::Rejected, "real")?;
    let b = encrypt_refused(b, &content::dummy(), &mut entropy, Error::Rejected, "dummy")?;
    assert_eq!(entropy.calls, 0, "refused before the nonce is drawn");
    let (_, b) = exchange(a, b, &text(0))?;
    let (_, cell) = send(b, &text(1))?;
    assert_eq!(cell.len(), CELL_LEN, "control: after its first step");
    Ok(())
}

/// `n_s += 1` is a `checked_add`: at `u32::MAX` encrypt aborts (§7.3); one below, it seals position `u32::MAX − 1`.
#[test]
fn encrypt_aborts_at_n_s_max() -> Result<()> {
    let (mut a, _) = session()?;
    let hk = key(a.hk_s.as_ref())?;
    a.n_s = u32::MAX.saturating_sub(1);
    let (a, cell) = send(a, &text(1))?;
    assert_eq!(
        header_in(&hk, &cell)?.n,
        u32::MAX.saturating_sub(1),
        "control"
    );
    assert_eq!(a.n_s, u32::MAX);
    let mut entropy = TestEntropy::failing_after(1);
    let a = encrypt_refused(
        a,
        &text(2),
        &mut entropy,
        Error::Rejected,
        "n_s at u32::MAX",
    )?;
    encrypt_refused(a, &content::dummy(), &mut entropy, Error::Rejected, "dummy")?;
    assert_eq!(entropy.calls, 0);
    Ok(())
}

/// A Content without an encoding (a body over 1689 bytes, an empty Batch, a one-fragment Fragment, a Receipt of
/// 256 ids) is refused before the nonce is drawn; a body of exactly 1689 bytes seals.
#[test]
fn encrypt_content_without_an_encoding() -> Result<()> {
    let (a, _) = session()?;
    let batch = |payload: usize| Content {
        seq: 1,
        ts: 1,
        body: ContentBody::Batch(BatchBody {
            messages: vec![AppMessage {
                msg_id: [1; 16],
                kind: AppKind::Text,
                expire_after: 0,
                payload: Zeroizing::new(vec![0x61; payload]),
            }],
        }),
    };
    let unencodable = [
        ("body 1690 bytes", batch(1666)),
        (
            "empty batch",
            Content {
                seq: 1,
                ts: 1,
                body: ContentBody::Batch(BatchBody { messages: vec![] }),
            },
        ),
        ("total 1", fragment(1, 0, 1, &[1])),
        (
            "256 receipts",
            Content {
                seq: 1,
                ts: 1,
                body: ContentBody::Receipt(ReceiptBody {
                    kind: ReceiptKind::Read,
                    msg_ids: vec![[1; 16]; 256],
                }),
            },
        ),
    ];
    let mut entropy = TestEntropy::failing_after(1);
    let mut a = a;
    for (what, c) in &unencodable {
        a = encrypt_refused(a, c, &mut entropy, Error::Rejected, what)?;
    }
    assert_eq!(entropy.calls, 0);
    let (a, _) = send(a, &batch(1665))?;
    assert_eq!(a.n_s, 1, "control: a body of exactly 1689 bytes");
    Ok(())
}

/// No header nonce (randomness unavailable): `Unavailable`, state unchanged, nothing sealed; with one draw
/// available, encrypt draws exactly the nonce.
#[test]
fn encrypt_unavailable_without_a_nonce() -> Result<()> {
    let (a, _) = session()?;
    let mut entropy = TestEntropy::failing_after(0);
    let a = encrypt_refused(a, &text(1), &mut entropy, Error::Unavailable, "no nonce")?;
    assert_eq!(entropy.calls, 1);
    let mut entropy = TestEntropy::failing_after(1);
    let sealed = a
        .encrypt_with(&text(1), &mut entropy)
        .map_err(|r| r.error())?;
    let (a, _) = sealed.persist(|_| Ok::<(), Error>(()))?;
    assert_eq!((a.n_s, entropy.calls), (1, 1), "control");
    Ok(())
}

/// If the new state cannot be encoded after sealing (`to_bytes` refuses a `skipped` over its bound — a state only
/// a hand-built in-memory value can have), `encrypt` is refused and hands back the state as it was (§7.3: no cell
/// leaves, `ck_s` and `n_s` unchanged).
#[test]
fn encrypt_refused_after_sealing_hands_back_the_old_state() -> Result<()> {
    let (_, mut b, _) = old_skipped()?;
    let (hk, mk) = front_entry(&b)?;
    while b.skipped.len() <= MAX_SKIPPED {
        b.skipped.push_back(SkippedKey {
            hk: key(Some(&hk))?,
            n: 0,
            mk: key(Some(&mk))?,
        });
    }
    let ck_s = key(b.ck_s.as_ref())?;
    let n_s = b.n_s;
    let mut entropy = TestEntropy::failing_after(1);
    let refusal = b.encrypt_with(&text(1), &mut entropy).err();
    assert!(refusal.is_some());
    let (b, error) = refusal.ok_or(Error::Rejected)?.into_parts();
    assert_eq!((error, entropy.calls), (Error::Rejected, 1));
    assert!(same(b.ck_s.as_ref(), &ck_s), "ck_s unchanged");
    assert_eq!(b.n_s, n_s, "n_s unchanged");
    Ok(())
}

/// A failing `Sealed::persist` / `Opened::commit` closure: its error is returned and nothing else; the closure
/// was offered the new state once; the durable (old) state then sends again / receives the same cell again.
#[test]
fn encrypt_persist_and_commit_errors_are_returned() -> Result<()> {
    let (a, b) = session()?;
    let durable_a = a.to_bytes()?;
    let mut offered = Vec::new();
    let result = a
        .encrypt(&text(1))
        .map_err(|r| r.error())?
        .persist(|bytes| {
            offered.push(bytes.to_vec());
            Err::<(), _>("disk full")
        });
    assert_eq!(result.err(), Some("disk full"));
    assert_eq!(offered.len(), 1);
    let offered_state = RatchetState::from_bytes(offered.first().ok_or(Error::Rejected)?)?;
    assert_eq!(offered_state.n_s, 1, "the new state was offered");
    // the durable state is the old one; it sends again
    let (_, cell) = send(RatchetState::from_bytes(&durable_a)?, &text(1))?;
    let durable_b = b.to_bytes()?;
    let opened = b.decrypt(&cell).map_err(|r| r.error())?;
    assert_eq!(seq(opened.plaintext())?, 1);
    let mut offered = Vec::new();
    let result = opened.commit(|bytes| {
        offered.push(bytes.to_vec());
        Err::<(), _>("io")
    });
    assert_eq!(result.err(), Some("io"));
    assert_eq!(offered.len(), 1);
    assert_ne!(offered.first(), Some(&durable_b.to_vec()));
    // the unacknowledged cell is delivered again to the reloaded durable state
    let b = RatchetState::from_bytes(&durable_b)?;
    assert_eq!(recv_seq(b, &cell)?.1, 1);
    Ok(())
}

// ------------------------------------------------------------------------ 3. `Unavailable` on decrypt

/// A DH step whose sending half cannot draw its keys (`X25519.keygen`, `ML-KEM-768.keygen`, `Encaps`, in that
/// order) is `Unavailable` with the state byte-identical: the cell is not consumed and is accepted afterwards
/// (plan D1, D2) — on the responder's first step and the initiator's; a chain message draws nothing.
#[test]
fn unavailable_step_consumes_nothing() -> Result<()> {
    let (a, b) = session()?;
    let (a, m0) = send(a, &text(0))?;
    let (a, m1) = send(a, &text(1))?;
    let mut b = b;
    for ok in 0..3 {
        let mut entropy = TestEntropy::failing_after(ok);
        b = refused(b, &m0, &mut entropy, Error::Unavailable, "responder's step")?;
        assert_eq!(entropy.calls, ok.saturating_add(1));
    }
    let (b, got) = recv_seq(b, &m0)?;
    assert_eq!(got, 0);
    // a chain message: accepted with a source that fails at once, which is never called
    let mut entropy = TestEntropy::failing_after(0);
    let (b, _) = b
        .decrypt_with(&m1, &mut entropy)
        .map_err(|r| r.error())?
        .commit(|_| Ok::<(), Error>(()))?;
    assert_eq!(entropy.calls, 0);
    // the initiator's first step, on the second message of B's chain (position 0 is stored)
    let (b, _) = send(b, &text(10))?;
    let (_, reply) = send(b, &text(11))?;
    let mut a = a;
    for ok in 0..3 {
        let mut entropy = TestEntropy::failing_after(ok);
        a = refused(
            a,
            &reply,
            &mut entropy,
            Error::Unavailable,
            "initiator's step",
        )?;
    }
    let (a, got) = recv_seq(a, &reply)?;
    assert_eq!(got, 11);
    assert_eq!(a.skipped.len(), 1);
    Ok(())
}

// -------------------------------------------------------------------- 4. the ratchet against the spec

/// Header keys (§7.2–§7.4): the initiator's first header is under `HK_A`, the responder's first under `NHK_B`;
/// at every step of the receiver `hk_s` = old `nhk_s`, `hk_r` = old `nhk_r`, and its new `nhk_r` is the sender's
/// `nhk_s` (four steps, both directions).
#[test]
fn ratchet_header_keys_rotate_per_spec() -> Result<()> {
    let sk = SecretBytes::random()?;
    let (_, hk_a, nhk_b) = tr_init(&sk)?;
    let (a, b) = session_with(&sk, &SB, &SB)?;
    assert!(same(a.hk_s.as_ref(), &hk_a) && same(a.nhk_r.as_ref(), &nhk_b));
    assert!(a.hk_r.is_none() && b.hk_s.is_none() && b.hk_r.is_none());
    assert!(same(b.nhk_s.as_ref(), &nhk_b) && same(b.nhk_r.as_ref(), &hk_a));
    let (a, first) = send(a, &text(0))?;
    assert!(header_in(&hk_a, &first).is_ok(), "initiator's first header");
    assert!(header_in(&nhk_b, &first).is_err());
    let (mut sender, mut receiver, mut cell) = (a, b, first);
    for round in 0..4_u64 {
        let old_nhk_s = key(receiver.nhk_s.as_ref())?;
        let old_nhk_r = key(receiver.nhk_r.as_ref())?;
        let sender_nhk_s = key(sender.nhk_s.as_ref())?;
        let (stepped, _) = recv(receiver, &cell)?;
        assert!(same(stepped.hk_s.as_ref(), &old_nhk_s), "hk_s, {round}");
        assert!(same(stepped.hk_r.as_ref(), &old_nhk_r), "hk_r, {round}");
        assert!(same(stepped.nhk_r.as_ref(), &sender_nhk_s), "{round}");
        assert!(!same(stepped.nhk_s.as_ref(), &old_nhk_s), "{round}");
        let (stepped, reply) = send(stepped, &text(round))?;
        assert!(header_in(&old_nhk_s, &reply).is_ok(), "{round}");
        if round == 0 {
            assert!(header_in(&nhk_b, &reply).is_ok(), "responder's first");
        }
        receiver = sender;
        sender = stepped;
        cell = reply;
    }
    Ok(())
}

/// KEM material (§7.3–§7.4, ADR-004): every header of a chain carries the chain's `ek_pq`, `ct_pq` and `dh_pk`
/// (the sender's `kem_s.ek`, `ct_s`, `dh_s`); every new chain carries new ones; the receiver takes them at its
/// step. Four chains, alternating directions.
#[test]
fn ratchet_kem_material_constant_within_a_chain_fresh_at_every_step() -> Result<()> {
    let (mut sender, mut receiver) = session()?;
    let mut seen: Vec<HeaderV1> = Vec::new();
    for round in 0..4_u64 {
        let hk = key(sender.hk_s.as_ref())?;
        let mut cells = Vec::new();
        for i in 0..3_u64 {
            let (next, cell) = send(sender, &text(i))?;
            sender = next;
            cells.push(cell);
        }
        let headers = cells
            .iter()
            .map(|c| header_in(&hk, c))
            .collect::<Result<Vec<_>>>()?;
        let ct_s = sender.ct_s.as_ref().ok_or(Error::Rejected)?;
        for (h, n) in headers.iter().zip(0_u32..) {
            assert_eq!(h.n, n);
            assert_eq!(h.ek_pq, sender.kem_s.ek, "ek_pq, chain {round}");
            assert_eq!(h.ct_pq.as_slice(), ct_s.as_bytes().as_slice(), "ct_pq");
            assert_eq!(h.dh_pk, sender.dh_s.pk, "dh_pk");
        }
        let first = headers.into_iter().next().ok_or(Error::Rejected)?;
        for earlier in &seen {
            assert_ne!(first.ek_pq, earlier.ek_pq, "a new ek_pq, chain {round}");
            assert_ne!(first.ct_pq, earlier.ct_pq, "a new ct_pq");
            assert_ne!(first.dh_pk, earlier.dh_pk, "a new dh_pk");
        }
        for cell in &cells {
            receiver = recv(receiver, cell)?.0;
        }
        let kem_r = receiver.kem_r.as_ref().ok_or(Error::Rejected)?;
        let last_ct_r = receiver.last_ct_r.as_ref().ok_or(Error::Rejected)?;
        assert_eq!(kem_r.as_bytes(), first.ek_pq.as_bytes());
        assert_eq!(last_ct_r.as_bytes(), &*first.ct_pq);
        assert_eq!(receiver.dh_r, Some(first.dh_pk));
        seen.push(first);
        core::mem::swap(&mut sender, &mut receiver);
    }
    Ok(())
}

/// §7.4 note (d): a message that is not the first of its chain performs the step (the first chain and a later
/// one), the positions before it are stored, and `pn`/`n_r` are set as `DHRatchet` says.
#[test]
fn ratchet_any_message_of_a_new_chain_steps() -> Result<()> {
    let (a, b) = session()?;
    let (a, m0) = send(a, &text(0))?;
    let (a, m1) = send(a, &text(1))?;
    let (a, m2) = send(a, &text(2))?;
    let (b, got) = recv_seq(b, &m2)?;
    assert_eq!(got, 2);
    assert!(b.ck_s.is_some(), "the responder stepped");
    assert_eq!((b.n_r, b.n_s, b.pn), (3, 0, 0));
    let (b, a) = exchange(b, a, &text(10))?;
    let (a, n0) = send(a, &text(3))?;
    let (_, n1) = send(a, &text(4))?;
    let dh_before = b.dh_s.pk;
    let (b, got) = recv_seq(b, &n1)?;
    assert_eq!(got, 4);
    assert_ne!(
        b.dh_s.pk, dh_before,
        "a later chain: stepped on its second message"
    );
    assert_eq!((b.n_r, b.n_s, b.pn), (2, 0, 1));
    let positions: Vec<u32> = b.skipped.iter().map(|e| e.n).collect();
    assert_eq!(positions, [0, 1, 0]);
    let mut b = b;
    for (cell, expected) in [(&m1, 1), (&n0, 3), (&m0, 0)] {
        let (next, got) = recv_seq(b, cell)?;
        assert_eq!(got, expected);
        b = next;
    }
    assert!(b.skipped.is_empty());
    Ok(())
}

/// `pn` (§7.3, §7.4): the length of the previous sending chain, in the header and in the state; the receiver
/// fast-forwards its old chain to it and stores the keys it skips.
#[test]
fn ratchet_pn_is_the_previous_chain_length() -> Result<()> {
    let (a, b) = session()?;
    let (a, m0) = send(a, &text(0))?;
    let (a, m1) = send(a, &text(1))?;
    let (a, m2) = send(a, &text(2))?;
    let (b, _) = recv(b, &m0)?;
    let (b, r0) = send(b, &text(10))?;
    let (b, r1) = send(b, &text(11))?;
    let (a, _) = recv(a, &r0)?;
    assert_eq!((a.pn, a.n_s), (3, 0));
    let hk = key(a.hk_s.as_ref())?;
    let (a, n0) = send(a, &text(3))?;
    assert_eq!(header_in(&hk, &n0)?.pn, 3);
    let old_hk_r = key(b.hk_r.as_ref())?;
    let (b, _) = recv(b, &n0)?;
    assert_eq!(b.pn, 2, "B had sent two on its chain");
    assert!(b.skipped.iter().all(|e| bool::from(e.hk.ct_eq(&old_hk_r))));
    let positions: Vec<u32> = b.skipped.iter().map(|e| e.n).collect();
    assert_eq!(positions, [1, 2], "the old chain up to pn = 3");
    // restored from its encoding, B continues; its next header carries pn = 2
    let b = copy(&b)?;
    let hk_b = key(b.hk_s.as_ref())?;
    let (b, r2) = send(b, &text(12))?;
    assert_eq!(header_in(&hk_b, &r2)?.pn, 2);
    let (a, _) = recv(a, &r2)?;
    assert_eq!(recv_seq(a, &r1)?.1, 11, "A stored r1 from B's old chain");
    let (b, _) = recv(b, &m2)?;
    assert_eq!(recv_seq(b, &m1)?.1, 1);
    Ok(())
}

/// `skip_message_keys` stores exactly the last `min(gap, SKIP_WINDOW)` message keys — positions and keys equal the
/// sender's — on the step path (gaps 1, 5, 256, 257, 300) and on the current chain (gap 300); the newest position
/// not stored is refused, the oldest stored one accepted.
#[test]
fn ratchet_skip_stores_exactly_the_last_min_gap_256_keys() -> Result<()> {
    for (gap, on_chain) in [
        (1, false),
        (5, false),
        (256, false),
        (257, false),
        (300, false),
        (300, true),
    ] {
        let (a, b) = session()?;
        let (a, b) = if on_chain {
            exchange(a, b, &text(0))?
        } else {
            (a, b)
        };
        let start = copy(&a)?;
        let mut a = a;
        let lost = advance(&mut a, gap)?;
        let (_, cell) = send(a, &text(1000))?;
        let (b, _) = recv(b, &cell)?;
        let hk = key(start.hk_s.as_ref())?;
        let stored = gap.min(SKIP_WINDOW);
        let first = gap.saturating_sub(SKIP_WINDOW);
        assert_eq!(
            b.skipped.len(),
            usize::try_from(stored).map_err(|_| Error::Rejected)?
        );
        let expected = (start.n_s..)
            .zip(&lost)
            .skip(usize::try_from(first).map_err(|_| Error::Rejected)?);
        for (e, (n, mk)) in b.skipped.iter().zip(expected) {
            assert_eq!(e.n, n, "gap {gap}");
            assert!(bool::from(e.hk.ct_eq(&hk) & e.mk.ct_eq(mk)), "gap {gap}");
        }
        let mut b = b;
        if let Some(older) = first.checked_sub(1) {
            b = rejects(b, &message_at(&start, older)?, "not stored")?;
        }
        let expected_seq = u64::from(start.n_s.saturating_add(first));
        assert_eq!(recv_seq(b, &message_at(&start, first)?)?.1, expected_seq);
    }
    Ok(())
}

/// Lose `k` messages of the sender's current chain, deliver the next one.
fn lose_then_deliver(
    a: RatchetState,
    b: RatchetState,
    k: u32,
) -> Result<(RatchetState, RatchetState)> {
    let mut a = a;
    advance(&mut a, k)?;
    exchange(a, b, &text(u64::from(k)))
}

/// `skipped` is bounded by 512 across chains, evicting the earliest-inserted entries (§7.4): chains of 256, 256
/// and 100 skipped keys leave chain 1's positions 100..256, chain 2's 0..256 and chain 3's 0..100, in insertion
/// order; a full state is the largest encoding.
#[test]
fn ratchet_skipped_bound_evicts_the_earliest_inserted() -> Result<()> {
    let (a, b) = session()?;
    let chain_1 = copy(&a)?;
    let (a, b) = lose_then_deliver(a, b, 256)?;
    let hk_1 = key(b.hk_r.as_ref())?;
    assert_eq!(b.skipped.len(), 256);
    let (b, a) = exchange(b, a, &text(1000))?;
    let (a, b) = lose_then_deliver(a, b, 256)?;
    let hk_2 = key(b.hk_r.as_ref())?;
    assert_eq!(
        b.skipped.len(),
        MAX_SKIPPED,
        "at the bound: nothing evicted"
    );
    assert_eq!(b.to_bytes()?.len(), RatchetState::MAX_ENCODED_LEN);
    let (b, a) = exchange(b, a, &text(1001))?;
    let (_, b) = lose_then_deliver(a, b, 100)?;
    let hk_3 = key(b.hk_r.as_ref())?;
    assert_eq!(b.skipped.len(), MAX_SKIPPED);
    let expected = (100..256_u32)
        .map(|n| (&hk_1, n))
        .chain((0..256).map(|n| (&hk_2, n)))
        .chain((0..100).map(|n| (&hk_3, n)));
    for (e, (hk, n)) in b.skipped.iter().zip(expected) {
        assert!(bool::from(e.hk.ct_eq(hk)));
        assert_eq!(e.n, n);
    }
    let b = rejects(b, &message_at(&chain_1, 99)?, "evicted")?;
    let (b, got) = recv_seq(b, &message_at(&chain_1, 100)?)?;
    assert_eq!(got, 100, "control: the oldest entry kept");
    assert_eq!(b.skipped.len(), 511);
    Ok(())
}

/// The skipped-key lookup tries every distinct header key of `skipped` (§7.4 step 1): keys of three old chains,
/// none of them `hk_r`, found in any order.
#[test]
fn ratchet_skipped_keys_found_under_three_header_keys() -> Result<()> {
    let (mut a, mut b) = session()?;
    let mut late = Vec::new();
    let mut hks = Vec::new();
    for chain in 0..3_u64 {
        let base = chain.saturating_mul(10);
        let (next_a, lost) = send(a, &text(base))?;
        let (next_a, next_b) = exchange(next_a, b, &text(base.saturating_add(1)))?;
        hks.push(key(next_b.hk_r.as_ref())?);
        late.push((lost, base));
        (b, a) = exchange(next_b, next_a, &text(100))?;
    }
    let (_, b) = exchange(a, b, &text(50))?;
    assert_eq!(b.skipped.len(), 3);
    for (e, hk) in b.skipped.iter().zip(&hks) {
        assert!(bool::from(e.hk.ct_eq(hk)));
        assert!(!same(b.hk_r.as_ref(), hk));
    }
    for (i, x) in hks.iter().enumerate() {
        for y in hks.iter().skip(i.saturating_add(1)) {
            assert!(!bool::from(x.ct_eq(y)), "three distinct header keys");
        }
    }
    let mut b = b;
    for i in [1_usize, 0, 2] {
        let (cell, expected) = late.get(i).ok_or(Error::Rejected)?;
        let (next, got) = recv_seq(b, cell)?;
        assert_eq!(got, *expected);
        b = next;
    }
    assert!(b.skipped.is_empty());
    Ok(())
}

/// The skipped path checks neither KEM constancy nor `dh_pk` (reference reading 4): a header under a skipped key
/// with foreign `dh_pk` (= the current `dh_r`, which a step refuses), `pn`, `ek_pq`, `ct_pq` is accepted. On the
/// current chain the skipped lookup comes first: at a skipped position such a header is accepted, at the next
/// position the chain path's constancy check refuses it.
#[test]
fn ratchet_skipped_path_checks_neither_kem_constancy_nor_dh_pk() -> Result<()> {
    let (_, b, _) = old_skipped()?;
    let (hk, mk) = front_entry(&b)?;
    let foreign = HeaderV1 {
        dh_pk: b.dh_r.ok_or(Error::Rejected)?,
        pn: 77,
        n: 0,
        ek_pq: ek768(3)?,
        ct_pq: Box::new([9; MLKEM768_CT_LEN]),
    };
    let (b, got) = recv_seq(b, &seal(&hk, &foreign, mk, &text(5))?)?;
    assert_eq!(got, 5);
    assert!(b.skipped.is_empty());
    // the current chain
    let (a, b) = session()?;
    let (a, _) = send(a, &text(0))?;
    let (a, b) = exchange(a, b, &text(1))?;
    let hk_r = key(b.hk_r.as_ref())?;
    let mut header = header_of(&a)?;
    header.ek_pq = ek768(3)?;
    let cell = seal(&hk_r, &header, chain_mk(&b, header.n)?, &text(2))?;
    let b = rejects(b, &cell, "chain path: constancy")?;
    header.n = 0;
    let (_, mk) = front_entry(&b)?;
    assert_eq!(recv_seq(b, &seal(&hk_r, &header, mk, &text(0))?)?.1, 0);
    Ok(())
}

/// Dummies take the same `encrypt` path as every message (CLAUDE.md §1.4): a dummy performs the first step,
/// advances `n_s`, decrypts to exactly `dummy()`'s encoding and is delivered as `Dummy`.
#[test]
fn ratchet_dummies_take_the_same_path() -> Result<()> {
    let (a, b) = session()?;
    let hk = key(a.hk_s.as_ref())?;
    let (a, d0) = send(a, &content::dummy())?;
    assert_eq!((d0.len(), a.n_s), (CELL_LEN, 1));
    let (a, t1) = send(a, &text(1))?;
    let (_, d2) = send(a, &content::dummy())?;
    for (cell, n) in [(&d0, 0), (&t1, 1), (&d2, 2)] {
        assert_eq!(header_in(&hk, cell)?.n, n);
    }
    let (b, pt) = recv(b, &d0)?;
    assert!(b.ck_s.is_some(), "the dummy performed the step");
    assert_eq!(
        pt.as_bytes().as_slice(),
        content::dummy().encode()?.as_slice()
    );
    let c = pt.content()?;
    assert!(matches!(c.body, ContentBody::Dummy) && c.seq == 0 && c.ts == 0);
    let (_, peer) = identity(1)?;
    let mut trust = Trust::Verified;
    let delivery = Inbox::new().receive(&pt, &content::ik_sig(&peer)?, &mut trust);
    assert_eq!(kind(&delivery), "Dummy");
    let (b, pt) = recv(b, &d2)?;
    assert!(matches!(pt.content()?.body, ContentBody::Dummy));
    let (b, _) = send(b, &content::dummy())?;
    assert_eq!(b.n_s, 1, "the responder's dummies likewise");
    Ok(())
}

/// Exactly `MAX_FF` positions are fast-forwarded on the current chain, `MAX_FF + 1` are not; both cells honest
/// (2 × 2^20 `KDF_CK`: ≈ 20 s in a debug build). Feature `kat` only, i.e. in the `kat` step and not for every
/// mutant of the mutation gate; the same bound is checked quickly by `select::tests::skip_plan_bounds`, the Kani
/// harness `tr_skip_plan`, vector N10 and the property tests' `MAX_FF` gaps.
#[cfg(feature = "kat")]
#[test]
fn ratchet_fast_forward_bound_on_the_chain() -> Result<()> {
    let (a, b) = session()?;
    let (a, b) = exchange(a, b, &text(0))?;
    let hk = key(a.hk_s.as_ref())?;
    let exact = b.n_r.checked_add(MAX_FF).ok_or(Error::Rejected)?;
    let mut ck = key(b.ck_r.as_ref())?;
    for _ in 0..MAX_FF {
        ck = kdf_ck(&ck)?.0;
    }
    let (ck_next, mk_exact) = kdf_ck(&ck)?;
    let mk_over = kdf_ck(&ck_next)?.1;
    let mut header = header_of(&a)?;
    header.n = exact.checked_add(1).ok_or(Error::Rejected)?;
    let b = rejects(b, &seal(&hk, &header, mk_over, &text(2))?, "MAX_FF + 1")?;
    header.n = exact;
    let (b, got) = recv_seq(b, &seal(&hk, &header, mk_exact, &text(1))?)?;
    assert_eq!(got, 1);
    assert_eq!(Some(b.n_r), exact.checked_add(1));
    let positions: Vec<u32> = b.skipped.iter().map(|e| e.n).collect();
    let window: Vec<u32> = (exact.saturating_sub(SKIP_WINDOW)..exact).collect();
    assert_eq!(positions, window);
    Ok(())
}

/// A DH step fast-forwards `MAX_FF` positions on the old chain (`pn`) and `MAX_FF` on the new one (`n`) — the worst
/// case of §7.4 note (a) — and refuses `MAX_FF + 1` on either; all cells honest (3 × 2^20 `KDF_CK`: ≈ 30 s in a
/// debug build). Feature `kat` only, as `ratchet_fast_forward_bound_on_the_chain`.
#[cfg(feature = "kat")]
#[test]
fn ratchet_fast_forward_bound_on_a_step() -> Result<()> {
    let (a, b) = session()?;
    let (_, b) = exchange(a, b, &text(0))?;
    let nhk_r = key(b.nhk_r.as_ref())?;
    let pn_exact = b.n_r.checked_add(MAX_FF).ok_or(Error::Rejected)?;
    let mut header = new_step_header(b.n_r, 0)?;
    let mut ck = step_ck(&b, &header)?;
    for _ in 0..MAX_FF {
        ck = kdf_ck(&ck)?.0;
    }
    let (ck_next, mk_exact) = kdf_ck(&ck)?;
    let mk_over = kdf_ck(&ck_next)?.1;
    header.n = MAX_FF.saturating_add(1);
    let b = rejects(b, &seal(&nhk_r, &header, mk_over, &text(2))?, "new chain")?;
    header.n = MAX_FF;
    header.pn = pn_exact.saturating_add(1);
    let cell = seal(&nhk_r, &header, key(Some(&mk_exact))?, &text(1))?;
    let b = rejects(b, &cell, "old chain")?;
    header.pn = pn_exact;
    let (b, got) = recv_seq(b, &seal(&nhk_r, &header, mk_exact, &text(1))?)?;
    assert_eq!(got, 1);
    assert_eq!((b.n_r, b.pn), (MAX_FF.saturating_add(1), 0));
    let positions: Vec<u32> = b.skipped.iter().map(|e| e.n).collect();
    let window: Vec<u32> = (pn_exact.saturating_sub(SKIP_WINDOW)..pn_exact)
        .chain(MAX_FF.saturating_sub(SKIP_WINDOW)..MAX_FF)
        .collect();
    assert_eq!(
        positions, window,
        "256 on the old chain, then 256 on the new"
    );
    Ok(())
}

/// Feature `kat`: the message-key digests of the two sides agree, and the accessors read the fields.
#[cfg(feature = "kat")]
#[test]
fn ratchet_kat_accessors() -> Result<()> {
    let (a, b) = session()?;
    assert!(same(a.hk_s_kat(), &key(a.hk_s.as_ref())?));
    assert_eq!(b.sb_kat(), &SB);
    let mk = mk_after(a.ck_s.as_ref().ok_or(Error::Rejected)?, 0)?;
    let sealed = a.encrypt(&text(1)).map_err(|r| r.error())?;
    let digest = sealed.message_key_digest_kat();
    assert_eq!(digest, secmp_crypto::sha256(&[mk.expose_secret()]));
    let (_, cell) = sealed.persist(|_| Ok::<(), Error>(()))?;
    let (b, pt) = recv(b, cell.as_bytes())?;
    assert_eq!(pt.message_key_digest_kat(), digest);
    let (hk_r, nhk_r) = b.receiving_header_keys_kat();
    assert!(same(hk_r, &key(b.hk_r.as_ref())?) && same(nhk_r, &key(b.nhk_r.as_ref())?));
    Ok(())
}

// ---------------------------------------------------------------------------------- 5. persistence

/// `RatchetStateV1` written field by field from the module documentation of `state.rs` — a writer independent of
/// `to_bytes`, for encodings no state produces.
struct Raw {
    fmt: u8,
    sb_rk_dh_s: Vec<u8>,
    dh_r: Option<Vec<u8>>,
    kem_seed: Vec<u8>,
    kem_r: Option<Vec<u8>>,
    last_ct_r: Option<Vec<u8>>,
    ct_s: Option<Vec<u8>>,
    ck_s: Option<Vec<u8>>,
    ck_r: Option<Vec<u8>>,
    hk_s: Option<Vec<u8>>,
    hk_r: Option<Vec<u8>>,
    nhk_s: Option<Vec<u8>>,
    nhk_r: Option<Vec<u8>>,
    n_s: u32,
    n_r: u32,
    pn: u32,
    /// The `count` field; `None`: the number of entries.
    count: Option<u16>,
    skipped: Vec<(Vec<u8>, u32, Vec<u8>)>,
}

/// An edit of a [`Raw`] encoding.
type RawEdit = fn(&mut Raw);

fn secret_vec(k: &SecretBytes<32>) -> Vec<u8> {
    k.expose_secret().to_vec()
}

impl Raw {
    fn of(s: &RatchetState) -> Self {
        Self {
            fmt: 1,
            sb_rk_dh_s: [
                s.sb.as_slice(),
                s.rk.expose_secret(),
                s.dh_s.sk.expose_secret(),
            ]
            .concat(),
            dh_r: s.dh_r.map(|k| k.as_bytes().to_vec()),
            kem_seed: s.kem_s.dk.expose_seed().to_vec(),
            kem_r: s.kem_r.as_ref().map(|k| k.as_bytes().to_vec()),
            last_ct_r: s.last_ct_r.as_ref().map(|c| c.as_bytes().to_vec()),
            ct_s: s.ct_s.as_ref().map(|c| c.as_bytes().to_vec()),
            ck_s: s.ck_s.as_ref().map(secret_vec),
            ck_r: s.ck_r.as_ref().map(secret_vec),
            hk_s: s.hk_s.as_ref().map(secret_vec),
            hk_r: s.hk_r.as_ref().map(secret_vec),
            nhk_s: s.nhk_s.as_ref().map(secret_vec),
            nhk_r: s.nhk_r.as_ref().map(secret_vec),
            n_s: s.n_s,
            n_r: s.n_r,
            pn: s.pn,
            count: None,
            skipped: s
                .skipped
                .iter()
                .map(|e| (secret_vec(&e.hk), e.n, secret_vec(&e.mk)))
                .collect(),
        }
    }

    /// The encoding and the offsets of its ten presence bytes.
    fn encode(&self) -> Result<(Vec<u8>, Vec<usize>)> {
        let mut out = vec![self.fmt];
        let mut presence = Vec::new();
        let mut opt = |out: &mut Vec<u8>, x: Option<&[u8]>| {
            presence.push(out.len());
            if let Some(bytes) = x {
                out.push(1);
                out.extend_from_slice(bytes);
            } else {
                out.push(0);
            }
        };
        out.extend_from_slice(&self.sb_rk_dh_s);
        opt(&mut out, self.dh_r.as_deref());
        out.extend_from_slice(&self.kem_seed);
        for x in [
            &self.kem_r,
            &self.last_ct_r,
            &self.ct_s,
            &self.ck_s,
            &self.ck_r,
            &self.hk_s,
            &self.hk_r,
            &self.nhk_s,
            &self.nhk_r,
        ] {
            opt(&mut out, x.as_deref());
        }
        for v in [self.n_s, self.n_r, self.pn] {
            out.extend_from_slice(&v.to_be_bytes());
        }
        let count = match self.count {
            Some(c) => c,
            None => u16::try_from(self.skipped.len()).map_err(|_| Error::Rejected)?,
        };
        out.extend_from_slice(&count.to_be_bytes());
        for (hk, n, mk) in &self.skipped {
            out.extend_from_slice(hk);
            out.extend_from_slice(&n.to_be_bytes());
            out.extend_from_slice(mk);
        }
        Ok((out, presence))
    }

    fn bytes(&self) -> Result<Vec<u8>> {
        Ok(self.encode()?.0)
    }
}

/// `from_bytes` refuses `bytes` with `Rejected` (never `Unavailable`).
fn state_rejected(bytes: &[u8], what: &str) {
    assert_eq!(
        RatchetState::from_bytes(bytes).err(),
        Some(Error::Rejected),
        "{what}"
    );
}

/// `from_bytes` accepts `bytes`, which re-encode to themselves.
fn state_accepted(bytes: &[u8], what: &str) -> Result<()> {
    let decoded = RatchetState::from_bytes(bytes);
    assert!(decoded.is_ok(), "{what}");
    assert_eq!(*decoded?.to_bytes()?, *bytes, "{what}");
    Ok(())
}

/// The encoding of `s` with `edit` applied is refused.
fn edit_rejected(s: &RatchetState, what: &str, edit: impl FnOnce(&mut Raw)) -> Result<()> {
    let mut raw = Raw::of(s);
    edit(&mut raw);
    state_rejected(&raw.bytes()?, what);
    Ok(())
}

/// The encoding of `s` with `edit` applied is accepted.
fn edit_accepted(s: &RatchetState, what: &str, edit: impl FnOnce(&mut Raw)) -> Result<()> {
    let mut raw = Raw::of(s);
    edit(&mut raw);
    state_accepted(&raw.bytes()?, what)
}

/// `from_bytes(to_bytes(s))` re-encodes identically; the encoding is the documented layout, at most
/// `MAX_ENCODED_LEN` long; the public halves of `dh_s`, `kem_s` are recomputed.
fn state_round_trip(s: &RatchetState, what: &str) -> Result<()> {
    let bytes = s.to_bytes()?;
    assert!(bytes.len() <= RatchetState::MAX_ENCODED_LEN, "{what}");
    assert_eq!(Raw::of(s).bytes()?, *bytes, "{what}: the documented layout");
    let back = RatchetState::from_bytes(&bytes)?;
    assert_eq!(*back.to_bytes()?, *bytes, "{what}");
    assert_eq!(back.dh_s.pk, s.dh_s.pk, "{what}");
    assert_eq!(back.kem_s.ek, s.kem_s.ek, "{what}");
    Ok(())
}

/// Round trips: fresh initiator and responder, after steps, with skipped keys (the full 512-entry state is in
/// `ratchet_skipped_bound_evicts_the_earliest_inserted`).
#[test]
fn state_round_trips_in_every_shape() -> Result<()> {
    let (a, b) = session()?;
    state_round_trip(&a, "initiator, fresh")?;
    state_round_trip(&b, "responder, fresh")?;
    let (a, b) = exchange(a, b, &text(0))?;
    state_round_trip(&a, "initiator, sending")?;
    state_round_trip(&b, "responder after its first step")?;
    let (b, a) = exchange(b, a, &text(1))?;
    state_round_trip(&a, "initiator after its first step")?;
    state_round_trip(&b, "responder, sending")?;
    let (_, b, _) = old_skipped()?;
    state_round_trip(&b, "with a skipped key")?;
    Ok(())
}

/// `count`: every option present and 512 entries is exactly `MAX_ENCODED_LEN`; 513 entries or a `count` of 65535
/// are refused; `to_bytes` refuses a `skipped` over its bound (never for a state built by this module).
#[test]
fn state_skipped_count_bound() -> Result<()> {
    let (_, full, _) = old_skipped()?;
    let entries = |k: u32| {
        (0..k)
            .map(|n| (vec![1; 32], n, vec![2; 32]))
            .collect::<Vec<_>>()
    };
    let mut raw = Raw::of(&full);
    raw.skipped = entries(512);
    let bytes = raw.bytes()?;
    assert_eq!(bytes.len(), RatchetState::MAX_ENCODED_LEN);
    state_accepted(&bytes, "512 entries")?;
    raw.skipped = entries(513);
    state_rejected(&raw.bytes()?, "513 entries");
    raw.count = Some(u16::MAX);
    state_rejected(&raw.bytes()?, "count 65535");
    let (hk, mk) = front_entry(&full)?;
    let mut full = full;
    while full.skipped.len() <= MAX_SKIPPED {
        full.skipped.push_back(SkippedKey {
            hk: key(Some(&hk))?,
            n: 0,
            mk: key(Some(&mk))?,
        });
    }
    assert_eq!(full.to_bytes().err(), Some(Error::Rejected));
    Ok(())
}

/// The format byte, every presence byte (2 or 0xff), every truncation and a trailing byte are refused — for a
/// fresh initiator, a fresh responder and a state with every option present.
#[test]
fn state_rejects_malformed_encodings() -> Result<()> {
    let (a, b) = session()?;
    let (_, full, _) = old_skipped()?;
    for (s, what) in [(&a, "initiator"), (&b, "responder"), (&full, "full")] {
        let (bytes, presence) = Raw::of(s).encode()?;
        assert_eq!(presence.len(), 10);
        state_accepted(&bytes, what)?;
        for fmt in [0_u8, 2, 0xff] {
            let mut wrong = bytes.clone();
            put(&mut wrong, 0, &[fmt]);
            state_rejected(&wrong, what);
        }
        for at in presence {
            for value in [2_u8, 0xff] {
                let mut wrong = bytes.clone();
                put(&mut wrong, at, &[value]);
                state_rejected(&wrong, what);
            }
        }
        for len in 0..bytes.len() {
            state_rejected(bytes.get(..len).ok_or(Error::Rejected)?, what);
        }
        let mut longer = bytes.clone();
        longer.push(0);
        state_rejected(&longer, what);
    }
    Ok(())
}

/// The key checks of the wire: `dh_r` not of low order (§4.1 (a)), `kem_r` passes the modulus check (c).
#[test]
fn state_rejects_refused_keys() -> Result<()> {
    let (_, full, _) = old_skipped()?;
    for (what, u) in [
        ("dh_r 0", [0; 32]),
        ("dh_r 1", U_ONE),
        ("dh_r p - 1", U_P_MINUS_ONE),
    ] {
        edit_rejected(&full, what, |r| r.dh_r = Some(u.to_vec()))?;
    }
    edit_rejected(&full, "kem_r modulus", |r| {
        if let Some(k) = r.kem_r.as_mut() {
            put(k, 0, &[0xff; 3]);
        }
    })?;
    let other_dh = x25519(5)?.as_bytes().to_vec();
    edit_accepted(&full, "control: another dh_r", |r| r.dh_r = Some(other_dh))?;
    let other_ek = ek768(4)?.as_bytes().to_vec();
    edit_accepted(&full, "control: another kem_r", |r| {
        r.kem_r = Some(other_ek);
    })?;
    Ok(())
}

/// The shape of a reachable state (module documentation of `state.rs`); the controls are the two extremes of
/// each group.
#[test]
fn state_rejects_unreachable_shapes() -> Result<()> {
    let (initiator, responder) = session()?;
    let (_, full, _) = old_skipped()?;
    let rejected: [(&str, RawEdit); 11] = [
        ("no nhk_s", |r| r.nhk_s = None),
        ("no nhk_r", |r| r.nhk_r = None),
        ("sending group without ck_s", |r| r.ck_s = None),
        ("sending group without hk_s", |r| r.hk_s = None),
        ("sending group without ct_s", |r| r.ct_s = None),
        ("sending group without kem_r", |r| r.kem_r = None),
        ("sending group without dh_r", |r| r.dh_r = None),
        ("receiving group without ck_r", |r| r.ck_r = None),
        ("receiving group without hk_r", |r| r.hk_r = None),
        ("receiving group without last_ct_r", |r| r.last_ct_r = None),
        ("receiving without sending", |r| {
            (r.ck_s, r.hk_s, r.ct_s, r.kem_r, r.dh_r) = (None, None, None, None, None);
            r.n_s = 0;
        }),
    ];
    for (what, edit) in rejected {
        edit_rejected(&full, what, edit)?;
    }
    edit_rejected(&responder, "responder without nhk_r", |r| r.nhk_r = None)?;
    edit_rejected(&initiator, "n_r without receiving", |r| r.n_r = 1)?;
    edit_rejected(&initiator, "pn without receiving", |r| r.pn = 1)?;
    edit_rejected(&initiator, "skipped without receiving", |r| {
        r.skipped = vec![(vec![1; 32], 0, vec![2; 32])];
    })?;
    edit_rejected(&responder, "n_s without sending", |r| r.n_s = 1)?;
    edit_accepted(&initiator, "control: n_s with sending", |r| r.n_s = 5)?;
    edit_accepted(&full, "control: no receiving group", |r| {
        (r.ck_r, r.hk_r, r.last_ct_r) = (None, None, None);
        (r.n_r, r.pn) = (0, 0);
        r.skipped.clear();
    })?;
    edit_accepted(&full, "control: neither group", |r| {
        (r.ck_s, r.hk_s, r.ct_s, r.kem_r, r.dh_r) = (None, None, None, None, None);
        (r.ck_r, r.hk_r, r.last_ct_r) = (None, None, None);
        (r.n_s, r.n_r, r.pn) = (0, 0, 0);
        r.skipped.clear();
    })?;
    Ok(())
}

/// `skipped` is canonical: grouped by header key in insertion order, `n` strictly increasing within a group, no
/// group's key repeated in a later group.
#[test]
fn state_rejects_noncanonical_skipped() -> Result<()> {
    let (_, full, _) = old_skipped()?;
    let entry = |hk: u8, n: u32| (vec![hk; 32], n, vec![9; 32]);
    for (what, entries) in [
        ("n repeated", vec![entry(1, 5), entry(1, 5)]),
        ("n decreasing", vec![entry(1, 5), entry(1, 4)]),
        (
            "a group's key repeated later",
            vec![entry(1, 0), entry(2, 0), entry(1, 1)],
        ),
    ] {
        edit_rejected(&full, what, move |r| r.skipped = entries)?;
    }
    for (what, entries) in [
        (
            "two groups",
            vec![entry(1, 0), entry(1, 1), entry(2, 0), entry(2, 7)],
        ),
        ("one entry", vec![entry(2, 9)]),
        ("none", vec![]),
    ] {
        edit_accepted(&full, what, move |r| r.skipped = entries)?;
    }
    Ok(())
}

/// Entries no run can produce are refused (M3 review F8): `(hk_r, n >= n_r)` and any `(nhk_r, *)`; the controls
/// are `(hk_r, n < n_r)` and an unrelated key.
#[test]
fn state_rejects_unreachable_skipped_entries() -> Result<()> {
    let (_, full, _) = old_skipped()?;
    assert!(full.n_r >= 1);
    edit_rejected(&full, "(hk_r, n_r)", |r| {
        let n_r = r.n_r;
        r.skipped = vec![(r.hk_r.clone().unwrap_or_default(), n_r, vec![9; 32])];
    })?;
    edit_rejected(&full, "(hk_r, n_r + 1)", |r| {
        let n_r = r.n_r.saturating_add(1);
        r.skipped = vec![(r.hk_r.clone().unwrap_or_default(), n_r, vec![9; 32])];
    })?;
    edit_rejected(&full, "(nhk_r, 0)", |r| {
        r.skipped = vec![(r.nhk_r.clone().unwrap_or_default(), 0, vec![9; 32])];
    })?;
    edit_rejected(&full, "(nhk_r, after a valid group)", |r| {
        r.skipped = vec![
            (vec![1; 32], 0, vec![9; 32]),
            (r.nhk_r.clone().unwrap_or_default(), 3, vec![9; 32]),
        ];
    })?;
    edit_accepted(&full, "control: (hk_r, n_r - 1)", |r| {
        let n = r.n_r.saturating_sub(1);
        r.skipped = vec![(r.hk_r.clone().unwrap_or_default(), n, vec![9; 32])];
    })?;
    edit_accepted(&full, "control: unrelated key with a large n", |r| {
        r.skipped = vec![(vec![1; 32], u32::MAX, vec![9; 32])];
    })?;
    Ok(())
}

// ------------------------------------------------------------------------------ 6. the content layer

/// A contact's identity signing key and its `IKSPublic` (§6.2).
fn identity(seed: u8) -> Result<(HybridSigningKey, IksPublic)> {
    let sk = HybridSigningKey::from_seeds(&[seed; 32], &[seed; 32])?;
    let vk = sk.verifying_key();
    let iks = IksPublic {
        ik_ed25519: Ed25519Pk::from_bytes(vk.ed25519())?,
        ik_mldsa65: Box::new(*vk.mldsa65()),
        ik_dh: x25519(seed)?,
    };
    Ok((sk, iks))
}

/// The verifying key of `identity(seed)` as the content layer imports it.
fn peer(seed: u8) -> Result<HybridVerifyingKey> {
    content::ik_sig(&identity(seed)?.1)
}

/// A `KeyChange` fragment payload (§7.6, §7.7): `carried` with `HybridSign(signer, label, fingerprint(of))`.
fn key_change(
    signer: &HybridSigningKey,
    label: Label,
    of: &IksPublic,
    carried: &IksPublic,
) -> Result<Zeroizing<Vec<u8>>> {
    let fp = Fingerprint::of_encoded_iks(&of.encode()?)?;
    let sig = signer.sign(label, fp.as_bytes())?;
    FragmentPayload::KeyChange(KeyChangeBody {
        iks: carried.clone(),
        sig: HybridSig::from_bytes(sig.as_bytes())?,
    })
    .encode()
}

/// One Fragment Content.
fn fragment(msg_id: u8, idx: u16, total: u16, chunk: &[u8]) -> Content {
    Content {
        seq: 0,
        ts: 0,
        body: ContentBody::Fragment(Fragment {
            msg_id: [msg_id; 16],
            idx,
            total,
            chunk: Zeroizing::new(chunk.to_vec()),
        }),
    }
}

/// `payload` fragmented under `msg_id` into chunks of `chunk` bytes (the last one shorter).
fn fragments(msg_id: u8, payload: &[u8], chunk: usize) -> Result<Vec<Content>> {
    let parts: Vec<&[u8]> = payload.chunks(chunk).collect();
    let total = u16::try_from(parts.len()).map_err(|_| Error::Rejected)?;
    Ok(parts
        .into_iter()
        .zip(0_u16..)
        .map(|(part, idx)| fragment(msg_id, idx, total, part))
        .collect())
}

/// `payload` fragmented under `msg_id` in the canonical shape (spec §7.6 rev 2.4): maximal chunks, remainder last.
fn fragments_canonical(msg_id: u8, payload: &[u8]) -> Result<Vec<Content>> {
    fragments(msg_id, payload, 1669)
}

/// The Contents as the responder of one session decrypts them.
fn plaintexts(contents: &[Content]) -> Result<Vec<Plaintext>> {
    let (mut a, mut b) = session()?;
    let mut out = Vec::with_capacity(contents.len());
    for c in contents {
        let (next_a, cell) = send(a, c)?;
        let (next_b, pt) = recv(b, &cell)?;
        assert_eq!(pt.as_bytes().as_slice(), c.encode()?.as_slice());
        (a, b) = (next_a, next_b);
        out.push(pt);
    }
    Ok(out)
}

/// The name of a delivery's variant.
fn kind(d: &Delivery) -> &'static str {
    match d {
        Delivery::Dummy => "Dummy",
        Delivery::Handshake(_) => "Handshake",
        Delivery::Messages(_) => "Messages",
        Delivery::Routes(_) => "Routes",
        Delivery::Receipt(_) => "Receipt",
        Delivery::Control(_) => "Control",
        Delivery::KeyChange(_) => "KeyChange",
        Delivery::KeyChangeRefused => "KeyChangeRefused",
        Delivery::Partial => "Partial",
        Delivery::Malformed => "Malformed",
        Delivery::Frozen => "Frozen",
    }
}

fn kinds(ds: &[Delivery]) -> Vec<&'static str> {
    ds.iter().map(kind).collect()
}

/// What the plaintexts at `order` deliver through `inbox`, in that order.
fn receive_all(
    inbox: &mut Inbox,
    pts: &[Plaintext],
    order: &[usize],
    peer: &HybridVerifyingKey,
    trust: &mut Trust,
) -> Result<Vec<Delivery>> {
    order
        .iter()
        .map(|i| Ok(inbox.receive(pts.get(*i).ok_or(Error::Rejected)?, peer, trust)))
        .collect()
}

/// Every Content type is delivered as its `Delivery`, with its values (§7.6, plan D7).
#[test]
fn content_every_type_is_delivered() -> Result<()> {
    let route = || RouteDescriptor::Unknown {
        kind: 2,
        blob: Zeroizing::new(vec![4; 8]),
    };
    let receipt = ReceiptBody {
        kind: ReceiptKind::Delivered,
        msg_ids: vec![[1; 16], [2; 16]],
    };
    let control = ControlBody {
        code: ControlCode::ContactRemoved,
        arg: Zeroizing::new(vec![3; 4]),
    };
    let wrap = |body| Content {
        seq: 7,
        ts: 8,
        body,
    };
    let contents = [
        content::dummy(),
        wrap(ContentBody::Handshake(HandshakeBody {
            profile: Profile::new("alice", None)?,
            routes: vec![route()],
        })),
        text(3),
        wrap(ContentBody::RouteUpdate(RouteUpdateBody {
            routes: vec![route(), route()],
        })),
        wrap(ContentBody::Receipt(receipt.clone())),
        wrap(ContentBody::Control(control.clone())),
    ];
    let pts = plaintexts(&contents)?;
    let mut inbox = Inbox::new();
    let mut trust = Trust::Unverified;
    let ds = receive_all(&mut inbox, &pts, &[0, 1, 2, 3, 4, 5], &peer(1)?, &mut trust)?;
    assert_eq!(
        kinds(&ds),
        [
            "Dummy",
            "Handshake",
            "Messages",
            "Routes",
            "Receipt",
            "Control"
        ]
    );
    let mut ds = ds.into_iter().skip(1);
    if let Some(Delivery::Handshake(h)) = ds.next() {
        assert_eq!((h.profile.name(), h.routes.len()), ("alice", 1));
    }
    if let Some(Delivery::Messages(m)) = ds.next() {
        assert_eq!(m, [message(3)]);
    }
    if let Some(Delivery::Routes(r)) = ds.next() {
        assert_eq!(r.len(), 2);
    }
    if let Some(Delivery::Receipt(r)) = ds.next() {
        assert_eq!(r, receipt);
    }
    if let Some(Delivery::Control(c)) = ds.next() {
        assert_eq!(c, control);
    }
    assert_eq!((trust, inbox.partials()), (Trust::Unverified, 0));
    Ok(())
}

/// A MAC-valid cell whose padded Content does not decode (plan D6): the ratchet accepts it (the state advances and
/// the message key is consumed — the same cell again is refused) and it is delivered as `Malformed`; on the step
/// path (the first body) and on the current chain.
#[test]
fn content_undecodable_content_is_consumed_and_malformed() -> Result<()> {
    let fields = |ver: u8, content_type: u8, body: &[u8]| -> Result<Zeroizing<Vec<u8>>> {
        let mut f = vec![ver, content_type];
        f.extend_from_slice(&[0; 16]);
        f.extend_from_slice(
            &u16::try_from(body.len())
                .map_err(|_| Error::Rejected)?
                .to_be_bytes(),
        );
        f.extend_from_slice(body);
        pad(&f, BODY_LEN)
    };
    let bodies = [
        Zeroizing::new(vec![0; BODY_LEN]),
        fields(1, 0x05, &[])?,
        fields(2, 0x00, &[])?,
        fields(1, 0x00, &[7])?,
        fields(1, 0x02, &[])?,
        fields(1, 0x08, &[])?,
    ];
    let peer = peer(1)?;
    let (mut a, mut b) = session()?;
    for (i, body) in (1_u32..).zip(&bodies) {
        let cell = forge(&mut a, |_| {}, body)?;
        let before = b.to_bytes()?;
        let (next, pt) = recv(b, &cell)?;
        assert_ne!(*next.to_bytes()?, *before, "{i}: the state advanced");
        assert_eq!(next.n_r, i);
        assert_eq!(pt.content().err(), Some(Error::Rejected), "{i}");
        let mut trust = Trust::Verified;
        let delivery = Inbox::new().receive(&pt, &peer, &mut trust);
        assert_eq!((kind(&delivery), trust), ("Malformed", Trust::Verified));
        b = rejects(next, &cell, "consumed")?;
    }
    Ok(())
}

/// Fragments are reassembled in order and out of order; identical duplicates are ignored (plan D7).
#[test]
fn content_fragments_reassemble_in_any_order() -> Result<()> {
    let batch = BatchBody {
        messages: vec![AppMessage {
            msg_id: [5; 16],
            kind: AppKind::AttachmentInline,
            expire_after: 9,
            payload: Zeroizing::new(vec![0x5a; 4000]),
        }],
    };
    let payload = FragmentPayload::Batch(batch.clone()).encode()?;
    let pts = plaintexts(&fragments_canonical(1, &payload)?)?;
    assert_eq!(pts.len(), 3);
    let peer = peer(1)?;
    for order in [&[0, 1, 2][..], &[2, 0, 1][..], &[0, 0, 1, 1, 2][..]] {
        let mut inbox = Inbox::new();
        let mut trust = Trust::Verified;
        let ds = receive_all(&mut inbox, &pts, order, &peer, &mut trust)?;
        let (last, earlier) = ds.split_last().ok_or(Error::Rejected)?;
        assert!(earlier.iter().all(|d| kind(d) == "Partial"), "{order:?}");
        assert_eq!(kind(last), "Messages", "{order:?}");
        if let Delivery::Messages(m) = last {
            assert_eq!(*m, batch.messages);
        }
        assert_eq!(inbox.partials(), 0);
    }
    Ok(())
}

/// A conflicting duplicate or a `total` mismatch discards the partial message (`Malformed`); a later fragment of
/// it starts a new one.
#[test]
fn content_inconsistent_fragments_are_discarded() -> Result<()> {
    let contents = [
        fragment(1, 0, 2, &[1]),
        fragment(1, 0, 2, &[2]),
        fragment(2, 0, 2, &[1]),
        fragment(2, 1, 3, &[2]),
        fragment(1, 1, 2, &[3]),
    ];
    let pts = plaintexts(&contents)?;
    let peer = peer(1)?;
    let mut inbox = Inbox::new();
    let mut trust = Trust::Verified;
    let mut seen = Vec::new();
    for i in 0..contents.len() {
        let ds = receive_all(&mut inbox, &pts, &[i], &peer, &mut trust)?;
        seen.push((kinds(&ds).concat(), inbox.partials()));
    }
    let expected = [
        ("Partial", 1),
        ("Malformed", 0),
        ("Partial", 1),
        ("Malformed", 0),
        ("Partial", 1),
    ];
    assert_eq!(seen, expected.map(|(k, n)| (k.to_owned(), n)));
    Ok(())
}

/// At most `MAX_PARTIALS` messages are in reassembly; the oldest is evicted first.
#[test]
fn content_partials_evict_the_oldest() -> Result<()> {
    let mut firsts = Vec::new();
    let mut seconds = Vec::new();
    for id in 10..19_u8 {
        let payload = FragmentPayload::Receipt(ReceiptBody {
            kind: ReceiptKind::Read,
            msg_ids: vec![[id; 16]; 120],
        })
        .encode()?;
        let mut parts = fragments_canonical(id, &payload)?.into_iter();
        firsts.push(parts.next().ok_or(Error::Rejected)?);
        seconds.push(parts.next().ok_or(Error::Rejected)?);
        assert!(parts.next().is_none());
    }
    firsts.extend(seconds);
    let pts = plaintexts(&firsts)?;
    let peer = peer(1)?;
    let mut inbox = Inbox::new();
    let mut trust = Trust::Verified;
    let order: Vec<usize> = (0..9).collect();
    let ds = receive_all(&mut inbox, &pts, &order, &peer, &mut trust)?;
    assert!(ds.iter().all(|d| kind(d) == "Partial"));
    assert_eq!(inbox.partials(), MAX_PARTIALS);
    // id 10 was evicted: its second fragment starts anew (evicting id 11); id 12 completes; id 11 starts anew
    let ds = receive_all(&mut inbox, &pts, &[9, 11, 10], &peer, &mut trust)?;
    assert_eq!(kinds(&ds), ["Partial", "Receipt", "Partial"]);
    assert_eq!(inbox.partials(), MAX_PARTIALS);
    Ok(())
}

/// A reassembled message is processed as a Content of its `inner_type` (§7.6): Batch, `RouteUpdate`, Receipt,
/// Control, `KeyChange`; an inner type outside {2, 4, 5, 6, 7} or an undecodable body is `Malformed` — except an
/// undecodable `KeyChange`, which is unverifiable and freezes (M3 review C3).
#[test]
fn content_reassembled_inner_types() -> Result<()> {
    let (old_sk, old_iks) = identity(1)?;
    let (_, new_iks) = identity(2)?;
    let kc = key_change(&old_sk, Label::TrKeychange, &new_iks, &new_iks)?;
    let long = |head: &[u8]| Zeroizing::new([head, &[0; 1700]].concat());
    let payloads = [
        (
            "Messages",
            FragmentPayload::Batch(BatchBody {
                messages: (1..=100).map(message).collect(),
            })
            .encode()?,
        ),
        (
            "Routes",
            FragmentPayload::RouteUpdate(RouteUpdateBody {
                routes: (0..200)
                    .map(|_| RouteDescriptor::Unknown {
                        kind: 3,
                        blob: Zeroizing::new(vec![1; 5]),
                    })
                    .collect(),
            })
            .encode()?,
        ),
        (
            "Receipt",
            FragmentPayload::Receipt(ReceiptBody {
                kind: ReceiptKind::Delivered,
                msg_ids: vec![[4; 16]; 120],
            })
            .encode()?,
        ),
        (
            "Control",
            FragmentPayload::Control(ControlBody {
                code: ControlCode::SessionResetRequest,
                arg: Zeroizing::new(vec![0; 1700]),
            })
            .encode()?,
        ),
        ("KeyChange", kc.clone()),
        ("Malformed", long(&[0x00])),
        ("Malformed", long(&[0x01])),
        ("Malformed", long(&[0x03])),
        ("Malformed", long(&[0x08])),
        ("Malformed", long(&[0x02])),
        // a truncated KeyChange does not decode: unverifiable, so it freezes (M3 review C3, reading of SQ-26)
        (
            "KeyChangeRefused",
            Zeroizing::new(kc.get(..5000).ok_or(Error::Rejected)?.to_vec()),
        ),
    ];
    let mut contents = Vec::new();
    let mut last_of = Vec::new();
    for (id, (_, payload)) in (1_u8..).zip(&payloads) {
        contents.extend(fragments_canonical(id, payload)?);
        last_of.push(contents.len().saturating_sub(1));
    }
    let pts = plaintexts(&contents)?;
    let mut inbox = Inbox::new();
    let mut trust = Trust::Verified;
    let order: Vec<usize> = (0..pts.len()).collect();
    let ds = receive_all(
        &mut inbox,
        &pts,
        &order,
        &content::ik_sig(&old_iks)?,
        &mut trust,
    )?;
    for (i, d) in ds.iter().enumerate() {
        let expected = last_of
            .iter()
            .position(|last| *last == i)
            .and_then(|m| payloads.get(m))
            .map_or("Partial", |(k, _)| *k);
        assert_eq!(kind(d), expected, "delivery {i}");
    }
    assert_eq!((trust, inbox.partials()), (Trust::Frozen, 0));
    Ok(())
}

/// A `KeyChange` signed by the old `IK_sig` (§7.7) is delivered as the new identity: the contact becomes unverified
/// and real messages are blocked until it is re-verified; messages keep arriving.
#[test]
fn content_verified_key_change() -> Result<()> {
    let (old_sk, old_iks) = identity(1)?;
    let peer = content::ik_sig(&old_iks)?;
    assert_eq!(peer, old_sk.verifying_key());
    let (_, new_iks) = identity(2)?;
    let kc = key_change(&old_sk, Label::TrKeychange, &new_iks, &new_iks)?;
    let mut contents = fragments(1, &kc, 1669)?;
    assert_eq!(contents.len(), 4);
    contents.push(text(9));
    let pts = plaintexts(&contents)?;
    for start in [Trust::Verified, Trust::Unverified] {
        assert!(start.may_send_real());
        let mut inbox = Inbox::new();
        let mut trust = start;
        let ds = receive_all(&mut inbox, &pts, &[0, 1, 2, 3, 4], &peer, &mut trust)?;
        assert_eq!(
            kinds(&ds),
            ["Partial", "Partial", "Partial", "KeyChange", "Messages"]
        );
        if let Some(Delivery::KeyChange(iks)) = ds.get(3) {
            assert_eq!(*iks, new_iks);
        }
        assert_eq!(trust, Trust::KeyChanged);
        assert!(!trust.may_send_real());
        trust.verify();
        assert_eq!(trust, Trust::Verified);
        assert!(trust.may_send_real());
    }
    Ok(())
}

/// An unverifiable `KeyChange` (§7.7) — signed by another key, under another label, over another identity, or with
/// its ML-DSA half damaged, and (M3 review C3) a reassembled `0x05` payload that does not decode: an all-zero
/// signature, Ed25519 `S = L`, a small-order `R`, a low-order `ik_dh` — is refused and freezes the session: every
/// later Content is `Frozen`, `verify()` keeps it frozen, and no real message may be sent. There is no accept path.
#[test]
fn content_unverifiable_key_change_freezes() -> Result<()> {
    let (old_sk, old_iks) = identity(1)?;
    let peer = content::ik_sig(&old_iks)?;
    let (other_sk, other_iks) = identity(3)?;
    let (_, new_iks) = identity(2)?;
    let mut damaged = key_change(&old_sk, Label::TrKeychange, &new_iks, &new_iks)?;
    flip(
        &mut damaged,
        sum(&[1, IKS_PUBLIC_LEN, ED25519_SIG_LEN, 100]),
    );
    let receipt = FragmentPayload::Receipt(ReceiptBody {
        kind: ReceiptKind::Read,
        msg_ids: vec![[1; 16]],
    })
    .encode()?;
    // M3 review C3 (reading of SQ-26): a reassembled 0x05 payload that does not decode as `IKSPublic ‖ HybridSig` is
    // unverifiable and freezes as well — `0x05 ‖ IKSPublic[2017] ‖ HybridSig[3373]`, with `ik_dh` the last 32 bytes
    // of the IKSPublic and the Ed25519 `R ‖ S` the first 64 bytes of the HybridSig
    let good = key_change(&old_sk, Label::TrKeychange, &new_iks, &new_iks)?;
    let sig_at = sum(&[1, IKS_PUBLIC_LEN]);
    let ik_dh_at = sig_at.checked_sub(32).ok_or(Error::Rejected)?;
    let s_at = sum(&[sig_at, 32]);
    // L = 2^252 + 27742317777372353535851937790883648493, little-endian
    let l_le: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut identity_point = [0_u8; 32];
    identity_point[0] = 1;
    let undecodable = [
        (
            "all-zero signature",
            overwrite(&good, sig_at, &[0; HYBRID_SIG_LEN])?,
        ),
        ("Ed25519 S = L", overwrite(&good, s_at, &l_le)?),
        (
            "small-order R (the identity)",
            overwrite(&good, sig_at, &identity_point)?,
        ),
        (
            "low-order ik_dh (u = 0)",
            overwrite(&good, ik_dh_at, &[0; 32])?,
        ),
    ];
    for (what, payload) in &undecodable {
        assert_eq!(payload.first(), Some(&0x05), "{what}");
        assert_eq!(payload.len(), good.len(), "{what}");
        assert!(
            FragmentPayload::decode(payload).is_err(),
            "{what}: must not decode"
        );
    }
    for (what, payload) in undecodable.into_iter().chain([
        (
            "another key",
            key_change(&other_sk, Label::TrKeychange, &new_iks, &new_iks)?,
        ),
        (
            "another label",
            key_change(&old_sk, Label::HxBundle, &new_iks, &new_iks)?,
        ),
        (
            "another identity",
            key_change(&old_sk, Label::TrKeychange, &other_iks, &new_iks)?,
        ),
        ("ML-DSA half damaged", damaged),
    ]) {
        let mut contents = fragments(1, &payload, 1669)?;
        contents.extend([text(9), content::dummy()]);
        contents.extend(fragments(2, &receipt, 10)?);
        let pts = plaintexts(&contents)?;
        let order: Vec<usize> = (0..pts.len()).collect();
        for start in [Trust::Verified, Trust::Unverified, Trust::KeyChanged] {
            let mut trust = start;
            let ds = receive_all(&mut Inbox::new(), &pts, &order, &peer, &mut trust)?;
            let mut expected = vec!["Partial"; 3];
            expected.extend(["KeyChangeRefused", "Frozen", "Frozen", "Frozen", "Frozen"]);
            assert_eq!(kinds(&ds), expected, "{what}");
            assert!(trust == Trust::Frozen && !trust.may_send_real(), "{what}");
            trust.verify();
            assert_eq!(trust, Trust::Frozen, "{what}: verify keeps it frozen");
        }
    }
    Ok(())
}

/// Spec §7.6 rev 2.4 (ADR-043 (j)): a Dummy carries `seq = 0` and `ts = 0`, also after the trip through a cell.
#[test]
fn dummy_carries_seq_zero_ts_zero() -> Result<()> {
    let d = content::dummy();
    assert_eq!((d.seq, d.ts), (0, 0));
    assert!(matches!(d.body, ContentBody::Dummy));
    let (a, b) = session()?;
    let (_, cell) = send(a, &d)?;
    let (_, pt) = recv(b, &cell)?;
    let got = pt.content()?;
    assert_eq!((got.seq, got.ts), (0, 0));
    assert!(matches!(got.body, ContentBody::Dummy));
    Ok(())
}

/// A Control payload (`inner_type ‖ code ‖ arg_len ‖ arg`) of exactly `len` ≥ 4 bytes, ready to be fragmented.
fn control_payload(len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let arg = len.checked_sub(4).ok_or(Error::Rejected)?;
    let payload = FragmentPayload::Control(ControlBody {
        code: ControlCode::SessionResetRequest,
        arg: Zeroizing::new(vec![0x61; arg]),
    })
    .encode()?;
    assert_eq!(payload.len(), len);
    Ok(payload)
}

/// The chunks of `payload` cut at `cuts` (cumulative offsets), as Fragment Contents of `total = cuts.len() + 1`.
fn fragments_cut(msg_id: u8, payload: &[u8], cuts: &[usize]) -> Result<Vec<Content>> {
    let mut parts = Vec::new();
    let mut from = 0;
    for to in cuts.iter().copied().chain([payload.len()]) {
        parts.push(payload.get(from..to).ok_or(Error::Rejected)?);
        from = to;
    }
    let total = u16::try_from(parts.len()).map_err(|_| Error::Rejected)?;
    Ok(parts
        .into_iter()
        .zip(0_u16..)
        .map(|(part, idx)| fragment(msg_id, idx, total, part))
        .collect())
}

/// What the Contents deliver, one by one, through a fresh session and inbox.
fn deliver_contents(contents: &[Content]) -> Result<Vec<&'static str>> {
    let pts = plaintexts(contents)?;
    let order: Vec<usize> = (0..pts.len()).collect();
    let mut trust = Trust::Verified;
    let ds = receive_all(&mut Inbox::new(), &pts, &order, &peer(1)?, &mut trust)?;
    Ok(kinds(&ds))
}

/// Spec §7.6 rev 2.4 (ADR-043 (f)): the encoder cuts `len` bytes into `total = ⌈len/1669⌉` chunks (1 for `len ≤ 1669`),
/// every chunk but the last exactly 1669 bytes, the last `len − 1669·(total − 1)`.
#[test]
fn content_chunk_shape_encoder_matches_rule() -> Result<()> {
    for len in [0_usize, 1, 1668, 1669, 1670, 3338, 3339, 10_000] {
        let bytes = vec![7_u8; len];
        let chunks = content::split_chunks(&bytes);
        let total = if len == 0 { 1 } else { len.div_ceil(1669) };
        assert_eq!(chunks.len(), total, "{len}: total");
        assert_eq!(content::chunk_total(len), total, "{len}: chunk_total");
        let (last, init) = chunks.split_last().ok_or(Error::Rejected)?;
        assert!(init.iter().all(|c| c.len() == 1669), "{len}: non-last");
        let before_last = total.checked_sub(1).ok_or(Error::Rejected)?;
        let rest = len
            .checked_sub(before_last.checked_mul(1669).ok_or(Error::Rejected)?)
            .ok_or(Error::Rejected)?;
        assert_eq!(last.len(), rest, "{len}: last");
        assert_eq!(chunks.concat(), bytes, "{len}: concatenation");
    }
    Ok(())
}

/// A non-last chunk shorter than 1669 bytes rejects the message, however the rest is cut — the payload decodes
/// fine, so only the shape rule can reject it.
#[test]
fn content_reassembly_rejects_short_nonlast_chunk() -> Result<()> {
    let payload = control_payload(3000)?;
    assert_eq!(
        deliver_contents(&fragments_cut(1, &payload, &[1669])?)?,
        ["Partial", "Control"],
        "control: the canonical cut delivers"
    );
    for cuts in [vec![1668], vec![1500], vec![1000, 2000], vec![1669, 2000]] {
        let contents = fragments_cut(1, &payload, &cuts)?;
        let kinds = deliver_contents(&contents)?;
        let (last, earlier) = kinds.split_last().ok_or(Error::Rejected)?;
        assert!(earlier.iter().all(|k| *k == "Partial"), "{cuts:?}");
        assert_eq!(*last, "Malformed", "{cuts:?}");
    }
    Ok(())
}

/// A last chunk longer than 1669 bytes cannot be carried by a cell (a Fragment's body is at most 1689 B including its
/// 20-byte header), so the reassembler's upper bound is a second line; what the wire can do is refused before it:
/// the encoder and the padding. A last chunk of exactly 1669 bytes is canonical and delivers.
#[test]
fn content_reassembly_rejects_long_last_chunk() -> Result<()> {
    let long = fragment(1, 1, 2, &[0x61; 1670]);
    assert_eq!(long.encode().err(), Some(Error::Rejected));
    let too_long = [
        vec![1_u8, 0x03],
        vec![0; 16],
        vec![0x06, 0x92],
        vec![0; 1690],
    ]
    .concat();
    assert!(pad(&too_long, BODY_LEN).is_err());
    let payload = control_payload(3338)?;
    assert_eq!(
        deliver_contents(&fragments_cut(1, &payload, &[1669])?)?,
        ["Partial", "Control"]
    );
    Ok(())
}

/// An empty last chunk with `total ≥ 2` — a cell forged by hand, as no encoder produces it — is refused and the
/// message is not delivered, although its first chunk is full and the whole decodes.
#[test]
fn content_reassembly_rejects_empty_last_chunk_with_total_ge_2() -> Result<()> {
    assert_eq!(fragment(1, 1, 2, &[]).encode().err(), Some(Error::Rejected));
    let payload = control_payload(1669)?;
    let fields = |idx: u16, chunk: &[u8]| -> Result<Zeroizing<Vec<u8>>> {
        let mut body = vec![1_u8; 16];
        body.extend_from_slice(&idx.to_be_bytes());
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(chunk);
        let mut f = vec![1_u8, 0x03];
        f.extend_from_slice(&[0; 16]);
        f.extend_from_slice(
            &u16::try_from(body.len())
                .map_err(|_| Error::Rejected)?
                .to_be_bytes(),
        );
        f.extend_from_slice(&body);
        pad(&f, BODY_LEN)
    };
    let (mut a, mut b) = session()?;
    let mut trust = Trust::Verified;
    let mut inbox = Inbox::new();
    let mut seen = Vec::new();
    for body in [fields(0, &payload)?, fields(1, &[])?] {
        let cell = forge(&mut a, |_| {}, &body)?;
        let (next, pt) = recv(b, &cell)?;
        b = next;
        seen.push(kind(&inbox.receive(&pt, &peer(1)?, &mut trust)));
    }
    assert_eq!(seen, ["Partial", "Malformed"]);
    Ok(())
}

/// A message of at most 1669 bytes is never fragmented (`total = 1`): split in two it rejects, whatever the cut.
#[test]
fn content_reassembly_rejects_two_chunks_for_short_message() -> Result<()> {
    for len in [4_usize, 100, 1668, 1669] {
        let payload = control_payload(len)?;
        for cut in [1, len / 2, len.saturating_sub(1)] {
            let contents = fragments_cut(1, &payload, &[cut])?;
            assert_eq!(
                deliver_contents(&contents)?,
                ["Partial", "Malformed"],
                "len {len}, cut {cut}"
            );
        }
    }
    Ok(())
}

/// The canonical shape delivers, for every `len` of the encoder test that a Fragment can carry (`len ≥ 1670`,
/// `total ≥ 2`); the unfragmented neighbours (`total = 1`) deliver as plain Contents.
#[test]
fn content_reassembly_accepts_canonical_shape() -> Result<()> {
    for len in [1668_usize, 1669, 1670, 3338, 3339, 10_000] {
        let payload = control_payload(len)?;
        let chunks = content::split_chunks(&payload);
        let total = chunks.len();
        assert_eq!(total, content::chunk_total(len));
        if total == 1 {
            let c = Content {
                seq: 0,
                ts: 0,
                body: ContentBody::Control(ControlBody {
                    code: ControlCode::SessionResetRequest,
                    arg: Zeroizing::new(vec![0x61; len.saturating_sub(4)]),
                }),
            };
            // the Content body limit is 1689 B: a 1669-byte payload fits unfragmented
            assert_eq!(deliver_contents(&[c])?, ["Control"], "len {len}");
            continue;
        }
        let ds = deliver_contents(&fragments_canonical(1, &payload)?)?;
        let (last, earlier) = ds.split_last().ok_or(Error::Rejected)?;
        assert_eq!(earlier.len(), total.saturating_sub(1), "len {len}");
        assert!(earlier.iter().all(|k| *k == "Partial"), "len {len}");
        assert_eq!(*last, "Control", "len {len}");
    }
    Ok(())
}

/// `Inbox::to_bytes` writes the documented `InboxV1` layout; `from_bytes` restores an inbox that re-encodes
/// identically and resumes the reassembly.
#[test]
fn content_inbox_round_trips_and_resumes() -> Result<()> {
    assert_eq!(*Inbox::new().to_bytes()?, [1, 0]);
    let payload = FragmentPayload::Batch(BatchBody {
        messages: (1..=120).map(message).collect(),
    })
    .encode()?;
    let parts = content::split_chunks(&payload);
    let mut contents = fragments_canonical(1, &payload)?;
    assert_eq!(contents.len(), 3);
    contents.push(fragment(2, 1, 2, &[7, 7]));
    let pts = plaintexts(&contents)?;
    let peer = peer(1)?;
    let mut trust = Trust::Verified;
    let mut inbox = Inbox::new();
    let ds = receive_all(&mut inbox, &pts, &[2, 3, 0], &peer, &mut trust)?;
    assert!(ds.iter().all(|d| kind(d) == "Partial"));
    let part = |i: usize| parts.get(i).copied().ok_or(Error::Rejected);
    let chunk = |idx: u16, bytes: &[u8]| -> Result<Vec<u8>> {
        let len = u16::try_from(bytes.len()).map_err(|_| Error::Rejected)?;
        Ok([idx.to_be_bytes().as_slice(), &len.to_be_bytes(), bytes].concat())
    };
    let expected = [
        vec![1, 2],
        vec![1; 16],
        vec![0, 3, 2],
        chunk(0, part(0)?)?,
        chunk(2, part(2)?)?,
        vec![2; 16],
        vec![0, 2, 1],
        chunk(1, &[7, 7])?,
    ]
    .concat();
    let bytes = inbox.to_bytes()?;
    assert_eq!(*bytes, expected, "the documented layout");
    let mut restored = Inbox::from_bytes(&bytes)?;
    assert_eq!(*restored.to_bytes()?, *bytes);
    assert_eq!(restored.partials(), 2);
    let ds = receive_all(&mut restored, &pts, &[1], &peer, &mut trust)?;
    assert_eq!(kinds(&ds), ["Messages"]);
    assert_eq!(restored.partials(), 1);
    Ok(())
}

/// One `InboxV1` entry by hand: `msg_id[16] ‖ total u16 ‖ present u8 ‖ { idx u16 ‖ len u16 ‖ chunk[len] }`.
fn inbox_entry(id: u8, total: u16, present: u8, chunks: &[(u16, usize)]) -> Result<Vec<u8>> {
    let mut out = vec![id; 16];
    out.extend_from_slice(&total.to_be_bytes());
    out.push(present);
    for (idx, len) in chunks {
        out.extend_from_slice(&idx.to_be_bytes());
        out.extend_from_slice(
            &u16::try_from(*len)
                .map_err(|_| Error::Rejected)?
                .to_be_bytes(),
        );
        out.extend_from_slice(&vec![0x42; *len]);
    }
    Ok(out)
}

/// `InboxV1` by hand: `fmt u8 ‖ count u8 ‖ entries`.
fn inbox_bytes(fmt: u8, count: u8, entries: &[Vec<u8>]) -> Vec<u8> {
    [vec![fmt, count], entries.concat()].concat()
}

/// `Inbox::from_bytes` is total and canonical: every rule of its documentation is enforced, every truncation and
/// a trailing byte are refused; the controls re-encode to themselves.
#[test]
fn content_inbox_rejects_every_noncanonical_encoding() -> Result<()> {
    let ok = |id: u8| inbox_entry(id, 3, 1, &[(1, 5)]);
    let one = |entry: Result<Vec<u8>>| -> Result<Vec<u8>> { Ok(inbox_bytes(1, 1, &[entry?])) };
    let eight = (1..=8).map(ok).collect::<Result<Vec<_>>>()?;
    let nine = (1..=9).map(ok).collect::<Result<Vec<_>>>()?;
    let sixty_three: Vec<(u16, usize)> = (0..63_u16).map(|i| (i, 1)).collect();
    let accepted = [
        inbox_bytes(1, 0, &[]),
        one(ok(1))?,
        inbox_bytes(1, 8, &eight),
        one(inbox_entry(1, 64, 63, &sixty_three))?,
        one(inbox_entry(1, 2, 1, &[(0, 1669)]))?,
        one(inbox_entry(1, 2, 1, &[(1, 1)]))?,
    ];
    for bytes in &accepted {
        assert_eq!(*Inbox::from_bytes(bytes)?.to_bytes()?, *bytes);
    }
    let rejected = [
        ("format 0", inbox_bytes(0, 0, &[])),
        ("format 2", inbox_bytes(2, 0, &[])),
        ("count 9", inbox_bytes(1, 9, &nine)),
        ("count beyond the entries", inbox_bytes(1, 2, &[ok(1)?])),
        ("trailing byte", [one(ok(1))?, vec![0]].concat()),
        ("msg_id repeated", inbox_bytes(1, 2, &[ok(1)?, ok(1)?])),
        ("total 0", one(inbox_entry(1, 0, 1, &[(0, 1)]))?),
        ("total 1", one(inbox_entry(1, 1, 1, &[(0, 1)]))?),
        ("total 65", one(inbox_entry(1, 65, 1, &[(0, 1)]))?),
        ("present 0", one(inbox_entry(1, 3, 0, &[]))?),
        (
            "present = total",
            one(inbox_entry(1, 2, 2, &[(0, 1), (1, 1)]))?,
        ),
        (
            "present beyond the chunks",
            one(inbox_entry(1, 3, 2, &[(0, 1)]))?,
        ),
        (
            "idx decreasing",
            one(inbox_entry(1, 4, 2, &[(2, 1), (1, 1)]))?,
        ),
        (
            "idx repeated",
            one(inbox_entry(1, 4, 2, &[(1, 1), (1, 1)]))?,
        ),
        ("idx = total", one(inbox_entry(1, 2, 1, &[(2, 1)]))?),
        ("idx 65535", one(inbox_entry(1, 2, 1, &[(u16::MAX, 1)]))?),
        ("chunk empty", one(inbox_entry(1, 2, 1, &[(0, 0)]))?),
        ("chunk 1670 bytes", one(inbox_entry(1, 2, 1, &[(0, 1670)]))?),
    ];
    for (what, bytes) in &rejected {
        assert_eq!(
            Inbox::from_bytes(bytes).err(),
            Some(Error::Rejected),
            "{what}"
        );
    }
    let full = inbox_bytes(1, 8, &eight);
    for len in 0..full.len() {
        let prefix = full.get(..len).ok_or(Error::Rejected)?;
        assert_eq!(
            Inbox::from_bytes(prefix).err(),
            Some(Error::Rejected),
            "{len}"
        );
    }
    Ok(())
}

/// F9 (M3 R-19): the bytes handed to `commit` are the serialisation of the state `commit` returns (they are
/// produced from the post-step state before it replaces the live one).
#[test]
fn receive_persist_bytes_equal_state_after_swap() -> Result<()> {
    let (a, b) = session()?;
    let (a, m0) = send(a, &text(0))?;
    let (_a, m1) = send(a, &text(1))?;
    // m1 first: a skipped key is stored; then m0 consumes it (both a chain step and a skipped lookup)
    let mut b = b;
    for cell in [&m1, &m0] {
        let mut handed = Vec::new();
        let (state, _) = b
            .decrypt(cell.as_slice())
            .map_err(|r| r.error())?
            .commit(|bytes| {
                handed = bytes.to_vec();
                Ok::<(), Error>(())
            })?;
        assert_eq!(handed.as_slice(), state.to_bytes()?.as_slice());
        b = state;
    }
    Ok(())
}

/// F9: a rejected cell leaves the state byte-identical (the state is handed back unchanged).
#[test]
fn receive_error_leaves_state_unchanged() -> Result<()> {
    let (a, b) = session()?;
    let (_a, mut cell) = send(a, &text(0))?;
    let last = cell.len().saturating_sub(1);
    if let Some(byte) = cell.get_mut(last) {
        *byte ^= 1;
    }
    let before = b.to_bytes()?;
    let refusal = b.decrypt(&cell).err();
    let (b, error) = refusal.ok_or(Error::Rejected)?.into_parts();
    assert_eq!(error, Error::Rejected);
    assert_eq!(*b.to_bytes()?, *before);
    Ok(())
}
