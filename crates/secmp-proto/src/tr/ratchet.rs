// SPDX-License-Identifier: AGPL-3.0-or-later
//! SecMP-TR initialisation (spec §7.2), `Encrypt` (§7.3) and `Decrypt` with `DHRatchet` and
//! `skip_message_keys` (§7.4), with the cell format of §7.5.
//!
//! **Persist-before-send / persist-before-ack (§7.5; M3 plan D4).** [`RatchetState::encrypt`] consumes the state and
//! returns a [`Sealed`]: the cell leaves it only through [`Sealed::persist`], which first hands the serialised new
//! state to the caller's durable write. [`RatchetState::decrypt`] consumes the state and returns an [`Opened`]:
//! [`Opened::commit`] hands the serialised new state to the caller's commit, after which the caller may acknowledge
//! the cell. A refused operation hands back the unchanged state ([`Refused`]).
//!
//! **Transactional decrypt without fallible allocation on the reject path (plan D2).** Everything that decides
//! whether a cell is accepted runs on the borrowed state — header trial decryption, header decoding, the step and
//! constancy checks, the skipped-key derivations, the *receiving* half of `DHRatchet` (`Decaps`, X25519 with the
//! current keys) and the body MAC — and yields an `Update`. Only after the body MAC verified does the *sending* half
//! draw fresh keys (locked memory, OS randomness: the only [`Error::Unavailable`] source), and only then is the
//! `Update` applied. The resulting state equals §7.4's order: the sending half reads `rk` as left by the receiving
//! half and `dh_r`/`kem_r` from the header, which `skip_message_keys` and `KDF_CK` on the new chain do not touch,
//! and writes `dh_s`, `kem_s`, `ct_s`, `rk`, `ck_s`, `nhk_s`, which they do not read. A rejection therefore changes
//! nothing, allocates no locked memory and draws no randomness.
//!
//! **Constant work in trial decryption (plan D3).** The header is opened under every candidate key — each distinct
//! header key of `skipped`, `hk_r`, `nhk_r`, an absent key replaced by a dummy key whose result is masked — and each
//! result ([`Aead::open_ct`]) is held as a [`select::CellChoice`], which has no conversion to `bool`;
//! `select_header` reduces them to the §7.4 case with [`select::first_opened`] and [`select::decide`], whose case
//! code is the one conversion to a branch up to and including `decide` (docs/06 §9; M3 review C6/F1, test
//! `any_skipped_single_conversion`). The `n` of the `(hk, n)` lookup is read from the plaintext bytes `[38..42]` of
//! every skipped candidate and selected with the one-hot `first` vector, so no header is decoded before `decide`.
//! After it, the first skipped key's header is decoded on every accepting path — `Open` includes decoding, and a
//! skipped key's header that opens but does not decode rejects the cell (ADR-043 (b)) — through a selection that
//! falls back to the header of `hk_r` or `nhk_r`, so that needs no branch on `any_skipped` either. The one other
//! `Choice` → `bool` conversion before `decide`, in `distinct_skipped_keys`, compares the state's own header keys
//! with each other: it does not depend on the cell. Keys, KEM material and ratchet keys are compared with `ct_eq`,
//! never `==`. The `(hk, n)` lookup visits every entry of `skipped` and selects the entry's message key with masks
//! (`lookup_skipped`, M4 review R-58): the skipped path loads no entry by its index before the body MAC.

use std::collections::VecDeque;

use secmp_crypto::{
    Aead, Choice, ConstantTimeEq, Label, MlKem768Ct, MlKem768Ek, MsgEncrypt, SecretBytes,
    X25519Public, X25519Secret, kdf_ck, kdf_rk, tr_init,
};

// the encodings' zeroizing buffer (`secmp_crypto::Zeroizing`; a stand-in under Kani, see `codec`)
use crate::codec::{Decode, Encode, Zeroizing};
use crate::error::{Error, Result};
use crate::keys::{self, X25519Pk};
use crate::sizes::{
    BODY_LEN, CELL_LEN, HASH_LEN, HDR_CT_LEN, HEADER_LEN, NONCE_LEN, X25519_PK_LEN, sum,
};
use crate::tr::entropy::{Entropy, OsEntropy};
use crate::tr::select::{self, CellChoice, MAX_FF, Path, SkipPlan};
use crate::tr::state::{DhPair, KemPair, RatchetState, SkippedKey};
use crate::wire::cell::{Cell, Content, HeaderV1};

/// The decrypted padded Content of a cell (1710 bytes), wiped on drop. Decode it with [`Plaintext::content`]; the
/// Content decoder is outside the decrypt transaction (plan D6).
pub struct Plaintext {
    bytes: SecretBytes<BODY_LEN>,
    /// SHA-256 of the message key that opened the body (feature `kat`: the property tests track every key).
    #[cfg(feature = "kat")]
    mk_digest: [u8; 32],
}

impl Plaintext {
    fn new(bytes: SecretBytes<BODY_LEN>, mk: &SecretBytes<32>) -> Self {
        #[cfg(not(feature = "kat"))]
        let _ = mk;
        Self {
            bytes,
            #[cfg(feature = "kat")]
            mk_digest: mk_digest(mk),
        }
    }

    /// The padded Content bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; BODY_LEN] {
        self.bytes.expose_secret()
    }

    /// The Content (spec §7.6).
    ///
    /// # Errors
    /// [`Error::Rejected`] if the plaintext is not exactly one padded Content.
    pub fn content(&self) -> Result<Content> {
        #[cfg(feature = "kat")]
        DECRYPT_SITE_KAT.set(Some("body decode"));
        Content::decode(self.bytes.expose_secret())
    }

    /// SHA-256 of the message key that opened this cell (feature `kat`; the property tests check that no message
    /// key is ever used twice).
    #[cfg(feature = "kat")]
    #[must_use]
    pub fn message_key_digest_kat(&self) -> [u8; 32] {
        self.mk_digest
    }
}

/// SHA-256 of a message key (feature `kat`).
#[cfg(feature = "kat")]
fn mk_digest(mk: &SecretBytes<32>) -> [u8; 32] {
    secmp_crypto::sha256(&[mk.expose_secret()])
}

#[cfg(feature = "kat")]
std::thread_local! {
    /// The reject-site tag of the last [`RatchetState::decrypt`] on this thread (feature `kat`; M3 review R-45, F19),
    /// read with `DECRYPT_SITE_KAT.get()`: the constant-time bench checks before measuring that each class of a TR
    /// target is refused at the step of §7.4 the target claims. The tag is set when a step begins, so after a
    /// rejection it names the step that rejected:
    ///
    /// - `"cell length"` — set by `decrypt` first: the cell is not 4096 bytes;
    /// - `"header: no key opened"` — the trial decryptions under every candidate key and the selection; at
    ///   `Path::Reject` no skipped key, `hk_r` or `nhk_r` opened the header;
    /// - `"skipped: (hk, n) not stored"` — at `Path::Reject`, a skipped key opened the header but `(hk, n)` is not in
    ///   `skipped`, and neither `hk_r` nor `nhk_r` opened it;
    /// - `"header decode"` — after the selection: the header the key opened does not decode (ADR-043 (b));
    /// - `"kem constancy"` — chain path: `ek_pq`/`ct_pq` differ from `kem_r`/`last_ct_r`;
    /// - `"counter rule"` — `skip_message_keys` (`until < n_r`, a gap beyond `MAX_FF`, a counter overflow) and
    ///   `n_r = header.n + 1`;
    /// - `"dh_pk"` — step path: `dh_pk` equals `dh_r` (no new ratchet key), and the receiving half of `DHRatchet`
    ///   with it (the X25519 all-zero check; the KEM imports and `Decaps` cannot fail after the header decoder);
    /// - `"body MAC"` — `MsgDecrypt` of the body under the message key, on every path; after it the step path's
    ///   sending half (`Unavailable` only) and the serialisation of the new state;
    /// - `"body decode"` — set by [`Plaintext::content`]: the Content decoder (outside the decrypt transaction, plan
    ///   D6).
    ///
    /// `None` before the first call on this thread. Without `kat` neither the tag nor any statement setting it
    /// exists (the `hx::ACCEPT_SITE_KAT` mechanism).
    pub static DECRYPT_SITE_KAT: core::cell::Cell<Option<&'static str>> = const { core::cell::Cell::new(None) };
}

#[cfg(any(test, feature = "kat"))]
std::thread_local! {
    /// The work of the last [`RatchetState::decrypt`] on this thread (feature `kat` and the unit tests; M3 review
    /// R-04): `(header trial decryptions, skipped entries visited by the (hk, n) lookup)`. Reset when a 4096-byte
    /// cell's processing begins; test `trial_opens_every_candidate_every_call` checks `distinct + 2` and
    /// `|skipped|` on every path — an early exit from the trial loop or the lookup changes them. Without `kat` and
    /// outside the tests neither the counters nor any statement updating them exists.
    pub static TRIAL_COUNTS_KAT: core::cell::Cell<(u32, u32)> = const { core::cell::Cell::new((0, 0)) };

    /// The `KDF_CK` steps `skip_message_keys` derived in the last [`RatchetState::decrypt`] on this thread (feature
    /// `kat` and the unit tests; M4 review C-9): reset with [`TRIAL_COUNTS_KAT`]. The test
    /// `first_msg_with_nonzero_n_rejects_before_any_chain_step` reads 0 after SecMP-HX rejected a first message with
    /// `n ≠ 0`. No shipped code path reads it; without `kat` and outside the tests it does not exist.
    pub static SKIP_STEPS_KAT: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
}

/// A refused `encrypt` or `decrypt`: the state, unchanged, and the error — [`Error::Rejected`] for every
/// input-dependent failure (uniform), [`Error::Unavailable`] if randomness or locked memory was unavailable (the
/// caller neither sends nor acknowledges; it retries).
pub struct Refused {
    state: Box<RatchetState>,
    error: Error,
}

impl Refused {
    fn new(state: RatchetState, error: Error) -> Self {
        Self {
            state: Box::new(state),
            error,
        }
    }

    /// The error.
    #[must_use]
    pub const fn error(&self) -> Error {
        self.error
    }

    /// The unchanged state.
    #[must_use]
    pub fn into_state(self) -> RatchetState {
        *self.state
    }

    /// The unchanged state and the error.
    #[must_use]
    pub fn into_parts(self) -> (RatchetState, Error) {
        (*self.state, self.error)
    }
}

/// The result of `encrypt`: the new state and the cell, which is released only after the new state was persisted
/// (§7.5 persist-before-send).
pub struct Sealed {
    state: RatchetState,
    state_bytes: Zeroizing<Vec<u8>>,
    cell: Cell,
    /// SHA-256 of the message key of the cell (feature `kat`).
    #[cfg(feature = "kat")]
    mk_digest: [u8; 32],
}

impl Sealed {
    /// SHA-256 of the message key that sealed the cell (feature `kat`; the property tests track every key).
    #[cfg(feature = "kat")]
    #[must_use]
    pub fn message_key_digest_kat(&self) -> [u8; 32] {
        self.mk_digest
    }

    /// Persist-before-send: `persist` receives the serialised new state (`RatchetStateV1`) and must make it durable;
    /// only if it returns `Ok` are the new state and the cell released. On `Err` both are dropped and the error is
    /// returned: the durable state is the previous one, and no cell of the new one left the process.
    ///
    /// # Errors
    /// The error of `persist`.
    pub fn persist<E>(
        self,
        persist: impl FnOnce(&[u8]) -> core::result::Result<(), E>,
    ) -> core::result::Result<(RatchetState, Cell), E> {
        persist(&self.state_bytes)?;
        Ok((self.state, self.cell))
    }
}

/// The result of `decrypt`: the new state and the plaintext. The caller processes [`Opened::plaintext`], then
/// [`Opened::commit`]s the new state together with what it derived, and acknowledges the cell only after that
/// (§7.5 persist-before-ack, §9.3).
pub struct Opened {
    state: RatchetState,
    state_bytes: Zeroizing<Vec<u8>>,
    plaintext: Plaintext,
    counters: (u32, u32),
}

impl Opened {
    /// The decrypted padded Content.
    #[must_use]
    pub fn plaintext(&self) -> &Plaintext {
        &self.plaintext
    }

    /// `(n, pn)` of the opened cell's header (§7.3). SecMP-HX requires `(0, 0)` of the first message
    /// (ADR-044 (e)).
    #[must_use]
    pub const fn header_counters(&self) -> (u32, u32) {
        self.counters
    }

    /// Persist-before-ack: `commit` receives the serialised new state and must durably write it (with the message
    /// or whatever the caller derived from the plaintext); only if it returns `Ok` are the new state and the
    /// plaintext released. On `Err` both are dropped: the caller reloads its durable state, and the unacknowledged
    /// cell is delivered again.
    ///
    /// # Errors
    /// The error of `commit`.
    pub fn commit<E>(
        self,
        commit: impl FnOnce(&[u8]) -> core::result::Result<(), E>,
    ) -> core::result::Result<(RatchetState, Plaintext), E> {
        commit(&self.state_bytes)?;
        Ok((self.state, self.plaintext))
    }
}

/// The new values of a DH step (§7.4 `DHRatchet`, both halves).
struct StepUpdate {
    pn: u32,
    hk_s: SecretBytes<32>,
    hk_r: SecretBytes<32>,
    dh_r: X25519Pk,
    kem_r: MlKem768Ek,
    last_ct_r: MlKem768Ct,
    rk: SecretBytes<32>,
    nhk_r: SecretBytes<32>,
    dh_s: DhPair,
    kem_s: KemPair,
    ct_s: MlKem768Ct,
    ck_s: SecretBytes<32>,
    nhk_s: SecretBytes<32>,
}

/// Everything an accepted cell changes, applied only after the body MAC verified (plan D2).
struct Update {
    /// The consumed skipped entry (§7.4 step 1).
    remove: Option<usize>,
    /// Skipped keys inserted, in insertion order (old chain first on a step).
    added: Vec<SkippedKey>,
    /// The receiving chain after this message: `(ck_r, n_r)`.
    chain: Option<(SecretBytes<32>, u32)>,
    step: Option<StepUpdate>,
    /// `(header.n, header.pn)` of the accepted cell (ADR-044 (e): the handshake's first message carries both 0).
    counters: (u32, u32),
}

fn copy32(k: &SecretBytes<32>) -> Result<SecretBytes<32>> {
    Ok(SecretBytes::from_slice(k.expose_secret())?)
}

/// `AD = "SecMP-TR/1 hdr" ‖ sb` (§7.3).
fn header_ad(sb: &[u8; HASH_LEN]) -> Vec<u8> {
    [Label::TrHdr.as_bytes(), sb.as_slice()].concat()
}

/// `AD = "SecMP-TR/1 body" ‖ sb ‖ hdr_nonce ‖ hdr_ct` (§7.3; 2401 bytes).
fn body_ad(sb: &[u8; HASH_LEN], hdr_nonce: &[u8], hdr_ct: &[u8]) -> Vec<u8> {
    [Label::TrBody.as_bytes(), sb.as_slice(), hdr_nonce, hdr_ct].concat()
}

/// `skip_message_keys` along one chain (§7.4): `plan.steps` × `KDF_CK` from `ck` at position `from`, storing
/// `(hk, p) → mk` for `p ≥ plan.store_from`; returns the chain key at `from + steps` and the stored entries. The
/// other derived message keys are dropped (wiped) at once.
fn derive_skipped(
    ck: &SecretBytes<32>,
    hk: &SecretBytes<32>,
    from: u32,
    plan: SkipPlan,
) -> Result<(SecretBytes<32>, Vec<SkippedKey>)> {
    let mut ck = copy32(ck)?;
    let mut stored = Vec::new();
    let mut p = from;
    for _ in 0..plan.steps {
        #[cfg(any(test, feature = "kat"))]
        SKIP_STEPS_KAT.set(SKIP_STEPS_KAT.get().saturating_add(1));
        let (next, mk) = kdf_ck(&ck)?;
        if p >= plan.store_from {
            stored.push(SkippedKey {
                hk: copy32(hk)?,
                n: p,
                mk,
            });
        }
        ck = next;
        p = p.checked_add(1).ok_or(Error::Rejected)?;
    }
    Ok((ck, stored))
}

/// One trial decryption of the header (spec §7.4, plan D3): whether the key opened it, and the plaintext
/// (`HEADER_LEN` bytes, all zero if the tag did not verify; [`Aead::open_ct`]).
type Trial = (CellChoice, Zeroizing<Vec<u8>>);

/// The trial decryptions of one header under every candidate key — all of them, every time (spec §7.4, plan D3).
struct Trials {
    /// Under each distinct header key of `skipped`, in first-seen order.
    skipped: Vec<Trial>,
    /// Under `hk_r`.
    current: Trial,
    /// Under `nhk_r`.
    next: Trial,
}

/// The §7.4 case of an accepted header, with the decoded header.
enum Selected {
    /// Step 1: the entry of `skipped` at this index (removed only after the body MAC verified), the header the
    /// skipped key opened, and the entry's message key, selected by masks over every entry (`lookup_skipped`).
    Skipped(usize, HeaderV1, SecretBytes<32>),
    /// Step 2 with `step = false`: the header `hk_r` opened.
    Chain(HeaderV1),
    /// Step 2 with `step = true`: the header `nhk_r` opened.
    Step(HeaderV1),
}

/// `Open(key, hdr_nonce, hdr_ct)` with constant work: an absent key is replaced by `dummy` and its result masked.
fn open_header(
    key: Option<&SecretBytes<32>>,
    dummy: &SecretBytes<32>,
    hdr_nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    hdr_ct: &[u8],
) -> Trial {
    #[cfg(any(test, feature = "kat"))]
    TRIAL_COUNTS_KAT.with(|c| {
        let (opens, visited) = c.get();
        c.set((opens.saturating_add(1), visited));
    });
    let mut out = Zeroizing::new(vec![0_u8; HEADER_LEN]);
    let present = Choice::from(u8::from(key.is_some()));
    let opened = Aead::open_ct(key.unwrap_or(dummy), hdr_nonce, ad, hdr_ct, &mut out);
    (CellChoice::from(opened & present), out)
}

/// The `(hk, n)` lookup of §7.4 step 1, comparing every entry of `skipped` in constant time: whether `(hk, n)` is
/// stored, the index of the match (used only after the body MAC verified, `Update::remove`) and the match's message
/// key, all-zero if none matched. mk selected by masks over every entry (R-58): no secret-indexed load before the
/// body MAC.
fn lookup_skipped(
    skipped: &VecDeque<SkippedKey>,
    hk: &[u8; 32],
    n: u32,
) -> (CellChoice, u32, Zeroizing<[u8; 32]>) {
    let mut found = CellChoice::from(Choice::from(0));
    let mut found_at = 0_u32;
    let mut mk = Zeroizing::new([0_u8; 32]);
    #[cfg(any(test, feature = "kat"))]
    let mut visited = 0_u32;
    for (j, e) in (0_u32..).zip(skipped) {
        let hit = CellChoice::from(e.hk.expose_secret().ct_eq(hk) & e.n.ct_eq(&n));
        found |= hit;
        hit.assign(&mut found_at, &j);
        for (dst, src) in mk.iter_mut().zip(e.mk.expose_secret()) {
            hit.assign(dst, src);
        }
        #[cfg(any(test, feature = "kat"))]
        {
            visited = visited.saturating_add(1);
        }
    }
    #[cfg(any(test, feature = "kat"))]
    TRIAL_COUNTS_KAT.with(|c| c.set((c.get().0, visited)));
    (found, found_at, mk)
}

/// The offset of `n` in an encoded header: `HeaderV1 = ver ‖ flags u8 ‖ dh_pk[32] ‖ pn u32 ‖ n u32 ‖ …` (spec §7.5,
/// App. D.5).
const HEADER_N_AT: usize = sum(&[1, 1, X25519_PK_LEN, 4]);
const _: () = assert!(HEADER_N_AT == 38);

/// `n` of an encoded header without decoding it: the big-endian `u32` at bytes `[38..42]` (spec §4.1, App. D.5).
/// Constant work. Every trial-decryption plaintext has `HEADER_LEN` bytes, so the error is unreachable for them.
fn header_n(header: &[u8]) -> Result<u32> {
    let (_, rest) = header
        .split_at_checked(HEADER_N_AT)
        .ok_or(Error::Rejected)?;
    Ok(u32::from_be_bytes(
        *rest.first_chunk::<4>().ok_or(Error::Rejected)?,
    ))
}

/// Spec §7.4's choice among the trial decryptions (plan D3; M3 review C6/F1). `skipped` are the state's skipped keys,
/// `distinct` their distinct header keys in first-seen order, in which `trials.skipped` tried them.
///
/// Up to [`select::path`] every cell-dependent result is a [`CellChoice`] and nothing branches on one: the first
/// skipped key that opened the header is selected with the one-hot `first` vector — its key, its `n` (read with
/// [`header_n`], not decoded) and its plaintext —, `(hk, n)` is looked up in `skipped` comparing every entry and
/// selecting the entry's message key with masks ([`lookup_skipped`], R-58), and `path` converts once. Only then are
/// headers decoded. `Open` includes decoding (ADR-043 (b)): if a skipped key
/// opened the header, the first one's plaintext must decode, whichever path follows — at `Path::Chain` and
/// `Path::Step` too, where `(hk, n)` was not found. The plaintext selected for that falls back to the header `hk_r`
/// opened, else the one `nhk_r` opened, so decoding it on every accepting path needs no branch on `any_skipped`: at
/// `Path::Skipped` it is the skipped key's header (used for the counters); at `Path::Chain` / `Path::Step` it is the
/// skipped key's header if one opened — the same plaintext as the path's for a skipped key of the current chain (that
/// key is `hk_r`), a different one only for a header ciphertext that opens under two keys, which a contact holding
/// both can craft — and otherwise the path's own header, which is then decoded again for the path.
///
/// # Errors
/// The uniform [`Error::Rejected`] if no key's case applies (`Path::Reject`) or a header to decode does not decode.
fn select_header(
    skipped: &VecDeque<SkippedKey>,
    distinct: &[&SecretBytes<32>],
    trials: &Trials,
) -> Result<Selected> {
    let (current_opened, current_header) = &trials.current;
    let (next_opened, next_header) = &trials.next;
    // the first skipped key that opened, selected without a branch: its key, its n, its plaintext — the latter
    // falling back to hk_r's plaintext if hk_r opened, else to nhk_r's
    let opened: Vec<CellChoice> = trials.skipped.iter().map(|(o, _)| *o).collect();
    let (first, any_skipped) = select::first_opened_cell(&opened);
    let mut selected = Zeroizing::new(next_header.to_vec());
    for (dst, src) in selected.iter_mut().zip(current_header.iter()) {
        current_opened.assign(dst, src);
    }
    let mut skipped_hk = Zeroizing::new([0_u8; 32]);
    let mut n = 0_u32;
    for ((f, (_, header)), hk) in first.iter().zip(&trials.skipped).zip(distinct) {
        for (dst, src) in selected.iter_mut().zip(header.iter()) {
            f.assign(dst, src);
        }
        for (dst, src) in skipped_hk.iter_mut().zip(hk.expose_secret()) {
            f.assign(dst, src);
        }
        f.assign(&mut n, &header_n(header)?);
    }
    // (hk, n) ∈ skipped? — every entry compared, its mk selected with masks, in constant time (R-58)
    let (found, found_at, mk) = lookup_skipped(skipped, &skipped_hk, n);
    // feature `kat`: the site of a `Path::Reject` (`DECRYPT_SITE_KAT`) — whether a skipped key opened — selected with a
    // mask, so the `kat` build adds no branch on `any_skipped` either
    #[cfg(feature = "kat")]
    let reject_site = {
        let mut at = 0_u8;
        any_skipped.assign(&mut at, &1);
        ["header: no key opened", "skipped: (hk, n) not stored"]
            .get(usize::from(at))
            .copied()
    };
    // the one conversion to a branch; then Open() includes decoding (ADR-043 (b))
    let path = select::path(any_skipped, found, *current_opened, *next_opened);
    #[cfg(feature = "kat")]
    DECRYPT_SITE_KAT.set(match path {
        Path::Reject => reject_site,
        Path::Skipped | Path::Chain | Path::Step => Some("header decode"),
    });
    match path {
        Path::Reject => Err(Error::Rejected),
        Path::Skipped => Ok(Selected::Skipped(
            usize::try_from(found_at).map_err(|_| Error::Rejected)?,
            HeaderV1::decode(&selected)?,
            SecretBytes::from_slice(&*mk)?,
        )),
        Path::Chain => {
            let _first_opened = HeaderV1::decode(&selected)?;
            Ok(Selected::Chain(HeaderV1::decode(current_header)?))
        }
        Path::Step => {
            let _first_opened = HeaderV1::decode(&selected)?;
            Ok(Selected::Step(HeaderV1::decode(next_header)?))
        }
    }
}

impl RatchetState {
    /// Spec §7.2, initiator (Alice role, sends first): `SK` and `transcript` from SecMP-HX (M4), the responder's
    /// `SPK_dh_R` and ML-KEM-768 ratchet prekey `RPK_kem_R` from its bundle. Draws `dh_s`, `kem_s` and the `Encaps`
    /// randomness from the OS.
    ///
    /// # Errors
    /// [`Error::Rejected`] if an input is refused (an all-zero X25519 output); [`Error::Unavailable`] if randomness
    /// or locked memory is unavailable.
    pub fn init_initiator(
        sk: &SecretBytes<32>,
        transcript: &[u8; HASH_LEN],
        spk_dh_r: &X25519Pk,
        rpk_kem_r: &keys::MlKem768Ek,
    ) -> Result<Self> {
        Self::init_initiator_with(sk, transcript, spk_dh_r, rpk_kem_r, &mut OsEntropy)
    }

    /// [`RatchetState::init_initiator`] with the given randomness (drawn in the order of §7.2: `dh_s`, `kem_s`,
    /// `Encaps`).
    ///
    /// # Errors
    /// As [`RatchetState::init_initiator`].
    pub fn init_initiator_with(
        sk: &SecretBytes<32>,
        transcript: &[u8; HASH_LEN],
        spk_dh_r: &X25519Pk,
        rpk_kem_r: &keys::MlKem768Ek,
        entropy: &mut impl Entropy,
    ) -> Result<Self> {
        // (RK ‖ HK_A ‖ NHK_B) = HKDF(salt = 0^32, IKM = SK, info = "SecMP-TR/1 init", L = 96)
        let (root, header_a, next_header_b) = tr_init(sk)?;
        let kem_r = MlKem768Ek::from_bytes(rpk_kem_r.as_bytes())?;
        // dh_s = X25519.keygen(); kem_s = ML-KEM-768.keygen(); (ct_s, ss_pq) = ML-KEM-768.Encaps(kem_r)
        let dh_s = DhPair::new(entropy.x25519()?)?;
        let kem_s = KemPair::new(entropy.mlkem768()?)?;
        let (send_ct, ss_pq) = entropy.encaps(&kem_r)?;
        // (rk, ck_s, nhk_s) = KDF_RK(rk, X25519(dh_s, dh_r) ‖ ss_pq)
        let dh = dh_s
            .sk
            .diffie_hellman(&X25519Public::from_bytes(spk_dh_r.as_bytes())?)?;
        let (rk, send_chain, send_next_header) = kdf_rk(&root, &dh, &ss_pq)?;
        Ok(Self {
            sb: *transcript,
            rk,
            dh_s,
            dh_r: Some(*spk_dh_r),
            kem_s,
            kem_r: Some(kem_r),
            last_ct_r: None,
            ct_s: Some(send_ct),
            ck_s: Some(send_chain),
            ck_r: None,
            hk_s: Some(header_a),
            hk_r: None,
            nhk_s: Some(send_next_header),
            nhk_r: Some(next_header_b),
            n_s: 0,
            n_r: 0,
            pn: 0,
            skipped: std::collections::VecDeque::new(),
        })
    }

    /// Spec §7.2, responder (Bob role): `dh_s` is the `SPK_dh_R` key pair and `kem_s` the `RPK_kem_R` key pair of
    /// the bundle the initiator used; no randomness.
    ///
    /// # Errors
    /// [`Error::Rejected`] only if a key is refused (not for a key generated by `secmp-crypto`).
    pub fn init_responder(
        sk: &SecretBytes<32>,
        transcript: &[u8; HASH_LEN],
        spk_dh: X25519Secret,
        rpk_kem: secmp_crypto::MlKem768Dk,
    ) -> Result<Self> {
        let (rk, header_a, next_header_b) = tr_init(sk)?;
        Ok(Self {
            sb: *transcript,
            rk,
            dh_s: DhPair::new(spk_dh)?,
            dh_r: None,
            kem_s: KemPair::new(rpk_kem)?,
            kem_r: None,
            last_ct_r: None,
            ct_s: None,
            ck_s: None,
            ck_r: None,
            hk_s: None,
            hk_r: None,
            nhk_s: Some(next_header_b),
            nhk_r: Some(header_a),
            n_s: 0,
            n_r: 0,
            pn: 0,
            skipped: std::collections::VecDeque::new(),
        })
    }

    /// Spec §7.3 `Encrypt(state, content)` with a header nonce from the OS. Real and dummy contents take this same
    /// path (CLAUDE.md §1.4); see [`crate::tr::content::dummy`].
    ///
    /// # Errors
    /// [`Refused`] with [`Error::Rejected`] if there is no sending chain (a responder before its first step), `n_s`
    /// is at `u32::MAX` (§7.3: abort) or the content has no encoding; with [`Error::Unavailable`] if randomness is
    /// unavailable. The state is unchanged.
    pub fn encrypt(self, content: &Content) -> core::result::Result<Sealed, Refused> {
        self.encrypt_with(content, &mut OsEntropy)
    }

    /// [`RatchetState::encrypt`] with the given randomness (the header nonce).
    ///
    /// # Errors
    /// As [`RatchetState::encrypt`].
    pub fn encrypt_with(
        self,
        content: &Content,
        entropy: &mut impl Entropy,
    ) -> core::result::Result<Sealed, Refused> {
        // pad(content, BODY_LEN)
        match content.encode() {
            Ok(body) => self.encrypt_body(&body, entropy),
            Err(error) => Err(Refused::new(self, error)),
        }
    }

    /// [`RatchetState::encrypt_with`] of an already padded body (1710 bytes), for the vector generator, which
    /// builds Contents the encoder refuses (a non-zero `caps`, SCHEMA-4.10 R9). Feature `kat` only.
    ///
    /// # Errors
    /// As [`RatchetState::encrypt`]; also [`Error::Rejected`] unless `body` is 1710 bytes.
    #[cfg(feature = "kat")]
    pub fn encrypt_padded_kat(
        self,
        body: &[u8],
        entropy: &mut impl Entropy,
    ) -> core::result::Result<Sealed, Refused> {
        self.encrypt_body(body, entropy)
    }

    fn encrypt_body(
        mut self,
        body: &[u8],
        entropy: &mut impl Entropy,
    ) -> core::result::Result<Sealed, Refused> {
        let (ck_s, n_s, cell, digest) = match self.seal(body, entropy) {
            Ok(x) => x,
            Err(error) => return Err(Refused::new(self, error)),
        };
        #[cfg(not(feature = "kat"))]
        let _ = digest;
        let previous = (self.ck_s.replace(ck_s), self.n_s);
        self.n_s = n_s;
        // cannot fail for a state of this module (`skipped` is untouched and within its bound); if it does, the
        // state is handed back as it was
        match self.to_bytes() {
            Ok(state_bytes) => Ok(Sealed {
                state: self,
                state_bytes,
                cell,
                #[cfg(feature = "kat")]
                mk_digest: digest,
            }),
            Err(error) => {
                (self.ck_s, self.n_s) = previous;
                Err(Refused::new(self, error))
            }
        }
    }

    /// §7.3 on the borrowed state: the new `ck_s`, the new `n_s`, the cell, and (feature `kat`, otherwise zeros)
    /// the digest of the message key.
    fn seal(
        &self,
        body: &[u8],
        entropy: &mut impl Entropy,
    ) -> Result<(SecretBytes<32>, u32, Cell, [u8; 32])> {
        let (Some(chain), Some(header_key), Some(chain_ct)) = (&self.ck_s, &self.hk_s, &self.ct_s)
        else {
            return Err(Error::Rejected);
        };
        // n_s += 1: checked_add; abort at u32::MAX
        let n_next = self.n_s.checked_add(1).ok_or(Error::Rejected)?;
        if body.len() != BODY_LEN {
            return Err(Error::Rejected);
        }
        // (ck_s, mk) = KDF_CK(ck_s)
        let (ck_next, mk) = kdf_ck(chain)?;
        // header = HeaderV1{ dh_pk = dh_s.pk, pn, n = n_s, ek_pq = kem_s.ek, ct_pq = ct_s }
        let header = HeaderV1 {
            dh_pk: self.dh_s.pk,
            pn: self.pn,
            n: self.n_s,
            ek_pq: self.kem_s.ek.clone(),
            ct_pq: Box::new(*chain_ct.as_bytes()),
        }
        .encode()?;
        // hdr_nonce = random 24 B; hdr_ct = XChaCha20-Poly1305.Seal(hk_s, hdr_nonce, "SecMP-TR/1 hdr" ‖ sb, header)
        let nonce = entropy.nonce()?;
        let hdr_nonce = *nonce.as_bytes();
        let hdr_ct = Aead::seal(header_key, nonce, &header_ad(&self.sb), &header)?;
        #[cfg(feature = "kat")]
        let digest = mk_digest(&mk);
        #[cfg(not(feature = "kat"))]
        let digest = [0_u8; 32];
        // body = MsgEncrypt(mk, "SecMP-TR/1 body" ‖ sb ‖ hdr_nonce ‖ hdr_ct, pad(content, BODY_LEN))
        let sealed_body = MsgEncrypt::seal(mk, &body_ad(&self.sb, &hdr_nonce, &hdr_ct), body)?;
        // Cell = hdr_nonce ‖ hdr_ct ‖ body (§7.5)
        let cell = [hdr_nonce.as_slice(), &hdr_ct, &sealed_body].concat();
        Ok((ck_next, n_next, Cell::from_bytes(&cell)?, digest))
    }

    /// Spec §7.4 `Decrypt(state, cell)`: `cell` is the received bytes (any length; not 4096 → rejected). New keys of
    /// a DH step come from the OS.
    ///
    /// # Errors
    /// [`Refused`] with the uniform [`Error::Rejected`] for every rejection of §7.4, or with
    /// [`Error::Unavailable`] if the sending half of a DH step could not draw its keys (after the body MAC verified;
    /// do not acknowledge, retry). The state is unchanged.
    pub fn decrypt(self, cell: &[u8]) -> core::result::Result<Opened, Refused> {
        self.decrypt_with(cell, &mut OsEntropy)
    }

    /// [`RatchetState::decrypt`] with the given randomness (a DH step's sending half: `dh_s`, `kem_s`, `Encaps`).
    ///
    /// # Errors
    /// As [`RatchetState::decrypt`].
    pub fn decrypt_with(
        self,
        cell: &[u8],
        entropy: &mut impl Entropy,
    ) -> core::result::Result<Opened, Refused> {
        self.decrypt_within(cell, entropy, MAX_FF)
    }

    /// [`RatchetState::decrypt_with`] of SecMP-HX's first message (§6.6 step 3, ADR-044 (e); M4 review C-9): the
    /// fast-forward bound is 0, so a header with `n ≠ 0` is rejected at `skip_message_keys`, before any `KDF_CK` step,
    /// the body MAC and the sending half's randomness. `pn` costs nothing on a fresh responder (no receiving chain);
    /// the caller still requires `(n, pn) = (0, 0)` of the opened cell. Crate-private: only `hx::responder` calls it.
    pub(crate) fn decrypt_first_with(
        self,
        cell: &[u8],
        entropy: &mut impl Entropy,
    ) -> core::result::Result<Opened, Refused> {
        self.decrypt_within(cell, entropy, 0)
    }

    /// [`RatchetState::decrypt_with`] with the fast-forward bound `max_ff` of `skip_message_keys` ([`MAX_FF`], or 0 for
    /// SecMP-HX's first message).
    fn decrypt_within(
        mut self,
        cell: &[u8],
        entropy: &mut impl Entropy,
        max_ff: u32,
    ) -> core::result::Result<Opened, Refused> {
        let (update, plaintext) = match self.open(cell, entropy, max_ff) {
            Ok(x) => x,
            Err(error) => return Err(Refused::new(self, error)),
        };
        let counters = update.counters;
        // build the post-step state aside and serialise it *before* it replaces the live one: any error up to here
        // hands back the genuinely unchanged `self`
        let built = self
            .to_bytes()
            .and_then(|live| RatchetState::from_bytes(&live));
        let mut next = match built {
            Ok(next) => next,
            Err(error) => return Err(Refused::new(self, error)),
        };
        next.apply(update);
        match next.to_bytes() {
            Ok(state_bytes) => {
                self = next;
                Ok(Opened {
                    state: self,
                    state_bytes,
                    plaintext,
                    counters,
                })
            }
            Err(error) => Err(Refused::new(self, error)),
        }
    }

    /// The distinct header keys of `skipped`, in first-seen order (the entries of a chain are contiguous, see
    /// `state::skipped_is_canonical`). The `ct_eq` → `bool` here compares the state's own keys with each other; it
    /// does not depend on the cell.
    fn distinct_skipped_keys(&self) -> Vec<&SecretBytes<32>> {
        let mut keys: Vec<&SecretBytes<32>> = Vec::new();
        for e in &self.skipped {
            let new_group = keys
                .last()
                .is_none_or(|last| !bool::from(last.ct_eq(&e.hk)));
            if new_group {
                keys.push(&e.hk);
            }
        }
        keys
    }

    /// Everything of §7.4 that decides acceptance, on the borrowed state (plan D2, D3); `max_ff` bounds
    /// `skip_message_keys`.
    fn open(
        &self,
        cell: &[u8],
        entropy: &mut impl Entropy,
        max_ff: u32,
    ) -> Result<(Update, Plaintext)> {
        #[cfg(feature = "kat")]
        DECRYPT_SITE_KAT.set(Some("cell length"));
        if cell.len() != CELL_LEN {
            return Err(Error::Rejected);
        }
        #[cfg(feature = "kat")]
        DECRYPT_SITE_KAT.set(Some("header: no key opened"));
        #[cfg(any(test, feature = "kat"))]
        {
            TRIAL_COUNTS_KAT.set((0, 0));
            SKIP_STEPS_KAT.set(0);
        }
        let (hdr_nonce, rest) = cell
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(Error::Rejected)?;
        let (hdr_ct, body) = rest.split_at_checked(HDR_CT_LEN).ok_or(Error::Rejected)?;
        let hdr_ad = header_ad(&self.sb);
        let body_ad = body_ad(&self.sb, hdr_nonce, hdr_ct);
        let dummy = SecretBytes::<32>::from_slice(&[0; 32])?;

        // 1. every distinct header key of `skipped`, then 2. hk_r and nhk_r — all of them, every time
        let distinct = self.distinct_skipped_keys();
        let trials = Trials {
            skipped: distinct
                .iter()
                .map(|hk| open_header(Some(hk), &dummy, hdr_nonce, &hdr_ad, hdr_ct))
                .collect(),
            current: open_header(self.hk_r.as_ref(), &dummy, hdr_nonce, &hdr_ad, hdr_ct),
            next: open_header(self.nhk_r.as_ref(), &dummy, hdr_nonce, &hdr_ad, hdr_ct),
        };
        match select_header(&self.skipped, &distinct, &trials)? {
            Selected::Skipped(at, header, mk) => {
                // the entry's mk as `lookup_skipped` selected it: `skipped` is not indexed before the body MAC (R-58)
                #[cfg(feature = "kat")]
                DECRYPT_SITE_KAT.set(Some("body MAC"));
                let plaintext = Plaintext::new(MsgEncrypt::open(&mk, &body_ad, body)?, &mk);
                Ok((
                    Update {
                        remove: Some(at),
                        added: Vec::new(),
                        chain: None,
                        step: None,
                        counters: (header.n, header.pn),
                    },
                    plaintext,
                ))
            }
            Selected::Chain(header) => self.open_chain(&header, &body_ad, body, max_ff),
            Selected::Step(header) => self.open_step(&header, &body_ad, body, entropy, max_ff),
        }
    }

    /// §7.4 with `step = false`: KEM constancy, `skip_message_keys(header.n)` (at most `max_ff` steps), `KDF_CK`,
    /// `MsgDecrypt`.
    fn open_chain(
        &self,
        header: &HeaderV1,
        body_ad: &[u8],
        body: &[u8],
        max_ff: u32,
    ) -> Result<(Update, Plaintext)> {
        #[cfg(feature = "kat")]
        DECRYPT_SITE_KAT.set(Some("kem constancy"));
        let (Some(kem_r), Some(last_ct_r), Some(ck_r), Some(hk_r)) =
            (&self.kem_r, &self.last_ct_r, &self.ck_r, &self.hk_r)
        else {
            return Err(Error::Rejected);
        };
        // KEM material must be constant within a chain
        let constant = header.ek_pq.as_bytes().ct_eq(kem_r.as_bytes())
            & header.ct_pq.as_slice().ct_eq(last_ct_r.as_bytes());
        if !bool::from(constant) {
            return Err(Error::Rejected);
        }
        #[cfg(feature = "kat")]
        DECRYPT_SITE_KAT.set(Some("counter rule"));
        let plan = select::skip_plan_within(self.n_r, header.n, max_ff)?;
        let (ck, added) = derive_skipped(ck_r, hk_r, self.n_r, plan)?;
        // (ck_r, mk) = KDF_CK(ck_r); n_r += 1
        let (ck_next, mk) = kdf_ck(&ck)?;
        let n_r = header.n.checked_add(1).ok_or(Error::Rejected)?;
        #[cfg(feature = "kat")]
        DECRYPT_SITE_KAT.set(Some("body MAC"));
        let plaintext = Plaintext::new(MsgEncrypt::open(&mk, body_ad, body)?, &mk);
        Ok((
            Update {
                remove: None,
                added,
                chain: Some((ck_next, n_r)),
                step: None,
                counters: (header.n, header.pn),
            },
            plaintext,
        ))
    }

    /// §7.4 with `step = true`: the new-ratchet-key check, `skip_message_keys(header.pn)` on the old chain,
    /// `DHRatchet` (receiving half), `skip_message_keys(header.n)` (each at most `max_ff` steps), `KDF_CK`,
    /// `MsgDecrypt`, and — only after the body MAC verified — `DHRatchet`'s sending half.
    fn open_step(
        &self,
        header: &HeaderV1,
        body_ad: &[u8],
        body: &[u8],
        entropy: &mut impl Entropy,
        max_ff: u32,
    ) -> Result<(Update, Plaintext)> {
        #[cfg(feature = "kat")]
        DECRYPT_SITE_KAT.set(Some("dh_pk"));
        // a step must carry a new ratchet key
        if let Some(dh_r) = &self.dh_r
            && bool::from(header.dh_pk.as_bytes().ct_eq(dh_r.as_bytes()))
        {
            return Err(Error::Rejected);
        }
        let (Some(nhk_s), Some(nhk_r)) = (&self.nhk_s, &self.nhk_r) else {
            return Err(Error::Rejected);
        };
        #[cfg(feature = "kat")]
        DECRYPT_SITE_KAT.set(Some("counter rule"));
        // skip_message_keys(header.pn) on the *old* receiving chain (none yet: nothing to skip)
        let mut added = Vec::new();
        if let (Some(ck_r), Some(hk_r)) = (&self.ck_r, &self.hk_r) {
            let plan = select::skip_plan_within(self.n_r, header.pn, max_ff)?;
            added = derive_skipped(ck_r, hk_r, self.n_r, plan)?.1;
        }
        #[cfg(feature = "kat")]
        DECRYPT_SITE_KAT.set(Some("dh_pk"));
        // DHRatchet, receiving half: dh_r = header.dh_pk; kem_r = header.ek_pq; last_ct_r = header.ct_pq;
        // ss_pq_recv = ML-KEM-768.Decaps(kem_s, header.ct_pq); (rk, ck_r, nhk_r) = KDF_RK(rk, X25519(dh_s, dh_r) ‖ ss)
        let dh_r = X25519Public::from_bytes(header.dh_pk.as_bytes())?;
        let kem_r = MlKem768Ek::from_bytes(header.ek_pq.as_bytes())?;
        let last_ct_r = MlKem768Ct::from_bytes(header.ct_pq.as_slice())?;
        let ss_recv = self.kem_s.dk.decapsulate(&last_ct_r);
        let dh_recv = self.dh_s.sk.diffie_hellman(&dh_r)?;
        let (rk_recv, ck_r, nhk_r_next) = kdf_rk(&self.rk, &dh_recv, &ss_recv)?;
        #[cfg(feature = "kat")]
        DECRYPT_SITE_KAT.set(Some("counter rule"));
        // skip_message_keys(header.n) on the new chain (n_r = 0, hk_r = the old nhk_r)
        let plan = select::skip_plan_within(0, header.n, max_ff)?;
        let (ck, new_chain) = derive_skipped(&ck_r, nhk_r, 0, plan)?;
        added.extend(new_chain);
        let (ck_next, mk) = kdf_ck(&ck)?;
        let n_r = header.n.checked_add(1).ok_or(Error::Rejected)?;
        #[cfg(feature = "kat")]
        DECRYPT_SITE_KAT.set(Some("body MAC"));
        let plaintext = Plaintext::new(MsgEncrypt::open(&mk, body_ad, body)?, &mk);
        // the body MAC verified: DHRatchet, sending half — dh_s = X25519.keygen(); kem_s = ML-KEM-768.keygen();
        // (ct_s, ss_pq_send) = ML-KEM-768.Encaps(kem_r); (rk, ck_s, nhk_s) = KDF_RK(rk, X25519(dh_s, dh_r) ‖ ss)
        let dh_s = DhPair::new(entropy.x25519()?)?;
        let kem_s = KemPair::new(entropy.mlkem768()?)?;
        let (send_ct, ss_send) = entropy.encaps(&kem_r)?;
        let dh_send = dh_s.sk.diffie_hellman(&dh_r)?;
        let (root, send_chain, send_next_header) = kdf_rk(&rk_recv, &dh_send, &ss_send)?;
        Ok((
            Update {
                remove: None,
                added,
                chain: Some((ck_next, n_r)),
                counters: (header.n, header.pn),
                step: Some(StepUpdate {
                    // pn = n_s; n_s = 0; hk_s = nhk_s; hk_r = nhk_r
                    pn: self.n_s,
                    hk_s: copy32(nhk_s)?,
                    hk_r: copy32(nhk_r)?,
                    dh_r: header.dh_pk,
                    kem_r,
                    last_ct_r,
                    rk: root,
                    nhk_r: nhk_r_next,
                    dh_s,
                    kem_s,
                    ct_s: send_ct,
                    ck_s: send_chain,
                    nhk_s: send_next_header,
                }),
            },
            plaintext,
        ))
    }

    /// Apply an accepted cell's changes; `skipped` is evicted earliest-first to its bound (§7.4).
    fn apply(&mut self, update: Update) {
        if let Some(at) = update.remove {
            self.skipped.remove(at);
        }
        if let Some(s) = update.step {
            self.pn = s.pn;
            self.n_s = 0;
            self.hk_s = Some(s.hk_s);
            self.hk_r = Some(s.hk_r);
            self.dh_r = Some(s.dh_r);
            self.kem_r = Some(s.kem_r);
            self.last_ct_r = Some(s.last_ct_r);
            self.rk = s.rk;
            self.nhk_r = Some(s.nhk_r);
            self.dh_s = s.dh_s;
            self.kem_s = s.kem_s;
            self.ct_s = Some(s.ct_s);
            self.ck_s = Some(s.ck_s);
            self.nhk_s = Some(s.nhk_s);
        }
        if let Some((ck_r, n_r)) = update.chain {
            self.ck_r = Some(ck_r);
            self.n_r = n_r;
        }
        self.skipped.extend(update.added);
        let evict = select::evicted(self.skipped.len());
        self.skipped.drain(..evict);
    }

    /// The sending header key `hk_s` (feature `kat`: the vector generator re-seals manipulated headers under it, the
    /// constant-time bench and the fuzz targets build headers the receiver opens).
    #[cfg(feature = "kat")]
    #[must_use]
    pub fn hk_s_kat(&self) -> Option<&SecretBytes<32>> {
        self.hk_s.as_ref()
    }

    /// The receiving header keys `(hk_r, nhk_r)` (feature `kat`; see [`RatchetState::hk_s_kat`]).
    #[cfg(feature = "kat")]
    #[must_use]
    pub fn receiving_header_keys_kat(
        &self,
    ) -> (Option<&SecretBytes<32>>, Option<&SecretBytes<32>>) {
        (self.hk_r.as_ref(), self.nhk_r.as_ref())
    }

    /// The session binding `sb` (feature `kat`).
    #[cfg(feature = "kat")]
    #[must_use]
    pub fn sb_kat(&self) -> &[u8; HASH_LEN] {
        &self.sb
    }
}

/// M3 review F12: the zeroizing field types of everything that holds a secret are pinned at compile time; changing
/// one to a plain `[u8; N]` / `Vec<u8>` fails here.
#[cfg(test)]
mod zeroizing_field_types {
    use secmp_crypto::{MlKem768Dk, SecretBytes, X25519Secret};

    use super::{Opened, Plaintext, Sealed, StepUpdate};
    use crate::codec::Zeroizing;
    use crate::sizes::BODY_LEN;
    use crate::tr::state::{RatchetState, SkippedKey};

    fn pins(
        s: &RatchetState,
        k: &SkippedKey,
        p: &Plaintext,
        sealed: &Sealed,
        opened: &Opened,
        u: &StepUpdate,
    ) {
        let _: &SecretBytes<32> = &s.rk;
        let _: &X25519Secret = &s.dh_s.sk;
        let _: &MlKem768Dk = &s.kem_s.dk;
        for key in [&s.ck_s, &s.ck_r, &s.hk_s, &s.hk_r, &s.nhk_s, &s.nhk_r] {
            let _: &Option<SecretBytes<32>> = key;
        }
        let _: &SecretBytes<32> = &k.hk;
        let _: &SecretBytes<32> = &k.mk;
        let _: &SecretBytes<BODY_LEN> = &p.bytes;
        let _: &Zeroizing<Vec<u8>> = &sealed.state_bytes;
        let _: &Zeroizing<Vec<u8>> = &opened.state_bytes;
        let _: &SecretBytes<BODY_LEN> = &opened.plaintext.bytes;
        let _: &SecretBytes<32> = &u.hk_s;
        let _: &SecretBytes<32> = &u.hk_r;
        let _: &SecretBytes<32> = &u.rk;
        let _: &SecretBytes<32> = &u.nhk_r;
        let _: &SecretBytes<32> = &u.ck_s;
        let _: &SecretBytes<32> = &u.nhk_s;
        let _: &X25519Secret = &u.dh_s.sk;
        let _: &MlKem768Dk = &u.kem_s.dk;
    }

    #[test]
    fn secret_fields_are_zeroizing_types() {
        // the body is type-checked; the pointer proves `pins` is used
        let _: fn(&RatchetState, &SkippedKey, &Plaintext, &Sealed, &Opened, &StepUpdate) = pins;
    }
}

/// M3 review F1 (R-03 (b)): up to and including `decide`, the header selection converts one cell-dependent `Choice`
/// to a branch — `decide`'s case code — on every path of §7.4.
#[cfg(test)]
mod single_conversion {
    use secmp_crypto::{Choice, ConstantTimeEq, MlKem768Dk, SecretBytes, X25519Secret};

    use crate::error::{Error, Result};
    use crate::keys::{MlKem768Ek, X25519Pk};
    use crate::sizes::CELL_LEN;
    use crate::tr::content;
    use crate::tr::select::{self, CellChoice};
    use crate::tr::state::RatchetState;

    /// `<S as NotInto<T, _>>::check` names one item if `S: Into<T>` does not hold: the impl with `A = ()` always
    /// applies, the one with `A = u8` only if the conversion exists — then `_` is ambiguous and the call does not
    /// compile (the construction of `static_assertions::assert_not_impl_any`).
    trait NotInto<T, A> {
        fn check() {}
    }
    impl<S, T> NotInto<T, ()> for S {}
    impl<S: Into<T>, T> NotInto<T, u8> for S {}

    /// As [`NotInto`], for `PartialEq` (`==` on two `CellChoice`s would be a conversion to `bool`).
    trait NotPartialEq<A> {
        fn check() {}
    }
    impl<S> NotPartialEq<()> for S {}
    impl<S: PartialEq> NotPartialEq<u8> for S {}

    /// The session binding.
    const SB: [u8; 32] = [7; 32];

    /// A fresh session (§7.2): the initiator and the responder.
    pub(super) fn session() -> Result<(RatchetState, RatchetState)> {
        let sk = SecretBytes::random()?;
        let spk = X25519Secret::generate()?;
        let rpk = MlKem768Dk::generate()?;
        let spk_pub = X25519Pk::from_bytes(spk.public_key().as_bytes())?;
        let rpk_ek = MlKem768Ek::from_bytes(rpk.encapsulation_key().as_bytes())?;
        let a = RatchetState::init_initiator(&sk, &SB, &spk_pub, &rpk_ek)?;
        let b = RatchetState::init_responder(&sk, &SB, spk, rpk)?;
        Ok((a, b))
    }

    /// The sender's next cell (a Dummy).
    pub(super) fn send(s: RatchetState) -> Result<(RatchetState, Vec<u8>)> {
        let (s, cell) = s
            .encrypt(&content::dummy())
            .map_err(|r| r.error())?
            .persist(|_| Ok::<(), Error>(()))?;
        Ok((s, cell.as_bytes().to_vec()))
    }

    /// `cell` is accepted with header counters `(n, pn)`, after one selection and one conversion.
    fn accepts(
        s: RatchetState,
        cell: &[u8],
        counters: (u32, u32),
        what: &str,
    ) -> Result<RatchetState> {
        let _ = select::hook::take();
        let opened = s.decrypt(cell).map_err(|r| r.error())?;
        assert_eq!(
            select::hook::take(),
            (1, 1),
            "{what}: (selections, conversions)"
        );
        assert_eq!(opened.header_counters(), counters, "{what}");
        Ok(opened.commit(|_| Ok::<(), Error>(()))?.0)
    }

    /// `cell` is refused with the uniform error, after one selection and one conversion.
    fn refuses(s: RatchetState, cell: &[u8], what: &str) -> Result<RatchetState> {
        let _ = select::hook::take();
        let refusal = s.decrypt(cell).err();
        assert_eq!(
            select::hook::take(),
            (1, 1),
            "{what}: (selections, conversions)"
        );
        assert!(refusal.is_some(), "{what}: accepted");
        let (s, error) = refusal.ok_or(Error::Rejected)?.into_parts();
        assert_eq!(error, Error::Rejected, "{what}");
        Ok(s)
    }

    /// Type level: a [`CellChoice`] has no conversion to `bool`, `u8` or `Choice` and no `==`, and `RatchetState::open`
    /// holds every cell-dependent result as one. Run time: every 4096-byte cell — on each path of §7.4: skipped key,
    /// current chain, DH step, rejection — goes through exactly one selection on `CellChoice`s
    /// (`select::first_opened_cell`) and one conversion (`select::path`, i.e. `decide`), counted by `select::hook`.
    /// Selecting on raw `Choice`s again (as M3 did, `bool::from(any_skipped)` before `decide`) counts `(0, 0)`;
    /// converting a `CellChoice` does not compile.
    #[test]
    fn any_skipped_single_conversion() -> Result<()> {
        <CellChoice as NotInto<bool, _>>::check();
        <CellChoice as NotInto<u8, _>>::check();
        <CellChoice as NotInto<Choice, _>>::check();
        <CellChoice as NotPartialEq<_>>::check();

        let (a, b) = session()?;
        let (a, m0) = send(a)?;
        let (a, m1) = send(a)?;
        let b = accepts(b, &m1, (1, 0), "step (nhk_r opens; position 0 skipped)")?;
        assert_eq!(b.skipped.len(), 1);
        let b = accepts(b, &m0, (0, 0), "skipped")?;
        let (a, m2) = send(a)?;
        let b = accepts(b, &m2, (2, 0), "chain")?;
        let (a, m3) = send(a)?;
        let (a, m4) = send(a)?;
        let b = accepts(b, &m4, (4, 0), "chain (position 3 skipped)")?;
        // the skipped key of the current chain is hk_r: it opens the next header too, and (hk_r, 5) is not in
        // `skipped` — any_skipped and not found, the case M3 converted (and decoded) before `decide`
        let hk_r = b.hk_r.as_ref().ok_or(Error::Rejected)?;
        let front = b.skipped.front().ok_or(Error::Rejected)?;
        assert!(bool::from(front.hk.ct_eq(hk_r)) && front.n == 3);
        let (_, m5) = send(a)?;
        let b = accepts(b, &m5, (5, 0), "chain while a skipped key opens too")?;
        let b = accepts(b, &m3, (3, 0), "skipped (current chain)")?;
        let b = refuses(b, &[0x5a; CELL_LEN], "no key opens")?;
        let b = refuses(b, &m5, "replay on the chain")?;
        let b = refuses(b, &m3, "replay of a consumed skipped key")?;
        // the cell length is public and checked before any trial decryption
        let short = m5
            .get(..CELL_LEN.saturating_sub(1))
            .ok_or(Error::Rejected)?;
        let _ = select::hook::take();
        assert!(b.decrypt(short).is_err(), "4095 bytes");
        assert_eq!(select::hook::take(), (0, 0), "4095 bytes");
        Ok(())
    }
}

/// `header_n` and `select_header` on trial results built by hand (M3 review F1; ADR-043 (b)).
#[cfg(test)]
mod selection {
    use std::collections::VecDeque;

    use secmp_crypto::{Choice, SecretBytes};

    use super::{Selected, Trial, Trials, header_n, lookup_skipped, select_header};
    use crate::codec::{Decode, Encode, Zeroizing};
    use crate::error::{Error, Result};
    use crate::sizes::{HEADER_LEN, PROTO_VER};
    use crate::tr::select::{self, CellChoice};
    use crate::tr::state::SkippedKey;
    use crate::wire::cell::HeaderV1;

    /// A decodable encoded header (spec §7.5): `dh_pk` the base point u = 9, `ek_pq` all zero (every coefficient
    /// 0 < q), `ct_pq` all zero.
    fn header(pn: u32, n: u32) -> Zeroizing<Vec<u8>> {
        let mut h = Zeroizing::new(Vec::with_capacity(HEADER_LEN));
        h.extend_from_slice(&[PROTO_VER, 0, 9]);
        h.extend_from_slice(&[0; 31]);
        h.extend_from_slice(&pn.to_be_bytes());
        h.extend_from_slice(&n.to_be_bytes());
        h.resize(HEADER_LEN, 0);
        h
    }

    /// [`header`] with `flags` = 1: opens, but does not decode (spec §7.5).
    fn undecodable(n: u32) -> Zeroizing<Vec<u8>> {
        let mut h = header(0, n);
        if let Some(flags) = h.get_mut(1) {
            *flags = 1;
        }
        h
    }

    /// A trial decryption that opened `plaintext`, or (`None`) did not open (all zero).
    fn trial(plaintext: Option<Zeroizing<Vec<u8>>>) -> Trial {
        let opened = Choice::from(u8::from(plaintext.is_some()));
        (
            CellChoice::from(opened),
            plaintext.unwrap_or_else(|| Zeroizing::new(vec![0; HEADER_LEN])),
        )
    }

    /// `select_header` for a state with the one skipped entry `(K, 5)` on the trial results under K (`skipped_key`),
    /// `hk_r` (`current`) and `nhk_r` (`next`): the case and its header's `n`, `None` if rejected (with the uniform
    /// error). Every call selects and converts exactly once.
    fn case(
        skipped_key: Option<Zeroizing<Vec<u8>>>,
        current: Option<Zeroizing<Vec<u8>>>,
        next: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<Option<(&'static str, u32)>> {
        let k = SecretBytes::<32>::from_slice(&[1; 32])?;
        let skipped = VecDeque::from([SkippedKey {
            hk: SecretBytes::from_slice(&[1; 32])?,
            n: 5,
            mk: SecretBytes::from_slice(&[3; 32])?,
        }]);
        let trials = Trials {
            skipped: vec![trial(skipped_key)],
            current: trial(current),
            next: trial(next),
        };
        let _ = select::hook::take();
        let selected = select_header(&skipped, &[&k], &trials);
        assert_eq!(select::hook::take(), (1, 1), "(selections, conversions)");
        Ok(match selected {
            Ok(Selected::Skipped(at, h, mk)) => {
                assert_eq!(at, 0);
                assert_eq!(mk.expose_secret(), &[3; 32], "the entry's mk");
                Some(("skipped", h.n))
            }
            Ok(Selected::Chain(h)) => Some(("chain", h.n)),
            Ok(Selected::Step(h)) => Some(("step", h.n)),
            Err(error) => {
                assert_eq!(error, Error::Rejected);
                None
            }
        })
    }

    /// `n` sits at bytes `[38..42]` of the encoding, big-endian (spec App. D.5): `header_n` agrees with the decoder
    /// and the encoder.
    #[test]
    fn header_n_reads_bytes_38_to_42() -> Result<()> {
        for (pn, n) in [(0, 0), (7, 1), (u32::MAX, 0x0102_0304), (1, u32::MAX)] {
            let bytes = header(pn, n);
            let decoded = HeaderV1::decode(&bytes)?;
            assert_eq!((decoded.pn, decoded.n), (pn, n));
            assert_eq!(*decoded.encode()?, *bytes);
            assert_eq!(bytes.get(38..42), Some(n.to_be_bytes().as_slice()));
            assert_eq!(header_n(&bytes), Ok(n));
            assert_eq!(header_n(&undecodable(n)), Ok(n));
        }
        assert_eq!(header_n(&[0; 41]), Err(Error::Rejected));
        assert_eq!(header_n(&[0, 0, 1, 2, 3, 4]), Err(Error::Rejected));
        Ok(())
    }

    /// ADR-043 (b) — `Open` includes decoding; a header a skipped key opens but that does not decode rejects the cell,
    /// no further key is tried — without a branch on `any_skipped` (M3 review F1): `n` is read undecoded for the
    /// lookup, and the first skipped key's header is decoded after `decide` on every accepting path. The first rows are
    /// trial results no honest cell yields — K's plaintext differs from the one `hk_r` or `nhk_r` opened, as only a
    /// header ciphertext that opens under two keys (crafted by a contact who holds both) can make it — on which reading
    /// `n` without decoding must not let the cell fall through to `hk_r`/`nhk_r`.
    #[test]
    fn undecodable_skipped_header_rejects_on_every_path() -> Result<()> {
        // K opened a header that does not decode: rejected, whatever else opened and whether (K, n) is in skipped
        assert_eq!(
            case(Some(undecodable(7)), Some(header(0, 8)), None)?,
            None,
            "hk_r opened too, (K, 7) not in skipped"
        );
        assert_eq!(
            case(Some(undecodable(7)), None, Some(header(0, 9)))?,
            None,
            "nhk_r opened too, (K, 7) not in skipped"
        );
        assert_eq!(
            case(Some(undecodable(5)), Some(header(0, 8)), None)?,
            None,
            "(K, 5) in skipped"
        );
        assert_eq!(case(Some(undecodable(5)), None, None)?, None, "K alone");
        // controls: the same with a decodable header under K
        assert_eq!(
            case(Some(header(0, 7)), Some(header(0, 8)), None)?,
            Some(("chain", 8))
        );
        assert_eq!(
            case(Some(header(0, 7)), None, Some(header(0, 9)))?,
            Some(("step", 9))
        );
        assert_eq!(
            case(Some(header(0, 5)), Some(header(0, 8)), None)?,
            Some(("skipped", 5))
        );
        assert_eq!(case(Some(header(0, 7)), None, None)?, None, "not found");
        // no skipped key opened: the path's own header decides
        assert_eq!(case(None, Some(header(0, 8)), None)?, Some(("chain", 8)));
        assert_eq!(
            case(None, Some(header(0, 8)), Some(header(0, 9)))?,
            Some(("chain", 8))
        );
        assert_eq!(case(None, Some(undecodable(8)), None)?, None);
        assert_eq!(case(None, None, Some(header(0, 9)))?, Some(("step", 9)));
        assert_eq!(case(None, None, Some(undecodable(9)))?, None);
        assert_eq!(case(None, None, None)?, None);
        Ok(())
    }

    /// M4 review R-58: `lookup_skipped` selects the matching entry's message key with masks over every entry — at
    /// index 0, in the middle and last — and gives the all-zero key on a miss; the index comes back for
    /// `Update::remove` only, and `RatchetState::open` passes the selected key to the body MAC (`Selected::Skipped`
    /// carries it), so `skipped` is not indexed before the MAC. A `VecDeque::get` cannot be hooked, and neither this
    /// test nor the counter of `trial_opens_every_candidate_every_call` would detect a reintroduced secret-indexed `mk`
    /// load (no M4 mutants run covered `tr/`): that absence is guarded by review only, until the counting accessor of
    /// F-M5 (M4 review R-42).
    #[test]
    fn skipped_mk_is_selected_without_indexing() -> Result<()> {
        // seven entries over three header keys, (hk_i, n) → mk = [10·i + n; 32]
        let mut skipped = VecDeque::new();
        for (i, n) in [
            (1_u8, 0_u32),
            (1, 1),
            (1, 4),
            (2, 0),
            (2, 3),
            (3, 0),
            (3, 1),
        ] {
            let mk = i
                .checked_mul(10)
                .and_then(|x| x.checked_add(u8::try_from(n).ok()?))
                .ok_or(Error::Rejected)?;
            skipped.push_back(SkippedKey {
                hk: SecretBytes::from_slice(&[i; 32])?,
                n,
                mk: SecretBytes::from_slice(&[mk; 32])?,
            });
        }
        let found = |c: CellChoice| {
            let mut f = 0_u8;
            c.assign(&mut f, &1);
            f
        };
        for (hk, n, at, mk) in [(1, 0, 0, 10), (2, 0, 3, 20), (3, 1, 6, 31), (1, 4, 2, 14)] {
            let (hit, index, key) = lookup_skipped(&skipped, &[hk; 32], n);
            assert_eq!(found(hit), 1, "({hk}, {n})");
            assert_eq!(index, at, "({hk}, {n})");
            assert_eq!(*key, [mk; 32], "({hk}, {n})");
        }
        // misses: a stored hk with another n, a stored n under another hk, an unknown key, an empty `skipped`
        for (hk, n) in [(1, 2), (2, 1), (3, 4), (4, 0)] {
            let (hit, index, key) = lookup_skipped(&skipped, &[hk; 32], n);
            assert_eq!(found(hit), 0, "({hk}, {n})");
            assert_eq!(index, 0, "({hk}, {n})");
            assert_eq!(*key, [0; 32], "({hk}, {n})");
        }
        let (hit, _, key) = lookup_skipped(&VecDeque::new(), &[1; 32], 0);
        assert_eq!((found(hit), *key), (0, [0; 32]));
        Ok(())
    }
}

/// M3 review R-04 (WEISUNG M4-4 Part D): the early-exit detector of the trial decryption, as a count. The constant-time
/// target `tr_decrypt_reject_skipped` no longer separates the opening trial's position (R-59); this test does.
#[cfg(test)]
mod trial_work {
    use secmp_crypto::MSG_TAG_LEN;

    use super::TRIAL_COUNTS_KAT;
    use super::single_conversion::{send, session};
    use crate::error::{Error, Result};
    use crate::sizes::CELL_LEN;
    use crate::tr::state::RatchetState;

    /// `state` decrypts `cell` and commits.
    fn receive(state: RatchetState, cell: &[u8]) -> Result<RatchetState> {
        let opened = state.decrypt(cell).map_err(|r| r.error())?;
        Ok(opened.commit(|_| Ok::<(), Error>(()))?.0)
    }

    /// B holding skipped keys of `chains` of A's chains, and A's cells for every candidate of B's trial decryption.
    struct Fixture {
        /// `skipped` = `(hk_i, 0)`, `(hk_i, 1)` for i = 1 … `chains`; `hk_r` is chain `chains + 1`.
        b: RatchetState,
        /// A's undelivered cell n = 0 of chain i (opens under the i-th distinct skipped key).
        skipped: Vec<Vec<u8>>,
        /// A's cell n = 1 of chain `chains + 1` (opens under `hk_r`).
        current: Vec<u8>,
        /// A's cell n = 0 of chain `chains + 2` (opens under `nhk_r`).
        next: Vec<u8>,
    }

    /// On each of A's chains 1 … `chains`, A sends n = 0, 1, 2 and B receives n = 2 (its DH step stores `(hk_i, 0)`
    /// and `(hk_i, 1)`), then B replies and A's DH step starts the next chain. B receives chain `chains + 1`'s n = 0
    /// (its current chain) and replies once more, so A's chain `chains + 2` is under B's `nhk_r`.
    fn fixture(chains: usize) -> Result<Fixture> {
        let (mut a, mut b) = session()?;
        let mut skipped = Vec::new();
        for _ in 0..chains {
            let (a1, first) = send(a)?;
            let (a2, _) = send(a1)?;
            let (a3, last) = send(a2)?;
            b = receive(b, &last)?;
            skipped.push(first);
            let (b1, reply) = send(b)?;
            b = b1;
            a = receive(a3, &reply)?;
        }
        let (a1, d0) = send(a)?;
        let (a2, current) = send(a1)?;
        b = receive(b, &d0)?;
        let (b1, reply) = send(b)?;
        let a3 = receive(a2, &reply)?;
        let (_, next) = send(a3)?;
        Ok(Fixture {
            b: b1,
            skipped,
            current,
            next,
        })
    }

    /// For `distinct` = 1, 3 and 6 distinct skipped header keys (2 entries each), cells opening at the first, a
    /// middle and the last skipped candidate (accepted; and the last one with its body tag wrong: rejected at the
    /// MAC), under `hk_r`, under `nhk_r` and under no key: every `decrypt` performs `distinct + 2` header trial
    /// decryptions and visits every entry of `skipped` (`TRIAL_COUNTS_KAT`). A trial loop or lookup that stops after
    /// the first key that opened (the regression M3 review R-04 is about) counts fewer for every cell that opens
    /// before the last candidate.
    #[test]
    fn trial_opens_every_candidate_every_call() -> Result<()> {
        for distinct in [1_usize, 3, 6] {
            let f = fixture(distinct)?;
            assert_eq!(f.b.skipped.len(), 2 * distinct);
            let middle = f.skipped.get(distinct / 2).ok_or(Error::Rejected)?;
            let first = f.skipped.first().ok_or(Error::Rejected)?;
            let last = f.skipped.last().ok_or(Error::Rejected)?;
            let mut wrong_tag = last.clone();
            let tag = wrong_tag
                .get_mut(CELL_LEN - MSG_TAG_LEN)
                .ok_or(Error::Rejected)?;
            *tag ^= 1;
            let none = vec![0x5a; CELL_LEN];
            let want = (
                u32::try_from(distinct + 2).map_err(|_| Error::Rejected)?,
                u32::try_from(2 * distinct).map_err(|_| Error::Rejected)?,
            );
            for (what, cell, accepted) in [
                ("first skipped candidate", first, true),
                ("middle skipped candidate", middle, true),
                ("last skipped candidate", last, true),
                ("last skipped candidate, body tag wrong", &wrong_tag, false),
                ("hk_r", &f.current, true),
                ("nhk_r", &f.next, true),
                ("no key", &none, false),
            ] {
                let b = RatchetState::from_bytes(&f.b.to_bytes()?)?;
                TRIAL_COUNTS_KAT.set((u32::MAX, u32::MAX));
                let result = b.decrypt(cell);
                assert_eq!(result.is_ok(), accepted, "{distinct} keys, {what}");
                assert_eq!(
                    TRIAL_COUNTS_KAT.get(),
                    want,
                    "{distinct} keys, {what}: (header trials, entries visited)"
                );
            }
        }
        Ok(())
    }
}
