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
//! header key of `skipped`, `hk_r`, `nhk_r`, an absent key replaced by a dummy key whose result is masked — as
//! `Choice`s ([`Aead::open_ct`]); [`select::first_opened`] and [`select::decide`] reduce them to the §7.4 case.
//! There are two conversions to a branch, not one (M3 review C6): `any_skipped` becomes a `bool` early, to decode
//! the selected skipped header for the `(hk, n)` lookup, and `decide`'s case code is the final one; the branch-free
//! variant is an M4 follow-up (review F1). Keys, KEM material and ratchet keys are compared with `ct_eq`, never
//! `==`.

use secmp_crypto::{
    Aead, Choice, ConditionallySelectable, ConstantTimeEq, Label, MlKem768Ct, MlKem768Ek,
    MsgEncrypt, SecretBytes, X25519Public, X25519Secret, kdf_ck, kdf_rk, tr_init,
};

// the encodings' zeroizing buffer (`secmp_crypto::Zeroizing`; a stand-in under Kani, see `codec`)
use crate::codec::{Decode, Encode, Zeroizing};
use crate::error::{Error, Result};
use crate::keys::{self, X25519Pk};
use crate::sizes::{BODY_LEN, CELL_LEN, HASH_LEN, HDR_CT_LEN, HEADER_LEN, NONCE_LEN};
use crate::tr::entropy::{Entropy, OsEntropy};
use crate::tr::select::{self, Path, SkipPlan};
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

/// `Open(key, hdr_nonce, hdr_ct)` with constant work: an absent key is replaced by `dummy` and its result masked.
fn open_header(
    key: Option<&SecretBytes<32>>,
    dummy: &SecretBytes<32>,
    hdr_nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    hdr_ct: &[u8],
) -> (Choice, Zeroizing<Vec<u8>>) {
    let mut out = Zeroizing::new(vec![0_u8; HEADER_LEN]);
    let present = Choice::from(u8::from(key.is_some()));
    let opened = Aead::open_ct(key.unwrap_or(dummy), hdr_nonce, ad, hdr_ct, &mut out);
    (opened & present, out)
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
        mut self,
        cell: &[u8],
        entropy: &mut impl Entropy,
    ) -> core::result::Result<Opened, Refused> {
        let (update, plaintext) = match self.open(cell, entropy) {
            Ok(x) => x,
            Err(error) => return Err(Refused::new(self, error)),
        };
        let counters = update.counters;
        // `to_bytes` fails only if `skipped` exceeds its bound; `apply` evicts to the bound, so check the post-apply
        // length first and hand back the genuinely unchanged state, before anything is swapped in
        let after = self
            .skipped
            .len()
            .saturating_sub(usize::from(update.remove.is_some()))
            .saturating_add(update.added.len());
        if after.saturating_sub(select::evicted(after)) > select::MAX_SKIPPED {
            return Err(Refused::new(self, Error::Rejected));
        }
        self.apply(update);
        // cannot fail: the bound was checked above
        match self.to_bytes() {
            Ok(state_bytes) => Ok(Opened {
                state: self,
                state_bytes,
                plaintext,
                counters,
            }),
            Err(error) => Err(Refused::new(self, error)),
        }
    }

    /// The distinct header keys of `skipped`, in first-seen order (the entries of a chain are contiguous, see
    /// `state::skipped_is_canonical`).
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

    /// Everything of §7.4 that decides acceptance, on the borrowed state (plan D2, D3).
    fn open(&self, cell: &[u8], entropy: &mut impl Entropy) -> Result<(Update, Plaintext)> {
        if cell.len() != CELL_LEN {
            return Err(Error::Rejected);
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
        let (opened, headers): (Vec<Choice>, Vec<Zeroizing<Vec<u8>>>) = distinct
            .iter()
            .map(|hk| open_header(Some(hk), &dummy, hdr_nonce, &hdr_ad, hdr_ct))
            .unzip();
        let (current_opened, current_header) =
            open_header(self.hk_r.as_ref(), &dummy, hdr_nonce, &hdr_ad, hdr_ct);
        let (next_opened, next_header) =
            open_header(self.nhk_r.as_ref(), &dummy, hdr_nonce, &hdr_ad, hdr_ct);

        // the first skipped key that opened, its header and its key, selected without a branch
        let (first, any_skipped) = select::first_opened(&opened);
        let mut skipped_header = Zeroizing::new(vec![0_u8; HEADER_LEN]);
        let mut skipped_hk = Zeroizing::new([0_u8; 32]);
        for ((f, header), hk) in first.iter().zip(&headers).zip(&distinct) {
            for (dst, src) in skipped_header.iter_mut().zip(header.iter()) {
                dst.conditional_assign(src, *f);
            }
            for (dst, src) in skipped_hk.iter_mut().zip(hk.expose_secret()) {
                dst.conditional_assign(src, *f);
            }
        }
        // Open() includes decoding (reference reading 3): a skipped key's header must decode to be looked up
        let skipped_decoded = if bool::from(any_skipped) {
            Some(HeaderV1::decode(&skipped_header)?)
        } else {
            None
        };
        // (hk, header.n) ∈ skipped? — every entry compared, in constant time
        let n = skipped_decoded.as_ref().map_or(0, |h| h.n);
        let mut found = Choice::from(0);
        let mut found_at = 0_u32;
        for (j, e) in (0_u32..).zip(&self.skipped) {
            let hit = e.hk.expose_secret().ct_eq(&*skipped_hk) & e.n.ct_eq(&n);
            found |= hit;
            found_at.conditional_assign(&j, hit);
        }
        match select::decide(any_skipped, found, current_opened, next_opened) {
            Path::Reject => Err(Error::Rejected),
            Path::Skipped => {
                let at = usize::try_from(found_at).map_err(|_| Error::Rejected)?;
                let entry = self.skipped.get(at).ok_or(Error::Rejected)?;
                let plaintext =
                    Plaintext::new(MsgEncrypt::open(&entry.mk, &body_ad, body)?, &entry.mk);
                Ok((
                    Update {
                        remove: Some(at),
                        added: Vec::new(),
                        chain: None,
                        step: None,
                        counters: skipped_decoded
                            .as_ref()
                            .map(|h| (h.n, h.pn))
                            .ok_or(Error::Rejected)?,
                    },
                    plaintext,
                ))
            }
            Path::Chain => self.open_chain(&HeaderV1::decode(&current_header)?, &body_ad, body),
            Path::Step => self.open_step(&HeaderV1::decode(&next_header)?, &body_ad, body, entropy),
        }
    }

    /// §7.4 with `step = false`: KEM constancy, `skip_message_keys(header.n)`, `KDF_CK`, `MsgDecrypt`.
    fn open_chain(
        &self,
        header: &HeaderV1,
        body_ad: &[u8],
        body: &[u8],
    ) -> Result<(Update, Plaintext)> {
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
        let plan = select::skip_plan(self.n_r, header.n)?;
        let (ck, added) = derive_skipped(ck_r, hk_r, self.n_r, plan)?;
        // (ck_r, mk) = KDF_CK(ck_r); n_r += 1
        let (ck_next, mk) = kdf_ck(&ck)?;
        let n_r = header.n.checked_add(1).ok_or(Error::Rejected)?;
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
    /// `DHRatchet` (receiving half), `skip_message_keys(header.n)`, `KDF_CK`, `MsgDecrypt`, and — only after the
    /// body MAC verified — `DHRatchet`'s sending half.
    fn open_step(
        &self,
        header: &HeaderV1,
        body_ad: &[u8],
        body: &[u8],
        entropy: &mut impl Entropy,
    ) -> Result<(Update, Plaintext)> {
        // a step must carry a new ratchet key
        if let Some(dh_r) = &self.dh_r
            && bool::from(header.dh_pk.as_bytes().ct_eq(dh_r.as_bytes()))
        {
            return Err(Error::Rejected);
        }
        let (Some(nhk_s), Some(nhk_r)) = (&self.nhk_s, &self.nhk_r) else {
            return Err(Error::Rejected);
        };
        // skip_message_keys(header.pn) on the *old* receiving chain (none yet: nothing to skip)
        let mut added = Vec::new();
        if let (Some(ck_r), Some(hk_r)) = (&self.ck_r, &self.hk_r) {
            let plan = select::skip_plan(self.n_r, header.pn)?;
            added = derive_skipped(ck_r, hk_r, self.n_r, plan)?.1;
        }
        // DHRatchet, receiving half: dh_r = header.dh_pk; kem_r = header.ek_pq; last_ct_r = header.ct_pq;
        // ss_pq_recv = ML-KEM-768.Decaps(kem_s, header.ct_pq); (rk, ck_r, nhk_r) = KDF_RK(rk, X25519(dh_s, dh_r) ‖ ss)
        let dh_r = X25519Public::from_bytes(header.dh_pk.as_bytes())?;
        let kem_r = MlKem768Ek::from_bytes(header.ek_pq.as_bytes())?;
        let last_ct_r = MlKem768Ct::from_bytes(header.ct_pq.as_slice())?;
        let ss_recv = self.kem_s.dk.decapsulate(&last_ct_r);
        let dh_recv = self.dh_s.sk.diffie_hellman(&dh_r)?;
        let (rk_recv, ck_r, nhk_r_next) = kdf_rk(&self.rk, &dh_recv, &ss_recv)?;
        // skip_message_keys(header.n) on the new chain (n_r = 0, hk_r = the old nhk_r)
        let plan = select::skip_plan(0, header.n)?;
        let (ck, new_chain) = derive_skipped(&ck_r, nhk_r, 0, plan)?;
        added.extend(new_chain);
        let (ck_next, mk) = kdf_ck(&ck)?;
        let n_r = header.n.checked_add(1).ok_or(Error::Rejected)?;
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
