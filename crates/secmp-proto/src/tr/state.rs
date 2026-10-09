// SPDX-License-Identifier: AGPL-3.0-or-later
//! `RatchetState` (spec §7.1, exactly) and its persistence encoding `RatchetStateV1` (M3 plan D5).
//!
//! **Zeroizing.** Every secret field is a zeroizing type: `rk`, the chain and header keys and every skipped entry are
//! `SecretBytes<32>` (heap, wiped on drop), `dh_s` and `kem_s` hold their secrets in locked memory
//! (`X25519Secret`, `MlKem768Dk`: `LockedSecret`, wiped on drop). A replaced field is dropped and so wiped; the
//! encoding is written into a `Zeroizing<Vec<u8>>` of its full size (one allocation, no growth).
//!
//! **`RatchetStateV1`** (big-endian, `opt(x)` = `0x00`, or `0x01 ‖ x`):
//!
//! ```text
//! fmt u8 = 0x01 ‖ sb[32] ‖ rk[32] ‖ dh_s.sk[32] ‖ opt(dh_r[32]) ‖ kem_s.seed[64] ‖ opt(kem_r[1184])
//! ‖ opt(last_ct_r[1088]) ‖ opt(ct_s[1088]) ‖ opt(ck_s[32]) ‖ opt(ck_r[32]) ‖ opt(hk_s[32]) ‖ opt(hk_r[32])
//! ‖ opt(nhk_s[32]) ‖ opt(nhk_r[32]) ‖ n_s u32 ‖ n_r u32 ‖ pn u32 ‖ count u16 (≤ 512)
//! ‖ { hk[32] ‖ n u32 ‖ mk[32] } × count                                  ; insertion order (spec §7.1)
//! ```
//!
//! `dh_s.sk` is the X25519 secret as drawn (before clamping), `kem_s.seed` the ML-KEM-768 seed `d ‖ z`; the public
//! halves are recomputed on load. At most [`RatchetState::MAX_ENCODED_LEN`] = 38 585 bytes.
//!
//! **Decoding** is total and canonical (one encoding per state): the format byte, every presence byte (0/1),
//! every length, `count ≤ 512`, the key checks of the wire (`dh_r` not of low order, spec §4.1 (a); `kem_r` passes
//! the FIPS 203 modulus check, (c)), and the shape of a reachable state (spec §7.2, §7.4): `nhk_s`, `nhk_r`
//! present; the sending group `ck_s, hk_s, ct_s, kem_r, dh_r` all present or all absent, likewise the receiving
//! group `ck_r, hk_r, last_ct_r`; a receiving group only with a sending group; without a receiving group `n_r =
//! pn = 0` and `skipped` empty; without a sending group `n_s = 0`; `skipped` grouped by header key in insertion
//! order, `n` strictly increasing within a group, no group's key repeated in a later group, no entry `(hk_r, n ≥ n_r)`
//! and none keyed by `nhk_r`. A malformed encoding
//! is [`Error::Rejected`]; [`Error::Unavailable`] only if locked memory is unavailable for `dh_s`/`kem_s`.

use std::collections::VecDeque;

use secmp_crypto::{
    Choice, ConstantTimeEq, MlKem768Ct, MlKem768Dk, MlKem768Ek, SecretBytes, X25519Secret,
};

// the encodings' zeroizing buffer (`secmp_crypto::Zeroizing`; a stand-in under Kani, see `codec`)
use crate::codec::{Reader, Writer, Zeroizing};
use crate::error::{Error, Result};
use crate::keys::{self, X25519Pk};
use crate::sizes::{HASH_LEN, MLKEM768_CT_LEN, MLKEM768_EK_LEN, X25519_PK_LEN, sum};
use crate::tr::select::MAX_SKIPPED;

/// The format byte of `RatchetStateV1`.
const FORMAT_V1: u8 = 0x01;

/// Length of an ML-KEM seed `d ‖ z`.
const SEED_LEN: usize = 64;
/// `opt(key[32])` present.
const OPT_KEY_LEN: usize = sum(&[1, 32]);
/// One skipped entry `hk[32] ‖ n u32 ‖ mk[32]`.
const ENTRY_LEN: usize = sum(&[32, 4, 32]);
/// A full `skipped`: 512 entries of 68 bytes.
const SKIPPED_MAX_BYTES: usize = 34_816;
const _: () = assert!(
    OPT_KEY_LEN == X25519_PK_LEN + 1
        && ENTRY_LEN == 68
        && SKIPPED_MAX_BYTES == MAX_SKIPPED * ENTRY_LEN
        && RatchetState::MAX_ENCODED_LEN == 38_585
);

/// An X25519 ratchet key pair (`dh_s`): the secret in locked memory and its public key as a header field.
pub(crate) struct DhPair {
    pub(crate) sk: X25519Secret,
    pub(crate) pk: X25519Pk,
}

impl DhPair {
    pub(crate) fn new(sk: X25519Secret) -> Result<Self> {
        let pk = X25519Pk::from_bytes(sk.public_key().as_bytes())?;
        Ok(Self { sk, pk })
    }
}

/// An ML-KEM-768 ratchet key pair (`kem_s`): the decapsulation key as its seed in locked memory and the
/// encapsulation key as a header field (`ek_pq`).
pub(crate) struct KemPair {
    pub(crate) dk: MlKem768Dk,
    pub(crate) ek: keys::MlKem768Ek,
}

impl KemPair {
    pub(crate) fn new(dk: MlKem768Dk) -> Result<Self> {
        let ek = keys::MlKem768Ek::from_bytes(dk.encapsulation_key().as_bytes())?;
        Ok(Self { dk, ek })
    }
}

/// One entry of `skipped`: `(hk, n) → mk`.
///
/// `mk` is private to this module: outside it the message key is read only through the counting accessor
/// [`SkippedKey::mk`] (M4 review R-42, campaign R-58), so that a reintroduced load of an entry's `mk` by a
/// secret-derived index in the §7.4 decision changes the count of message-key reads that test
/// `tr_skipped_lookup_touches_every_entry` checks to be exactly `|skipped|` per decryption. This module's own reads
/// (the encoding, which writes every entry in insertion order after the decision) do not count.
pub(crate) struct SkippedKey {
    pub(crate) hk: SecretBytes<32>,
    pub(crate) n: u32,
    mk: SecretBytes<32>,
}

impl SkippedKey {
    /// The entry `(hk, n) → mk`.
    pub(crate) const fn new(hk: SecretBytes<32>, n: u32, mk: SecretBytes<32>) -> Self {
        Self { hk, n, mk }
    }

    /// The entry's message key. Feature `kat` and the unit tests: every call counts one message-key read in the
    /// second component of `tr::TRIAL_COUNTS_KAT` (reset when a 4096-byte cell's processing begins); without `kat`
    /// and outside the tests the counting statement does not exist.
    pub(crate) fn mk(&self) -> &SecretBytes<32> {
        #[cfg(any(test, feature = "kat"))]
        super::ratchet::TRIAL_COUNTS_KAT.with(|c| {
            let (opens, mk_reads) = c.get();
            c.set((opens, mk_reads.saturating_add(1)));
        });
        &self.mk
    }
}

/// The SecMP-TR state of one session (spec §7.1). No `Clone`, `Debug` or `PartialEq`: it holds secrets. Persist
/// it with [`RatchetState::to_bytes`] (the new state of every operation is also handed out serialised, see
/// [`crate::tr::Sealed`] and [`crate::tr::Opened`]).
pub struct RatchetState {
    /// Session binding = HX transcript.
    pub(crate) sb: [u8; HASH_LEN],
    /// Root key.
    pub(crate) rk: SecretBytes<32>,
    /// Own ratchet key pair.
    pub(crate) dh_s: DhPair,
    /// Peer ratchet public key.
    pub(crate) dh_r: Option<X25519Pk>,
    /// Own KEM key pair; its ek is in every header we send.
    pub(crate) kem_s: KemPair,
    /// Peer's current ek; we encapsulate to it at our sending step.
    pub(crate) kem_r: Option<MlKem768Ek>,
    /// The KEM ciphertext of the peer's current chain.
    pub(crate) last_ct_r: Option<MlKem768Ct>,
    /// Our current chain's ciphertext to `kem_r`.
    pub(crate) ct_s: Option<MlKem768Ct>,
    /// Sending chain key.
    pub(crate) ck_s: Option<SecretBytes<32>>,
    /// Receiving chain key.
    pub(crate) ck_r: Option<SecretBytes<32>>,
    /// Sending header key.
    pub(crate) hk_s: Option<SecretBytes<32>>,
    /// Receiving header key.
    pub(crate) hk_r: Option<SecretBytes<32>>,
    /// Next sending header key.
    pub(crate) nhk_s: Option<SecretBytes<32>>,
    /// Next receiving header key.
    pub(crate) nhk_r: Option<SecretBytes<32>>,
    /// Next sending position.
    pub(crate) n_s: u32,
    /// Next receiving position.
    pub(crate) n_r: u32,
    /// Length of the previous sending chain.
    pub(crate) pn: u32,
    /// Skipped message keys, insertion-ordered, at most 512.
    pub(crate) skipped: VecDeque<SkippedKey>,
}

/// `opt(x)`.
fn write_opt(w: &mut Writer, x: Option<&[u8]>) {
    match x {
        Some(bytes) => {
            w.u8(1);
            w.bytes(bytes);
        }
        None => w.u8(0),
    }
}

fn read_opt<'a>(r: &mut Reader<'a>, len: usize) -> Result<Option<&'a [u8]>> {
    if r.flag()? {
        Ok(Some(r.take(len)?))
    } else {
        Ok(None)
    }
}

fn secret32(bytes: &[u8]) -> Result<SecretBytes<32>> {
    Ok(SecretBytes::from_slice(bytes)?)
}

fn opt_secret(x: Option<&[u8]>) -> Result<Option<SecretBytes<32>>> {
    x.map(secret32).transpose()
}

impl RatchetState {
    /// The largest encoding: 3769 fixed bytes and [`MAX_SKIPPED`] = 512 skipped entries of 68 bytes.
    pub const MAX_ENCODED_LEN: usize = sum(&[
        1,
        HASH_LEN,
        32,
        32,
        OPT_KEY_LEN,
        SEED_LEN,
        sum(&[1, MLKEM768_EK_LEN]),
        sum(&[1, MLKEM768_CT_LEN]),
        sum(&[1, MLKEM768_CT_LEN]),
        OPT_KEY_LEN,
        OPT_KEY_LEN,
        OPT_KEY_LEN,
        OPT_KEY_LEN,
        OPT_KEY_LEN,
        OPT_KEY_LEN,
        4,
        4,
        4,
        2,
        SKIPPED_MAX_BYTES,
    ]);

    /// The encoding `RatchetStateV1` (module documentation), in one zeroizing buffer.
    ///
    /// # Errors
    /// [`Error::Rejected`] only if `skipped` exceeds its bound (never for a state built by this module).
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.skipped.len() > MAX_SKIPPED {
            return Err(Error::Rejected);
        }
        let mut w = Writer::with_capacity(Self::MAX_ENCODED_LEN);
        w.u8(FORMAT_V1);
        w.bytes(&self.sb);
        w.bytes(self.rk.expose_secret());
        w.bytes(self.dh_s.sk.expose_secret());
        write_opt(&mut w, self.dh_r.as_ref().map(|k| k.as_bytes().as_slice()));
        w.bytes(self.kem_s.dk.expose_seed());
        write_opt(&mut w, self.kem_r.as_ref().map(|k| k.as_bytes().as_slice()));
        write_opt(
            &mut w,
            self.last_ct_r.as_ref().map(|c| c.as_bytes().as_slice()),
        );
        write_opt(&mut w, self.ct_s.as_ref().map(|c| c.as_bytes().as_slice()));
        for key in [
            &self.ck_s,
            &self.ck_r,
            &self.hk_s,
            &self.hk_r,
            &self.nhk_s,
            &self.nhk_r,
        ] {
            write_opt(&mut w, key.as_ref().map(|k| k.expose_secret().as_slice()));
        }
        w.u32(self.n_s);
        w.u32(self.n_r);
        w.u32(self.pn);
        w.u16(u16::try_from(self.skipped.len()).map_err(|_| Error::Rejected)?);
        for e in &self.skipped {
            w.bytes(e.hk.expose_secret());
            w.u32(e.n);
            w.bytes(e.mk.expose_secret());
        }
        Ok(w.into_bytes())
    }

    /// Decode `RatchetStateV1` (module documentation): total, canonical, reachable shapes only.
    ///
    /// # Errors
    /// [`Error::Rejected`] for any malformed or unreachable encoding; [`Error::Unavailable`] if locked memory for
    /// `dh_s` or `kem_s` is unavailable.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.expect(FORMAT_V1)?;
        let sb: [u8; HASH_LEN] = r.array()?;
        let rk = secret32(r.take(32)?)?;
        let dh_s_bytes = r.take(32)?;
        let dh_r = read_opt(&mut r, X25519_PK_LEN)?
            .map(X25519Pk::from_bytes)
            .transpose()?;
        let kem_seed = r.take(SEED_LEN)?;
        let kem_r = read_opt(&mut r, MLKEM768_EK_LEN)?
            .map(MlKem768Ek::from_bytes)
            .transpose()?;
        let last_ct_r = read_opt(&mut r, MLKEM768_CT_LEN)?
            .map(MlKem768Ct::from_bytes)
            .transpose()?;
        let send_ct = read_opt(&mut r, MLKEM768_CT_LEN)?
            .map(MlKem768Ct::from_bytes)
            .transpose()?;
        let ck_s = opt_secret(read_opt(&mut r, 32)?)?;
        let ck_r = opt_secret(read_opt(&mut r, 32)?)?;
        let hk_s = opt_secret(read_opt(&mut r, 32)?)?;
        let hk_r = opt_secret(read_opt(&mut r, 32)?)?;
        let nhk_s = opt_secret(read_opt(&mut r, 32)?)?;
        let nhk_r = opt_secret(read_opt(&mut r, 32)?)?;
        let n_s = r.u32()?;
        let n_r = r.u32()?;
        let pn = r.u32()?;
        let count = usize::from(r.u16()?);
        if count > MAX_SKIPPED {
            return Err(Error::Rejected);
        }
        let mut skipped = VecDeque::with_capacity(count);
        for _ in 0..count {
            skipped.push_back(SkippedKey {
                hk: secret32(r.take(32)?)?,
                n: r.u32()?,
                mk: secret32(r.take(32)?)?,
            });
        }
        r.finish()?;
        // the shape of a reachable state (§7.2 init, §7.4 DHRatchet)
        let sending = [
            ck_s.is_some(),
            hk_s.is_some(),
            send_ct.is_some(),
            kem_r.is_some(),
            dh_r.is_some(),
        ];
        let receiving = [ck_r.is_some(), hk_r.is_some(), last_ct_r.is_some()];
        let has_sending = sending.iter().all(|b| *b);
        let has_receiving = receiving.iter().all(|b| *b);
        let shape_ok = nhk_s.is_some()
            && nhk_r.is_some()
            && (has_sending || sending.iter().all(|b| !*b))
            && (has_receiving || receiving.iter().all(|b| !*b))
            && (has_sending || !has_receiving)
            && (has_receiving || (n_r == 0 && pn == 0 && skipped.is_empty()))
            && (has_sending || n_s == 0);
        if !shape_ok
            || !skipped_is_canonical(&skipped)
            || !skipped_is_reachable(&skipped, hk_r.as_ref(), nhk_r.as_ref(), n_r)
        {
            return Err(Error::Rejected);
        }
        // locked memory last: a malformed encoding is rejected before any fallible allocation
        let dh_s = DhPair::new(X25519Secret::from_bytes(dh_s_bytes)?)?;
        let kem_s = KemPair::new(MlKem768Dk::from_seed(kem_seed)?)?;
        Ok(Self {
            sb,
            rk,
            dh_s,
            dh_r,
            kem_s,
            kem_r,
            last_ct_r,
            ct_s: send_ct,
            ck_s,
            ck_r,
            hk_s,
            hk_r,
            nhk_s,
            nhk_r,
            n_s,
            n_r,
            pn,
            skipped,
        })
    }
}

/// No skipped entry that cannot arise: `(hk_r, n)` is stored only for `n < n_r` (positions already passed on the
/// current receiving chain), and `nhk_r` never keys an entry (a chain's header key becomes `hk_r` only at a step,
/// and then the entries of the old chain carry the old `hk_r`). Keys are compared in constant time.
fn skipped_is_reachable(
    skipped: &VecDeque<SkippedKey>,
    hk_r: Option<&SecretBytes<32>>,
    nhk_r: Option<&SecretBytes<32>>,
    n_r: u32,
) -> bool {
    let mut bad = Choice::from(0);
    for e in skipped {
        if let Some(k) = hk_r {
            bad |= k.ct_eq(&e.hk) & Choice::from(u8::from(e.n >= n_r));
        }
        if let Some(k) = nhk_r {
            bad |= k.ct_eq(&e.hk);
        }
    }
    !bool::from(bad)
}

/// `skipped` as insertion can produce it: entries grouped by header key, `n` strictly increasing within a group, no
/// group's key in a later group (a chain's entries are inserted together and a chain's header key never returns).
/// Keys are compared in constant time.
fn skipped_is_canonical(skipped: &VecDeque<SkippedKey>) -> bool {
    let mut group_starts: Vec<&SkippedKey> = Vec::new();
    let mut previous: Option<&SkippedKey> = None;
    for e in skipped {
        let ok = match previous {
            Some(p) if bool::from(p.hk.ct_eq(&e.hk)) => e.n > p.n,
            _ => {
                let mut repeated = Choice::from(0);
                for g in &group_starts {
                    repeated |= g.hk.ct_eq(&e.hk);
                }
                group_starts.push(e);
                !bool::from(repeated)
            }
        };
        if !ok {
            return false;
        }
        previous = Some(e);
    }
    true
}
