// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The fixed SecMP-TR session of the `tr_decrypt` fuzz target (M3 plan step 10), built deterministically: every
//! key and nonce comes from `FixedEntropy` over constant bytes (SHA-256 of a label and a counter), so the receiver's
//! state, the honest cells and the header keys are the same in every run and on every machine, and the tracked seed
//! corpus `fuzz/corpus/tr_decrypt/` (honest cells and headers of this session) stays valid.
//!
//! The session (A the §7.2 initiator, B the responder and the fuzzed receiver; Dummy contents):
//!
//! 1. A sends a0 … a3 on its first chain (header key `hk_A1`); B receives a0 (B's DH step) and a2 (skips n = 1).
//! 2. B sends b0; A receives it (A's DH step). A sends a'0 … a'2 on its second chain (`hk_A2`, `pn` = 4).
//! 3. B receives a'1: a DH step that skips n = 3 of the old chain and n = 0 of the new one.
//! 4. B sends b'0; A receives it (A's DH step) and sends a''0 on its third chain (`hk_A3`, `pn` = 3).
//!
//! B then has a current receiving chain (`hk_r` = `hk_A2`, `n_r` = 2), a next header key (`nhk_r` = `hk_A3`) and
//! three skipped keys under two distinct header keys: `(hk_A1, 1)`, `(hk_A1, 3)`, `(hk_A2, 0)`. The undelivered
//! honest cells a1, a3, a'0, a'2 and a''0 take every accepting path of spec §7.4 (skipped key on the old chain and
//! on the current one, the current chain, a DH step). The header modes of the target seal a header under one of
//! B's keys with the nonce and body of one of these cells ([`HEADER_MODES`]).

use std::sync::OnceLock;

use secmp_crypto::{
    Aead, ConstantTimeEq, Label, MlKem768Dk, Nonce24, SecretBytes, X25519Secret, Zeroizing, sha256,
};
use secmp_proto::Error;
use secmp_proto::keys::{MlKem768Ek, X25519Pk};
use secmp_proto::sizes::{HDR_CT_LEN, HEADER_LEN, NONCE_LEN};
use secmp_proto::tr::content::dummy;
use secmp_proto::tr::{FixedEntropy, RatchetState};

/// The randomness of a DH step's sending half (X25519 secret 32, ML-KEM-768 seed 64, `Encaps` 32): every decrypt
/// of the target gets this much, so a refusal is never `Unavailable`.
pub const STEP_RANDOMNESS: usize = 128;

/// The fixed session (module documentation).
pub struct Fixture {
    /// B's `RatchetStateV1`: every input starts from a fresh decoding of it.
    pub receiver: Zeroizing<Vec<u8>>,
    /// The undelivered honest cells a1, a3, a'0, a'2, a''0 (each accepted by B).
    pub cells: Vec<Vec<u8>>,
    /// Per header mode 1 …= 4 of `tr_decrypt`, the sealing key and the undelivered honest cell that lends its nonce
    /// and body: 1 `hk_r` with a'2 (the current chain, n = `n_r` = 2); 2 `nhk_r` with a''0 (a DH step); 3 `hk_r`
    /// with a'0 (the skipped entry `(hk_A2, 0)` of the current chain); 4 `hk_A1` with a1 (the skipped entry
    /// `(hk_A1, 1)` of the old chain).
    modes: Vec<(SecretBytes<32>, Vec<u8>)>,
    /// `AD = "SecMP-TR/1 hdr" ‖ sb` (spec §7.3).
    hdr_ad: Vec<u8>,
}

/// `n` constant bytes: `SHA-256(label ‖ i)` for i = 0, 1, …
fn constant(label: &str, n: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(n));
    let mut i = 0_u32;
    while out.len() < n {
        out.extend_from_slice(&sha256(&[label.as_bytes(), &i.to_be_bytes()]));
        i = i.checked_add(1).unwrap();
    }
    out.truncate(n);
    out
}

fn copy(key: &SecretBytes<32>) -> SecretBytes<32> {
    SecretBytes::from_slice(key.expose_secret()).unwrap()
}

/// Encrypt a Dummy; the new state was "persisted" (the cell is released).
fn send(state: RatchetState, entropy: &mut FixedEntropy) -> (RatchetState, Vec<u8>) {
    let (state, cell) = state
        .encrypt_with(&dummy(), entropy)
        .map_err(|r| r.error())
        .unwrap()
        .persist(|_| Ok::<(), Error>(()))
        .unwrap();
    (state, cell.as_bytes().to_vec())
}

/// Decrypt and commit.
fn recv(state: RatchetState, cell: &[u8], entropy: &mut FixedEntropy) -> RatchetState {
    state
        .decrypt_with(cell, entropy)
        .map_err(|r| r.error())
        .unwrap()
        .commit(|_| Ok::<(), Error>(()))
        .unwrap()
        .0
}

/// The cell's `hdr_nonce`, `hdr_ct` and body (spec §7.5).
fn parts(cell: &[u8]) -> (&[u8; NONCE_LEN], &[u8], &[u8]) {
    let (nonce, rest) = cell.split_first_chunk::<NONCE_LEN>().unwrap();
    let (hdr_ct, body) = rest.split_at(HDR_CT_LEN);
    (nonce, hdr_ct, body)
}

impl Fixture {
    /// Build the session (module documentation); checks that every undelivered cell is accepted by B.
    pub fn new() -> Self {
        let sk = SecretBytes::<32>::from_slice(&constant("tr-fuzz sk", 32)).unwrap();
        let sb: [u8; 32] = sha256(&[b"tr-fuzz sb"]);
        let spk = X25519Secret::from_bytes(&constant("tr-fuzz spk", 32)).unwrap();
        let rpk = MlKem768Dk::from_seed(&constant("tr-fuzz rpk", 64)).unwrap();
        let spk_pub = X25519Pk::from_bytes(spk.public_key().as_bytes()).unwrap();
        let rpk_ek = MlKem768Ek::from_bytes(rpk.encapsulation_key().as_bytes()).unwrap();
        let mut ea = FixedEntropy::new(&constant("tr-fuzz A", 1024));
        let mut eb = FixedEntropy::new(&constant("tr-fuzz B", 1024));
        let mut a =
            RatchetState::init_initiator_with(&sk, &sb, &spk_pub, &rpk_ek, &mut ea).unwrap();
        let mut b = RatchetState::init_responder(&sk, &sb, spk, rpk).unwrap();
        let hk_a1 = copy(a.hk_s_kat().unwrap());
        // 1. a0 … a3; B receives a0 (step) and a2 (skips n = 1)
        let mut first = Vec::new();
        for _ in 0..4 {
            let cell;
            (a, cell) = send(a, &mut ea);
            first.push(cell);
        }
        let [a0, a1, a2, a3] = <[Vec<u8>; 4]>::try_from(first).unwrap();
        b = recv(b, &a0, &mut eb);
        b = recv(b, &a2, &mut eb);
        // 2. b0 → A (step); a'0 … a'2
        let b0;
        (b, b0) = send(b, &mut eb);
        a = recv(a, &b0, &mut ea);
        let hk_a2 = copy(a.hk_s_kat().unwrap());
        let mut second = Vec::new();
        for _ in 0..3 {
            let cell;
            (a, cell) = send(a, &mut ea);
            second.push(cell);
        }
        let [a2_0, a2_1, a2_2] = <[Vec<u8>; 3]>::try_from(second).unwrap();
        // 3. B receives a'1 (step: skips (hk_A1, 3) and (hk_A2, 0))
        b = recv(b, &a2_1, &mut eb);
        // 4. b'0 → A (step); a''0
        let b1;
        (b, b1) = send(b, &mut eb);
        a = recv(a, &b1, &mut ea);
        let hk_a3 = copy(a.hk_s_kat().unwrap());
        let (_, a3_0) = send(a, &mut ea);

        let (hk_r, nhk_r) = b.receiving_header_keys_kat();
        assert!(bool::from(hk_r.unwrap().ct_eq(&hk_a2)));
        assert!(bool::from(nhk_r.unwrap().ct_eq(&hk_a3)));
        let hdr_ad = [Label::TrHdr.as_bytes(), sb.as_slice()].concat();
        let receiver = b.to_bytes().unwrap();
        let fixture = Self {
            receiver,
            cells: vec![a1.clone(), a3, a2_0.clone(), a2_2.clone(), a3_0.clone()],
            modes: vec![
                (copy(&hk_a2), a2_2),
                (hk_a3, a3_0),
                (hk_a2, a2_0),
                (hk_a1, a1),
            ],
            hdr_ad,
        };
        // every undelivered cell is accepted; every header mode re-seals its honest header to the honest cell
        for cell in &fixture.cells {
            let state = RatchetState::from_bytes(&fixture.receiver).unwrap();
            let mut entropy = FixedEntropy::new(&constant("tr-fuzz step", STEP_RANDOMNESS));
            assert!(state.decrypt_with(cell, &mut entropy).is_ok());
        }
        for (mode, (_, cell)) in (1..).zip(&fixture.modes) {
            assert_eq!(&fixture.sealed(mode, &fixture.honest_header(mode)), cell);
        }
        fixture
    }

    /// The fixture of this process (built on first use).
    pub fn get() -> &'static Self {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(Self::new)
    }

    /// Randomness for one decrypt (a DH step's sending half), the same for every input.
    pub fn step_entropy() -> FixedEntropy {
        FixedEntropy::new(&constant("tr-fuzz step", STEP_RANDOMNESS))
    }

    fn mode(&self, mode: usize) -> &(SecretBytes<32>, Vec<u8>) {
        self.modes.get(mode.checked_sub(1).unwrap()).unwrap()
    }

    /// The honest header plaintext of the cell of header mode `mode` (1 …= 4).
    pub fn honest_header(&self, mode: usize) -> Zeroizing<Vec<u8>> {
        let (key, cell) = self.mode(mode);
        let (nonce, hdr_ct, _) = parts(cell);
        Aead::open(key, nonce, &self.hdr_ad, hdr_ct).unwrap()
    }

    /// Header mode `mode` (1 …= 4): `header` zero-padded or cut to `HEADER_LEN`, sealed under the mode's key with
    /// the honest cell's nonce, followed by the honest cell's body (whose AD binds `hdr_nonce ‖ hdr_ct`, so the body
    /// MAC verifies only for the honest header).
    pub fn sealed(&self, mode: usize, header: &[u8]) -> Vec<u8> {
        let (key, cell) = self.mode(mode);
        let (nonce, _, body) = parts(cell);
        let mut plaintext = Zeroizing::new(vec![0_u8; HEADER_LEN]);
        for (dst, src) in plaintext.iter_mut().zip(header) {
            *dst = *src;
        }
        let hdr_ct = Aead::seal(
            key,
            Nonce24::from_bytes_kat(*nonce),
            &self.hdr_ad,
            &plaintext,
        )
        .unwrap();
        [nonce.as_slice(), &hdr_ct, body].concat()
    }
}
