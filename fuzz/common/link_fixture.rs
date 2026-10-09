// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The fixed SecMP-LINK handshake of the `link_*` fuzz targets (M5): a relay whose every secret comes from
//! `FixedEntropy`-style constant bytes (SHA-256 of a label and a counter), so its identity, `RELAYINFO`, the honest
//! `HS1` and `HS2` and the honest link are the same in every run and on every machine.
//!
//! The fixture also holds what the structured targets need to re-compose the parts of spec §8.3 that a mutated
//! record has to satisfy (`h0`, `mac1`, `h1`, `mac2`), built here from `secmp-crypto` primitives and not from the
//! library under test, so that a mutated but consistent record is accepted exactly when the library should accept it.

use std::sync::OnceLock;

use secmp_crypto::{
    Ed25519SigningKey, HybridKem768SecretKey, HybridKem1024SecretKey, Label, MlKem768Dk,
    MlKem1024Dk, SecretBytes, X25519Secret, hkdf_extract, hmac_sha256, sha256,
};
use secmp_proto::link::Link;
use secmp_proto::link::client::{self, AwaitHs2};
use secmp_proto::link::ids::{AccessKey, akc};
use secmp_proto::link::relay::{self, RelayKeys};
use secmp_proto::tr::FixedEntropy;

/// `now` of the client's checks.
pub const NOW: u64 = 1_700_000_100;
/// `valid_until` of the honest `RELAYINFO`.
pub const VALID_UNTIL: u64 = NOW + 1_000;
/// The `HELLO` record (D.1: `len` 7, type 1, `"SECMP"`, ver 1... the library encodes it; this is its encoding).
pub const HELLO: [u8; 9] = [0, 7, 1, b'S', b'E', b'C', b'M', b'P', 1];
/// The client's draws: `e_c_sk` 32, `ek_c_seed` 64, `sk_e1` 32, `m1` 32.
pub const CLIENT_DRAWS: usize = 160;
/// The relay's draws: `sk_er` 32, `m2` 32.
pub const RELAY_DRAWS: usize = 64;

/// Offsets inside a `RELAYINFO` record (D.1): `len` 2, type 1, then the body.
pub mod ri {
    pub const VER: usize = 3;
    pub const SIG_PK: usize = 4;
    pub const KID: usize = 36;
    pub const DH_PK: usize = 40;
    pub const KEM_EK: usize = 72;
    pub const KEM_EK_LEN: usize = 1568;
    pub const AKC: usize = 1640;
    pub const VALID_UNTIL: usize = 1672;
    pub const SIGNED_END: usize = 1680;
    pub const SIG: usize = 1680;
    pub const LEN: usize = 1744;
}

/// Offsets inside an `HS1` record (2856 B).
pub mod h1 {
    pub const VER: usize = 3;
    pub const KID: usize = 4;
    pub const E_C: usize = 8;
    pub const EK_C: usize = 40;
    pub const EK_C_LEN: usize = 1184;
    pub const PK_E1: usize = 1224;
    pub const CT_KEM: usize = 1256;
    pub const CT_KEM_LEN: usize = 1568;
    pub const MAC1: usize = 2824;
    pub const LEN: usize = 2856;
}

/// Offsets inside an `HS2` record (1156 B).
pub mod h2 {
    pub const VER: usize = 3;
    pub const E_R: usize = 4;
    pub const CT_C: usize = 36;
    pub const CT_C_LEN: usize = 1088;
    pub const MAC2: usize = 1124;
    pub const LEN: usize = 1156;
}

pub struct Fixture {
    pub relay_keys: RelayKeys,
    pub sig_seed: Vec<u8>,
    pub access_bytes: [u8; 32],
    pub fp: [u8; 32],
    pub akc: [u8; 32],
    /// `kid` of the honest generation.
    pub kid: u32,
    pub sig_pk: Vec<u8>,
    pub dh_pk: Vec<u8>,
    pub kem_ek: Vec<u8>,
    /// The relay's static `HybridKEM-1024` secret (a second copy of the one inside `relay_keys`).
    pub relay_kem: HybridKem1024SecretKey,
    /// The honest `RELAYINFO` record (valid until [`VALID_UNTIL`]).
    pub relay_info: Vec<u8>,
    pub client_draws: Vec<u8>,
    pub relay_draws: Vec<u8>,
    /// The honest `HS1` of the client (draws `client_draws`) and the honest `HS2` of the relay (draws `relay_draws`).
    pub hs1: Vec<u8>,
    pub hs2: Vec<u8>,
}

fn constant(label: &str, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut i = 0_u32;
    while out.len() < n {
        out.extend_from_slice(&sha256(&[label.as_bytes(), &i.to_be_bytes()]));
        i = i.checked_add(1).unwrap();
    }
    out.truncate(n);
    out
}

impl Fixture {
    pub fn get() -> &'static Self {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(Self::build)
    }

    fn build() -> Self {
        let sig_seed = constant("link-fuzz relay sig", 32);
        let dh_sk = constant("link-fuzz relay dh", 32);
        let kem_seed = constant("link-fuzz relay kem", 64);
        let access_bytes: [u8; 32] = constant("link-fuzz access key", 32).try_into().unwrap();
        let kid = 1;
        let make = || {
            RelayKeys::new(
                Ed25519SigningKey::from_seed(&sig_seed).unwrap(),
                X25519Secret::from_bytes(&dh_sk).unwrap(),
                MlKem1024Dk::from_seed(&kem_seed).unwrap(),
                SecretBytes::from_slice(&access_bytes).unwrap(),
                kid,
            )
            .unwrap()
        };
        let relay_keys = make();
        let relay_kem = HybridKem1024SecretKey::from_parts(
            X25519Secret::from_bytes(&dh_sk).unwrap(),
            MlKem1024Dk::from_seed(&kem_seed).unwrap(),
        );
        let relay_info = relay_keys.relay_info_record(VALID_UNTIL).unwrap();
        let access: AccessKey = SecretBytes::from_slice(&access_bytes).unwrap();
        let mut fx = Self {
            fp: relay_keys.fp(),
            akc: akc(&access),
            kid,
            sig_pk: relay_info[ri::SIG_PK..ri::KID].to_vec(),
            dh_pk: relay_info[ri::DH_PK..ri::KEM_EK].to_vec(),
            kem_ek: relay_info[ri::KEM_EK..ri::AKC].to_vec(),
            relay_kem,
            relay_info,
            client_draws: constant("link-fuzz client draws", CLIENT_DRAWS),
            relay_draws: constant("link-fuzz relay draws", RELAY_DRAWS),
            hs1: Vec::new(),
            hs2: Vec::new(),
            relay_keys,
            sig_seed,
            access_bytes,
        };
        let (hs1, _) = fx
            .client(true)
            .on_relayinfo(&fx.relay_info, &mut fx.client_entropy())
            .unwrap();
        let (_, st) = relay::accept(&fx.relay_keys)
            .on_hello(&HELLO, VALID_UNTIL)
            .unwrap();
        let (hs2, _) = st.on_hs1(&hs1, &mut fx.relay_entropy()).unwrap();
        fx.hs1 = hs1;
        fx.hs2 = hs2;
        fx
    }

    pub fn access(&self) -> AccessKey {
        SecretBytes::from_slice(&self.access_bytes).unwrap()
    }

    pub fn client_entropy(&self) -> FixedEntropy {
        FixedEntropy::new(&self.client_draws)
    }

    pub fn relay_entropy(&self) -> FixedEntropy {
        FixedEntropy::new(&self.relay_draws)
    }

    /// A client that has sent `HELLO`; it holds the access key if `with_access`.
    pub fn client(&self, with_access: bool) -> client::AwaitRelayInfo {
        let access = self.access();
        let (hello, st) = client::start(self.fp, with_access.then_some(&access), NOW).unwrap();
        assert_eq!(hello, HELLO);
        st
    }

    /// The client up to `HS2` on the honest `RELAYINFO`.
    pub fn client_awaiting_hs2(&self) -> AwaitHs2 {
        self.client(true)
            .on_relayinfo(&self.relay_info, &mut self.client_entropy())
            .unwrap()
            .1
    }

    /// The client's static `HybridKEM-768` secret, from its draws (`e_c_sk`, `ek_c_seed`).
    pub fn client_kem(&self) -> HybridKem768SecretKey {
        HybridKem768SecretKey::from_parts(
            X25519Secret::from_bytes(self.client_draws.get(..32).unwrap()).unwrap(),
            MlKem768Dk::from_seed(self.client_draws.get(32..96).unwrap()).unwrap(),
        )
    }

    /// `(sk_e1, m1)` of the client's draws.
    pub fn client_encaps_draws(&self) -> ([u8; 32], [u8; 32]) {
        (
            self.client_draws.get(96..128).unwrap().try_into().unwrap(),
            self.client_draws.get(128..160).unwrap().try_into().unwrap(),
        )
    }

    /// A relay session that has answered `HELLO`: the responder awaiting `HS1`.
    pub fn relay_awaiting_hs1(&self) -> relay::AwaitHs1<'_> {
        relay::accept(&self.relay_keys)
            .on_hello(&HELLO, VALID_UNTIL)
            .unwrap()
            .1
    }

    /// The honest link: the client's and the relay's end.
    pub fn honest_links(&self) -> (Link, Link) {
        let client_link = self.client_awaiting_hs2().on_hs2(&self.hs2).unwrap();
        let (_, relay_link) = self
            .relay_awaiting_hs1()
            .on_hs1(&self.hs1, &mut self.relay_entropy())
            .unwrap();
        (client_link, relay_link)
    }

    /// `RELAYINFO`-style signature of the `fields = record[3..1680]` under `seed`, written into `record[1680..]`.
    pub fn sign_relay_info(record: &mut [u8], seed: &[u8]) {
        let signed = [
            Label::LinkRelayinfo.as_bytes(),
            record.get(ri::VER..ri::SIGNED_END).unwrap(),
        ]
        .concat();
        let sig = Ed25519SigningKey::from_seed(seed).unwrap().sign(&signed);
        record
            .get_mut(ri::SIG..ri::LEN)
            .unwrap()
            .copy_from_slice(&sig);
    }
}

/// `h0 = SHA-256("SecMP-LINK/1 h0" ‖ ver ‖ u32be(kid) ‖ relay_fp ‖ e_c ‖ SHA-256(ek_c) ‖ pk_e1 ‖ SHA-256(ct_kem))`
/// (spec §8.3).
pub fn h0_of(
    kid: u32,
    relay_fp: &[u8],
    e_c: &[u8],
    ek_c: &[u8],
    pk_e1: &[u8],
    ct_kem: &[u8],
) -> [u8; 32] {
    sha256(&[
        Label::LinkH0.as_bytes(),
        &[1],
        &kid.to_be_bytes(),
        relay_fp,
        e_c,
        &sha256(&[ek_c]),
        pk_e1,
        &sha256(&[ct_kem]),
    ])
}

/// `(ck1, mac1)` for `h0` and `ss1` (spec §8.3).
pub fn ck1_mac1(h0: &[u8; 32], ss1: &[u8]) -> (SecretBytes<32>, [u8; 32]) {
    let ck1 = hkdf_extract(h0, ss1).unwrap();
    let mac1 = hmac_sha256(ck1.expose_secret(), Label::LinkHs1, &[]).unwrap();
    (ck1, mac1)
}

/// `h1 = SHA-256(h0 ‖ mac1 ‖ e_r ‖ SHA-256(ct_c))`, `ck2 = HKDF-Extract(salt = h1, IKM = ck1 ‖ ss2)` and
/// `mac2 = HMAC-SHA-256(ck2, "SecMP-LINK/1 hs2")` (spec §8.3).
pub fn ck2_mac2(
    h0: &[u8; 32],
    mac1: &[u8; 32],
    ck1: &[u8; 32],
    e_r: &[u8],
    ct_c: &[u8],
    ss2: &[u8],
) -> (SecretBytes<32>, [u8; 32]) {
    let h1 = sha256(&[h0, mac1, e_r, &sha256(&[ct_c])]);
    let ck2 = hkdf_extract(&h1, &[ck1.as_slice(), ss2].concat()).unwrap();
    let mac2 = hmac_sha256(ck2.expose_secret(), Label::LinkHs2, &[]).unwrap();
    (ck2, mac2)
}

/// An `HS1` record with these fields (the 2856-byte layout of D.1); `ver` is written as given.
pub fn hs1_record(
    ver: u8,
    kid: u32,
    e_c: &[u8],
    ek_c: &[u8],
    pk_e1: &[u8],
    ct_kem: &[u8],
    mac1: &[u8],
) -> Vec<u8> {
    let body = [
        &[3, ver][..],
        &kid.to_be_bytes(),
        e_c,
        ek_c,
        pk_e1,
        ct_kem,
        mac1,
    ]
    .concat();
    let mut rec = u16::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    rec.extend_from_slice(&body);
    rec
}

/// `bytes` cut or zero-padded to `n`.
pub fn fit(bytes: &[u8], n: usize) -> Vec<u8> {
    let mut v = vec![0_u8; n];
    let k = bytes.len().min(n);
    v.get_mut(..k)
        .unwrap()
        .copy_from_slice(bytes.get(..k).unwrap());
    v
}

/// A cursor over the fuzzer's bytes: every read is zero-padded at the end of the input.
pub struct Bytes<'a>(pub &'a [u8]);

impl Bytes<'_> {
    pub fn take(&mut self, n: usize) -> Vec<u8> {
        let k = n.min(self.0.len());
        let (head, rest) = self.0.split_at(k);
        self.0 = rest;
        fit(head, n)
    }

    pub fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.take(2).try_into().unwrap())
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().unwrap())
    }

    pub fn arr32(&mut self) -> [u8; 32] {
        self.take(32).try_into().unwrap()
    }
}
