// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! Canonicality property tests (docs/06 §4 "Property"; M2 acceptance "`decode(encode(x)) == x` and
//! `encode(decode(b)) == b` for all structures"), on generators built from `rand` (WEISUNG M2-1, ADR-040):
//!
//! 1. for random valid values `x` of every Appendix D structure: `decode(encode(x)) == x` (for the structures with
//!    secret fields, which have no `PartialEq`, and for those carrying a MAC, commitment, token or tag, which have it
//!    only in the crate's unit tests (M2 review F1), the equivalent `encode(decode(encode(x))) == encode(x)`: the
//!    encoding is injective);
//! 2. for random mutations `b′` of every such encoding (bit flips, byte overwrites, truncation, extension, byte
//!    insertion and deletion): whenever `decode(b′)` succeeds, `encode(decode(b′)) == b′` — no second encoding of
//!    any value is accepted;
//! 3. targeted edge values: every counter and length at its minimum and maximum, every enum variant.
//!
//! The generator is `StdRng` seeded from a master seed, so a failure is reproducible: the fixed [`DEFAULT_SEED`],
//! or the decimal `u64` in the environment variable `SECMP_PROPTEST_SEED` if it is set and not empty (M2 review
//! F10: the nightly run draws a fresh seed to explore across runs; an unparsable value fails the run). The seed in
//! use (as `SECMP_PROPTEST_SEED=<n>`, ready to re-run) and the case index are in every assertion message. No
//! shrinking: a failing case prints its structure, index and seed.

use std::num::NonZeroU16;

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

use secmp_crypto::{SecretBytes, Zeroizing};
use secmp_proto::keys::{Ed25519Pk, Ed25519Sig, HybridSig, MlKem768Ek, MlKem1024Ek, X25519Pk};
use secmp_proto::sizes::{
    BLOB_PART_LEN, CELL_LEN, CONT_DATA_LEN, CONTENT_BODY_MAX, HANDSHAKE_CELL_CT_LEN,
    HANDSHAKE_CHUNK_LEN, INNER_CT_CT_LEN, LINK_BLOB_CT_LEN, MLDSA65_PK_LEN, MLKEM768_CT_LEN,
    MLKEM1024_CT_LEN,
};
use secmp_proto::wire::Period;
use secmp_proto::wire::cell::{
    AppKind, AppMessage, BatchBody, Cell, Content, ContentBody, ControlBody, ControlCode, Fragment,
    FragmentPayload, HandshakeBody, HeaderV1, KeyChangeBody, ReceiptBody, ReceiptKind, RelayQueue,
    RouteDescriptor, RouteUpdateBody,
};
use secmp_proto::wire::frame::{
    Cellr, CellrContext, CellrError, Cont, ContIdx, ErrCode, FetchEntry, LinkGetMode, Request,
    RequestCmd, Response, ResponseCmd,
};
use secmp_proto::wire::hx::{HandshakeCell, HandshakeCellPlaintext, Inner, InnerCt, Outer};
use secmp_proto::wire::inv::{
    Direct, Host, IksPublic, InvitationV1, LinkBlob, LinkDataV1, Onion, PrekeyBundle, Profile,
    RelayRef,
};
use secmp_proto::wire::record::{Hello, Hs1, Hs2, RelayInfoRecord, RelayInfoV1};
use secmp_proto::{Decode, Encode};

/// Random values per structure (debug build; every value also gets `MUTATIONS` mutants).
const CASES: usize = 48;
/// Mutations per encoding.
const MUTATIONS: usize = 24;
/// The master seed when `SECMP_PROPTEST_SEED` is not set (a failure names the structure, the case index and the
/// seed).
const DEFAULT_SEED: u64 = 0x5ec3_2d00_0000_0002;

/// The one reader of `SECMP_PROPTEST_SEED` (M4 review R-93, TEST-SPEC-M5 X-07).
#[path = "common/seed.rs"]
mod seed;

/// The master seed of this run: `SECMP_PROPTEST_SEED` (decimal `u64`) if set and not empty, else [`DEFAULT_SEED`].
fn master_seed() -> u64 {
    seed::master_seed(DEFAULT_SEED)
}

/// Keys and signatures drawn once (key generation dominates the run time otherwise).
struct Pools {
    x25519: Vec<X25519Pk>,
    ed25519: Vec<Ed25519Pk>,
    sigs: Vec<Ed25519Sig>,
    hybrid: Vec<HybridSig>,
    ek768: Vec<MlKem768Ek>,
    ek1024: Vec<MlKem1024Ek>,
}

struct Gen {
    /// The master seed of the run (reported in every assertion message).
    seed: u64,
    rng: StdRng,
    pools: Pools,
    /// Mutants that decoded (and re-encoded to themselves): property 2 was exercised, not vacuous.
    accepted: usize,
}

impl Gen {
    /// The generator of one test: seeded with the master seed of the run XOR the test's own `stream`.
    fn new(stream: u64) -> Self {
        let seed = master_seed();
        let mut rng = StdRng::seed_from_u64(seed ^ stream);
        let bytes = |n: usize, rng: &mut StdRng| {
            let mut v = vec![0_u8; n];
            rng.fill(&mut v[..]);
            v
        };
        let mut x25519 = Vec::new();
        let mut ed25519 = Vec::new();
        let mut sigs = Vec::new();
        for _ in 0..8 {
            let sk = secmp_crypto::X25519Secret::from_bytes(&bytes(32, &mut rng)).unwrap();
            x25519.push(X25519Pk::from_bytes(sk.public_key().as_bytes()).unwrap());
            let ed = secmp_crypto::Ed25519SigningKey::from_seed(&bytes(32, &mut rng)).unwrap();
            ed25519.push(Ed25519Pk::from_bytes(ed.verifying_key().as_bytes()).unwrap());
            sigs.push(Ed25519Sig::from_bytes(&ed.sign(&bytes(20, &mut rng))).unwrap());
        }
        let mut hybrid = Vec::new();
        let mut ek768 = Vec::new();
        let mut ek1024 = Vec::new();
        for _ in 0..3 {
            let hs = secmp_crypto::HybridSigningKey::from_seeds(
                &bytes(32, &mut rng),
                &bytes(32, &mut rng),
            )
            .unwrap();
            let sig = hs
                .sign(secmp_crypto::Label::HxBundle, &bytes(40, &mut rng))
                .unwrap();
            hybrid.push(HybridSig::from_bytes(sig.as_bytes().as_slice()).unwrap());
            let dk = secmp_crypto::MlKem768Dk::from_seed(&bytes(64, &mut rng)).unwrap();
            ek768.push(MlKem768Ek::from_bytes(dk.encapsulation_key().as_bytes()).unwrap());
            let dk = secmp_crypto::MlKem1024Dk::from_seed(&bytes(64, &mut rng)).unwrap();
            ek1024.push(MlKem1024Ek::from_bytes(dk.encapsulation_key().as_bytes()).unwrap());
        }
        Self {
            seed,
            rng,
            pools: Pools {
                x25519,
                ed25519,
                sigs,
                hybrid,
                ek768,
                ek1024,
            },
            accepted: 0,
        }
    }

    /// `what case n (SECMP_PROPTEST_SEED=s)`: the prefix of every assertion message.
    fn at(&self, what: &str, case: usize) -> String {
        format!("{what} case {case} (SECMP_PROPTEST_SEED={})", self.seed)
    }

    fn pick<T: Clone>(&mut self, pool: fn(&Pools) -> &Vec<T>) -> T {
        let v = pool(&self.pools);
        v.get(self.rng.random_range(0..v.len())).cloned().unwrap()
    }

    /// One element of `options`.
    fn one_of<T: Copy>(&mut self, options: &[T]) -> T {
        *options
            .get(self.rng.random_range(0..options.len()))
            .unwrap()
    }

    fn x25519(&mut self) -> X25519Pk {
        self.pick(|p| &p.x25519)
    }
    fn ed25519(&mut self) -> Ed25519Pk {
        self.pick(|p| &p.ed25519)
    }
    fn sig(&mut self) -> Ed25519Sig {
        self.pick(|p| &p.sigs)
    }
    fn hybrid(&mut self) -> HybridSig {
        self.pick(|p| &p.hybrid)
    }
    fn ek768(&mut self) -> MlKem768Ek {
        self.pick(|p| &p.ek768)
    }
    fn ek1024(&mut self) -> MlKem1024Ek {
        self.pick(|p| &p.ek1024)
    }

    fn arr<const N: usize>(&mut self) -> [u8; N] {
        let mut a = [0_u8; N];
        self.rng.fill(&mut a[..]);
        a
    }

    fn boxed<const N: usize>(&mut self) -> Box<[u8; N]> {
        self.bytes(N).into_boxed_slice().try_into().unwrap()
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0_u8; n];
        self.rng.fill(&mut v[..]);
        v
    }

    /// A length in `0..=max`, a quarter of the time one of the edges `min`, `max`.
    fn len(&mut self, min: usize, max: usize) -> usize {
        match self.rng.random_range(0..8) {
            0 => min,
            1 => max,
            _ => self.rng.random_range(min..=max),
        }
    }

    /// An integer, a quarter of the time 0 or the maximum.
    fn u32(&mut self) -> u32 {
        match self.rng.random_range(0..8) {
            0 => 0,
            1 => u32::MAX,
            _ => self.rng.random(),
        }
    }
    fn u64(&mut self) -> u64 {
        match self.rng.random_range(0..8) {
            0 => 0,
            1 => u64::MAX,
            _ => self.rng.random(),
        }
    }

    fn secret(&mut self) -> SecretBytes<32> {
        SecretBytes::from_slice(&self.arr::<32>()).unwrap()
    }

    fn period(&mut self) -> Period {
        self.one_of(&Period::ALL)
    }

    fn cell(&mut self) -> Cell {
        Cell::from_bytes(&self.bytes(CELL_LEN)).unwrap()
    }

    /// A printable host of 1..=253 bytes.
    fn host(&mut self) -> Host {
        let n = self.len(1, 253);
        let h: Vec<u8> = (0..n)
            .map(|_| self.rng.random_range(0x21_u8..=0x7e))
            .collect();
        Host::from_bytes(&h).unwrap()
    }

    fn relay_ref(&mut self) -> RelayRef {
        let direct = self.rng.random_bool(0.5).then(|| Direct {
            host: self.host(),
            port: NonZeroU16::new(self.rng.random_range(1..=u16::MAX)).unwrap(),
            spki_sha256: self.arr(),
        });
        RelayRef {
            relay_fp: self.arr(),
            onion: Onion::from_pubkey(&self.arr()),
            akc: self.arr(),
            direct,
        }
    }

    /// A UTF-8 name of at most 64 bytes, mixing 1- to 4-byte characters.
    fn name(&mut self) -> String {
        const CHARS: [char; 8] = ['a', 'Z', '0', ' ', 'ë', 'Å', '李', '🙂'];
        let mut s = String::new();
        let target = self.len(0, 64);
        loop {
            let c = self.one_of(&CHARS);
            if s.len().saturating_add(c.len_utf8()) > target {
                break;
            }
            s.push(c);
        }
        s
    }

    fn profile(&mut self) -> Profile {
        let name = self.name();
        let avatar = self.rng.random_bool(0.5).then(|| self.arr());
        Profile::new(&name, avatar).unwrap()
    }

    fn iks(&mut self) -> IksPublic {
        IksPublic {
            ik_ed25519: self.ed25519(),
            ik_mldsa65: self.boxed::<MLDSA65_PK_LEN>(),
            ik_dh: self.x25519(),
        }
    }

    fn bundle(&mut self) -> PrekeyBundle {
        PrekeyBundle {
            spk_id: self.u32(),
            spk_dh: self.x25519(),
            spk_kem: self.ek1024(),
            rpk_kem: self.ek768(),
            spk_expiry: self.u64(),
            opk_id: self.u32(),
            opk_dh: self.x25519(),
            opk_kem: self.ek1024(),
            sig: self.hybrid(),
        }
    }

    fn app_message(&mut self, max_payload: usize) -> AppMessage {
        let n = self.len(0, max_payload);
        AppMessage {
            msg_id: self.arr(),
            kind: self.one_of(&AppKind::ALL),
            expire_after: self.u32(),
            payload: Zeroizing::new(self.bytes(n)),
        }
    }

    fn relay_queue(&mut self) -> RelayQueue {
        RelayQueue {
            relay: self.relay_ref(),
            sid: self.arr(),
            send_seed: self.secret(),
            period_s: self.period(),
        }
    }

    fn route(&mut self, max_blob: usize) -> RouteDescriptor {
        if self.rng.random_bool(0.6) {
            RouteDescriptor::RelayQueue(self.relay_queue())
        } else {
            let kind = loop {
                let k: u8 = self.rng.random();
                if k != 0x01 {
                    break k;
                }
            };
            let n = self.len(0, max_blob);
            RouteDescriptor::Unknown {
                kind,
                blob: Zeroizing::new(self.bytes(n)),
            }
        }
    }

    fn routes(&mut self, max: usize, max_blob: usize) -> Vec<RouteDescriptor> {
        let n = self.len(1, max);
        (0..n).map(|_| self.route(max_blob)).collect()
    }

    fn receipt(&mut self, max: usize) -> ReceiptBody {
        let n = self.len(1, max);
        ReceiptBody {
            kind: if self.rng.random_bool(0.5) {
                ReceiptKind::Delivered
            } else {
                ReceiptKind::Read
            },
            msg_ids: (0..n).map(|_| self.arr()).collect(),
        }
    }

    fn control(&mut self, max_arg: usize) -> ControlBody {
        let n = self.len(0, max_arg);
        ControlBody {
            code: if self.rng.random_bool(0.5) {
                ControlCode::ContactRemoved
            } else {
                ControlCode::SessionResetRequest
            },
            arg: Zeroizing::new(self.bytes(n)),
        }
    }

    fn fragment(&mut self, max_chunk: usize) -> Fragment {
        let total: u16 = match self.rng.random_range(0..4) {
            0 => 2,
            1 => 64,
            _ => self.rng.random_range(2..=64),
        };
        let idx = if self.rng.random_bool(0.3) {
            total.saturating_sub(1)
        } else {
            self.rng.random_range(0..total)
        };
        let n = self.len(1, max_chunk);
        Fragment {
            msg_id: self.arr(),
            idx,
            total,
            chunk: Zeroizing::new(self.bytes(n)),
        }
    }

    /// A `ContentBody` whose encoding fits the 1689-byte limit (a body that happens not to fit is redrawn).
    fn content_body(&mut self) -> ContentBody {
        loop {
            let body = match self.rng.random_range(0..7) {
                0 => ContentBody::Dummy,
                1 => ContentBody::Handshake(HandshakeBody {
                    profile: self.profile(),
                    routes: self.routes(3, 64),
                }),
                2 => {
                    let n = self.len(1, 4);
                    ContentBody::Batch(BatchBody {
                        messages: (0..n).map(|_| self.app_message(300)).collect(),
                    })
                }
                3 => ContentBody::Fragment(self.fragment(CONTENT_BODY_MAX - 20)),
                4 => ContentBody::RouteUpdate(RouteUpdateBody {
                    routes: self.routes(4, 64),
                }),
                5 => ContentBody::Receipt(self.receipt(105)),
                _ => ContentBody::Control(self.control(CONTENT_BODY_MAX - 3)),
            };
            let probe = Content {
                seq: 0,
                ts: 0,
                body,
            };
            if probe.encode().is_ok() {
                return probe.body;
            }
        }
    }

    fn request(&mut self) -> Request {
        let cmd = match self.rng.random_range(0..10) {
            0 => RequestCmd::QueueNew {
                recv_pk: self.ed25519(),
                send_pk: self.ed25519(),
                token: self.arr(),
                sig: self.sig(),
            },
            1 => RequestCmd::Send {
                sid: self.arr(),
                cell: self.cell(),
                sig: self.sig(),
            },
            2 => RequestCmd::Fetch {
                rid: self.arr(),
                ack: self.u64(),
                sig: self.sig(),
            },
            3 => {
                let n = self.len(1, 32);
                RequestCmd::FetchMulti {
                    entries: (0..n)
                        .map(|_| FetchEntry {
                            rid: self.arr(),
                            ack: self.u64(),
                            sig: self.sig(),
                        })
                        .collect(),
                }
            }
            4 => RequestCmd::QueueDel {
                rid: self.arr(),
                sig: self.sig(),
            },
            5 => RequestCmd::LinkPut {
                ld_id: self.arr(),
                one_time: self.rng.random_bool(0.5),
                expires_bucket: self.u32(),
                owner_pk: self.ed25519(),
                token: self.arr(),
                sig: self.sig(),
                blob_part: self.boxed::<BLOB_PART_LEN>().into(),
            },
            6 => RequestCmd::LinkGet {
                ld_id: self.arr(),
                mode: if self.rng.random_bool(0.5) {
                    LinkGetMode::Consume
                } else {
                    LinkGetMode::OwnerStatus(self.sig())
                },
            },
            7 => RequestCmd::Ping,
            _ => RequestCmd::Cont(self.cont()),
        };
        Request {
            cmd_seq: self.u32(),
            cmd,
        }
    }

    fn cont(&mut self) -> Cont {
        Cont {
            idx: if self.rng.random_bool(0.5) {
                ContIdx::One
            } else {
                ContIdx::Two
            },
            data: self.boxed::<CONT_DATA_LEN>(),
        }
    }

    fn response(&mut self) -> (Response, CellrContext) {
        let ctx = if self.rng.random_bool(0.5) {
            CellrContext::Fetch
        } else {
            CellrContext::FetchMulti
        };
        let cmd = match self.rng.random_range(0..7) {
            0 => ResponseCmd::Ok,
            1 => ResponseCmd::OkQueueNew {
                rid: self.arr(),
                sid: self.arr(),
            },
            2 => ResponseCmd::OkSend {
                cell_id: self.u64(),
                evicted: self.rng.random_bool(0.5).then(|| self.u64()),
            },
            3 => ResponseCmd::Cellr(match self.rng.random_range(0..3) {
                0 => Cellr::Dummy { cell: self.cell() },
                1 => Cellr::Cell {
                    rid: if ctx == CellrContext::Fetch {
                        [0; 16]
                    } else {
                        self.arr()
                    },
                    cell_id: self.u64(),
                    cell: self.cell(),
                },
                _ => Cellr::Error {
                    error: self.one_of(&[
                        CellrError::NoQueue,
                        CellrError::Auth,
                        CellrError::Malformed,
                    ]),
                    rid: self.arr(),
                    cell: self.cell(),
                },
            }),
            4 => ResponseCmd::LinkR {
                present: self.rng.random_bool(0.5),
                consumed: self.rng.random_bool(0.5),
                blob_part: self.boxed::<BLOB_PART_LEN>().into(),
            },
            5 => ResponseCmd::Err(self.one_of(&ErrCode::ALL)),
            _ => ResponseCmd::Cont(self.cont()),
        };
        (
            Response {
                cmd_seq: self.u32(),
                cmd,
            },
            ctx,
        )
    }

    /// A mutation of `b`: bit flip, byte overwrite, truncation, extension, insertion or deletion.
    fn mutate(&mut self, b: &[u8]) -> Vec<u8> {
        let mut m = b.to_vec();
        let at = if m.is_empty() {
            0
        } else {
            self.rng.random_range(0..m.len())
        };
        let bit = 1_u8.checked_shl(self.rng.random_range(0..8)).unwrap_or(1);
        let byte: u8 = self.rng.random();
        match self.rng.random_range(0..6) {
            0 if !m.is_empty() => {
                if let Some(x) = m.get_mut(at) {
                    *x ^= bit;
                }
            }
            1 if !m.is_empty() => {
                if let Some(x) = m.get_mut(at) {
                    *x = byte;
                }
            }
            2 => m.truncate(at),
            3 => m.push(self.rng.random()),
            4 => m.insert(at, self.rng.random()),
            _ if !m.is_empty() => {
                m.remove(at);
            }
            _ => m.push(0),
        }
        m
    }
}

/// Property 2 on the mutants of `bytes`: any mutant `decode` accepts must re-encode to itself.
fn mutants_are_canonical(
    g: &mut Gen,
    what: &str,
    case: usize,
    bytes: &[u8],
    again: impl Fn(&[u8]) -> Option<Vec<u8>>,
) {
    for m in 0..MUTATIONS {
        let b = g.mutate(bytes);
        if let Some(back) = again(&b) {
            assert_eq!(
                back,
                b,
                "{} mutant {m}: a second encoding was accepted",
                g.at(what, case)
            );
            g.accepted = g.accepted.saturating_add(1);
        }
    }
}

/// Property 2 was exercised: some mutants of this test's encodings were accepted and re-encoded to themselves.
fn exercised(g: &Gen, what: &str) {
    assert!(
        g.accepted > 0,
        "{what}: no mutant was ever accepted (SECMP_PROPTEST_SEED={})",
        g.seed
    );
}

/// Properties 1 and 2 for a structure with `PartialEq`.
fn check<T: Encode + Decode + PartialEq>(g: &mut Gen, what: &str, case: usize, x: &T) {
    let at = g.at(what, case);
    let bytes = x
        .encode()
        .map_err(|e| format!("{at}: encode: {e}"))
        .unwrap();
    let y = T::decode(&bytes)
        .map_err(|e| format!("{at}: decode: {e}"))
        .unwrap();
    assert!(y == *x, "{at}: decode(encode(x)) != x");
    assert_eq!(y.encode().unwrap(), bytes, "{at}");
    mutants_are_canonical(g, what, case, &bytes, |b| {
        T::decode(b).ok().map(|v| v.encode().unwrap().to_vec())
    });
}

/// Properties 1 and 2 for a structure without `PartialEq` (secret fields; MACs, commitments, tokens and tags —
/// M2 review F1): the encoding is injective, so `encode(decode(encode(x))) == encode(x)` is `decode(encode(x)) == x`.
fn check_bytes<T: Encode + Decode>(g: &mut Gen, what: &str, case: usize, x: &T) {
    let at = g.at(what, case);
    let bytes = x
        .encode()
        .map_err(|e| format!("{at}: encode: {e}"))
        .unwrap();
    let y = T::decode(&bytes)
        .map_err(|e| format!("{at}: decode: {e}"))
        .unwrap();
    assert_eq!(y.encode().unwrap(), bytes, "{at}");
    mutants_are_canonical(g, what, case, &bytes, |b| {
        T::decode(b).ok().map(|v| v.encode().unwrap().to_vec())
    });
}

#[test]
fn records() {
    let mut g = Gen::new(0);
    for case in 0..CASES {
        check(&mut g, "Hello", case, &Hello);
        let info = RelayInfoV1 {
            relay_sig_pk: g.ed25519(),
            kid: g.u32(),
            relay_dh_pk: g.x25519(),
            relay_kem_ek: g.ek1024(),
            akc: g.arr(),
            valid_until: g.u64(),
            sig: g.sig(),
        };
        check(&mut g, "RelayInfoV1", case, &info);
        check(
            &mut g,
            "RelayInfoRecord",
            case,
            &RelayInfoRecord { relay_info: info },
        );
        let hs1 = Hs1 {
            kid: g.u32(),
            e_c: g.x25519(),
            ek_c: g.ek768(),
            pk_e1: g.x25519(),
            ct_kem: g.boxed::<MLKEM1024_CT_LEN>(),
            mac1: g.arr(),
        };
        check_bytes(&mut g, "Hs1", case, &hs1);
        let hs2 = Hs2 {
            e_r: g.x25519(),
            ct_c: g.boxed::<MLKEM768_CT_LEN>(),
            mac2: g.arr(),
        };
        check_bytes(&mut g, "Hs2", case, &hs2);
    }
    exercised(&g, "records");
}

#[test]
fn frames() {
    let mut g = Gen::new(1);
    for case in 0..(CASES * 4) {
        let req = g.request();
        check_bytes(&mut g, "Request", case, &req);
        let (resp, ctx) = g.response();
        let at = g.at("Response", case);
        let bytes = resp.encode().unwrap();
        let back = Response::decode(&bytes, ctx)
            .map_err(|e| format!("{at}: {e}"))
            .unwrap();
        // no `PartialEq` outside unit tests (F1): the encoding is injective
        assert_eq!(back.encode().unwrap(), bytes, "{at}");
        mutants_are_canonical(&mut g, "Response", case, &bytes, |b| {
            Response::decode(b, ctx)
                .ok()
                .map(|v| v.encode().unwrap().to_vec())
        });
    }
    exercised(&g, "frames");
}

#[test]
fn invitation_and_link_data() {
    let mut g = Gen::new(2);
    for case in 0..CASES {
        let r = g.relay_ref();
        check(&mut g, "RelayRef", case, &r);
        let inv = InvitationV1 {
            relay: g.relay_ref(),
            ld_id: g.arr(),
            link_key: g.secret(),
            inviter_fp: g.arr(),
            inv_sid: g.arr(),
            inv_send_seed: g.secret(),
            inv_period_s: g.period(),
            expires: g.u64(),
        };
        check_bytes(&mut g, "InvitationV1", case, &inv);
        let p = g.profile();
        check(&mut g, "Profile", case, &p);
        let iks = g.iks();
        check(&mut g, "IKSPublic", case, &iks);
        let bundle = g.bundle();
        check(&mut g, "PrekeyBundle", case, &bundle);
        let ld = LinkDataV1 {
            inviter_iks: g.iks(),
            bundle: g.bundle(),
            profile: g.profile(),
            created: g.u64(),
        };
        check(&mut g, "LinkDataV1", case, &ld);
        let blob = LinkBlob {
            n: g.arr(),
            com: g.arr(),
            ct: g.boxed::<LINK_BLOB_CT_LEN>(),
        };
        check_bytes(&mut g, "LinkBlob", case, &blob);
    }
    exercised(&g, "invitation and link data");
}

#[test]
fn handshake_envelope() {
    let mut g = Gen::new(3);
    for case in 0..CASES {
        let inner_ct = InnerCt {
            n2: g.arr(),
            com: g.arr(),
            ct: g.boxed::<INNER_CT_CT_LEN>(),
        };
        check_bytes(&mut g, "inner_ct", case, &inner_ct);
        let outer = Outer {
            ek_i: g.x25519(),
            spk_id: g.u32(),
            opk_id: g.u32(),
            ct_spk: g.boxed::<MLKEM1024_CT_LEN>(),
            ct_opk: g.boxed::<MLKEM1024_CT_LEN>(),
            inner_ct,
        };
        check_bytes(&mut g, "Outer", case, &outer);
        let inner = Inner {
            iks: g.iks(),
            first_msg: g.cell(),
        };
        check_bytes(&mut g, "Inner", case, &inner);
        let hc = HandshakeCell {
            n: g.arr(),
            com: g.arr(),
            ct: g.boxed::<HANDSHAKE_CELL_CT_LEN>(),
        };
        check_bytes(&mut g, "HandshakeCell", case, &hc);
        let pt = HandshakeCellPlaintext {
            init_id: g.arr(),
            i: g.rng.random_range(0..3),
            chunk: g.boxed::<HANDSHAKE_CHUNK_LEN>(),
        };
        check(&mut g, "HandshakeCellPlaintext", case, &pt);
    }
    exercised(&g, "handshake envelope");
}

#[test]
fn ratchet_cell_content_and_bodies() {
    let mut g = Gen::new(4);
    for case in 0..CASES {
        let cell = g.cell();
        check_bytes(&mut g, "Cell", case, &cell);
        let header = HeaderV1 {
            dh_pk: g.x25519(),
            pn: g.u32(),
            n: g.u32(),
            ek_pq: g.ek768(),
            ct_pq: g.boxed::<MLKEM768_CT_LEN>(),
        };
        check(&mut g, "HeaderV1", case, &header);
        for _ in 0..4 {
            let content = Content {
                seq: g.u64(),
                ts: g.u64(),
                body: g.content_body(),
            };
            check_bytes(&mut g, "Content", case, &content);
        }
        let message = g.app_message(2_000);
        check_bytes(&mut g, "AppMessage", case, &message);
        let count = g.len(1, 6);
        let batch = BatchBody {
            messages: (0..count).map(|_| g.app_message(400)).collect(),
        };
        check_bytes(&mut g, "BatchBody", case, &batch);
        let fragment = g.fragment(3_000);
        check_bytes(&mut g, "Fragment", case, &fragment);
        let rd = g.route(3_000);
        check_bytes(&mut g, "RouteDescriptor", case, &rd);
        let rq = g.relay_queue();
        check_bytes(&mut g, "RelayQueue", case, &rq);
        let ru = RouteUpdateBody {
            routes: g.routes(6, 300),
        };
        check_bytes(&mut g, "RouteUpdateBody", case, &ru);
        let hb = HandshakeBody {
            profile: g.profile(),
            routes: g.routes(6, 300),
        };
        check_bytes(&mut g, "HandshakeBody", case, &hb);
        let kc = KeyChangeBody {
            iks: g.iks(),
            sig: g.hybrid(),
        };
        check(&mut g, "KeyChangeBody", case, &kc);
        let receipt = g.receipt(255);
        check(&mut g, "ReceiptBody", case, &receipt);
        let control = g.control(3_000);
        check_bytes(&mut g, "ControlBody", case, &control);
        let payload = match g.rng.random_range(0..5) {
            0 => FragmentPayload::Batch(batch),
            1 => FragmentPayload::RouteUpdate(ru),
            2 => FragmentPayload::KeyChange(kc),
            3 => FragmentPayload::Receipt(receipt),
            _ => FragmentPayload::Control(control),
        };
        check_bytes(&mut g, "FragmentPayload", case, &payload);
    }
    exercised(&g, "ratchet cell, content and bodies");
}

/// Property 3: counters at 0 and at their maxima round-trip exactly.
#[test]
fn edge_counters() {
    let mut g = Gen::new(5);
    for (seq, n) in [(0_u32, 0_u64), (u32::MAX, u64::MAX)] {
        for cmd in [
            RequestCmd::Fetch {
                rid: [0; 16],
                ack: n,
                sig: g.sig(),
            },
            RequestCmd::Ping,
        ] {
            check_bytes(&mut g, "Request edge", 0, &Request { cmd_seq: seq, cmd });
        }
        let header = HeaderV1 {
            dh_pk: g.x25519(),
            pn: seq,
            n: seq,
            ek_pq: g.ek768(),
            ct_pq: g.boxed::<MLKEM768_CT_LEN>(),
        };
        check(&mut g, "HeaderV1 edge", 0, &header);
        check_bytes(
            &mut g,
            "Content edge",
            0,
            &Content {
                seq: n,
                ts: n,
                body: ContentBody::Dummy,
            },
        );
    }
}

/// Property 3: lengths and counts at their maxima (and minima) round-trip exactly.
#[test]
fn edge_lengths() {
    let mut g = Gen::new(6);
    let max_payload = AppMessage {
        msg_id: [1; 16],
        kind: AppKind::AttachmentInline,
        expire_after: u32::MAX,
        payload: Zeroizing::new(vec![7; 65_535]),
    };
    assert_eq!(max_payload.encode().unwrap().len(), 65_558);
    check_bytes(&mut g, "AppMessage max", 0, &max_payload);
    check_bytes(
        &mut g,
        "ControlBody max",
        0,
        &ControlBody {
            code: ControlCode::ContactRemoved,
            arg: Zeroizing::new(vec![7; 65_535]),
        },
    );
    check_bytes(
        &mut g,
        "RouteDescriptor max",
        0,
        &RouteDescriptor::Unknown {
            kind: 0xff,
            blob: Zeroizing::new(vec![7; 65_535]),
        },
    );
    check(
        &mut g,
        "ReceiptBody max",
        0,
        &ReceiptBody {
            kind: ReceiptKind::Read,
            msg_ids: vec![[3; 16]; 255],
        },
    );
    check(
        &mut g,
        "Profile max",
        0,
        &Profile::new(&"🙂".repeat(16), Some([1; 32])).unwrap(),
    );
    check(&mut g, "Profile empty", 0, &Profile::new("", None).unwrap());
    let mut max_host = g.relay_ref();
    max_host.direct = Some(Direct {
        host: Host::from_bytes(&[b'h'; 253]).unwrap(),
        port: NonZeroU16::MAX,
        spki_sha256: [9; 32],
    });
    check(&mut g, "RelayRef max host", 0, &max_host);
    let full_fetch = Request {
        cmd_seq: 1,
        cmd: RequestCmd::FetchMulti {
            entries: (0..32)
                .map(|i| FetchEntry {
                    rid: [i; 16],
                    ack: u64::MAX,
                    sig: g.sig(),
                })
                .collect(),
        },
    };
    check_bytes(&mut g, "FETCH_MULTI 32", 0, &full_fetch);
    // the fullest Content body (1689 bytes) and the extreme fragment indices
    for (idx, total) in [(0_u16, 2_u16), (63, 64), (1, 2)] {
        let body = ContentBody::Fragment(Fragment {
            msg_id: [2; 16],
            idx,
            total,
            chunk: Zeroizing::new(vec![5; CONTENT_BODY_MAX - 20]),
        });
        check_bytes(
            &mut g,
            "Content with a 1689-byte body",
            usize::from(idx),
            &Content {
                seq: 1,
                ts: 2,
                body,
            },
        );
    }
}

/// Property 3: every enum variant round-trips exactly.
#[test]
fn edge_enum_variants() {
    let mut g = Gen::new(7);
    for p in Period::ALL {
        check(&mut g, "Period", 0, &p);
    }
    for kind in AppKind::ALL {
        check_bytes(
            &mut g,
            "AppKind",
            usize::from(kind.byte()),
            &AppMessage {
                msg_id: [0; 16],
                kind,
                expire_after: 0,
                payload: Zeroizing::new(vec![]),
            },
        );
    }
    for code in ErrCode::ALL {
        let resp = Response {
            cmd_seq: 0,
            cmd: ResponseCmd::Err(code),
        };
        let bytes = resp.encode().unwrap();
        let back = Response::decode(&bytes, CellrContext::Fetch).unwrap();
        assert_eq!(
            back.encode().unwrap(),
            bytes,
            "{}",
            g.at("ERR", usize::from(code.byte()))
        );
    }
    for error in [CellrError::NoQueue, CellrError::Auth, CellrError::Malformed] {
        let resp = Response {
            cmd_seq: 0,
            cmd: ResponseCmd::Cellr(Cellr::Error {
                error,
                rid: [4; 16],
                cell: g.cell(),
            }),
        };
        let bytes = resp.encode().unwrap();
        for ctx in [CellrContext::Fetch, CellrContext::FetchMulti] {
            let back = Response::decode(&bytes, ctx).unwrap();
            assert_eq!(back.encode().unwrap(), bytes, "{}", g.at("CELLR error", 0));
        }
    }
    for kind in [0x00_u8, 0x02, 0x03, 0x7e, 0xff] {
        check_bytes(
            &mut g,
            "RouteDescriptor kind",
            usize::from(kind),
            &RouteDescriptor::Unknown {
                kind,
                blob: Zeroizing::new(vec![]),
            },
        );
    }
}

/// Implemented twice for every `T: PartialEq` (`A = ()` and `A = HasPartialEq`), once for every other `T`: naming
/// `<T as AmbiguousIfPartialEq<_>>::check` compiles only if `T` has no `PartialEq` (the construction of
/// `static_assertions::assert_not_impl_any`).
trait AmbiguousIfPartialEq<A> {
    fn check() {}
}
impl<T: ?Sized> AmbiguousIfPartialEq<()> for T {}
struct HasPartialEq;
impl<T: ?Sized + PartialEq> AmbiguousIfPartialEq<HasPartialEq> for T {}

/// M2 review F1: the structures carrying a MAC (`Hs1.mac1`, `Hs2.mac2`), a CAEAD commitment (`LinkBlob`, `InnerCt`,
/// `HandshakeCell`), an access token (`RequestCmd`) or a tag (`Cell`), and those containing one, have no
/// `PartialEq` outside the crate's unit tests (`==` is variable-time); this test crate builds `secmp-proto` without
/// `cfg(test)`, so re-adding the derive fails to compile here. A structure without such fields keeps its `PartialEq`
/// (`HeaderV1`, the control).
#[test]
fn structures_with_macs_commitments_tokens_or_tags_have_no_partial_eq() {
    <Hs1 as AmbiguousIfPartialEq<_>>::check();
    <Hs2 as AmbiguousIfPartialEq<_>>::check();
    <RequestCmd as AmbiguousIfPartialEq<_>>::check();
    <Request as AmbiguousIfPartialEq<_>>::check();
    <Cellr as AmbiguousIfPartialEq<_>>::check();
    <ResponseCmd as AmbiguousIfPartialEq<_>>::check();
    <Response as AmbiguousIfPartialEq<_>>::check();
    <LinkBlob as AmbiguousIfPartialEq<_>>::check();
    <InnerCt as AmbiguousIfPartialEq<_>>::check();
    <Outer as AmbiguousIfPartialEq<_>>::check();
    <Inner as AmbiguousIfPartialEq<_>>::check();
    <HandshakeCell as AmbiguousIfPartialEq<_>>::check();
    <Cell as AmbiguousIfPartialEq<_>>::check();
    // M3 review F11: the content types that may carry secret bytes (a Fragment's chunk can hold a `send_seed`)
    <Fragment as AmbiguousIfPartialEq<_>>::check();
    <AppMessage as AmbiguousIfPartialEq<_>>::check();
    <BatchBody as AmbiguousIfPartialEq<_>>::check();
    <ControlBody as AmbiguousIfPartialEq<_>>::check();
    <HeaderV1 as AmbiguousIfPartialEq<HasPartialEq>>::check();
}
