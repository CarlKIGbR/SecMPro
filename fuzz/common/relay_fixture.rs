// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The fixed relay of the `relay_*` fuzz targets (M5 Phase B: FZ-07 `relay_executor`, FZ-08 `relay_link_session`):
//! a relay whose every secret comes from constant bytes (SHA-256 of a label and a counter, as
//! `common/link_fixture.rs`), the honest SecMP-LINK handshake with constant draws, the client keys of four queue
//! pairs and two link-data owners, and the request builders of D.2 signed honestly over the D.6 messages of
//! `secmp_proto::wire::signed` with the §9.6 token of `secmp_proto::link::ids`.
//!
//! Every input starts from a new, empty relay (`relay`) and a new link, so that an input's outcome does not depend
//! on the inputs before it.

use std::sync::OnceLock;

use secmp_crypto::{Ed25519SigningKey, MlKem1024Dk, SecretBytes, X25519Secret, sha256};
use secmp_proto::Encode;
use secmp_proto::codec::unpad;
use secmp_proto::keys::{Ed25519Pk, Ed25519Sig};
use secmp_proto::link::cont::split_blob;
use secmp_proto::link::ids::{self, AccessKey};
use secmp_proto::link::relay::RelayKeys;
use secmp_proto::link::{self, Link};
use secmp_proto::sizes::FRAME_PLAINTEXT_LEN;
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::Id;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::frame::{FetchEntry, LinkGetMode, Request, RequestCmd};
use secmp_proto::wire::signed::{self, LinkPutFields};
use secmp_relay::event::NullSink;
use secmp_relay::{Executor, KeyRing, Limits, Now, Relay};

/// The relay's wall clock (bucket 472 222).
pub const NOW: u64 = 1_700_000_100;
/// `valid_until` of the relay's key generation.
pub const VALID_UNTIL: u64 = NOW + 1_000_000;
/// The client's handshake draws: `e_c_sk` 32, `ek_c_seed` 64, `sk_e1` 32, `m1` 32.
pub const CLIENT_DRAWS: usize = 160;
/// The relay's handshake draws: `sk_er` 32, `m2` 32.
pub const RELAY_DRAWS: usize = 64;
/// The largest relay draw of one answer: eight random cells (`FETCH_MULTI`), or a dummy blob.
pub const ANSWER_DRAWS: usize = 8 * 4096;

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

/// An Ed25519 key of the client side.
pub struct Key {
    pub sk: Ed25519SigningKey,
    pub pk: Ed25519Pk,
}

impl Key {
    fn of(label: &str) -> Self {
        let sk = Ed25519SigningKey::from_seed(&constant(label, 32)).unwrap();
        let pk = Ed25519Pk::from_bytes(sk.verifying_key().as_bytes()).unwrap();
        Self { sk, pk }
    }

    pub fn sign(&self, msg: &[u8]) -> Ed25519Sig {
        Ed25519Sig::from_bytes(&self.sk.sign(msg)).unwrap()
    }
}

/// The constant secrets and keys.
pub struct Fixture {
    sig_seed: Vec<u8>,
    dh_sk: Vec<u8>,
    kem_seed: Vec<u8>,
    access: Vec<u8>,
    pub fp: [u8; 32],
    /// Four queue key pairs (recv, send).
    pub pairs: Vec<(Key, Key)>,
    /// Two link-data owners.
    pub owners: Vec<Key>,
    client_draws: Vec<u8>,
    relay_draws: Vec<u8>,
    answer_draws: Vec<u8>,
}

impl Fixture {
    pub fn get() -> &'static Self {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let mut fx = Self {
                sig_seed: constant("relay-fuzz relay sig", 32),
                dh_sk: constant("relay-fuzz relay dh", 32),
                kem_seed: constant("relay-fuzz relay kem", 64),
                access: constant("relay-fuzz access key", 32),
                fp: [0; 32],
                pairs: (0..4)
                    .map(|i| {
                        (
                            Key::of(&format!("relay-fuzz recv {i}")),
                            Key::of(&format!("relay-fuzz send {i}")),
                        )
                    })
                    .collect(),
                owners: (0..2)
                    .map(|i| Key::of(&format!("relay-fuzz owner {i}")))
                    .collect(),
                client_draws: constant("relay-fuzz client draws", CLIENT_DRAWS),
                relay_draws: constant("relay-fuzz relay draws", RELAY_DRAWS),
                answer_draws: constant("relay-fuzz answer draws", ANSWER_DRAWS),
            };
            fx.fp = fx.keys().fp();
            fx
        })
    }

    /// A fresh copy of the relay's keys (a `KeyRing` owns them).
    pub fn keys(&self) -> RelayKeys {
        RelayKeys::new(
            Ed25519SigningKey::from_seed(&self.sig_seed).unwrap(),
            X25519Secret::from_bytes(&self.dh_sk).unwrap(),
            MlKem1024Dk::from_seed(&self.kem_seed).unwrap(),
            self.access(),
            1,
        )
        .unwrap()
    }

    pub fn access(&self) -> AccessKey {
        SecretBytes::from_slice(&self.access).unwrap()
    }

    /// A new, empty relay with `limits` (kid 1, valid until [`VALID_UNTIL`]).
    pub fn relay(&self, limits: Limits) -> Relay {
        let ring = KeyRing::new(vec![(self.keys(), VALID_UNTIL)]).unwrap();
        Relay::new(ring, limits, Box::new(NullSink), at(0, 0))
    }

    pub fn client_entropy(&self) -> FixedEntropy {
        FixedEntropy::new(&self.client_draws)
    }

    pub fn relay_entropy(&self) -> FixedEntropy {
        FixedEntropy::new(&self.relay_draws)
    }

    /// Enough relay draws for any one answer.
    pub fn answer_entropy(&self) -> FixedEntropy {
        FixedEntropy::new(&self.answer_draws)
    }

    /// The honest handshake with `relay` through the library API: the client's end and the relay's executor.
    pub fn link(&self, relay: &Relay) -> (Link, Executor) {
        let access = self.access();
        let (hello, st) = link::client::start(self.fp, Some(&access), NOW).unwrap();
        let (info, st_r) = link::relay::accept_ring(relay.keys().ring())
            .on_hello(&hello, VALID_UNTIL)
            .unwrap();
        let (hs1, wait) = st.on_relayinfo(&info, &mut self.client_entropy()).unwrap();
        let (hs2, relay_link) = st_r.on_hs1(&hs1, &mut self.relay_entropy()).unwrap();
        let client = wait.on_hs2(&hs2).unwrap();
        (
            client,
            Executor::new(relay_link, relay.limits().link_rate, at(0, 0)),
        )
    }
}

/// The relay's time: `hours` after [`NOW`], monotonic `mono_ms`.
pub fn at(hours: u64, mono_ms: u64) -> Now {
    Now {
        unix_secs: NOW + hours * 3600,
        mono_ms,
    }
}

/// The hour bucket of [`NOW`] (472 222).
pub fn now_bucket() -> u32 {
    u32::try_from(NOW / 3600).unwrap()
}

/// The unpadded payload `op ‖ cmd_seq ‖ fields` of a request.
pub fn payload(req: &Request) -> Vec<u8> {
    unpad(&req.encode().unwrap(), FRAME_PLAINTEXT_LEN)
        .unwrap()
        .to_vec()
}

/// The client's request builders on one link (spec §9.2, §9.6, D.2, D.6).
pub struct Client<'a> {
    pub sess: Id,
    pub access: &'a AccessKey,
}

impl Client<'_> {
    pub fn token(&self, cmd_seq: u32) -> [u8; 32] {
        ids::token(self.access, &self.sess, cmd_seq).unwrap()
    }

    pub fn queue_new(
        &self,
        s: u32,
        recv: &Key,
        send: &Key,
        token: [u8; 32],
        signer: &Key,
    ) -> Request {
        let msg = signed::queue_new(&self.sess, s, &recv.pk, &send.pk, &token);
        Request {
            cmd_seq: s,
            cmd: RequestCmd::QueueNew {
                recv_pk: recv.pk,
                send_pk: send.pk,
                token,
                sig: signer.sign(&msg),
            },
        }
    }

    pub fn send(&self, s: u32, recv: &Key, send: &Key, cell: &[u8], signer: &Key) -> Request {
        let sid = ids::sid(&recv.pk, &send.pk).unwrap();
        let cell = Cell::from_bytes(cell).unwrap();
        let msg = signed::send(&self.sess, s, &sid, &cell);
        Request {
            cmd_seq: s,
            cmd: RequestCmd::Send {
                sid,
                cell,
                sig: signer.sign(&msg),
            },
        }
    }

    pub fn fetch(&self, s: u32, recv: &Key, ack: u64, signer: &Key) -> Request {
        let rid = ids::rid(&recv.pk).unwrap();
        let msg = signed::fetch(&self.sess, s, &rid, ack);
        Request {
            cmd_seq: s,
            cmd: RequestCmd::Fetch {
                rid,
                ack,
                sig: signer.sign(&msg),
            },
        }
    }

    pub fn entry(&self, s: u32, recv: &Key, ack: u64, signer: &Key) -> FetchEntry {
        let rid = ids::rid(&recv.pk).unwrap();
        let msg = signed::fetch_multi_entry(&self.sess, s, &rid, ack);
        FetchEntry {
            rid,
            ack,
            sig: signer.sign(&msg),
        }
    }

    pub fn queue_del(&self, s: u32, recv: &Key, signer: &Key) -> Request {
        let rid = ids::rid(&recv.pk).unwrap();
        let msg = signed::queue_del(&self.sess, s, &rid);
        Request {
            cmd_seq: s,
            cmd: RequestCmd::QueueDel {
                rid,
                sig: signer.sign(&msg),
            },
        }
    }

    /// The three frames of a `LINK_PUT` (frame 1 with the head fields and `blob[0..4160]`, two `CONT`s).
    pub fn link_put(&self, s: u32, p: &Put<'_>) -> [Request; 3] {
        let fields = LinkPutFields {
            ld_id: &p.ld_id,
            one_time: p.one_time,
            expires_bucket: p.expires_bucket,
            owner_pk: &p.owner.pk,
            token: &p.token,
        };
        let msg = signed::link_put_hashed(&self.sess, s, &fields, &sha256(&[p.blob]));
        let (blob_part, one, two) = split_blob(p.blob).unwrap();
        [
            Request {
                cmd_seq: s,
                cmd: RequestCmd::LinkPut {
                    ld_id: p.ld_id,
                    one_time: p.one_time,
                    expires_bucket: p.expires_bucket,
                    owner_pk: p.owner.pk,
                    token: p.token,
                    sig: p.signer.sign(&msg),
                    blob_part,
                },
            },
            Request {
                cmd_seq: s,
                cmd: RequestCmd::Cont(one),
            },
            Request {
                cmd_seq: s,
                cmd: RequestCmd::Cont(two),
            },
        ]
    }

    pub fn link_get(&self, s: u32, ld_id: &Id, owner: Option<(&Key, u32)>) -> Request {
        let mode = match owner {
            None => LinkGetMode::Consume,
            Some((key, sig_seq)) => LinkGetMode::OwnerStatus(
                key.sign(&signed::link_get_owner_status(&self.sess, sig_seq, ld_id)),
            ),
        };
        Request {
            cmd_seq: s,
            cmd: RequestCmd::LinkGet {
                ld_id: *ld_id,
                mode,
            },
        }
    }
}

/// The fields of a `LINK_PUT`: the blob is 12360 B; `signer` signs the D.6 message (the owner, or another key).
pub struct Put<'a> {
    pub ld_id: Id,
    pub one_time: bool,
    pub expires_bucket: u32,
    pub owner: &'a Key,
    pub token: [u8; 32],
    pub blob: &'a [u8],
    pub signer: &'a Key,
}

/// `rid` and `sid` of a pair (spec §9.1).
pub fn ids_of(recv: &Key, send: &Key) -> (Id, Id) {
    (
        ids::rid(&recv.pk).unwrap(),
        ids::sid(&recv.pk, &send.pk).unwrap(),
    )
}

/// A cursor over the fuzzer's bytes: every read is zero-padded at the end of the input.
pub struct Bytes<'a>(pub &'a [u8]);

impl Bytes<'_> {
    pub fn take(&mut self, n: usize) -> Vec<u8> {
        let k = n.min(self.0.len());
        let (head, rest) = self.0.split_at(k);
        self.0 = rest;
        let mut v = head.to_vec();
        v.resize(n, 0);
        v
    }

    pub fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.take(2).try_into().unwrap())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
