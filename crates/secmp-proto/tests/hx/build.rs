// SPDX-License-Identifier: AGPL-3.0-or-later
//! Builders of manipulated envelopes for the responder's negative tests: everything re-sealed under `K_inv`
//! (the outer layer) and `K_id` (the inner layer) with the independent harness, from the scenario's own values.

use secmp_crypto::{Aead, Label, Nonce24, SecretBytes, VectorStream};
use secmp_proto::Encode;
use secmp_proto::codec::pad;
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::cell::{Cell, Content, ContentBody, RouteDescriptor};

use crate::hx_gen::harness::{
    self, CHUNK, OPK_ID, PADDED_LEN, SPK_ID, cell_plaintext, cell_raw, inner_ct, outer, snapshot,
};
use crate::hx_gen::tr_digest::{StateFields, fields};
use crate::scenario::Lib;

/// `n` pseudo-random bytes (the SCHEMA §2 stream of the suite `hx-test`, index `tag`).
pub fn random_bytes(tag: u32, n: usize) -> Vec<u8> {
    VectorStream::new("hx-test", tag).take(n)
}

/// `count` pseudo-random 4096-byte cells (garbage: they do not open under any key).
pub fn garbage(tag: u32, count: usize) -> Vec<Vec<u8>> {
    let mut s = VectorStream::new("hx-garbage", tag);
    (0..count).map(|_| s.take(4096)).collect()
}

/// A padded Content: `ver ‖ type ‖ seq ‖ ts ‖ body_len ‖ body`, padded to 1710.
pub fn raw_content(ver: u8, ty: u8, body: &[u8]) -> Vec<u8> {
    let mut c = vec![ver, ty];
    c.extend_from_slice(&1_u64.to_be_bytes());
    c.extend_from_slice(&1_700_000_001_u64.to_be_bytes());
    c.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    c.extend_from_slice(body);
    pad(&c, 1710).unwrap().to_vec()
}

/// A Handshake body: `Profile ‖ caps u32 ‖ route_count ‖ routes`.
pub fn handshake_body(lib: &Lib, caps: u32, routes: &[Vec<u8>]) -> Vec<u8> {
    let mut b = harness::profile_bytes("alice", Some(lib.w.b6.avatar));
    b.extend_from_slice(&caps.to_be_bytes());
    b.push(u8::try_from(routes.len()).unwrap());
    for r in routes {
        b.extend_from_slice(r);
    }
    b
}

impl Lib {
    /// The three cells of `padded` (12018 bytes) under `init_id = [tag; 16]` and the nonces `[tag; 24]`,
    /// `[tag + 1; 24]`, `[tag + 2; 24]`.
    pub fn reseal_padded(&self, padded: &[u8], tag: u8) -> Vec<Vec<u8>> {
        assert_eq!(padded.len(), PADDED_LEN);
        let init_id = [tag; 16];
        (0..3_u8)
            .map(|i| {
                let k = usize::from(i);
                cell_raw(
                    &self.w.k_inv,
                    &self.w.inv.ld_id,
                    &[tag.wrapping_add(i); 24],
                    &cell_plaintext(&init_id, i, 3, padded.chunks(CHUNK).nth(k).unwrap()),
                )
            })
            .collect()
    }

    /// The three cells of `outer` (unpadded) under `init_id = [tag; 16]`.
    pub fn reseal(&self, outer_bytes: &[u8], tag: u8) -> Vec<Vec<u8>> {
        self.reseal_padded(&pad(outer_bytes, PADDED_LEN).unwrap(), tag)
    }

    /// The honest `Outer`, changed by `f`, in three cells.
    pub fn outer_variant(&self, tag: u8, f: impl FnOnce(&mut Vec<u8>)) -> Vec<Vec<u8>> {
        let mut o = self.w.b6.outer.clone();
        f(&mut o);
        self.reseal(&o, tag)
    }

    /// An `Outer` carrying `inner_ct` (the honest ephemeral key and ciphertexts).
    pub fn outer_of(&self, inner_ct_bytes: &[u8]) -> Vec<u8> {
        let a = &self.w.b6.a;
        outer(
            &a.ek_pk,
            SPK_ID,
            OPK_ID,
            &a.ct_spk,
            &a.ct_opk,
            inner_ct_bytes,
        )
    }

    /// An envelope whose `Inner` is `inner`, sealed under the right `K_id`, in three cells.
    pub fn inner_variant(&self, tag: u8, inner: &[u8]) -> Vec<Vec<u8>> {
        let ict = inner_ct(&self.w.b6.a.k_id, &self.w.inv.ld_id, &[tag; 24], inner);
        self.reseal(&self.outer_of(&ict), tag)
    }

    /// `Inner = IKSPublic_I ‖ first_msg`.
    pub fn inner_with(&self, iks: &[u8], first_msg: &[u8]) -> Vec<u8> {
        let _ = self; // a method for call-site symmetry with the other `Lib` helpers
        [iks, first_msg].concat()
    }

    /// The honest `Inner`.
    pub fn honest_inner(&self) -> Vec<u8> {
        self.w.b6.inner.clone()
    }

    /// A first message encrypting the padded Content `body` from the initiator's post-init state (the header
    /// nonce `[tag; 24]`).
    pub fn first_msg_of(&self, body: &[u8], tag: u8) -> Vec<u8> {
        let state = snapshot(&self.w.b6.i_after_init);
        let sealed = state
            .encrypt_padded_kat(body, &mut FixedEntropy::new(&[tag; 24]))
            .map_err(|r| r.error())
            .unwrap();
        let (_, cell) = sealed.persist(|_| Ok::<(), ()>(())).unwrap();
        cell.as_bytes().to_vec()
    }

    /// A first message of the initiator's post-init state with the pre-encrypt counters `n_s` and `pn` set (the
    /// header carries them, §7.3). A state with `pn ≠ 0` is only reachable after receiving a DH step, so the
    /// serialisation is rebuilt with a receiving chain (`ck_r`, `hk_r`, `last_ct_r`); the sending half, which
    /// seals the cell, is the honest one.
    pub fn first_msg_with_counters(&self, n_s: u32, pn: u32, tag: u8) -> Vec<u8> {
        let mut f = fields(&self.w.b6.i_after_init);
        f.n_s = n_s;
        f.pn = pn;
        // the cell is sealed under message key n_s of the chain: advance `ck_s` n_s times, so that the receiver's
        // `skip_message_keys` derives the same key and the body MAC verifies (only the counter rule can reject)
        let mut ck =
            secmp_crypto::SecretBytes::<32>::from_slice(f.keys.first().unwrap().as_ref().unwrap())
                .unwrap();
        for _ in 0..n_s {
            ck = secmp_crypto::kdf_ck(&ck).unwrap().0;
        }
        f.keys[0] = Some(ck.expose_secret().to_vec());
        if pn != 0 {
            f.keys[1] = Some(vec![1; 32]);
            f.keys[3] = Some(vec![2; 32]);
            f.kem[1] = Some(vec![3; 1088]);
        }
        let state = secmp_proto::tr::RatchetState::from_bytes(&encode_state(&f)).unwrap();
        let sealed = state
            .encrypt_padded_kat(
                &self.honest_content_padded(),
                &mut FixedEntropy::new(&[tag; 24]),
            )
            .map_err(|r| r.error())
            .unwrap();
        sealed
            .persist(|_| Ok::<(), ()>(()))
            .unwrap()
            .1
            .as_bytes()
            .to_vec()
    }

    /// The honest Content, padded to 1710.
    pub fn honest_content_padded(&self) -> Vec<u8> {
        pad(&self.w.b6.content, 1710).unwrap().to_vec()
    }

    /// An envelope whose first message is `first_msg` (honest `IKSPublic_I`, right `K_id`).
    pub fn first_msg_variant(&self, tag: u8, first_msg: &[u8]) -> Vec<Vec<u8>> {
        self.inner_variant(tag, &self.inner_with(&self.w.i.iks_bytes, first_msg))
    }

    /// An envelope for the padded Content `body`.
    pub fn content_variant(&self, tag: u8, body: &[u8]) -> Vec<Vec<u8>> {
        self.first_msg_variant(tag, &self.first_msg_of(body, tag))
    }

    /// A Handshake Content with these routes (encoded `RouteDescriptor`s).
    pub fn handshake_with_routes(&self, routes: &[Vec<u8>]) -> Vec<u8> {
        raw_content(1, 1, &handshake_body(self, 0, routes))
    }

    /// The header of `first_msg` re-sealed under `key` (the body unchanged): a header that does not open under
    /// `HK_A` (spec §7.4).
    pub fn first_msg_header_under(&self, first_msg: &[u8], key: &SecretBytes<32>) -> Vec<u8> {
        let hk_a = self.w.b6.i_after_init.hk_s_kat().unwrap();
        let cell = Cell::from_bytes(first_msg).unwrap();
        let p = cell.parts().unwrap();
        let nonce: [u8; 24] = p.hdr_nonce.try_into().unwrap();
        let ad = [Label::TrHdr.as_bytes(), self.w.b6.a.transcript.as_slice()].concat();
        let header = Aead::open(hk_a, &nonce, &ad, p.hdr_ct).unwrap();
        let hdr_ct = Aead::seal(key, Nonce24::from_bytes_kat(nonce), &ad, &header).unwrap();
        [p.hdr_nonce, &hdr_ct, p.body_ct, p.tag].concat()
    }

    /// The route of the scenario, encoded.
    pub fn route(&self) -> Vec<u8> {
        self.w.b6.route.clone()
    }

    /// Another valid `RelayQueue` route (one byte of `relay_fp` changed).
    pub fn other_route(&self) -> Vec<u8> {
        let mut r = self.w.b6.route.clone();
        *r.get_mut(10).unwrap() ^= 1;
        r
    }

    /// A route of an unknown kind (0x02) with a short blob.
    pub fn unknown_route(&self) -> Vec<u8> {
        let _ = self; // a method for call-site symmetry with the other `Lib` helpers
        RouteDescriptor::Unknown {
            kind: 2,
            blob: secmp_crypto::Zeroizing::new(vec![7; 10]),
        }
        .encode()
        .unwrap()
        .to_vec()
    }

    /// A Batch Content of one `AppMessage` (type 0x02), padded.
    pub fn batch_content(&self) -> Vec<u8> {
        use secmp_proto::wire::cell::{AppKind, AppMessage, BatchBody};
        let _ = self; // a method for call-site symmetry with the other `Lib` helpers
        Content {
            seq: 1,
            ts: 1_700_000_001,
            body: ContentBody::Batch(BatchBody {
                messages: vec![AppMessage {
                    msg_id: [1; 16],
                    kind: AppKind::Text,
                    expire_after: 0,
                    payload: secmp_crypto::Zeroizing::new(vec![2; 8]),
                }],
            }),
        }
        .encode()
        .unwrap()
        .to_vec()
    }

    /// A Dummy Content (type 0x00, empty body), padded.
    pub fn dummy_content(&self) -> Vec<u8> {
        let _ = self; // a method for call-site symmetry with the other `Lib` helpers
        raw_content(1, 0, &[])
    }

    /// A random `IKSPublic`-sized identity: another valid identity's `IKSPublic`.
    pub fn other_identity(&self, tag: u8) -> harness::Identity {
        let _ = self; // a method for call-site symmetry with the other `Lib` helpers
        harness::identity(
            &[tag; 32],
            &[tag.wrapping_add(1); 32],
            &[tag.wrapping_add(2); 32],
        )
    }
}

fn put_opt(out: &mut Vec<u8>, x: Option<&Vec<u8>>) {
    match x {
        None => out.push(0),
        Some(x) => {
            out.push(1);
            out.extend_from_slice(x);
        }
    }
}

/// `RatchetStateV1` from its fields (the inverse of `tr_digest::fields`).
pub fn encode_state(f: &StateFields) -> Vec<u8> {
    let mut out = vec![1];
    out.extend_from_slice(&f.sb_rk_dh_s);
    put_opt(&mut out, f.dh_r.as_ref());
    out.extend_from_slice(&f.kem_s_seed);
    for x in f.kem.iter().chain(&f.keys) {
        put_opt(&mut out, x.as_ref());
    }
    for n in [f.n_s, f.n_r, f.pn] {
        out.extend_from_slice(&n.to_be_bytes());
    }
    out.extend_from_slice(&u16::try_from(f.skipped.len()).unwrap().to_be_bytes());
    for e in &f.skipped {
        out.extend_from_slice(e);
    }
    out
}
