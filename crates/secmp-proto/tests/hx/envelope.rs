// SPDX-License-Identifier: AGPL-3.0-or-later
//! A complete envelope for an arbitrary initiator identity and Content, from the scenario's randomness.

use secmp_proto::keys::{MlKem768Ek, X25519Pk};
use secmp_proto::tr::{FixedEntropy, RatchetState};

use crate::hx_gen::harness::{self, AgreeIn, OPK_ID, SPK_ID, agree, inner_ct, outer};
use crate::scenario::Lib;

impl Lib {
    /// A complete envelope for `initiator` from the scenario's randomness (case 6's draws): the key agreement
    /// against R's bundle, the TR initiator state — with `sb` replaced by `sb_override` if given, the keys still
    /// derived from the real `SK` —, the padded Content `content` as `first_msg`, and the three cells. With the
    /// scenario's initiator, the honest content and no override it reproduces the honest cells byte for byte.
    pub fn full_envelope(
        &self,
        initiator: &harness::Identity,
        content: &[u8],
        sb_override: Option<[u8; 32]>,
    ) -> Vec<Vec<u8>> {
        let e = &self.w.b6.entropy;
        let at = |from: usize, to: usize| &e[from..to];
        let a = agree(&AgreeIn {
            i: initiator,
            r: &self.w.r,
            keys: &self.w.keys,
            ld_id: &self.w.inv.ld_id,
            link_key: &self.w.inv.link_key,
            ek_sk: at(0, 32),
            m_spk: at(32, 64).try_into().unwrap(),
            m_opk: at(64, 96).try_into().unwrap(),
        });
        let sb = sb_override.unwrap_or(a.transcript);
        let spk_dh = X25519Pk::from_bytes(self.w.keys.spk_dh.public_key().as_bytes()).unwrap();
        let rpk =
            MlKem768Ek::from_bytes(self.w.keys.rpk_kem.encapsulation_key().as_bytes()).unwrap();
        let mut tr_entropy = FixedEntropy::new(at(96, 224));
        let state = RatchetState::init_initiator_with(&a.sk, &sb, &spk_dh, &rpk, &mut tr_entropy)
            .unwrap();
        let first_msg = state
            .encrypt_padded_kat(content, &mut FixedEntropy::new(at(224, 248)))
            .map_err(|r| r.error())
            .unwrap()
            .persist(|_| Ok::<(), ()>(()))
            .unwrap()
            .1;
        let inner = [initiator.iks_bytes.as_slice(), first_msg.as_bytes()].concat();
        let ict = inner_ct(&a.k_id, &self.w.inv.ld_id, at(248, 272), &inner);
        let outer_bytes = outer(&a.ek_pk, SPK_ID, OPK_ID, &a.ct_spk, &a.ct_opk, &ict);
        let init_id: [u8; 16] = at(272, 288).try_into().unwrap();
        harness::cells(
            &self.w.k_inv,
            &self.w.inv.ld_id,
            &init_id,
            [at(288, 312), at(312, 336), at(336, 360)],
            &outer_bytes,
        )
        .to_vec()
    }
}
