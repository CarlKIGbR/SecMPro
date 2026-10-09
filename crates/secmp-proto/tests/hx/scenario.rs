// SPDX-License-Identifier: AGPL-3.0-or-later
//! The scenario of the negative tests: the vector suite's own parties and values (cases 1–6), seen through the
//! library (`IdentityKeys`, `MemoryPrekeyStore`, `Responder`) and through the independent harness (re-sealing).

use crate::hx_gen::harness::{self, CREATED, EXPIRES, NOW, OPK_ID, SPK_ID};
use crate::hx_gen::{World, world};
use secmp_crypto::SecretBytes;
use secmp_proto::hx::{Accepted, Responder};
use secmp_proto::inv::invitee_accept;
use secmp_proto::prekeys::{IdentityKeys, InvitationRecord, MemoryPrekeyStore};
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::inv::LinkDataV1;
use secmp_proto::{Decode, Error};

pub struct Lib {
    pub w: World,
    pub r_id: IdentityKeys,
    pub i_id: IdentityKeys,
}

pub fn fixed(parts: &[&[u8]]) -> FixedEntropy {
    FixedEntropy::new(&parts.concat())
}

impl Lib {
    pub fn new() -> Self {
        let w = world();
        let r_id = IdentityKeys::generate(&mut FixedEntropy::new(&w.r_seed)).unwrap();
        let i_id = IdentityKeys::generate(&mut FixedEntropy::new(&w.i_seed)).unwrap();
        Self { w, r_id, i_id }
    }

    /// R's store after cases 1–4: the SPK 7, the OPK 42 and the invitation's record.
    pub fn store(&self) -> MemoryPrekeyStore {
        let mut e = FixedEntropy::new(self.w.r_seed.get(96..).unwrap());
        let mut store = MemoryPrekeyStore::starting_at(SPK_ID, OPK_ID);
        store.create_spk(CREATED, &mut e).unwrap();
        store.issue_opk(&mut e).unwrap();
        store.add_record(self.record()).unwrap();
        store
    }

    pub fn record(&self) -> InvitationRecord {
        InvitationRecord {
            ld_id: self.w.inv.ld_id,
            link_key: SecretBytes::from_slice(&self.w.inv.link_key).unwrap(),
            owner_seed: SecretBytes::from_slice(&self.w.inv.owner_seed).unwrap(),
            invq_recv_seed: SecretBytes::from_slice(&self.w.inv.invq_recv_seed).unwrap(),
            spk_id: SPK_ID,
            opk_id: OPK_ID,
            expires: EXPIRES,
        }
    }

    pub fn honest(&self) -> Vec<Vec<u8>> {
        self.w.b6.cells.to_vec()
    }

    /// `accept` on `cells` with the honest DH-step randomness.
    pub fn accept(
        &self,
        store: &mut MemoryPrekeyStore,
        cells: &[Vec<u8>],
    ) -> Result<Accepted, Error> {
        let cells: Vec<Cell> = cells.iter().map(|c| Cell::from_bytes(c).unwrap()).collect();
        Responder::accept(
            &cells,
            &self.record(),
            store,
            &self.r_id.responder_keys(),
            &mut FixedEntropy::new(&self.w.step),
        )
    }

    /// `accept` must reject with the uniform error, leave the store byte-for-byte as it was and keep the OPK.
    pub fn assert_rejected(&self, cells: &[Vec<u8>], what: &str) {
        let mut store = self.store();
        let before = store.digest_kat();
        let result = self.accept(&mut store, cells);
        assert_eq!(
            result.err(),
            Some(Error::Rejected),
            "{what}: uniform Rejected"
        );
        assert_eq!(store.digest_kat(), before, "{what}: the store is unchanged");
        assert!(store.opk_ids().contains(&OPK_ID), "{what}: the OPK is kept");
    }

    /// [`Lib::assert_rejected`], and the reject site that `Responder::accept` tagged is `site` (M4 review C-15, R-31):
    /// the check a row names is the one that rejected, not a later backstop.
    pub fn assert_rejected_at(&self, cells: &[Vec<u8>], site: &str) {
        self.assert_rejected(cells, site);
        assert_eq!(
            secmp_proto::hx::ACCEPT_SITE_KAT.get(),
            Some(site),
            "the reject site"
        );
    }

    /// The invitee's check at `NOW`.
    pub fn invitee(&self, uri: &str, blob: &[u8]) -> Result<(), Error> {
        let _ = self; // a method for call-site symmetry with the other `Lib` helpers
        invitee_accept(uri, blob, NOW).map(|_| ())
    }

    /// The URI of invitation bytes.
    pub fn uri_of(&self, invitation: &[u8]) -> String {
        let _ = self; // a method for call-site symmetry with the other `Lib` helpers
        format!(
            "secmp://i/{}",
            secmp_proto::inv::base64url_encode(invitation).as_str()
        )
    }

    /// A blob of `linkdata` (unpadded bytes) sealed under the invitation's `K_ld` with the nonce `[tag; 24]`.
    pub fn blob_of(&self, linkdata: &[u8], tag: u8) -> Vec<u8> {
        harness::blob(&self.w.k_ld, &self.w.inv.ld_id, &[tag; 24], linkdata)
    }

    /// `LinkDataV1` bytes with the given IKS and bundle.
    pub fn linkdata_of(&self, iks: &[u8], bundle: &[u8]) -> Vec<u8> {
        let _ = self; // a method for call-site symmetry with the other `Lib` helpers
        harness::linkdata_bytes(iks, bundle, &harness::profile_bytes("bob", None), CREATED)
    }

    /// Whether the library decodes `linkdata` (padded) — used to confirm a mutation really is a decoder case.
    pub fn decodes(&self, padded: &[u8]) -> bool {
        let _ = self; // a method for call-site symmetry with the other `Lib` helpers
        LinkDataV1::decode(padded).is_ok()
    }
}
