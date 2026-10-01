// SPDX-License-Identifier: AGPL-3.0-or-later
//! Replay of the frozen `hx` suite (`vectors/SCHEMA-4.10-hx.md`) through the library: `secmp-proto::inv`,
//! `secmp-proto::hx` and `secmp-proto::prekeys` reproduce every output of every positive case byte for byte and
//! reject every negative case with the uniform error, leaving the prekey store as the case says (TEST-SPEC-M4 (a)
//! `hx_vectors`; one assertion message per case id).
//!
//! Reads the frozen `vectors/hx.json` (ADR-026: a verbatim copy of the reference file) and the reference file
//! `vectors/ref/hx.json` while the suite is not frozen yet.


use std::collections::BTreeMap;

use crate::hx_gen::harness::{CREATED, EXPIRES, NOW, OPK_ID, SPK_ID, hex};
use crate::hx_gen::tr_digest::digest;
use secmp_crypto::{Nonce24, SecretBytes};
use secmp_proto::codec::unpad;
use secmp_proto::hx::{self, Initiator, Responder, Shared, TranscriptInputs};
use secmp_proto::inv::{
    derive_k_inv, derive_k_ld, invitation_uri, invitee_accept, seal_blob,
};
use secmp_proto::keys::X25519Pk;
use secmp_proto::prekeys::{IdentityKeys, InvitationRecord, MemoryPrekeyStore};
use secmp_proto::sizes::MLKEM1024_CT_LEN;
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::cell::{Cell, RelayQueue, RouteDescriptor};
use secmp_proto::wire::inv::{
    InvitationV1, LinkDataV1, Onion, PrekeyBundle, Profile, RelayRef,
};
use secmp_proto::wire::Period;
use secmp_proto::{Decode, Encode, Error};
use serde_json::Value;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn vector_file() -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors");
    let frozen = root.join("hx.json");
    let path = if frozen.exists() {
        frozen
    } else {
        root.join("ref").join("hx.json")
    };
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// A case of the file: its named byte strings.
struct Case {
    id: String,
    op: String,
    inputs: BTreeMap<String, Value>,
    outputs: BTreeMap<String, Value>,
}

impl Case {
    fn new(v: &Value) -> Self {
        let map = |key: &str| -> BTreeMap<String, Value> {
            v.get(key)
                .and_then(Value::as_object)
                .map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default()
        };
        Self {
            id: v["id"].as_str().unwrap().to_owned(),
            op: v["op"].as_str().unwrap().to_owned(),
            inputs: map("inputs"),
            outputs: map("outputs"),
        }
    }

    fn input(&self, name: &str) -> Vec<u8> {
        unhex(self.inputs[name].as_str().unwrap())
    }

    fn has_input(&self, name: &str) -> bool {
        self.inputs.contains_key(name)
    }

    fn output(&self, name: &str) -> Vec<u8> {
        unhex(self.outputs[name].as_str().unwrap())
    }

    fn list(&self, key: &str) -> Vec<Vec<u8>> {
        self.inputs[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| unhex(x.as_str().unwrap()))
            .collect()
    }

    fn array(&self, name: &str) -> [u8; 32] {
        self.input(name).try_into().unwrap()
    }
}

/// The inputs of the cases the later ones build on.
struct World {
    r_identity: IdentityKeys,
    /// R's store after cases 1–4 (the SPK and the OPK of case 1, the record of case 3).
    store_seed: Vec<u8>,
    record: InvitationRecord,
    invitation: Vec<u8>,
    uri: String,
    blob: Vec<u8>,
}

fn fixed(parts: &[&[u8]]) -> FixedEntropy {
    FixedEntropy::new(&parts.concat())
}

fn store_from(seed: &[u8]) -> MemoryPrekeyStore {
    let mut e = FixedEntropy::new(seed);
    let mut store = MemoryPrekeyStore::starting_at(SPK_ID, OPK_ID);
    store.create_spk(CREATED, &mut e).unwrap();
    store.issue_opk(&mut e).unwrap();
    store
}

fn route(c: &Case) -> RouteDescriptor {
    let onion_key = secmp_crypto::Ed25519SigningKey::from_seed(&c.input("onion_seed")).unwrap();
    RouteDescriptor::RelayQueue(RelayQueue {
        relay: RelayRef {
            relay_fp: c.array("relay_fp"),
            onion: Onion::from_pubkey(onion_key.verifying_key().as_bytes()),
            akc: c.array("akc"),
            direct: None,
        },
        sid: c.input("sid").try_into().unwrap(),
        send_seed: SecretBytes::from_slice(&c.input("send_seed")).unwrap(),
        period_s: Period::S20,
    })
}

fn cells_of(list: &[Vec<u8>]) -> Vec<Cell> {
    list.iter().map(|c| Cell::from_bytes(c).unwrap()).collect()
}

#[test]
fn hx_vectors() {
    let file = vector_file();
    assert_eq!(file["schema"], 5);
    assert_eq!(file["suite"], "hx");
    let cases: Vec<Case> = file["cases"].as_array().unwrap().iter().map(Case::new).collect();
    assert_eq!(cases.len(), 30);
    let by_id = |id: &str| cases.iter().find(|c| c.id == id).unwrap();

    // cases 1–2: identities, the bundle, the opks
    let c1 = by_id("hx-0001");
    let seed1 = [
        c1.input("ik_mldsa_xi"),
        c1.input("ik_ed_seed"),
        c1.input("ik_dh_sk"),
        c1.input("spk_dh_sk"),
        c1.input("spk_kem_seed"),
        c1.input("rpk_kem_seed"),
        c1.input("opk_dh_sk"),
        c1.input("opk_kem_seed"),
        c1.input("rnd"),
    ]
    .concat();
    let mut e = FixedEntropy::new(&seed1);
    let r_identity = IdentityKeys::generate(&mut e).unwrap();
    let store_seed = seed1[96..96 + 32 + 64 + 64 + 32 + 64].to_vec();
    let mut store = MemoryPrekeyStore::starting_at(SPK_ID, OPK_ID);
    store.create_spk(CREATED, &mut e).unwrap();
    store.issue_opk(&mut e).unwrap();
    let bundle = store
        .bundle(&r_identity, SPK_ID, OPK_ID, EXPIRES, &mut e)
        .unwrap();
    assert_eq!(e.remaining(), 0, "{}: every draw consumed", c1.id);
    assert_eq!(hex(&r_identity.public().encode().unwrap()), hex(&c1.output("iks")), "{} iks", c1.id);
    assert_eq!(hex(&r_identity.fingerprint().unwrap()), hex(&c1.output("fp")), "{} fp", c1.id);
    assert_eq!(hex(&bundle.encode().unwrap()), hex(&c1.output("bundle")), "{} bundle", c1.id);
    assert_eq!(store.opk_ids(), vec![OPK_ID], "{} opks_post", c1.id);

    let c2 = by_id("hx-0002");
    let seed2 = [c2.input("ik_mldsa_xi"), c2.input("ik_ed_seed"), c2.input("ik_dh_sk")].concat();
    let i_identity = IdentityKeys::generate(&mut FixedEntropy::new(&seed2)).unwrap();
    assert_eq!(hex(&i_identity.public().encode().unwrap()), hex(&c2.output("iks")), "{} iks", c2.id);
    assert_eq!(hex(&i_identity.fingerprint().unwrap()), hex(&c2.output("fp")), "{} fp", c2.id);

    // case 3: the invitation and its URI
    let c3 = by_id("hx-0003");
    let invitation = InvitationV1 {
        relay: RelayRef {
            relay_fp: c3.array("relay_fp"),
            onion: Onion::from_pubkey(&c3.array("onion_pubkey")),
            akc: c3.array("akc"),
            direct: None,
        },
        ld_id: c3.input("ld_id").try_into().unwrap(),
        link_key: SecretBytes::from_slice(&c3.input("link_key")).unwrap(),
        inviter_fp: r_identity.fingerprint().unwrap(),
        inv_sid: c3.input("inv_sid").try_into().unwrap(),
        inv_send_seed: SecretBytes::from_slice(&c3.input("inv_send_seed")).unwrap(),
        inv_period_s: Period::S20,
        expires: EXPIRES,
    };
    let invitation_bytes = invitation.encode().unwrap().to_vec();
    let uri = invitation_uri(&invitation).unwrap();
    assert_eq!(hex(&invitation_bytes), hex(&c3.output("invitation")), "{} invitation", c3.id);
    assert_eq!(uri, c3.outputs["uri"].as_str().unwrap(), "{} uri", c3.id);

    // case 4: the link data and its blob
    let c4 = by_id("hx-0004");
    let link_data = LinkDataV1 {
        inviter_iks: r_identity.public().clone(),
        bundle: PrekeyBundle::decode(&bundle.encode().unwrap()).unwrap(),
        profile: Profile::new("bob", None).unwrap(),
        created: CREATED,
    };
    let blob = seal_blob(
        &invitation.ld_id,
        &invitation.link_key,
        Nonce24::from_bytes_kat(c4.input("n").try_into().unwrap()),
        &link_data,
    )
    .unwrap();
    let blob_bytes = blob.encode().unwrap().to_vec();
    let k_ld = derive_k_ld(&invitation.ld_id, &invitation.link_key).unwrap();
    assert_eq!(hex(k_ld.expose_secret()), hex(&c4.output("k_ld")), "{} k_ld", c4.id);
    assert_eq!(
        hex(&unpad(&link_data.encode().unwrap(), 12_288).unwrap().to_vec()),
        hex(&c4.output("linkdata")),
        "{} linkdata",
        c4.id
    );
    assert_eq!(hex(&blob_bytes), hex(&c4.output("blob")), "{} blob", c4.id);

    // case 5: the invitee's checks
    let c5 = by_id("hx-0005");
    let accepted = invitee_accept(&uri, &blob_bytes, NOW).unwrap_or_else(|_| panic!("{} accept", c5.id));
    let k_inv = derive_k_inv(&invitation.ld_id, &invitation.link_key).unwrap();
    assert_eq!(hex(k_ld.expose_secret()), hex(&c5.output("k_ld")), "{} k_ld", c5.id);
    assert_eq!(hex(k_inv.expose_secret()), hex(&c5.output("k_inv")), "{} k_inv", c5.id);
    assert_eq!(c5.outputs["accept"], true, "{} accept", c5.id);

    // case 6: the initiator
    let c6 = by_id("hx-0006");
    let routes = [route(c6)];
    let mut e = fixed(&[
        &c6.input("ek_sk"),
        &c6.input("m_spk"),
        &c6.input("m_opk"),
        &c6.input("dh_s_sk"),
        &c6.input("kem_s_seed"),
        &c6.input("m_tr"),
        &c6.input("hdr_nonce"),
        &c6.input("inner_nonce"),
        &c6.input("init_id"),
        &c6.input("cell_nonce_0"),
        &c6.input("cell_nonce_1"),
        &c6.input("cell_nonce_2"),
    ]);
    let (handshake_cells, i_state) = Initiator::start(
        &accepted.invitation,
        &accepted.link_data,
        &i_identity.initiator_keys(),
        &routes,
        &Profile::new("alice", Some(c6.array("avatar_sha256"))).unwrap(),
        1_700_000_001,
        &mut e,
    )
    .unwrap_or_else(|_| panic!("{} start", c6.id));
    assert_eq!(e.remaining(), 0, "{}: every draw consumed", c6.id);
    let sent = handshake_cells.release(|_| Ok::<(), ()>(())).unwrap();
    for (k, cell) in sent.iter().enumerate() {
        assert_eq!(
            hex(cell.as_bytes()),
            hex(&c6.output(&format!("cell_{k}"))),
            "{} cell_{k}",
            c6.id
        );
    }
    assert_eq!(digest(&i_state), hex(&c6.output("state_post_I")), "{} state_post_I", c6.id);
    assert_eq!(hex(i_state.sb_kat()), hex(&c6.output("transcript")), "{} transcript (sb)", c6.id);
    derive_checks(c6, &r_identity, &i_identity, &link_data, &invitation);

    // cases 7 and 8: the responder, from the state after cases 1–4
    let world = World {
        r_identity,
        store_seed,
        record: InvitationRecord {
            ld_id: invitation.ld_id,
            link_key: SecretBytes::from_slice(invitation.link_key.expose_secret()).unwrap(),
            spk_id: SPK_ID,
            opk_id: OPK_ID,
            expires: EXPIRES,
        },
        invitation: invitation_bytes,
        uri,
        blob: blob_bytes,
    };
    let mut after_7 = None;
    for id in ["hx-0007", "hx-0008"] {
        let c = by_id(id);
        let mut store = store_from(&world.store_seed);
        let fetched = cells_of(&c.list("fetched"));
        let mut e = fixed(&[&c.input("dh_sk"), &c.input("kem_seed"), &c.input("m")]);
        let accepted = Responder::accept(
            &fetched,
            &world.record,
            &mut store,
            &world.r_identity.responder_keys(),
            &mut e,
        )
        .unwrap_or_else(|_| panic!("{} accept", c.id));
        assert_eq!(e.remaining(), 0, "{}: DH-step draws consumed", c.id);
        assert_eq!(hex(&accepted.peer.encode().unwrap()), hex(&c.output("peer_iks")), "{} peer_iks", c.id);
        assert_eq!(hex(&accepted.profile.encode().unwrap()), hex(&c.output("profile")), "{} profile", c.id);
        let routes: Vec<String> = accepted.routes.iter().map(|r| hex(&r.encode().unwrap())).collect();
        let listed: Vec<String> = c.outputs["routes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(routes, listed, "{} routes", c.id);
        assert_eq!(digest(&accepted.state), hex(&c.output("state_post_R")), "{} state_post_R", c.id);
        assert_eq!(hex(accepted.state.sb_kat()), hex(&c.output("transcript")), "{} transcript (sb)", c.id);
        assert_eq!(store.opk_ids(), Vec::<u32>::new(), "{} opks_post", c.id);
        if id == "hx-0007" {
            after_7 = Some(store);
        }
    }

    // invitee-reject (V1–V9) and respond-reject (R1–R13)
    for c in &cases {
        match c.op.as_str() {
            "invitee-reject" => {
                let uri = if c.has_input("uri") {
                    c.inputs["uri"].as_str().unwrap().to_owned()
                } else {
                    world.uri.clone()
                };
                let blob = if c.has_input("blob") { c.input("blob") } else { world.blob.clone() };
                let _ = &world.invitation;
                assert_eq!(
                    invitee_accept(&uri, &blob, NOW).err(),
                    Some(Error::Rejected),
                    "{} invitee-reject",
                    c.id
                );
            }
            "respond-reject" => {
                let mut fresh = store_from(&world.store_seed);
                let store = if c.id == "hx-0019" {
                    after_7.as_mut().unwrap()
                } else {
                    &mut fresh
                };
                let before = store.digest_kat();
                let fetched = cells_of(&c.list("fetched"));
                let mut e = if c.has_input("dh_sk") {
                    fixed(&[&c.input("dh_sk"), &c.input("kem_seed"), &c.input("m")])
                } else {
                    FixedEntropy::new(&[])
                };
                assert_eq!(
                    Responder::accept(
                        &fetched,
                        &world.record,
                        store,
                        &world.r_identity.responder_keys(),
                        &mut e,
                    )
                    .err(),
                    Some(Error::Rejected),
                    "{} respond-reject",
                    c.id
                );
                assert_eq!(store.digest_kat(), before, "{}: store unchanged", c.id);
                let expected: Vec<u32> = c.outputs["opks_post"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| u32::try_from(n.as_u64().unwrap()).unwrap())
                    .collect();
                assert_eq!(store.opk_ids(), expected, "{} opks_post", c.id);
            }
            _ => {}
        }
    }
}

/// The `hx::derive` functions against the values of case 6: `transcript`, `SK` and `K_id` from the listed DH
/// outputs and shared secrets (§6.4).
fn derive_checks(
    c6: &Case,
    r: &IdentityKeys,
    i: &IdentityKeys,
    link_data: &LinkDataV1,
    invitation: &InvitationV1,
) {
    let bundle = &link_data.bundle;
    let ct_spk: [u8; MLKEM1024_CT_LEN] = c6.output("ct_spk").try_into().unwrap();
    let ct_opk: [u8; MLKEM1024_CT_LEN] = c6.output("ct_opk").try_into().unwrap();
    let ek_i = X25519Pk::from_bytes(&c6.output("ek_pk")).unwrap();
    let tr = hx::transcript(&TranscriptInputs {
        iks_r: r.public(),
        spk_id: bundle.spk_id,
        spk_dh: &bundle.spk_dh,
        spk_kem: &bundle.spk_kem,
        rpk_kem: &bundle.rpk_kem,
        opk_id: bundle.opk_id,
        opk_dh: &bundle.opk_dh,
        opk_kem: &bundle.opk_kem,
        iks_i: i.public(),
        ek_i: &ek_i,
        ct_spk: &ct_spk,
        ct_opk: &ct_opk,
        ld_id: &invitation.ld_id,
    })
    .unwrap();
    assert_eq!(hex(&tr), hex(&c6.output("transcript")), "{} transcript", c6.id);
    let secret = |name: &str| SecretBytes::<32>::from_slice(&c6.output(name)).unwrap();
    let sk = hx::session_key(
        &Shared {
            dh1: secret("dh1"),
            dh2: secret("dh2"),
            dh3: secret("dh3"),
            dh4: secret("dh4"),
            ss_spk: secret("ss_spk"),
            ss_opk: secret("ss_opk"),
        },
        &tr,
    )
    .unwrap();
    assert_eq!(hex(sk.expose_secret()), hex(&c6.output("sk")), "{} sk", c6.id);
    let k_id = hx::k_id(
        &invitation.ld_id,
        &invitation.link_key,
        &secret("dh3"),
        &secret("ss_spk"),
        &secret("dh4"),
        &secret("ss_opk"),
    )
    .unwrap();
    assert_eq!(hex(k_id.expose_secret()), hex(&c6.output("k_id")), "{} k_id", c6.id);
}
