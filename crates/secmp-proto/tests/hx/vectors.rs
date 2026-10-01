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
    InviteeAccepted, derive_k_inv, derive_k_ld, invitation_uri, invitee_accept, seal_blob,
};
use secmp_proto::keys::X25519Pk;
use secmp_proto::prekeys::{IdentityKeys, InvitationRecord, MemoryPrekeyStore};
use secmp_proto::sizes::MLKEM1024_CT_LEN;
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::Period;
use secmp_proto::wire::cell::{Cell, RelayQueue, RouteDescriptor};
use secmp_proto::wire::inv::{InvitationV1, LinkDataV1, Onion, PrekeyBundle, Profile, RelayRef};
use secmp_proto::{Decode, Encode, Error};
use serde_json::Value;

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
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
            id: v.get("id").unwrap().as_str().unwrap().to_owned(),
            op: v.get("op").unwrap().as_str().unwrap().to_owned(),
            inputs: map("inputs"),
            outputs: map("outputs"),
        }
    }

    fn input(&self, name: &str) -> Vec<u8> {
        unhex(self.inputs.get(name).unwrap().as_str().unwrap())
    }

    fn has_input(&self, name: &str) -> bool {
        self.inputs.contains_key(name)
    }

    fn output(&self, name: &str) -> Vec<u8> {
        unhex(self.outputs.get(name).unwrap().as_str().unwrap())
    }

    fn list(&self, key: &str) -> Vec<Vec<u8>> {
        self.inputs
            .get(key)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|x| unhex(x.as_str().unwrap()))
            .collect()
    }

    fn out_str(&self, name: &str) -> &str {
        self.outputs.get(name).unwrap().as_str().unwrap()
    }

    fn in_str(&self, name: &str) -> &str {
        self.inputs.get(name).unwrap().as_str().unwrap()
    }

    /// `got` equals the output `name`, message `"<id> <name>"`.
    fn expect(&self, name: &str, got: &[u8]) {
        assert_eq!(hex(got), hex(&self.output(name)), "{} {name}", self.id);
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

fn by_id<'a>(cases: &'a [Case], id: &str) -> &'a Case {
    cases.iter().find(|c| c.id == id).unwrap()
}

fn cells_of(list: &[Vec<u8>]) -> Vec<Cell> {
    list.iter().map(|c| Cell::from_bytes(c).unwrap()).collect()
}

/// Cases 1–2: the responder's and the initiator's identities, the bundle, the opks.
struct Identities {
    r_identity: IdentityKeys,
    i_identity: IdentityKeys,
    store_seed: Vec<u8>,
    bundle: PrekeyBundle,
}

fn case_identities(cases: &[Case]) -> Identities {
    let c1 = by_id(cases, "hx-0001");
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
    let store_seed = seed1.get(96..96 + 32 + 64 + 64 + 32 + 64).unwrap().to_vec();
    let mut store = MemoryPrekeyStore::starting_at(SPK_ID, OPK_ID);
    store.create_spk(CREATED, &mut e).unwrap();
    store.issue_opk(&mut e).unwrap();
    let bundle = store
        .bundle(&r_identity, SPK_ID, OPK_ID, EXPIRES, &mut e)
        .unwrap();
    assert_eq!(e.remaining(), 0, "{}: every draw consumed", c1.id);
    c1.expect("iks", &r_identity.public().encode().unwrap());
    c1.expect("fp", &r_identity.fingerprint().unwrap());
    c1.expect("bundle", &bundle.encode().unwrap());
    assert_eq!(store.opk_ids(), vec![OPK_ID], "{} opks_post", c1.id);

    let c2 = by_id(cases, "hx-0002");
    let seed2 = [
        c2.input("ik_mldsa_xi"),
        c2.input("ik_ed_seed"),
        c2.input("ik_dh_sk"),
    ]
    .concat();
    let i_identity = IdentityKeys::generate(&mut FixedEntropy::new(&seed2)).unwrap();
    c2.expect("iks", &i_identity.public().encode().unwrap());
    c2.expect("fp", &i_identity.fingerprint().unwrap());
    Identities {
        r_identity,
        i_identity,
        store_seed,
        bundle,
    }
}

/// Case 3: the invitation and its URI.
fn case_invitation(c3: &Case, r_identity: &IdentityKeys) -> (InvitationV1, Vec<u8>, String) {
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
    c3.expect("invitation", &invitation_bytes);
    assert_eq!(uri, c3.out_str("uri"), "{} uri", c3.id);
    (invitation, invitation_bytes, uri)
}

/// Case 4: the link data and its blob.
fn case_blob(
    c4: &Case,
    ids: &Identities,
    invitation: &InvitationV1,
) -> (LinkDataV1, Vec<u8>, SecretBytes<32>) {
    let link_data = LinkDataV1 {
        inviter_iks: ids.r_identity.public().clone(),
        bundle: PrekeyBundle::decode(&ids.bundle.encode().unwrap()).unwrap(),
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
    c4.expect("k_ld", k_ld.expose_secret());
    c4.expect(
        "linkdata",
        unpad(&link_data.encode().unwrap(), 12_288).unwrap(),
    );
    c4.expect("blob", &blob_bytes);
    (link_data, blob_bytes, k_ld)
}

/// Case 6: the initiator.
fn case_initiator(
    c6: &Case,
    ids: &Identities,
    link_data: &LinkDataV1,
    invitation: &InvitationV1,
    accepted: &InviteeAccepted,
) {
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
    let started = Initiator::start(
        &accepted.invitation,
        &accepted.link_data,
        &ids.i_identity.initiator_keys(),
        &routes,
        &Profile::new("alice", Some(c6.array("avatar_sha256"))).unwrap(),
        1_700_000_001,
        &mut e,
    );
    assert!(started.is_ok(), "{} start", c6.id);
    let (handshake_cells, i_state) = started.unwrap();
    assert_eq!(e.remaining(), 0, "{}: every draw consumed", c6.id);
    let sent = handshake_cells.release(|_| Ok::<(), ()>(())).unwrap();
    for (k, cell) in sent.iter().enumerate() {
        c6.expect(&format!("cell_{k}"), cell.as_bytes());
    }
    assert_eq!(
        digest(&i_state),
        hex(&c6.output("state_post_I")),
        "{} state_post_I",
        c6.id
    );
    assert_eq!(
        hex(i_state.sb_kat()),
        hex(&c6.output("transcript")),
        "{} transcript (sb)",
        c6.id
    );
    derive_checks(c6, &ids.r_identity, &ids.i_identity, link_data, invitation);
}

/// Cases 7 and 8: the responder, from the state after cases 1–4; returns the store after case 7.
fn case_responder(cases: &[Case], world: &World) -> MemoryPrekeyStore {
    let mut after_7 = None;
    for id in ["hx-0007", "hx-0008"] {
        let c = by_id(cases, id);
        let mut store = store_from(&world.store_seed);
        let fetched = cells_of(&c.list("fetched"));
        let mut e = fixed(&[&c.input("dh_sk"), &c.input("kem_seed"), &c.input("m")]);
        let accepted = Responder::accept(
            &fetched,
            &world.record,
            &mut store,
            &world.r_identity.responder_keys(),
            &mut e,
        );
        assert!(accepted.is_ok(), "{} accept", c.id);
        let accepted = accepted.unwrap();
        assert_eq!(e.remaining(), 0, "{}: DH-step draws consumed", c.id);
        c.expect("peer_iks", &accepted.peer.encode().unwrap());
        c.expect("profile", &accepted.profile.encode().unwrap());
        let routes: Vec<String> = accepted
            .routes
            .iter()
            .map(|r| hex(&r.encode().unwrap()))
            .collect();
        let listed: Vec<String> = c
            .outputs
            .get("routes")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(routes, listed, "{} routes", c.id);
        assert_eq!(
            digest(&accepted.state),
            hex(&c.output("state_post_R")),
            "{} state_post_R",
            c.id
        );
        assert_eq!(
            hex(accepted.state.sb_kat()),
            hex(&c.output("transcript")),
            "{} transcript (sb)",
            c.id
        );
        assert_eq!(store.opk_ids(), Vec::<u32>::new(), "{} opks_post", c.id);
        if id == "hx-0007" {
            after_7 = Some(store);
        }
    }
    after_7.unwrap()
}

/// The invitee-reject (V1–V9) and respond-reject (R1–R13) cases.
fn case_rejects(cases: &[Case], world: &World, mut after_7: MemoryPrekeyStore) {
    for c in cases {
        match c.op.as_str() {
            "invitee-reject" => {
                let uri = if c.has_input("uri") {
                    c.in_str("uri").to_owned()
                } else {
                    world.uri.clone()
                };
                let blob = if c.has_input("blob") {
                    c.input("blob")
                } else {
                    world.blob.clone()
                };
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
                    &mut after_7
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
                let expected: Vec<u32> = c
                    .outputs
                    .get("opks_post")
                    .unwrap()
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

#[test]
fn hx_vectors() {
    let file = vector_file();
    assert_eq!(file.get("schema").unwrap(), 5);
    assert_eq!(file.get("suite").unwrap(), "hx");
    let cases: Vec<Case> = file
        .get("cases")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(Case::new)
        .collect();
    assert_eq!(cases.len(), 30);

    let ids = case_identities(&cases);
    let (invitation, invitation_bytes, uri) =
        case_invitation(by_id(&cases, "hx-0003"), &ids.r_identity);
    let (link_data, blob_bytes, k_ld) = case_blob(by_id(&cases, "hx-0004"), &ids, &invitation);

    // case 5: the invitee's checks
    let c5 = by_id(&cases, "hx-0005");
    let accepted = invitee_accept(&uri, &blob_bytes, NOW);
    assert!(accepted.is_ok(), "{} accept", c5.id);
    let accepted = accepted.unwrap();
    let k_inv = derive_k_inv(&invitation.ld_id, &invitation.link_key).unwrap();
    c5.expect("k_ld", k_ld.expose_secret());
    c5.expect("k_inv", k_inv.expose_secret());
    assert_eq!(c5.outputs.get("accept").unwrap(), true, "{} accept", c5.id);

    case_initiator(
        by_id(&cases, "hx-0006"),
        &ids,
        &link_data,
        &invitation,
        &accepted,
    );

    let world = World {
        r_identity: ids.r_identity,
        store_seed: ids.store_seed,
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
    let after_7 = case_responder(&cases, &world);
    case_rejects(&cases, &world, after_7);
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
    let ct_signed: [u8; MLKEM1024_CT_LEN] = c6.output("ct_spk").try_into().unwrap();
    let ct_onetime: [u8; MLKEM1024_CT_LEN] = c6.output("ct_opk").try_into().unwrap();
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
        ct_spk: &ct_signed,
        ct_opk: &ct_onetime,
        ld_id: &invitation.ld_id,
    })
    .unwrap();
    assert_eq!(
        hex(&tr),
        hex(&c6.output("transcript")),
        "{} transcript",
        c6.id
    );
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
    assert_eq!(
        hex(sk.expose_secret()),
        hex(&c6.output("sk")),
        "{} sk",
        c6.id
    );
    let k_id = hx::k_id(
        &invitation.ld_id,
        &invitation.link_key,
        &secret("dh3"),
        &secret("ss_spk"),
        &secret("dh4"),
        &secret("ss_opk"),
    )
    .unwrap();
    assert_eq!(
        hex(k_id.expose_secret()),
        hex(&c6.output("k_id")),
        "{} k_id",
        c6.id
    );
}
