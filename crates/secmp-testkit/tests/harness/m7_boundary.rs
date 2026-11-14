// SPDX-License-Identifier: AGPL-3.0-or-later
//! TEST-SPEC-M7 AP-05 (Q153, Q166; `docs/07:147`, §12.2 `docs/03:748`): the dynamic identifier oracle. A virtual run — three
//! parties, two invitations, messages, a verification, a rotation and a key change — over real stores; every request the
//! clients wrote (decoded from the frames on the scheduled links and on the control links) is searched for the canary set:
//! message texts, display names, fingerprints, identity keys, the safety number, the invitation's link key and URI, the
//! passphrase, and the store row ids (which start at a random 64-bit offset, so that a search for them means something).

use secmp_client_core::api::{ContactId, Request, Response};
use secmp_crypto::Zeroizing;
use secmp_proto::Encode as _;
use secmp_testkit::harness::{EntropyPool, Inspect, VirtualDriver};

use super::m7_world::{PASS, Party, add_party, driver, hub, invite_pair};

/// Contact rows of this run start above this offset: a placeholder row (removed, without a session) takes the id.
fn offset_ids(d: &mut VirtualDriver, p: &Party, offset: i64) {
    let store = hub(d, p.idx).profile_store();
    store
        .lock()
        .unwrap()
        .txn(|tx| {
            secmp_store::contacts::put_contact(
                tx,
                &secmp_store::contacts::Contact {
                    id: offset,
                    iks: &[0; 8],
                    fingerprint: &[0; 32],
                    display_name: None,
                    verified: false,
                    routes: None,
                    queues: None,
                    state: secmp_store::contacts::STATE_REMOVED,
                    profile: None,
                },
            )
        })
        .unwrap();
}

fn hex(bytes: &[u8], upper: bool) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|b| {
            let s = if upper {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            };
            s.into_bytes()
        })
        .collect()
}

fn utf16le(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// The plaintext of every request client `i` wrote.
fn plaintexts(d: &VirtualDriver, i: usize) -> Vec<Vec<u8>> {
    let c = d.client_ref(i);
    c.requests
        .iter()
        .map(|(_, _, r)| r)
        .chain(
            c.control_requests
                .iter()
                .flat_map(|(_, _, reqs)| reqs.iter()),
        )
        .map(|r| r.encode().unwrap().to_vec())
        .collect()
}

const OWN_NAME: &str = "Alpha-Own-Canary-5a1e0f33";
const NAME_B: &str = "Zebulon-Canary-b00b1e55";
const NAME_C: &str = "Zebulon-Canary-c0de0042";
const TEXTS: [&str; 2] = ["CANARY-MSG-0123456789abcdef", "CANARY-MSG-fedcba9876543210"];

/// Run `ms` virtual milliseconds on.
fn advance(sim: &mut VirtualDriver, ms: u64) {
    let now = sim.now();
    sim.run_until(now.saturating_add(ms));
}

/// The answer of `party`'s core to `request`.
fn ask(sim: &mut VirtualDriver, party: &Party, request: Request) -> Response {
    hub(sim, party.idx).core_mut().handle(request).unwrap()
}

/// What the oracle looks for.
#[derive(Default)]
struct Canaries(Vec<(String, Vec<u8>)>);

impl Canaries {
    fn note(&mut self, what: &str, bytes: Vec<u8>) {
        self.0.push((what.to_owned(), bytes));
    }

    /// The public identity of `party`: fingerprint (raw, hex, HEX) and the first 32 bytes of each component of its `IKSPublic`
    /// (ed25519 32 ‖ ML-DSA-65 1952 ‖ x25519 32).
    fn identity(&mut self, sim: &mut VirtualDriver, party: &Party) {
        let fingerprint = hub(sim, party.idx).own_fingerprint().unwrap();
        self.note("fingerprint raw", fingerprint.to_vec());
        self.note("fingerprint hex", hex(&fingerprint, false));
        self.note("fingerprint HEX", hex(&fingerprint, true));
        let iks = hub(sim, party.idx).own_iks().unwrap();
        for (label, at) in [("ik_ed", 0_usize), ("ik_mldsa", 32), ("ik_dh", 1_984)] {
            let component = iks.get(at..at.saturating_add(32)).unwrap().to_vec();
            self.note(label, component);
        }
    }

    /// Search every request plaintext of `clients` for every canary; returns how many plaintexts were searched.
    fn scan(&self, sim: &VirtualDriver, clients: &[usize]) -> usize {
        let mut searched = 0_usize;
        for client in clients {
            for plain in plaintexts(sim, *client) {
                searched = searched.saturating_add(1);
                for (what, bytes) in &self.0 {
                    assert!(
                        !bytes.is_empty() && !contains(&plain, bytes),
                        "client {client}: {what} occurs in a request plaintext"
                    );
                }
            }
        }
        searched
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The contact of `owner` whose fingerprint is `peer`'s own — the handshakes' links start at random phases, so the order the
/// contacts were made in is not the order of the invitations.
fn contact_of(sim: &mut VirtualDriver, owner: &Party, peer: &Party) -> i64 {
    let fingerprint = hub(sim, peer.idx).own_fingerprint().unwrap();
    let Response::Contacts(list) = ask(sim, owner, Request::Contacts) else {
        unreachable!("Contacts is answered with Contacts")
    };
    list.iter()
        .find(|contact| contact.fingerprint == fingerprint)
        .unwrap()
        .id
        .0
}

/// Both sides type the safety number of the contact `(owner, contact)` and `(peer, peer_contact)`; returns its digits.
fn verify_both(
    sim: &mut VirtualDriver,
    (owner, contact): (&Party, i64),
    (peer, peer_contact): (&Party, i64),
) -> String {
    let Response::SafetyNumber(digits) = ask(
        sim,
        owner,
        Request::SafetyNumber {
            contact: ContactId(contact),
        },
    ) else {
        unreachable!("SafetyNumber is answered with SafetyNumber")
    };
    for (party, id) in [(owner, contact), (peer, peer_contact)] {
        let answer = ask(
            sim,
            party,
            Request::Verify {
                contact: ContactId(id),
                digits: digits.clone(),
            },
        );
        assert!(matches!(answer, Response::Verified(true)));
    }
    digits
}

/// The rest of the canary set, and the search of every request plaintext of the three parties.
fn search(
    sim: &mut VirtualDriver,
    parties: [&Party; 3],
    canaries: &mut Canaries,
    invitation_sid: [u8; 16],
) {
    let [host, first, second] = parties;
    // the rest of the canary set, and the search
    for (label, bytes) in [
        ("own name", OWN_NAME.as_bytes().to_vec()),
        ("name first", NAME_B.as_bytes().to_vec()),
        ("name second", NAME_C.as_bytes().to_vec()),
        ("name first utf-16", utf16le(NAME_B)),
        ("passphrase", PASS.to_vec()),
    ] {
        canaries.note(label, bytes);
    }
    for party in parties {
        canaries.identity(sim, party);
    }
    let clients = [host.idx, first.idx, second.idx];
    let searched = canaries.scan(sim, &clients);
    assert!(searched > 1_000, "{searched} request plaintexts searched");

    // the oracle is not blind: the sender id of an invitation queue, which a `SEND` names, is found in the plaintexts of the
    // invitee, and a canary planted in a plaintext is found
    let sid = invitation_sid.as_slice();
    assert!(
        plaintexts(sim, first.idx)
            .iter()
            .any(|plain| contains(plain, sid)),
        "the invitation queue's sender id is in the invitee's SENDs"
    );
    let canary = canaries.0.first().map(|(_, bytes)| bytes.clone()).unwrap();
    assert!(contains(&[canary.as_slice(), b"padding"].concat(), &canary));
}

/// AP-05: no canary and no row id occurs in any request plaintext of the run.
#[test]
fn no_identifiers_in_request_plaintexts() {
    let mut sim = driver();
    let host = add_party(&mut sim, OWN_NAME, 8, 21);
    let first = add_party(&mut sim, NAME_B, 3, 22);
    let second = add_party(&mut sim, NAME_C, 3, 23);
    for party in [&host, &first, &second] {
        sim.client(party.idx).opts.inspect = Inspect::Requests;
    }
    // row ids start at a random 60-bit offset
    let offset = i64::from_be_bytes(
        <[u8; 8]>::try_from(EntropyPool::new("ap05-ids", 0).bytes(8).as_slice()).unwrap(),
    ) & 0x0fff_ffff_ffff_fff0;
    for party in [&host, &first, &second] {
        offset_ids(&mut sim, party, offset);
    }
    let mut canaries = Canaries::default();

    // two invitations: the host invites both
    let to_first = invite_pair(&mut sim, &host, &first);
    let to_second = invite_pair(&mut sim, &host, &second);
    for (label, invite) in [("first", &to_first), ("second", &to_second)] {
        canaries.note(&format!("link_key {label}"), invite.link_key.to_vec());
        canaries.note(&format!("uri {label}"), invite.uri.clone().into_bytes());
    }
    advance(&mut sim, 600_000);
    let host_first = contact_of(&mut sim, &host, &first);
    let host_second = contact_of(&mut sim, &host, &second);
    let ids = [
        host_first,
        host_second,
        to_first.guest_contact,
        to_second.guest_contact,
        offset,
    ];
    for id in ids {
        assert!(id >= offset);
        canaries.note("row id BE", id.to_be_bytes().to_vec());
        canaries.note("row id LE", id.to_le_bytes().to_vec());
    }

    // messages, a verification, a rotation, a key change
    for text in TEXTS {
        for (party, contact) in [
            (&host, host_first),
            (&first, to_first.guest_contact),
            (&host, host_second),
        ] {
            let payload = Zeroizing::new(text.as_bytes().to_vec());
            let sent = ask(
                &mut sim,
                party,
                Request::Send {
                    contact: ContactId(contact),
                    kind: 1,
                    payload,
                    expire_after: 0,
                },
            );
            assert!(matches!(sent, Response::Sent(_)));
        }
        canaries.note("text", text.as_bytes().to_vec());
        canaries.note("text utf-16", utf16le(text));
    }
    let digits = verify_both(
        &mut sim,
        (&host, host_first),
        (&first, to_first.guest_contact),
    );
    canaries.note("sas digits", digits.replace(' ', "").into_bytes());
    canaries.note("sas", digits.into_bytes());
    advance(&mut sim, 300_000);
    let rotated = ask(
        &mut sim,
        &host,
        Request::Rotate {
            contact: ContactId(host_first),
            relay: 1,
        },
    );
    assert!(matches!(rotated, Response::Rotated(true)));
    advance(&mut sim, 300_000);
    let changed = ask(&mut sim, &first, Request::RotateIdentity);
    assert!(matches!(changed, Response::IdentityRotated(_)));
    advance(&mut sim, 1_800_000);
    for party in [&host, &first, &second] {
        assert_eq!(sim.client_ref(party.idx).hub_errors, Vec::<String>::new());
    }

    search(
        &mut sim,
        [&host, &first, &second],
        &mut canaries,
        to_first.inv_sid,
    );
}
