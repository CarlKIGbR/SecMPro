// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fixtures of the SecMP-INV/HX tests: an inviter with its store and one issued invitation, an invitee identity,
//! and the honest initiator run. Built only from the library's public API; the independent re-computations the
//! negative tests need live in `hx_harness.rs`.

use secmp_crypto::{SecretBytes, X25519Secret};
use secmp_proto::hx::{HandshakeCells, Initiator, ResponderKeys};
use secmp_proto::inv::{invitation_uri, invitee_accept};
use secmp_proto::keys::X25519Pk;
use secmp_proto::prekeys::{IdentityKeys, InvitationRecord, IssueParams, Issued, MemoryPrekeyStore};
use secmp_proto::tr::{Entropy, RatchetState};
use secmp_proto::wire::cell::{Cell, RelayQueue, RouteDescriptor};
use secmp_proto::wire::inv::{InvitationV1, LinkDataV1, Onion, Profile, RelayRef};
use secmp_proto::wire::Period;

pub const CREATED: u64 = 1_700_000_000;
pub const NOW: u64 = 1_700_000_100;
pub const EXPIRES: u64 = 1_702_592_000;

pub fn relay_ref(seed: u8) -> RelayRef {
    RelayRef {
        relay_fp: [seed; 32],
        onion: Onion::from_pubkey(&[seed.wrapping_add(1); 32]),
        akc: [seed.wrapping_add(2); 32],
        direct: None,
    }
}

pub fn route(seed: u8) -> RouteDescriptor {
    RouteDescriptor::RelayQueue(RelayQueue {
        relay: relay_ref(seed),
        sid: [seed.wrapping_add(3); 16],
        send_seed: SecretBytes::from_slice(&[seed.wrapping_add(4); 32]).unwrap(),
        period_s: Period::S20,
    })
}

/// The inviter: identity, prekey store, and one issued invitation with its URI.
pub struct Inviter {
    pub identity: IdentityKeys,
    pub store: MemoryPrekeyStore,
    pub issued: Issued,
    pub uri: String,
}

impl Inviter {
    pub fn new(entropy: &mut impl Entropy) -> Self {
        let identity = IdentityKeys::generate(entropy).unwrap();
        let mut store = MemoryPrekeyStore::default();
        let issued = store
            .issue_invitation(
                &identity,
                IssueParams {
                    relay: relay_ref(10),
                    inv_period: Period::S20,
                    profile: Profile::new("bob", None).unwrap(),
                    now: CREATED,
                    expires: EXPIRES,
                    spk_expiry: EXPIRES,
                },
                entropy,
            )
            .unwrap();
        let uri = invitation_uri(&issued.invitation).unwrap();
        Self {
            identity,
            store,
            issued,
            uri,
        }
    }

    pub fn record(&self) -> &InvitationRecord {
        self.store.record(&self.issued.invitation.ld_id).unwrap()
    }

    pub fn keys(&self) -> ResponderKeys<'_> {
        self.identity.responder_keys()
    }
}

/// The honest initiator run: invitee identity, the verified invitation and link data, the three cells and the
/// initiator's state.
pub struct Invitee {
    pub identity: IdentityKeys,
    pub invitation: InvitationV1,
    pub link_data: LinkDataV1,
    pub cells: Vec<Cell>,
    pub state: RatchetState,
}

pub fn invitee_run(inviter: &Inviter, entropy: &mut impl Entropy) -> Invitee {
    let identity = IdentityKeys::generate(entropy).unwrap();
    let accepted = invitee_accept(&inviter.uri, &blob_bytes(&inviter.issued), NOW).unwrap();
    let (cells, state) = Initiator::start(
        &accepted.invitation,
        &accepted.link_data,
        &identity.initiator_keys(),
        &[route(20)],
        &Profile::new("alice", Some([9; 32])).unwrap(),
        NOW + 1,
        entropy,
    )
    .unwrap();
    let cells = release(cells);
    Invitee {
        identity,
        invitation: accepted.invitation,
        link_data: accepted.link_data,
        cells,
        state,
    }
}

pub fn release(cells: HandshakeCells) -> Vec<Cell> {
    cells.release(|_| Ok::<(), ()>(())).unwrap().to_vec()
}

pub fn blob_bytes(issued: &Issued) -> Vec<u8> {
    use secmp_proto::Encode;
    issued.blob.encode().unwrap().to_vec()
}

pub fn x25519_pk(secret: &X25519Secret) -> X25519Pk {
    X25519Pk::from_bytes(secret.public_key().as_bytes()).unwrap()
}
