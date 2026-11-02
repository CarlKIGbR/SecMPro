// SPDX-License-Identifier: AGPL-3.0-or-later
//! Store-backed parties on the virtual driver (TEST-SPEC-M7 IN-17, SE-02, SE-03, SE-14, SE-19, AP-05): a profile on disk
//! (the `kat` Argon2 cost), a `Hub` as the client's cell source, and its pool queues made on the relay beforehand. The
//! handshake, the rotation and the retirement then run as scheduled operations of the driver — no set-up link of the
//! `two-clients` kind.

use std::path::PathBuf;

use secmp_client_core::api::{Request, Response};
use secmp_client_core::clock::ManualClock;
use secmp_client_core::hub::{Hub, HubConfig};
use secmp_client_core::invitations::SparePool;
use secmp_client_core::profile::Profile;
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::types::RelayId;
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::Period;
use secmp_proto::wire::inv::{Onion, Profile as WireProfile, RelayRef};
use secmp_proto::{Decode as _, Encode as _};
use secmp_store::kat::TempDir;
use secmp_store::wrap::{Argon2Params, create_kat, unlock_kat};
use secmp_testkit::harness::{EntropyPool, HarnessConfig, START_UNIX, SimClient, VirtualDriver};

/// The passphrase of the test profiles.
pub const PASS: &[u8] = b"correct horse";

/// The hub type of these tests.
pub type TestHub = Hub<ManualClock, EntropyPool>;

/// A store-backed client of the driver.
pub struct Party {
    /// Keeps the profile directory alive.
    pub _root: TempDir,
    /// The profile directory.
    pub dir: PathBuf,
    /// Its name (the entropy streams are named after it).
    pub name: String,
    /// The driver's index.
    pub idx: usize,
    /// The hub's clock (the driver moves it with virtual time).
    pub clock: ManualClock,
}

/// A new virtual world: a relay and no client.
pub fn driver() -> VirtualDriver {
    VirtualDriver::new(HarnessConfig::default())
}

/// The relay reference of the harness relay.
fn relay_ref(d: &VirtualDriver) -> RelayRef {
    RelayRef {
        relay_fp: d.harness().relay_fp(),
        onion: Onion::from_pubkey(&[2; 32]),
        akc: [3; 32],
        direct: None,
    }
}

/// The hub of the profile in `dir`: sessions, queues and invitations registered from the store.
pub fn open_hub(name: &str, dir: &std::path::Path, clock: &ManualClock, epoch: u32) -> TestHub {
    let unlocked = unlock_kat(dir, PASS, Argon2Params::kat_small()).unwrap();
    let profile = Profile::open_with(dir, &unlocked).unwrap();
    hub_of(name, profile, clock, epoch, Period::S10)
}

fn hub_of(
    name: &str,
    profile: Profile,
    clock: &ManualClock,
    epoch: u32,
    period: Period,
) -> TestHub {
    let tag = name.to_owned();
    let mut n = epoch.saturating_mul(10_000);
    let core = secmp_client_core::api::Core::with_profile(profile, clock.clone(), move || {
        n = n.saturating_add(1);
        EntropyPool::new(&format!("{tag}-src"), n)
    })
    .unwrap();
    Hub::new(
        core,
        HubConfig {
            relay: RelayId(1),
            inv_period: period,
            reply_period: period,
            profile: WireProfile::new(name, None).unwrap(),
        },
    )
    .unwrap()
}

/// A party named `name` with `pool` spare queues (made on the relay too), added to `d` as a Strict client with timing seed
/// `seed`.
pub fn add_party(d: &mut VirtualDriver, name: &str, pool: usize, seed: u64) -> Party {
    add_party_mode(d, name, pool, (Mode::Strict, seed))
}

/// [`add_party`] in scheduler mode `mode`.
pub fn add_party_mode(
    d: &mut VirtualDriver,
    name: &str,
    pool: usize,
    (mode, seed): (Mode, u64),
) -> Party {
    add_party_period(d, name, pool, (mode, seed), Period::S10)
}

/// [`add_party_mode`] whose queues (invitation, reply, rotation) have period `period`.
pub fn add_party_period(
    d: &mut VirtualDriver,
    name: &str,
    pool: usize,
    (mode, seed): (Mode, u64),
    period: Period,
) -> Party {
    let root = TempDir::new(name).unwrap();
    let dir = root.path().join("profile");
    std::fs::create_dir_all(&dir).unwrap();
    let unlocked = create_kat(&dir, PASS, Argon2Params::kat_small()).unwrap();
    let clock = ManualClock::new(START_UNIX);
    let mut keys = FixedEntropy::new(&EntropyPool::new(&format!("{name}-keys"), 0).bytes(1 << 21));
    let profile = Profile::create_with(&dir, &unlocked, &clock, &mut keys).unwrap();
    let encoded = relay_ref(d).encode().unwrap();
    profile
        .store()
        .lock()
        .unwrap()
        .txn(|tx| secmp_store::profile::put_relay(tx, 1, &encoded, None))
        .unwrap();
    let spares = SparePool::new(profile.store());
    let mut pool_e =
        FixedEntropy::new(&EntropyPool::new(&format!("{name}-pool"), 0).bytes(1 << 20));
    spares.fill(RelayId(1), pool, &mut pool_e).unwrap();
    let idx = d.add_client(mode, Params::default(), seed);
    d.client(idx).relay = RelayId(1);
    for (_, recv, send) in spares.seeds(RelayId(1)).unwrap() {
        d.new_queue_with(idx, &recv, &send);
    }
    let mut hub = hub_of(name, profile, &clock, 0, period);
    // the profile's mode is the scheduler's (the user's choice, persisted)
    let Response::Settings(mut settings) = hub.core_mut().handle(Request::Settings).unwrap() else {
        unreachable!("Settings is answered with Settings")
    };
    settings.mode = mode;
    hub.core_mut()
        .handle(Request::SetSettings(settings))
        .unwrap();
    d.attach_hub(idx, Box::new(hub));
    Party {
        _root: root,
        dir,
        name: name.to_owned(),
        idx,
        clock,
    }
}

/// Client `i`'s hub.
pub fn hub(d: &mut VirtualDriver, i: usize) -> &mut TestHub {
    d.client(i)
        .hub
        .as_mut()
        .unwrap()
        .any()
        .downcast_mut::<TestHub>()
        .unwrap()
}

/// The invitation up to the point where the invitee has accepted: the inviter and the invitee, the issued invitation's
/// sender id and queue, and the invitee's persisted handshake cells.
pub struct Started {
    /// The inviter.
    pub host: Party,
    /// The invitee.
    pub guest: Party,
    /// The invitation queue's sender id.
    pub inv_sid: [u8; 16],
    /// The invitation queue.
    pub inv_queue: secmp_client_core::scheduler::types::QueueId,
    /// The invitee's persisted handshake cells.
    pub handshake: Vec<Vec<u8>>,
}

/// The cells of the persisted handshake of `contact` on `client`.
pub fn persisted(client: &mut SimClient, contact: i64) -> Vec<Vec<u8>> {
    let hub = client
        .hub
        .as_mut()
        .unwrap()
        .any()
        .downcast_mut::<TestHub>()
        .unwrap();
    let store = hub.profile_store();
    let bytes = store.lock().unwrap().handshake(contact).unwrap().unwrap();
    secmp_proto::hx::PersistedCells::from_bytes(&bytes)
        .unwrap()
        .into_cells()
        .iter()
        .map(|c| c.as_bytes().to_vec())
        .collect()
}

/// An inviter and an invitee (`pool` spare queues each, Strict, one relay): the inviter issues, the `LINK_PUT` runs, the
/// invitee's `LINK_GET` runs and it accepts — all as the driver's scheduled operations, until virtual time 31 s.
pub fn start(d: &mut VirtualDriver, label: &str, pool: usize) -> Started {
    start_seeded(d, label, pool, None)
}

/// What [`invite_pair`] made.
pub struct Invite {
    /// The invitation's URI (a secret).
    pub uri: String,
    /// The invitation's link key (a secret).
    pub link_key: [u8; 32],
    /// The invitation queue's sender id.
    pub inv_sid: [u8; 16],
    /// The invitation queue.
    pub inv_queue: secmp_client_core::scheduler::types::QueueId,
    /// The invitee's contact (the inviter) and its persisted handshake cells.
    pub guest_contact: i64,
    /// The invitee's persisted handshake cells.
    pub handshake: Vec<Vec<u8>>,
}

/// The ids of the contacts of client `i`, ascending.
pub fn contact_ids(d: &mut VirtualDriver, i: usize) -> Vec<i64> {
    use secmp_client_core::api::{Request, Response};

    match hub(d, i).core_mut().handle(Request::Contacts).unwrap() {
        Response::Contacts(c) => c.iter().map(|c| c.id.0).collect(),
        _ => Vec::new(),
    }
}

/// `host` invites `guest`, as the driver's scheduled operations: the `LINK_PUT` on a one-shot link, the `LINK_GET` on another,
/// the accept by the invitee — until 31 s of virtual time have passed.
pub fn invite_pair(d: &mut VirtualDriver, host: &Party, guest: &Party) -> Invite {
    use secmp_client_core::scheduler::types::ControlKind;
    use secmp_testkit::harness::LinkMaterial;

    let before = d.client_ref(host.idx).controls_done.len();
    let issued = hub(d, host.idx).invite(START_UNIX + 5 * 86_400).unwrap();
    let inv_queue = hub(d, host.idx)
        .invitation_queue(&issued.invitation.ld_id)
        .unwrap();
    let t = d.now();
    d.run_until(t.saturating_add(30_000));
    assert!(
        d.client_ref(host.idx)
            .controls_done
            .iter()
            .skip(before)
            .any(|(_, k)| matches!(k, ControlKind::LinkPut(_))),
        "the LINK_PUT ran on a one-shot link"
    );
    let known = contact_ids(d, guest.idx);
    let consumed = d.client_ref(guest.idx).controls_done.len();
    let (ld_id, n) = hub(d, guest.idx).begin_accept(&issued.uri).unwrap();
    d.client(guest.idx).links.insert(
        n,
        LinkMaterial {
            ld_id,
            owner_seed: [0; 32],
            blob: Vec::new(),
            one_time: true,
            expires_bucket: 0,
        },
    );
    let t = d.now();
    d.run_until(t.saturating_add(1_000));
    assert_eq!(d.client_ref(guest.idx).hub_errors, Vec::<String>::new());
    assert!(
        d.client_ref(guest.idx)
            .controls_done
            .iter()
            .skip(consumed)
            .any(|(_, k)| matches!(k, ControlKind::LinkGetConsume(_))),
        "the LINK_GET ran on a one-shot link"
    );
    let guest_contact = *contact_ids(d, guest.idx)
        .iter()
        .find(|c| !known.contains(c))
        .expect("the invitee has a new contact");
    let handshake = persisted(d.client(guest.idx), guest_contact);
    assert_eq!(handshake.len(), 3);
    Invite {
        uri: issued.uri.to_string(),
        link_key: *issued.invitation.link_key.expose_secret(),
        inv_sid: issued.invitation.inv_sid,
        inv_queue,
        guest_contact,
        handshake,
    }
}

/// [`start`] with the timing randomness of the parties seeded.
pub fn start_seeded(
    d: &mut VirtualDriver,
    label: &str,
    pool: usize,
    seeds: Option<(u64, u64)>,
) -> Started {
    start_seeded_mode(d, label, pool, seeds, Mode::Strict)
}

/// [`start_seeded`] with both parties in scheduler mode `mode`.
pub fn start_seeded_mode(
    d: &mut VirtualDriver,
    label: &str,
    pool: usize,
    seeds: Option<(u64, u64)>,
    mode: Mode,
) -> Started {
    use secmp_testkit::harness::Inspect;

    let host = add_party_mode(d, &format!("{label}-host"), pool, (mode, 11));
    let guest = add_party_mode(d, &format!("{label}-guest"), pool, (mode, 12));
    for p in [&host, &guest] {
        d.client(p.idx).opts.inspect = Inspect::Requests;
    }
    if let Some((h, g)) = seeds {
        hub(d, host.idx).seed_timing_kat(h);
        hub(d, guest.idx).seed_timing_kat(g);
    }
    let invite = invite_pair(d, &host, &guest);
    Started {
        host,
        guest,
        inv_sid: invite.inv_sid,
        inv_queue: invite.inv_queue,
        handshake: invite.handshake,
    }
}

/// Two parties with an established session: [`start`], then the virtual clock runs until the invitee has the first reply
/// (and the inviter's invitation queue is in overlap).
pub fn establish(d: &mut VirtualDriver, label: &str, pool: usize) -> Started {
    establish_seeded(d, label, pool, None)
}

/// [`establish`] with the timing randomness of the inviter and of the invitee seeded (runs that repeat, and a choice of the
/// draws: the range of every draw is asserted wherever it matters).
pub fn establish_seeded(
    d: &mut VirtualDriver,
    label: &str,
    pool: usize,
    seeds: Option<(u64, u64)>,
) -> Started {
    let s = start_seeded(d, label, pool, seeds);
    d.run_until(600_000);
    assert_eq!(d.client_ref(s.guest.idx).hub_errors, Vec::<String>::new());
    assert_eq!(d.client_ref(s.host.idx).hub_errors, Vec::<String>::new());
    s
}

/// [`establish_seeded`] with both parties in scheduler mode `mode`.
pub fn establish_seeded_mode(
    d: &mut VirtualDriver,
    label: &str,
    pool: usize,
    seeds: Option<(u64, u64)>,
    mode: Mode,
) -> Started {
    let s = start_seeded_mode(d, label, pool, seeds, mode);
    d.run_until(600_000);
    assert_eq!(d.client_ref(s.guest.idx).hub_errors, Vec::<String>::new());
    assert_eq!(d.client_ref(s.host.idx).hub_errors, Vec::<String>::new());
    s
}

/// The sender id of the first relay-queue route of contact 1 of client `i` — the queue it sends to.
pub fn send_sid(d: &mut VirtualDriver, i: usize) -> [u8; 16] {
    use secmp_proto::wire::cell::{RouteDescriptor, RouteUpdateBody};

    let store = hub(d, i).profile_store();
    let bytes = store
        .lock()
        .unwrap()
        .contact_routes(1)
        .unwrap()
        .expect("routes");
    let body = RouteUpdateBody::decode(&bytes).unwrap();
    body.routes
        .iter()
        .find_map(|r| match r {
            RouteDescriptor::RelayQueue(q) => Some(q.sid),
            RouteDescriptor::Unknown { .. } => None,
        })
        .unwrap()
}

/// How many `SEND`s to the queue `sid` client `i` has written on scheduled links.
pub fn cells_on(d: &VirtualDriver, i: usize, sid: [u8; 16]) -> usize {
    use secmp_proto::wire::frame::RequestCmd;
    use secmp_testkit::harness::CONTROL_SLOT_BASE;

    d.client_ref(i)
        .requests
        .iter()
        .filter(|(_, slot, r)| {
            *slot < CONTROL_SLOT_BASE
                && matches!(&r.cmd, RequestCmd::Send { sid: s, .. } if *s == sid)
        })
        .count()
}

/// The queue id `rid` of the queue with recipient seed `seed` (spec §9.1).
pub fn rid_of(seed: &[u8; 32]) -> [u8; 16] {
    let key = secmp_crypto::Ed25519SigningKey::from_seed(seed).unwrap();
    let pk = secmp_proto::keys::Ed25519Pk::from_bytes(key.verifying_key().as_bytes()).unwrap();
    secmp_proto::link::ids::rid(&pk).unwrap()
}

/// The process of `p` dies and starts again from its profile on disk (a new scheduler, a new hub; the old hub is dropped
/// first, which closes its store). `epoch` names the new life's entropy streams.
pub fn restart_party(d: &mut VirtualDriver, p: &Party, epoch: u32) {
    d.client(p.idx).hub = None;
    let hub = open_hub(&p.name, &p.dir, &p.clock, epoch);
    d.restart_client(
        p.idx,
        Box::new(hub),
        (
            Mode::Strict,
            Params::default(),
            900_u64.saturating_add(u64::from(epoch)),
        ),
    );
}
