// SPDX-License-Identifier: AGPL-3.0-or-later
//! M7 Phase B, the transactional accept (TEST-SPEC-M7 IN-05, IN-06, IN-07, IN-20; `docs/07:149` F-M7/C-12/R-26): the
//! host fetches the three handshake cells of an invitation from a recording relay and decides them with
//! `Invitations::process_round` over a real profile store.
//!
//! The world is two profiles on disk (the `kat` Argon2 cost, the store's own key wrap), each with relay row 1 and two
//! spare queues; the host issues an invitation, the guest accepts it and releases the three cells.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use secmp_client_core::api::{ContactId, Error};
use secmp_client_core::clock::ManualClock;
use secmp_client_core::invitations::{
    AcceptRequest, Invitations, Issuance, IssueRequest, Round, SparePool,
};
use secmp_client_core::profile::Profile;
use secmp_client_core::scheduler::types::RelayId;
use secmp_proto::Encode as _;
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::Period;
use secmp_proto::wire::cell::Cell;
use secmp_proto::wire::inv::{Onion, Profile as WireProfile, RelayRef};
use secmp_store::kat::{CrashAt, FailAt, TempDir};
use secmp_store::profile::{INVITATION_CONSUMED, INVITATION_OPEN, KIND_OPK};
use secmp_store::wrap::{Argon2Params, create_kat, unlock_kat};
use secmp_testkit::harness::EntropyPool;

/// The test's name in this binary (the children re-enter it).
const TEST: &str = "m7_accept::crash_inside_accept_is_atomic";
/// The child role.
const ROLE: &str = "in07";
/// The passphrase of the test profiles.
const PASS: &[u8] = b"correct horse";
/// Unix seconds at the first instant of the clocks.
const T0: u64 = 1_800_000_000;
/// One day.
const DAY: u64 = 86_400;

/// Deterministic entropy of `suite`.
fn entropy(suite: &str) -> FixedEntropy {
    FixedEntropy::new(&EntropyPool::new(suite, 0).bytes(1 << 21))
}

fn relay_ref() -> RelayRef {
    RelayRef {
        relay_fp: [1; 32],
        onion: Onion::from_pubkey(&[2; 32]),
        akc: [3; 32],
        direct: None,
    }
}

fn wire_profile(name: &str) -> WireProfile {
    WireProfile::new(name, None).unwrap()
}

/// A party: its profile (relay 1, two spare queues), clock and entropy.
struct Party {
    _root: Option<TempDir>,
    dir: PathBuf,
    profile: Profile,
    clock: ManualClock,
    e: FixedEntropy,
}

/// Create party `name` in `dir`.
fn party_at(dir: &Path, name: &str, root: Option<TempDir>) -> Party {
    std::fs::create_dir_all(dir).unwrap();
    let unlocked = create_kat(dir, PASS, Argon2Params::kat_small()).unwrap();
    let clock = ManualClock::new(T0);
    let mut e = entropy(name);
    let profile = Profile::create_with(dir, &unlocked, &clock, &mut e).unwrap();
    install_relay(&profile, 2, &mut entropy(&format!("{name}-pool")));
    Party {
        _root: root,
        dir: dir.to_path_buf(),
        profile,
        clock,
        e,
    }
}

/// Create party `name` in a new directory.
fn party(name: &str) -> Party {
    let root = TempDir::new(name).unwrap();
    let dir = root.path().join("profile");
    party_at(&dir, name, Some(root))
}

/// Relay row 1 and `pool` spare queues.
fn install_relay(profile: &Profile, pool: usize, e: &mut FixedEntropy) {
    let store = profile.store();
    let encoded = relay_ref().encode().unwrap();
    store
        .lock()
        .unwrap()
        .txn(|tx| secmp_store::profile::put_relay(tx, 1, &encoded, None))
        .unwrap();
    SparePool::new(store).fill(RelayId(1), pool, e).unwrap();
}

/// An invitation that expires ten days on, issued by `host`.
fn issue(host: &mut Party) -> Issuance {
    Invitations::new(host.profile.clone())
        .issue(
            &IssueRequest {
                relay: RelayId(1),
                inv_period: Period::S10,
                profile: wire_profile("inviter"),
                expires: T0 + 10 * DAY,
            },
            &host.clock,
            &mut host.e,
        )
        .unwrap()
}

/// The three cells of `guest` accepting `issued`.
fn handshake(guest: &mut Party, issued: &Issuance) -> [Cell; 3] {
    let profile = wire_profile("invitee");
    let start = Invitations::new(guest.profile.clone())
        .accept_invitation(
            &issued.uri,
            &issued.blob.encode().unwrap(),
            &AcceptRequest {
                relay: RelayId(1),
                reply_period: Period::S10,
                profile: &profile,
            },
            &guest.clock,
            &mut guest.e,
        )
        .unwrap();
    start.cells
}

/// A copy of a cell.
fn copy(c: &Cell) -> Cell {
    Cell::from_bytes(c.as_bytes()).unwrap()
}

/// A garbage cell.
fn garbage(n: u8) -> Cell {
    Cell::from_bytes(&vec![n; 4096]).unwrap()
}

/// What a recording relay saw of the host's invitation queue, in order.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Fetch(Vec<u64>),
    /// The host's store committed `n` transactions up to here.
    Commits(u64),
    Ack(u64),
    QueueDel,
}

/// The cells on the invitation queue, with the relay's log.
struct Relay {
    cells: Vec<(u64, Cell)>,
    acked: u64,
    log: Vec<Seen>,
}

impl Relay {
    /// The queue holds garbage, the three cells of a handshake (ids 3, 5, 6) and garbage.
    fn with(cells: [Cell; 3]) -> Self {
        let [c0, c1, c2] = cells;
        Self {
            cells: vec![
                (1, garbage(1)),
                (2, garbage(2)),
                (3, c0),
                (4, garbage(4)),
                (5, c1),
                (6, c2),
                (7, garbage(7)),
            ],
            acked: 0,
            log: Vec::new(),
        }
    }

    /// `FETCH`: the cells above the acknowledgement (copies).
    fn fetch(&mut self) -> Vec<(u64, Cell)> {
        let out: Vec<(u64, Cell)> = self
            .cells
            .iter()
            .filter(|(id, _)| *id > self.acked)
            .map(|(id, c)| (*id, copy(c)))
            .collect();
        self.log
            .push(Seen::Fetch(out.iter().map(|(id, _)| *id).collect()));
        out
    }

    /// `ACK` up to `id`: the cells at or below it are deleted.
    fn ack(&mut self, id: u64) {
        self.acked = self.acked.max(id);
        self.cells.retain(|(i, _)| *i > id);
        self.log.push(Seen::Ack(id));
    }
}

/// The rows of the host's store that the accept changes: (OPK 1 present, invitation status, contacts, session).
fn state_of(p: &Profile) -> (bool, Option<i64>, usize, bool) {
    let store = p.store();
    let s = store.lock().unwrap();
    let opk = s.prekeys(KIND_OPK).unwrap().iter().any(|r| r.id == 1);
    let status = s.invitations().unwrap().first().map(|r| r.status);
    let contacts = s.contacts().unwrap().len();
    let session = s.session_rows(1).unwrap().is_some();
    (opk, status, contacts, session)
}

/// The state before an accept: the OPK present, the invitation open, no contact, no session.
const BEFORE: (bool, Option<i64>, usize, bool) = (true, Some(INVITATION_OPEN), 0, false);
/// The state after: the OPK gone, the invitation consumed, one contact, one session.
const AFTER: (bool, Option<i64>, usize, bool) = (false, Some(INVITATION_CONSUMED), 1, true);

/// A world up to the fetch: the host with an invitation, the relay holding the three cells.
fn world(name: &str) -> (Party, Issuance, Relay, Party) {
    let mut host = party(&format!("{name}-a"));
    let mut guest = party(&format!("{name}-b"));
    let issued = issue(&mut host);
    let relay = Relay::with(handshake(&mut guest, &issued));
    (host, issued, relay, guest)
}

/// One accept round over the whole queue.
fn round(host: &mut Party, issued: &Issuance, relay: &mut Relay) -> Result<Round, Error> {
    let fetched = relay.fetch();
    Invitations::new(host.profile.clone()).process_round(
        &issued.invitation.ld_id,
        &fetched,
        &host.clock,
        &mut host.e,
    )
}

/// The statements of the accept transaction of a world (a dry run).
fn accept_statements() -> usize {
    let (mut host, issued, mut relay, _invitee) = world("n-statements");
    secmp_store::kat::reset_counters();
    round(&mut host, &issued, &mut relay).unwrap();
    let log = secmp_store::kat::txn_log();
    assert!(!log.is_empty());
    log.len()
}

/// IN-05 (F-M7, C-12; `docs/07:149`; `prekeys.rs:382-390`): the host fetches the three cells from a recording relay.
/// The accept is one store transaction — the OPK row delete, the record's consumption, the contact (peer, routes,
/// profile) and the session (`Accepted.state` in its parts) — and the relay is told to acknowledge a cell only after that
/// commit is durable; the queue is not retired before it. The trace (the transaction log and the sequence at the relay)
/// is written to `target/m7-evidence/in-05-accept-trace.txt` (the evidence file `in-05-accept-trace-<sha7>.txt`).
#[test]
fn commit_with_accepted_before_any_ack() {
    let (mut host, issued, mut relay, guest) = world("in05");
    secmp_store::kat::reset_counters();
    let commits0 = secmp_store::kat::store_txn_commits();

    let r = round(&mut host, &issued, &mut relay).unwrap();
    let commits = secmp_store::kat::store_txn_commits() - commits0;
    relay.log.push(Seen::Commits(commits));
    // the acknowledgement is asked for only now, after the commit returned
    let ack = r.ack_through.unwrap();
    assert_eq!(relay.acked, 0, "no acknowledgement before the commit");
    relay.ack(ack);

    // one transaction decided the round, and it holds everything the accept changes
    assert_eq!(commits, 1, "exactly one store transaction");
    let log = secmp_store::kat::txn_log();
    assert!(log.iter().all(|(seq, _, _)| *seq == 1), "{log:?}");
    let has = |table: &str, verb: &str| log.iter().any(|(_, t, v)| *t == table && *v == verb);
    assert!(has("prekeys", "delete"), "the OPK row is deleted");
    assert!(has("invitations", "update"), "the record is consumed");
    assert!(has("contacts", "insert"), "the contact row");
    assert!(has("sessions", "insert"), "the session rows");
    assert!(r.ops.is_empty(), "the queue is not retired in the accept");
    assert!(!relay.log.contains(&Seen::QueueDel));
    assert_eq!(r.accepted, Some(ContactId(1)));
    assert_eq!(ack, 7, "the whole fetch is decided");
    assert_eq!(state_of(&host.profile), AFTER);

    // the contact holds the peer, its reply routes and its profile
    {
        let store = host.profile.store();
        let s = store.lock().unwrap();
        let contacts = s.contacts().unwrap();
        let c = contacts.first().unwrap();
        assert_eq!(c.fingerprint, guest.profile.fingerprint().unwrap());
        assert!(!c.verified);
        assert_eq!(c.display_name.as_deref(), Some("invitee"));
        let routes = s.contact_routes(1).unwrap().unwrap();
        assert_eq!(routes.first(), Some(&1), "one reply route");
        assert!(s.session_rows(1).unwrap().is_some());
    }
    // the order at the relay: fetch, the commit, the acknowledgement
    assert_eq!(
        relay.log,
        [
            Seen::Fetch(vec![1, 2, 3, 4, 5, 6, 7]),
            Seen::Commits(1),
            Seen::Ack(7)
        ]
    );
    {
        let mut text = String::from(
            "IN-05 transactional accept: the host fetches the three handshake cells (ids 3, 5, 6 among garbage 1, 2, 4, 7)\n\
             from a recording relay; kat::txn_log() of the round (txn seq, table, verb):\n",
        );
        for (seq, table, verb) in &log {
            writeln!(text, "  txn {seq}: {verb:<6} {table}").unwrap();
        }
        text.push_str("sequence at the relay:\n");
        for e in &relay.log {
            writeln!(text, "  {e:?}").unwrap();
        }
        writeln!(
            text,
            "store transactions committed by the round: {commits}; acknowledged only after the commit; QUEUE_DEL not asked for"
        )
        .unwrap();
        crate::m7_persist::evidence("in-05-accept-trace", &text);
    }
}

/// IN-06 (R-26; `docs/07:149`): `FailAt(k)` for every statement `k` of the accept transaction gives
/// `Error::Unavailable` with the OPK present, the record open, no contact, no session and nothing acknowledged
/// (the call is an error, the relay is not told); the guest's byte-identical cells, fetched again, are accepted
/// afterwards.
#[test]
fn commit_failure_is_unavailable() {
    let statements = accept_statements();
    assert!(
        statements >= 6,
        "the accept transaction has {statements} statements"
    );
    let (mut host, issued, mut relay, _invitee) = world("in06");
    for k in 1..=u32::try_from(statements).unwrap() {
        secmp_store::kat::fail_at(FailAt(k));
        let r = round(&mut host, &issued, &mut relay);
        assert_eq!(r.err(), Some(Error::Unavailable), "statement {k}");
        assert_eq!(state_of(&host.profile), BEFORE, "statement {k}");
        assert_eq!(relay.acked, 0, "nothing acknowledged after statement {k}");
        let store = host.profile.store();
        assert!(
            store
                .lock()
                .unwrap()
                .invitation_retained(&issued.invitation.ld_id)
                .unwrap()
                .is_none(),
            "statement {k}: nothing retained either"
        );
    }
    // the same cells again (the relay still has them): accepted
    let r = round(&mut host, &issued, &mut relay).unwrap();
    assert_eq!(r.accepted, Some(ContactId(1)));
    assert_eq!(state_of(&host.profile), AFTER);
}

/// The variables of the child of IN-07.
fn var(k: &str) -> String {
    std::env::var(k).unwrap()
}

/// The child of IN-07: reopen the host's profile from disk, arm `point`, decide the cells — the process aborts there.
fn child() {
    let dir = PathBuf::from(var("SECMP_IN07_DIR"));
    let point = match var("SECMP_IN07_POINT").as_str() {
        "after-commit" => CrashAt::AfterCommitBeforeAck,
        k => CrashAt::MidTxn(k.parse().unwrap()),
    };
    let unlocked = unlock_kat(&dir.join("a"), PASS, Argon2Params::kat_small()).unwrap();
    let profile = Profile::open_with(&dir.join("a"), &unlocked).unwrap();
    let ld_id: [u8; 16] = std::fs::read(dir.join("ld_id"))
        .unwrap()
        .try_into()
        .unwrap();
    let bytes = std::fs::read(dir.join("cells")).unwrap();
    let fetched: Vec<(u64, Cell)> = bytes
        .chunks(4096)
        .zip(1_u64..)
        .map(|(c, id)| (id, Cell::from_bytes(c).unwrap()))
        .collect();
    let clock = ManualClock::new(T0);
    secmp_store::kat::arm_crash(point, 1);
    let r = Invitations::new(profile).process_round(
        &ld_id,
        &fetched,
        &clock,
        &mut entropy("in07-child"),
    );
    // reached only if the crash point did not fire: the child ends successfully, which the parent refuses
    drop(r);
    std::process::exit(0);
}

/// IN-07 [E2E, process]: `CrashAt::MidTxn(k)` for every statement `k` of the accept transaction — and the crash after the
/// commit, before the acknowledgement — in a child process; the profile reopened from disk is all-before (the OPK, the
/// record, the contact and the session together) after a crash inside the transaction, and all-after after the commit;
/// never in between.
#[test]
fn crash_inside_accept_is_atomic() {
    if secmp_store::kat::child_role().as_deref() == Some(ROLE) {
        child();
        return;
    }
    let statements = accept_statements();
    let mut points: Vec<String> = (1..=statements).map(|k| k.to_string()).collect();
    points.push("after-commit".to_owned());
    for point in points {
        let root = TempDir::new("in07").unwrap();
        let dir = root.path();
        let (ld_id, cells) = {
            let (a_dir, b_dir) = (dir.join("a"), dir.join("b"));
            std::fs::create_dir_all(&a_dir).unwrap();
            std::fs::create_dir_all(&b_dir).unwrap();
            let mut host = party_at(&a_dir, "in07-a", None);
            let mut guest = party_at(&b_dir, "in07-b", None);
            let issued = issue(&mut host);
            let cells = handshake(&mut guest, &issued);
            let all: Vec<u8> = [garbage(1), garbage(2)]
                .iter()
                .chain(cells.iter())
                .flat_map(|c| c.as_bytes().to_vec())
                .collect();
            (issued.invitation.ld_id, all)
        };
        std::fs::write(dir.join("ld_id"), ld_id).unwrap();
        std::fs::write(dir.join("cells"), &cells).unwrap();
        let ok = secmp_store::kat::run_child(
            TEST,
            ROLE,
            &[
                ("SECMP_IN07_DIR", dir),
                ("SECMP_IN07_POINT", Path::new(&point)),
            ],
        )
        .unwrap();
        assert!(!ok, "point {point}: the child aborts at its crash point");

        let unlocked = unlock_kat(&dir.join("a"), PASS, Argon2Params::kat_small()).unwrap();
        let profile = Profile::open_with(&dir.join("a"), &unlocked).unwrap();
        let state = state_of(&profile);
        if point == "after-commit" {
            assert_eq!(state, AFTER, "point {point}: all-after");
        } else {
            assert_eq!(state, BEFORE, "point {point}: all-before");
        }
        assert!(state == BEFORE || state == AFTER);
    }
}

/// IN-20 (F-13; M05 review P-12/R-56): one invitation record duplicated into two stores (two host profiles built from
/// the same entropy: the same keys, prekeys, queue and record — the sealed records' plaintexts are asserted byte-identical;
/// not `InvitationRecord::duplicate_kat`, which copies the record without the prekeys it names, B-3b D-B13), two
/// initiators with different identities but the same handshake entropy — `K_id` (kat accessor) is equal on both sides and
/// in both stores, `SK` differs: `K_id` does not depend on the initiator's identity, `SK` does.
#[test]
fn k_id_independent_end_to_end() {
    type Run = (Vec<u8>, Vec<u8>, [u8; 32], [u8; 32], Party, Issuance, Relay);
    let handshake_of = |seed: &str| -> Run {
        let mut host = party("in20-a");
        let issued = issue(&mut host);
        let record = host
            .profile
            .store()
            .lock()
            .unwrap()
            .invitation_record(&issued.invitation.ld_id)
            .unwrap()
            .unwrap()
            .to_vec();
        // the initiator's identity differs (its own profile entropy); its handshake entropy is the same for both
        let mut guest = party(&format!("in20-{seed}"));
        guest.e = entropy("in20-handshake");
        let cells = handshake(&mut guest, &issued);
        let k_initiator = secmp_proto::hx::k_id_kat().unwrap();
        let sk = secmp_proto::hx::sk_digest_kat().unwrap();
        let relay = Relay::with(cells);
        (
            issued.invitation.ld_id.to_vec(),
            record,
            k_initiator,
            sk,
            host,
            issued,
            relay,
        )
    };
    let (ld1, rec1, k1, sk1, mut inv1, iss1, mut relay1) = handshake_of("x");
    round(&mut inv1, &iss1, &mut relay1).unwrap();
    let responder1 = secmp_proto::hx::k_id_kat().unwrap();
    let (ld2, rec2, k2, sk2, mut inv2, iss2, mut relay2) = handshake_of("y");
    round(&mut inv2, &iss2, &mut relay2).unwrap();
    let responder2 = secmp_proto::hx::k_id_kat().unwrap();
    assert_eq!(ld1, ld2, "the same invitation record in both stores");
    assert_eq!(rec1, rec2, "the record is byte-identical in both stores");
    assert_eq!(k1, k2, "K_id of the initiators");
    assert_eq!(responder1, responder2, "K_id of the responders");
    assert_eq!(
        k1, responder1,
        "initiator and responder derive the same K_id"
    );
    assert_ne!(sk1, sk2, "SK depends on the initiator's identity");
}

/// IN-14 (§6.5 `docs/03:342`, Q150): the invitee accepts, sends cell 0 of its handshake and the process dies; started again
/// from the store it sends the three cells — cells 1 and 2 among them, and any retry of a cell whose send failed — byte for
/// byte as persisted at the accept (`sessions` part 4). Nothing is encrypted again: the actor's `tr_encrypt_calls` does not move; the one encryption
/// of the envelope is `Initiator::start`'s, in `secmp-proto`, which has no counter (the row's "= 1", read as this).
#[test]
fn initiator_cells_byte_identical_after_restart() {
    use secmp_client_core::scheduler::types::{CellSource, QueueId, SendFailure};
    use secmp_client_core::sessions::actor::{Conversations, counters};
    use secmp_client_core::sessions::open_conversation;

    let mut host = party("in14-host");
    let issued = issue(&mut host);
    let mut guest = party("in14-guest");
    let profile = wire_profile("invitee");
    let start = Invitations::new(guest.profile.clone())
        .accept_invitation(
            &issued.uri,
            &issued.blob.encode().unwrap(),
            &AcceptRequest {
                relay: RelayId(1),
                reply_period: Period::S10,
                profile: &profile,
            },
            &guest.clock,
            &mut guest.e,
        )
        .unwrap();
    let want: Vec<Vec<u8>> = start.cells.iter().map(|c| c.as_bytes().to_vec()).collect();
    let (contact, encrypts) = (start.contact, counters::tr_encrypt_calls());
    let life = |profile: &Profile, n: u32| -> Conversations<_, _, EntropyPool> {
        let conversation = open_conversation(
            &profile.store(),
            contact,
            EntropyPool::new("in14-src", n),
            0,
        )
        .unwrap();
        let mut convs = Conversations::new();
        let at = convs.add(conversation);
        convs.get_mut(at).unwrap().bind(QueueId(1), QueueId(2));
        convs
    };

    // first life: cell 0 is the first cell persisted at the accept
    let mut convs = life(&guest.profile, 1);
    let first = convs.prepare_cell(QueueId(1), 0).unwrap().unwrap();
    assert_eq!(first.cell.as_bytes(), want.first().unwrap().as_slice());
    convs.relayed(QueueId(1), first.token, 1);
    drop(convs);

    // the process dies: the store is closed and opened again from disk
    let Party { dir, profile, .. } = guest;
    drop(profile);
    let unlocked = unlock_kat(&dir, PASS, Argon2Params::kat_small()).unwrap();
    let profile = Profile::open_with(&dir, &unlocked).unwrap();

    // second life: what was in flight at the crash is not known to have arrived, so the three persisted cells go out again,
    // in order, byte for byte; a send that failed is retried with the same bytes
    let mut convs = life(&profile, 2);
    for (n, token_cell) in [(1_u64, 0_usize), (2, 1)] {
        let sent = convs.prepare_cell(QueueId(1), n * 10_000).unwrap().unwrap();
        assert_eq!(
            sent.cell.as_bytes(),
            want.get(token_cell).unwrap().as_slice()
        );
        convs.relayed(QueueId(1), sent.token, n);
    }
    let third = convs.prepare_cell(QueueId(1), 30_000).unwrap().unwrap();
    assert_eq!(third.cell.as_bytes(), want.get(2).unwrap().as_slice());
    convs.send_failed(QueueId(1), third.token, SendFailure::Unknown);
    let retry = convs.prepare_cell(QueueId(1), 40_000).unwrap().unwrap();
    assert_eq!(
        retry.cell.as_bytes(),
        want.get(2).unwrap().as_slice(),
        "the retry"
    );
    convs.relayed(QueueId(1), retry.token, 3);
    // nothing was encrypted again, and the first thing sealed afterwards is not a handshake cell
    assert_eq!(counters::tr_encrypt_calls(), encrypts);
    let after = convs.prepare_cell(QueueId(1), 50_000).unwrap().unwrap();
    assert!(want.iter().all(|w| w.as_slice() != after.cell.as_bytes()));
    assert_eq!(counters::tr_encrypt_calls(), encrypts + 1);
}
