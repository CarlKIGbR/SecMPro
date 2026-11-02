// SPDX-License-Identifier: AGPL-3.0-or-later
//! TEST-SPEC-M7 SE-19 (REDICT-B E6; §10.1 `docs/03:656`, `docs/06` §4; F14): the emission of a store-backed client does not
//! depend on its activity. Six hours of virtual time, every party's profile on disk, a commit that completes `U[0, 200] ms`
//! late (on the worker, never on a tick, Q160); the client under test has two contacts, a third joins at hour two by an
//! invitation it accepts, and it rotates a queue at hour three; the activity of the active run is the user's sends, the
//! peers' sends, a verification, a peer's key change and the user's re-verification, an invalid key change (the session
//! freezes), a reset request, a removal and a contact that came from a backup (`ReinviteRequired`) — with the sends the user
//! tries in each of these states, which are refused. The idle run has the structural events only (the invitations, the
//! rotation: a new queue starts a link at a random phase, §10.6 (1)). **The C2R trace of the client under test is the idle
//! trace** (same frames, same links, `|Δt| ≤ 5 ms`), in every mode.

use secmp_client_core::api::{ContactId, Error, Request, Response};
use secmp_client_core::scheduler::params::Mode;
use secmp_crypto::Zeroizing;
use secmp_proto::prekeys::IdentityKeys;
use secmp_proto::tr::{Entropy as _, FixedEntropy};
use secmp_proto::wire::Period;
use secmp_testkit::harness::{CONTROL_SLOT_BASE, Dir, EntropyPool, Trace, VirtualDriver};

use super::m6_activity::par_map;
use super::m6_common::{evidence, max_dt};
use super::m6_rand::Mix;
use super::m7_world::{Party, add_party, add_party_period, driver, hub, invite_pair};

const HOURS: u64 = 6;
const HOUR_MS: u64 = 3_600_000;

/// What happens in the active run.
#[derive(Clone, Copy, Debug)]
enum Act {
    UserSend(usize),
    PeerSend(usize),
    ReinviteRow,
    VerifyFirst,
    FirstKeyChange,
    ReverifyFirst,
    InvalidKeyChange,
    ThirdReset,
    ThirdRemove,
}

/// A value in `[lo, hi)`.
fn within(mix: &mut Mix, lo: u64, hi: u64) -> u64 {
    lo.saturating_add(mix.below(hi.saturating_sub(lo).max(1)))
}

/// The activity of one run: sends spread over the six hours, and the state changes at random times inside their windows.
fn activity(seed: u64) -> Vec<(u64, Act)> {
    let mut mix = Mix::new(0x5e19_0000 ^ seed);
    let end = HOURS.saturating_mul(HOUR_MS);
    let mut events = Vec::new();
    for _ in 0..160 {
        let user = usize::try_from(mix.below(3)).unwrap();
        events.push((within(&mut mix, 120_000, end), Act::UserSend(user)));
        let peer = usize::try_from(mix.below(3)).unwrap();
        events.push((within(&mut mix, 120_000, end), Act::PeerSend(peer)));
    }
    let hour = |count: u64| count.saturating_mul(HOUR_MS);
    let after = |count: u64, extra: u64| hour(count).saturating_add(extra);
    let half = HOUR_MS / 2;
    events.push((within(&mut mix, 60_000, 600_000), Act::ReinviteRow));
    events.push((within(&mut mix, hour(1), after(1, half)), Act::VerifyFirst));
    events.push((
        within(&mut mix, after(1, half), hour(2)),
        Act::InvalidKeyChange,
    ));
    events.push((
        within(
            &mut mix,
            after(2, half),
            after(3, 0).saturating_sub(600_000),
        ),
        Act::FirstKeyChange,
    ));
    events.push((
        within(&mut mix, after(3, 600_000), hour(4)),
        Act::ReverifyFirst,
    ));
    events.push((within(&mut mix, hour(4), after(4, half)), Act::ThirdReset));
    events.push((within(&mut mix, hour(5), after(5, half)), Act::ThirdRemove));
    // a send to the contact that removed us, after its `Control{1}` (Q212 (8), VERIFY-B4 P2 m-6, P3 m-11)
    events.push((within(&mut mix, after(5, half), end), Act::UserSend(2)));
    events.sort_by_key(|(time, _)| *time);
    events
}

/// How many sends were refused, by reason. There is no `Error::Removed`: a send to a contact that sent `Control{1}` is
/// `Blocked` (as one to a changed identity), counted apart by its target's state (Q212 (8)).
#[derive(Clone, Copy, Debug, Default)]
struct Refused {
    frozen: usize,
    reset: usize,
    blocked: usize,
    removed: usize,
    reinvite: usize,
}

/// The client under test, its peers and what the run has done so far.
struct Rig {
    sim: VirtualDriver,
    client: Party,
    peers: Vec<Party>,
    /// The client's contacts: the first two peers, and the third once it has joined.
    contacts: Vec<i64>,
    backup_row: Option<i64>,
    sent: usize,
    refused: Refused,
}

/// The id of `owner`'s contact whose fingerprint is `peer`'s own, if `owner` has made it already (an inviter makes the contact
/// when the invitee's handshake has arrived, minutes after the accept).
fn find_contact(sim: &mut VirtualDriver, owner: &Party, peer: &Party) -> Option<i64> {
    let fingerprint = hub(sim, peer.idx).own_fingerprint().unwrap();
    let Response::Contacts(list) = hub(sim, owner.idx)
        .core_mut()
        .handle(Request::Contacts)
        .unwrap()
    else {
        unreachable!("Contacts is answered with Contacts")
    };
    list.iter()
        .find(|contact| contact.fingerprint == fingerprint)
        .map(|contact| contact.id.0)
}

/// [`find_contact`] for a contact that must exist.
fn contact_of(sim: &mut VirtualDriver, owner: &Party, peer: &Party) -> i64 {
    find_contact(sim, owner, peer).unwrap()
}

/// A `Send` of a short text from `from` to `contact`; a refusal is the outcome, not a failure.
fn send(sim: &mut VirtualDriver, from: &Party, contact: i64, count: usize) -> Result<(), Error> {
    let payload = Zeroizing::new(format!("message {count}").into_bytes());
    hub(sim, from.idx)
        .core_mut()
        .handle(Request::Send {
            contact: ContactId(contact),
            kind: 1,
            payload,
            expire_after: 0,
        })
        .map(|_| ())
}

/// The user types the safety number of `contact` of `owner`.
fn verify(sim: &mut VirtualDriver, owner: &Party, contact: i64) {
    let Response::SafetyNumber(digits) = hub(sim, owner.idx)
        .core_mut()
        .handle(Request::SafetyNumber {
            contact: ContactId(contact),
        })
        .unwrap()
    else {
        unreachable!("SafetyNumber is answered with SafetyNumber")
    };
    let answer = hub(sim, owner.idx)
        .core_mut()
        .handle(Request::Verify {
            contact: ContactId(contact),
            digits,
        })
        .unwrap();
    assert!(matches!(answer, Response::Verified(true)));
}

impl Rig {
    /// The parties, the two invitations of the first minutes and their completion.
    fn new(mode: Mode) -> Self {
        let period = match mode {
            Mode::Strict => Period::S10,
            Mode::Balanced => Period::S40,
            Mode::LowBw => Period::S80,
        };
        let mut sim = driver();
        sim.commit_latency(200, 0x1a7e);
        sim.prepare_cost(20, 1);
        sim.receive_cost(5);
        let client = add_party_period(&mut sim, "se19-x", 10, (mode, 31), period);
        let peers: Vec<Party> = (1..=3_u64)
            .map(|number| {
                add_party(
                    &mut sim,
                    &format!("se19-p{number}"),
                    4,
                    40_u64.saturating_add(number),
                )
            })
            .collect();
        // the timing draws of every hub and core are fixed: the two runs differ in activity only
        hub(&mut sim, client.idx).seed_timing_kat(7);
        for (number, peer) in peers.iter().enumerate() {
            let seed = 100_u64.saturating_add(u64::try_from(number).unwrap());
            hub(&mut sim, peer.idx).seed_timing_kat(seed);
        }
        // the structural events: the client invites the first two peers now
        for peer in peers.iter().take(2) {
            invite_pair(&mut sim, &client, peer);
        }
        // the handshakes are scheduled sends: both contacts exist ten minutes on
        let now = sim.now();
        sim.run_until(now.saturating_add(600_000));
        let contacts = peers
            .iter()
            .take(2)
            .map(|peer| contact_of(&mut sim, &client, peer))
            .collect();
        Self {
            sim,
            client,
            peers,
            contacts,
            backup_row: None,
            sent: 0,
            refused: Refused::default(),
        }
    }

    /// Hour two: the third peer invites the client, which accepts.
    fn third_joins(&mut self) {
        let third = self.peers.get(2).unwrap();
        invite_pair(&mut self.sim, third, &self.client);
        let contact = contact_of(&mut self.sim, &self.client, third);
        self.contacts.push(contact);
    }

    /// Hour three: the client rotates the queue of its first contact.
    fn rotate(&mut self) {
        let first = *self.contacts.first().unwrap();
        let answer = hub(&mut self.sim, self.client.idx)
            .core_mut()
            .handle(Request::Rotate {
                contact: ContactId(first),
                relay: 1,
            })
            .unwrap();
        assert!(matches!(answer, Response::Rotated(true)));
    }

    /// Whether the client's contact `id` is `Removed` (the peer sent `Control{1}`).
    fn removed(&mut self, id: i64) -> bool {
        let list = hub(&mut self.sim, self.client.idx)
            .core_mut()
            .handle(Request::Contacts)
            .unwrap();
        matches!(list, Response::Contacts(c) if c.iter().any(|c| c.id.0 == id
            && c.state == secmp_client_core::contacts::ContactState::Removed))
    }

    fn note(&mut self, outcome: Result<(), Error>) {
        match outcome {
            Ok(()) => self.sent = self.sent.saturating_add(1),
            Err(Error::Frozen) => self.refused.frozen = self.refused.frozen.saturating_add(1),
            Err(Error::ResetRequested) => {
                self.refused.reset = self.refused.reset.saturating_add(1);
            }
            Err(Error::Blocked) => self.refused.blocked = self.refused.blocked.saturating_add(1),
            Err(Error::ReinviteRequired) => {
                self.refused.reinvite = self.refused.reinvite.saturating_add(1);
            }
            Err(_) => {}
        }
    }

    /// One piece of the activity, applied around the scheduler.
    fn apply(&mut self, act: Act) {
        let count = self.sent;
        match act {
            Act::UserSend(which) => {
                let target = self
                    .contacts
                    .get(which)
                    .or_else(|| self.contacts.first())
                    .copied()
                    .unwrap();
                let removed = self.removed(target);
                let outcome = send(&mut self.sim, &self.client, target, count);
                if removed && outcome == Err(Error::Blocked) {
                    self.refused.removed = self.refused.removed.saturating_add(1);
                } else {
                    self.note(outcome);
                }
                // and to the contact that came from a backup, once it exists: refused, the slots are untouched
                if let Some(row) = self.backup_row {
                    let refused = send(&mut self.sim, &self.client, row, count);
                    self.note(refused);
                }
            }
            Act::PeerSend(which) => {
                // the third peer has no contact before hour two
                if which == 2 && self.contacts.len() < 3 {
                    return;
                }
                let peer = self.peers.get(which).unwrap();
                // an inviter has no contact until the handshake has arrived
                let Some(to) = find_contact(&mut self.sim, peer, &self.client) else {
                    return;
                };
                let outcome = send(&mut self.sim, peer, to, count);
                self.note(outcome);
            }
            Act::ReinviteRow => self.insert_backup_row(),
            Act::VerifyFirst | Act::ReverifyFirst => {
                let first = *self.contacts.first().unwrap();
                verify(&mut self.sim, &self.client, first);
            }
            Act::FirstKeyChange => {
                let first = self.peers.first().unwrap().idx;
                let answer = hub(&mut self.sim, first)
                    .core_mut()
                    .handle(Request::RotateIdentity)
                    .unwrap();
                assert!(matches!(answer, Response::IdentityRotated(_)));
            }
            Act::InvalidKeyChange => self.forged_key_change(),
            Act::ThirdReset | Act::ThirdRemove if self.contacts.len() < 3 => {}
            Act::ThirdReset => self.third_asks(true),
            Act::ThirdRemove => self.third_asks(false),
        }
    }

    /// A contact that came from a backup: no session, `ReinviteRequired`.
    fn insert_backup_row(&mut self) {
        let store = hub(&mut self.sim, self.client.idx).profile_store();
        store
            .lock()
            .unwrap()
            .txn(|tx| {
                secmp_store::contacts::put_contact(
                    tx,
                    &secmp_store::contacts::Contact {
                        id: 9_000,
                        iks: &[0; 8],
                        fingerprint: &[0xee; 32],
                        display_name: None,
                        verified: false,
                        routes: None,
                        queues: None,
                        state: secmp_store::contacts::STATE_REINVITE_REQUIRED,
                        profile: None,
                    },
                )
            })
            .unwrap();
        self.backup_row = Some(9_000);
    }

    /// The second peer sends a key change signed by a key that is not its identity: the client's session with it freezes.
    fn forged_key_change(&mut self) {
        let mut entropy = FixedEntropy::new(&EntropyPool::new("se19-forger", 0).bytes(1 << 20));
        let forger = entropy.hybrid_signing_key().unwrap();
        let new = IdentityKeys::generate(&mut entropy).unwrap();
        let body = secmp_proto::tr::content::key_change_body(&forger, new.public()).unwrap();
        let second = self.peers.get(1).unwrap();
        let to = contact_of(&mut self.sim, second, &self.client);
        hub(&mut self.sim, second.idx)
            .core_mut()
            .queue_key_change_kat(ContactId(to), body)
            .unwrap();
    }

    /// The third peer asks for a new session (`reset`) or removes the client.
    fn third_asks(&mut self, reset: bool) {
        let third = self.peers.get(2).unwrap();
        let contact = ContactId(contact_of(&mut self.sim, third, &self.client));
        let request = if reset {
            Request::ResetSession { contact }
        } else {
            Request::Remove { contact }
        };
        hub(&mut self.sim, third.idx)
            .core_mut()
            .handle(request)
            .unwrap();
    }

    /// Run to the end and take stock.
    fn finish(mut self) -> Run {
        self.sim.run_until(HOURS.saturating_mul(HOUR_MS));
        for party in std::iter::once(&self.client).chain(&self.peers) {
            let errors = &self.sim.client_ref(party.idx).hub_errors;
            assert_eq!(errors, &Vec::<String>::new(), "{}", party.name);
        }
        let under_test = self.sim.client_ref(self.client.idx);
        let mut control: Vec<(u64, usize, Dir)> = under_test
            .trace
            .iter()
            .filter(|entry| entry.slot >= CONTROL_SLOT_BASE)
            .map(|entry| (entry.t_ms, entry.len, entry.dir))
            .collect();
        control.sort();
        Run {
            c2r: self.sim.scheduled(self.client.idx, Dir::C2R),
            r2c: self.sim.scheduled(self.client.idx, Dir::R2C),
            control,
            draws: under_test.sched.timing_draws(),
            sent: self.sent,
            refused: self.refused,
        }
    }
}

/// What a run leaves.
struct Run {
    c2r: Trace,
    r2c: Trace,
    control: Vec<(u64, usize, Dir)>,
    draws: (u64, u64),
    sent: usize,
    refused: Refused,
}

/// One run of `mode`: the idle one (`act` is `None`) or an active one.
fn run(mode: Mode, act: Option<&[(u64, Act)]>) -> Run {
    enum Step {
        ThirdJoins,
        Rotate,
        Activity(Act),
    }
    let mut rig = Rig::new(mode);
    let mut steps = vec![(2 * HOUR_MS, Step::ThirdJoins), (3 * HOUR_MS, Step::Rotate)];
    if let Some(events) = act {
        steps.extend(
            events
                .iter()
                .map(|(time, what)| (*time, Step::Activity(*what))),
        );
    }
    steps.sort_by_key(|(time, _)| *time);
    for (time, step) in steps {
        rig.sim.run_until(time);
        match step {
            Step::ThirdJoins => rig.third_joins(),
            Step::Rotate => rig.rotate(),
            Step::Activity(what) => rig.apply(what),
        }
    }
    rig.finish()
}

/// SE-19: in every mode the C2R trace of the client under test with the activity is the idle one — the same frames on the
/// same links, `|Δt| ≤ 5 ms` — although its cell source is the store and every commit completes up to 200 ms late; the
/// control links and the timing draws are the same; the activity really happened (messages, refusals in each state).
#[test]
fn store_backed_source_activity_independent() {
    let modes = [Mode::Strict, Mode::Balanced, Mode::LowBw];
    let traces: Vec<Vec<(u64, Act)>> = (1..=3_u64).map(activity).collect();
    // the six runs in parallel: one idle run and one active run per mode
    let jobs: Vec<(Mode, bool, usize)> = modes
        .iter()
        .enumerate()
        .flat_map(|(number, mode)| [(*mode, false, number), (*mode, true, number)])
        .collect();
    let runs = par_map(jobs, |(mode, active, number)| {
        run(mode, active.then(|| traces.get(number).unwrap().as_slice()))
    });
    let mut table = Vec::new();
    for (number, mode) in modes.iter().enumerate() {
        let idle = runs.get(number.saturating_mul(2)).unwrap();
        let active = runs
            .get(number.saturating_mul(2).saturating_add(1))
            .unwrap();
        assert!(idle.c2r.len() > 100, "{mode:?}: {} frames", idle.c2r.len());
        let c2r = max_dt(&idle.c2r, &active.c2r).unwrap_or_else(|| {
            unreachable!("{mode:?}: the C2R traces differ in length, size, direction or link")
        });
        let r2c = max_dt(&idle.r2c, &active.r2c).unwrap_or_else(|| {
            unreachable!("{mode:?}: the R2C traces differ in length, size, direction or link")
        });
        assert!(c2r <= 5, "{mode:?}: C2R max |Δt| = {c2r} ms");
        assert_eq!(idle.draws, active.draws, "{mode:?}: timing draws");
        assert_eq!(idle.control, active.control, "{mode:?}: control links");
        assert!(active.sent > 100, "{mode:?}: {} messages sent", active.sent);
        let refused = active.refused;
        for (state, count) in [
            ("Frozen", refused.frozen),
            ("ResetRequested", refused.reset),
            ("Blocked", refused.blocked),
            ("Removed", refused.removed),
            ("ReinviteRequired", refused.reinvite),
        ] {
            assert!(count > 0, "{mode:?}: no send was refused as {state}");
        }
        table.push(format!(
            "{mode:?}: frames C2R {} / R2C {}, max |Δt| C2R {c2r} ms / R2C {r2c} ms; messages sent {}; refused: {refused:?}",
            idle.c2r.len(),
            idle.r2c.len(),
            active.sent
        ));
    }
    evidence("SE-19-activity", &table.join("\n"));
}
