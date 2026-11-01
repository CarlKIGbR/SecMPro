// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 Phase C2-2: the `turmoil` simulations of TEST-SPEC-M6 (f), SIM-01…SIM-10 — the shared rig.
//!
//! One simulated network: a host `relay` (the M5 relay's sans-IO `Connection`, one task per accepted socket, served by
//! `MemRelay::serve`; a restart of the host is a restart of the relay: a fresh store, the same keys), two client hosts
//! `a` (the inviter) and `b` (the invitee) that run the engine of `two-clients` — pool, scripted handshake, then the
//! constant-rate scheduler on the tokio driver — over [`TurmoilProvider`], and one dummy client that fixes the end of the
//! simulation. Everything runs under turmoil's virtual clock; nothing reads a wall clock.
//!
//! **The common assertions.** (E) every real message enqueued is delivered to the application exactly once: each client
//! reports `delivered N/N` and `exact=true` (the received payloads and ids are the script's, in order, once each).
//! (K) the digests of all message keys each sender sealed a cell under are pairwise distinct — the H-12 method
//! (`Sealed::message_key_digest_kat`, SHA-256 of the message key), taken where the cell is sealed
//! (`Conversation::message_key_digests_kat`, feature `kat`) and so including real cells, dummies, receipts and the cells
//! that were sealed and never written. [`Outcome::assert_e_and_k`] asserts both; every row calls it.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use secmp_client_core::clock::TokioClock;
use secmp_client_core::scheduler::params::Mode;
use secmp_proto::wire::inv::RelayRef;
use secmp_testkit::harness::{EntropyPool, HarnessConfig, MemRelay, START_UNIX};
use secmp_testkit::two_clients::cli::{Cli, Role, Script, TransportArg};
use secmp_testkit::two_clients::run::{Convs, Observer, World, WorldConfig, resume, session};
use secmp_transport::Error as TransportError;
use secmp_transport::driver::{Isolation, StreamProvider};

use crate::m6_tokio::runtime;

/// The relay's simulated port.
pub const RELAY_PORT: u16 = 7443;

/// The provider of the clients of a simulation: a connect is a simulated TCP connection to the host `relay`.
#[derive(Clone, Copy, Default)]
pub struct TurmoilProvider;

impl StreamProvider for TurmoilProvider {
    type Stream = turmoil::net::TcpStream;

    async fn connect(
        &self,
        _relay: &RelayRef,
        _isolation: Isolation,
    ) -> Result<Self::Stream, TransportError> {
        turmoil::net::TcpStream::connect(("relay", RELAY_PORT))
            .await
            .map_err(|_| TransportError::Closed)
    }
}

/// What a row sets.
#[derive(Clone)]
pub struct Spec {
    /// turmoil's seed (the order of its randomness).
    pub seed: u64,
    /// Messages each way.
    pub messages: u64,
    /// Seconds between two messages of one client.
    pub interval_s: u64,
    /// The clients run `end_s` seconds, then report.
    pub end_s: u64,
    /// Per-message failure rate of the links between each client and the relay, from `fail_from_s` on (the set-up of
    /// the clients, which has no retry, is over by then), and the repair rate (turmoil breaks the TCP connection on a loss).
    pub fail_rate: Option<(f64, f64)>,
    /// When the failure rate starts, in seconds.
    pub fail_from_s: u64,
    /// A host that sends `HELLO` to the relay at `rate` per second between `start` and `start + length`.
    pub flood: Option<Flood>,
    /// Minimum and maximum one-way message latency of every link.
    pub latency: Option<(Duration, Duration)>,
    /// The relay's configuration.
    pub relay: HarnessConfig,
    /// The scheduler mode of both clients.
    pub mode: Mode,
    /// The clients' connect timeout in ms (`None`: the driver's 120 s).
    pub connect_timeout_ms: Option<u64>,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            seed: 1,
            messages: 200,
            interval_s: 30,
            end_s: 3 * 3600,
            fail_rate: None,
            fail_from_s: 900,
            flood: None,
            latency: None,
            relay: HarnessConfig::default(),
            mode: Mode::Strict,
            connect_timeout_ms: None,
        }
    }
}

/// A `HELLO` flood (SIM-09).
#[derive(Clone, Copy)]
pub struct Flood {
    /// `HELLO`s per second.
    pub rate: u64,
    /// Start, seconds.
    pub start: u64,
    /// Length, seconds.
    pub length: u64,
}

/// What a row can touch while the simulation runs.
pub struct Rig<'a, 'b> {
    /// The simulation.
    pub sim: &'a mut turmoil::Sim<'b>,
    /// The simulation's virtual time.
    pub now: Duration,
    /// The relay of the current start of the host `relay`.
    pub relay: &'a Arc<Mutex<Option<MemRelay>>>,
    /// What the engine of each client shows from outside: `a`, `b`.
    pub observers: &'a [Arc<Observer>; 2],
}

/// What a row reads after the run.
pub struct Outcome {
    /// Virtual time at the end.
    pub elapsed: Duration,
    /// What each client's engine printed, by start (`a`, `b`).
    pub out: [Vec<String>; 2],
    /// What each client showed from outside.
    pub observers: [Arc<Observer>; 2],
    /// The relay of the last start.
    pub relay: Arc<Mutex<Option<MemRelay>>>,
    /// The script of the run.
    pub script: Script,
}

fn host_error(e: &impl core::fmt::Debug) -> Box<dyn std::error::Error> {
    format!("{e:?}").into()
}

/// The identity of the simulated relay (its reference and access key): the same on every start.
fn relay_identity() -> (RelayRef, [u8; 32]) {
    runtime().block_on(async {
        let relay = MemRelay::new(HarnessConfig::default());
        (relay.relay_ref(), *relay.access_key().expose_secret())
    })
}

/// A directory of its own for the invitation file.
fn sim_dir(name: &str) -> PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("sim-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One client host: the engine of `two-clients` for `role`, restarted from its conversations if the host restarts.
fn client_host(
    sim: &mut turmoil::Sim<'_>,
    name: &'static str,
    idx: usize,
    role: Role,
    spec: &Spec,
    script: Script,
    shared: &Shared,
) {
    let (relay, access) = (shared.relay_ref.clone(), shared.access);
    let (observer, out) = (
        Arc::clone(shared.observers.get(idx).unwrap()),
        Arc::clone(shared.out.get(idx).unwrap()),
    );
    let invite = shared.invite.clone();
    let (mode, end_s, connect_timeout_ms) = (spec.mode, spec.end_s, spec.connect_timeout_ms);
    sim.host(name, move || {
        let (relay, observer, out, invite) = (
            relay.clone(),
            Arc::clone(&observer),
            Arc::clone(&out),
            invite.clone(),
        );
        async move {
            let started = turmoil::elapsed();
            let unix = START_UNIX.saturating_add(started.as_secs());
            let clock = TokioClock::new(unix);
            let world = World::new(
                TurmoilProvider,
                WorldConfig {
                    relay,
                    access: secmp_crypto::SecretBytes::from_slice(&access).unwrap(),
                    clock,
                    unix_base: unix,
                    mode,
                    direct: false,
                    connect_timeout_ms,
                },
                Some(Arc::clone(&observer)),
            );
            let cli = Cli {
                role,
                mode,
                transport: TransportArg::Mem,
                relay_ref: None,
                invite_out: (role == Role::Inviter).then(|| invite.clone()),
                invite_in: (role == Role::Invitee).then(|| invite.clone()),
                script: None,
                duration_s: Some(end_s.saturating_sub(started.as_secs()).max(1)),
                trace_out: None,
                tor_dir: None,
            };
            let mut text = Vec::new();
            let result = if let Some((convs, restart)) = observer.client::<EntropyPool>() {
                Box::pin(resume::<TurmoilProvider, EntropyPool>(
                    &cli, world, &restart, convs, &script, &mut text,
                ))
                .await
            } else {
                if role == Role::Invitee {
                    while !invite.exists() {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
                Box::pin(session::<TurmoilProvider, EntropyPool>(
                    &cli, world, &script, &mut text,
                ))
                .await
            };
            out.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&text).into_owned());
            result.map_err(|e| host_error(&e))
        }
    });
}

/// What the hosts share with the row.
struct Shared {
    relay_ref: RelayRef,
    access: [u8; 32],
    invite: PathBuf,
    observers: [Arc<Observer>; 2],
    out: [Arc<Mutex<Vec<String>>>; 2],
}

/// Run a simulation of `spec`, calling `timeline` after every step.
///
/// On a thread of its own with a large stack: the handshake keeps large frames in an unoptimised build.
pub fn simulate(
    name: &str,
    spec: &Spec,
    timeline: impl FnMut(&mut Rig<'_, '_>) + Send + 'static,
) -> Outcome {
    let (name, spec) = (name.to_owned(), spec.clone());
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || simulate_here(&name, &spec, timeline))
        .unwrap()
        .join()
        .unwrap()
}

fn simulate_here(name: &str, spec: &Spec, mut timeline: impl FnMut(&mut Rig<'_, '_>)) -> Outcome {
    let (relay_ref, access) = relay_identity();
    let shared = Shared {
        relay_ref,
        access,
        invite: sim_dir(name).join("invite"),
        observers: [Observer::new(), Observer::new()],
        out: [Arc::default(), Arc::default()],
    };
    let relay_cell: Arc<Mutex<Option<MemRelay>>> = Arc::default();
    let script = Script {
        messages: spec.messages,
        size_min: 1,
        size_max: 1_000,
        seed: spec.seed,
        interval_s: spec.interval_s,
        start_s: 0,
        bursts: 0,
        burst_size: 20,
    };
    let end = Duration::from_secs(spec.end_s.saturating_add(120));
    let mut builder = turmoil::Builder::new();
    builder
        .simulation_duration(end.saturating_add(Duration::from_secs(60)))
        .tick_duration(Duration::from_millis(10))
        .rng_seed(spec.seed);
    if let Some((_, repair)) = spec.fail_rate {
        builder.repair_rate(repair);
    }
    if let Some((min, max)) = spec.latency {
        builder.min_message_latency(min).max_message_latency(max);
    }
    let mut sim = builder.build();
    let config = spec.relay;
    let cell = Arc::clone(&relay_cell);
    sim.host("relay", move || {
        let cell = Arc::clone(&cell);
        async move {
            let unix = START_UNIX.saturating_add(turmoil::elapsed().as_secs());
            let relay = MemRelay::new_at(config, unix);
            *cell.lock().unwrap() = Some(relay.clone());
            let listener =
                turmoil::net::TcpListener::bind((IpAddr::from(Ipv4Addr::UNSPECIFIED), RELAY_PORT))
                    .await?;
            loop {
                let (stream, _) = listener.accept().await?;
                let _ = relay.serve(Isolation(0), stream);
            }
        }
    });
    client_host(&mut sim, "a", 0, Role::Inviter, spec, script, &shared);
    client_host(&mut sim, "b", 1, Role::Invitee, spec, script, &shared);
    if let Some(flood) = spec.flood {
        add_attacker(&mut sim, flood);
    }
    // the simulation ends when this client does
    sim.client("clock", async move {
        tokio::time::sleep(end).await;
        Ok(())
    });
    let mut failing = false;
    loop {
        if sim.step().unwrap() {
            break;
        }
        let now = sim.elapsed();
        if let (false, Some((fail, _))) = (failing, spec.fail_rate)
            && now >= Duration::from_secs(spec.fail_from_s)
        {
            failing = true;
            for client in ["a", "b"] {
                sim.set_link_fail_rate(client, "relay", fail);
            }
        }
        timeline(&mut Rig {
            sim: &mut sim,
            now,
            relay: &relay_cell,
            observers: &shared.observers,
        });
    }
    let elapsed = sim.elapsed();
    let out = [
        shared.out[0].lock().unwrap().clone(),
        shared.out[1].lock().unwrap().clone(),
    ];
    Outcome {
        elapsed,
        out,
        observers: shared.observers,
        relay: relay_cell,
        script,
    }
}

impl Outcome {
    /// The last report of client `idx` (`a` = 0, `b` = 1): the lines the engine printed when its run ended.
    pub fn report(&self, idx: usize) -> String {
        self.out
            .get(idx)
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default()
    }

    /// The conversations of client `idx`.
    pub fn convs(&self, idx: usize) -> Arc<Mutex<Convs<EntropyPool>>> {
        self.observers
            .get(idx)
            .unwrap()
            .client::<EntropyPool>()
            .unwrap()
            .0
    }

    /// No message was delivered twice or altered: everything each client received is one of the script's messages, once,
    /// with the script's payload (the engine's `exact`).
    pub fn assert_exact(&self, what: &str) {
        for (idx, side) in ["inviter", "invitee"].into_iter().enumerate() {
            let report = self.report(idx);
            assert!(
                report.contains("result exact=true"),
                "{what}: (E) {side}: a message was duplicated or altered:\n{report}"
            );
        }
    }

    /// (K) the message keys of each sender are pairwise distinct (H-12: SHA-256 of the key of every cell it sealed), with
    /// at least one key per message — the check is not vacuous.
    pub fn assert_k(&self, what: &str) {
        let n = self.script.messages;
        for (idx, side) in ["inviter", "invitee"].into_iter().enumerate() {
            let convs = self.convs(idx);
            let guard = convs.lock().unwrap();
            let digests = guard.get(0).unwrap().message_key_digests_kat();
            let distinct: std::collections::BTreeSet<&[u8; 32]> = digests.iter().collect();
            assert!(
                u64::try_from(digests.len()).unwrap() >= n,
                "{what}: (K) {side}: {} keys for {n} messages",
                digests.len()
            );
            assert_eq!(
                distinct.len(),
                digests.len(),
                "{what}: (K) {side}: a message key was used twice"
            );
        }
    }

    /// (E) every real message enqueued was delivered to the application exactly once — each client received all of the
    /// script's messages ([`Outcome::assert_exact`]) — and (K) ([`Outcome::assert_k`]).
    pub fn assert_e_and_k(&self, what: &str) {
        let n = self.script.messages;
        for (idx, side) in ["inviter", "invitee"].into_iter().enumerate() {
            let report = self.report(idx);
            assert!(
                report.contains(&format!("delivered side={side} {n}/{n}")),
                "{what}: (E) {side}: not every message was delivered:\n{report}"
            );
        }
        self.assert_exact(what);
        self.assert_k(what);
    }
}

/// The attacker host of a `HELLO` flood: connect, send a `HELLO`, drop, `rate` times per second, for `length` seconds from
/// `start`.
fn add_attacker(sim: &mut turmoil::Sim<'_>, flood: Flood) {
    let hello = secmp_proto::link::client::start([0; 32], None, 0)
        .unwrap()
        .0;
    sim.client("attacker", async move {
        use tokio::io::AsyncWriteExt as _;
        tokio::time::sleep(Duration::from_secs(flood.start)).await;
        let gap = Duration::from_millis(1_000_u64.checked_div(flood.rate).unwrap_or(1_000));
        let until = turmoil::elapsed().saturating_add(Duration::from_secs(flood.length));
        while turmoil::elapsed() < until {
            if let Ok(mut s) = turmoil::net::TcpStream::connect(("relay", RELAY_PORT)).await {
                let _ = s.write_all(&hello).await;
            }
            tokio::time::sleep(gap).await;
        }
        Ok(())
    });
}

/// Each teardown of a client with the delay until the connect that renews its logical link (FIN5b-1; M7 B-SC SC-04:
/// `LinkEvent::TornDown` and `Purpose::Link` carry the logical link id): the teardowns, in time order, are matched to the
/// later connects of the same logical link, each to the earliest one not taken. On one logical link teardowns and
/// connects alternate, so this is the link's own reconnect; a connect of another link never counts (a swap of two links'
/// reconnects inside the pooled bound is a finding). See [`check_reconnects`].
pub fn reconnect_delays(
    events: &[(u64, secmp_client_core::scheduler::types::LinkEvent)],
    connects: &[(u64, secmp_client_core::scheduler::run::Purpose)],
) -> Vec<(
    secmp_client_core::scheduler::types::Reason,
    u64,
    Option<u64>,
)> {
    use secmp_client_core::scheduler::run::Purpose;
    use secmp_client_core::scheduler::types::{LinkEvent, LogicalLinkId};
    let mut conn: Vec<(u64, LogicalLinkId)> = connects
        .iter()
        .filter_map(|(t, p)| match p {
            Purpose::Link(_, logical) => Some((*t, *logical)),
            Purpose::Control(_) => None,
        })
        .collect();
    conn.sort_unstable();
    let mut downs: Vec<(
        u64,
        LogicalLinkId,
        secmp_client_core::scheduler::types::Reason,
    )> = events
        .iter()
        .filter_map(|(t, e)| match e {
            LinkEvent::TornDown(_, logical, why) => Some((*t, *logical, *why)),
            _ => None,
        })
        .collect();
    downs.sort_by_key(|d| d.0);
    let mut taken = vec![false; conn.len()];
    downs
        .into_iter()
        .map(|(t, logical, why)| {
            let next = conn.iter().enumerate().find(|(i, (c, l))| {
                *l == logical && *c >= t && !taken.get(*i).copied().unwrap_or(true)
            });
            let delay = next.map(|(i, (c, _))| {
                if let Some(slot) = taken.get_mut(i) {
                    *slot = true;
                }
                c.saturating_sub(t)
            });
            (why, t, delay)
        })
        .collect()
}

/// The reconnect oracle (LR-02, SIM-01/SIM-07): for every teardown of a scheduled link whose reason has a bound
/// (`bound` returns `Some(ms)`), the matching of [`reconnect_delays`] has a reconnect **of the same logical link** within
/// `bound + 1 000 ms`, unless the teardown is in the last `bound + 1 000 ms` before `end_ms` (the run ended before it could
/// reconnect). Returns the number of teardowns checked. FIN5b-1 (M6: a pooled bound over all connects) is now per logical
/// link (M7 B-SC SC-04, the logical link id in `LinkEvent` and `Purpose::Link`): every checked teardown has its own link's
/// reconnect within its bound (a teardown that never reconnects is a failure).
pub fn check_reconnects(
    events: &[(u64, secmp_client_core::scheduler::types::LinkEvent)],
    connects: &[(u64, secmp_client_core::scheduler::run::Purpose)],
    end_ms: u64,
    bound: impl Fn(secmp_client_core::scheduler::types::Reason) -> Option<u64>,
) -> Result<usize, String> {
    let mut checked = 0_usize;
    for (why, t, delay) in reconnect_delays(events, connects) {
        let Some(bound) = bound(why) else { continue };
        let Some(delay) = delay else {
            // a teardown in the last `bound + 1 000 ms` of the run may not have had the time to reconnect: excused, and
            // not counted as checked
            if t.saturating_add(bound).saturating_add(1_000) > end_ms {
                continue;
            }
            return Err(format!("{why:?} at {t}: no reconnect follows"));
        };
        checked = checked.saturating_add(1);
        if delay > bound.saturating_add(1_000) {
            return Err(format!(
                "{why:?} at {t}: the reconnect {delay} ms later, bound {bound}"
            ));
        }
    }
    Ok(checked)
}

pub const ORACLE_BOUND: u64 = 100;

/// The end of the fixture runs (ms), far beyond `ORACLE_BOUND + 1 000`.
pub const ORACLE_END: u64 = 10_000;

pub fn oracle_bound(why: secmp_client_core::scheduler::types::Reason) -> Option<u64> {
    (why != secmp_client_core::scheduler::types::Reason::ModeChange).then_some(ORACLE_BOUND)
}

/// A teardown at `t` of connection `id` of logical link `logical`.
pub fn oracle_down(
    t: u64,
    id: u64,
    logical: u64,
) -> (u64, secmp_client_core::scheduler::types::LinkEvent) {
    use secmp_client_core::scheduler::types::{LinkEvent, LinkId, LogicalLinkId, Reason};
    (
        t,
        LinkEvent::TornDown(LinkId(id), LogicalLinkId(logical), Reason::Closed),
    )
}

/// A connect at `t` of connection `id` of logical link `logical`.
pub fn oracle_connect(
    t: u64,
    id: u64,
    logical: u64,
) -> (u64, secmp_client_core::scheduler::run::Purpose) {
    use secmp_client_core::scheduler::run::Purpose;
    use secmp_client_core::scheduler::types::{LinkId, LogicalLinkId};
    (t, Purpose::Link(LinkId(id), LogicalLinkId(logical)))
}

/// Positive control: two teardowns (logical links 0 and 1), each reconnected within the bound.
#[test]
fn oracle_accepts_reconnects_within_the_bound() {
    let events = [oracle_down(0, 1, 0), oracle_down(10, 2, 1)];
    let connects = [oracle_connect(50, 3, 0), oracle_connect(60, 4, 1)];
    assert_eq!(
        check_reconnects(&events, &connects, ORACLE_END, oracle_bound),
        Ok(2)
    );
}

/// FIN5b-1: a teardown that never reconnects fails (it used to be skipped by `if let Some(delay)`).
#[test]
fn oracle_rejects_a_teardown_without_reconnect() {
    let events = [oracle_down(0, 1, 0), oracle_down(10, 2, 1)];
    let connects = [oracle_connect(50, 3, 0)];
    assert!(check_reconnects(&events, &connects, ORACLE_END, oracle_bound).is_err());
}

/// FIN5b-1: teardowns of A (t = 0) and B (t = 10); B reconnects at 500, A only at 2 500 (crossed). A's own reconnect is
/// 2 500 ms after its teardown, beyond the bound + 1 000 ms, so the oracle rejects, though the earlier connect (B's) alone
/// would have been in time (M7 B-SC: matched per logical link).
#[test]
fn oracle_rejects_a_crossed_reconnect_that_breaks_the_pooled_bound() {
    let events = [oracle_down(0, 1, 0), oracle_down(10, 2, 1)];
    let connects = [oracle_connect(500, 3, 1), oracle_connect(2_500, 4, 0)];
    let e = check_reconnects(&events, &connects, ORACLE_END, oracle_bound).unwrap_err();
    assert!(e.contains("2500 ms"), "{e}");
}

/// A teardown in the last `bound + 1 000 ms` of the run has not had the time to reconnect and is not a finding; it is
/// not counted as checked either (the `teardowns >= 10` of SIM-01 counts checked teardowns only).
#[test]
fn oracle_excuses_a_teardown_in_the_last_bound_window() {
    let events = [oracle_down(0, 1, 0), oracle_down(ORACLE_END - 500, 2, 1)];
    let connects = [oracle_connect(50, 3, 0)];
    assert_eq!(
        check_reconnects(&events, &connects, ORACLE_END, oracle_bound),
        Ok(1)
    );
}

/// The edge of the window, both sides: the teardown is excused iff `t + bound + 1 000 > end` — exactly `bound + 1 s`
/// before the end it is still checked (and fails without a reconnect), one millisecond later it is excused.
#[test]
fn oracle_window_edge_is_pinned_on_both_sides() {
    let window = ORACLE_BOUND + 1_000;
    let connects = [oracle_connect(50, 3, 0)];
    let at_edge = [oracle_down(0, 1, 0), oracle_down(ORACLE_END - window, 2, 1)];
    assert!(check_reconnects(&at_edge, &connects, ORACLE_END, oracle_bound).is_err());
    let inside = [
        oracle_down(0, 1, 0),
        oracle_down(ORACLE_END - window + 1, 2, 1),
    ];
    assert_eq!(
        check_reconnects(&inside, &connects, ORACLE_END, oracle_bound),
        Ok(1)
    );
}
