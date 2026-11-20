// SPDX-License-Identifier: AGPL-3.0-or-later
//! The external review of `f68d923` (WEISUNG M6-B-5, EXTB-3, EXTB-4): the tokio driver's writes and connects on a
//! paused clock, over a provider that holds back (or splits) one connection's first frame, or answers late.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::run::{CONNECT_TIMEOUT_MS, Purpose, Step};
use secmp_client_core::scheduler::types::{LinkEvent, LinkId, Reason};
use secmp_proto::wire::inv::RelayRef;
use secmp_testkit::harness::{Costs, Dir, MemProvider};
use secmp_transport::Error;
use secmp_transport::driver::{Isolation, StreamProvider};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

use crate::m6_activity::Scenario;
use crate::m6_tokio::{Setup, TClient, TRun, TokioRig, runtime};

/// The client's handshake bytes (`HELLO` 9 + `HS1` 2856): the first frame starts after them.
const HANDSHAKE: usize = 9 + 2856;

/// How one connection's first frame is held back: `first` bytes of it go out at once, the rest after `delay_ms`.
#[derive(Clone, Copy)]
pub(crate) struct Hold {
    pub(crate) first: usize,
    pub(crate) delay_ms: u64,
}

/// A stream that holds back its first frame after the handshake (see [`Hold`]).
pub(crate) struct Throttled {
    inner: DuplexStream,
    written: usize,
    hold: Option<Hold>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    /// Bytes read so far, and after how many the peer goes silent (a black hole: nothing more is delivered).
    read: usize,
    mute_after: Option<usize>,
}

impl Throttled {
    /// The `Hold::delay_ms` that makes the first frame after the handshake fail to write (its flush stays Ok) instead of waiting.
    pub(crate) const FAILING_WRITES: u64 = u64::MAX;
}

impl AsyncRead for Throttled {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(after) = self.mute_after {
            let left = after.saturating_sub(self.read);
            if left == 0 {
                // a black hole: nothing more arrives, ever
                return Poll::Pending;
            }
            let mut limited = buf.take(left);
            let polled = Pin::new(&mut self.inner).poll_read(cx, &mut limited);
            let n = limited.filled().len();
            // `take` filled the first `n` bytes of `buf`'s unfilled part
            buf.advance(n);
            self.read = self.read.saturating_add(n);
            return polled;
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Throttled {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut limit = buf.len();
        if let Some(hold) = self.hold {
            let gate = HANDSHAKE.saturating_add(hold.first);
            if self.written < gate {
                limit = limit.min(gate.saturating_sub(self.written));
            } else {
                if hold.delay_ms == Throttled::FAILING_WRITES {
                    // `Throttled::FAILING_WRITES` marks a failing writer: the first frame after the handshake cannot be written (flush stays Ok)
                    return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)));
                }
                let sleep = self.sleep.get_or_insert_with(|| {
                    Box::pin(tokio::time::sleep(std::time::Duration::from_millis(
                        hold.delay_ms,
                    )))
                });
                if sleep.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                self.hold = None;
            }
        }
        let chunk = buf.get(..limit).unwrap();
        let polled = Pin::new(&mut self.inner).poll_write(cx, chunk);
        if let Poll::Ready(Ok(n)) = &polled {
            self.written = self.written.saturating_add(*n);
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The `MemProvider` whose connection number `which` (counted from 0) holds back its first frame; every connect may
/// answer `answer_ms` late.
#[derive(Clone)]
pub(crate) struct Holding {
    inner: MemProvider,
    which: usize,
    hold: Option<Hold>,
    answer_ms: u64,
    count: Arc<AtomicUsize>,
    /// Connection `which` goes silent after this many bytes from the relay.
    mute_after: Option<usize>,
    /// The connect of connection `which` never completes (a dial that hangs).
    hang: bool,
    /// `answer_ms` applies to connection `which` only.
    late_only_which: bool,
    /// Per connection number: its first-frame hold, its connect delay and whether the connect hangs (overrides the
    /// fields above for the connections it lists; FIN-1).
    plans: Vec<(Option<Hold>, u64, bool)>,
    /// Connection numbers whose connect fails (after their delay).
    fails: Vec<usize>,
}

impl Holding {
    pub(crate) fn new(
        inner: MemProvider,
        which: usize,
        hold: Option<Hold>,
        answer_ms: u64,
    ) -> Self {
        Self {
            inner,
            which,
            hold,
            answer_ms,
            count: Arc::new(AtomicUsize::new(0)),
            mute_after: None,
            hang: false,
            late_only_which: false,
            plans: Vec::new(),
            fails: Vec::new(),
        }
    }
}

impl StreamProvider for Holding {
    type Stream = Throttled;

    fn connect(
        &self,
        relay: &RelayRef,
        isolation: Isolation,
    ) -> impl core::future::Future<Output = Result<Throttled, Error>> + Send {
        let n = self.count.fetch_add(1, Ordering::SeqCst);
        let hold = (n == self.which).then_some(self.hold).flatten();
        let mute_after = (n == self.which).then_some(self.mute_after).flatten();
        let answer_ms = if self.late_only_which && n != self.which {
            0
        } else {
            self.answer_ms
        };
        let (inner, relay) = (self.inner.clone(), relay.clone());
        let fail = self.fails.contains(&n);
        let mut hang = self.hang && n == self.which;
        let (mut hold, mut answer_ms) = (hold, answer_ms);
        if let Some((h, a, g)) = self.plans.get(n) {
            (hold, answer_ms, hang) = (*h, *a, *g);
        }
        async move {
            if hang {
                core::future::pending::<()>().await;
            }
            if answer_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(answer_ms)).await;
            }
            if fail {
                return Err(Error::Closed);
            }
            let stream = inner.connect(&relay, isolation).await?;
            Ok(Throttled {
                inner: stream,
                written: 0,
                hold,
                sleep: None,
                read: 0,
                mute_after,
            })
        }
    }
}

pub(crate) fn scenario(seed: u64) -> Scenario {
    Scenario {
        mode: Mode::Strict,
        contacts: vec![(10_000, 10_000), (10_000, 10_000)],
        pool: false,
        seed,
    }
}

/// `minutes` of the scenario through a `Holding` provider; the rig is returned for inspection.
fn run_holding(
    params: Params,
    seed: u64,
    which: usize,
    hold: Option<Hold>,
    minutes: u64,
) -> (TRun, TokioRig<Holding>) {
    runtime().block_on(async {
        let setup = Setup::new();
        let provider = Holding::new(setup.provider.clone(), which, hold, 0);
        let sc = scenario(seed);
        let x = TClient::with_provider(
            &setup,
            provider,
            sc.mode,
            params,
            sc.seed,
            Costs::default(),
            0,
        );
        let mut rig = TokioRig::assemble(setup, x, &sc).await;
        let run = rig.run_minutes(minutes, None).await;
        (run, rig)
    })
}

/// The link of connection number `n`.
pub(crate) fn link_of(rig: &TokioRig<Holding>, n: usize) -> LinkId {
    let links: Vec<LinkId> = rig
        .x
        .driver
        .log()
        .unwrap()
        .connects
        .iter()
        .filter_map(|(_, p, _)| match p {
            Purpose::Link(l, _) => Some(*l),
            Purpose::Control(_) => None,
        })
        .collect();
    *links.get(n).unwrap()
}

pub(crate) fn no_phase() -> Params {
    Params {
        phase_max_ms: 0,
        ..Params::default()
    }
}

/// EXTB-3: four Strict links ticking together; the first frame of one link hangs for 20 s. The other three write
/// every tick on time (10 s, 20 s, 30 s, …) — the hanging write delays nobody — and nothing overruns; the hanging link
/// is closed when its next tick comes while its write is still pending, and connects again.
#[test]
fn driver_hanging_writer_does_not_delay_other_links() {
    let hold = Hold {
        first: 0,
        delay_ms: 20_000,
    };
    let (run, rig) = run_holding(no_phase(), 41, 1, Some(hold), 1);
    let held_link = link_of(&rig, 1);
    let log = rig.x.driver.log().unwrap();
    let up = |l: LinkId| {
        log.events
            .iter()
            .find_map(|(t, e)| (matches!(e, LinkEvent::Up(x, _) if *x == l)).then_some(*t))
            .unwrap()
    };
    for n in [0_usize, 2, 3] {
        let l = link_of(&rig, n);
        let frames: Vec<u64> = run
            .c2r
            .iter()
            .filter(|e| e.slot == l.0 && e.len == 4352)
            .map(|e| e.t_ms)
            .collect();
        let t_up = up(l);
        for k in 1..=5_u64 {
            assert!(
                frames.contains(&(t_up + k * 10_000)),
                "link {l:?}: no frame at tick {k}: {frames:?}"
            );
        }
    }
    assert_eq!(run.overruns, 0);
    assert!(
        log.events.iter().any(
            |(_, e)| matches!(e, LinkEvent::TornDown(x, _, Reason::Closed) if *x == held_link)
        ),
        "the hanging link is closed: {:?}",
        log.events
    );
}

/// Whether `link`'s first frame was complete before the work of the pass that submitted it: a pass that began at or
/// before the write's completion reports a work end at or after it.
fn wrote_before_work(steps: &[Step], link: LinkId) -> bool {
    let Some(done) = steps.iter().find_map(|s| match s {
        Step::Wrote(t, l, 4352) if *l == link => Some(*t),
        _ => None,
    }) else {
        return false;
    };
    steps
        .iter()
        .any(|s| matches!(s, Step::Work(start, end) if *start <= done && *end >= done))
}

/// EXTB-3: a frame the stream takes in two parts — 2176 bytes at once, the rest 100 ms later — is complete before the
/// pass goes on to `work`: the pass's work ends no earlier than the frame's completion; the link stays up.
#[test]
fn driver_partial_write_is_completed_before_work() {
    let hold = Hold {
        first: 2176,
        delay_ms: 100,
    };
    let (run, rig) = run_holding(no_phase(), 42, 1, Some(hold), 1);
    let held_link = link_of(&rig, 1);
    let log = rig.x.driver.log().unwrap();
    assert!(wrote_before_work(&log.steps, held_link), "{:?}", log.steps);
    assert!(
        !log.events
            .iter()
            .any(|(_, e)| matches!(e, LinkEvent::TornDown(..))),
        "{:?}",
        log.events
    );
    assert_eq!(run.overruns, 0);
}

/// EXTB-3: two links write in the same pass (they tick together); one frame needs 100 ms. Both are flushed before the
/// pass's `work`: its work ends no earlier than either frame's completion.
#[test]
fn driver_pending_flush_same_tick() {
    let hold = Hold {
        first: 0,
        delay_ms: 100,
    };
    let (run, rig) = run_holding(no_phase(), 43, 0, Some(hold), 1);
    let log = rig.x.driver.log().unwrap();
    for n in [0_usize, 2] {
        assert!(
            wrote_before_work(&log.steps, link_of(&rig, n)),
            "link {n}: {:?}",
            log.steps
        );
    }
    assert_eq!(run.overruns, 0);
}

/// EXTB-3: one link's first frame needs 5 s — longer than the flush wait of its pass, shorter than its period and the
/// stall bound. Another link's tick inside those 5 s goes out on time: the emission of every other link equals that of
/// an unheld run to the millisecond, the held frame arrives 5 s late, and no link is torn down.
#[test]
fn driver_pending_flush_later_tick_other_link() {
    let hold = Hold {
        first: 0,
        delay_ms: 5_000,
    };
    // phases within 30 s, so the other links are up when the last one writes its first frame
    let params = Params {
        phase_max_ms: 30_000,
        ..Params::default()
    };
    let (free, _) = run_holding(params.clone(), 44, 3, None, 3);
    let (held_run, rig) = run_holding(params, 44, 3, Some(hold), 3);
    let held_link = link_of(&rig, 3);
    let others = |r: &TRun| {
        let mut v: Vec<(u64, u64)> = r
            .c2r
            .iter()
            .filter(|e| e.slot != held_link.0 && e.dir == Dir::C2R)
            .map(|e| (e.t_ms, e.slot))
            .collect();
        v.sort_unstable();
        v
    };
    assert_eq!(
        others(&free),
        others(&held_run),
        "other links' emission moved"
    );
    let first = |r: &TRun| {
        r.c2r
            .iter()
            .find(|e| e.slot == held_link.0 && e.len == 4352)
            .map(|e| e.t_ms)
            .unwrap()
    };
    let (t_free, t_held) = (first(&free), first(&held_run));
    assert_eq!(t_held, t_free + 5_000);
    // not vacuous: another link wrote while the held frame was pending
    assert!(
        others(&held_run)
            .iter()
            .any(|(t, _)| *t > t_free && *t < t_held),
        "no other tick inside the 5 s"
    );
    let log = rig.x.driver.log().unwrap();
    assert!(
        !log.events
            .iter()
            .any(|(_, e)| matches!(e, LinkEvent::TornDown(..))),
        "{:?}",
        log.events
    );
    assert_eq!(held_run.overruns, 0);
}

// ---- EXTB-4: connects ------------------------------------------------------------------------------------------------

/// One Strict contact (two links, no phase) through a provider that answers every connect `answer_ms` late.
pub(crate) async fn late_rig(answer_ms: u64, seed: u64) -> TokioRig<Holding> {
    let setup = Setup::new();
    let provider = Holding::new(setup.provider.clone(), usize::MAX, None, answer_ms);
    let sc = Scenario {
        mode: Mode::Strict,
        contacts: vec![(10_000, 10_000)],
        pool: false,
        seed,
    };
    let x = TClient::with_provider(
        &setup,
        provider,
        sc.mode,
        no_phase(),
        sc.seed,
        Costs::default(),
        0,
    );
    TokioRig::assemble(setup, x, &sc).await
}

/// The connections the client under test (not the set-up) reached the relay with.
pub(crate) fn client_connects(rig: &TokioRig<Holding>) -> usize {
    rig.setup
        .provider
        .connects()
        .iter()
        .filter(|(_, iso)| iso.0 < crate::m6_tokio::SETUP_ISO)
        .count()
}

/// EXTB-4: connects outlive neither the driver's shutdown nor its drop. The provider answers 100 ms late; the driver runs
/// 5 ms (both links' connects pending) and is shut down — explicitly (`Driver::shutdown`, which reports every pending
/// connect as failed to the scheduler) or by dropping it. Afterwards no connection reaches the relay and nothing is
/// written.
#[test]
fn driver_shutdown_aborts_pending_connects() {
    for explicit in [true, false] {
        runtime().block_on(async {
            let mut rig = late_rig(100, 51).await;
            let t0 = rig.setup.now();
            rig.x.run_until(t0 + 5).await;
            let pending: Vec<LinkId> = rig
                .x
                .driver
                .log()
                .unwrap()
                .connects
                .iter()
                .filter_map(|(_, p, _)| match p {
                    Purpose::Link(l, _) => Some(*l),
                    Purpose::Control(_) => None,
                })
                .collect();
            assert_eq!(pending.len(), 2, "both connects pending");
            if explicit {
                rig.x.driver.shutdown(&mut rig.x.sched).unwrap();
                let log = rig.x.driver.log().unwrap();
                for l in &pending {
                    assert!(
                        log.resolved.iter().any(|(_, r, up)| r == l && !up),
                        "{l:?} resolved as failed"
                    );
                }
                assert!(
                    rig.x.sched.links().iter().all(|l| l.id.is_none()),
                    "no link is left connecting"
                );
            } else {
                let fresh = TClient::with_provider(
                    &rig.setup,
                    Holding::new(rig.setup.provider.clone(), usize::MAX, None, 0),
                    Mode::Strict,
                    no_phase(),
                    51,
                    Costs::default(),
                    1,
                );
                drop(core::mem::replace(&mut rig.x.driver, fresh.driver));
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            assert_eq!(
                client_connects(&rig),
                0,
                "explicit {explicit}: a connection after the shutdown"
            );
            assert!(
                rig.setup
                    .relay
                    .units()
                    .iter()
                    .all(|u| u.isolation.0 >= crate::m6_tokio::SETUP_ISO),
                "explicit {explicit}: bytes after the shutdown"
            );
        });
    }
}

/// EXTB-4: a link closed while its connect is pending (a mode change tears it down) never starts I/O — whether its
/// connect is aborted before the provider answers (at 5 ms), or its completion is already on its way (at 100 ms, the
/// moment the provider answers): the completion is discarded before any stream task starts, the old link writes no
/// frame, and the new link of the new mode comes up and writes.
#[test]
fn driver_close_reconnect_race_discards_old_completion() {
    use crate::m6_sched_bal::NoCells;
    for close_at in [5_u64, 100] {
        runtime().block_on(async {
            let mut rig = late_rig(100, 52).await;
            let t0 = rig.setup.now();
            rig.x.run_until(t0 + close_at).await;
            let old: Vec<(LinkId, Isolation)> = rig
                .x
                .driver
                .log()
                .unwrap()
                .connects
                .iter()
                .filter_map(|(_, p, iso)| match p {
                    Purpose::Link(l, _) => Some((*l, *iso)),
                    Purpose::Control(_) => None,
                })
                .collect();
            let connecting = rig
                .x
                .sched
                .links()
                .iter()
                .any(|l| l.id.is_some() && l.t_up.is_none());
            let outs = rig
                .x
                .sched
                .set_mode(t0 + close_at, Mode::Balanced, &mut NoCells)
                .unwrap();
            rig.x.driver.submit(&mut rig.x.sched, outs).unwrap();
            rig.x.run_until(t0 + 60_000).await;
            let log = rig.x.driver.log().unwrap();
            for (l, iso) in &old {
                let frames = rig
                    .setup
                    .relay
                    .units()
                    .iter()
                    .filter(|u| u.isolation == *iso && u.len == 4352)
                    .count();
                assert_eq!(
                    frames, 0,
                    "close at {close_at}: old link {l:?} wrote frames"
                );
                assert!(
                    !rig.x.driver.has_link_io(*l),
                    "close at {close_at}: old link {l:?} has stream tasks"
                );
            }
            if connecting {
                assert!(
                    old.iter()
                        .all(|(l, _)| log.discarded.iter().any(|(_, d)| d == l)),
                    "close at {close_at}: the old completions were discarded: {:?}",
                    log.discarded
                );
            }
            let new_up = log.events.iter().any(|(_, e)| match e {
                LinkEvent::Up(l, _) => !old.iter().any(|(o, _)| o == l),
                _ => false,
            });
            assert!(new_up, "close at {close_at}: the Balanced link came up");
        });
    }
}

// ---- GLMB-1: a black-holed link -------------------------------------------------------------------------------------

/// The relay's handshake bytes (`RELAYINFO` 1744 + `HS2` 1156): a black hole after them leaves the link up and silent.
const RELAY_HANDSHAKE: usize = 1744 + 1156;

/// GLMB-1: a link whose peer goes silent right after the handshake — it takes the client's frames and never answers,
/// as a black-holed TCP connection does — is closed within the relay's idle bound `link_idle_secs` (240 s = 3 × the
/// slowest period), even at the slowest period (80 s): the unanswered requests reach the in-flight bound at the third
/// tick, and the link is torn down and connects again; the other link is untouched. (The direct dialer's own socket
/// options are `tls::tests::direct_tcp_socket_has_keepalive_and_no_delay`; the kernel's timers cannot be driven by the
/// paused clock.)
#[test]
fn direct_blackhole_link_is_closed_within_idle_bound() {
    runtime().block_on(async {
        let setup = Setup::new();
        let mut provider = Holding::new(setup.provider.clone(), 0, None, 0);
        provider.mute_after = Some(RELAY_HANDSHAKE);
        let sc = Scenario {
            mode: Mode::Strict,
            contacts: vec![(80_000, 80_000)],
            pool: false,
            seed: 61,
        };
        let x = TClient::with_provider(
            &setup,
            provider,
            sc.mode,
            no_phase(),
            sc.seed,
            Costs::default(),
            0,
        );
        let mut rig = TokioRig::assemble(setup, x, &sc).await;
        rig.run_minutes(6, None).await;
        let silent = link_of(&rig, 0);
        let other = link_of(&rig, 1);
        let log = rig.x.driver.log().unwrap();
        let up = log
            .events
            .iter()
            .find_map(|(t, e)| (matches!(e, LinkEvent::Up(x, _) if *x == silent)).then_some(*t))
            .unwrap();
        let torn = log
            .events
            .iter()
            .find_map(|(t, e)| match e {
                LinkEvent::TornDown(l, _, reason) if *l == silent => Some((*t, *reason)),
                _ => None,
            })
            .unwrap();
        let idle_bound = secmp_testkit::harness::RelayLimits::defaults().link_idle_ms;
        assert_eq!(idle_bound, 240_000);
        assert!(
            torn.0 - up <= idle_bound,
            "closed after {} ms: {torn:?}",
            torn.0 - up
        );
        assert_eq!(torn.1, Reason::InFlight);
        assert!(
            !rig.x.driver.has_link_io(silent),
            "its stream tasks stopped"
        );
        assert!(
            !log.events
                .iter()
                .any(|(_, e)| matches!(e, LinkEvent::TornDown(l, _, _) if *l == other)),
            "{:?}",
            log.events
        );
    });
}

/// CLIENT-BOUND (WEISUNG M6-CI-4): a connect that never completes — the dial hangs (`hang`), or the peer accepts and
/// never writes a byte (`mute_after` 0: the link handshake never gets its `RELAYINFO`) — is bounded: the link is
/// resolved as failed / torn down and tried again within `link_idle_ms` (240 s), its connect task is gone, and the other
/// link of the contact is unaffected.
#[test]
fn driver_never_completing_connect_is_bounded() {
    for hang in [true, false] {
        runtime().block_on(async {
            let setup = Setup::new();
            let mut provider = Holding::new(setup.provider.clone(), 0, None, 0);
            if hang {
                provider.hang = true;
            } else {
                provider.mute_after = Some(0);
            }
            let sc = Scenario {
                mode: Mode::Strict,
                contacts: vec![(10_000, 10_000)],
                pool: false,
                seed: 71,
            };
            let x = TClient::with_provider(
                &setup,
                provider,
                sc.mode,
                no_phase(),
                sc.seed,
                Costs::default(),
                0,
            );
            let mut rig = TokioRig::assemble(setup, x, &sc).await;
            rig.run_minutes(10, None).await;
            let stuck = link_of(&rig, 0);
            let other = link_of(&rig, 1);
            let log = rig.x.driver.log().unwrap();
            let started = log
                .connects
                .iter()
                .find_map(|(t, p, _)| matches!(p, Purpose::Link(l, _) if *l == stuck).then_some(*t))
                .unwrap();
            let bound = secmp_testkit::harness::RelayLimits::defaults().link_idle_ms;
            assert_eq!(bound, 240_000);
            let ended = log
                .resolved
                .iter()
                .find_map(|(t, l, up)| (*l == stuck && !up).then_some(*t))
                .or_else(|| {
                    log.events.iter().find_map(|(t, e)| {
                        matches!(e, LinkEvent::TornDown(l, _, _) if *l == stuck).then_some(*t)
                    })
                });
            // the mechanism: the driver's own connect timeout over provider connect + link handshake, which is below the
            // relay's idle bound
            assert!(CONNECT_TIMEOUT_MS < bound);
            assert_eq!(
                ended,
                Some(started + CONNECT_TIMEOUT_MS),
                "hang {hang}: connect started at {started}, ended {ended:?} (bound {bound} ms)"
            );
            assert!(
                !rig.x.driver.has_link_io(stuck),
                "hang {hang}: its tasks are gone"
            );
            assert!(
                !log.events
                    .iter()
                    .any(|(_, e)| matches!(e, LinkEvent::TornDown(l, _, _) if *l == other)),
                "hang {hang}: the other link was torn down"
            );
        });
    }
}

/// EXT3B-2 (Codex M6B-EXT3c): a hanging writer on one link does not shift the tick of another link whose tick is due
/// inside the flush wait. Strict, one contact (two links, P = 10 s, no phase): link 1 is up at 0 and ticks at 130 000;
/// link 0 connects late, is up at 119 999, and its first write, due at 129 999, hangs for 20 s. The flush wait of the
/// pass at 129 999 must end before link 1's tick (it waited 250 ms: `PollDue(130249)`, `TornDown(LinkId(1), Overrun)`).
/// The equal-due case is `driver_hanging_writer_does_not_delay_other_links`.
#[test]
fn driver_hanging_writer_does_not_shift_staggered_tick() {
    runtime().block_on(async {
        let setup = Setup::new();
        let mut provider = Holding::new(
            setup.provider.clone(),
            0,
            Some(Hold {
                first: 0,
                delay_ms: 20_000,
            }),
            119_999,
        );
        provider.late_only_which = true;
        let sc = Scenario {
            mode: Mode::Strict,
            contacts: vec![(10_000, 10_000)],
            pool: false,
            seed: 81,
        };
        let x = TClient::with_provider(
            &setup,
            provider,
            sc.mode,
            no_phase(),
            sc.seed,
            Costs::default(),
            0,
        );
        let mut rig = TokioRig::assemble(setup, x, &sc).await;
        let run = rig.run_minutes(3, None).await;
        let (held, healthy) = (link_of(&rig, 0), link_of(&rig, 1));
        let log = rig.x.driver.log().unwrap();
        let up_held = log
            .events
            .iter()
            .find_map(|(t, e)| (matches!(e, LinkEvent::Up(x, _) if *x == held)).then_some(*t))
            .unwrap();
        assert_eq!(up_held, 119_999, "the late link comes up at 119 999");
        let torn_healthy: Vec<_> = log
            .events
            .iter()
            .filter(|(_, e)| matches!(e, LinkEvent::TornDown(l, _, _) if *l == healthy))
            .collect();
        assert!(
            torn_healthy.is_empty(),
            "the healthy link was torn down: {torn_healthy:?}"
        );
        assert!(
            run.c2r
                .iter()
                .any(|e| e.slot == healthy.0 && e.len == 4352 && e.t_ms == 130_000),
            "the healthy link wrote its tick at 130 000"
        );
        assert_eq!(run.overruns, 0);
    });
}

/// Mutants-156 (`run.rs` `stop_tasks` → `()`): `shutdown` aborts the control tasks too. One Strict contact and the pool
/// through a provider that answers every connect 60 s late; the run goes on until a control operation's one-shot connection
/// is pending, the driver is shut down, and no connection reaches the relay afterwards (the links' connects are aborted by
/// `shutdown` itself; the control task is `stop_tasks`'s).
#[test]
fn driver_shutdown_aborts_pending_control_operations() {
    runtime().block_on(async {
        let setup = Setup::new();
        let provider = Holding::new(setup.provider.clone(), usize::MAX, None, 60_000);
        let sc = Scenario {
            mode: Mode::Strict,
            contacts: vec![(10_000, 10_000)],
            pool: true,
            seed: 54,
        };
        let x = TClient::with_provider(
            &setup,
            provider,
            sc.mode,
            no_phase(),
            sc.seed,
            Costs::default(),
            0,
        );
        let mut rig = TokioRig::assemble(setup, x, &sc).await;
        let t0 = rig.setup.now();
        let mut t = t0;
        let control_pending = |rig: &TokioRig<Holding>| {
            rig.x
                .driver
                .log()
                .unwrap()
                .connects
                .iter()
                .any(|(_, p, _)| matches!(p, Purpose::Control(_)))
        };
        while !control_pending(&rig) {
            t += 1_000;
            assert!(t < t0 + 4 * 3_600_000, "no control operation started");
            rig.x.run_until(t).await;
        }
        let before = client_connects(&rig);
        rig.x.driver.shutdown(&mut rig.x.sched).unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        assert_eq!(
            client_connects(&rig),
            before,
            "a control operation connected after the shutdown"
        );
    });
}

/// Mutants-156 (`run.rs` `apply`, `io.pending > 0` → `<` in the stalled-write branch): a link whose write is still pending
/// when its next tick's write is handed out is closed at that tick. With the shipped periods (≥ 10 s = `WRITE_STALL_MS`)
/// `close_stalled` always comes first, so the periods are 5 s here (`Params::periods_ms`): the first frame, written at
/// 5 s, hangs for 20 s; the tick at 10 s closes the link (not the stall bound at 15 s).
#[test]
fn driver_closes_a_link_whose_write_is_pending_at_its_next_tick() {
    runtime().block_on(async {
        let setup = Setup::new();
        let provider = Holding::new(
            setup.provider.clone(),
            0,
            Some(Hold {
                first: 0,
                delay_ms: 20_000,
            }),
            0,
        );
        let sc = Scenario {
            mode: Mode::Strict,
            contacts: vec![(5_000, 5_000)],
            pool: false,
            seed: 91,
        };
        let params = Params {
            phase_max_ms: 0,
            periods_ms: [5_000, 10_000, 20_000, 40_000],
            ..Params::default()
        };
        let x = TClient::with_provider(
            &setup,
            provider,
            sc.mode,
            params,
            sc.seed,
            Costs::default(),
            0,
        );
        let mut rig = TokioRig::assemble(setup, x, &sc).await;
        rig.run_minutes(1, None).await;
        let held = link_of(&rig, 0);
        let log = rig.x.driver.log().unwrap();
        let torn = log.events.iter().find_map(|(t, e)| {
            matches!(e, LinkEvent::TornDown(l, _, _) if *l == held).then_some(*t)
        });
        assert_eq!(torn, Some(10_000), "{:?}", log.events);
    });
}

/// The `Flushed` time of the pass whose `PollDue` is at `t` (the first one at `t`).
fn flushed_of_pass(steps: &[Step], t: u64) -> Option<u64> {
    let at = steps.iter().position(|s| *s == Step::PollDue(t))?;
    steps.get(at..)?.iter().find_map(|s| match s {
        Step::Flushed(f) => Some(*f),
        _ => None,
    })
}

/// Mutants-156 (`run.rs` `flush_wait`: replaced by `Ok(())`, `pending > 0` → `==`/`<`, `oldest == Some(now)` → `!=`,
/// `left == 0` → `!=`): the pass that hands a write out waits for it. Two links' first frames are due together, one is held
/// 100 ms: the pass's `Flushed` is the held write's completion — not the pass's own time (no wait), not 250 ms — and its
/// `work` starts after it. (The old `wrote_before_work` checks pass without any wait: the next pass starts at the completion.)
#[test]
fn flush_wait_ends_at_the_completion_of_the_pass_writes() {
    let hold = Hold {
        first: 0,
        delay_ms: 100,
    };
    let (_, rig) = run_holding(no_phase(), 43, 0, Some(hold), 1);
    let log = rig.x.driver.log().unwrap();
    let stuck = link_of(&rig, 0);
    let done = log
        .steps
        .iter()
        .find_map(|s| match s {
            Step::Wrote(t, l, 4352) if *l == stuck => Some(*t),
            _ => None,
        })
        .unwrap();
    let t = done - 100;
    assert_eq!(
        flushed_of_pass(&log.steps, t),
        Some(done),
        "{:?}",
        log.steps
    );
    assert!(
        !log.steps
            .iter()
            .any(|s| matches!(s, Step::Work(start, _) if *start > t && *start < done)),
        "no work starts inside the stuck write"
    );
}

/// Mutants-156 (`flush_wait`, `pending > 0 && oldest == Some(now)` → `||`): only the writes handed out in THIS pass are waited
/// for. One first frame is stuck 9.5 s (past the 250 ms wait, inside the stall bound); the pass at the FETCH lead of the
/// next tick (tick − 1000 ms), which hands out nothing, does not wait for the old write: `Flushed` is its own time.
#[test]
fn flush_wait_does_not_wait_for_an_earlier_pass_write() {
    let hold = Hold {
        first: 0,
        delay_ms: 9_500,
    };
    let (_, rig) = run_holding(no_phase(), 43, 0, Some(hold), 1);
    let log = rig.x.driver.log().unwrap();
    let stuck = link_of(&rig, 0);
    let done = log
        .steps
        .iter()
        .find_map(|s| match s {
            Step::Wrote(t, l, 4352) if *l == stuck => Some(*t),
            _ => None,
        })
        .unwrap();
    let submitted = done - 9_500;
    let lead = submitted + 9_000;
    assert!(
        log.steps.contains(&Step::PollDue(lead)),
        "a pass at the FETCH lead: {:?}",
        log.steps
    );
    assert_eq!(flushed_of_pass(&log.steps, lead), Some(lead));
    // the pass that handed the write out waited its 250 ms, no more
    assert_eq!(
        flushed_of_pass(&log.steps, submitted),
        Some(submitted + 250)
    );
}

/// One FIN-1 run (Strict, two contacts, four links, no phase, the AI costs): the connections are planned — connection 0
/// stalls on its first frame (5 s), connection 1 completes at 10 100 ms (inside the flush wait of the pass at the first
/// tick, 10 000), connection 2 is healthy, connection 3 never completes. Returns the relay-visible client frames
/// `(time, slot, size)`; `active` adds the activity (real cells cost 20 ms, dummies 1 ms, in the worker).
pub(crate) fn fin1_run(trace: Option<u64>, connect_fails: bool) -> Vec<(u64, u64, usize)> {
    use crate::m6_activity::activity;
    use crate::m6_tokio::AI_COSTS;
    runtime().block_on(async {
        let setup = Setup::new();
        let mut provider = Holding::new(setup.provider.clone(), usize::MAX, None, 0);
        provider.plans = vec![
            (
                Some(Hold {
                    first: 0,
                    delay_ms: 5_000,
                }),
                0,
                false,
            ),
            (None, 10_100, false),
            (None, 0, false),
            (None, 0, true),
        ];
        if connect_fails {
            provider.fails = vec![1];
        }
        let sc = Scenario {
            mode: Mode::Strict,
            contacts: vec![(10_000, 10_000), (10_000, 10_000)],
            pool: false,
            seed: 95,
        };
        let x = TClient::with_provider(&setup, provider, sc.mode, no_phase(), sc.seed, AI_COSTS, 0);
        let mut rig = TokioRig::assemble(setup, x, &sc).await;
        let act = trace.map(|t| activity(95_u64.saturating_add(t), 3, sc.contacts.len()));
        let run = rig.run_minutes(1, act.as_ref()).await;
        run.c2r
            .iter()
            .filter(|e| e.dir == Dir::C2R)
            .map(|e| (e.t_ms, e.slot, e.len))
            .collect()
    })
}

/// FIN-1 (Astra final pass): an event that arrived during a flush wait is anchored at its occurrence, not at the time a
/// worker job happened to wake the loop. A connection completing at 10 100 ms while another writer stalls — or failing
/// at 10 100 ms, and the reconnect after it — gives the same relay-visible frames idle and active (the pin: every frame
/// of the late link 19 ms later in the active run, 20251 vs 20270).
#[test]
fn driver_stashed_connect_is_anchored_at_its_occurrence() {
    for connect_fails in [false, true] {
        let idle = fin1_run(None, connect_fails);
        let active = fin1_run(Some(0), connect_fails);
        assert!(idle.iter().any(|e| e.2 == 4352), "frames were sent");
        if !connect_fails {
            // anchored at the occurrence: the connection that completed at 10 100 ticks at 20 100, not at the end of the
            // flush wait of the pass in which it arrived (20 250 / 20 251)
            assert!(idle.contains(&(20_100, 1, 4352)), "{idle:?}");
        }
        assert_eq!(idle, active, "connect fails: {connect_fails}");
    }
}

/// FIN-2 (Astra final pass): the Balanced round-robin position advances when a SEND frame was completely written, not when
/// the core handed it out. Balanced, three send queues at 10 s; the first connection's first frame is held at zero bytes
/// (a stalled writer) and the driver closes the link at the next tick; the replacement link's first SEND goes to the queue
/// the abandoned frame was for (the pin: queue 2, the rotation having moved past a SEND that never left the process).
#[test]
fn driver_rr_does_not_advance_for_a_send_never_written() {
    fn send_rids(hold: Option<Hold>) -> Vec<secmp_proto::wire::Id> {
        runtime().block_on(async {
            let setup = Setup::new();
            let provider = Holding::new(setup.provider.clone(), 0, hold, 0);
            let sc = Scenario {
                mode: Mode::Balanced,
                contacts: vec![(10_000, 10_000); 3],
                pool: false,
                seed: 97,
            };
            let x = TClient::with_provider(
                &setup,
                provider,
                sc.mode,
                no_phase(),
                sc.seed,
                Costs::default(),
                0,
            );
            let mut rig = TokioRig::assemble(setup, x, &sc).await;
            let run = rig.run_minutes(2, None).await;
            run.sends.iter().take(6).map(|s| s.1).collect()
        })
    }
    let free = send_rids(None);
    // the normal path: the rotation advances exactly once per written SEND — three queues, each in turn, then again
    assert_eq!(free.len(), 6);
    let (first, second) = (free.get(..3).unwrap(), free.get(3..).unwrap());
    assert_eq!(first, second);
    let distinct: std::collections::BTreeSet<_> = first.iter().collect();
    assert_eq!(distinct.len(), 3);
    let stalled = send_rids(Some(Hold {
        first: 0,
        delay_ms: 600_000,
    }));
    assert_eq!(
        stalled.first(),
        free.first(),
        "the rotation moved past a SEND that was never written"
    );
}

/// The relay-visible SENDs `(time, queue, next_cell_id)` of one Balanced run (three send queues at 10 s, no phase, seed 103,
/// the AI costs: a real cell 20 ms, a dummy 1 ms) whose first frame is held for `delay_ms` after `first` bytes; `active`
/// adds the activity.
fn fin21_sends(
    first: usize,
    delay_ms: u64,
    active: bool,
) -> Vec<(u64, secmp_proto::wire::Id, u64)> {
    use crate::m6_activity::activity;
    use crate::m6_tokio::AI_COSTS;
    runtime().block_on(async {
        let setup = Setup::new();
        let provider = Holding::new(setup.provider.clone(), 0, Some(Hold { first, delay_ms }), 0);
        let sc = Scenario {
            mode: Mode::Balanced,
            contacts: vec![(10_000, 10_000); 3],
            pool: false,
            seed: 103,
        };
        let x = TClient::with_provider(&setup, provider, sc.mode, no_phase(), sc.seed, AI_COSTS, 0);
        let mut rig = TokioRig::assemble(setup, x, &sc).await;
        let act = activity(103, 3, sc.contacts.len());
        let run = rig
            .run_minutes(1, if active { Some(&act) } else { None })
            .await;
        run.sends
    })
}

/// FIN2-1 (Astra FINAL2, GLM EXT5): the next SEND is chosen against the position the pending SEND will commit, not the
/// committed one, so the choice does not depend on whether the worker finishes preparing before or after the write
/// completes. Balanced, first frame held 260 ms (past the 250-ms flush bound; 0 or 128 bytes written first): idle and
/// active relay-visible SENDs are equal (the pin: `20000 Q0` idle against `20000 Q1` active); a 200-ms hold, inside the
/// flush wait, is the control.
#[test]
fn driver_rr_reservation_does_not_depend_on_worker_timing() {
    for (first, delay_ms) in [(0, 260), (128, 260), (0, 200)] {
        let idle = fin21_sends(first, delay_ms, false);
        let active = fin21_sends(first, delay_ms, true);
        assert!(idle.len() >= 4, "{idle:?}");
        let rids = |v: &[(u64, secmp_proto::wire::Id, u64)]| -> Vec<(u64, u8)> {
            v.iter()
                .map(|s| (s.0, s.1.first().copied().unwrap_or(0)))
                .collect()
        };
        assert_eq!(
            rids(&idle),
            rids(&active),
            "held {delay_ms} ms after {first} bytes"
        );
    }
}

/// C2-03 (item 10): the tokio driver reports every write once, in order: after the scenario of
/// `driver_rr_reservation_does_not_depend_on_worker_timing` (Balanced, seed 103, first frame held 260 ms) the scheduler
/// counted no unmatched `frame_written`; the driver's `debug_assert_eq!` after each `on_written` did not fire either.
#[test]
fn driver_reports_no_unmatched_written() {
    use crate::m6_tokio::AI_COSTS;
    runtime().block_on(async {
        let setup = Setup::new();
        let provider = Holding::new(
            setup.provider.clone(),
            0,
            Some(Hold {
                first: 0,
                delay_ms: 260,
            }),
            0,
        );
        let sc = Scenario {
            mode: Mode::Balanced,
            contacts: vec![(10_000, 10_000); 3],
            pool: false,
            seed: 103,
        };
        let x = TClient::with_provider(&setup, provider, sc.mode, no_phase(), sc.seed, AI_COSTS, 0);
        let mut rig = TokioRig::assemble(setup, x, &sc).await;
        let run = rig.run_minutes(1, None).await;
        assert!(run.sends.len() >= 4, "{:?}", run.sends);
        assert_eq!(rig.x.sched.unmatched_written(), 0);
    });
}

/// R-01 (OPEN-M6-B-1, a characterisation, not a requirement): the receive throughput of the driver's `Deferred` facade. One
/// Balanced client with one recv queue and the AI costs (a received cell 5 ms); the peer has stored four cells before the first
/// `FETCH_MULTI`. Per period the test records how many cells were newly committed (decided and persisted by the worker, so
/// delivered to the conversation) and when each cell became ready to acknowledge — the scheduler's *internal* acknowledgement
/// state (`Scheduler::acked`), which the next `FETCH_MULTI` carries — and, as a second series, when the relay saw the
/// acknowledgement (its head moved). M7 B-SC (OQ-20, OPEN-M7-08 A; the M6 series — one cell per response, each acknowledged
/// one period after its commit — is history): the core hands every cell of a response to the worker at once and
/// acknowledges the highest committed prefix, so the expectation is now **all four cells are committed after the first
/// response, each is ready to be acknowledged as soon as it is committed, and the relay sees one acknowledgement of all four
/// with the next `FETCH_MULTI`, at most one period later**. The numbers are printed (`target/m6-evidence/R-01.txt`) and
/// change only with the reviewer.
#[test]
fn receive_throughput_per_fetch_is_measured() {
    use crate::m6_activity::Event;
    use crate::m6_tokio::AI_COSTS;
    runtime().block_on(async {
        let setup = Setup::new();
        let sc = Scenario {
            mode: Mode::Balanced,
            contacts: vec![(10_000, 10_000)],
            pool: false,
            seed: 71,
        };
        let x = TClient::new(&setup, sc.mode, no_phase(), sc.seed, AI_COSTS, 0);
        let mut rig = TokioRig::assemble(setup, x, &sc).await;
        let t0 = rig.setup.now();
        for n in 0..4_u64 {
            rig.apply(Event::PeerSend { contact: 0, len: 20 }, t0, n);
        }
        rig.pump(t0).await;
        let recv = secmp_client_core::scheduler::types::QueueId(1);
        let committed = |rig: &TokioRig| {
            rig.x
                .convs
                .lock()
                .unwrap()
                .get(0)
                .unwrap()
                .received()
                .len()
        };
        let (mut got_at, mut acked_at) = (Vec::new(), Vec::new());
        let mut per_second = Vec::new();
        for s in 1..=90_u64 {
            rig.x.run_until(t0 + s * 1_000).await;
            let (c, a) = (
                committed(&rig),
                usize::try_from(rig.x.sched.acked(recv).unwrap()).unwrap(),
            );
            while got_at.len() < c {
                got_at.push(s);
            }
            while acked_at.len() < a {
                acked_at.push(s);
            }
            per_second.push((s, c, a));
        }
        let delays: Vec<u64> = acked_at
            .iter()
            .zip(&got_at)
            .map(|(a, g)| a.saturating_sub(*g))
            .collect();
        let steps: Vec<u64> = got_at
            .windows(2)
            .map(|w| {
                w.get(1)
                    .copied()
                    .unwrap_or(0)
                    .saturating_sub(w.first().copied().unwrap_or(0))
            })
            .collect();
        let text = format!(
            "R-01 receive throughput of the facade (Balanced, 4 cells stored before the first FETCH, costs 5 ms per received cell)\n\
             committed at (s): {got_at:?}\nready to acknowledge at (s, internal): {acked_at:?}\n\
             seconds between commits: {steps:?}\nack delay per cell (s): {delays:?}"
        );
        let relay_acks: Vec<u64> = {
            let mut last: std::collections::BTreeMap<secmp_proto::wire::Id, u64> =
                std::collections::BTreeMap::new();
            let mut seen = Vec::new();
            for c in rig.setup.relay.store_changes() {
                let before = last.insert(c.rid, c.head).unwrap_or(0);
                if c.isolation.0 < crate::m6_tokio::SETUP_ISO && c.head != before {
                    seen.push(c.t_ms.saturating_sub(t0) / 1_000);
                }
            }
            seen
        };
        let text = format!("{text}\nrelay-observed acknowledgement at (s): {relay_acks:?}");
        crate::m6_common::evidence("R-01", &text);
        assert_eq!(got_at.len(), 4, "all four cells are committed: {text}");
        assert_eq!(acked_at.len(), 4, "all four become ready to acknowledge: {text}");
        assert_eq!(relay_acks.len(), 1, "the relay saw one acknowledgement of all four: {text}");
        assert!(
            acked_at.iter().all(|a| relay_acks.iter().all(|w| w >= a)),
            "the relay sees the acknowledgement no earlier than it is ready: {text}"
        );
        // every cell of the response at once: the commits fall in one second
        assert!(steps.iter().all(|d| *d == 0), "{text}");
        // each acknowledgement is ready as soon as its cell is committed
        assert!(delays.iter().all(|d| *d == 0), "{text}");
        // the next FETCH_MULTI carries it: at most one period (10 s) after the commits
        assert!(
            relay_acks
                .iter()
                .all(|w| w.saturating_sub(got_at.last().copied().unwrap_or(0)) <= 10),
            "{text}"
        );
    });
}
