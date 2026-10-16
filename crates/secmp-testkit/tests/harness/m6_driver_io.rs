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
struct Hold {
    first: usize,
    delay_ms: u64,
}

/// A stream that holds back its first frame after the handshake (see [`Hold`]).
struct Throttled {
    inner: DuplexStream,
    written: usize,
    hold: Option<Hold>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    /// Bytes read so far, and after how many the peer goes silent (a black hole: nothing more is delivered).
    read: usize,
    mute_after: Option<usize>,
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
struct Holding {
    inner: MemProvider,
    which: usize,
    hold: Option<Hold>,
    answer_ms: u64,
    count: Arc<AtomicUsize>,
    /// Connection `which` goes silent after this many bytes from the relay.
    mute_after: Option<usize>,
    /// The connect of connection `which` never completes (a dial that hangs).
    hang: bool,
}

impl Holding {
    fn new(inner: MemProvider, which: usize, hold: Option<Hold>, answer_ms: u64) -> Self {
        Self {
            inner,
            which,
            hold,
            answer_ms,
            count: Arc::new(AtomicUsize::new(0)),
            mute_after: None,
            hang: false,
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
        let (inner, relay, answer_ms) = (self.inner.clone(), relay.clone(), self.answer_ms);
        let hang = self.hang && n == self.which;
        async move {
            if hang {
                core::future::pending::<()>().await;
            }
            if answer_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(answer_ms)).await;
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

fn scenario(seed: u64) -> Scenario {
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
fn link_of(rig: &TokioRig<Holding>, n: usize) -> LinkId {
    let links: Vec<LinkId> = rig
        .x
        .driver
        .log()
        .unwrap()
        .connects
        .iter()
        .filter_map(|(_, p, _)| match p {
            Purpose::Link(l) => Some(*l),
            Purpose::Control(_) => None,
        })
        .collect();
    *links.get(n).unwrap()
}

fn no_phase() -> Params {
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
            .find_map(|(t, e)| (*e == LinkEvent::Up(l)).then_some(*t))
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
        log.events
            .iter()
            .any(|(_, e)| *e == LinkEvent::TornDown(held_link, Reason::Closed)),
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
async fn late_rig(answer_ms: u64, seed: u64) -> TokioRig<Holding> {
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
fn client_connects(rig: &TokioRig<Holding>) -> usize {
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
                    Purpose::Link(l) => Some(*l),
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
                    Purpose::Link(l) => Some((*l, *iso)),
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
                LinkEvent::Up(l) => !old.iter().any(|(o, _)| o == l),
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
            .find_map(|(t, e)| (*e == LinkEvent::Up(silent)).then_some(*t))
            .unwrap();
        let torn = log
            .events
            .iter()
            .find_map(|(t, e)| match e {
                LinkEvent::TornDown(l, reason) if *l == silent => Some((*t, *reason)),
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
                .any(|(_, e)| matches!(e, LinkEvent::TornDown(l, _) if *l == other)),
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
                .find_map(|(t, p, _)| matches!(p, Purpose::Link(l) if *l == stuck).then_some(*t))
                .unwrap();
            let bound = secmp_testkit::harness::RelayLimits::defaults().link_idle_ms;
            assert_eq!(bound, 240_000);
            let ended = log
                .resolved
                .iter()
                .find_map(|(t, l, up)| (*l == stuck && !up).then_some(*t))
                .or_else(|| {
                    log.events.iter().find_map(|(t, e)| {
                        matches!(e, LinkEvent::TornDown(l, _) if *l == stuck).then_some(*t)
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
                    .any(|(_, e)| matches!(e, LinkEvent::TornDown(l, _) if *l == other)),
                "hang {hang}: the other link was torn down"
            );
        });
    }
}
