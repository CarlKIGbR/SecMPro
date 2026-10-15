// SPDX-License-Identifier: AGPL-3.0-or-later
//! The external review of `f68d923` (WEISUNG M6-B-5, EXTB-3, EXTB-4): the tokio driver's writes and connects on a
//! paused clock, over a provider that holds back (or splits) one connection's first frame, or answers late.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::run::{Purpose, Step};
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
}

impl AsyncRead for Throttled {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
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
}

impl Holding {
    fn new(inner: MemProvider, which: usize, hold: Option<Hold>, answer_ms: u64) -> Self {
        Self {
            inner,
            which,
            hold,
            answer_ms,
            count: Arc::new(AtomicUsize::new(0)),
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
        let (inner, relay, answer_ms) = (self.inner.clone(), relay.clone(), self.answer_ms);
        async move {
            if answer_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(answer_ms)).await;
            }
            let stream = inner.connect(&relay, isolation).await?;
            Ok(Throttled {
                inner: stream,
                written: 0,
                hold,
                sleep: None,
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

/// Whether `link`'s first frame was complete before the work of the pass that submitted it: the pass (the last
/// `poll_due` at or before the write's completion) reports a work end at or after that completion.
fn wrote_before_work(steps: &[Step], link: LinkId) -> bool {
    let Some(done) = steps.iter().find_map(|s| match s {
        Step::Wrote(t, l, 4352) if *l == link => Some(*t),
        _ => None,
    }) else {
        return false;
    };
    let Some(pass) = steps
        .iter()
        .filter_map(|s| match s {
            Step::PollDue(t) if *t <= done => Some(*t),
            _ => None,
        })
        .filter(|t| steps.contains(&Step::Wrote(*t, link, 4352)) || *t < done)
        .last()
    else {
        return false;
    };
    let _ = pass;
    // the work of the submitting pass: the first Work step whose start is the tick the frame was due at
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
