// SPDX-License-Identifier: AGPL-3.0-or-later
//! The server loops (`secmp_relay::server::{serve, handle}`) over in-memory streams, an in-memory listener and a
//! virtual clock — no socket (`docs/06` §4): the accept loop retries on `WouldBlock`/`Interrupted`, retries every
//! other `accept` error after a recorded wait and an `accept_retry` event, ends only when the listener is gone,
//! refuses connections while draining and over the connection cap (closed unread, no thread), hands each connection
//! to its own job, survives a job that cannot be started, and exits with an `exit` event once the drain has lasted
//! `drain_secs`; the connection loop ticks on read timeouts, retries interrupted reads, stops on EOF, an I/O error, a
//! failed write or a teardown, and always closes the stream. Extra tests of M5 Phase B (not TEST-SPEC rows) and of
//! the M05 review conditions C-1 and C-2.

use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use secmp_relay::event::{CaptureSink, EventSink};
use secmp_relay::server::{self, Listener, Stream, Time};
use secmp_relay::{Error, KeyRing, Limits, Now, Relay};

use crate::fixture::{HELLO, NOW, RelayFx, VALID_UNTIL};

/// A virtual clock: every reading advances the monotonic clock by `step` milliseconds; the accept loop's waits are
/// recorded, not slept. The log holds the readings (`None`) and the waits (`Some`) in order.
#[derive(Clone)]
struct Virtual(Arc<VirtualState>);

struct VirtualState {
    mono_ms: AtomicU64,
    step: u64,
    log: Mutex<Vec<Option<Duration>>>,
}

impl Virtual {
    fn new(step: u64) -> Self {
        Self(Arc::new(VirtualState {
            mono_ms: AtomicU64::new(0),
            step,
            log: Mutex::new(Vec::new()),
        }))
    }

    /// The readings (`None`) and the waits (`Some`) so far, in order.
    fn log(&self) -> Vec<Option<Duration>> {
        self.0.log.lock().unwrap().clone()
    }
}

impl Time for Virtual {
    fn now(&self) -> Now {
        let mut log = self.0.log.lock().unwrap();
        log.push(None);
        Now {
            unix_secs: NOW,
            mono_ms: self.0.mono_ms.fetch_add(self.0.step, Ordering::SeqCst),
        }
    }

    fn pause(&self, d: Duration) {
        self.0.log.lock().unwrap().push(Some(d));
    }
}

/// One read of a scripted stream.
enum In {
    Data(Vec<u8>),
    Fail(ErrorKind),
    /// An idle peer: the read blocks until the test releases it (or drops the sender), then EOF.
    Block(Receiver<()>),
}

/// What a scripted stream saw.
#[derive(Default)]
struct Seen {
    written: Vec<u8>,
    reads: usize,
    closed: bool,
    /// The read poll and the write timeout `set_poll` was given.
    timeouts: Option<(Duration, Duration)>,
}

/// A stream that reads its script (then EOF) and records writes, reads and the close.
struct Scripted {
    script: VecDeque<In>,
    seen: Arc<Mutex<Seen>>,
    fail_poll: bool,
    fail_write: bool,
    closed: Option<Sender<()>>,
    reading: Option<Sender<()>>,
}

impl Scripted {
    fn new(script: Vec<In>) -> (Self, Arc<Mutex<Seen>>) {
        let seen = Arc::new(Mutex::new(Seen::default()));
        (
            Self {
                script: script.into(),
                seen: Arc::clone(&seen),
                fail_poll: false,
                fail_write: false,
                closed: None,
                reading: None,
            },
            seen,
        )
    }
}

impl Read for Scripted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut seen = self.seen.lock().unwrap();
        seen.reads = seen.reads.checked_add(1).unwrap();
        drop(seen);
        if let Some(tx) = &self.reading {
            let _ = tx.send(());
        }
        match self.script.pop_front() {
            Some(In::Data(d)) => {
                buf.get_mut(..d.len()).unwrap().copy_from_slice(&d);
                Ok(d.len())
            }
            Some(In::Fail(kind)) => Err(io::Error::from(kind)),
            Some(In::Block(release)) => {
                let _ = release.recv();
                Ok(0)
            }
            None => Ok(0),
        }
    }
}

impl Write for Scripted {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.fail_write {
            return Err(io::Error::from(ErrorKind::BrokenPipe));
        }
        self.seen.lock().unwrap().written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Stream for Scripted {
    fn set_poll(&mut self, poll: Duration, write: Duration) -> io::Result<()> {
        self.seen.lock().unwrap().timeouts = Some((poll, write));
        if self.fail_poll {
            Err(io::Error::from(ErrorKind::Other))
        } else {
            Ok(())
        }
    }

    fn close(&mut self) {
        self.seen.lock().unwrap().closed = true;
        if let Some(tx) = &self.closed {
            let _ = tx.send(());
        }
    }
}

/// The accept calls a test lets `serve` make: a one-second drain on a clock of ≥ 100 ms per reading ends within ≈ 10
/// calls; the next call fails like a dead listener, so a drain that never starts or never finishes fails the test
/// (`serve` returns `Error::Io`) instead of hanging it.
const ACCEPT_CALLS_MAX: usize = 100;

/// A dead listener's error (EBADF, the first of `server::LISTENER_GONE`): `serve` ends on it.
fn dead() -> io::Error {
    let [ebadf, _, _] = server::LISTENER_GONE;
    io::Error::from_raw_os_error(ebadf)
}

/// The relay a listener drains, its clock, and the signal of the handed-out connection's close (taken once).
type Drain = (Arc<Relay>, Virtual, Mutex<Option<Receiver<()>>>);

/// A listener that hands out its script, then (once, after the handed-out connection has closed) starts the relay's
/// drain and reports `WouldBlock`; after `ACCEPT_CALLS_MAX` calls it fails.
struct ScriptedListener {
    script: Mutex<VecDeque<io::Result<Scripted>>>,
    drain: Option<Drain>,
    calls: AtomicUsize,
}

impl Listener for ScriptedListener {
    type Conn = Scripted;

    fn accept_next(&self) -> io::Result<Scripted> {
        if self.calls.fetch_add(1, Ordering::SeqCst) >= ACCEPT_CALLS_MAX {
            return Err(dead());
        }
        if let Some(next) = self.script.lock().unwrap().pop_front() {
            return next;
        }
        if let Some((relay, clock, closed)) = &self.drain
            && !relay.draining()
            && let Some(closed) = closed.lock().unwrap().take()
        {
            closed.recv_timeout(SIGNAL).unwrap();
            relay.start_drain(clock.now());
        }
        Err(io::Error::from(ErrorKind::WouldBlock))
    }
}

/// An event sink the test keeps a handle to.
struct Shared(Arc<CaptureSink>);

impl EventSink for Shared {
    fn emit(&self, event: &secmp_relay::event::Event<'_>) {
        self.0.emit(event);
    }
}

/// The relay of case 1 with a one-second drain; its events.
fn relay() -> (Arc<Relay>, Arc<CaptureSink>) {
    relay_with(Limits::vectors().max_connections)
}

/// The relay of case 1 with a one-second drain and a connection cap of `max_connections`; its events.
fn relay_with(max_connections: usize) -> (Arc<Relay>, Arc<CaptureSink>) {
    let events = Arc::new(CaptureSink::default());
    let fx = RelayFx::case1();
    let relay = Relay::new(
        KeyRing::new(vec![(fx.keys(1), VALID_UNTIL)]).unwrap(),
        Limits {
            drain_secs: 1,
            max_connections,
            ..Limits::vectors()
        },
        Box::new(Shared(Arc::clone(&events))),
        Now {
            unix_secs: NOW,
            mono_ms: 0,
        },
    );
    (Arc::new(relay), events)
}

fn names(events: &CaptureSink) -> Vec<&'static str> {
    events.events().into_iter().map(|(n, _)| n).collect()
}

fn listener(script: Vec<io::Result<Scripted>>) -> ScriptedListener {
    ScriptedListener {
        script: Mutex::new(script.into()),
        drain: None,
        calls: AtomicUsize::new(0),
    }
}

/// `WouldBlock` and `Interrupted` are retried; once the drain has lasted `drain_secs` the loop ends with `exit`.
#[test]
fn serve_retries_and_exits_after_the_drain() {
    let (relay, events) = relay();
    // 100 ms per clock reading: the three scripted errors come before the one-second drain has passed
    let clock = Virtual::new(100);
    relay.start_drain(clock.now());
    let l = listener(vec![
        Err(io::Error::from(ErrorKind::WouldBlock)),
        Err(io::Error::from(ErrorKind::Interrupted)),
        Err(io::Error::from(ErrorKind::WouldBlock)),
    ]);
    assert_eq!(
        server::serve(&relay, &l, &clock, server::spawn_thread),
        Ok(())
    );
    assert!(
        l.script.lock().unwrap().is_empty(),
        "every scripted error was seen"
    );
    assert_eq!(names(&events), vec!["keys_loaded", "drain_started", "exit"]);
}

/// C-2 (M05 review R-106) `serve_retries_on_a_transient_accept_error`: an `accept` error of one connection
/// (`ConnectionAborted`, `ConnectionReset`) or of a resource (ENOMEM, EMFILE) does not end the loop: each gets one
/// `accept_retry` event and a wait of `ACCEPT_RETRY` before the next `accept` (recorded by the virtual clock, not
/// slept); the next connection is served (`HELLO` answered with `RELAYINFO`), and the drain ends the loop with `exit`.
#[test]
fn serve_retries_on_a_transient_accept_error() {
    let (relay, events) = relay();
    let clock = Virtual::new(100);
    let (tx, rx) = mpsc::channel();
    let (mut stream, seen) = Scripted::new(vec![In::Data(HELLO.to_vec())]);
    stream.closed = Some(tx);
    let transient = [
        io::Error::from(ErrorKind::ConnectionAborted),
        io::Error::from(ErrorKind::ConnectionReset),
        io::Error::from(ErrorKind::OutOfMemory),
        // EMFILE on Unix; every code outside `LISTENER_GONE` is retried
        io::Error::from_raw_os_error(24),
    ];
    let retries = transient.len();
    let mut script: Vec<io::Result<Scripted>> = transient.into_iter().map(Err).collect();
    script.push(Ok(stream));
    let l = ScriptedListener {
        script: Mutex::new(script.into()),
        drain: Some((Arc::clone(&relay), clock.clone(), Mutex::new(Some(rx)))),
        calls: AtomicUsize::new(0),
    };
    assert_eq!(
        server::serve(&relay, &l, &clock, server::spawn_thread),
        Ok(()),
        "C-2: the loop runs on to the drain"
    );
    {
        let s = seen.lock().unwrap();
        assert_eq!(
            (s.written.len(), s.closed),
            (1744, true),
            "C-2: the next connection is served"
        );
    }
    let mut want = vec!["keys_loaded"];
    want.extend(std::iter::repeat_n("accept_retry", retries));
    want.extend(["drain_started", "exit"]);
    assert_eq!(names(&events), want, "C-2: one accept_retry per error");
    // the start-up reading, then per retried error: the loop's reading and the wait; then the reading of the accept
    // that hands out the connection
    let mut prefix = vec![None];
    for _ in 0..retries {
        prefix.extend([None, Some(server::ACCEPT_RETRY)]);
    }
    prefix.push(None);
    let log = clock.log();
    assert_eq!(
        log.get(..prefix.len()),
        Some(prefix.as_slice()),
        "C-2: each retried error waits ACCEPT_RETRY before the next accept"
    );
    assert_eq!(server::ACCEPT_RETRY, Duration::from_millis(50));
}

/// C-2 (M05 review R-106) `serve_exits_on_a_dead_listener`: EBADF, EINVAL and ENOTSOCK (`server::LISTENER_GONE`)
/// mean the listener is gone: the loop ends at the first such error with `Error::Io` — no `accept_retry`, no wait,
/// no `exit` event. (The drain runs, so a loop that retried the error would end with `exit` instead of hanging.)
#[test]
fn serve_exits_on_a_dead_listener() {
    for code in server::LISTENER_GONE {
        let (relay, events) = relay();
        let clock = Virtual::new(400);
        relay.start_drain(clock.now());
        let l = listener(vec![Err(io::Error::from_raw_os_error(code))]);
        assert_eq!(
            server::serve(&relay, &l, &clock, server::spawn_thread),
            Err(Error::Io),
            "C-2: os error {code} ends the loop"
        );
        assert_eq!(
            names(&events),
            vec!["keys_loaded", "drain_started"],
            "C-2: os error {code}: nothing retried, no exit"
        );
        assert_eq!(l.calls.load(Ordering::SeqCst), 1, "C-2: one accept");
        assert!(
            clock.log().iter().all(Option::is_none),
            "C-2: os error {code}: no wait"
        );
    }
}

/// While draining, an accepted connection is closed unread (OPEN-M5-09).
#[test]
fn serve_closes_connections_while_draining() {
    let (relay, _) = relay();
    let clock = Virtual::new(100);
    relay.start_drain(clock.now());
    let (stream, seen) = Scripted::new(vec![In::Data(HELLO.to_vec())]);
    let l = listener(vec![Ok(stream)]);
    assert_eq!(
        server::serve(&relay, &l, &clock, server::spawn_thread),
        Ok(())
    );
    let s = seen.lock().unwrap();
    assert!(s.closed && s.reads == 0 && s.written.is_empty());
}

/// An accepted connection runs on its own thread: `HELLO` is answered with `RELAYINFO`, EOF closes it; the loop
/// keeps accepting until the drain has finished.
#[test]
fn serve_hands_each_connection_to_its_thread() {
    let (relay, events) = relay();
    let clock = Virtual::new(100);
    let (tx, rx) = mpsc::channel();
    let (mut stream, seen) = Scripted::new(vec![In::Data(HELLO.to_vec())]);
    stream.closed = Some(tx);
    let l = ScriptedListener {
        script: Mutex::new(vec![Ok(stream)].into()),
        drain: Some((Arc::clone(&relay), clock.clone(), Mutex::new(Some(rx)))),
        calls: AtomicUsize::new(0),
    };
    assert_eq!(
        server::serve(&relay, &l, &clock, server::spawn_thread),
        Ok(())
    );
    let s = seen.lock().unwrap();
    assert_eq!(s.written.len(), 1744, "RELAYINFO");
    assert!(s.closed);
    assert_eq!(names(&events).last(), Some(&"exit"));
}

/// The connection loop: `HELLO` answered, EOF ends it, the stream is closed.
#[test]
fn handle_answers_and_closes_at_eof() {
    let (relay, _) = relay();
    let (stream, seen) = Scripted::new(vec![In::Data(HELLO.to_vec())]);
    server::handle(&relay, stream, &Virtual::new(10));
    let s = seen.lock().unwrap();
    assert_eq!((s.written.len(), s.reads, s.closed), (1744, 2, true));
}

/// Read timeouts tick, an interrupted read is retried, any other error ends the loop at once.
#[test]
fn handle_ticks_retries_and_stops_on_an_error() {
    let (relay, _) = relay();
    let (stream, seen) = Scripted::new(vec![
        In::Fail(ErrorKind::WouldBlock),
        In::Fail(ErrorKind::TimedOut),
        In::Fail(ErrorKind::Interrupted),
        In::Data(HELLO.to_vec()),
        In::Fail(ErrorKind::ConnectionReset),
        In::Data(vec![0; 9]),
    ]);
    server::handle(&relay, stream, &Virtual::new(10));
    let s = seen.lock().unwrap();
    assert_eq!((s.written.len(), s.reads, s.closed), (1744, 5, true));
}

/// A teardown (a `HELLO` of the wrong length) closes the connection without reading on; so does a failed write; a
/// stream whose read timeout cannot be set, or a relay that refuses the connection, is closed unread.
#[test]
fn handle_stops_on_teardown_write_failure_and_refusal() {
    let (relay, _) = relay();
    let mut bad = HELLO.to_vec();
    *bad.get_mut(1).unwrap() = 8;
    let (stream, seen) = Scripted::new(vec![In::Data(bad), In::Data(HELLO.to_vec())]);
    server::handle(&relay, stream, &Virtual::new(10));
    assert_eq!(
        {
            let s = seen.lock().unwrap();
            (s.written.len(), s.reads, s.closed)
        },
        (0, 1, true),
        "teardown"
    );
    let (mut stream, seen) = Scripted::new(vec![In::Data(HELLO.to_vec()), In::Data(vec![0; 9])]);
    stream.fail_write = true;
    server::handle(&relay, stream, &Virtual::new(10));
    assert_eq!(
        {
            let s = seen.lock().unwrap();
            (s.reads, s.closed)
        },
        (1, true),
        "write failure"
    );
    let (mut stream, seen) = Scripted::new(vec![In::Data(HELLO.to_vec())]);
    stream.fail_poll = true;
    server::handle(&relay, stream, &Virtual::new(10));
    assert_eq!(
        {
            let s = seen.lock().unwrap();
            (s.reads, s.closed)
        },
        (0, true),
        "poll setup failure"
    );
    relay.start_drain(Now {
        unix_secs: NOW,
        mono_ms: 0,
    });
    let (stream, seen) = Scripted::new(vec![In::Data(HELLO.to_vec())]);
    server::handle(&relay, stream, &Virtual::new(10));
    assert_eq!(
        {
            let s = seen.lock().unwrap();
            (s.reads, s.closed)
        },
        (0, true),
        "refused while draining"
    );
}

/// The accept calls a [`Fed`] listener answers before it reports a dead listener, so a test whose expectation fails
/// ends `serve` instead of hanging it.
const FED_CALLS_MAX: usize = 20_000;

/// A listener the test feeds through a channel: it waits up to 5 ms for a connection, then reports `WouldBlock`;
/// after `FED_CALLS_MAX` calls, or once the test has dropped its sender (the test ended or failed), it is dead.
struct Fed {
    rx: Mutex<Receiver<Scripted>>,
    calls: AtomicUsize,
}

impl Fed {
    fn new() -> (Self, Sender<Scripted>) {
        let (tx, rx) = mpsc::channel();
        (
            Self {
                rx: Mutex::new(rx),
                calls: AtomicUsize::new(0),
            },
            tx,
        )
    }
}

impl Listener for Fed {
    type Conn = Scripted;

    fn accept_next(&self) -> io::Result<Scripted> {
        if self.calls.fetch_add(1, Ordering::SeqCst) >= FED_CALLS_MAX {
            return Err(dead());
        }
        match self
            .rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_millis(5))
        {
            Ok(stream) => Ok(stream),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::from(ErrorKind::WouldBlock)),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(dead()),
        }
    }
}

/// An idle peer: it sends nothing until released.
struct Idle {
    stream: Scripted,
    seen: Arc<Mutex<Seen>>,
    release: Sender<()>,
    /// Signalled at each read.
    reading: Receiver<()>,
    /// Signalled at the close.
    closed: Receiver<()>,
}

fn idle() -> Idle {
    let (release, wait) = mpsc::channel();
    let (stream, seen) = Scripted::new(vec![In::Block(wait)]);
    let (stream, reading, closed) = signalled(stream);
    Idle {
        stream,
        seen,
        release,
        reading,
        closed,
    }
}

/// `stream` with the signals of its reads and of its close.
fn signalled(mut stream: Scripted) -> (Scripted, Receiver<()>, Receiver<()>) {
    let (read_tx, reading) = mpsc::channel();
    let (close_tx, closed) = mpsc::channel();
    stream.reading = Some(read_tx);
    stream.closed = Some(close_tx);
    (stream, reading, closed)
}

/// How long a test waits for a signal of another thread before it fails.
const SIGNAL: Duration = Duration::from_secs(10);

/// A spawner that starts each job on its own thread and signals `done` after the job has returned (its slot is then
/// counted out); `started` counts the jobs.
fn signalling_spawner(
    done: Sender<()>,
    started: Arc<AtomicUsize>,
) -> impl FnMut(server::Job) -> io::Result<()> {
    move |job: server::Job| {
        started.fetch_add(1, Ordering::SeqCst);
        let done = done.clone();
        std::thread::Builder::new()
            .spawn(move || {
                job();
                let _ = done.send(());
            })
            .map(drop)
    }
}

/// C-1 (M05 review R-105) `cap_refuses_the_n_plus_first_idle_connection`: with `max_connections` 4, four idle
/// connections get a job each and stay open; the fifth is closed by the relay before any read and without a job; no
/// panic; once one of the four has closed, the next connection is served again.
#[test]
fn cap_refuses_the_n_plus_first_idle_connection() {
    let (relay, _) = relay_with(4);
    let clock = Virtual::new(100);
    let (listener, feed) = Fed::new();
    let (done_tx, done) = mpsc::channel();
    let started = Arc::new(AtomicUsize::new(0));
    let spawner = signalling_spawner(done_tx, Arc::clone(&started));
    std::thread::scope(|scope| {
        // owned by this closure: a failing assertion drops it, the listener is dead and `serve` ends, so the scope
        // joins at once instead of after `FED_CALLS_MAX` accepts
        let feed = feed;
        let serving = scope.spawn(|| server::serve(&relay, &listener, &clock, spawner));
        let mut held = Vec::new();
        for i in 0..4 {
            let peer = idle();
            feed.send(peer.stream).unwrap();
            peer.reading.recv_timeout(SIGNAL).unwrap();
            assert!(
                !peer.seen.lock().unwrap().closed,
                "C-1: connection {i} is open"
            );
            held.push((peer.seen, peer.release));
        }
        let fifth = idle();
        feed.send(fifth.stream).unwrap();
        fifth.closed.recv_timeout(SIGNAL).unwrap();
        {
            let s = fifth.seen.lock().unwrap();
            assert!(
                s.closed && s.reads == 0 && s.written.is_empty(),
                "C-1: the fifth is closed unread"
            );
        }
        assert_eq!(
            started.load(Ordering::SeqCst),
            4,
            "C-1: no job for the fifth"
        );
        for (i, (seen, _)) in held.iter().enumerate() {
            assert!(
                !seen.lock().unwrap().closed,
                "C-1: connection {i} stays open"
            );
        }
        // one of the four ends; its slot is counted out before `done`
        let (first_seen, first_release) = held.remove(0);
        first_release.send(()).unwrap();
        done.recv_timeout(SIGNAL).unwrap();
        assert!(first_seen.lock().unwrap().closed);
        let sixth = idle();
        feed.send(sixth.stream).unwrap();
        sixth.reading.recv_timeout(SIGNAL).unwrap();
        assert_eq!(
            started.load(Ordering::SeqCst),
            5,
            "C-1: served again after one closed"
        );
        assert!(!sixth.seen.lock().unwrap().closed);
        sixth.release.send(()).unwrap();
        for (_, release) in &held {
            release.send(()).unwrap();
        }
        for _ in 0..4 {
            done.recv_timeout(SIGNAL).unwrap();
        }
        relay.start_drain(clock.now());
        assert_eq!(
            serving.join().unwrap(),
            Ok(()),
            "C-1: the loop ran on to the drain"
        );
        assert!(sixth.seen.lock().unwrap().closed);
        for (seen, _) in &held {
            assert!(seen.lock().unwrap().closed);
        }
    });
}

/// C-1 (M05 review R-105) `spawn_failure_closes_the_stream_and_keeps_serving`: a job the spawner cannot start is
/// dropped — its connection is closed unread and counted out (with a cap of 1 the next connection is still served)
/// — and the loop serves on: the next `HELLO` is answered with `RELAYINFO`; no panic.
#[test]
fn spawn_failure_closes_the_stream_and_keeps_serving() {
    let (relay, _) = relay_with(1);
    let clock = Virtual::new(100);
    let (listener, feed) = Fed::new();
    let (done_tx, done) = mpsc::channel();
    let started = Arc::new(AtomicUsize::new(0));
    let mut inner = signalling_spawner(done_tx, Arc::clone(&started));
    let mut failed = 0_usize;
    let spawner = move |job: server::Job| {
        if failed == 0 {
            failed = 1;
            drop(job);
            return Err(io::Error::from(ErrorKind::WouldBlock));
        }
        inner(job)
    };
    std::thread::scope(|scope| {
        // owned by this closure: a failing assertion drops it, the listener is dead and `serve` ends, so the scope
        // joins at once instead of after `FED_CALLS_MAX` accepts
        let feed = feed;
        let serving = scope.spawn(|| server::serve(&relay, &listener, &clock, spawner));
        let (first, first_seen) = Scripted::new(vec![In::Data(HELLO.to_vec())]);
        let (first, _, first_closed) = signalled(first);
        feed.send(first).unwrap();
        first_closed.recv_timeout(SIGNAL).unwrap();
        {
            let s = first_seen.lock().unwrap();
            assert!(
                s.closed && s.reads == 0 && s.written.is_empty(),
                "C-1: a job that cannot start closes its stream unread"
            );
        }
        let (second, second_seen) = Scripted::new(vec![In::Data(HELLO.to_vec())]);
        feed.send(second).unwrap();
        done.recv_timeout(SIGNAL).unwrap();
        {
            let s = second_seen.lock().unwrap();
            assert_eq!(
                (s.written.len(), s.closed),
                (1744, true),
                "C-1: the next connection is served (RELAYINFO), within the cap of 1"
            );
        }
        assert_eq!(started.load(Ordering::SeqCst), 1);
        relay.start_drain(clock.now());
        assert_eq!(serving.join().unwrap(), Ok(()), "C-1: serving went on");
    });
}

/// C-3 (M05 review R-107) `write_timeout_is_set`: before its first read the connection loop gives the stream the read
/// poll and the 30-s write timeout, so a peer that stops reading loses its connection at a blocked write.
#[test]
fn write_timeout_is_set() {
    let (relay, _) = relay();
    let (stream, seen) = Scripted::new(vec![In::Data(HELLO.to_vec())]);
    server::handle(&relay, stream, &Virtual::new(10));
    let s = seen.lock().unwrap();
    assert_eq!(
        s.timeouts,
        Some((server::READ_POLL, server::WRITE_TIMEOUT)),
        "C-3: both timeouts are set"
    );
    assert_eq!(server::WRITE_TIMEOUT, Duration::from_secs(30));
    assert_eq!((s.written.len(), s.closed), (1744, true));
}

/// A connected loopback pair (`127.0.0.1:0`; network outside unit tests, `docs/06` §4): the relay's side, non-blocking
/// as if accepted from `server::bind`'s non-blocking listener (inherited on macOS and the BSDs), and the peer.
fn loopback() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let accepted = listener.accept_next().unwrap();
    accepted.set_nonblocking(true).unwrap();
    (accepted, peer)
}

/// C-3 (M05 review R-107, R-163) `set_poll_sets_read_and_write_timeouts_on_a_real_socket`: `set_poll` on an accepted
/// `TcpStream` sets the read timeout (the 30-s `HELLO` bound and the drain rely on it) and the write timeout, and makes
/// the socket blocking: a read with no data waits for the poll, then fails with `WouldBlock`/`TimedOut`.
#[test]
fn set_poll_sets_read_and_write_timeouts_on_a_real_socket() {
    let (mut relay_side, _peer) = loopback();
    Stream::set_poll(&mut relay_side, server::READ_POLL, server::WRITE_TIMEOUT).unwrap();
    assert_eq!(relay_side.read_timeout().unwrap(), Some(server::READ_POLL));
    assert_eq!(
        relay_side.write_timeout().unwrap(),
        Some(server::WRITE_TIMEOUT)
    );
    let start = Instant::now();
    let err = relay_side.read(&mut [0_u8; 16]).unwrap_err();
    assert!(
        matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
        "{err}"
    );
    assert!(
        start.elapsed() >= server::READ_POLL.checked_div(2).unwrap(),
        "C-3: the read blocked for the poll, not at once"
    );
}

/// C-7 (M05 review R-114, R-163) `close_closes_the_socket`: `Stream::close` on an accepted `TcpStream` shuts both
/// directions down while the relay's side is still alive (not by its drop): the peer reads EOF, and a write on the
/// relay's side fails.
#[test]
fn close_closes_the_socket() {
    let (mut relay_side, mut peer) = loopback();
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    Stream::close(&mut relay_side);
    let mut buf = [0_u8; 8];
    assert_eq!(peer.read(&mut buf).unwrap(), 0, "C-7: the peer reads EOF");
    assert!(
        relay_side.write_all(b"x").is_err(),
        "C-7: the relay's side is shut for writing"
    );
    drop(relay_side);
}
