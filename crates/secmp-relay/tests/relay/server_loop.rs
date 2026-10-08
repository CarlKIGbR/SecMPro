// SPDX-License-Identifier: AGPL-3.0-or-later
//! The server loops (`secmp_relay::server::{serve, handle}`) over in-memory streams, an in-memory listener and a
//! virtual clock — no socket (`docs/06` §4): the accept loop retries on `WouldBlock`/`Interrupted`, fails on any other
//! listener error, refuses connections while draining, hands each connection to its own thread and exits with an
//! `exit` event once the drain has lasted `drain_secs`; the connection loop ticks on read timeouts, retries
//! interrupted reads, stops on EOF, an I/O error, a failed write or a teardown, and always closes the stream. Extra
//! tests of M5 Phase B (not TEST-SPEC rows).

use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use secmp_relay::event::{CaptureSink, EventSink};
use secmp_relay::server::{self, Listener, Stream, Time};
use secmp_relay::{Error, KeyRing, Limits, Now, Relay};

use crate::fixture::{HELLO, NOW, RelayFx, VALID_UNTIL};

/// A virtual clock: every reading advances the monotonic clock by `step` milliseconds.
#[derive(Clone)]
struct Virtual(Arc<(AtomicU64, u64)>);

impl Virtual {
    fn new(step: u64) -> Self {
        Self(Arc::new((AtomicU64::new(0), step)))
    }
}

impl Time for Virtual {
    fn now(&self) -> Now {
        Now {
            unix_secs: NOW,
            mono_ms: self.0.0.fetch_add(self.0.1, Ordering::SeqCst),
        }
    }
}

/// One read of a scripted stream.
enum In {
    Data(Vec<u8>),
    Fail(ErrorKind),
}

/// What a scripted stream saw.
#[derive(Default)]
struct Seen {
    written: Vec<u8>,
    reads: usize,
    closed: bool,
}

/// A stream that reads its script (then EOF) and records writes, reads and the close.
struct Scripted {
    script: VecDeque<In>,
    seen: Arc<Mutex<Seen>>,
    fail_poll: bool,
    fail_write: bool,
    closed: Option<Sender<()>>,
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
        match self.script.pop_front() {
            Some(In::Data(d)) => {
                buf.get_mut(..d.len()).unwrap().copy_from_slice(&d);
                Ok(d.len())
            }
            Some(In::Fail(kind)) => Err(io::Error::from(kind)),
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
    fn set_poll(&mut self, poll: Duration) -> io::Result<()> {
        assert_eq!(poll, server::READ_POLL);
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
/// calls; the next call fails like a broken listener, so a drain that never starts or never finishes fails the test
/// (`serve` returns `Error::Io`) instead of hanging it.
const ACCEPT_CALLS_MAX: usize = 100;

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
            return Err(io::Error::from(ErrorKind::Other));
        }
        if let Some(next) = self.script.lock().unwrap().pop_front() {
            return next;
        }
        if let Some((relay, clock, closed)) = &self.drain
            && !relay.draining()
            && let Some(closed) = closed.lock().unwrap().take()
        {
            closed.recv_timeout(Duration::from_secs(60)).unwrap();
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
    let events = Arc::new(CaptureSink::default());
    let fx = RelayFx::case1();
    let relay = Relay::new(
        KeyRing::new(vec![(fx.keys(1), VALID_UNTIL)]).unwrap(),
        Limits {
            drain_secs: 1,
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
    assert_eq!(server::serve(&relay, &l, &clock), Ok(()));
    assert!(
        l.script.lock().unwrap().is_empty(),
        "every scripted error was seen"
    );
    assert_eq!(names(&events), vec!["keys_loaded", "drain_started", "exit"]);
}

/// Any other listener error ends the loop with `Error::Io` and no `exit` event.
#[test]
fn serve_fails_on_a_listener_error() {
    let (relay, events) = relay();
    let clock = Virtual::new(400);
    relay.start_drain(clock.now());
    let l = listener(vec![Err(io::Error::from(ErrorKind::ConnectionAborted))]);
    assert_eq!(server::serve(&relay, &l, &clock), Err(Error::Io));
    assert_eq!(names(&events), vec!["keys_loaded", "drain_started"]);
}

/// While draining, an accepted connection is closed unread (OPEN-M5-09).
#[test]
fn serve_closes_connections_while_draining() {
    let (relay, _) = relay();
    let clock = Virtual::new(100);
    relay.start_drain(clock.now());
    let (stream, seen) = Scripted::new(vec![In::Data(HELLO.to_vec())]);
    let l = listener(vec![Ok(stream)]);
    assert_eq!(server::serve(&relay, &l, &clock), Ok(()));
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
    assert_eq!(server::serve(&relay, &l, &clock), Ok(()));
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
