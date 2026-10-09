// SPDX-License-Identifier: AGPL-3.0-or-later
//! The process around the sans-IO relay (`docs/02` §5.1, `docs/05` §4–§5): start-up, the listener, one thread per
//! connection up to the connection cap (`max_connections`, M05 review C-1).
//!
//! Start-up refuses before any listener binds (test RL-23): [`prepare`] reads the configuration and the key file
//! and builds the [`Relay`]; only then [`bind`] opens the loopback listener C tor forwards to. Serving writes no
//! file (spec §9.7 item 1; test RL-02). The listener is `std::net` (no async runtime in M5; the 200-client load test
//! is M10). The client's address is never read beyond the accept call and never reported.
//!
//! The loops ([`serve`], [`handle`]) are generic over the listener, the stream and the clock ([`Listener`],
//! [`Stream`], [`Time`]): the binary passes `std::net` and the process clock, the tests in-memory streams and a
//! virtual clock (no network in tests, `docs/06` §4).

use std::io::{self, ErrorKind};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use secmp_proto::tr::OsEntropy;

use crate::clock::{Now, wall_clock_unix_secs};
use crate::config::Config;
use crate::conn::Connection;
use crate::error::{Error, Result};
use crate::event::{Event, EventSink};
use crate::keys::KeyFile;
use crate::relay::Relay;

/// How long a connection read blocks before the connection checks its timeout and the drain.
pub const READ_POLL: Duration = Duration::from_millis(500);
/// How long the accept loop sleeps when no connection is waiting.
const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// The sweeper's period on the monotonic clock.
const TICK_MS: u64 = 1000;

/// Where the loops take their time from.
pub trait Time: Send + Sync {
    /// The current time.
    fn now(&self) -> Now;
}

/// The process clock: the wall clock and a monotonic clock from the process start.
#[derive(Clone, Copy)]
pub struct Clock {
    origin: Instant,
}

impl Clock {
    /// A clock whose monotonic origin is now.
    #[must_use]
    pub fn start() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Time for Clock {
    fn now(&self) -> Now {
        Now {
            unix_secs: wall_clock_unix_secs(),
            mono_ms: u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    }
}

/// One accepted connection.
pub trait Stream: io::Read + io::Write + Send + 'static {
    /// Make reads block for at most `poll`, after which they fail with `WouldBlock` or `TimedOut`.
    ///
    /// # Errors
    /// The I/O error of the underlying stream.
    fn set_poll(&mut self, poll: Duration) -> io::Result<()>;
    /// Close both directions.
    fn close(&mut self);
}

impl Stream for TcpStream {
    fn set_poll(&mut self, poll: Duration) -> io::Result<()> {
        self.set_nonblocking(false)?;
        self.set_read_timeout(Some(poll))
    }

    fn close(&mut self) {
        let _ = self.shutdown(Shutdown::Both);
    }
}

/// A non-blocking listener: `accept_next` fails with `WouldBlock` when no connection waits.
pub trait Listener {
    /// The connections it accepts.
    type Conn: Stream;
    /// The next waiting connection; the peer's address is not part of the result (never stored, never reported).
    ///
    /// # Errors
    /// `WouldBlock` when none waits, `Interrupted`, or the listener's failure.
    fn accept_next(&self) -> io::Result<Self::Conn>;
}

impl Listener for TcpListener {
    type Conn = TcpStream;

    fn accept_next(&self) -> io::Result<TcpStream> {
        // the peer address is dropped here
        self.accept().map(|(stream, _)| stream)
    }
}

/// Read the configuration at `config_path` and the key file it names, and build the relay. Nothing is bound.
///
/// # Errors
/// [`Error::Config`] or [`Error::KeyFile`] (reported as a `config_error` event first), [`Error::NoValidKeys`] if no
/// key generation is valid now, [`Error::Unavailable`] without locked memory.
pub fn prepare(
    config_path: &Path,
    events: Box<dyn EventSink>,
    now: Now,
) -> Result<(Config, Relay)> {
    let config = match Config::read(config_path) {
        Ok(c) => c,
        Err(e) => {
            events.emit(&Event::ConfigError { reason: reason(e) });
            return Err(e);
        }
    };
    let ring = match KeyFile::read(&config.key_file).and_then(|f| f.ring()) {
        Ok(r) => r,
        Err(e) => {
            events.emit(&Event::ConfigError { reason: reason(e) });
            return Err(e);
        }
    };
    let usable = ring
        .newest()
        .is_ok_and(|(k, _)| ring.usable(k.kid(), now.unix_secs));
    if !usable {
        events.emit(&Event::ConfigError {
            reason: "no key generation is valid now",
        });
        return Err(Error::NoValidKeys);
    }
    let relay = Relay::new(ring, config.limits, events, now);
    Ok((config, relay))
}

const fn reason(e: Error) -> &'static str {
    match e {
        Error::Config(why) => why,
        Error::KeyFile => "key file missing, unreadable or malformed",
        Error::NoValidKeys => "no key generation is valid now",
        Error::Io => "i/o error",
        Error::Unavailable => "randomness or locked memory unavailable",
    }
}

/// Bind the relay's listener at `addr` (a loopback address, `Config::parse`), non-blocking.
///
/// # Errors
/// [`Error::Io`] if the address cannot be bound.
pub fn bind(relay: &Relay, addr: SocketAddr) -> Result<TcpListener> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let own = listener.local_addr()?;
    relay.events().emit(&Event::ListenerBound { addr: &own });
    Ok(listener)
}

/// Whether the sweeper is due: a full period since the last tick (a clock that steps back is not due).
const fn tick_due(last_ms: u64, now_ms: u64) -> bool {
    now_ms.saturating_sub(last_ms) >= TICK_MS
}

/// The work of one accepted connection, handed to the spawner of [`serve`].
pub type Job = Box<dyn FnOnce() + Send + 'static>;

/// The production spawner of [`serve`]: one OS thread per connection through `std::thread::Builder`, whose failure
/// (the unit's `TasksMax`, memory) is returned instead of raised (M05 review C-1). A job that is not started is
/// dropped, which closes its connection.
///
/// # Errors
/// The thread could not be created.
pub fn spawn_thread(job: Job) -> io::Result<()> {
    std::thread::Builder::new().spawn(job).map(drop)
}

/// One served connection, counted in the live connections: dropped after its thread's loop or, if no thread could be
/// started for it, at once — either way the stream is closed and the count goes down.
struct Slot<S: Stream> {
    stream: Option<S>,
    live: Arc<AtomicUsize>,
}

impl<S: Stream> Slot<S> {
    /// Drive the connection to its end ([`handle`] closes it).
    fn run<T: Time>(mut self, relay: &Relay, clock: &T) {
        if let Some(stream) = self.stream.take() {
            handle(relay, stream, clock);
        }
    }
}

impl<S: Stream> Drop for Slot<S> {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.as_mut() {
            stream.close();
        }
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serve until the drain has finished: one job per connection, started by `spawn` ([`spawn_thread`] in the binary),
/// at most `max_connections` at once — a connection over the cap, or one accepted while draining, is closed before
/// any read and without a job; the sweeper ticks once per second.
///
/// # Errors
/// [`Error::Io`] if the listener fails.
pub fn serve<L: Listener, T: Time + Clone + 'static>(
    relay: &Arc<Relay>,
    listener: &L,
    clock: &T,
    mut spawn: impl FnMut(Job) -> io::Result<()>,
) -> Result<()> {
    let live = Arc::new(AtomicUsize::new(0));
    let cap = relay.limits().max_connections;
    let mut last_tick = clock.now().mono_ms;
    loop {
        let now = clock.now();
        if relay.drain_finished(now) {
            relay.events().emit(&Event::Exit);
            return Ok(());
        }
        if tick_due(last_tick, now.mono_ms) {
            relay.tick(now);
            last_tick = now.mono_ms;
        }
        match listener.accept_next() {
            Ok(mut stream) => {
                // only this loop adds to `live`, so the count cannot pass the cap between the check and the add
                if !relay.accepts_connections() || live.load(Ordering::SeqCst) >= cap {
                    stream.close();
                    continue;
                }
                live.fetch_add(1, Ordering::SeqCst);
                let slot = Slot {
                    stream: Some(stream),
                    live: Arc::clone(&live),
                };
                let relay = Arc::clone(relay);
                let clock = clock.clone();
                // a spawn failure drops the job: the slot closes the stream and counts it out; serving goes on
                let _ = spawn(Box::new(move || slot.run(&relay, &clock)));
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(ACCEPT_POLL),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
}

/// Drive one connection until it closes, the peer leaves, an I/O error occurs or the drain has finished; then
/// close it.
pub fn handle<S: Stream, T: Time>(relay: &Relay, mut stream: S, clock: &T) {
    if stream.set_poll(READ_POLL).is_err() {
        stream.close();
        return;
    }
    let Some(mut conn) = Connection::accept(relay, clock.now()) else {
        stream.close();
        return;
    };
    let mut entropy = OsEntropy;
    let mut buf = vec![0_u8; 16_384];
    loop {
        let out = match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => conn.on_bytes(buf.get(..n).unwrap_or_default(), clock.now(), &mut entropy),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                conn.on_tick(clock.now())
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if !out.bytes.is_empty() && stream.write_all(&out.bytes).is_err() {
            break;
        }
        if out.close || relay.drain_finished(clock.now()) {
            break;
        }
    }
    stream.close();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sweeper_ticks_once_a_second() {
        assert!(!tick_due(0, 999));
        assert!(tick_due(0, 1000));
        assert!(tick_due(500, 1500));
        assert!(!tick_due(5000, 4000));
    }
}
