// SPDX-License-Identifier: AGPL-3.0-or-later
//! The process around the sans-IO relay (`docs/02` §5.1, `docs/05` §4–§5): start-up, the listener, one thread per
//! connection.
//!
//! Start-up refuses before any listener binds (test RL-23): [`prepare`] reads the configuration and the key file
//! and builds the [`Relay`]; only then [`bind`] opens the loopback listener C tor forwards to. Serving writes no
//! file (spec §9.7 item 1; test RL-02). The listener is `std::net` (no async runtime in M5; the 200-client load test
//! is M10). The client's address is never read beyond the accept call and never reported.

use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
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
const READ_POLL: Duration = Duration::from_millis(500);
/// How long the accept loop sleeps when no connection is waiting.
const ACCEPT_POLL: Duration = Duration::from_millis(50);

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

    /// The current time.
    #[must_use]
    pub fn now(&self) -> Now {
        Now {
            unix_secs: wall_clock_unix_secs(),
            mono_ms: u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
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

/// Bind the relay's listener at `addr` (a loopback address, `Config::parse`).
///
/// # Errors
/// [`Error::Io`] if the address cannot be bound.
pub fn bind(relay: &Relay, addr: SocketAddr) -> Result<TcpListener> {
    let listener = TcpListener::bind(addr)?;
    let own = listener.local_addr()?;
    relay.events().emit(&Event::ListenerBound { addr: &own });
    Ok(listener)
}

/// Serve until the drain has finished: one thread per connection; the sweeper ticks once per second.
///
/// # Errors
/// [`Error::Io`] if the listener fails.
pub fn serve(relay: &Arc<Relay>, listener: &TcpListener, clock: Clock) -> Result<()> {
    listener.set_nonblocking(true)?;
    let mut last_tick = clock.now();
    loop {
        let now = clock.now();
        if relay.drain_finished(now) {
            relay.events().emit(&Event::Exit);
            return Ok(());
        }
        if now.mono_ms.saturating_sub(last_tick.mono_ms) >= 1000 {
            relay.tick(now);
            last_tick = now;
        }
        match listener.accept() {
            // the peer address is dropped here: never stored, never reported
            Ok((stream, _)) => {
                if relay.accepts_connections() {
                    let relay = Arc::clone(relay);
                    std::thread::spawn(move || handle(&relay, stream, clock));
                } else {
                    let _ = stream.shutdown(Shutdown::Both);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(ACCEPT_POLL),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
}

/// Drive one connection until it closes, the peer leaves or the drain has finished.
fn handle(relay: &Relay, mut stream: TcpStream, clock: Clock) {
    if stream.set_nonblocking(false).is_err() || stream.set_read_timeout(Some(READ_POLL)).is_err() {
        return;
    }
    let Some(mut conn) = Connection::accept(relay, clock.now()) else {
        let _ = stream.shutdown(Shutdown::Both);
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
    let _ = stream.shutdown(Shutdown::Both);
}
