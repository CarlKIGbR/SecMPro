// SPDX-License-Identifier: AGPL-3.0-or-later
//! The optional direct TLS listener (feature `direct-tls`; `docs/05` §7, OPEN-M6-08 A, ADR-051 Part 2; TEST-SPEC-M6
//! TLS-12…TLS-14).
//!
//! **What it is.** A second listener next to the onion loopback one, for "testing / own-VPN use" (`docs/05` §7): a
//! synchronous rustls [`ServerConnection`] over a `std::net` [`TcpStream`] in the existing thread-per-connection model
//! ([`crate::server`]). Behind the TLS stream runs the identical SecMP-LINK handshake and frames; the connection
//! counts toward the same `max_connections` cap as the onion listener's ([`Listeners`]). TLS is a transport here and
//! never a SecMP construction (CLAUDE.md §1.6).
//!
//! **The configuration** ([`server_config`]) is built with `ServerConfig::builder_with_provider` — never from the
//! process-default provider (TLS-10):
//! - aws-lc-rs with the key exchange restricted to `X25519MLKEM768` (CLAUDE.md §1.3: the one group, hybrid; no
//!   classical group, no fallback) and the TLS 1.3 cipher suites only; asserted when the configuration is built, since
//!   rustls's `tls12` feature is on in the graph;
//! - ALPN `secmp/1`: a connection that did not select it is closed before its first SecMP byte is read ([`TlsConn`]);
//! - no session tickets, no session cache, no 0-RTT, no client certificates;
//! - one self-signed certificate (`docs/05` §7: Ed25519, pinned by clients through `RelayRef.direct.spki_sha256`, which
//!   `secmp-relay spki` prints); rustls refuses a key that does not match the certificate.
//!
//! **Fail closed.** A certificate or key that cannot be loaded refuses the start before any listener binds
//! ([`crate::Error::Config`]). Every TLS failure of a connection closes it without a SecMP byte; the relay reports
//! nothing per connection (ADR-022).

use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::NoServerSessionStorage;
use rustls::{NamedGroup, ProtocolVersion, ServerConfig, ServerConnection, StreamOwned};

use crate::error::{Error, Result};
use crate::event::Event;
use crate::relay::Relay;
use crate::server::{Listener, READ_POLL, Stream, WRITE_TIMEOUT};

/// The ALPN protocol of SecMP-LINK over TLS (spec §8.1).
pub const ALPN: &[u8] = b"secmp/1";

/// The one key-exchange group (IANA 0x11EC).
pub const GROUP: NamedGroup = NamedGroup::X25519MLKEM768;

/// The crypto provider of the listener: aws-lc-rs, the TLS 1.3 cipher suites only, `X25519MLKEM768` only (`docs/05`
/// §7; the same restriction as the client's, `secmp_transport::tls::crypto_provider`).
#[must_use]
pub fn crypto_provider() -> Arc<CryptoProvider> {
    let base = rustls::crypto::aws_lc_rs::default_provider();
    let cipher_suites = base
        .cipher_suites
        .iter()
        .copied()
        .filter(|s| s.version() == &rustls::version::TLS13)
        .collect();
    Arc::new(CryptoProvider {
        cipher_suites,
        kx_groups: vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768],
        ..base
    })
}

/// Whether `provider` can negotiate nothing but TLS 1.3 with `X25519MLKEM768`.
#[must_use]
pub fn is_tls13_hybrid_only(provider: &CryptoProvider) -> bool {
    !provider.cipher_suites.is_empty()
        && provider
            .cipher_suites
            .iter()
            .all(|s| s.version() == &rustls::version::TLS13)
        && provider.kx_groups.len() == 1
        && provider.kx_groups.iter().all(|g| g.name() == GROUP)
}

/// The listener's configuration for the certificate `cert` (DER) and its PKCS#8 key `key` (DER); see the module
/// documentation.
///
/// # Errors
/// [`Error::Config`] if the key does not load or does not match the certificate, or (never in a correct build) if the
/// configuration could negotiate anything but TLS 1.3 with `X25519MLKEM768`.
pub fn server_config(cert: Vec<u8>, key: Vec<u8>) -> Result<Arc<ServerConfig>> {
    let provider = crypto_provider();
    if !is_tls13_hybrid_only(&provider) {
        return Err(Error::Config(
            "direct_tls: the TLS provider is not TLS 1.3 X25519MLKEM768 only",
        ));
    }
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Config("direct_tls: TLS 1.3 is unavailable"))?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )
        .map_err(|_| Error::Config("direct_tls: the certificate or its key is invalid"))?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    // the `tls12` feature is on in the graph: assert that the configuration as built cannot negotiate it
    if !is_tls13_hybrid_only(config.crypto_provider()) {
        return Err(Error::Config(
            "direct_tls: the TLS provider is not TLS 1.3 X25519MLKEM768 only",
        ));
    }
    Ok(Arc::new(config))
}

/// Read the certificate and key files of the configuration and build [`server_config`].
///
/// # Errors
/// [`Error::Config`] if a file cannot be read or [`server_config`] refuses them.
pub fn load(cert: &std::path::Path, key: &std::path::Path) -> Result<Arc<ServerConfig>> {
    let cert = std::fs::read(cert)
        .map_err(|_| Error::Config("direct_tls: cannot read the certificate"))?;
    let key = std::fs::read(key).map_err(|_| Error::Config("direct_tls: cannot read the key"))?;
    server_config(cert, key)
}

/// Whether a finished handshake is the one the listener allows: TLS 1.3, `X25519MLKEM768`, ALPN `secmp/1`.
fn acceptable(conn: &ServerConnection) -> bool {
    !conn.is_handshaking()
        && conn.protocol_version() == Some(ProtocolVersion::TLSv1_3)
        && conn
            .negotiated_key_exchange_group()
            .map(rustls::crypto::SupportedKxGroup::name)
            == Some(GROUP)
        && conn.alpn_protocol() == Some(ALPN)
}

/// One accepted direct connection: the TLS server side over a socket `S` (TCP in the binary; the relay's tests use
/// an in-memory socket). The handshake runs inside the first reads (bounded like every connection's start, by the
/// `HELLO`→`HS1` timeout, [`crate::conn`]); the first plaintext byte is handed on only after the handshake passed
/// [`acceptable`], and nothing is written before.
pub struct TlsConn<S: Stream> {
    inner: StreamOwned<ServerConnection, Deadlined<S>>,
    checked: bool,
}

/// The socket under rustls with an absolute deadline for the current `read` call (EXT2B-1, Codex probe
/// `review_tls_inner_read_outlives_poll`): `StreamOwned::read` loops over raw reads until a TLS record is complete, and
/// every raw read has its own timeout, so a peer that trickles one byte per poll period would keep the call — and the
/// connection slot — for as long as it likes, out of reach of the `hello_timeout` check of the connection loop. With
/// the deadline every raw read and write is capped by what is left of it and fails with `TimedOut` at zero; rustls
/// keeps its partial state, the loop of [`crate::server::handle`] ticks and checks its timeouts, and calls again.
struct Deadlined<S: Stream> {
    sock: S,
    /// The read and write timeouts the connection loop asked for through [`Stream::set_poll`].
    poll: Duration,
    write: Duration,
    deadline: Option<Instant>,
    /// The socket's timeouts are the capped ones of the last call.
    capped: bool,
}

impl<S: Stream> Deadlined<S> {
    /// The time left, or `TimedOut` at zero; sets the socket's timeouts to the lesser of the asked ones and that.
    fn cap(&mut self) -> io::Result<()> {
        let Some(deadline) = self.deadline else {
            return Ok(());
        };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::from(ErrorKind::TimedOut));
        }
        self.capped = true;
        self.sock
            .set_poll(self.poll.min(left), self.write.min(left))
    }

    /// The end of a call: the asked timeouts again.
    fn disarm(&mut self) {
        self.deadline = None;
        if self.capped {
            self.capped = false;
            let _ = self.sock.set_poll(self.poll, self.write);
        }
    }
}

impl<S: Stream> Read for Deadlined<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.cap()?;
        self.sock.read(buf)
    }
}

impl<S: Stream> Write for Deadlined<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.cap()?;
        self.sock.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sock.flush()
    }
}

/// The refusal of a connection whose handshake the listener does not allow (no detail; the connection closes).
fn refused() -> io::Error {
    io::Error::from(ErrorKind::PermissionDenied)
}

impl<S: Stream> TlsConn<S> {
    /// The server side of `sock` under `config`.
    ///
    /// # Errors
    /// The connection could not be set up (never for a configuration from [`server_config`]).
    pub fn new(config: &Arc<ServerConfig>, sock: S) -> io::Result<Self> {
        let conn = ServerConnection::new(Arc::clone(config)).map_err(|_| refused())?;
        Ok(Self {
            inner: StreamOwned::new(
                conn,
                Deadlined {
                    sock,
                    poll: READ_POLL,
                    write: WRITE_TIMEOUT,
                    deadline: None,
                    capped: false,
                },
            ),
            checked: false,
        })
    }
}

impl<S: Stream> Read for TlsConn<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // one absolute deadline for the whole call, however many raw reads rustls makes in it
        let sock = &mut self.inner.sock;
        sock.deadline = Instant::now().checked_add(sock.poll);
        let n = self.inner.read(buf);
        self.inner.sock.disarm();
        let n = n?;
        if !self.checked {
            if n != 0 && !acceptable(&self.inner.conn) {
                return Err(refused());
            }
            self.checked = n != 0;
        }
        Ok(n)
    }
}

impl<S: Stream> Write for TlsConn<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // the relay answers only after a read: before the check passed nothing is written
        if !self.checked {
            return Err(refused());
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<S: Stream> Stream for TlsConn<S> {
    fn set_poll(&mut self, poll: Duration, write: Duration) -> io::Result<()> {
        let sock = &mut self.inner.sock;
        sock.poll = poll;
        sock.write = write;
        sock.capped = false;
        sock.sock.set_poll(poll, write)
    }

    fn close(&mut self) {
        if self.checked {
            self.inner.conn.send_close_notify();
            let _ = self.inner.conn.write_tls(&mut self.inner.sock);
        }
        self.inner.sock.sock.close();
    }
}

/// The direct listener: the connections of `L` (TCP in the binary), each wrapped in a [`TlsConn`].
pub struct TlsListener<L: Listener = TcpListener> {
    raw: L,
    config: Arc<ServerConfig>,
}

impl<L: Listener> TlsListener<L> {
    /// TLS under `config` on the connections of `raw`.
    pub const fn new(raw: L, config: Arc<ServerConfig>) -> Self {
        Self { raw, config }
    }
}

impl TlsListener {
    /// The listener's address (the tests bind port 0).
    ///
    /// # Errors
    /// The I/O error of the socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.raw.local_addr()
    }
}

impl<L: Listener> Listener for TlsListener<L> {
    type Conn = TlsConn<L::Conn>;

    fn accept_next(&self) -> io::Result<Self::Conn> {
        TlsConn::new(&self.config, self.raw.accept_next()?)
    }
}

/// Bind the direct listener at `addr` (any address: the operator chose to expose it, `docs/05` §7), non-blocking.
///
/// # Errors
/// [`Error::Io`] if the address cannot be bound.
pub fn bind(relay: &Relay, addr: SocketAddr, config: Arc<ServerConfig>) -> Result<TlsListener> {
    let tcp = TcpListener::bind(addr)?;
    tcp.set_nonblocking(true)?;
    let own = tcp.local_addr()?;
    relay.events().emit(&Event::ListenerBound { addr: &own });
    Ok(TlsListener::new(tcp, config))
}

/// A connection of either listener of [`Listeners`].
pub enum AnyConn<A: Stream, B: Stream> {
    /// From the onion loopback listener.
    Onion(A),
    /// From the direct listener.
    Direct(Box<B>),
}

impl<A: Stream, B: Stream> Read for AnyConn<A, B> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Onion(s) => s.read(buf),
            Self::Direct(s) => s.read(buf),
        }
    }
}

impl<A: Stream, B: Stream> Write for AnyConn<A, B> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Onion(s) => s.write(buf),
            Self::Direct(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Onion(s) => s.flush(),
            Self::Direct(s) => s.flush(),
        }
    }
}

impl<A: Stream, B: Stream> Stream for AnyConn<A, B> {
    fn set_poll(&mut self, poll: Duration, write: Duration) -> io::Result<()> {
        match self {
            Self::Onion(s) => s.set_poll(poll, write),
            Self::Direct(s) => s.set_poll(poll, write),
        }
    }

    fn close(&mut self) {
        match self {
            Self::Onion(s) => s.close(),
            Self::Direct(s) => s.close(),
        }
    }
}

/// The onion listener and the direct one behind one accept loop ([`crate::server::serve`]), so both share the
/// connection cap. The two are asked in turn; `WouldBlock` only when neither has a connection waiting.
pub struct Listeners<A: Listener, B: Listener> {
    onion: A,
    direct: B,
    direct_first: AtomicBool,
}

impl<A: Listener, B: Listener> Listeners<A, B> {
    /// Both listeners.
    pub const fn new(onion: A, direct: B) -> Self {
        Self {
            onion,
            direct,
            direct_first: AtomicBool::new(false),
        }
    }
}

impl<A: Listener, B: Listener> Listener for Listeners<A, B> {
    type Conn = AnyConn<A::Conn, B::Conn>;

    fn accept_next(&self) -> io::Result<Self::Conn> {
        let direct_first = self.direct_first.fetch_xor(true, Ordering::SeqCst);
        let onion = || self.onion.accept_next().map(AnyConn::Onion);
        let direct = || {
            self.direct
                .accept_next()
                .map(|c| AnyConn::Direct(Box::new(c)))
        };
        let first = if direct_first { direct() } else { onion() };
        match first {
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if direct_first {
                    onion()
                } else {
                    direct()
                }
            }
            other => other,
        }
    }
}

#[cfg(all(test, feature = "direct-tls"))]
mod m6_mut {
    //! `Deadlined::flush` reaches the socket (FIN4-3; mutant `Deadlined::flush -> Ok(())`).

    use std::io::{self, ErrorKind, Read, Write};
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    /// A socket that takes every write and fails every flush; it reads as ended.
    struct FlushFails;

    impl Read for FlushFails {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for FlushFails {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(ErrorKind::BrokenPipe))
        }
    }

    impl Stream for FlushFails {
        fn set_poll(&mut self, _poll: Duration, _write: Duration) -> io::Result<()> {
            Ok(())
        }

        fn close(&mut self) {}
    }

    /// Pinned rustls (0.23.46) calls `flush` on the socket in `complete_io` after it wrote the `ClientHello`: through
    /// `Deadlined` the socket's `BrokenPipe` reaches the caller. With `flush -> Ok(())` rustls goes on to read the end of the
    /// stream and fails with `UnexpectedEof` instead.
    #[test]
    fn deadlined_flush_reaches_the_socket() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let config = rustls::ClientConfig::builder_with_provider(crypto_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut client =
            rustls::ClientConnection::new(Arc::new(config), "relay.example".try_into()?)?;
        let mut sock = Deadlined {
            sock: FlushFails,
            poll: READ_POLL,
            write: WRITE_TIMEOUT,
            deadline: None,
            capped: false,
        };
        let err = client.complete_io(&mut sock).err();
        assert_eq!(err.map(|e| e.kind()), Some(ErrorKind::BrokenPipe));
        Ok(())
    }
}
