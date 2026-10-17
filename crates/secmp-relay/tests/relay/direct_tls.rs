// SPDX-License-Identifier: AGPL-3.0-or-later
//! The direct TLS listener (feature `direct-tls`; `docs/05` §7, OPEN-M6-08 A) over an in-memory socket — no network
//! (`docs/06` §4; the loopback rows TLS-13/TLS-14 are in `secmp-transport`): `server::handle` drives a
//! `tls::TlsConn` exactly as the binary's connection threads do, and a rustls client in the test talks to it. The
//! listener serves the SecMP-LINK handshake only after a TLS 1.3 / `X25519MLKEM768` / ALPN `secmp/1` handshake, sends
//! nothing but an alert to a classical client, hands nothing on without ALPN, and closes with
//! `close_notify`. The two listeners of the binary alternate behind one accept loop. Extra tests of M6 Phase B (they
//! back TLS-09, TLS-12…TLS-14 on the relay side).

use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use secmp_relay::server::{self, Listener, Stream, Time};
use secmp_relay::tls::{self, AnyConn, Listeners, TlsConn, TlsListener};
use secmp_relay::{Limits, Now};

use crate::fixture::{HELLO, NOW, RelayFx};

// ---- an in-memory socket -----------------------------------------------------------------------------------------

/// One direction: bytes in flight and whether the writer has closed.
#[derive(Default)]
struct Chan {
    state: Mutex<(VecDeque<u8>, bool)>,
    ready: Condvar,
}

/// One end of an in-memory socket; reads block up to the poll timeout set through `Stream::set_poll` (then
/// `WouldBlock`, as a TCP read timeout), a closed peer reads as EOF.
struct End {
    rx: Arc<Chan>,
    tx: Arc<Chan>,
    poll: Option<Duration>,
    /// Every byte this end wrote (the server's side of the capture).
    wrote: Arc<Mutex<Vec<u8>>>,
    closed: Arc<AtomicUsize>,
    /// `flush` fails (to see that a wrapper passes the inner result on).
    flush_fails: bool,
    /// While set, writes fail with `WouldBlock` (a full socket buffer).
    writes_block: Arc<std::sync::atomic::AtomicBool>,
    /// Every `(poll, write)` pair `set_poll` was given, in order.
    polls: Arc<Mutex<Vec<(Duration, Duration)>>>,
}

fn pair() -> (End, End) {
    let (a, b) = (Arc::new(Chan::default()), Arc::new(Chan::default()));
    let end = |rx: &Arc<Chan>, tx: &Arc<Chan>| End {
        rx: Arc::clone(rx),
        tx: Arc::clone(tx),
        poll: Some(Duration::from_secs(10)),
        wrote: Arc::new(Mutex::new(Vec::new())),
        closed: Arc::new(AtomicUsize::new(0)),
        flush_fails: false,
        writes_block: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        polls: Arc::new(Mutex::new(Vec::new())),
    };
    (end(&a, &b), end(&b, &a))
}

impl Read for End {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let deadline = self.poll.and_then(|p| Instant::now().checked_add(p));
        let mut st = self.rx.state.lock().unwrap();
        loop {
            if !st.0.is_empty() {
                let n = buf.len().min(st.0.len());
                for (slot, byte) in buf.iter_mut().zip(st.0.drain(..n)) {
                    *slot = byte;
                }
                return Ok(n);
            }
            if st.1 {
                return Ok(0);
            }
            let wait = match deadline {
                None => Duration::from_secs(3600),
                Some(d) => match d.checked_duration_since(Instant::now()) {
                    Some(left) if !left.is_zero() => left,
                    _ => return Err(io::Error::from(ErrorKind::WouldBlock)),
                },
            };
            st = self.rx.ready.wait_timeout(st, wait).unwrap().0;
        }
    }
}

impl Write for End {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.writes_block.load(Ordering::SeqCst) {
            return Err(io::Error::from(ErrorKind::WouldBlock));
        }
        let mut st = self.tx.state.lock().unwrap();
        if st.1 {
            return Err(io::Error::from(ErrorKind::BrokenPipe));
        }
        st.0.extend(buf);
        self.wrote.lock().unwrap().extend_from_slice(buf);
        self.tx.ready.notify_all();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.flush_fails {
            Err(io::Error::from(ErrorKind::BrokenPipe))
        } else {
            Ok(())
        }
    }
}

impl Stream for End {
    fn set_poll(&mut self, poll: Duration, write: Duration) -> io::Result<()> {
        self.poll = Some(poll);
        self.polls.lock().unwrap().push((poll, write));
        Ok(())
    }

    fn close(&mut self) {
        for chan in [&self.tx, &self.rx] {
            chan.state.lock().unwrap().1 = true;
            chan.ready.notify_all();
        }
        self.closed.fetch_add(1, Ordering::SeqCst);
    }
}

// ---- the relay side ----------------------------------------------------------------------------------------------

/// The fixture's time (`NOW`, when its key generation is valid) on a real monotonic clock.
#[derive(Clone, Copy)]
struct FixtureTime(Instant);

impl Time for FixtureTime {
    fn now(&self) -> Now {
        Now {
            unix_secs: NOW,
            mono_ms: u64::try_from(self.0.elapsed().as_millis()).unwrap(),
        }
    }

    fn pause(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

// ---- certificates ------------------------------------------------------------------------------------------------

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let n = content.len();
    let mut out = vec![tag];
    if n < 0x80 {
        out.push(u8::try_from(n).unwrap());
    } else if n < 0x100 {
        out.extend([0x81, u8::try_from(n).unwrap()]);
    } else {
        out.extend([
            0x82,
            u8::try_from(n >> 8).unwrap(),
            u8::try_from(n & 0xff).unwrap(),
        ]);
    }
    out.extend_from_slice(content);
    out
}

const ED25519_ALG: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

/// A self-signed Ed25519 certificate of seed `seed` and its PKCS#8 key (RFC 8410).
fn cert_and_key(seed: u8) -> (Vec<u8>, Vec<u8>) {
    let key = secmp_crypto::Ed25519SigningKey::from_seed(&[seed; 32]).unwrap();
    let cn = [
        &[0x06, 0x03, 0x55, 0x04, 0x03][..],
        &der(0x0c, b"relay.test"),
    ]
    .concat();
    let name = der(0x30, &der(0x31, &der(0x30, &cn)));
    let validity = der(
        0x30,
        &[der(0x17, b"200101000000Z"), der(0x17, b"491231235959Z")].concat(),
    );
    let bits = [&[0_u8][..], key.verifying_key().as_bytes()].concat();
    let spki = der(0x30, &[&ED25519_ALG[..], &der(0x03, &bits)].concat());
    let tbs = der(
        0x30,
        &[
            &der(0xa0, &[0x02, 0x01, 0x02])[..],
            &[0x02, 0x01, 0x01],
            &ED25519_ALG,
            &name,
            &validity,
            &name,
            &spki,
        ]
        .concat(),
    );
    let sig = key.sign(&tbs);
    let sig_bits = [&[0_u8][..], sig.as_ref()].concat();
    let cert = der(
        0x30,
        &[&tbs[..], &ED25519_ALG, &der(0x03, &sig_bits)].concat(),
    );
    let pkcs8 = der(
        0x30,
        &[
            &[0x02, 0x01, 0x00][..],
            &ED25519_ALG,
            &der(0x04, &der(0x04, &[seed; 32])),
        ]
        .concat(),
    );
    (cert, pkcs8)
}

// ---- the client side ---------------------------------------------------------------------------------------------

/// Accepts exactly the fixture certificate and checks the handshake signature with its key.
#[derive(Debug)]
struct Exactly(Vec<u8>, Arc<CryptoProvider>);

impl ServerCertVerifier for Exactly {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.0.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("not the fixture".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.1.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.1.signature_verification_algorithms.supported_schemes()
    }
}

/// A TLS 1.3 client: `groups`, ALPN `secmp/1` if `alpn`, trusting exactly `cert`.
fn client(
    cert: &[u8],
    groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
    alpn: bool,
) -> ClientConnection {
    let provider = Arc::new(CryptoProvider {
        kx_groups: groups,
        ..rustls::crypto::aws_lc_rs::default_provider()
    });
    let verifier: Arc<dyn ServerCertVerifier> =
        Arc::new(Exactly(cert.to_vec(), Arc::clone(&provider)));
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    if alpn {
        config.alpn_protocols = vec![tls::ALPN.to_vec()];
    }
    ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("relay.test").unwrap(),
    )
    .unwrap()
}

fn compliant(cert: &[u8], alpn: bool) -> ClientConnection {
    client(
        cert,
        vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768],
        alpn,
    )
}

/// One connection: the relay's `handle` on a thread over the server end; the test holds the client end.
struct Session {
    end: End,
    server_wrote: Arc<Mutex<Vec<u8>>>,
    server_closed: Arc<AtomicUsize>,
    done: Option<std::thread::JoinHandle<()>>,
}

/// The server thread of `s` ends within a bound: a `handle` that does not return (a retry loop on an error that must end
/// the connection) fails the test here after 5 s — not by hanging it, which cargo-mutants would count as a timeout.
fn ended(s: &mut Session) {
    let done = s.done.take().unwrap();
    let limit = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
    while !done.is_finished() && Instant::now() < limit {
        std::thread::sleep(Duration::from_millis(20));
    }
    // not joined when it did not end: a loop that retries a persistent error never returns, EOF or not, and the test
    // fails here; the thread dies with the test process
    assert!(done.is_finished(), "the connection did not end within 5 s");
    done.join().unwrap();
}

fn session(seed: u8) -> (Session, Vec<u8>) {
    let (cert, key) = cert_and_key(seed);
    let config = tls::server_config(cert.clone(), key).unwrap();
    let (server_end, client_end) = pair();
    let server_wrote = Arc::clone(&server_end.wrote);
    let server_closed = Arc::clone(&server_end.closed);
    let conn = TlsConn::new(&config, server_end).unwrap();
    let done = std::thread::spawn(move || {
        let relay = RelayFx::case1().relay(Limits::defaults());
        server::handle(&relay, conn, &FixtureTime(Instant::now()));
    });
    (
        Session {
            end: client_end,
            server_wrote,
            server_closed,
            done: Some(done),
        },
        cert,
    )
}

/// Write everything the client has queued (its last handshake flight, application data, alerts).
fn flush(c: &mut ClientConnection, end: &mut End) {
    while c.wants_write() {
        c.write_tls(end).unwrap();
    }
}

/// Drive the client's handshake over `end`: Ok when it completed, Err with rustls's error otherwise (or when the
/// peer closed first).
fn handshake(c: &mut ClientConnection, end: &mut End) -> Result<(), String> {
    while c.is_handshaking() {
        while c.wants_write() {
            c.write_tls(end).map_err(|e| e.to_string())?;
        }
        if !c.is_handshaking() {
            break;
        }
        match c.read_tls(end) {
            Ok(0) => return Err("closed".into()),
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        }
        c.process_new_packets().map_err(|e| e.to_string())?;
    }
    flush(c, end);
    Ok(())
}

/// The plaintext the relay sends until it closes (or `limit` bytes, or a 10-s silence); and whether the close came
/// with `close_notify`.
fn plaintext(c: &mut ClientConnection, end: &mut End, limit: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    loop {
        let mut buf = [0_u8; 4096];
        match c.reader().read(&mut buf) {
            Ok(0) => return (out, true),
            Ok(n) => {
                out.extend_from_slice(buf.get(..n).unwrap());
                if out.len() >= limit {
                    return (out, false);
                }
                continue;
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(_) => return (out, false),
        }
        match c.read_tls(end) {
            Ok(0) | Err(_) => {
                let _ = c.process_new_packets();
                let clean = matches!(c.reader().read(&mut buf), Ok(0));
                return (out, clean);
            }
            Ok(_) => {
                if c.process_new_packets().is_err() {
                    return (out, false);
                }
            }
        }
    }
}

/// The TLS record types in `bytes` (5-byte headers).
fn record_types(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while let (Some(&t), Some(len)) = (rest.first(), rest.get(3..5)) {
        out.push(t);
        let n = usize::from(u16::from_be_bytes(len.try_into().unwrap()));
        rest = rest.get(n.saturating_add(5)..).unwrap_or_default();
    }
    out
}

/// The `RELAYINFO` record (D.1): 1 744 bytes.
const RELAYINFO_RECORD: usize = 1744;

/// A compliant client gets the SecMP-LINK `RELAYINFO` for its `HELLO` through TLS; when it leaves, the relay closes
/// with `close_notify` and releases the socket.
#[test]
fn direct_tls_serves_the_link_handshake() {
    let (mut s, cert) = session(41);
    let mut c = compliant(&cert, true);
    handshake(&mut c, &mut s.end).unwrap();
    assert_eq!(c.alpn_protocol(), Some(tls::ALPN));
    c.writer().write_all(&HELLO).unwrap();
    flush(&mut c, &mut s.end);
    let (relayinfo, _) = plaintext(&mut c, &mut s.end, RELAYINFO_RECORD);
    assert_eq!(relayinfo.len(), RELAYINFO_RECORD);
    assert_eq!(
        relayinfo.get(..2),
        Some(
            u16::try_from(RELAYINFO_RECORD - 2)
                .unwrap()
                .to_be_bytes()
                .as_slice()
        )
    );
    // the client leaves with close_notify: the relay ends the connection cleanly, with its own close_notify (TLS 1.3
    // encrypts alerts, so the clean end is what the client sees, not a record type)
    c.send_close_notify();
    flush(&mut c, &mut s.end);
    let (rest, clean) = plaintext(&mut c, &mut s.end, 1);
    assert!(rest.is_empty());
    assert!(clean, "the relay's close carries close_notify");
    ended(&mut s);
    assert_eq!(s.server_closed.load(Ordering::SeqCst), 1);
    // the relay wrote TLS records only: its handshake flight, the RELAYINFO record and the alert
    let types = record_types(&s.server_wrote.lock().unwrap());
    assert!(
        types.len() >= 4 && types.iter().all(|t| [0x14, 0x16, 0x17].contains(t)),
        "{types:?}"
    );
}

/// The relay closes on `close_notify` from the client side as well as on its own teardown — and a relay-side close
/// after a served exchange carries `close_notify` (the client sees a clean end, not a truncation).
#[test]
fn direct_tls_close_sends_close_notify() {
    let (mut s, cert) = session(42);
    let mut c = compliant(&cert, true);
    handshake(&mut c, &mut s.end).unwrap();
    // a HELLO, then a short HS1: the relay's link layer tears down, the TLS layer closes cleanly
    c.writer().write_all(&HELLO).unwrap();
    flush(&mut c, &mut s.end);
    let (relayinfo, _) = plaintext(&mut c, &mut s.end, RELAYINFO_RECORD);
    assert_eq!(relayinfo.len(), RELAYINFO_RECORD);
    c.writer()
        .write_all(&[0x00, 0x03, 0x02, 0x00, 0x00])
        .unwrap();
    flush(&mut c, &mut s.end);
    let (rest, clean) = plaintext(&mut c, &mut s.end, 1);
    assert!(rest.is_empty(), "nothing after a broken HS1");
    assert!(clean, "the relay's close carries close_notify");
    ended(&mut s);
    assert_eq!(s.server_closed.load(Ordering::SeqCst), 1);
}

/// A client offering only a classical group (X25519, or P-256) gets one alert and nothing else; the relay closes.
#[test]
fn direct_tls_refuses_classical_groups() {
    for (seed, group) in [
        (43, rustls::crypto::aws_lc_rs::kx_group::X25519),
        (44, rustls::crypto::aws_lc_rs::kx_group::SECP256R1),
    ] {
        let (mut s, cert) = session(seed);
        let mut c = client(&cert, vec![group], true);
        assert!(handshake(&mut c, &mut s.end).is_err());
        ended(&mut s);
        let wrote = s.server_wrote.lock().unwrap().clone();
        assert_eq!(record_types(&wrote), vec![0x15], "{wrote:02x?}");
        assert_eq!(s.server_closed.load(Ordering::SeqCst), 1);
    }
}

/// A client that completes the TLS handshake without ALPN gets no SecMP byte: its `HELLO` is not handed to the link
/// layer, and the connection closes.
#[test]
fn direct_tls_hands_nothing_on_without_alpn() {
    let (mut s, cert) = session(46);
    let mut c = compliant(&cert, false);
    handshake(&mut c, &mut s.end).unwrap();
    assert_eq!(c.alpn_protocol(), None);
    c.writer().write_all(&HELLO).unwrap();
    flush(&mut c, &mut s.end);
    let (answer, _) = plaintext(&mut c, &mut s.end, 1);
    assert!(answer.is_empty(), "{} SecMP bytes", answer.len());
    ended(&mut s);
    assert_eq!(s.server_closed.load(Ordering::SeqCst), 1);
}

// ---- the two listeners -------------------------------------------------------------------------------------------

/// A listener with a fixed number of waiting connections; then `WouldBlock`, or another error if `fail`.
struct Counted {
    left: AtomicUsize,
    calls: AtomicUsize,
    fail: bool,
}

impl Counted {
    fn new(left: usize, fail: bool) -> Self {
        Self {
            left: AtomicUsize::new(left),
            calls: AtomicUsize::new(0),
            fail,
        }
    }
}

impl Listener for Counted {
    type Conn = End;

    fn accept_next(&self) -> io::Result<End> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.left.load(Ordering::SeqCst) > 0 {
            self.left.fetch_sub(1, Ordering::SeqCst);
            return Ok(pair().0);
        }
        Err(io::Error::from(if self.fail {
            ErrorKind::ConnectionAborted
        } else {
            ErrorKind::WouldBlock
        }))
    }
}

fn kind<A: Stream, B: Stream>(c: &io::Result<AnyConn<A, B>>) -> &'static str {
    match c {
        Ok(AnyConn::Onion(_)) => "onion",
        Ok(AnyConn::Direct(_)) => "direct",
        Err(e) if e.kind() == ErrorKind::WouldBlock => "would-block",
        Err(_) => "error",
    }
}

/// Both listeners behind one accept loop: asked in turn (onion first), the other one when the first has nothing
/// waiting, `WouldBlock` only when neither has; another error of the first is returned as it is.
#[test]
fn listeners_alternate_and_fall_through() {
    let both = Listeners::new(Counted::new(2, false), Counted::new(2, false));
    let got: Vec<_> = (0..5).map(|_| kind(&both.accept_next())).collect();
    assert_eq!(got, ["onion", "direct", "onion", "direct", "would-block"]);
    let only_direct = Listeners::new(Counted::new(0, false), Counted::new(2, false));
    let got: Vec<_> = (0..3).map(|_| kind(&only_direct.accept_next())).collect();
    assert_eq!(got, ["direct", "direct", "would-block"]);
    let only_onion = Listeners::new(Counted::new(2, false), Counted::new(0, false));
    let got: Vec<_> = (0..3).map(|_| kind(&only_onion.accept_next())).collect();
    assert_eq!(got, ["onion", "onion", "would-block"]);
    let failing = Listeners::new(Counted::new(0, true), Counted::new(1, false));
    assert_eq!(kind(&failing.accept_next()), "error");
    assert_eq!(kind(&failing.accept_next()), "direct");
}

/// The direct listener wraps each raw connection in TLS under its configuration (the binary's `TlsListener` over
/// TCP); a failing raw accept is passed on.
#[test]
fn tls_listener_wraps_raw_connections() {
    let (cert, key) = cert_and_key(47);
    let config = tls::server_config(cert, key).unwrap();
    let raw = Counted::new(1, false);
    let listener = TlsListener::new(raw, Arc::clone(&config));
    assert!(listener.accept_next().is_ok());
    assert_eq!(
        listener.accept_next().err().map(|e| e.kind()),
        Some(ErrorKind::WouldBlock)
    );
}

/// The configuration refuses a key of another certificate, and a key that is no PKCS#8 key.
#[test]
fn server_config_refuses_a_foreign_or_broken_key() {
    let (cert, _) = cert_and_key(48);
    let (_, other) = cert_and_key(49);
    assert!(tls::server_config(cert.clone(), other).is_err());
    assert!(tls::server_config(cert, vec![0x30, 0x00]).is_err());
}

/// The listener's provider check refuses every provider but TLS 1.3 with `X25519MLKEM768` alone: no suite, a second
/// group, a classical group, aws-lc-rs's default.
#[test]
fn provider_check_refuses_other_providers() {
    use rustls::crypto::aws_lc_rs::kx_group::{SECP256R1, X25519, X25519MLKEM768};
    let ours = tls::crypto_provider();
    assert!(tls::is_tls13_hybrid_only(&ours));
    let with = |groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>| CryptoProvider {
        kx_groups: groups,
        ..(*ours).clone()
    };
    assert!(!tls::is_tls13_hybrid_only(&with(vec![
        X25519MLKEM768,
        X25519
    ])));
    assert!(!tls::is_tls13_hybrid_only(&with(vec![X25519])));
    assert!(!tls::is_tls13_hybrid_only(&with(vec![SECP256R1])));
    assert!(!tls::is_tls13_hybrid_only(&with(vec![])));
    let no_suite = CryptoProvider {
        cipher_suites: vec![],
        ..(*ours).clone()
    };
    assert!(!tls::is_tls13_hybrid_only(&no_suite));
    assert!(!tls::is_tls13_hybrid_only(
        &rustls::crypto::aws_lc_rs::default_provider()
    ));
}

/// `AnyConn` hands every call to the connection it holds, either kind: reads, writes, flushes (with their result),
/// timeouts and the close.
#[test]
fn any_conn_delegates_to_its_connection() {
    for direct in [false, true] {
        let (mut ours, mut peer) = pair();
        ours.flush_fails = true;
        let closed = Arc::clone(&ours.closed);
        let mut c: AnyConn<End, End> = if direct {
            AnyConn::Direct(Box::new(ours))
        } else {
            AnyConn::Onion(ours)
        };
        peer.write_all(b"in").unwrap();
        let mut buf = [0_u8; 8];
        assert_eq!(c.read(&mut buf).unwrap(), 2);
        assert_eq!(buf.get(..2), Some(b"in".as_slice()));
        assert_eq!(c.write(b"out!").unwrap(), 4);
        assert_eq!(peer.read(&mut buf).unwrap(), 4);
        assert_eq!(buf.get(..4), Some(b"out!".as_slice()));
        assert!(c.flush().is_err());
        c.set_poll(Duration::from_millis(1), Duration::from_secs(1))
            .unwrap();
        let start = Instant::now();
        assert_eq!(
            c.read(&mut buf).err().map(|e| e.kind()),
            Some(ErrorKind::WouldBlock)
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the poll timeout was passed on"
        );
        c.close();
        assert_eq!(closed.load(Ordering::SeqCst), 1);
        assert_eq!(peer.read(&mut buf).unwrap(), 0, "the peer sees the close");
    }
}

/// `TlsConn` passes the connection loop's read timeout to its socket: a read on a silent peer returns `WouldBlock`
/// after the poll time (the binary's `READ_POLL`), not after the socket's own.
#[test]
fn tls_conn_passes_the_poll_timeout_on() {
    let (cert, key) = cert_and_key(50);
    let config = tls::server_config(cert, key).unwrap();
    let (server_end, _client_end) = pair();
    let mut conn = TlsConn::new(&config, server_end).unwrap();
    conn.set_poll(Duration::from_millis(1), Duration::from_secs(1))
        .unwrap();
    let start = Instant::now();
    let mut buf = [0_u8; 8];
    assert_eq!(
        conn.read(&mut buf).err().map(|e| e.kind()),
        Some(ErrorKind::WouldBlock)
    );
    assert!(start.elapsed() < Duration::from_secs(5));
}

/// `TlsConn::flush` pushes out what a refused socket write left in the TLS buffer: with the socket full, a write is
/// buffered (the relay's `write_all` does not see the refusal), and the flush after it delivers the bytes.
#[test]
fn tls_conn_flush_delivers_buffered_bytes() {
    let (cert, key) = cert_and_key(51);
    let config = tls::server_config(cert.clone(), key).unwrap();
    let (server_end, mut client_end) = pair();
    let block = Arc::clone(&server_end.writes_block);
    let mut conn = TlsConn::new(&config, server_end).unwrap();
    let server = std::thread::spawn(move || {
        let mut buf = [0_u8; 64];
        // the handshake runs inside the reads; the first plaintext is the client's byte
        let n = loop {
            match conn.read(&mut buf) {
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                read => break read.unwrap(),
            }
        };
        assert_eq!(buf.get(..n), Some(b"?".as_slice()));
        // as in the connection loop: short read polls (rustls's I/O step reads after a refused write)
        conn.set_poll(Duration::from_millis(50), Duration::from_secs(1))
            .unwrap();
        block.store(true, Ordering::SeqCst);
        assert_eq!(conn.write(b"!").unwrap(), 1);
        block.store(false, Ordering::SeqCst);
        conn.flush().unwrap();
        conn
    });
    let mut c = compliant(&cert, true);
    handshake(&mut c, &mut client_end).unwrap();
    c.writer().write_all(b"?").unwrap();
    flush(&mut c, &mut client_end);
    let (answer, _) = plaintext(&mut c, &mut client_end, 1);
    assert_eq!(answer, b"!");
    drop(server.join().unwrap());
}

/// EXT2B-1 (Codex probe `review_tls_inner_read_outlives_poll`): a `ClientHello` record trickled one byte per 300 ms —
/// every raw read returns within `READ_POLL`, so rustls's I/O loop never gives control back — must still end at the
/// `hello_timeout`: the connection is closed within `hello_timeout + READ_POLL` (plus scheduling slack) and `handle`
/// returns, so the connection slot (`server::Slot`, counted out when `handle` returns) is free.
#[test]
fn a_trickled_client_hello_ends_at_the_hello_timeout() {
    const HELLO_TIMEOUT_MS: u64 = 1500;
    const PER_BYTE: Duration = Duration::from_millis(300);
    let (cert, key) = cert_and_key(21);
    let config = tls::server_config(cert, key).unwrap();
    let (server_end, mut client_end) = pair();
    let server_closed = Arc::clone(&server_end.closed);
    let conn = TlsConn::new(&config, server_end).unwrap();
    let started = Instant::now();
    let server = std::thread::spawn(move || {
        let relay = RelayFx::case1().relay(Limits {
            hello_timeout_ms: HELLO_TIMEOUT_MS,
            ..Limits::defaults()
        });
        server::handle(&relay, conn, &FixtureTime(Instant::now()));
        Instant::now()
    });
    // a handshake record header announcing 1400 bytes, then one filler byte per 300 ms; the trickle stops at 40 bytes so
    // that the unfixed code ends (after ~12 s) instead of after 7 minutes
    let mut record = vec![0x16, 0x03, 0x01, 0x05, 0x78];
    record.resize(40, 0x01);
    for byte in record {
        if server_closed.load(Ordering::SeqCst) > 0 {
            break;
        }
        client_end.write_all(&[byte]).unwrap();
        std::thread::sleep(PER_BYTE);
    }
    // bounded: a `handle` that does not close on the timeout fails here, it does not hang the test (mutants-156)
    let limit = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
    while !server.is_finished() && Instant::now() < limit {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        server.is_finished(),
        "the connection did not end within 5 s"
    );
    let ended = server.join().unwrap().duration_since(started);
    let bound =
        Duration::from_millis(HELLO_TIMEOUT_MS) + server::READ_POLL + Duration::from_millis(300);
    assert!(
        ended <= bound,
        "EXT2B-1: closed after {ended:?}, hello_timeout + READ_POLL is {bound:?}"
    );
    assert!(server_closed.load(Ordering::SeqCst) > 0);
}

/// EXT3B mutants-156 (`tls.rs`, `TlsConn::set_poll` replaced by `Ok(())`): the timeouts the connection loop asks for
/// reach the socket under the TLS stream — at once, and again after a `read` (which narrows them to its deadline and
/// restores them) — so that a write to a peer that does not read is bounded by the asked write timeout, and a failure of
/// the socket's `set_poll` is the caller's. (The read side is bounded by the per-call deadline of `Deadlined` in any
/// case; this is what the write timeout and the restore depend on.)
#[test]
fn tls_conn_set_poll_reaches_the_socket() {
    let (cert, key) = cert_and_key(22);
    let config = tls::server_config(cert, key).unwrap();
    let (server_end, _client_end) = pair();
    let polls = Arc::clone(&server_end.polls);
    let mut conn = TlsConn::new(&config, server_end).unwrap();
    let (poll, write) = (Duration::from_millis(123), Duration::from_secs(45));
    conn.set_poll(poll, write).unwrap();
    assert_eq!(polls.lock().unwrap().last(), Some(&(poll, write)));
    // a read narrows the socket's timeouts to the call's deadline (never above the asked poll) and puts them back
    let mut buf = [0_u8; 8];
    let err = conn.read(&mut buf).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
    let seen = polls.lock().unwrap().clone();
    assert!(seen.len() >= 3, "{seen:?}");
    assert!(
        seen.iter().skip(1).all(|(p, w)| *p <= poll && *w <= write),
        "{seen:?}"
    );
    assert_eq!(seen.last(), Some(&(poll, write)), "restored after the read");
}
