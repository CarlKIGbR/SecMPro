// SPDX-License-Identifier: AGPL-3.0-or-later
//! The TLS fixtures of the direct-mode tests of `secmp-transport` (TEST-SPEC-M6 TLS-01…TLS-15): Ed25519 certificates built in code
//! (`secmp_testkit::harness::cert`; no `rcgen`, OPEN-M6-09 A; no `openssl` at test time), an in-process rustls server whose configuration the test chooses
//! (always through `builder_with_provider`, TLS-10), a tap on the bytes the client sends, and a parser of the client's
//! `ClientHello`.

use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello as RustlsClientHello, ResolvesServerCert, ServerConfig};
use rustls::sign::CertifiedKey;
use secmp_transport::Error as TransportError;
use secmp_transport::driver::Isolation;
use secmp_transport::tls::Dialer;
use tokio::io::{AsyncRead, AsyncWriteExt, DuplexStream, ReadBuf};

use secmp_testkit::harness::MemRelay;

// ---- certificates ------------------------------------------------------------------------------------------------

pub use secmp_testkit::harness::cert::{
    EXPIRED, FixtureKey, NOT_YET, VALID, certificate, self_signed, self_signed_of_len,
};

/// `key` as rustls takes it.
#[must_use]
pub fn private_der(key: &FixtureKey) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.pkcs8()))
}

// ---- servers ---------------------------------------------------------------------------------------------------------

/// How the test server is configured.
#[derive(Clone)]
pub struct ServerSpec {
    /// The certificate chain it presents.
    pub chain: Vec<Vec<u8>>,
    /// The key it signs `CertificateVerify` with (need not match the certificate: TLS-07).
    pub key: Arc<FixtureKey>,
    /// Its key-exchange groups.
    pub groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
    /// TLS 1.2 only instead of TLS 1.3 only.
    pub tls12_only: bool,
    /// The ALPN protocols it selects from.
    pub alpn: Vec<Vec<u8>>,
    /// The session tickets it sends after the handshake.
    pub tickets: usize,
}

impl ServerSpec {
    /// A compliant direct-mode server for a self-signed certificate of `key` (TLS 1.3, `X25519MLKEM768`, ALPN
    /// `secmp/1`, no tickets).
    #[must_use]
    pub fn compliant(key: Arc<FixtureKey>) -> Self {
        Self {
            chain: vec![self_signed(&key, "relay.test", VALID)],
            key,
            groups: vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768],
            tls12_only: false,
            alpn: vec![secmp_transport::tls::ALPN.to_vec()],
            tickets: 0,
        }
    }
}

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl ResolvesServerCert for Fixed {
    fn resolve(&self, _hello: RustlsClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// The rustls server configuration of `spec` (always `builder_with_provider`, TLS-10).
///
/// # Panics
/// On a violated harness invariant: a test failure, never a production path.
#[must_use]
pub fn server_config(spec: &ServerSpec) -> Arc<ServerConfig> {
    let base = rustls::crypto::aws_lc_rs::default_provider();
    let provider = Arc::new(CryptoProvider {
        kx_groups: spec.groups.clone(),
        ..base
    });
    let versions: &[&'static rustls::SupportedProtocolVersion] = if spec.tls12_only {
        &[&rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };
    let signer =
        rustls::crypto::aws_lc_rs::sign::any_supported_type(&private_der(&spec.key)).unwrap();
    let chain: Vec<CertificateDer<'static>> = spec
        .chain
        .iter()
        .map(|c| CertificateDer::from(c.clone()))
        .collect();
    // the resolver does not check that the key matches the certificate (TLS-07 needs a mismatch)
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Fixed(Arc::new(CertifiedKey::new(chain, signer)))));
    config.alpn_protocols.clone_from(&spec.alpn);
    config.send_tls13_tickets = spec.tickets;
    config.max_early_data_size = 0;
    Arc::new(config)
}

/// The bytes a client sent, as a server saw them before TLS (the tap).
#[derive(Clone, Default)]
pub struct Tap(Arc<Mutex<Vec<u8>>>);

impl Tap {
    /// Append bytes (a hand-made server).
    pub fn push(&self, bytes: &[u8]) {
        self.0.lock().unwrap().extend_from_slice(bytes);
    }

    /// What was captured so far.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

/// A stream that records every byte read from it into a [`Tap`].
pub struct Tapped<S> {
    inner: S,
    tap: Tap,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tapped<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &polled {
            let new = buf.filled().get(before..).unwrap_or_default().to_vec();
            self.tap.0.lock().unwrap().extend(new);
        }
        polled
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Tapped<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// What the server side of a test connection did.
#[derive(Clone, Default)]
pub struct ServerLog {
    /// The bytes the client sent (raw TLS records).
    pub tap: Tap,
    /// Whether the TLS handshake completed on the server.
    pub accepted: Arc<Mutex<Vec<bool>>>,
    /// The plaintext (SecMP) bytes the server received after the handshake.
    pub plaintext: Arc<Mutex<Vec<u8>>>,
}

/// Serve one TLS connection on `stream` with `config`: record the client's raw bytes; after the handshake, carry the
/// plaintext to `relay` (a new in-process connection) in both directions, or, without a relay, read and record it.
pub async fn serve<S>(stream: S, config: Arc<ServerConfig>, relay: Option<MemRelay>, log: ServerLog)
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let tapped = Tapped {
        inner: stream,
        tap: log.tap.clone(),
    };
    let accepted = tokio_rustls::TlsAcceptor::from(config).accept(tapped).await;
    log.accepted.lock().unwrap().push(accepted.is_ok());
    let Ok(mut tls) = accepted else { return };
    let mut buf = vec![0_u8; 1 << 16];
    match relay.and_then(|r| r.open(Isolation(u64::MAX))) {
        Some(mut relay_stream) => {
            let (mut tr, mut tw) = tokio::io::split(tls);
            let (mut rr, mut rw) = tokio::io::split(relay_stream_take(&mut relay_stream));
            let plaintext = Arc::clone(&log.plaintext);
            let up = async move {
                let mut buf = vec![0_u8; 1 << 16];
                while let Ok(n) = tokio::io::AsyncReadExt::read(&mut tr, &mut buf).await {
                    if n == 0 || rw.write_all(buf.get(..n).unwrap()).await.is_err() {
                        break;
                    }
                    plaintext
                        .lock()
                        .unwrap()
                        .extend_from_slice(buf.get(..n).unwrap());
                }
                let _ = rw.shutdown().await;
            };
            let down = async move {
                let _ = tokio::io::copy(&mut rr, &mut tw).await;
                let _ = tw.shutdown().await;
            };
            tokio::spawn(up);
            tokio::spawn(down);
        }
        None => {
            while let Ok(n) = tokio::io::AsyncReadExt::read(&mut tls, &mut buf).await {
                if n == 0 {
                    break;
                }
                log.plaintext
                    .lock()
                    .unwrap()
                    .extend_from_slice(buf.get(..n).unwrap());
            }
        }
    }
}

fn relay_stream_take(s: &mut DuplexStream) -> DuplexStream {
    let (empty, _) = tokio::io::duplex(1);
    core::mem::replace(s, empty)
}

/// A [`Dialer`] whose every dial is an in-process connection to a test server (`config`, optionally fronting `relay`).
#[derive(Clone)]
pub struct MemTlsDialer {
    config: Arc<ServerConfig>,
    relay: Option<MemRelay>,
    /// What the server sides saw, one per dial.
    pub logs: Arc<Mutex<Vec<ServerLog>>>,
}

impl MemTlsDialer {
    /// A dialer to servers of `config`.
    #[must_use]
    pub fn new(config: Arc<ServerConfig>, relay: Option<MemRelay>) -> Self {
        Self {
            config,
            relay,
            logs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// The log of dial `n`.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn log(&self, n: usize) -> ServerLog {
        self.logs.lock().unwrap().get(n).cloned().unwrap()
    }
}

impl Dialer for MemTlsDialer {
    type Stream = DuplexStream;

    fn dial(
        &self,
        _host: &str,
        _port: u16,
    ) -> impl core::future::Future<Output = Result<DuplexStream, TransportError>> + Send {
        let (client, server) = tokio::io::duplex(1 << 17);
        let log = ServerLog::default();
        self.logs.lock().unwrap().push(log.clone());
        tokio::spawn(serve(
            server,
            Arc::clone(&self.config),
            self.relay.clone(),
            log,
        ));
        core::future::ready(Ok(client))
    }
}

// ---- the ClientHello --------------------------------------------------------------------------------------------------

/// The fields of a `ClientHello` the TLS rows look at (RFC 8446 §4.1.2, §4.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// `supported_groups` (10).
    pub groups: Vec<u16>,
    /// The groups of the `key_share` entries (51).
    pub key_shares: Vec<u16>,
    /// `supported_versions` (43).
    pub versions: Vec<u16>,
    /// `pre_shared_key` (41) present.
    pub psk: bool,
    /// `early_data` (42) present.
    pub early_data: bool,
    /// The ALPN protocols (16).
    pub alpn: Vec<Vec<u8>>,
    /// `server_name` (0) present.
    pub sni: bool,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *b.get(at)?,
        *b.get(at.checked_add(1)?)?,
    ]))
}

/// The handshake messages of the TLS records in `bytes` (records of type 22 only, as long as they are complete).
#[must_use]
pub fn handshake_messages(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut stream = Vec::new();
    let mut at = 0_usize;
    while let (Some(&kind), Some(len)) = (bytes.get(at), u16_at(bytes, at.saturating_add(3))) {
        let start = at.saturating_add(5);
        let end = start.saturating_add(usize::from(len));
        let Some(body) = bytes.get(start..end) else {
            break;
        };
        if kind == 22 {
            stream.extend_from_slice(body);
        }
        at = end;
    }
    let mut out = Vec::new();
    let mut at = 0_usize;
    while let Some(&kind) = stream.get(at) {
        let len = stream
            .get(at.saturating_add(1)..at.saturating_add(4))
            .and_then(|l| match l {
                [a, b, c] => {
                    Some((usize::from(*a) << 16) | (usize::from(*b) << 8) | usize::from(*c))
                }
                _ => None,
            });
        let Some(len) = len else { break };
        let start = at.saturating_add(4);
        let Some(body) = stream.get(start..start.saturating_add(len)) else {
            break;
        };
        out.push((kind, body.to_vec()));
        at = start.saturating_add(len);
    }
    out
}

/// The record content types of the TLS records in `bytes`, in order.
#[must_use]
pub fn record_types(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut at = 0_usize;
    while let (Some(&kind), Some(len)) = (bytes.get(at), u16_at(bytes, at.saturating_add(3))) {
        out.push(kind);
        at = at.saturating_add(5).saturating_add(usize::from(len));
    }
    out
}

/// Parse a `ClientHello` body.
#[must_use]
pub fn parse_client_hello(body: &[u8]) -> Option<ClientHelloInfo> {
    let mut at = 2_usize.checked_add(32)?;
    let sid = usize::from(*body.get(at)?);
    at = at.checked_add(1)?.checked_add(sid)?;
    let suites = usize::from(u16_at(body, at)?);
    at = at.checked_add(2)?.checked_add(suites)?;
    let comp = usize::from(*body.get(at)?);
    at = at.checked_add(1)?.checked_add(comp)?;
    let ext_len = usize::from(u16_at(body, at)?);
    at = at.checked_add(2)?;
    let exts = body.get(at..at.checked_add(ext_len)?)?;
    let mut info = ClientHelloInfo::default();
    let mut p = 0_usize;
    while p < exts.len() {
        let kind = u16_at(exts, p)?;
        let len = usize::from(u16_at(exts, p.checked_add(2)?)?);
        let data = exts.get(p.checked_add(4)?..p.checked_add(4)?.checked_add(len)?)?;
        match kind {
            0 => info.sni = true,
            10 => {
                let n = usize::from(u16_at(data, 0)?);
                info.groups = (0..n / 2)
                    .filter_map(|i| u16_at(data, i.saturating_mul(2).saturating_add(2)))
                    .collect();
            }
            16 => {
                let mut q = 2_usize;
                while q < data.len() {
                    let l = usize::from(*data.get(q)?);
                    let start = q.checked_add(1)?;
                    info.alpn
                        .push(data.get(start..start.checked_add(l)?)?.to_vec());
                    q = q.checked_add(1)?.checked_add(l)?;
                }
            }
            41 => info.psk = true,
            42 => info.early_data = true,
            43 => {
                let n = usize::from(*data.first()?);
                info.versions = (0..n / 2)
                    .filter_map(|i| u16_at(data, i.saturating_mul(2).saturating_add(1)))
                    .collect();
            }
            51 => {
                let mut q = 2_usize;
                while q < data.len() {
                    info.key_shares.push(u16_at(data, q)?);
                    let l = usize::from(u16_at(data, q.checked_add(2)?)?);
                    q = q.checked_add(4)?.checked_add(l)?;
                }
            }
            _ => {}
        }
        p = p.checked_add(4)?.checked_add(len)?;
    }
    Some(info)
}

/// The `ClientHello`s among the client's records.
#[must_use]
pub fn client_hellos(bytes: &[u8]) -> Vec<ClientHelloInfo> {
    handshake_messages(bytes)
        .into_iter()
        .filter(|(kind, _)| *kind == 1)
        .filter_map(|(_, body)| parse_client_hello(&body))
        .collect()
}

/// The legacy session id of the first `ClientHello` in `bytes` (an HRR must echo it).
#[must_use]
pub fn client_session_id(bytes: &[u8]) -> Vec<u8> {
    handshake_messages(bytes)
        .into_iter()
        .find(|(kind, _)| *kind == 1)
        .and_then(|(_, body)| {
            let n = usize::from(*body.get(34)?);
            body.get(35..35 + n).map(<[u8]>::to_vec)
        })
        .unwrap_or_default()
}

/// A `HelloRetryRequest` record asking for `group`, echoing `session_id` (RFC 8446 §4.1.4).
#[must_use]
pub fn hello_retry_request(session_id: &[u8], group: u16) -> Vec<u8> {
    const HRR_RANDOM: [u8; 32] = [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ];
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&HRR_RANDOM);
    body.push(u8::try_from(session_id.len()).unwrap());
    body.extend_from_slice(session_id);
    body.extend([0x13, 0x01, 0x00]);
    let mut exts = vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
    exts.extend([0x00, 0x33, 0x00, 0x02]);
    exts.extend(group.to_be_bytes());
    body.extend(u16::try_from(exts.len()).unwrap().to_be_bytes());
    body.extend(exts);
    let mut hs = vec![0x02, 0x00];
    hs.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
    hs.extend(body);
    let mut record = vec![0x16, 0x03, 0x03];
    record.extend(u16::try_from(hs.len()).unwrap().to_be_bytes());
    record.extend(hs);
    record
}
