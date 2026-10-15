// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![forbid(unsafe_code)]
//! Direct mode: `secmp_transport::tls` (TEST-SPEC-M6 TLS-01…TLS-11; spec §8.1, `docs/05` §7). An in-process rustls
//! server (always built with `builder_with_provider`) behind a duplex stream, or on loopback TCP for TLS-04 and TLS-11
//! (`docs/06:95`), fronting the in-process relay.

mod fixture;
mod relay;

use std::num::NonZeroU16;
use std::sync::Arc;

use secmp_proto::wire::inv::{Direct, Host, RelayRef};
use secmp_testkit::harness::{EntropyPool, HarnessConfig, MemRelay, START_UNIX};
use secmp_transport::Error;
use secmp_transport::driver::{
    AsyncQueueTransport, AsyncRelayQueueTransport, Isolation, StreamProvider,
};
use secmp_transport::tls::{self, Dialer, TlsProvider};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use fixture::{
    ClientHelloInfo, EXPIRED, FixtureKey, MemTlsDialer, NOT_YET, ServerLog, ServerSpec, VALID,
    certificate, client_hellos, client_session_id, hello_retry_request, record_types, self_signed,
    server_config,
};

const X25519MLKEM768: u16 = 0x11ec;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn key(n: u8) -> Arc<FixtureKey> {
    Arc::new(FixtureKey::new([n; 32]))
}

/// The relay's `RelayRef` with a direct endpoint `host:port` pinned by `pin`.
fn relay_ref(relay: &MemRelay, host: &str, port: u16, pin: [u8; 32]) -> RelayRef {
    let mut r = relay.relay_ref();
    r.direct = Some(Direct {
        host: Host::from_bytes(host.as_bytes()).unwrap(),
        port: NonZeroU16::new(port).unwrap(),
        spki_sha256: pin,
    });
    r
}

/// One in-process connection to a server of `spec`, pinned by `pin`; the server fronts `relay` if given.
async fn connect(
    spec: &ServerSpec,
    pin: [u8; 32],
    relay: Option<MemRelay>,
) -> (
    Result<tokio_rustls::client::TlsStream<DuplexStream>, Error>,
    ServerLog,
) {
    let dialer = MemTlsDialer::new(server_config(spec), relay);
    let provider = TlsProvider::with_dialer(dialer.clone());
    let target = MemRelay::new(HarnessConfig::default());
    let result = provider
        .connect(&relay_ref(&target, "relay.test", 443, pin), Isolation(1))
        .await;
    // let the server side finish its half
    tokio::task::yield_now().await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    (result, dialer.log(0))
}

fn first_hello(log: &ServerLog) -> ClientHelloInfo {
    client_hellos(&log.tap.bytes()).into_iter().next().unwrap()
}

/// TLS-01 (§8.1; CLAUDE.md §1.3): the client's provider has exactly one group, `X25519MLKEM768` (0x11EC), and its
/// `ClientHello` names and shares exactly that one.
#[test]
fn tls_client_offers_exactly_x25519mlkem768() {
    let config = tls::client_config([0; 32]).unwrap();
    let groups = &config.crypto_provider().kx_groups;
    assert_eq!(groups.len(), 1);
    assert_eq!(
        groups.first().map(|g| u16::from(g.name())),
        Some(X25519MLKEM768)
    );
    runtime().block_on(async {
        let k = key(1);
        let (result, log) = connect(&ServerSpec::compliant(Arc::clone(&k)), k.pin(), None).await;
        assert!(result.is_ok());
        let hello = first_hello(&log);
        assert_eq!(hello.groups, vec![X25519MLKEM768]);
        assert_eq!(hello.key_shares, vec![X25519MLKEM768]);
        assert!(!hello.sni, "no SNI");
    });
}

/// TLS-02 (§8.1): against a server limited to TLS 1.2 the handshake fails, no SecMP byte is written, and the client
/// offered only TLS 1.3.
#[test]
fn tls_client_is_tls13_only() {
    runtime().block_on(async {
        let k = key(2);
        let mut spec = ServerSpec::compliant(Arc::clone(&k));
        spec.tls12_only = true;
        spec.groups = vec![
            rustls::crypto::aws_lc_rs::kx_group::X25519,
            rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
        ];
        let (result, log) = connect(&spec, k.pin(), None).await;
        assert_eq!(result.err(), Some(Error::Rejected));
        assert!(log.plaintext.lock().unwrap().is_empty());
        assert_eq!(first_hello(&log).versions, vec![0x0304]);
    });
}

/// A dialer whose server answers the first `ClientHello` with a `HelloRetryRequest` for `group`, then records what the
/// client sends until it closes.
#[derive(Clone, Default)]
struct HrrDialer {
    tap: fixture::Tap,
    group: u16,
}

impl Dialer for HrrDialer {
    type Stream = DuplexStream;

    fn dial(
        &self,
        _host: &str,
        _port: u16,
    ) -> impl core::future::Future<Output = Result<DuplexStream, Error>> + Send {
        let (client, mut server) = tokio::io::duplex(1 << 16);
        let tap = self.tap.clone();
        let group = self.group;
        tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut buf = [0_u8; 4096];
            let mut answered = false;
            while let Ok(n) = server.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(buf.get(..n).unwrap());
                tap.push(buf.get(..n).unwrap());
                if !answered && !client_hellos(&seen).is_empty() {
                    answered = true;
                    let hrr = hello_retry_request(&client_session_id(&seen), group);
                    if server.write_all(&hrr).await.is_err() {
                        break;
                    }
                }
            }
        });
        core::future::ready(Ok(client))
    }
}

/// TLS-03 (CLAUDE.md §1.2–1.3): servers that offer only X25519, only secp256r1, or answer with a `HelloRetryRequest`
/// for X25519 all fail; the client sends exactly one `ClientHello` and no second key share — no classical retry.
#[test]
fn tls_no_classical_fallback() {
    runtime().block_on(async {
        let k = key(3);
        for group in [
            rustls::crypto::aws_lc_rs::kx_group::X25519,
            rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
        ] {
            let mut spec = ServerSpec::compliant(Arc::clone(&k));
            spec.groups = vec![group];
            let (result, log) = connect(&spec, k.pin(), None).await;
            assert_eq!(result.err(), Some(Error::Rejected), "{:?}", group.name());
            assert_eq!(client_hellos(&log.tap.bytes()).len(), 1);
            assert!(log.plaintext.lock().unwrap().is_empty());
        }
        let dialer = HrrDialer {
            tap: fixture::Tap::default(),
            group: 0x001d,
        };
        let provider = TlsProvider::with_dialer(dialer.clone());
        let target = MemRelay::new(HarnessConfig::default());
        let result = provider
            .connect(
                &relay_ref(&target, "relay.test", 443, k.pin()),
                Isolation(1),
            )
            .await;
        assert_eq!(result.err(), Some(Error::Rejected));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let sent = dialer.tap.bytes();
        let hellos = client_hellos(&sent);
        assert_eq!(hellos.len(), 1, "exactly one ClientHello");
        assert_eq!(
            hellos.first().map(|h| h.key_shares.clone()),
            Some(vec![X25519MLKEM768])
        );
        // after the ClientHello only an alert may follow, never a second handshake record
        let types = record_types(&sent);
        assert_eq!(types.first(), Some(&22));
        assert!(types.iter().skip(1).all(|t| *t == 21), "{types:?}");
    });
}

/// A loopback TCP server of `spec` fronting `relay`; its port.
async fn loopback_server(spec: &ServerSpec, relay: MemRelay) -> (u16, ServerLog) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = server_config(spec);
    let log = ServerLog::default();
    let server_log = log.clone();
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            fixture::serve(stream, config, Some(relay), server_log).await;
        }
    });
    (port, log)
}

/// TLS-04 (§8.1, `docs/05` §7): against a compliant, pinned relay on loopback TCP the handshake succeeds with
/// `X25519MLKEM768` and ALPN `secmp/1`, and the SecMP-LINK handshake and a `PING` run over it.
#[test]
fn tls_handshake_with_pinned_relay_succeeds() {
    runtime().block_on(async {
        let relay = MemRelay::new(HarnessConfig::default());
        let k = key(4);
        let (port, log) =
            loopback_server(&ServerSpec::compliant(Arc::clone(&k)), relay.clone()).await;
        let provider = TlsProvider::new();
        let stream = provider
            .connect(&relay_ref(&relay, "127.0.0.1", port, k.pin()), Isolation(1))
            .await
            .unwrap();
        {
            let (_, session) = stream.get_ref();
            assert_eq!(
                session
                    .negotiated_key_exchange_group()
                    .map(|g| u16::from(g.name())),
                Some(X25519MLKEM768)
            );
            assert_eq!(session.alpn_protocol(), Some(tls::ALPN));
        }
        let mut pool = EntropyPool::new("tls-04", 0);
        let access = relay.access_key();
        let mut t = AsyncRelayQueueTransport::connect(
            stream,
            relay.relay_fp(),
            Some(&access),
            START_UNIX,
            pool.get(),
        )
        .await
        .unwrap();
        t.ping().await.unwrap();
        let (rc, _) = t
            .create_queue(
                &secmp_crypto::SecretBytes::from_slice(&[5; 32]).unwrap(),
                &secmp_crypto::SecretBytes::from_slice(&[6; 32]).unwrap(),
                &access,
            )
            .await
            .unwrap();
        assert!(t.fetch(&rc, 0).await.unwrap().is_empty());
        assert_eq!(log.accepted.lock().unwrap().as_slice(), &[true]);
    });
}

/// TLS-05 (§8.1, D.3): a pin with byte 0 or byte 31 flipped, and a second valid certificate under the right pin, fail
/// with `Error::Rejected` before any SecMP byte.
#[test]
fn tls_spki_pin_mismatch_rejects() {
    runtime().block_on(async {
        let k = key(5);
        let spec = ServerSpec::compliant(Arc::clone(&k));
        for flip in [0_usize, 31] {
            let mut pin = k.pin();
            *pin.get_mut(flip).unwrap() ^= 0x01;
            let (result, log) =
                connect(&spec, pin, Some(MemRelay::new(HarnessConfig::default()))).await;
            assert_eq!(result.err(), Some(Error::Rejected), "byte {flip}");
            assert!(log.plaintext.lock().unwrap().is_empty());
        }
        let other = key(55);
        let (result, log) = connect(&ServerSpec::compliant(other), k.pin(), None).await;
        assert_eq!(result.err(), Some(Error::Rejected));
        assert!(log.plaintext.lock().unwrap().is_empty());
    });
}

/// TLS-06 (`docs/05` §7 "Web PKI is not used"): the pin is the only trust anchor — expired, not yet valid, wrongly named
/// and self-signed certificates with the pinned SPKI are accepted; a CA-signed certificate without the pin, and a chain
/// of two certificates, are rejected.
#[test]
fn tls_pin_is_the_only_trust_anchor() {
    runtime().block_on(async {
        let k = key(6);
        let pinned = [
            self_signed(&k, "relay.test", EXPIRED),
            self_signed(&k, "relay.test", NOT_YET),
            self_signed(&k, "other.example", VALID),
            self_signed(&k, "relay.test", VALID),
        ];
        for cert in pinned {
            let mut spec = ServerSpec::compliant(Arc::clone(&k));
            spec.chain = vec![cert];
            let (result, _) = connect(&spec, k.pin(), None).await;
            assert!(result.is_ok());
        }
        // a CA-signed certificate of another key: not pinned
        let ca = key(60);
        let leaf_key = key(61);
        let ca_cert = certificate(&ca, "Test CA", &ca, "Test CA", VALID, true, 7);
        let leaf = certificate(&leaf_key, "relay.test", &ca, "Test CA", VALID, false, 8);
        let mut spec = ServerSpec::compliant(Arc::clone(&leaf_key));
        spec.chain = vec![leaf, ca_cert.clone()];
        let (result, _) = connect(&spec, k.pin(), None).await;
        assert_eq!(result.err(), Some(Error::Rejected));
        // the pinned key, but a chain of two: refused (chain length 1)
        let mut spec = ServerSpec::compliant(Arc::clone(&k));
        spec.chain = vec![self_signed(&k, "relay.test", VALID), ca_cert];
        let (result, _) = connect(&spec, k.pin(), None).await;
        assert_eq!(result.err(), Some(Error::Rejected));
    });
}

/// TLS-07 (TLS 1.3 §4.4.3): the server presents the pinned certificate but signs `CertificateVerify` with another key —
/// the handshake fails (the pin does not replace the signature check).
#[test]
fn tls_certificate_verify_still_checked() {
    runtime().block_on(async {
        let k = key(7);
        let mut spec = ServerSpec::compliant(Arc::clone(&k));
        spec.key = key(77);
        let (result, log) = connect(&spec, k.pin(), None).await;
        assert_eq!(result.err(), Some(Error::Rejected));
        assert!(log.plaintext.lock().unwrap().is_empty());
    });
}

/// TLS-08 (§8.1 "no tickets/resumption/0-RTT"): the server issues two tickets; the client keeps none and its second
/// `ClientHello` carries no `pre_shared_key` and no `early_data`; early data is off.
#[test]
fn tls_no_resumption_no_early_data() {
    let config = tls::client_config([0; 32]).unwrap();
    assert!(!config.enable_early_data);
    runtime().block_on(async {
        let k = key(8);
        let mut spec = ServerSpec::compliant(Arc::clone(&k));
        spec.tickets = 2;
        let dialer = MemTlsDialer::new(server_config(&spec), None);
        let provider = TlsProvider::with_dialer(dialer.clone());
        let target = MemRelay::new(HarnessConfig::default());
        let r = relay_ref(&target, "relay.test", 443, k.pin());
        for _ in 0..2 {
            let mut stream = provider.connect(&r, Isolation(1)).await.unwrap();
            // read once so that the tickets are processed by the client
            stream.write_all(b"x").await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        for n in 0..2 {
            let hello = first_hello(&dialer.log(n));
            assert!(!hello.psk, "ClientHello {n} offers a PSK");
            assert!(!hello.early_data, "ClientHello {n} offers early data");
        }
    });
}

/// TLS-09 (§8.1): a server without ALPN, and one with only `h2`, fail before any SecMP byte.
#[test]
fn tls_alpn_secmp1_required() {
    runtime().block_on(async {
        let k = key(9);
        for alpn in [vec![], vec![b"h2".to_vec()]] {
            let mut spec = ServerSpec::compliant(Arc::clone(&k));
            spec.alpn = alpn.clone();
            let (result, log) = connect(&spec, k.pin(), None).await;
            assert_eq!(result.err(), Some(Error::Rejected), "{alpn:?}");
            assert!(log.plaintext.lock().unwrap().is_empty());
        }
    });
}

fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// TLS-10 (§8.1; CLAUDE.md §1.6): with aws-lc-rs's default provider (several groups) installed as the process default,
/// our configuration still has exactly one group — it is built with `builder_with_provider`; no workspace source calls
/// `ClientConfig::builder()` or `ServerConfig::builder()`.
#[test]
fn tls_provider_is_explicit() {
    let default = rustls::crypto::aws_lc_rs::default_provider();
    assert!(default.kx_groups.len() >= 3);
    let _ = default.install_default();
    assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    let config = tls::client_config([1; 32]).unwrap();
    assert_eq!(config.crypto_provider().kx_groups.len(), 1);
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    rust_files(&root.join("xtask"), &mut files);
    assert!(files.len() > 100);
    // the patterns are built from parts, so this file does not match itself
    let forbidden = [
        ["Client", "Config::builder()"].concat(),
        ["Server", "Config::builder()"].concat(),
    ];
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or_default();
            for pattern in &forbidden {
                assert!(
                    !code.contains(pattern.as_str()),
                    "{}:{}",
                    f.display(),
                    n + 1
                );
            }
        }
    }
    // the scan is not vacuous
    let planted = ["let c = rustls::", "Client", "Config::builder();"].concat();
    assert!(forbidden.iter().any(|p| planted.contains(p.as_str())));
}

/// The client's SecMP bytes (as the relay received them) of: handshake, then `QUEUE_NEW`, `SEND`, `FETCH`.
async fn link_bytes<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send>(
    stream: S,
    relay: &MemRelay,
) -> Vec<u8> {
    let mut pool = EntropyPool::new("harness-client", 0);
    let access = relay.access_key();
    let mut t = AsyncRelayQueueTransport::connect(
        stream,
        relay.relay_fp(),
        Some(&access),
        START_UNIX,
        pool.get(),
    )
    .await
    .unwrap();
    let mut seeds = EntropyPool::new("tls-11-seeds", 0);
    let (rc, sc) = t
        .create_queue(
            &secmp_crypto::SecretBytes::from_slice(&seeds.bytes(32)).unwrap(),
            &secmp_crypto::SecretBytes::from_slice(&seeds.bytes(32)).unwrap(),
            &access,
        )
        .await
        .unwrap();
    t.send(
        &sc,
        &secmp_proto::wire::cell::Cell::from_bytes(&[0x11; 4096]).unwrap(),
    )
    .await
    .unwrap();
    t.fetch(&rc, 0).await.unwrap();
    relay.capture(0).0
}

/// TLS-11 (§8.1 "identical SecMP-LINK bytes"): with the same randomness, `HELLO`, `HS1` and the first three C2R frames
/// are byte-identical over TLS on loopback and over the in-memory stream.
#[test]
fn tls_link_bytes_equal_other_transports() {
    runtime().block_on(async {
        let over_tls = MemRelay::new(HarnessConfig::default());
        let k = key(11);
        let (port, _) =
            loopback_server(&ServerSpec::compliant(Arc::clone(&k)), over_tls.clone()).await;
        let stream = TlsProvider::new()
            .connect(
                &relay_ref(&over_tls, "127.0.0.1", port, k.pin()),
                Isolation(1),
            )
            .await
            .unwrap();
        let tls_bytes = link_bytes(stream, &over_tls).await;
        let in_memory = MemRelay::new(HarnessConfig::default());
        let stream = in_memory.open(Isolation(1)).unwrap();
        let mem_bytes = link_bytes(stream, &in_memory).await;
        let n = 9 + 2856 + 3 * 4352;
        assert!(tls_bytes.len() >= n && mem_bytes.len() >= n);
        assert_eq!(tls_bytes.get(..9), mem_bytes.get(..9), "HELLO");
        assert_eq!(tls_bytes.get(9..2865), mem_bytes.get(9..2865), "HS1");
        assert_eq!(
            tls_bytes.get(2865..n),
            mem_bytes.get(2865..n),
            "the first three frames"
        );
    });
}
