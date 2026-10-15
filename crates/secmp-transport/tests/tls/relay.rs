// SPDX-License-Identifier: AGPL-3.0-or-later
//! The relay's direct listener (TEST-SPEC-M6 TLS-12…TLS-14; `docs/05` §7, OPEN-M6-08 A): its configuration as
//! `secmp-relay` builds it, and the relay process behind it on loopback TCP (`secmp_testkit::harness::DirectRelay`,
//! the binary's accept loop and thread model) against the direct-mode client of this crate and against a classical
//! client.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use secmp_testkit::harness::{DirectRelay, EntropyPool, RelayConfig, RelayLimits, relay_tls};
use secmp_transport::driver::{
    AsyncQueueTransport, AsyncRelayQueueTransport, Isolation, StreamProvider,
};
use secmp_transport::tls::{self, PinVerifier, TlsProvider};

use crate::fixture::{VALID, record_types, self_signed};
use crate::{X25519MLKEM768, key, runtime};

/// The relay's limits for the loopback rows: the defaults with the given connection cap.
fn limits(max_connections: usize) -> RelayLimits {
    RelayLimits {
        max_connections,
        ..RelayLimits::defaults()
    }
}

/// A relay with a self-signed certificate of fixture key `n`.
fn start(n: u8, max_connections: usize) -> DirectRelay {
    let k = key(n);
    let cert = self_signed(&k, "relay.test", VALID);
    DirectRelay::start(&cert, &k.pkcs8(), limits(max_connections))
}

/// The direct-mode client over loopback: TLS, then HELLO…HS2, `PING`, `QUEUE_NEW` (whose ids the transport checks
/// against the keys, spec §9.1) and an empty `FETCH`.
async fn link_and_queue(relay: &DirectRelay, label: &str) -> Result<(), secmp_transport::Error> {
    let stream = TlsProvider::new()
        .connect(&relay.relay_ref(), Isolation(1))
        .await?;
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
    let mut pool = EntropyPool::new(label, 0);
    let access = relay.access_key();
    let fp = relay.relay_ref().relay_fp;
    // the relay runs on the wall clock, and so does this client's handshake
    let now = DirectRelay::unix_now();
    let mut t =
        AsyncRelayQueueTransport::connect(stream, fp, Some(&access), now, pool.get()).await?;
    t.ping().await?;
    let (rc, _) = t
        .create_queue(
            &secmp_crypto::SecretBytes::from_slice(&[5; 32]).unwrap(),
            &secmp_crypto::SecretBytes::from_slice(&[6; 32]).unwrap(),
            &access,
        )
        .await?;
    assert!(t.fetch(&rc, 0).await?.is_empty());
    Ok(())
}

/// TLS-12 `relay_direct_tls_config` (`docs/05` §7; OPEN-M6-08 A): the listener's configuration as the relay builds it
/// from a fixture certificate and key — exactly the group `X25519MLKEM768`, TLS 1.3 only, ALPN [`secmp/1`], no
/// tickets, no early data, no session cache, no client authentication (a client without a certificate completes the
/// handshake, TLS-13); a key of another certificate is refused; the listener is off unless `direct_tls` is set.
#[test]
fn relay_direct_tls_config() {
    let k = key(12);
    let cert = self_signed(&k, "relay.test", VALID);
    let config = relay_tls::server_config(cert.clone(), k.pkcs8()).unwrap();
    let provider = config.crypto_provider();
    assert!(relay_tls::is_tls13_hybrid_only(provider));
    assert_eq!(
        provider
            .kx_groups
            .iter()
            .map(|g| u16::from(g.name()))
            .collect::<Vec<_>>(),
        vec![X25519MLKEM768]
    );
    assert!(
        provider
            .cipher_suites
            .iter()
            .all(|s| s.version() == &rustls::version::TLS13)
    );
    assert_eq!(config.alpn_protocols, vec![b"secmp/1".to_vec()]);
    assert_eq!(config.send_tls13_tickets, 0);
    assert_eq!(config.max_early_data_size, 0);
    assert!(!config.session_storage.can_cache());
    assert!(!config.ticketer.enabled());
    // a key that does not belong to the certificate
    assert!(relay_tls::server_config(cert, key(13).pkcs8()).is_err());
    // the relay source builds the listener without client authentication and with the explicit provider only
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../secmp-relay/src/tls.rs"),
    )
    .unwrap();
    assert!(src.contains(".with_no_client_auth()"));
    assert!(!src.contains("with_client_cert_verifier"));
    assert!(src.contains("ServerConfig::builder_with_provider("));
    // off by default
    let base = "[listen]\ntor_loopback = \"127.0.0.1:1\"\n[access]\nkey_file = \"k\"\n";
    assert_eq!(RelayConfig::parse(base).unwrap().direct_tls, None);
}

/// TLS-13 `relay_direct_tls_serves_link` (`docs/02` §2, `docs/05` §7; loopback integration test, `docs/06` §4): the
/// direct-mode client reaches the relay process through its TLS listener — HELLO…HS2, `PING` → `OK`, `QUEUE_NEW` →
/// `OK_QUEUE_NEW` with the ids derived from the keys — the identical SecMP-LINK as over the onion listener.
#[test]
fn relay_direct_tls_serves_link() {
    let relay = start(13, 8);
    runtime().block_on(async {
        link_and_queue(&relay, "tls-13").await.unwrap();
    });
}

/// A client configuration with a classical group only (otherwise like the direct-mode client: TLS 1.3, ALPN
/// `secmp/1`, the pin verifier) — what TLS-14 offers the relay.
fn classical_client(pin: [u8; 32]) -> Arc<ClientConfig> {
    let base = rustls::crypto::aws_lc_rs::default_provider();
    let provider = Arc::new(CryptoProvider {
        kx_groups: vec![rustls::crypto::aws_lc_rs::kx_group::X25519],
        ..base
    });
    let verifier: Arc<dyn ServerCertVerifier> = Arc::new(PinVerifier::new(pin));
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![tls::ALPN.to_vec()];
    Arc::new(config)
}

/// TLS-14 `relay_tls_refuses_classical_client` (CLAUDE.md §1.3): a client offering only X25519 fails the handshake;
/// the relay sends nothing but a TLS alert (no handshake flight, 0 SecMP bytes) and closes; its connection slot is
/// released — with `max_connections` = 1 a compliant client is served afterwards.
#[test]
fn relay_tls_refuses_classical_client() {
    let relay = start(14, 1);
    let mut tcp = TcpStream::connect(relay.addr()).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut client = ClientConnection::new(
        classical_client(relay.relay_ref().direct.as_ref().unwrap().spki_sha256),
        ServerName::try_from("relay.test").unwrap(),
    )
    .unwrap();
    while client.wants_write() {
        client.write_tls(&mut tcp).unwrap();
    }
    tcp.flush().unwrap();
    let mut answer = Vec::new();
    let _ = tcp.read_to_end(&mut answer);
    // the relay's bytes are TLS records: one alert, nothing else
    assert!(!answer.is_empty(), "the relay answers with an alert");
    assert_eq!(record_types(&answer), vec![0x15], "{answer:02x?}");
    let mut rd: &[u8] = &answer;
    client.read_tls(&mut rd).unwrap();
    assert!(client.process_new_packets().is_err());
    assert!(client.is_handshaking());
    // the slot is free again: a compliant client is served (the relay closes the refused one on its thread)
    let deadline = Instant::now() + Duration::from_secs(20);
    runtime().block_on(async {
        loop {
            match link_and_queue(&relay, "tls-14").await {
                Ok(()) => break,
                Err(e) => assert!(Instant::now() < deadline, "slot not released: {e:?}"),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
}

/// The listener's own ALPN check (not a TEST-SPEC row; it backs TLS-09 on the relay side): a client that completes the
/// TLS 1.3 / `X25519MLKEM768` handshake without offering ALPN gets no SecMP byte — its `HELLO` is not answered and the
/// connection closes.
#[test]
fn relay_tls_refuses_a_client_without_alpn() {
    let relay = start(15, 8);
    let pin = relay.relay_ref().direct.as_ref().unwrap().spki_sha256;
    let mut config = (*tls::client_config(pin).unwrap()).clone();
    config.alpn_protocols.clear();
    runtime().block_on(async {
        let tcp = tokio::net::TcpStream::connect(relay.addr()).await.unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let stream = connector
            .connect(ServerName::try_from("relay.test").unwrap(), tcp)
            .await
            .unwrap();
        assert_eq!(stream.get_ref().1.alpn_protocol(), None);
        // the same SecMP-LINK client that TLS-13 completes: here its HELLO is never answered
        let mut pool = EntropyPool::new("relay-no-alpn", 0);
        let access = relay.access_key();
        let fp = relay.relay_ref().relay_fp;
        let link = tokio::time::timeout(
            Duration::from_secs(20),
            AsyncRelayQueueTransport::connect(
                stream,
                fp,
                Some(&access),
                DirectRelay::unix_now(),
                pool.get(),
            ),
        )
        .await
        .unwrap();
        assert!(link.is_err(), "the link came up without ALPN");
    });
}
