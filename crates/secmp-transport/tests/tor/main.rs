// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Tor provider (TEST-SPEC-M6 TOR-01…TOR-04, TOR-08, TOR-09; spec §8.1, §12.3; CS-3.6): its configuration, the
//! isolation per connection, the bootstrap gate and events, the onion address and port — over a recording backend in
//! place of Arti's network calls (no network in tests, `docs/06` §4). TOR-05/TOR-06 (the provider selection) are in
//! the testkit harness (`m6_tor`), TOR-07 in `xtask` (`cargo metadata`).
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use arti_client::{ErrorKind, HasKind, IsolationToken, TorClient, TorClientConfig};
use secmp_proto::wire::inv::{Onion, RelayRef};
use secmp_transport::Error;
use secmp_transport::driver::{Isolation, StreamProvider};
use secmp_transport::tor::{self, ONION_PORT, Status, TorBackend, TorEvent, TorProvider, TorState};
use tokio::io::DuplexStream;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A fresh, empty directory for one test (under the build's temporary directory).
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("secmp-tor-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The 35 onion bytes of `pk`, encoded independently of `secmp-proto`: `pk ‖ SHA3-256(".onion checksum" ‖ pk ‖
/// 0x03)[0..2] ‖ 0x03` (rend-spec-v3 §6).
fn onion_bytes(pk: [u8; 32]) -> Vec<u8> {
    let check = secmp_crypto::sha3_256(&[b".onion checksum", &pk, &[0x03]]);
    [&pk[..], check.get(..2).unwrap(), &[0x03]].concat()
}

/// RFC 4648 base32, lowercase, no padding — written for the test (bit by bit), independent of the provider's.
fn base32(bytes: &[u8]) -> String {
    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
    let bits: Vec<u8> = bytes
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1))
        .collect();
    bits.chunks(5)
        .map(|c| {
            let v = c
                .iter()
                .chain(std::iter::repeat(&0))
                .take(5)
                .fold(0_usize, |a, b| (a << 1) | usize::from(*b));
            char::from(*alphabet.get(v).unwrap())
        })
        .collect()
}

fn relay_ref(pk: u8) -> RelayRef {
    RelayRef {
        relay_fp: [1; 32],
        onion: Onion::from_bytes(&onion_bytes([pk; 32])).unwrap(),
        akc: [2; 32],
        direct: None,
    }
}

/// What the backend was asked: (host, port, token).
type Calls = Arc<Mutex<Vec<(String, u16, IsolationToken)>>>;

/// A backend that records every connect and answers with an in-memory stream, or fails.
#[derive(Clone, Default)]
struct Recording {
    calls: Calls,
    fail: bool,
}

impl TorBackend for Recording {
    type Stream = DuplexStream;

    fn connect(
        &self,
        host: String,
        port: u16,
        isolation: IsolationToken,
    ) -> impl core::future::Future<Output = Result<DuplexStream, Error>> + Send {
        self.calls.lock().unwrap().push((host, port, isolation));
        let fail = self.fail;
        async move {
            if fail {
                Err(Error::Closed)
            } else {
                Ok(tokio::io::duplex(64).0)
            }
        }
    }
}

const READY: Status = Status {
    frac: 1.0,
    ready: true,
    blocked: false,
};

fn ready_provider(backend: Recording) -> TorProvider<Recording> {
    let state = Arc::new(TorState::new());
    let _ = state.observe(READY);
    TorProvider::with_backend(backend, state)
}

/// TOR-01 `tor_config_uses_profile_state_dir` (§12.3; CS-3.6): the Arti configuration of profile `D` keeps its state in
/// `D/tor/state` and its cache in `D/tor/cache` (the built `TorClientConfig`), and `fs-mistrust` is on: a directory
/// that others may write is refused; the source never switches the check off.
#[test]
fn tor_config_uses_profile_state_dir() {
    let profile = scratch("tor-01");
    let config: TorClientConfig = tor::config(&profile).unwrap();
    let dirs = config.dir_mgr_config().unwrap();
    assert_eq!(dirs.cache_dir, profile.join("tor").join("cache"));
    let debug = format!("{config:?}");
    let state = profile.join("tor").join("state");
    assert!(debug.contains(state.to_str().unwrap()), "{debug}");
    // no storage path is one of Arti's defaults (`${ARTI_LOCAL_DATA}`, `${ARTI_CACHE}`; the resolver's variable table
    // itself is listed without the `${`)
    assert!(!debug.contains("${ARTI"), "{debug}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let open = profile.join("open");
        std::fs::create_dir_all(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            config.fs_mistrust().check_directory(&open).is_err(),
            "fs-mistrust is on"
        );
        assert!(dirs.cache_trust.check_directory(&open).is_err());
    }
    let src = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tor/mod.rs"))
        .unwrap();
    assert!(src.contains(".ignore_environment()"));
    for f in ["src/tor/mod.rs", "src/tor/arti.rs"] {
        let text = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(f)).unwrap();
        assert!(
            !text.contains(concat!("dangerously_", "trust_everyone")),
            "{f}"
        );
    }
}

/// TOR-02 `tor_isolation_token_per_link` (§8.1; §12.3): three scheduled and two one-shot links make five connects with
/// five pairwise-distinct isolation tokens; the reconnect of link 1 gets a sixth — no token is shared, cached per relay
/// or reused after a close.
#[test]
fn tor_isolation_token_per_link() {
    let backend = Recording::default();
    let provider = ready_provider(backend.clone());
    runtime().block_on(async {
        let relay = relay_ref(0x42);
        for i in 0..5 {
            provider.connect(&relay, Isolation(i)).await.unwrap();
        }
        // the reconnect of link 1, to the same relay
        provider.connect(&relay, Isolation(5)).await.unwrap();
    });
    let calls = backend.calls.lock().unwrap();
    assert_eq!(calls.len(), 6);
    let mut tokens: Vec<IsolationToken> = calls.iter().map(|c| c.2).collect();
    tokens.sort();
    tokens.dedup();
    assert_eq!(tokens.len(), 6, "pairwise-distinct tokens");
}

/// TOR-03 `tor_no_link_before_bootstrap` (§12.3 "No link is opened before Tor has bootstrapped"; CLAUDE.md §1.5): at
/// 0 %, 50 % and 99 % a connect is `TorNotReady` and no stream is opened; once Arti is ready one connect opens one
/// stream.
#[test]
fn tor_no_link_before_bootstrap() {
    let backend = Recording::default();
    let state = Arc::new(TorState::new());
    let provider = TorProvider::with_backend(backend.clone(), Arc::clone(&state));
    runtime().block_on(async {
        let relay = relay_ref(0x43);
        assert_eq!(
            provider.connect(&relay, Isolation(0)).await.err(),
            Some(Error::TorNotReady)
        );
        for frac in [0.0, 0.5, 0.99] {
            let _ = state.observe(Status {
                frac,
                ready: false,
                blocked: false,
            });
            assert_eq!(
                provider.connect(&relay, Isolation(1)).await.err(),
                Some(Error::TorNotReady),
                "{frac}"
            );
        }
        assert!(
            backend.calls.lock().unwrap().is_empty(),
            "no stream before ready"
        );
        let _ = state.observe(READY);
        provider.connect(&relay, Isolation(2)).await.unwrap();
        assert_eq!(backend.calls.lock().unwrap().len(), 1);
        // blocked again (Arti lost its directory, say): no new link
        let _ = state.observe(Status {
            frac: 0.8,
            ready: false,
            blocked: true,
        });
        assert_eq!(
            provider.connect(&relay, Isolation(3)).await.err(),
            Some(Error::TorNotReady)
        );
        assert_eq!(backend.calls.lock().unwrap().len(), 1);
    });
}

/// TOR-04 `tor_bootstrap_events_mapped` (§12.3): Arti's statuses at 0.0, 0.5, 1.0 (ready), then a blockage, become
/// `Progress(0)`, `Progress(50)`, `Ready`, `Blocked` in this order and nothing else; a repeated status reports nothing.
#[test]
fn tor_bootstrap_events_mapped() {
    let state = TorState::new();
    let statuses = [
        Status {
            frac: 0.0,
            ready: false,
            blocked: false,
        },
        Status {
            frac: 0.0,
            ready: false,
            blocked: false,
        },
        Status {
            frac: 0.5,
            ready: false,
            blocked: false,
        },
        READY,
        READY,
        Status {
            frac: 1.0,
            ready: true,
            blocked: true,
        },
    ];
    let events: Vec<TorEvent> = statuses.iter().filter_map(|s| state.observe(*s)).collect();
    assert_eq!(
        events,
        vec![
            TorEvent::Progress(0),
            TorEvent::Progress(50),
            TorEvent::Ready,
            TorEvent::Blocked
        ]
    );
    // a failed bootstrap: connects are TorUnavailable from then on
    state.fail();
    assert_eq!(state.admit(), Err(Error::TorUnavailable));
}

/// TOR-08 `onion_address_from_relayref` (§5.3; rend-spec-v3 §6): the host of the 35-byte `onion` of a fixed key
/// (pk = 32 × 0x42) is `<56 lowercase base32 characters>.onion`, equal to the independent encoding here; Arti accepts
/// it as an onion address (an unbootstrapped Arti client — no network — parses it and then reports only that it is not
/// bootstrapped), and refuses it with a broken checksum.
///
/// Deviation from the row (report §5): the row asks that "Arti's `HsId` parse re-encodes to the same 35 B". `HsId` is
/// public in `arti-client` 0.46 only with its `experimental-api` feature, which TOR-07 forbids, and `tor-hscrypto` is
/// not a dependency of this workspace (ADR-051); Arti's own address check, reached through `connect_with_prefs`, is the
/// substitute.
#[test]
fn onion_address_from_relayref() {
    let pk = [0x42_u8; 32];
    let bytes = onion_bytes(pk);
    let onion = Onion::from_bytes(&bytes).unwrap();
    let host = tor::onion_host(&onion);
    assert_eq!(host, format!("{}.onion", base32(&bytes)));
    assert_eq!(host.len(), 56 + 6);
    assert!(
        host.trim_end_matches(".onion")
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    );
    // a published v3 address round-trips (DuckDuckGo's onion service, as in secmp-proto's test)
    let ddg = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad";
    let decoded = base32_decode(ddg);
    assert_eq!(
        tor::onion_host(&Onion::from_bytes(&decoded).unwrap()),
        format!("{ddg}.onion")
    );
    // Arti's own address check
    let mut broken = host.clone().into_bytes();
    *broken.get_mut(52).unwrap() = if broken.get(52) == Some(&b'a') {
        b'b'
    } else {
        b'a'
    };
    let broken = String::from_utf8(broken).unwrap();
    let profile = scratch("tor-08");
    runtime().block_on(async {
        let mut builder = arti_client::config::TorClientConfigBuilder::from_directories(
            profile.join("state"),
            profile.join("cache"),
        );
        // the scratch directory's permissions are the build's, not a profile's
        builder.storage().permissions().ignore_environment();
        builder.storage().permissions().dangerously_trust_everyone();
        let client = TorClient::builder()
            .config(builder.build().unwrap())
            .bootstrap_behavior(arti_client::BootstrapBehavior::Manual)
            .create_unbootstrapped()
            .unwrap();
        let ok = client
            .connect((host.as_str(), ONION_PORT))
            .await
            .err()
            .unwrap();
        assert_eq!(ok.kind(), ErrorKind::BootstrapRequired, "{ok}");
        let bad = client
            .connect((broken.as_str(), ONION_PORT))
            .await
            .err()
            .unwrap();
        assert_eq!(bad.kind(), ErrorKind::InvalidStreamTarget, "{bad}");
    });
}

fn base32_decode(s: &str) -> Vec<u8> {
    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
    let bits: Vec<u8> = s
        .bytes()
        .flat_map(|c| {
            let v = alphabet.iter().position(|a| *a == c).unwrap();
            (0..5)
                .rev()
                .map(move |i| u8::try_from((v >> i) & 1).unwrap())
        })
        .collect();
    bits.as_chunks::<8>()
        .0
        .iter()
        .map(|c| c.iter().fold(0_u8, |a, b| (a << 1) | b))
        .collect()
}

/// TOR-09 `onion_connect_uses_port_443` (§12.3; `docs/05` §2 `HiddenServicePort 443`): every connect asks the backend
/// for the relay's onion host on port 443 — no other port, no DNS name.
#[test]
fn onion_connect_uses_port_443() {
    let backend = Recording::default();
    let provider = ready_provider(backend.clone());
    runtime().block_on(async {
        for pk in [0x42, 0x43, 0x44] {
            provider
                .connect(&relay_ref(pk), Isolation(u64::from(pk)))
                .await
                .unwrap();
        }
    });
    let calls = backend.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    for ((host, port, _), pk) in calls.iter().zip([0x42_u8, 0x43, 0x44]) {
        assert_eq!(*port, 443);
        assert_eq!(*host, format!("{}.onion", base32(&onion_bytes([pk; 32]))));
    }
}

/// A backend failure is `TorUnavailable` (TOR-05's onion-connect half; the provider has no other provider to try).
#[test]
fn tor_connect_failure_is_tor_unavailable() {
    let backend = Recording {
        fail: true,
        ..Recording::default()
    };
    let provider = ready_provider(backend.clone());
    runtime().block_on(async {
        assert_eq!(
            provider.connect(&relay_ref(0x45), Isolation(0)).await.err(),
            Some(Error::TorUnavailable)
        );
    });
    assert_eq!(backend.calls.lock().unwrap().len(), 1);
}
