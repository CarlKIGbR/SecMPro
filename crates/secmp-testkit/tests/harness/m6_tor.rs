// SPDX-License-Identifier: AGPL-3.0-or-later
//! The choice between the Tor and the direct provider (TEST-SPEC-M6 TOR-05, TOR-06; spec §5.3, §8.1; CLAUDE.md §1.5):
//! `scheduler::run::Selected` over the Tor provider (its Arti backend replaced by a recording one; no network) and a
//! counting stand-in for the TLS provider. The transport comes from the scheduler, which takes it from the user's
//! direct-mode setting only.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use secmp_client_core::scheduler::core::Scheduler;
use secmp_client_core::scheduler::params::{Mode, Params};
use secmp_client_core::scheduler::run::{Providers, Selected};
use secmp_client_core::scheduler::types::{Output, RelayId, Transport};
use secmp_client_core::timing::TimingRng;
use secmp_proto::wire::inv::{Direct, Host, RelayRef};
use secmp_testkit::harness::{HarnessConfig, MemRelay};
use secmp_transport::Error;
use secmp_transport::driver::{EitherStream, Isolation, StreamProvider};
use secmp_transport::tor::{IsolationToken, Status, TorBackend, TorProvider, TorState};
use tokio::io::DuplexStream;

use crate::m6_sched_bal::{NoCells, fresh_recv_cap};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A Tor backend that counts its connects and fails them (an unreachable onion service) or answers in memory.
#[derive(Clone, Default)]
struct Onion {
    connects: Arc<Mutex<Vec<(String, u16)>>>,
    fail: bool,
}

impl TorBackend for Onion {
    type Stream = DuplexStream;

    fn connect(
        &self,
        host: String,
        port: u16,
        _isolation: IsolationToken,
    ) -> impl core::future::Future<Output = Result<DuplexStream, Error>> + Send {
        self.connects.lock().unwrap().push((host, port));
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

/// The direct provider's stand-in: counts every connect (a real one would open a TCP socket at that point).
#[derive(Clone, Default)]
struct CountingDirect(Arc<AtomicUsize>);

impl StreamProvider for CountingDirect {
    type Stream = DuplexStream;

    fn connect(
        &self,
        _relay: &RelayRef,
        _isolation: Isolation,
    ) -> impl core::future::Future<Output = Result<DuplexStream, Error>> + Send {
        self.0.fetch_add(1, Ordering::SeqCst);
        core::future::ready(Ok(tokio::io::duplex(64).0))
    }
}

fn tor(backend: Onion, status: Option<Status>) -> TorProvider<Onion> {
    let state = Arc::new(TorState::new());
    if let Some(s) = status {
        let _ = state.observe(s);
    }
    TorProvider::with_backend(backend, state)
}

const READY: Status = Status {
    frac: 1.0,
    ready: true,
    blocked: false,
};

/// A relay with a direct endpoint (or without).
fn relay(direct: bool) -> RelayRef {
    let mut r = MemRelay::new(HarnessConfig::default()).relay_ref();
    if direct {
        r.direct = Some(Direct {
            host: Host::from_bytes(b"relay.example").unwrap(),
            port: core::num::NonZeroU16::new(443).unwrap(),
            spki_sha256: [7; 32],
        });
    }
    r
}

/// The transport the scheduler names for a link, with the user's direct-mode setting `direct`.
fn scheduler_transport(direct: bool) -> Transport {
    let mut sched = Scheduler::new(Params::default(), Mode::Balanced, TimingRng::seeded(9));
    sched.set_direct(0, direct, &mut NoCells).unwrap();
    sched
        .add_recv_queue(0, RelayId(0), fresh_recv_cap(9), 80_000)
        .unwrap();
    let now = sched.links().first().unwrap().starts_at.unwrap();
    sched
        .poll(now, &mut NoCells)
        .unwrap()
        .into_iter()
        .find_map(|o| match o {
            Output::Connect { transport, .. } => Some(transport),
            _ => None,
        })
        .unwrap()
}

/// TOR-05 `tor_never_falls_back_to_direct` (CLAUDE.md §1.5; §5.3): in Tor mode with a `RelayRef` that has a direct
/// endpoint, a failed bootstrap and a failed onion connect both surface `TorUnavailable` (before bootstrap:
/// `TorNotReady`); the direct provider is never called — no TCP socket is opened.
#[test]
fn tor_never_falls_back_to_direct() {
    runtime().block_on(async {
        let r = relay(true);
        assert_eq!(scheduler_transport(false), Transport::Tor);
        // bootstrap failed
        let direct = CountingDirect::default();
        let failed = tor(Onion::default(), None);
        failed.state().fail();
        let s = Selected::new(failed, direct.clone());
        let e = s.connect(Transport::Tor, &r, Isolation(1)).await.err();
        assert_eq!(e, Some(Error::TorUnavailable));
        // not bootstrapped yet
        let s = Selected::new(tor(Onion::default(), None), direct.clone());
        let e = s.connect(Transport::Tor, &r, Isolation(2)).await.err();
        assert_eq!(e, Some(Error::TorNotReady));
        // ready, but the onion service cannot be reached
        let unreachable = Onion {
            fail: true,
            ..Onion::default()
        };
        let s = Selected::new(tor(unreachable.clone(), Some(READY)), direct.clone());
        for i in 0..3 {
            let e = s.connect(Transport::Tor, &r, Isolation(3 + i)).await.err();
            assert_eq!(e, Some(Error::TorUnavailable));
        }
        assert_eq!(unreachable.connects.lock().unwrap().len(), 3);
        assert_eq!(
            direct.0.load(Ordering::SeqCst),
            0,
            "the direct provider was never called"
        );
    });
}

/// TOR-06 `transport_selection_follows_user_choice_only` (§5.3; §8.1): (direct setting, `RelayRef.direct`) = (off,
/// present) → Tor; (on, present) → TLS; (on, absent) → `NoDirectEndpoint` with no attempt over Tor either. The
/// scheduler names the transport from the setting alone.
#[test]
fn transport_selection_follows_user_choice_only() {
    runtime().block_on(async {
        for (setting, present, want) in [
            (false, true, "tor"),
            (true, true, "direct"),
            (true, false, "none"),
            (false, false, "tor"),
        ] {
            let onion = Onion::default();
            let direct = CountingDirect::default();
            let s = Selected::new(tor(onion.clone(), Some(READY)), direct.clone());
            let transport = scheduler_transport(setting);
            assert_eq!(transport == Transport::Direct, setting);
            let got = s.connect(transport, &relay(present), Isolation(1)).await;
            let label = match &got {
                Ok(EitherStream::Left(_)) => "tor",
                Ok(EitherStream::Right(_)) => "direct",
                Err(Error::NoDirectEndpoint) => "none",
                Err(_) => "other error",
            };
            assert_eq!(label, want, "setting {setting}, direct endpoint {present}");
            let (tor_calls, direct_calls) = (
                onion.connects.lock().unwrap().len(),
                direct.0.load(Ordering::SeqCst),
            );
            match want {
                "tor" => assert_eq!((tor_calls, direct_calls), (1, 0)),
                "direct" => assert_eq!((tor_calls, direct_calls), (0, 1)),
                _ => assert_eq!((tor_calls, direct_calls), (0, 0), "no attempt at all"),
            }
        }
    });
}
