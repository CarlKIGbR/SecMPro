// SPDX-License-Identifier: AGPL-3.0-or-later
//! `transport::tor` — the Tor stream provider (spec §8.1, §12.3; ADR-007, ADR-024, ADR-051 Part 2; CS-3.6; TEST-SPEC-M6
//! TOR-01…TOR-09, FZ-03).
//!
//! **What it is.** A [`StreamProvider`] that opens a stream to the relay's onion service (`RelayRef.onion`, spec §5.3)
//! on port [`ONION_PORT`] through Arti; the SecMP-LINK handshake and frames run inside unchanged (the PQ link layer
//! runs inside Tor's classical circuits, CLAUDE.md §1.3).
//!
//! **Rules it keeps.**
//! - **Profile directories** ([`config`]): Arti's state and cache live under the profile (`<profile>/tor/state`,
//!   `<profile>/tor/cache`, CS-3.6), never in Arti's default user directories; `fs-mistrust` stays on and ignores the
//!   environment variable that would switch it off.
//! - **One circuit per connection** (§8.1): every [`StreamProvider::connect`] takes a fresh `IsolationToken` — per link
//!   and per reconnect, never cached per relay, never reused.
//! - **No link before bootstrap** (§12.3, CLAUDE.md §1.5): until Arti reports ready for traffic, a connect is
//!   [`Error::TorNotReady`] without opening a stream; after a bootstrap failure, or when the onion connection fails, it
//!   is [`Error::TorUnavailable`]. This provider never falls back to anything: the direct provider is a separate
//!   provider that only the user's explicit choice selects (`secmp_client_core::scheduler::run::Selected`).
//! - **Bootstrap events** ([`TorState::observe`]): Arti's bootstrap status becomes [`TorEvent`]s for the user
//!   interface — progress in percent, ready, blocked — each change once.
//! - **The address** ([`onion_host`]): `RelayRef.onion` is the decoded v3 address (`PUBKEY ‖ CHECKSUM ‖ VERSION`,
//!   rend-spec-v3 §6, validated by `secmp_proto::wire::inv::Onion`); the host name is its base32 (RFC 4648, lowercase,
//!   no padding) plus `.onion`. No DNS name ever reaches Arti.
//!
//! The Arti calls that need a live Tor network (client creation, bootstrap, the onion connect) are in [`arti`]; this
//! module is the testable rest, generic over [`TorBackend`].

pub mod arti;

use core::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub use arti_client::IsolationToken;
use arti_client::config::TorClientConfigBuilder;
use secmp_proto::wire::inv::{Onion, RelayRef};

use crate::driver::{Isolation, ProviderStream, StreamProvider};
use crate::error::{Error, Result};

/// The onion service's virtual port (`docs/05` §2 `HiddenServicePort 443`; OPEN-M6-07 A).
pub const ONION_PORT: u16 = 443;

/// The RFC 4648 base32 alphabet, lowercase (Tor writes onion addresses in lowercase).
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// RFC 4648 base32 of `bytes`, lowercase, without padding.
fn base32(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut acc: u16 = 0;
    let mut bits: u8 = 0;
    for &b in bytes {
        acc = (acc << 8) | u16::from(b);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            let i = usize::from((acc >> bits) & 0x1f);
            out.push(char::from(BASE32.get(i).copied().unwrap_or(b'a')));
        }
        acc &= (1_u16 << bits).wrapping_sub(1);
    }
    if bits > 0 {
        let i = usize::from((acc << (5_u8.saturating_sub(bits))) & 0x1f);
        out.push(char::from(BASE32.get(i).copied().unwrap_or(b'a')));
    }
    out
}

/// The onion host name of `onion`: 56 base32 characters of the 35 bytes, then `.onion` (rend-spec-v3 §6).
#[must_use]
pub fn onion_host(onion: &Onion) -> String {
    let mut host = base32(onion.as_bytes());
    host.push_str(".onion");
    host
}

/// The stream target of `onion`: its host name and [`ONION_PORT`], checked with Arti's own address parser to be a host
/// name (Arti's onion form) and not an IP address (TEST-SPEC-M6 TOR-08, TOR-09, FZ-03).
///
/// # Errors
/// [`Error::Invalid`] if Arti does not take it as a host name (never for a decoded `Onion`).
pub fn target(onion: &Onion) -> Result<(String, u16)> {
    let host = onion_host(onion);
    let addr =
        arti_client::TorAddr::from((host.as_str(), ONION_PORT)).map_err(|_| Error::Invalid)?;
    if addr.is_ip_address() {
        return Err(Error::Invalid);
    }
    Ok((host, ONION_PORT))
}

/// What the user interface hears from Tor's bootstrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TorEvent {
    /// Bootstrapping, at this percentage (0…100).
    Progress(u8),
    /// Ready for traffic: links may be opened.
    Ready,
    /// Arti reports that bootstrap cannot make progress.
    Blocked,
}

/// The part of Arti's `BootstrapStatus` the provider reads (`as_frac`, `ready_for_traffic`, `blocked().is_some()`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Status {
    /// How far bootstrap is, 0.0…1.0.
    pub frac: f32,
    /// Ready for traffic.
    pub ready: bool,
    /// Stuck.
    pub blocked: bool,
}

/// `frac` (0.0…1.0) in whole percent, rounded down; out of range and NaN clamp to 0 and 100.
#[must_use]
pub fn percent(frac: f32) -> u8 {
    let scaled = frac * 100.0;
    (0_u8..=100)
        .take_while(|p| f32::from(*p) <= scaled)
        .last()
        .unwrap_or(0)
}

/// The event a status stands for: blocked before ready before progress.
fn event_of(s: Status) -> TorEvent {
    if s.blocked {
        TorEvent::Blocked
    } else if s.ready {
        TorEvent::Ready
    } else {
        TorEvent::Progress(percent(s.frac))
    }
}

/// Where bootstrap stands, as the provider sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Not (or no longer) ready for traffic.
    Waiting,
    /// Ready for traffic.
    Ready,
    /// Bootstrap failed.
    Failed,
}

#[derive(Debug)]
struct Inner {
    phase: Phase,
    last: Option<TorEvent>,
}

/// The bootstrap state shared by the provider and the task that follows Arti's status ([`arti`]).
#[derive(Debug)]
pub struct TorState(Mutex<Inner>);

impl Default for TorState {
    fn default() -> Self {
        Self(Mutex::new(Inner {
            phase: Phase::Waiting,
            last: None,
        }))
    }
}

impl TorState {
    /// A state before any status: not ready.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        // a poisoned lock means a panicking thread held it: treat Tor as unavailable from then on
        match self.0.lock() {
            Ok(mut g) => f(&mut g),
            Err(p) => {
                let mut g = p.into_inner();
                g.phase = Phase::Failed;
                f(&mut g)
            }
        }
    }

    /// Take Arti's latest status: links are allowed exactly while it is ready for traffic and not blocked. The event
    /// it stands for, if it differs from the last one reported (each change once).
    pub fn observe(&self, status: Status) -> Option<TorEvent> {
        let event = event_of(status);
        self.with(|g| {
            if g.phase != Phase::Failed {
                g.phase = if event == TorEvent::Ready {
                    Phase::Ready
                } else {
                    Phase::Waiting
                };
            }
            if g.last == Some(event) {
                None
            } else {
                g.last = Some(event);
                Some(event)
            }
        })
    }

    /// Bootstrap failed: every later connect is [`Error::TorUnavailable`].
    pub fn fail(&self) {
        self.with(|g| g.phase = Phase::Failed);
    }

    /// Whether a link may be opened now: `Ok`, or the error a connect reports.
    ///
    /// # Errors
    /// [`Error::TorNotReady`] before Arti is ready for traffic, [`Error::TorUnavailable`] after a bootstrap failure.
    pub fn admit(&self) -> Result<()> {
        match self.with(|g| g.phase) {
            Phase::Ready => Ok(()),
            Phase::Waiting => Err(Error::TorNotReady),
            Phase::Failed => Err(Error::TorUnavailable),
        }
    }
}

/// The Arti side of the provider: one isolated stream to `host:port` (an onion host, [`ONION_PORT`]).
pub trait TorBackend: Send + Sync + 'static {
    /// The stream.
    type Stream: ProviderStream;

    /// Open a stream to `host:port` on a circuit of its own (`isolation`).
    ///
    /// # Errors
    /// Any failure (the provider reports it as [`Error::TorUnavailable`]).
    fn connect(
        &self,
        host: String,
        port: u16,
        isolation: IsolationToken,
    ) -> impl Future<Output = Result<Self::Stream>> + Send;
}

/// The Tor stream provider (see the module documentation).
pub struct TorProvider<B> {
    backend: B,
    state: Arc<TorState>,
}

impl<B: TorBackend> TorProvider<B> {
    /// A provider over `backend` whose bootstrap is followed in `state`.
    pub const fn with_backend(backend: B, state: Arc<TorState>) -> Self {
        Self { backend, state }
    }

    /// The bootstrap state.
    #[must_use]
    pub const fn state(&self) -> &Arc<TorState> {
        &self.state
    }
}

impl<B: TorBackend> StreamProvider for TorProvider<B> {
    type Stream = B::Stream;

    fn connect(
        &self,
        relay: &RelayRef,
        _isolation: Isolation,
    ) -> impl Future<Output = Result<Self::Stream>> + Send {
        let admitted = self.state.admit();
        let target = target(&relay.onion);
        // a fresh token for every connection (per link and per reconnect): its own circuit (spec §8.1)
        let token = IsolationToken::new();
        async move {
            admitted?;
            let (host, port) = target?;
            self.backend
                .connect(host, port, token)
                .await
                .map_err(|_| Error::TorUnavailable)
        }
    }
}

/// The Arti configuration of a profile: state in `<profile>/tor/state`, cache in `<profile>/tor/cache`, `fs-mistrust`
/// on and deaf to `ARTI_FS_DISABLE_PERMISSION_CHECKS` (CS-3.6; TEST-SPEC-M6 TOR-01).
///
/// # Errors
/// [`Error::Invalid`] if Arti refuses the configuration.
pub fn config(profile: &Path) -> Result<arti_client::TorClientConfig> {
    let tor = profile.join("tor");
    let mut builder =
        TorClientConfigBuilder::from_directories(tor.join("state"), tor.join("cache"));
    builder.storage().permissions().ignore_environment();
    builder.build().map_err(|_| Error::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_follows_rfc4648() {
        // RFC 4648 §10, lowercase, no padding
        for (input, expected) in [
            ("", ""),
            ("f", "my"),
            ("fo", "mzxq"),
            ("foo", "mzxw6"),
            ("foob", "mzxw6yq"),
            ("fooba", "mzxw6ytb"),
            ("foobar", "mzxw6ytboi"),
        ] {
            assert_eq!(base32(input.as_bytes()), expected, "{input:?}");
        }
        assert_eq!(base32(&[0xff; 35]).len(), 56);
    }

    #[test]
    fn percent_rounds_down_and_clamps() {
        assert_eq!(percent(0.0), 0);
        assert_eq!(percent(0.5), 50);
        assert_eq!(percent(0.999), 99);
        assert_eq!(percent(1.0), 100);
        assert_eq!(percent(7.0), 100);
        assert_eq!(percent(-1.0), 0);
        assert_eq!(percent(f32::NAN), 0);
    }

    #[test]
    fn a_failed_bootstrap_stays_failed() {
        let s = TorState::new();
        s.fail();
        let ready = Status {
            frac: 1.0,
            ready: true,
            blocked: false,
        };
        assert_eq!(s.observe(ready), Some(TorEvent::Ready));
        assert_eq!(s.admit(), Err(Error::TorUnavailable));
    }
}
