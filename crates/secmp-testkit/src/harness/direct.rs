// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The relay process behind its direct TLS listener, on loopback (TEST-SPEC-M6 TLS-13, TLS-14; `docs/06` §4: the
//! loopback integration rows are the only tests with sockets): [`DirectRelay`] runs `secmp_relay::server::serve` with
//! the real clock and one thread per connection, exactly as the binary does with `direct_tls` set, over the
//! [`secmp_relay::tls::Listeners`] pair (an onion loopback listener nobody connects to, and the direct listener).
//! The relay's keys are the M5 harness's.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::num::NonZeroU16;
use std::sync::Arc;

use secmp_proto::link::ids::{AccessKey, akc};
use secmp_proto::wire::inv::{Direct, Host, Onion, RelayRef};
use secmp_relay::event::NullSink;
use secmp_relay::server::{self, Clock, Time as _};
use secmp_relay::tls::{self, Listeners};
use secmp_relay::{KeyRing, Limits, Relay};

use super::world::{KEY_VALIDITY_SECS, RelaySeeds};

/// A running relay with a direct TLS listener on `127.0.0.1` (see the module documentation). The serving thread
/// lives until the test process ends.
pub struct DirectRelay {
    relay: Arc<Relay>,
    addr: SocketAddr,
    pin: [u8; 32],
    access: AccessKey,
}

impl DirectRelay {
    /// Start a relay with `limits` whose direct listener presents `cert` (DER) with its PKCS#8 key `key` (DER),
    /// through `secmp_relay::tls::server_config` as the binary builds it.
    ///
    /// # Panics
    /// On a violated harness invariant (the configuration refused, no loopback port): a test failure.
    #[must_use]
    pub fn start(cert: &[u8], key: &[u8], limits: Limits) -> Self {
        let clock = Clock::start();
        let seeds = RelaySeeds::new();
        let now = clock.now();
        let ring = KeyRing::new(vec![(
            seeds.keys(),
            now.unix_secs.saturating_add(KEY_VALIDITY_SECS),
        )])
        .unwrap();
        let relay = Arc::new(Relay::new(ring, limits, Box::new(NullSink), now));
        let config = tls::server_config(cert.to_vec(), key.to_vec()).unwrap();
        let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let onion: TcpListener = server::bind(&relay, loopback).unwrap();
        let direct = tls::bind(&relay, loopback, config).unwrap();
        let addr = direct.local_addr().unwrap();
        let listeners = Listeners::new(onion, direct);
        let serving = Arc::clone(&relay);
        std::thread::spawn(move || {
            let _ = server::serve(&serving, &listeners, &clock, server::spawn_thread);
        });
        Self {
            relay,
            addr,
            pin: secmp_relay::spki::pin_of(cert).unwrap(),
            access: seeds.access(),
        }
    }

    /// The relay's wall-clock time in Unix seconds (`secmp_relay::clock`, its sanctioned wall-clock site): what a
    /// client of this relay passes as its handshake time.
    #[must_use]
    pub fn unix_now() -> u64 {
        secmp_relay::clock::wall_clock_unix_secs()
    }

    /// The direct listener's address.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The relay (its stores through the `kat` accessors).
    #[must_use]
    pub fn relay(&self) -> &Relay {
        &self.relay
    }

    /// The relay's access key.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn access_key(&self) -> AccessKey {
        secmp_crypto::SecretBytes::from_slice(self.access.expose_secret()).unwrap()
    }

    /// A `RelayRef` of this relay: its fingerprint, the `akc` of its access key, a fixed test onion (pk = 32 × 0x42),
    /// and the direct endpoint `127.0.0.1:<port>` pinned to the listener certificate's SPKI.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn relay_ref(&self) -> RelayRef {
        let pk = [0x42_u8; 32];
        let check = secmp_crypto::sha3_256(&[b".onion checksum", &pk, &[0x03]]);
        let onion = [&pk[..], check.get(..2).unwrap(), &[0x03]].concat();
        RelayRef {
            relay_fp: self.relay.keys().newest().unwrap().0.fp(),
            onion: Onion::from_bytes(&onion).unwrap(),
            akc: akc(&self.access),
            direct: Some(Direct {
                host: Host::from_bytes(b"127.0.0.1").unwrap(),
                port: NonZeroU16::new(self.addr.port()).unwrap(),
                spki_sha256: self.pin,
            }),
        }
    }
}
