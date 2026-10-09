// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! [`Harness`]: one relay and N clients over in-process streams, on a virtual clock and deterministic randomness
//! (spec §8–§9; `docs/07` M5). The scenario DSL of M6's `two-clients` is this surface: add clients, connect them
//! (each connection is a new SecMP-LINK handshake), create queues, move cells, advance the clock, restart the relay.
//!
//! Everything a scenario draws comes from per-actor streams (`harness-relay`, `harness-client-<k>`), the relay's
//! keys from the stream `harness-relay-keys`; nothing reads the OS or the wall clock.

use std::cell::RefCell;
use std::rc::Rc;

use secmp_crypto::{Ed25519SigningKey, MlKem1024Dk, SecretBytes, VectorStream, X25519Secret};
use secmp_proto::link::ids::AccessKey;
use secmp_proto::link::relay::RelayKeys;
use secmp_proto::tr::FixedEntropy;
use secmp_relay::event::NullSink;
use secmp_relay::{KeyRing, Limits, Now, Relay};
use secmp_transport::{Error, QueueTransport, RecvCap, RelayQueueTransport, SendCap};

use super::clock::Clock;
use super::entropy::EntropyPool;
use super::stream::{Capture, HarnessStream, Split};

/// Unix seconds at which every scenario starts (any fixed value; not a vector constant).
pub const START_UNIX: u64 = 1_760_000_000;

/// How a harness is set up.
#[derive(Clone, Copy, Debug)]
pub struct HarnessConfig {
    /// The relay's limits. The default is the OPEN-M5 defaults with the rate limits off (the scenario rate).
    pub limits: Limits,
    /// How every connection of the scenario is cut into pieces.
    pub split: Split,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        Self {
            limits: Limits {
                link_rate: None,
                hello_rate: None,
                ..Limits::defaults()
            },
            split: Split::Whole,
        }
    }
}

/// A client of the harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClientId(usize);

/// One client: its randomness and its current link.
pub struct Client {
    entropy: EntropyPool,
    transport: Option<RelayQueueTransport<HarnessStream>>,
    /// Every connection this client opened, oldest first (for the byte captures).
    streams: Vec<HarnessStream>,
}

impl Client {
    /// The client's randomness (deterministic).
    pub fn entropy(&mut self) -> &mut FixedEntropy {
        self.entropy.get()
    }

    /// `n` bytes the scenario chooses for this client (a seed, an id), from its stream.
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        self.entropy.bytes(n)
    }

    /// A 32-byte secret from the client's stream (a queue key seed).
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn seed(&mut self) -> SecretBytes<32> {
        SecretBytes::from_slice(&self.entropy.bytes(32)).unwrap()
    }

    /// The client's link and its randomness at once.
    ///
    /// # Errors
    /// [`Error::Closed`] if the client is not connected.
    pub fn link(
        &mut self,
    ) -> Result<(&mut RelayQueueTransport<HarnessStream>, &mut FixedEntropy), Error> {
        let transport = self.transport.as_mut().ok_or(Error::Closed)?;
        Ok((transport, self.entropy.get()))
    }

    /// The client's current link.
    ///
    /// # Errors
    /// [`Error::Closed`] if the client is not connected.
    pub fn transport(&mut self) -> Result<&mut RelayQueueTransport<HarnessStream>, Error> {
        self.transport.as_mut().ok_or(Error::Closed)
    }

    /// The captures of every connection the client opened, oldest first.
    #[must_use]
    pub fn captures(&self) -> Vec<Capture> {
        self.streams.iter().map(HarnessStream::capture).collect()
    }

    /// The streams of every connection the client opened, oldest first.
    #[must_use]
    pub fn streams(&self) -> &[HarnessStream] {
        &self.streams
    }
}

/// The relay's key material of a scenario: fixed seeds, so a restarted relay is the same relay (spec §8.2).
struct RelaySeeds {
    sig: Vec<u8>,
    dh: Vec<u8>,
    kem: Vec<u8>,
    access: Vec<u8>,
}

impl RelaySeeds {
    fn new() -> Self {
        let mut s = VectorStream::new("harness-relay-keys", 0);
        Self {
            sig: s.take(32),
            dh: s.take(32),
            kem: s.take(64),
            access: s.take(32),
        }
    }

    fn keys(&self) -> RelayKeys {
        RelayKeys::new(
            Ed25519SigningKey::from_seed(&self.sig).unwrap(),
            X25519Secret::from_bytes(&self.dh).unwrap(),
            MlKem1024Dk::from_seed(&self.kem).unwrap(),
            SecretBytes::from_slice(&self.access).unwrap(),
            1,
        )
        .unwrap()
    }
}

/// The relay's `valid_until` offset from the scenario start: the longest a `RELAYINFO` may announce (60 days).
const KEY_VALIDITY_SECS: u64 = 5_184_000;

/// One relay and N clients (see the module documentation).
pub struct Harness {
    config: HarnessConfig,
    clock: Clock,
    seeds: RelaySeeds,
    // The relay is leaked: a `Connection` borrows it for its whole life and the streams outlive any scope a
    // scenario could name. Test code, bounded (one relay per `new` / `restart_relay`).
    relay: &'static Relay,
    relay_entropy: Rc<RefCell<EntropyPool>>,
    clients: Vec<Client>,
    generation: u32,
}

impl Harness {
    /// A relay and no clients.
    #[must_use]
    pub fn new(config: HarnessConfig) -> Self {
        let clock = Clock::new(START_UNIX);
        let seeds = RelaySeeds::new();
        let relay = Self::start_relay(&seeds, &config, clock.now());
        Self {
            config,
            clock,
            seeds,
            relay,
            relay_entropy: Rc::new(RefCell::new(EntropyPool::new("harness-relay", 0))),
            clients: Vec::new(),
            generation: 0,
        }
    }

    fn start_relay(seeds: &RelaySeeds, config: &HarnessConfig, now: Now) -> &'static Relay {
        let ring = KeyRing::new(vec![(
            seeds.keys(),
            now.unix_secs.saturating_add(KEY_VALIDITY_SECS),
        )])
        .unwrap();
        Box::leak(Box::new(Relay::new(
            ring,
            config.limits,
            Box::new(NullSink),
            now,
        )))
    }

    /// The virtual clock (a handle: it reads and moves the scenario's time).
    #[must_use]
    pub fn clock(&self) -> Clock {
        self.clock.clone()
    }

    /// A new connection to the relay (the relay's accept; `None` while it drains). The scheduler driver opens its
    /// connections here.
    pub fn open_stream(&mut self) -> Option<HarnessStream> {
        HarnessStream::open(
            self.relay,
            &self.clock,
            &self.relay_entropy,
            self.config.split,
        )
    }

    /// The relay (its stores and limits through the `kat` accessors).
    #[must_use]
    pub const fn relay(&self) -> &'static Relay {
        self.relay
    }

    /// The relay's pinned fingerprint (what an invitation's `RelayRef` carries, spec §5.3).
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn relay_fp(&self) -> [u8; 32] {
        self.relay.keys().newest().unwrap().0.fp()
    }

    /// The relay's access key (the token credential of `QUEUE_NEW` and `LINK_PUT`, spec §9.6).
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    #[must_use]
    pub fn access_key(&self) -> AccessKey {
        SecretBytes::from_slice(&self.seeds.access).unwrap()
    }

    /// Add a client; it is not connected yet.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn add_client(&mut self) -> ClientId {
        let k = u32::try_from(self.clients.len()).unwrap();
        self.clients.push(Client {
            entropy: EntropyPool::new("harness-client", k),
            transport: None,
            streams: Vec::new(),
        });
        ClientId(usize::try_from(k).unwrap())
    }

    /// The client.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn client(&mut self, id: ClientId) -> &mut Client {
        self.clients.get_mut(id.0).unwrap()
    }

    /// Open a new connection for the client and run the SecMP-LINK handshake on it (spec §8.2–§8.3: the
    /// `RELAYINFO` of this link is used for this link only). The client's previous link, if any, is dropped.
    ///
    /// # Errors
    /// [`Error::Closed`] if the relay refuses the connection (it drains); the handshake's errors otherwise.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn connect(&mut self, id: ClientId) -> Result<(), Error> {
        let stream = HarnessStream::open(
            self.relay,
            &self.clock,
            &self.relay_entropy,
            self.config.split,
        )
        .ok_or(Error::Closed)?;
        let access = self.access_key();
        let pinned = self.relay_fp();
        let now = self.clock.unix();
        let client = self.clients.get_mut(id.0).unwrap();
        client.transport = None;
        client.streams.push(stream.clone());
        client.transport = Some(RelayQueueTransport::connect(
            stream,
            pinned,
            Some(&access),
            now,
            client.entropy.get(),
        )?);
        Ok(())
    }

    /// Create `n` queues for the client: fresh recipient and sender keys from its stream, `QUEUE_NEW` for each.
    ///
    /// # Errors
    /// The error of the first `create_queue` that fails.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn create_queues(
        &mut self,
        id: ClientId,
        n: usize,
    ) -> Result<Vec<(RecvCap, SendCap)>, Error> {
        let token = self.access_key();
        let client = self.clients.get_mut(id.0).unwrap();
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let (recv, send) = (client.seed(), client.seed());
            out.push(client.transport()?.create_queue(&recv, &send, &token)?);
        }
        Ok(out)
    }

    /// Move the clock forward and let the relay's sweeper run.
    pub fn advance_secs(&mut self, secs: u64) {
        self.clock.advance_secs(secs);
        self.relay.tick(self.clock.now());
    }

    /// Move the clock forward by hours and let the relay's sweeper run.
    pub fn advance_hours(&mut self, hours: u64) {
        self.advance_secs(hours.saturating_mul(3600));
    }

    /// Restart the relay (spec §9.7 item 1): the same keys, no state; every connection is cut, so each client's next
    /// call is [`Error::Closed`] until it connects again.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure, never a production path.
    pub fn restart_relay(&mut self) {
        for client in &self.clients {
            for stream in &client.streams {
                stream.cut();
            }
        }
        self.generation = self.generation.checked_add(1).unwrap();
        self.relay = Self::start_relay(&self.seeds, &self.config, self.clock.now());
    }

    /// How often the relay was restarted.
    #[must_use]
    pub const fn restarts(&self) -> u32 {
        self.generation
    }

    /// Start the relay's drain (OPEN-M5-09).
    pub fn start_drain(&self) {
        self.relay.start_drain(self.clock.now());
    }
}
