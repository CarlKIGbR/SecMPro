// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Arti glue of the Tor provider: the calls that need a live Tor network — creating the client, bootstrapping it,
//! following its bootstrap status, and the onion connect (spec §12.3; ADR-007, ADR-024). Nothing here decides
//! anything: the rules (profile directories, one isolation token per connection, no link before ready, no fallback,
//! the address and the port) are in the parent module and its tests. This file is kept out of the mutation gate
//! (`expect::MUTANT_EXCLUDE_FILES`, `docs/mutants-accepted.md` §Excluded: it can only be exercised against the Tor
//! network, which no test may reach, `docs/06` §4); the owner-operated rows TOR-10 and X-10 run it.
//!
//! The client's runtime type (Arti's `PreferredRuntime`) is not nameable without a dependency on `tor-rtcompat`, so
//! the client is held only inside the closures and tasks created here.

use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use std::path::Path;
use std::sync::Arc;

use arti_client::{BootstrapBehavior, DataStream, IsolationToken, StreamPrefs, TorClient};
use tokio::sync::mpsc::UnboundedSender;

use super::{Status, TorBackend, TorEvent, TorProvider, TorState};
use crate::error::{Error, Result};

/// How often the follower reads Arti's bootstrap status.
const STATUS_POLL: Duration = Duration::from_millis(250);

/// One onion connect.
type Connecting = Pin<Box<dyn Future<Output = Result<DataStream>> + Send>>;

/// The onion connect of a running Arti client.
type Connect = Box<dyn Fn(String, u16, IsolationToken) -> Connecting + Send + Sync>;

/// The [`TorBackend`] of a shipped build: Arti's `connect_with_prefs` with the connection's own isolation token.
pub struct ArtiBackend {
    connect: Connect,
}

impl TorBackend for ArtiBackend {
    type Stream = DataStream;

    fn connect(
        &self,
        host: String,
        port: u16,
        isolation: IsolationToken,
    ) -> impl Future<Output = Result<DataStream>> + Send {
        (self.connect)(host, port, isolation)
    }
}

/// Start Arti for the profile at `profile` on the current tokio runtime: create the client without bootstrapping it,
/// start the bootstrap and a follower that turns Arti's status into [`TorEvent`]s on `events`. The provider admits
/// links once Arti is ready for traffic.
///
/// # Errors
/// [`Error::Invalid`] if the configuration is refused, [`Error::TorUnavailable`] if Arti cannot be created (its
/// directories fail the `fs-mistrust` check, for example).
pub fn start(
    profile: &Path,
    events: UnboundedSender<TorEvent>,
) -> Result<TorProvider<ArtiBackend>> {
    let config = super::config(profile)?;
    let client = TorClient::builder()
        .config(config)
        .bootstrap_behavior(BootstrapBehavior::Manual)
        .create_unbootstrapped()
        .map_err(|_| Error::TorUnavailable)?;
    let state = Arc::new(TorState::new());
    {
        let client = Arc::clone(&client);
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if client.bootstrap().await.is_err() {
                state.fail();
            }
        });
    }
    {
        let client = Arc::clone(&client);
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let s = client.bootstrap_status();
                let status = Status {
                    frac: s.as_frac(),
                    ready: s.ready_for_traffic(),
                    blocked: s.blocked().is_some(),
                };
                if let Some(event) = state.observe(status)
                    && events.send(event).is_err()
                {
                    break;
                }
                tokio::time::sleep(STATUS_POLL).await;
            }
        });
    }
    let connect: Connect = Box::new(move |host, port, isolation| {
        let client = Arc::clone(&client);
        Box::pin(async move {
            let mut prefs = StreamPrefs::new();
            prefs.set_isolation(isolation);
            client
                .connect_with_prefs((host.as_str(), port), &prefs)
                .await
                .map_err(|_| Error::TorUnavailable)
        })
    });
    Ok(TorProvider::with_backend(ArtiBackend { connect }, state))
}
