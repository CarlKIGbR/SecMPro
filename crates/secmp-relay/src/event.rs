// SPDX-License-Identifier: AGPL-3.0-or-later
//! What the relay reports about itself (spec §9.7 item 2; OPEN-M5-08 A; `docs/05` principle 2 "can't, not won't").
//!
//! The events form a closed set — start-up, key load, the relay's own listener bound, a retried `accept` (M05 review
//! C-2), a configuration error, drain start and exit — and no variant has a field that could carry per-request data: no id, key, token, `sess_id`,
//! `cmd_seq`, `cell_id`, client address or timing. Per-request logging is therefore impossible, not merely off; the
//! connection, the executor and the stores emit nothing at all. `expect::RELAY_TRACE_ALLOW` (xtask) lists exactly
//! [`EVENT_NAMES`]; test RL-03 captures every event of a full scenario. Aggregate counters (§9.7 item 2, "only if
//! enabled") are not part of M5.

use std::io::Write as _;
use std::net::SocketAddr;

/// One event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// The process started (name and version only).
    Startup,
    /// The key file was loaded; how many key generations it holds.
    KeysLoaded {
        /// Generations held.
        generations: usize,
    },
    /// The relay's own listener is bound (its own loopback address).
    ListenerBound {
        /// The address the relay listens on.
        addr: &'a SocketAddr,
    },
    /// An `accept` failed with an error that does not end the listener (a connection's, a resource limit's); the
    /// loop waits and accepts on (M05 review C-2). No field: neither the error nor a peer.
    AcceptRetry,
    /// The start was refused: configuration or key file (the rule, never a value).
    ConfigError {
        /// Which rule.
        reason: &'static str,
    },
    /// Graceful drain began.
    DrainStarted,
    /// The process exits.
    Exit,
}

/// The names of every event, in declaration order (`expect::RELAY_TRACE_ALLOW`).
pub const EVENT_NAMES: [&str; 7] = [
    "startup",
    "keys_loaded",
    "listener_bound",
    "accept_retry",
    "config_error",
    "drain_started",
    "exit",
];

impl Event<'_> {
    /// The event's name, one of [`EVENT_NAMES`].
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::KeysLoaded { .. } => "keys_loaded",
            Self::ListenerBound { .. } => "listener_bound",
            Self::AcceptRetry => "accept_retry",
            Self::ConfigError { .. } => "config_error",
            Self::DrainStarted => "drain_started",
            Self::Exit => "exit",
        }
    }

    /// The one-line text of the event.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Startup => format!(
                "startup {} {}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            ),
            Self::KeysLoaded { generations } => format!("keys_loaded generations={generations}"),
            Self::ListenerBound { addr } => format!("listener_bound {addr}"),
            Self::AcceptRetry => "accept_retry".to_owned(),
            Self::ConfigError { reason } => format!("config_error {reason}"),
            Self::DrainStarted => "drain_started".to_owned(),
            Self::Exit => "exit".to_owned(),
        }
    }
}

/// Where events go.
pub trait EventSink: Send + Sync {
    /// Record one event.
    fn emit(&self, event: &Event<'_>);
}

/// Discards every event.
pub struct NullSink;

impl EventSink for NullSink {
    fn emit(&self, _: &Event<'_>) {}
}

/// Writes each event as one line to standard error (`docs/05` §4: start-up and shutdown notices only).
pub struct StderrSink;

impl EventSink for StderrSink {
    fn emit(&self, event: &Event<'_>) {
        // a closed stderr is not an error of the relay
        let _ = writeln!(std::io::stderr().lock(), "secmp-relay: {}", event.render());
    }
}

/// Keeps every rendered event (tests).
#[cfg(feature = "kat")]
#[derive(Default)]
pub struct CaptureSink(std::sync::Mutex<Vec<(&'static str, String)>>);

#[cfg(feature = "kat")]
impl CaptureSink {
    /// `(name, rendered line)` of every event so far.
    #[must_use]
    pub fn events(&self) -> Vec<(&'static str, String)> {
        self.0.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

#[cfg(feature = "kat")]
impl EventSink for CaptureSink {
    fn emit(&self, event: &Event<'_>) {
        if let Ok(mut v) = self.0.lock() {
            v.push((event.name(), event.render()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_lines() {
        let addr: SocketAddr = ([127, 0, 0, 1], 7443).into();
        let all = [
            Event::Startup,
            Event::KeysLoaded { generations: 2 },
            Event::ListenerBound { addr: &addr },
            Event::AcceptRetry,
            Event::ConfigError {
                reason: "unknown key",
            },
            Event::DrainStarted,
            Event::Exit,
        ];
        let names: Vec<&str> = all.iter().map(Event::name).collect();
        assert_eq!(names, EVENT_NAMES.to_vec());
        assert_eq!(
            Event::KeysLoaded { generations: 2 }.render(),
            "keys_loaded generations=2"
        );
        assert_eq!(
            Event::ListenerBound { addr: &addr }.render(),
            "listener_bound 127.0.0.1:7443"
        );
        assert_eq!(Event::AcceptRetry.render(), "accept_retry");
        assert!(Event::Startup.render().starts_with("startup secmp-relay "));
        NullSink.emit(&Event::Exit);
        StderrSink.emit(&Event::Exit);
    }
}
