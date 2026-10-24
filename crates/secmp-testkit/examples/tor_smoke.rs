// SPDX-License-Identifier: AGPL-3.0-or-later
//! `tor_smoke` — the owner-operated Tor check (TEST-SPEC-M6 TOR-10, X-10; OPEN-M6-20): Arti bootstraps in a fresh
//! profile directory through the shipped provider (`secmp_transport::tor::arti::start`), then one link to the test
//! relay's onion service runs HELLO…HS2 and a `PING`. It prints the bootstrap events, `READY`, `PING OK` (or the
//! failure) and the Unix time; nothing secret is printed (the relay reference and the access key are the operator's
//! inputs). It needs the Tor network: no test runs it.
//!
//! ```text
//! cargo run --locked -p secmp-testkit --features harness --example tor_smoke -- <profile-dir> [<relay-ref-hex> [<access-key-hex>]]
//! ```
//!
//! **Without a relay** (`<profile-dir>` only) it measures the cost of a cold bootstrap (TEST-SPEC-M6 MR-07, ADR-051:
//! `compression` off) and prints one machine-readable last line, `MR07 bootstrap_seconds=<s> bytes_down=<n>`: the seconds
//! from the start of Arti to `Ready`, and the bytes received on the host's network interfaces other than loopback over
//! the same time (Linux `/proc/net/dev`; `n/a` elsewhere — other traffic of the host is included, so the dispatch job runs
//! it on an otherwise idle runner). The dispatch job `tor-smoke` runs this form.
//!
//! `<relay-ref-hex>` is the relay's `RelayRef` encoding (spec §5.3, D.3) in hex; `<access-key-hex>` the relay's
//! 32-byte access key, if the relay requires one (spec §8.2).
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use secmp_client_core::clock::{Clock as _, SystemClock};
use secmp_crypto::SecretBytes;
use secmp_proto::Decode as _;
use secmp_proto::tr::OsEntropy;
use secmp_proto::wire::inv::RelayRef;
use secmp_transport::driver::{AsyncRelayQueueTransport, Isolation, StreamProvider as _};
use secmp_transport::tor::{self, TorEvent};

/// How long the smoke test waits for Arti to be ready.
const BOOTSTRAP_LIMIT: Duration = Duration::from_secs(600);

fn say(line: &str) {
    let _ = writeln!(std::io::stdout().lock(), "{line}");
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| {
        char::from(c)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| match p {
            [hi, lo] => Some((digit(*hi)? << 4) | digit(*lo)?),
            _ => None,
        })
        .collect()
}

/// Bytes received on the interfaces other than `lo` (Linux `/proc/net/dev`).
fn rx_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/net/dev").ok()?;
    let mut total = 0_u64;
    for line in text.lines().skip(2) {
        let (name, rest) = line.split_once(':')?;
        if name.trim() == "lo" {
            continue;
        }
        total = total.saturating_add(rest.split_whitespace().next()?.parse::<u64>().ok()?);
    }
    Some(total)
}

async fn smoke(
    profile: PathBuf,
    relay: Option<RelayRef>,
    access: Option<SecretBytes<32>>,
) -> Result<(), String> {
    let clock = SystemClock::new();
    let (started_ms, started_rx) = (clock.mono_ms(), rx_bytes());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let provider = tor::arti::start(&profile, tx).map_err(|e| format!("Arti start: {e}"))?;
    let ready = tokio::time::timeout(BOOTSTRAP_LIMIT, async {
        while let Some(event) = rx.recv().await {
            say(&format!("tor-event {event:?}"));
            if event == TorEvent::Ready {
                return true;
            }
        }
        false
    })
    .await;
    if ready != Ok(true) {
        return Err(format!(
            "bootstrap: no Ready within {} s",
            BOOTSTRAP_LIMIT.as_secs()
        ));
    }
    say(&format!("READY unix={}", clock.unix_secs()));
    let millis = clock.mono_ms().saturating_sub(started_ms);
    let seconds = format!("{}.{}", millis / 1000, millis % 1000 / 100);
    let bytes = match (started_rx, rx_bytes()) {
        (Some(a), Some(b)) => b.saturating_sub(a).to_string(),
        _ => "n/a".to_owned(),
    };
    let Some(relay) = relay else {
        say(&format!(
            "MR07 bootstrap_seconds={seconds} bytes_down={bytes}"
        ));
        return Ok(());
    };
    let stream = provider
        .connect(&relay, Isolation(1))
        .await
        .map_err(|e| format!("onion connect: {e}"))?;
    let mut entropy = OsEntropy;
    let mut t = AsyncRelayQueueTransport::connect(
        stream,
        relay.relay_fp,
        access.as_ref(),
        clock.unix_secs(),
        &mut entropy,
    )
    .await
    .map_err(|e| format!("handshake: {e}"))?;
    t.ping().await.map_err(|e| format!("ping: {e}"))?;
    say(&format!("PING OK unix={}", clock.unix_secs()));
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(profile) = args.first() else {
        say("usage: tor_smoke <profile-dir> [<relay-ref-hex> [<access-key-hex>]]");
        return ExitCode::from(2);
    };
    let relay = match args.get(1) {
        None => None,
        Some(hex) => {
            let Some(relay) = unhex(hex).and_then(|b| RelayRef::decode(&b).ok()) else {
                say("FAIL the second argument is not a hex RelayRef encoding (spec §5.3)");
                return ExitCode::from(2);
            };
            Some(relay)
        }
    };
    let access = args
        .get(2)
        .map(|k| unhex(k).and_then(|b| SecretBytes::<32>::from_slice(&b).ok()));
    if access.as_ref().is_some_and(Option::is_none) {
        say("FAIL the third argument is not a 32-byte hex access key");
        return ExitCode::from(2);
    }
    let access = access.flatten();
    say(&format!(
        "tor-smoke start unix={}",
        SystemClock::new().unix_secs()
    ));
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        say("FAIL no tokio runtime");
        return ExitCode::FAILURE;
    };
    match runtime.block_on(smoke(PathBuf::from(profile), relay, access)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            say(&format!("FAIL {why}"));
            ExitCode::FAILURE
        }
    }
}
