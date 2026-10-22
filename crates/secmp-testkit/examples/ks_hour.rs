// SPDX-License-Identifier: AGPL-3.0-or-later
//! `ks_hour` — the real-time activity-independence run (TEST-SPEC-M6 AI-07, loopback part; `docs/07:125` "real hardware").
//!
//! Two contacts (two pairs of clients) run the engine of `two-clients` in real time against a relay on loopback behind its
//! direct TLS listener (`DirectRelay`): Balanced (direct mode implies Balanced, spec §10.2), `T_BALANCED` = 10 s, the first hour idle, the second hour active (one message every
//! 30 s per client and 10 bursts of 20). The inter-departure times of the C2R frames of every scheduled link, idle hour
//! against active hour, go through the two-sample KS test of [`secmp_testkit::ks`]: `p ≥ 0.01` per link and pooled, every
//! unit of a scheduled link 4 352 B. `D`, `p`, `n` and the SHA-256 of the frames analysed are written to
//! `<out-dir>/ks-hour.txt` (the dispatch job `ks-hour` uploads the directory) and printed; the exit status is 1 on a
//! failed criterion.
//!
//! ```text
//! cargo run --locked --release -p secmp-testkit --features harness --example ks_hour -- <out-dir> [<idle-s> [<active-s>]]
//! ```
//!
//! `idle-s` and `active-s` default to 3 600; shorter values are a smoke run (the criterion needs the hour's `n`).
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use secmp_client_core::clock::{Clock as _, SystemClock, TokioClock};
use secmp_client_core::scheduler::conversation::OsSource;
use secmp_client_core::scheduler::params::Mode;
use secmp_testkit::harness::cert::{FixtureKey, VALID, self_signed};
use secmp_testkit::harness::{Dir, DirectRelay, RelayLimits};
use secmp_testkit::ks::{self, Frame};
use secmp_testkit::two_clients::cli::{Cli, Role, Script, TransportArg};
use secmp_testkit::two_clients::run::{Observer, World, WorldConfig, session};

/// The common split of the time axis.
const SPLIT: u64 = 10_000_000;

/// The frames of a pair, as `(t, slot, len)` of the C2R units, and the time of its first message.
struct Pair {
    frames: Vec<Frame>,
    first_message_ms: u64,
}

fn say(out: &mut String, line: &str) {
    let _ = writeln!(std::io::stdout().lock(), "{line}");
    out.push_str(line);
    out.push('\n');
}

async fn run_pair(
    relay: Arc<DirectRelay>,
    index: u64,
    idle_s: u64,
    active_s: u64,
) -> Result<Pair, String> {
    let unix = SystemClock::new().unix_secs();
    let clock = TokioClock::new(unix);
    let observer = Observer::new();
    let world = World::new(
        secmp_transport::tls::TlsProvider::new(),
        WorldConfig {
            relay: relay.relay_ref(),
            access: relay.access_key(),
            clock,
            unix_base: unix,
            mode: Mode::Balanced,
            direct: true,
            connect_timeout_ms: None,
        },
        Some(Arc::clone(&observer)),
    );
    let bursts = if active_s >= 3_600 { 10_u64 } else { 0 };
    let steady = active_s / 30;
    let script = Script {
        messages: steady.saturating_add(bursts.saturating_mul(20)),
        size_min: 1,
        size_max: 1_000,
        seed: 1_000_u64.saturating_add(index),
        interval_s: 30,
        start_s: idle_s,
        bursts,
        burst_size: 20,
    };
    let cli = Cli {
        role: Role::Both,
        mode: Mode::Balanced,
        transport: TransportArg::Tls,
        relay_ref: None,
        invite_out: None,
        invite_in: None,
        script: None,
        // from the start of the clients: the handshake (a few minutes), the idle hour, the active hour
        duration_s: Some(idle_s.saturating_add(active_s).saturating_add(900)),
        trace_out: None,
        tor_dir: None,
    };
    let mut text = Vec::new();
    Box::pin(session::<_, OsSource>(&cli, world, &script, &mut text))
        .await
        .map_err(|e| format!("pair {index}: {e:?}"))?;
    let recorder = observer.recorder().ok_or("no recorder")?;
    let first_message_ms = recorder
        .events()
        .iter()
        .filter(|e| e.event == "enqueue")
        .map(|e| e.t_ms)
        .min()
        .ok_or("no message was queued")?;
    let frames = recorder
        .units()
        .iter()
        .filter(|u| u.dir == Dir::C2R)
        .map(|u| (u.t_ms, u.slot, u.len))
        .collect();
    Ok(Pair {
        frames,
        first_message_ms,
    })
}

async fn run(out_dir: PathBuf, idle_s: u64, active_s: u64) -> Result<bool, String> {
    let key = FixtureKey::new([7; 32]);
    let cert = self_signed(&key, "relay.test", VALID);
    let relay = Arc::new(DirectRelay::start(
        &cert,
        &key.pkcs8(),
        RelayLimits::defaults(),
    ));
    let (a, b) = tokio::join!(
        run_pair(Arc::clone(&relay), 0, idle_s, active_s),
        run_pair(Arc::clone(&relay), 1, idle_s, active_s)
    );
    let pairs = [a?, b?];
    // both pairs on one time axis: the first message of each at the common split
    let mut frames: Vec<Frame> = Vec::new();
    let mut shown = String::new();
    say(
        &mut shown,
        &format!(
            "ks-hour: idle {idle_s} s, active {active_s} s, P = 10 s, 2 contacts, loopback TLS (direct mode: the effective mode is Balanced, spec §10.2; frames of one slot are one departure)"
        ),
    );
    for (i, pair) in pairs.iter().enumerate() {
        let slot_base = u64::try_from(i)
            .map_err(|e| e.to_string())?
            .saturating_mul(1_000);
        let end = pair
            .first_message_ms
            .saturating_add(active_s.saturating_mul(1000));
        for (t, slot, len) in &pair.frames {
            if *t <= end {
                let moved = t
                    .saturating_add(SPLIT)
                    .saturating_sub(pair.first_message_ms);
                frames.push((moved, slot.saturating_add(slot_base), *len));
            }
        }
    }
    let report =
        ks::analyse(&frames, SPLIT, 100).ok_or("no scheduled link had gaps in both hours")?;
    let mut digest_input = String::new();
    frames.sort_unstable();
    for (t, slot, len) in &frames {
        let _ = writeln!(digest_input, "{t} {slot} {len}");
    }
    let digest = secmp_crypto::sha256(&[digest_input.as_bytes()]);
    let hex: String = digest.iter().fold(String::new(), |mut h, b| {
        let _ = write!(h, "{b:02x}");
        h
    });
    say(&mut shown, &ks::evidence(&report));
    for (slot, samples) in ks::gaps(&frames, SPLIT, 100) {
        let median = |v: &[u64]| {
            let mut v = v.to_vec();
            v.sort_unstable();
            v.get(v.len() / 2).copied().unwrap_or(0)
        };
        let total = frames
            .iter()
            .filter(|f| f.1 == slot && f.2 == ks::FRAME)
            .count();
        say(
            &mut shown,
            &format!(
                "link {slot}: {total} frames, median gap idle {} ms, active {} ms",
                median(&samples.idle),
                median(&samples.active)
            ),
        );
    }
    say(
        &mut shown,
        &format!("frames analysed: {}, sha256 {hex}", frames.len()),
    );
    let links_ok = report.per_link.iter().all(|(_, k)| k.p >= 0.01);
    // Balanced: every departure carries one frame per queue of the client, 2 (one conversation: a send and a receive queue),
    // in both hours; a different or varying number is a finding, not a detail the 100 ms merge may hide
    let per_departure = report.constant_frames_per_departure() == Some(2);
    let ok = links_ok
        && report.pooled.p >= 0.01
        && report.counts_pooled.p >= 0.01
        && per_departure
        && report.all_frames_full
        && report.per_link.len() >= 4;
    say(
        &mut shown,
        &format!(
            "criterion (p >= 0.01 per link and pooled, 4 links, a constant 2 frames per departure, 4352 B): {}",
            if ok { "MET" } else { "NOT MET" }
        ),
    );
    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    std::fs::write(out_dir.join("ks-hour.txt"), shown).map_err(|e| e.to_string())?;
    Ok(ok)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(out_dir) = args.first() else {
        let _ = writeln!(
            std::io::stderr(),
            "usage: ks_hour <out-dir> [<idle-s> [<active-s>]]"
        );
        return ExitCode::from(2);
    };
    let number = |i: usize| args.get(i).map_or(Some(3_600), |s| s.parse::<u64>().ok());
    let (Some(idle), Some(active)) = (number(1), number(2)) else {
        let _ = writeln!(
            std::io::stderr(),
            "ks_hour: the durations are whole seconds"
        );
        return ExitCode::from(2);
    };
    let out_dir = PathBuf::from(out_dir);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(64 << 20)
        .enable_all()
        .build();
    let Ok(runtime) = runtime else {
        return ExitCode::FAILURE;
    };
    let handle = std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || runtime.block_on(run(out_dir, idle, active)));
    match handle.map(std::thread::JoinHandle::join) {
        Ok(Ok(Ok(true))) => ExitCode::SUCCESS,
        Ok(Ok(Ok(false))) => ExitCode::from(1),
        Ok(Ok(Err(why))) => {
            let _ = writeln!(std::io::stderr(), "ks_hour: {why}");
            ExitCode::FAILURE
        }
        _ => ExitCode::FAILURE,
    }
}
