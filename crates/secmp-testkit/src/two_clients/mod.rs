// SPDX-License-Identifier: AGPL-3.0-or-later
//! `two-clients` (TEST-SPEC-M6 TC-01…TC-09; `docs/07` M6): two clients, one relay, a scripted invitation and handshake,
//! and a message exchange over constant-rate links. The binary `two-clients` (`src/bin/two-clients.rs`,
//! `required-features = ["harness"]`, never shipped) is a thin `main` over [`main_with`].
//!
//! - [`cli`]: the flags and the message script.
//! - [`run`]: the engine ([`run::run`]): invitation, handshake, the two clients on the tokio driver.
//! - [`trace`]: the JSON-lines trace (TC-09) and the recording providers.
//!
//! **Profiles are in memory** (TC-02): the ratchet state, outbox and queues of both clients live in the process; the
//! only files a run touches are the ones named on the command line (`--trace-out`, `--invite-out`, `--invite-in`,
//! `--relay-ref`, `--script`).
//!
//! Exit codes: 0 ok · 1 the run failed · 2 usage error · 3 the chosen transport is unavailable (no other transport is
//! tried) · 101 the engine panicked (the standard Rust panic code; a bug, never a result).

pub mod cli;
pub mod rand;
pub mod run;
#[cfg(test)]
mod script_tests;
pub mod trace;

use std::io::Write;

use cli::{Cli, CliError, Script, USAGE};
use run::Fail;

/// The stack of the thread the engine runs on: the handshake and the ratchet keep large frames, and the main thread of a
/// Windows process has 1 MiB (8 MiB on Linux) — the program does not depend on its caller's stack.
const ENGINE_STACK: usize = 64 << 20;

/// Run `f` on a scoped thread of [`ENGINE_STACK`] bytes. A panic of the engine is exit code 101 (as the standard
/// runtime reports a panic of `main`), a thread that cannot be spawned is 1.
fn on_stack(f: impl FnOnce() -> u8 + Send) -> u8 {
    std::thread::scope(|s| {
        match std::thread::Builder::new()
            .stack_size(ENGINE_STACK)
            .spawn_scoped(s, f)
        {
            Ok(handle) => handle.join().unwrap_or(101),
            Err(_) => 1,
        }
    })
}

/// Run `exec` on a thread of [`ENGINE_STACK`] bytes.
fn on_big_stack(
    runtime: Option<&tokio::runtime::Runtime>,
    args: &[String],
    out: &mut (dyn Write + Send),
    err: &mut (dyn Write + Send),
) -> u8 {
    on_stack(|| exec(runtime, args, out, err))
}

/// Run the program: `args` without the program name, the two output streams; returns the exit code.
pub fn main_with(
    args: &[String],
    out: &mut (dyn Write + Send),
    err: &mut (dyn Write + Send),
) -> u8 {
    on_big_stack(None, args, out, err)
}

/// As [`main_with`], on `runtime` — a paused one (`tokio::time::pause`, tests only) makes the `mem` transport virtual.
pub fn main_in(
    runtime: &tokio::runtime::Runtime,
    args: &[String],
    out: &mut (dyn Write + Send),
    err: &mut (dyn Write + Send),
) -> u8 {
    on_big_stack(Some(runtime), args, out, err)
}

fn exec(
    runtime: Option<&tokio::runtime::Runtime>,
    args: &[String],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let cli: Cli = match cli::parse(args) {
        Ok(c) => c,
        Err(CliError::Help) => {
            let _ = out.write_all(USAGE.as_bytes());
            return 0;
        }
        Err(CliError::Usage(why)) => {
            let _ = writeln!(err, "two-clients: {why}");
            let _ = err.write_all(USAGE.as_bytes());
            return 2;
        }
    };
    let script = match &cli.script {
        None => Script::default(),
        Some(path) => match std::fs::read_to_string(path)
            .map_err(|_| "cannot read --script".to_owned())
            .and_then(|t| Script::parse(&t))
        {
            Ok(s) => s,
            Err(why) => {
                let _ = writeln!(err, "two-clients: {why}");
                return 2;
            }
        },
    };
    let result = match runtime {
        Some(rt) => run::run_in(rt, &cli, &script, out),
        None => run::run(&cli, &script, out),
    };
    match result {
        Ok(()) => 0,
        Err(Fail::Usage(why)) => {
            let _ = writeln!(err, "two-clients: {why}");
            2
        }
        Err(Fail::Unavailable(why)) => {
            let _ = writeln!(err, "two-clients: transport unavailable: {why}");
            3
        }
        Err(Fail::Run(why)) => {
            let _ = writeln!(err, "two-clients: failed: {why}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real (virtual-time) run of both clients on the mem transport with an observer: the pools fill (each client's
    /// pool makes its `pool_target` = 2 spares by `QUEUE_NEW` one-shots), the clients' drivers open their links, the
    /// script sends one message each way. Returns the observer and what the engine printed.
    fn observed_mem_run() -> Result<(std::sync::Arc<run::Observer>, String), String> {
        std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .start_paused(true)
                    .build()
                    .map_err(|e| e.to_string())?;
                runtime.block_on(async {
                    let relay =
                        crate::harness::MemRelay::new(crate::harness::HarnessConfig::default());
                    let observer = run::Observer::new();
                    let world = run::World::new(
                        crate::harness::MemProvider::new(relay.clone()),
                        run::WorldConfig {
                            relay: relay.relay_ref(),
                            access: relay.access_key(),
                            clock: relay.clock(),
                            unix_base: crate::harness::START_UNIX,
                            mode: secmp_client_core::scheduler::params::Mode::Strict,
                            direct: false,
                            connect_timeout_ms: None,
                        },
                        Some(std::sync::Arc::clone(&observer)),
                    );
                    let cli = cli::Cli {
                        role: cli::Role::Both,
                        mode: secmp_client_core::scheduler::params::Mode::Strict,
                        transport: cli::TransportArg::Mem,
                        relay_ref: None,
                        invite_out: None,
                        invite_in: None,
                        script: None,
                        duration_s: Some(300),
                        trace_out: None,
                        tor_dir: None,
                    };
                    let script = cli::Script {
                        messages: 1,
                        interval_s: 30,
                        ..cli::Script::default()
                    };
                    let mut out = Vec::new();
                    Box::pin(run::session::<
                        crate::harness::MemProvider,
                        crate::harness::EntropyPool,
                    >(&cli, world, &script, &mut out))
                    .await
                    .map_err(|e| format!("{e:?}"))?;
                    Ok((observer, String::from_utf8_lossy(&out).into_owned()))
                })
            })
            .map_err(|e| e.to_string())?
            .join()
            .map_err(|_| "the run's thread panicked".to_owned())?
    }

    /// C2-18c (verifier G1): on a real run the control slots are exactly the pool drivers' connections — 2 × `pool_target`
    /// = 4 for the pair — and none of them is a link slot of a client driver.
    #[test]
    fn control_slots_are_exactly_the_pool_connections() -> Result<(), String> {
        let (observer, out) = observed_mem_run()?;
        let control = observer.control_slots();
        assert_eq!(control.len(), 4, "control slots {control:?}\n{out}");
        let rec = observer.recorder().ok_or("no recorder")?;
        // exactly the slots the pool drivers' (control-class) providers created
        assert_eq!(control, rec.control_slots());
        // the pool drivers are not client drivers: no control slot shares a driver with a link slot
        let origins = rec.origins();
        let driver_of = |slot: &u64| origins.get(slot).map(|(d, _)| *d);
        let pool_drivers: std::collections::BTreeSet<u64> =
            control.iter().filter_map(driver_of).collect();
        assert_eq!(
            pool_drivers.len(),
            2,
            "one pool driver per client: {pool_drivers:?}"
        );
        let mut lens: std::collections::BTreeMap<u64, Vec<usize>> =
            std::collections::BTreeMap::new();
        for u in rec.units() {
            if u.dir == crate::harness::Dir::C2R {
                lens.entry(u.slot).or_default().push(u.len);
            }
        }
        let links: Vec<u64> = lens
            .keys()
            .copied()
            .filter(|s| !control.contains(s))
            .collect();
        assert!(
            links
                .iter()
                .all(|s| driver_of(s).is_some_and(|d| !pool_drivers.contains(&d))),
            "a link slot from a pool driver"
        );
        // each client opened at least one link that carried frames
        let link_drivers: std::collections::BTreeSet<u64> = links
            .iter()
            .filter(|s| lens.get(s).is_some_and(|l| l.contains(&4_352)))
            .filter_map(driver_of)
            .collect();
        assert!(link_drivers.len() >= 2, "links of {link_drivers:?}\n{out}");
        // every control slot is HELLO, HS1 and at most one 4 352 B unit (the cap of `ks`)
        for slot in &control {
            let l = lens.get(slot).cloned().unwrap_or_default();
            assert_eq!(
                l.get(..2),
                Some(&[9, 2_856][..]),
                "control slot {slot}: {l:?}"
            );
            assert!(
                l.iter().skip(2).all(|n| *n == 4_352)
                    && u64::try_from(l.len()).is_ok_and(|n| n <= 2 + crate::ks::CONTROL_FRAMES_CAP),
                "control slot {slot}: {l:?}"
            );
        }
        Ok(())
    }

    /// m-9 (verifier): the engine's thread ends in a panic → exit code 101, not a swallowed `1`; a normal return is its code.
    #[test]
    fn two_clients_engine_panic_exits_101() {
        assert_eq!(on_stack(|| 7), 7);
        assert_eq!(
            on_stack(|| std::panic::resume_unwind(Box::new("the engine panicked"))),
            101
        );
    }
}
