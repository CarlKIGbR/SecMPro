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
