// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-cli` — the headless, scriptable SecMPro client.
//!
//! **Responsibility.** Profile, invitation, contact and send commands with JSON-lines output for integration/E2E tests and
//! operations (M7 Phase C). Output timestamps are the core clock's (`Stamped.at_ms`); this crate reads no clock.
//!
//! **Allowed dependencies** (docs/02 §3): `secmp-client-core` (and the crates below it); no key material handling outside the
//! core's API. It names only `secmp_client_core::api` paths.
//!
//! **Commands.** No arguments: the banner. `profile new <dir> --passphrase-file F [--relay R]`. `open <dir>
//! --passphrase-file F [--direct] [--name N]`, then command lines on stdin (`invite create`, `invite accept <uri>`,
//! `contacts list`, `send <id> <text…>`, `quit`) and one JSON object per line on stdout. Exit codes: 0 ok, 1 other, 2 usage
//! (stderr only), 3 transport unavailable, 4 unlock, 5 busy.
#![forbid(unsafe_code)]

pub mod args;
pub mod daemon;
pub mod json;
pub mod lock;
pub mod passphrase;

use args::{Command, USAGE, parse};
use daemon::{ENGINE_STACK, EXIT_OTHER, EXIT_USAGE, OpenArgs, err, out};

/// The banner of a run without arguments.
const BANNER: &str = concat!(
    env!("CARGO_PKG_NAME"),
    " ",
    env!("CARGO_PKG_VERSION"),
    " (M7 Phase C)"
);

/// Run the program on `args` (without the program name) and return the exit code. The engine runs on a thread of
/// [`ENGINE_STACK`] bytes; a panic of it is exit code 101 (as the standard runtime reports one of `main`).
#[must_use]
pub fn run(args: &[String]) -> u8 {
    let args = args.to_vec();
    std::thread::scope(|s| {
        match std::thread::Builder::new()
            .stack_size(ENGINE_STACK)
            .spawn_scoped(s, move || dispatch(&args))
        {
            Ok(handle) => handle.join().unwrap_or(101),
            Err(_) => EXIT_OTHER,
        }
    })
}

fn dispatch(args: &[String]) -> u8 {
    match parse(args) {
        Err(_) => {
            // the usage text only: never an argument (it may be a passphrase typed in the wrong place)
            err(USAGE.trim_end());
            EXIT_USAGE
        }
        Ok(Command::Banner) => {
            out(BANNER);
            daemon::EXIT_OK
        }
        Ok(Command::ProfileNew {
            dir,
            passphrase_file,
            relay,
        }) => daemon::profile_new(&dir, &passphrase_file, relay.as_deref()),
        Ok(Command::Open {
            dir,
            passphrase_file,
            direct,
            name,
        }) => daemon::open(&OpenArgs {
            dir: &dir,
            passphrase_file: &passphrase_file,
            direct,
            name: name.as_deref(),
        }),
    }
}
