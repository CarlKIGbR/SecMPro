// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-relay` binary entry point; see the library crate documentation for responsibility and
//! allowed dependencies.
//!
//! ```text
//! secmp-relay                                       print the banner (the M0 hello check)
//! secmp-relay --config <file>                       serve (docs/05 §4)
//! secmp-relay keygen --out <file> [--valid-days N]  new identity and key generation 1; prints relay_fp
//! secmp-relay rotate-static --keys <file> [--valid-days N]   add generation kid + 1, drop the expired ones
//! ```
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use secmp_relay::clock::wall_clock_unix_secs;
use secmp_relay::event::{Event, EventSink as _, StderrSink};
use secmp_relay::keys::{DEFAULT_VALIDITY_SECS, KeyFile};
use secmp_relay::server::{self, Clock, Time as _};

const BANNER: &str = concat!(
    env!("CARGO_PKG_NAME"),
    " ",
    env!("CARGO_PKG_VERSION"),
    " (M5)"
);

fn out(line: &str) -> ExitCode {
    match writeln!(std::io::stdout().lock(), "{line}") {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

fn fail(why: &str) -> ExitCode {
    let _ = writeln!(std::io::stderr().lock(), "secmp-relay: {why}");
    ExitCode::FAILURE
}

/// `--valid-days N` → seconds (1..=60 days, checked by the key file).
fn validity(args: &[String]) -> Result<u64, &'static str> {
    match args.iter().position(|a| a == "--valid-days") {
        None => Ok(DEFAULT_VALIDITY_SECS),
        Some(i) => args
            .get(i.saturating_add(1))
            .and_then(|d| d.parse::<u64>().ok())
            .and_then(|d| d.checked_mul(86_400))
            .ok_or("--valid-days needs a number of days"),
    }
}

fn path_after(args: &[String], flag: &str) -> Option<PathBuf> {
    let i = args.iter().position(|a| a == flag)?;
    args.get(i.saturating_add(1)).map(PathBuf::from)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn keygen(args: &[String]) -> ExitCode {
    let Some(path) = path_after(args, "--out") else {
        return fail("keygen needs --out <file>");
    };
    let secs = match validity(args) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let result = KeyFile::generate(wall_clock_unix_secs(), secs).and_then(|f| {
        f.write_new(&path)?;
        let ring = f.ring()?;
        Ok(ring.newest()?.0.fp())
    });
    match result {
        Ok(fp) => out(&format!("relay_fp {}", hex(&fp))),
        Err(e) => fail(&e.to_string()),
    }
}

fn rotate(args: &[String]) -> ExitCode {
    let Some(path) = path_after(args, "--keys") else {
        return fail("rotate-static needs --keys <file>");
    };
    let secs = match validity(args) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let result = KeyFile::read(&path).and_then(|mut f| {
        let kid = f.rotate(wall_clock_unix_secs(), secs)?;
        f.replace(&path)?;
        Ok(kid)
    });
    match result {
        Ok(kid) => out(&format!("kid {kid}")),
        Err(e) => fail(&e.to_string()),
    }
}

fn run(config: &std::path::Path) -> ExitCode {
    let clock = Clock::start();
    StderrSink.emit(&Event::Startup);
    let Ok((cfg, relay)) = server::prepare(config, Box::new(StderrSink), clock.now()) else {
        return ExitCode::FAILURE;
    };
    let relay = Arc::new(relay);
    let Ok(listener) = server::bind(&relay, cfg.listen) else {
        return fail("cannot bind the listener");
    };
    match server::serve(&relay, &listener, &clock, server::spawn_thread) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&e.to_string()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("--version") => out(BANNER),
        Some("keygen") => keygen(&args),
        Some("rotate-static") => rotate(&args),
        Some("--config") => match path_after(&args, "--config") {
            Some(p) => run(&p),
            None => fail("--config needs a file"),
        },
        Some(_) => fail("unknown arguments (see the crate documentation)"),
    }
}
