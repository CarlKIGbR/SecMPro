// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The command line of `two-clients` (TEST-SPEC-M6 TC-01), parsed by hand: no argument-parser dependency.
//!
//! ```text
//! two-clients [--role inviter|invitee|both] [--mode strict|balanced|lowbw]
//!             [--transport mem|loopback|tls|tor] [--relay-ref FILE]
//!             [--invite-out FILE] [--invite-in FILE] [--script FILE]
//!             [--duration-s N] [--trace-out FILE] [--tor-dir DIR]
//! ```
//!
//! Defaults: `--role both --mode strict --transport mem`. A usage error is [`CliError::Usage`] (exit 2).

use std::path::PathBuf;

use secmp_client_core::scheduler::params::Mode;

/// The usage text (`--help`, and after a usage error).
pub const USAGE: &str = "\
usage: two-clients [options]
  --role {inviter,invitee,both}          which client(s) this process runs (default both)
  --mode {strict,balanced,lowbw}         scheduler mode (default strict)
  --transport {mem,loopback,tls,tor}     how the clients reach the relay (default mem)
  --relay-ref FILE                       the relay's reference file (loopback, tls, tor)
  --invite-out FILE                      the inviter writes its invitation here
  --invite-in FILE                       the invitee reads the invitation here
  --script FILE                          the message script (messages, size_min, size_max, seed)
  --duration-s N                         run N seconds, then stop (default: until the script is done)
  --trace-out FILE                       write the trace (JSON lines) here
  --tor-dir DIR                          Arti's profile directory (tor)
  --help                                 print this text
exit codes: 0 ok, 1 the run failed, 2 usage error, 3 the chosen transport is unavailable
";

/// Which clients this process runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The inviter only (a second process runs the invitee).
    Inviter,
    /// The invitee only.
    Invitee,
    /// Both, in this process.
    Both,
}

/// How the clients reach the relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportArg {
    /// The in-process relay on the virtual clock (no socket).
    Mem,
    /// Plain TCP to the relay's loopback listener (the one the onion service forwards to).
    Loopback,
    /// Direct TLS to the relay's direct listener, pinned by SPKI (spec §8.1).
    Tls,
    /// Tor (Arti), to the relay's onion service.
    Tor,
}

/// The parsed command line.
#[derive(Clone, Debug)]
pub struct Cli {
    /// `--role`.
    pub role: Role,
    /// `--mode`.
    pub mode: Mode,
    /// `--transport`.
    pub transport: TransportArg,
    /// `--relay-ref`.
    pub relay_ref: Option<PathBuf>,
    /// `--invite-out`.
    pub invite_out: Option<PathBuf>,
    /// `--invite-in`.
    pub invite_in: Option<PathBuf>,
    /// `--script`.
    pub script: Option<PathBuf>,
    /// `--duration-s`.
    pub duration_s: Option<u64>,
    /// `--trace-out`.
    pub trace_out: Option<PathBuf>,
    /// `--tor-dir`.
    pub tor_dir: Option<PathBuf>,
}

/// Why parsing stopped.
#[derive(Debug, PartialEq, Eq)]
pub enum CliError {
    /// `--help`: print the usage, exit 0.
    Help,
    /// A usage error: exit 2.
    Usage(String),
}

fn usage<T>(why: impl Into<String>) -> Result<T, CliError> {
    Err(CliError::Usage(why.into()))
}

/// Parse `args` (without the program name).
///
/// # Errors
/// [`CliError::Help`] for `--help`; [`CliError::Usage`] for an unknown flag, a missing or malformed value, a repeated
/// flag, or a combination that cannot run (see the checks at the end).
pub fn parse(args: &[String]) -> Result<Cli, CliError> {
    let mut cli = Cli {
        role: Role::Both,
        mode: Mode::Strict,
        transport: TransportArg::Mem,
        relay_ref: None,
        invite_out: None,
        invite_in: None,
        script: None,
        duration_s: None,
        trace_out: None,
        tor_dir: None,
    };
    let mut seen: Vec<&str> = Vec::new();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        if flag == "--help" || flag == "-h" {
            return Err(CliError::Help);
        }
        if seen.contains(&flag.as_str()) {
            return usage(format!("{flag} given twice"));
        }
        let Some(value) = it.next() else {
            return usage(format!("{flag} needs a value"));
        };
        let path = || PathBuf::from(value);
        match flag.as_str() {
            "--role" => {
                cli.role = match value.as_str() {
                    "inviter" => Role::Inviter,
                    "invitee" => Role::Invitee,
                    "both" => Role::Both,
                    _ => return usage("--role is inviter, invitee or both"),
                };
            }
            "--mode" => {
                cli.mode = match value.as_str() {
                    "strict" => Mode::Strict,
                    "balanced" => Mode::Balanced,
                    "lowbw" => Mode::LowBw,
                    _ => return usage("--mode is strict, balanced or lowbw"),
                };
            }
            "--transport" => {
                cli.transport = match value.as_str() {
                    "mem" => TransportArg::Mem,
                    "loopback" => TransportArg::Loopback,
                    "tls" => TransportArg::Tls,
                    "tor" => TransportArg::Tor,
                    _ => return usage("--transport is mem, loopback, tls or tor"),
                };
            }
            "--relay-ref" => cli.relay_ref = Some(path()),
            "--invite-out" => cli.invite_out = Some(path()),
            "--invite-in" => cli.invite_in = Some(path()),
            "--script" => cli.script = Some(path()),
            "--trace-out" => cli.trace_out = Some(path()),
            "--tor-dir" => cli.tor_dir = Some(path()),
            "--duration-s" => match value.parse::<u64>() {
                Ok(n) if n > 0 => cli.duration_s = Some(n),
                _ => return usage("--duration-s needs a positive number of seconds"),
            },
            other => return usage(format!("unknown flag {other}")),
        }
        seen.push(flag.as_str());
    }
    check(&cli)?;
    Ok(cli)
}

/// The combinations that cannot run.
fn check(cli: &Cli) -> Result<(), CliError> {
    let mem = cli.transport == TransportArg::Mem;
    if mem && cli.role != Role::Both {
        return usage("the mem relay is in this process: --transport mem needs --role both");
    }
    if mem && (cli.relay_ref.is_some() || cli.tor_dir.is_some()) {
        return usage("--relay-ref and --tor-dir do not apply to --transport mem");
    }
    if !mem && cli.relay_ref.is_none() {
        return usage("this transport needs --relay-ref");
    }
    if cli.transport == TransportArg::Tor && cli.tor_dir.is_none() {
        return usage("--transport tor needs --tor-dir");
    }
    if cli.transport != TransportArg::Tor && cli.tor_dir.is_some() {
        return usage("--tor-dir applies to --transport tor only");
    }
    if cli.role == Role::Inviter && cli.invite_out.is_none() {
        return usage("--role inviter needs --invite-out");
    }
    if cli.role == Role::Invitee && cli.invite_in.is_none() {
        return usage("--role invitee needs --invite-in");
    }
    if cli.role != Role::Inviter && cli.role != Role::Both && cli.invite_out.is_some() {
        return usage("--invite-out belongs to the inviter");
    }
    if cli.role != Role::Invitee && cli.role != Role::Both && cli.invite_in.is_some() {
        return usage("--invite-in belongs to the invitee");
    }
    if cli.role == Role::Both && cli.invite_in.is_some() {
        return usage("--role both makes its own invitation: no --invite-in");
    }
    Ok(())
}

/// What a message script says (`--script`): `key = value` lines, `#` comments; unknown or repeated keys are refused.
///
/// ```text
/// messages = 100        # each way
/// size_min = 1
/// size_max = 65535
/// seed = 7
/// interval_s = 60       # one message every 60 s (default 0: all at the start)
/// start_s = 3600        # nothing is queued before this many seconds (default 0)
/// bursts = 10           # of `messages`, the last `bursts × burst_size` come in bursts, one every 360 s from start_s + 180 s
/// burst_size = 20
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Script {
    /// Messages each way.
    pub messages: u64,
    /// Smallest payload, bytes.
    pub size_min: u64,
    /// Largest payload, bytes.
    pub size_max: u64,
    /// The seed of the sizes and the payload bytes.
    pub seed: u64,
    /// Seconds between two messages of one client (0: all are queued at the start).
    pub interval_s: u64,
    /// Seconds of silence before the first message (an idle period).
    pub start_s: u64,
    /// Bursts among the `messages` (0: none).
    pub bursts: u64,
    /// Messages per burst.
    pub burst_size: u64,
}

impl Default for Script {
    /// No messages: the clients only keep their constant-rate links.
    fn default() -> Self {
        Self {
            messages: 0,
            size_min: 1,
            size_max: 65_535,
            seed: 1,
            interval_s: 0,
            start_s: 0,
            bursts: 0,
            burst_size: 20,
        }
    }
}

/// The largest payload of a message (spec §7.6: `MAX_MSG_BYTES`).
pub const MAX_PAYLOAD: u64 = 65_535;

impl Script {
    /// The queueing order: `(index, due)` of every message sorted by due time (then index). `enqueue_at_ms` is not monotone
    /// in the index (the bursts come after the steady messages in index order and between them in time), so a host that
    /// queues in index order and stops at the first message not yet due would hold the bursts back.
    #[must_use]
    pub fn schedule(&self) -> Vec<(u64, u64)> {
        let mut plan: Vec<(u64, u64)> = (0..self.messages)
            .map(|i| (i, self.enqueue_at_ms(i)))
            .collect();
        plan.sort_by_key(|(i, due)| (*due, *i));
        plan
    }

    /// When message `i` of a client is queued, in milliseconds after the start of the conversation: the steady messages at
    /// `start_s + i × interval_s`, then the bursts (`burst_size` messages at once), one every 360 s from `start_s + 180 s`.
    #[must_use]
    pub fn enqueue_at_ms(&self, i: u64) -> u64 {
        let in_bursts = self.bursts.saturating_mul(self.burst_size);
        let steady = self.messages.saturating_sub(in_bursts);
        let start = self.start_s.saturating_mul(1000);
        if i < steady || self.burst_size == 0 {
            return start.saturating_add(i.saturating_mul(self.interval_s.saturating_mul(1000)));
        }
        let burst = i
            .saturating_sub(steady)
            .checked_div(self.burst_size)
            .unwrap_or(0);
        start
            .saturating_add(180_000)
            .saturating_add(burst.saturating_mul(360_000))
    }

    /// Parse a script file's text.
    ///
    /// # Errors
    /// The reason (a usage error: exit 2).
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut s = Self::default();
        let mut seen: Vec<String> = Vec::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("script line without `=`: {line}"))?;
            let (key, value) = (key.trim(), value.trim());
            if seen.iter().any(|k| k == key) {
                return Err(format!("script key {key} given twice"));
            }
            let n: u64 = value
                .replace('_', "")
                .parse()
                .map_err(|_| format!("script key {key} needs a number"))?;
            match key {
                "messages" => s.messages = n,
                "size_min" => s.size_min = n,
                "size_max" => s.size_max = n,
                "seed" => s.seed = n,
                "interval_s" => s.interval_s = n,
                "start_s" => s.start_s = n,
                "bursts" => s.bursts = n,
                "burst_size" => s.burst_size = n,
                other => return Err(format!("unknown script key {other}")),
            }
            seen.push(key.to_owned());
        }
        if s.size_min == 0 || s.size_min > s.size_max || s.size_max > MAX_PAYLOAD {
            return Err(format!(
                "script sizes must satisfy 1 <= size_min <= size_max <= {MAX_PAYLOAD}"
            ));
        }
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn defaults_and_flags() {
        let c = parse(&args("")).unwrap();
        assert_eq!(
            (c.role, c.mode, c.transport),
            (Role::Both, Mode::Strict, TransportArg::Mem)
        );
        let c = parse(&args("--mode lowbw --duration-s 600 --trace-out t.jsonl")).unwrap();
        assert_eq!(c.mode, Mode::LowBw);
        assert_eq!(c.duration_s, Some(600));
    }

    #[test]
    fn refuses_what_cannot_run() {
        for bad in [
            "--bogus 1",
            "--role",
            "--role nobody",
            "--role inviter",
            "--role invitee --transport loopback --relay-ref r",
            "--transport tls",
            "--transport tor --relay-ref r",
            "--transport mem --relay-ref r",
            "--duration-s 0",
            "--mode strict --mode balanced",
        ] {
            assert!(
                matches!(parse(&args(bad)), Err(CliError::Usage(_))),
                "{bad}"
            );
        }
        assert_eq!(parse(&args("--help")).unwrap_err(), CliError::Help);
    }

    #[test]
    fn script_grammar() {
        let s = Script::parse("# a\nmessages = 100\nsize_max = 1_000\nseed = 3\n").unwrap();
        assert_eq!(
            (s.messages, s.size_min, s.size_max, s.seed),
            (100, 1, 1000, 3)
        );
        for bad in [
            "messages",
            "messages = x",
            "messages = 1\nmessages = 2",
            "nope = 1",
            "size_min = 0",
            "size_max = 65536",
            "size_min = 9\nsize_max = 8",
        ] {
            assert!(Script::parse(bad).is_err(), "{bad}");
        }
    }
}
