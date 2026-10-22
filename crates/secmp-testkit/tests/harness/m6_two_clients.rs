// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 Phase C2-1: the `two-clients` binary (TEST-SPEC-M6 TC-01…TC-06, TC-09; X-08 is in `xtask`). TC-07 and TC-08
//! (two machines, real Tor / direct TLS) are owner-operated and have no test here.
//!
//! The `mem` transport runs in-process on a paused runtime (`secmp_testkit::two_clients::main_in`): virtual time needs
//! tokio's `test-util`, which no build of the binary has (ADR-051 Am. 3). The loopback and TLS rows run the binary
//! itself against a relay on `127.0.0.1` in real time.

use std::path::{Path, PathBuf};
use std::process::Command;

use secmp_proto::wire::inv::{Direct, Host, RelayRef};
use secmp_testkit::harness::{HarnessConfig, MemRelay};
use secmp_testkit::two_clients::main_in;
use secmp_testkit::two_clients::run::relay_ref_file;

use crate::m6_tokio::runtime;

/// The binary under test.
const BIN: &str = env!("CARGO_BIN_EXE_two-clients");

/// An empty directory `<CARGO_TARGET_TMPDIR>/two-clients-<name>-<pid>`.
fn tmp(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("two-clients-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn args(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_owned).collect()
}

/// The result of one run of the engine.
struct Run {
    code: u8,
    out: String,
    err: String,
}

impl Run {
    /// The value of `key=` in the line that starts with `prefix`.
    fn line(&self, prefix: &str) -> Option<&str> {
        self.out.lines().find(|l| l.starts_with(prefix))
    }
}

/// `two-clients <args>` in this process on a paused runtime (virtual time).
///
/// On a thread of its own with a large stack: the handshake and the ratchet keep large frames in an unoptimised build,
/// which a test thread's 2 MiB does not hold (the binary's main thread has 8 MiB).
fn mem(args_text: &str) -> Run {
    let args = args(args_text);
    std::thread::Builder::new()
        .stack_size(32 << 20)
        .spawn(move || {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let code = main_in(&runtime(), &args, &mut out, &mut err);
            Run {
                code,
                out: String::from_utf8(out).unwrap(),
                err: String::from_utf8(err).unwrap(),
            }
        })
        .unwrap()
        .join()
        .unwrap()
}

/// The binary as a process.
fn process(args: &[&str]) -> (Option<i32>, String, String) {
    let o = Command::new(BIN).args(args).output().unwrap();
    (
        o.status.code(),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// Every file below `dir`, with its size, sorted.
fn listing(dir: &Path) -> Vec<(PathBuf, u64)> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let meta = e.metadata().unwrap();
            if meta.is_dir() {
                todo.push(e.path());
            } else {
                out.push((e.path(), meta.len()));
            }
        }
    }
    out.sort();
    out
}

/// A `RelayRef` of a relay that is nobody: a direct endpoint at `127.0.0.1:port` (or none).
fn relay_ref_at(port: Option<u16>) -> (RelayRef, secmp_proto::link::ids::AccessKey) {
    runtime().block_on(async {
        let relay = MemRelay::new(HarnessConfig::default());
        let mut r = relay.relay_ref();
        r.direct = port.map(|p| Direct {
            host: Host::from_bytes(b"127.0.0.1").unwrap(),
            port: core::num::NonZeroU16::new(p).unwrap(),
            spki_sha256: [7; 32],
        });
        (r, relay.access_key())
    })
}

/// TC-01 `two_clients_cli_contract` (`docs/07` M6): `--help` lists the flags `--role {inviter,invitee,both}`, `--mode
/// {strict,balanced,lowbw}`, `--transport {mem,loopback,tls,tor}`, `--relay-ref`, `--invite-out`, `--invite-in`,
/// `--script`, `--duration-s`, `--trace-out`, `--tor-dir`; a bad flag or value exits 2; a transport that cannot be used
/// exits 3 — and no other transport is tried in its place (a direct endpoint that answers like a plain TCP relay sees
/// a TLS `ClientHello`, never SecMP's cleartext `HELLO`).
#[test]
fn two_clients_cli_contract() {
    let (code, out, _) = process(&["--help"]);
    assert_eq!(code, Some(0));
    for flag in [
        "--role {inviter,invitee,both}",
        "--mode {strict,balanced,lowbw}",
        "--transport {mem,loopback,tls,tor}",
        "--relay-ref",
        "--invite-out",
        "--invite-in",
        "--script",
        "--duration-s",
        "--trace-out",
        "--tor-dir",
    ] {
        assert!(out.contains(flag), "--help does not list {flag}");
    }
    for bad in [
        &["--bogus", "1"][..],
        &["--role", "nobody"],
        &["--transport", "carrier-pigeon"],
        &["--mode"],
        &["--transport", "tls"],
        &["--transport", "tor", "--relay-ref", "x"],
        &["--role", "inviter"],
        &["--duration-s", "0"],
    ] {
        let (code, out, err) = process(bad);
        assert_eq!(code, Some(2), "{bad:?}: {err}");
        assert!(out.is_empty() && err.contains("two-clients:"), "{bad:?}");
    }
    let dir = tmp("cli");
    // exit 3: tls against a relay reference without a direct endpoint — nothing is tried over any transport
    let (relay, access) = relay_ref_at(None);
    let no_direct = dir.join("no-direct.ref");
    std::fs::write(&no_direct, relay_ref_file(&relay, &access)).unwrap();
    for transport in ["tls", "loopback"] {
        let (code, out, err) = process(&[
            "--transport",
            transport,
            "--relay-ref",
            no_direct.to_str().unwrap(),
        ]);
        assert_eq!(code, Some(3), "{transport}: {err}");
        assert!(err.contains("transport unavailable"), "{err}");
        assert!(!out.contains("session=up"), "{out}");
    }
    // exit 3: a closed port
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let (relay, access) = relay_ref_at(Some(closed));
    let refused = dir.join("refused.ref");
    std::fs::write(&refused, relay_ref_file(&relay, &access)).unwrap();
    let (code, _, err) = process(&[
        "--transport",
        "loopback",
        "--relay-ref",
        refused.to_str().unwrap(),
    ]);
    assert_eq!(code, Some(3), "{err}");
    no_fallback_to_plain_tcp(&dir);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A listener on loopback that reads the first byte of every connection for up to 20 s (and stops 50 ms polls after
/// the first connection ended); the port, and the bytes it saw.
fn decoy_listener() -> (u16, std::thread::JoinHandle<Vec<u8>>) {
    use std::io::Read as _;
    use std::time::{Duration, Instant};
    let decoy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = decoy.local_addr().unwrap().port();
    decoy.set_nonblocking(true).unwrap();
    let seen = std::thread::spawn(move || {
        let mut first = Vec::new();
        let deadline = Instant::now().checked_add(Duration::from_secs(20)).unwrap();
        while Instant::now() < deadline {
            if let Ok((mut s, _)) = decoy.accept() {
                s.set_nonblocking(false).unwrap();
                s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut b = [0_u8; 1];
                if s.read(&mut b).unwrap_or(0) == 1 {
                    first.push(b[0]);
                }
            } else if !first.is_empty() {
                break;
            } else {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        first
    });
    (port, seen)
}

/// Exit 3 and no fallback: `--transport tls` against a listener that is not a relay speaks TLS to it and nothing else.
fn no_fallback_to_plain_tcp(dir: &Path) {
    let (port, seen) = decoy_listener();
    let (relay, access) = relay_ref_at(Some(port));
    let decoy_ref = dir.join("decoy.ref");
    std::fs::write(&decoy_ref, relay_ref_file(&relay, &access)).unwrap();
    let (code, _, err) = process(&[
        "--transport",
        "tls",
        "--relay-ref",
        decoy_ref.to_str().unwrap(),
    ]);
    assert_eq!(code, Some(3), "{err}");
    let first = seen.join().unwrap();
    assert!(!first.is_empty(), "the decoy was never contacted");
    assert!(
        first.iter().all(|b| *b == 0x16),
        "{first:?}: something other than a TLS handshake record reached the listener"
    );
}

/// TC-02 `two_clients_profiles_are_in_memory`: `--role both --transport mem` for 600 s of virtual time creates no
/// file but `--trace-out` — the ratchet states, outboxes and queues of both clients stay in the process.
#[test]
fn two_clients_profiles_are_in_memory() {
    let dir = tmp("profiles");
    let before = listing(&dir);
    assert!(before.is_empty());
    let trace = dir.join("trace.jsonl");
    let run = mem(&format!(
        "--role both --transport mem --duration-s 600 --trace-out {}",
        trace.display()
    ));
    assert_eq!(run.code, 0, "{}", run.err);
    assert!(run.line("session=up side=inviter").is_some(), "{}", run.out);
    assert!(
        run.line("result ")
            .is_some_and(|l| l.contains("end_ms=600")),
        "600 s of virtual time: {}",
        run.out
    );
    let after = listing(&dir);
    assert_eq!(
        after.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>(),
        vec![trace.clone()],
        "a file besides --trace-out"
    );
    assert!(after.first().unwrap().1 > 1_000, "the trace is empty");
    let _ = std::fs::remove_dir_all(&dir);
}
