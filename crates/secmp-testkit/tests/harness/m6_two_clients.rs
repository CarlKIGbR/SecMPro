// SPDX-License-Identifier: AGPL-3.0-or-later
//! M6 Phase C2-1: the `two-clients` binary (TEST-SPEC-M6 TC-01…TC-06, TC-09; X-08 is in `xtask`). TC-07 and TC-08
//! (two machines, real Tor / direct TLS) are owner-operated and have no test here.
//!
//! The `mem` transport runs in-process on a paused runtime (`secmp_testkit::two_clients::main_in`): virtual time needs
//! tokio's `test-util`, which no build of the binary has (ADR-051 Am. 3). The loopback and TLS rows run the binary
//! itself against a relay on `127.0.0.1` in real time.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

/// The digits of the line that starts with `prefix` (the part after the last space).
fn last_word<'a>(run: &'a Run, prefix: &str) -> &'a str {
    run.line(prefix)
        .and_then(|l| l.rsplit(' ').next())
        .unwrap_or_default()
}

/// TC-03 `two_clients_scripted_invitation_handshake` (§5.5, §6.4–6.6): `--role both --transport mem` — the inviter's
/// `LINK_PUT` and invitation queue, the invitee's `LINK_GET` consume (the owner status then reads consumed), the
/// initiator's three cells, the responder's acceptance; both clients report `session=up`; the 60-digit safety numbers
/// equal.
#[test]
fn two_clients_scripted_invitation_handshake() {
    let run = mem("--role both --transport mem");
    assert_eq!(run.code, 0, "{}", run.err);
    let steps: Vec<&str> = run.out.lines().filter(|l| l.starts_with("step=")).collect();
    assert_eq!(
        steps,
        [
            "step=link_put",
            "step=invitation_queue",
            "step=link_get_consume",
            "step=hx_initiator cells=3",
            "step=hx_responder accepted=true link_data present=false consumed=true",
        ],
        "{}",
        run.out
    );
    assert!(run.line("session=up side=inviter").is_some(), "{}", run.out);
    assert!(run.line("session=up side=invitee").is_some(), "{}", run.out);
    let (a, b) = (
        last_word(&run, "sas side=inviter"),
        last_word(&run, "sas side=invitee"),
    );
    assert_eq!(a.len(), 60, "{}", run.out);
    assert!(a.bytes().all(|c| c.is_ascii_digit()));
    assert_eq!(a, b, "the safety numbers differ");
    assert!(run.line("sas=equal").is_some());
}

/// The number under `key` of a trace line.
fn num(v: &serde_json::Value, key: &str) -> u64 {
    v.get(key).and_then(serde_json::Value::as_u64).unwrap()
}

/// The string under `key` of a JSON object.
fn word<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v.get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
}

/// The `deliver` events of the message ordinals `lo..hi` in a trace, in file order (time order): `(msg, t_ms)`.
fn delivers(trace: &str, lo: u64, hi: u64) -> Vec<(u64, u64)> {
    trace
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|v| v.get("event").and_then(serde_json::Value::as_str) == Some("deliver"))
        .map(|v| (num(&v, "msg"), num(&v, "t_ms")))
        .filter(|(m, _)| (lo..hi).contains(m))
        .collect()
}

/// TC-04 `two_clients_exchange_script_mem` (§7.6): a script of 100 messages each way, sizes seeded in 1…65 535 B —
/// each is delivered once, in order, with the bytes sent (the engine compares every received payload and id with the
/// script's; the trace shows each message delivered exactly once, in order, in both directions).
#[test]
fn two_clients_exchange_script_mem() {
    let dir = tmp("exchange");
    let script = dir.join("exchange.script");
    std::fs::write(
        &script,
        "messages = 100\nsize_min = 1\nsize_max = 65535\nseed = 11\n",
    )
    .unwrap();
    let trace = dir.join("trace.jsonl");
    let run = mem(&format!(
        "--role both --transport mem --script {} --trace-out {}",
        script.display(),
        trace.display()
    ));
    assert_eq!(run.code, 0, "{}", run.err);
    assert!(
        run.line("delivered side=inviter 100/100").is_some(),
        "{}",
        run.out
    );
    assert!(
        run.line("delivered side=invitee 100/100").is_some(),
        "{}",
        run.out
    );
    assert!(
        run.line("result exact=true complete=true").is_some(),
        "{}",
        run.out
    );
    let text = std::fs::read_to_string(&trace).unwrap();
    for (lo, hi) in [(0, 100), (100, 200)] {
        let d = delivers(&text, lo, hi);
        assert_eq!(
            d.iter().map(|(m, _)| *m).collect::<Vec<_>>(),
            (lo..hi).collect::<Vec<_>>(),
            "delivered once, in order"
        );
        assert!(d.is_sorted_by_key(|x| x.1));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- the rows with a relay on 127.0.0.1 (real time) -------------------------------------------------------------------

/// The `secmp-relay` binary of this profile, built if it is not (`cargo build --locked --offline -p secmp-relay`; a test
/// of another package has no `CARGO_BIN_EXE_` for it): the path cargo reports.
fn relay_bin() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let mut cmd = Command::new(env!("CARGO"));
    cmd.args([
        "build",
        "--locked",
        "--offline",
        "-p",
        "secmp-relay",
        "--message-format",
        "json",
    ]);
    if exe.components().any(|c| c.as_os_str() == "release") {
        cmd.arg("--release");
    }
    let out = cmd.stderr(Stdio::inherit()).output().unwrap();
    assert!(out.status.success(), "cargo build -p secmp-relay failed");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| {
            word(v, "reason") == "compiler-artifact"
                && v.get("target")
                    .is_some_and(|t| word(t, "name") == "secmp-relay")
        })
        .find_map(|v| {
            v.get("executable")
                .and_then(serde_json::Value::as_str)
                .map(PathBuf::from)
        })
        .expect("cargo reported no secmp-relay executable")
}

/// A running `secmp-relay` process serving plain TCP on loopback (the listener an onion service forwards to); killed
/// when dropped.
struct RelayProcess {
    child: std::process::Child,
}

impl Drop for RelayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start the relay binary in `dir`: `keygen`, a configuration with `tor_loopback = "127.0.0.1:0"`, the port it reports in
/// its `listener_bound` line; the relay reference file for the clients.
fn start_relay(dir: &Path) -> (RelayProcess, PathBuf) {
    use std::io::BufRead as _;
    let bin = relay_bin();
    let keys = dir.join("relay.keys");
    let keygen = Command::new(&bin)
        .arg("keygen")
        .arg("--out")
        .arg(&keys)
        .output()
        .unwrap();
    assert!(keygen.status.success());
    let fp_hex = String::from_utf8_lossy(&keygen.stdout)
        .trim()
        .strip_prefix("relay_fp ")
        .unwrap()
        .to_owned();
    // the key file: "SMPRKEYS" ‖ ver ‖ relay_sig seed[32] ‖ relay_access_key[32] ‖ …
    let file = std::fs::read(&keys).unwrap();
    let access = secmp_crypto::SecretBytes::<32>::from_slice(file.get(41..73).unwrap()).unwrap();
    let config = dir.join("relay.toml");
    std::fs::write(
        &config,
        format!(
            "[listen]\ntor_loopback = \"127.0.0.1:0\"\n[access]\nkey_file = \"{}\"\n",
            keys.display()
        ),
    )
    .unwrap();
    let mut child = Command::new(&bin)
        .arg("--config")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let relay = RelayProcess { child };
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // keep draining: a relay whose stderr pipe fills would block
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            if let Some(addr) = line.split("listener_bound ").nth(1) {
                let _ = tx.send(addr.trim().to_owned());
            }
        }
    });
    let addr = rx
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("the relay reported no listener");
    let port: u16 = addr.rsplit(':').next().unwrap().parse().unwrap();
    let relay_fp: [u8; 32] = fp_hex
        .as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let reference = RelayRef {
        relay_fp,
        onion: secmp_proto::wire::inv::Onion::from_pubkey(&[0x33; 32]),
        akc: secmp_proto::link::ids::akc(&access),
        direct: Some(Direct {
            host: Host::from_bytes(b"127.0.0.1").unwrap(),
            port: core::num::NonZeroU16::new(port).unwrap(),
            spki_sha256: [0; 32],
        }),
    };
    let path = dir.join("relay.ref");
    std::fs::write(&path, relay_ref_file(&reference, &access)).unwrap();
    (relay, path)
}

/// `two-clients <args>` as a process, killed after `secs` of wall time.
fn process_within(args: &[String], secs: u64) -> Run {
    use std::time::{Duration, Instant};
    let mut child = Command::new(BIN)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(secs))
        .unwrap();
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            // exit code 124 (as `timeout(1)`): the caller's `assert_eq!(code, 0)` fails with what it printed
            return Run {
                code: 124,
                out: String::from_utf8_lossy(&out.stdout).into_owned(),
                err: format!("two-clients ran past {secs} s"),
            };
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let out = child.wait_with_output().unwrap();
    Run {
        code: u8::try_from(out.status.code().unwrap_or(255)).unwrap_or(255),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The units of a trace file as `(t_ms, len, dir, slot)`.
fn units(trace: &str) -> Vec<(u64, u64, String, u64)> {
    trace
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|v| v.get("len").is_some())
        .map(|v| {
            (
                num(&v, "t_ms"),
                num(&v, "len"),
                word(&v, "dir").to_owned(),
                num(&v, "link_slot"),
            )
        })
        .collect()
}

/// After the handshake of every link, every unit is a frame of 4 352 B: per link and direction the lengths are the
/// records of spec D.1 (`HELLO` 9, `HS1` 2 856 to the relay; `RELAYINFO` 1 744, `HS2` 1 156 from it), then frames only.
fn assert_frames_after_hs2(trace: &str) {
    let all = units(trace);
    let slots: std::collections::BTreeSet<u64> = all.iter().map(|u| u.3).collect();
    assert!(!slots.is_empty(), "no unit in the trace");
    for slot in slots {
        for (dir, head) in [("c2r", [9_u64, 2_856]), ("r2c", [1_744, 1_156])] {
            let lens: Vec<u64> = all
                .iter()
                .filter(|u| u.3 == slot && u.2 == dir)
                .map(|u| u.1)
                .collect();
            assert!(
                lens.len() > 2,
                "link {slot} {dir}: {} units, no frame after the handshake",
                lens.len()
            );
            assert_eq!(lens.get(..2).unwrap(), head, "link {slot} {dir}");
            assert!(
                lens.get(2..).unwrap().iter().all(|n| *n == 4_352),
                "link {slot} {dir}: a unit after HS2 is not 4352 B: {lens:?}"
            );
        }
    }
}

/// `--role both` over a real transport: 20 messages each way, delivered; every unit after HS2 is 4 352 B.
fn loopback_run(name: &str, transport: &str, mode: &str, reference: &Path) {
    let dir = tmp(name);
    let script = dir.join("script");
    std::fs::write(
        &script,
        "messages = 20\nsize_min = 1\nsize_max = 1000\nseed = 5\n",
    )
    .unwrap();
    let trace = dir.join("trace.jsonl");
    let run = process_within(
        &args(&format!(
            "--role both --transport {transport} --mode {mode} --relay-ref {} --script {} --trace-out {}",
            reference.display(),
            script.display(),
            trace.display()
        )),
        1_500,
    );
    assert_eq!(run.code, 0, "{}\n{}", run.out, run.err);
    assert!(
        run.line("delivered side=inviter 20/20").is_some(),
        "{}",
        run.out
    );
    assert!(
        run.line("delivered side=invitee 20/20").is_some(),
        "{}",
        run.out
    );
    assert!(run.line("result exact=true").is_some(), "{}", run.out);
    assert_frames_after_hs2(&std::fs::read_to_string(&trace).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

/// TC-09 `two_clients_trace_schema`: every line of `--trace-out` is a JSON object with exactly the keys `t_ms`, `len`,
/// `dir`, `link_slot` (a unit) or `event`, `msg`, `t_ms` (a message event) — no identifier, key or address field, and
/// the only strings are `c2r`, `r2c`, `enqueue` and `deliver`; the units have the lengths of spec D.1.
#[test]
fn two_clients_trace_schema() {
    let dir = tmp("schema");
    let script = dir.join("script");
    std::fs::write(
        &script,
        "messages = 3\nsize_min = 1\nsize_max = 3000\nseed = 2\ninterval_s = 30\n",
    )
    .unwrap();
    let trace = dir.join("trace.jsonl");
    let run = mem(&format!(
        "--role both --transport mem --script {} --trace-out {}",
        script.display(),
        trace.display()
    ));
    assert_eq!(run.code, 0, "{}", run.err);
    let text = std::fs::read_to_string(&trace).unwrap();
    let (mut unit_lines, mut event_lines) = (0_u32, 0_u32);
    for line in text.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let obj = v.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert!(
            obj.values().all(|x| x.is_u64()
                || ["c2r", "r2c", "enqueue", "deliver"].contains(&x.as_str().unwrap_or_default())),
            "a value that is no number and no known word: {line}"
        );
        if keys == ["dir", "len", "link_slot", "t_ms"] {
            unit_lines += 1;
            assert!([9, 1_744, 2_856, 1_156, 4_352].contains(&num(&v, "len")));
            assert!(["c2r", "r2c"].contains(&word(&v, "dir")));
        } else {
            assert_eq!(keys, ["event", "msg", "t_ms"], "unknown keys in {line}");
            event_lines += 1;
            assert!(["enqueue", "deliver"].contains(&word(&v, "event")));
            assert!(num(&v, "msg") < 6);
        }
    }
    assert!(unit_lines > 100, "{unit_lines} units");
    assert_eq!(
        event_lines, 12,
        "3 + 3 messages, each enqueued and delivered"
    );
    assert_frames_after_hs2(&text);
    // `interval_s = 30`: the messages of one client are queued 30 s apart
    let enqueued: Vec<u64> = text
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|v| word(v, "event") == "enqueue" && num(v, "msg") < 3)
        .map(|v| num(&v, "t_ms"))
        .collect();
    assert_eq!(enqueued.len(), 3);
    assert!(
        enqueued
            .windows(2)
            .all(|w| w.get(1).unwrap() - w.first().unwrap() == 30_000),
        "{enqueued:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// F-1 (reviewer, C2-1 diff): a stream that ends inside a unit is an error entry, not a dropped tail — a frame of
/// 4 352 B followed by 100 B and a close fails the row, in either direction, naming the residual.
#[test]
fn two_clients_trace_rejects_partial_unit() {
    use secmp_client_core::clock::TokioClock;
    use secmp_testkit::two_clients::trace::Recorder;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    runtime().block_on(async {
        // the client writes 4352 B, flushes, writes 100 B more and closes
        let rec = Recorder::new(TokioClock::new(0));
        let (a, _peer) = tokio::io::duplex(1 << 16);
        let mut s = rec.wrap(a);
        s.write_all(&[0; 4352]).await.unwrap();
        s.flush().await.unwrap();
        s.write_all(&[0; 100]).await.unwrap();
        s.shutdown().await.unwrap();
        let err = rec.check().unwrap_err();
        assert!(err.contains("c2r: residual 100 B"), "{err}");
        assert_eq!(
            rec.units().iter().map(|u| u.len).collect::<Vec<_>>(),
            [4352]
        );
        // the relay sends 4352 B + 100 B and closes; the client reads two frames
        let rec = Recorder::new(TokioClock::new(0));
        let (c, mut relay) = tokio::io::duplex(1 << 16);
        let mut r = rec.wrap(c);
        relay.write_all(&[7; 4452]).await.unwrap();
        relay.shutdown().await.unwrap();
        r.read_exact(&mut [0; 4352]).await.unwrap();
        assert!(r.read_exact(&mut [0; 4352]).await.is_err());
        let err = rec.check().unwrap_err();
        assert!(err.contains("r2c: residual 100 B"), "{err}");
        assert_eq!(
            rec.units().iter().map(|u| u.len).collect::<Vec<_>>(),
            [4352]
        );
    });
}

/// F-1: the length of a unit is what crossed, never an assumed one — a unit of 4 353 B is 4 353 in the trace (both
/// directions), not 4 352 and a residual; a handshake record (a two-byte length, then its body) is one unit of `2 + n`.
#[test]
fn two_clients_trace_unit_lengths_are_observed_not_assumed() {
    use secmp_client_core::clock::TokioClock;
    use secmp_testkit::harness::Dir;
    use secmp_testkit::two_clients::trace::Recorder;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    runtime().block_on(async {
        let rec = Recorder::new(TokioClock::new(0));
        let (a, mut relay) = tokio::io::duplex(1 << 16);
        let mut s = rec.wrap(a);
        s.write_all(&[1; 4353]).await.unwrap();
        s.flush().await.unwrap();
        relay.write_all(&[2; 4353]).await.unwrap();
        s.read_exact(&mut [0; 4353]).await.unwrap();
        // a record: length 5 (big endian), then 5 bytes of body
        relay.write_all(&[0, 5, 9, 9, 9, 9, 9]).await.unwrap();
        s.read_exact(&mut [0; 2]).await.unwrap();
        s.read_exact(&mut [0; 5]).await.unwrap();
        let seen: Vec<(usize, Dir)> = rec.units().iter().map(|u| (u.len, u.dir)).collect();
        assert_eq!(
            seen,
            [(4353, Dir::C2R), (4353, Dir::R2C), (7, Dir::R2C)],
            "{seen:?}"
        );
        assert_eq!(rec.check(), Ok(()));
        assert!(rec.jsonl().contains("\"len\":4353"));
    });
}

/// TC-05 `two_clients_loopback_tcp` (`docs/06` §4): the relay binary on 127.0.0.1, plain TCP, Strict and Balanced, 20
/// messages each way — all delivered; in the trace every unit after HS2 is 4 352 B.
#[test]
fn two_clients_loopback_tcp() {
    let dir = tmp("loopback");
    let (_relay, reference) = start_relay(&dir);
    std::thread::scope(|s| {
        let strict = s.spawn(|| loopback_run("loopback-strict", "loopback", "strict", &reference));
        let balanced =
            s.spawn(|| loopback_run("loopback-balanced", "loopback", "balanced", &reference));
        strict.join().unwrap();
        balanced.join().unwrap();
    });
    let _ = std::fs::remove_dir_all(&dir);
}

/// TC-06 `two_clients_direct_tls_loopback` (§8.1): the relay's direct listener (`DirectRelay`: the binary's accept loop
/// behind TLS 1.3 with the hybrid group), the SPKI pinned from the relay reference, 20 messages each way — all delivered.
#[test]
fn two_clients_direct_tls_loopback() {
    use secmp_testkit::harness::cert::{FixtureKey, VALID, self_signed};
    use secmp_testkit::harness::{DirectRelay, RelayLimits};
    let dir = tmp("tls");
    let key = FixtureKey::new([7; 32]);
    let cert = self_signed(&key, "relay.test", VALID);
    let relay = DirectRelay::start(&cert, &key.pkcs8(), RelayLimits::defaults());
    let reference = dir.join("relay.ref");
    std::fs::write(
        &reference,
        relay_ref_file(&relay.relay_ref(), &relay.access_key()),
    )
    .unwrap();
    loopback_run("tls-strict", "tls", "strict", &reference);
    let _ = std::fs::remove_dir_all(&dir);
}
