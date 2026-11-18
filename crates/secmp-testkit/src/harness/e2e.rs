// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The end-to-end helper of M7 Phase C (TEST-SPEC-M7 E2-01, CL rows; `docs/06` §4: loopback integration rows are the only
//! tests with sockets): the `secmp-relay` binary behind its direct TLS listener on 127.0.0.1 ([`E2eRelay`]), the `secmp-cli`
//! binary as a child process whose stdout lines are JSON ([`CliProc`]), profiles seeded with spare queues before the first
//! `open` ([`E2eRelay::seed_spares`], as `m7_world` + the driver's set-up traffic do on the virtual driver).
//!
//! Both binaries are built by `cargo build --locked --offline -p <package> [--features direct-tls]` (a test of another package
//! has no `CARGO_BIN_EXE_` for them; a separate build also keeps feature unification from putting `kat` in the binary under
//! test) and copied into the test's own directory, so that another build of the same path cannot change the file under test.

use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use secmp_client_core::invitations::SparePool;
use secmp_client_core::profile::Profile;
use secmp_client_core::scheduler::types::RelayId;
use secmp_crypto::SecretBytes;
use secmp_proto::Encode as _;
use secmp_proto::link::ids::{AccessKey, akc};
use secmp_proto::tr::FixedEntropy;
use secmp_proto::wire::inv::{Direct, Host, Onion, RelayRef};
use secmp_transport::driver::{AsyncQueueTransport, AsyncRelayQueueTransport, StreamProvider};
use secmp_transport::tls::TlsProvider;

use super::EntropyPool;
use super::cert::{FixtureKey, VALID, self_signed};

/// One JSON line of the CLI.
pub type Json = serde_json::Value;

/// One stdout line of the CLI as JSON.
///
/// # Panics
/// On a line that is not one JSON object with a `type`: a test failure (every line of the CLI is one).
#[must_use]
pub fn parse_line(line: &str) -> Json {
    let value: Json = serde_json::from_str(line).unwrap();
    assert!(
        value.get("type").and_then(Json::as_str).is_some(),
        "a line without a type: {line:?}"
    );
    value
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut out = String::new();
    for b in bytes {
        write!(out, "{b:02x}").unwrap();
    }
    out
}

/// The path `cargo build -p package [--features features]` reports for the package's binary, copied to `into`.
fn build_bin(package: &str, features: Option<&str>, into: &Path) -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let mut cmd = Command::new(env!("CARGO"));
    cmd.args(["build", "--locked", "--offline", "-p", package]);
    if let Some(features) = features {
        cmd.args(["--features", features]);
    }
    cmd.args(["--message-format", "json"]);
    if exe.components().any(|c| c.as_os_str() == "release") {
        cmd.arg("--release");
    }
    let out = cmd.stderr(Stdio::inherit()).output().unwrap();
    assert!(out.status.success(), "cargo build -p {package} failed");
    let built = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<Json>(l).ok())
        .filter(|v| {
            v.get("reason").and_then(Json::as_str) == Some("compiler-artifact")
                && v.get("target")
                    .and_then(|t| t.get("name"))
                    .and_then(Json::as_str)
                    == Some(package)
        })
        .find_map(|v| {
            v.get("executable")
                .and_then(Json::as_str)
                .map(PathBuf::from)
        })
        .expect("cargo reported no executable");
    std::fs::create_dir_all(into).unwrap();
    let copy = into.join(built.file_name().unwrap());
    std::fs::copy(&built, &copy).unwrap();
    copy
}

/// The `secmp-relay` binary with its direct TLS listener, built and copied into `into`.
#[must_use]
pub fn relay_bin(into: &Path) -> PathBuf {
    build_bin("secmp-relay", Some("direct-tls"), into)
}

/// The `secmp-cli` binary of this profile (no feature of the test harness in it), built and copied into `into`.
#[must_use]
pub fn cli_bin(into: &Path) -> PathBuf {
    build_bin("secmp-cli", None, into)
}

/// Write `content` to `path` with mode 0600 on Unix: a passphrase file the CLI accepts.
///
/// # Panics
/// If the file cannot be written: a test failure.
pub fn write_secret_file(path: &Path, content: &[u8]) {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).unwrap();
    file.write_all(content).unwrap();
}

/// A running `secmp-relay` process with a direct TLS listener on 127.0.0.1; killed when dropped.
pub struct E2eRelay {
    child: Child,
    dir: PathBuf,
    relay: RelayRef,
    access: AccessKey,
    lines: Arc<Mutex<Vec<String>>>,
}

impl Drop for E2eRelay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl E2eRelay {
    /// Start the relay in `dir`: `keygen`, a certificate and key, a configuration with `tor_loopback = "127.0.0.1:0"` and
    /// `direct_tls` on a port picked by binding and dropping a listener on 127.0.0.1:0, the relay reference file
    /// `relay.ref` (`Direct { 127.0.0.1, port, SPKI pin of the certificate }`). Waits for the `listener_bound` line of the
    /// direct listener.
    ///
    /// # Panics
    /// On a violated harness invariant (no relay binary, a relay that does not bind): a test failure.
    #[must_use]
    pub fn start(dir: &Path) -> Self {
        std::fs::create_dir_all(dir).unwrap();
        let bin = relay_bin(&dir.join("bin"));
        let keys = "relay.keys";
        let keygen = Command::new(&bin)
            .current_dir(dir)
            .args(["keygen", "--out", keys])
            .output()
            .unwrap();
        assert!(keygen.status.success(), "relay keygen failed");
        let fp_hex = String::from_utf8_lossy(&keygen.stdout)
            .trim()
            .strip_prefix("relay_fp ")
            .unwrap()
            .to_owned();
        let relay_fp: [u8; 32] = (0..fp_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(fp_hex.get(i..i.saturating_add(2)).unwrap(), 16).unwrap())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        // the key file: "SMPRKEYS" ‖ ver ‖ relay_sig seed[32] ‖ relay_access_key[32] ‖ …
        let file = std::fs::read(dir.join(keys)).unwrap();
        let access = SecretBytes::<32>::from_slice(file.get(41..73).unwrap()).unwrap();
        let key = FixtureKey::new([0x77; 32]);
        std::fs::write(
            dir.join("relay-tls.der"),
            self_signed(&key, "relay.test", VALID),
        )
        .unwrap();
        std::fs::write(dir.join("relay-tls.key"), key.pkcs8()).unwrap();
        let port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        std::fs::write(
            dir.join("relay.toml"),
            format!(
                "[listen]\ntor_loopback = \"127.0.0.1:0\"\ndirect_tls = \"127.0.0.1:{port}\"\n\
                 direct_tls_cert = \"relay-tls.der\"\ndirect_tls_key = \"relay-tls.key\"\n\
                 [access]\nkey_file = \"{keys}\"\n"
            ),
        )
        .unwrap();
        let mut child = Command::new(&bin)
            .current_dir(dir)
            .args(["--config", "relay.toml"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let collected = Arc::clone(&lines);
        let direct = format!("127.0.0.1:{port}");
        std::thread::spawn(move || {
            // keep draining: a relay whose stderr pipe fills would block
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                if line.split("listener_bound ").nth(1).map(str::trim) == Some(direct.as_str()) {
                    let _ = tx.send(());
                }
                collected.lock().unwrap().push(line);
            }
        });
        let mut me = Self {
            child,
            dir: dir.to_path_buf(),
            relay: RelayRef {
                relay_fp,
                onion: Onion::from_pubkey(&[0x33; 32]),
                akc: akc(&access),
                direct: Some(Direct {
                    host: Host::from_bytes(b"127.0.0.1").unwrap(),
                    port: core::num::NonZeroU16::new(port).unwrap(),
                    spki_sha256: key.pin(),
                }),
            },
            access,
            lines,
        };
        let heard = rx.recv_timeout(Duration::from_secs(60));
        assert!(
            heard.is_ok(),
            "the relay did not bind its direct listener; exit status {:?}; stderr:\n{}",
            me.child.try_wait(),
            me.lines.lock().unwrap().join("\n")
        );
        std::fs::write(me.ref_path(), me.ref_text()).unwrap();
        me
    }

    /// The relay reference file the clients are given (`relay_ref = …`, `access_key = …`).
    #[must_use]
    pub fn ref_path(&self) -> PathBuf {
        self.dir.join("relay.ref")
    }

    /// A relay reference file of the same relay without its direct endpoint (`relay-nodirect.ref`): an invitation issued
    /// from a profile that holds it is the 332-character form of §5.2 (`InvitationV1` without `direct`), and a client
    /// that holds it cannot connect over direct TLS.
    ///
    /// # Panics
    /// If the file cannot be written: a test failure.
    #[must_use]
    pub fn ref_path_without_direct(&self) -> PathBuf {
        let mut relay = self.relay.clone();
        relay.direct = None;
        let text = format!(
            "relay_ref = {}\naccess_key = {}\n",
            hex(&relay.encode().unwrap()),
            hex(self.access.expose_secret())
        );
        let path = self.dir.join("relay-nodirect.ref");
        std::fs::write(&path, text).unwrap();
        path
    }

    fn ref_text(&self) -> String {
        format!(
            "relay_ref = {}\naccess_key = {}\n",
            hex(&self.relay.encode().unwrap()),
            hex(self.access.expose_secret())
        )
    }

    /// The relay's direct TLS port: the upstream of E2-10's proxies (0 if the relay has no direct endpoint).
    #[must_use]
    pub fn direct_port(&self) -> u16 {
        self.relay.direct.as_ref().map_or(0, |d| d.port.get())
    }

    /// A relay reference file (`relay-via-<port>.ref`) of the same relay and SPKI pin at `127.0.0.1:port`; TLS still ends
    /// at the relay, so a TCP proxy on `port` sees only TLS records.
    ///
    /// # Panics
    /// If `port` is 0 or the file cannot be written: a test failure.
    #[must_use]
    pub fn ref_path_via(&self, port: u16) -> PathBuf {
        let mut relay = self.relay.clone();
        if let Some(direct) = relay.direct.as_mut() {
            direct.port = core::num::NonZeroU16::new(port).unwrap();
        }
        let text = format!(
            "relay_ref = {}\naccess_key = {}\n",
            hex(&relay.encode().unwrap()),
            hex(self.access.expose_secret())
        );
        let path = self.dir.join(format!("relay-via-{port}.ref"));
        std::fs::write(&path, text).unwrap();
        path
    }

    /// Give the profile in `profile` (created by `profile new … --relay <ref_path>`) `n` spare queues, made on the relay too
    /// — what a profile has some time after its first open (spec §10.6 (3)): the seeds are drawn and stored with
    /// `SparePool::fill`, each queue is created with a `QUEUE_NEW` on a link of its own over the direct listener.
    ///
    /// # Panics
    /// On a violated harness invariant: a test failure.
    pub fn seed_spares(&self, profile: &Path, passphrase: &[u8], n: usize, label: &str) {
        let unlocked = secmp_store::wrap::unlock(profile, passphrase).unwrap();
        let store = Profile::open_with(profile, &unlocked).unwrap().store();
        let pool = SparePool::new(store);
        let mut entropy =
            FixedEntropy::new(&EntropyPool::new(&format!("{label}-spares"), 0).bytes(1 << 20));
        pool.fill(RelayId(1), n, &mut entropy).unwrap();
        let seeds = pool.seeds(RelayId(1)).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let provider = TlsProvider::new();
            let mut link_entropy =
                FixedEntropy::new(&EntropyPool::new(&format!("{label}-links"), 0).bytes(1 << 16));
            for (_, recv, send) in &seeds {
                let stream = provider
                    .connect(&self.relay, secmp_transport::driver::Isolation(1))
                    .await
                    .unwrap();
                let unix = secmp_relay::clock::wall_clock_unix_secs();
                let mut link = AsyncRelayQueueTransport::connect(
                    stream,
                    self.relay.relay_fp,
                    Some(&self.access),
                    unix,
                    &mut link_entropy,
                )
                .await
                .unwrap();
                link.create_queue(recv, send, &self.access).await.unwrap();
            }
        });
    }
}

/// A `secmp-cli` child process: stdin lines in, stdout JSON lines out; killed when dropped.
pub struct CliProc {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    stderr: Arc<Mutex<String>>,
}

impl Drop for CliProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl CliProc {
    /// Start `bin` with `args` and `envs` (added to the inherited environment).
    ///
    /// # Panics
    /// If the process cannot start: a test failure.
    #[must_use]
    pub fn spawn(bin: &Path, args: &[&str], envs: &[(&str, &str)]) -> Self {
        let mut child = Command::new(bin)
            .args(args)
            .envs(envs.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
            {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let errors = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&errors);
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                let mut text = sink.lock().unwrap();
                text.push_str(&line);
                text.push('\n');
            }
        });
        let stdin = child.stdin.take();
        Self {
            child,
            stdin,
            lines,
            stderr: errors,
        }
    }

    /// One line to the process's stdin.
    ///
    /// # Panics
    /// If stdin is closed or the write fails: a test failure.
    pub fn send_line(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    /// Raw bytes to the process's stdin, as they are (a newline is the caller's): for lines that are not UTF-8.
    ///
    /// # Panics
    /// If stdin is closed or the write fails: a test failure.
    pub fn send_bytes(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        stdin.write_all(bytes).unwrap();
        stdin.flush().unwrap();
    }

    /// Close stdin (end of input).
    pub fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// The next stdout line parsed as JSON, within `wait`; `None` on a timeout or when the process closed stdout.
    ///
    /// # Panics
    /// On a line that is not one JSON object: a test failure (every line of the CLI is).
    pub fn next_json(&mut self, wait: Duration) -> Option<Json> {
        match self.lines.recv_timeout(wait) {
            Ok(line) => Some(parse_line(&line)),
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => None,
        }
    }

    /// The first line within `wait` (counted from now over all lines) for which `want` holds; the others are skipped and
    /// returned too, in order.
    ///
    /// # Panics
    /// On a stdout line that is not a JSON object with a `type`.
    pub fn wait_for(
        &mut self,
        within: Duration,
        want: impl Fn(&Json) -> bool,
    ) -> (Option<Json>, Vec<Json>) {
        let end = Instant::now().checked_add(within).unwrap();
        let mut skipped = Vec::new();
        loop {
            let left = end.saturating_duration_since(Instant::now());
            match self.next_json(left) {
                Some(line) if want(&line) => return (Some(line), skipped),
                Some(line) => skipped.push(line),
                None => return (None, skipped),
            }
        }
    }

    /// Wait for the process to end within `wait`.
    ///
    /// # Panics
    /// If `wait` overflows the clock: a test failure.
    pub fn wait_exit(&mut self, wait: Duration) -> Option<ExitStatus> {
        let end = Instant::now().checked_add(wait).unwrap();
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Some(status);
            }
            if Instant::now() >= end {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Everything the process wrote to stderr so far.
    ///
    /// # Panics
    /// If the collecting thread panicked: a test failure.
    #[must_use]
    pub fn stderr_text(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    /// Kill the process (SIGKILL) and wait for it.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
