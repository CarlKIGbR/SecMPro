// SPDX-License-Identifier: AGPL-3.0-or-later
//! `ks_cli` — E2-10, the activity independence of the CLI host in real time (TEST-SPEC-M7 E2-10; spec §10.1, §10.2,
//! §10.6 (1); AI-07's method, R3; Q293).
//!
//! Two real `secmp-cli open --direct` processes (Balanced, spec §10.2) on one real `secmp-relay`, each through its own
//! recording TCP proxy (TLS ends at the relay; the proxy sees records only). After the invitation, 240 s settle (longer than
//! the 180 s link offset of §10.6 (1)), an idle phase with no stdin line, then an active phase: sends, bursts, `status`,
//! `contacts list`, `contacts sas` and Argon2id `export`s (the R3 load). The client-to-relay reads of every connection,
//! idle phase against active phase, go through the two-sample KS test of [`secmp_testkit::ks`] (`p ≥ 0.01`, one link per
//! client), no other connection of a client may carry more than a control operation (no torn link), every call is answered,
//! every message arrives and both processes exit 0. `D`, `p`, `n` and the SHA-256 of the reads analysed are written to
//! `<out-dir>/e2e-10.txt` and printed. No text, id, key or digit string is written.
//!
//! ```text
//! ks_cli <out-dir> [<idle-s> [<active-s>]]
//! ```
//!
//! `idle-s` and `active-s` default to 1 800; shorter values are a smoke run (not judged, exit 3). Exit 0: criterion met,
//! 1: not met; a violated harness invariant panics (101).
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use secmp_testkit::harness::EntropyPool;
use secmp_testkit::harness::e2e::{CliProc, E2eRelay, Json, cli_bin, write_secret_file};
use secmp_testkit::ks::{self, Frame};

/// The profile passphrase.
const PASS: &[u8] = b"correct horse\n";
/// The passphrase of the exported backups.
const BACKUP: &[u8] = b"backup horse\n";
/// One wait of the set-up (as the harness tests).
const ROW: Duration = Duration::from_secs(600);
/// The settle time after the invitation: longer than the 180 s link offset of §10.6 (1).
const SETTLE_MS: u64 = 240_000;
/// How long the drain after the active phase may take.
const DRAIN: Duration = Duration::from_secs(600);
/// The fewest reads of a link slot in a full run.
const MIN_READS: usize = 100;
/// The fewest reads of a link slot in a smoke run.
const SMOKE_READS: usize = 5;
/// The most departures of a connection that is not the link (a control operation, spec §10.6).
const CONTROL_MAX: u64 = 3;
/// The full run's phase length in seconds.
const FULL_S: u64 = 1_800;

/// Milliseconds since `t0`.
fn ms(t0: Instant) -> u64 {
    u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Copy both directions of `down` and `up`; every read of the client side is recorded as `(ms, slot, bytes)`.
fn pipe(down: TcpStream, up: TcpStream, slot: u64, t0: Instant, reads: Arc<Mutex<Vec<Frame>>>) {
    let (Ok(mut down_r), Ok(mut up_w)) = (down.try_clone(), up.try_clone()) else {
        return;
    };
    std::thread::spawn(move || {
        let mut buf = vec![0_u8; 65_536];
        loop {
            let n = match down_r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            reads.lock().unwrap().push((ms(t0), slot, n));
            if up_w.write_all(buf.get(..n).unwrap_or_default()).is_err() {
                break;
            }
        }
        let _ = up_w.shutdown(Shutdown::Write);
    });
    std::thread::spawn(move || {
        let (mut up_r, mut down_w) = (up, down);
        let _ = std::io::copy(&mut up_r, &mut down_w);
        let _ = down_w.shutdown(Shutdown::Write);
    });
}

/// A recording TCP proxy of `client` to `127.0.0.1:upstream`; the slot of a connection is `client × 1000 + n`. Returns the
/// local port.
fn proxy(client: u64, upstream: u16, t0: Instant, reads: Arc<Mutex<Vec<Frame>>>) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut n = 0_u64;
        for down in listener.incoming().map_while(Result::ok) {
            n = n.saturating_add(1);
            let slot = client.saturating_mul(1_000).saturating_add(n);
            let Ok(up) = TcpStream::connect(("127.0.0.1", upstream)) else {
                continue;
            };
            let _ = down.set_nodelay(true);
            let _ = up.set_nodelay(true);
            pipe(down, up, slot, t0, Arc::clone(&reads));
        }
    });
    port
}

/// The `type` of a line.
fn kind(v: &Json) -> String {
    text(v, "type")
}

/// The string field `key` of `v`.
fn text(v: &Json, key: &str) -> String {
    v.get(key)
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// The first line of kind `want` within `within`.
fn expect(p: &mut CliProc, within: Duration, want: &str) -> Json {
    let (found, skipped) = p.wait_for(within, |v| kind(v) == want);
    assert!(
        found.is_some(),
        "no `{want}` within {within:?}; saw {skipped:?}; stderr: {}",
        p.stderr_text()
    );
    found.unwrap()
}

/// `profile new` of `name` under `root` with the relay reference `relay`: the profile directory and its passphrase file.
fn profile(bin: &Path, root: &Path, name: &str, relay: &Path) -> (String, String) {
    let dir = root.join(name).display().to_string();
    let pass = root.join(format!("{name}.pass"));
    write_secret_file(&pass, PASS);
    let pass = pass.display().to_string();
    let out = std::process::Command::new(bin)
        .args(["profile", "new", &dir, "--passphrase-file", &pass])
        .args(["--relay", &relay.display().to_string()])
        .output()
        .unwrap();
    assert!(out.status.success(), "profile new {name}: {:?}", out.status);
    (dir, pass)
}

/// `secmp-cli open --direct` of the profile.
fn open(bin: &Path, (dir, pass): &(String, String), name: &str) -> CliProc {
    CliProc::spawn(
        bin,
        &[
            "open",
            dir,
            "--passphrase-file",
            pass,
            "--direct",
            "--name",
            name,
        ],
        &[],
    )
}

/// `invite accept <uri>` until the contact appears (an `error/invitation` before the link data is on the relay is sent
/// again after 2 s).
fn accept(p: &mut CliProc, uri: &str, end: Instant) -> Json {
    while Instant::now() < end {
        p.send_line(&format!("invite accept {uri}"));
        let within = end.saturating_duration_since(Instant::now());
        let (found, _) = p.wait_for(within, |v| kind(v) == "contact" || kind(v) == "error");
        let line = found.expect("an answer to the accept");
        if kind(&line) == "contact" {
            return line;
        }
        assert_eq!(text(&line, "code"), "invitation", "{line:?}");
        std::thread::sleep(Duration::from_secs(2));
    }
    Json::Null
}

/// One CLI process, what it was asked and what it answered.
struct Side {
    /// The process.
    p: CliProc,
    /// The contact id of the other side.
    peer: u64,
    /// `send`s issued.
    sends: u64,
    /// Calls issued (`status`, `contacts …`, `export`).
    calls: u64,
    /// `queued` lines seen.
    queued: u64,
    /// Answers to calls seen.
    answered: u64,
    /// Messages of the peer printed.
    received: u64,
    /// The codes of `error` lines.
    errors: Vec<String>,
    /// The exit code after `quit`.
    exit: Option<i32>,
}

impl Side {
    /// A side over `p` talking to contact `peer`.
    const fn new(p: CliProc, peer: u64) -> Self {
        Self {
            p,
            peer,
            sends: 0,
            calls: 0,
            queued: 0,
            answered: 0,
            received: 0,
            errors: Vec::new(),
            exit: None,
        }
    }

    /// Count one line.
    fn take(&mut self, v: &Json) {
        match kind(v).as_str() {
            "queued" => self.queued = self.queued.saturating_add(1),
            "message" if v.get("contact").and_then(Json::as_u64) == Some(self.peer) => {
                self.received = self.received.saturating_add(1);
            }
            "status" | "contacts" | "sas" | "exported" => {
                self.answered = self.answered.saturating_add(1);
            }
            "error" => self.errors.push(text(v, "code")),
            _ => {}
        }
    }

    /// Read every pending line.
    fn pump(&mut self) {
        while let Some(v) = self.p.next_json(Duration::ZERO) {
            self.take(&v);
        }
    }

    /// `quit`, the `closed` line, the exit code.
    fn finish(&mut self) {
        self.p.send_line("quit");
        let (found, skipped) = self
            .p
            .wait_for(Duration::from_secs(60), |v| kind(v) == "closed");
        for v in &skipped {
            self.take(v);
        }
        assert!(
            found.is_some(),
            "no `closed`; stderr: {}",
            self.p.stderr_text()
        );
        self.exit = self
            .p
            .wait_exit(Duration::from_secs(60))
            .and_then(|s| s.code());
    }

    /// Whether everything asked was answered.
    const fn settled(&self) -> bool {
        self.queued == self.sends && self.answered == self.calls
    }
}

/// Pump both sides until `at_ms` after `t0`.
fn wait_until(t0: Instant, at_ms: u64, sides: &mut [Side]) {
    loop {
        for s in sides.iter_mut() {
            s.pump();
        }
        let now = ms(t0);
        if now >= at_ms {
            return;
        }
        std::thread::sleep(Duration::from_millis(at_ms.saturating_sub(now).min(1_000)));
    }
}

/// The two processes, the relay and what the proxies recorded. Field order is drop order: processes first.
struct Run {
    /// Alice (client 0) and bob (client 1).
    sides: Vec<Side>,
    /// The relay.
    _relay: E2eRelay,
    /// The run directory.
    root: PathBuf,
    /// The start of the time axis.
    t0: Instant,
    /// The client-to-relay reads of both proxies.
    reads: Arc<Mutex<Vec<Frame>>>,
    /// When both had the contact.
    ready: u64,
}

/// The relay, the proxies, two profiles opened and one invitation accepted.
fn setup(out: &Path) -> Run {
    let root = out.join("run");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let relay = E2eRelay::start(&root.join("relay"));
    let bin = cli_bin(&root.join("bin"));
    write_secret_file(&root.join("backup.pass"), BACKUP);
    let t0 = Instant::now();
    let reads = Arc::new(Mutex::new(Vec::new()));
    let pass = PASS.strip_suffix(b"\n").unwrap();
    let mut procs = Vec::new();
    for (client, (name, label)) in [("alice", "e210-a"), ("bob", "e210-b")]
        .into_iter()
        .enumerate()
    {
        let port = proxy(
            u64::try_from(client).unwrap(),
            relay.direct_port(),
            t0,
            Arc::clone(&reads),
        );
        let prof = profile(&bin, &root, name, &relay.ref_path_via(port));
        relay.seed_spares(Path::new(&prof.0), pass, 2, label);
        procs.push(open(&bin, &prof, name));
    }
    let mut it = procs.into_iter();
    let (mut a, mut b) = (it.next().unwrap(), it.next().unwrap());
    expect(&mut a, ROW, "opened");
    expect(&mut b, ROW, "opened");
    a.send_line("invite create");
    let uri = text(&expect(&mut a, ROW, "invitation"), "uri");
    let contact = accept(&mut b, &uri, Instant::now().checked_add(ROW).unwrap());
    let b_of_a = contact.get("id").and_then(Json::as_u64).unwrap();
    let a_of_b = expect(&mut a, ROW, "contact")
        .get("id")
        .and_then(Json::as_u64)
        .unwrap();
    Run {
        sides: vec![Side::new(a, a_of_b), Side::new(b, b_of_a)],
        _relay: relay,
        root,
        t0,
        reads,
        ready: ms(t0),
    }
}

/// One scheduled line: offset in the active phase (ms), the side, the line, whether it is a `send`.
type Entry = (u64, usize, String, bool);

/// The offsets `first + step × k` below `limit`, at most `max` of them.
fn every(first: u64, step: u64, limit: u64, max: u64) -> impl Iterator<Item = u64> {
    (0..max)
        .map(move |k| step.saturating_mul(k).saturating_add(first))
        .take_while(move |o| *o < limit)
}

/// A text of `16 + 3 r` bytes: the stamp of side `s` and send `k`, padded by a letter chosen by the draw `r`.
fn send_text(s: u64, k: u64, r: u8) -> String {
    let mut t = format!("e210-{s}-{k:03}-");
    let pad = char::from(b'a'.saturating_add(r.checked_rem(26).unwrap_or(0)));
    let len = 16_usize.saturating_add(usize::from(r).saturating_mul(3));
    while t.len() < len {
        t.push(pad);
    }
    t
}

/// The active phase's lines of both sides, sorted by offset (Q293: 90 sends per side, `status`, `contacts list`, `contacts
/// sas`, three `export`s).
fn plan(root: &Path, peers: [u64; 2], active_ms: u64) -> Vec<Entry> {
    let mut pool = EntropyPool::new("m7-e2e-10", 0);
    let mut draws = pool.bytes(1_024).into_iter();
    let mut out: Vec<Entry> = Vec::new();
    for (side, peer) in peers.into_iter().enumerate() {
        let s = u64::try_from(side).unwrap();
        let d = 7_000_u64.saturating_mul(s);
        let mut k = 0_u64;
        let mut offsets: Vec<u64> = every(d, 30_000, active_ms, 60).collect();
        for j in 0..3_u64 {
            let at = 600_000_u64
                .saturating_mul(j)
                .saturating_add(100_000_u64.saturating_add(d));
            if at < active_ms {
                offsets.extend(core::iter::repeat_n(at, 10));
            }
        }
        for at in offsets {
            let line = format!("send {peer} {}", send_text(s, k, draws.next().unwrap()));
            out.push((at, side, line, true));
            k = k.saturating_add(1);
        }
        let mut call = |at: u64, line: String| out.push((at, side, line, false));
        for at in every(5_000_u64.saturating_add(d), 60_000, active_ms, 1_000) {
            call(at, "status".to_owned());
        }
        for at in every(20_000_u64.saturating_add(d), 60_000, active_ms, 1_000) {
            call(at, "contacts list".to_owned());
        }
        for at in every(40_000_u64.saturating_add(d), 300_000, active_ms, 1_000) {
            call(at, format!("contacts sas {peer}"));
        }
        for (n, at) in every(50_000_u64.saturating_add(d), 600_000, active_ms, 3).enumerate() {
            let r = root.display();
            call(
                at,
                format!(
                    "export {r}/export-{s}-{n}.smpb --backup-passphrase-file {r}/backup.pass --confirm"
                ),
            );
        }
    }
    out.sort_by_key(|e| (e.0, e.1));
    out
}

/// Issue the plan at `split + offset`, wait for `end`, drain, `quit`.
fn drive(run: &mut Run, split: u64, end: u64, entries: Vec<Entry>) {
    for (offset, side, line, is_send) in entries {
        wait_until(run.t0, split.saturating_add(offset), &mut run.sides);
        let s = run.sides.get_mut(side).unwrap();
        s.p.send_line(&line);
        if is_send {
            s.sends = s.sends.saturating_add(1);
        } else {
            s.calls = s.calls.saturating_add(1);
        }
    }
    wait_until(run.t0, end, &mut run.sides);
    let deadline = Instant::now().checked_add(DRAIN).unwrap();
    loop {
        wait_until(run.t0, ms(run.t0).saturating_add(10_000), &mut run.sides);
        let (a, b) = (run.sides.first().unwrap(), run.sides.get(1).unwrap());
        let done = a.settled() && b.settled() && a.received == b.queued && b.received == a.queued;
        if done || Instant::now() >= deadline {
            break;
        }
    }
    for s in &mut run.sides {
        s.finish();
    }
}

/// The phase boundaries on the time axis (ms).
struct Window {
    /// Reads before this are the settle phase.
    idle_start: u64,
    /// The end of the idle phase, the start of the active one.
    split: u64,
    /// The end of the active phase.
    end: u64,
}

/// The median of `v`.
fn median(v: &[u64]) -> u64 {
    let mut v = v.to_vec();
    v.sort_unstable();
    v.get(v.len() / 2).copied().unwrap_or(0)
}

/// The `link` lines: every slot with gaps in both phases and a two-sample result; per client the slots and their `p`.
fn links(
    units: &[Frame],
    w: &Window,
    min: usize,
    out: &mut Vec<String>,
) -> BTreeMap<u64, Vec<(u64, f64)>> {
    let mut found: BTreeMap<u64, Vec<(u64, f64)>> = BTreeMap::new();
    for (slot, samples) in ks::gaps(units, w.split, min) {
        let Some(k) = ks::two_sample(&samples.idle, &samples.active) else {
            continue;
        };
        let client = slot.checked_div(1_000).unwrap_or(0);
        out.push(format!(
            "link {slot} (client {client}): D = {:.6}, p = {:.6}, n_idle = {}, n_active = {}, median gap idle {} ms, active {} ms",
            k.d,
            k.p,
            k.n1,
            k.n2,
            median(&samples.idle),
            median(&samples.active)
        ));
        found.entry(client).or_default().push((slot, k.p));
    }
    found
}

/// The `connection` lines of every slot with a read in the window; whether every connection that is not the analysed link
/// of its client has at most [`CONTROL_MAX`] departures (no torn link).
fn connections(
    reads: &[Frame],
    w: &Window,
    found: &BTreeMap<u64, Vec<(u64, f64)>>,
    out: &mut Vec<String>,
) -> bool {
    let mut by_slot: BTreeMap<u64, Vec<(u64, usize)>> = BTreeMap::new();
    for (t, slot, n) in reads {
        if *t >= w.idle_start && *t <= w.end {
            by_slot.entry(*slot).or_default().push((*t, *n));
        }
    }
    let mut ok = true;
    for (slot, mut rs) in by_slot {
        rs.sort_unstable();
        let mut departures = 0_u64;
        let mut prev: Option<u64> = None;
        let mut bytes = 0_usize;
        for (t, n) in &rs {
            if prev.is_none_or(|p| t.saturating_sub(p) >= ks::SAME_SLOT_MS) {
                departures = departures.saturating_add(1);
            }
            prev = Some(*t);
            bytes = bytes.saturating_add(*n);
        }
        let client = slot.checked_div(1_000).unwrap_or(0);
        out.push(format!(
            "connection {slot} (client {client}): first {} ms, last {} ms, {departures} departures, {bytes} bytes",
            rs.first().map_or(0, |r| r.0),
            rs.last().map_or(0, |r| r.0),
        ));
        let is_link = found
            .get(&client)
            .is_some_and(|l| l.iter().any(|(s, _)| *s == slot));
        if !is_link && departures > CONTROL_MAX {
            ok = false;
        }
    }
    ok
}

/// The `client` lines; whether every side did and got what it should and exited 0.
fn sides_lines(sides: &[Side], out: &mut Vec<String>) -> bool {
    let mut ok = true;
    for (i, s) in sides.iter().enumerate() {
        let peer_queued = sides.get(usize::from(i == 0)).map_or(0, |p| p.queued);
        out.push(format!(
            "client {i}: sends {}, queued {}, received from the peer {}, calls {}, answered {}, errors {:?}, exit {:?}",
            s.sends, s.queued, s.received, s.calls, s.answered, s.errors, s.exit
        ));
        ok &= s.settled() && s.received == peer_queued && s.errors.is_empty() && s.exit == Some(0);
    }
    ok
}

/// The whole text of the evidence and the verdict: `Some(met)` in a full run, `None` in a smoke run.
fn analyse(
    reads: &[Frame],
    w: &Window,
    sides: &[Side],
    full: bool,
    shape: (u64, u64),
) -> (Vec<String>, Option<bool>) {
    let mut out = vec![format!(
        "ks-cli: idle {} s, active {} s, settle {} s, 2 secmp-cli processes (Balanced, direct mode, spec §10.2), P = 10 s, each through its own recording TCP proxy (TLS end to end; one read is one unit); a departure is reads less than {} ms apart; the trace is cut on departure boundaries at the end of the active phase",
        shape.0,
        shape.1,
        SETTLE_MS.saturating_div(1_000),
        ks::SAME_SLOT_MS
    )];
    let units: Vec<Frame> = reads
        .iter()
        .filter(|r| r.0 >= w.idle_start)
        .map(|r| (r.0, r.1, ks::FRAME))
        .collect();
    let mut units = ks::cut_at(&units, w.end);
    let min = if full { MIN_READS } else { SMOKE_READS };
    let found = links(&units, w, min, &mut out);
    let no_torn = connections(reads, w, &found, &mut out);
    let sides_ok = sides_lines(sides, &mut out);
    units.sort_unstable();
    let mut input = String::new();
    for (t, slot, len) in &units {
        let _ = writeln!(input, "{t} {slot} {len}");
    }
    let hex = secmp_crypto::sha256(&[input.as_bytes()])
        .iter()
        .fold(String::new(), |mut h, b| {
            let _ = write!(h, "{b:02x}");
            h
        });
    out.push(format!("reads analysed: {}, sha256 {hex}", units.len()));
    let one_link = (0..2_u64).all(|c| {
        found
            .get(&c)
            .is_some_and(|l| l.len() == 1 && l.iter().all(|(_, p)| *p >= 0.01))
    });
    let met = one_link && no_torn && sides_ok;
    let verdict = match (full, met) {
        (false, _) => "NOT JUDGED (smoke)",
        (true, true) => "MET",
        (true, false) => "NOT MET",
    };
    out.push(format!(
        "criterion (p >= 0.01 on exactly one link per client, no torn link: at most {CONTROL_MAX} departures on every other connection, every call answered and every message received, exits 0): {verdict}"
    ));
    (out, full.then_some(met))
}

/// The run: set-up, phases, analysis, evidence file.
fn run(out_dir: &Path, idle_s: u64, active_s: u64) -> ExitCode {
    let full = idle_s >= FULL_S && active_s >= FULL_S;
    std::fs::create_dir_all(out_dir).unwrap();
    let mut run = setup(out_dir);
    let idle_start = run.ready.saturating_add(SETTLE_MS);
    let split = idle_start.saturating_add(idle_s.saturating_mul(1_000));
    let end = split.saturating_add(active_s.saturating_mul(1_000));
    let peers = [
        run.sides.first().unwrap().peer,
        run.sides.get(1).unwrap().peer,
    ];
    let entries = plan(&run.root, peers, active_s.saturating_mul(1_000));
    wait_until(run.t0, split, &mut run.sides);
    drive(&mut run, split, end, entries);
    let reads = run.reads.lock().unwrap().clone();
    let w = Window {
        idle_start,
        split,
        end,
    };
    let (lines, verdict) = analyse(&reads, &w, &run.sides, full, (idle_s, active_s));
    let shown = lines.join("\n") + "\n";
    let _ = write!(std::io::stdout().lock(), "{shown}");
    std::fs::write(out_dir.join("e2e-10.txt"), shown).unwrap();
    drop(run);
    match verdict {
        Some(true) => ExitCode::SUCCESS,
        Some(false) => ExitCode::from(1),
        None => ExitCode::from(3),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(out_dir) = args.first() else {
        let _ = writeln!(
            std::io::stderr(),
            "usage: ks_cli <out-dir> [<idle-s> [<active-s>]]"
        );
        return ExitCode::from(2);
    };
    let number = |i: usize| args.get(i).map_or(Some(FULL_S), |s| s.parse::<u64>().ok());
    let (Some(idle), Some(active)) = (number(1), number(2)) else {
        let _ = writeln!(std::io::stderr(), "ks_cli: the durations are whole seconds");
        return ExitCode::from(2);
    };
    // absolute: the relay is started with its own directory as the working directory, and its binary path must survive that
    let out_dir = std::path::absolute(PathBuf::from(out_dir)).unwrap();
    run(&out_dir, idle, active)
}
