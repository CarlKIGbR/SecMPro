// SPDX-License-Identifier: AGPL-3.0-or-later
//! Relay obligations of the process (TEST-SPEC-M5 (b5)): no file written after the start (RL-02; spec §9.7 item 1,
//! `docs/02` §5.1), no per-request report (RL-03; §9.7 item 2, OPEN-M5-08 A), and the configuration that controls
//! the start and the limits in effect (RL-23; `docs/07:105`).
//!
//! RL-02 and RL-03 run the scenario of H-03 (Phase C's harness does not exist yet) through two `Connection`s, as
//! the server feeds them: two queues, cells each way over two links, FETCH with a cumulative ack, `LINK_PUT`, owner
//! status and consume — with the OPEN-M5-02 limits on and a virtual clock. No network (`docs/06` §4): RL-02 runs the
//! relay in a child process of this test binary inside an empty directory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use secmp_proto::tr::OsEntropy;
use secmp_proto::wire::frame::Request;
use secmp_relay::budget::BudgetLimits;
use secmp_relay::event::{EVENT_NAMES, Event, NullSink};
use secmp_relay::keys::{DEFAULT_VALIDITY_SECS, KeyFile};
use secmp_relay::rate::RateLimit;
use secmp_relay::relay::kat::StoreSnapshot;
use secmp_relay::{Connection, Error, KeyRing, Limits, Now, Output, Relay, server};

use crate::fixture::{
    Client, EXPIRES, FRAME, HELLO, Key, NOW, RelayFx, VALID_UNTIL, hex, now, rid_of, sid_of,
};
use crate::rl_util::{
    BLOB, CELL, Seq, V, Wire, add, capture, code, distinct_bytes, flags, fresh_dir, identity,
    key_file, linkr, names, one_time, pair, presents, relay_sources, times,
};

// ---------------------------------------------------------------------------------------------------------------
// The H-03 scenario.

/// The virtual clock of the scenario: one second per request (the per-link rate of OPEN-M5-02 refills one frame
/// per second), the wall clock moving with it.
struct Clock {
    ms: u64,
}

impl Clock {
    const fn new() -> Self {
        Self { ms: 0 }
    }

    fn tick(&mut self) -> Now {
        self.ms = add(self.ms, 1000);
        Now {
            unix_secs: add(NOW, self.ms.checked_div(1000).unwrap()),
            mono_ms: self.ms,
        }
    }
}

/// Every value of the scenario a per-request report could carry.
#[derive(Default)]
struct Trail {
    /// Ids, keys, seeds, tokens, `sess_id`s, link keys, cell and blob prefixes.
    bytes: Vec<Vec<u8>>,
    /// `cmd_seq`s and `cell_id`s.
    numbers: Vec<u64>,
}

/// A cell of the scenario: `u64be(i)`, then `tag`.
fn cell(tag: u8, i: u64) -> Vec<u8> {
    let mut c = vec![tag; CELL];
    c.get_mut(..8).unwrap().copy_from_slice(&i.to_be_bytes());
    c
}

/// One client of the scenario: its link and the cells it fetched.
struct Peer<'r> {
    w: Wire<'r>,
    got: Vec<(u64, Vec<u8>)>,
}

impl<'r> Peer<'r> {
    fn connect(relay: &'r Relay, clock: &mut Clock, seq: Seq) -> Self {
        let (fp, access) = identity(relay);
        let mut w = Wire::connect(
            relay,
            fp,
            &access,
            clock.tick(),
            &mut OsEntropy,
            &mut OsEntropy,
        );
        w.seq = seq;
        Self { w, got: Vec::new() }
    }

    /// Run a request built for the next `cmd_seq` (recorded in `trail`) at the next tick.
    fn go(
        &mut self,
        clock: &mut Clock,
        trail: &mut Trail,
        build: impl FnOnce(&Client, u32) -> Request,
    ) -> (u32, Vec<V>) {
        let mut used = 0;
        let frames = self.w.go(clock.tick(), &mut OsEntropy, |c, s| {
            used = s;
            build(c, s)
        });
        trail.numbers.push(u64::from(used));
        (used, frames)
    }

    /// FETCH of `recv`'s queue with the cumulative ack of everything received so far; how many cells came.
    fn fetch(&mut self, clock: &mut Clock, trail: &mut Trail, recv: &Key) -> usize {
        let ack = self.got.last().map_or(0, |(id, _)| *id);
        let (_, frames) = self.go(clock, trail, |c, s| c.fetch(s, recv, ack));
        let before = self.got.len();
        for v in frames {
            if let V::Cellr(1, _, id, cell) = v {
                self.got.push((id, cell));
            }
        }
        self.got.len().checked_sub(before).unwrap()
    }
}

/// The scenario of H-03 with `n` cells each way (module documentation); returns its trail.
fn h03(relay: &Relay, n: u64, clock: &mut Clock) -> Trail {
    let mut trail = Trail::default();
    let (qa, qb, owner) = (pair(0xa1, 0xa2), pair(0xb1, 0xb2), Key::of(0xc1));
    // A receives on qa and sends on qb; B the other way round
    let mut a = Peer::connect(relay, clock, Seq::starting(1_000_003, 3));
    let mut b = Peer::connect(relay, clock, Seq::starting(2_000_005, 5));
    for (p, (r, s)) in [(&mut a, &qa), (&mut b, &qb)] {
        let (seq, frames) = p.go(clock, &mut trail, |c, x| c.queue_new(x, r, s));
        assert_eq!(
            frames,
            vec![V::QueueNew(rid_of(&r.pk), sid_of(&r.pk, &s.pk))]
        );
        trail.bytes.push(p.w.client.token(seq).to_vec());
    }
    for i in 1..=n {
        let (_, sent) = a.go(clock, &mut trail, |c, x| {
            c.send(x, &qb.0, &qb.1, &cell(0xab, i))
        });
        assert_eq!(sent, vec![V::Send(i, None)], "A's cell {i}");
        let (_, sent) = b.go(clock, &mut trail, |c, x| {
            c.send(x, &qa.0, &qa.1, &cell(0xba, i))
        });
        assert_eq!(sent, vec![V::Send(i, None)], "B's cell {i}");
        if i.is_multiple_of(4) {
            a.fetch(clock, &mut trail, &qa.0);
            b.fetch(clock, &mut trail, &qb.0);
        }
    }
    let count = |p: &Peer<'_>| u64::try_from(p.got.len()).unwrap();
    while count(&a) < n || count(&b) < n {
        a.fetch(clock, &mut trail, &qa.0);
        b.fetch(clock, &mut trail, &qb.0);
    }
    // the last cumulative ack deletes everything delivered
    assert_eq!(a.fetch(clock, &mut trail, &qa.0), 0, "A has everything");
    assert_eq!(b.fetch(clock, &mut trail, &qb.0), 0, "B has everything");
    let expected = |tag| (1..=n).map(|i| (i, cell(tag, i))).collect::<Vec<_>>();
    assert_eq!(a.got, expected(0xba), "A received B's {n} cells in order");
    assert_eq!(b.got, expected(0xab), "B received A's {n} cells in order");
    let (ld_id, blob) = ([0xd1; 16], distinct_bytes(0xd1, BLOB));
    let put_seq = a.w.seq.peek();
    let put = a.w.put(
        clock.tick(),
        &mut OsEntropy,
        &one_time(&ld_id, EXPIRES, &owner, &blob),
    );
    assert_eq!(put, vec![V::Ok], "LINK_PUT");
    trail.numbers.push(u64::from(put_seq));
    trail.bytes.push(a.w.client.token(put_seq).to_vec());
    let status = |p: &mut Peer<'_>, clock: &mut Clock, trail: &mut Trail| {
        flags(
            &p.go(clock, trail, |c, x| c.link_get_owner(x, &ld_id, &owner))
                .1,
        )
    };
    assert_eq!(
        status(&mut a, clock, &mut trail),
        (true, false),
        "owner status"
    );
    let (_, got) = b.go(clock, &mut trail, |_, x| {
        Client::link_get_consume(x, &ld_id)
    });
    assert_eq!(
        linkr(&got),
        (true, false, blob.clone()),
        "the consume returns the blob"
    );
    let (_, got) = b.go(clock, &mut trail, |_, x| {
        Client::link_get_consume(x, &ld_id)
    });
    assert_eq!(flags(&got), (false, true), "consumed");
    assert_eq!(
        status(&mut a, clock, &mut trail),
        (false, true),
        "owner status: consumed"
    );
    assert_eq!(
        b.go(clock, &mut trail, |c, x| c.queue_del(x, &qb.0)).1,
        vec![V::Ok]
    );
    assert_eq!(
        a.go(clock, &mut trail, |_, x| Client::ping(x)).1,
        vec![V::Ok]
    );
    record(&mut trail, &[&qa, &qb], &owner, &[&a, &b]);
    trail.bytes.push(ld_id.to_vec());
    trail.bytes.push(blob.get(..32).unwrap().to_vec());
    for i in 1..=n {
        trail.numbers.push(i);
        for tag in [0xab, 0xba] {
            trail.bytes.push(cell(tag, i).get(..16).unwrap().to_vec());
        }
    }
    trail
}

/// The keys, seeds, ids, `sess_id`s and link keys of the scenario.
fn record(trail: &mut Trail, queues: &[&(Key, Key)], owner: &Key, peers: &[&Peer<'_>]) {
    for (r, s) in queues.iter().map(|q| (&q.0, &q.1)) {
        trail.bytes.push(rid_of(&r.pk).to_vec());
        trail.bytes.push(sid_of(&r.pk, &s.pk).to_vec());
    }
    let keys = queues.iter().flat_map(|q| [&q.0, &q.1]).chain([owner]);
    for k in keys {
        trail.bytes.push(k.pk.as_bytes().to_vec());
    }
    for seed in [0xa1, 0xa2, 0xb1, 0xb2, 0xc1] {
        trail.bytes.push(vec![seed; 32]);
    }
    for p in peers {
        trail.bytes.push(p.w.client.sess_id().to_vec());
        let (k_send, k_recv) = p.w.client.link.keys_kat();
        trail.bytes.push(k_send.to_vec());
        trail.bytes.push(k_recv.to_vec());
    }
}

// ---------------------------------------------------------------------------------------------------------------
// RL-02.

/// The environment variable that marks the child process of RL-02.
const CHILD: &str = "SECMP_RL02_CHILD";
/// The configuration of RL-02's relay (relative to the child's working directory).
const RL02_CONFIG: &str =
    "[listen]\ntor_loopback = \"127.0.0.1:7443\"\n[access]\nkey_file = \"relay-keys\"\n";
/// Cells each way in RL-02's scenario.
const RL02_CELLS: u64 = 1000;

/// Name, kind, size and modification time of every entry under `root`, `root` itself included.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, (bool, u64, SystemTime)> {
    let mut out = BTreeMap::new();
    let mut todo = vec![root.to_path_buf()];
    while let Some(dir) = todo.pop() {
        let meta = std::fs::metadata(&dir).unwrap();
        let rel = dir.strip_prefix(root).unwrap().to_path_buf();
        out.insert(rel, (true, meta.len(), meta.modified().unwrap()));
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                todo.push(path);
            } else {
                let rel = path.strip_prefix(root).unwrap().to_path_buf();
                out.insert(rel, (false, meta.len(), meta.modified().unwrap()));
            }
        }
    }
    out
}

/// RL-02 `relay_writes_no_file_after_start`: a relay started from its configuration and key file in an empty
/// directory (working directory, `TMPDIR` and `HOME`) runs the H-03 scenario — two links, queues, cells each way,
/// FETCH, `LINK_PUT`, owner status, consume, `QUEUE_DEL`, a teardown, the sweeper across every TTL, the drain — and
/// no file is created or modified (spec §9.7 item 1; `docs/02` §5.1). The relay runs in a child process of this
/// test binary (re-executed with `--exact`, marked by `SECMP_RL02_CHILD`); the parent compares the directory before
/// and after.
#[test]
fn relay_writes_no_file_after_start() {
    if std::env::var_os(CHILD).is_some() {
        rl02_child();
        return;
    }
    let dir = fresh_dir("rl02");
    key_file(&dir, DEFAULT_VALIDITY_SECS);
    std::fs::write(dir.join("relay.toml"), RL02_CONFIG).unwrap();
    let before = snapshot(&dir);
    let (_, module) = module_path!().split_once("::").unwrap();
    let name = format!("{module}::relay_writes_no_file_after_start");
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            name.as_str(),
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(CHILD, "1")
        .env("HOME", &dir)
        .env("TMPDIR", &dir)
        .current_dir(&dir)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "RL-02: the child passes: {stdout} {stderr}"
    );
    assert!(
        stdout.contains("test result: ok. 1 passed"),
        "RL-02: the child ran the scenario: {stdout}"
    );
    assert_eq!(
        snapshot(&dir),
        before,
        "RL-02: no file created or modified after the start"
    );
    std::fs::write(dir.join("probe"), b"x").unwrap();
    assert_ne!(
        snapshot(&dir),
        before,
        "RL-02: positive control, the comparison sees a new file"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The child of RL-02: start, the scenario, a teardown, the sweeper, the drain.
fn rl02_child() {
    let start = now();
    let (_, relay) = server::prepare(Path::new("relay.toml"), Box::new(NullSink), start).unwrap();
    let mut clock = Clock::new();
    let trail = h03(&relay, RL02_CELLS, &mut clock);
    assert!(!trail.numbers.is_empty());
    let (fp, access) = identity(&relay);
    let mut w = Wire::connect(
        &relay,
        fp,
        &access,
        clock.tick(),
        &mut OsEntropy,
        &mut OsEntropy,
    );
    let torn = w.conn.on_bytes(&[0; FRAME], clock.tick(), &mut OsEntropy);
    assert_eq!(
        torn,
        Output {
            bytes: Vec::new(),
            close: true
        },
        "a teardown"
    );
    for hours in [169, 721, 1442] {
        relay.tick(Now {
            unix_secs: add(NOW, times(hours, 3600)),
            mono_ms: add(clock.ms, times(hours, 3_600_000)),
        });
    }
    assert_eq!(
        relay.snapshot_kat(),
        StoreSnapshot::default(),
        "the sweeper emptied the store"
    );
    let drain = clock.tick();
    relay.start_drain(drain);
    assert!(relay.drain_finished(Now {
        unix_secs: add(drain.unix_secs, 60),
        mono_ms: add(drain.mono_ms, 60_000),
    }));
}

// ---------------------------------------------------------------------------------------------------------------
// RL-03.

/// `expect::RELAY_TRACE_ALLOW`, read from `xtask/src/expect.rs` as text.
fn trace_allow() -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../xtask/src/expect.rs");
    let text = std::fs::read_to_string(path).unwrap();
    let start = text
        .find("RELAY_TRACE_ALLOW: &[&str] = &[")
        .expect("expect::RELAY_TRACE_ALLOW");
    let rest = text.get(start..).unwrap();
    let body = rest.get(..rest.find("];").unwrap()).unwrap();
    body.split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64 of `v` (RFC 4648 §4 or §5 alphabet, with or without padding).
fn b64(v: &[u8], alphabet: &[u8; 64], pad: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in v.chunks(3) {
        let mut group = [0_u8; 4];
        for (g, b) in group.iter_mut().skip(1).zip(chunk) {
            *g = *b;
        }
        let bits = u32::from_be_bytes(group);
        for (k, shift) in [18_u32, 12, 6, 0].into_iter().enumerate() {
            if k <= chunk.len() {
                let idx = usize::try_from(bits.wrapping_shr(shift) & 0x3f).unwrap();
                out.push(*alphabet.get(idx).unwrap());
            } else if pad {
                out.push(b'=');
            }
        }
    }
    out
}

/// `v` as a big-endian unsigned integer in decimal.
fn decimal(v: &[u8]) -> String {
    let mut digits: Vec<u32> = vec![0];
    for &byte in v {
        let mut carry = u32::from(byte);
        for d in &mut digits {
            let x = d.checked_mul(256).unwrap().checked_add(carry).unwrap();
            *d = x.checked_rem(10).unwrap();
            carry = x.checked_div(10).unwrap();
        }
        while carry > 0 {
            digits.push(carry.checked_rem(10).unwrap());
            carry = carry.checked_div(10).unwrap();
        }
    }
    while digits.len() > 1 && digits.last() == Some(&0) {
        digits.pop();
    }
    digits
        .iter()
        .rev()
        .map(|d| char::from_digit(*d, 10).unwrap())
        .collect()
}

/// The renderings of a byte string a report could carry: raw, hex (lower, upper), base64 (standard and URL,
/// padded and not), `Debug` of the bytes, and the decimal of the big-endian integer if `with_decimal`.
fn renderings(v: &[u8], with_decimal: bool) -> Vec<Vec<u8>> {
    let lower = hex(v);
    let mut out = vec![
        v.to_vec(),
        lower.to_uppercase().into_bytes(),
        lower.into_bytes(),
        b64(v, B64_STD, true),
        b64(v, B64_STD, false),
        b64(v, B64_URL, true),
        b64(v, B64_URL, false),
        format!("{v:?}").into_bytes(),
    ];
    if with_decimal {
        out.push(decimal(v).into_bytes());
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// The scenario values `line` carries in any rendering. A counter's decimal is matched as a whole number; one-digit
/// counters are left to the exact-line check (a `cell_id` 1 cannot be told from `generations=1` by a search).
fn leaks(line: &str, trail: &Trail) -> Vec<String> {
    let hay = line.as_bytes();
    let mut found = Vec::new();
    for v in &trail.bytes {
        if renderings(v, true).iter().any(|r| contains(hay, r)) {
            found.push(format!("{} in {line:?}", hex(v)));
        }
    }
    let numbers: Vec<&str> = line
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .collect();
    for n in &trail.numbers {
        let mut forms = renderings(&n.to_be_bytes(), false);
        if let Ok(short) = u32::try_from(*n) {
            forms.extend(renderings(&short.to_be_bytes(), false));
        }
        let decimal = n.to_string();
        if forms.iter().any(|r| contains(hay, r))
            || (*n >= 10 && numbers.contains(&decimal.as_str()))
        {
            found.push(format!("{n} in {line:?}"));
        }
    }
    found
}

/// RL-03 `relay_tracing_emits_no_per_request_field`: over the H-03 scenario (1000 cells each way) the relay reports
/// exactly its start-up line and its drain — the events are the closed set `expect::RELAY_TRACE_ALLOW` (= the
/// relay's `EVENT_NAMES`), every line is a rendering fixed by the configuration alone, and none carries a `rid`,
/// `sid`, `ld_id`, key, seed, token, `sess_id`, `cmd_seq`, `cell_id` or cell bytes of the scenario, raw, in hex,
/// base64 or decimal; the relay has no `tracing` dependency, no other output path, and no client address to report
/// (spec §9.7 item 2; `docs/07:105`; OPEN-M5-08 A).
#[test]
fn relay_tracing_emits_no_per_request_field() {
    let allow = trace_allow();
    assert_eq!(
        allow,
        EVENT_NAMES.to_vec(),
        "RL-03: RELAY_TRACE_ALLOW lists exactly the relay's events"
    );
    let fx = RelayFx::case1();
    let (cap, sink) = capture();
    let ring = KeyRing::new(vec![(fx.keys(1), VALID_UNTIL)]).unwrap();
    let relay = Relay::new(ring, Limits::defaults(), sink, now());
    let mut clock = Clock::new();
    let mut trail = h03(&relay, 1000, &mut clock);
    relay.start_drain(clock.tick());
    relay.start_drain(clock.tick());
    let events = cap.events();
    let lines: Vec<String> = events.iter().map(|(_, l)| l.clone()).collect();
    let fixed = vec![
        Event::KeysLoaded { generations: 1 }.render(),
        Event::DrainStarted.render(),
    ];
    assert_eq!(
        lines, fixed,
        "RL-03: nothing per request: the start-up line and the drain only"
    );
    for (name, _) in &events {
        assert!(
            allow.iter().any(|a| a == name),
            "RL-03: event {name} is not in RELAY_TRACE_ALLOW"
        );
    }
    let (keys, _) = relay.keys().newest().unwrap();
    trail.bytes.extend([
        keys.fp().to_vec(),
        keys.sig_pk().as_bytes().to_vec(),
        keys.akc().to_vec(),
        fx.access_key.clone(),
    ]);
    for line in &lines {
        assert_eq!(
            leaks(line, &trail),
            Vec::<String>::new(),
            "RL-03: a scenario value in an event"
        );
    }
    // positive controls: the search finds a token (hex, base64url, decimal) and a cmd_seq (decimal)
    let token = trail.bytes.first().unwrap().clone();
    let seq = *trail.numbers.first().unwrap();
    let b64url = String::from_utf8(b64(&token, B64_URL, false)).unwrap();
    for probe in [hex(&token), b64url, decimal(&token), format!("cmd {seq}.")] {
        assert!(
            !leaks(&probe, &trail).is_empty(),
            "RL-03: the search finds {probe}"
        );
    }
    no_other_output();
}

/// The structural half of RL-03: no `tracing` among the relay's dependencies, standard output and error only in the
/// event sink and the binary's CLI, and the client's address never read.
fn no_other_output() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let deps = manifest
        .split("\n[")
        .find(|s| s.starts_with("dependencies]"))
        .expect("a [dependencies] section");
    assert!(
        !deps.contains("tracing"),
        "RL-03: the relay has no tracing dependency"
    );
    let mut writers: Vec<String> = Vec::new();
    for file in relay_sources() {
        let text = std::fs::read_to_string(&file).unwrap();
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        for line in text.lines().map(code) {
            assert!(
                !line.contains("peer_addr"),
                "RL-03: {name} reads a peer address"
            );
            let out = ["stderr()", "stdout()", "print!", "println!", "eprint"];
            if out.iter().any(|w| line.contains(w)) && !writers.contains(&name) {
                writers.push(name.clone());
            }
        }
    }
    assert_eq!(
        writers,
        vec!["event.rs", "main.rs"],
        "RL-03: the only output paths"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// RL-23.

/// A path as a configuration string (forward slashes: the configuration's strings take no escapes).
fn config_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// A configuration naming `key_file`, then `extra`.
fn config_text(key_file: &Path, extra: &str) -> String {
    format!(
        "[listen]\ntor_loopback = \"127.0.0.1:7443\"\n[access]\nkey_file = \"{}\"\n{extra}",
        config_path(key_file)
    )
}

/// Every limit of the configuration, set away from its default.
const LIMITS: &str = "[limits]\nqueue_budget_bytes = 524_800\nlinkdata_budget_bytes = 12_488\nlink_frames_burst = 3\n\
link_frames_per_sec = 2\nhello_burst = 2\nhello_per_sec = 1\nhello_hs1_timeout_secs = 7\nmax_connections = 5\n\
[shutdown]\ndrain_secs = 9\n";

/// RL-23 `relay_config_controls_start_and_limits`: a missing or unreadable configuration, a malformed one, a
/// missing key file and a key file with no generation valid now refuse the start with an error (no panic) and a
/// `config_error` event, before any listener binds (no `listener_bound`; the binary exits likewise); a valid
/// configuration with the budget, the rate limits, the `HELLO`→`HS1` timeout, the connection cap (M05 review C-1)
/// and `drain_secs` starts the relay with exactly those values in effect (`docs/07:105`; `docs/05` §5).
#[test]
fn relay_config_controls_start_and_limits() {
    let dir = fresh_dir("rl23");
    let keys = key_file(&dir, DEFAULT_VALIDITY_SECS);
    let write = |name: &str, text: &[u8]| {
        let p = dir.join(name);
        std::fs::write(&p, text).unwrap();
        p
    };
    let expired_keys = dir.join("expired-keys");
    KeyFile::generate(NOW.checked_sub(7200).unwrap(), 3600)
        .unwrap()
        .write_new(&expired_keys)
        .unwrap();
    let missing = dir.join("absent.toml");
    let refused: [(&str, PathBuf, Option<Error>); 6] = [
        ("missing configuration", missing.clone(), None),
        ("unreadable configuration (a directory)", dir.clone(), None),
        (
            "unreadable configuration (not UTF-8)",
            write("binary.toml", &[0xff, 0xfe, 0x00]),
            None,
        ),
        (
            "malformed configuration",
            write(
                "bad.toml",
                config_text(&keys, "[limits]\nnope = 1\n").as_bytes(),
            ),
            None,
        ),
        (
            "missing key file",
            write(
                "nokeys.toml",
                config_text(&dir.join("absent-keys"), "").as_bytes(),
            ),
            Some(Error::KeyFile),
        ),
        (
            "no valid key generation",
            write("expired.toml", config_text(&expired_keys, "").as_bytes()),
            Some(Error::NoValidKeys),
        ),
    ];
    for (what, path, want) in &refused {
        let (cap, sink) = capture();
        let err = server::prepare(path, sink, now())
            .err()
            .expect("RL-23: the start is refused");
        match want {
            Some(e) => assert_eq!(err, *e, "RL-23: {what}"),
            None => assert!(
                matches!(err, Error::Config(_)),
                "RL-23: {what}: a configuration error"
            ),
        }
        assert_eq!(
            names(&cap),
            vec!["config_error"],
            "RL-23: {what}: refused before any listener binds"
        );
    }
    cli_refuses(&missing);
    cli_refuses(&dir.join("nokeys.toml"));
    let full = write("relay.toml", config_text(&keys, LIMITS).as_bytes());
    let (cap, sink) = capture();
    let (cfg, relay) = server::prepare(&full, sink, now()).unwrap();
    assert_eq!(
        names(&cap),
        vec!["keys_loaded"],
        "RL-23: prepare binds no listener"
    );
    assert_eq!(
        (cfg.listen.to_string(), cfg.key_file.clone()),
        ("127.0.0.1:7443".to_owned(), keys)
    );
    let want = Limits {
        budget: BudgetLimits {
            queue_bytes: Some(524_800),
            linkdata_bytes: Some(12_488),
        },
        link_rate: Some(RateLimit {
            burst: 3,
            per_sec: 2,
        }),
        hello_rate: Some(RateLimit {
            burst: 2,
            per_sec: 1,
        }),
        hello_timeout_ms: 7_000,
        drain_secs: 9,
        max_connections: 5,
    };
    assert_eq!(
        *relay.limits(),
        want,
        "RL-23: the configured values are in effect"
    );
    in_effect(&relay);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `secmp-relay --config <path>` exits with an error after a `config_error` line and binds nothing.
fn cli_refuses(config: &Path) {
    let out = Command::new(env!("CARGO_BIN_EXE_secmp-relay"))
        .arg("--config")
        .arg(config)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "RL-23: the binary refuses to start: {stderr}"
    );
    assert!(
        stderr.contains("secmp-relay: config_error "),
        "RL-23: a config_error line: {stderr}"
    );
    assert!(
        !stderr.contains("listener_bound"),
        "RL-23: no listener bound: {stderr}"
    );
    assert!(out.stdout.is_empty(), "RL-23: nothing on standard output");
}

/// RL-23: the values of [`LIMITS`] act — the `HELLO` burst, the timeout, the link rate, both budget pools, the
/// drain.
fn in_effect(relay: &Relay) {
    let t = |ms| Now {
        unix_secs: NOW,
        mono_ms: ms,
    };
    let closed = Output {
        bytes: Vec::new(),
        close: true,
    };
    let (fp, access) = identity(relay);
    let mut w = Wire::connect(relay, fp, &access, t(0), &mut OsEntropy, &mut OsEntropy);
    let mut waiting = Connection::accept(relay, t(0)).unwrap();
    assert!(
        !waiting.on_bytes(&HELLO, t(0), &mut OsEntropy).close,
        "the second HELLO of the burst"
    );
    let mut third = Connection::accept(relay, t(0)).unwrap();
    assert_eq!(
        third.on_bytes(&HELLO, t(0), &mut OsEntropy),
        closed,
        "RL-23: hello_burst 2"
    );
    assert_eq!(waiting.on_tick(t(6_999)), Output::default());
    assert_eq!(
        waiting.on_tick(t(7_000)),
        closed,
        "RL-23: hello_hs1_timeout_secs 7"
    );
    let (q1, q2) = (pair(1, 2), pair(3, 4));
    let created = w.go(t(0), &mut OsEntropy, |c, s| c.queue_new(s, &q1.0, &q1.1));
    assert_eq!(
        created,
        vec![V::QueueNew(rid_of(&q1.0.pk), sid_of(&q1.0.pk, &q1.1.pk))]
    );
    let full = w.go(t(0), &mut OsEntropy, |c, s| c.queue_new(s, &q2.0, &q2.1));
    assert_eq!(
        full,
        vec![V::Err(2)],
        "RL-23: queue_budget_bytes = one queue"
    );
    assert_eq!(
        w.go(t(0), &mut OsEntropy, |_, s| Client::ping(s)),
        vec![V::Ok]
    );
    let over = w.go(t(0), &mut OsEntropy, |_, s| Client::ping(s));
    assert_eq!(over, vec![V::Err(7)], "RL-23: link_frames_burst 3");
    let (owner, blob) = (Key::of(5), distinct_bytes(0x23, BLOB));
    let put = w.put(
        t(10_000),
        &mut OsEntropy,
        &one_time(&[0x23; 16], EXPIRES, &owner, &blob),
    );
    assert_eq!(
        put,
        vec![V::Ok],
        "RL-23: link_frames_per_sec 2 refilled the burst"
    );
    let put = w.put(
        t(20_000),
        &mut OsEntropy,
        &one_time(&[0x24; 16], EXPIRES, &owner, &blob),
    );
    assert_eq!(
        put,
        vec![V::Err(2)],
        "RL-23: linkdata_budget_bytes = one entry"
    );
    let fetched = w.go(t(25_000), &mut OsEntropy, |c, s| c.fetch(s, &q1.0, 0));
    assert_eq!(presents(&fetched), vec![(0, 0); 4]);
    relay.start_drain(t(30_000));
    assert!(!relay.drain_finished(t(38_999)), "RL-23: drain_secs 9");
    assert!(relay.drain_finished(t(39_000)), "RL-23: drain_secs 9");
}
