// SPDX-License-Identifier: AGPL-3.0-or-later
//! M7-C1 smoke (the "usable binary" goal of Phase C): the real `secmp-relay` behind its direct TLS listener on 127.0.0.1 and two
//! real `secmp-cli open --direct` processes. One invites, the other accepts, both see the contact; each sends a text and the
//! other prints it; both end on `quit` with exit 0. Real time (Balanced, periods S10): a few minutes at most.
//!
//! M7-C3 (Q291): the E2E rows over the same pair. E2-01 (+E2-08: the pair is made over `--direct`, where the TLS group, version
//! and ALPN are refused otherwise on both ends); E2-02 (+E2-09/FO-01 and the run-log part of E2-11: `at_ms` of the core clock,
//! monotone per process life) with `E2_02_EACH_WAY` single-cell messages each way and two seeded SIGKILLs per side; E2-03, CLI
//! part (the old queue's `QUEUE_DEL` is C-4); E2-04 (spec §7.7); E2-11, source part (no wall clock in `secmp-cli/src`).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use secmp_testkit::harness::EntropyPool;
use secmp_testkit::harness::e2e::{CliProc, E2eRelay, Json, cli_bin, write_secret_file};

const PASS: &[u8] = b"correct horse\n";
/// The brief says 4 minutes; each new send queue's link starts `U[0, 3 min]` later (spec §10.6 (1)) and the chain has two of them
/// (the invitee's accept, the inviter's first message): 218 s and more than 240 s were measured, so the deadline is ten minutes.
const DEADLINE: Duration = Duration::from_secs(600);

fn text(v: &Json, key: &str) -> String {
    v.get(key)
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// A progress line on stderr (shown when the test fails).
fn note(started: Instant, what: &str) {
    use std::io::Write as _;
    let _ = writeln!(
        std::io::stderr(),
        "[{:>6.1}s] {what}",
        started.elapsed().as_secs_f64()
    );
}

fn kind(v: &Json) -> String {
    text(v, "type")
}

/// The first line of kind `want` within `within`; the others seen on the way are kept for the failure message.
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

/// `invite accept <uri>` until the contact appears: the inviter's link data is put on the relay a moment after `invite
/// create` answered, and an accept that comes first is `error/invitation`, a defined answer, sent again.
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

/// The text `from` printed as a `message` of `contact`, within `within`.
fn message_text(p: &mut CliProc, contact: u64, within: Duration) -> String {
    let (found, skipped) = p.wait_for(within, |v| {
        kind(v) == "message" && v.get("contact").and_then(Json::as_u64) == Some(contact)
    });
    assert!(
        found.is_some(),
        "no message within {within:?}; saw {skipped:?}; stderr: {}",
        p.stderr_text()
    );
    text(&found.unwrap(), "text")
}

/// The 600 s budget starts after the in-test builds of the relay and the CLI (Q294): on a cold Windows runner those builds alone took longer.
#[test]
fn smoke_invite_and_message_both_ways() {
    let built = Instant::now();
    let root = std::env::temp_dir().join(format!("secmp-e2e-smoke-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let relay = E2eRelay::start(&root.join("relay"));
    let bin = cli_bin(&root.join("bin"));
    note(built, "relay and cli built");
    let started = Instant::now();
    let end = started + DEADLINE;
    let left = |(): ()| end.saturating_duration_since(Instant::now());
    let pass = PASS.strip_suffix(b"\n").unwrap();

    let a_profile = profile(&bin, &root, "alice", &relay.ref_path());
    let b_profile = profile(&bin, &root, "bob", &relay.ref_path());
    relay.seed_spares(Path::new(&a_profile.0), pass, 2, "smoke-a");
    relay.seed_spares(Path::new(&b_profile.0), pass, 2, "smoke-b");

    let mut a = open(&bin, &a_profile, "alice");
    let mut b = open(&bin, &b_profile, "bob");
    expect(&mut a, left(()), "opened");
    expect(&mut b, left(()), "opened");
    note(started, "both open");

    a.send_line("invite create");
    let uri = text(&expect(&mut a, left(()), "invitation"), "uri");
    assert!(uri.starts_with("secmp://i/"));
    let b_contact = accept(&mut b, &uri, end);
    assert_eq!(text(&b_contact, "state"), "unverified");
    note(started, "bob has the contact");
    let b_sees = b_contact.get("id").and_then(Json::as_u64).unwrap();
    let a_contact = expect(&mut a, left(()), "contact");
    assert_eq!(text(&a_contact, "state"), "unverified");
    note(started, "alice has the contact");
    let a_sees = a_contact.get("id").and_then(Json::as_u64).unwrap();

    a.send_line(&format!("send {a_sees} ping"));
    let queued = expect(&mut a, left(()), "queued");
    assert_eq!(text(&queued, "msg_id").len(), 32);
    assert_eq!(message_text(&mut b, b_sees, left(())), "ping");
    note(started, "bob got ping");

    b.send_line(&format!("send {b_sees} pong"));
    expect(&mut b, left(()), "queued");
    assert_eq!(message_text(&mut a, a_sees, left(())), "pong");
    note(started, "alice got pong");

    for p in [&mut a, &mut b] {
        p.send_line("quit");
        expect(p, Duration::from_secs(60), "closed");
        let status = p.wait_exit(Duration::from_secs(60));
        assert_eq!(status.and_then(|s| s.code()), Some(0), "exit 0 on quit");
    }
}

/// One wait of a row (the invitation chain took 176–326 s per C-1; every new link starts `U[0, 180 s]` late).
const ROW: Duration = Duration::from_secs(600);
/// Draining the messages of one direction.
const DRAIN: Duration = Duration::from_mins(20);
/// A local command (`contacts …`, `quit`).
const SHORT: Duration = Duration::from_secs(60);
/// E2-02: messages each way (Q291: one message is one cell and one SEND per 10 s, HB-41).
const E2_02_EACH_WAY: usize = 40;

fn after(d: Duration) -> Instant {
    Instant::now().checked_add(d).unwrap()
}

fn id_of(v: &Json, key: &str) -> u64 {
    v.get(key).and_then(Json::as_u64).unwrap()
}

/// Like [`expect`], and the lines skipped on the way hold no `message`.
fn expect_nomsg(p: &mut CliProc, within: Duration, want: &str) -> Json {
    let (found, skipped) = p.wait_for(within, |v| kind(v) == want);
    assert!(
        found.is_some(),
        "no `{want}` within {within:?}; saw {skipped:?}; stderr: {}",
        p.stderr_text()
    );
    assert!(
        skipped.iter().all(|v| kind(v) != "message"),
        "a message before `{want}`: {skipped:?}"
    );
    found.unwrap()
}

/// Two profiles on one relay, opened, invited and accepted. Field order is drop order: processes first.
struct Pair {
    a: CliProc,
    b: CliProc,
    relay: E2eRelay,
    root: PathBuf,
    bin: PathBuf,
    a_profile: (String, String),
    b_profile: (String, String),
    a_of_b: u64,
    b_of_a: u64,
    uri: String,
}

fn pair(label: &str, names: [&str; 2], a_spares: usize) -> Pair {
    let root = std::env::temp_dir().join(format!("secmp-e2e-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let relay = E2eRelay::start(&root.join("relay"));
    let bin = cli_bin(&root.join("bin"));
    let pass = PASS.strip_suffix(b"\n").unwrap();
    let a_profile = profile(&bin, &root, "alice", &relay.ref_path());
    let b_profile = profile(&bin, &root, "bob", &relay.ref_path());
    relay.seed_spares(
        Path::new(&a_profile.0),
        pass,
        a_spares,
        &format!("{label}-a"),
    );
    relay.seed_spares(Path::new(&b_profile.0), pass, 2, &format!("{label}-b"));
    let mut a = open(&bin, &a_profile, names[0]);
    let mut b = open(&bin, &b_profile, names[1]);
    expect(&mut a, ROW, "opened");
    expect(&mut b, ROW, "opened");
    a.send_line("invite create");
    let uri = text(&expect(&mut a, ROW, "invitation"), "uri");
    assert!(uri.starts_with("secmp://i/"));
    let contact = accept(&mut b, &uri, after(ROW));
    assert_eq!(text(&contact, "state"), "unverified");
    let b_of_a = id_of(&contact, "id");
    let a_of_b = id_of(&expect(&mut a, ROW, "contact"), "id");
    Pair {
        a,
        b,
        relay,
        root,
        bin,
        a_profile,
        b_profile,
        a_of_b,
        b_of_a,
        uri,
    }
}

/// The safety number of contact `id`: 60 ASCII digits.
fn sas(p: &mut CliProc, id: u64) -> String {
    p.send_line(&format!("contacts sas {id}"));
    let line = expect_nomsg(p, SHORT, "sas");
    assert_eq!(id_of(&line, "contact"), id);
    let digits = text(&line, "digits");
    assert!(digits.len() == 60 && digits.bytes().all(|b| b.is_ascii_digit()));
    digits
}

fn verify(p: &mut CliProc, id: u64, digits: &str) -> bool {
    p.send_line(&format!("contacts verify {id} {digits}"));
    let line = expect_nomsg(p, SHORT, "verified");
    assert_eq!(id_of(&line, "contact"), id);
    line.get("ok").and_then(Json::as_bool).unwrap()
}

fn listed(p: &mut CliProc) -> Vec<Json> {
    p.send_line("contacts list");
    let line = expect_nomsg(p, SHORT, "contacts");
    line.get("list").and_then(Json::as_array).unwrap().clone()
}

fn quit(p: &mut CliProc) {
    p.send_line("quit");
    expect(p, SHORT, "closed");
    let status = p.wait_exit(SHORT);
    assert_eq!(status.and_then(|s| s.code()), Some(0), "exit 0 on quit");
}

fn done(p: Pair) {
    let root = p.root.clone();
    drop(p);
    let _ = std::fs::remove_dir_all(&root);
}

/// FO-01a's scan (`secmp_store::kat::scan_dir`) of the profile directory `dir`, as FO-03 calls it.
fn scan(dir: &str, needles: &[Vec<u8>]) {
    let refs: Vec<&[u8]> = needles.iter().map(Vec::as_slice).collect();
    let (hits, files, bytes) = secmp_store::kat::scan_dir(Path::new(dir), &refs, 8).unwrap();
    assert!(files > 0, "no files under {dir}");
    assert!(bytes > 0, "no bytes under {dir}");
    assert!(hits.is_empty(), "forensic hits under {dir}: {hits:?}");
}

/// `s` as UTF-16LE.
fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// E2-01 (+E2-08, D5/Q281): two profiles, one invitation by URI, the safety numbers match and both verify. The pair runs over
/// `--direct`: the relay and the client refuse any TLS group but `X25519MLKEM768`, any version but 1.3 and any ALPN but
/// `secmp/1` before the first SecMP byte (M6 TLS-13/14 observed the group), so a pair that exists is the E2-08 evidence.
/// Oracle: the CLI's own lines. Not evidenced here: the relay's view of the handshake (M6).
#[test]
fn two_profiles_invite_by_uri_sas_match() {
    let mut p = pair("e201", ["alice", "bob"], 2);
    let (a_of_b, b_of_a) = (p.a_of_b, p.b_of_a);
    for (proc, id) in [(&mut p.a, a_of_b), (&mut p.b, b_of_a)] {
        let list = listed(proc);
        assert_eq!(list.len(), 1, "{list:?}");
        let only = list.first().unwrap();
        assert_eq!(id_of(only, "id"), id);
        assert_eq!(text(only, "state"), "unverified");
    }
    let digits = sas(&mut p.a, a_of_b);
    assert_eq!(digits, sas(&mut p.b, b_of_a));
    assert!(verify(&mut p.a, a_of_b, &digits));
    assert!(verify(&mut p.b, b_of_a, &digits));
    for proc in [&mut p.a, &mut p.b] {
        let list = listed(proc);
        assert_eq!(list.len(), 1, "{list:?}");
        assert_eq!(text(list.first().unwrap(), "state"), "verified");
    }
    p.a.send_line("status");
    let status = expect_nomsg(&mut p.a, SHORT, "status");
    assert_eq!(text(&status, "mode"), "balanced");
    assert_eq!(status.get("direct").and_then(Json::as_bool), Some(true));
    quit(&mut p.a);
    quit(&mut p.b);
    done(p);
}

/// One line of `p`; an `error` fails; a `message` of `contact` is pushed to `got`.
fn pump(p: &mut CliProc, contact: u64, got: &mut Vec<String>, end: Instant) -> Json {
    let line = p.next_json(end.saturating_duration_since(Instant::now()));
    assert!(
        line.is_some(),
        "no line; got {}; stderr: {}",
        got.len(),
        p.stderr_text()
    );
    let line = line.unwrap();
    assert_ne!(kind(&line), "error", "{line:?}");
    if kind(&line) == "message" && line.get("contact").and_then(Json::as_u64) == Some(contact) {
        got.push(text(&line, "text"));
    }
    line
}

/// E2-03, CLI part: 20 messages in flight while the receiver rotates the queue onto a spare (spec §10.6 (4)), then 5 more
/// sent after the sender's `RoutesChanged` (C3-1: on the new route; they are required once each, no timing assumption).
/// Oracle: the printed texts, each exactly once, and the sender's `RoutesChanged`. Not evidenced: the old queue's `QUEUE_DEL` after 1–24 h
/// (C-4, virtual time).
#[test]
fn rotation_with_overlap() {
    let mut p = pair("e203", ["alice", "bob"], 3);
    let (a_of_b, b_of_a) = (p.a_of_b, p.b_of_a);
    let mut sent: Vec<String> = (0..20).map(|n| format!("rotation-{n:02}")).collect();
    for t in &sent {
        p.b.send_line(&format!("send {b_of_a} {t}"));
        expect(&mut p.b, ROW, "queued");
    }
    let mut got = Vec::new();
    p.a.send_line(&format!("rotate {a_of_b}"));
    let end = after(DRAIN);
    let rotated = loop {
        let l = pump(&mut p.a, a_of_b, &mut got, end);
        if kind(&l) == "rotated" {
            break l;
        }
    };
    assert_eq!(id_of(&rotated, "contact"), a_of_b);
    assert_eq!(rotated.get("started").and_then(Json::as_bool), Some(true));
    let (changed, _) = p.b.wait_for(ROW, |v| {
        kind(v) == "event"
            && text(v, "name") == "RoutesChanged"
            && v.get("contact").and_then(Json::as_u64) == Some(b_of_a)
    });
    assert!(changed.is_some(), "no RoutesChanged; {}", p.b.stderr_text());
    // C3-1: sent after RoutesChanged, so on the new route; their arrival needs no timing assumption
    for n in 20..25 {
        let t = format!("rotation-{n:02}");
        p.b.send_line(&format!("send {b_of_a} {t}"));
        expect(&mut p.b, ROW, "queued");
        sent.push(t);
    }
    while got.len() < sent.len() {
        pump(&mut p.a, a_of_b, &mut got, end);
    }
    p.a.send_line("quit");
    while kind(&pump(&mut p.a, a_of_b, &mut got, after(SHORT))) != "closed" {}
    assert_eq!(p.a.wait_exit(SHORT).and_then(|s| s.code()), Some(0));
    let mut want = sent;
    want.sort();
    got.sort();
    assert_eq!(got, want, "each message exactly once");
    quit(&mut p.b);
    done(p);
}

/// E2-04 (spec §7.7): after the peer's identity rotation a send is `blocked` until the safety number is verified again; the
/// new number differs from the old one, and the first message that arrives is the one sent after the re-verification (the
/// blocked one was never sent). Oracle: the CLI lines. Not evidenced: the persisted trust state (M4/M6 store tests).
#[test]
fn key_change_blocks_until_reverified() {
    let mut p = pair("e204", ["alice", "bob"], 2);
    let (a_of_b, b_of_a) = (p.a_of_b, p.b_of_a);
    let old = sas(&mut p.a, a_of_b);
    assert_eq!(old, sas(&mut p.b, b_of_a));
    assert!(verify(&mut p.a, a_of_b, &old));
    assert!(verify(&mut p.b, b_of_a, &old));
    p.a.send_line("identity rotate");
    expect_nomsg(&mut p.a, ROW, "identity_rotated");
    let sent = expect_nomsg(&mut p.a, ROW, "key_change_sent");
    assert_eq!(id_of(&sent, "contact"), a_of_b);
    let (changed, _) = p.b.wait_for(ROW, |v| {
        kind(v) == "event"
            && text(v, "name") == "KeyChanged"
            && v.get("contact").and_then(Json::as_u64) == Some(b_of_a)
    });
    assert!(changed.is_some(), "no KeyChanged; {}", p.b.stderr_text());
    p.b.send_line(&format!("send {b_of_a} before-reverify"));
    let (answer, _) =
        p.b.wait_for(ROW, |v| kind(v) == "error" || kind(v) == "queued");
    let answer = answer.expect("an answer to the blocked send");
    assert_eq!(kind(&answer), "error", "{answer:?}");
    assert_eq!(text(&answer, "code"), "blocked");
    let new = sas(&mut p.b, b_of_a);
    assert_eq!(new, sas(&mut p.a, a_of_b));
    assert_ne!(new, old);
    assert!(verify(&mut p.b, b_of_a, &new));
    p.b.send_line(&format!("send {b_of_a} after-reverify"));
    expect(&mut p.b, ROW, "queued");
    let (msg, skipped) = p.a.wait_for(ROW, |v| kind(v) == "message");
    assert!(msg.is_some(), "no message; saw {skipped:?}");
    let msg = msg.unwrap();
    assert_eq!(id_of(&msg, "contact"), a_of_b);
    assert_eq!(text(&msg, "text"), "after-reverify");
    quit(&mut p.a);
    quit(&mut p.b);
    done(p);
}

/// E2-11, source part: nothing in `secmp-cli/src` reads a wall clock, and the one timestamp the CLI prints is the core clock's.
/// Not evidenced here: the run-log part (E2-02 checks `at_ms` per process life).
#[test]
fn cli_uses_no_wall_clock_for_schedule() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../secmp-cli/src");
    let mut files = Vec::new();
    crate::m6_driver::rust_files(&dir, &mut files);
    assert!(files.len() >= 7, "{}", files.len());
    let mut daemon = String::new();
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap();
        let reads = crate::m6_driver::wall_clock_reads(&src);
        assert!(
            reads.is_empty(),
            "{}: wall clock at lines {reads:?}",
            f.display()
        );
        for l in src.lines() {
            let code = l.split("//").next().unwrap_or_default();
            assert!(!code.contains("UNIX_EPOCH"), "{}: {l}", f.display());
        }
        if f.file_name().is_some_and(|n| n == "daemon.rs") {
            daemon = src;
        }
    }
    assert_eq!(
        daemon
            .matches("event_line(&caller, stamped.at_ms, &stamped.event)")
            .count(),
        1
    );
    assert_eq!(daemon.matches(".num(\"at_ms\", at_ms)").count(), 1);
}

/// The next draw.
fn draw(it: &mut impl Iterator<Item = u8>) -> u8 {
    it.next().unwrap()
}

/// The `E2_02_EACH_WAY` texts of side `s` and its two kill points `k1 ∈ [1, N/2)`, `k2 ∈ [N/2, N-1)`.
fn script(s: char, it: &mut impl Iterator<Item = u8>) -> (Vec<String>, [usize; 2]) {
    let mut texts = Vec::new();
    for i in 0..E2_02_EACH_WAY {
        if i.checked_rem(10) == Some(0) {
            texts.push(format!("CANARY-MSG-{s}{i:015x}"));
            continue;
        }
        let r = usize::from(draw(it));
        let len = 8_usize.checked_add(r.checked_rem(57).unwrap()).unwrap();
        let mut t = format!("{s}{i:03}-");
        while t.len() < len {
            let b = draw(it);
            t.push(char::from(
                b'a'.checked_add(b.checked_rem(26).unwrap()).unwrap(),
            ));
        }
        texts.push(t);
    }
    let half = E2_02_EACH_WAY.checked_div(2).unwrap();
    let span1 = half.checked_sub(1).unwrap();
    let span2 = E2_02_EACH_WAY
        .checked_sub(half)
        .unwrap()
        .checked_sub(1)
        .unwrap();
    let r1 = usize::from(draw(it));
    let r2 = usize::from(draw(it));
    let k1 = 1_usize.checked_add(r1.checked_rem(span1).unwrap()).unwrap();
    let k2 = half.checked_add(r2.checked_rem(span2).unwrap()).unwrap();
    (texts, [k1, k2])
}

/// The canaries a CLI run exposes, as ASCII and UTF-16LE.
fn needles(texts: [&[String]; 2], extra: &[&str]) -> Vec<Vec<u8>> {
    let canaries = texts
        .into_iter()
        .flatten()
        .filter(|t| t.starts_with("CANARY-MSG-"))
        .map(String::as_str);
    canaries
        .chain(extra.iter().copied())
        .flat_map(|s| [s.as_bytes().to_vec(), utf16le(s)])
        .collect()
}

/// One CLI process of E2-02 with its script and what it printed.
struct Side {
    p: CliProc,
    peer: u64,
    profile: (String, String),
    name: &'static str,
    texts: Vec<String>,
    kills: [usize; 2],
    killed: usize,
    sent: usize,
    got: Vec<String>,
    last_at: u64,
    started: Instant,
}

impl Side {
    /// One line; an `error` fails; a `message` of the peer is checked (`at_ms` of the core clock, monotone per process life)
    /// and collected.
    fn read(&mut self, end: Instant) -> Json {
        let line = pump(&mut self.p, self.peer, &mut self.got, end);
        if kind(&line) == "message" && line.get("contact").and_then(Json::as_u64) == Some(self.peer)
        {
            let at = id_of(&line, "at_ms");
            assert!(
                at >= self.last_at,
                "{}: at_ms went back: {line:?}",
                self.name
            );
            self.last_at = at;
        }
        line
    }

    fn until(&mut self, want: &str, end: Instant) -> Json {
        loop {
            let line = self.read(end);
            if kind(&line) == want {
                return line;
            }
        }
    }

    fn drain(&mut self, n: usize, end: Instant) {
        while self.got.len() < n {
            self.read(end);
        }
    }

    /// SIGKILL, the FO-01 scan on the first kill (WAL as left), reopen.
    fn restart(&mut self, bin: &Path, needles: &[Vec<u8>], end: Instant) {
        self.p.kill();
        if self.killed == 0 {
            scan(&self.profile.0, needles);
        }
        self.p = open(bin, &self.profile, self.name);
        self.last_at = 0;
        self.killed = self.killed.checked_add(1).unwrap();
        self.until("opened", end);
    }

    /// A process is killed only after it printed every message the peer has queued (HB-40), then message `i` is sent.
    fn step(&mut self, i: usize, peer_sent: usize, bin: &Path, needles: &[Vec<u8>], end: Instant) {
        if self.kills.contains(&i) {
            note(
                self.started,
                &format!("kill point {i}: draining {peer_sent}"),
            );
            self.drain(peer_sent, end);
            self.restart(bin, needles, end);
            note(self.started, &format!("kill point {i}: reopened"));
        }
        let text_i = self.texts.get(i).unwrap().clone();
        self.p.send_line(&format!("send {} {text_i}", self.peer));
        let queued = self.until("queued", end);
        assert_eq!(text(&queued, "msg_id").len(), 32);
        self.sent = self.sent.checked_add(1).unwrap();
    }

    fn finish(&mut self) {
        self.p.send_line("quit");
        self.until("closed", after(SHORT));
        let status = self.p.wait_exit(SHORT);
        assert_eq!(
            status.and_then(|s| s.code()),
            Some(0),
            "{}: exit 0 on quit",
            self.name
        );
    }
}

fn side(
    p: CliProc,
    peer: u64,
    profile: &(String, String),
    name: &'static str,
    s: (Vec<String>, [usize; 2]),
    started: Instant,
) -> Side {
    Side {
        p,
        peer,
        profile: profile.clone(),
        name,
        texts: s.0,
        kills: s.1,
        killed: 0,
        sent: 0,
        got: Vec::new(),
        last_at: 0,
        started,
    }
}

/// E2-02 at `E2_02_EACH_WAY` messages each way, with E2-09/FO-01 and the run-log part of E2-11 (Q291). Two seeded SIGKILLs per
/// side, each after the victim printed everything sent to it; every message arrives exactly once, in send order, and the
/// profile directories hold none of the canaries (texts, names, URI, SAS digits, passphrase) after the first kill and after a
/// clean close. Not evidenced: 500 messages each way (E2-02v, C-4), key material in the scan (FO-01a, C-4), PC-05.
#[test]
fn five_hundred_both_ways_with_restarts() {
    let started = Instant::now();
    let names = ["Ownname-Canary-5e6f7a8b", "Zebulon-Canary-1a2b3c4d"];
    let Pair {
        mut a,
        b,
        relay,
        root,
        bin,
        a_profile,
        b_profile,
        a_of_b,
        b_of_a,
        uri,
    } = pair("e202", names, 2);
    let digits = sas(&mut a, a_of_b);
    let mut pool = EntropyPool::new("m7-e2e-02", 0);
    let mut it = pool.bytes(8192).into_iter();
    let (a_script, b_script) = (script('a', &mut it), script('b', &mut it));
    let needles = needles(
        [&a_script.0, &b_script.0],
        &[names[0], names[1], &uri, &digits, "correct horse"],
    );
    let mut alice = side(a, a_of_b, &a_profile, names[0], a_script, started);
    let mut bob = side(b, b_of_a, &b_profile, names[1], b_script, started);
    note(started, "script ready");
    for i in 0..E2_02_EACH_WAY {
        alice.step(i, bob.sent, &bin, &needles, after(DRAIN));
        bob.step(i, alice.sent, &bin, &needles, after(DRAIN));
    }
    alice.drain(E2_02_EACH_WAY, after(DRAIN));
    note(started, "alice drained");
    bob.drain(E2_02_EACH_WAY, after(DRAIN));
    note(started, "bob drained");
    note(started, "all drained");
    alice.finish();
    bob.finish();
    assert_eq!(
        alice.got, bob.texts,
        "alice printed bob's messages once, in order"
    );
    assert_eq!(
        bob.got, alice.texts,
        "bob printed alice's messages once, in order"
    );
    assert_eq!((alice.killed, bob.killed), (2, 2));
    drop(alice);
    drop(bob);
    scan(&a_profile.0, &needles);
    scan(&b_profile.0, &needles);
    // C3-2: the same scan over a planted canary must hit
    let control = root.join("fo-control");
    std::fs::create_dir_all(&control).unwrap();
    std::fs::write(control.join("canary.bin"), needles.first().unwrap()).unwrap();
    let refs: Vec<&[u8]> = needles.iter().map(Vec::as_slice).collect();
    let (hits, _, _) = secmp_store::kat::scan_dir(&control, &refs, 8).unwrap();
    assert!(
        hits.iter().any(|h| h.needle == 0 && h.raw),
        "the control scan missed the planted canary: {hits:?}"
    );
    drop(relay);
    let _ = std::fs::remove_dir_all(&root);
    note(started, "done");
}
