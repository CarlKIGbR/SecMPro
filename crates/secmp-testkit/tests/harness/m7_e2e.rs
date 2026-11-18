// SPDX-License-Identifier: AGPL-3.0-or-later
//! M7-C1 smoke (the "usable binary" goal of Phase C): the real `secmp-relay` behind its direct TLS listener on 127.0.0.1 and two
//! real `secmp-cli open --direct` processes. One invites, the other accepts, both see the contact; each sends a text and the
//! other prints it; both end on `quit` with exit 0. Real time (Balanced, periods S10): a few minutes at most.

use std::path::Path;
use std::time::{Duration, Instant};

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

#[test]
fn smoke_invite_and_message_both_ways() {
    let started = Instant::now();
    let end = started + DEADLINE;
    let left = |(): ()| end.saturating_duration_since(Instant::now());
    let root = std::env::temp_dir().join(format!("secmp-e2e-smoke-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let relay = E2eRelay::start(&root.join("relay"));
    let bin = cli_bin(&root.join("bin"));
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
