// SPDX-License-Identifier: AGPL-3.0-or-later
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! TEST-SPEC-M7 (j) CL-01, CL-02, CL-03, CL-10, CL-11, CL-13: the `secmp-cli` binary as a process, `--direct` everywhere.
//! The rows that need a relay run the real `secmp-relay` binary behind its direct TLS listener on 127.0.0.1
//! (`E2eRelay`); a profile that needs spare queues has them made before its first `open` (`seed_spares`).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use secmp_testkit::harness::e2e::{CliProc, E2eRelay, Json, parse_line, write_secret_file};

const BIN: &str = env!("CARGO_BIN_EXE_secmp-cli");
const PASS: &[u8] = b"correct horse\n";
const SHORT: Duration = Duration::from_secs(60);
const LONG: Duration = Duration::from_secs(180);

/// An empty scratch directory of this test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("secmp-cli-it-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn text(v: &Json, key: &str) -> String {
    v.get(key)
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn kind(v: &Json) -> String {
    text(v, "type")
}

/// The stdout of a finished process as JSON lines.
fn lines(out: &Output) -> Vec<Json> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(parse_line)
        .collect()
}

/// A new profile `name` under `root` with the passphrase file `<name>.pass` (mode 0600); `relay`: its reference file.
fn new_profile(root: &Path, name: &str, relay: Option<&Path>) -> (PathBuf, PathBuf) {
    let dir = root.join(name);
    let pass = root.join(format!("{name}.pass"));
    write_secret_file(&pass, PASS);
    let (d, p) = (dir.to_str().unwrap(), pass.to_str().unwrap());
    let mut args = vec!["profile", "new", d, "--passphrase-file", p];
    let relay = relay.map(|r| r.to_str().unwrap().to_owned());
    if let Some(r) = &relay {
        args.extend(["--relay", r]);
    }
    let out = run(&args);
    assert!(out.status.success(), "profile new: {:?}", out.status);
    let l = lines(&out);
    assert_eq!(l.len(), 1);
    assert_eq!(kind(l.first().unwrap()), "created");
    (dir, pass)
}

fn open(dir: &Path, pass: &Path, name: &str) -> CliProc {
    CliProc::spawn(
        Path::new(BIN),
        &[
            "open",
            dir.to_str().unwrap(),
            "--passphrase-file",
            pass.to_str().unwrap(),
            "--direct",
            "--name",
            name,
        ],
        &[],
    )
}

fn expect(p: &mut CliProc, within: Duration, want: &str) -> Json {
    let (found, skipped) = p.wait_for(within, |v| kind(v) == want);
    assert!(
        found.is_some(),
        "no `{want}` line within {within:?}; saw {skipped:?}; stderr: {}",
        p.stderr_text()
    );
    found.unwrap()
}

/// CL-01: `profile new` makes a profile; `open` answers `opened` and exits 0 on `quit`; a wrong passphrase is exit 4 with
/// the one line `{"type":"error","code":"unlock"}`.
#[test]
fn profile_new_and_open() {
    let root = scratch("cl01");
    let (dir, pass) = new_profile(&root, "alice", None);
    let mut p = open(&dir, &pass, "alice");
    let opened = expect(&mut p, LONG, "opened");
    assert_eq!(kind(&opened), "opened");
    p.send_line("quit");
    expect(&mut p, SHORT, "closed");
    let status = p.wait_exit(SHORT).expect("the process ends on quit");
    assert_eq!(status.code(), Some(0));

    let wrong = root.join("wrong.pass");
    write_secret_file(&wrong, b"battery staple\n");
    let out = run(&[
        "open",
        dir.to_str().unwrap(),
        "--passphrase-file",
        wrong.to_str().unwrap(),
        "--direct",
    ]);
    assert_eq!(out.status.code(), Some(4));
    let l = lines(&out);
    assert_eq!(l.len(), 1, "one line");
    assert_eq!(kind(l.first().unwrap()), "error");
    assert_eq!(text(l.first().unwrap(), "code"), "unlock");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "{\"type\":\"error\",\"code\":\"unlock\"}"
    );
}

/// CL-02: `invite create` answers one line with the invitation's `uri` (`secmp://i/` and 322 characters); a profile without a
/// spare queue answers `error/pool_empty`.
#[test]
fn invite_create_prints_uri() {
    let root = scratch("cl02");
    let relay = E2eRelay::start(&root.join("relay"));
    // the 332-character form of §5.2 is the invitation of a relay reference without `direct`; the spares exist on the relay
    // and in the store all the same
    let plain = relay.ref_path_without_direct();
    let (dir, pass) = new_profile(&root, "alice", Some(&plain));
    let (bare, bare_pass) = new_profile(&root, "bare", Some(&plain));
    relay.seed_spares(&dir, PASS.strip_suffix(b"\n").unwrap(), 2, "cl02");

    let mut p = open(&dir, &pass, "alice");
    expect(&mut p, LONG, "opened");
    p.send_line("invite create");
    let invitation = expect(&mut p, LONG, "invitation");
    let uri = text(&invitation, "uri");
    assert!(uri.starts_with("secmp://i/"), "{}", uri.len());
    assert_eq!(uri.chars().count(), 332);
    p.send_line("quit");
    expect(&mut p, SHORT, "closed");

    let mut b = open(&bare, &bare_pass, "bare");
    expect(&mut b, LONG, "opened");
    b.send_line("invite create");
    let refused = expect(&mut b, SHORT, "error");
    assert_eq!(text(&refused, "code"), "pool_empty");
    b.send_line("quit");
    expect(&mut b, SHORT, "closed");
}

/// CL-03: `invite accept <uri>` of an invitation another profile issued answers `contact` in the state `unverified`; a URI
/// that does not parse answers `error/invitation`.
#[test]
fn invite_accept_uri() {
    let root = scratch("cl03");
    let relay = E2eRelay::start(&root.join("relay"));
    let pass_text = PASS.strip_suffix(b"\n").unwrap();
    let (a_dir, a_pass) = new_profile(&root, "alice", Some(&relay.ref_path()));
    let (b_dir, b_pass) = new_profile(&root, "bob", Some(&relay.ref_path()));
    relay.seed_spares(&a_dir, pass_text, 2, "cl03-a");
    relay.seed_spares(&b_dir, pass_text, 2, "cl03-b");

    let mut a = open(&a_dir, &a_pass, "alice");
    expect(&mut a, LONG, "opened");
    a.send_line("invite create");
    let uri = text(&expect(&mut a, LONG, "invitation"), "uri");

    let mut b = open(&b_dir, &b_pass, "bob");
    expect(&mut b, LONG, "opened");
    b.send_line("invite accept not-an-invitation");
    let refused = expect(&mut b, SHORT, "error");
    assert_eq!(text(&refused, "code"), "invitation");
    let contact = accept(&mut b, &uri);
    assert_eq!(text(&contact, "state"), "unverified");
    assert!(contact.get("id").and_then(Json::as_u64).is_some());
    for p in [&mut a, &mut b] {
        p.send_line("quit");
        expect(p, SHORT, "closed");
    }
}

/// `invite accept <uri>` until the contact appears. The inviter's link data is put on the relay a moment after `invite
/// create` answered; an accept that comes first finds nothing and is `error/invitation` (a defined answer): it is sent again.
fn accept(p: &mut CliProc, uri: &str) -> Json {
    for _ in 0..20 {
        p.send_line(&format!("invite accept {uri}"));
        let (found, skipped) = p.wait_for(LONG, |v| kind(v) == "contact" || kind(v) == "error");
        let line = found.unwrap_or_else(|| Json::from(skipped.len()));
        if kind(&line) == "contact" {
            return line;
        }
        assert_eq!(text(&line, "code"), "invitation", "{line:?}");
        std::thread::sleep(Duration::from_secs(2));
    }
    Json::Null
}

/// CL-10: an unknown verb or a missing argument is exit 2, the usage on stderr and nothing on stdout.
#[test]
fn usage_errors() {
    for args in [
        &["frobnicate"][..],
        &["open"],
        &["open", "somewhere"],
        &["profile"],
        &["profile", "new"],
        &["profile", "new", "somewhere"],
        &["open", "somewhere", "--passphrase-file"],
        &["open", "somewhere", "--passphrase-file", "f", "--bogus"],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}: nothing on stdout");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("usage"),
            "{args:?}: the usage on stderr"
        );
    }
}

/// CL-11: the passphrase comes only from a file only the user can read: a file of mode 0644 is refused (exit 2, stderr only),
/// `--passphrase` is an unknown flag (and the secret is not echoed), the environment variable `SECMP_PASSPHRASE` is never
/// read (it neither supplies the passphrase nor overrides the file's).
#[test]
#[cfg(unix)]
fn passphrase_input_rules() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = scratch("cl11");
    let (dir, pass) = new_profile(&root, "alice", None);
    let d = dir.to_str().unwrap();

    let open_file = root.join("open.pass");
    std::fs::write(&open_file, PASS).unwrap();
    std::fs::set_permissions(&open_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = run(&["open", d, "--passphrase-file", open_file.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("refused"));

    let secret = "hunter2-on-the-command-line";
    let out = run(&["open", d, "--passphrase", secret]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&out.stderr).contains(secret));

    // the environment is never read: the right passphrase in it does not replace a missing flag, nor beat a wrong file
    let out = Command::new(BIN)
        .args(["open", d])
        .env("SECMP_PASSPHRASE", "correct horse")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let wrong = root.join("wrong.pass");
    write_secret_file(&wrong, b"battery staple\n");
    let out = Command::new(BIN)
        .args(["open", d, "--passphrase-file", wrong.to_str().unwrap()])
        .env("SECMP_PASSPHRASE", "correct horse")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4), "the file decides");
    // and the right file still opens it
    let mut p = open(&dir, &pass, "alice");
    expect(&mut p, LONG, "opened");
    p.send_line("quit");
    expect(&mut p, SHORT, "closed");
}

/// CL-13: a second `open` of the same profile directory is exit 5 with `{"type":"error","code":"busy"}`; the first process is
/// unaffected — it still answers `contacts list`.
#[test]
fn single_writer_lock() {
    let root = scratch("cl13");
    let (dir, pass) = new_profile(&root, "alice", None);
    let mut first = open(&dir, &pass, "alice");
    expect(&mut first, LONG, "opened");

    let out = run(&[
        "open",
        dir.to_str().unwrap(),
        "--passphrase-file",
        pass.to_str().unwrap(),
        "--direct",
    ]);
    assert_eq!(out.status.code(), Some(5));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "{\"type\":\"error\",\"code\":\"busy\"}"
    );

    first.send_line("contacts list");
    let list = expect(&mut first, SHORT, "contacts");
    assert_eq!(
        list.get("list").and_then(Json::as_array).map(Vec::len),
        Some(0)
    );
    first.send_line("quit");
    expect(&mut first, SHORT, "closed");
    assert_eq!(first.wait_exit(SHORT).and_then(|s| s.code()), Some(0));
}

// ---- M7-C2: the verbs of a paired session (CL-04 … CL-09) and the totality of the line parser (CL-14) -----------------------

/// The deadline of a row that pairs two profiles: C-1 measured 176–326 s for one invitation chain.
const ROW: Duration = Duration::from_secs(600);

/// `expect` that also keeps every line it read (the skipped ones and the found one) on `tape`.
fn expect_tape(p: &mut CliProc, within: Duration, want: &str, tape: &mut Vec<Json>) -> Json {
    expect_where(p, within, tape, &format!("`{want}`"), |v| kind(v) == want)
}

/// The first line within `within` for which `want` holds; every line read goes to `tape`.
fn expect_where(
    p: &mut CliProc,
    within: Duration,
    tape: &mut Vec<Json>,
    what: &str,
    want: impl Fn(&Json) -> bool,
) -> Json {
    let (found, skipped) = p.wait_for(within, want);
    tape.extend(skipped.iter().cloned());
    assert!(
        found.is_some(),
        "no {what} line within {within:?}; saw {skipped:?}; stderr: {}",
        p.stderr_text()
    );
    let found = found.unwrap();
    tape.push(found.clone());
    found
}

/// Two paired profiles on one relay: alice invited, bob accepted; both processes are open.
struct Pair {
    root: PathBuf,
    relay: E2eRelay,
    a: CliProc,
    b: CliProc,
    a_dir: PathBuf,
    a_pass: PathBuf,
    /// alice's id of bob, and bob's id of alice.
    a_of_b: u64,
    b_of_a: u64,
    /// The invitation's URI.
    uri: String,
    /// Every line the two processes wrote while the pair was made.
    tape: Vec<Json>,
}

/// `new_profile` + `seed_spares` (before `open`) + `invite create` / `accept`, `--direct`.
fn pair(root: &Path, label: &str) -> Pair {
    let relay = E2eRelay::start(&root.join("relay"));
    let pass_text = PASS.strip_suffix(b"\n").unwrap();
    let (a_dir, a_pass) = new_profile(root, "alice", Some(&relay.ref_path()));
    let (b_dir, b_pass) = new_profile(root, "bob", Some(&relay.ref_path()));
    relay.seed_spares(&a_dir, pass_text, 2, &format!("{label}-a"));
    relay.seed_spares(&b_dir, pass_text, 2, &format!("{label}-b"));
    let mut tape = Vec::new();
    let mut a = open(&a_dir, &a_pass, "alice");
    expect_tape(&mut a, ROW, "opened", &mut tape);
    a.send_line("invite create");
    let uri = text(&expect_tape(&mut a, ROW, "invitation", &mut tape), "uri");
    let mut b = open(&b_dir, &b_pass, "bob");
    expect_tape(&mut b, ROW, "opened", &mut tape);
    let b_of_a = accept_tape(&mut b, &uri, &mut tape).expect("the invitation was accepted");
    let a_of_b = expect_tape(&mut a, ROW, "contact", &mut tape)
        .get("id")
        .and_then(Json::as_u64)
        .unwrap();
    Pair {
        root: root.to_owned(),
        relay,
        a,
        b,
        a_dir,
        a_pass,
        a_of_b,
        b_of_a,
        uri,
        tape,
    }
}

/// `accept` that keeps the lines it read; returns the contact's id.
fn accept_tape(p: &mut CliProc, uri: &str, tape: &mut Vec<Json>) -> Option<u64> {
    for _ in 0..20 {
        p.send_line(&format!("invite accept {uri}"));
        let (found, skipped) = p.wait_for(ROW, |v| kind(v) == "contact" || kind(v) == "error");
        tape.extend(skipped);
        let line = found.expect("an answer to `invite accept`");
        tape.push(line.clone());
        if kind(&line) == "contact" {
            return line.get("id").and_then(Json::as_u64);
        }
        assert_eq!(text(&line, "code"), "invitation", "{line:?}");
        std::thread::sleep(Duration::from_secs(2));
    }
    None
}

/// `contacts sas <id>`: the 60 digits.
fn sas(p: &mut CliProc, id: u64, tape: &mut Vec<Json>) -> String {
    p.send_line(&format!("contacts sas {id}"));
    let line = expect_tape(p, ROW, "sas", tape);
    assert_eq!(line.get("contact").and_then(Json::as_u64), Some(id));
    text(&line, "digits")
}

/// `contacts verify <id> <digits>`: the answer's `ok`.
fn verify(p: &mut CliProc, id: u64, digits: &str, tape: &mut Vec<Json>) -> bool {
    p.send_line(&format!("contacts verify {id} {digits}"));
    let line = expect_tape(p, ROW, "verified", tape);
    assert_eq!(line.get("contact").and_then(Json::as_u64), Some(id));
    line.get("ok").and_then(Json::as_bool).unwrap()
}

/// Both sides verify each other (receipts go only to verified contacts, spec §10.4).
fn verify_both(p: &mut Pair) {
    let mut tape = std::mem::take(&mut p.tape);
    let digits = sas(&mut p.a, p.a_of_b, &mut tape);
    assert_eq!(
        sas(&mut p.b, p.b_of_a, &mut tape),
        digits,
        "the same safety number"
    );
    assert!(verify(&mut p.a, p.a_of_b, &digits, &mut tape));
    assert!(verify(&mut p.b, p.b_of_a, &digits, &mut tape));
    p.tape = tape;
}

/// A line of `contacts list` for `id`.
fn listed(p: &mut CliProc, id: u64, tape: &mut Vec<Json>) -> Json {
    p.send_line("contacts list");
    let list = expect_tape(p, ROW, "contacts", tape);
    let found = list
        .get("list")
        .and_then(Json::as_array)
        .unwrap()
        .iter()
        .find(|c| c.get("id").and_then(Json::as_u64) == Some(id))
        .cloned();
    assert!(found.is_some(), "contact {id} is not listed: {list:?}");
    found.unwrap()
}

fn quit(p: &mut CliProc) {
    p.send_line("quit");
    expect(p, SHORT, "closed");
}

/// CL-04: `contacts list` shows id, name and state; `contacts verify <id> <60 digits>` with the digits of the peer's `contacts
/// sas` answers `verified` and the list shows the contact verified; a wrong number is `ok: false` and changes nothing.
#[test]
fn contacts_list_and_verify() {
    let root = scratch("cl04");
    let mut p = pair(&root, "cl04");
    let mut tape = Vec::new();
    let c = listed(&mut p.a, p.a_of_b, &mut tape);
    assert_eq!(text(&c, "state"), "unverified");
    assert!(c.get("name").and_then(Json::as_str).is_some(), "{c:?}");
    let digits = sas(&mut p.b, p.b_of_a, &mut tape);
    assert_eq!(digits.len(), 60);
    assert!(digits.bytes().all(|d| d.is_ascii_digit()));
    let mut wrong = digits.clone().into_bytes();
    let last = wrong.last_mut().unwrap();
    *last = if *last == b'0' { b'1' } else { b'0' };
    let wrong = String::from_utf8(wrong).unwrap();
    assert!(!verify(&mut p.a, p.a_of_b, &wrong, &mut tape));
    assert_eq!(
        text(&listed(&mut p.a, p.a_of_b, &mut tape), "state"),
        "unverified"
    );
    assert!(verify(&mut p.a, p.a_of_b, &digits, &mut tape));
    assert_eq!(
        text(&listed(&mut p.a, p.a_of_b, &mut tape), "state"),
        "verified"
    );
    quit(&mut p.a);
    quit(&mut p.b);
}

/// CL-05: `send <id> <text>` answers `queued` with the `msg_id`; later the `relayed` and the `delivered` events of that
/// `msg_id` follow (both sides verified first: receipts only for verified contacts, §10.4); the peer prints the `message`.
#[test]
fn send_and_tail() {
    let root = scratch("cl05");
    let mut p = pair(&root, "cl05");
    verify_both(&mut p);
    let mut tape = Vec::new();
    p.a.send_line(&format!("send {} hello bob", p.a_of_b));
    let queued = expect_tape(&mut p.a, ROW, "queued", &mut tape);
    let id = text(&queued, "msg_id");
    assert_eq!(id.len(), 32);
    for event in ["relayed", "delivered"] {
        let line = expect_where(&mut p.a, ROW, &mut tape, event, |v| {
            kind(v) == event && text(v, "msg_id") == id
        });
        assert_eq!(line.get("contact").and_then(Json::as_u64), Some(p.a_of_b));
    }
    let got = expect_tape(&mut p.b, ROW, "message", &mut tape);
    assert_eq!(text(&got, "text"), "hello bob");
    assert_eq!(text(&got, "msg_id"), id);
    quit(&mut p.a);
    quit(&mut p.b);
}

/// CL-06: `status` answers the mode, the direct flag, the numbers of links, contacts and spares, and the relay view lines
/// (AP-03); one profile, no pair.
#[test]
fn status_shape() {
    let root = scratch("cl06");
    let (dir, pass) = new_profile(&root, "alice", None);
    let mut p = open(&dir, &pass, "alice");
    expect(&mut p, LONG, "opened");
    p.send_line("status");
    let s = expect(&mut p, SHORT, "status");
    assert!(["strict", "balanced", "low_bw"].contains(&text(&s, "mode").as_str()));
    assert_eq!(text(&s, "mode"), "balanced", "direct implies Balanced");
    assert_eq!(s.get("direct").and_then(Json::as_bool), Some(true));
    assert!(s.get("links").and_then(Json::as_u64).is_some());
    assert_eq!(s.get("contacts").and_then(Json::as_u64), Some(0));
    assert!(s.get("spares").and_then(Json::as_u64).is_some());
    let view = s.get("relay_view").and_then(Json::as_array).unwrap();
    assert!(view.len() >= 5, "the five items of AP-03: {view:?}");
    assert!(
        view.iter()
            .all(|l| l.as_str().is_some_and(|l| !l.is_empty()))
    );
    quit(&mut p);
}

/// CL-07: `export <path> --backup-passphrase-file G` without `--confirm` is `error/confirm_required` and writes nothing; with
/// it the file is written (mode 0600) and `exported`; `import` into a new directory answers `imported` with the contacts, the
/// imported profile lists the contact in the state `reinvite_required`, and a `send` to it is `error/reinvite_required`.
#[test]
fn export_import() {
    let root = scratch("cl07");
    let mut p = pair(&root, "cl07");
    let backup = root.join("backup.smpb");
    let backup_pass = root.join("backup.pass");
    write_secret_file(&backup_pass, b"backup horse\n");
    let line = format!(
        "export {} --backup-passphrase-file {}",
        backup.display(),
        backup_pass.display()
    );
    p.a.send_line(&line);
    let refused = expect(&mut p.a, SHORT, "error");
    assert_eq!(text(&refused, "code"), "confirm_required");
    assert!(!backup.exists(), "nothing written without the confirmation");
    p.a.send_line(&format!("{line} --confirm"));
    expect(&mut p.a, ROW, "exported");
    assert!(backup.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    quit(&mut p.a);
    quit(&mut p.b);

    let new_dir = root.join("restored");
    let new_pass = root.join("restored.pass");
    write_secret_file(&new_pass, PASS);
    let out = run(&[
        "import",
        backup.to_str().unwrap(),
        new_dir.to_str().unwrap(),
        "--passphrase-file",
        new_pass.to_str().unwrap(),
        "--backup-passphrase-file",
        backup_pass.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{:?}", out.status);
    let l = lines(&out);
    assert_eq!(l.len(), 1);
    assert_eq!(kind(l.first().unwrap()), "imported");
    assert_eq!(
        l.first().unwrap().get("contacts").and_then(Json::as_u64),
        Some(1)
    );
    let out = run(&[
        "contacts",
        "list",
        new_dir.to_str().unwrap(),
        "--passphrase-file",
        new_pass.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{:?}", out.status);
    let l = lines(&out);
    let list = l
        .first()
        .unwrap()
        .get("list")
        .and_then(Json::as_array)
        .unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(text(list.first().unwrap(), "state"), "reinvite_required");
    let id = list
        .first()
        .unwrap()
        .get("id")
        .and_then(Json::as_u64)
        .unwrap();
    let mut r = open(&new_dir, &new_pass, "restored");
    expect(&mut r, LONG, "opened");
    r.send_line(&format!("send {id} hello again"));
    let refused = expect(&mut r, SHORT, "error");
    assert_eq!(text(&refused, "code"), "reinvite_required");
    quit(&mut r);
}

/// CL-08: `identity rotate` answers `identity_rotated` (without the fingerprint) and then one `key_change_sent` per contact: A
/// with the contacts B and C gives two lines.
#[test]
fn identity_rotate() {
    let root = scratch("cl08");
    let relay = E2eRelay::start(&root.join("relay"));
    let pass_text = PASS.strip_suffix(b"\n").unwrap();
    let (a_dir, a_pass) = new_profile(&root, "alice", Some(&relay.ref_path()));
    let (b_dir, b_pass) = new_profile(&root, "bob", Some(&relay.ref_path()));
    let (c_dir, c_pass) = new_profile(&root, "carol", Some(&relay.ref_path()));
    relay.seed_spares(&a_dir, pass_text, 4, "cl08-a");
    relay.seed_spares(&b_dir, pass_text, 2, "cl08-b");
    relay.seed_spares(&c_dir, pass_text, 2, "cl08-c");
    let mut tape = Vec::new();
    let mut a = open(&a_dir, &a_pass, "alice");
    expect_tape(&mut a, ROW, "opened", &mut tape);
    let mut ids = Vec::new();
    let mut others = Vec::new();
    for (dir, pass, name) in [(&b_dir, &b_pass, "bob"), (&c_dir, &c_pass, "carol")] {
        a.send_line("invite create");
        let uri = text(&expect_tape(&mut a, ROW, "invitation", &mut tape), "uri");
        let mut o = open(dir, pass, name);
        expect_tape(&mut o, ROW, "opened", &mut tape);
        assert!(accept_tape(&mut o, &uri, &mut tape).is_some());
        let contact = expect_tape(&mut a, ROW, "contact", &mut tape);
        ids.push(contact.get("id").and_then(Json::as_u64).unwrap());
        others.push(o);
    }
    assert_ne!(ids.first(), ids.get(1));
    a.send_line("identity rotate");
    let rotated = expect_tape(&mut a, ROW, "identity_rotated", &mut tape);
    assert_eq!(
        rotated.as_object().map(|o| o.keys().count()),
        Some(1),
        "only its type"
    );
    let mut sent = Vec::new();
    for _ in 0..2 {
        let line = expect_tape(&mut a, ROW, "key_change_sent", &mut tape);
        sent.push(line.get("contact").and_then(Json::as_u64).unwrap());
    }
    sent.sort_unstable();
    ids.sort_unstable();
    assert_eq!(sent, ids, "one line per contact");
    quit(&mut a);
    for o in &mut others {
        quit(o);
    }
}

/// Every key and string value of `v`, recursively: `f(key, value)`; array items have the key of their array.
fn walk(key: &str, v: &Json, f: &mut impl FnMut(&str, &Json)) {
    f(key, v);
    if let Some(object) = v.as_object() {
        for (k, item) in object {
            walk(k, item, f);
        }
    } else if let Some(array) = v.as_array() {
        for item in array {
            walk(key, item, f);
        }
    }
}

/// CL-09: every line of every verb is one JSON object with a `type`; no key names key material (`key`, `seed`, `secret`,
/// `fingerprint`, `passphrase`); no value is the passphrase, the access key (hex) or the invitation's URI outside the
/// `invitation` line; the only timestamp is the `at_ms` of a core event.
#[test]
fn jsonl_schema() {
    let root = scratch("cl09");
    let mut p = pair(&root, "cl09");
    let uri = p.uri.clone();
    verify_both(&mut p);
    let access = std::fs::read_to_string(p.relay.ref_path())
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("access_key = ").map(str::to_owned))
        .unwrap();
    assert_eq!(access.len(), 64);
    let backup = p.root.join("backup.smpb");
    let backup_pass = p.root.join("backup.pass");
    write_secret_file(&backup_pass, b"backup horse\n");

    let mut tape = std::mem::take(&mut p.tape);
    p.a.send_line(&format!("send {} schema", p.a_of_b));
    expect_tape(&mut p.a, ROW, "queued", &mut tape);
    p.a.send_line("status");
    expect_tape(&mut p.a, ROW, "status", &mut tape);
    p.a.send_line(&format!("rotate {}", p.a_of_b));
    expect_where(&mut p.a, ROW, &mut tape, "`rotated` or `error`", |v| {
        kind(v) == "rotated" || kind(v) == "error"
    });
    p.a.send_line("export nowhere");
    expect_tape(&mut p.a, SHORT, "error", &mut tape);
    p.a.send_line(&format!(
        "export {} --backup-passphrase-file {} --confirm",
        backup.display(),
        backup_pass.display()
    ));
    expect_tape(&mut p.a, ROW, "exported", &mut tape);
    p.a.send_line("identity rotate");
    expect_tape(&mut p.a, ROW, "identity_rotated", &mut tape);
    expect_tape(&mut p.a, ROW, "key_change_sent", &mut tape);
    expect_tape(&mut p.b, ROW, "message", &mut tape);
    p.a.send_line("quit");
    expect_tape(&mut p.a, SHORT, "closed", &mut tape);
    p.b.send_line("quit");
    expect_tape(&mut p.b, SHORT, "closed", &mut tape);
    // the one-shots
    let fresh = p.root.join("fresh");
    let fresh_pass = p.root.join("fresh.pass");
    write_secret_file(&fresh_pass, PASS);
    let out = run(&[
        "profile",
        "new",
        fresh.to_str().unwrap(),
        "--passphrase-file",
        fresh_pass.to_str().unwrap(),
    ]);
    tape.extend(lines(&out));
    let new_dir = p.root.join("restored");
    let new_pass = p.root.join("restored.pass");
    write_secret_file(&new_pass, PASS);
    let out = run(&[
        "import",
        backup.to_str().unwrap(),
        new_dir.to_str().unwrap(),
        "--passphrase-file",
        new_pass.to_str().unwrap(),
        "--backup-passphrase-file",
        backup_pass.to_str().unwrap(),
    ]);
    tape.extend(lines(&out));
    let out = run(&[
        "contacts",
        "list",
        p.a_dir.to_str().unwrap(),
        "--passphrase-file",
        p.a_pass.to_str().unwrap(),
    ]);
    tape.extend(lines(&out));

    check_schema(&tape, &uri, &access);
}

/// The rules of CL-09 over every line of `tape`.
fn check_schema(tape: &[Json], uri: &str, access: &str) {
    let secrets = ["correct horse", "backup horse", access];
    let mut seen_types = std::collections::BTreeSet::new();
    for line in tape {
        assert!(line.as_object().is_some(), "{line:?}");
        seen_types.insert(kind(line));
        let is_invitation = kind(line) == "invitation";
        walk("", line, &mut |key, v| {
            let k = key.to_ascii_lowercase();
            for bad in ["key", "seed", "secret", "fingerprint", "passphrase"] {
                assert!(!k.contains(bad), "key `{key}` in {line:?}");
            }
            if k.ends_with("_ms") || k.contains("time") || k == "ts" || k == "at" {
                assert_eq!(key, "at_ms", "a timestamp other than at_ms: {line:?}");
            }
            if let Some(s) = v.as_str() {
                for secret in &secrets {
                    assert!(!s.contains(secret), "a secret in {line:?}");
                }
                if !is_invitation {
                    assert!(
                        !s.contains(uri) && !s.contains("secmp://i/"),
                        "the URI in {line:?}"
                    );
                }
            }
        });
    }
    for want in [
        "created",
        "opened",
        "invitation",
        "contact",
        "contacts",
        "sas",
        "verified",
        "queued",
        "status",
        "exported",
        "identity_rotated",
        "key_change_sent",
        "imported",
        "closed",
        "error",
        "message",
    ] {
        assert!(
            seen_types.contains(want),
            "no `{want}` line: {seen_types:?}"
        );
    }
}

/// The seed of CL-14. The environment seed of the property tests is read by the one helper of `secmp-proto` only (R-93, X-07), and CI removes it
/// for this crate anyway: the row runs on this fixed seed.
const CL14_SEED: u64 = 0x5EC3_7000_C114;

/// A source of the seeded pseudo-random numbers of CL-14 (xorshift64*).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A number below `n` (`n` > 0).
    fn below(&mut self, n: u64) -> u64 {
        self.next().checked_rem(n).unwrap()
    }

    /// A random `i64`: negative, zero, huge — any.
    fn id(&mut self) -> i64 {
        match self.below(8) {
            0 => 0,
            1 => -1,
            2 => i64::MAX,
            3 => i64::MIN,
            4 => i64::try_from(self.below(10)).unwrap(),
            _ => i64::from_ne_bytes(self.next().to_ne_bytes()),
        }
    }

    /// A random character of the single-line text: not a line break, not a surrogate.
    fn text_char(&mut self) -> char {
        let c = u32::try_from(self.below(0x3000).saturating_add(0x20)).unwrap();
        char::from_u32(c).unwrap_or('x')
    }

    /// Random text of at most `max` bytes (a character is never cut).
    fn text(&mut self, max: usize) -> String {
        let mut s = String::new();
        while s.len() < max {
            let c = self.text_char();
            if s.len().saturating_add(c.len_utf8()) > max {
                break;
            }
            s.push(c);
        }
        s
    }

    /// A word without white space or control characters (an arbitrary non-space argument).
    fn word(&mut self, max: usize) -> String {
        let n = self.below(u64::try_from(max).unwrap()).saturating_add(1);
        (0..n)
            .map(|_| self.text_char())
            .filter(|c| !c.is_whitespace() && !c.is_control())
            .collect()
    }

    /// `1..=12` random digit groups of `1..=8` digits, separated by spaces.
    fn digit_groups(&mut self) -> String {
        let groups = self.below(12).saturating_add(1);
        (0..groups)
            .map(|_| {
                let n = self.below(8).saturating_add(1);
                (0..n)
                    .map(|_| char::from(b'0'.saturating_add(u8::try_from(self.below(10)).unwrap())))
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// `invite accept` with `secmp://i/` and random URI characters, or an arbitrary non-space word.
    fn invite_accept(&mut self) -> String {
        if self.below(2) == 0 {
            let n = self.below(401);
            let uri: String = (0..n)
                .map(|_| {
                    let set = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                    char::from(*set.get(usize::try_from(self.below(64)).unwrap()).unwrap())
                })
                .collect();
            format!("invite accept secmp://i/{uri}")
        } else {
            format!("invite accept {}", self.word(60))
        }
    }

    /// The text of a `send`: `1..=16 384` bytes, now and then more (16 385 and up).
    fn send_text(&mut self) -> String {
        let max = if self.below(20) == 0 {
            16_385_usize.saturating_add(usize::try_from(self.below(3_000)).unwrap())
        } else {
            usize::try_from(self.below(16_384))
                .unwrap()
                .saturating_add(1)
        };
        let mut text = self.text(max);
        if text.is_empty() {
            text.push('x');
        }
        text
    }

    /// One of the ten verbs that reach the runtime, with random arguments. Index 8 is `export` without `--confirm` (answered
    /// by `confirm_required` before any work); index 9 is `identity rotate`.
    fn runtime_line(&mut self, verb: u64, passphrase_file: &Path) -> String {
        match verb {
            0 => "status".to_owned(),
            1 => "contacts list".to_owned(),
            2 => format!("contacts sas {}", self.id()),
            3 => format!("contacts verify {} {}", self.id(), self.digit_groups()),
            4 => format!("send {} {}", self.id(), self.send_text()),
            5 => format!("rotate {}", self.id()),
            6 => "invite create".to_owned(),
            7 => self.invite_accept(),
            8 => format!(
                "export /tmp/secmp-cl14-{} --backup-passphrase-file {}",
                self.word(12),
                passphrase_file.display()
            ),
            _ => "identity rotate".to_owned(),
        }
    }
}

/// CL-14: ten thousand seeded lines (lines that start with `quit` are dropped) into one `open`: nothing panics, every line is
/// answered by one JSON line, the process exits 0. Sixty of them reach the runtime — with random arguments over all ten verbs
/// (`export` without `--confirm`: `confirm_required`, no Argon2; `identity rotate` at most six times) — the rest are
/// mangled verbs and random text, so usage errors; one over-long line (`LINE_MAX` + 1 bytes) and one line that is not UTF-8
/// are among them.
#[test]
fn stdin_commands_are_total() {
    const MANGLED: [&str; 8] = [
        "status",
        "contacts list",
        "contacts sas 7",
        "rotate 7",
        "invite create",
        "invite accept secmp://i/x",
        "export x --backup-passphrase-file y",
        "identity rotate",
    ];
    let mut rng = Rng(CL14_SEED | 1);
    let root = scratch("cl14");
    let (dir, pass) = new_profile(&root, "alice", None);
    let backup_pass = root.join("backup.pass");
    write_secret_file(&backup_pass, b"backup horse\n");
    let mut p = open(&dir, &pass, "alice");
    expect(&mut p, LONG, "opened");
    let (mut sent, mut runtime_calls, mut rotations) = (0_u32, 0_u32, 0_u32);
    let mut hits = [0_u32; 10];
    while sent < 10_000 {
        // the two special lines, at fixed places
        if sent == 1_234 {
            let mut long = vec![b'a'; secmp_cli::args::LINE_MAX + 1];
            long.push(b'\n');
            p.send_bytes(&long);
            sent = sent.saturating_add(1);
            continue;
        }
        if sent == 5_678 {
            p.send_bytes(b"\xff\xfe status\n");
            sent = sent.saturating_add(1);
            continue;
        }
        let r = rng.next();
        let line = match r % 100 {
            // a verb that reaches the runtime, rarely (a call waits for a chunk of the loop)
            0 if runtime_calls < 60 => {
                let mut verb = rng.below(10);
                if verb == 9 && rotations >= 6 {
                    verb = rng.below(9);
                }
                if verb == 9 {
                    rotations = rotations.saturating_add(1);
                }
                runtime_calls = runtime_calls.saturating_add(1);
                if let Some(hit) = hits.get_mut(usize::try_from(verb).unwrap()) {
                    *hit = hit.saturating_add(1);
                }
                rng.runtime_line(verb, &backup_pass)
            }
            // a verb with a mangled tail: a usage error
            1..=30 => {
                let verb = MANGLED.get(usize::try_from(rng.below(8)).unwrap()).unwrap();
                let cut = usize::try_from(rng.below(6)).unwrap().min(verb.len());
                let head = verb.get(..verb.len().saturating_sub(cut)).unwrap();
                format!("{head} \u{e9}\u{1f642}\t\"\\")
            }
            // random text, ASCII and not
            _ => {
                let n = usize::try_from(rng.below(40)).unwrap();
                rng.text(n)
            }
        };
        if line.starts_with("quit") {
            continue;
        }
        p.send_line(&line);
        sent = sent.saturating_add(1);
    }
    p.send_line("quit");
    let mut answers = 0_u32;
    loop {
        let v = p
            .next_json(ROW)
            .expect("a line, or the process ended without `closed`");
        if kind(&v) == "closed" {
            break;
        }
        answers = answers.saturating_add(1);
    }
    assert_eq!(answers, sent, "one JSON line per line");
    let status = p.wait_exit(SHORT).expect("the process ends");
    assert_eq!(status.code(), Some(0));
    assert_eq!(runtime_calls, 60);
    assert!(hits.iter().all(|h| *h > 0), "every verb was hit: {hits:?}");
}
