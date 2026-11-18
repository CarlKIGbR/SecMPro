// SPDX-License-Identifier: AGPL-3.0-or-later
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
