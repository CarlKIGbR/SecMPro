// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `secmp-relay` command line (`docs/05` §6 runbook: `keygen`, `rotate-static`; `--config`): the binary is run
//! as a child process on files in a fresh temporary directory, never with a listener (no network in tests,
//! `docs/06` §4). Extra tests of M5 Phase B (not TEST-SPEC rows).
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

use secmp_relay::KeyFile;

fn relay(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_secmp-relay"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8(o.stderr.clone()).unwrap()
}

/// A fresh, empty directory for one test.
fn scratch(name: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "secmp-relay-cli-{}-{name}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// `p` as a string of the configuration's TOML subset, which takes no backslash (`config.rs`): Windows accepts `/`.
fn toml_path(p: &Path) -> String {
    s(p).replace('\\', "/")
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut out, x| {
        let _ = write!(out, "{x:02x}");
        out
    })
}

fn wall_secs() -> u64 {
    secmp_relay::clock::wall_clock_unix_secs()
}

/// No arguments and `--version` print the banner (the M0 hello check) and succeed.
#[test]
fn cli_prints_the_banner() {
    for args in [&[][..], &["--version"][..]] {
        let o = relay(args);
        assert!(o.status.success(), "{args:?}");
        let expected = concat!("secmp-relay ", env!("CARGO_PKG_VERSION"), " (M5)\n");
        assert_eq!(stdout(&o), expected, "{args:?}");
    }
}

/// `keygen --out` writes a key file of generation 1 (45 days by default, `docs/05` §5), prints `relay_fp`, and
/// never overwrites an existing file.
#[test]
fn cli_keygen_writes_a_key_file_and_prints_relay_fp() {
    let dir = scratch("keygen");
    let path = dir.join("relay-keys");
    let before = wall_secs();
    let o = relay(&["keygen", "--out", s(&path)]);
    let after = wall_secs();
    assert!(o.status.success(), "{}", stderr(&o));
    let file = KeyFile::read(&path).unwrap();
    let ring = file.ring().unwrap();
    let (keys, until) = ring.newest().unwrap();
    assert_eq!(stdout(&o), format!("relay_fp {}\n", hex(&keys.fp())));
    assert_eq!(ring.kids(), vec![1]);
    assert!(until >= before + 3_888_000 && until <= after + 3_888_000);
    // a second keygen to the same path fails and leaves the file as it was
    let bytes = std::fs::read(&path).unwrap();
    let again = relay(&["keygen", "--out", s(&path)]);
    assert!(!again.status.success());
    assert!(stderr(&again).starts_with("secmp-relay: "));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the key file is private");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `--valid-days N` sets the validity; 0, more than 60 days (spec §8.2) and a non-number are refused.
#[test]
fn cli_keygen_takes_the_validity_in_days() {
    let dir = scratch("valid-days");
    let path = dir.join("k10");
    let before = wall_secs();
    let o = relay(&["keygen", "--out", s(&path), "--valid-days", "10"]);
    let after = wall_secs();
    assert!(o.status.success(), "{}", stderr(&o));
    let until = KeyFile::read(&path)
        .unwrap()
        .generations()
        .first()
        .unwrap()
        .valid_until;
    assert!(until >= before + 864_000 && until <= after + 864_000);
    let sixty = dir.join("k60");
    assert!(
        relay(&["keygen", "--out", s(&sixty), "--valid-days", "60"])
            .status
            .success()
    );
    for bad in ["0", "61", "x", ""] {
        let p = dir.join(format!("bad-{bad}"));
        let o = relay(&["keygen", "--out", s(&p), "--valid-days", bad]);
        assert!(!o.status.success(), "--valid-days {bad:?}");
        assert!(!p.exists(), "--valid-days {bad:?} wrote a file");
    }
    let o = relay(&["keygen", "--out", s(&dir.join("k-missing")), "--valid-days"]);
    assert!(!o.status.success());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `rotate-static --keys` adds generation `kid + 1`, keeps `relay_sig` (the fingerprint) and prints the new `kid`.
#[test]
fn cli_rotate_static_adds_the_next_generation() {
    let dir = scratch("rotate");
    let path = dir.join("relay-keys");
    assert!(relay(&["keygen", "--out", s(&path)]).status.success());
    let fp = KeyFile::read(&path)
        .unwrap()
        .ring()
        .unwrap()
        .newest()
        .unwrap()
        .0
        .fp();
    let o = relay(&["rotate-static", "--keys", s(&path)]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(stdout(&o), "kid 2\n");
    let ring = KeyFile::read(&path).unwrap().ring().unwrap();
    assert_eq!(ring.kids(), vec![1, 2]);
    assert_eq!(ring.newest().unwrap().0.fp(), fp);
    assert!(
        !dir.join("relay-keys.new").exists(),
        "the temporary file is renamed away"
    );
    let o = relay(&["rotate-static", "--keys", s(&path), "--valid-days", "61"]);
    assert!(!o.status.success());
    let o = relay(&["rotate-static", "--keys", s(&path), "--valid-days", "x"]);
    assert!(!o.status.success());
    assert_eq!(
        stderr(&o),
        "secmp-relay: --valid-days needs a number of days\n"
    );
    assert_eq!(
        KeyFile::read(&path).unwrap().ring().unwrap().kids(),
        vec![1, 2]
    );
    let missing = relay(&["rotate-static", "--keys", s(&dir.join("absent"))]);
    assert!(!missing.status.success());
    assert_eq!(
        stderr(&missing),
        "secmp-relay: key file missing, unreadable or malformed\n"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Missing values and unknown arguments are refused with a message and a failing exit status.
#[test]
fn cli_refuses_incomplete_and_unknown_arguments() {
    for (args, why) in [
        (&["keygen"][..], "secmp-relay: keygen needs --out <file>\n"),
        (
            &["rotate-static"][..],
            "secmp-relay: rotate-static needs --keys <file>\n",
        ),
        (&["--config"][..], "secmp-relay: --config needs a file\n"),
        (
            &["serve"][..],
            "secmp-relay: unknown arguments (see the crate documentation)\n",
        ),
    ] {
        let o = relay(args);
        assert!(!o.status.success(), "{args:?}");
        assert_eq!(stderr(&o), why, "{args:?}");
        assert!(stdout(&o).is_empty(), "{args:?}");
    }
}

/// A configuration that cannot be read, or one naming a missing key file, refuses the start (before any listener
/// binds) with a `config_error` event.
#[test]
fn cli_config_errors_refuse_the_start() {
    let dir = scratch("config");
    let o = relay(&["--config", s(&dir.join("absent.toml"))]);
    assert!(!o.status.success());
    let err = stderr(&o);
    assert!(err.contains("secmp-relay: startup secmp-relay "), "{err}");
    assert!(
        err.contains("secmp-relay: config_error cannot read the file\n"),
        "{err}"
    );
    assert!(!err.contains("listener_bound"), "{err}");
    let cfg = dir.join("relay.toml");
    std::fs::write(
        &cfg,
        format!(
            "[listen]\ntor_loopback = \"127.0.0.1:7443\"\n[access]\nkey_file = \"{}\"\n",
            toml_path(&dir.join("no-keys"))
        ),
    )
    .unwrap();
    let o = relay(&["--config", s(&cfg)]);
    assert!(!o.status.success());
    let err = stderr(&o);
    assert!(
        err.contains("secmp-relay: config_error key file missing, unreadable or malformed\n"),
        "{err}"
    );
    assert!(!err.contains("listener_bound"), "{err}");
    std::fs::remove_dir_all(&dir).unwrap();
}
