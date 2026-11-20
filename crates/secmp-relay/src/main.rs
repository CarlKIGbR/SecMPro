// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-relay` binary entry point; see the library crate documentation for responsibility and
//! allowed dependencies.
//!
//! ```text
//! secmp-relay                                       print the banner (the M0 hello check)
//! secmp-relay --config <file>                       serve (docs/05 §4)
//! secmp-relay keygen --out <file> [--valid-days N]  new identity and key generation 1; prints relay_fp
//! secmp-relay rotate-static --keys <file> [--valid-days N]   add generation kid + 1, drop the expired ones
//! secmp-relay spki <cert.der>                       the pin of the direct listener's certificate (docs/05 §7)
//! secmp-relay ref --keys <file> --onion <addr>.onion [--direct <host>:<port> --cert <cert.der>] --out <file>   the client's relay reference file (holds the access key; never printed)
//! ```
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use secmp_crypto::Zeroizing;
use secmp_proto::Encode as _;
use secmp_proto::link::ids::akc;
use secmp_proto::wire::inv::{Direct, Host, Onion, RelayRef};
use secmp_relay::clock::wall_clock_unix_secs;
use secmp_relay::event::{Event, EventSink as _, StderrSink};
use secmp_relay::keys::{DEFAULT_VALIDITY_SECS, KeyFile};
use secmp_relay::server::{self, Clock, Time as _};

const BANNER: &str = concat!(
    env!("CARGO_PKG_NAME"),
    " ",
    env!("CARGO_PKG_VERSION"),
    " (M5)"
);

fn out(line: &str) -> ExitCode {
    match writeln!(std::io::stdout().lock(), "{line}") {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

fn fail(why: &str) -> ExitCode {
    let _ = writeln!(std::io::stderr().lock(), "secmp-relay: {why}");
    ExitCode::FAILURE
}

/// `--valid-days N` → seconds (1..=60 days, checked by the key file).
fn validity(args: &[String]) -> Result<u64, &'static str> {
    match args.iter().position(|a| a == "--valid-days") {
        None => Ok(DEFAULT_VALIDITY_SECS),
        Some(i) => args
            .get(i.saturating_add(1))
            .and_then(|d| d.parse::<u64>().ok())
            .and_then(|d| d.checked_mul(86_400))
            .ok_or("--valid-days needs a number of days"),
    }
}

fn path_after(args: &[String], flag: &str) -> Option<PathBuf> {
    let i = args.iter().position(|a| a == flag)?;
    args.get(i.saturating_add(1)).map(PathBuf::from)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn value_after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let i = args.iter().position(|a| a == flag)?;
    args.get(i.saturating_add(1)).map(String::as_str)
}

fn hex_to(out: &mut String, bytes: &[u8]) {
    use std::fmt::Write as _;
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
}

/// The 35 bytes of a v3 onion address text (rend-spec-v3 §6, spec §5.3): 56 lower-case base32 characters and
/// `.onion`; the version and the checksum are checked by [`Onion::from_bytes`].
fn onion_of(text: &str) -> Option<Onion> {
    let label = text.strip_suffix(".onion")?;
    if label.len() != 56 {
        return None;
    }
    let mut bits: Vec<bool> = Vec::with_capacity(280);
    for c in label.bytes() {
        let v = b"abcdefghijklmnopqrstuvwxyz234567"
            .iter()
            .position(|a| *a == c)?;
        for shift in (0..5_u32).rev() {
            bits.push((v >> shift) & 1 == 1);
        }
    }
    let bytes: Vec<u8> = bits
        .as_chunks::<8>()
        .0
        .iter()
        .map(|byte| byte.iter().fold(0_u8, |a, b| (a << 1) | u8::from(*b)))
        .collect();
    Onion::from_bytes(&bytes).ok()
}

/// The text of the client's relay reference file (`relay_ref`, `access_key`; spec §5.3). It holds the access key and
/// lives only in a `Zeroizing` string; no error carries a value. It is built in one allocation of its exact length (no
/// reallocation leaves an unwiped copy).
fn ref_text(
    keys: &Path,
    onion: &str,
    direct: Option<(&str, &Path)>,
) -> Result<Zeroizing<String>, &'static str> {
    const KEYS: &str = "key file missing, unreadable or malformed";
    const HEAD: &str = "# SecMPro relay reference (spec §5.3); it holds the relay's access key: keep it private\nrelay_ref = ";
    const MID: &str = "\naccess_key = ";
    let ring = KeyFile::read(keys)
        .and_then(|f| f.ring())
        .map_err(|_| KEYS)?;
    let relay_fp = ring.newest().map_err(|_| KEYS)?.0.fp();
    let access = ring.access_key().map_err(|_| KEYS)?;
    let onion = onion_of(onion).ok_or("--onion needs a v3 onion address")?;
    let direct = match direct {
        None => None,
        Some((hostport, cert)) => {
            const USAGE: &str = "--direct needs <host>:<port>";
            let (host, port) = hostport.rsplit_once(':').ok_or(USAGE)?;
            let host = Host::from_bytes(host.as_bytes()).map_err(|_| USAGE)?;
            let port = port
                .parse::<u16>()
                .ok()
                .and_then(NonZeroU16::new)
                .ok_or(USAGE)?;
            let cert = std::fs::read(cert).map_err(|_| "cannot read the certificate")?;
            let spki_sha256 =
                secmp_relay::spki::pin_of(&cert).ok_or("not a DER X.509 certificate")?;
            Some(Direct {
                host,
                port,
                spki_sha256,
            })
        }
    };
    let encoded = RelayRef {
        relay_fp,
        onion,
        akc: akc(access),
        direct,
    }
    .encode()
    .map_err(|_| "the relay reference does not encode")?;
    let secret = access.expose_secret();
    let cap = encoded
        .len()
        .checked_mul(2)
        .and_then(|e| e.checked_add(HEAD.len()))
        .and_then(|n| n.checked_add(MID.len()))
        .and_then(|n| secret.len().checked_mul(2).and_then(|k| n.checked_add(k)))
        .and_then(|n| n.checked_add(1))
        .ok_or("the relay reference does not encode")?;
    let mut text = Zeroizing::new(String::with_capacity(cap));
    text.push_str(HEAD);
    hex_to(&mut text, &encoded);
    text.push_str(MID);
    hex_to(&mut text, secret);
    text.push('\n');
    Ok(text)
}

/// A new file at `path`, never overwriting; mode 0600 on Unix. Windows: no mode, the file inherits the directory's
/// ACL, exactly as the key file of `keygen` (HB-39). A partial file is removed on a write or sync error.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut f = options.open(path)?;
    let written = f.write_all(bytes).and_then(|()| f.sync_all());
    if written.is_err() {
        drop(f);
        let _ = std::fs::remove_file(path);
    }
    written
}

/// `ref`: the file `secmp-client-core`'s `read_relay_ref` reads. The only output is `ref written`.
fn reference(args: &[String]) -> ExitCode {
    let (Some(keys), Some(onion), Some(out_path)) = (
        path_after(args, "--keys"),
        value_after(args, "--onion"),
        path_after(args, "--out"),
    ) else {
        return fail("ref needs --keys <file>, --onion <address> and --out <file>");
    };
    let direct = match (value_after(args, "--direct"), path_after(args, "--cert")) {
        (None, None) => None,
        (Some(hostport), Some(cert)) => Some((hostport, cert)),
        _ => return fail("ref needs --direct and --cert together"),
    };
    let text = match ref_text(
        &keys,
        onion,
        direct.as_ref().map(|(h, c)| (*h, c.as_path())),
    ) {
        Ok(t) => t,
        Err(why) => return fail(why),
    };
    if write_private(&out_path, text.as_bytes()).is_err() {
        return fail("cannot write the reference file (it must not exist)");
    }
    out("ref written")
}

fn keygen(args: &[String]) -> ExitCode {
    let Some(path) = path_after(args, "--out") else {
        return fail("keygen needs --out <file>");
    };
    let secs = match validity(args) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let result = KeyFile::generate(wall_clock_unix_secs(), secs).and_then(|f| {
        f.write_new(&path)?;
        let ring = f.ring()?;
        Ok(ring.newest()?.0.fp())
    });
    match result {
        Ok(fp) => out(&format!("relay_fp {}", hex(&fp))),
        Err(e) => fail(&e.to_string()),
    }
}

fn rotate(args: &[String]) -> ExitCode {
    let Some(path) = path_after(args, "--keys") else {
        return fail("rotate-static needs --keys <file>");
    };
    let secs = match validity(args) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let result = KeyFile::read(&path).and_then(|mut f| {
        let kid = f.rotate(wall_clock_unix_secs(), secs)?;
        f.replace(&path)?;
        Ok(kid)
    });
    match result {
        Ok(kid) => out(&format!("kid {kid}")),
        Err(e) => fail(&e.to_string()),
    }
}

/// `spki <cert.der>`: the 64-hex SHA-256 of the certificate's `SubjectPublicKeyInfo` — the value clients pin as
/// `RelayRef.direct.spki_sha256` (spec D.3; TEST-SPEC-M6 TLS-15).
fn spki(args: &[String]) -> ExitCode {
    let Some(path) = args.get(1) else {
        return fail("spki needs <cert.der>");
    };
    let Ok(cert) = std::fs::read(path) else {
        return fail("cannot read the certificate");
    };
    match secmp_relay::spki::pin_of(&cert) {
        Some(pin) => out(&hex(&pin)),
        None => fail("not a DER X.509 certificate"),
    }
}

fn run(config: &std::path::Path) -> ExitCode {
    let clock = Clock::start();
    StderrSink.emit(&Event::Startup);
    let Ok((cfg, relay)) = server::prepare(config, Box::new(StderrSink), clock.now()) else {
        return ExitCode::FAILURE;
    };
    let relay = Arc::new(relay);
    #[cfg(feature = "direct-tls")]
    let direct = match &cfg.direct_tls {
        None => None,
        Some(d) => match secmp_relay::tls::load(&d.cert, &d.key) {
            Ok(tls) => Some((d.addr, tls)),
            Err(e) => {
                relay.events().emit(&Event::ConfigError {
                    reason: "direct_tls certificate or key",
                });
                return fail(&e.to_string());
            }
        },
    };
    let Ok(listener) = server::bind(&relay, cfg.listen) else {
        return fail("cannot bind the listener");
    };
    #[cfg(feature = "direct-tls")]
    if let Some((addr, tls)) = direct {
        let Ok(direct) = secmp_relay::tls::bind(&relay, addr, tls) else {
            return fail("cannot bind the direct_tls listener");
        };
        let both = secmp_relay::tls::Listeners::new(listener, direct);
        return match server::serve(&relay, &both, &clock, server::spawn_thread) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e.to_string()),
        };
    }
    match server::serve(&relay, &listener, &clock, server::spawn_thread) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&e.to_string()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("--version") => out(BANNER),
        Some("keygen") => keygen(&args),
        Some("rotate-static") => rotate(&args),
        Some("spki") => spki(&args),
        Some("ref") => reference(&args),
        Some("--config") => match path_after(&args, "--config") {
            Some(p) => run(&p),
            None => fail("--config needs a file"),
        },
        Some(_) => fail("unknown arguments (see the crate documentation)"),
    }
}
