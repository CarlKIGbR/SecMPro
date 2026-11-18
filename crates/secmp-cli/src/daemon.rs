// SPDX-License-Identifier: AGPL-3.0-or-later
//! The commands: `profile new` (one shot) and `open` (a long-lived session: stdin command lines in, JSON lines out).
//!
//! stdin is read on a `std::thread` that only forwards lines; what a line asks goes to the client core's runtime as a call, and
//! the runtime's loop answers it between two chunks of its schedule. Nothing typed here moves a slot: the links keep their
//! rhythm whatever stdin does (spec §10.1). Output is a JSON object per line (`json`), written only with `writeln!` to the
//! locked stdout; no key, seed, fingerprint, passphrase, relay reference or access key is ever printed, and no `Debug` of a
//! request or response — the one secret that appears is the invitation URI, as the answer to `invite create`.

use std::collections::BTreeMap;
use std::io::{BufRead, Read as _, Write as _};
use std::path::Path;

use secmp_client_core::api::runtime::{
    Answer, Call, Caller, Client, Notice, RuntimeConfig, create_profile, import_profile,
    list_contacts, start,
};
use secmp_client_core::api::{
    Contact, ContactId, ContactState, Error, Event, Mode, Request, Response,
};
use secmp_crypto::Zeroizing;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use crate::args::{LINE_MAX, Line, parse_line};
use crate::json::{Obj, hex, list, string};
use crate::lock::{self, Lock};
use crate::passphrase::{self, Refusal};

/// The stack of the threads that run the engine: the handshake and the ratchet keep large frames, and the main thread of a
/// Windows process has 1 MiB — the program does not depend on its caller's stack.
pub const ENGINE_STACK: usize = 64 << 20;

/// How long an invitation issued by `invite create` stays open (spec §5.2 allows 30 days at most).
const INVITE_LIFETIME_S: u64 = 86_400;

/// The name presented in a handshake when `--name` is not given.
const DEFAULT_NAME: &str = "secmp-cli";

/// Exit code: success.
pub const EXIT_OK: u8 = 0;
/// Exit code: any other failure.
pub const EXIT_OTHER: u8 = 1;
/// Exit code: a usage error.
pub const EXIT_USAGE: u8 = 2;
/// Exit code: the transport could not be started.
pub const EXIT_TRANSPORT: u8 = 3;
/// Exit code: the profile did not unlock.
pub const EXIT_UNLOCK: u8 = 4;
/// Exit code: another process holds the profile.
pub const EXIT_BUSY: u8 = 5;

/// Write one line to stdout. A closed pipe has nobody to tell: the line is dropped.
pub fn out(line: &str) {
    let _ = writeln!(std::io::stdout().lock(), "{line}");
}

/// Write one line to stderr.
pub fn err(line: &str) {
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

fn error_line(code: &'static str) -> String {
    Obj::new("error").text("code", code).done()
}

/// The code a refusal of the core is reported under (a fixed list; no id or detail).
const fn code_of(e: Error) -> &'static str {
    match e {
        Error::Unlock => "unlock",
        Error::Blocked | Error::ResetRequested => "blocked",
        Error::Frozen => "frozen",
        Error::ReinviteRequired => "reinvite_required",
        Error::ConfirmRequired => "confirm_required",
        Error::CloudFolder => "cloud_folder",
        Error::Unverified => "unverified",
        Error::Invitation(_) => "invitation",
        Error::Transport => "transport",
        _ => "unavailable",
    }
}

/// `profile new <dir> --passphrase-file F [--relay R]`.
#[must_use]
pub fn profile_new(dir: &Path, passphrase_file: &Path, relay: Option<&Path>) -> u8 {
    let pass = match read_passphrase(passphrase_file) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let Ok(relay_text) = relay.map(read_text).transpose() else {
        err("the relay reference file cannot be read");
        return EXIT_USAGE;
    };
    match create_profile(dir, &pass, relay_text.as_ref().map(|t| t.as_str())) {
        Ok(()) => {
            out(&Obj::new("created").done());
            EXIT_OK
        }
        Err(e) => {
            out(&error_line(code_of(e)));
            EXIT_OTHER
        }
    }
}

fn read_text(path: &Path) -> Result<Zeroizing<String>, ()> {
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|_| ())?);
    Ok(Zeroizing::new(
        std::str::from_utf8(&bytes).map_err(|_| ())?.to_owned(),
    ))
}

/// The passphrase of `--passphrase-file`, or the exit code to end with (the reason goes to stderr, stdout stays empty).
fn read_passphrase(path: &Path) -> Result<Zeroizing<Vec<u8>>, u8> {
    passphrase::read(path).map_err(|why| {
        err(match why {
            Refusal::Mode => "refused: the passphrase file is accessible to group or others",
            Refusal::Unreadable => "refused: the passphrase file cannot be used",
        });
        EXIT_USAGE
    })
}

/// What `open` was asked.
pub struct OpenArgs<'a> {
    /// The profile directory.
    pub dir: &'a Path,
    /// The passphrase file.
    pub passphrase_file: &'a Path,
    /// Direct TLS instead of Tor.
    pub direct: bool,
    /// The name presented in a handshake.
    pub name: Option<&'a str>,
}

/// `open`: returns the exit code.
#[must_use]
pub fn open(a: &OpenArgs<'_>) -> u8 {
    let pass = match read_passphrase(a.passphrase_file) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let _lock = match Lock::acquire(a.dir) {
        Ok(l) => l,
        Err(lock::Refusal::Busy) => {
            out(&error_line("busy"));
            return EXIT_BUSY;
        }
        Err(lock::Refusal::Unavailable) => {
            out(&error_line("unavailable"));
            return EXIT_OTHER;
        }
    };
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(ENGINE_STACK)
        .build()
    else {
        out(&error_line("unavailable"));
        return EXIT_OTHER;
    };
    runtime.block_on(session(a, &pass))
}

async fn session(a: &OpenArgs<'_>, pass: &[u8]) -> u8 {
    let cfg = RuntimeConfig {
        direct: a.direct,
        name: a.name.unwrap_or(DEFAULT_NAME).to_owned(),
    };
    let (client, serve) = match start(a.dir, pass, cfg) {
        Ok(parts) => parts,
        Err(e) => {
            out(&error_line(code_of(e)));
            return match e {
                Error::Unlock => EXIT_UNLOCK,
                Error::Transport => EXIT_TRANSPORT,
                _ => EXIT_OTHER,
            };
        }
    };
    out(&Obj::new("opened").done());
    let caller = client.caller();
    let events = tokio::spawn(events(client));
    let input = tokio::spawn(input(caller, stdin_lines(), a.direct));
    serve.run().await;
    let stopped = events.await.unwrap_or(false);
    // the stdin thread blocks in a read: the task that waits for it is dropped
    input.abort();
    let (line, code) = session_end(stopped);
    out(&line);
    code
}

/// How a session ends: `quit` or the end of stdin is `closed` and exit 0; a loop that stopped by itself (no randomness: fail
/// closed) is an `unavailable` error and exit 1 — not a clean close.
fn session_end(stopped: bool) -> (String, u8) {
    if stopped {
        (error_line("unavailable"), EXIT_OTHER)
    } else {
        (Obj::new("closed").done(), EXIT_OK)
    }
}

/// The next line of `input` (without its newline): a line over [`LINE_MAX`] bytes is drained to its newline and given empty, as
/// is one that is not UTF-8 — a usage error either way. `None` at the end of the input or on a read error.
fn next_line(input: &mut impl BufRead) -> Option<Zeroizing<String>> {
    let cap = u64::try_from(LINE_MAX.saturating_add(2)).unwrap_or(u64::MAX);
    let mut buf = Zeroizing::new(Vec::new());
    let read = input.by_ref().take(cap).read_until(b'\n', &mut buf).ok()?;
    if read == 0 {
        return None;
    }
    let ended = buf.last() == Some(&b'\n');
    if ended {
        buf.pop();
    }
    if buf.len() > LINE_MAX {
        // the rest of the line is read and dropped, a piece at a time
        let mut rest = ended;
        while !rest {
            let mut piece = Zeroizing::new(Vec::new());
            let n = input
                .by_ref()
                .take(cap)
                .read_until(b'\n', &mut piece)
                .ok()?;
            rest = n == 0 || piece.last() == Some(&b'\n');
        }
        return Some(Zeroizing::new(String::new()));
    }
    Some(Zeroizing::new(
        std::str::from_utf8(&buf)
            .map(str::to_owned)
            .unwrap_or_default(),
    ))
}

/// stdin on a thread of its own, forwarding the lines.
fn stdin_lines() -> UnboundedReceiver<Zeroizing<String>> {
    let (tx, rx) = unbounded_channel();
    let _ = std::thread::Builder::new().spawn(move || {
        let mut stdin = std::io::stdin().lock();
        while let Some(line) = next_line(&mut stdin) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// The lines the user types, until `quit` or the end of stdin.
async fn input(caller: Caller, mut lines: UnboundedReceiver<Zeroizing<String>>, direct: bool) {
    while let Some(line) = lines.recv().await {
        match parse_line(&line) {
            Err(_) => out(&error_line("usage")),
            Ok(Line::Quit) => break,
            Ok(command) => out(&run_line(&caller, command, direct).await),
        }
    }
    let _ = caller.call(Call::Quit).await;
}

const fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Strict => "strict",
        Mode::Balanced => "balanced",
        Mode::LowBw => "low_bw",
    }
}

/// The one output line of a command.
async fn run_line(caller: &Caller, command: Line, direct: bool) -> String {
    match command {
        Line::InviteCreate => {
            let call = Call::InviteCreate {
                expires_s: INVITE_LIFETIME_S,
            };
            answer_line(caller.call(call).await)
        }
        Line::InviteAccept(uri) => {
            // the contact (or the refusal) is reported when the handshake's first step has run
            match caller.call(Call::InviteAccept { uri }).await {
                Ok(Answer::Accepting) => Obj::new("accepting").done(),
                other => answer_line(other),
            }
        }
        Line::ContactsList => answer_line(caller.call(Call::Core(Request::Contacts)).await),
        Line::ContactsSas(id) => {
            let request = Request::SafetyNumber {
                contact: ContactId(id),
            };
            match caller.call(Call::Core(request)).await {
                Ok(Answer::Core(Response::SafetyNumber(digits))) => Obj::new("sas")
                    .num("contact", number(id))
                    .text("digits", &digits)
                    .done(),
                other => answer_line(other),
            }
        }
        Line::ContactsVerify(id, digits) => {
            let request = Request::Verify {
                contact: ContactId(id),
                digits,
            };
            match caller.call(Call::Core(request)).await {
                Ok(Answer::Core(Response::Verified(ok))) => Obj::new("verified")
                    .num("contact", number(id))
                    .flag("ok", ok)
                    .done(),
                other => answer_line(other),
            }
        }
        Line::Status => status_line(caller, direct).await,
        Line::IdentityRotate => match caller.call(Call::Core(Request::RotateIdentity)).await {
            // the new fingerprint is not printed
            Ok(Answer::Core(Response::IdentityRotated(_))) => Obj::new("identity_rotated").done(),
            other => answer_line(other),
        },
        Line::Rotate(id) => {
            let request = Request::Rotate {
                contact: ContactId(id),
                relay: 1,
            };
            match caller.call(Call::Core(request)).await {
                Ok(Answer::Core(Response::Rotated(started))) => Obj::new("rotated")
                    .num("contact", number(id))
                    .flag("started", started)
                    .done(),
                other => answer_line(other),
            }
        }
        Line::Send(id, text) => {
            let request = Request::Send {
                contact: ContactId(id),
                kind: 1,
                payload: Zeroizing::new(text.into_bytes()),
                expire_after: 0,
            };
            answer_line(caller.call(Call::Core(request)).await)
        }
        Line::Export {
            path,
            passphrase_file,
            confirm,
            force,
        } => {
            // a passphrase file that is refused is a usage error (the reason is not told in a session)
            let Ok(passphrase) = passphrase::read(&passphrase_file) else {
                return error_line("usage");
            };
            let call = Call::Export {
                path,
                passphrase,
                confirm,
                force,
            };
            match caller.call(call).await {
                Ok(Answer::Core(Response::Done)) => Obj::new("exported").done(),
                other => answer_line(other),
            }
        }
        Line::Quit => Obj::new("closed").done(),
    }
}

/// `status`: the runtime's numbers and the relay view (AP-03) of its mode and transport.
async fn status_line(caller: &Caller, direct: bool) -> String {
    let status = match caller.call(Call::Status).await {
        Ok(Answer::Status(status)) => status,
        other => return answer_line(other),
    };
    let request = Request::RelayView {
        direct: status.direct || direct,
    };
    let view = match caller.call(Call::Core(request)).await {
        Ok(Answer::Core(Response::RelayView(lines))) => lines,
        other => return answer_line(other),
    };
    let items: Vec<String> = view.iter().map(|l| string(l)).collect();
    Obj::new("status")
        .text("mode", mode_name(status.mode))
        .flag("direct", status.direct)
        .num("links", u64::try_from(status.links).unwrap_or(u64::MAX))
        .num(
            "contacts",
            u64::try_from(status.contacts).unwrap_or(u64::MAX),
        )
        .num("spares", u64::try_from(status.spares).unwrap_or(u64::MAX))
        .raw("relay_view", &list(&items))
        .done()
}

/// The `contacts` line (also the answer of the one-shot `contacts list`).
fn contacts_line(contacts: &[Contact]) -> String {
    let items: Vec<String> = contacts
        .iter()
        .map(|c| {
            let state = match (&c.state, c.verified) {
                (ContactState::Active, true) => "verified",
                (ContactState::Active, false) => "unverified",
                (ContactState::ReinviteRequired, _) => "reinvite_required",
                _ => "removed",
            };
            format!(
                "{{\"id\":{},\"name\":{},\"state\":{}}}",
                c.id.0,
                string(c.display_name.as_deref().unwrap_or_default()),
                string(state)
            )
        })
        .collect();
    Obj::new("contacts").raw("list", &list(&items)).done()
}

fn answer_line(answer: Result<Answer, Error>) -> String {
    match answer {
        Ok(Answer::Invitation { uri }) => Obj::new("invitation").text("uri", &uri).done(),
        Ok(Answer::PoolEmpty) => error_line("pool_empty"),
        Ok(Answer::Core(Response::Contacts(contacts))) => contacts_line(&contacts),
        Ok(Answer::Core(Response::Sent(id))) => Obj::new("queued").text("msg_id", &hex(&id)).done(),
        Ok(_) => error_line("unavailable"),
        Err(e) => error_line(code_of(e)),
    }
}

/// `contacts list <dir> --passphrase-file F`: the contacts of a profile no process has open.
#[must_use]
pub fn contacts_list(dir: &Path, passphrase_file: &Path) -> u8 {
    let pass = match read_passphrase(passphrase_file) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let _lock = match take_lock(dir) {
        Ok(l) => l,
        Err(code) => return code,
    };
    match list_contacts(dir, &pass) {
        Ok(contacts) => {
            out(&contacts_line(&contacts));
            EXIT_OK
        }
        Err(e) => one_shot_error(e),
    }
}

/// `import <backup> <newdir> --passphrase-file F --backup-passphrase-file G`: a backup into a new profile.
#[must_use]
pub fn import(
    backup: &Path,
    dir: &Path,
    passphrase_file: &Path,
    backup_passphrase_file: &Path,
) -> u8 {
    let pass = match read_passphrase(passphrase_file) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let backup_pass = match read_passphrase(backup_passphrase_file) {
        Ok(p) => p,
        Err(code) => return code,
    };
    if std::fs::create_dir_all(dir).is_err() {
        out(&error_line("unavailable"));
        return EXIT_OTHER;
    }
    let _lock = match take_lock(dir) {
        Ok(l) => l,
        Err(code) => return code,
    };
    match import_profile(dir, &pass, backup, &backup_pass) {
        Ok(n) => {
            let n = u64::try_from(n).unwrap_or(u64::MAX);
            out(&Obj::new("imported").num("contacts", n).done());
            EXIT_OK
        }
        Err(e) => one_shot_error(e),
    }
}

/// The profile lock of a one-shot, or the exit code to end with (the error line is written).
fn take_lock(dir: &Path) -> Result<Lock, u8> {
    Lock::acquire(dir).map_err(|why| match why {
        lock::Refusal::Busy => {
            out(&error_line("busy"));
            EXIT_BUSY
        }
        lock::Refusal::Unavailable => {
            out(&error_line("unavailable"));
            EXIT_OTHER
        }
    })
}

fn one_shot_error(e: Error) -> u8 {
    out(&error_line(code_of(e)));
    match e {
        Error::Unlock => EXIT_UNLOCK,
        _ => EXIT_OTHER,
    }
}

/// The notices of the runtime, as lines.
///
/// Returns whether the runtime reported that its loop stopped by itself.
async fn events(mut client: Client) -> bool {
    let caller = client.caller();
    let mut stopped = false;
    let mut seen = BTreeMap::new();
    while let Some(notice) = client.next_event().await {
        match notice {
            Notice::Event(stamped) => {
                if repeats(&mut seen, &stamped.event) {
                    continue;
                }
                let line = event_line(&caller, stamped.at_ms, &stamped.event).await;
                out(&line);
            }
            Notice::Refused => out(&Obj::new("event").text("name", "Refused").done()),
            Notice::Stopped => stopped = true,
            _ => out(&error_line("unavailable")),
        }
    }
    stopped
}

/// D-B55 (g): `ContactRemoved` and `ResetRequested` of one contact are printed once until its state changes — another event
/// of that contact, or the other of the two.
fn repeats(seen: &mut BTreeMap<i64, &'static str>, event: &Event) -> bool {
    let (contact, name) = match event {
        Event::ContactRemoved(c) => (c.0, "ContactRemoved"),
        Event::ResetRequested(c) => (c.0, "ResetRequested"),
        other => {
            if let Some(c) = contact_of(other) {
                seen.remove(&c);
            }
            return false;
        }
    };
    seen.insert(contact, name) == Some(name)
}

const fn contact_of(event: &Event) -> Option<i64> {
    match event {
        Event::RotationDeferred(c)
        | Event::RoutesChanged(c)
        | Event::KeyChanged(c)
        | Event::KeyChangeInvalid(c)
        | Event::ContactRemoved(c)
        | Event::ResetRequested(c)
        | Event::SuccessionPending(c)
        | Event::KeyChangeSent(c)
        | Event::ContactAdded(c) => Some(c.0),
        Event::NotConfirmed { contact, .. }
        | Event::MessageReceived { contact, .. }
        | Event::Relayed { contact, .. }
        | Event::Delivered { contact, .. } => Some(contact.0),
        Event::DuplicateIdentity { new, .. } => Some(new.0),
        _ => None,
    }
}

fn number(id: i64) -> u64 {
    u64::try_from(id).unwrap_or_default()
}

async fn event_line(caller: &Caller, at_ms: u64, event: &Event) -> String {
    match event {
        Event::ContactAdded(id) => Obj::new("contact")
            .num("id", number(id.0))
            .text("state", "unverified")
            .done(),
        Event::InviteFailed(_) => error_line("invitation"),
        Event::MessageReceived {
            contact,
            msg_id,
            kind,
        } => {
            let request = Request::Message {
                contact: *contact,
                msg_id: *msg_id,
            };
            if let Ok(Answer::Core(Response::Message { payload, .. })) =
                caller.call(Call::Core(request)).await
            {
                return Obj::new("message")
                    .num("contact", number(contact.0))
                    .text("msg_id", &hex(msg_id))
                    .num("kind", u64::from(*kind))
                    .num("at_ms", at_ms)
                    .text("text", &String::from_utf8_lossy(&payload))
                    .done();
            }
            // a view-once is not in the history: only the fact
            Obj::new("event")
                .text("name", "MessageReceived")
                .num("contact", number(contact.0))
                .done()
        }
        Event::Relayed { contact, msg_id } => Obj::new("relayed")
            .num("contact", number(contact.0))
            .text("msg_id", &hex(msg_id))
            .done(),
        Event::Delivered { contact, msg_id } => Obj::new("delivered")
            .num("contact", number(contact.0))
            .text("msg_id", &hex(msg_id))
            .done(),
        Event::KeyChangeSent(contact) => Obj::new("key_change_sent")
            .num("contact", number(contact.0))
            .done(),
        other => {
            let line = Obj::new("event").text("name", &format!("{other:?}"));
            match contact_of(other) {
                Some(id) => line.num("contact", number(id)).done(),
                None => line.done(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D-B55 (g): a repeated `ContactRemoved` or `ResetRequested` of one contact is printed once; another event of the contact,
    /// or the other of the two, makes the next one new again; another contact is its own.
    #[test]
    fn removal_events_are_printed_once() {
        let mut seen = BTreeMap::new();
        let (a, b) = (ContactId(1), ContactId(2));
        assert!(!repeats(&mut seen, &Event::ContactRemoved(a)));
        assert!(repeats(&mut seen, &Event::ContactRemoved(a)));
        assert!(!repeats(&mut seen, &Event::ContactRemoved(b)));
        assert!(!repeats(&mut seen, &Event::ResetRequested(a)));
        assert!(repeats(&mut seen, &Event::ResetRequested(a)));
        assert!(!repeats(&mut seen, &Event::KeyChanged(a)));
        assert!(!repeats(&mut seen, &Event::ResetRequested(a)));
        assert!(repeats(&mut seen, &Event::ContactRemoved(b)));
    }

    /// A line is cut at `LINE_MAX` bytes: a longer one is drained to its newline and forwarded empty, the next line is whole;
    /// a line that is not UTF-8 is forwarded empty; the last line needs no newline.
    #[test]
    fn long_lines_are_drained() {
        let mut data = Vec::new();
        data.extend_from_slice(&vec![b'a'; LINE_MAX]);
        data.extend_from_slice(b"\n");
        data.extend_from_slice(&vec![b'b'; LINE_MAX + 1]);
        data.extend_from_slice(b"\nstatus\n");
        data.extend_from_slice(&vec![b'c'; 3 * LINE_MAX]);
        data.extend_from_slice(b"\n\xff\xfe\nlast");
        let mut input = std::io::Cursor::new(data);
        let lines: Vec<String> = std::iter::from_fn(|| next_line(&mut input))
            .map(|l| l.as_str().to_owned())
            .collect();
        let lens: Vec<usize> = lines.iter().map(String::len).collect();
        assert_eq!(lens, [LINE_MAX, 0, 6, 0, 0, 4]);
        assert_eq!(lines.get(2).map(String::as_str), Some("status"));
        assert_eq!(lines.last().map(String::as_str), Some("last"));
    }

    /// M7-C1b (C1-8): a session whose loop stopped by itself ends with the `unavailable` error and exit 1, not `closed` and 0.
    #[test]
    fn stopped_session_exits_1() {
        assert_eq!(
            session_end(true),
            (
                "{\"type\":\"error\",\"code\":\"unavailable\"}".to_owned(),
                1
            )
        );
        assert_eq!(session_end(false), ("{\"type\":\"closed\"}".to_owned(), 0));
    }
}
