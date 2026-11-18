// SPDX-License-Identifier: AGPL-3.0-or-later
//! The commands: `profile new` (one shot) and `open` (a long-lived session: stdin command lines in, JSON lines out).
//!
//! stdin is read on a `std::thread` that only forwards lines; what a line asks goes to the client core's runtime as a call, and
//! the runtime's loop answers it between two chunks of its schedule. Nothing typed here moves a slot: the links keep their
//! rhythm whatever stdin does (spec §10.1). Output is a JSON object per line (`json`), written only with `writeln!` to the
//! locked stdout; no key, seed, fingerprint, passphrase, relay reference or access key is ever printed, and no `Debug` of a
//! request or response — the one secret that appears is the invitation URI, as the answer to `invite create`.

use std::io::{BufRead as _, Write as _};
use std::path::Path;

use secmp_client_core::api::runtime::{
    Answer, Call, Caller, Client, Notice, RuntimeConfig, create_profile, start,
};
use secmp_client_core::api::{ContactState, Error, Event, Request, Response};
use secmp_crypto::Zeroizing;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use crate::args::{Line, parse_line};
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
        Error::Blocked | Error::Frozen | Error::ResetRequested | Error::ReinviteRequired => {
            "blocked"
        }
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
    let input = tokio::spawn(input(caller, stdin_lines()));
    serve.run().await;
    let _ = events.await;
    // the stdin thread blocks in a read: the task that waits for it is dropped, the process ends with `closed`
    input.abort();
    out(&Obj::new("closed").done());
    EXIT_OK
}

/// stdin on a thread of its own, forwarding the lines (a line that is not UTF-8 is forwarded empty: a usage error).
fn stdin_lines() -> UnboundedReceiver<String> {
    let (tx, rx) = unbounded_channel();
    let _ = std::thread::Builder::new().spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => String::new(),
                Err(_) => break,
            };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// The lines the user types, until `quit` or the end of stdin.
async fn input(caller: Caller, mut lines: UnboundedReceiver<String>) {
    while let Some(line) = lines.recv().await {
        match parse_line(&line) {
            Err(_) => out(&error_line("usage")),
            Ok(Line::Quit) => break,
            Ok(command) => out(&run_line(&caller, command).await),
        }
    }
    let _ = caller.call(Call::Quit).await;
}

/// The one output line of a command.
async fn run_line(caller: &Caller, command: Line) -> String {
    let answer = match command {
        Line::InviteCreate => {
            caller
                .call(Call::InviteCreate {
                    expires_s: INVITE_LIFETIME_S,
                })
                .await
        }
        Line::InviteAccept(uri) => {
            return match caller
                .call(Call::InviteAccept {
                    uri: Zeroizing::new(uri),
                })
                .await
            {
                // the contact (or the refusal) is reported when the handshake's first step has run
                Ok(Answer::Accepting) => Obj::new("accepting").done(),
                other => answer_line(other),
            };
        }
        Line::ContactsList => caller.call(Call::Core(Request::Contacts)).await,
        Line::Send(id, text) => {
            caller
                .call(Call::Core(Request::Send {
                    contact: secmp_client_core::api::ContactId(id),
                    kind: 1,
                    payload: Zeroizing::new(text.into_bytes()),
                    expire_after: 0,
                }))
                .await
        }
        Line::Quit => return Obj::new("closed").done(),
    };
    answer_line(answer)
}

fn answer_line(answer: Result<Answer, Error>) -> String {
    match answer {
        Ok(Answer::Invitation { uri }) => Obj::new("invitation").text("uri", &uri).done(),
        Ok(Answer::PoolEmpty) => error_line("pool_empty"),
        Ok(Answer::Core(Response::Contacts(contacts))) => {
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
        Ok(Answer::Core(Response::Sent(id))) => Obj::new("queued").text("msg_id", &hex(&id)).done(),
        Ok(_) => error_line("unavailable"),
        Err(e) => error_line(code_of(e)),
    }
}

/// The notices of the runtime, as lines.
async fn events(mut client: Client) {
    let caller = client.caller();
    while let Some(notice) = client.next_event().await {
        match notice {
            Notice::Event(stamped) => {
                let line = event_line(&caller, stamped.at_ms, &stamped.event).await;
                out(&line);
            }
            _ => out(&error_line("unavailable")),
        }
    }
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
        | Event::ContactAdded(c) => Some(c.0),
        Event::NotConfirmed { contact, .. } | Event::MessageReceived { contact, .. } => {
            Some(contact.0)
        }
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
        other => {
            let line = Obj::new("event").text("name", &format!("{other:?}"));
            match contact_of(other) {
                Some(id) => line.num("contact", number(id)).done(),
                None => line.done(),
            }
        }
    }
}
