// SPDX-License-Identifier: AGPL-3.0-or-later
//! The tests of the M8 part-1 screens (T1, T2, T6–T12; T3 is in `locale`, T4 in xtask, T5 in `secmp-sys-desktop`). The window
//! runs under Slint's testing backend (no display); the real core runs on a temporary directory.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

pub(crate) type Test = Result<(), Box<dyn std::error::Error>>;

use secmp_client_core::Zeroizing;
use secmp_client_core::api::runtime::create_profile;

use slint::Model as _;

use crate::app::render;
use crate::bridge::{Backend, Bridge, CoreEvent, Request, Response, Sink};
use crate::capture::{EXCLUDED, Refused, Report, Surface, verify};
use crate::core_backend::CoreBackend;
use crate::locale::{self, Lang, key};
use crate::screens::MainWindow;
use crate::vm::{ContactRow, Failure, ModeChoice, Protection, RowState, Screen, Vm};

/// A sink that queues what the bridge sends, to be taken on the test's thread (the "UI thread").
pub(crate) fn queue() -> (Sink, Receiver<Response>) {
    let (tx, rx) = channel();
    let tx = Mutex::new(tx);
    let sink: Sink = Arc::new(move |response| {
        if let Ok(tx) = tx.lock() {
            let _ = tx.send(response);
        }
    });
    (sink, rx)
}

/// Apply responses to `vm` until `done` holds.
pub(crate) fn pump(
    vm: &mut Vm,
    bridge: &Bridge,
    rx: &Receiver<Response>,
    done: impl Fn(&Vm) -> bool,
) {
    while !done(vm) {
        let Ok(response) = rx.recv() else {
            return;
        };
        vm.apply(response, bridge);
    }
}

pub(crate) fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("secmp-ui-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

pub(crate) fn row(id: i64, name: &str, verified: bool) -> ContactRow {
    ContactRow {
        id,
        name: name.to_owned(),
        key: format!("{id:016x}"),
        verified,
        state: RowState::Active,
    }
}

/// The invitation the stub issues.
pub(crate) const INVITE_URI: &str = "secmp://i/QWJjZGVmZ2hpamtsbW5vcA";

/// The id of the message the stub queues.
pub(crate) const SENT_ID: [u8; 16] = [7; 16];

/// The text of a received message, the text of a view-once and the digits of the safety number, as the stub gives them.
pub(crate) const HELLO: &str = "hello";
pub(crate) const SECRET: &str = "the-view-once-secret";
pub(crate) const DIGITS: &str = "12345 67890 13579 24680 11223 34455";

/// A backend with scripted answers: the contacts it lists are shared with the test; with a gate it holds every
/// `Contacts` answer until the test sends on the gate.
pub(crate) struct Stub {
    contacts: Arc<Mutex<Vec<ContactRow>>>,
    gate: Option<Receiver<()>>,
    /// How many `Reveal` requests reached the backend.
    pub(crate) reveals: Arc<AtomicUsize>,
}

impl Backend for Stub {
    fn handle(&mut self, request: Request, _events: &Sink) -> Response {
        match request {
            Request::InviteCreate => Response::Invitation(Zeroizing::new(INVITE_URI.to_owned())),
            // as the core: a URI that does not parse is refused at once, a used one only when the handshake's first step ran
            // (an event after the answer, which the test raises)
            Request::InviteAccept(uri) => match uri.as_str() {
                "used-invitation" | "good-invitation" => Response::Accepting,
                _ => Response::Failed(Failure::InviteAccept),
            },
            Request::Contacts => {
                if let Some(gate) = &self.gate {
                    let _ = gate.recv();
                }
                Response::Contacts(self.contacts.lock().map(|c| c.clone()).unwrap_or_default())
            }
            Request::RelayView(_) => Response::RelayView(Vec::new()),
            Request::Create { .. } | Request::Unlock { .. } => Response::Opened,
            Request::Send { contact, .. } => Response::Sent {
                contact,
                msg_id: SENT_ID,
            },
            Request::Load { contact, msg_id } => Response::Message {
                contact,
                msg_id,
                at_ms: 3_600_000,
                text: Zeroizing::new(HELLO.to_owned()),
            },
            Request::Reveal { contact, msg_id } => {
                self.reveals.fetch_add(1, Ordering::SeqCst);
                Response::Revealed {
                    contact,
                    msg_id,
                    text: Zeroizing::new(SECRET.to_owned()),
                }
            }
            Request::SafetyNumber(contact) => Response::SafetyNumber {
                contact,
                digits: Zeroizing::new(DIGITS.to_owned()),
            },
            Request::Verify { contact, .. } => Response::Verified { contact, ok: true },
        }
    }
}

pub(crate) fn stub(
    rows: Vec<ContactRow>,
    gate: Option<Receiver<()>>,
) -> (Stub, Arc<Mutex<Vec<ContactRow>>>) {
    let contacts = Arc::new(Mutex::new(rows));
    (
        Stub {
            contacts: contacts.clone(),
            gate,
            reveals: Arc::new(AtomicUsize::new(0)),
        },
        contacts,
    )
}

/// T1: the main window is created under the testing backend and its text element shows the `en` string.
#[test]
fn spike_window_instantiates_under_testing_backend() -> Test {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new()?;
    render(&ui, &Vm::new(Lang::En, Screen::Onboarding, ""));
    assert_eq!(
        ui.get_tagline().as_str(),
        locale::text(Lang::En, key::APP_TAGLINE)
    );
    Ok(())
}

pub(crate) fn remove(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// T6: the real core on a temporary directory — the onboarding form creates the profile and the model reaches the contacts
/// screen (direct mode: no Tor is started; there is no relay, so nothing connects).
#[test]
fn onboarding_create_profile_reaches_contacts_screen() -> Test {
    let root = scratch("t6");
    let (sink, rx) = queue();
    let bridge = Bridge::spawn(CoreBackend::new(root.clone(), true), sink);
    let mut vm = Vm::new(Lang::En, Screen::Onboarding, "");
    vm.create(
        &bridge,
        "alice",
        "correct horse",
        "correct horse",
        ModeChoice::Balanced,
    );
    assert!(vm.busy());
    pump(&mut vm, &bridge, &rx, |vm| vm.screen() == Screen::Contacts);
    // the contact list answer follows the opening
    let response = rx.recv()?;
    vm.apply(response, &bridge);
    assert_eq!(vm.screen(), Screen::Contacts);
    assert!(!vm.busy());
    assert_eq!(vm.error_text(), "");
    assert!(vm.contacts().is_empty());
    bridge.shutdown();
    remove(&root);
    Ok(())
}

/// Open `name` in `root` under `pass`; the model's answer text.
fn try_unlock(root: &Path, name: &str, pass: &str) -> (Screen, &'static str) {
    let (sink, rx) = queue();
    let bridge = Bridge::spawn(CoreBackend::new(root.to_path_buf(), true), sink);
    let mut vm = Vm::new(Lang::En, Screen::Unlock, name);
    vm.unlock(&bridge, pass);
    pump(&mut vm, &bridge, &rx, |vm| !vm.busy());
    let out = (vm.screen(), vm.error_text());
    bridge.shutdown();
    out
}

/// T7: a wrong passphrase and a damaged store leave the unlock screen with the same message, byte for byte.
#[test]
fn unlock_wrong_passphrase_and_damaged_store_show_same_message() -> Test {
    let root = scratch("t7");
    std::fs::create_dir_all(&root)?;
    create_profile(&root.join("alice"), b"right", None).map_err(|_| "create alice")?;
    create_profile(&root.join("bob"), b"right", None).map_err(|_| "create bob")?;
    for entry in std::fs::read_dir(root.join("bob"))? {
        let path = entry?.path();
        if path.is_file() {
            std::fs::write(path, [0xA5_u8; 4096])?;
        }
    }
    let (screen_wrong, wrong) = try_unlock(&root, "alice", "wrong");
    let (screen_damaged, damaged) = try_unlock(&root, "bob", "right");
    assert_eq!(screen_wrong, Screen::Unlock);
    assert_eq!(screen_damaged, Screen::Unlock);
    assert!(!wrong.is_empty());
    assert_eq!(wrong.as_bytes(), damaged.as_bytes());
    assert_eq!(wrong, locale::text(Lang::En, Failure::Unlock.message_key()));
    remove(&root);
    Ok(())
}

/// T8 (stub core: the client core has no utility that makes a real contact without a relay and a handshake; the mapping of
/// the core's contacts and events is tested in `core_backend`): the contacts screen lists the contacts with their verification
/// state, and an added-contact event adds a row.
#[test]
fn contacts_screen_lists_stub_contacts() -> Test {
    let (sink, rx) = queue();
    let (backend, contacts) = stub(vec![row(1, "Ann", true), row(2, "Bo", false)], None);
    let bridge = Bridge::spawn(backend, sink);
    let mut vm = Vm::new(Lang::En, Screen::Unlock, "alice");
    vm.set_protection(Protection::Verified);
    vm.apply(Response::Opened, &bridge);
    pump(&mut vm, &bridge, &rx, |vm| vm.contacts().len() == 2);
    let rows = vm.rows();
    let status: Vec<(&str, bool)> = rows
        .iter()
        .map(|r| (r.status.as_str(), r.verified))
        .collect();
    assert_eq!(
        status,
        [
            (locale::text(Lang::En, key::CONTACTS_VERIFIED), true),
            (locale::text(Lang::En, key::CONTACTS_UNVERIFIED), false),
        ]
    );

    contacts
        .lock()
        .map_err(|_| "poisoned")?
        .push(row(3, "Cy", false));
    vm.apply(Response::Event(CoreEvent::ContactAdded(3)), &bridge);
    pump(&mut vm, &bridge, &rx, |vm| vm.contacts().len() == 3);
    assert_eq!(vm.rows().get(2).map(|r| r.name.as_str()), Some("Cy"));
    bridge.shutdown();
    Ok(())
}

/// T9: a request returns before the core answers; the model updates after the core does.
#[test]
fn ui_request_returns_before_core_responds() -> Test {
    let (sink, rx) = queue();
    let (open, close): (Sender<()>, Receiver<()>) = channel();
    let (backend, _) = stub(vec![row(1, "Ann", true)], Some(close));
    let bridge = Bridge::spawn(backend, sink);
    let mut vm = Vm::new(Lang::En, Screen::Unlock, "alice");
    // asks the core for the contacts; the stub holds its answer behind the gate
    vm.apply(Response::Opened, &bridge);
    assert!(vm.contacts().is_empty());
    assert!(rx.try_recv().is_err());
    open.send(())?;
    pump(&mut vm, &bridge, &rx, |vm| !vm.contacts().is_empty());
    assert_eq!(vm.contacts().len(), 1);
    bridge.shutdown();
    Ok(())
}

/// The rendered rows of `ui` as (name, key, status) texts.
fn rendered(ui: &MainWindow) -> Vec<(String, String, String)> {
    ui.get_contacts()
        .iter()
        .map(|r| (r.name.to_string(), r.key.to_string(), r.status.to_string()))
        .collect()
}

/// A model on the contacts screen with one contact named "Zed", its answer already applied.
fn zed(protection: Protection) -> (Vm, Bridge) {
    let (sink, rx) = queue();
    let (backend, _) = stub(vec![row(1, "Zed", true)], None);
    let bridge = Bridge::spawn(backend, sink);
    let mut vm = Vm::new(Lang::En, Screen::Unlock, "alice");
    vm.set_protection(protection);
    vm.apply(Response::Opened, &bridge);
    pump(&mut vm, &bridge, &rx, |vm| !vm.contacts().is_empty());
    (vm, bridge)
}

/// T10: while the protection is not verified the rendered rows say "locked" and carry nothing of the contact.
#[test]
fn content_is_locked_until_protection_is_verified() -> Test {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new()?;
    let (mut vm, bridge) = zed(Protection::Locked);
    assert_eq!(vm.protection(), Protection::Locked);
    render(&ui, &vm);
    let locked = locale::text(Lang::En, key::CONTENT_LOCKED);
    assert_eq!(
        rendered(&ui),
        [(locked.to_owned(), String::new(), String::new())]
    );
    assert!(!format!("{:?}", rendered(&ui)).contains("Zed"));
    assert_eq!(
        ui.get_indicator_text().as_str(),
        locale::text(Lang::En, key::INDICATOR_LOCKED)
    );
    assert!(ui.get_indicator_locked());
    // verified: the contact shows, the indicator says protected
    vm.set_protection(Protection::Verified);
    render(&ui, &vm);
    assert_eq!(rendered(&ui).first().map(|r| r.0.as_str()), Some("Zed"));
    assert_eq!(
        ui.get_indicator_text().as_str(),
        locale::text(Lang::En, key::INDICATOR_PROTECTED)
    );
    bridge.shutdown();
    Ok(())
}

/// T11: the per-session override shows the content; it is held in the model only, so a second model on the same profile
/// directory starts locked and no file under the profile directory changed (names, sizes, modification times).
#[cfg(target_os = "linux")]
#[test]
fn session_override_shows_content_and_is_not_persisted() -> Test {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new()?;
    let root = scratch("t11");
    std::fs::create_dir_all(&root)?;
    create_profile(&root.join("alice"), b"right", None).map_err(|_| "create alice")?;
    let before = snapshot(&root.join("alice"))?;
    assert!(!before.is_empty());
    let (mut vm, bridge) = zed(Protection::Locked);
    assert!(vm.override_available());
    vm.override_session();
    assert_eq!(vm.protection(), Protection::Overridden);
    render(&ui, &vm);
    assert_eq!(rendered(&ui).first().map(|r| r.0.as_str()), Some("Zed"));
    assert_eq!(
        ui.get_indicator_text().as_str(),
        locale::text(Lang::En, key::INDICATOR_OVERRIDDEN)
    );
    assert!(!ui.get_show_override());
    bridge.shutdown();
    let second = Vm::new(Lang::En, Screen::Unlock, "alice");
    assert_eq!(second.protection(), Protection::Locked);
    assert_eq!(snapshot(&root.join("alice"))?, before);
    remove(&root);
    Ok(())
}

/// Every file under `dir` with its size and modification time, in path order.
#[cfg(target_os = "linux")]
fn snapshot(dir: &Path) -> Result<Vec<(PathBuf, u64, std::time::SystemTime)>, std::io::Error> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if meta.is_dir() {
                pending.push(entry.path());
            } else {
                found.push((entry.path(), meta.len(), meta.modified()?));
            }
        }
    }
    found.sort();
    Ok(found)
}

/// A window whose three calls give the scripted outcomes.
struct Fake {
    reads: Mutex<Vec<Result<u32, Refused>>>,
    set: Result<(), Refused>,
}

impl Surface for Fake {
    fn affinity(&self) -> Result<u32, Refused> {
        self.reads
            .lock()
            .map_err(|_| Refused)?
            .pop()
            .unwrap_or(Err(Refused))
    }

    fn exclude(&self) -> Result<(), Refused> {
        self.set
    }
}

fn check(
    pre: Result<u32, Refused>,
    set: Result<(), Refused>,
    post: Result<u32, Refused>,
) -> Report {
    // `pop` takes from the end: `post` is read second
    verify(&Fake {
        reads: Mutex::new(vec![post, pre]),
        set,
    })
}

/// T12: every failure of the capture check ends locked; only a clean sequence with `post == 0x11` is verified, and the
/// reads and the call run in the order read, set, read.
#[test]
fn capture_failures_end_locked() {
    let ok = Ok(());
    let cases: [(&str, Report, Protection); 8] = [
        (
            "all fine",
            check(Ok(0), ok, Ok(EXCLUDED)),
            Protection::Verified,
        ),
        (
            "pre already excluded",
            check(Ok(EXCLUDED), ok, Ok(EXCLUDED)),
            Protection::Verified,
        ),
        (
            "pre read fails",
            check(Err(Refused), ok, Ok(EXCLUDED)),
            Protection::Locked,
        ),
        (
            "set fails",
            check(Ok(0), Err(Refused), Ok(EXCLUDED)),
            Protection::Locked,
        ),
        (
            "post read fails",
            check(Ok(0), ok, Err(Refused)),
            Protection::Locked,
        ),
        (
            "post is monitor-only",
            check(Ok(0), ok, Ok(1)),
            Protection::Locked,
        ),
        ("post is none", check(Ok(0), ok, Ok(0)), Protection::Locked),
        (
            "everything fails",
            check(Err(Refused), Err(Refused), Err(Refused)),
            Protection::Locked,
        ),
    ];
    for (name, report, want) in cases {
        assert_eq!(report.protection(), want, "{name}");
    }
    // a model that never hears from the check stays locked
    assert_eq!(
        Vm::new(Lang::En, Screen::Contacts, "").protection(),
        Protection::Locked
    );
}

/// A model on the invitation screen of a stub core, protection as given.
fn invitations(protection: Protection) -> (Vm, Bridge, Receiver<Response>) {
    let (sink, rx) = queue();
    let (backend, _) = stub(vec![row(1, "Zed", true)], None);
    let bridge = Bridge::spawn(backend, sink);
    let mut vm = Vm::new(Lang::En, Screen::Unlock, "alice");
    vm.set_protection(protection);
    vm.apply(Response::Opened, &bridge);
    pump(&mut vm, &bridge, &rx, |vm| !vm.contacts().is_empty());
    vm.open_invitations();
    (vm, bridge, rx)
}

/// P2: a URI that does not parse, a truncated one and one that was used already (refused only later, as an event) show the
/// same text, byte for byte.
#[test]
fn invite_accept_rejected_uris_show_one_message() {
    let mut shown = Vec::new();
    for uri in ["not-an-invitation", "secmp://i/abc", "used-invitation", ""] {
        let (mut vm, bridge, rx) = invitations(Protection::Verified);
        vm.accept_invitation(&bridge, uri);
        if !uri.is_empty() {
            assert!(vm.busy());
            pump(&mut vm, &bridge, &rx, |vm| !vm.busy());
            if uri == "used-invitation" {
                // accepted by the core, refused when the handshake's first step ran
                assert_eq!(
                    vm.invite_status(),
                    locale::text(Lang::En, key::INVITE_ACCEPTING)
                );
                vm.apply(Response::Event(CoreEvent::InviteFailed), &bridge);
            }
        }
        assert_eq!(vm.invite_status(), "");
        shown.push(vm.error_text());
        bridge.shutdown();
    }
    let want = locale::text(Lang::En, Failure::InviteAccept.message_key());
    for text in &shown {
        assert_eq!(text.as_bytes(), want.as_bytes());
    }
    assert_eq!(shown.len(), 4);
}

/// P3: the invitation is content: while locked the text is the placeholder, the code is not drawn and nothing is copyable;
/// leaving the screen drops it.
#[test]
fn invitation_uri_is_hidden_while_locked_and_cleared_on_leave() -> Test {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new()?;
    let (mut vm, bridge, rx) = invitations(Protection::Locked);
    vm.create_invitation(&bridge);
    pump(&mut vm, &bridge, &rx, Vm::invitation_held);
    render(&ui, &vm);
    let locked = locale::text(Lang::En, key::CONTENT_LOCKED);
    assert_eq!(ui.get_invite_uri().as_str(), locked);
    assert!(!ui.get_invite_copyable());
    assert_eq!(ui.get_invite_qr().size().width, 0);
    assert!(!format!("{:?}", ui.get_invite_uri()).contains("secmp://"));

    vm.set_protection(Protection::Verified);
    render(&ui, &vm);
    assert_eq!(ui.get_invite_uri().as_str(), INVITE_URI);
    assert!(ui.get_invite_copyable());
    assert!(ui.get_invite_qr().size().width > 0);

    vm.leave();
    assert!(!vm.invitation_held());
    assert_eq!(vm.screen(), Screen::Contacts);
    render(&ui, &vm);
    assert_eq!(ui.get_invite_uri().as_str(), "");
    assert_eq!(ui.get_invite_qr().size().width, 0);
    bridge.shutdown();
    Ok(())
}
