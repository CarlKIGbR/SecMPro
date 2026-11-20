// SPDX-License-Identifier: AGPL-3.0-or-later
//! The tests of the M8 part-1 screens (T1, T2, T6–T9; T3 is in `locale`, T4 in xtask, T5 in `secmp-sys-desktop`). The window
//! runs under Slint's testing backend (no display); the real core runs on a temporary directory.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

type Test = Result<(), Box<dyn std::error::Error>>;

use secmp_client_core::api::runtime::create_profile;

use crate::app::render;
use crate::bridge::{Backend, Bridge, CoreEvent, Request, Response, Sink};
use crate::core_backend::CoreBackend;
use crate::locale::{self, Lang, key};
use crate::screens::MainWindow;
use crate::vm::{ContactRow, Failure, ModeChoice, RowState, Screen, Vm};

/// A sink that queues what the bridge sends, to be taken on the test's thread (the "UI thread").
fn queue() -> (Sink, Receiver<Response>) {
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
fn pump(vm: &mut Vm, bridge: &Bridge, rx: &Receiver<Response>, done: impl Fn(&Vm) -> bool) {
    while !done(vm) {
        let Ok(response) = rx.recv() else {
            return;
        };
        vm.apply(response, bridge);
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("secmp-ui-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn row(id: i64, name: &str, verified: bool) -> ContactRow {
    ContactRow {
        id,
        name: name.to_owned(),
        key: format!("{id:016x}"),
        verified,
        state: RowState::Active,
    }
}

/// A backend with scripted answers: the contacts it lists are shared with the test; with a gate it holds every
/// `Contacts` answer until the test sends on the gate.
struct Stub {
    contacts: Arc<Mutex<Vec<ContactRow>>>,
    gate: Option<Receiver<()>>,
}

impl Backend for Stub {
    fn handle(&mut self, request: Request, _events: &Sink) -> Response {
        match request {
            Request::Contacts => {
                if let Some(gate) = &self.gate {
                    let _ = gate.recv();
                }
                Response::Contacts(self.contacts.lock().map(|c| c.clone()).unwrap_or_default())
            }
            Request::RelayView(_) => Response::RelayView(Vec::new()),
            Request::Create { .. } | Request::Unlock { .. } => Response::Opened,
        }
    }
}

fn stub(rows: Vec<ContactRow>, gate: Option<Receiver<()>>) -> (Stub, Arc<Mutex<Vec<ContactRow>>>) {
    let contacts = Arc::new(Mutex::new(rows));
    (
        Stub {
            contacts: contacts.clone(),
            gate,
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

/// T2: the window title is the product name on every screen state.
#[test]
fn window_title_is_constant_product_name() -> Test {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new()?;
    let (sink, rx) = queue();
    let (backend, _) = stub(vec![row(1, "Zed", true)], None);
    let bridge = Bridge::spawn(backend, sink);

    let mut vm = Vm::new(Lang::En, Screen::Onboarding, "");
    render(&ui, &vm);
    assert_eq!(ui.get_product_name().as_str(), "SecMPro");

    vm = Vm::new(Lang::En, Screen::Unlock, "alice");
    render(&ui, &vm);
    assert_eq!(ui.get_product_name().as_str(), "SecMPro");

    vm.apply(Response::Opened, &bridge);
    pump(&mut vm, &bridge, &rx, |vm| !vm.contacts().is_empty());
    render(&ui, &vm);
    assert_eq!(vm.screen(), Screen::Contacts);
    assert_eq!(vm.contacts().first().map(|c| c.name.as_str()), Some("Zed"));
    assert_eq!(ui.get_product_name().as_str(), "SecMPro");
    bridge.shutdown();
    Ok(())
}

fn remove(dir: &Path) {
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

/// T8: the contacts screen lists the contacts with their verification state, and an added-contact event adds a row.
#[test]
fn contacts_screen_lists_core_contacts_with_verification_state() -> Test {
    let (sink, rx) = queue();
    let (backend, contacts) = stub(vec![row(1, "Ann", true), row(2, "Bo", false)], None);
    let bridge = Bridge::spawn(backend, sink);
    let mut vm = Vm::new(Lang::En, Screen::Unlock, "alice");
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
