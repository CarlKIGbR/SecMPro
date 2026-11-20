// SPDX-License-Identifier: AGPL-3.0-or-later
//! The shell: it binds the view model to the window, hands the window's callbacks to the model, and carries the bridge's
//! responses back onto the UI thread. The model and the bridge live on the UI thread (a thread-local); responses cross threads
//! only as plain data through `slint::invoke_from_event_loop`.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use slint::{ComponentHandle as _, ModelRc, SharedString, VecModel};

use crate::bridge::{Bridge, Request, Response, Sink};
use crate::capture;
use crate::core_backend::CoreBackend;
use crate::locale::{self, Lang, key};
use crate::screens::{ContactRowData, MainWindow};
use crate::vm::{ModeChoice, Screen, Vm, name_is_valid};

struct Shell {
    ui: MainWindow,
    vm: Vm,
    bridge: Bridge,
}

thread_local! {
    static SHELL: RefCell<Option<Shell>> = const { RefCell::new(None) };
}

fn with_shell(f: impl FnOnce(&mut Shell)) {
    SHELL.with(|cell| {
        if let Ok(mut slot) = cell.try_borrow_mut()
            && let Some(shell) = slot.as_mut()
        {
            f(shell);
        }
    });
}

fn strings(lang: Lang, keys: &[&'static str]) -> ModelRc<SharedString> {
    ModelRc::new(VecModel::from(
        keys.iter()
            .map(|k| SharedString::from(locale::text(lang, k)))
            .collect::<Vec<_>>(),
    ))
}

/// Show `vm` in `ui`: the screen, every string of the screen in the language of the model, the contact rows and the state of
/// the request. The title stays the product name (a constant of the component).
pub fn render(ui: &MainWindow, vm: &Vm) {
    let lang = vm.lang();
    let t = |k: &'static str| SharedString::from(locale::text(lang, k));
    ui.set_screen(match vm.screen() {
        Screen::Onboarding => 0,
        Screen::Unlock => 1,
        Screen::Contacts => 2,
    });
    ui.set_tagline(t(key::APP_TAGLINE));
    ui.set_busy(vm.busy());
    ui.set_busy_text(t(key::WORKING));
    ui.set_error_text(SharedString::from(vm.error_text()));

    ui.set_onboarding_title(t(key::ONBOARDING_TITLE));
    ui.set_name_label(t(key::ONBOARDING_NAME));
    ui.set_pass_label(t(key::ONBOARDING_PASS));
    ui.set_pass_again_label(t(key::ONBOARDING_PASS_AGAIN));
    ui.set_mode_label(t(key::ONBOARDING_MODE));
    ui.set_relay_view_title(t(key::ONBOARDING_RELAY_VIEW));
    ui.set_create_text(t(key::ONBOARDING_CREATE));
    ui.set_mode_names(strings(lang, &ModeChoice::ALL.map(ModeChoice::name_key)));
    ui.set_relay_lines(ModelRc::new(VecModel::from(
        vm.relay_lines()
            .iter()
            .map(|l| SharedString::from(l.as_str()))
            .collect::<Vec<_>>(),
    )));

    ui.set_unlock_title(t(key::UNLOCK_TITLE));
    ui.set_unlock_pass_label(t(key::UNLOCK_PASS));
    ui.set_unlock_text(t(key::UNLOCK_BUTTON));
    ui.set_unlock_profile(SharedString::from(vm.profile()));

    ui.set_contacts_title(t(key::CONTACTS_TITLE));
    ui.set_contacts_empty(t(key::CONTACTS_EMPTY));
    ui.set_contacts(ModelRc::new(VecModel::from(
        vm.rows()
            .into_iter()
            .map(|r| ContactRowData {
                name: r.name.into(),
                key: r.key.into(),
                status: r.status.into(),
                verified: r.verified,
            })
            .collect::<Vec<_>>(),
    )));
}

/// Put `vm` and `bridge` behind `ui`: the window's callbacks drive the model, which renders after every step.
fn wire(ui: &MainWindow, vm: Vm, bridge: Bridge) {
    ui.on_create(|name, pass, again, mode| {
        with_shell(|sh| {
            let mode = ModeChoice::from_index(mode);
            sh.vm.create(&sh.bridge, &name, &pass, &again, mode);
            // the fields are emptied whatever came of the request; the model holds the passphrase in a zeroising buffer
            sh.ui.set_pass1(SharedString::new());
            sh.ui.set_pass2(SharedString::new());
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_mode_picked(|index| {
        with_shell(|sh| {
            sh.vm
                .show_relay_view(&sh.bridge, ModeChoice::from_index(index));
        });
    });
    ui.on_unlock(|pass| {
        with_shell(|sh| {
            sh.vm.unlock(&sh.bridge, &pass);
            sh.ui.set_unlock_pass(SharedString::new());
            render(&sh.ui, &sh.vm);
        });
    });
    render(ui, &vm);
    SHELL.with(|cell| {
        *cell.borrow_mut() = Some(Shell {
            ui: ui.clone_strong(),
            vm,
            bridge,
        });
    });
}

/// Take one response of the bridge on the UI thread.
fn deliver(response: Response) {
    with_shell(|sh| {
        sh.vm.apply(response, &sh.bridge);
        render(&sh.ui, &sh.vm);
    });
}

/// The sink of the bridge: every response and event hops onto the UI's event loop.
#[must_use]
pub fn event_loop_sink() -> Sink {
    Arc::new(|response| {
        let _ = slint::invoke_from_event_loop(move || deliver(response));
    })
}

/// The directory that holds the profiles: `SECMP_PROFILE_DIR`, else the platform's per-user data directory.
#[must_use]
pub fn profile_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("SECMP_PROFILE_DIR") {
        return PathBuf::from(dir);
    }
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".local/share")))
    };
    base.unwrap_or_else(|| PathBuf::from(".")).join("secmpro")
}

/// The name of the profile in `root` the unlock screen is for: the first directory (in name order) with a usable name.
#[must_use]
pub fn existing_profile(root: &Path) -> Option<String> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .ok()?
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| name_is_valid(n))
        .collect();
    names.sort_unstable();
    names.into_iter().next()
}

/// Select the toolkit's backend: winit, with the content-protection window attribute (which the platforms that have it apply
/// while the window is created); the renderer is the first of femtovg and software that starts.
///
/// # Errors
/// The toolkit's error if no backend can be set.
pub fn select_backend() -> Result<(), slint::PlatformError> {
    slint::BackendSelector::new()
        .backend_name("winit".into())
        .with_winit_window_attributes_hook(|attributes| attributes.with_content_protected(true))
        .select()
}

/// Run the application until its window closes. Over Tor unless `direct`.
#[must_use]
pub fn run(root: &Path, direct: bool) -> ExitCode {
    if select_backend().is_err() {
        return ExitCode::FAILURE;
    }
    let Ok(ui) = MainWindow::new() else {
        return ExitCode::FAILURE;
    };
    let lang = Lang::from_env();
    let existing = existing_profile(root);
    let screen = if existing.is_some() {
        Screen::Unlock
    } else {
        Screen::Onboarding
    };
    let vm = Vm::new(lang, screen, existing.as_deref().unwrap_or(""));
    let bridge = Bridge::spawn(
        CoreBackend::new(root.to_path_buf(), direct),
        event_loop_sink(),
    );
    if screen == Screen::Onboarding {
        // the first look at what the relay can see, for the default mode
        let _ = bridge.submit(Request::RelayView(ModeChoice::Strict));
    }
    wire(&ui, vm, bridge);

    let refused = std::rc::Rc::new(std::cell::Cell::new(false));
    let flag = refused.clone();
    let weak = ui.as_weak();
    capture::arm(&ui, move |outcome| {
        if outcome.is_err() {
            flag.set(true);
            if let Some(ui) = weak.upgrade() {
                let _ = ui.hide();
            }
            let _ = slint::quit_event_loop();
        }
    });
    if ui.show().is_err() {
        return ExitCode::FAILURE;
    }
    let ran = slint::run_event_loop();

    // the window is gone: take the shell down, which ends the core's runtime
    let shell = SHELL.with(|cell| cell.borrow_mut().take());
    if let Some(shell) = shell {
        shell.bridge.shutdown();
    }
    if ran.is_ok() && !refused.get() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
