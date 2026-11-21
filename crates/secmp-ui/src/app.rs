// SPDX-License-Identifier: AGPL-3.0-or-later
//! The shell: it binds the view model to the window, hands the window's callbacks to the model, and carries the bridge's
//! responses back onto the UI thread. The model and the bridge live on the UI thread (a thread-local); responses cross threads
//! only as plain data through `slint::invoke_from_event_loop`.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use slint::winit_030::{EventResult, WinitWindowAccessor as _, winit};
use slint::{ComponentHandle as _, Model as _, ModelRc, SharedString, Timer, TimerMode, VecModel};

use crate::bridge::{Bridge, Request, Response, Sink};
use crate::capture;
use crate::core_backend::CoreBackend;
use crate::locale::{self, Lang, key};
use crate::screens::{ContactRowData, MainWindow, MessageRowData};
use crate::vm::{ModeChoice, Protection, ReceiptChoice, Screen, Vm, name_is_valid};

/// How often the model's clock is read for the 20 seconds of a reveal (CS-1.14).
const TICK: Duration = Duration::from_millis(250);

/// How often the connection line is refreshed.
const STATUS_EVERY: Duration = Duration::from_secs(5);

struct Shell {
    ui: MainWindow,
    vm: Vm,
    bridge: Bridge,
    /// The model's clock starts here.
    started: Instant,
    /// Reads the clock for a reveal in progress: the model ends it after [`crate::vm::REVEAL_MAX_S`] seconds, whatever the
    /// user does.
    tick_timer: Timer,
    /// Asks the core about the connection.
    status_timer: Timer,
}

impl Shell {
    /// The model's clock in milliseconds.
    fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
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

/// Bring the message rows of `ui` to `rows` row by row: the rows stay the same elements while their data changes, so a
/// view-once under the user's finger keeps its touch area when its text arrives (a new model would rebuild every row and lose
/// the release).
fn sync_messages(ui: &MainWindow, rows: Vec<MessageRowData>) {
    let current = ui.get_conv_messages();
    let Some(model) = current.as_any().downcast_ref::<VecModel<MessageRowData>>() else {
        ui.set_conv_messages(ModelRc::new(VecModel::from(rows)));
        return;
    };
    for (index, row) in rows.iter().enumerate() {
        match model.row_data(index) {
            Some(shown) if shown == *row => {}
            Some(_) => model.set_row_data(index, row.clone()),
            None => model.push(row.clone()),
        }
    }
    while model.row_count() > rows.len() {
        model.remove(model.row_count().saturating_sub(1));
    }
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
        Screen::Stopped => 3,
        Screen::Invitations => 4,
        Screen::Conversation => 5,
        Screen::Safety => 6,
        Screen::Settings => 7,
        Screen::Options => 8,
    });
    ui.set_indicator_text(t(vm.indicator_key()));
    ui.set_indicator_locked(!matches!(vm.protection(), Protection::Verified));
    ui.set_show_override(vm.override_available());
    ui.set_override_text(t(key::OVERRIDE_SHOW));
    ui.set_tagline(t(key::APP_TAGLINE));
    ui.set_busy(vm.busy());
    ui.set_busy_text(t(key::WORKING));
    ui.set_error_text(SharedString::from(vm.error_text()));
    ui.set_unavailable_text(SharedString::from(vm.unavailable_text()));
    ui.set_status_text(SharedString::from(vm.status_text()));
    ui.set_notice_text(SharedString::from(vm.notice_text()));
    ui.set_confirm_text(SharedString::from(vm.confirm_text()));
    ui.set_confirm_button_text(t(key::CONFIRM_BUTTON));
    ui.set_cancel_button_text(t(key::CANCEL_BUTTON));
    if !vm.content_visible() {
        // the fields that hold what the user typed are emptied and disabled while content is locked
        ui.set_conv_draft(SharedString::new());
        ui.set_invite_input(SharedString::new());
    }

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
    ui.set_contacts_invite_text(t(key::CONTACTS_INVITE));
    ui.set_contacts_settings_text(t(key::CONTACTS_SETTINGS));
    ui.set_back_text(t(key::NAV_BACK));

    render_content(ui, vm);
    render_settings(ui, vm);

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

/// The invitation, conversation and safety number screens.
fn render_content(ui: &MainWindow, vm: &Vm) {
    let lang = vm.lang();
    let t = |k: &'static str| SharedString::from(locale::text(lang, k));
    ui.set_invite_title(t(key::INVITE_TITLE));
    ui.set_invite_create_text(t(key::INVITE_CREATE));
    ui.set_invite_uri_label(t(key::INVITE_URI_LABEL));
    ui.set_invite_copy_text(t(key::INVITE_COPY));
    ui.set_invite_accept_label(t(key::INVITE_ACCEPT_LABEL));
    ui.set_invite_accept_text(t(key::INVITE_ACCEPT));
    ui.set_invite_input_enabled(vm.invite_input_enabled());
    ui.set_invite_uri(SharedString::from(vm.invite_text()));
    ui.set_invite_copyable(vm.invite_copyable());
    ui.set_invite_qr(vm.invite_qr().cloned().unwrap_or_default());
    ui.set_invite_status(SharedString::from(vm.invite_status()));

    ui.set_conv_title(SharedString::from(vm.conv_title()));
    ui.set_conv_banners(ModelRc::new(VecModel::from(
        vm.conv_banners()
            .into_iter()
            .map(SharedString::from)
            .collect::<Vec<_>>(),
    )));
    ui.set_conv_input_enabled(vm.conv_input_enabled());
    ui.set_conv_empty(t(key::CONV_EMPTY));
    ui.set_conv_input_label(t(key::CONV_INPUT_LABEL));
    ui.set_conv_send_text(t(key::CONV_SEND));
    ui.set_conv_safety_text(t(key::CONV_SAFETY));
    ui.set_conv_options_text(t(key::CONV_OPTIONS));
    ui.set_conv_load_earlier_text(t(key::CONV_LOAD_EARLIER));
    ui.set_conv_more(vm.conv_more());
    sync_messages(
        ui,
        vm.conv_rows()
            .into_iter()
            .map(|m| MessageRowData {
                text: m.text.into(),
                meta: m.meta.into(),
                incoming: m.incoming,
                hold: m.hold,
            })
            .collect(),
    );

    ui.set_safety_title(t(key::SAFETY_TITLE));
    ui.set_safety_hint(t(key::SAFETY_HINT));
    ui.set_safety_verify_text(t(key::SAFETY_VERIFY));
    ui.set_safety_digits(SharedString::from(vm.safety_text()));
    ui.set_safety_qr(vm.safety_qr().cloned().unwrap_or_default());
    ui.set_safety_can_verify(vm.safety_can_verify());
    ui.set_safety_status(SharedString::from(vm.safety_status()));
}

/// The settings and the contact options screens.
fn render_settings(ui: &MainWindow, vm: &Vm) {
    let lang = vm.lang();
    let t = |k: &'static str| SharedString::from(locale::text(lang, k));
    ui.set_settings_title(t(key::SETTINGS_TITLE));
    ui.set_settings_relay_title(t(key::SETTINGS_RELAY_VIEW));
    ui.set_settings_retention_label(t(key::SETTINGS_RETENTION));
    ui.set_settings_delivered_label(t(key::SETTINGS_DELIVERED));
    ui.set_settings_read_text(t(key::SETTINGS_READ));
    ui.set_settings_screen_title(t(key::SETTINGS_SCREEN));
    ui.set_settings_screen_hint(t(key::SETTINGS_SCREEN_HINT));
    ui.set_settings_profile_title(t(key::SETTINGS_PROFILE));
    ui.set_identity_text(t(key::ACTION_IDENTITY));
    ui.set_export_path_label(t(key::ACTION_EXPORT_PATH));
    ui.set_export_pass_label(t(key::ACTION_EXPORT_PASS));
    ui.set_export_pass_again_label(t(key::ONBOARDING_PASS_AGAIN));
    ui.set_export_locked(vm.confirming());
    ui.set_export_text(t(key::ACTION_EXPORT));
    ui.set_retention_names(ModelRc::new(VecModel::from(
        vm.retention_names()
            .into_iter()
            .map(SharedString::from)
            .collect::<Vec<_>>(),
    )));
    ui.set_delivered_names(strings(
        lang,
        &ReceiptChoice::ALL.map(ReceiptChoice::name_key),
    ));
    ui.set_settings_enabled(vm.settings_enabled());
    if let Some(shown) = vm.settings_shown() {
        ui.set_settings_mode_index(shown.mode.index());
        ui.set_retention_index(vm.retention_index());
        ui.set_delivered_index(vm.delivered_index());
        ui.set_settings_read(shown.read_receipts);
    }
    ui.set_options_title(t(key::OPTIONS_TITLE));
    ui.set_rotate_text(t(key::ACTION_ROTATE));
    ui.set_reset_text(t(key::ACTION_RESET));
    ui.set_remove_text(t(key::ACTION_REMOVE));
}

/// The callbacks of the settings and the contact options screens.
fn wire_settings(ui: &MainWindow) {
    ui.on_open_settings(|| {
        with_shell(|sh| {
            sh.vm.open_settings(&sh.bridge);
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_settings_mode_picked(|index| {
        with_shell(|sh| {
            sh.vm.pick_mode(&sh.bridge, index);
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_settings_retention_picked(|index| {
        with_shell(|sh| {
            sh.vm.pick_retention(&sh.bridge, index);
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_settings_delivered_picked(|index| {
        with_shell(|sh| {
            sh.vm.pick_delivered(&sh.bridge, index);
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_settings_read_toggled(|on| {
        with_shell(|sh| {
            sh.vm.set_read_receipts(&sh.bridge, on);
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_ask_identity(|| {
        with_shell(|sh| {
            sh.vm.ask_identity();
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_ask_export(|path, pass, again| {
        with_shell(|sh| {
            sh.vm.ask_export(&path, &pass, &again);
            // the model holds the passphrase in a zeroising buffer; the fields are emptied
            sh.ui.set_export_pass(SharedString::new());
            sh.ui.set_export_pass2(SharedString::new());
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_open_options(|| {
        with_shell(|sh| {
            sh.vm.open_options();
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_ask_rotate(|| {
        with_shell(|sh| {
            sh.vm.ask_rotate();
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_ask_reset(|| {
        with_shell(|sh| {
            sh.vm.ask_reset();
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_ask_remove(|| {
        with_shell(|sh| {
            sh.vm.ask_remove();
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_confirm_clicked(|| {
        with_shell(|sh| {
            sh.vm.confirm(&sh.bridge);
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_cancel_clicked(|| {
        with_shell(|sh| {
            sh.vm.cancel(&sh.bridge);
            render(&sh.ui, &sh.vm);
        });
    });
}

/// The callbacks of the conversation and the safety number screens.
fn wire_conversation(ui: &MainWindow) {
    ui.on_open_contact(|index| {
        with_shell(|sh| {
            sh.vm
                .open_contact(&sh.bridge, usize::try_from(index).unwrap_or(usize::MAX));
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_conv_send(|text| {
        with_shell(|sh| {
            // the field keeps the text until the core has taken it
            sh.vm.send(&sh.bridge, &text);
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_reveal_pressed(|index| {
        with_shell(|sh| {
            // the 20 seconds run from the press that starts the reveal (the model's clock), a second press changes nothing
            let now = sh.now_ms();
            sh.vm.reveal_press(
                &sh.bridge,
                usize::try_from(index).unwrap_or(usize::MAX),
                now,
            );
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_reveal_released(|| {
        with_shell(|sh| {
            sh.vm.reveal_release();
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_conv_load_earlier(|| {
        with_shell(|sh| {
            sh.vm.load_earlier(&sh.bridge);
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_open_safety(|| {
        with_shell(|sh| {
            sh.vm.open_safety(&sh.bridge);
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_safety_verify(|| {
        with_shell(|sh| {
            sh.vm.verify(&sh.bridge);
            render(&sh.ui, &sh.vm);
        });
    });
}

/// The callbacks of the invitation screen.
fn wire_invitations(ui: &MainWindow) {
    ui.on_invite_create(|| {
        with_shell(|sh| {
            sh.vm.create_invitation(&sh.bridge);
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_invite_accept(|uri| {
        with_shell(|sh| {
            sh.vm.accept_invitation(&sh.bridge, &uri);
            // the field is emptied whatever came of the request; the model passed the URI on in a zeroising buffer
            sh.ui.set_invite_input(SharedString::new());
            render(&sh.ui, &sh.vm);
        });
    });
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
    ui.on_open_invitations(|| {
        with_shell(|sh| {
            sh.vm.open_invitations();
            render(&sh.ui, &sh.vm);
        });
    });
    ui.on_back(|| {
        with_shell(|sh| {
            let was = sh.vm.screen();
            sh.vm.leave();
            // the fields are emptied with the model's copy
            sh.ui.set_invite_input(SharedString::new());
            if was == Screen::Conversation {
                sh.ui.set_conv_draft(SharedString::new());
            }
            if was == Screen::Settings {
                sh.ui.set_export_path(SharedString::new());
                sh.ui.set_export_pass(SharedString::new());
                sh.ui.set_export_pass2(SharedString::new());
            }
            render(&sh.ui, &sh.vm);
        });
    });
    wire_conversation(ui);
    wire_settings(ui);
    wire_invitations(ui);
    #[cfg(target_os = "linux")]
    ui.on_override_requested(|| {
        with_shell(|sh| {
            sh.vm.override_session();
            sh.vm.sync_display(&sh.bridge);
            render(&sh.ui, &sh.vm);
        });
    });
    render(ui, &vm);
    SHELL.with(|cell| {
        *cell.borrow_mut() = Some(Shell {
            ui: ui.clone_strong(),
            vm,
            bridge,
            started: Instant::now(),
            tick_timer: Timer::default(),
            status_timer: Timer::default(),
        });
    });
    with_shell(|sh| {
        sh.tick_timer.start(TimerMode::Repeated, TICK, || {
            with_shell(|sh| {
                let now = sh.now_ms();
                if sh.vm.tick(now) {
                    render(&sh.ui, &sh.vm);
                }
            });
        });
        sh.status_timer
            .start(TimerMode::Repeated, STATUS_EVERY, || {
                with_shell(|sh| {
                    sh.vm.poll_status(&sh.bridge);
                    render(&sh.ui, &sh.vm);
                });
            });
    });
    // a window that loses the focus ends a reveal (CS-1.14)
    ui.window().on_winit_window_event(|_, event| {
        if matches!(event, winit::event::WindowEvent::Focused(false)) {
            with_shell(|sh| {
                sh.vm.focus_lost();
                render(&sh.ui, &sh.vm);
            });
        }
        EventResult::Propagate
    });
}

/// Take one response of the bridge on the UI thread.
fn deliver(response: Response) {
    with_shell(|sh| {
        let sent = matches!(response, Response::Sent { .. });
        sh.vm.apply(response, &sh.bridge);
        if sent {
            // the core took the text: the field is emptied
            sh.ui.set_conv_draft(SharedString::new());
        }
        render(&sh.ui, &sh.vm);
    });
}

/// Take the result of the platform check on the UI thread.
fn deliver_protection(protection: Protection) {
    with_shell(|sh| {
        sh.vm.set_protection(protection);
        sh.vm.sync_display(&sh.bridge);
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

    // Windows: the check runs once the native window exists and decides the protection state; every other outcome, and every
    // other platform, leaves the display locked (fail closed)
    let armed = capture::arm(&ui, |outcome| {
        let protection = outcome.map_or(Protection::Locked, |report| report.protection());
        // the task runs on the UI thread: the outcome is taken there, directly
        deliver_protection(protection);
    });
    if armed.is_err() {
        // the model starts locked and stays so; the window is still shown, without content
        deliver_protection(Protection::Locked);
    }
    if ui.show().is_err() {
        return ExitCode::FAILURE;
    }
    let ran = slint::run_event_loop();

    // the window is gone: take the shell down, which ends the core's runtime
    let shell = SHELL.with(|cell| cell.borrow_mut().take());
    if let Some(shell) = shell {
        shell.bridge.shutdown();
    }
    if ran.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
