// SPDX-License-Identifier: AGPL-3.0-or-later
//! The tests of M8 part 3 (S1–S4, S7–S11; S5 extends P1 in `tests_conv`, S6 is `history_never_returns_view_once_payload` in
//! `secmp-client-core`): the fixes of the part-2 review, the history, the settings, the contact actions and the status line,
//! through the view models on the testing backend (no display).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use secmp_client_core::api::runtime::create_profile;
use secmp_client_core::relay_view::relay_view;
use slint::Model as _;

use crate::app::render;
use crate::bridge::{Bridge, CoreEvent, Request, Response};
use crate::core_backend::{CoreBackend, mode_of};
use crate::locale::{self, Lang, key};
use crate::screens::MainWindow;
use crate::tests::{SECRET, Test, pump, queue, remove, row, scratch, settle, stub};
use crate::tests_conv::Rig;
use crate::vm::{
    Failure, ModeChoice, Protection, ReceiptChoice, RetentionChoice, Screen, SettingsView, Vm,
};

/// A new message of kind `kind` and id `[id; 16]` arrives from contact 1.
fn arrives(rig: &mut Rig, kind: u8, id: u8) {
    rig.vm.apply(
        Response::Event(CoreEvent::MessageReceived {
            contact: 1,
            msg_id: [id; 16],
            kind,
            at_ms: 3_600_000,
        }),
        &rig.bridge,
    );
    rig.settle();
}

/// S1: while the display is locked the banners are withheld, the draft and the invitation input are emptied and their fields are
/// disabled, and an invitation is not accepted from a locked model.
#[test]
fn banners_and_inputs_are_withheld_while_locked() -> Test {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new()?;
    let mut rig = Rig::conversation();
    rig.vm
        .apply(Response::Event(CoreEvent::KeyChanged(1)), &rig.bridge);
    rig.settle();
    assert_eq!(rig.vm.conv_banners().len(), 2);
    ui.set_conv_draft("a draft".into());
    ui.set_invite_input("an invitation".into());

    rig.vm.set_protection(Protection::Locked);
    assert!(rig.vm.conv_banners().is_empty());
    assert!(!rig.vm.conv_input_enabled());
    assert!(!rig.vm.invite_input_enabled());
    render(&ui, &rig.vm);
    assert_eq!(ui.get_conv_banners().row_count(), 0);
    assert!(ui.get_conv_draft().is_empty());
    assert!(ui.get_invite_input().is_empty());
    assert!(!ui.get_conv_input_enabled());
    assert!(!ui.get_invite_input_enabled());

    // the invitation screen of a locked model takes nothing
    rig.vm.set_protection(Protection::Verified);
    rig.vm.leave();
    rig.vm.open_invitations();
    rig.vm.set_protection(Protection::Locked);
    rig.vm.accept_invitation(&rig.bridge, "good-invitation");
    assert!(!rig.vm.busy());
    assert_eq!(rig.vm.invite_status(), "");

    // and verified again, the banners come back
    rig.vm.set_protection(Protection::Verified);
    rig.vm.leave();
    rig.vm.open_contact(&rig.bridge, 0);
    assert_eq!(rig.vm.conv_banners().len(), 2);
    rig.bridge.shutdown();
    Ok(())
}

/// S2: the 20 seconds of a reveal run from the press that starts it; a second press does not extend them (and asks the core for
/// nothing); the window losing the focus, a change of the protection and leaving the screen end a reveal at once.
#[test]
fn reveal_timer_is_not_extended_by_second_press_and_focus_loss_releases() {
    let mut rig = Rig::conversation();
    rig.receive(3);
    // t = 1 000 ms: the reveal starts; t = 15 000 ms: a second press changes nothing
    rig.vm.reveal_press(&rig.bridge, 0, 1_000);
    assert!(rig.vm.revealing());
    rig.settle();
    rig.vm.reveal_press(&rig.bridge, 0, 15_000);
    rig.settle();
    assert_eq!(rig.reveals.load(Ordering::SeqCst), 1);
    // 20 s after the first press (21 000 ms) it is over, not 20 s after the second
    assert!(!rig.vm.tick(20_999));
    assert!(rig.vm.revealing());
    assert!(rig.vm.tick(21_000));
    assert!(!rig.vm.revealing());
    assert!(!rig.vm.tick(40_000));

    // the focus is lost while the text shows
    arrives(&mut rig, 3, 9);
    rig.vm.reveal_press(&rig.bridge, 1, 100_000);
    rig.settle();
    let shown = |rig: &Rig| rig.vm.conv_rows().get(1).map(|r| r.text.clone());
    assert_eq!(shown(&rig).as_deref(), Some(SECRET));
    rig.vm.focus_lost();
    assert!(!rig.vm.revealing());
    assert_ne!(shown(&rig).as_deref(), Some(SECRET));

    // the protection is lost while the text shows
    arrives(&mut rig, 3, 10);
    rig.vm.reveal_press(&rig.bridge, 2, 200_000);
    rig.settle();
    assert_eq!(
        rig.vm.conv_rows().get(2).map(|r| r.text.as_str()),
        Some(SECRET)
    );
    rig.vm.set_protection(Protection::Locked);
    assert!(!rig.vm.revealing());
    rig.vm.set_protection(Protection::Verified);

    // the screen is left while the text shows
    arrives(&mut rig, 3, 11);
    rig.vm.reveal_press(&rig.bridge, 3, 300_000);
    rig.settle();
    assert!(rig.vm.revealing());
    rig.vm.leave();
    assert!(!rig.vm.revealing());
    rig.bridge.shutdown();
}

/// S3: the answer to a `Verify` clears the warnings raised before it was submitted; a key change that came after the submit stays,
/// the conversation stays frozen, and the safety number on the screen is fetched again.
#[test]
fn verify_answer_does_not_clear_newer_key_change() {
    let mut rig = Rig::conversation();
    rig.vm
        .apply(Response::Event(CoreEvent::KeyChanged(1)), &rig.bridge);
    rig.vm.open_safety(&rig.bridge);
    pump(&mut rig.vm, &rig.bridge, &rig.rx, Vm::safety_can_verify);
    assert!(!rig.vm.safety_text().is_empty());

    rig.vm.verify(&rig.bridge);
    assert!(rig.vm.busy());
    // a second key change, before the answer to the verify
    rig.vm
        .apply(Response::Event(CoreEvent::KeyChanged(1)), &rig.bridge);
    // the number shown belongs to the old key: it is gone at once, and asked for again
    assert_eq!(rig.vm.safety_text(), "");
    rig.settle();
    assert!(!rig.vm.busy());
    assert!(!rig.vm.safety_text().is_empty());
    assert_eq!(rig.vm.safety_status(), "");
    rig.vm.leave();
    assert_eq!(rig.vm.screen(), Screen::Conversation);
    assert!(!rig.vm.conv_input_enabled());
    assert!(
        rig.vm
            .conv_banners()
            .contains(&locale::text(Lang::En, key::WARN_KEY_CHANGED))
    );

    // a verify submitted after it clears it
    rig.vm.open_safety(&rig.bridge);
    pump(&mut rig.vm, &rig.bridge, &rig.rx, Vm::safety_can_verify);
    rig.vm.verify(&rig.bridge);
    rig.settle();
    rig.vm.leave();
    assert!(rig.vm.conv_input_enabled());
    assert!(rig.vm.conv_banners().is_empty());
    rig.bridge.shutdown();
}

/// The backend waits at the gate with a request, and eight more wait behind it: the queue is full.
fn jam(bridge: &Bridge, entered: &AtomicUsize) -> Test {
    let before = entered.load(Ordering::SeqCst);
    bridge.submit(Request::Contacts).map_err(|_| "submit")?;
    for _ in 0..1_000 {
        if entered.load(Ordering::SeqCst) > before {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(entered.load(Ordering::SeqCst) > before, "the gate holds");
    while bridge.submit(Request::Contacts).is_ok() {}
    Ok(())
}

/// A model method that asks for an action.
type Ask = fn(&mut Vm);

/// S4: with the bridge's queue full, a safety number request and a history request (the first page and a page of older
/// messages) set `Failure::Busy`; nothing is dropped silently, and the safety number screen is not entered.
#[test]
fn full_queue_sets_busy_on_safety_and_history_requests() -> Test {
    let (sink, rx) = queue();
    let (open, close) = channel::<()>();
    let (backend, _) = stub(vec![row(1, "Zed", true), row(2, "Bo", true)], Some(close));
    // a full page: more messages are to be had
    backend.page.store(50, Ordering::SeqCst);
    let entered = backend.entered.clone();
    let bridge = Bridge::spawn(backend, sink);
    let mut vm = Vm::new(Lang::En, Screen::Unlock, "alice");
    vm.set_protection(Protection::Verified);
    vm.apply(Response::Opened, &bridge);
    open.send(())?;
    pump(&mut vm, &bridge, &rx, |vm| !vm.contacts().is_empty());
    // Zed's first page arrives while the queue is free
    vm.open_contact(&bridge, 0);
    settle(&mut vm, &bridge, &rx)?;
    assert!(vm.conv_more());
    assert_eq!(vm.error_text(), "");

    jam(&bridge, &entered)?;
    let busy = locale::text(Lang::En, Failure::Busy.message_key());

    vm.open_safety(&bridge);
    assert_eq!(vm.error_text(), busy, "safety");
    assert_eq!(vm.screen(), Screen::Conversation);

    vm.load_earlier(&bridge);
    assert_eq!(vm.error_text(), busy, "older page");

    vm.leave();
    assert_eq!(vm.error_text(), "");
    vm.open_contact(&bridge, 1);
    assert_eq!(vm.error_text(), busy, "first page");
    assert_eq!(vm.screen(), Screen::Conversation);

    // the gate is open for good: the queue drains, and the page that was refused is asked for again when the contact is reopened
    drop(open);
    vm.leave();
    settle(&mut vm, &bridge, &rx)?;
    vm.open_contact(&bridge, 1);
    settle(&mut vm, &bridge, &rx)?;
    assert!(vm.conv_more());
    bridge.shutdown();
    Ok(())
}

/// A profile's root directory, its model, its bridge and the receiving end of the bridge.
type Real = (std::path::PathBuf, Vm, Bridge, Receiver<Response>);

/// A real profile `alice` under a new scratch root, unlocked through its view model; the model is on the contact list and
/// everything it asked for has been answered.
fn real(name: &str, protection: Protection) -> Result<Real, Box<dyn std::error::Error>> {
    let root = scratch(name);
    std::fs::create_dir_all(&root)?;
    create_profile(&root.join("alice"), b"right", None).map_err(|_| "create alice")?;
    let (vm, bridge, rx) = reopen(&root, protection)?;
    Ok((root, vm, bridge, rx))
}

/// Unlock `alice` under `root` (again).
fn reopen(
    root: &std::path::Path,
    protection: Protection,
) -> Result<(Vm, Bridge, Receiver<Response>), Box<dyn std::error::Error>> {
    let (sink, rx) = queue();
    let bridge = Bridge::spawn(CoreBackend::new(root.to_path_buf(), true), sink);
    let mut vm = Vm::new(Lang::En, Screen::Unlock, "alice");
    vm.set_protection(protection);
    vm.unlock(&bridge, "right");
    pump(&mut vm, &bridge, &rx, |vm| vm.screen() == Screen::Contacts);
    settle(&mut vm, &bridge, &rx)?;
    Ok((vm, bridge, rx))
}

/// S7: retention and both receipt settings are changed through the settings screen, the profile is closed and opened again, and
/// the settings screen shows the new values (the window's controls too).
#[test]
fn settings_roundtrip_through_real_core() -> Test {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new()?;
    let (root, mut vm, bridge, rx) = real("s7", Protection::Verified)?;
    vm.open_settings(&bridge);
    pump(&mut vm, &bridge, &rx, Vm::settings_enabled);
    let start = vm.settings_shown().ok_or("settings")?;
    assert_eq!(
        (start.retention, start.delivered, start.read_receipts),
        (RetentionChoice::Keep, ReceiptChoice::VerifiedOnly, false)
    );

    // 30 days is the third of the offered retentions, "every contact" the third receipt choice
    vm.pick_retention(&bridge, 2);
    pump(&mut vm, &bridge, &rx, Vm::settings_enabled);
    vm.pick_delivered(&bridge, 2);
    pump(&mut vm, &bridge, &rx, Vm::settings_enabled);
    vm.set_read_receipts(&bridge, true);
    pump(&mut vm, &bridge, &rx, Vm::settings_enabled);
    settle(&mut vm, &bridge, &rx)?;
    assert_eq!(vm.error_text(), "");
    bridge.shutdown();
    drop(vm);

    let (mut vm, bridge, rx) = reopen(&root, Protection::Verified)?;
    vm.open_settings(&bridge);
    pump(&mut vm, &bridge, &rx, Vm::settings_enabled);
    let want = SettingsView {
        mode: start.mode,
        retention: RetentionChoice::Days(30),
        delivered: ReceiptChoice::All,
        read_receipts: true,
    };
    assert_eq!(vm.settings_shown(), Some(want));
    render(&ui, &vm);
    assert_eq!(ui.get_retention_index(), 2);
    assert_eq!(ui.get_delivered_index(), 2);
    assert!(ui.get_settings_read());
    assert_eq!(ui.get_screen(), 7);
    assert_eq!(
        ui.get_indicator_text().as_str(),
        locale::text(Lang::En, key::INDICATOR_PROTECTED)
    );
    bridge.shutdown();
    remove(&root);
    Ok(())
}

/// S8: picking another traffic mode lists what the relay can see in it and asks for a confirm click; nothing is stored before the
/// click, and a cancel restores the list of the mode in force.
#[test]
fn mode_change_needs_confirmation_and_shows_relay_view() {
    let mut rig = Rig::new();
    rig.vm.open_settings(&rig.bridge);
    pump(&mut rig.vm, &rig.bridge, &rig.rx, |vm| {
        vm.settings_enabled()
    });
    rig.settle();
    let lines = |mode| -> Vec<String> {
        relay_view(mode_of(mode), false)
            .into_iter()
            .map(str::to_owned)
            .collect()
    };
    assert_eq!(rig.vm.relay_lines(), lines(ModeChoice::Strict));
    assert_ne!(lines(ModeChoice::Strict), lines(ModeChoice::Balanced));

    // Strict -> Balanced: the list of Balanced, a question, no store
    rig.vm.pick_mode(&rig.bridge, 1);
    rig.settle();
    assert_eq!(rig.vm.relay_lines(), lines(ModeChoice::Balanced));
    assert_eq!(
        rig.vm.confirm_text(),
        locale::text(Lang::En, key::CONFIRM_MODE)
    );
    assert_eq!(
        rig.vm.settings_shown().map(|s| s.mode),
        Some(ModeChoice::Balanced)
    );
    assert_eq!(rig.sets.load(Ordering::SeqCst), 0);

    // cancelled: the list of the mode in force, nothing stored
    rig.vm.cancel(&rig.bridge);
    rig.settle();
    assert_eq!(rig.vm.confirm_text(), "");
    assert_eq!(rig.vm.relay_lines(), lines(ModeChoice::Strict));
    assert_eq!(
        rig.vm.settings_shown().map(|s| s.mode),
        Some(ModeChoice::Strict)
    );
    assert_eq!(rig.sets.load(Ordering::SeqCst), 0);

    // picked again and confirmed: stored once
    rig.vm.pick_mode(&rig.bridge, 2);
    rig.settle();
    assert_eq!(rig.sets.load(Ordering::SeqCst), 0);
    rig.vm.confirm(&rig.bridge);
    rig.settle();
    rig.vm.confirm(&rig.bridge);
    rig.settle();
    assert_eq!(rig.sets.load(Ordering::SeqCst), 1);
    assert_eq!(
        rig.vm.settings_shown().map(|s| s.mode),
        Some(ModeChoice::LowBw)
    );
    assert_eq!(rig.vm.relay_lines(), lines(ModeChoice::LowBw));
    rig.bridge.shutdown();
}

/// S9: rotating the session keys, resetting the session, removing the contact, rotating the identity and exporting each ask a
/// question first; nothing reaches the core before the confirm click, a cancel sends nothing, and one confirm sends once.
#[test]
fn contact_and_identity_actions_send_nothing_before_confirmation() -> Test {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new()?;
    let mut rig = Rig::conversation();
    rig.vm.open_options();
    assert_eq!(rig.vm.screen(), Screen::Options);
    let sent = |rig: &Rig| rig.actions.load(Ordering::SeqCst);

    let asks: [(Ask, &str); 3] = [
        (Vm::ask_rotate, key::CONFIRM_ROTATE),
        (Vm::ask_reset, key::CONFIRM_RESET),
        (Vm::ask_remove, key::CONFIRM_REMOVE),
    ];
    for (n, (ask, question)) in asks.into_iter().enumerate() {
        ask(&mut rig.vm);
        rig.settle();
        assert_eq!(rig.vm.confirm_text(), locale::text(Lang::En, question));
        render(&ui, &rig.vm);
        assert_eq!(
            ui.get_confirm_text().as_str(),
            locale::text(Lang::En, question)
        );
        assert_eq!(sent(&rig), n, "asked, not confirmed");
        // cancelled: nothing
        rig.vm.cancel(&rig.bridge);
        rig.settle();
        assert_eq!(rig.vm.confirm_text(), "");
        assert_eq!(sent(&rig), n, "cancelled");
        // asked again and confirmed: once
        ask(&mut rig.vm);
        rig.vm.confirm(&rig.bridge);
        rig.settle();
        rig.vm.confirm(&rig.bridge);
        rig.settle();
        assert_eq!(sent(&rig), n + 1, "confirmed");
        assert_eq!(
            rig.vm.notice_text(),
            locale::text(Lang::En, key::ACTION_DONE)
        );
    }

    // the profile actions on the settings screen
    rig.vm.leave();
    rig.vm.leave();
    rig.vm.open_settings(&rig.bridge);
    rig.settle();
    rig.vm.ask_identity();
    rig.settle();
    assert_eq!(
        rig.vm.confirm_text(),
        locale::text(Lang::En, key::CONFIRM_IDENTITY)
    );
    assert_eq!(sent(&rig), 3);
    rig.vm.cancel(&rig.bridge);
    assert_eq!(sent(&rig), 3);
    rig.vm.ask_identity();
    rig.vm.confirm(&rig.bridge);
    rig.settle();
    assert_eq!(sent(&rig), 4);
    assert_eq!(
        rig.vm.notice_text(),
        locale::text(Lang::En, key::ACTION_IDENTITY_DONE)
    );

    // an export needs its path and passphrase, then a confirm click
    rig.vm.ask_export("", "pass", "pass");
    assert_eq!(rig.vm.confirm_text(), "");
    assert_eq!(
        rig.vm.error_text(),
        locale::text(Lang::En, Failure::ExportInput.message_key())
    );
    rig.vm.ask_export("/tmp/backup.smpb", "pass", "other");
    assert_eq!(rig.vm.confirm_text(), "");
    assert_eq!(
        rig.vm.error_text(),
        locale::text(Lang::En, Failure::PassphraseMismatch.message_key())
    );
    rig.vm.ask_export("/tmp/backup.smpb", "pass", "pass");
    rig.settle();
    assert_eq!(sent(&rig), 4);
    // the question names the target
    assert_eq!(
        rig.vm.confirm_text(),
        format!(
            "{}\n/tmp/backup.smpb",
            locale::text(Lang::En, key::CONFIRM_EXPORT)
        )
    );
    rig.vm.confirm(&rig.bridge);
    rig.settle();
    assert_eq!(sent(&rig), 5);
    rig.bridge.shutdown();
    Ok(())
}

/// The display state the core holds, asked through the bridge (the queue has been settled).
fn core_display(
    vm: &mut Vm,
    bridge: &Bridge,
    rx: &Receiver<Response>,
) -> Result<Protection, Box<dyn std::error::Error>> {
    settle(vm, bridge, rx)?;
    bridge.submit(Request::DisplayState).map_err(|_| "submit")?;
    loop {
        match rx.recv()? {
            Response::Display(state) => return Ok(state),
            other => vm.apply(other, bridge),
        }
    }
}

/// S10: the indicator text follows the display state on every screen the model reaches, and the core reports what the UI set
/// (CS-1.18: the indicator is testable through the core API); nothing is written to the profile for it.
#[test]
fn indicator_text_follows_display_state_and_core_reports_it() -> Test {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new()?;
    let (root, mut vm, bridge, rx) = real("s10", Protection::Locked)?;
    let expect = |ui: &MainWindow, k: &'static str| {
        assert_eq!(ui.get_indicator_text().as_str(), locale::text(Lang::En, k));
    };
    // the state the UI starts in is the state the core is told on opening
    render(&ui, &vm);
    expect(&ui, key::INDICATOR_LOCKED);
    assert_eq!(core_display(&mut vm, &bridge, &rx)?, Protection::Locked);

    for (state, k) in [
        (Protection::Verified, key::INDICATOR_PROTECTED),
        (Protection::Partial, key::INDICATOR_PARTIAL),
        (Protection::Locked, key::INDICATOR_LOCKED),
    ] {
        vm.set_protection(state);
        vm.sync_display(&bridge);
        render(&ui, &vm);
        expect(&ui, k);
        assert_eq!(core_display(&mut vm, &bridge, &rx)?, state);
        // permanent: the same line on another screen
        vm.open_settings(&bridge);
        settle(&mut vm, &bridge, &rx)?;
        render(&ui, &vm);
        expect(&ui, k);
        vm.leave();
    }
    // the content is shown for the partial state and locked for the locked one
    vm.set_protection(Protection::Partial);
    assert!(vm.content_visible());
    assert!(!vm.override_available());
    #[cfg(target_os = "linux")]
    {
        vm.set_protection(Protection::Locked);
        vm.override_session();
        vm.sync_display(&bridge);
        render(&ui, &vm);
        expect(&ui, key::INDICATOR_OVERRIDDEN);
        assert_eq!(core_display(&mut vm, &bridge, &rx)?, Protection::Overridden);
    }
    // a profile opened again starts locked, in the model and in the core
    bridge.shutdown();
    let (mut vm, bridge, rx) = reopen(&root, Protection::Locked)?;
    assert_eq!(core_display(&mut vm, &bridge, &rx)?, Protection::Locked);
    bridge.shutdown();
    remove(&root);
    Ok(())
}

/// S11: the connection line names the transport and one of connected, connecting, unavailable; it carries no address, no port
/// and no number, whatever the engine's state.
#[test]
fn status_line_shows_no_address_and_no_activity_counters() -> Test {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new()?;
    let plain = |text: &str| {
        !text
            .chars()
            .any(|c| c.is_ascii_digit() || matches!(c, '.' | '/' | '@' | '['))
    };

    // a real profile in direct mode without a relay: no link comes up
    let (root, mut vm, bridge, rx) = real("s11", Protection::Verified)?;
    vm.poll_status(&bridge);
    settle(&mut vm, &bridge, &rx)?;
    let text = vm.status_text();
    assert_eq!(
        text,
        format!(
            "{}: {}",
            locale::text(Lang::En, key::STATUS_DIRECT),
            locale::text(Lang::En, key::STATUS_CONNECTING)
        )
    );
    assert!(plain(&text), "{text}");
    render(&ui, &vm);
    assert_eq!(ui.get_status_text().as_str(), text);
    bridge.shutdown();
    remove(&root);

    // a stub whose link is up: connected, and the engine's notice turns it into unavailable
    let mut rig = Rig::new();
    rig.vm.poll_status(&rig.bridge);
    rig.settle();
    let up = rig.vm.status_text();
    assert_eq!(
        up,
        format!(
            "{}: {}",
            locale::text(Lang::En, key::STATUS_DIRECT),
            locale::text(Lang::En, key::STATUS_CONNECTED)
        )
    );
    assert!(plain(&up), "{up}");
    rig.vm
        .apply(Response::Event(CoreEvent::Unavailable), &rig.bridge);
    let down = rig.vm.status_text();
    assert!(down.ends_with(locale::text(Lang::En, key::STATUS_UNAVAILABLE)));
    assert!(plain(&down), "{down}");
    rig.bridge.shutdown();
    Ok(())
}

/// X2: a settings change whose submit is refused (the queue is full) is not shown: the stored value stays on the screen, with
/// the busy failure, and nothing was stored.
#[test]
fn refused_settings_submit_keeps_showing_the_stored_value() -> Test {
    let (sink, rx) = queue();
    let (open, close) = channel::<()>();
    let (backend, _) = stub(vec![row(1, "Zed", true)], Some(close));
    let (entered, sets) = (backend.entered.clone(), backend.sets.clone());
    let bridge = Bridge::spawn(backend, sink);
    let mut vm = Vm::new(Lang::En, Screen::Unlock, "alice");
    vm.set_protection(Protection::Verified);
    vm.apply(Response::Opened, &bridge);
    open.send(())?;
    pump(&mut vm, &bridge, &rx, |vm| !vm.contacts().is_empty());
    vm.open_settings(&bridge);
    pump(&mut vm, &bridge, &rx, Vm::settings_enabled);
    let stored = vm.settings_shown();
    assert!(stored.is_some());

    jam(&bridge, &entered)?;
    vm.pick_retention(&bridge, 2);
    assert_eq!(vm.settings_shown(), stored);
    assert_eq!(
        vm.error_text(),
        locale::text(Lang::En, Failure::Busy.message_key())
    );
    assert!(!vm.busy());

    drop(open);
    settle(&mut vm, &bridge, &rx)?;
    assert_eq!(vm.settings_shown(), stored);
    assert_eq!(sets.load(Ordering::SeqCst), 0);
    bridge.shutdown();
    Ok(())
}

/// X3: an export writes an encrypted file (the profile's name is not in it); a second export to the same path is refused with
/// the export error and leaves the file as it was.
#[test]
fn export_writes_encrypted_backup_and_never_overwrites() -> Test {
    let (root, mut vm, bridge, rx) = real("x3", Protection::Verified)?;
    vm.open_settings(&bridge);
    pump(&mut vm, &bridge, &rx, Vm::settings_enabled);
    let path = root.join("backup.smpb");
    let path_text = path.to_string_lossy().into_owned();

    vm.ask_export(&path_text, "backup pass", "backup pass");
    assert!(vm.confirm_text().ends_with(&path_text));
    assert!(
        !path.exists(),
        "nothing is written before the confirm click"
    );
    vm.confirm(&bridge);
    pump(&mut vm, &bridge, &rx, |vm| !vm.busy());
    assert_eq!(vm.error_text(), "");
    assert_eq!(vm.notice_text(), locale::text(Lang::En, key::ACTION_DONE));
    let first = std::fs::read(&path)?;
    assert!(!first.is_empty());
    assert!(!first.windows(5).any(|w| w == b"alice"));

    vm.ask_export(&path_text, "backup pass", "backup pass");
    vm.confirm(&bridge);
    pump(&mut vm, &bridge, &rx, |vm| !vm.busy());
    assert_eq!(
        vm.error_text(),
        locale::text(Lang::En, Failure::Export.message_key())
    );
    assert_eq!(std::fs::read(&path)?, first);
    bridge.shutdown();
    remove(&root);
    Ok(())
}

/// X4: an action that waits for its confirm click is dropped when the display state drops to locked, and when the screen is
/// left; the click that follows sends nothing.
#[test]
fn pending_action_is_cleared_when_protection_drops() {
    let mut rig = Rig::conversation();
    rig.vm.open_options();
    rig.vm.ask_remove();
    assert!(rig.vm.confirming());
    rig.vm.set_protection(Protection::Locked);
    assert!(!rig.vm.confirming());
    assert_eq!(rig.vm.confirm_text(), "");
    rig.vm.set_protection(Protection::Verified);
    rig.vm.confirm(&rig.bridge);
    rig.settle();
    assert_eq!(rig.actions.load(Ordering::SeqCst), 0);

    rig.vm.ask_rotate();
    assert!(rig.vm.confirming());
    rig.vm.leave();
    assert!(!rig.vm.confirming());
    rig.vm.confirm(&rig.bridge);
    rig.settle();
    assert_eq!(rig.actions.load(Ordering::SeqCst), 0);
    rig.bridge.shutdown();
}
