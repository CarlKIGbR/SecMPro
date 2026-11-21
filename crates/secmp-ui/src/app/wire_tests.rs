// SPDX-License-Identifier: AGPL-3.0-or-later
//! The shell of `app` under Slint's testing backend (no display): `wire` binds the window's callbacks to a model over a stub
//! core, and every callback is driven through the window's `invoke_*`, as a click would. What the window shows afterwards is
//! what is asserted; the event loop, the native window and the platform check are not part of these tests.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::time::Duration;

use slint::Model as _;
use slint::SharedString;

use super::{SHELL, deliver, deliver_protection, existing_profile, wire, with_shell};
use crate::bridge::{Bridge, Request, Response};
use crate::locale::{self, Lang, key};
use crate::screens::MainWindow;
use crate::tests::{DIGITS, INVITE_URI, Test, queue, remove, row, scratch, stub};
use crate::vm::{ContactRow, Protection, Screen, Vm};

/// The window, the answers of the bridge waiting for the UI thread, and the stub's counters.
struct Rig {
    ui: MainWindow,
    rx: Receiver<Response>,
    sets: Arc<AtomicUsize>,
    actions: Arc<AtomicUsize>,
}

impl Rig {
    fn new(
        screen: Screen,
        rows: Vec<ContactRow>,
        protection: Protection,
    ) -> Result<Self, slint::PlatformError> {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new()?;
        let (sink, rx) = queue();
        let (backend, _) = stub(rows, None);
        let sets = backend.sets.clone();
        let actions = backend.actions.clone();
        let bridge = Bridge::spawn(backend, sink);
        wire(&ui, Vm::new(Lang::En, screen, "alice"), bridge);
        let rig = Self {
            ui,
            rx,
            sets,
            actions,
        };
        if screen == Screen::Contacts {
            with_shell(|sh| {
                let _ = sh.bridge.submit(Request::Contacts);
            });
        }
        deliver_protection(protection);
        rig.settle();
        Ok(rig)
    }

    /// Take every answer of the bridge on this thread until none comes for a while.
    fn settle(&self) {
        while let Ok(response) = self.rx.recv_timeout(Duration::from_millis(250)) {
            deliver(response);
        }
    }

    fn screen(&self) -> i32 {
        self.ui.get_screen()
    }
}

impl Drop for Rig {
    /// The window is gone: the shell is taken down, which ends the stub's thread.
    fn drop(&mut self) {
        let shell = SHELL.with(|cell| cell.borrow_mut().take());
        if let Some(shell) = shell {
            shell.bridge.shutdown();
        }
    }
}

const ONBOARDING: i32 = 0;
const UNLOCK: i32 = 1;
const CONTACTS: i32 = 2;
const INVITATIONS: i32 = 4;
const CONVERSATION: i32 = 5;
const SAFETY: i32 = 6;
const SETTINGS: i32 = 7;
const OPTIONS: i32 = 8;

/// The unlock click hands the passphrase to the model and empties the field at once; the core's answer opens the profile.
#[test]
fn unlock_click_empties_the_field_and_opens_the_contacts() -> Test {
    let rig = Rig::new(Screen::Unlock, vec![], Protection::Locked)?;
    assert_eq!(rig.screen(), UNLOCK);
    rig.ui.set_unlock_pass(SharedString::from("correct horse"));
    rig.ui.invoke_unlock(SharedString::from("correct horse"));
    assert_eq!(rig.ui.get_unlock_pass().as_str(), "");
    rig.settle();
    assert_eq!(rig.screen(), CONTACTS);
    assert_eq!(rig.ui.get_error_text().as_str(), "");
    Ok(())
}

/// The create click empties both passphrase fields whatever comes of it; a mismatch stays on the form with the model's text.
#[test]
fn create_click_empties_both_passphrase_fields() -> Test {
    let rig = Rig::new(Screen::Onboarding, vec![], Protection::Locked)?;
    rig.ui.set_pass1(SharedString::from("one"));
    rig.ui.set_pass2(SharedString::from("two"));
    rig.ui
        .invoke_create("alice".into(), "one".into(), "two".into(), 1);
    assert_eq!(rig.ui.get_pass1().as_str(), "");
    assert_eq!(rig.ui.get_pass2().as_str(), "");
    rig.settle();
    assert_eq!(rig.screen(), ONBOARDING);
    assert!(!rig.ui.get_error_text().is_empty());

    rig.ui
        .invoke_create("alice".into(), "same".into(), "same".into(), 1);
    rig.settle();
    assert_eq!(rig.screen(), CONTACTS);
    Ok(())
}

/// Picking a mode on the onboarding form shows the relay's view of that mode in the window.
#[test]
fn mode_pick_shows_the_relay_view_lines() -> Test {
    let rig = Rig::new(Screen::Onboarding, vec![], Protection::Locked)?;
    assert_eq!(rig.ui.get_relay_lines().row_count(), 0);
    rig.ui.invoke_mode_picked(2);
    rig.settle();
    assert!(rig.ui.get_relay_lines().row_count() > 0);
    Ok(())
}

/// The invitation screen: a created invitation is shown on a verified display only, accepting empties the input field, and
/// back returns to the contacts.
#[test]
fn invitation_callbacks_create_accept_and_leave() -> Test {
    let rig = Rig::new(Screen::Contacts, vec![], Protection::Verified)?;
    rig.ui.invoke_open_invitations();
    assert_eq!(rig.screen(), INVITATIONS);
    rig.ui.invoke_invite_create();
    rig.settle();
    assert_eq!(rig.ui.get_invite_uri().as_str(), INVITE_URI);
    assert!(rig.ui.get_invite_copyable());

    rig.ui
        .set_invite_input(SharedString::from("good-invitation"));
    rig.ui.invoke_invite_accept("good-invitation".into());
    assert_eq!(rig.ui.get_invite_input().as_str(), "");
    rig.settle();

    rig.ui.set_invite_input(SharedString::from("left over"));
    rig.ui.invoke_back();
    assert_eq!(rig.screen(), CONTACTS);
    assert_eq!(rig.ui.get_invite_input().as_str(), "");
    Ok(())
}

/// The same invitation is not shown while the display is locked.
#[test]
fn locked_display_shows_no_invitation() -> Test {
    let rig = Rig::new(Screen::Contacts, vec![], Protection::Locked)?;
    rig.ui.invoke_open_invitations();
    rig.ui.invoke_invite_create();
    rig.settle();
    assert!(!rig.ui.get_invite_uri().as_str().contains(INVITE_URI));
    assert!(!rig.ui.get_invite_copyable());
    Ok(())
}

/// The conversation callbacks: open a contact, send (the draft stays until the core took the text), the press on a message
/// that does not exist starts no reveal, the safety number and its verification, and leaving empties the draft.
#[test]
fn conversation_callbacks_send_reveal_and_verify() -> Test {
    let rig = Rig::new(
        Screen::Contacts,
        vec![row(1, "Ann", false)],
        Protection::Verified,
    )?;
    assert_eq!(rig.ui.get_contacts().row_count(), 1);
    rig.ui.invoke_open_contact(0);
    rig.settle();
    assert_eq!(rig.screen(), CONVERSATION);
    assert!(rig.ui.get_conv_input_enabled());

    rig.ui.set_conv_draft(SharedString::from("hi"));
    rig.ui.invoke_conv_send("hi".into());
    assert_eq!(rig.ui.get_conv_draft().as_str(), "hi");
    rig.settle();
    assert_eq!(rig.ui.get_conv_draft().as_str(), "");

    rig.ui.invoke_reveal_pressed(99);
    with_shell(|sh| assert!(!sh.vm.revealing()));
    rig.ui.invoke_reveal_released();
    rig.ui.invoke_conv_load_earlier();
    rig.settle();
    assert!(!rig.ui.get_conv_more());

    rig.ui.invoke_open_safety();
    rig.settle();
    assert_eq!(rig.screen(), SAFETY);
    assert_eq!(rig.ui.get_safety_digits().as_str(), DIGITS);
    assert!(rig.ui.get_safety_can_verify());
    rig.ui.invoke_safety_verify();
    rig.settle();
    assert!(!rig.ui.get_safety_can_verify());
    assert_eq!(
        rig.ui.get_safety_status().as_str(),
        locale::text(Lang::En, key::SAFETY_VERIFIED)
    );

    rig.ui.invoke_back();
    assert_eq!(rig.screen(), CONVERSATION);
    rig.ui.set_conv_draft(SharedString::from("unsent"));
    rig.ui.invoke_back();
    assert_eq!(rig.screen(), CONTACTS);
    assert_eq!(rig.ui.get_conv_draft().as_str(), "");
    Ok(())
}

/// The settings callbacks reach the core one by one, and the export form empties its passphrase fields whatever came of it.
#[test]
fn settings_callbacks_store_choices_and_empty_export_fields() -> Test {
    let rig = Rig::new(Screen::Contacts, vec![], Protection::Verified)?;
    rig.ui.invoke_open_settings();
    rig.settle();
    assert_eq!(rig.screen(), SETTINGS);
    assert!(rig.ui.get_settings_enabled());
    assert!(!rig.ui.get_settings_read());

    rig.ui.invoke_settings_read_toggled(true);
    rig.settle();
    assert!(rig.ui.get_settings_read());
    assert_eq!(rig.sets.load(Ordering::SeqCst), 1);
    rig.ui.invoke_settings_retention_picked(1);
    rig.settle();
    assert_eq!(rig.sets.load(Ordering::SeqCst), 2);
    rig.ui.invoke_settings_delivered_picked(0);
    rig.settle();
    assert_eq!(rig.sets.load(Ordering::SeqCst), 3);

    // a mode change asks first and sends nothing until the click
    rig.ui.invoke_settings_mode_picked(2);
    assert!(!rig.ui.get_confirm_text().is_empty());
    assert_eq!(rig.sets.load(Ordering::SeqCst), 3);
    rig.ui.invoke_cancel_clicked();
    rig.settle();
    assert!(rig.ui.get_confirm_text().is_empty());
    assert_eq!(rig.sets.load(Ordering::SeqCst), 3);
    rig.ui.invoke_settings_mode_picked(2);
    rig.ui.invoke_confirm_clicked();
    rig.settle();
    assert_eq!(rig.sets.load(Ordering::SeqCst), 4);

    // a mismatching export passphrase: nothing is asked, the fields are empty
    rig.ui.set_export_pass(SharedString::from("a"));
    rig.ui.set_export_pass2(SharedString::from("b"));
    rig.ui
        .invoke_ask_export("/tmp/x".into(), "a".into(), "b".into());
    assert_eq!(rig.ui.get_export_pass().as_str(), "");
    assert_eq!(rig.ui.get_export_pass2().as_str(), "");
    assert!(rig.ui.get_confirm_text().is_empty());
    assert!(!rig.ui.get_error_text().is_empty());
    assert_eq!(rig.actions.load(Ordering::SeqCst), 0);

    // a matching one is asked, and sent only by the click
    rig.ui
        .invoke_ask_export("/tmp/x".into(), "a".into(), "a".into());
    assert!(!rig.ui.get_confirm_text().is_empty());
    assert_eq!(rig.actions.load(Ordering::SeqCst), 0);
    rig.ui.invoke_confirm_clicked();
    rig.settle();
    assert_eq!(rig.actions.load(Ordering::SeqCst), 1);

    rig.ui.invoke_ask_identity();
    assert!(!rig.ui.get_confirm_text().is_empty());
    rig.ui.invoke_confirm_clicked();
    rig.settle();
    assert_eq!(rig.actions.load(Ordering::SeqCst), 2);

    rig.ui.set_export_path(SharedString::from("/tmp/y"));
    rig.ui.invoke_back();
    assert_eq!(rig.screen(), CONTACTS);
    assert_eq!(rig.ui.get_export_path().as_str(), "");
    Ok(())
}

/// The contact options: each action asks first, cancel sends nothing, the click sends exactly one request.
#[test]
fn option_callbacks_ask_before_acting() -> Test {
    let rig = Rig::new(
        Screen::Contacts,
        vec![row(1, "Ann", true)],
        Protection::Verified,
    )?;
    rig.ui.invoke_open_contact(0);
    rig.settle();
    rig.ui.invoke_open_options();
    assert_eq!(rig.screen(), OPTIONS);
    let asks: [&dyn Fn(&MainWindow); 3] = [
        &|ui| ui.invoke_ask_rotate(),
        &|ui| ui.invoke_ask_reset(),
        &|ui| ui.invoke_ask_remove(),
    ];
    for ask in asks {
        ask(&rig.ui);
        assert!(!rig.ui.get_confirm_text().is_empty());
        rig.ui.invoke_cancel_clicked();
        assert!(rig.ui.get_confirm_text().is_empty());
    }
    rig.settle();
    assert_eq!(rig.actions.load(Ordering::SeqCst), 0);
    rig.ui.invoke_ask_reset();
    rig.ui.invoke_confirm_clicked();
    rig.settle();
    assert_eq!(rig.actions.load(Ordering::SeqCst), 1);
    Ok(())
}

/// Fail closed: the window starts locked, only a verified check unlocks it, and a later locked outcome locks it again.
#[test]
fn protection_outcome_drives_the_indicator() -> Test {
    let rig = Rig::new(Screen::Unlock, vec![], Protection::Locked)?;
    assert!(rig.ui.get_indicator_locked());
    assert_eq!(
        rig.ui.get_indicator_text().as_str(),
        locale::text(Lang::En, key::INDICATOR_LOCKED)
    );
    deliver_protection(Protection::Verified);
    assert!(!rig.ui.get_indicator_locked());
    assert!(!rig.ui.get_show_override());
    assert_eq!(
        rig.ui.get_indicator_text().as_str(),
        locale::text(Lang::En, key::INDICATOR_PROTECTED)
    );
    deliver_protection(Protection::Locked);
    assert!(rig.ui.get_indicator_locked());
    Ok(())
}

/// Linux: the per-session override is offered on a locked display only, and the click moves it to Overridden, which still
/// reads as not protected.
#[cfg(target_os = "linux")]
#[test]
fn override_click_shows_content_but_stays_unprotected() -> Test {
    let rig = Rig::new(Screen::Unlock, vec![], Protection::Locked)?;
    assert!(rig.ui.get_show_override());
    rig.ui.invoke_override_requested();
    assert!(!rig.ui.get_show_override());
    assert!(rig.ui.get_indicator_locked());
    assert_eq!(
        rig.ui.get_indicator_text().as_str(),
        locale::text(Lang::En, key::INDICATOR_OVERRIDDEN)
    );
    with_shell(|sh| assert_eq!(sh.vm.protection(), Protection::Overridden));
    // a later locked outcome takes the override away again
    deliver_protection(Protection::Locked);
    with_shell(|sh| assert_eq!(sh.vm.protection(), Protection::Locked));
    Ok(())
}

/// The profile of the unlock screen is the first usable directory name in order; files and unusable names are skipped, and
/// no directory means none.
#[test]
fn existing_profile_picks_the_first_usable_directory() -> Test {
    let root = scratch("existing");
    assert_eq!(existing_profile(&root), None);
    std::fs::create_dir_all(root.join("zed"))?;
    std::fs::create_dir_all(root.join("bob"))?;
    std::fs::create_dir_all(root.join(".hidden"))?;
    std::fs::write(root.join("aaa"), b"a file, not a profile")?;
    assert_eq!(existing_profile(&root).as_deref(), Some("bob"));
    remove(&root.join("bob"));
    assert_eq!(existing_profile(&root).as_deref(), Some("zed"));
    remove(&root);
    Ok(())
}
