// SPDX-License-Identifier: AGPL-3.0-or-later
//! The tests of M8 part 2 (P1, P5, P6, P7; P2–P4 are in `tests` and `qr`, P8 is the locale test): invitation, conversation,
//! view-once and safety number through the view models, on the testing backend (no display).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use secmp_client_core::api::runtime::create_profile;
use secmp_testkit::harness::e2e::E2eRelay;
use slint::Model as _;

use crate::app::render;
use crate::bridge::{Bridge, CoreEvent, Request, Response};
use crate::core_backend::CoreBackend;
use crate::locale::{self, Lang, key};
use crate::screens::MainWindow;
use crate::tests::{
    DIGITS, HELLO, INVITE_URI, SECRET, Test, pump, queue, remove, row, scratch, stub,
};
use crate::vm::{ModeChoice, Protection, Screen, Vm};

/// A view model on a stub core with one contact, "Zed" (id 1), and the receiving end of its bridge.
struct Rig {
    vm: Vm,
    bridge: Bridge,
    rx: Receiver<Response>,
    reveals: Arc<AtomicUsize>,
}

impl Rig {
    /// On the contact list, protection verified.
    fn new() -> Self {
        let (sink, rx) = queue();
        let (backend, _) = stub(vec![row(1, "Zed", true)], None);
        let reveals = backend.reveals.clone();
        let bridge = Bridge::spawn(backend, sink);
        let mut vm = Vm::new(Lang::En, Screen::Unlock, "alice");
        vm.set_protection(Protection::Verified);
        vm.apply(Response::Opened, &bridge);
        pump(&mut vm, &bridge, &rx, |vm| !vm.contacts().is_empty());
        Self {
            vm,
            bridge,
            rx,
            reveals,
        }
    }

    /// In the conversation with Zed.
    fn conversation() -> Self {
        let mut rig = Self::new();
        rig.vm.open_contact(0);
        assert_eq!(rig.vm.screen(), Screen::Conversation);
        rig
    }

    /// Everything submitted so far has been handled and its answer applied (the bridge answers in order).
    fn settle(&mut self) {
        assert!(
            self.bridge
                .submit(Request::RelayView(ModeChoice::Strict))
                .is_ok()
        );
        while let Ok(response) = self.rx.recv() {
            let done = matches!(response, Response::RelayView(_));
            self.vm.apply(response, &self.bridge);
            if done {
                break;
            }
        }
    }

    /// A message of `kind` arrives from Zed, and its first row shows once the core has answered.
    fn receive(&mut self, kind: u8) {
        self.vm.apply(
            Response::Event(CoreEvent::MessageReceived {
                contact: 1,
                msg_id: [kind; 16],
                kind,
                at_ms: 3_600_000,
            }),
            &self.bridge,
        );
        self.settle();
    }
}

/// Every text a window shows that a screen can fill with content (the contact rows, the message rows, the invitation, the
/// titles, the safety number, the banners and the messages), in one string.
fn all_text(ui: &MainWindow) -> String {
    let mut out: Vec<String> = Vec::new();
    for r in ui.get_contacts().iter() {
        out.push(format!("{} {} {}", r.name, r.key, r.status));
    }
    for m in ui.get_conv_messages().iter() {
        out.push(format!("{} {}", m.text, m.meta));
    }
    for b in ui.get_conv_banners().iter() {
        out.push(b.to_string());
    }
    out.extend([
        ui.get_invite_uri().to_string(),
        ui.get_invite_status().to_string(),
        ui.get_conv_title().to_string(),
        ui.get_safety_digits().to_string(),
        ui.get_safety_status().to_string(),
        ui.get_error_text().to_string(),
        ui.get_unavailable_text().to_string(),
    ]);
    out.join("\n")
}

/// P5: a view-once is revealed only on a display verified as protected; while locked, and on the user's override, no
/// `Request::Reveal` reaches the core. Verified, the text shows while held and is gone after the release.
#[test]
fn view_once_reveal_is_refused_unless_verified() {
    let mut rig = Rig::conversation();
    rig.receive(3);
    let first = |rig: &Rig| rig.vm.conv_rows().into_iter().next();
    assert_eq!(
        first(&rig).map(|r| (r.text, r.hold)),
        Some((locale::text(Lang::En, key::MSG_VIEW_ONCE).to_owned(), true))
    );

    for protection in [Protection::Locked, Protection::Overridden] {
        rig.vm.set_protection(protection);
        rig.vm.reveal_press(&rig.bridge, 0);
        assert!(!rig.vm.revealing(), "{protection:?}");
        rig.settle();
        assert_eq!(rig.reveals.load(Ordering::SeqCst), 0, "{protection:?}");
    }
    // the override shows the placeholder that says why, not the hold area
    rig.vm.set_protection(Protection::Overridden);
    assert_eq!(
        first(&rig).map(|r| (r.text, r.hold)),
        Some((
            locale::text(Lang::En, key::MSG_VIEW_ONCE_LOCKED).to_owned(),
            false
        ))
    );

    rig.vm.set_protection(Protection::Verified);
    rig.vm.reveal_press(&rig.bridge, 0);
    assert!(rig.vm.revealing());
    rig.settle();
    assert_eq!(rig.reveals.load(Ordering::SeqCst), 1);
    assert_eq!(
        first(&rig).map(|r| (r.text, r.hold)),
        Some((SECRET.to_owned(), true))
    );
    rig.vm.reveal_release();
    assert_eq!(
        first(&rig).map(|r| (r.text, r.hold)),
        Some((
            locale::text(Lang::En, key::MSG_VIEW_ONCE_VIEWED).to_owned(),
            false
        ))
    );
    // it is gone: a second hold asks nothing
    rig.vm.reveal_press(&rig.bridge, 0);
    assert!(!rig.vm.revealing());
    rig.bridge.shutdown();
}

/// P6: a changed key freezes the conversation (banner, no input, nothing is sent) until the contact is verified again on the
/// safety number screen.
#[test]
fn key_changed_freezes_conversation_until_verified() -> Test {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new()?;
    let mut rig = Rig::conversation();
    assert!(rig.vm.conv_input_enabled());
    assert!(rig.vm.conv_banners().is_empty());

    rig.vm
        .apply(Response::Event(CoreEvent::KeyChanged(1)), &rig.bridge);
    assert!(!rig.vm.conv_input_enabled());
    assert!(!rig.vm.send(&rig.bridge, "still here?"));
    let banners = rig.vm.conv_banners();
    assert_eq!(
        banners.first(),
        Some(&locale::text(Lang::En, key::WARN_KEY_CHANGED))
    );
    assert!(banners.contains(&locale::text(Lang::En, key::CONV_FROZEN)));
    render(&ui, &rig.vm);
    assert!(!ui.get_conv_input_enabled());
    assert_eq!(ui.get_conv_banners().row_count(), 2);

    // nothing was queued: the next answer is the one to the next request
    rig.settle();
    assert!(rig.vm.conv_rows().is_empty());

    rig.vm.open_safety(&rig.bridge);
    pump(&mut rig.vm, &rig.bridge, &rig.rx, Vm::safety_can_verify);
    assert_eq!(rig.vm.safety_text(), DIGITS);
    rig.vm.verify(&rig.bridge);
    pump(&mut rig.vm, &rig.bridge, &rig.rx, |vm| !vm.busy());
    assert_eq!(
        rig.vm.safety_status(),
        locale::text(Lang::En, key::SAFETY_VERIFIED)
    );
    rig.vm.leave();
    assert_eq!(rig.vm.screen(), Screen::Conversation);
    assert!(rig.vm.conv_input_enabled());
    assert!(rig.vm.conv_banners().is_empty());
    assert!(rig.vm.send(&rig.bridge, "back"));
    rig.bridge.shutdown();
    Ok(())
}

/// P7: while the display is locked no screen puts a name, a message, the invitation or the safety number into a property of
/// the window; verified, the same screens show them (the positive control).
#[test]
fn no_content_strings_while_locked_on_any_screen() -> Test {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new()?;
    let mut rig = Rig::new();
    let needles = ["Zed", HELLO, INVITE_URI, DIGITS];
    // locked: none of the contents is in any property; verified: `shows` is
    let check = |rig: &mut Rig, shows: &str| {
        rig.vm.set_protection(Protection::Locked);
        render(&ui, &rig.vm);
        let locked = all_text(&ui);
        for needle in needles {
            assert!(!locked.contains(needle), "locked, {shows}: {needle}");
        }
        rig.vm.set_protection(Protection::Verified);
        render(&ui, &rig.vm);
        assert!(all_text(&ui).contains(shows), "verified: {shows}");
    };

    // the contact list
    check(&mut rig, "Zed");

    // the invitation
    rig.vm.open_invitations();
    rig.vm.create_invitation(&rig.bridge);
    pump(&mut rig.vm, &rig.bridge, &rig.rx, Vm::invitation_held);
    check(&mut rig, INVITE_URI);
    rig.vm.leave();

    // the conversation: the contact's name in the title, the message in a row
    rig.vm.open_contact(0);
    rig.receive(1);
    pump(&mut rig.vm, &rig.bridge, &rig.rx, |vm| {
        vm.conv_rows().first().is_some_and(|r| r.text == HELLO)
    });
    check(&mut rig, "Zed");
    check(&mut rig, HELLO);

    // the safety number
    rig.vm.open_safety(&rig.bridge);
    pump(&mut rig.vm, &rig.bridge, &rig.rx, Vm::safety_can_verify);
    check(&mut rig, DIGITS);
    assert_eq!(rig.vm.screen(), Screen::Safety);
    rig.bridge.shutdown();
    Ok(())
}

/// How long one step of the end-to-end test may take: a profile opens (key derivation) within this.
const LONG: Duration = Duration::from_secs(180);

/// How long the chain invitation → handshake → message → receipt may take (the cell schedule runs on periods of seconds).
const ROW: Duration = Duration::from_mins(15);

/// The passphrase of both profiles.
const PASS: &str = "correct horse";

/// A profile on the real core, opened through its view model.
struct Side {
    vm: Vm,
    bridge: Bridge,
    rx: Receiver<Response>,
}

impl Side {
    /// Create the profile `name` under `root` with the relay of `relay`, give it spare queues, and unlock it.
    fn open(
        root: &std::path::Path,
        name: &str,
        relay: &E2eRelay,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = root.join(name);
        let relay_text = std::fs::read_to_string(relay.ref_path())?;
        create_profile(&dir, PASS.as_bytes(), Some(&relay_text)).map_err(|_| "create profile")?;
        relay.seed_spares(&dir, PASS.as_bytes(), 2, name);
        let (sink, rx) = queue();
        let bridge = Bridge::spawn(CoreBackend::new(root.to_path_buf(), true), sink);
        let mut vm = Vm::new(Lang::En, Screen::Unlock, name);
        vm.set_protection(Protection::Verified);
        vm.unlock(&bridge, PASS);
        let mut side = Self { vm, bridge, rx };
        side.until(LONG, |vm| vm.screen() == Screen::Contacts)?;
        Ok(side)
    }

    /// Apply the answers and events that come until `done` holds.
    fn until(&mut self, within: Duration, done: impl Fn(&Vm) -> bool) -> Test {
        let deadline = Instant::now().checked_add(within).ok_or("deadline")?;
        while !done(&self.vm) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("timed out".into());
            }
            if let Ok(response) = self.rx.recv_timeout(left.min(Duration::from_secs(1))) {
                self.vm.apply(response, &self.bridge);
            }
        }
        Ok(())
    }
}

/// P1 (ADR-062 (3), the end-to-end test of M8): two real profiles on temporary directories and a relay (the process of the
/// workspace's end-to-end harness, direct TLS on 127.0.0.1, no Tor), driven through the view models only. A issues an
/// invitation, B accepts it, both see the contact; A sends "hello", B's conversation shows it, A's message is delivered; the
/// safety numbers are equal.
#[test]
fn two_profiles_exchange_invitation_and_messages_through_view_models() -> Test {
    let root = scratch("p1");
    std::fs::create_dir_all(&root)?;
    let relay = E2eRelay::start(&root.join("relay"));
    let profiles = root.join("profiles");
    let mut a = Side::open(&profiles, "alice", &relay)?;
    let mut b = Side::open(&profiles, "bob", &relay)?;

    // A issues an invitation
    a.vm.open_invitations();
    a.vm.create_invitation(&a.bridge);
    a.until(LONG, Vm::invitation_held)?;
    let uri = a.vm.invite_text();
    assert!(uri.starts_with("secmp://i/"));

    // B accepts it; the link data may reach the relay a moment after the invitation was shown, so a refusal is tried again
    b.vm.open_invitations();
    let mut added = false;
    for _ in 0..20 {
        b.vm.accept_invitation(&b.bridge, &uri);
        b.until(LONG, |vm| !vm.busy())?;
        b.until(ROW, |vm| {
            !vm.contacts().is_empty() || !vm.error_text().is_empty()
        })?;
        if !b.vm.contacts().is_empty() {
            added = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    assert!(added, "B has no contact");

    // both see the contact
    a.until(ROW, |vm| !vm.contacts().is_empty())?;
    assert_eq!(a.vm.rows().len(), 1);
    assert_eq!(b.vm.rows().len(), 1);
    // the safety numbers are equal; both mark the contact verified (receipts are sent for verified contacts only, spec §10.4)
    for side in [&mut a, &mut b] {
        side.vm.leave();
        side.vm.open_contact(0);
        side.vm.open_safety(&side.bridge);
        side.until(LONG, Vm::safety_can_verify)?;
    }
    assert!(!a.vm.safety_text().is_empty());
    assert_eq!(a.vm.safety_text(), b.vm.safety_text());
    for side in [&mut a, &mut b] {
        side.vm.verify(&side.bridge);
        side.until(LONG, |vm| !vm.busy() && !vm.safety_can_verify())?;
        side.vm.leave();
    }

    // A sends "hello"; B's conversation shows it
    assert!(a.vm.send(&a.bridge, "hello"));
    a.until(LONG, |vm| !vm.busy() && !vm.conv_rows().is_empty())?;
    b.until(ROW, |vm| {
        vm.conv_rows().first().is_some_and(|r| r.text == "hello")
    })?;
    assert!(b.vm.conv_rows().first().is_some_and(|r| r.incoming));

    // A's message reaches the delivered state
    let delivered = locale::text(Lang::En, key::MSG_STATE_DELIVERED);
    a.until(ROW, |vm| {
        vm.conv_rows()
            .first()
            .is_some_and(|r| r.meta.ends_with(delivered))
    })?;

    a.bridge.shutdown();
    b.bridge.shutdown();
    remove(&root);
    Ok(())
}
