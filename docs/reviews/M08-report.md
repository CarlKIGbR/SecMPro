# Milestone report — M8 Desktop UI (Slint), part 1

Branch: `m08-desktop-ui` · Base: `d3799116ebc54f325667b0c172e5e2ea09e70356` · Author: Claude Code (Sonnet 5.5) · Date: 2026-11-20 · Regime: ADR-062 (build phase)

## 1. Plan

| Step | What | Status |
|---|---|---|
| U0 | `miri` and `coverage` jobs out of `linux-full`; `harness` required | done (`29124e3`) |
| U1 | Slint pins, supply chain, ADR-063, WDA bindings, probe, `M8-spike.md` | done (`0ceb1ab`, `815933d`); xwin step could not run here (below) |
| U2 | bridge / vm / screens / locale; onboarding, unlock, contacts | done (`815933d`) |

Not in this brief: invitations, conversation, safety number, settings, Tor status, indicators, retention, screen security beyond the two probes (M9).

## 3. Evidence

| Item | Command | Result |
|---|---|---|
| U0 | `cargo nextest run -p xtask`; `cargo xtask policy` | 332/332; PASS |
| T1, T6, T7, T8', T9, T10, T11, T12 | `cargo nextest run -p secmp-ui` | 12 passed (incl. T3, `row_of…`, `event_of…`, the M0 `hello` test with `--version`) |
| T2 | `policy::tests::window_title_is_constant_product_name` | pass |
| T3 | `locale::tests::locale_tables_en_de_have_identical_key_sets` | pass |
| T4 | `policy::tests::ui_crate_dependencies_are_allowlisted` | pass |
| T5 | `secmp-sys-desktop` `capture_exclusion_rejects_null_window`, `cfg(windows)` | not run on this host; compiled and linted: `cargo clippy -p secmp-sys-desktop --target x86_64-pc-windows-msvc --all-targets --locked -- -D warnings` PASS; runs in `windows-native` |
| ci-fast | `cargo xtask ci-fast --delegated harness` (after WEISUNG M8-3) | PASS (fmt, clippy, policy, deny, vet 586 exemptions, audit, cooldown, nextest, doctest, hello, kat, fuzz-check) |
| xwin | `cargo xtask step windows-cross` | FAIL, environment: `cargo xwin` gets proxy 403 for `https://aka.ms/vs/17/release/channel` (MSVC CRT). Not run: `windows-native` after the push |
| `--probe` | `cargo run -p secmp-ui -- --probe` | no display (`WAYLAND_DISPLAY`/`DISPLAY` unset), no Xvfb/weston installed: P1 FAIL, P2–P4, P5a, P5b NOT-RUN, P6 FAIL (session unknown) |

## 5. Deviations from the brief / WEISUNG

- fontconfig: `RUST_FONTCONFIG_DLOPEN=1` alone does not compile (`fontique` needs its feature `fontconfig-dlopen`). `secmp-ui` depends on `i-slint-common` (same exact pin as `slint`) with that feature (WEISUNG M8-3 C6); the xtask environment variable and its test are removed, a bare `cargo build -p secmp-ui` and `ci-fast` work without it. ADR-063 (4), docs/06 §1.
- `cargo update -p … --precise` pinned `zcheapstr 1.2.0`, `vtable(-macro) 0.5.0`, `nix 0.31.3` (cooldown).
- Licences: only `BSL-1.0` added to the allowlist; the Slint family takes per-crate `GPL-3.0-only` exceptions (10 crates).
- `mod screens` is private (Slint macro output trips `missing_docs`; no allow).
- WEISUNG M8-3 A: a failed capture check no longer hides the window and exits non-zero (BRIEF_M8 U1.4); the display stays locked, no content shown.
- T2: the testing backend cannot read a window title: `window_title_is_constant_product_name` is an xtask policy test over the `.slint` source. T8: no `secmp-client-core` utility makes a real contact without relay and handshake: `contacts_screen_lists_stub_contacts` plus `row_of_maps_every_contact_state`, `event_of_maps_contact_events`.
- C4: `secmp-crypto` has no slice constant-time equality: `same_secret` stays (HB-74). C5: HB-75.
- The xwin step could not run here (proxy 403); `windows-native` after the push.

## 6. Dependencies

See ADR-063 (`docs/08-decisions.md`): slint, i-slint-backend-testing (dev), i-slint-common (feature only), windows-sys features; 289 unique crate names added to `Cargo.lock` (316 package entries), 281 vet exemptions added / 23 dropped, 22 `skip` entries, 6 advisory ignores (HB-66…HB-71).

## 7. Open risks

- Windows code of `secmp-ui` (`capture.rs`) compiles only in `windows-native`.
- The window is created inside `show()`; the exclusion call cannot be ordered strictly before the first frame; the `content_protected` window attribute is the layer that closes it. To be confirmed on the Windows VM (`--probe` P5a, P5b).
- HB-72, HB-73 (passphrase copies in Slint, `unstable-winit-030`).

## 8. Part 2 (BRIEF M8-P2) — U3, U4, U5

| Unit | Commit | Content |
|---|---|---|
| U3 | `49c61e5` | delta-review fixes 1–8 (HB-76, HB-77) |
| U4 | `6ab8960` | invitation create/accept, QR (`qrcode =0.14.1`, ADR-064, one vet exemption, no new licence) |
| U5 | this commit | conversation, view-once, safety number, key-change warnings |

Evidence (`cargo nextest run -p secmp-ui`; `cargo xtask ci-fast --delegated harness`: PASS after U3, U4, U5):

| Test | Name | Result |
|---|---|---|
| P1 | `tests_conv::two_profiles_exchange_invitation_and_messages_through_view_models` (relay process of `E2eRelay`, direct TLS, no Tor; both sides verify before the send, because receipts go to verified contacts only, §10.4) | pass (137 s) |
| P2 | `tests::invite_accept_rejected_uris_show_one_message` | pass |
| P3 | `tests::invitation_uri_is_hidden_while_locked_and_cleared_on_leave` | pass |
| P4 | `qr::tests::qr_matrix_roundtrips_known_string` | pass |
| P5 | `tests_conv::view_once_reveal_is_refused_unless_verified` | pass |
| P6 | `tests_conv::key_changed_freezes_conversation_until_verified` | pass |
| P7 | `tests_conv::no_content_strings_while_locked_on_any_screen` | pass |
| P8 | `locale::tests::locale_tables_en_de_have_identical_key_sets` | pass |

Functions added to `secmp-client-core`: none. Core gaps: no list of the message history (`Request::Message` is by id), so the conversation shows this run's messages only and a view-once lost with an earlier run has no placeholder; no accessor for persisted warning state after a restart; times are shown in UTC (no time-zone source). The invitation URI and message text leave their zeroising buffers when shown (HB-78). Not run on this host: the screens under a real display; the 20 s reveal timer and the hold area (touch events) have no test under the testing backend.

## 9. Part 3 (BRIEF M8-P3) — U6, U7, U8

Head before: `6d6f372`. One commit holds all three units (their changes share files; see the deviation below).

| Unit | Content |
|---|---|
| U6 | cross-review fixes 1–12: banners and inputs withheld while locked; reveal clock (`Vm::tick`, `focus_lost`, release on protection loss and on leaving); warning epochs for `Verify`; safety number fetched again on `KeyChanged`; every submit through `Vm::submit` (full queue → `Failure::Busy`); `Chat.early` capped at 256; QR images built once; "Accepting…" from the submit on; T11 on a real profile; P1 attempts asserted; P7 extended; ADR-064 status, ADR-063 panic policy |
| U7 | `Request::History` (core) / `Store::history` (read only), pages of 50, older pages on scroll or button; placeholders, never a payload, for view-once; banners from the contact record after a restart, freeze learned from a refused send (HB-79); times as `YYYY-MM-DD HH:MM UTC` (HB-80) |
| U8 | settings screen (mode with relay view and confirm, retention, delivery and read receipts, screen security), contact options (rotate, reset, remove) and profile actions (rotate identity, export) behind a confirm click, connection line, security indicator with `Request::SetDisplayState` / `DisplayState` (CS-1.18) |

Core boundary (no schema change, no migration, no write path, no new persistence): `secmp-client-core::api`: `Request::History{contact,before,limit}` → `Response::History(Vec<HistoryEntry>)`, `Request::SetDisplayState(DisplayState)`, `Request::DisplayState` → `Response::DisplayState`, types `HistoryEntry`, `DisplayState`, field `Core.display` (memory only); `runtime::admitted` classifies the three; `secmp-store::messages`: `Store::history`, `HistoryRow`, `HISTORY_MAX`. The `Message` and `History` arms of `Core::handle` are private helpers (`message`, `history`).

Evidence: `cargo nextest run -p secmp-ui` (all pass, P1 with the attempt count asserted to be 1), `cargo nextest run -p secmp-client-core --features kat history_never_returns_view_once_payload` (S6), `cargo xtask ci-fast --delegated harness`: PASS (after the last change).

| Test | Name | Result |
|---|---|---|
| S1 | `tests_p3::banners_and_inputs_are_withheld_while_locked` | pass |
| S2 | `tests_p3::reveal_timer_is_not_extended_by_second_press_and_focus_loss_releases` | pass |
| S3 | `tests_p3::verify_answer_does_not_clear_newer_key_change` | pass |
| S4 | `tests_p3::full_queue_sets_busy_on_safety_and_history_requests` | pass |
| S5 | `tests_conv::two_profiles_exchange_invitation_and_messages_through_view_models` (extended: A reopened, history lists "hello", still verified) | pass |
| S6 | `secmp-client-core` `api::tests::history_never_returns_view_once_payload` | pass |
| S7 | `tests_p3::settings_roundtrip_through_real_core` | pass |
| S8 | `tests_p3::mode_change_needs_confirmation_and_shows_relay_view` | pass |
| S9 | `tests_p3::contact_and_identity_actions_send_nothing_before_confirmation` | pass |
| S10 | `tests_p3::indicator_text_follows_display_state_and_core_reports_it` | pass |
| S11 | `tests_p3::status_line_shows_no_address_and_no_activity_counters` | pass |

Core gaps: HB-79 (frozen session after a restart), HB-80 (no time zone), HB-81 (accessibility mode: no `Settings` field), HB-82 (held view-once and delivery state of earlier messages are not in the history), HB-83 (focus-loss event, scroll trigger and list position not testable under the testing backend), HB-84 (export path, relay of a rotation).

Deviations: (1) one commit for U6–U8 instead of three, and `ci-fast` once at the end instead of after each unit: the units touch the same files (`vm.rs`, `convo.rs`, `app.rs`, `screens.rs`, tests). (2) The brief names `Request::Export`; the UI uses `Call::Export`, because the runtime refuses `Request::Export` on `Call::Core` (`admitted`). (3) S6 lives in `secmp-client-core` (the UI crate has no store dependency, ADR-063 allow-list); a held view-once is not in the `messages` table at all, so the placeholder of a view-once in the history is the model's own (from the event of this run), and a row of kind 3 that some tool wrote comes back without payload. (4) The relay-view stub of the UI tests returns the core's text for the non-direct transport, because direct mode lists the same lines for every mode.

## 10. Part 3 fixes (WEISUNG M8-P3-1, U9)

Settings show a new value only after the submit was accepted (refusal: stored value re-read, failure shown); `Store::history` decodes direction 0/1 only (else `Unavailable`); export passphrase typed twice, the confirm line names the path, the path field stays visible; `reported` is set on the core's answer; a pending action is dropped on `Locked` and on leaving the screen; a deferred rotation shows the banner only (`Response::ActionDeferred`); the rotation relay stays the constant 1 (no accessor, HB-88); ADR-063 and HB-73 name the focus-loss use; HB-85 to HB-88 added. Tests: S6 extended (expired row, second contact, `HISTORY_MAX`, `limit` 0 and negative `before`), X1 (`secmp-store`, feature `kat`), X2, X3, X4 (`secmp-ui`).
