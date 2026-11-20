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
