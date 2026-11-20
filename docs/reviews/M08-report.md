# Milestone report — M8 Desktop UI (Slint), part 1

Branch: `m08-desktop-ui` · Base: `d3799116ebc54f325667b0c172e5e2ea09e70356` · Author: Claude Code (Sonnet 5.5) · Date: 2026-11-20 · Regime: ADR-062 (build phase)

## 1. Plan (written before implementation, updated during)

| Step | What | Proves | Status |
|---|---|---|---|
| U0 | CI: jobs `miri` and `coverage` out of `linux-full` (+ dispatch twins, `ci-verdict` needs, xtask pins, `harness` required) | `cargo xtask policy` / xtask tests | open |
| U1.1–3 | Slint pins (femtovg + software, no Skia), `windows-sys` for WDA, vet/deny/advisory handling, ADR-063 | `cargo xtask ci-fast` deny/vet/audit/cooldown | open |
| U1.4 | `slint!` main window, `--probe`, `set_exclude_from_capture`/`display_affinity` (`cfg(windows)`), fail-closed before first show | T1, T5; xwin cross-build | open |
| U1.5–6 | `docs/reviews/M8-spike.md`, mechanical go/no-go gate | T1–T4, ci-fast, xwin step | open |
| U2 | `bridge`/`vm`/`screens`/`locale`; onboarding, unlock, contacts; HB line for Slint passphrase copies | T2, T3, T6–T9 | open |
| Tests | exactly T1–T9 of the brief | — | open |

Status 2026-11-20: U0 done (commit `29124e3`; `cargo nextest run -p xtask`: 330/330, `cargo xtask policy` PASS). U1 code written, **not committed**, build blocked (§8).

Not in this brief: invitations, conversation, safety number, settings, Tor status, indicators, retention, screen-security beyond the two probes (M9).

## 8. Blocked / questions

**U1 build blocked (STOP: a system library the host lacks for building).** `cargo build -p secmp-ui` fails in the build script of `yeslogic-fontconfig-sys v6.0.1` (a transitive crate of `slint` 1.18.1, text stack): `pkg-config --libs --cflags fontconfig` finds no `fontconfig.pc` (package `libfontconfig-dev`). Slint/crate versions are not the cause; the host lacks the development files. Options for the planner/owner: (a) install `libfontconfig-dev` on the host and on the CI runner images that build `secmp-ui` (`ubuntu-latest` has to be checked); (b) build with `RUST_FONTCONFIG_DLOPEN=1` (the crate's own switch: no link-time need, library loaded at run time) — an environment setting in xtask/CI, needs the reviewer's acceptance as an engineering ADR item. Not done: neither was applied, the brief says STOP. Further system libraries may surface after this one (the build stopped at the first failure).

The U1/U2 sources are in the working tree of branch `m08-desktop-ui`, uncommitted, uncompiled against Slint. Also open: after U2, `secmp-ui` depends on `secmp-client-core` (store, vendored OpenSSL), which `cargo xwin` cannot build (ADR-034 Amendment 1, `XWIN_EXCLUDE` lists `secmp-ui`); the brief's U1 gate line "the xwin step builds `secmp-ui`" is only reachable before that dependency is added. Also: HWND access needs Slint feature `unstable-winit-030` (not in the brief's list); `raw-window-handle-06` would need a direct `raw-window-handle` dependency, which T4 forbids.
