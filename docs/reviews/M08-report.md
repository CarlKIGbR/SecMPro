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

Not in this brief: invitations, conversation, safety number, settings, Tor status, indicators, retention, screen-security beyond the two probes (M9).
