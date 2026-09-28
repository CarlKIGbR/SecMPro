// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-sys-desktop` — desktop-only operating-system integration.
//!
//! **Responsibility.** `WDA_EXCLUDEFROMCAPTURE`/`DISPLAY_ONLY`, process DACL and mitigation policies, WER
//! exclusion, Recall input scope, Wayland/compositor probes and exclusion requests, OS keystores (DPAPI/CNG/TPM,
//! Secret Service/TPM2) and clipboard formats (docs/02 §3, docs/04 §1).
//!
//! **Unsafe code.** One of the only two crates that may contain `unsafe` (the other is `secmp-sys-mem`);
//! therefore it does not declare `#![forbid(unsafe_code)]`. The workspace lint `unsafe_code = "deny"` still
//! applies. Every `unsafe` block will carry a `// SAFETY:` comment and a test and run under Miri where feasible
//! (docs/06 §4).
//!
//! **Allowed dependencies** (docs/02 §3): no workspace crate; platform binding crates added with an ADR. Used only
//! by `secmp-ui`, `secmp-store` and `secmp-client-core` — never by `secmp-relay`.
//!
//! **Status.** M0 skeleton — no code (implementation starts in M9).
