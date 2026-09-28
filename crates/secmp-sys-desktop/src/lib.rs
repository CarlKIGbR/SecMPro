// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-sys-desktop` — desktop-only operating-system integration.
//!
//! **Responsibility.** `WDA_EXCLUDEFROMCAPTURE`/`DISPLAY_ONLY`, process DACL and mitigation policies, WER
//! exclusion, Recall input scope, Wayland/compositor probes and exclusion requests, OS keystores (DPAPI/CNG/TPM,
//! Secret Service/TPM2) and clipboard formats (docs/02 §3, docs/04 §1).
//!
//! **Unsafe code.** One of the only two crates that may contain `unsafe` (the other is `secmp-sys-mem`); it
//! carries `#![allow(unsafe_code)]` at the crate root instead of `#![forbid(unsafe_code)]` (docs/06 §2 (a),
//! checked by `cargo xtask policy`). Every `unsafe` block must have a `// SAFETY:` comment
//! (`clippy::undocumented_unsafe_blocks`), do one thing (`clippy::multiple_unsafe_ops_per_block`), and be
//! covered by a unit test and, where feasible, Miri (docs/06 §4).
//!
//! **Allowed dependencies** (docs/02 §3): no workspace crate; platform binding crates added with an ADR. Used only
//! by `secmp-ui`, `secmp-store` and `secmp-client-core` — never by `secmp-relay`.
//!
//! **Status.** M0 skeleton — no code (implementation starts in M9).
#![allow(unsafe_code)]
