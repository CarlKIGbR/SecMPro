// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-sys-mem` — portable operating-system memory and sandbox primitives.
//!
//! **Responsibility.** `SecretPage` (`memfd_secret` / `mlock` / `VirtualLock`), dumpable and core-dump control,
//! Landlock, seccomp and mlockall for the client and the relay (docs/02 §3, docs/04 §2, docs/05 §4).
//!
//! **Unsafe code.** One of the only two crates that may contain `unsafe` (the other is `secmp-sys-desktop`);
//! therefore it does not declare `#![forbid(unsafe_code)]`. The workspace lint `unsafe_code = "deny"` still
//! applies. Every `unsafe` block will carry a `// SAFETY:` comment and a test and run under Miri (docs/06 §4).
//!
//! **Allowed dependencies** (docs/02 §3): no workspace crate; operating-system binding crates added with an ADR.
//! Used by `secmp-crypto`, `secmp-relay` and the client.
//!
//! **Status.** M0 skeleton — no code (first use in M1).
