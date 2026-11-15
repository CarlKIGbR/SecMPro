// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-sys-mem` — portable operating-system memory and sandbox primitives.
//!
//! **Responsibility.** `SecretPage` (`memfd_secret` / `mlock` / `VirtualLock`), dumpable and core-dump control,
//! Landlock, seccomp and mlockall for the client and the relay (docs/02 §3, docs/04 §2, docs/05 §4). M1 provides
//! [`SecretPage`] (CS-2.2); the process-hardening primitives follow with M9/M10.
//!
//! **Unsafe code.** One of the only two crates that may contain `unsafe` (the other is `secmp-sys-desktop`);
//! it carries `#![allow(unsafe_code)]` at the crate root instead of `#![forbid(unsafe_code)]` (docs/06 §2 (a),
//! checked by `cargo xtask policy`). Every `unsafe` block must have a `// SAFETY:` comment
//! (`clippy::undocumented_unsafe_blocks`), do one thing (`clippy::multiple_unsafe_ops_per_block`), and be
//! covered by a unit test and Miri (docs/06 §4). Under Miri, which cannot execute the operating-system calls,
//! [`SecretPage`] uses a heap backend so that the safe wrapper (pointer handling, zeroisation) is still checked;
//! the operating-system paths run natively on Linux, Windows and macOS. Under Kani, which cannot execute them
//! either, the same heap backend is the verification backend (Kani), like the Miri one: it lets the `secmp-proto`
//! harnesses run the real prekey store (M4 K4). Both are selected only by `cfg(miri)`/`cfg(kani)`, which no test or
//! production build sets (`heap_backend_only_under_miri_or_kani`).
//!
//! **Allowed dependencies** (docs/02 §3): no workspace crate; operating-system binding crates added with an ADR
//! (`libc` on Unix, `windows-sys` on Windows; ADR-037) and `zeroize`. Used by `secmp-crypto`, `secmp-relay` and
//! the client.
#![allow(unsafe_code)]

mod secret_page;

pub use secret_page::{Backend, Error, SecretPage};
