// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-ui` — the desktop user interface (Slint, winit backend; ADR-013, ADR-063).
//!
//! **Responsibility.** Screens and screen-security behaviours (exclude-from-capture, blur on focus loss,
//! view-once reveal, watermark, clipboard policy, accessibility mode) together with `secmp-sys-desktop`
//! (docs/02 §4.5, docs/04). The UI never touches key material and never receives the store handle; it only
//! receives decrypted view models from the core `Api`.
//!
//! **Structure.** [`bridge`] owns the thread that talks to the core and never blocks the UI thread; [`vm`] holds the view models
//! (plain data and the state machine of the screens); [`screens`] is the Slint window; [`locale`] holds every user-visible
//! string; [`core_backend`] is the bridge's backend over the client core; [`app`] binds all of it; [`capture`] and [`probe`] are
//! the capture-exclusion hook and the spike's probe; [`qr`] makes the QR codes (ADR-064).
//!
//! **Allowed dependencies** (docs/02 §3): `secmp-client-core`, `secmp-sys-desktop`; `slint` (the single copyleft
//! licence exception, docs/06 §3), ADR-063.
//!
//! **Unsafe code.** None. The crate declares `#![deny(unsafe_code)]` instead of `forbid`, because `slint!` expansions carry a
//! generated `allow(unsafe_code)` (E0453 under `forbid`; docs/06 §2 (b), ADR-033). `cargo xtask policy` rejects the keyword
//! and any hand-written relaxation of `unsafe_code` in this crate's sources.
//!
//! **Status.** M8 part 1: window, onboarding, unlock, contacts.
#![deny(unsafe_code)]

pub mod app;
pub mod bridge;
pub mod capture;
pub mod convo;
pub mod core_backend;
pub mod locale;
pub mod probe;
pub mod qr;
mod screens;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_conv;
#[cfg(test)]
mod tests_p3;
pub mod vm;
