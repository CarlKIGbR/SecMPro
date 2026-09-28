// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-transport` — moving opaque cells between a client and a relay.
//!
//! **Responsibility.** The `QueueTransport` trait; the SecMP-LINK client over an abstract byte stream; the
//! relay-queue transport; the Tor (`arti-client`) and direct TLS stream providers. It only ever sees opaque,
//! already end-to-end-encrypted cells and capabilities — never identifiers or plaintext (docs/02 §6).
//!
//! **Allowed dependencies** (docs/02 §3, §7): `secmp-proto`, `secmp-crypto`; `arti-client` (features
//! `onion-service-client` + `rustls`, never `hs-pow-full` — ADR-024); `rustls` with `aws-lc-rs` for TLS only
//! (exempt from the "only `secmp-crypto`" rule and never used for SecMP constructions); an async runtime, each
//! added with an ADR.
//!
//! **Status.** M0 skeleton — no code (implementation starts in M5/M6).
#![forbid(unsafe_code)]
