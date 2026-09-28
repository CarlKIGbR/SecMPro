// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-store` — the encrypted local profile store.
//!
//! **Responsibility.** One encrypted database per profile (rusqlite + SQLCipher, or the ADR-027 fallback),
//! master-key wrapping (docs/04 §3), migrations, outbox tables, incremental ratchet persistence
//! (persist-before-send, persist-before-ack), secure delete, and backup export/import without ratchet state
//! (CS-3.5). Schema per docs/02 §4.2.
//!
//! **Allowed dependencies** (docs/02 §3): `secmp-proto`, `secmp-crypto`, `secmp-sys-desktop` (OS keystores);
//! `rusqlite` with bundled SQLCipher/OpenSSL (exempt from the "only `secmp-crypto`" rule, never used for SecMP
//! constructions), added with an ADR.
//!
//! **Status.** M0 skeleton — no code (implementation starts in M7).
#![forbid(unsafe_code)]
