// SPDX-License-Identifier: AGPL-3.0-or-later
//! `secmp-crypto` — typed cryptographic primitives and the SecMP/1 constructions.
//!
//! **Responsibility.** The only crate that uses cryptographic crates for SecMP constructions (CLAUDE.md §1.6,
//! docs/06 §2–3): typed keys, nonces and counters; `HybridKEM` (spec §3.2), `MsgEncrypt` (§3.3), `CAEAD` (§3.4),
//! `HybridSign` (§3.5), HKDF helpers with the labels of spec Appendix A, the safety number (§6.7) and
//! fingerprints. No primitive is implemented here; constructions only compose allowlisted crates exactly as the
//! spec defines them.
//!
//! **Allowed dependencies** (docs/02 §3, docs/06 §3): `secmp-sys-mem`; the allowlisted crypto crates of docs/06 §3
//! (`libcrux-ml-kem`, `ml-kem` for differential tests, `ml-dsa`, `aws-lc-rs` for differential tests,
//! `x25519-dalek`, `ed25519-dalek`, `curve25519-dalek`, `chacha20`, `chacha20poly1305`, `hmac`, `hkdf`, `sha2`,
//! `sha3`, `argon2`, `subtle`, `zeroize`, `getrandom`, `rand_core`), each pinned exactly and added with an ADR
//! and a cargo-vet record. Sans-IO: no tokio, no I/O crate. Its dependency closure must have zero cargo-vet
//! exemptions.
//!
//! **Status.** M0 skeleton — no code (implementation starts in M1).
#![forbid(unsafe_code)]
