# ref/ — independent reference implementation (vectors only)

This directory will hold an **independent Python implementation** of HybridKEM, HybridSign, MsgEncrypt, CAEAD,
SAS, the encodings, HX, TR and LINK. Its only purpose is to cross-generate the SecMP test vectors: `cargo xtask
vectors` runs it and the Rust implementation over the same inputs and freezes `vectors/` only when both agree
byte-for-byte (ADR-026, docs/06 §5 step 12a).

**Rule (ADR-026).** The code here is written **from the specification alone** — `docs/03-protocol-spec.md`
including its appendices — in a **separate agent session that has no access to the Rust code** (`crates/`,
`xtask/`, `fuzz/`) or to vectors produced by it. The owner starts that session before M1 and the reviewer
supplies its brief (OQ-17). The implementer of the Rust code never writes or edits anything in `ref/`.

It is test tooling only: never shipped, never imported by a Rust crate. Every source file starts with
`# SPDX-License-Identifier: AGPL-3.0-or-later`.

Status: empty in M0 (this README only).
