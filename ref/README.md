# ref/ — independent reference implementation (vectors only)

This directory will hold an **independent Python implementation** of HybridKEM, HybridSign, MsgEncrypt, CAEAD,
SAS, the encodings, HX, TR and LINK. Its only purpose is to cross-generate the SecMP test vectors: `cargo xtask
vectors` runs it and the Rust implementation over the same inputs and freezes `vectors/` only when both agree structurally per `vectors/SCHEMA.md` §1
(the `generator` field excluded; the frozen file is a verbatim copy of the reference file) (ADR-026, docs/06 §5 step 12a).

**Rule (ADR-026).** The code here is written **from the specification alone** — `docs/03-protocol-spec.md`
including its appendices — in a **separate agent session that has no access to the Rust code** (`crates/`,
`xtask/`, `fuzz/`) or to vectors produced by it. The owner starts that session before M1 and the reviewer
supplies its brief (OQ-17). The implementer of the Rust code never writes or edits anything in `ref/`.

It is test tooling only: never shipped, never imported by a Rust crate. Every source file starts with
`# SPDX-License-Identifier: AGPL-3.0-or-later`.

Status: the M1 constructions and the M2 encodings are implemented (`secmp_ref/`, generator `gen_vectors.py`, tests in `tests/` with the official KATs extracted by `tools/fetch_kats.py`, pinned dependencies in `requirements.txt`, the spec questions and answers in `SPEC-QUESTIONS.md`). The tree is copied into the repository by the reviewer from the reference session's workspace, unchanged, at each milestone (committed with M2 after external review finding EXT-1, `docs/reviews/M01-review-ext-glm.md`); the outputs are `vectors/ref/<suite>.json`. Run it with `python3 -m venv ref/.venv && ref/.venv/bin/pip install -r ref/requirements.txt && ref/.venv/bin/pytest ref/tests`. CI never runs it (ADR-026).
