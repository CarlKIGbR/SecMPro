# Milestone report — M03 SecMP-TR hybrid ratchet (sans-IO) + ProVerif model

Branch: `m03-tr` · Base: `main` at `e4a3d55bb1f67db83ed4d6346e40d6404ba7dffd` (M2 squash merge) · Author: Claude Code (Opus 5.5) · Date: 2026-09-30

Status: **in progress** (plan written before any M3 code; §2–§9 are filled in as the steps land).

Inputs: `docs/07` M3; spec `docs/03` rev 2.3 §7 (7.1–7.8, the pseudocode is normative), §3.3–3.4, App. A/B/D.5;
`docs/06` §4 (gates incl. Formal), §8, §9; `docs/08` ADR-004, ADR-026, ADR-038, ADR-041 with Amendment 1;
`docs/reviews/M02-review.md` §C/§E/§H/§I (follow-ups F1–F10, F13, F15–F18), `docs/reviews/M02-review-ext-glm.md`
(F19–F21); `formal/README.md`; `vectors/SCHEMA.md` rev 4 with `vectors/SCHEMA-4.9-tr.md`;
`docs/reviews/ref-spec-questions-M3.md` (SQ-22 … SQ-24 and the reference's twelve readings, all accepted by the
reviewer); the reviewer's M3 brief with the `formal/CLAIMS.md` §TR query set. `ref/`, `vectors/ref/`,
`vectors/SCHEMA*.md`, `docs/reviews/ref-spec-questions-M3.md` (except the implementer's SQ rows, if any, which the
brief assigns to that file) and the sibling `SecMProRef/` are not edited by this session; the reference's Python
TR code is not read while the Rust TR code is written (ADR-026: it is consulted only to localise a vector
disagreement, and any such consultation is recorded in §8).

## 1. Plan (written before implementation, updated during)

Scope: `docs/07` M3 — `secmp-proto::tr` (state, init, encrypt, decrypt, DH ratchet with the KEM in both halves,
skipped keys, dummies, content handling, persistence API), the `tr` vector suite, property tests, Kani, fuzz,
mutants, coverage, the ct gate, `formal/tr.pv`, the performance criterion; plus the M2 follow-ups the brief carries.
Not in scope: HX, invitations, `K_id` (M4); relay, queues, LINK (M5); scheduler (M6); application-layer message
semantics (M7). `secmp-proto` stays sans-IO; every cryptographic operation goes through `secmp-crypto` types.

### 1.1 Steps

| Step | What | Proves acceptance criterion / brief item | Status |
|---|---|---|---|
| 0a | Reference file verified: `vectors/ref/tr.json` SHA-256 `01a6d161…201a837`, `"schema": 4`, `"spec": "SecMP/1 rev 2.3"`, 96 cases (1 init, 40 send, 40 recv, 2 advance, 13 recv-reject) | precondition | done (before any change) |
| 0b | Commit 1: the inherited reference files unchanged (`ref/` TR files, `vectors/ref/tr.json`, `vectors/SCHEMA.md` rev 4, `vectors/SCHEMA-4.9-tr.md`, `docs/reviews/ref-spec-questions-M3.md`); `formal/CLAIMS.md` §TR verbatim; this plan; `expect::VECTOR_REF_PENDING` = [`tr`] (the reference file is committed before its freeze, as in M2 step 0j); **F19** — the policy check refuses a job-level `if:` on the four required jobs other than the one pinned in `expect::REQUIRED_JOB_CONDITIONS`, with a test (`required_jobs_keep_their_pinned_conditions`) | brief commit 1 | done (commit 1) |
| 0c | **F1** `PartialEq`/`Eq` only under `cfg_attr(test, …)` on the types carrying MACs, commitments, tokens or tags (`Hs1`, `Hs2`, `RequestCmd`, `LinkBlob`, `InnerCt`, `HandshakeCell`, `Cell`) and on the types that contain them (`Request`, `Cellr`, `ResponseCmd`, `Response`, `Outer`); the integration tests compare encodings for them (`check_bytes`) | M2 review F1 | open |
| 0d | **F9** `const` assertion LinkDataV1 maximum fields 9899 ≤ 12288 (`sizes.rs`); **F20** `wire/signed.rs` returns `Zeroizing<Vec<u8>>` | F9, F20 | open |
| 0e | **F3** `secmp-proto` in `MIRI_PACKAGES` (heavy TR tests in `MIRI_SKIP` with the measured reason); **F5** `${{ github.run_attempt }}` in the `linux-full` ct artefact name | F3, F5 | open |
| 0f | **F2 + F10** scheduled, non-required `fuzz-nightly.yml` (4 h, scratch corpus, per-target budget = 4 h / number of targets, the `fuzz/README.md` claim made true) with an env-seeded property run (`SECMP_PROPTEST_SEED` from the run, printed); **F7** the fuzz gate fuzzes a scratch corpus under `target/` seeded from `fuzz/corpus/<t>` (read-only) plus a seeding step from the frozen vectors, so the tracked corpus is never written by a gate; **F18** a unit test for the `-max_len` argument of the fuzz command | F2, F7, F10, F18 | open |
| 0g | **F8** CI step 12a byte-compares `vectors/<suite>.json` with `vectors/ref/<suite>.json` | F8 | open |
| 0h | **F13** the fine-timer recomputation as a committed script under `docs/reviews/M02-evidence/ct-adr041-amendment1/` (input: the recorded per-crop statistics of PR run 36651079069; output: the table of `README.md` l. 97–130), with its output checked against the README | F13 | open |
| 0i | **F15–F17** ct gate: the positive control's detection checked for any verdict label; refusal tests for the checks that can currently be removed unnoticed (mixed-crop `!fail_sure`, target floor × 1.4, t-rounding margin, control name, duplicate target); an upper bound on a target's `q_eff_ticks` | F15, F16, F17 | open |
| 1 | `secmp-crypto` additions (all spec-defined, no new construction): `Aead` — plain XChaCha20-Poly1305 for ratchet headers (§7.3, §7.5; §8.4 frames in M5) with `seal`, `open` and a constant-time `open_ct` returning a `Choice`; `tr_init`, `kdf_rk`, `kdf_ck` (§7.2); `X25519Secret::expose_secret` and `MlKem{768,1024}Dk::expose_seed` for the persistence encoding; re-export of `subtle::{Choice, ConditionallySelectable, ConstantTimeEq}` so that `secmp-proto` keeps no direct crypto dependency. Tests: draft-irtf-cfrg-xchacha A.3.1 vector, RFC 4231 HMAC vectors through `kdf_ck`, the frozen `hkdf-labels` rows 5/6 through `tr_init`/`kdf_rk`, every failure path | foundation; review focus L3 | open |
| 2 | **F4** (design D1 below): `secmp_proto::Error::Unavailable`, distinct from `Rejected`, never produced by a wire decoder | F4 | open |
| 3 | `tr::RatchetState` (§7.1 exactly) and its versioned persistence encoding `RatchetStateV1` (D5), zeroizing; `from_bytes` total, canonical and restricted to reachable shapes | deliverable "serialisable, zeroizing"; property "state round-trips at every step" | open |
| 4 | `init_initiator`/`init_responder` (§7.2), `encrypt` (§7.3, persist-before-send by construction, D4), `decrypt` (§7.4, transactional, D2/D3), `DHRatchet` with the KEM in both halves, `skip_message_keys` (`SKIP_WINDOW` 256, `MAX_FF` 2^20, earliest-inserted eviction, total ≤ 512), skipped-key lookup over every distinct `hk`, the `dh_pk == dh_r` rejection, KEM constancy on non-step messages, u32 counters with `checked_add` | review focus: header-key rotation, KEM constancy, fast-forward bounds, transactional decrypt | open |
| 5 | `tr::content` (D6, D7): dummy generation, Batch, Fragment reassembly (≤ 64 fragments, same `msg_id`), `KeyChange` verified with the old `IK_sig` (§7.7: contact unverified, outgoing real messages blocked; unverifiable → session frozen), `RouteUpdate`; **F21** decrypted Content, `AppMessage.payload`, `Control.arg` and reassembly buffers are `Zeroizing` | deliverable "dummy generation, fragment/batch/KeyChange/RouteUpdate content handling"; F21 | open |
| 6 | `tr` suite: `tests/tr_vectors.rs` replays the 96 events with both states, checking every `state_pre`/`state_post` (`StateDigestV1` implemented in the test crate from the documented persistence layout), every `cell`, every `content`, every rejection with an unchanged state; Rust generator (`examples/gen-tr.rs`, no vector file read) and `cargo xtask vectors` freeze `vectors/tr.json` byte-identical to `vectors/ref/tr.json`; `VECTOR_SUITES` += `tr` | "Vectors … pass"; frozen vectors (40 messages, two round trips, out-of-order, dropped first message of a chain, 10 000 gap; negatives) | open |
| 7 | Negative unit tests, one per rejection path of §7.4 (cell length, no header key incl. absent keys, header decode, step with `dh_pk == dh_r`, KEM constancy `ek_pq` and `ct_pq`, replay below `n_r` on a chain and on a skipped key, gap > `MAX_FF` on `pn` and on `n`, `n_r` at `u32::MAX`, body MAC on the chain / skipped / step paths, wrong `sb`), each asserting the uniform error and the byte-identical state; encrypt refusals (no sending chain, `n_s` at `u32::MAX`) | "negative tests for every rejection path of §7.4" | open |
| 8 | Property tests (`rand`, fixed seed, `SECMP_PROPTEST_SEED` override): random interleavings with drops, duplicates, reorders and gaps up to and beyond `MAX_FF`; every message key tracked (never reused), never a panic, state round-trips through `to_bytes`/`from_bytes` after every event, every rejection leaves the state byte-identical | property criterion | open |
| 9 | Kani: `tr_header_selection` (the constant-time selection equals the §7.4 sequential pseudocode for every combination of opened keys and lookups, up to 4 distinct skipped header keys), `tr_skip_plan` (per-call bounds: rejection below `n_r` and above `MAX_FF`, at most `SKIP_WINDOW` stored, the stored positions are exactly the last `min(gap, 256)`, no overflow), `tr_eviction` (total ≤ 512, earliest first); `KANI_HARNESSES` extended | brief: Kani for header-decrypt selection and skip bounds | open |
| 10 | Fuzz: `tr_decrypt` (selector: raw cell bytes of any length; a header plaintext sealed under the receiver's `hk_r` or `nhk_r` with an honest body — reaches decode, constancy, step and skip) and `tr_state` (`from_bytes` never panics; an accepted input re-encodes to itself); corpora seeded from the vectors; `FUZZ_TARGETS`/`FUZZ_MAX_LEN` extended | fuzz obligation (CLAUDE.md §2.4) | open |
| 11 | ct gate (D8, D9): targets `tr_decrypt_reject_hdr_key`, `tr_decrypt_reject_body_tag`, `tr_decrypt_reject_ct_pq` and the inline A/A′ control `aa_prime_control` (F6) in `expect::CT_TARGETS`; the bench moves to `secmp-testkit` so it can call `secmp-proto` (ADR-042, engineering) | brief ct item; F6 | open |
| 12 | `formal/tr.pv` with exactly the queries of `CLAIMS.md` §TR and its abstractions; the ProVerif gate compares every `RESULT` with the expected verdict (`expect::PROVERIF_EXPECTED`: T1–T6, T8, T9, T11 true; T7, T10 false; T12 informative); `PROVERIF_MODELS` += `tr` | "ProVerif green on the fixed query set" | open |
| 13 | Performance (D11): `cargo xtask step perf` runs a release measurement of encrypt + decrypt (a chain message and a DH-step message), fails at ≥ 3 ms; recorded locally and from the CI Linux runner in `M03-evidence/` | "encrypt+decrypt of a message < 3 ms" | open |
| 14 | Mutants (`secmp-crypto`, `secmp-proto`: zero survivors or documented), coverage ≥ 90 %, Miri, Kani, fuzz, ProVerif, ct; local `ci-full` chunks and the PR run; gate logs under `docs/reviews/M03-evidence/`; CHANGELOG; report; PR | `docs/06` §8 DoD | open |

### 1.2 Design decisions (brief: F4, F6, persistence and incremental API are decided here)

**D1 — errors (F4).** `secmp_proto::Error` gains `Unavailable`: the local environment could not provide OS
randomness or locked memory. It never depends on input and is never produced by a wire decoder (the M2 decoders
allocate no secret fallibly; a test runs every negative `encodings` row and asserts `Rejected`). Every
input-dependent TR failure is the one `Rejected`. `Unavailable` arises only (a) in `encrypt` before a cell exists
and (b) in `decrypt` after the body MAC verified, when the sending half of the DH step draws its new keys; in both
cases the state is unchanged, nothing is released, and the caller must neither send nor acknowledge — it retries
the slot. Rule recorded for later decoders: a wire decoder never allocates a secret fallibly; the persistence
decoder `RatchetState::from_bytes` (locked memory for `dh_s`, `kem_s`) may return `Unavailable`, never for a
malformed input.

**D2 — transactional decrypt without fallible allocation on the reject path.** `decrypt` computes everything that
decides acceptance on the borrowed state: header trial decryption, header decoding, the step/constancy checks, the
skipped-key derivations, the *receiving* half of `DHRatchet` (`Decaps` and X25519 with the current `kem_s`/`dh_s` —
heap only, no locked memory, no randomness), `KDF_CK` and `MsgDecrypt`. Only after the body MAC verified does it run
the *sending* half (X25519 and ML-KEM-768 key generation, `Encaps` to the new `kem_r`: locked memory and OS
randomness) and apply every change. The resulting state is identical to §7.4's order: the sending half reads only
`rk` (as left by the receiving half), `dh_r` and `kem_r` (from the header), none of which `skip_message_keys` or
`KDF_CK` on the new chain touches, and it writes only `dh_s`, `kem_s`, `ct_s`, `rk`, `ck_s`, `nhk_s`, none of which
those read. The vectors check this state digest by state digest; for N1 the reference runs `DHRatchet` on its
working copy before the MAC fails, the Rust side rejects before drawing — the state is unchanged in both, which is
what the case compares. A rejection therefore never allocates locked memory or draws randomness, and on every
rejection the state is byte-identical (tested per path and as a property).

**D3 — constant work in trial decryption (review focus L3).** The header is opened under *every* candidate key on
every call: each distinct header key of `skipped` (first-seen order), `hk_r`, `nhk_r`; an absent key is replaced by
a fixed dummy key and its result masked to "not opened". Each attempt yields a `Choice` (`Aead::open_ct`); the
header of the first successful key is selected with `ConditionallySelectable`; the `(hk, n)` lookup scans every
skipped entry with `ct_eq` on `hk` and `n`. The §7.4 case analysis (skipped hit / skipped key opened but no entry →
fall through to `hk_r`, `nhk_r` / chain / step / reject) is computed on `Choice`s and converted to a `bool` exactly
once, at the final branch. Comparisons of keys, `ek_pq`, `ct_pq`, `dh_pk` use `ct_eq`, never `==`. The
selection function is a pure function of the per-key results so that Kani can prove it equal to the sequential
pseudocode (step 9).

**D4 — persist-before-send / persist-before-ack in the API.** `encrypt` consumes the state and returns a `Sealed`
holding the new state and the cell; the only way to obtain the cell is `Sealed::persist(f)`, which hands `f` the
serialised new state and releases `(state, cell)` only if `f` returns `Ok` (on `Err` the cell is dropped and `f`'s
error returned — the durable state is the old one, and no cell of the new one left the process). `decrypt`
consumes the state and returns an `Opened` holding the new state and the padded plaintext; `Opened::plaintext()`
lets the caller process the content, and `Opened::commit(f)` hands `f` the serialised new state and returns
`(state, plaintext)` only if `f` returns `Ok`; the caller acknowledges the cell only after that (§7.5, §9.3). On a
failed commit the new in-memory state is dropped with it: the caller reloads the durable state, and the relay
delivers the unacknowledged cell again. A rejected `encrypt`/`decrypt` returns the unchanged state with the error
(`Refused { state, error }`).

**D5 — persistence: full serialisation, not a delta.** `RatchetState::to_bytes()` → `Zeroizing<Vec<u8>>` in the
versioned layout `RatchetStateV1` (documented byte by byte in `tr/state.rs` and §2): `fmt u8 = 0x01 ‖ sb[32] ‖
rk[32] ‖ dh_s.sk[32] ‖ opt(dh_r[32]) ‖ kem_s.seed[64] ‖ opt(kem_r[1184]) ‖ opt(last_ct_r[1088]) ‖ opt(ct_s[1088]) ‖
opt(ck_s) ‖ opt(ck_r) ‖ opt(hk_s) ‖ opt(hk_r) ‖ opt(nhk_s) ‖ opt(nhk_r) ‖ n_s u32 ‖ n_r u32 ‖ pn u32 ‖ count u16 ‖
{hk[32] ‖ n u32 ‖ mk[32]} × count` (insertion order), at most 38 585 bytes. Public halves are not stored; they are
recomputed on load. `from_bytes` checks the format byte, every presence byte, every length, `count ≤ 512`, the key
checks of the wire (`dh_r` not low order, `kem_r` modulus), and that the state has a reachable shape (§7.2/§7.4:
`nhk_s`/`nhk_r` present; the sending group `ck_s, hk_s, ct_s, kem_r, dh_r` all present or all absent; the receiving
group `ck_r, hk_r, last_ct_r` likewise; no receiving group without a sending group; without a receiving chain
`n_r = pn = 0` and `skipped` empty; without a sending chain `n_s = 0`; skipped entries grouped by header key in
insertion order with `n` strictly increasing within a group and no group repeated) — so a state has exactly one
encoding. Justification: one record replaced atomically per slot is the simplest thing the M7 store can make
durable (a delta would need multi-record atomicity to avoid torn states); the size is bounded and small against a
4352-byte frame per slot; the encoding is the same one the property tests round-trip after every event. The
`StateDigestV1` of the vectors is a test construct and is computed in the test crate, not here.

**D6 — Content decoding is outside the decrypt transaction** (reference reading 5, which the plan must state).
The transaction ends at the body MAC, as in the reference: a MAC-valid cell whose padded Content does not decode
still advances the state (its message key is consumed). The content layer reports it as `Delivery::Malformed`
(never delivered to the application), and the caller commits the state and acknowledges the cell as for any other
decided cell. Rolling back would leave the authentic cell decryptable forever and a hole in the chain; the
reference behaves the same.

**D7 — content handling (`tr::content`).** `Delivery` = `Dummy` (discarded) · `Handshake` (returned to M4, which
checks it is the first message) · `Messages` (Batch, direct or reassembled) · `Routes` (`RouteUpdate`) ·
`Receipt` · `Control` · `KeyChange` · `Partial` (fragment stored) · `Malformed`. Reassembly (spec §7.6 leaves the
rules to reassembly; readings, raised as SQ-25, non-blocking because no vector exercises them): fragments of one
`msg_id` must agree on `total`; an identical duplicate of a stored `idx` is ignored; a conflicting duplicate or a
`total` mismatch discards the partial message; the message is complete when every `idx < total` is present and
is the concatenation in `idx` order, decoded as `FragmentPayload` (`inner_type` ∈ {2, 4, 5, 6, 7}); any chunk sizes
are accepted; at most `MAX_PARTIALS = 8` messages are in reassembly (the oldest is evicted), so memory is bounded
by 8 × 64 × 1669 B. The reassembly state is serialisable (`Inbox::to_bytes`/`from_bytes`, zeroizing), because a
stored fragment is "processing committed" before its cell is acknowledged (§7.5). `KeyChange` (§7.7): verified
with `HybridVerify(old IK_sig, "SecMP-TR/1 keychange", fingerprint(new IKSPublic))`; valid → `Trust::Unverified`
(contact unverified, outgoing *real* messages blocked until re-verification — dummies continue, CLAUDE.md §1.4);
invalid → `Trust::Frozen` (warning; no content delivered, no real message sent); no accept path. Dummy generation:
`content::dummy()` = `Content { seq: 0, ts: 0, body: Dummy }`, encrypted through the same `encrypt` as every
message (dummies consume no `seq`, so lost dummies never show as gaps).

**D8 — F6, the inline A/A′ control.** A control target `aa_prime_control`: `MsgEncrypt::open` rejecting (as
`msg_open_reject`), both classes with *identical contents*, class 1 copied from its own source allocation — the
M1-F9 pattern, deliberately. It is judged like a target; if it FAILs (a reproduced shift at or above the effect
floor) the run is `CONTROL_FAIL` (the placement artefact reaches the floor on this runner, so a violation of the
F9 rule could produce a verdict); PASS and `SUB_FLOOR_SHIFT` pass and its t and Δ are in every report — the
per-run bound on the artefact that was until now enforced by review only.

**D9 — ct targets for TR (and ADR-042).** Three targets through `RatchetState::decrypt` on one fixed state (the
state is handed back by every rejection): `tr_decrypt_reject_hdr_key` (class 0: header sealed under a wrong key;
class 1: sealed under `hk_r` with the tag's last byte flipped — both open under no key), `tr_decrypt_reject_body_tag`
(valid header under `hk_r`; body tag wrong in byte 0 vs byte 31), `tr_decrypt_reject_ct_pq` (valid header under
`hk_r` whose `ct_pq` differs from `last_ct_r` in byte 0 vs byte 1087 — the constancy check). Both classes are built
from one common source per target (`blend`, F9 rule). The bench cannot call `secmp-proto` from `secmp-crypto`
(`secmp-proto` depends on `secmp-crypto`; a dev-dependency back would rebuild `secmp-proto` for every
`secmp-crypto` mutant), so it moves unchanged to `crates/secmp-testkit/benches/ct.rs` (dev-dependencies
`secmp-crypto`/`secmp-proto` with `kat`); the one `unsafe_code` exemption moves with it (`UNSAFE_EXEMPT_ROOT`).
ADR-042 records this (engineering: gate and tooling).

**D10 — ProVerif.** One file `formal/tr.pv`, the abstractions exactly as listed in `CLAIMS.md` (constructors and
the two equations); the scenarios of the claims (no compromise; phase-1 compromise after step 2 or 3; compromise of
A after step 1 with no oracle, DHO, KEMO, both) are independent parallel sessions with their own `SK` in one
process, the oracles scoped to their session. The gate compares the `RESULT` lines in order with an
`expect::PROVERIF_EXPECTED` table derived from `CLAIMS.md`. If a query cannot be proved as fixed, or a scenario
does not fit one file, that is a stop condition (brief) and is reported, not worked around.

**D11 — performance.** `crates/secmp-proto/examples/tr-perf.rs` (release, feature `kat` off): median and maximum
of `encrypt` + `decrypt` for a chain message and for a DH-step message (N = 200 each, including persistence
encoding); the report goes to `target/tr-perf.txt`; `cargo xtask step perf` (ci-full) fails at ≥ 3 ms.

**D12 — randomness injection.** A sealed trait `tr::Entropy` with `OsEntropy` (X25519/ML-KEM key generation,
`Encaps`, `hdr_nonce` from the OS CSPRNG — the only implementation in a shipped build) and, under a new
`secmp-proto` feature `kat` (= `secmp-crypto/kat`; `KAT_PACKAGES` += `secmp-proto`), `FixedEntropy`, which reads
the SCHEMA §2 byte stream in the order of SCHEMA-4.9 (X25519 secret 32 B, ML-KEM seed 64 B, `Encaps` `m` 32 B,
`hdr_nonce` 24 B).

## 2. What was built

(filled in as the steps land)

## 3. Evidence per acceptance criterion

(filled in as the steps land)

## 4. Gates

(filled in as the steps land)

## 5. Deviations from spec / plan

(filled in as the steps land)

## 6. Dependencies added or bumped

None planned (no new crate; `secmp-proto` gains a `kat` feature; the ct bench's dev-dependencies are existing
workspace crates).

## 7. Open risks and known limitations

(filled in as the steps land)

## 8. Blocked / questions for the reviewer or owner

- Q-1 (ADR-041, Consequences): "data-independent timing (DIT) on Apple Silicon is a separate M3 ADR". The M3 brief
  does not list it. Setting the `DIT` bit is an `msr` instruction (`unsafe`, only in `secmp-sys-*`) and a client
  hardening measure; I propose it becomes an ADR drafted with M9 (client hardening) unless the reviewer wants it in
  M3.

## 9. Checklist before requesting review

- [ ] All acceptance criteria evidenced above
- [ ] `cargo xtask ci` green on a clean checkout
- [ ] No `#[ignore]`, no lint allowances added for security lints, no disabled gates
- [ ] Vectors frozen and reviewed (if changed)
- [ ] Docs/CHANGELOG updated
- [ ] Threat model and spec untouched (or ADR'd)
