# CLAUDE.md — Working rules for the implementing agent

You are building **SecMPro**, a zero-trust, post-quantum, metadata-free desktop messenger with its own protocol (SecMP/1), in Rust. The architecture and the protocol are already designed; your job is to implement them **exactly as specified**, milestone by milestone, with evidence. The reviewer (Fable) checks every milestone against the documents in `docs/`. Changes to the spec (`docs/03`) and the threat model (`docs/01`) go through an ADR that the reviewer reviews and the owner approves; engineering ADRs (tooling, gates, CI, dev-dependencies, evidence rules, measurement method) are accepted by the reviewer under the owner's delegation of 2026-09-30. Milestone PRs are merged by the implementer on the reviewer's written GO (delegation of 2026-09-29); policy, money, secrets and GitHub settings stay with the owner.

## 0. Read order (do this at the start of every session)

1. This file.
2. `docs/07-milestones.md` — find the current milestone (the first one without a `docs/reviews/Mxx-review.md` marked *approved*).
3. The documents that milestone references — at minimum `docs/03-protocol-spec.md` for anything touching the wire, `docs/04-client-security.md` for anything touching the client, `docs/05-relay-ops.md` for the relay, `docs/06-engineering-standards.md` always.
4. `docs/08-decisions.md` (ADRs) and `docs/09-open-questions.md` — never decide an open question yourself.
5. `docs/01-threat-model.md` when unsure whether something is acceptable.

The research briefs in `docs/research/` are background with sources; they are **not normative**. If a brief and the spec disagree, the spec wins; if you think the spec is wrong, stop and write it up (see §6).

## 1. Non-negotiable invariants

These are the properties every line of code must preserve. Violating one is a blocker, not a trade-off.

1. **The relay learns nothing but opaque, fixed-size cells** — no identities, no plaintext, no sizes, no message-level activity, no linkable ids beyond a single queue. The only accepted leakage is the list in spec §11.3; anything beyond it is wrong.
2. **Single ciphersuite, no negotiation, no fallback.** Version mismatch = hard error. No "classical-only if PQ fails".
3. **Every key agreement SecMPro performs is hybrid (X25519 + ML-KEM).** Handshake, every ratchet step, client-relay link, and TLS in direct mode. (Tor's own circuits are classical and outside our control; that is why the PQ link layer runs inside them.)
4. **Constant-rate traffic.** The frames a client emits depend only on mode, configured periods, the set of links and the random phases fixed at link start — never on user activity (spec §10.1; the sanctioned exceptions are the control operations of §10.6). Real and dummy cells go through the same ratchet code path; frames are pre-built before the tick.
5. **Fail closed.** Verification failure → drop, freeze, warn. Screen protection not verified → content locked (also on GNOME, unknown compositors, X11, remote sessions). Tor unavailable → no connection unless the user explicitly chose direct mode.
6. **Secrets are typed, zeroized, never logged, never compared with `==`.** Only `secmp-crypto` uses cryptographic crates for SecMP constructions (rustls/aws-lc-rs, Arti and SQLCipher are exempt, in their own crates, never for SecMP constructions). Only `secmp-sys-mem` and `secmp-sys-desktop` contain `unsafe`.
7. **Persist-before-send and persist-before-ack.** Ratchet state is written to the encrypted store before a cell leaves the process, and a received cell is acknowledged only after its processing is committed.
8. **Decoders are total, consistent and canonical**, fuzzed, and covered by negative vectors; every wire structure is in spec Appendix D.
9. **No new direct dependency without an ADR entry and a `cargo vet` record**; transitive gaps are tracked exemptions (`06` §3). No crate younger than 7 days. No git dependencies. No build scripts in our crates.
10. **The spec and the threat model are not changed by code.** Changes go through an ADR and reviewer approval first. Frozen vectors change only with a spec revision.

## 2. How to work a milestone

1. Create the branch `mNN-<slug>`. Read the milestone's Goal, Deliverables, Acceptance, Review focus.
2. Write a short **plan** at the top of `docs/reviews/MNN-report.md` (from `docs/templates/milestone-report.md`): what you will build, in which order, which tests prove each acceptance criterion. Keep it updated as you go.
3. Implement in small commits (Conventional Commits). After every logical unit run `cargo xtask ci-fast`; run `cargo xtask ci-full` before the report.
4. Every function that touches the wire or a key gets: unit tests including failure paths, a property test where the input space is large, a fuzz target if it parses bytes, and — for crypto/protocol code — external or frozen test vectors.
5. When the acceptance criteria are met and `cargo xtask ci` is green, finish the report: evidence (exact commands and outputs/summary), deviations from spec (must be empty or ADR'd), open risks, questions. Open the PR. Stop. Do not start the next milestone until the review is recorded as approved.

Work **one milestone at a time**, sequentially, exactly as listed. Do not "prepare" later milestones.

## 3. Commands

```
cargo xtask ci-fast       # minutes: fmt, clippy (deny set), forbid(unsafe) grep, deny/vet/audit/cooldown, nextest, KATs
cargo xtask ci-full       # everything: ci-fast + fuzz smoke, coverage, mutants (crypto/proto), Miri/Kani subsets, ProVerif (mandatory), ref/ vector cross-check, unit exposure score
cargo xtask vectors       # cross-generate vectors from ref/ and the Rust code, compare, freeze — initial generation in M1–M5; afterwards only with a spec revision
cargo xtask repro-check   # reproducible build check (release profile)
cargo xtask sbom          # CycloneDX SBOM
cargo xtask win-test      # cross-build (cargo-xwin) and run tests in the Windows 11 VM (owner-operated)
cargo xtask ops-check     # run deploy/check-hardening.sh against a relay host (owner-operated)
cargo nextest run -p <crate>
cargo fuzz run <target> -- -max_total_time=120
cargo mutants -p secmp-crypto -p secmp-proto
```

Install once: `cargo install cargo-nextest cargo-deny cargo-vet cargo-audit cargo-auditable cargo-cyclonedx cargo-fuzz cargo-mutants cargo-llvm-cov cargo-xwin`; `proverif` via `apt` or opam; Kani via `cargo install --locked kani-verifier && cargo kani setup`.

## 4. Coding rules (summary of `docs/06-engineering-standards.md`)

- Lints are enforced by the workspace: `unsafe_code = deny` plus `#![forbid(unsafe_code)]` in every crate except `secmp-sys-mem`/`secmp-sys-desktop`; `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, `as_conversions`, `todo`, `dbg_macro`, `print_*` all **deny**. The only sanctioned `#[allow]`s are listed in `06` §2 (tests: unwrap/expect at file level; the named `SystemTime::now` sites).
- Errors: one uniform error type per crate; **authentication failures must produce indistinguishable errors** (no "bad MAC" vs "bad length" externally). Never embed secrets or ids in error messages.
- Randomness: `OsRng`/`getrandom` only.
- Time: `secmp-client-core::clock` (injectable). `SystemTime::now()` only at the sites sanctioned in `06` §2.
- Sans-IO: `secmp-crypto` and `secmp-proto` have no tokio and no I/O.
- Logging: `tracing` with a redaction layer; never log cell contents, ids, keys, fingerprints, names. The relay logs no per-request data at all — there is a test for that.
- Comments: every `unsafe` block has a `// SAFETY:` comment; every crypto composition cites the spec section (`// spec §7.3`).
- Encoding: hand-written fixed-layout big-endian per spec §4.1 — no serde on the wire.

## 5. Crypto rules (checked by the reviewer on every PR)

- Never invent a construction. If the spec does not define it, it does not exist. Ask.
- Use the exact labels from spec Appendix A. Adding a label = spec change.
- Bind every public key, ciphertext and version byte into the transcript/AD exactly as the spec lists them.
- Check every X25519 output for all-zero; use `verify_strict`; validate ML-KEM encapsulation keys on import; store decapsulation keys as seeds.
- Counters: `checked_add`, abort on overflow; strict `+1` on receive.
- Trial decryption and MAC checks must do constant work regardless of outcome; compare tags with `subtle`.
- Tests that only round-trip your own code do not count; use Wycheproof/ACVP/RFC vectors and the frozen SecMP vectors.

## 6. Stop conditions — when to halt and ask instead of proceeding

Stop, write the issue into `docs/reviews/MNN-report.md` under "Blocked", and end your turn with a clear question, when:

- An acceptance criterion cannot be met without weakening an invariant (§1) or a threat-model statement.
- The spec is ambiguous or (you believe) wrong in a way that affects security. Propose the fix as a draft ADR; do not implement your interpretation silently.
- A required crate does not exist at the pinned version, is unmaintained, has an open RustSec advisory, or needs `unsafe` outside `secmp-sys-mem`/`secmp-sys-desktop`.
- A platform API behaves differently from `docs/04-client-security.md` (e.g., `WDA_EXCLUDEFROMCAPTURE` fails with the chosen renderer).
- A decision belongs to the owner (`docs/09-open-questions.md`).
- An acceptance criterion needs a deliverable of a *later* milestone (plan error) — report it; do not pull later work forward.
- A ProVerif query from `formal/CLAIMS.md` is false or cannot be proved, or a query would have to be weakened to pass.
- A size, offset or arithmetic statement in the spec does not add up (e.g., a structure does not fit its padding) — report the exact numbers.
- A frozen vector would have to change.
- Owner-operated infrastructure (Windows VM, Tor test host, relay host, KDE machine, signing key) is unavailable and the milestone needs it — do the rest, report the gap, do not fake the evidence.

Never: weaken a lint to make CI pass, add `#[allow]` for a security lint, mark a test `#[ignore]` without an ADR, disable a gate, or claim a test ran that did not.

## 7. Reporting format (end of every session)

Update `docs/reviews/MNN-report.md` and summarise in your final message: (1) what was done, (2) which acceptance criteria are now evidenced (with test names), (3) what is left, (4) blockers/questions, (5) any deviation from the spec or the plan (there should be none). Keep it factual; no marketing.

## 8. Glossary

Cell (4096 B E2E unit) · Frame (4352 B link unit) · Queue (unidirectional capability mailbox; `rid` recipient id, `sid` sender id, both derived from keys) · Link (client↔relay session, `sess_id`) · Link data (`ld_id`, the inviter's encrypted blob) · Slot (scheduler tick) · Period `P_q` (recipient-chosen send period of a queue) · IKS (identity key set: `IK_sig` = Ed25519 ‖ ML-DSA-65, `IK_dh` = X25519) · SPK/RPK/OPK (signed, ratchet and one-time prekeys) · HX (handshake) · TR (ratchet) · LINK (client↔relay layer) · Q (queue commands) · INV (invitations) · SAS (safety number) · Strict/Balanced/Low-bw (scheduler modes) · RouteDescriptor (transport-neutral address of a queue/endpoint) · `akc` (access-key commitment).
