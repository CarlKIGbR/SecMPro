# SecMPro — Engineering Standards, Testing, CI and Supply Chain

Status: v1 baseline (2026-09-25). Normative for every crate. `CLAUDE.md` summarises the parts the implementing agent must apply on every change; this document is the full rule set and the Definition of Done. Research basis: `docs/research/R5-server-ops-supply-chain.md`.

## 1. Language, toolchain, workspace

- Rust stable, pinned exactly in `rust-toolchain.toml` (`channel = "1.9x.y"`, `components = ["clippy", "rustfmt", "llvm-tools"]`, `targets = ["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"]`). MSRV = the pinned version. Upgrades are their own PR with an ADR note.
- Edition 2024. One Cargo workspace; all versions in `[workspace.dependencies]`; every crate uses `workspace = true` for deps and lints.
- `Cargo.lock` committed. `cargo build --locked` everywhere. `cargo vendor` for release builds.

## 2. Lints and code rules (`[workspace.lints]`)

```toml
[workspace.lints.rust]
unsafe_code = "deny"              # every crate except secmp-sys-* additionally declares #![forbid(unsafe_code)] (checked by `xtask ci` with a grep);
                                  # a workspace-level "forbid" cannot be relaxed per crate (E0453), hence deny + per-crate forbid
missing_docs = "warn"
unused_must_use = "deny"

[workspace.lints.clippy]
all = { level = "deny", priority = -1 }
pedantic = { level = "warn", priority = -1 }
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
indexing_slicing = "deny"
arithmetic_side_effects = "deny"
as_conversions = "deny"
dbg_macro = "deny"
print_stdout = "deny"
print_stderr = "deny"
todo = "deny"
unimplemented = "deny"
mem_forget = "deny"
large_stack_arrays = "warn"
undocumented_unsafe_blocks = "deny"      # every unsafe block needs a `// SAFETY:` comment (fires only where unsafe exists)
multiple_unsafe_ops_per_block = "deny"   # one unsafe operation per block
```

`clippy.toml`: `disallowed-methods` for `rand::thread_rng` (use `OsRng`) and `std::time::SystemTime::now` (sanctioned exceptions, each with `#[allow(clippy::disallowed_methods)]` and a comment: `secmp-client-core::clock`, the relay's hour-bucket function, and `secmp-cli` output timestamps). Hash maps keyed by attacker-influenced data use `std::collections::HashMap` with the default `RandomState` (SipHash-1-3, randomly keyed — the HashDoS-resistant choice); `ahash`/`foldhash` are permitted only for maps keyed by relay-generated ids.

Test code (`#[cfg(test)]`, `tests/`, `fuzz/`, `testkit`) may use `unwrap`/`expect` via `#![allow(clippy::unwrap_used, clippy::expect_used)]` at the file top.

Logging: for `secmp-relay`, `CLAUDE.md` §4 "`tracing` with a redaction layer" is met by the closed event set of `secmp_relay::event` instead of `tracing` — no variant can carry per-request data, `expect::RELAY_TRACE_ALLOW` pins the set and test RL-03 captures a full scenario (ADR-049, accepted 2026-10-08).

**Sanctioned `unsafe_code` relaxations (M0 review, 2026-09-28):** (a) `secmp-sys-mem` and `secmp-sys-desktop` carry `#![allow(unsafe_code)]` at the crate root — these two crates exist for platform bindings and every `unsafe` block in them must have a `// SAFETY:` comment (`undocumented_unsafe_blocks`), do one thing (`multiple_unsafe_ops_per_block`), and be covered by a unit test and, where feasible, Miri; (b) `secmp-ui` carries `#![deny(unsafe_code)]` instead of `forbid`, because Slint's `slint!` macro expansion contains `#[allow(unsafe_code)]` (E0453 under `forbid`); the `policy` step verifies that `secmp-ui`'s own source files contain neither the token `unsafe` nor a hand-written `allow(unsafe_code)`/`expect(unsafe_code)` (ADR-033). Every other crate carries `#![forbid(unsafe_code)]`.

The lint allowances listed in this section are the only sanctioned ones; the review checklist treats any other `#[allow]` on a `deny` lint as a finding.

Crypto-specific rules (enforced by review checklist and, where possible, by types):

| Rule | Mechanism |
|---|---|
| No cryptographic primitive is implemented in this repo (no hand-rolled KDF/MAC/cipher/curve) | `secmp-crypto` composes only allowlisted crates and is the **only crate that uses cryptographic crates for SecMP constructions**. Exempt, and never used for SecMP constructions: rustls + aws-lc-rs (TLS in `secmp-transport`), `arti-client` and its dependencies (Tor), SQLCipher/OpenSSL (`secmp-store`). Any composition (combiner, EtM) is specified in `03-protocol-spec.md` and has KATs |
| Secret types: `Zeroize`, no `Clone` (unless justified), no `Debug` of contents, no `PartialEq`; comparisons via `subtle` | Newtypes + `#[derive(ZeroizeOnDrop)]`; a `secrecy`-style `expose_secret()` API |
| Nonces are never reused: link frames use per-direction `u64` counters with `checked_add`; ratchet message keys are single-use; XChaCha nonces elsewhere are random 24 B | `Nonce` newtypes that are consumed by value (`!Clone`) |
| Every DH output checked for all-zero; Ed25519 `verify_strict`; ML-KEM ek validated on import | Wrapper functions; Wycheproof negative vectors in CI |
| All public keys, ciphertexts and version bytes are bound into transcripts/AD | Spec §6.4, §7.5, §8.3; reviewed against Appendix A labels |
| Constant-time behaviour for secret-dependent operations | Only constant-time crates; `dudect`-style tests for tag comparison, the openers, SAS derivation and (M3) the SecMP-TR reject paths (`crates/secmp-testkit/benches/ct.rs`, ADR-042) |
| Every decoder is total, exact-fit, canonical | Property tests (encode∘decode = id), fuzzing, negative vectors |

## 3. Dependency policy

- **Allowlist in `deny.toml`**: `[sources]` crates.io only; `[bans] multiple-versions = "deny"` (wildcard exceptions listed with justification); `[licenses]` allowlist (MIT, Apache-2.0, BSD-2/3 (covers SQLCipher), ISC, Zlib, Unicode, MPL-2.0; Slint's GPLv3 / royalty-free dual license as the single copyleft exception; **no LGPL** — which is why Arti's `hs-pow-full` is excluded, ADR-024 — recorded in ADR-015 pending the project license decision OQ-1).
- **Adding a *direct* dependency requires**: an ADR line in `08-decisions.md` (why, alternatives, maintenance status, audit status), a `cargo vet` entry (an imported audit from Mozilla/Google/ISRG/Bytecode Alliance/Zcash, or a local audit by a named human reviewer — an AI agent must not record itself as auditor), and passing `cargo deny check`.
- **Transitive dependencies** (Arti, Slint and wgpu bring several hundred): `cargo vet` runs with imports; uncovered crates are recorded as *tracked exemptions* in `supply-chain/config.toml` with the crate, version and the direct dependency that pulls them, and reviewed at every release. The **zero-exemption requirement applies to the dependency closure of `secmp-crypto` and `secmp-proto` only**.
- **Publisher trust** (M0 review): `cargo vet trust` entries are permitted for individual publishers whom at least two of the imported audit sets trust (currently dtolnay and BurntSushi, per Mozilla, ISRG and Bytecode Alliance), recorded in `supply-chain/audits.toml` with `criteria = "safe-to-deploy"`, an `end` date at most 12 months out, and a note naming the importing organisations; reviewed at every release. Trust entries are not exemptions.
- **Cryptographic closure** (ADR-036, M1): in the *normal* dependency closure of `secmp-crypto`/`secmp-proto` every crate is covered by an imported audit, by publisher trust for the accounts that publish the chosen primitive crates (RustCrypto, dalek-cryptography, Cryspen/CE Labs, AWS — per account, ≤ 12 months, note naming the crate family), or by a delta audit against an audited/trusted version (diff attached under `docs/reviews/Mxx-evidence/vet-deltas/`, read by the reviewer, approved by the owner, whose name is in the note). KATs on every target, three-way differential tests, fuzzing and the mutation gate are mandatory compensating controls. Dev- and build-only crates outside the normal closure may be tracked exemptions; **zero exemptions** applies to the normal closure.
- **Cooldown**: no dependency version younger than 7 days is allowed (`cargo` `global-min-publish-age = "7 days"` once stabilised in Rust 1.100; until then Renovate/Dependabot cooldown + a CI check comparing `Cargo.lock` versions against crates.io publish dates).
- **Crypto crates** (only in `secmp-crypto`): `libcrux-ml-kem`, `ml-kem` (differential), `ml-dsa`, `aws-lc-rs` (differential + TLS), `x25519-dalek`, `ed25519-dalek`, `curve25519-dalek`, `chacha20`, `chacha20poly1305`, `hmac`, `hkdf`, `sha2`, `sha3`, `argon2`, `subtle`, `zeroize`, `getrandom`, `rand_core`. Versions pinned to exact (`=`) in `[workspace.dependencies]` and bumped only with KAT re-runs.
- **No git dependencies** except pinned by full `rev` with an ADR. **No build scripts** in our crates. Dependencies with build scripts are inspected on every bump (`cargo vet` `build-script` criteria).
- `cargo audit` (RustSec) in CI daily; a new advisory on a used crate blocks merges until triaged.

## 4. Testing

| Layer | Requirement |
|---|---|
| Unit | Every public function in `secmp-crypto`/`secmp-proto` has tests including failure paths. Coverage gate ≥ 90 % lines for those two crates, ≥ 80 % elsewhere (`cargo llvm-cov`). |
| Known-answer tests | Wycheproof (X25519, Ed25519, XChaCha20-Poly1305, HMAC, HKDF, ML-KEM, ML-DSA), NIST ACVP (ML-KEM, ML-DSA), RFC vectors (7748, 8032, 8439, 5869) run on **every target** (Linux x86_64, Windows x86_64 in the VM; aarch64 Linux optional). Frozen SecMP vectors in `vectors/` (spec Appendix C). |
| Differential | ML-KEM: libcrux vs RustCrypto `ml-kem` vs `aws-lc-rs` on random inputs (encaps/decaps agree). ML-DSA: `ml-dsa` vs `aws-lc-rs`. Ed25519: dalek vs `aws-lc-rs`. |
| Property | `proptest` for encodings (canonical), ratchet (arbitrary interleavings/out-of-order/duplicates never break or reuse keys), scheduler (traffic pattern independent of activity — a model-based test that records emitted frame sizes/times for random activity and asserts identical sequences). |
| Fuzzing | `cargo-fuzz` targets for every decoder, the HX/TR/LINK state machines (message sequences), the relay command executor. Short run (≈2 min per target) on every PR, nightly 4 h; corpora committed. |
| Mutation | `cargo mutants` on `secmp-crypto`, `secmp-proto`, `secmp-relay` (ADR-047 Amendment 3): **zero surviving mutants, or each survivor documented** in `docs/mutants-accepted.md` with the reason it is untestable (e.g., zeroization-on-drop, constant-time helpers). |
| Miri | `secmp-sys-mem`, `secmp-sys-desktop`, `secmp-crypto` and (M3, M2 review F3) `secmp-proto` under Miri (where feasible). Bounded scope in `ci-full`: the skip list `expect::MIRI_SKIP` names each skipped test module with its reason (runtime) and is reviewed at every milestone; a weekly scheduled `miri-full` job runs, with a 6-hour timeout per package, every test that a build without features contains, the skipped modules included (M1 review F3, 2026-09-29); the test targets with `required-features` (`expect::MIRI_FEATURE_GATED`: `hx`, `tr_generator`, `tr_properties`, `tr_vectors` of `secmp-proto`) and the tests of `expect::MIRI_UNSUPPORTED` run under Miri in neither, only natively (`kat` step, `nextest`; M4 review C-4, delta review VD1-6). |
| Constant time | dudect-style Welch-t tests (`ci-full` step `ct`; threshold 4.5; the early-exit positive control must be detected) for tag comparison, the openers, SAS derivation and (M3) the SecMP-TR decrypt rejections (wrong header key, wrong body tag, wrong `ct_pq`), on every target. Harness rule (M1 review F7): the two classes may differ only in the *contents* of their inputs, never in where the inputs live — every measured input is prepared afresh, in the same allocation sequence for both classes (one fixed buffer or key object per class turns alignment into a class signal). The rule applies one step earlier, to the source buffers the fresh copies are made from: every measured input is built branch-free from one common source per target (M2 finding F9, `f7b3066`). A failing gate is a STOP condition (report the run, root-cause it in the code under test first); the threshold, the sample counts and the control are never changed to make it pass. A target FAILs only if |t| > 4.5 in two independent measurements at the same crop with the same sign **and** the shift of the cropped class means reaches the effect floor — one effective quantum (the sample lattice spacing measured from the data) or 10 ns, whichever is larger — with the run's inline A/A control passing and the sensitivity control `min_leak_control` caught by this same rule with class 0 slower (ADR-041 Amendment 3; else the run is `CONTROL_FAIL`) and the positive control detected; a reproduced shift below the floor is reported as a sub-floor shift (**ADR-041**, Amendment 1). Sensitivity rule (ADR-041 Amendment 1): secret-dependent comparisons are measured as bundled primitives (×256 per sample, e.g. `tag_compare`, `caead_com_compare`), whose single-byte early exit the gate detects, while composed operations (`msg_open_*`, `caead_open_*`) are checked against the floor only and so catch leaks of branch or cache-miss scale, not data effects below 10 ns. Timer, batching and runner metadata per **ADR-038**. |
| Model checking | Kani harnesses for the cell/frame parsers (no panics, exact-fit) and the queue store bounds. |
| Integration | `secmp-testkit`: in-process relay + N clients on tokio with a virtual clock; end-to-end invitation → handshake → 1 000 messages both ways → rotation → key change. |
| Simulation | `turmoil`: partitions, delays, reordering, relay restart; asserts eventual delivery and no key reuse. |
| Platform | **Development host is macOS (Apple Silicon, `aarch64-apple-darwin`)** — a dev host only, not a shipping target; the full suite and all KATs run natively there, which makes aarch64 a first-class KAT target. Linux: GitHub-hosted `ubuntu-latest` runs the full Linux pipeline; local Linux-target checks from macOS via `cargo-zigbuild` (or a container). Windows, M0–M8: GitHub-hosted `windows-latest` builds natively with the MSVC toolchain and runs the tests. Windows, M9 onward (screen-capture tests, signed installers): the owner's libvirt Windows 11 VM as an ephemeral self-hosted runner (overlay reverted per job; no secrets; never runs fork PRs) via `cargo xtask win-test --backend libvirt`. Screen-security tests per `04-client-security.md` §7. Linux desktop: nested compositor (KWin ≥ 6.7 preferred; sway as second) for Wayland tests. |
| Formal | ProVerif models in `formal/` run in CI (`proverif` from Debian/Ubuntu packages or opam); a model change requires a spec change reference. |
| Benchmarks | `criterion` for AEAD/KEM/ratchet step; relay throughput harness (frames/s) run manually per release and recorded. The ratchet's acceptance bound (docs/07 M3: encrypt + decrypt of a message < 3 ms) is checked on every `ci-full` run by the step `perf` (`crates/secmp-proto/examples/tr-perf.rs`: the maximum of 200 chain and 200 DH-step messages, `expect::TR_PERF_MAX_MS`). |

CI triggers (M2, 2026-09-29): `push` runs only for `main`; every PR head is covered by its `pull_request` run, whose jobs are the `main-protection` required checks (a cancelled push run on `7d4e4f0` had left `cancelled` check runs under the required names and blocked the merge). Required job names exist only in the pull_request/push workflow; dispatch workflows use distinct job names (M2 review C2: `ci.yml` holds the required checks and has no `workflow_dispatch`; on-demand runs use `ci-dispatch.yml`, checked by `cargo xtask policy`).

Nothing that touches the network or wall clock in unit tests; `secmp-client-core::clock` is injectable.

## 5. CI pipeline (`cargo xtask ci-fast` / `cargo xtask ci-full` mirror it locally)

`ci-fast` (minutes; run after every logical unit): steps 1–5. `ci-full` (before a milestone report; nightly in CI): everything. `cargo xtask ci` is an alias for `ci-full`.

1. `cargo fmt --check`
2. `cargo clippy --workspace --all-targets --locked -- -D warnings`
3. `cargo deny check` · `cargo vet` · `cargo audit` · cooldown check
4. `cargo nextest run --workspace --locked` (+ doctests)
5. KATs + differential tests (feature `kat`)
6. Fuzz smoke (2 min/target)
7. Coverage gate
8. Mutation gate (nightly, and on PRs touching `secmp-crypto`/`secmp-proto`/`secmp-relay`)
9. Miri + Kani (nightly, and on PRs touching `secmp-sys-*`/parsers)
10. ProVerif models (**mandatory**; CI installs `proverif` from the distribution package or opam; a missing prover fails the gate)
11. Windows: native build + tests on GitHub-hosted `windows-latest` (every PR); `cargo-xwin` cross-build job as a compile-compatibility check only (with NASM once `aws-lc-rs` is in the graph; a hard job from M1 on); from M9: tests on the owner's libvirt VM runner (nightly + on PRs touching platform code) — **owner-operated**; if unavailable the report says so and the milestone is not closed
12a. Reference-implementation cross-check: `ref/` (independent Python implementation, ADR-026) regenerates the SecMP vectors and they must match `vectors/` byte-for-byte
12. Reproducible build check: two independent builders per target must produce identical hashes for release profiles — Linux artefacts on two Linux builders (GitHub-hosted + the owner's server, or two containers with different base images); **Windows artefacts on two Windows builders, built natively** (GitHub `windows-latest` and, from M9, the owner's libvirt VM; before that, two GitHub Windows jobs with different runner images/dates) — ADR-034, because SQLCipher's vendored OpenSSL cannot be cross-built to MSVC
13. SBOM (CycloneDX via `cargo-cyclonedx`), `cargo auditable` binaries
14. `systemd-analyze security --offline` on `deploy/secmp-relay.service` (≤ 2.0)

Build-script-selected code paths (M1 review F6, 2026-09-29): a dependency whose build script or run-time dispatch selects between implementations independently of Cargo features (libcrux: portable / NEON / AVX2 backends) has its KATs and the frozen SecMP vectors run on **every selectable path on every target** (for libcrux: the host backend and a re-run with `LIBCRUX_DISABLE_SIMD128=1 LIBCRUX_DISABLE_SIMD256=1`); the ADR of that dependency names the paths.

CI hygiene: no `pull_request_target`/`workflow_run` triggers; all actions pinned by commit SHA; no caches shared between PR and release workflows; release workflow is a reusable workflow producing SLSA v1.2 Build L3 attestations; artefacts additionally signed offline with minisign by the maintainer **after** the two-builder reproducibility check.

## 6. Reproducible builds

- Release profile: `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`, `debug = false`.
- `RUSTFLAGS` fixed in `.cargo/config.toml` (`--remap-path-prefix` for `$CARGO_HOME` and the workspace; `-C target-cpu=x86-64-v2`; Windows: `-C control-flow-guard`). `SOURCE_DATE_EPOCH` from the git commit time. `trim-paths` once stable.
- Builds run in a pinned container image (digest-pinned) with vendored deps; `diffoscope` on mismatch.
- C dependencies (SQLCipher via `bundled-sqlcipher-vendored-openssl`, `aws-lc-sys`) are the main reproducibility risk: pinned `cc`/`cmake`/NASM/MSVC versions in the image or runner; if a dependency cannot be made reproducible, the milestone report says so and the ADR decides.
- Release builds run only through `cargo xtask release` (M11), which injects the `--remap-path-prefix` flags for `$CARGO_HOME` and the workspace (ADR-032; Cargo cannot expand those paths in `.cargo/config.toml` and `trim-paths` is still unstable). A plain `cargo build --release` is a developer convenience, never a release.

## 7. Repository conventions

- Branch per milestone (`m03-handshake`), PR to `main` with the milestone report (`docs/templates/milestone-report.md`) attached. Squash merge. Conventional Commits 1.0 (`feat(proto): …`, `fix(relay)!: …`).
- ADRs: `docs/08-decisions.md` (single file, MADR-style entries, numbered). Superseded ADRs stay, marked.
- `SECURITY.md` + `.well-known/security.txt` (RFC 9116) with `Contact`, `Expires`, `Encryption`, `Policy`, `Preferred-Languages: en, de`.
- Docs are English; code comments English; user-facing strings via a locale table (English + German).

## 8. Definition of Done (per milestone)

A milestone is done only when all of the following hold and are evidenced in the milestone report:

1. All acceptance criteria in `07-milestones.md` for that milestone are demonstrated (test names/commands listed).
2. `cargo xtask ci` is green on Linux; Windows jobs green where the milestone touches platform code.
3. New/changed crypto or protocol code: KATs frozen in `vectors/`, mutation gate passed, fuzz targets added, formal model updated if the message flow changed.
4. Threat model (`01`) and spec (`03`) unchanged — or changed through an ADR with reviewer approval.
5. No new dependency without ADR + vet entry.
6. `docs/` updated for anything a user or operator would need; `CHANGELOG.md` entry.
7. Open risks and deviations listed explicitly in the report (empty list is a claim, not a default).
8. Reviewer (Fable) sign-off recorded in `docs/reviews/Mxx-review.md`.

## 9. Guard rails for AI-written crypto code (review focus list)

Reviewers check every crypto/protocol PR against: invented constructions; nonce/counter handling (reset on restart? same nonce both directions?); missing domain separation or transcript binding; non-constant-time comparisons; constant-time results (`Choice`, `ct_eq`) turned into `bool` before being combined with another check (`bool::from(a) && b` is a secret-dependent branch even when both arms reject — combine with `&`/`|` on `Choice` and convert exactly once, at the final decision; M1 review C4, caught by the `ct` gate); unchecked inputs (zero DH, non-canonical points, malformed KEM keys); secrets in `Debug`/logs/errors; tests that only round-trip against the same code (external vectors mandatory); panics on malformed input; hallucinated crate names or APIs (must exist at the pinned version — CI catches, but review looks for near-miss crates); error messages that create oracles (uniform errors for all auth failures); persistence ordering (persist-before-send); and timing side channels in "helpful" early returns.
