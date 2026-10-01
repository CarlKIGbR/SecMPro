// SPDX-License-Identifier: AGPL-3.0-or-later
//! The explicit input set of every gate.
//!
//! Gates discover their inputs (KAT features, fuzz targets, ProVerif models, Kani harnesses, systemd units)
//! and **fail if the discovered set differs from the set listed here**, in either direction. A gate can
//! therefore never pass vacuously because its inputs disappeared: removing a fuzz target or a model is a
//! reviewed change of this file. Each milestone that adds inputs extends these lists.

/// The two crates that may contain `unsafe` (CLAUDE.md §1.6, docs/02 §3, docs/06 §2 (a)). Their library root
/// carries `#![allow(unsafe_code)]` — the only relaxation of `unsafe_code` allowed in first-party code; their
/// other target roots (integration tests, benches, examples) carry `#![forbid(unsafe_code)]` like every crate
/// not listed here or in `UNSAFE_DENY_ONLY`.
pub(crate) const UNSAFE_ALLOWED: &[&str] = &["secmp-sys-mem", "secmp-sys-desktop"];

/// The one target root outside the two sys crates that may relax `unsafe_code` (ADR-038 (1)): the constant-time
/// bench reads the CPU cycle counter (`rdtscp` / `cntvct_el0`). Matched path-exactly (relative to the workspace
/// root) by the `policy` step; its header must carry `#![allow(unsafe_code)]` at the file top, nothing else. Moved
/// with the bench from `crates/secmp-crypto/benches/ct.rs` by ADR-042 (M3).
pub(crate) const UNSAFE_EXEMPT_ROOT: &str = "crates/secmp-testkit/benches/ct.rs";

/// Crates that carry `#![deny(unsafe_code)]` instead of `forbid`, because `slint::slint!` expansions contain
/// `#[allow(unsafe_code)]` (E0453 under `forbid`; docs/06 §2 (b), ADR-033). Their own `.rs` files may contain
/// neither the token `unsafe` nor any relaxation of `unsafe_code`.
pub(crate) const UNSAFE_DENY_ONLY: &[&str] = &["secmp-ui"];

/// Crates whose normal (shipped) dependency closure must have zero cargo-vet exemptions (docs/06 §3, ADR-036).
pub(crate) const ZERO_EXEMPTION_ROOTS: &[&str] = &["secmp-crypto", "secmp-proto"];

/// The targets over which that closure is taken and united: the `[graph] targets` of `deny.toml` (the two
/// shipped targets and the development host, ADR-029).
pub(crate) const VET_CLOSURE_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "aarch64-apple-darwin",
];

/// Workspace binaries (hello-world banner in M0; SBOM + `cargo auditable` release builds).
pub(crate) const BINARIES: &[&str] = &["secmp-relay", "secmp-cli", "secmp-ui"];

/// `RustSec` advisories that `cargo audit` (docs/06 §5 step 3) ignores, as (id, reason). An entry needs an ADR
/// (`deny.toml`: "An advisory may only be ignored with an ADR and a reason") and is re-triaged at every release.
/// The gate prints every ignored id in its result line.
pub(crate) const AUDIT_IGNORES: &[(&str, &str)] = &[(
    "RUSTSEC-2026-0173",
    "ADR-037: proc-macro-error2 (unmaintained) is in Cargo.lock only as a cfg(hax) dependency of hax-lib-macros \
     and is never compiled for any target; cargo deny, which evaluates the per-target graph, does not report it",
)];

/// Packages exposing the `kat` feature (docs/06 §5 step 5): external KATs, differential tests, vector checks; M3:
/// `secmp-proto` (derandomised TR entry points for the vectors and the ct bench, ADR-042).
pub(crate) const KAT_PACKAGES: &[&str] = &["secmp-crypto", "secmp-proto", "secmp-testkit"];

/// ADR-041 (1), replacing the two tiers of ADR-038 (2): the |t| threshold of the `ct` gate — a target's shift counts
/// as reproduced if |t| exceeds it in both measurements at the same crop with the same sign; the positive control
/// must exceed it. (The immediate-FAIL tier above 10 is withdrawn.) The bench reads this line and the `CT_*` lines
/// below from this file at compile time, and the gate checks that the report echoes every one, so the values are
/// written down exactly once. Keep each on one line.
pub(crate) const CT_THRESHOLDS: f64 = 4.5;

/// ADR-041 (2) with Amendment 1 (1): a reproduced shift fails only if |Δ| of the cropped class means reaches the
/// effect floor `max(CT_EFFECT_FLOOR_QUANTA × q_eff, CT_EFFECT_FLOOR_NS)` (`q_eff`: the lattice spacing of the
/// samples, measured from the data); below it the report says `SUB_FLOOR_SHIFT`.
pub(crate) const CT_EFFECT_FLOOR_QUANTA: f64 = 1.0;

/// ADR-041 Amendment 1 (1): the absolute part of the effect floor, in ns (≈ one coarse timer lattice, ≈ 25 cycles);
/// the sensitivity control `min_leak_control` must reach the same floor in every run (Amendment 1 (2)), otherwise
/// the run is `CONTROL_FAIL`.
pub(crate) const CT_EFFECT_FLOOR_NS: f64 = 10.0;

/// ADR-041 (3): the inline A/A control of a run passes if its |t| is at most this at every crop of every target;
/// otherwise the run is `CONTROL_FAIL`.
pub(crate) const CT_AA_MAX_T: f64 = 4.5;

/// ADR-038 (3): the timer resolution may be at most this fraction of a sample's median; where a single call is
/// too short, one sample batches `k = ceil(quantum / (fraction · median))` calls.
pub(crate) const CT_RESOLUTION_MAX_FRACTION: f64 = 0.01;

/// ADR-038 (3): the largest batch size; a target that would need more is NOT MEASURABLE on that runner.
pub(crate) const CT_MAX_BATCH: u32 = 64;

/// ADR-038 (3), amended 2026-09-29 (M1 review F8): the calibration aims at this multiple of the resolution bound,
/// a 10 % margin: `k = ceil(110 · quantum / median)` with the 1 % fraction above.
pub(crate) const CT_BATCH_MARGIN: f64 = 1.1;

/// ADR-038 (3), amended 2026-09-29: a measurement whose realised batch median is below this many timer quanta
/// is NOT MEASURABLE for that target (from here up to 100 the realised count is informative only).
pub(crate) const CT_MIN_REALISED_QUANTA: u64 = 80;

/// Samples per measurement of every ct target but `sas` (docs/06 §4; M2 review C3 (c): fixed here, echoed by the
/// report, checked per target by the gate). `SECMP_CT_SCALE` may shorten them in local runs only: the report then
/// carries `secmp_ct_scale`, which the gate refuses, and the gate unsets the variable for its own run.
pub(crate) const CT_SAMPLES: usize = 1_000_000;

/// Samples per measurement of `sas` (`SafetyNumber::new`, Argon2id: about a millisecond per call).
pub(crate) const CT_SAS_SAMPLES: usize = 20_000;

/// The ct targets (M2 review C3 (a)): the gate refuses a report whose target set differs. Exactly one of them, the
/// positive control, is measured once and must be detected. M3: the three SecMP-TR rejection targets
/// `tr_decrypt_reject_*` (plan D9: `RatchetState::decrypt_with` on one fixed receiver state), the A/A′ placement
/// control (ADR-042) and the same-content control (ADR-042 Amendment 2).
pub(crate) const CT_TARGETS: &[&str] = &[
    "control_variable_time_compare",
    "tag_compare",
    "msg_open_reject",
    "caead_open_reject",
    "sas",
    "caead_derive",
    "caead_aead_reject",
    "caead_com_compare",
    "caead_open_reject_samekey",
    "aa_prime_control",
    "tr_decrypt_reject_hdr_key",
    "tr_decrypt_reject_body_tag",
    "tr_decrypt_reject_ct_pq",
    "same_content_control",
];

/// The positive control among [`CT_TARGETS`].
pub(crate) const CT_POSITIVE_CONTROL: &str = "control_variable_time_compare";

/// The A/A′ placement control among [`CT_TARGETS`] (ADR-042 (2), M2 review F6): judged like a target; a FAIL makes the
/// run `CONTROL_FAIL`, PASS and `SUB_FLOOR_SHIFT` pass. Not the positive control.
pub(crate) const CT_AA_PRIME_CONTROL: &str = "aa_prime_control";

/// The same-content control among [`CT_TARGETS`] (ADR-042 Amendment 2): identical contents in both classes through
/// the per-class preparation path, judged like a target; a FAIL makes the run `CONTROL_FAIL`, PASS and
/// `SUB_FLOOR_SHIFT` pass. Not the positive control.
pub(crate) const CT_SAME_CONTENT_CONTROL: &str = "same_content_control";

/// docs/07 M3 acceptance "encrypt+decrypt of a message < 3 ms" (M3 plan D11): the `perf` step fails if the maximum of
/// a kind of `crates/secmp-proto/examples/tr-perf.rs` (release profile; encrypt, persist, decrypt and commit of one
/// message) reaches this many milliseconds.
pub(crate) const TR_PERF_MAX_MS: f64 = 3.0;

/// The messages per kind of the `perf` report (`n=`, the example's `N`); a report with another count is refused.
pub(crate) const TR_PERF_MESSAGES: usize = 200;

/// The kinds of the `perf` report, each with `<kind>_median_us` and `<kind>_max_us`: a message on an established
/// chain, and a message that makes the receiver perform a DH step.
pub(crate) const TR_PERF_KINDS: &[&str] = &["chain", "step"];

/// cargo-fuzz targets under `fuzz/fuzz_targets/` (docs/06 §5 step 6): M1 key, ciphertext and signature parsers
/// and the two openers of `secmp-crypto`; M2 every `secmp-proto` decoder, one target per Appendix D section
/// (`proto_*`, a selector byte picks the decoder); M3 SecMP-TR `Decrypt` on a fixed receiver state (`tr_decrypt`)
/// and the TR persistence decoders (`tr_state`); M4 the invitation URI (`inv_uri`), the link data (`inv_linkdata`),
/// the three handshake structures (`hx_outer`, `hx_inner`, `hx_cell_plaintext`) and `Responder::accept` on raw and
/// on structurally mutated envelopes (`hx_accept_raw`, `hx_accept_structured`).
pub(crate) const FUZZ_TARGETS: &[&str] = &[
    "caead_open",
    "ed25519_verify",
    "hx_accept_raw",
    "hx_accept_structured",
    "hx_cell_plaintext",
    "hx_inner",
    "hx_outer",
    "hybrid_sign_verify",
    "inv_linkdata",
    "inv_uri",
    "mldsa65_verify",
    "mlkem_parse",
    "msg_open",
    "proto_cell",
    "proto_frames",
    "proto_handshake",
    "proto_invitation",
    "proto_records",
    "tr_decrypt",
    "tr_state",
    "x25519_dh",
];

/// Seconds per fuzz target of the `fuzz` gate (ci-full step 6, docs/06 §4: "≈2 min per target on every PR").
pub(crate) const FUZZ_SMOKE_SECONDS: u64 = 120;

/// libFuzzer's per-input `-timeout` in seconds for every target (M3; libFuzzer's default is 1200 s). The slowest
/// legitimate input is a `tr_decrypt` header that makes the receiver derive `MAX_FF` = 2^20 chain keys twice (a DH
/// step with the largest `pn` and `n`): 6.5 s measured on the M1 Pro in the fuzz build with the address sanitizer
/// (while a Kani run loaded the machine), so the cap leaves about a factor of 9; every other target's inputs take
/// milliseconds.
pub(crate) const FUZZ_INPUT_TIMEOUT_SECONDS: u64 = 60;

/// Seconds of the scheduled campaign (`.github/workflows/fuzz-nightly.yml`, docs/06 §4 "nightly 4 h"; M2 review F2),
/// shared equally by the fuzz targets: each gets `FUZZ_NIGHTLY_SECONDS / FUZZ_TARGETS.len()` seconds (M2: 12
/// targets, 1200 s each; M3: 14 targets, 1028 s each).
pub(crate) const FUZZ_NIGHTLY_SECONDS: u64 = 14_400;

/// libFuzzer `-max_len` per fuzz target (M2 review C4: without it libFuzzer caps inputs at the largest corpus file,
/// 5 397 B for `proto_cell` after `cargo fuzz cmin`). Each value is the target's largest valid input plus one byte
/// (so the too-long rejection is reached): the selector/mode bytes and split fields of the target, and each decoder
/// at its maximum with every length field at its maximum and every list at one element (a list of 255 maximal
/// elements would be megabytes). `crates/secmp-proto/tests/fuzz_max_len.rs` recomputes every entry from `sizes.rs`
/// and the `secmp-crypto` constants; one entry per line, as that test parses them.
/// - `caead_open`: mode 1 + nonce 24 + `ad_len` 1 + AD 255 + the largest `COM ‖ C` of the protocol (`LinkBlob`:
///   32 + 12288 + 16) = 12617.
/// - `ed25519_verify`: key 32 + signature 64 + the largest Ed25519-signed message (D.6 `SEND`, 4146) = 4242.
/// - `hybrid_sign_verify`: mode 1 + label 1 + `HybridSig` 3373 + the largest HybridSign message (the bundle's signed
///   fields 4402 ‖ `ik_dh` 32) = 7809.
/// - `mldsa65_verify`: mode 1 + the larger of a key (1952) and `ctx_len` 1 + context 255 + signature 3309 = 3566.
/// - `mlkem_parse`: mode 1 + the largest key or ciphertext (ML-KEM-1024, 1568) = 1569.
/// - `msg_open`: mode 1 + `ad_len` 1 + AD 255 + `C ‖ TAG` 1742 = 1999.
/// - `x25519_dh`: two secrets and a public key, 3 × 32 = 96.
/// - `proto_cell`: selector 1 + `HandshakeBody` (Profile 98 + `caps` 4 + count 1 + a `RouteDescriptor` of kind ≠ 1
///   with a 65535-byte blob, 65539) = 65643.
/// - `proto_frames`: selector 1 + a frame plaintext 4336 = 4337.
/// - `proto_handshake`: selector 1 + `Outer` 12018 = 12019.
/// - `proto_invitation`: selector 1 + `LinkBlob` 12360 = 12361.
/// - `proto_records`: selector 1 + the HS1 record (`len` 2 + type 1 + 2853) = 2857.
/// - `tr_decrypt`: mode 1 + the larger of a cell (4096) and a header plaintext (2314; mode ≠ 0) = 4097.
/// - `tr_state`: selector 1 + the larger of `RatchetStateV1` at its maximum (38 585, `skipped` full) and `InboxV1`
///   with one message of one maximal chunk (1694) = 38586.
/// - `inv_uri`: the URI of the largest `InvitationV1` (a 253-byte `direct` host: 530 B → 707 characters, 10 for the
///   prefix) = 717.
/// - `inv_linkdata`: mode 1 + the larger of an opened `LinkDataV1` (12288) and a `LinkBlob` (12360) = 12361.
/// - `hx_outer`: the padded `Outer` = 12018. `hx_inner`: `Inner` = 6113. `hx_cell_plaintext`: 4024.
/// - `hx_accept_raw`: count 1 + 12 cells of (selector 1 + 4096 raw bytes) = 49165.
/// - `hx_accept_structured`: selector 1 + the larger of `Padded` (12018), `Inner` (6113) and the `Outer` head (3177)
///   = 12019.
pub(crate) const FUZZ_MAX_LEN: &[(&str, usize)] = &[
    ("caead_open", 12_618),
    ("ed25519_verify", 4_243),
    ("hx_accept_raw", 49_166),
    ("hx_accept_structured", 12_020),
    ("hx_cell_plaintext", 4_025),
    ("hx_inner", 6_114),
    ("hx_outer", 12_019),
    ("hybrid_sign_verify", 7_810),
    ("inv_linkdata", 12_362),
    ("inv_uri", 718),
    ("mldsa65_verify", 3_567),
    ("mlkem_parse", 1_570),
    ("msg_open", 2_000),
    ("proto_cell", 65_644),
    ("proto_frames", 4_338),
    ("proto_handshake", 12_020),
    ("proto_invitation", 12_362),
    ("proto_records", 2_858),
    ("tr_decrypt", 4_098),
    ("tr_state", 38_587),
    ("x25519_dh", 97),
];

/// Packages under the mutation gate (docs/06 §4, §5 step 8).
pub(crate) const MUTANT_PACKAGES: &[&str] = &["secmp-crypto", "secmp-proto"];

/// Code compiled only under Kani (`#[cfg(kani)]`: `secmp-proto`'s harnesses and the `kani_stubs` modules), kept out
/// of the mutation gate by file and by mutant name: no test build contains it, so every mutant of it would survive
/// (M2: 52 such survivors in the CI run on `774e04a`); Kani runs it (ci-full step 9).
pub(crate) const MUTANT_EXCLUDE_FILES: &[&str] = &["crates/secmp-proto/src/kani_proofs.rs"];
/// Mutant names (regex, `cargo mutants --exclude-re`) excluded: `kani_stubs::` for the reason above; and (M3) the
/// `secmp-proto` code compiled only with `secmp-proto`'s own feature `kat` — the vector, test and bench tooling of
/// SecMP-TR (`tr::FixedEntropy`, the message-key digests, the header-key and `sb` accessors), never in a shipped
/// build. The gate builds `secmp-proto` without that feature (its `kat` tests — the `tr` vectors, generator and
/// property tests — take minutes, per mutant), so every mutant of that code would survive unbuilt (M3 local run: 27
/// such survivors). The `kat` step runs it: `tests/tr_vectors.rs` and `tests/tr_generator.rs` reproduce every byte
/// `FixedEntropy` supplies, the property tests check the digests.
pub(crate) const MUTANT_EXCLUDE_RE: &[&str] = &[
    "kani_stubs::",
    "FixedEntropy",
    "message_key_digest_kat",
    "replace mk_digest ",
    "RatchetState::(hk_s_kat|receiving_header_keys_kat|sb_kat)",
];

/// Packages run under Miri (docs/06 §4); M3: `secmp-proto` (M2 review F3).
pub(crate) const MIRI_PACKAGES: &[&str] = &[
    "secmp-sys-mem",
    "secmp-sys-desktop",
    "secmp-crypto",
    "secmp-proto",
];

/// The target Miri interprets, on every host. `libcrux-ml-kem` selects its backend at run time through
/// `libcrux-platform`, which executes `cpuid` (inline assembly, unsupported by Miri) on `x86`/`x86_64`; on `AArch64` the
/// selection is a compile-time constant (and the gate compiles libcrux's NEON backend out, since Miri cannot run
/// SIMD intrinsics). `secmp-sys-mem` uses its heap backend under Miri on every target.
pub(crate) const MIRI_TARGET: &str = "aarch64-unknown-linux-gnu";

/// Tests excluded from the `ci-full` Miri run for their run time (docs/06 §4: "under Miri (where feasible)"), as
/// (package, filter, reason); the weekly `miri-full` runs them, and they run natively on every target. The gate runs
/// Miri per package of [`MIRI_PACKAGES`] (`gates::miri_runs`), so a filter applies to its own package only. A filter
/// is either a libtest `--skip` substring of the test path (`module::tests::name`, or the function name of an
/// integration test; choose it so that it matches no other test of the package), or `test-target:<name>`, which
/// leaves out the whole integration-test target `tests/<name>.rs` (it must exist). To add an entry: measure the test
/// under Miri (`cargo +nightly-2026-09-21 miri test --locked --target aarch64-unknown-linux-gnu --package <p>
/// [--lib | --test <t>] <name> -- --exact --test-threads=1` with `LIBCRUX_DISABLE_SIMD128=1 LIBCRUX_DISABLE_SIMD256=1
/// CARGO_TARGET_DIR=target/miri-portable`; libtest's own `--report-time` shows Miri's virtual clock, not the host's)
/// and write the measured time into the reason. Measured M1 (macOS arm64, nightly-2026-09-21): one ML-DSA-65 test
/// takes about 25 minutes under Miri, the two modules together several hours. Measured M3 for `secmp-proto` (macOS
/// arm64, nightly-2026-09-21, host wall time per test with `--test-threads=1` on a shared machine;
/// `docs/reviews/M03-evidence/miri-secmp-proto-aarch64-apple-darwin.txt`): every test of 60 s or more is skipped
/// here — `secmp-proto` has no `unsafe` (`forbid(unsafe_code)`), so under Miri its tests re-check the dependencies'
/// `unsafe` code, which the kept tests reach on shorter inputs; the kept lib tests take about 5.4 min together.
pub(crate) const MIRI_SKIP: &[(&str, &str, &str)] = &[
    (
        "secmp-crypto",
        "mldsa::",
        "ML-DSA-65 key generation and signing take ~25 min per test under Miri",
    ),
    (
        "secmp-crypto",
        "hybrid_sign::",
        "HybridSign runs ML-DSA-65 (as above)",
    ),
    (
        "secmp-crypto",
        "sas::",
        "5200 SHA-256 iterations per half take ~10 min per test under Miri; SHA-256 itself runs under Miri in hash::",
    ),
    (
        "secmp-proto",
        "wire::inv::tests::iks_bundle_link_data_blob",
        "963 s under Miri (M3): prekey bundles with ML-KEM-768/1024 key generation and a HybridSign signature \
         (ML-DSA-65 key generation and signing)",
    ),
    (
        "secmp-proto",
        "wire::frame::tests::reserved_and_foreign_opcodes_reject",
        "444 s under Miri (M3): all 256 opcodes in both directions, each in a full 4336-byte frame",
    ),
    (
        "secmp-proto",
        "wire::cell::tests::fragment_payload_inner_types",
        "360 s under Miri (M3): a KeyChange payload with a HybridSign signature (ML-DSA-65 key generation and \
         signing) and every inner type",
    ),
    (
        "secmp-proto",
        "wire::cell::tests::key_change_receipt_control",
        "216 s under Miri (M3): a KeyChange body with a HybridSign signature (ML-DSA-65) and 255-entry receipts",
    ),
    (
        "secmp-proto",
        "wire::inv::tests::largest_link_data_fits_its_padding",
        "187 s under Miri (M3): a maximal LinkDataV1 with its prekey bundle (as iks_bundle_link_data_blob)",
    ),
    (
        "secmp-proto",
        "wire::frame::tests::fetch_multi_count_and_link_get_rules",
        "102 s under Miri (M3)",
    ),
    (
        "secmp-proto",
        "wire::frame::tests::every_request_round_trips_at_frame_size",
        "101 s under Miri (M3)",
    ),
    (
        "secmp-proto",
        "wire::frame::tests::every_response_round_trips_at_frame_size",
        "79 s under Miri (M3)",
    ),
    (
        "secmp-proto",
        "tr::tests::",
        "the SecMP-TR unit tests (M3): each builds a session — X25519 and ML-KEM-768 key generation, encapsulation \
         and decapsulation at every step — `reject_cell_length`, the lightest, takes 125 s under Miri, the 51 \
         together about 1.8 h (two fast-forward tests derive 2^20 chain keys each); `tests/tr_smoke.rs` (360 s) and \
         `tr::select`, `tr::entropy` stay under Miri",
    ),
    (
        "secmp-proto",
        "test-target:canonical",
        "the canonicality property tests (48 random values per structure, and the edge cases): edge_counters 508 s, \
         edge_enum_variants 764 s, edge_lengths 1561 s under Miri (M3); frames, handshake_envelope and \
         ratchet_cell_content_and_bodies had not finished after 50 min each when measured",
    ),
    (
        "secmp-proto",
        "canonical_writer_is_stable",
        "4082 s under Miri (M3): generates the 78 positive rows of the encodings suite",
    ),
];

/// Tests Miri cannot run at all, left out of `miri` and `miri-full` alike, as (package, filter, reason); same filter
/// rules as [`MIRI_SKIP`].
pub(crate) const MIRI_UNSUPPORTED: &[(&str, &str, &str)] = &[
    (
        "secmp-proto",
        "every_row_of_the_encodings_file",
        "reads vectors/encodings.json at run time: Miri's isolation refuses the file access (`statx` not available \
         when isolation is enabled) and aborts the test binary (M3); the rows run natively in nextest and kat",
    ),
    (
        "secmp-proto",
        "the_rust_generator_reproduces_every_positive_row",
        "reads vectors/encodings.json before anything else (by reading the test; Miri never reached it, since the \
         refused file access of every_row_of_the_encodings_file aborted the test binary first)",
    ),
];

/// Packages containing Kani harnesses (docs/06 §4). M2: `secmp-proto` (`src/kani_proofs.rs`).
pub(crate) const KANI_PACKAGES: &[&str] = &["secmp-proto"];

/// The Kani harnesses (M2 review C5): the gate refuses a run unless Kani reports exactly these as successfully
/// verified ("Complete - N successfully verified harnesses, 0 failures, N total." with N = this count), so a
/// deleted or renamed harness fails the gate instead of passing silently. M3 (plan step 9): the three `tr_*`
/// harnesses of the SecMP-TR decisions (`tr::select`).
pub(crate) const KANI_HARNESSES: &[&str] = &[
    "kani_proofs::cell",
    "kani_proofs::header_v1",
    "kani_proofs::header_v1_reencodes",
    "kani_proofs::padding",
    "kani_proofs::request_cont",
    "kani_proofs::request_fetch",
    "kani_proofs::request_fetch_multi",
    "kani_proofs::request_frame",
    "kani_proofs::request_link_get",
    "kani_proofs::request_link_put",
    "kani_proofs::request_ping",
    "kani_proofs::request_queue_del",
    "kani_proofs::request_queue_new",
    "kani_proofs::request_send",
    "kani_proofs::request_skey",
    "kani_proofs::response_frame",
    "kani_proofs::tr_eviction",
    "kani_proofs::tr_header_selection",
    "kani_proofs::tr_skip_plan",
];

/// The SecMP vector suites (`vectors/SCHEMA.md` §3): frozen as `vectors/<suite>.json`, reference files
/// `vectors/ref/<suite>.json`, Rust files `vectors/rust/<suite>.json` (docs/06 §5 step 12a). M2–M5 add suites.
pub(crate) const VECTOR_SUITES: &[&str] = &[
    "caead",
    "encodings",
    "fingerprint",
    "hkdf-labels",
    "hx",
    "hybridkem-1024",
    "hybridkem-768",
    "hybridsign",
    "msgencrypt",
    "sas",
    "tr",
];

/// Reference files committed before their suite is generated by the Rust side and frozen: present as
/// `vectors/ref/<suite>.json`, absent from `vectors/`. The `ref-vectors` step requires each to be present and
/// well-formed (JSON, `suite` = its name, a non-empty `cases` array) and compares nothing yet. Moving a suite from
/// here to `VECTOR_SUITES` is its freeze step (M2: `encodings`, frozen in `docs/reviews/M02-report.md` plan step 10;
/// M3: `tr`, committed with the M3 brief and frozen in `docs/reviews/M03-report.md` plan step 6; M4: `hx`, committed
/// with the M4 plan commit and frozen in `docs/reviews/M04-report.md` plan step 5). None pending.
pub(crate) const VECTOR_REF_PENDING: &[&str] = &[];

/// Suites whose Rust generator writes the positive rows only (M2 cross-generates the `encodings` positives, docs/07
/// M2 deliverables): `cargo xtask vectors` compares the header and the positive rows, and requires the decoders to
/// reject every other row of the reference file (`secmp-proto` test `encodings_ref`) before the freeze.
pub(crate) const VECTOR_POSITIVE_ONLY: &[&str] = &["encodings"];

/// ProVerif models under `formal/` (docs/06 §5 step 10). M3 adds `tr.pv`, M4 `hx.pv`, M5 `link.pv`.
pub(crate) const PROVERIF_MODELS: &[&str] = &["tr"];

/// What one ProVerif `RESULT` line must say (`formal/CLAIMS.md`, gate rule).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Proved {
    /// "… is true.": the property is proved.
    True,
    /// "… is false.": ProVerif reports an attack (the sanity queries).
    False,
    /// Any outcome (documented, not a gate).
    Informative,
}

/// The expected `RESULT` lines of one model: runs of (CLAIMS ID, number of lines, expected verdict), in order.
pub(crate) type ProverifRuns = &'static [(&'static str, usize, Proved)];

/// The expected `RESULT` lines of each model of [`PROVERIF_MODELS`], in the order ProVerif prints them, as runs of
/// (`formal/CLAIMS.md` ID, number of lines, expected verdict). The `proverif` step expands the runs and compares line
/// by line (`gates::proverif_check`, M3 plan D10): the number of lines must match, a `True` line must be proved, a
/// `False` line must be an attack, an `Informative` line may say anything; a test checks the verdicts against the
/// "Expected" column of `formal/CLAIMS.md`.
///
/// `tr` (M3, 39 lines; CLAIMS §TR gate rule: T1–T6, T8, T9, T11 true, T7 and T10 false, T12 informative): T1 the six
/// contents of steps 1–3 (n = 0, 1); T2 both directions; T3 the four contents of steps 1–2; T4, T5, T6 and T7 the two
/// contents of step 3 each; T8 per step `dh_pk` and `ek_pq` of its header and `n` of both messages (twelve); T9 the
/// same four fields of step 1; T10 one content; T11 and T12 one query each (T12: the model gives false).
pub(crate) const PROVERIF_EXPECTED: &[(&str, ProverifRuns)] = &[(
    "tr",
    &[
        ("T1", 6, Proved::True),
        ("T2", 2, Proved::True),
        ("T3", 4, Proved::True),
        ("T4", 2, Proved::True),
        ("T5", 2, Proved::True),
        ("T6", 2, Proved::True),
        ("T7", 2, Proved::False),
        ("T8", 12, Proved::True),
        ("T9", 4, Proved::True),
        ("T10", 1, Proved::False),
        ("T11", 1, Proved::True),
        ("T12", 1, Proved::Informative),
    ],
)];

/// systemd units under `deploy/` checked with `systemd-analyze security --offline` (docs/06 §5 step 14,
/// exposure ≤ 2.0). M10 adds `secmp-relay.service`.
pub(crate) const SYSTEMD_UNITS: &[&str] = &[];

/// Maximum systemd exposure level (docs/05 §4, docs/06 §5 step 14).
pub(crate) const SYSTEMD_MAX_EXPOSURE: f64 = 2.0;

/// Line-coverage thresholds in percent (docs/06 §4): `secmp-crypto` and `secmp-proto` ≥ 90, every other
/// shipped crate ≥ 80. `xtask` is build tooling and not measured.
pub(crate) const COVERAGE_STRICT: &[&str] = &["secmp-crypto", "secmp-proto"];
pub(crate) const COVERAGE_STRICT_MIN: f64 = 90.0;
pub(crate) const COVERAGE_MIN: f64 = 80.0;

/// Every lint-relaxing attribute (`allow`, `expect`, `warn`, also inside `cfg_attr`) in first-party Rust code,
/// as (path relative to the workspace root, lint, reason). Anything not listed fails the `policy` step.
/// Deny-level lints (every `clippy::all` lint, `unsafe_code`, `unused_must_use` and the explicit deny list of
/// docs/06 §2) may only appear here for the sites sanctioned by docs/06 §2 — the `SystemTime::now` sites
/// (`secmp-client-core::clock`, the relay's hour bucket, `secmp-cli` output timestamps); none exist in M0.
/// The docs/06 §2 test allowance (`#![allow(clippy::unwrap_used, clippy::expect_used)]` at the top of a file
/// under `tests/`, `fuzz/` or `crates/secmp-testkit/`) is handled by rule and needs no entry.
pub(crate) const LINT_ALLOWANCES: &[(&str, &str, &str)] = &[];

/// The only lints the docs/06 §2 test-file allowance may relax.
pub(crate) const TEST_FILE_ALLOWANCE: &[&str] = &["clippy::unwrap_used", "clippy::expect_used"];

/// Path prefixes (relative to the workspace root) where the test-file allowance applies.
pub(crate) const TEST_FILE_PREFIXES: &[&str] = &["fuzz/", "crates/secmp-testkit/"];

/// CI jobs that may use `continue-on-error: true`. None: Amendment A1 §5 allowed it for the cargo-xwin
/// cross-build in M0 only, and the M0 review (condition C1) made that job a hard gate from M1 on.
pub(crate) const CONTINUE_ON_ERROR_JOBS: &[&str] = &[];

/// The workflow that holds the required checks of the `main-protection` ruleset (docs/06 §4).
pub(crate) const REQUIRED_WORKFLOW: &str = ".github/workflows/ci.yml";

/// The job names of the required checks (M2 review C2): they exist only in [`REQUIRED_WORKFLOW`], which has no
/// `workflow_dispatch` trigger, so no dispatch can add a `skipped` (= passing) check run under a required name.
pub(crate) const REQUIRED_JOBS: &[&str] =
    &["linux-fast", "windows-native", "xwin-cross", "linux-full"];

/// The job-level `if:` of every required job, `None` for none (external review EXT-1, M3 follow-up F19): the policy
/// step refuses any other condition — a condition that evaluates to false on `pull_request` would leave a `skipped`
/// check run under a required name, which GitHub counts as passing. `linux-full` excludes only `push` (on `main`),
/// by design since the M2 workflow change; the other three run on every event.
pub(crate) const REQUIRED_JOB_CONDITIONS: &[(&str, Option<&str>)] = &[
    ("linux-fast", None),
    ("windows-native", None),
    ("xwin-cross", None),
    (
        "linux-full",
        Some("github.event_name == 'schedule' || github.event_name == 'pull_request'"),
    ),
];
