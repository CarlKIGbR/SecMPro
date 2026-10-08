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
/// `secmp-proto` (derandomised TR entry points for the vectors and the ct bench, ADR-042); M5: `secmp-relay` (the
/// store snapshot and digest, the live-buffer count and the event capture of its test crate `relay`).
pub(crate) const KAT_PACKAGES: &[&str] = &[
    "secmp-crypto",
    "secmp-proto",
    "secmp-relay",
    "secmp-testkit",
];

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

/// ADR-045 Amendment 1 (M4 review C-1): the wall-clock budget of the bench run of the `ct` step, in seconds. At
/// expiry the gate kills the bench and fails naming the target and phase of the last line of
/// `target/ct-progress.jsonl`. 290 min: 40 min below the 330 min of the `ct` job of `ci.yml` and of `ci-dispatch.yml`
/// `dispatch-ct` (build and setup fit in the rest; delta review VD1-2).
pub(crate) const CT_STEP_TIMEOUT_SECONDS: u64 = 17_400;

/// Samples per measurement of `sas` (`SafetyNumber::new`, Argon2id: about a millisecond per call).
pub(crate) const CT_SAS_SAMPLES: usize = 20_000;

/// The ct targets (M2 review C3 (a)): the gate refuses a report whose target set differs. Exactly one of them, the
/// positive control, is measured once and must be detected. M3: the three SecMP-TR rejection targets
/// `tr_decrypt_reject_*` (plan D9: `RatchetState::decrypt_with` on one fixed receiver state), the A/A′ placement
/// control (ADR-042) and the same-content control (ADR-042 Amendment 2). M4: `tr_decrypt_reject_skipped` (M3 review
/// R-04, F2; WEISUNG M4-4: the skipped path, entry 0 vs entry 4 of nine under the first of three distinct skipped
/// header keys — the opening trial is the same, R-59) and the INV/HX targets of
/// TEST-SPEC-M4 (f): `inv_fingerprint_compare` (`inv::invitee_check`, §5.5 step 3), `x25519_zero_check`
/// (`X25519Secret::diffie_hellman`, §3, §6.4), `hx_accept_reject_inner` and `hx_accept_reject_first_msg`
/// (`Responder::accept`, §6.6 steps 2 and 3); M4 review C-2: the HX same-content control (ADR-042 Amendment 3). M5,
/// TEST-SPEC-M5 (g): CT-01 `link_hs1_reject_mac1` (the relay's `mac1` compare, §8.3), CT-02 `link_hs2_reject_mac2`
/// (the client's `mac2` compare, §8.3), CT-03 `link_frame_open_reject` (`Link::open`, §8.4), CT-04
/// `q_queue_new_reject_token` (`link::ids::token_verify`, §9.6), CT-05 `tr_decrypt_trial_open_position` (§7.4, the
/// opening trial's position among 2 distinct skipped header keys; M4 review R-42, campaign R-59) and CT-06 the LINK
/// same-content control [`CT_LINK_SAME_CONTENT_CONTROL`].
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
    "tr_decrypt_reject_skipped",
    "same_content_control",
    "inv_fingerprint_compare",
    "x25519_zero_check",
    "hx_accept_reject_inner",
    "hx_accept_reject_first_msg",
    "hx_same_content_control",
    "link_hs1_reject_mac1",
    "link_hs2_reject_mac2",
    "link_frame_open_reject",
    "q_queue_new_reject_token",
    "tr_decrypt_trial_open_position",
    "link_same_content_control",
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

/// The HX same-content control among [`CT_TARGETS`] (ADR-042 Amendment 3, M4 review C-2): the class-1 cells of
/// `hx_accept_reject_inner` in both classes through the HX preparation path, judged like [`CT_SAME_CONTENT_CONTROL`]: a
/// FAIL makes the run `CONTROL_FAIL`, PASS and `SUB_FLOOR_SHIFT` pass. Not the positive control.
pub(crate) const CT_HX_SAME_CONTENT_CONTROL: &str = "hx_same_content_control";

/// The LINK same-content control among [`CT_TARGETS`] (TEST-SPEC-M5 CT-06; the ADR-042 Amendment 2 rule: a new
/// artefact class gets its control): `Link::open` of the class-1 frame of `link_frame_open_reject` (4352 B, the
/// largest LINK blend) in both classes through the LINK preparation path, judged like [`CT_SAME_CONTENT_CONTROL`]: a
/// FAIL makes the run `CONTROL_FAIL`, PASS and `SUB_FLOOR_SHIFT` pass. Not the positive control.
pub(crate) const CT_LINK_SAME_CONTENT_CONTROL: &str = "link_same_content_control";

/// M4 review R-47 (TEST-SPEC-M5 X-08): the reject site each ct target that claims one is bound to — the site of its
/// claim in `crates/secmp-testkit/benches/ct.rs`, one of [`KNOWN_SITES`]. The gate (`gates::ct_site_lines`) refuses a
/// report in which a listed target claims another site or none, or a target not listed here claims a site, so a
/// bench edit that re-aims a target at another (known) site fails unless this table changes in the same reviewed
/// commit. The SecMP-LINK/Q targets claim no site (the LINK layer tags none, spec §8.5; their pre-check is the
/// positive twin) and are not listed.
pub(crate) const CT_TARGET_SITES: &[(&str, &str)] = &[
    ("tr_decrypt_reject_hdr_key", "header: no key opened"),
    ("tr_decrypt_reject_body_tag", "body MAC"),
    ("tr_decrypt_reject_ct_pq", "kem constancy"),
    ("tr_decrypt_reject_skipped", "body MAC"),
    ("same_content_control", "body MAC"),
    ("inv_fingerprint_compare", "fingerprint"),
    (
        "x25519_zero_check",
        "§3/§6.4 all-zero check of the output (passes: not a reject target)",
    ),
    ("hx_accept_reject_inner", "inner open"),
    ("hx_accept_reject_first_msg", "first_msg decrypt"),
    ("hx_same_content_control", "inner open"),
    ("tr_decrypt_trial_open_position", "body MAC"),
];

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
/// on structurally mutated envelopes (`hx_accept_raw`, `hx_accept_structured`); M5 (Phase A) the SecMP-LINK record
/// decoders (`link_records`), the client and the relay side of the handshake (`link_client_handshake`,
/// `link_relay_handshake`), `Link::open` (`link_frame_open`) and the D.2 frame-plaintext decoders (`q_request_decode`,
/// `q_response_decode`); `hx_accept_structured` gains its mode 3 (M4 review R-44); M5 (Phase B) the relay's executor
/// on structured, honestly signed command scripts (`relay_executor`, FZ-07) and a relay connection on honestly
/// sealed arbitrary plaintexts with `LINK_PUT`/`CONT` interleavings (`relay_link_session`, FZ-08).
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
    "link_client_handshake",
    "link_frame_open",
    "link_records",
    "link_relay_handshake",
    "mldsa65_verify",
    "mlkem_parse",
    "msg_open",
    "proto_cell",
    "proto_frames",
    "proto_handshake",
    "proto_invitation",
    "proto_records",
    "q_request_decode",
    "q_response_decode",
    "relay_executor",
    "relay_link_session",
    "tr_decrypt",
    "tr_state",
    "x25519_dh",
];

/// Fuzz targets that rely on their tracked corpus (`fuzz/corpus/<target>/`) alone, because the frozen suite their
/// seeding rule would read is not frozen yet (`xtask::fuzzseed`: a rule names a suite of [`VECTOR_SUITES`]).
/// M5 Phase A: the six SecMP-LINK/Q targets read the `link` suite, which is frozen in Phase B (TEST-SPEC-M5 X-01,
/// V-22); Phase B moved them out of this list with their seeding rules once `link` was frozen (the unit test
/// `the_rules_name_listed_targets_and_frozen_suites` fails if a listed target has both). M5 Phase B: the two relay
/// targets (TEST-SPEC-M5 FZ-07, FZ-08) are structured — their input is a command script that the harness signs,
/// tokens and seals (`fuzz/fuzz_targets/relay_*.rs` headers), a layout no frozen suite has — so they rely on their
/// tracked seeds (`fuzz/corpus/relay_executor/`, `fuzz/corpus/relay_link_session/`, M4 C-6).
#[cfg(test)]
pub(crate) const FUZZ_TRACKED_ONLY: &[&str] = &["relay_executor", "relay_link_session"];

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
///   = 12019. M5 mode 3 (a padded `Content`, 1710) is shorter.
/// - `link_records`: selector 1 + the HS1 record (`len` 2 + type 1 + 2853, the largest of the four) = 2857.
/// - `link_client_handshake`: selector 1 + flag byte 1 + the `RELAYINFO` record (`len` 2 + type 1 + 1741; mode 0, the
///   structured modes take at most 112) = 1746.
/// - `link_relay_handshake`: selector 1 + the HS1 record (2856) = 2857.
/// - `link_frame_open`: selector 1 + a unit of 4352 B (the other modes take at most 4339) = 4353.
/// - `q_request_decode`: selector 1 + a frame plaintext 4336 = 4337.
/// - `q_response_decode`: mode 1 + a frame plaintext 4336 = 4337.
/// - `relay_executor`: a script the harness reads at most 160 commands of, after the configuration byte: 1 + 160 ×
///   27 (the longest command, `FETCH_MULTI` with 12 entries: opcode, `cmd_seq`, count, 12 × (key, ack)) = 4321.
/// - `relay_link_session`: the configuration byte and at most 16 units of at most 4339 bytes (split, kind, `u16`
///   length, a 4335-byte plaintext) = 69425.
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
    ("link_client_handshake", 1_747),
    ("link_frame_open", 4_354),
    ("link_records", 2_858),
    ("link_relay_handshake", 2_858),
    ("mldsa65_verify", 3_567),
    ("mlkem_parse", 1_570),
    ("msg_open", 2_000),
    ("proto_cell", 65_644),
    ("proto_frames", 4_338),
    ("proto_handshake", 12_020),
    ("proto_invitation", 12_362),
    ("proto_records", 2_858),
    ("q_request_decode", 4_338),
    ("q_response_decode", 4_338),
    ("relay_executor", 4_322),
    ("relay_link_session", 69_426),
    ("tr_decrypt", 4_098),
    ("tr_state", 38_587),
    ("x25519_dh", 97),
];

/// Packages under the mutation gate (docs/06 §4, §5 step 8); M5: `secmp-relay`, the relay security kernel (ADR-047
/// Amendment 3, OPEN-M5-12).
pub(crate) const MUTANT_PACKAGES: &[&str] = &["secmp-crypto", "secmp-proto", "secmp-relay"];

/// ADR-047 Amendment 1 (2): the shards of the mutation gate in CI — the matrix job `mutants-shard` of `ci.yml` runs
/// `cargo xtask step --strict mutants --shard K/8` for K = 0…7, and the job `mutants` (`step mutants-merge`) merges
/// their results and gives the verdict.
pub(crate) const MUTANT_SHARDS: usize = 8;

/// ADR-047 Amendment 2 (1) (replacing the unviable cap of Amendment 1 (4), M4 review R-06): the floor per package of
/// [`MUTANT_PACKAGES`] — at least one caught mutant, and caught at least this percentage of all the package's generated
/// mutants (caught + missed + unviable + timeout); otherwise the merge fails naming the package.
pub(crate) const MUTANT_MIN_CAUGHT_PERCENT: usize = 50;

/// ADR-047 Amendment 2 (2): an unviable share above this percentage of a package's mutants is printed as a WARNING in
/// the verdict text and the job summary, never a failure (PR run 37127247911: `secmp-crypto` 99 of 268 = 36.9 %, all
/// `FnValue` replacements needing `Default` on types that have none by design).
pub(crate) const MUTANT_UNVIABLE_WARN_PERCENT: usize = 35;

/// ADR-047 Amendment 1 (5), M4 review R-05: tests left out of the test run of every mutant (libtest `--skip` filters
/// after `cargo mutants … -- --`, each matching only its test), as (name, reason). The `kat` and `nextest` steps still
/// run them; the same bound is checked quickly by `select::tests::skip_plan_bounds`, the Kani harness `tr_skip_plan`,
/// vector N10 and the property tests.
pub(crate) const MUTANT_SKIP_TESTS: &[(&str, &str)] = &[
    (
        "ratchet_fast_forward_bound_on_the_chain",
        "secmp-proto tr::tests (feature kat): 2 × 2^20 KDF_CK, 49–110 s per run on CI",
    ),
    (
        "ratchet_fast_forward_bound_on_a_step",
        "secmp-proto tr::tests (feature kat): 3 × 2^20 KDF_CK, 37–73 s per run on CI",
    ),
];

/// ADR-047 Amendment 1, with the budget rule of ADR-045 Amendment 1: the wall-clock budget of one run of the `mutants`
/// step (one shard in CI), in seconds; at expiry the gate stops cargo-mutants and fails naming the last line of its
/// output. 280 min: 20 min below the `mutants-shard` job of `ci.yml` (300 min), whose setup fits in the rest.
pub(crate) const MUTANTS_STEP_TIMEOUT_SECONDS: u64 = 16_800;

/// Code compiled only under Kani (`#[cfg(kani)]`: `secmp-proto`'s harnesses and the `kani_stubs` modules), kept out
/// of the mutation gate by file and by mutant name: no test build contains it, so every mutant of it would survive
/// (M2: 52 such survivors in the CI run on `774e04a`); Kani runs it (ci-full step 9).
pub(crate) const MUTANT_EXCLUDE_FILES: &[&str] = &[
    "crates/secmp-proto/src/kani_proofs.rs",
    "crates/secmp-relay/src/kani_proofs.rs",
];
/// Mutant names (regex, `cargo mutants --exclude-re`) excluded: `kani_stubs::` for the reason above; and (M3) the
/// `secmp-proto` code compiled only with `secmp-proto`'s own feature `kat` — the vector, test and bench tooling of
/// SecMP-TR (`tr::FixedEntropy`, the message-key digests, the header-key and `sb` accessors, and (M4)
/// `encrypt_padded_kat`), never in a shipped build. Since R-60 the gate builds with feature `kat` (`--features kat` for
/// both packages since ADR-047 Amendment 1; the HX integration suite is `required-features`); the exclusion stays, as
/// these functions are tooling, not product code. Formerly
/// the gate built without it, so every mutant of that code would survive unbuilt (M3 local run: 27 such survivors; M4 local run on `tr/ratchet.rs` 2026-10-02: 1,
/// `encrypt_padded_kat`). The `kat` step runs it: `tests/tr_vectors.rs` and `tests/tr_generator.rs` reproduce every
/// byte `FixedEntropy` supplies, the `hx` suite's generator (`tests/common/hx_gen.rs`) seals its padded first
/// messages with `encrypt_padded_kat`, the property tests check the digests.
pub(crate) const MUTANT_EXCLUDE_RE: &[&str] = &[
    "kani_stubs::",
    "FixedEntropy",
    "message_key_digest_kat",
    "replace mk_digest ",
    "RatchetState::(hk_s_kat|receiving_header_keys_kat|sb_kat|encrypt_padded_kat)",
    // cfg(kani)-only helpers (M4-12): not compiled in the mutants build
    "Groups<.*>::(get|remove_completed) ",
    // error text, no logic (M4-12)
    "impl (core::fmt::)?Display for \\w+Error>::fmt",
];

/// The reject sites a `ct` target may claim (M4 review R-63): every site name in use, in one place (M4 review C-14:
/// `gates::tests::known_sites_equal_the_product_site_tags` checks the set against the product's tags). The product tags
/// them under feature `kat` (`tr::DECRYPT_SITE_KAT`, `inv::INVITEE_SITE_KAT`, `hx::ACCEPT_SITE_KAT`); the bench's
/// claims (`crates/secmp-testkit/benches/ct.rs`) name one of them (the `x25519_zero_check` claim names the all-zero
/// check, which passes: it is no reject target). A new site is added here with the code that sets it, so a claim with
/// a misspelt or retired site fails the gate instead of being reported as it stands.
pub(crate) const KNOWN_SITES: &[&str] = &[
    // SecMP-TR (`tr::ratchet`, §7.4)
    "cell length",
    "header: no key opened",
    "skipped: (hk, n) not stored",
    "header decode",
    "body MAC",
    "kem constancy",
    "counter rule",
    "dh_pk",
    "body decode",
    // SecMP-INV (`inv`, `wire::inv`, §5.5)
    "uri",
    "invitation decode",
    "blob open",
    "linkdata decode",
    "opk_present",
    "expired",
    "fingerprint",
    "bundle signature",
    "bundle expired",
    // SecMP-HX (`hx`, §6.5, §6.6)
    "no complete group",
    "outer",
    "x25519",
    "inner open",
    "inner checks",
    "first_msg decrypt",
    "first_msg checks",
    "opk delete",
    // the Output claim of `x25519_zero_check`
    "§3/§6.4 all-zero check of the output (passes: not a reject target)",
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
/// Measured M4 (`x86_64` GitHub runner, `linux-full` run 37127247911;
/// `docs/reviews/M04-evidence/linux-full-37127247911-miri-excerpt.txt`): the 67 kept `secmp-proto` lib tests took
/// 7232 s, six of them 60 s or more, which the same 60-s rule skips.
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
    (
        "secmp-proto",
        "test-target:hx_persist",
        "731 s, 573 s and 699 s per test under Miri (M4-fix, measured on 7a38edd, 2003 s in all; \
         docs/reviews/M04-evidence/miri-hx-persist-7a38edd.txt): each test generates two identities (ML-DSA-65 key \
         generation) and runs a full handshake; the fourth test (release_persists_the_state_at_release_time, M4 \
         review C-8) is of the same kind",
    ),
    (
        "secmp-proto",
        "tr::ratchet::trial_work::trial_opens_every_candidate_every_call",
        "5392 s under Miri (M4, linux-full run 37127247911, x86_64 GitHub runner; \
         docs/reviews/M04-evidence/linux-full-37127247911-miri-excerpt.txt): 3 fixtures x 7 cells, each decrypt \
         trial-opens every skipped header key; the kept `tests/tr_smoke.rs` runs a session through the same \
         AEAD, X25519 and ML-KEM code",
    ),
    (
        "secmp-proto",
        "wire::cell::tests::read_routes_pre_sizes_the_vector",
        "553 s under Miri (M4, linux-full run 37127247911, x86_64 GitHub runner; \
         docs/reviews/M04-evidence/linux-full-37127247911-miri-excerpt.txt): encodes and decodes 1, 10 and 255 \
         relay-queue routes; `wire::cell::tests::handshake_body_caps_and_routes` decodes one route \
         through the same `RouteDescriptor` and `Zeroizing` code",
    ),
    (
        "secmp-proto",
        "tr::ratchet::single_conversion::any_skipped_single_conversion",
        "520 s under Miri (M4, linux-full run 37127247911, x86_64 GitHub runner; \
         docs/reviews/M04-evidence/linux-full-37127247911-miri-excerpt.txt): a session with six cells through \
         skipped-key, chain, step and rejection paths; the kept `tests/tr_smoke.rs` reaches the same \
         `RatchetState::open` code and dependency `unsafe` code",
    ),
    (
        "secmp-proto",
        "wire::cell::tests::routes",
        "90 s under Miri (M4, linux-full run 37127247911, x86_64 GitHub runner; \
         docs/reviews/M04-evidence/linux-full-37127247911-miri-excerpt.txt): route descriptors up to a 65535-byte \
         unknown blob and a route update; `wire::cell::tests::handshake_body_caps_and_routes` reaches the same \
         route codec on shorter inputs",
    ),
    (
        "secmp-proto",
        "wire::cell::tests::app_message_and_batch",
        "85 s under Miri (M4, linux-full run 37127247911, x86_64 GitHub runner; \
         docs/reviews/M04-evidence/linux-full-37127247911-miri-excerpt.txt): every app kind, a 65535-byte message \
         and batches; `wire::cell::tests::content_types_padding_and_limits` (26 s) and \
         `wire::cell::tests::header` (22 s) reach the same codec code on shorter inputs",
    ),
    (
        "secmp-proto",
        "tr::entropy::tests::os_entropy_draws_fresh_values",
        "66 s under Miri (M4, linux-full run 37127247911, x86_64 GitHub runner; \
         docs/reviews/M04-evidence/linux-full-37127247911-miri-excerpt.txt): draws X25519, ML-KEM-768 and nonce \
         values from the OS and runs one encapsulation; `test_entropy_fails_after_its_budget` (46 s) and \
         `keys::tests::mlkem_fields` (40 s) reach the same ML-KEM code",
    ),
];

/// Integration-test targets with `required-features` that no Miri run builds (`miri` and `miri-full` run without
/// features; naming such a target would make cargo refuse the run), as (package, test target, reason). M4 review C-4
/// (R-12): the Miri gate fails unless this list equals the package's test targets with `required-features`, in both
/// directions; every one of them runs natively in the `kat` step (and `nextest`).
pub(crate) const MIRI_FEATURE_GATED: &[(&str, &str, &str)] = &[
    (
        "secmp-proto",
        "link",
        "required-features = [\"kat\"]: the replay of the SecMP-LINK vector groups (M5), natively in the kat step",
    ),
    (
        "secmp-proto",
        "hx",
        "required-features = [\"kat\"]: the SecMP-HX integration suite (M4), natively in the kat step",
    ),
    (
        "secmp-proto",
        "tr_generator",
        "required-features = [\"kat\"]: the SecMP-TR vector generator test (M3), natively in the kat step",
    ),
    (
        "secmp-proto",
        "tr_properties",
        "required-features = [\"kat\"]: the SecMP-TR property tests (M3), natively in the kat step",
    ),
    (
        "secmp-proto",
        "tr_vectors",
        "required-features = [\"kat\"]: the frozen SecMP-TR vectors (M3), natively in the kat step",
    ),
    (
        "secmp-proto",
        "tr_trial_counts",
        "required-features = [\"kat\"]: the counting accessors of the TR header trial and the skipped lookup \
         (M5 G-01, G-02), natively in the kat step",
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

/// Packages containing Kani harnesses (docs/06 §4). M2: `secmp-proto` (`src/kani_proofs.rs`). M5 (Phase B):
/// `secmp-relay` (`src/kani_proofs.rs`, TEST-SPEC-M5 K-05…K-07).
pub(crate) const KANI_PACKAGES: &[&str] = &["secmp-proto", "secmp-relay"];

/// The Kani harnesses (M2 review C5): the gate refuses a run unless Kani reports exactly these as successfully
/// verified ("Complete - N successfully verified harnesses, 0 failures, N total." with N = this count), so a
/// deleted or renamed harness fails the gate instead of passing silently. M3 (plan step 9): the three `tr_*`
/// harnesses of the SecMP-TR decisions (`tr::select`). M4: the five `kani_*` harnesses of SecMP-HX, and (WEISUNG M4-8)
/// K4b `kani_commit_accept_atomic` on the real prekey store. M5 Phase B: the three relay harnesses of `secmp-relay`
/// (`kani_cmd_seq_monotone`, `kani_queue_eviction_bounds`, `kani_executor_response_count`; TEST-SPEC-M5 K-05…K-07).
pub(crate) const KANI_HARNESSES: &[&str] = &[
    "kani_proofs::cell",
    "kani_proofs::header_v1",
    "kani_proofs::header_v1_reencodes",
    "kani_proofs::kani_accept_opk_delete_only_on_success",
    "kani_proofs::kani_cell_plaintext_decode_total",
    "kani_proofs::kani_cmd_seq_monotone",
    "kani_proofs::kani_commit_accept_atomic",
    "kani_proofs::kani_cont_assembly",
    "kani_proofs::kani_executor_response_count",
    "kani_proofs::kani_frame_pad_total",
    "kani_proofs::kani_hx_chunk_bounds",
    "kani_proofs::kani_hx_grouping",
    "kani_proofs::kani_link_counter_checked_add",
    "kani_proofs::kani_link_counter_strict_plus_one",
    "kani_proofs::kani_outer_unpad_total",
    "kani_proofs::kani_q_frame_plaintext_exact_fit",
    "kani_proofs::kani_queue_eviction_bounds",
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

/// M4 delta review VD1-5: the `kani::cover!` properties per harness. The gate requires exactly these cover summaries
/// ("N of N cover properties satisfied" for each, no other harness with one), so a deleted or an added cover fails it
/// instead of changing the count silently.
pub(crate) const KANI_COVERS: &[(&str, usize)] = &[
    ("kani_proofs::kani_accept_opk_delete_only_on_success", 1),
    ("kani_proofs::kani_cmd_seq_monotone", 5),
    ("kani_proofs::kani_commit_accept_atomic", 1),
    ("kani_proofs::kani_cont_assembly", 1),
    ("kani_proofs::kani_executor_response_count", 6),
    ("kani_proofs::kani_link_counter_strict_plus_one", 2),
    ("kani_proofs::kani_queue_eviction_bounds", 3),
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
    "link",
    "msgencrypt",
    "sas",
    "tr",
];

/// Reference files committed before their suite is generated by the Rust side and frozen: present as
/// `vectors/ref/<suite>.json`, absent from `vectors/`. The `ref-vectors` step requires each to be present and
/// well-formed (JSON, `suite` = its name, a non-empty `cases` array) and compares nothing yet. Moving a suite from
/// here to `VECTOR_SUITES` is its freeze step (M2: `encodings`, frozen in `docs/reviews/M02-report.md` plan step 10;
/// M3: `tr`, committed with the M3 brief and frozen in `docs/reviews/M03-report.md` plan step 6; M4: `hx`, committed
/// with the M4 plan commit and frozen in `docs/reviews/M04-report.md` plan step 5; M5: `link`, committed with the
/// M5 plan commit, frozen by Phase B, TEST-SPEC-M5 V-22 and X-01). Pending: none.
pub(crate) const VECTOR_REF_PENDING: &[&str] = &[];

/// Suites whose Rust generator writes the positive rows only (M2 cross-generates the `encodings` positives, docs/07
/// M2 deliverables): `cargo xtask vectors` compares the header and the positive rows, and requires the decoders to
/// reject every other row of the reference file (`secmp-proto` test `encodings_ref`) before the freeze.
pub(crate) const VECTOR_POSITIVE_ONLY: &[&str] = &["encodings"];

/// The single-file ProVerif models `formal/<name>.pv` (docs/06 §5 step 10): M3 `tr.pv`. The `proverif` step refuses any
/// other `formal/*.pv`. M4 (WEISUNG M4-5 §4, gate F7, M3 review R-14): the SecMP-HX model is not one of them — it is the
/// library [`PROVERIF_HX_LIB`] and one model per session under [`PROVERIF_HX_DIR`] (the files of
/// [`PROVERIF_EXPECTED_HX`]), each run as `proverif -lib formal/hx.pvl formal/hx/<session>.pv`; the old joint model
/// `formal/hx.pv` must not exist. M5 (OPEN-M5-16 A, CLAIMS §LINK LO-1): neither is SecMP-LINK — the library
/// [`PROVERIF_LINK_LIB`] and one model per session under [`PROVERIF_LINK_DIR`] (the files of
/// [`PROVERIF_EXPECTED_LINK`]); a joint `formal/link.pv` is refused like any other unlisted `formal/*.pv`.
pub(crate) const PROVERIF_MODELS: &[&str] = &["tr"];

/// The SecMP-HX ProVerif library (M4, WEISUNG M4-5): required whenever the `hx` models run.
pub(crate) const PROVERIF_HX_LIB: &str = "formal/hx.pvl";

/// The directory of the SecMP-HX session models `<session>.pv` (M4, WEISUNG M4-5): its set of `.pv` stems must equal
/// the set of files of [`PROVERIF_EXPECTED_HX`].
pub(crate) const PROVERIF_HX_DIR: &str = "formal/hx";

/// The SecMP-LINK ProVerif library (M5, OPEN-M5-16 A, CLAIMS §LINK LO-1): required whenever the `link` models run.
pub(crate) const PROVERIF_LINK_LIB: &str = "formal/link.pvl";

/// The directory of the SecMP-LINK session models `<session>.pv` (M5, OPEN-M5-16 A): its set of `.pv` stems must equal
/// the set of files of [`PROVERIF_EXPECTED_LINK`] — the nine sessions of the CLAIMS §LINK gate rule.
pub(crate) const PROVERIF_LINK_DIR: &str = "formal/link";

/// Seconds one ProVerif process may run (WEISUNG M4-5 §4, gate F7): a run still going after this is killed, and the
/// gate fails naming the file and its last progress line (`… rules inserted. …`). Applies to every model file.
pub(crate) const PROVERIF_TIMEOUT_SECONDS: u64 = 1800;

/// The largest number of parallel ProVerif processes (`--jobs N`), and the cap of the default (the available cores).
pub(crate) const PROVERIF_MAX_JOBS: usize = 4;

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

/// The expected `RESULT` lines of each model of [`PROVERIF_MODELS`]: one row per line, (file stem, `formal/CLAIMS.md`
/// ID, query text, expected verdict) in the order ProVerif prints them, matched by query text like the HX files
/// (`gates::proverif_check_hx_in`, M4 review C-7, ADR-046 Amendment 1 (3); M3 plan D10 compared only count and
/// verdict per position): a missing, an extra or a re-ordered line fails, as does a `True` line that is not "is true."
/// and a `False` line that is not "is false."; an `Informative` line may say anything. A test checks the IDs and
/// verdicts against the "Expected" column of `formal/CLAIMS.md`.
pub(crate) const PROVERIF_EXPECTED: &[(&str, &[HxExpected])] = &[("tr", PROVERIF_EXPECTED_TR)];

/// `tr` (M3, 39 lines; CLAIMS §TR gate rule: T1–T6, T8, T9, T11 true, T7 and T10 false, T12 informative): T1 the six
/// contents of steps 1–3 (n = 0, 1); T2 both directions; T3 the four contents of steps 1–2; T4, T5, T6 and T7 the two
/// contents of step 3 each; T8 per step `dh_pk` and `ek_pq` of its header and `n` of both messages (twelve); T9 the
/// same four fields of step 1; T10 one content; T11 and T12 one query each (T12: the model gives false). M4 (WEISUNG
/// M4-5, M3 review R-52, EXT-1): T13, reachability sanity, one query per honest session of the model (sClean, sFS,
/// sPCS, sPCSdh, sPCSkem, sPCSboth, sHFS), each false (the honest run completes) — 46 lines. The query texts are the
/// `RESULT` lines of the gate run on `569c2e2` (`docs/reviews/M04-evidence/proverif-tr-569c2e2.txt`). M5 (PV-02, M4
/// review R-41): T14, injective agreement after a skipped-path acceptance and a second offer, true — 47 lines; its text
/// is the `RESULT` line of `docs/reviews/M05-evidence/proverif-tr-t14-local.txt`. One entry per line; `rustfmt` leaves
/// the table alone.
#[rustfmt::skip]
pub(crate) const PROVERIF_EXPECTED_TR: &[HxExpected] = &[
    ("tr", "T1", "not attacker_p1(content(sClean,st1,c0))", Proved::True),
    ("tr", "T1", "not attacker_p1(content(sClean,st1,c1))", Proved::True),
    ("tr", "T1", "not attacker_p1(content(sClean,st2,c0))", Proved::True),
    ("tr", "T1", "not attacker_p1(content(sClean,st2,c1))", Proved::True),
    ("tr", "T1", "not attacker_p1(content(sClean,st3,c0))", Proved::True),
    ("tr", "T1", "not attacker_p1(content(sClean,st3,c1))", Proved::True),
    ("tr", "T2", "inj-event(Recv(sClean,pB,i_55,n_55,x)) ==> inj-event(Send(sClean,pA,i_55,n_55,x))", Proved::True),
    ("tr", "T2", "inj-event(Recv(sClean,pA,i_55,n_55,x)) ==> inj-event(Send(sClean,pB,i_55,n_55,x))", Proved::True),
    ("tr", "T3", "not attacker_p1(content(sFS,st1,c0))", Proved::True),
    ("tr", "T3", "not attacker_p1(content(sFS,st1,c1))", Proved::True),
    ("tr", "T3", "not attacker_p1(content(sFS,st2,c0))", Proved::True),
    ("tr", "T3", "not attacker_p1(content(sFS,st2,c1))", Proved::True),
    ("tr", "T4", "not attacker_p1(content(sPCS,st3,c0))", Proved::True),
    ("tr", "T4", "not attacker_p1(content(sPCS,st3,c1))", Proved::True),
    ("tr", "T5", "not attacker_p1(content(sPCSdh,st3,c0))", Proved::True),
    ("tr", "T5", "not attacker_p1(content(sPCSdh,st3,c1))", Proved::True),
    ("tr", "T6", "not attacker_p1(content(sPCSkem,st3,c0))", Proved::True),
    ("tr", "T6", "not attacker_p1(content(sPCSkem,st3,c1))", Proved::True),
    ("tr", "T7", "not attacker_p1(content(sPCSboth,st3,c0))", Proved::False),
    ("tr", "T7", "not attacker_p1(content(sPCSboth,st3,c1))", Proved::False),
    ("tr", "T8", "not attacker_p1(exp(g,dhsk(sClean,kA1)))", Proved::True),
    ("tr", "T8", "not attacker_p1(pk(kemsk(sClean,kA1)))", Proved::True),
    ("tr", "T8", "not attacker_p1(nmark(sClean,st1,c0))", Proved::True),
    ("tr", "T8", "not attacker_p1(nmark(sClean,st1,c1))", Proved::True),
    ("tr", "T8", "not attacker_p1(exp(g,dhsk(sClean,kB2)))", Proved::True),
    ("tr", "T8", "not attacker_p1(pk(kemsk(sClean,kB2)))", Proved::True),
    ("tr", "T8", "not attacker_p1(nmark(sClean,st2,c0))", Proved::True),
    ("tr", "T8", "not attacker_p1(nmark(sClean,st2,c1))", Proved::True),
    ("tr", "T8", "not attacker_p1(exp(g,dhsk(sClean,kA3)))", Proved::True),
    ("tr", "T8", "not attacker_p1(pk(kemsk(sClean,kA3)))", Proved::True),
    ("tr", "T8", "not attacker_p1(nmark(sClean,st3,c0))", Proved::True),
    ("tr", "T8", "not attacker_p1(nmark(sClean,st3,c1))", Proved::True),
    ("tr", "T9", "not attacker_p1(exp(g,dhsk(sHFS,kA1)))", Proved::True),
    ("tr", "T9", "not attacker_p1(pk(kemsk(sHFS,kA1)))", Proved::True),
    ("tr", "T9", "not attacker_p1(nmark(sHFS,st1,c0))", Proved::True),
    ("tr", "T9", "not attacker_p1(nmark(sHFS,st1,c1))", Proved::True),
    ("tr", "T10", "not attacker_p1(content(sPCS,st1,c1))", Proved::False),
    ("tr", "T11", "event(RecvKem(s_14,p_55,i_55,n_55,x,ct)) ==> event(ChainKem(s_14,p_55,i_55,ct))", Proved::True),
    ("tr", "T12", "event(HdrOpenTwice(k1_1,k2_1,h)) ==> k1_1 = k2_1", Proved::Informative),
    ("tr", "T13", "not event(Recv(sClean,pB,st3,c1,content(sClean,st3,c1)))", Proved::False),
    ("tr", "T13", "not event(Recv(sFS,pA,st2,c1,content(sFS,st2,c1)))", Proved::False),
    ("tr", "T13", "not event(Recv(sPCS,pB,st3,c1,content(sPCS,st3,c1)))", Proved::False),
    ("tr", "T13", "not event(Recv(sPCSdh,pB,st3,c1,content(sPCSdh,st3,c1)))", Proved::False),
    ("tr", "T13", "not event(Recv(sPCSkem,pB,st3,c1,content(sPCSkem,st3,c1)))", Proved::False),
    ("tr", "T13", "not event(Recv(sPCSboth,pB,st3,c1,content(sPCSboth,st3,c1)))", Proved::False),
    ("tr", "T13", "not event(Recv(sHFS,pB,st3,c1,content(sHFS,st3,c1)))", Proved::False),
    ("tr", "T14", "inj-event(Accepted(sClean,kid,n_55,m)) ==> inj-event(Sent(sClean,kid,n_55,m))", Proved::True),
];

/// The SHA-256 of every ProVerif model file — `formal/tr.pv`, the library `formal/hx.pvl` and every `formal/hx/*.pv`, and
/// (M5) `formal/link.pvl` and every `formal/link/*.pv` (X-05 `gates::tests::proverif_link_model_hashes_are_pinned`)
/// (M4 review C-7, ADR-046 Amendment 1 (1)): the `proverif` step refuses to run on other content, and a test in
/// `linux-fast` (`gates::tests::proverif_model_hashes_are_pinned`) fails on any byte changed, so a model change touches
/// this table in the same reviewed commit. The digest is taken over the committed text (CRLF read as LF).
pub(crate) const PROVERIF_MODEL_SHA256: &[(&str, &str)] = &[
    (
        "formal/tr.pv",
        "f726a1032e5b54a0b0b95039068182f4c5db8270745d9f160607868cf78b483d",
    ),
    (
        "formal/hx.pvl",
        "a24b1a50637c7b13d22c8e23568d1d402d18b8e7650d4bd65b85261505f3d20b",
    ),
    (
        "formal/hx/hBoth.pv",
        "6a606316c7401a7924b8894bb7893b9551a477a2cfb25051edca7cea67cf4ef8",
    ),
    (
        "formal/hx/hClean-auth.pv",
        "d7e0a63c0f5efa2c75ae63049ffe39b3b8aa81db62db2b6a1e36812609201d6e",
    ),
    (
        "formal/hx/hClean.pv",
        "c18c398e3d46b96e79ad45d8750d15aec50758cf6e18b976baedc842d7690fbd",
    ),
    (
        "formal/hx/hDH-auth.pv",
        "1beed1798581053ce0f200da6f7bcba2296604334aff0485cdc906ac07babe59",
    ),
    (
        "formal/hx/hDH.pv",
        "28ed0e6819a164cd0829f0b0705e061643ec910209c31872bae12fe5e5a1f018",
    ),
    (
        "formal/hx/hFS.pv",
        "f21c9d1f5a4e9190ffbe539ff3fe44bebe87cfbc08e6b5e0c704af10993fb15f",
    ),
    (
        "formal/hx/hFSDH.pv",
        "dc87046c29964180e4ceae349b9fef6fc12dcbb4c279a22312aa3e72bbc3a0ec",
    ),
    (
        "formal/hx/hFSOPK.pv",
        "ac8df3c07a2cb1212e99d60e4e9434ce0565bd7c580f33822a41acb6857e8e75",
    ),
    (
        "formal/hx/hId.pv",
        "4ed5e5205221c86e6466f090eb6f633341ddc6958b967ead56406d996fda3c52",
    ),
    (
        "formal/hx/hIdLater.pv",
        "2c6b2265c7b7af98682cd63aac9daf20918cadeab2377c814d88c954d98d53fa",
    ),
    (
        "formal/hx/hIdLaterOPK.pv",
        "43b483e056a221ca357ade4989739caeaaaffad0a2e9eb7b61b3a217b956b85e",
    ),
    (
        "formal/hx/hIdThief.pv",
        "a2c855940c688a0481ea7267e45f3314c898c68c749de8111975984c4f48abe5",
    ),
    (
        "formal/hx/hKCI-auth.pv",
        "d6c5870001a50f9f639a5571821ea96d1c1e1fd844ffd6a973a5437870b686d3",
    ),
    (
        "formal/hx/hKCI.pv",
        "eaf38619a061040a35770e3a486d5f85e2055d4a6c8c792fe5c867d941188113",
    ),
    (
        "formal/hx/hKCIi.pv",
        "df6fe825f759a5c43d481e0bc6c5a595195864fa1acccb81c5bdea744dce84e9",
    ),
    (
        "formal/hx/hKCIlt-auth.pv",
        "3ddae9f7502f3b90851ac2e4ff574ccd0312928234d01e0ce3631d414021f812",
    ),
    (
        "formal/hx/hKCIlt.pv",
        "7157b89d3d9cab0cf5d673f2476b506fd32a3b4aeada6373ab1e174b1a6bab4c",
    ),
    (
        "formal/hx/hKEM-auth.pv",
        "307f29dd51c29771404d930e44d640291263b2b133be711f39fcc75f724ccc76",
    ),
    (
        "formal/hx/hKEM.pv",
        "016d5c86fb75efaf6706034fb4d6e0d7f3a7316c45667fedb6e6c227e8c3a967",
    ),
    // M5 (OPEN-M5-16 A): the SecMP-LINK library and its nine session files
    (
        "formal/link.pvl",
        "3deba154ed01ed93f48099849feee3ec76b0cbc2913914d2085510c4d8ad9c25",
    ),
    (
        "formal/link/lBoth.pv",
        "2d7e595ee9de6f2814ba8c79c631894de2eb72169f479f706d3ae97a812fc261",
    ),
    (
        "formal/link/lClean.pv",
        "d9a0dcd5e4865ac06743d8868451befad050ae3a09f00c64e86caf0f907f6a27",
    ),
    (
        "formal/link/lDH.pv",
        "790619d8996d34fce1b7bca91516aae1e97780d24a4992e65d0d3cf810e6e8a1",
    ),
    (
        "formal/link/lFS.pv",
        "b23e7b75052b2e5d922ae12e00c3ee94f401e100501d720cc7596e61a9f9a04e",
    ),
    (
        "formal/link/lFSDH.pv",
        "97f48931b341df472e03bd61bc70cb85bd338405828d4973b5be4c55231a6e4c",
    ),
    (
        "formal/link/lFSEph.pv",
        "adfa9fa88b2dcf1b8bf80f1f06575da0f36821b5ba050ebd4e182ba9a82633f8",
    ),
    (
        "formal/link/lKEM.pv",
        "3789840b78dbd4d172bd973f814adde2cb43645ee7fe4b7fc9fcdc71598eb4e9",
    ),
    (
        "formal/link/lQKey.pv",
        "5589100a569fc5bd1b89427ee2b201a6479a5b57ac81134dbcf5b9f70e2dcd83",
    ),
    (
        "formal/link/lSig.pv",
        "b24c958a0d84d18da80c160a4386e882f401e7c55b6fd4fe2dc1fac3e1560f42",
    ),
];

/// One expected `RESULT` line of a SecMP-HX session model: (file stem under [`PROVERIF_HX_DIR`], `formal/CLAIMS.md` ID,
/// query text, expected verdict). The query text is what ProVerif prints between `RESULT ` and the final ` is true.`,
/// ` is false.` or ` cannot be proved.`; the `RESULT (but …)` remark ProVerif adds under an injective query is not a
/// `RESULT` line of its own.
pub(crate) type HxExpected = (&'static str, &'static str, &'static str, Proved);

/// The expected `RESULT` lines of every SecMP-HX session model (WEISUNG M4-5 §4, gate F7), in the order ProVerif prints
/// them within each file. The `proverif` step (`gates::proverif_check_hx`) matches the lines by query text, not by
/// position: a missing, an extra or a re-ordered `RESULT` line fails, as does a verdict other than the expected one (a
/// `True` line must say "is true.", a `False` line "is false.") and an `hx/*.pv` file without entries here.
///
/// Derived from the session files' queries in ProVerif 2.05's display form (spaces removed; `b_2`, `tr_2`, `rt_2`,
/// `sk_2`, `ld_N` with N = 4 + the `Leak`/`RevOPK` calls of the file's `Invitation`; `attacker_p1` in files with a
/// phase 1; `not (…)` for reachability queries). WEISUNG M4-7 (O-20…O-22): 19 files — the 14 session files and the
/// auth files `hClean-auth`, `hKEM-auth`, `hDH-auth`, `hKCI-auth`, `hKCIlt-auth`, each with the begin-`IStart`
/// declaration (H5/H8/H9/H9b; `ld_6`, `b_3`, `tr_3`, `rt_3`, `sk_3`: the attacker-as-inviter process adds bindings)
/// and, since the M4 review (C-7, erratum 5), one H11 line before it (the honest pair, same bindings); declarations
/// ordered no-begin, H6b, H10, H6a. The 82 rows of the session files equal the printed `RESULT` lines of the M4-7 runs;
/// the 10 auth rows equal the `RESULT` lines of the M4-fix run (`docs/reviews/M04-evidence/proverif-hx-<head>.txt`) —
/// 92 in total. Expected verdict: the `formal/CLAIMS.md` gate rule. One entry per line; `rustfmt` leaves the table
/// alone.
#[rustfmt::skip]
pub(crate) const PROVERIF_EXPECTED_HX: &[HxExpected] = &[
    ("hClean", "H1 (i)", "not (event(IStart(hClean,iI,iks(vk(iksig(hClean,pR)),exp(g,dhsk(hClean,kIKR))),b_2,tr_2,rt_2,sk_2)) && attacker(sk_2))", Proved::True),
    ("hClean", "H1 (ii)", "not (event(RAccept(hClean,iR,iks(vk(iksig(hClean,pI)),exp(g,dhsk(hClean,kIKI))),ld_5,oid,tr_2,rt_2,sk_2)) && attacker(sk_2))", Proved::True),
    ("hClean", "H11", "not event(IStart(hClean,iks(vk(iksig(hClean,pI)),exp(g,dhsk(hClean,kIKI))),iks(vk(iksig(hClean,pR)),exp(g,dhsk(hClean,kIKR))),b_2,tr_2,rt_2,sk_2))", Proved::False),
    ("hClean", "H11", "not event(BundleSigned(hClean,iR,b_2))", Proved::False),
    ("hClean", "H11", "not (event(RAccept(hClean,iR,iks(vk(iksig(hClean,pI)),exp(g,dhsk(hClean,kIKI))),ld_5,oid,tr_2,rt_2,sk_2)) && event(IStart(hClean,iks(vk(iksig(hClean,pI)),exp(g,dhsk(hClean,kIKI))),iR,b_2,tr_2,rt_2,sk_2)))", Proved::False),
    ("hClean", "H11", "not event(IConfirm(hClean,iks(vk(iksig(hClean,pI)),exp(g,dhsk(hClean,kIKI))),iks(vk(iksig(hClean,pR)),exp(g,dhsk(hClean,kIKR))),tr_2,sk_2))", Proved::False),
    ("hClean", "H6b", "inj-event(IConfirm(hClean,iI,iks(vk(iksig(hClean,pR)),exp(g,dhsk(hClean,kIKR))),tr_2,sk_2)) ==> inj-event(RAccept(hClean,iks(vk(iksig(hClean,pR)),exp(g,dhsk(hClean,kIKR))),iI,ld_5,oid,tr_2,rt_2,sk_2))", Proved::True),
    ("hClean", "H10", "inj-event(RAccept(hClean,iR,iI,ld_5,oid,tr_2,rt_2,sk_2)) ==> inj-event(InvIssued(hClean,iR,ld_5,oid))", Proved::True),
    ("hClean", "H6a", "event(IStart(hClean,iI,iks(vk(iksig(hClean,pR)),exp(g,dhsk(hClean,kIKR))),b_2,tr_2,rt_2,sk_2)) ==> event(BundleSigned(s2,iks(vk(iksig(hClean,pR)),exp(g,dhsk(hClean,kIKR))),b_2))", Proved::True),
    ("hClean-auth", "H11", "not (event(RAccept(hClean,iR,iks(vk(iksig(hClean,pI)),exp(g,dhsk(hClean,kIKI))),ld_6,oid,tr_3,rt_3,sk_3)) && event(IStart(hClean,iks(vk(iksig(hClean,pI)),exp(g,dhsk(hClean,kIKI))),iR,b_3,tr_3,rt_3,sk_3)))", Proved::False),
    ("hClean-auth", "H5", "inj-event(RAccept(hClean,iR,iks(vk(iksig(hClean,pI)),exp(g,dhsk(hClean,kIKI))),ld_6,oid,tr_3,rt_3,sk_3)) ==> inj-event(IStart(hClean,iks(vk(iksig(hClean,pI)),exp(g,dhsk(hClean,kIKI))),iR,b_3,tr_3,rt_3,sk_3))", Proved::True),
    ("hDH", "H2 (i)", "not (event(IStart(hDH,iI,iks(vk(iksig(hDH,pR)),exp(g,dhsk(hDH,kIKR))),b_2,tr_2,rt_2,sk_2)) && attacker(sk_2))", Proved::True),
    ("hDH", "H2 (ii)", "not (event(RAccept(hDH,iR,iks(vk(iksig(hDH,pI)),exp(g,dhsk(hDH,kIKI))),ld_5,oid,tr_2,rt_2,sk_2)) && event(IStart(hDH,iks(vk(iksig(hDH,pI)),exp(g,dhsk(hDH,kIKI))),iR,b_2,tr_2,rt_2,sk_2)) && attacker(sk_2))", Proved::True),
    ("hDH", "H11", "not event(IStart(hDH,iks(vk(iksig(hDH,pI)),exp(g,dhsk(hDH,kIKI))),iks(vk(iksig(hDH,pR)),exp(g,dhsk(hDH,kIKR))),b_2,tr_2,rt_2,sk_2))", Proved::False),
    ("hDH", "H11", "not event(BundleSigned(hDH,iR,b_2))", Proved::False),
    ("hDH", "H11", "not (event(RAccept(hDH,iR,iks(vk(iksig(hDH,pI)),exp(g,dhsk(hDH,kIKI))),ld_5,oid,tr_2,rt_2,sk_2)) && event(IStart(hDH,iks(vk(iksig(hDH,pI)),exp(g,dhsk(hDH,kIKI))),iR,b_2,tr_2,rt_2,sk_2)))", Proved::False),
    ("hDH", "H11", "not event(IConfirm(hDH,iks(vk(iksig(hDH,pI)),exp(g,dhsk(hDH,kIKI))),iks(vk(iksig(hDH,pR)),exp(g,dhsk(hDH,kIKR))),tr_2,sk_2))", Proved::False),
    ("hDH-auth", "H11", "not (event(RAccept(hDH,iR,iks(vk(iksig(hDH,pI)),exp(g,dhsk(hDH,kIKI))),ld_6,oid,tr_3,rt_3,sk_3)) && event(IStart(hDH,iks(vk(iksig(hDH,pI)),exp(g,dhsk(hDH,kIKI))),iR,b_3,tr_3,rt_3,sk_3)))", Proved::False),
    ("hDH-auth", "H8", "inj-event(RAccept(hDH,iR,iks(vk(iksig(hDH,pI)),exp(g,dhsk(hDH,kIKI))),ld_6,oid,tr_3,rt_3,sk_3)) ==> inj-event(IStart(hDH,iks(vk(iksig(hDH,pI)),exp(g,dhsk(hDH,kIKI))),iR,b_3,tr_3,rt_3,sk_3))", Proved::False),
    ("hKEM", "H3 (i)", "not (event(IStart(hKEM,iI,iks(vk(iksig(hKEM,pR)),exp(g,dhsk(hKEM,kIKR))),b_2,tr_2,rt_2,sk_2)) && attacker(sk_2))", Proved::True),
    ("hKEM", "H3 (ii)", "not (event(RAccept(hKEM,iR,iks(vk(iksig(hKEM,pI)),exp(g,dhsk(hKEM,kIKI))),ld_5,oid,tr_2,rt_2,sk_2)) && attacker(sk_2))", Proved::True),
    ("hKEM", "H11", "not event(IStart(hKEM,iks(vk(iksig(hKEM,pI)),exp(g,dhsk(hKEM,kIKI))),iks(vk(iksig(hKEM,pR)),exp(g,dhsk(hKEM,kIKR))),b_2,tr_2,rt_2,sk_2))", Proved::False),
    ("hKEM", "H11", "not event(BundleSigned(hKEM,iR,b_2))", Proved::False),
    ("hKEM", "H11", "not (event(RAccept(hKEM,iR,iks(vk(iksig(hKEM,pI)),exp(g,dhsk(hKEM,kIKI))),ld_5,oid,tr_2,rt_2,sk_2)) && event(IStart(hKEM,iks(vk(iksig(hKEM,pI)),exp(g,dhsk(hKEM,kIKI))),iR,b_2,tr_2,rt_2,sk_2)))", Proved::False),
    ("hKEM", "H11", "not event(IConfirm(hKEM,iks(vk(iksig(hKEM,pI)),exp(g,dhsk(hKEM,kIKI))),iks(vk(iksig(hKEM,pR)),exp(g,dhsk(hKEM,kIKR))),tr_2,sk_2))", Proved::False),
    ("hKEM-auth", "H11", "not (event(RAccept(hKEM,iR,iks(vk(iksig(hKEM,pI)),exp(g,dhsk(hKEM,kIKI))),ld_6,oid,tr_3,rt_3,sk_3)) && event(IStart(hKEM,iks(vk(iksig(hKEM,pI)),exp(g,dhsk(hKEM,kIKI))),iR,b_3,tr_3,rt_3,sk_3)))", Proved::False),
    ("hKEM-auth", "H5", "inj-event(RAccept(hKEM,iR,iks(vk(iksig(hKEM,pI)),exp(g,dhsk(hKEM,kIKI))),ld_6,oid,tr_3,rt_3,sk_3)) ==> inj-event(IStart(hKEM,iks(vk(iksig(hKEM,pI)),exp(g,dhsk(hKEM,kIKI))),iR,b_3,tr_3,rt_3,sk_3))", Proved::True),
    ("hBoth", "H4", "not (event(IStart(hBoth,iI,iks(vk(iksig(hBoth,pR)),exp(g,dhsk(hBoth,kIKR))),b_2,tr_2,rt_2,sk_2)) && attacker(sk_2))", Proved::False),
    ("hBoth", "H11", "not event(IStart(hBoth,iks(vk(iksig(hBoth,pI)),exp(g,dhsk(hBoth,kIKI))),iks(vk(iksig(hBoth,pR)),exp(g,dhsk(hBoth,kIKR))),b_2,tr_2,rt_2,sk_2))", Proved::False),
    ("hBoth", "H11", "not event(BundleSigned(hBoth,iR,b_2))", Proved::False),
    ("hBoth", "H11", "not (event(RAccept(hBoth,iR,iks(vk(iksig(hBoth,pI)),exp(g,dhsk(hBoth,kIKI))),ld_5,oid,tr_2,rt_2,sk_2)) && event(IStart(hBoth,iks(vk(iksig(hBoth,pI)),exp(g,dhsk(hBoth,kIKI))),iR,b_2,tr_2,rt_2,sk_2)))", Proved::False),
    ("hBoth", "H11", "not event(IConfirm(hBoth,iks(vk(iksig(hBoth,pI)),exp(g,dhsk(hBoth,kIKI))),iks(vk(iksig(hBoth,pR)),exp(g,dhsk(hBoth,kIKR))),tr_2,sk_2))", Proved::False),
    ("hId", "H7a", "not attacker(exp(g,dhsk(hId,kIKI)))", Proved::True),
    ("hId", "H7a", "not attacker(vk(iksig(hId,pI)))", Proved::True),
    ("hId", "H11", "not event(IStart(hId,iks(vk(iksig(hId,pI)),exp(g,dhsk(hId,kIKI))),iks(vk(iksig(hId,pR)),exp(g,dhsk(hId,kIKR))),b_2,tr_2,rt_2,sk_2))", Proved::False),
    ("hId", "H11", "not event(BundleSigned(hId,iR,b_2))", Proved::False),
    ("hId", "H11", "not (event(RAccept(hId,iR,iks(vk(iksig(hId,pI)),exp(g,dhsk(hId,kIKI))),ld_4,oid,tr_2,rt_2,sk_2)) && event(IStart(hId,iks(vk(iksig(hId,pI)),exp(g,dhsk(hId,kIKI))),iR,b_2,tr_2,rt_2,sk_2)))", Proved::False),
    ("hId", "H11", "not event(IConfirm(hId,iks(vk(iksig(hId,pI)),exp(g,dhsk(hId,kIKI))),iks(vk(iksig(hId,pR)),exp(g,dhsk(hId,kIKR))),tr_2,sk_2))", Proved::False),
    ("hId", "H6a", "event(IStart(hId,iI,iks(vk(iksig(hId,pR)),exp(g,dhsk(hId,kIKR))),b_2,tr_2,rt_2,sk_2)) ==> event(BundleSigned(s2,iks(vk(iksig(hId,pR)),exp(g,dhsk(hId,kIKR))),b_2))", Proved::True),
    ("hIdThief", "H7b", "not attacker(exp(g,dhsk(hIdThief,kIKI)))", Proved::True),
    ("hIdThief", "H7b", "not attacker(vk(iksig(hIdThief,pI)))", Proved::True),
    ("hIdThief", "H11", "not event(IStart(hIdThief,iks(vk(iksig(hIdThief,pI)),exp(g,dhsk(hIdThief,kIKI))),iks(vk(iksig(hIdThief,pR)),exp(g,dhsk(hIdThief,kIKR))),b_2,tr_2,rt_2,sk_2))", Proved::False),
    ("hIdThief", "H11", "not event(BundleSigned(hIdThief,iR,b_2))", Proved::False),
    ("hIdThief", "H11", "not (event(RAccept(hIdThief,iR,iks(vk(iksig(hIdThief,pI)),exp(g,dhsk(hIdThief,kIKI))),ld_5,oid,tr_2,rt_2,sk_2)) && event(IStart(hIdThief,iks(vk(iksig(hIdThief,pI)),exp(g,dhsk(hIdThief,kIKI))),iR,b_2,tr_2,rt_2,sk_2)))", Proved::False),
    ("hIdThief", "H11", "not event(IConfirm(hIdThief,iks(vk(iksig(hIdThief,pI)),exp(g,dhsk(hIdThief,kIKI))),iks(vk(iksig(hIdThief,pR)),exp(g,dhsk(hIdThief,kIKR))),tr_2,sk_2))", Proved::False),
    ("hIdLater", "H7c", "not attacker_p1(exp(g,dhsk(hIdLater,kIKI)))", Proved::True),
    ("hIdLater", "H7c", "not attacker_p1(vk(iksig(hIdLater,pI)))", Proved::True),
    ("hIdLater", "H11", "not event(IStart(hIdLater,iks(vk(iksig(hIdLater,pI)),exp(g,dhsk(hIdLater,kIKI))),iks(vk(iksig(hIdLater,pR)),exp(g,dhsk(hIdLater,kIKR))),b_2,tr_2,rt_2,sk_2))", Proved::False),
    ("hIdLater", "H11", "not event(BundleSigned(hIdLater,iR,b_2))", Proved::False),
    ("hIdLater", "H11", "not (event(RAccept(hIdLater,iR,iks(vk(iksig(hIdLater,pI)),exp(g,dhsk(hIdLater,kIKI))),ld_5,oid,tr_2,rt_2,sk_2)) && event(IStart(hIdLater,iks(vk(iksig(hIdLater,pI)),exp(g,dhsk(hIdLater,kIKI))),iR,b_2,tr_2,rt_2,sk_2)))", Proved::False),
    ("hIdLater", "H11", "not event(IConfirm(hIdLater,iks(vk(iksig(hIdLater,pI)),exp(g,dhsk(hIdLater,kIKI))),iks(vk(iksig(hIdLater,pR)),exp(g,dhsk(hIdLater,kIKR))),tr_2,sk_2))", Proved::False),
    ("hIdLaterOPK", "H7d", "not attacker_p1(exp(g,dhsk(hIdLaterOPK,kIKI)))", Proved::False),
    ("hIdLaterOPK", "H7d", "not attacker_p1(vk(iksig(hIdLaterOPK,pI)))", Proved::False),
    ("hIdLaterOPK", "H11", "not event(IStart(hIdLaterOPK,iks(vk(iksig(hIdLaterOPK,pI)),exp(g,dhsk(hIdLaterOPK,kIKI))),iks(vk(iksig(hIdLaterOPK,pR)),exp(g,dhsk(hIdLaterOPK,kIKR))),b_2,tr_2,rt_2,sk_2))", Proved::False),
    ("hIdLaterOPK", "H11", "not event(BundleSigned(hIdLaterOPK,iR,b_2))", Proved::False),
    ("hIdLaterOPK", "H11", "not (event(RAccept(hIdLaterOPK,iR,iks(vk(iksig(hIdLaterOPK,pI)),exp(g,dhsk(hIdLaterOPK,kIKI))),ld_6,oid,tr_2,rt_2,sk_2)) && event(IStart(hIdLaterOPK,iks(vk(iksig(hIdLaterOPK,pI)),exp(g,dhsk(hIdLaterOPK,kIKI))),iR,b_2,tr_2,rt_2,sk_2)))", Proved::False),
    ("hIdLaterOPK", "H11", "not event(IConfirm(hIdLaterOPK,iks(vk(iksig(hIdLaterOPK,pI)),exp(g,dhsk(hIdLaterOPK,kIKI))),iks(vk(iksig(hIdLaterOPK,pR)),exp(g,dhsk(hIdLaterOPK,kIKR))),tr_2,sk_2))", Proved::False),
    ("hKCI", "H11", "not event(IStart(hKCI,iks(vk(iksig(hKCI,pI)),exp(g,dhsk(hKCI,kIKI))),iks(vk(iksig(hKCI,pR)),exp(g,dhsk(hKCI,kIKR))),b_2,tr_2,rt_2,sk_2))", Proved::False),
    ("hKCI", "H11", "not event(BundleSigned(hKCI,iR,b_2))", Proved::False),
    ("hKCI", "H11", "not (event(RAccept(hKCI,iR,iks(vk(iksig(hKCI,pI)),exp(g,dhsk(hKCI,kIKI))),ld_5,oid,tr_2,rt_2,sk_2)) && event(IStart(hKCI,iks(vk(iksig(hKCI,pI)),exp(g,dhsk(hKCI,kIKI))),iR,b_2,tr_2,rt_2,sk_2)))", Proved::False),
    ("hKCI", "H11", "not event(IConfirm(hKCI,iks(vk(iksig(hKCI,pI)),exp(g,dhsk(hKCI,kIKI))),iks(vk(iksig(hKCI,pR)),exp(g,dhsk(hKCI,kIKR))),tr_2,sk_2))", Proved::False),
    ("hKCI-auth", "H11", "not (event(RAccept(hKCI,iR,iks(vk(iksig(hKCI,pI)),exp(g,dhsk(hKCI,kIKI))),ld_6,oid,tr_3,rt_3,sk_3)) && event(IStart(hKCI,iks(vk(iksig(hKCI,pI)),exp(g,dhsk(hKCI,kIKI))),iR,b_3,tr_3,rt_3,sk_3)))", Proved::False),
    ("hKCI-auth", "H9", "inj-event(RAccept(hKCI,iR,iks(vk(iksig(hKCI,pI)),exp(g,dhsk(hKCI,kIKI))),ld_6,oid,tr_3,rt_3,sk_3)) ==> inj-event(IStart(hKCI,iks(vk(iksig(hKCI,pI)),exp(g,dhsk(hKCI,kIKI))),iR,b_3,tr_3,rt_3,sk_3))", Proved::False),
    ("hKCIlt", "H11", "not event(IStart(hKCIlt,iks(vk(iksig(hKCIlt,pI)),exp(g,dhsk(hKCIlt,kIKI))),iks(vk(iksig(hKCIlt,pR)),exp(g,dhsk(hKCIlt,kIKR))),b_2,tr_2,rt_2,sk_2))", Proved::False),
    ("hKCIlt", "H11", "not event(BundleSigned(hKCIlt,iR,b_2))", Proved::False),
    ("hKCIlt", "H11", "not (event(RAccept(hKCIlt,iR,iks(vk(iksig(hKCIlt,pI)),exp(g,dhsk(hKCIlt,kIKI))),ld_5,oid,tr_2,rt_2,sk_2)) && event(IStart(hKCIlt,iks(vk(iksig(hKCIlt,pI)),exp(g,dhsk(hKCIlt,kIKI))),iR,b_2,tr_2,rt_2,sk_2)))", Proved::False),
    ("hKCIlt", "H11", "not event(IConfirm(hKCIlt,iks(vk(iksig(hKCIlt,pI)),exp(g,dhsk(hKCIlt,kIKI))),iks(vk(iksig(hKCIlt,pR)),exp(g,dhsk(hKCIlt,kIKR))),tr_2,sk_2))", Proved::False),
    ("hKCIlt-auth", "H11", "not (event(RAccept(hKCIlt,iR,iks(vk(iksig(hKCIlt,pI)),exp(g,dhsk(hKCIlt,kIKI))),ld_6,oid,tr_3,rt_3,sk_3)) && event(IStart(hKCIlt,iks(vk(iksig(hKCIlt,pI)),exp(g,dhsk(hKCIlt,kIKI))),iR,b_3,tr_3,rt_3,sk_3)))", Proved::False),
    ("hKCIlt-auth", "H9b", "inj-event(RAccept(hKCIlt,iR,iks(vk(iksig(hKCIlt,pI)),exp(g,dhsk(hKCIlt,kIKI))),ld_6,oid,tr_3,rt_3,sk_3)) ==> inj-event(IStart(hKCIlt,iks(vk(iksig(hKCIlt,pI)),exp(g,dhsk(hKCIlt,kIKI))),iR,b_3,tr_3,rt_3,sk_3))", Proved::True),
    ("hKCIi", "H9c", "not (event(IStart(hKCIi,iI,iks(vk(iksig(hKCIi,pR)),exp(g,dhsk(hKCIi,kIKR))),b_2,tr_2,rt_2,sk_2)) && attacker(sk_2))", Proved::True),
    ("hKCIi", "H11", "not event(IStart(hKCIi,iks(vk(iksig(hKCIi,pI)),exp(g,dhsk(hKCIi,kIKI))),iks(vk(iksig(hKCIi,pR)),exp(g,dhsk(hKCIi,kIKR))),b_2,tr_2,rt_2,sk_2))", Proved::False),
    ("hKCIi", "H11", "not event(BundleSigned(hKCIi,iR,b_2))", Proved::False),
    ("hKCIi", "H11", "not (event(RAccept(hKCIi,iR,iks(vk(iksig(hKCIi,pI)),exp(g,dhsk(hKCIi,kIKI))),ld_5,oid,tr_2,rt_2,sk_2)) && event(IStart(hKCIi,iks(vk(iksig(hKCIi,pI)),exp(g,dhsk(hKCIi,kIKI))),iR,b_2,tr_2,rt_2,sk_2)))", Proved::False),
    ("hKCIi", "H11", "not event(IConfirm(hKCIi,iks(vk(iksig(hKCIi,pI)),exp(g,dhsk(hKCIi,kIKI))),iks(vk(iksig(hKCIi,pR)),exp(g,dhsk(hKCIi,kIKR))),tr_2,sk_2))", Proved::False),
    ("hFS", "H11", "not event(IStart(hFS,iks(vk(iksig(hFS,pI)),exp(g,dhsk(hFS,kIKI))),iks(vk(iksig(hFS,pR)),exp(g,dhsk(hFS,kIKR))),b_2,tr_2,rt_2,sk_2))", Proved::False),
    ("hFS", "H11", "not event(BundleSigned(hFS,iR,b_2))", Proved::False),
    ("hFS", "H11", "not (event(RAccept(hFS,iR,iks(vk(iksig(hFS,pI)),exp(g,dhsk(hFS,kIKI))),ld_5,oid,tr_2,rt_2,sk_2)) && event(IStart(hFS,iks(vk(iksig(hFS,pI)),exp(g,dhsk(hFS,kIKI))),iR,b_2,tr_2,rt_2,sk_2)))", Proved::False),
    ("hFS", "H11", "not event(IConfirm(hFS,iks(vk(iksig(hFS,pI)),exp(g,dhsk(hFS,kIKI))),iks(vk(iksig(hFS,pR)),exp(g,dhsk(hFS,kIKR))),tr_2,sk_2))", Proved::False),
    ("hFS", "H12 (i)", "not (event(IStart(hFS,iI,iks(vk(iksig(hFS,pR)),exp(g,dhsk(hFS,kIKR))),b_2,tr_2,rt_2,sk_2)) && attacker_p1(sk_2))", Proved::True),
    ("hFS", "H12 (ii)", "not (event(RAccept(hFS,iR,iks(vk(iksig(hFS,pI)),exp(g,dhsk(hFS,kIKI))),ld_5,oid,tr_2,rt_2,sk_2)) && attacker_p1(sk_2))", Proved::True),
    ("hFSOPK", "H11", "not event(IStart(hFSOPK,iks(vk(iksig(hFSOPK,pI)),exp(g,dhsk(hFSOPK,kIKI))),iks(vk(iksig(hFSOPK,pR)),exp(g,dhsk(hFSOPK,kIKR))),b_2,tr_2,rt_2,sk_2))", Proved::False),
    ("hFSOPK", "H11", "not event(BundleSigned(hFSOPK,iR,b_2))", Proved::False),
    ("hFSOPK", "H11", "not (event(RAccept(hFSOPK,iR,iks(vk(iksig(hFSOPK,pI)),exp(g,dhsk(hFSOPK,kIKI))),ld_6,oid,tr_2,rt_2,sk_2)) && event(IStart(hFSOPK,iks(vk(iksig(hFSOPK,pI)),exp(g,dhsk(hFSOPK,kIKI))),iR,b_2,tr_2,rt_2,sk_2)))", Proved::False),
    ("hFSOPK", "H11", "not event(IConfirm(hFSOPK,iks(vk(iksig(hFSOPK,pI)),exp(g,dhsk(hFSOPK,kIKI))),iks(vk(iksig(hFSOPK,pR)),exp(g,dhsk(hFSOPK,kIKR))),tr_2,sk_2))", Proved::False),
    ("hFSOPK", "H12b (i)", "not (event(IStart(hFSOPK,iI,iks(vk(iksig(hFSOPK,pR)),exp(g,dhsk(hFSOPK,kIKR))),b_2,tr_2,rt_2,sk_2)) && attacker_p1(sk_2))", Proved::False),
    ("hFSOPK", "H12b (ii)", "not (event(RAccept(hFSOPK,iR,iks(vk(iksig(hFSOPK,pI)),exp(g,dhsk(hFSOPK,kIKI))),ld_6,oid,tr_2,rt_2,sk_2)) && attacker_p1(sk_2))", Proved::False),
    ("hFSDH", "H11", "not event(IStart(hFSDH,iks(vk(iksig(hFSDH,pI)),exp(g,dhsk(hFSDH,kIKI))),iks(vk(iksig(hFSDH,pR)),exp(g,dhsk(hFSDH,kIKR))),b_2,tr_2,rt_2,sk_2))", Proved::False),
    ("hFSDH", "H11", "not event(BundleSigned(hFSDH,iR,b_2))", Proved::False),
    ("hFSDH", "H11", "not (event(RAccept(hFSDH,iR,iks(vk(iksig(hFSDH,pI)),exp(g,dhsk(hFSDH,kIKI))),ld_5,oid,tr_2,rt_2,sk_2)) && event(IStart(hFSDH,iks(vk(iksig(hFSDH,pI)),exp(g,dhsk(hFSDH,kIKI))),iR,b_2,tr_2,rt_2,sk_2)))", Proved::False),
    ("hFSDH", "H11", "not event(IConfirm(hFSDH,iks(vk(iksig(hFSDH,pI)),exp(g,dhsk(hFSDH,kIKI))),iks(vk(iksig(hFSDH,pR)),exp(g,dhsk(hFSDH,kIKR))),tr_2,sk_2))", Proved::False),
    ("hFSDH", "H12c (i)", "not (event(IStart(hFSDH,iI,iks(vk(iksig(hFSDH,pR)),exp(g,dhsk(hFSDH,kIKR))),b_2,tr_2,rt_2,sk_2)) && attacker_p1(sk_2))", Proved::True),
    ("hFSDH", "H12c (ii)", "not (event(RAccept(hFSDH,iR,iks(vk(iksig(hFSDH,pI)),exp(g,dhsk(hFSDH,kIKI))),ld_5,oid,tr_2,rt_2,sk_2)) && attacker_p1(sk_2))", Proved::True),
];

/// The expected `RESULT` lines of every SecMP-LINK session model (M5, OPEN-M5-16 A, CLAIMS §LINK), in the order ProVerif
/// prints them within each file, matched by query text like [`PROVERIF_EXPECTED_HX`] (`gates::proverif_check_session`):
/// a missing, an extra or a re-ordered line fails, as does a verdict other than the CLAIMS §LINK gate rule's (L1, L1a,
/// L1b, L3, L3a, L3b, L4, L5, L5a, L6, L7 true; L1c, L2, L3c, L5b, L6a and every L8 line false) and a `link/*.pv` file
/// without entries. Declarations per file (formal/link.pvl 3., 6.): the payload lines of L3/L5 (`CSend`, `RSend`) and the
/// three L8 lines, then the L1-type line, L4 (two lines), L6-type, L7 — 55 lines in 9 files. Query texts in ProVerif 2.05's
/// display form from the local runs (docs/reviews/M05-evidence/proverif-link-local.txt); `rustfmt` leaves the table alone.
#[rustfmt::skip]
pub(crate) const PROVERIF_EXPECTED_LINK: &[HxExpected] = &[
    ("lClean", "L3", "not (event(CAccept(lClean,h((lbl_relayfp,vk(sigk(lClean,kRsig)))),kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(CSend(lClean,sid_4,ctr,m)) && attacker(m))", Proved::True),
    ("lClean", "L3", "not (event(CAccept(lClean,h((lbl_relayfp,vk(sigk(lClean,kRsig)))),kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(RSend(lClean,sid_4,ctr,m)) && attacker(m))", Proved::True),
    ("lClean", "L8", "not event(CStart(lClean,fp,kid_2,h0_3))", Proved::False),
    ("lClean", "L8", "not (event(RAccept(lClean,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(CAccept(lClean,fp,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)))", Proved::False),
    ("lClean", "L8", "not event(RExec(lClean,sid_4,cs,cmd,vk(sigk(lClean,iQ(x_1)))))", Proved::False),
    ("lClean", "L1", "inj-event(CAccept(lClean,h((lbl_relayfp,vk(sigk(lClean,kRsig)))),kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) ==> inj-event(RAccept(lClean,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3))", Proved::True),
    ("lClean", "L4", "inj-event(RRecv(lClean,sid_4,ctr,m)) && event(CStart(lClean,fp,kid_2,h0_3)) && event(RAccept(lClean,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) ==> inj-event(CSend(lClean,sid_4,ctr,m))", Proved::True),
    ("lClean", "L4", "inj-event(CRecv(lClean,sid_4,ctr,m)) ==> inj-event(RSend(lClean,sid_4,ctr,m))", Proved::True),
    ("lClean", "L6", "inj-event(RExec(lClean,sid_4,cs,cmd,vk(sigk(lClean,iQ(x_1))))) ==> inj-event(CSign(lClean,sid_4,cs,cmd,vk(sigk(lClean,iQ(x_1)))))", Proved::True),
    ("lClean", "L7", "event(CAccept(lClean,fp,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) ==> event(RInfo(lClean,kid_2,fp,h((lbl_akc,ak[]))))", Proved::True),
    ("lDH", "L3a", "not (event(CAccept(lDH,h((lbl_relayfp,vk(sigk(lDH,kRsig)))),kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(CSend(lDH,sid_4,ctr,m)) && attacker(m))", Proved::True),
    ("lDH", "L3a", "not (event(CAccept(lDH,h((lbl_relayfp,vk(sigk(lDH,kRsig)))),kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(RSend(lDH,sid_4,ctr,m)) && attacker(m))", Proved::True),
    ("lDH", "L8", "not event(CStart(lDH,fp,kid_2,h0_3))", Proved::False),
    ("lDH", "L8", "not (event(RAccept(lDH,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(CAccept(lDH,fp,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)))", Proved::False),
    ("lDH", "L8", "not event(RExec(lDH,sid_4,cs,cmd,vk(sigk(lDH,iQ(x_1)))))", Proved::False),
    ("lDH", "L1a", "inj-event(CAccept(lDH,h((lbl_relayfp,vk(sigk(lDH,kRsig)))),kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) ==> inj-event(RAccept(lDH,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3))", Proved::True),
    ("lDH", "L4", "inj-event(RRecv(lDH,sid_4,ctr,m)) && event(CStart(lDH,fp,kid_2,h0_3)) && event(RAccept(lDH,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) ==> inj-event(CSend(lDH,sid_4,ctr,m))", Proved::True),
    ("lDH", "L4", "inj-event(CRecv(lDH,sid_4,ctr,m)) ==> inj-event(RSend(lDH,sid_4,ctr,m))", Proved::True),
    ("lKEM", "L3b", "not (event(CAccept(lKEM,h((lbl_relayfp,vk(sigk(lKEM,kRsig)))),kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(CSend(lKEM,sid_4,ctr,m)) && attacker(m))", Proved::True),
    ("lKEM", "L3b", "not (event(CAccept(lKEM,h((lbl_relayfp,vk(sigk(lKEM,kRsig)))),kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(RSend(lKEM,sid_4,ctr,m)) && attacker(m))", Proved::True),
    ("lKEM", "L8", "not event(CStart(lKEM,fp,kid_2,h0_3))", Proved::False),
    ("lKEM", "L8", "not (event(RAccept(lKEM,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(CAccept(lKEM,fp,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)))", Proved::False),
    ("lKEM", "L8", "not event(RExec(lKEM,sid_4,cs,cmd,vk(sigk(lKEM,iQ(x_1)))))", Proved::False),
    ("lKEM", "L1b", "inj-event(CAccept(lKEM,h((lbl_relayfp,vk(sigk(lKEM,kRsig)))),kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) ==> inj-event(RAccept(lKEM,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3))", Proved::True),
    ("lKEM", "L4", "inj-event(RRecv(lKEM,sid_4,ctr,m)) && event(CStart(lKEM,fp,kid_2,h0_3)) && event(RAccept(lKEM,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) ==> inj-event(CSend(lKEM,sid_4,ctr,m))", Proved::True),
    ("lKEM", "L4", "inj-event(CRecv(lKEM,sid_4,ctr,m)) ==> inj-event(RSend(lKEM,sid_4,ctr,m))", Proved::True),
    ("lBoth", "L3c", "not (event(CAccept(lBoth,h((lbl_relayfp,vk(sigk(lBoth,kRsig)))),kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(CSend(lBoth,sid_4,ctr,m)) && attacker(m))", Proved::False),
    ("lBoth", "L3c", "not (event(CAccept(lBoth,h((lbl_relayfp,vk(sigk(lBoth,kRsig)))),kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(RSend(lBoth,sid_4,ctr,m)) && attacker(m))", Proved::False),
    ("lBoth", "L8", "not event(CStart(lBoth,fp,kid_2,h0_3))", Proved::False),
    ("lBoth", "L8", "not (event(RAccept(lBoth,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(CAccept(lBoth,fp,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)))", Proved::False),
    ("lBoth", "L8", "not event(RExec(lBoth,sid_4,cs,cmd,vk(sigk(lBoth,iQ(x_1)))))", Proved::False),
    ("lBoth", "L1c", "inj-event(CAccept(lBoth,h((lbl_relayfp,vk(sigk(lBoth,kRsig)))),kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) ==> inj-event(RAccept(lBoth,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3))", Proved::False),
    ("lSig", "L8", "not event(CStart(lSig,fp,kid_2,h0_3))", Proved::False),
    ("lSig", "L8", "not (event(RAccept(lSig,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(CAccept(lSig,fp,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)))", Proved::False),
    ("lSig", "L8", "not event(RExec(lSig,sid_4,cs,cmd,vk(sigk(lSig,iQ(x_1)))))", Proved::False),
    ("lSig", "L2", "inj-event(CAccept(lSig,h((lbl_relayfp,vk(sigk(lSig,kRsig)))),kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) ==> inj-event(RAccept(lSig,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3))", Proved::False),
    ("lFS", "L5", "not (event(CAccept(lFS,h((lbl_relayfp,vk(sigk(lFS,kRsig)))),kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(CSend(lFS,sid_4,ctr,m)) && attacker_p1(m))", Proved::True),
    ("lFS", "L5", "not (event(CAccept(lFS,h((lbl_relayfp,vk(sigk(lFS,kRsig)))),kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(RSend(lFS,sid_4,ctr,m)) && attacker_p1(m))", Proved::True),
    ("lFS", "L8", "not event(CStart(lFS,fp,kid_2,h0_3))", Proved::False),
    ("lFS", "L8", "not (event(RAccept(lFS,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(CAccept(lFS,fp,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)))", Proved::False),
    ("lFS", "L8", "not event(RExec(lFS,sid_4,cs,cmd,vk(sigk(lFS,iQ(x_1)))))", Proved::False),
    ("lFSDH", "L5a", "not (event(CAccept(lFSDH,h((lbl_relayfp,vk(sigk(lFSDH,kRsig)))),kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(CSend(lFSDH,sid_4,ctr,m)) && attacker_p1(m))", Proved::True),
    ("lFSDH", "L5a", "not (event(CAccept(lFSDH,h((lbl_relayfp,vk(sigk(lFSDH,kRsig)))),kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(RSend(lFSDH,sid_4,ctr,m)) && attacker_p1(m))", Proved::True),
    ("lFSDH", "L8", "not event(CStart(lFSDH,fp,kid_2,h0_3))", Proved::False),
    ("lFSDH", "L8", "not (event(RAccept(lFSDH,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(CAccept(lFSDH,fp,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)))", Proved::False),
    ("lFSDH", "L8", "not event(RExec(lFSDH,sid_4,cs,cmd,vk(sigk(lFSDH,iQ(x_2)))))", Proved::False),
    ("lFSEph", "L5b", "not (event(CAccept(lFSEph,h((lbl_relayfp,vk(sigk(lFSEph,kRsig)))),kid_4,h0_5,h1_5,sid_6,k1_5,k2_5)) && event(CSend(lFSEph,sid_6,ctr,m)) && attacker_p1(m))", Proved::False),
    ("lFSEph", "L5b", "not (event(CAccept(lFSEph,h((lbl_relayfp,vk(sigk(lFSEph,kRsig)))),kid_4,h0_5,h1_5,sid_6,k1_5,k2_5)) && event(RSend(lFSEph,sid_6,ctr,m)) && attacker_p1(m))", Proved::False),
    ("lFSEph", "L8", "not event(CStart(lFSEph,fp,kid_4,h0_5))", Proved::False),
    ("lFSEph", "L8", "not (event(RAccept(lFSEph,kid_4,h0_5,h1_5,sid_6,k1_5,k2_5)) && event(CAccept(lFSEph,fp,kid_4,h0_5,h1_5,sid_6,k1_5,k2_5)))", Proved::False),
    ("lFSEph", "L8", "not event(RExec(lFSEph,sid_6,cs,cmd,vk(sigk(lFSEph,iQ(x_1)))))", Proved::False),
    ("lQKey", "L8", "not event(CStart(lQKey,fp,kid_2,h0_3))", Proved::False),
    ("lQKey", "L8", "not (event(RAccept(lQKey,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)) && event(CAccept(lQKey,fp,kid_2,h0_3,h1_3,sid_4,k1_3,k2_3)))", Proved::False),
    ("lQKey", "L8", "not event(RExec(lQKey,sid_4,cs,cmd,vk(sigk(lQKey,iQ(x_1)))))", Proved::False),
    ("lQKey", "L6a", "inj-event(RExec(lQKey,sid_4,cs,cmd,vk(sigk(lQKey,iQ(x_1))))) ==> inj-event(CSign(lQKey,sid_4,cs,cmd,vk(sigk(lQKey,iQ(x_1)))))", Proved::False),
];

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
pub(crate) const LINT_ALLOWANCES: &[(&str, &str, &str)] = &[(
    "crates/secmp-relay/src/clock.rs",
    "clippy::disallowed_methods",
    "docs/06 §2: the relay's hour-bucket function `wall_clock_unix_secs`, the crate's one `SystemTime::now` site (M5, test RL-11)",
)];

/// The only lints the docs/06 §2 test-file allowance may relax.
pub(crate) const TEST_FILE_ALLOWANCE: &[&str] = &["clippy::unwrap_used", "clippy::expect_used"];

/// Path prefixes (relative to the workspace root) where the test-file allowance applies.
pub(crate) const TEST_FILE_PREFIXES: &[&str] = &["fuzz/", "crates/secmp-testkit/"];

/// CI jobs that may use `continue-on-error: true`. None: Amendment A1 §5 allowed it for the cargo-xwin
/// cross-build in M0 only, and the M0 review (condition C1) made that job a hard gate from M1 on.
pub(crate) const CONTINUE_ON_ERROR_JOBS: &[&str] = &[];

/// The events `secmp-relay` may emit (spec §9.7 item 2; OPEN-M5-08 A): start-up, key load, its own listener bound,
/// a configuration error, drain start and exit — nothing per request at any level. Equal to
/// `secmp_relay::event::EVENT_NAMES` (test `relay_trace_allow_equals_the_event_names`); test RL-03 captures a full
/// scenario against this list.
pub(crate) const RELAY_TRACE_ALLOW: &[&str] = &[
    "startup",
    "keys_loaded",
    "listener_bound",
    "config_error",
    "drain_started",
    "exit",
];

/// The workflow that holds the required checks of the `main-protection` ruleset (docs/06 §4).
pub(crate) const REQUIRED_WORKFLOW: &str = ".github/workflows/ci.yml";

/// The job names of the required checks of the `main-protection` ruleset (M2 review C2): they exist only in
/// [`REQUIRED_WORKFLOW`], which has no `workflow_dispatch` trigger, so no dispatch can add a `skipped` (= passing) check
/// run under a required name. The policy step pins [`PINNED_JOBS`], a superset.
pub(crate) const REQUIRED_JOBS: &[&str] =
    &["linux-fast", "windows-native", "xwin-cross", "linux-full"];

/// The jobs whose gate lines ([`REQUIRED_GATE_RUNS`]), conditions ([`REQUIRED_JOB_CONDITIONS`]) and structure the
/// policy step pins (M4 review C-5, R-01): the required checks of [`REQUIRED_JOBS`] and the jobs `linux-full`
/// delegates to — the ct gate `ct`, the mutation shards `mutants-shard` with their verdict job `mutants`, and the
/// SecMP-HX models `proverif-hx`. Like the required names they exist only in [`REQUIRED_WORKFLOW`]. (A skipped job
/// counts as passing on GitHub, so the in-repo pin is needed whether or not the ruleset requires them.)
pub(crate) const PINNED_JOBS: &[&str] = &[
    "linux-fast",
    "windows-native",
    "xwin-cross",
    "linux-full",
    "ct",
    "mutants-shard",
    "mutants",
    "proverif-hx",
    // M5 (BRIEF_M5-B §1): the SecMP-LINK models
    "proverif-link",
];

/// The `needs:` of a pinned job, as (job, the one job it needs) — M4 review C-5: the verdict job `mutants` needs
/// exactly `mutants-shard` (ADR-047 Amendment 1 (2)), written as that plain scalar; any other `needs:` on a pinned job
/// is a finding (a skipped or failing dependency would skip the job).
pub(crate) const PINNED_JOB_NEEDS: &[(&str, &str)] = &[("mutants", "mutants-shard")];

/// Where each `--delegated <step>` of a pinned gate line runs, as (step, pinned job) — M4 review C-5: the policy step
/// refuses a delegation without an entry here, and an entry whose job has no pinned gate line of its own; a pinned
/// `--models tr` needs a pinned `proverif --models hx` line.
pub(crate) const DELEGATED_TO: &[(&str, &str)] = &[
    ("windows-native", "windows-native"),
    ("windows-cross", "xwin-cross"),
    ("mutants", "mutants"),
    ("ct", "ct"),
    // M5 (BRIEF_M5-B §1): the `ci-full` step `proverif-link` runs in the job of the same name
    ("proverif-link", "proverif-link"),
];

/// The `cargo xtask` gate `run:` lines of each pinned job of [`PINNED_JOBS`], in order (M3 review F3, R-09;
/// `install-tools` aside; M4 review C-5 adds the delegated jobs). The policy step refuses any other gate line, a
/// missing one and an appended `|| true`. An accident guard (the real control is review of the workflow and of this
/// file), not a tamper-proof one.
pub(crate) const REQUIRED_GATE_RUNS: &[(&str, &[&str])] = &[
    (
        "linux-fast",
        &[
            "cargo xtask ci-fast --strict",
            "cargo xtask step --strict sbom systemd",
        ],
    ),
    (
        "windows-native",
        &["cargo xtask step --strict clippy nextest doctest kat hello"],
    ),
    ("xwin-cross", &["cargo xtask step --strict windows-cross"]),
    (
        "linux-full",
        // the SecMP-HX models run in their own job `proverif-hx` (WEISUNG M4-5 §5), mutation testing in `mutants` (ADR-047),
        // the ct gate in `ct` (ADR-047 Amendment 1, M4 review C-2), the SecMP-LINK models in `proverif-link` (BRIEF_M5-B §1)
        &[
            "cargo xtask ci-full --strict --delegated windows-native --delegated windows-cross --delegated mutants --delegated ct --delegated proverif-link --models tr",
        ],
    ),
    // M4 review C-5 (R-01): the delegated jobs
    ("ct", &["cargo xtask step --strict ct"]),
    (
        "mutants-shard",
        &["cargo xtask step --strict mutants --shard ${{ matrix.shard }}/8"],
    ),
    ("mutants", &["cargo xtask step --strict mutants-merge"]),
    (
        "proverif-hx",
        &["cargo xtask step --strict proverif --models hx --jobs 4"],
    ),
    (
        "proverif-link",
        &["cargo xtask step --strict proverif --models link --jobs 4"],
    ),
];

/// The job-level `if:` of every pinned job of [`PINNED_JOBS`], `None` for none (external review EXT-1, M3 follow-up
/// F19; M4 review C-5): the policy step (an accident guard, not a tamper-proof control; the real control is review, M3
/// review F23) refuses any other condition — a condition that evaluates to false on `pull_request` would leave a
/// `skipped` check run under a pinned name, which GitHub counts as passing. `linux-full` and its delegated jobs exclude
/// only `push` (on `main`), by design since the M2 workflow change; the verdict job `mutants` runs after its shards
/// whatever their outcome (`always()`); the other three required jobs run on every event.
pub(crate) const REQUIRED_JOB_CONDITIONS: &[(&str, Option<&str>)] = &[
    ("linux-fast", None),
    ("windows-native", None),
    ("xwin-cross", None),
    (
        "linux-full",
        Some("github.event_name == 'schedule' || github.event_name == 'pull_request'"),
    ),
    (
        "ct",
        Some("github.event_name == 'schedule' || github.event_name == 'pull_request'"),
    ),
    (
        "mutants-shard",
        Some("github.event_name == 'schedule' || github.event_name == 'pull_request'"),
    ),
    (
        "mutants",
        Some(
            "always() && (github.event_name == 'schedule' || github.event_name == 'pull_request')",
        ),
    ),
    (
        "proverif-hx",
        Some("github.event_name == 'schedule' || github.event_name == 'pull_request'"),
    ),
    (
        "proverif-link",
        Some("github.event_name == 'schedule' || github.event_name == 'pull_request'"),
    ),
];
