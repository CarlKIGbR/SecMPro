# fuzz/ — cargo-fuzz targets

One target for every decoder, the HX/TR/LINK state machines (message sequences) and the relay command
executor (docs/06 §4). Corpora are committed (`fuzz/corpus/<target>/`, minimised with `cargo fuzz cmin`).
The gates run exactly the targets listed in `xtask/src/expect.rs` (`FUZZ_TARGETS`), so a removed target fails
CI, with the pinned nightly (`xtask/src/tools.rs`) and a per-target `-max_len` (`FUZZ_MAX_LEN`).

- **Fuzz smoke** (`ci-full` step 6, `cargo xtask step fuzz`, every PR): every target for 120 s
  (`FUZZ_SMOKE_SECONDS`).
- **Nightly campaign** (`.github/workflows/fuzz-nightly.yml`, daily at 00:23 UTC and on dispatch; not a
  required check; `cargo xtask step fuzz-nightly`): 4 h (`FUZZ_NIGHTLY_SECONDS` = 14 400 s) shared equally by
  the targets (1 200 s each with the 12 targets of M2). The workflow uploads the scratch corpus and any crash
  inputs as artefacts; taking inputs into `fuzz/corpus/` (after `cargo fuzz cmin`) is a manual, reviewed commit.
  The same workflow runs the `secmp-proto` tests with `SECMP_PROPTEST_SEED` set to the run id, so the seeded
  property tests explore a new seed every night.

Both run each target as `cargo fuzz run --fuzz-dir fuzz <t> target/fuzz-corpus/<t> fuzz/corpus/<t> --
-max_total_time=<s> -max_len=<n>` (M2 review F7): libFuzzer writes new inputs only into the first corpus
directory, the scratch corpus under `target/`, so a gate never changes the tracked corpus; crash inputs go to
`fuzz/artifacts/<t>/`. Before each target runs, a seeding step deletes and re-creates
`target/fuzz-corpus/<t>/` and writes the inputs derived from the frozen vectors into it
(`xtask/src/fuzzseed.rs`, keyed by target):

| Target | Frozen suite | Seeds |
|---|---|---|
| `msg_open` | `msgencrypt` | seal cases in mode 1 (seal, open, flip) and their `C ‖ TAG` in mode 0; open cases in mode 0 |
| `caead_open` | `caead` | seal cases in mode 1 and their `COM ‖ C` in mode 0; open cases in mode 0 |
| `mlkem_parse` | `hybridkem-768`, `hybridkem-1024` | every `ek`, `ct` and 64-byte seed behind its mode byte |
| `x25519_dh` | `hybridkem-768`, `hybridkem-1024` | the case's X25519 secrets and each of its public keys |
| `ed25519_verify` | `hybridsign` | `pk_ed` (and `ed_seed`) ‖ the Ed25519 half of `sig` ‖ `msg` |
| `hybrid_sign_verify` | `hybridsign` | key import (mode 0), `sig ‖ msg` (mode 1), signing `msg` (mode 2) |
| `mldsa65_verify` | `hybridsign` | key import (mode 0), the ML-DSA-65 half of `sig` (mode 1) |
| `proto_*` | `encodings` | every decodable row (positives and negatives) as selector ‖ bytes, by structure (below) |

A seed longer than the target's `-max_len` is cut to it; an AD above 255 bytes to the targets' one-byte length.
A target without a seeding rule relies on its tracked corpus.

This directory is its own Cargo workspace with its own `Cargo.lock` (seeded from the workspace lockfile so
shared crates keep their vetted, cooled-down versions; `cargo xtask cooldown` checks both lockfiles). Its only
additional dependencies are `libfuzzer-sys` and `arbitrary` (ADR-037); it is never part of a shipped build.

Test code here may use `#![allow(clippy::unwrap_used, clippy::expect_used)]` at the file top (docs/06 §2).
The targets do not declare `#![forbid(unsafe_code)]`: `fuzz_target!` expands to a `#[no_mangle]` entry point,
which the `unsafe_code` lint reports; the targets themselves contain no `unsafe`.

## M1 targets (`secmp-crypto`)

| Target | Input | Invariants |
|---|---|---|
| `x25519_dh` | two secrets, one public key | no panic; result non-zero or the uniform rejection; DH symmetric |
| `ed25519_verify` | `A ‖ sig ‖ msg` | strict import round-trips; honest signatures verify; any other signature is rejected |
| `mldsa65_verify` | key bytes / context and signature | import round-trips; arbitrary signatures are rejected under a fixed key |
| `mlkem_parse` | ML-KEM-768/1024 ek, ct or seed | validated ek import round-trips; decapsulation deterministic (implicit rejection); seed keys round-trip |
| `hybrid_sign_verify` | key bytes / label, signature, message | import round-trips; forged signatures and non-HybridSign labels are rejected; sign → verify, one flipped byte → reject |
| `msg_open` | `AD`, `C ‖ TAG` | arbitrary input is rejected (any length); seal → open; one flipped byte → reject |
| `caead_open` | nonce, `AD`, `COM ‖ C` | arbitrary input is rejected; seal → open; one flipped byte → reject |

## M2 targets (`secmp-proto`)

Every Appendix D decoder, one target per section; the first input byte selects the decoder (modulo the number
of decoders, order as listed). Invariants for all: no panic; whatever a decoder accepts re-encodes to exactly its
input (total, exact-fit, canonical). The key and signature checks of `secmp-crypto` run for real.

| Target | Decoders (selector 0, 1, …) |
|---|---|
| `proto_records` | D.1: `HELLO`, `RELAYINFO`, `HS1`, `HS2` records, `RelayInfoV1` |
| `proto_frames` | D.2: request plaintext, response plaintext in answer to `FETCH`, to `FETCH_MULTI` |
| `proto_invitation` | D.3: `RelayRef`, `InvitationV1`, `Profile`, `LinkDataV1`, `LinkBlob`, `IKSPublic`, `PrekeyBundle` |
| `proto_handshake` | D.4: `Outer`, `inner_ct`, `Inner`, `HandshakeCell`, `HandshakeCellPlaintext` |
| `proto_cell` | D.5: `Cell`, `HeaderV1`, `Content`, `AppMessage`, `BatchBody`, `Fragment`, `FragmentPayload`, `RouteDescriptor`, `RelayQueue`, `RouteUpdateBody`, `HandshakeBody`, `KeyChangeBody`, `ReceiptBody`, `ControlBody` |

Seed corpora: every row of the frozen `vectors/encodings.json` except the encode-only `Signed/*` rows (78
positives, 547 negatives), each as `selector ‖ bytes` in the target of its structure, file name the SHA-1 of the
content (the libFuzzer convention); `Response/CELLR` rows go to the selector of their `context`, the other
`Response/*` rows to selector 1 (`FETCH`). The gates' seeding step writes the same rows into the scratch corpus on
every run (`fuzzseed::encodings_target`), so the tracked corpus holds what `cargo fuzz cmin` kept.
