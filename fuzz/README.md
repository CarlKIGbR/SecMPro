# fuzz/ — cargo-fuzz targets

One target for every decoder, the HX/TR/LINK state machines (message sequences) and the relay command
executor (docs/06 §4). Corpora are committed (`fuzz/corpus/<target>/`, minimised with `cargo fuzz cmin`).
`ci-full` runs every target for 120 s (fuzz smoke, step 6) with the pinned nightly (`xtask/src/tools.rs`)
and a per-target `-max_len` (`FUZZ_MAX_LEN`). The nightly 4 h campaign of docs/06 §4 does not exist yet; a
scheduled, non-required job arrives in M3 (M2 review F2). The gate runs exactly the targets listed in
`xtask/src/expect.rs` (`FUZZ_TARGETS`), so a removed target fails CI.

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
content (the libFuzzer convention); `Response/CELLR` rows go to the selector of their `context`.
