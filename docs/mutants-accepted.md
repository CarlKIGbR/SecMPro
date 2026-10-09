# Accepted mutation survivors

`docs/06` §4: `cargo mutants` on `secmp-crypto`, `secmp-proto` and `secmp-relay` (ADR-047 Amendment 3) must leave **zero surviving mutants, or each
survivor documented here** with the reason it cannot be detected by a test. Every entry names the mutant as
`cargo mutants` prints it in `missed.txt`/`timeout.txt` (`<path>:<line>:<column>: <description>`): its place as
`` `<path>:<line>` `` (`` `<path>:<line>:<column>` `` where two survivors share a line) and its description in backticks,
and the milestone that accepted it. The gate (`xtask/src/gates.rs`, `undocumented_survivors`) accepts a survivor only
when one row names both its place and its description (M5 review R-114, C-7), so the same mutation elsewhere in the
file is not accepted. A row whose code moves is updated to the new line; an entry is removed when the code changes.

| Mutant | Why no test can detect it | Compensating control | Accepted in |
|---|---|---|---|
| `crates/secmp-crypto/src/secret.rs:59`: `replace <impl Drop for SecretBytes<N>>::drop with ()` | Zeroisation on drop: after `drop` the heap allocation is freed; reading it again is undefined behaviour, so no sound test can observe whether the bytes were overwritten. | The zeroising `Drop` is two lines calling `zeroize::Zeroize` (volatile writes + compiler fence); the zeroising step itself is unit-tested (`secret::tests::secret_bytes_zeroise_on_drop_step`); long-lived secrets use `LockedSecret`, whose `SecretPage` zeroises before `munmap`/`VirtualFree` (its `Drop` is outside the mutated crates). | M1 |
| `crates/secmp-proto/src/inv.rs:163:32`: `replace | with ^ in base64url_encode` | Equivalent mutant (the first `\|`): in `(b0 << 16) \| (b1 << 8) \| b2` the three operands occupy disjoint bit ranges (bits 16..24, 8..16, 0..8; each byte is at most 0xff), so `\|` and `^` give the same value on every input. | The masks are stated in a comment at the line; `inv::tests::base64url_vectors` checks the whole encoding against RFC 4648 §10. | M4 (M4-12) |
| `crates/secmp-proto/src/inv.rs:163:44`: `replace | with ^ in base64url_encode` | Equivalent mutant (the second `\|` of the same expression): the operands are disjoint as above, so `\|` and `^` give the same value on every input. | As above. | M4 (M4-12) |
| `crates/secmp-proto/src/inv.rs:202`: `replace | with ^ in base64url_decode` | Equivalent mutant: in `(group << 6) \| (v & 0x3f)` the shifted operand has bits 0..6 clear and the appended one has only bits 0..6 set, so `\|` and `^` give the same value on every input. | The masks are stated in a comment at the line; `base64url_vectors` checks the decoding against RFC 4648 §10. | M4 (M4-12) |

History (M1, first full run, 2026-09-28: 241 mutants, 149 caught, 86 unviable, 6 missed): besides the entry above,
the missed mutants were fixed rather than accepted — an unused `kat` helper (`Caead::commitment_kat`) was removed;
the equivalent `<`/`<=` mutant in `ed25519::strict::less_than` disappeared with a `cmp`-based comparison; the
byte-level signature checks of `Ed25519VerifyingKey::verify` (which `ed25519-dalek` duplicates, so an end-to-end
test cannot see them) moved into `strict::signature_ok` with direct unit tests; the redundant `% 100000` in the SAS
digit conversion (equivalent to the five-digit extraction that follows) was removed.

M5 (review 2026-10-09, R-114/R-163, C-7): the two `secmp-relay` rows of Phase B (`server.rs:81`
`<impl Stream for TcpStream>::set_poll` and `server.rs:86` `<impl Stream for TcpStream>::close`) were removed — not
equivalent (`set_poll`'s read timeout carries the 30-s pre-HELLO bound); a loopback test kills both.
