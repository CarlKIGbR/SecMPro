# Accepted mutation survivors

`docs/06` §4: `cargo mutants` on `secmp-crypto`, `secmp-proto` and `secmp-relay` (ADR-047 Amendment 3) must leave **zero surviving mutants, or each
survivor documented here** with the reason it cannot be detected by a test. Every entry names the mutant as
`cargo mutants` prints it and the milestone that accepted it. An entry is removed when the code changes.

| Mutant | Why no test can detect it | Compensating control | Accepted in |
|---|---|---|---|
| `crates/secmp-crypto/src/secret.rs`: `replace <impl Drop for SecretBytes<N>>::drop with ()` | Zeroisation on drop: after `drop` the heap allocation is freed; reading it again is undefined behaviour, so no sound test can observe whether the bytes were overwritten. | The zeroising `Drop` is two lines calling `zeroize::Zeroize` (volatile writes + compiler fence); the zeroising step itself is unit-tested (`secret::tests::secret_bytes_zeroise_on_drop_step`); long-lived secrets use `LockedSecret`, whose `SecretPage` zeroises before `munmap`/`VirtualFree` (its `Drop` is outside the mutated crates). | M1 |
| `crates/secmp-proto/src/inv.rs`: `replace | with ^ in base64url_encode` | Equivalent mutant: in `(b0 << 16) \| (b1 << 8) \| b2` the three operands occupy disjoint bit ranges (bits 16..24, 8..16, 0..8; each byte is at most 0xff), so `\|` and `^` give the same value on every input. | The masks are stated in a comment at the line; `inv::tests::base64url_vectors` checks the whole encoding against RFC 4648 §10. | M4 (M4-12) |
| `crates/secmp-proto/src/inv.rs`: `replace | with ^ in base64url_decode` | Equivalent mutant: in `(group << 6) \| (v & 0x3f)` the shifted operand has bits 0..6 clear and the appended one has only bits 0..6 set, so `\|` and `^` give the same value on every input. | The masks are stated in a comment at the line; `base64url_vectors` checks the decoding against RFC 4648 §10. | M4 (M4-12) |
| `crates/secmp-relay/src/server.rs` (`:81`): `replace <impl Stream for TcpStream>::set_poll -> io::Result<()> with Ok(())` | The `std::net` shim of the server's `Stream` trait (2 lines: blocking mode and read timeout of a real `TcpStream`); only a socket can observe it, and `docs/06` §4 allows no network in tests. | Every loop decision is in the generic `server::handle`/`serve`, tested with in-memory streams and a virtual clock (`server_loop::*`, incl. a stream whose `set_poll` fails); the shim only forwards to `TcpStream`. | M5 (Phase B) |
| `crates/secmp-relay/src/server.rs` (`:86`): `replace <impl Stream for TcpStream>::close with ()` | The `std::net` shim's close (one `shutdown(Both)` of a real `TcpStream`); only a socket can observe it (no network in tests, `docs/06` §4). | `server_loop::*` checks that every path of `handle`/`serve` calls `close` on the in-memory stream; a dropped `TcpStream` is closed by the OS as well. | M5 (Phase B) |

History (M1, first full run, 2026-09-28: 241 mutants, 149 caught, 86 unviable, 6 missed): besides the entry above,
the missed mutants were fixed rather than accepted — an unused `kat` helper (`Caead::commitment_kat`) was removed;
the equivalent `<`/`<=` mutant in `ed25519::strict::less_than` disappeared with a `cmp`-based comparison; the
byte-level signature checks of `Ed25519VerifyingKey::verify` (which `ed25519-dalek` duplicates, so an end-to-end
test cannot see them) moved into `strict::signature_ok` with direct unit tests; the redundant `% 100000` in the SAS
digit conversion (equivalent to the five-digit extraction that follows) was removed.
