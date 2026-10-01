# Reference-implementation spec questions — M3 (`tr` suite)

Reviewer: Fable. Date: 2026-09-30. Brief: REF-M3 (2026-09-30). Spec: `docs/03-protocol-spec.md` rev 2.3 (unchanged by these answers). SCHEMA: `vectors/SCHEMA.md` rev 4 (adds §4.9 `tr`, tag `tr`, case table `vectors/SCHEMA-4.9-tr.md`). The form follows `ref-spec-questions-M2.md`, in a table: the question as the reference asked it, the cases it touches, the reviewer's answer, the status. The reference's "readings adopted without a question — REF-M3" are listed in the second section; the reviewer accepts all of them.

Reference deliverable: `vectors/ref/tr.json`, SHA-256 `01a6d161138508af8fedd27df0fe5c62d473dbbf27530accbe6cde293201a837`, 96 cases (1 `init`, 40 `send`, 40 `recv`, 2 `advance`, 13 `recv-reject`); 10 340 distinct message keys tracked, none reused. Libraries: Python 3.12.14, kyber-py 1.2.0, dilithium-py 1.4.0, PyNaCl 1.6.2 (libsodium 1.0.20), cryptography 50.0.1.

Copy direction: `SecMProRef → SecMPro` only (ADR-026).

## Questions and answers

| ID | Question | Affected cases | Answer | Status |
|---|---|---|---|---|
| SQ-22 | **Batch payload length (§7.6, D.5).** The brief said "m05 Batch L=1689". A Batch body is `count(1) ‖ AppMessage(msg_id 16 ‖ kind 1 ‖ expire_after 4 ‖ payload_len 2 ‖ payload L)` = 24 + L, and it must fit the Content body limit of 1689 B, so L ≤ 1665. Which is meant? | m05 `send` and m05 `recv` (bytes change); no state digest | **L = 1665 is the reading.** The brief's figure was the reviewer's slip: 1689 is the limit of the whole Batch body, not of the payload (24 + 1665 = 1689). It touches the bytes of the two cases and no state digest. | answered |
| SQ-23 | **Key that seals negative N9 (§7.4).** The brief's N9 said "sealed under the sender's `nhk_s`". Taken literally, the receiver A holds no key that opens such a header. Which key is meant? | N9 (one case); the SCHEMA-4.9 row wording | **The reference's reading is the intended one.** N9 is sealed under the key m16 is sealed under: B's current `hk_s`, which is A's `nhk_r`. A therefore opens the header through `nhk_r`, and it is the `dh_pk == dh_r` check that rejects it, as N9 is meant to test. The SCHEMA §4.9 row is corrected to read "under the sender's current `hk_s`". | answered |
| SQ-24 | **Digest label not in App. A (App. A).** The state digest uses the label `"SecMP-TR/1 state-digest"`. App. A calls itself exhaustive and does not list it. Is the label allowed, and where is it recorded? | none | **Yes.** It is a test-construct label, of the same kind as `"SecMP-vectors/1"`, and not a protocol label. It is recorded in SCHEMA §4.9 now. It is to be listed in App. A with the next spec revision, by an ADR of the reviewer. Until then the reference's prefix-freedom test is the guard. | answered |

## Readings adopted by the reference without a question (all accepted by the reviewer)

1. **KDF output split (§7.2).** KDF outputs are split into 32-byte thirds. The root-KDF input is the X25519 output ‖ the ML-KEM secret, in that order.
2. **Randomness order (§7.2, §7.4).** `hdr_nonce` is drawn after the message key. Key generation and Encaps are drawn in the order of the §7.2 and §7.4 lines.
3. **Opening a header includes decoding it.** A header that opens but does not decode rejects (negative N11).
4. **Skipped-key path.** It has no KEM-constancy check and no `dh_pk` check. The entry is removed only after the body MAC verifies.
5. **Decrypt transaction.** It ends at the body MAC; the Content is decoded afterwards. Note for the Rust side: a MAC-valid cell whose Content does not decode advances the state. No vector exercises this case. The Rust plan must state its behaviour.
6. **u32 counter overflow.** It aborts on send and rejects on receive.
7. **Order inside a phase.** All sends precede the deliveries.
8. **Re-sealed negative headers.** They keep the original `hdr_nonce` and the original body.
9. **Advance Dummies.** They use `seq = 0` and `ts = 0`, and list their nonces as `hdr_nonces`.
10. **N1.** It lists the DH-step randomness, because it is rejected after the step has run.
11. **`party`.** It is `"AB"` for `init`. `recv-reject` also carries `msg` and `from`.
12. **Batch payloads.** They are raw stream bytes.

## State 2026-09-30

All three answers are settled. Spec rev 2.3 is unchanged and SCHEMA is rev 4. SQ-22 touches the bytes of two cases (m05 `send` and `recv`), SQ-23 touches one case (N9), SQ-24 touches none, and no answer changes a state digest. Open: the listing of `"SecMP-TR/1 state-digest"` in App. A, which waits for the next spec revision and an ADR of the reviewer; the reference's prefix-freedom test is the guard until then. The twelve readings above are accepted as they stand; item 5 is a duty for the Rust plan, not a vector.

## Implementer questions (Rust, M3) — added 2026-10-01 by the implementer, for the reviewer

The M3 brief directs spec clarifications found while implementing to this file. None of the three touches a vector
or a byte layout; each has a reading in place (`docs/reviews/M03-report.md` §1.2 D6/D7), so none blocks.

| ID | Question | Affected | Reading implemented | Status |
|---|---|---|---|---|
| SQ-25 | **Fragment reassembly rules (§7.6, D.5: "chunk sizing and consistency across the fragments of one `msg_id` are reassembly rules").** The spec defines the encoding of a fragment but not the reassembly: what if fragments of one `msg_id` disagree on `total`, an `idx` arrives twice, the chunks have unequal sizes, or many messages are in reassembly at once? | `tr::content::Inbox` (no vector) | Fragments of one `msg_id` must agree on `total`; an identical duplicate of a stored `idx` is ignored (re-sends after eviction or rotation, §9.5, §10.6 rule 4, repeat fragments); a conflicting duplicate or a `total` mismatch discards the partial message; complete = every `idx < total` present, the chunks concatenated in `idx` order and decoded as `FragmentPayload`; chunks of any size are accepted (the sender uses maximal 1669-byte chunks, SCHEMA-4.9); at most `MAX_PARTIALS` = 8 messages in reassembly, the oldest evicted first (memory ≤ 8 × 64 × 1669 B); the partial messages are persisted with the session (`Inbox::to_bytes`), since a stored fragment is "processing committed" before its cell is acknowledged (§7.5). | open (reading in place) |
| SQ-26 | **Key-change semantics (§7.7, §6.6, §6.7).** §7.7: "receivers verify, mark the contact unverified, block outgoing messages until re-verification. Unsigned/unverifiable changes freeze the session with a warning." Which messages are blocked, what does "freeze" stop, and how does a frozen session end? | `tr::content::Trust` (no vector) | Blocked = *real* outgoing messages; dummies continue in every state (CLAUDE.md §1.4: the frames never depend on activity or trust). A verified change → `KeyChanged` (no real message sent until the user confirms the new safety number → `Verified`). An unverifiable change → `Frozen`: no content is delivered and no real message sent; `verify()` does not unfreeze — only a new invitation (§7.8) does. A new contact before its safety-number confirmation (`Unverified`, §6.6 step 4) may send real messages (§6.6 step 4 "start sending to I's reply route"). | open (reading in place) |
| SQ-27 | **`seq`/`ts` of a dummy (§7.6).** §7.6 gives every Content a `seq` ("per-session application sequence … gaps ⇒ messages may be missing") and a `ts`; a Dummy is "discarded silently". Which `seq`/`ts` does a dummy carry? | `tr::content::dummy()` (no vector: the vectors' dummies m02/m06/m31 carry the message number, the advance dummies 0, SCHEMA-4.9 "(proposal)") | `seq` = 0 and `ts` = 0: dummies are not application messages, so they take no sequence number (a lost dummy — routine under eviction — must not show as a gap) and carry no clock value. | open (reading in place) |
