**Reviewer:** codex gpt-6.1-sol  
**Pin:** `e8359b19aa0b34b6b8b9b6e99eddbc984579819b` (`m04-hx`)  
**Tree:** `b01cf1417cb5d1597af52e5b75a253ff053eb144`  
**Base:** `836a94e4f8abec27d877740291ecbe9957c10177`  
**Date:** 2026-10-03  
**Files read:** 99 distinct files, including files read in relevant portions.

HEAD and tree matched the requested pin at the beginning and end of the review. No source files were edited; the final Git working-tree status was clean. The prohibited internal reports and evidence directories were not read.

The findings below comprise **two blockers and four majors**. Rust reproductions are source-level reproductions, not executed tests. The independent Python grouping reproduction was executed with preauthenticated plaintext inputs.

**Findings**

[EXT-1] **blocker — `crates/secmp-proto/src/hx/mod.rs:67@e8359b1` — `HandshakeCells::release` can persist an older ratchet state after the caller has advanced and persisted the state returned by `Initiator::start`, enabling message-key reuse after restart.**

`Initiator::start` returns both a usable `RatchetState` and `HandshakeCells` containing a separate, frozen serialization of that state. Advancing the returned state does not update the serialization subsequently supplied by `release`.

Evidence:

```rust
state_bytes: state.to_bytes()?,                         // hx/mod.rs:70
persist(&self.to_bytes(), &self.state_bytes)?;           // hx/mod.rs:91
Ok((HandshakeCells::new(cells, &state)?, state))          // hx/initiator.rs:244
```

Source-level reproduction using the public APIs:

1. `Initiator::start` returns pending handshake cells and state S1, after encryption of `first_msg`, with `n_s = 1`.
2. Encrypt a dummy or queued message using S1, then call `Sealed::persist` with the real checkpoint writer. This creates and persists S2, with `n_s = 2`. A real message can remain in the outbox as §6.5 requires.
3. Call the pending `HandshakeCells::release` with the same durable checkpoint destination. Its callback receives S1, overwriting the newer checkpoint with the old sending chain.
4. Restart from that checkpoint and encrypt again. The sending chain and counter are those used for the earlier message.

**Expected:** releasing the pending handshake cannot roll back a newer durable sending chain.  
**Observed by source:** `release` supplies its original S1 snapshot without observing the live state. `tr/ratchet.rs:675–681` derives the message key from that chain; fresh header randomness does not make the message key new.

This violates the single-use message-key and persistence requirements in `docs/03-protocol-spec.md:488` and `docs/06-engineering-standards.md:54`. The persistence test at `tests/hx_persist.rs:139` compares only an unadvanced returned state with the frozen snapshot.

**Smallest fix:** make the pending handshake own the live ratchet state. Release the cells and usable state together only after their persistence succeeds, so no independently advanceable state exists before that transaction.

[EXT-2] **blocker — `crates/secmp-proto/src/prekeys.rs:495@e8359b1` — `add_record` permits two invitation records to name the same OPK, violating the “one per one-time invitation” invariant and allowing one record’s expiry or successful acceptance to invalidate the other.**

The validation checks that the named SPK and OPK exist and that `ld_id` is unique. It does not check whether another record already names `record.opk_id`.

Source-level reproduction:

- Generate SPK 7 and OPK 42.
- Add record A with `(ld_id=A, spk_id=7, opk_id=42, expires=100)`.
- Add record B with `(ld_id=B, spk_id=7, opk_id=42, expires=200)`.
- Both calls pass the checks at `prekeys.rs:496–498`.
- Call `retire_expired(100)`.

**Expected:** B has its own OPK and remains usable, or the second insertion is rejected.  
**Observed by source:** A contributes 42 to `dead_opks`; `prekeys.rs:550` removes OPK 42 globally. B remains an unexpired, offered record but acceptance fails because its OPK is gone. Successful acceptance of A has the same effect on B.

The public bundle construction path can also sign multiple bundles naming the same live OPK; normal `issue_invitation` avoids this by generating a fresh OPK. This finding concerns the permitted store state, not two successful accepts within one store: `commit_accept` correctly prevents the latter.

`docs/03-protocol-spec.md:275` requires a single-use OPK pair, one per one-time invitation. `prekey_store_one_opk_per_invitation` tests two normal issuances, not two distinct records naming one OPK. K4b has only one record.

**Smallest fix:** reject `add_record` whenever an existing record names the same `opk_id`, and cover insertion, expiry and acceptance with two distinct `ld_id`s competing for one OPK.

[EXT-3] **major — `crates/secmp-proto/src/prekeys.rs:289@e8359b1` — the persistent invitation `link_key` is held in ordinary zeroized heap memory rather than locked, guarded memory.**

Evidence:

```rust
pub link_key: SecretBytes<HASH_LEN>,                    // prekeys.rs:289
/// A copy (the link key is duplicated into locked memory) // prekeys.rs:299
link_key: SecretBytes::from_slice(self.link_key.expose_secret())?, // :307
```

`SecretBytes` is an ordinary heap allocation with wipe-on-drop (`secmp-crypto/src/secret.rs:13`). `LockedSecret` uses `SecretPage` (`secret.rs:71`). Invitation records retain this key until consumption or expiry; it protects both the link-data blob and the outer handshake layer.

**Expected:** the long-lived record key follows CS-2.2’s locked, guarded storage requirement.  
**Observed:** neither the record nor `duplicate` locks it. The documentation also incorrectly describes the copy as locked.

The explicit M3 memory exception in `docs/04-client-security.md:45` covers ratchet `rk/ck/hk/nhk` and specified library stack residues. It does not cover invitation-record `link_key`. No actual swap disclosure was demonstrated.

**Smallest fix:** store the persistent record key in `LockedSecret<32>` or an equivalent guarded allocation, retaining zeroized temporary copies where required, and correct the `duplicate` documentation.

[EXT-4] **major — `crates/secmp-proto/src/hx/responder.rs:117@e8359b1` — grouping compares decrypted `init_id`s through ordinary `PartialEq` and stops at the first matching group, outside the constant-time comparison guard.**

Evidence:

```rust
impl<K: PartialEq, C, const N: usize> Groups<K, C, N> {   // responder.rs:94
.position(|g| g.as_ref().is_some_and(|g| g.init_id == *init_id)) // :121
```

Production `K` is the 16-byte `init_id` parsed from authenticated, decrypted handshake-cell plaintext (`responder.rs:251`). It is generated through `entropy.secret::<16>()` and is deliberately concealed from the relay. It is distinct from the public bundle `spk_id`/`opk_id` comparisons explicitly excluded from the CT targets.

Source-level input: hold eight partial groups, then deliver a valid duplicate chunk matching the first versus the eighth group. The search performs one versus eight identifier comparisons and exits on the match. Ordinary array equality supplies no constant-time guarantee for the comparison itself.

**Expected:** protected identifier comparisons follow the `subtle` comparison guard; early matching does not introduce an unreviewed identifier-dependent timing path.  
**Observed:** ordinary equality and first-match search are used. No timing measurement or practical extraction of an identifier was demonstrated. Existing HX CT targets do not measure this path.

**Smallest fix:** use constant-time identifier equality and a fixed scan with accumulated selection, then make the grouping decision. Add coverage for matches at different retained positions. The accepted timing difference between authentication stages remains a separate limitation.

[EXT-5] **major — `ref/secmp_ref/hx.py:328@e8359b1` — the Python responder implements the older grouping and acceptance rules, leaving ADR-044’s M4 behavior without corresponding independent reference coverage.**

`_complete_chunks` uses an unbounded dictionary and returns the first completed group. `respond` invokes it once; rejection of that group ends the attempt. The responder also lacks the Rust implementation’s reflection, `n/pn = 0`, and at-least-one-known-route checks.

Executed reproduction: extract and execute the original `_complete_chunks` function with `open_cell` replaced by an identity function over preauthenticated plaintexts. Supply chunks 0 and 1 for nine distinct `init_id`s, then chunk 2 for the oldest group.

**Expected under ADR-044(c):** the oldest group was evicted when the ninth partial group arrived; no group completes.  
**Observed from the original Python function:** the oldest group completes and returns 12,018 bytes. A separate eight-group oracle returns no completed group and retains eight partial groups.

The function’s first-complete return is at `hx.py:340–341`; single-attempt use is at `:356`. After decoding the initiator identity and decrypting `first_msg`, `respond` checks content type and then deletes the OPK (`:381–401`) without the additional ADR-044(e)/(f) checks.

This finding does **not** challenge the accepted decision to keep the 30 frozen vectors unchanged. It identifies the reference’s revision gap: the unchanged vectors cannot independently validate the new rules.

**Smallest fix:** implement the ADR-044 responder rules independently in Python and add separate revision-specific cases for eviction, rejected-group continuation, reflection, nonzero counters and unknown-only routes, while retaining the frozen vector set.

[EXT-6] **major — `xtask/src/gates.rs:179@e8359b1` — the forced portable-backend KAT rerun omits the HX integration target and therefore does not run the frozen HX vectors on that selectable backend.**

Evidence:

```rust
("secmp-crypto", &["kat_mlkem", "vectors"][..]),
("secmp-proto", &["tr_vectors"][..]),                    // gates.rs:181–182
```

That loop sets `LIBCRUX_DISABLE_SIMD128=1` and `LIBCRUX_DISABLE_SIMD256=1`. The normal KAT invocation includes the HX suite, but the portable rerun selects only `tr_vectors` for `secmp-proto`. The M4 integration target is named `hx` in `crates/secmp-proto/Cargo.toml`.

**Expected:** the portable invocation runs frozen HX vectors as required by `docs/06-engineering-standards.md:115`, which requires the KATs and frozen SecMP vectors on every selectable backend.  
**Observed by gate construction:** no `--test hx` is added. Primitive ML-KEM and TR KATs do not exercise the full HX composition on that path.

**Smallest fix:** include the `hx` target, or explicitly select its vector checks, in the portable-backend rerun.

**Review-focus verdicts**

“Met” below means met by inspected source and assertions; it does not represent a fresh successful test or proof run.

| Review focus item | Verdict | Evidence pointer |
|---|---|---|
| M4: transcript completeness, §6.4 | met | `hx/derive.rs:52–75`; independent concatenation and 13-component sensitivity tests in `hx/tests.rs` and `tests/hx/props.rs` |
| M4: `K_id` inputs | met | `hx/derive.rs:118–134`: salt `ld_id`; `link_key ‖ DH3 ‖ ss_spk ‖ DH4 ‖ ss_opk`; no DH1/DH2 or initiator identity input |
| M4: OPK deleted only on success | met | Acceptance driver `hx/responder.rs:202–214`; record/OPK binding and atomic in-memory consumption `prekeys.rs:715–724`. Record exclusivity separately fails EXT-2 |
| M4: no signature by I | met | `InitiatorKeys`, `Initiator::start`; envelope layouts; signature-call counting assertion in `tests/hx/accept_ok.rs` |
| M4: `first_msg` route equals stored route | met | `hx/responder.rs:375–390` moves the authenticated Handshake routes; route-equality tests |
| M4: garbage cells ignored, not fatal | met | Trial-open filtering `hx/responder.rs:239–251`; later-group processing `:193–214`; interleaving and grouping tests |
| §9: invented constructions | met | INV/HX compositions match §§5–6 and Appendix A; primitives remain behind `secmp-crypto` |
| §9: nonce/counter handling, including restart | not met | EXT-1 permits durable sending-chain rollback and message-key reuse |
| §9: domain separation and transcript binding | met | `inv.rs:261–270`, `hx/derive.rs`, envelope AD construction and Appendix A labels |
| §9: non-constant-time comparisons | not met | EXT-4: decrypted `init_id` equality and grouping search |
| §9: premature `Choice`→`bool` conversion / secret `&&` or `||` | met | Fingerprint and reflection conversion occurs at their final individual decisions; CAEAD checks combine `Choice`s; hybrid verification evaluates both halves |
| §9: unchecked zero DH, noncanonical points or malformed KEM keys | met | Key import wrappers, `dh_checked`, wire decoders; relevant INV/HX negative assertions |
| §9: secrets in `Debug`, logs or errors | met | Secret wrappers redact contents; uniform protocol error; no identifying production logging in reviewed INV/HX paths |
| §9: tests only round-trip against the same implementation | not met | External vectors exist and match, but ADR-044 reference coverage and portable HX execution are incomplete: EXT-5, EXT-6 |
| §9: panics on malformed input | met | Exact-fit/fallible decoders, checked slicing and bounded grouping; parser/fuzz/Kani assertions inspected. Execution remains unverified |
| §9: crate names/APIs exist at pinned versions | not verifiable | Source references inspected, but offline Cargo dependency resolution failed before compilation |
| §9: authentication error-message oracles | met | Authentication/input failures return payload-free `Rejected`; `Unavailable` remains an environmental failure |
| §9: persistence ordering | not met | EXT-1; handshake cells are withheld until a callback succeeds, but the callback can receive stale state |
| §9: timing side channels in helpful early returns | not met | EXT-4. Authentication-stage cost differences already documented and accepted were not re-reported |
| Additional requested memory check: persistent `link_key` locked | not met | EXT-3 |
| Additional requested memory check: temporary key/plaintext wiping and growth copies | met | Secret RAII, zeroized derivation buffers, CAEAD plaintext buffers and `Writer::reserve`; subject to dependency-stack limitations below |

**Other results and categories checked without a finding**

**INV encoding, derivation and authentication — nothing found beyond EXT-3’s persistent storage issue.** The base64url implementation uses arithmetic rather than secret-indexed tables. Decoding rejects padding, the alternative alphabet, invalid length classes and nonzero unused trailing bits. The URI prefix is exact; the decoded invitation is exact-fit.

`K_ld` and `K_inv` match the specified salts, input order, lengths and distinct labels. The blob uses the specified 12,288-byte padding and AD containing its label and `ld_id`; its encoded length is 12,360 bytes.

R’s signature covers all encoded prekey-bundle fields preceding `sig`, followed by R’s `ik_dh`: a 4,434-byte signed message. The invitation fingerprint pins the complete 2,017-byte R identity. Invitee checks cover fingerprint, both signature halves, expiry boundaries, presence of the OPK, canonical imported keys and zero DH.

Invitation fields outside that signed message, and `LinkDataV1.profile/created`, remain outside the stated transcript agreement. An invitation holder can alter and reseal such material with the invitation key. This is the recorded RR-15 scope limitation, not an additional finding. The issuer-only bounds interpretation in ADR-043(h) was likewise not re-reported.

**HX derivation, wire protection and responder rejection paths — nothing found beyond EXT-1 and EXT-4.** All 13 transcript components appear in the specified order, with encoded identities, big-endian IDs and the required inner hashes. SK uses the `0xFF^32` prefix, all four DH shares, both ML-KEM-1024 shares and the transcript. `K_id` is computable before parsing I’s identity.

Inner size, outer size, padding, three-way chunking and both AD labels match the specification. The initiator’s EK secret is released after agreement, before state/envelope completion, and is absent from the returned and serialized state.

The Rust responder implements first-seen wins, processing of later groups after a complete group rejects, and the eight-partial-group bound. Reflection, valid-MAC nonzero counters, Handshake content/caps, and the known-route rule are checked. Replayed accepted envelopes lose access to the consumed record/OPK.

I found no Rust acceptance rejection path that mutates the in-memory prekey store. Cryptographic processing borrows it immutably; the final commit validates both objects and their binding before mutation. A rejected working ratchet is dropped. Entropy may be consumed while processing a working ratchet; it is not transactional state. The generic `PrekeyStore` implementation must honor its atomic-commit contract.

**Prekey rotation, ordinary issuance and deletion reachability — nothing found beyond EXT-2 and EXT-3.** Weekly SPK rotation retains referenced generations, and each RPK follows its SPK. Normal issuance allocates a fresh OPK and removes that newly allocated OPK on issuance failure. Rotation and ID allocation are not generally rolled back on issuance failure; no unchanged-store guarantee was inferred for that local creation API.

`delete_opk` is publicly reachable for explicit lifecycle operations, but acceptance reaches deletion through `commit_accept`. Test-feature duplication does not establish production-wide uniqueness across independent durable stores. I found no production clone API that by itself duplicates a held OPK into another `MemoryPrekeyStore`.

**Secret handling and unsafe code — nothing found beyond EXT-3 and EXT-4.** SK, `K_id`, `K_inv`, DH/KEM shares and derivation concatenations use wipe-on-drop storage. Opened inner plaintext and encoded plaintext buffers use zeroized allocations through success and error returns. Invitation and route types wipe their sensitive fields. The encoder’s explicit reserve path replaces the old zeroized allocation instead of leaving an ordinary growing-buffer copy.

The only `unsafe` found outside `secmp-sys-*` was the CT benchmark’s architecture-specific timer code, covered by ADR-038. No new production unsafe block was found.

**Formal claims and gate binding — nothing found outside the recorded model abstractions.**

The static inventory contains **21 HX rows**, including H6’s explicit “not claimed” row, and **20 active claimed rows**. Across the 19 files there are **87 individual result queries**, expressed in 23 query declarations: 31 property queries and 56 H11 reachability queries. The expected-result table also has 87 entries. No active claimed row lacks a corresponding query, and no result query lacks a claim row.

The following identifies each row’s proving or sanity query. T/F denotes the **expected gate verdict**, not a newly executed ProVerif result.

| Row | Query form / property | File(s), result-query count | Expected |
|---|---|---|---|
| H1 | IStart/RAccept together with attacker knowledge of SK is unreachable | `hClean`, 2 | T |
| H2 | I-side SK secrecy; R-side secrecy restricted to matching IStart | `hDH`, 2 | T |
| H3 | I- and R-side SK secrecy under KEM oracle | `hKEM`, 2 | T |
| H4 | I-side SK secrecy under both break oracles | `hBoth`, 1 | F |
| H5 | Injective RAccept→IStart agreement on identities, transcript, route and SK | `hClean-auth`, `hKEM-auth`, 2 total | T |
| H6 | No claim or query | — | — |
| H6a | IStart→BundleSigned origin correspondence | `hClean`, `hId`, 2 total | T |
| H6b | Injective IConfirm→RAccept correspondence | `hClean`, 1 | T |
| H7a | Nondeducibility of I’s DH and signing public keys | `hId`, 2 | T |
| H7b | Same, with phase-0 invitation leak | `hIdThief`, 2 | T |
| H7c | Same, after the specified phase-1 compromises | `hIdLater`, 2 | T |
| H7d | Same, additionally revealing the OPK | `hIdLaterOPK`, 2 | F |
| H8 | H5 correspondence under the DH oracle | `hDH-auth`, 1 | F |
| H9 | H5 correspondence after R’s SPK compromise | `hKCI-auth`, 1 | F |
| H9b | H5 correspondence after only R’s identity-key compromise | `hKCIlt-auth`, 1 | T |
| H9c | I-side SK secrecy after I’s identity-key compromise | `hKCIi`, 1 | T |
| H10 | Injective RAccept→InvIssued correspondence | `hClean`, 1 | T |
| H11 | Reachability of IStart, BundleSigned, matched RAccept/IStart and IConfirm | Four queries in each of 14 base session files, 56 total | F |
| H12 | Phase-1 I/R SK secrecy | `hFS`, 2 | T |
| H12b | Same, additionally revealing the OPK | `hFSOPK`, 2 | F |
| H12c | Same, additionally enabling a later DH break | `hFSDH`, 2 | T |

Each of the 14 base files has its four H11 queries. The five authentication files contain only their authentication query and do not have separate H11 declarations; they use the shared honest processes and add attacker-as-inviter behavior. No fresh per-file reachability result was obtained in this review.

The relevant abstractions are explicit:

- The envelope is one abstract cell; there is no chunking, `init_id` or padding implementation.
- The first TR message and reply are abstract committing encryption constructions. This binds `first_msg` content to the modeled SK; it does not prove the implemented ratchet.
- There is one acceptance attempt per OPK. Consequently, H10 is model consistency rather than a proof of retry behavior, failure retention or arbitrary prekey-store bookkeeping. It cannot exclude EXT-2.
- Attacker-as-inviter behavior is added in the five authentication files, within the stated bundle scope. Identity secrecy assumes the honest inviter; it is nondeducibility, not observational equivalence or unlinkability.
- Phase-1 compromise and omitted EK/OPK revelation represent erasure assumptions; they do not prove memory wiping.
- `select` and `nounif` are search hints. I found no added cryptographic equation or restriction in those hints that removes the stated attack capability.

The expected-false authentication rows have the stated mechanism. For H8, a leaked invitation plus the DH oracle lets an attacker compute DH1 for I’s public identity and supply its own EK and encapsulations. For H9, R’s SPK-DH secret supplies DH1 instead. KEM encapsulation alone does not authenticate I. H9b preserves DH1 when only R’s identity keys are compromised. The OPK-reveal sanity rows expose the material withheld by the forward-secrecy models.

The ProVerif gate checks the selected file set, normalized query text, result order/count and exact expected verdicts (`xtask/src/gates.rs:1808`; `expect.rs` HX table). Timeouts and unproved results fail. It records file hashes as evidence; it does **not** compare them with an independently trusted model hash or establish the semantic adequacy of the model, compromise assumptions, or reason for a false result. Hashes of unselected files do not mean those files were executed.

**Reference and vectors — nothing found beyond EXT-5.**

Both files are byte-identical and have SHA-256:

```text
vectors/hx.json      a33cf162e36969dc4bd70114a7c1b0ae3a97e09a187cd210c47dc374f436e7d2
vectors/ref/hx.json  a33cf162e36969dc4bd70114a7c1b0ae3a97e09a187cd210c47dc374f436e7d2
```

Their declared revision is `SecMP/1 rev2.3`. The 30 cases comprise eight positives, nine INV negatives and thirteen responder negatives.

INV negatives cover invitation expiry, kind, version, fingerprint, both signature halves, bundle expiry, missing OPK and wrong link key. HX negatives cover prekey IDs, used OPK/replay, zero EK, low-order initiator DH identity, chunk damage/completeness, inner authentication, first-message authentication, caps, changed SPK ciphertext and non-Handshake content.

Frozen negatives do not independently cover URI canonicality, all key-import failures, signed-field/`ik_dh` binding mutations, several AD/padding paths, changed OPK ciphertext, or ADR-044’s reflection, counter, known-route, bounded-group and later-group rules. Rust tests cover many of these; that does not supply independent Python coverage.

ADR-026’s process claim that Python was produced from the specification alone cannot be verified from a repository snapshot. The reference declares that process, but byte identity and source inspection do not prove authorship independence.

**Tests, Kani, fuzz, mutants, CT and CI — nothing found beyond the coverage gaps in EXT-1, EXT-2, EXT-4, EXT-5 and EXT-6.**

The matrix’s **71 active N rows, 11 P rows and five K rows** all have their exact current function names. Positive and review-focus assertion names are also present. The five superseded draft names are accounted for by the matrix’s rename/withdrawal table.

Assertion bodies and fixture construction were sampled for more than 20 rows: N1–22, N26–30, N34–57, the additional grouping/counter/route rows, and P1–P11. In particular:

| Sample | Check-isolation result |
|---|---|
| N1–2 URI prefix/canonical base64 | Inputs reach the intended textual decoder checks |
| N6/N18 expiry | Include boundary controls; expiry is checked after otherwise valid inputs |
| N11–12 fingerprint/substituted identity | Substitution uses a valid new identity and valid new signature, preserving the original pin |
| N13–17 signature halves, fields, `ik_dh`, label | Signature-oriented mutations are resealed; diagnostic assertions distinguish signature rejection |
| N19–22 missing OPK / low-order DH / KEM modulus / Ed25519 encoding | These are intended parser/import rejections; low-order inputs need not reach DH computation |
| N26–30 incomplete, damaged, mixed or spliced chunks | Expected grouping incompleteness or envelope authentication failure is asserted |
| N36–37 prekey IDs | Additional site tests keep alternative keys live and demonstrate rejection at the ID check |
| N42–46 changed EK/KEM shares and inner authentication | Fixtures preserve the outer layer where needed to exercise derivation/opening |
| N48–55 first-message header, body, binding and content | Fixture mutations distinguish TR authentication from authenticated content rejection |
| N68–69 nonzero counters | Additional `accept_counter_rules_reject_after_a_valid_mac` proves the valid-MAC path reaches the HX counter rule |
| Group duplication/eviction and unknown-only routes | Resealed fixtures exercise the ADR-044 checks rather than failing the outer authentication first |
| Persistence and OPK allocation assertions | Cover unchanged start snapshots and ordinary fresh issuance; do not cover EXT-1 or EXT-2 |

Kani’s actual scope is narrower than an unrestricted implementation proof:

| Harness | What is under proof |
|---|---|
| K1 | Symbolic chunk/index arithmetic and tiling bounds; not cryptography or the entire envelope construction |
| K2 | Outer decoding with `unpad` replaced by an over-approximation returning a proper prefix or rejection; the full 12,018-byte padding scan is not executed by this harness |
| K3 | Production grouping algorithm instantiated with three slots, four distinct IDs and at most six inserts; eviction and completion are reachable, but the production eight-slot/unbounded-stream behavior is not directly proven |
| K4 | Production acceptance driver with eight groups, at most six chunks and three IDs; cryptographic stages are nondeterministic outcomes and the store supplies an assumed atomic contract |
| K4b | Real in-memory commit logic on two fixed store configurations with two OPKs and one record, including a missing-OPK configuration; no two-record alias configuration |
| K5 | Actual handshake-cell plaintext decoder on lengths 4,023–4,025, checking exact length, index, total and re-encoding |

The relevant assumptions admit success, completion and eviction; I found no blanket assumption making these harnesses vacuous. They nevertheless cannot establish arbitrary store states, actual cryptographic validation, or the persistence sequence in EXT-1.

All eight requested fuzz targets reach their parsers or acceptance paths. Structured acceptance can reseal mutated outer/inner inputs and reach deeper checks. `hx_outer` has no tracked corpus entries, but the gate generates ten valid vector-derived seeds into its scratch corpus. Gate seed counts are: raw acceptance 17, structured acceptance 24, cell plaintext 30, inner 4, outer 10, link data 13, URI 4 and `proto_invitation` 132. Thus an empty tracked directory does not leave that target without valid gate seeds.

Mutation scope includes `secmp-proto` with `kat`, making the HX integration suite eligible. Exclusions primarily cover proof/stub code, test entropy/diagnostics and explicitly identified support functions. The documented survivors are the unobservable-after-free `SecretBytes` drop mutation and two equivalent base64 bit-combination mutations. The gate matches documented survivors by identity and rejects undocumented misses and timeouts. No mutation run was reproduced.

The four M4 CT targets are present: fingerprint mismatch position, X25519 all-zero comparison, HX inner rejection and HX first-message rejection. Their preparation includes valid positive controls and checks that the intended rejection site is reached. The gate checks target completeness, sample parameters, variable-time sensitivity, A/A and placement controls, the effect floor, and independently reproduced verdicts. This does not cover grouping in EXT-4 or prove constant-time behavior across every rejected input.

CI’s `linux-full` explicitly delegates Windows jobs and mutation testing and selects `--models tr`. HX ProVerif and mutants have separate jobs. A green `linux-full` alone therefore does not establish that those M4 gates passed. ADR-046 and ADR-047 already record that the new jobs are reviewer-required until added to the owner’s Required set; this accepted arrangement was not repeated as a finding. Source policy checks pin required job commands/conditions, but do not establish live GitHub ruleset enforcement or actual execution of delegated jobs.

**What was not verified**

- **Rust execution:** the offline test attempt failed before compilation with `no matching package named chacha20 found`, required by `secmp-crypto`. No Rust tests ran. Cargo’s writable home and target directory were placed under `target/`; no dependency installation or network retrieval was attempted.
- **Fresh gate results:** ProVerif, Kani, fuzzing, mutation testing, CT measurements, coverage, Miri and platform jobs were not rerun. Their source, scope and failure handling were inspected; historical results were not imported from the prohibited evidence.
- **End-to-end Python cryptography or vector regeneration:** required Python dependencies were unavailable. Only standard-library inspection, hashes, inventories and the extracted grouping reproduction were executed.
- **Runtime timing exploit:** EXT-4 establishes non-constant-work source behavior and lack of a comparison guarantee, not a measured remote extraction channel.
- **Actual swap exposure or complete dependency-stack erasure:** no memory-forensics test was performed. Library-internal stack residues and the accepted M9 scrub work remain outside this verification.
- **Durable-store implementations and crash atomicity:** the reviewed M4 store is in memory. An arbitrary `PrekeyStore` implementation’s transaction contract, client contact persistence, future M7 policy and cross-process/store coordination were not proven.
- **Live CI configuration:** GitHub Required checks, owner rulesets, job outcomes and artifact provenance were not queried.
- **Reference authorship independence:** ADR-026’s development-process restriction cannot be established from source alone.
- **Internal review reconciliation:** the prohibited internal review material was not read, so no “after reading the internal material” amendment was made.

Verdict: blockers: 2