## ADR-048 — Spec clarifications rev 2.6: SecMP-LINK/Q readings, editorial errata, `inv_sid` derivation, RT-3

**Status:** Proposed (reviewer) — owner default +24 h after delivery. **Date:** 2026-10-03. **Deciders:** reviewer
(Fable) proposes; owner (Christopher) ratifies — changes to `docs/03` are owner-reserved (`docs/03:3`). Items (o), (p)
and the optional (q) are the owner-class OPEN-M5 defaults (OPEN-M5-06, -02, -01); they go into the owner memo with the
same +24 h default.

**Context.** The reference implementation built §8/§9 for brief REF-M5 (2026-10-02) under the reviewer's readings
OPEN-1…OPEN-13 and (a)–(g); its `vectors/link.json` (86 cases, sha256 `dd77bb7c96d2…4c77`) pins them. It raised SQ-26,
SQ-27 and SQ-28 and pinned a reading for each; no case depends on them. The M4 review (2026-10-03) assigned R-90
(`inv_sid` drawn at random although §9.1 derives every `sid`), RT-3 (HX authenticates `IK_dh_I` only) and the editorial
list R-60…R-65 to this ADR. M5 planning (OPEN-M5, reviewer decisions of 2026-10-03) found three wire-visible gaps that
need docs/03 text: (o), (p), (q). Line numbers below are those of `docs/03` rev 2.5. Brief REF-M5 promised "ADR-048 (spec
clarifications rev 2.6, Proposed)" for OPEN-2…OPEN-11; this ADR records all thirteen readings and (a)–(g).

**Decision.** `docs/03` becomes revision 2.6 with the text below (new text in quotes; "replace X → Y" is literal).

### Part 1 — SecMP-LINK (§8)

- **(a) §8.2 RelayInfo checks** (OPEN-4; brief REF-M5 `akc` reading; (g)). Replace in `:539` "Static keys SHOULD be
  rotated monthly with overlapping validity; `valid_until − now ≤ 60 days`." → "The client MUST also reject a RelayInfo
  with `valid_until − now` > 60 days (5 184 000 s); exactly 60 days is accepted. A client that holds an access key
  compares `akc` with SHA-256(`"SecMP-Q/1 akc"` ‖ access key). Static keys SHOULD be rotated monthly with overlapping
  validity." Strict Ed25519 for `RelayInfoV1.sig` and every D.2 `sig` ((g)) is already §3.5/§4.1 (b): no text change.
- **(b) New §8.5 "Rejection"** (OPEN-2, OPEN-6; SQ-27 via (f)). "A failed check of HELLO, RELAYINFO, HS1, HS2 or a
  frame is one uniform error: a record or unit of the wrong length or type, a decoder failure (§4.1), a failed
  signature, `relay_fp`, `valid_until` or `akc` check, an unknown `kid`, a wrong `mac1` or `mac2`, a counter other than
  the expected one, a failed AEAD open, a frame plaintext that opens but does not decode (padding, opcode, fields), and
  a `CONT` that does not continue the pending multi-frame command. The receiver emits nothing further and closes the
  connection; its frame counters, its recorded `cmd_seq` and the relay's store are unchanged. The relay draws no HS2
  randomness before `mac1` verifies. A unit of any length other than 4352 B is rejected before the AEAD. `SKEY` (0x02)
  is the one reserved request opcode that is answered (ERR_MALFORMED, D.2)."
- **(c) §8.3, after "…not by `mac1`."** (OPEN-3). "The relay keeps no HS1 replay cache: a replayed HS1 is answered as a
  new handshake with fresh `e_r` and `ct_c`; frames replayed from the earlier link then fail under the new keys (§8.4)."
- **(d) §8.4 `:570`** ((a)). After "strict `+1` on receive" add "(the frame counter; `cmd_seq` is only strictly
  increasing, §9.2)".
- **(e) Vector readings without `docs/03` text** (recorded in `vectors/SCHEMA-4.11-link.md`): OPEN-1 draw order (C:
  `e_c_sk`, `ek_c_seed`, `sk_e1`, `m1`; R: `sk_er`, `m2`); OPEN-12 `budget_queues` = 2 is a vector-only relay
  parameter (queues count, link data does not); OPEN-13 the "first three frames each direction" of App. C are
  QUEUE_NEW, SEND, PING.

### Part 2 — SecMP-Q (§9, D.2)

- **(f) §9.2 `cmd_seq`** (OPEN-5; SQ-26 and SQ-27 **proposed; reviewer accepted the reference's reading (A), owner
  decides**). Replace `:593` "(per link, strictly increasing; the relay rejects `≤ last`; `CONT` frames repeat the
  continued command's `cmd_seq` and are exempt from the increase check)" → "(per link, strictly increasing, not
  necessarily +1. The relay's `last` starts at 0; every request frame that opens and decodes with `cmd_seq > last` sets
  `last`, whatever the command's outcome. A request with `cmd_seq ≤ last` is not executed and is answered with exactly
  one ERR frame, code 6 (MALFORMED), for every command; for `LINK_PUT` the relay first takes its two `CONT` frames and
  answers after the third. `CONT` frames repeat the continued command's `cmd_seq` and are exempt from the increase
  check; only the next `CONT` of the pending `LINK_PUT` (same `cmd_seq`, `idx` 1, then `idx` 2) continues it, and any
  other frame while a `LINK_PUT` is pending is a LINK-level rejection (§8.5))". **D.2 `:839`**: append "Exception: a
  request with a stale `cmd_seq` (§9.2) is answered with exactly one ERR 6 frame."
- **(g) §9.6 tokens** ((b)). Append to `:622`: "The token is bound to `sess_id` and to the command's own `cmd_seq`; a
  token computed for another `cmd_seq` or another link is `ERR_TOKEN`. v1 keeps no double-spend list (M13)."
- **(h) §9.3 table** ((c), (d), OPEN-9, OPEN-10, OPEN-11; makes the table agree with §9.7 item 8). Rows become:
  `QUEUE_NEW` → "`OK_QUEUE_NEW { rid, sid }` \| `ERR_TOKEN` \| `ERR_AUTH` (signature does not verify; known `recv_pk`
  with another `send_pk`) \| `ERR_FULL`; an identical request (same `recv_pk`, `send_pk`) answers `OK_QUEUE_NEW`
  without side effects although its token and signature differ"; `QUEUE_DEL` → "`OK` \| `ERR_NOQUEUE` \| `ERR_AUTH`";
  `LINK_PUT` → "`OK` \| `ERR_EXISTS` \| `ERR_FULL` \| `ERR_TOKEN` \| `ERR_AUTH`, one response frame after the third
  frame, also on failure"; `LINK_GET` → "3 frames: `LINKR { present, consumed, blob part 4160 B }`, then two `CONT`
  (0xFF) of 4100 B. Consume mode: a stored blob answers {1, 0, blob} (a one-time blob is then deleted, §9.4); an absent
  or consumed one answers {0, 0} or {0, 1} with a dummy blob. Owner status: {present, consumed} with a dummy blob, and
  {0, 0} with a dummy blob when the signature does not verify. A dummy blob is 12360 random bytes".
- **(i) FETCH layout** (OPEN-7). §9.3 `FETCH` row → "exactly `F` `CELLR` frames: on success the stored cells with
  `cell_id > ack`, oldest first (ascending `cell_id`), then dummies; on an error frame 1 carries `present ∈ {2, 3, 4}`,
  the requested `rid`, `cell_id` 0 and a random cell, frames 2…`F` are dummies". §9.1 `:589` replace "with
  `ERR_MALFORMED`" → "with `F` `CELLR` frames whose first has `present = 4` (MALFORMED); nothing is deleted".
- **(j) FETCH_MULTI** (OPEN-8; SQ-28 **proposed; reviewer accepted the reference's readings (A, A), owner decides**).
  §9.3 `FETCH_MULTI` row, append: "Each entry has the `FETCH` ack semantics (`ack ≥ next_cell_id` ⇒ `present` 4 for
  that entry). Error frames come first in request order; when more than `F_M` entries fail, the first `F_M` errors in
  request order are answered and nothing else. A `rid` listed twice is checked and acknowledged per entry, in request
  order, and its cells are selected once. A `present` 1 `CELLR` carries its queue's `rid`."
- **(k) §9.4 one-time data** ((f), OPEN-11). Replace `:614` "returns it and deletes it atomically" → "returns it with
  `present = 1, consumed = 0` and deletes it atomically (the first consume wins)"; append "Owner status never consumes.
  A `LINK_PUT` whose `ld_id` names a consumption marker is `ERR_EXISTS` until the marker expires; a blob with
  `one_time = 0` is returned by every consume-mode `LINK_GET` and kept." (REF-M5 readings 5 and 6, confirmed by the
  reviewer under OPEN-M5-13.)
- **(l) §9.5 eviction** ((e)). Append to `:618`: "`OK_SEND` then carries `evicted_present = 1` and the evicted
  `cell_id`; otherwise `evicted_present = 0` and `evicted_id = 0`; `cell_id`s keep increasing."

### Part 3 — `inv_sid` derived (R-90; M4 review §E)

- **(m) §5.2.** Replace the field comment of `inv_sid` (`:202`) "sender id of the invitation queue" → "sender id of the
  invitation queue, derived as in §9.1: SHA-256(`"SecMP-Q/1 sid"` ‖ `recv_pk` ‖ `send_pk`)[0..16] with `recv_pk` the
  invitation queue's recipient key and `send_pk` the Ed25519 public key of `inv_send_seed`; derived, not chosen". After
  `:211` add: "The invitation queue is one of the inviter's pooled recv-queues (§10.6 rule 3) whose sender seed is
  `inv_send_seed`." (This sentence goes beyond R-90; it is kept deliberately because it states why the inviter holds
  that queue's `recv_pk` at issue time, and it only restates §10.6 rule 3.)
- **Consequence: re-freeze of `vectors/hx.json` and `vectors/ref/hx.json`** (R-66, R-90, R-67; WEISUNG_REF M5-2).
  Vector reading OPEN-M5-14 B: in the `invite` case the generator still draws the 16 bytes formerly taken for `inv_sid`
  and discards them, so every later draw of that case keeps its bytes; `invq_recv_seed` (32) and `owner_seed` (32) are
  appended after the case's last draw, and `inv_sid` is derived. Changed are therefore only `hx-0003` (`invite`, the
  case that carries the URI, M4 review R-60: its `inv_sid`, InvitationV1, URI and the two new outputs `invq_recv_pk`,
  `owner_pk`) and every case whose inputs or outputs contain that InvitationV1 or URI — the `invitee-accept` case and
  any `invitee-reject` case among V1–V9 that is built from it rather than from its own stream; the ref names them by id from `SCHEMA-4.10-hx.md` (not
  available to this planning pass) and reports every case against `a33cf162…` (procedure of Weisung REF-M4-1). The
  responder cases (`respond`, R1–R13) keep their bytes: `K_inv`, `K_id` and the transcript take no `inv_sid`. Route
  `sid`s inside Handshake contents (hx) and RouteUpdates (tr, encodings) stay stream-drawn: they are opaque to every
  decoder and no relay exists in those suites (TEST-SPEC G-06). The rev-2.5 cases of R-66 (later group after a rejected one, rejected
  `init_id` not re-formed, `n` ≠ 0, `pn` ≠ 0, reflection, Handshake without a known route) and the retained-SPK
  positive (RF-1, E-7) are appended after `hx-0030`, so no earlier index or seed moves. The file header stays
  `"schema": 5` and names rev 2.6. The `link` file is not touched by this ADR.

### Part 4 — RT-3 (HX identity binding; M4 review RT-3)

- **(n) §6.6 Authentication, `:356`.** After "I is authenticated to R by `DH1`." insert: "The handshake therefore
  authenticates `IK_dh_I` only: `IK_sig_I` is bound into the transcript as part of `IKSPublic_I` but never exercised (I
  signs nothing), so a party can present an `IKSPublic` that combines another user's `IK_sig` with its own `IK_dh` and
  be accepted as an unverified contact. The safety number (§6.7) covers the whole `IKSPublic` and a key change (§7.7)
  needs the old `IK_sig`, so nothing is gained cryptographically; a client MUST NOT key a contact's identity or display
  on `IK_sig` alone before the contact is verified (client core, M7)." The docs/01 sentence is F-M7.

### Part 4b — owner-class decisions of OPEN-M5 (SecMP-LINK/Q) (owner memo; default = the OPEN-M5 default, +24 h)

- **(o) LINK_PUT `expires_bucket` range** (OPEN-M5-06 B). §9.3 `LINK_PUT` row, append: "`expires_bucket` must satisfy
  now_bucket ≤ `expires_bucket` ≤ now_bucket + 720 (`LINKDATA_TTL` in hours); otherwise `ERR_MALFORMED`, answered after
  the third frame, nothing stored." The check runs after the token and the signature and before the `ld_id` lookup
  (OPEN-M5-04 order).
- **(p) Rate limits** (OPEN-M5-02 A). §9.7 item 7, append: "A request over the relay's per-link frame-rate limit is not
  executed and is answered with exactly one `ERR` frame, code 7 (RATE) — for `LINK_PUT` after its third frame — and its
  `cmd_seq` is recorded (§9.2). A `HELLO` over the handshake-rate limit is answered by closing the connection before
  `RELAYINFO`." D.2 `:839`: the exception sentence of (f) becomes "Exceptions: a request with a stale `cmd_seq` (§9.2)
  is answered with exactly one ERR 6 frame, and a request over the frame-rate limit (§9.7 item 7) with exactly one
  ERR 7 frame; for `LINK_PUT` either comes after its third frame." The limit values are relay configuration.
- **(q) optional — `akc` without an access key** (OPEN-M5-01 B; **default: not adopted**, i.e. reading A stands). If the
  owner adopts it, §8.2 `:539` gains: "A client that holds a `RelayRef` for `relay_fp` also rejects a RelayInfo whose
  `akc` differs from `RelayRef.akc`, whether or not it holds an access key." TEST-SPEC C-12 is then re-dictated.

### Part 5 — Editorial errata (ADR-048 list of the M4 review: R-60…R-65, RT-3)

| # | File:line (at the M4 pin) | Replace → with | RID |
|---|---|---|---|
| E-1 | `docs/03:209` | "(≈ 322 chars)" → "(332 chars: `secmp://i/` + 322 base64url)" | R-60, D-07 |
| E-2 | `docs/03:711` | "`formal/hx.pv`" → "`formal/hx.pvl` + `formal/hx/*.pv` (one file per session, ADR-046)"; "`formal/link.pv`" → "`formal/link.pvl` + `formal/link/*.pv`" (OPEN-M5-16 A) | R-61, D-08 |
| E-3 | `docs/07:93`, `:107` | "`formal/hx.pv`" → "`formal/hx.pvl` + `formal/hx/*.pv`"; "`formal/link.pv`" → as E-2 | R-61, D-11 |
| E-4 | `docs/01:48`, `:161`; `docs/02:111` (found in M5 planning, same class) | "HandshakeInit" → "handshake cells (App. D `HandshakeCell`)" — plural, unlike D-04's "handshake cell", because each sentence names the three cells | R-64, D-04 |
| E-5 | `docs/01:180` (RR-13) | "once the OPK is deleted" → "once the OPK is deleted and EK_I discarded" | R-65, D-05 |
| E-6 | `formal/CLAIMS.md` (13 anchors, R-62 at e8359b1), `docs/08-decisions.md:323-333` | re-anchor every `docs/03:<line>` to rev 2.6 in the commit that applies rev 2.6 (content unchanged) — rev 2.6, not D-27's rev 2.5, because this ADR moves the lines again | R-62, D-27 |
| E-7 | `formal/CLAIMS.md` O-3 "SQ-28 (ref): retained-SPK positive at next freeze"; `TEST-SPEC-M4.md:42` "SQ-28 (for the ref)" | → "WEISUNG_REF item RF-1 (retained-SPK positive), delivered with the R-66/R-90 re-freeze" (the ref's SQ-28 is now the FETCH_MULTI question of (j)) | R-63, D-28 |
| E-8 | `docs/03` changelog line 5 | add "**rev 2.6** (2026-10-0x): ADR-048 (a)–(d), (f)–(p) [and (q) if adopted], E-1, E-2." ((e) adds no docs/03 text) and Status line "revision 2.6" | — |

**Consequences.**
- `vectors/link.json` is unchanged; its header keeps "SecMP/1 rev 2.3" (frozen bytes). Rust M5 enforces (a)–(l) with
  the tests named in TEST-SPEC-M5; the rows marked [SQ-26], [SQ-27], [SQ-28] and the owner-class rows [O-1], [O-2],
  [O-6] land in the first commit after ratification (M4 precedent for ADR-043 (f)–(h)). A veto of the SQ-26/SQ-27 part
  of (f), of the SQ-28 part of (j), or of (o)/(p) changes only the rows marked for them; a veto of anything else in
  (a)–(l) touches a reading that `link.json` pins (OPEN-5 in (f): E23 and every `link_post`; OPEN-7 in (i): P12–P14,
  P21, E11–E14; OPEN-8 in (j): P18, E15) and is a STOP for M5 and a WEISUNG_REF re-generation.
- `vectors/hx.json` is re-frozen (Part 3); until the new reference file arrives, Rust keeps the M4 behaviour and the
  [HX-RF] rows wait (STOP rule "frozen vector would change" stays in force).
- `docs/reviews/ref-spec-questions-M5.md` records SQ-26…SQ-28 with these answers; `ref/` changes nothing for (f)–(j);
  it adds the (o) range check to `relay.py` (no `link` case changes; WEISUNG_REF M5-2 item 6); (p) is outside the ref.
- Wire format: no byte layout changes. Behaviour changes for a v1 peer: none for a peer that follows §8/§9 as the
  reference does; (a) adds a client reject for `valid_until − now` > 60 days; (o) a relay reject of an out-of-range
  `expires_bucket`; (p) the ERR 7 answer; (n) a client-core MUST.
