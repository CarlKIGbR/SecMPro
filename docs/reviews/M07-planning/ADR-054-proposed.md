### ADR-054 — Application-layer payloads for M7: text, view-once, Control arguments, `Profile.name`

**Status.** Proposed (planner, 2026-10-27; M7 planning, OPEN-M7-02, reviewer decision Q81). **OWNER class** (protocol
semantics above the encoding layer). Owner default **+24 h** after delivery of the memo of 2026-10-27: build as written.
Fulfils the obligation of §7.6 `docs/03:509` ("defined by an application-layer ADR before M7") for the kinds M7 sends;
answers M02 review F12 (`Profile.name` control characters, `docs/reviews/M02-review.md:91`). No byte layout changes.

**Context.** §7.6 (`docs/03:490-509`) defines `AppMessage { msg_id, kind (1 text, 2 attachment-inline, 3 view-once-text,
4 reaction, 5 edit, 6 delete), expire_after, payload_len, payload }` and `Control { code, arg_len, arg }` (codes 1
contact-removed, 2 session-reset-request), with `payload` and `arg` opaque at the encoding layer and "Text ≤ 16 KiB
UTF-8". `Profile.name` is checked as UTF-8 at decode (D.3) but control characters are not ruled out (F12). M7 sends
text, view-once text, receipts, RouteUpdate, KeyChange and the two Control codes (`docs/07:141-143`).

**Decision.**
1. *Kind 1 text and kind 3 view-once-text.* `payload` = UTF-8 (well-formed, no overlong forms), 1 ≤ `payload_len` ≤
   16 384, no U+0000. A receiver drops (and acknowledges, §9.3) an `AppMessage` that violates this; the sender's `Api`
   refuses it before queueing.
2. *Kind 3 handling* is CS-1.14/CS-3.4 (`docs/04:35,55`, "kept only in memory") plus OPEN-M7-27 (owner default A, Q125):
   the sender refuses view-once to an unverified contact; on both sides a view-once lives in memory only, never in the
   outbox or messages table — an unsent view-once is lost at a restart and the `Api` reports `ViewOnceLost(msg_id)`; a
   receiver holds a view-once from an unverified sender locked in memory until verification.
3. *Kinds 2, 4, 5, 6.* Not defined by this ADR. The M7 `Api` refuses to send them; a receiver drops them (acknowledged).
   Kind 2 (inline ≤ 64 KiB, OQ-11) is defined by a later amendment of this ADR; until then SE-20 runs on a kind-1 text of
   16 KiB.
4. *Control.* Codes 1 and 2 carry `arg_len = 0`; a non-empty `arg` or another code is dropped (acknowledged) and
   surfaced as nothing to the user.
5. *`Profile.name`.* 0…64 bytes of UTF-8 (D.3) without C0 (U+0000–U+001F), DEL (U+007F) and C1 (U+0080–U+009F) control
   characters; a name violating this is shown as empty and never rejects the handshake (the HX rejection set of §6.6
   is unchanged).

**Alternatives.** (a) Define all six kinds now — reaction/edit/delete target semantics need UI decisions (M8). (b) Reject
the handshake on a bad `Profile.name` — would change §6.6 (spec, vectors); rejected.

**Consequences.** `secmp-client-core` validates at the `Api` and at delivery; rows SE-10, SE-11, SE-15, SE-20, CL-05
follow this text. A later amendment adds kinds 2/4/5/6 without changing these rules.
