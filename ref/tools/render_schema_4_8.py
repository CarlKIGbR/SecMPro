# SPDX-License-Identifier: AGPL-3.0-or-later
"""Write SCHEMA-4.8-encodings.md (SCHEMA §4.8, the `encodings` case table) from the table that
generates vectors/encodings.json, so that the two cannot drift apart.

    ref/.venv/bin/python -m tools.render_schema_4_8          (from ref/)
"""

import collections
import pathlib
import sys

from secmp_ref import encodings as enc
from secmp_ref import encodings_cases as ec

OUT = pathlib.Path(__file__).resolve().parent.parent.parent / "vectors" / "SCHEMA-4.8-encodings.md"

STREAM_ORDER = [
    ("Record/HELLO", "— (no stream input)"),
    ("Record/RELAYINFO", "`relay_info` as RelayInfoV1"),
    ("RelayInfoV1", "relay_sig_seed 32 → `relay_sig_pk`; `kid` 4; relay_dh_sk 32 → `relay_dh_pk`; relay_kem_seed 64 → "
                    "`relay_kem_ek` (ML-KEM-1024); `akc` 32; `valid_until` 8; `sig` = Ed25519.Sign(relay_sig_seed, "
                    "`\"SecMP-LINK/1 relayinfo\"` ‖ the 1677 bytes before `sig`) (§8.2)"),
    ("Record/HS1", "`kid` 4; e_c_sk 32 → `e_c`; ek_c_seed 64 → `ek_c` (ML-KEM-768); pk_e1_sk 32 → `pk_e1`; `ct_kem` 1568; "
                   "`mac1` 32"),
    ("Record/HS2", "e_r_sk 32 → `e_r`; `ct_c` 1088; `mac2` 32"),
    ("Request/QUEUE_NEW", "`cmd_seq` 4; recv_seed 32 → `recv_pk`; send_seed 32 → `send_pk`; `token` 32; sess_id 16; "
                          "`sig` by recv_seed"),
    ("Request/SEND", "`cmd_seq` 4; `sid` 16; `cell` 4096; sess_id 16; send_seed 32; `sig`"),
    ("Request/FETCH", "`cmd_seq` 4; `rid` 16; `ack` 8; sess_id 16; recv_seed 32; `sig`"),
    ("Request/FETCH_MULTI", "`cmd_seq` 4; per entry `rid` 16, `ack` 8; sess_id 16; per entry recv_seed 32; each entry's "
                            "`sig` over its own `MFETCH` message"),
    ("Request/QUEUE_DEL", "`cmd_seq` 4; `rid` 16; sess_id 16; recv_seed 32; `sig`"),
    ("Request/LINK_PUT", "`cmd_seq` 4; `ld_id` 16; `expires_bucket` 4; owner_seed 32 → `owner_pk`; `token` 32; blob 12360 "
                         "(`blob_part` = its first 4160 bytes); sess_id 16; `sig` by owner_seed, with SHA-256(blob)"),
    ("Request/LINK_GET", "`cmd_seq` 4; `ld_id` 16; mode `consume`: `sig` = 0^64; mode `owner-status`: sess_id 16, "
                         "owner_seed 32, `sig`"),
    ("Request/PING", "`cmd_seq` 4"),
    ("Request/CONT", "`cmd_seq` 4; `data` 4100"),
    ("Response/OK", "`cmd_seq` 4"),
    ("Response/OK_QUEUE_NEW", "`cmd_seq` 4; `rid` 16; `sid` 16"),
    ("Response/OK_SEND", "`cmd_seq` 4; `cell_id` 8; `evicted_id` 8 if `evicted_present` = 1 (else 0, nothing drawn)"),
    ("Response/CELLR", "`cmd_seq` 4; `rid` 16 unless zero by D.2 (present 0, or present 1 in context FETCH); `cell_id` 8 "
                       "if present = 1 (else 0); `cell` 4096"),
    ("Response/LINKR", "`cmd_seq` 4; `blob_part` 4160"),
    ("Response/ERR", "`cmd_seq` 4"),
    ("Response/CONT", "`cmd_seq` 4; `data` 4100"),
    ("RelayRef", "`relay_fp` 32; onion_seed 32 → `onion` = PUBKEY ‖ SHA3-256(`\".onion checksum\"` ‖ PUBKEY ‖ 0x03)[0..2] ‖ "
                 "0x03 with PUBKEY the Ed25519 public key (Tor rend-spec-v3 §6); `akc` 32; if direct_present = 1: "
                 "`spki_sha256` 32 (`host`, `port` from the table)"),
    ("InvitationV1", "`relay` (RelayRef order); `ld_id` 16; `link_key` 32; `inviter_fp` 32; `inv_sid` 16; "
                     "`inv_send_seed` 32; `expires` 8"),
    ("Profile", "`name` (the table: text of k stream bytes, or a fixed string); `avatar_sha256` 32 if avatar_present = 1"),
    ("LinkDataV1", "`inviter_iks` (IKSPublic order); `bundle` (PrekeyBundle order, signed by inviter_iks: no signer "
                   "seeds drawn); `profile` (Profile order); `created` 8"),
    ("LinkBlob", "`N` 24; `COM` 32; `ct` 12304"),
    ("IKSPublic", "ed_seed 32 → `ik_ed25519`; mldsa_seed 32 → `ik_mldsa65` (KeyGen_internal(ξ)); dh_sk 32 → `ik_dh` "
                  "(as SCHEMA §4.6)"),
    ("PrekeyBundle", "`spk_id` 4; spk_dh_sk 32; spk_kem_seed 64 (ML-KEM-1024); rpk_kem_seed 64 (ML-KEM-768); "
                     "`spk_expiry` 8; `opk_id` 4; opk_dh_sk 32; opk_kem_seed 64 (ML-KEM-1024); signer IKS in IKSPublic "
                     "order (standalone rows only); rnd 32; `sig` = HybridSign(signer, `\"SecMP-HX/1 bundle\"`, the "
                     "fields before `sig` ‖ the signer's ik_dh) (§6.3; ML-DSA hedged with rnd)"),
    ("Outer", "ek_I_sk 32 → `ek_I`; `spk_id` 4; `opk_id` 4; `ct_spk` 1568; `ct_opk` 1568; `inner_ct` 6185"),
    ("inner_ct", "`N2` 24; `COM` 32; `ct` 6129"),
    ("Inner", "`iks` (IKSPublic order); `first_msg` 4096"),
    ("HandshakeCell", "`N_i` 24; `COM` 32; `ct` 4040"),
    ("HandshakeCellPlaintext", "`init_id` 16; `chunk` 4006"),
    ("Cell", "`hdr_nonce` 24; `hdr_ct` 2330; `body_ct` 1710; `tag` 32"),
    ("HeaderV1", "dh_sk 32 → `dh_pk`; `pn` 4; `n` 4; ek_pq_seed 64 → `ek_pq` (ML-KEM-768); `ct_pq` 1088"),
    ("Content", "`seq` 8; `ts` 8; `body` (the body structure's order; Dummy: nothing)"),
    ("AppMessage", "`msg_id` 16; `expire_after` 4; `payload` = text of k stream bytes"),
    ("BatchBody", "`messages` in order (AppMessage order)"),
    ("Fragment", "`msg_id` 16; `chunk` (length from the table)"),
    ("FragmentPayload", "`inner_body` (KeyChangeBody order)"),
    ("RouteDescriptor", "kind 0x01: `blob` (RelayQueue order); another kind: `blob` = n stream bytes"),
    ("RelayQueue", "`relay` (RelayRef order); `sid` 16; `send_seed` 32"),
    ("RouteUpdateBody", "`routes` in order (RouteDescriptor order)"),
    ("HandshakeBody", "`profile` (Profile order); `routes` in order"),
    ("KeyChangeBody", "`iks` (IKSPublic order: the new identity); old_ed_seed 32; old_mldsa_seed 32; rnd 32; `sig` = "
                      "HybridSign(old, `\"SecMP-TR/1 keychange\"`, fingerprint(iks)) (§7.6)"),
    ("ReceiptBody", "`msg_ids` count × 16"),
    ("ControlBody", "`arg` (arg_len from the table)"),
    ("Signed/*", "`sess_id` 16; `cmd_seq` 4; the signed D.2 fields in order (Ed25519 keys from 32-byte seeds); "
                 "LINK_PUT: `blob` 12360"),
]

PREAMBLE = """\
### 4.8 `encodings` — byte layouts of Appendix D (spec App. B, D)

*SCHEMA §4.8 (ADR-039): the `ref/` proposal of brief REF-M2 as adopted, with the reviewer's corrections of Weisung
REF-M2-1 (2026-09-29) applied. Spec rev 2.2 plus the answers to SQ-12 … SQ-19 in `ref/SPEC-QUESTIONS.md`, which spec
rev 2.3 takes over. The tables are generated by `ref/tools/render_schema_4_8.py` from `ref/secmp_ref/encodings_cases.py`,
the table that generates `vectors/encodings.json`.*

Tag `enc` (SCHEMA §3). File header `"schema": 3` (SCHEMA §1). Rows 1–{npos} are positive, rows {nfirst}–{nlast}
negative ({nneg} negatives).

**Cases.** Positive rows: `op` = `"encode"`; inputs `structure` (ASCII string), `value` (the structure's fields, see
below) and, for `Response/CELLR` only, `context`; outputs `bytes` (the canonical encoding). Each positive row obliges
both directions: `encode(value) = bytes` and `decode(bytes) = value` (so `encode(decode(bytes)) = bytes`). The D.6 rows
(`Signed/*`) are encode-only: a signed message is computed by both sides and never parsed. Negative rows: `op` =
`"decode"`; inputs `structure`, `bytes` (the manipulated encoding) and, for CELLR, `context`; `expect: "reject"`, the
decoder's single uniform error for every row. A case that a decoder must *accept* is always written as a positive
`encode` row (SCHEMA §1 has no accepting `decode` shape).

**Structure names.** D.1: `Record/HELLO`, `Record/RELAYINFO`, `Record/HS1`, `Record/HS2` (the whole record, `len`
included) and `RelayInfoV1`. D.2: `Request/<name>` and `Response/<name>` with the D.2 command names (the two CONT
opcodes are `Request/CONT` 0x7F and `Response/CONT` 0xFF); a frame plaintext is decoded by the frame decoder of its
direction, which dispatches on `op`, and a positive must decode to the named command. The op byte is read before
anything command-specific, so the unknown-opcode rows and the empty input are listed once per direction, under
`Request/PING` and `Response/OK`; they test the direction's decoder. `Response/CELLR` takes `context`
= `"FETCH"` or `"FETCH_MULTI"`, the request it answers (D.2: "For FETCH, rid is zero on present 0/1"). D.3: `RelayRef`,
`InvitationV1`, `Profile`, `LinkDataV1` (padded, 12288 B), `LinkBlob`, `IKSPublic`, `PrekeyBundle`. D.4: `Outer`
(padded, 12018 B), `inner_ct`, `Inner` (its plaintext `IKSPublic ‖ first_msg`), `HandshakeCell`,
`HandshakeCellPlaintext` (`init_id ‖ i ‖ total ‖ chunk`). D.5: `Cell`, `HeaderV1`, `Content` (padded, 1710 B),
`AppMessage`, `Fragment`, `RouteDescriptor`, `RelayQueue` (the kind-0x01 blob), `HandshakeBody`, `KeyChangeBody`,
`ReceiptBody`, `ControlBody`, and the three layouts §7.6 gives and rev 2.3 adds to D.5 (SQ-16): `BatchBody`
(`count ‖ AppMessage[]`), `RouteUpdateBody` (`count ‖ RouteDescriptor[]`), `FragmentPayload` (the reassembled
`inner_type ‖ inner_body`). D.6: `Signed/<command>` for the seven signed commands.

**Value representation (SCHEMA §1, `"schema": 3`).** `value` is a JSON object holding the structure's wire fields
under App. D's names. `op` (the frame opcode) and `mode` (LINK_GET and `Signed/LINK_GET`) are JSON strings, as
everywhere in SCHEMA §1: `op` is the D.2 command name (`"QUEUE_NEW"`, …, `"OK"`, …; `"CONT"` in both directions, the
structure name tells which), `mode` is `"consume"` (0) or `"owner-status"` (1). Every other u8 … u64 field — `ver`,
`type`, `kind`, `code`, lengths, counts, and the boolean u8 fields (`*_present`, `one_time`, `consumed`, which are 0 or
1) — is a JSON number; u64 values can exceed 2^53 and are exact JSON integers. `[n]` and variable byte fields — `name`,
`host` and payloads included — are lowercase hex; a nested structure is a JSON object; a repeated field is a JSON
array (of objects, or of hex strings for `msg_ids`); padding is not a field. An optional field appears iff its
presence byte is 1 (`direct_present`, `avatar_present`). Polymorphic fields: `Content.body` is the object of the
type's body structure, or `""` for Dummy; `RouteDescriptor.blob` is a RelayQueue object for kind 0x01 and hex for any
other kind; `FragmentPayload.inner_body` is the body object. Names App. D leaves unnamed: Record `len`, `type`,
`magic`, `relay_info`; LinkDataV1 `inviter_iks`, `bundle`, `profile`, `created` (§5.4); InvitationV1 and RelayQueue
`relay` (§5.2, §9.8); Inner `iks`, `first_msg`; KeyChangeBody `iks`, `sig`; HandshakeBody `profile`, `caps`,
`route_count`, `routes`; BatchBody `count`, `messages`; RouteUpdateBody `count`, `routes`; ReceiptBody `kind`,
`count`, `msg_ids`; FETCH_MULTI `count`, `entries`; Signed/* `sess_id`, `cmd_seq`, and for LINK_PUT `blob` (the whole
12360-byte blob).

**Decoding contract.** "Decode" is structural validation of exactly one encoding; every negative row violates at
least one of these rules. The answers to SQ-12 … SQ-19 are part of them (spec rev 2.3, §4.1 "decoder obligations").

- **D-1** One encoding: bytes left over or missing reject. Fixed-size and padded structures have exactly their App. B
  size.
- **D-2** Every `ver` field is 0x01 (§4.1). `ver` is exactly where App. D lists it: records start with `len ‖ type`
  (HELLO's `ver` follows the magic), frames with `op`, the Cell with `hdr_nonce`; `RelayRef`, `IKSPublic`,
  `PrekeyBundle`, `HeaderV1`, `Content` and `RouteDescriptor` carry their own `ver` also where they are nested (see
  SQ-20).
- **D-3** Lengths and counts (§4.1 consistency rule): a length covers exactly the bytes of its field, which the inner
  structure consumes completely. Ranges: `name_len` ≤ 64 (bytes); `body_len` ≤ 1689; FETCH_MULTI `count` 1..=32;
  Batch, RouteUpdate and Receipt `count` and Handshake `route_count` 1..=255 (SQ-17); `host_len` 1..=253 (SQ-14);
  Fragment `total` 2..=64 (SQ-18). A Record `len` is the body length (type byte included) and must be the type's
  fixed body size.
- **D-4** Padding (§4.1): ISO/IEC 7816-4 wherever App. D says pad — fields ‖ 0x80 ‖ 0x00…; the marker must be present
  and every byte after it zero (frames 4336, Content 1710, LinkDataV1 12288, Outer 12018).
- **D-5** Presence and boolean bytes (`direct_present`, `avatar_present`, `evicted_present`, `one_time`, LINKR
  `present`/`consumed`) are 0x00 or 0x01 (§4.1; a canonical encoding has one byte string per value); the optional fields
  follow iff 0x01. `opk_present` must be 0x01 (§6.3).
- **D-6** Closed enumerations — an unknown value rejects: Record type (each record decoder expects its own), `op` per
  direction (SKEY 0x02 is reserved and rejects; a response opcode is unknown to the request decoder and vice versa),
  `InvitationV1.kind` (0x02 reserved: MUST reject), `Content.type`, `AppMessage.kind` (1–6), Receipt `kind` (1, 2),
  Control `code` (1, 2), ERR `code` (1–7), `FragmentPayload.inner_type` ∈ {{0x02, 0x04, 0x05, 0x06, 0x07}} (0x00, 0x01
  and 0x03 reject, SQ-18). Open: `RouteDescriptor.kind` — an unknown kind is accepted and its blob kept as opaque bytes
  (§9.8 "MUST ignore unknown kinds"; keeping it makes re-encoding canonical). Content type 0x05 never appears
  unfragmented (a KeyChange body is 5390 B > 1689): it rejects (SQ-16).
- **D-7** Reserved and zero fields: `HeaderV1.flags` = 0 (§7.5); `HandshakeBody.caps` = 0 (SQ-15); LINK_GET `sig` =
  0^64 when `mode` = 0; OK_SEND `evicted_id` = 0 when `evicted_present` = 0; CELLR: present 0 ⇒ `rid` = 0 and
  `cell_id` = 0, present 2–4 ⇒ `cell_id` = 0, context FETCH and present 1 ⇒ `rid` = 0;
  `HandshakeCellPlaintext.total` = 3; a Dummy's body is empty (§7.6).
- **D-8** Value sets: `inv_period_s`, `period_s` ∈ PERIODS = {{10, 20, 40, 80}}; LINK_GET `mode` ∈ {{0, 1}}; CELLR
  `present` ≤ 4; CONT (both directions) `idx` ∈ {{1, 2}} and `data` exactly 4100 B (LINK_PUT and LINKR are v1's only
  multi-frame messages, D.2); `HandshakeCellPlaintext.i` ∈ {{0, 1, 2}}; Fragment `idx` < `total` (counted from 0) and
  `chunk` ≥ 1 byte (SQ-18); `RelayRef.onion` = PUBKEY ‖ CHECKSUM ‖ VERSION with VERSION = 0x03 and CHECKSUM =
  SHA3-256(`".onion checksum"` ‖ PUBKEY ‖ VERSION)[0..2] (rend-spec-v3 §6; no rule on PUBKEY; SQ-13); `direct.host`
  bytes in 0x21..=0x7E and `direct.port` ≠ 0 (SQ-14).
- **D-9** X25519 public keys (`relay_dh_pk`, `e_c`, `pk_e1`, `e_r`, `ik_dh`, `spk_dh`, `opk_dh`, `ek_I`, `dh_pk`): a
  low-order value rejects — after RFC 7748 decoding (bit 255 masked, u mod p) u ∈ {{0, 1, p − 1, the two order-8
  u-coordinates}}, 14 byte strings. Anything else, non-canonical u and bit 255 set included, is accepted and kept as
  received (§3, SQ-11, SQ-12).
- **D-10** Ed25519 (the §3.5 byte rules, message-independent; SQ-12): public keys (`relay_sig_pk`, `ik_ed25519`,
  `recv_pk`, `send_pk`, `owner_pk`) reject when y ≥ p, when y is one of the five y-coordinates of the points of order
  dividing 8, or when the encoding is not a curve point (RFC 8032 §5.1.3 decoding fails); signatures (every D.2 `sig`,
  RelayInfoV1 `sig`, and bytes 0–63 of a HybridSig in PrekeyBundle and KeyChangeBody) reject when R does or S ≥ L.
- **D-11** ML-KEM encapsulation keys (`relay_kem_ek`, `ek_c`, `spk_kem`, `rpk_kem`, `opk_kem`, `ek_pq`) pass the FIPS
  203 §7.2 modulus check: no packed 12-bit coefficient ≥ q = 3329 (SQ-12 (b)).
- **D-12** `Profile.name` is strict UTF-8 (RFC 3629: no overlong forms, no surrogates, nothing above U+10FFFF).
- **D-13** Not checked by decoding (other suites or later layers): signatures, MACs, AEAD tags, fingerprints, `akc`,
  `relay_fp`, timestamps and expiry, `cmd_seq` order; ML-DSA sigDecode MUST NOT run at decode (SQ-12 (c)); the
  contents of `AppMessage.payload` and `ControlBody.arg` (opaque, SQ-19), `cell` and ciphertexts; the opaque
  structures `Cell`, `HandshakeCell`, `LinkBlob`, `inner_ct` (length only).

**Input derivation (SCHEMA §2).** Every case draws from its own stream in the order below. Public keys and signatures
are derived from stream seeds with the M1 primitives (X25519 secret 32 → X25519(sk, 9); Ed25519 seed 32; ML-KEM seed
`d ‖ z` 64 → `ek`; ML-DSA ξ 32; hedge `rnd` 32), so every positive contains valid keys and verifying signatures.
Ciphertexts, MACs, hashes, ids, tokens and nonces are raw stream bytes. A free integer of width w is w stream bytes,
big-endian, unless the row's table-fixed values fix it (the maximum-value rows: the fixed integer is not drawn and
the stream moves on to the next field). `ver`, type/op/kind/code bytes, presence bytes, periods, counts,
`i`/`idx`/`total`, `host`, `port`, lengths and chunk lengths come from the table. "Text of k stream bytes" is the
lowercase hex of k stream bytes as ASCII (2k bytes: valid UTF-8). A negative "from row r" draws its own stream
exactly as row r does (SCHEMA §4 preamble), builds the honest value, then applies its manipulation.

**Manipulations.** `f := v` re-encodes field f (a dotted path; `[k]` is element k of a list) with value v in the
field's own width; `f := f ± 1` likewise. Unless the row sets a length or count field, every length and count field
(`len`, `host_len`, `name_len`, `body_len`, `payload_len`, `arg_len`, `count`, `route_count`) is recomputed after the
manipulation, so the row isolates its defect; a row that sets one sets it after that recomputation, and "(… kept)" means
the bytes it covers are unchanged. A field "removed" is not written. A padded structure is padded again to its size
after a field manipulation (with no padding at all if the fields fill it). Byte-level manipulations act on the final
bytes: `drop-last`, `append-zero`, `empty`, `prefix(n)`; `pad: marker := x` (the byte after the fields), `pad: last
byte := 0x01`, `pad: marker late` = pad(fields ‖ 00), `pad: marker early` = pad(fields without their last byte), "the
unpadded fields alone". `sig: S := S + L` and `sig: R := x` act on bytes 32–63 and 0–31 of the Ed25519 signature (of a
HybridSig: its Ed25519 part). "bytes 0–2 := ff ff ff" on an ML-KEM `ek` makes its first packed coefficient 0xfff ≥ q.

**Families.** Each negative row is tagged with the family it exercises. The brief's families map as follows: wrong
`ver` → VER; length off by one / zero / max + 1 → SIZE, TRAIL, LEN (for a fixed-size structure max + 1 is
`append-zero`); wrong padding → PAD (ISO/IEC 7816-4 has no pad-length value: "wrong pad length" is `marker late`, "pad
longer than the payload allows" is `marker early` and the no-room-for-the-marker rows); trailing bytes → TRAIL;
reserved bits → RSV; unknown opcode/type → TYPE; Option present/absent → OPT; low-order X25519 → X25519; Ed25519 →
ED25519; overflow → OVF (a field at its maximum value; the positives also carry every kind of counter and length at
its maximum, which must round-trip exactly).

{families}

The column "ref check" names the check of the reference decoder that fires first. It is informational: another
decoder may reject the same bytes at a different check; only the uniform rejection is compared.
"""


def _md(text):
    return str(text).replace("|", "\\|")


def render() -> str:
    npos, nneg = len(ec.POSITIVES), len(ec.NEGATIVES)
    fam_rows = "| family | meaning |\n|---|---|\n" + "\n".join(f"| {k} | {_md(v)} |" for k, v in ec.FAMILIES.items())
    out = [PREAMBLE.format(npos=npos, nfirst=npos + 1, nlast=npos + nneg, nneg=nneg, families=fam_rows)]

    out.append("#### Stream order per structure\n\n| structure | stream order |\n|---|---|")
    out += [f"| `{s}` | {_md(t)} |" for s, t in STREAM_ORDER]
    documented = {s for s, _ in STREAM_ORDER}
    assert all(p.structure in documented or p.structure.startswith("Signed/") for p in ec.POSITIVES)

    out.append("\n#### Positive rows (`op` = `\"encode\"`)\n\n| i | structure | table-fixed values | bytes |\n|---|---|---|---|")
    for i, pos in enumerate(ec.POSITIVES, start=1):
        data = enc.encode(pos.structure, ec.honest_value(pos.key, i), pos.context)
        out.append(f"| {i} | `{pos.structure}` | {_md(pos.variant)} | {len(data)} |")

    out.append("\n#### Negative rows (`op` = `\"decode\"`, `expect: reject`)\n\n"
               "| i | structure | from row | manipulation | family | ref check |\n|---|---|---|---|---|---|")
    for i, neg in enumerate(ec.NEGATIVES, start=npos + 1):
        rule = ec.check_negative(i, neg, ec.negative_bytes(neg, i))
        ctx = f" [context {ec.context_of(neg)}]" if neg.structure == "Response/CELLR" else ""
        out.append(f"| {i} | `{neg.structure}` | {ec.POS_INDEX[neg.row]} | {_md(neg.manipulation)}{ctx} | "
                   f"{neg.family} | `{rule}` |")

    out.append("\n#### Changes from the proposal (Weisung REF-M2-1)\n\n"
               "1. **Renumbered and re-seeded once.** Every id and every case stream changed. Row numbers quoted in the "
               "proposal, in SQ-12 … SQ-19 and in earlier notes refer to the proposal (REF-M2 report), not to this "
               "table.\n"
               "2. **`op` and `mode` are JSON strings** inside `value` (the proposal wrote JSON numbers), and the file "
               "header is `\"schema\": 3`.\n"
               "3. **The 22 rows the proposal withheld are written** with their answered outcome: 21 rejects and one "
               "positive (below). Only one of them has an outcome that differs from the proposal's reading: `Fragment` "
               "with `total` := 1, `idx` := 0 (proposed: accept; SQ-18 answer (2): reject).\n"
               "4. **Rows added** by the Weisung (below): one ML-KEM modulus reject per encapsulation-key field that had "
               "none (addition 2), and the rows of correction 4, including positives with counters and lengths at "
               "their maximum values.\n"
               "5. **Check names.** Checks that implemented a proposed reading had `sqNN-` names; they now carry the "
               "names of the answered rules (`host`, `onion`, `range`, `len`, `type`, `reserved`, `mlkem-ek`, "
               "`ed25519-key-off-curve`, `ed25519-sig-R-off-curve`).\n"
               "6. **No row written in the proposal changed its outcome.** Every case of the proposal's file was "
               "decoded again under the answered rules: all its positives still decode and all its negatives still "
               "reject.\n\n"
               "| source | row | structure | manipulation (negative) or table-fixed values (positive) | outcome |\n"
               "|---|---|---|---|---|")
    for sq, structure, start in ec.FORMERLY_WITHHELD:
        for i in ec.rows_matching(structure, start):
            neg = ec.NEGATIVES[i - npos - 1]
            differs = " (differs from the proposal)" if (structure, start) in ec.OUTCOME_DIFFERS_FROM_PROPOSAL else ""
            out.append(f"| withheld, {sq} | {i} | `{structure}` | {_md(neg.manipulation)} | reject{differs} |")
    for key in ec.FORMERLY_WITHHELD_POSITIVES:
        pos = ec.POS_BY_KEY[key]
        out.append(f"| withheld, SQ-18 | {ec.POS_INDEX[key]} | `{pos.structure}` | {_md(pos.variant)} | accept (positive) |")
    for source, structure, start in ec.ADDED:
        for i in ec.rows_matching(structure, start):
            neg = ec.NEGATIVES[i - npos - 1]
            out.append(f"| added, {source} | {i} | `{structure}` | {_md(neg.manipulation)} | reject |")
    for key in ec.ADDED_POSITIVES:
        pos = ec.POS_BY_KEY[key]
        out.append(f"| added, correction 4 | {ec.POS_INDEX[key]} | `{pos.structure}` | {_md(pos.variant)} | accept (positive) |")

    out.append("\n#### Coverage per structure\n\n| structure | positive rows | negative rows | families (rows) |\n"
               "|---|---|---|---|")
    fam = collections.defaultdict(collections.Counter)
    for neg in ec.NEGATIVES:
        fam[neg.structure][neg.family] += 1
    for structure in ec.APPLIES:
        prows = [str(i) for i, p in enumerate(ec.POSITIVES, start=1) if p.structure == structure]
        nrows = sum(fam[structure].values())
        cover = ", ".join(f"{f} {n}" for f, n in sorted(fam[structure].items())) or "— (encode only)"
        out.append(f"| `{structure}` | {', '.join(prows)} | {nrows} | {cover} |")

    out.append("""
#### Constants asserted by the generator (App. B, D)

Every size below is re-derived from its App. D field list at import time (`ref/secmp_ref/encodings.py`) and every
positive of a fixed-size structure is checked against it: HELLO body 7; RelayInfoV1 1741; HS1 2853; HS2 1153; frame
plaintext 4336 = 4352 − 16 = 4096 + 240; LINK_PUT 4160 + 4100 + 4100 = 12360; largest frame payloads LINK_PUT 4314,
CELLR 4126, FETCH_MULTI (32) 2822 — all < 4336; InvitationV1 without direct 241; IKSPublic 2017; PrekeyBundle 7775;
LinkDataV1 fields ≤ 9899 < 12288; blob 24 + 32 + 12288 + 16 = 12360; Inner 6113; inner_ct 6185; Outer 9362, padded
3 × 4006 = 12018; HandshakeCell plaintext 4024, sealed 4096; HeaderV1 2314, hdr_ct 2330; Cell 24 + 2330 + 1710 + 32 =
4096; Content body ≤ 1710 − 20 − 1 = 1689; KeyChange body 2017 + 3373 = 5390 > 1689; 64 fragments of 1669 B hold a
65535-byte payload; `host_len` ≤ 253. All agree with App. B and D; no size question arose.
""")
    return "\n".join(out)


def main():
    OUT.write_text(render(), encoding="utf-8")
    print(OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
