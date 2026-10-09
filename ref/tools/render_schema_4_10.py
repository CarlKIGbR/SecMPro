# SPDX-License-Identifier: AGPL-3.0-or-later
"""Write SCHEMA-4.10-hx.md (SCHEMA §4.10, the `hx` case table) from the table that generates
vectors/hx.json, so that the two cannot drift apart.

    .venv/bin/python -m tools.render_schema_4_10          (from ref/)
"""

import pathlib

from secmp_ref import hx_cases
from secmp_ref.hx_cases import EXTRA, INVITEE_NEGATIVES, POSITIVES, RESPONDER_NEGATIVES

EXTRA_POS = [e for e in EXTRA if not isinstance(e, hx_cases.ResponderNeg)]
EXTRA_NEG = [e for e in EXTRA if isinstance(e, hx_cases.ResponderNeg)]
ALL_RESPONDER_NEGATIVES = [*RESPONDER_NEGATIVES, *EXTRA_NEG]

OUT = pathlib.Path(__file__).resolve().parent.parent.parent / "SCHEMA-4.10-hx.md"


def _fields(layout):
    return ", ".join(f"`{name}` {n}" for name, n in layout) or "—"


HEAD = """\
### 4.10 `hx` — SecMP-INV/HX full run (spec §5, §6)

*SCHEMA §4.10 as proposed by `ref/` for brief REF-M4 (2026-09-30), from spec rev 2.3 §5, §6, §7.2–7.3, §7.6, §3 and
App. A–D. The reviewer's decisions in the brief are written down as given; what `ref/` adds is marked
**(proposal)**, and the reading pinned for SQ-25 is marked with the question. Weisung REF-M4-1 (2026-09-30)
confirmed every reading and proposal, answered SQ-25 (reading A) and appended V9 and R13. Weisung REF-M5-2 (2026-10-07) re-froze the file for spec rev 2.6: `inv_sid` is derived, and A1, R14 … R18 and A2 are appended. The tables are generated
by `ref/tools/render_schema_4_10.py` from `ref/secmp_ref/hx_cases.py`, the table that generates `vectors/hx.json`.*

Suite `hx`, tag `hx` (SCHEMA §3), file `vectors/hx.json`, header `"schema": 5` and `"spec": "SecMP/1 rev 2.6"`
(SCHEMA §1). {total} cases, one per step: {n_pos} positive, {n_inv} `invitee-reject` (V1–V9) and {n_resp}
`respond-reject` (R1–R18). The order is the positives (`hx-0001` … `hx-0008`), V1–V8 (`hx-0009` … `hx-0016`), R1–R12
(`hx-0017` … `hx-0028`), then V9 (`hx-0029`) and R13 (`hx-0030`), which Weisung REF-M4-1 appended so that no earlier
case index, and so no seed, moves (SCHEMA §1: negatives after the positives), and then the cases of Weisung REF-M5-2
(**proposal**: ids, op names, stream lists): A1 (`hx-0031`), R14 … R18 (`hx-0032` … `hx-0036`) and A2 (`hx-0037`),
appended in the same way. The file header names spec rev 2.6 (the rev-2.5 rules of §5.2, §6.1, §6.5 and §6.6 and the
clarifications of ADR-048); a case whose bytes did not change keeps its stream. Case *i* draws from its own stream (SCHEMA §2,
suite name `hx`, index *i*); every stream-derived value is listed in `inputs` in stream order, and the *derived*
values follow them.

**Case shape (SCHEMA §1, `"schema": 5`).** Every case has `id` (`hx-0001` …), `op`, `party` and `inputs`;
`party` is `"I"` (the initiator = the invitee) or `"R"` (the responder = the inviter). A positive case has
`outputs`. An `invitee-reject` case has `manipulation` (an ASCII name) and `"expect": "reject"`, and no `outputs`.
A `respond-reject` case has `manipulation`, `"expect": "reject"` **and** `outputs` = {{`opks_post`}}. Values are
lowercase-hex byte strings except: `uri`, an ASCII JSON string; `accept`, a JSON boolean; `opks_post`, a JSON array
of numbers in ascending order; `fetched` and `routes`, JSON arrays of byte strings in order **(proposal: these
four JSON shapes)**. The suite's constants are not repeated in `inputs`.

**Constants** (brief REF-M4): `now` = 1 700 000 100; `created` = 1 700 000 000; `expires` = `spk_expiry` =
1 702 592 000 (`created` + 30 days); `spk_id` = 7; `opk_id` = 42; `inv_period_s` = 20; `kind` = 0x01; `RelayRef.direct`
absent; Profile_R = name `"bob"`, `avatar_present` 0; Profile_I = name `"alice"`, `avatar_present` 1. State digests
are `StateDigestV1` of SCHEMA §4.9, unchanged. R's prekey state is `opks_post`, the list of its unused `opk_id`s.

**Keys from the stream** (SCHEMA §2): an X25519 secret is 32 raw bytes (clamped inside X25519); IK_sig =
Ed25519 seed `ik_ed_seed` ‖ ML-DSA-65 `KeyGen_internal(ik_mldsa_xi)`; an ML-KEM key pair is `KeyGen_internal(d ‖ z)`
of its 64-byte seed (SPK, OPK: ML-KEM-1024; RPK and the ratchet: ML-KEM-768); `m_*` and `m` are
`Encaps_internal` randomness; `rnd` hedges ML-DSA (HybridSign, §3.5).

**The Handshake Content** (§7.6, D.5; case 6). `ver` 1, `type` 0x01, `seq` 1, `ts` 1 700 000 001, body = Profile_I
{{`name_len` 5, `"alice"`, `avatar_present` 1, `avatar_sha256`}} ‖ `caps` 0 ‖ `route_count` 1 ‖ one RouteDescriptor
built exactly as the §4.8 positive row `rd_relayqueue` (`ver` 1, kind 0x01, RelayQueue without `direct`, `period_s`
20; stream fields {route}; `onion` from `onion_seed` as in §4.8). Unpadded {content_len} B.

**Obligations per op.** An implementation reproduces every case from its inputs and the cases before it:

- `keys-R`: R's identity from `ik_mldsa_xi`, `ik_ed_seed`, `ik_dh_sk`; SPK_dh `spk_dh_sk`, SPK_kem `spk_kem_seed`,
  RPK_kem `rpk_kem_seed`, OPK 42 = (`opk_dh_sk`, `opk_kem_seed`). `iks` is the encoded IKSPublic_R, `fp` its
  fingerprint (§6.2). `bundle` is the PrekeyBundle (§6.3) {{`ver` 1, `spk_id` 7, …, `spk_expiry`, `opk_present` 1,
  `opk_id` 42, …}} with `sig` = HybridSign(IK_sig_R, `"SecMP-HX/1 bundle"`, the 4402 encoded bytes before `sig` ‖
  IK_dh_R) hedged with `rnd`.
- `keys-I`: I's identity; `iks`, `fp`.
- `invite`: InvitationV1 {{`ver` 1, `kind` 0x01, RelayRef {{`ver` 1, `relay_fp`, `onion` = `onion_pubkey` ‖
  SHA3-256(".onion checksum" ‖ `onion_pubkey` ‖ 0x03)[0..2] ‖ 0x03, `akc`, `direct_present` 0}}, `ld_id`, `link_key`,
  `inviter_fp` = case 1 `fp`, `inv_sid`, `inv_send_seed`, `inv_period_s` 20, `expires`}}. `inv_sid` is **derived**
  (§9.1, ADR-048 (m)): SHA-256(`"SecMP-Q/1 sid"` ‖ `invq_recv_pk` ‖ Ed25519.pk(`inv_send_seed`))[0..16], where
  `invq_recv_pk` is the Ed25519 public key of `invq_recv_seed` (the invitation queue's recipient key). The 16 bytes
  formerly drawn for `inv_sid` are still drawn, at their old position, and discarded (`inv_sid_discarded`, reading
  OPEN-M5-14 B), so every other draw keeps its bytes; `invq_recv_seed` and `owner_seed` (the link-data owner key,
  §5.2) follow the last draw. Outputs: `invitation` is its encoding ({inv_len} B), `uri` = `"secmp://i/"` ‖ base64url
  without padding ({uri_len} characters in all), and **(proposal)** `inv_sid`, `invq_recv_pk` and `owner_pk` (the
  Ed25519 public key of `owner_seed`). R records (`ld_id`, `link_key`, `spk_id` 7, `opk_id` 42, `expires`) for this
  invitation (§5.2).
- `linkdata`: LinkDataV1 {{`ver` 1, case 1 `iks`, case 1 `bundle`, Profile_R, `created`}}. `linkdata` is its encoding
  without padding ({ld_len} B); `k_ld` = HKDF(`ld_id`, `link_key`, `"SecMP-INV/1 linkdata"`, 32); `blob` = `n` ‖
  CAEAD.Seal(`k_ld`, `n`, `"SecMP-INV/1 blob"` ‖ `ld_id`, pad(`linkdata`, 12288)) (12360 B).
- `invitee-accept`: I processes case 3's `uri` and case 4's `blob` at `now`: §5.5 step 1 (the URI, InvitationV1
  decoding, `expires` > `now`), the blob opening of step 2 (CAEAD.Open with `K_ld`, LinkDataV1 decoding), step 3
  (fingerprint(`inviter_iks`) = `inviter_fp`) and step 4 (HybridVerify of `bundle.sig` under `inviter_iks`,
  `spk_expiry` > `now`, `opk_present` = 1). Outputs `k_ld`, `k_inv` (§6.5) and `accept` = true.
- `initiate`: I (case 2) runs §6.4 on the values of case 5. EK_I is the X25519 secret `ek_sk`; (`ct_spk`, `ss_spk`) =
  `Encaps_internal`(SPK_kem_R, `m_spk`), (`ct_opk`, `ss_opk`) = `Encaps_internal`(OPK_kem_R, `m_opk`); DH1–DH4,
  `transcript`, `sk`, `k_id`, `k_inv`. The TR initiator (§7.2) from `sk` with `sb` = `transcript`, `dh_r` = SPK_dh_R,
  `kem_r` = RPK_kem_R draws `dh_s_sk`, `kem_s_seed`, `m_tr`. Then the Handshake Content (above) from `avatar_sha256`
  and the route fields; `first_msg` = Encrypt(state, `content`) with `hdr_nonce` (§7.3); Inner = IKSPublic_I ‖
  `first_msg`; `inner_ct` = `inner_nonce` ‖ CAEAD.Seal(`k_id`, `inner_nonce`, `"SecMP-HX/1 inner"` ‖ `ld_id`, Inner);
  `outer` (unpadded, 9362 B); Padded = pad(`outer`, 12018); `cell_k` = `cell_nonce_k` ‖ CAEAD.Seal(`k_inv`,
  `cell_nonce_k`, `"SecMP-HX/1 initcell"` ‖ `ld_id`, `init_id` ‖ k ‖ 0x03 ‖ Padded[4006·k .. 4006·(k+1)]).
  `state_post_I` is I's TR state digest after the Encrypt.
- `respond`: R, from its state after cases 1–4, runs §6.6 steps 1–4 on `fetched`. It trial-opens every cell with
  `K_inv` (AD `"SecMP-HX/1 initcell"` ‖ `ld_id`) and ignores a cell that does not open or whose plaintext does not
  decode as a HandshakeCellPlaintext (`total` = 3, `i` ∈ {{0, 1, 2}}); it groups the chunks by `init_id` and processes
  the first `init_id`, in fetch order, for which chunks 0, 1 and 2 have all arrived **(proposal: a later chunk with
  an (`init_id`, `i`) already seen is ignored)**. Then: decode Outer (padded, §4.1 decoder obligations); `spk_id` = 7,
  `opk_id` = 42, and OPK 42 unused; DH3, DH4, `ss_spk`, `ss_opk` (Decaps), `K_id`; open `inner_ct`; decode Inner
  (IKSPublic_I decodable, `ik_dh` not low-order); DH1, DH2, `transcript`, `SK`; the TR responder (§7.2: `dh_s` =
  SPK_dh_R, `kem_s` = RPK_kem_R); Decrypt(`first_msg`) (§7.4, a DH step drawing `dh_sk`, `kem_seed`, `m`); decode the
  Content (type 0x01, `caps` = 0). Success deletes OPK 42. Outputs: `transcript`, `sk`, `k_id` (equal to case 6),
  `peer_iks` (= case 2 `iks`), `content` (= case 6, unpadded), `profile` (the Handshake's encoded Profile), `routes`
  (its encoded RouteDescriptors) **(proposal: `profile` and `routes` as encodings)**, `state_post_R` (after the
  Decrypt), `opks_post` = [].
- `respond-garbage`: as `respond`, again from R's state after cases 1–4 (not after case 7), with `fetched` =
  [`g1`, `cell_0`, `g2`, `cell_1`, `cell_2`]; `g1` and `g2` do not open and are ignored.
- `respond-later-group` (A1, **proposal**): as `respond`, from R's state after cases 1–4, on a `fetched` that holds a
  complete group that R rejects, followed by case 6's cells. A complete group that is rejected is discarded, the OPK is
  kept, and later groups with other `init_id`s are processed (§6.5 rev 2.5). The outputs are those of `respond`.
- `respond-retained-spk` (A2, RF-1, **proposal**): as `respond`, from a state in which R holds two SPK generations:
  the current one (`spk_id` 8) and, retained, the SPK 7 that the invitation references (§6.1 rev 2.5). R finds the
  generation by the `spk_id` of the Outer, which must be the invitation's. The outputs are those of `respond`.
- `invitee-reject`: I processes (`uri`, `blob`) as in `invitee-accept`, where `uri` is the case's derived `uri` if it
  lists one and else case 3's, and `blob` the case's derived `blob` if it lists one and else case 4's; it must reject
  with its single uniform error.
- `respond-reject`: R, from its state after cases 1–4 (R3: after case 7), processes `fetched` as in `respond` and
  must reject with its single uniform error, leave its OPKs as `opks_post` says and persist nothing. `fetched` is
  listed in every responder case, also where it repeats case 6's cells **(proposal)**. R8, R9 and R13 list R's
  DH-step draws after the construction draws: R's Decrypt takes the step on its working copy before the failure, as
  tr's N1 **(proposal)**; no output depends on them.
- **Rev 2.5 rules of `respond`** (Weisung REF-M5-2; all **proposal** as to their wording in the vector file): groups
  are processed in the order they complete. A duplicate (`init_id`, `i`) is ignored whether its bytes are identical or
  differ (first-seen wins); a group that has completed is closed, so later chunks of its `init_id` are ignored and a
  rejected `init_id` cannot re-form; at most 8 partial groups are stored, the oldest evicted. After a rejected complete
  group the OPK is kept and the next group is processed; if none is accepted the op rejects, with the reference check
  of the last rejected group (or `no-complete-envelope` if no group completed). The `first_msg` header must carry
  `n` = 0 and `pn` = 0 (`first-msg-header`). `IKSPublic_I` must differ from `IKSPublic_R` (`reflection`, §6.6 step 2).
  The Handshake content must contain at least one route of a known kind (`no-known-route`; SQ-29). The Outer's
  `spk_id` must be the invitation's, and may name a retained SPK generation.

#### Positive cases

| # | id | op | party | `inputs`: stream order; *derived* | `outputs` (B) | step |
|---|---|---|---|---|---|---|
{positives}

#### Rev 2.5 positive cases (A1, A2; appended by Weisung REF-M5-2, **proposal**)

Both are `party` R, with `outputs` as `respond` (case 7), and `fetched` listed in `inputs`.

| A | id | op | `inputs`: stream order; *derived* | `outputs` (B) | construction |
|---|---|---|---|---|---|
{extra}

#### `invitee-reject` (base = cases 3 and 4)

"ref check" names the check of the reference invitee that fires. It is informational; only the uniform rejection is
compared. The checks are `invitation-decode` (the InvitationV1 decoder), `expired` (`now` ≥ `expires`), `blob-open`
(CAEAD.Open with `K_ld`), `linkdata-decode` (the LinkDataV1 decoder), `fingerprint` (step 3), `bundle-sig`
(HybridVerify, step 4) and `bundle-expired` (`spk_expiry` ≤ `now`, step 4).

| V | id | `manipulation` | `inputs`: stream order; *derived* | construction | ref check |
|---|---|---|---|---|---|
{invitee}

#### `respond-reject` (base = case 6; everything not named is case 6's)

Re-sealing draws, in this order: `inner_nonce` 24 only when Inner changes, then `init_id` 16 and `cell_nonce_0/1/2`
24 each when the outer changes (brief). The checks of the reference responder are `no-complete-envelope`,
`outer-decode` (the Outer decoder), `prekey-ids` (`spk_id`/`opk_id` not this invitation's), `opk-used` (OPK already
deleted), `inner-open` (CAEAD.Open with `K_id`), `inner-decode` (the Inner decoder), `tr-decrypt` (§7.4),
`content-decode` (the Content decoder), `not-handshake` (a valid Content of another type than 0x01), and, from
Weisung REF-M5-2, `first-msg-header` (`n` or `pn` ≠ 0), `reflection` (`IKSPublic_I` = `IKSPublic_R`) and
`no-known-route` (no route of kind 0x01) — and, not reached by any case, `dh-zero` (the §6.4 non-zero check, defence in depth behind the §4.1(a) decoders).

| R | id | `manipulation` | R's state | `inputs`: stream order; *derived* | construction | ref check | `opks_post` |
|---|---|---|---|---|---|---|---|
{responder}

#### Readings and questions

- **SQ-29** (§6.5 rev 2.5, §9.8): "the Handshake content MUST contain at least one route of a known kind". `ref/`
  reads "known" as the kinds a v1 responder can use, that is 0x01 (`RelayQueue`, §9.8 "v1"); 0x02 and 0x03 are marked
  v1.1 there. R18 uses kind 0x7F and rejects under either reading. Open; blocks nothing.
- Readings adopted without a question — REF-M5-2 (`ref/SPEC-QUESTIONS.md`): the §6.5 grouping rules above (an
  accepted group also closes its `init_id`); the order of the rev 2.5 checks in `respond` (header `n`/`pn` after
  Decrypt and before the Content decoder; reflection right after the Inner decoder; routes after the Handshake type
  check); R15's header `n` = 1 is built by encrypting one message first and discarding its cell, so that R's Decrypt
  succeeds and only the header rule rejects; R16's `pn` = 1 is set on I's TR state before encrypting; A1's rejected
  group is case 8's R8 construction under a fresh `init_id`; RF-1's current SPK is a new generation `spk_id` 8
  (`spk_expiry` unchanged) and its keys come from the case's own stream; `inv_sid`'s derivation draws
  `invq_recv_seed` and `owner_seed` after the last old draw.

- **SQ-25** (§5.2, §6.3, §5.5): §5.2 "`expires` … MUST be ≤ creation + 30 days" and §6.3 "`spk_expiry` MUST be ≥ the
  expiry of every invitation referencing it" bind the inviter; §5.5 does not say whether the invitee checks them
  (InvitationV1 carries no creation time; LinkDataV1 has `created`). `ref/` pins the brief's lists for steps 1 and 4:
  the invitee checks neither. No case depends on it: the positive run has `expires` = `created` + 30 days exactly
  and `spk_expiry` = `expires`, and V1 and V6 reject under every reading. **Answered** (Weisung REF-M4-1): reading
  A; the invitee checks exactly §5.5 steps 1, 3 and 4, and no case is added.
- Readings adopted without a question (`ref/SPEC-QUESTIONS.md`, "Readings adopted without a question — REF-M4",
  all confirmed by Weisung REF-M4-1):
  `spk_id`/`opk_id` in the transcript are u32 big-endian; the bundle signs its encoded fields as they stand ‖ the
  signer's `ik_dh`; the invitee's order of checks and `expires` > `now`; the strict URI decoding; the responder's
  grouping, and "no complete envelope" as the op's rejection; R4 rejected by the Outer decoder; the Content type
  check; no time check at R; R9's reuse of I's first message key (a vector-only construction); the two `onion`
  derivations; V8's `flip(link_key, 0)`; and the JSON shapes above.
"""


def _names(layout, derived):
    parts = [f"`{name}` {n}" for name, n in layout] + [f"*`{name}`*" for name in derived]
    return ", ".join(parts) or "—"


def _out(k, v):
    """A byte string by its length; a list of byte strings by the lengths; other values as they are."""
    if isinstance(v, bytes):
        return f"`{k}` {len(v)}"
    if isinstance(v, str):
        return f"`{k}` ({len(v)} chars)"
    if isinstance(v, bool):
        return f"`{k}` = {str(v).lower()}"
    if all(isinstance(x, int) for x in v):
        return f"`{k}` = {v}"
    return f"`{k}` [{', '.join(str(len(x)) for x in v)}]"


def _positives(run):
    out = []
    for p, case, row in zip(POSITIVES, run.cases[:len(POSITIVES)], run.rows[:len(POSITIVES)]):
        outputs = ", ".join(_out(k, v) for k, v in case.outputs.items())
        out.append(f"| {case.i} | {row['id']} | `{p.op}` | {p.party} | {_names(p.stream, row['derived'])} | "
                   f"{outputs} | {p.text} |")
    return "\n".join(out)


def _extra(run):
    out = []
    for ex in EXTRA_POS:
        case, row = next((c, r) for c, r in zip(run.cases, run.rows) if r.get("name") == ex.name)
        outputs = ", ".join(_out(k, v) for k, v in case.outputs.items())
        out.append(f"| {ex.name} | {row['id']} | `{ex.op}` | {_names(ex.stream, row['derived'])} | {outputs} | "
                   f"{ex.text} |")
    return "\n".join(out)


def _negatives(run, table, op):
    out = []
    rows = [r for r in run.rows if r["op"] == op]
    for neg, row in zip(table, rows, strict=True):
        assert neg.name == row["name"]
        cells = [neg.name, row["id"], f"`{neg.manipulation}`"]
        if op == "respond-reject":
            cells.append("after case 7" if row["after7"] else "after cases 1–4")
        cells += [_names(neg.stream, row["derived"]), neg.text, f"`{neg.rule}`"]
        if op == "respond-reject":
            cells.append(str(row["opks_post"]))
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out)


def render() -> str:
    run = hx_cases.run()
    outs = {c.op: c.outputs for c in run.cases if c.outputs}
    return HEAD.format(
        total=len(run.cases), n_pos=len(POSITIVES) + len(EXTRA_POS), n_inv=len(INVITEE_NEGATIVES),
        n_resp=len(ALL_RESPONDER_NEGATIVES),
        route=_fields(hx_cases.ROUTE_STREAM), content_len=len(run.ctx.content),
        inv_len=len(outs["invite"]["invitation"]), uri_len=len(outs["invite"]["uri"]),
        ld_len=len(outs["linkdata"]["linkdata"]),
        positives=_positives(run), invitee=_negatives(run, INVITEE_NEGATIVES, "invitee-reject"),
        responder=_negatives(run, ALL_RESPONDER_NEGATIVES, "respond-reject"), extra=_extra(run))


def main():
    text = render()
    OUT.write_text(text, encoding="utf-8")
    print(f"{OUT.name}: {len(text.splitlines())} lines")


if __name__ == "__main__":
    main()
