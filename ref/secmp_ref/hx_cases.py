# SPDX-License-Identifier: AGPL-3.0-or-later
"""The `hx` case table (SCHEMA §4.10 = SCHEMA-4.10-hx.md; brief REF-M4): one full SecMP-INV/HX run.

One case per step, in order: the responder's keys and bundle, the initiator's keys, the invitation,
the link data, the invitee's checks, the initiator's envelope, the responder's processing (plain
and with garbage cells), then the invitee rejections V1 … V8, the responder rejections R1 … R12, and
V9 and R13, which Weisung REF-M4-1 appended so that no earlier case index moves.
Every case draws from its own stream (SCHEMA §2, suite name "hx", the case index); every
stream-derived value is listed in `inputs` in stream order, then the *derived* values.

The run checks itself while it generates: both sides derive the same `transcript`, `SK` and `K_id`;
the responder returns the initiator's Content; every rejection is raised by the check the table names,
draws exactly what the table lists, and leaves the responder's OPKs as the table says. A disagreement
raises TableMismatch instead of writing a file.
"""

import dataclasses
import functools
from typing import NamedTuple

from . import encodings as enc
from . import encodings_cases as ec
from . import hx, inv, primitives, sizes, tr
from . import relay as relay_q
from .cases import TableMismatch
from .errors import Reject
from .tr_cases import ROUTE_PERIOD, ROUTE_STREAM, STEP_DRAWS, state_digest
from .vectorfile import Case, CaseStream, case_id, flip

SUITE = "hx"

# ---------------------------------------------------------------------------------------------
# Suite constants (brief REF-M4)

NOW = 1_700_000_100
CREATED = 1_700_000_000
EXPIRES = SPK_EXPIRY = 1_702_592_000
assert EXPIRES == CREATED + 30 * 86_400           # §5.2 "MUST be ≤ creation + 30 days": exactly 30 days
SPK_ID, OPK_ID = 7, 42
INV_PERIOD = 20
KIND = 0x01
NAME_R, NAME_I = b"bob", b"alice"
HS_SEQ, HS_TS = 1, 1_700_000_001
LOW_ORDER = enc.X25519_ORDER8[0]                  # R5: e0eb7a7c…b800, a point of order 8
assert LOW_ORDER.hex() == "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"

# ---------------------------------------------------------------------------------------------
# Stream layouts (name, bytes), in stream order

IKS_STREAM = [("ik_mldsa_xi", 32), ("ik_ed_seed", 32), ("ik_dh_sk", 32)]
KEYS_R_STREAM = IKS_STREAM + [("spk_dh_sk", 32), ("spk_kem_seed", 64), ("rpk_kem_seed", 64), ("opk_dh_sk", 32),
                              ("opk_kem_seed", 64), ("rnd", 32)]
# `inv_sid` is derived (§9.1, ADR-048 (m)); its 16 bytes are still drawn, at their old position, and discarded
# (reading OPEN-M5-14 B, Weisung REF-M5-2), so that every other draw of the case keeps its bytes. The queue keys
# come last.
INVITE_STREAM = [("relay_fp", 32), ("onion_pubkey", 32), ("akc", 32), ("ld_id", 16), ("link_key", 32),
                 ("inv_sid_discarded", 16), ("inv_send_seed", 32), ("invq_recv_seed", 32), ("owner_seed", 32)]
N_STREAM = [("n", 24)]
START_DRAWS = [("ek_sk", 32), ("m_spk", 32), ("m_opk", 32), ("dh_s_sk", 32), ("kem_s_seed", 64), ("m_tr", 32)]
CELL_NONCES = [("cell_nonce_0", 24), ("cell_nonce_1", 24), ("cell_nonce_2", 24)]
OUTER_RESEAL = [("init_id", 16)] + CELL_NONCES
INNER_RESEAL = [("inner_nonce", 24)] + OUTER_RESEAL
ENVELOPE_DRAWS = [("hdr_nonce", 24)] + INNER_RESEAL
INITIATE_STREAM = START_DRAWS + [("avatar_sha256", 32)] + ROUTE_STREAM + ENVELOPE_DRAWS
GARBAGE = [("g1", sizes.CELL), ("g2", sizes.CELL)]
assert STEP_DRAWS == [("dh_sk", 32), ("kem_seed", 64), ("m", 32)]


class _Named:
    """The case stream handed out as randomness against a layout: each draw must have the size the
    layout expects next, and is kept under its name, in stream order."""

    def __init__(self, stream, layout):
        names = [name for name, _ in layout]
        assert len(set(names)) == len(names)
        self.stream, self.layout, self.values = stream, list(layout), {}

    def take(self, n):
        k = len(self.values)
        if k >= len(self.layout) or self.layout[k][1] != n:
            raise TableMismatch(f"draw {k} of {n} B, the layout is {self.layout}")
        name = self.layout[k][0]
        self.values[name] = self.stream.take(n)
        return self.values[name]

    def done(self) -> dict:
        if len(self.values) != len(self.layout):
            raise TableMismatch(f"{len(self.values)} draws, the layout has {len(self.layout)}")
        return dict(self.values)


# ---------------------------------------------------------------------------------------------
# Values


def profile(name: bytes, avatar: bytes | None) -> dict:
    v = {"name_len": len(name), "name": name, "avatar_present": int(avatar is not None)}
    if avatar is not None:
        v["avatar_sha256"] = avatar
    return v


def handshake_content(avatar: bytes, route: dict, caps: int = 0) -> dict:
    """§7.6: ver 1, type 0x01, seq 1, ts; body Profile_I ‖ caps ‖ route_count 1 ‖ the RouteDescriptor."""
    body = {"profile": profile(NAME_I, avatar), "caps": caps, "route_count": 1, "routes": [route]}
    v = {"ver": enc.PROTO_VER, "type": enc.CT_HANDSHAKE, "seq": HS_SEQ, "ts": HS_TS, "body_len": 0, "body": body}
    enc.refresh("Content", v)
    if caps == 0:
        enc.encode("Content", v)                  # a valid Content (the M2 decoder agrees), else ValueError
    return v


@dataclasses.dataclass
class Ctx:
    """What the cases hand on to later cases."""
    r: hx.Identity = None
    prekeys: hx.Prekeys = None
    bundle: dict = None
    i: hx.Identity = None
    invitation_value: dict = None
    invitation: bytes = None
    uri: str = None
    record: hx.InvitationRecord = None
    linkdata_value: dict = None
    linkdata: bytes = None
    blob: bytes = None
    k_ld: bytes = None
    accepted: inv.Accepted = None
    start: hx.Start = None
    post_init: tr.RatchetState = None             # I's TR state before first_msg (R9)
    avatar: bytes = None
    route: dict = None
    content: bytes = None
    env: hx.Envelope = None
    after7: hx.Responder = None                   # R after case 7 (R3)
    accepted7: hx.Accepted = None                 # R's result in case 7 (its TR state: the tests' session)

    def fresh_responder(self) -> hx.Responder:
        """R's state after cases 1–4: its keys, the OPK 42 unused, the invitation record."""
        return hx.Responder(self.r, dataclasses.replace(self.prekeys, opks=dict(self.prekeys.opks)), self.record)


def _opks(responder: hx.Responder) -> list:
    return sorted(responder.prekeys.opks)


def _check(cond, what):
    if not cond:
        raise TableMismatch(what)


# ---------------------------------------------------------------------------------------------
# Positive cases


def _keys_r(ctx, rng):
    ctx.r = hx.Identity.from_secrets(rng.take(32), rng.take(32), rng.take(32))
    spk_dh = tr.DhKey.from_secret(rng.take(32))
    spk_kem = hx.Kem1024Key.from_seed(rng.take(64))
    rpk_kem = tr.KemKey.from_seed(rng.take(64))
    opk = hx.Opk(tr.DhKey.from_secret(rng.take(32)), hx.Kem1024Key.from_seed(rng.take(64)))
    ctx.prekeys = hx.Prekeys(SPK_ID, spk_dh, spk_kem, rpk_kem, SPK_EXPIRY, {OPK_ID: opk})
    ctx.bundle = hx.sign_bundle(ctx.r, ctx.prekeys.bundle_value(OPK_ID), rng)
    hx.verify_bundle(ctx.r.iks_value(), ctx.bundle)
    return {}, {"iks": ctx.r.iks, "fp": ctx.r.fp, "bundle": enc.encode("PrekeyBundle", ctx.bundle),
                "opks_post": sorted(ctx.prekeys.opks)}


def _keys_i(ctx, rng):
    ctx.i = hx.Identity.from_secrets(rng.take(32), rng.take(32), rng.take(32))
    return {}, {"iks": ctx.i.iks, "fp": ctx.i.fp}


def _invite(ctx, rng):
    relay = {"ver": enc.PROTO_VER, "relay_fp": rng.take(32)}
    relay["onion"] = enc.onion_from_pubkey(rng.take(32))       # PUBKEY ‖ CHECKSUM ‖ 0x03 (§5.3)
    relay.update(akc=rng.take(32), direct_present=0)
    v = {"ver": enc.PROTO_VER, "kind": KIND, "relay": relay, "ld_id": rng.take(16), "link_key": rng.take(32),
         "inviter_fp": ctx.r.fp}
    rng.take(16)                                   # inv_sid_discarded
    inv_send_seed = rng.take(32)
    invq_recv_pk = primitives.ed25519_public(rng.take(32))     # the invitation queue's recipient key
    owner_pk = primitives.ed25519_public(rng.take(32))         # the link-data owner key (§5.2)
    inv_sid = relay_q.sid_of(invq_recv_pk, primitives.ed25519_public(inv_send_seed))        # §9.1
    v.update(inv_sid=inv_sid, inv_send_seed=inv_send_seed, inv_period_s=INV_PERIOD, expires=EXPIRES)
    ctx.invitation_value, ctx.invitation = v, enc.encode("InvitationV1", v)
    ctx.uri = inv.uri_encode(ctx.invitation)
    ctx.record = hx.InvitationRecord(v["ld_id"], v["link_key"], SPK_ID, OPK_ID, EXPIRES)
    _check(len(ctx.invitation) == sizes.INVITATION_NO_DIRECT and inv.uri_decode(ctx.uri) == ctx.invitation,
           "invite: size or URI round trip")
    return {}, {"invitation": ctx.invitation, "uri": ctx.uri, "inv_sid": inv_sid, "invq_recv_pk": invq_recv_pk,
                "owner_pk": owner_pk}


def _linkdata(ctx, rng):
    ctx.linkdata_value = {"ver": enc.PROTO_VER, "inviter_iks": ctx.r.iks_value(), "bundle": ctx.bundle,
                          "profile": profile(NAME_R, None), "created": CREATED}
    enc.encode("LinkDataV1", ctx.linkdata_value)
    ctx.linkdata = enc.payload("LinkDataV1", ctx.linkdata_value)
    ctx.k_ld = inv.derive_k_ld(ctx.invitation_value["ld_id"], ctx.invitation_value["link_key"])
    ctx.blob = inv.seal_blob(ctx.k_ld, rng.take(24), ctx.invitation_value["ld_id"], ctx.linkdata)
    return {}, {"k_ld": ctx.k_ld, "linkdata": ctx.linkdata, "blob": ctx.blob}


def _invitee_accept(ctx, rng):
    acc = inv.invitee_accept(ctx.uri, ctx.blob, NOW)
    _check(acc.invitation == ctx.invitation_value and acc.linkdata == ctx.linkdata_value,
           "invitee-accept: decoded values differ")
    ctx.accepted = acc
    return {}, {"k_ld": acc.k_ld, "k_inv": acc.k_inv, "accept": True}


def _initiate(ctx, rng):
    s = hx.start(ctx.i, ctx.accepted.invitation, ctx.accepted.linkdata, rng)
    ctx.start, ctx.post_init = s, dataclasses.replace(s.state, skipped=dict(s.state.skipped))
    ctx.avatar = rng.take(32)
    ctx.route = ec._route(("rq", ROUTE_PERIOD, False))(rng)    # exactly the encodings row rd_relayqueue
    ctx.content = enc.payload("Content", handshake_content(ctx.avatar, ctx.route))
    ctx.env = e = hx.envelope(s, ctx.content, rng)
    _check([len(e.first_msg), len(e.inner_ct), len(e.outer), *map(len, e.cells)]
           == [sizes.CELL, enc.INNER_CT, sizes.HS_OUTER] + [sizes.CELL] * 3, "initiate: sizes")
    out = {"ek_pk": s.ek.pk, "dh1": s.dh1, "dh2": s.dh2, "dh3": s.dh3, "dh4": s.dh4, "ct_spk": s.ct_spk,
           "ss_spk": s.ss_spk, "ct_opk": s.ct_opk, "ss_opk": s.ss_opk, "transcript": s.transcript, "sk": s.sk,
           "k_id": s.k_id, "k_inv": s.k_inv, "content": ctx.content, "first_msg": e.first_msg,
           "inner_ct": e.inner_ct, "outer": e.outer}
    out.update({f"cell_{k}": c for k, c in enumerate(e.cells)})
    out["state_post_I"] = state_digest(s.state)
    return {}, out


def _accepted_outputs(ctx, responder, acc):
    s = ctx.start
    _check((acc.transcript, acc.sk, acc.k_id) == (s.transcript, s.sk, s.k_id), "respond: keys differ from I's")
    _check(acc.peer_iks == ctx.i.iks and acc.init_id == ctx.env.init_id, "respond: peer IKS or init_id")
    content = enc.payload("Content", acc.content)
    _check(content == ctx.content, "respond: content differs from I's")
    body = acc.content["body"]
    return {"transcript": acc.transcript, "sk": acc.sk, "k_id": acc.k_id, "peer_iks": acc.peer_iks,
            "content": content, "profile": enc.payload("Profile", body["profile"]),
            "routes": [enc.payload("RouteDescriptor", r) for r in body["routes"]],
            "state_post_R": state_digest(acc.state), "opks_post": _opks(responder)}


def _respond(ctx, rng):
    responder = ctx.fresh_responder()
    fetched = list(ctx.env.cells)
    acc = hx.respond(responder, fetched, rng)
    ctx.after7, ctx.accepted7 = responder, acc
    _check(_opks(responder) == [], "respond: the OPK was not deleted")
    return {"fetched": fetched}, _accepted_outputs(ctx, responder, acc)


def _respond_garbage(ctx, rng):
    g1, g2 = rng.take(sizes.CELL), rng.take(sizes.CELL)
    k_inv, ld_id = ctx.accepted.k_inv, ctx.record.ld_id
    _check(hx.open_cell(k_inv, ld_id, g1) is None and hx.open_cell(k_inv, ld_id, g2) is None, "garbage opens")
    c0, c1, c2 = ctx.env.cells
    fetched = [g1, c0, g2, c1, c2]
    responder = ctx.fresh_responder()
    acc = hx.respond(responder, fetched, rng)
    return {"fetched": fetched}, _accepted_outputs(ctx, responder, acc)


class Pos(NamedTuple):
    op: str
    party: str
    stream: list
    build: object                                 # (ctx, rng) → (derived inputs, outputs)
    text: str


POSITIVES = [
    Pos("keys-R", "R", KEYS_R_STREAM, _keys_r,
        "R's identity (IK_sig = Ed25519 `ik_ed_seed` ‖ ML-DSA-65 `KeyGen_internal(ik_mldsa_xi)`, IK_dh), SPK_dh, "
        "SPK_kem (ML-KEM-1024), RPK_kem (ML-KEM-768), OPK 42 (X25519, ML-KEM-1024); the bundle signed with `rnd`"),
    Pos("keys-I", "I", IKS_STREAM, _keys_i, "I's identity"),
    Pos("invite", "R", INVITE_STREAM, _invite,
        "InvitationV1 with `inviter_fp` = case 1 `fp`, `onion` = `onion_pubkey` ‖ CHECKSUM ‖ 0x03, `inv_sid` derived (§9.1) from `invq_recv_seed` and `inv_send_seed`; its URI; `invq_recv_pk`, `owner_pk`"),
    Pos("linkdata", "R", N_STREAM, _linkdata,
        "LinkDataV1 {case 1 `iks`, case 1 bundle, Profile_R, `created`} sealed under `K_ld` with `n`"),
    Pos("invitee-accept", "I", [], _invitee_accept,
        "§5.5 steps 1, 3, 4 on case 3's `uri` and case 4's `blob`"),
    Pos("initiate", "I", INITIATE_STREAM, _initiate, "§6.4, §6.5, §7.2 initiator, §7.3 Encrypt of the Handshake Content"),
    Pos("respond", "R", STEP_DRAWS, _respond, "§6.6 steps 1–4 on `fetched` = case 6's cells 0, 1, 2"),
    Pos("respond-garbage", "R", GARBAGE + STEP_DRAWS, _respond_garbage,
        "§6.6 on `fetched` = [`g1`, cell 0, `g2`, cell 1, cell 2]; `g1`, `g2` do not open and are ignored"),
]


# ---------------------------------------------------------------------------------------------
# invitee-reject (V1 … V8): the invitee processes (uri, blob); base = cases 3 and 4.


def _inv_edit(ctx, rng, **edit):
    v = {**ctx.invitation_value, **edit}
    invitation = enc.raw("InvitationV1", v)
    uri = inv.uri_encode(invitation)
    return {"invitation": invitation, "uri": uri}, uri, ctx.blob


def _ld_seal(ctx, rng, ld_value, k_ld=None):
    linkdata = enc.payload("LinkDataV1", ld_value)
    blob = inv.seal_blob(k_ld or ctx.k_ld, rng.take(24), ctx.record.ld_id, linkdata)
    return {"linkdata": linkdata, "blob": blob}, ctx.uri, blob


def _v4(ctx, rng):
    fresh = hx.Identity.from_secrets(rng.take(32), rng.take(32), rng.take(32))
    return _ld_seal(ctx, rng, {**ctx.linkdata_value, "inviter_iks": fresh.iks_value()})


def _sig_flip(k):
    """V5 (k = -1: the ML-DSA half) and V9 (k = 0: the Ed25519 half, its R)."""
    def build(ctx, rng):
        return _ld_seal(ctx, rng, {**ctx.linkdata_value, "bundle": {**ctx.bundle, "sig": flip(ctx.bundle["sig"], k)}})
    return build


def _resigned(ctx, rng, **edit):
    bundle = hx.sign_bundle(ctx.r, {**ctx.bundle, **edit}, rng)
    return _ld_seal(ctx, rng, {**ctx.linkdata_value, "bundle": bundle})


def _v8(ctx, rng):
    wrong = inv.derive_k_ld(ctx.record.ld_id, flip(ctx.record.link_key, 0))
    blob = inv.seal_blob(wrong, rng.take(24), ctx.record.ld_id, ctx.linkdata)
    return {"blob": blob}, ctx.uri, blob


class InviteeNeg(NamedTuple):
    name: str
    manipulation: str
    stream: list
    build: object                                 # (ctx, rng) → (derived inputs, uri, blob)
    rule: str                                     # the check of inv.invitee_accept that fires
    text: str


INVITEE_NEGATIVES = [
    InviteeNeg("V1", "inv-expired", [], lambda c, r: _inv_edit(c, r, expires=NOW - 1), "expired",
               "case 3's invitation with `expires` := `now` − 1; case 4's blob"),
    InviteeNeg("V2", "inv-kind-multi", [], lambda c, r: _inv_edit(c, r, kind=enc.INVITATION_KIND_MULTI),
               "invitation-decode", "case 3's invitation with `kind` := 0x02 (multi-use, reserved); case 4's blob"),
    InviteeNeg("V3", "inv-ver", [], lambda c, r: _inv_edit(c, r, ver=0x02), "invitation-decode",
               "case 3's invitation with `ver` := 0x02; case 4's blob"),
    InviteeNeg("V4", "ld-fp-mismatch", IKS_STREAM + N_STREAM, _v4, "fingerprint",
               "LinkDataV1 with `inviter_iks` := a fresh IKS, bundle unchanged, sealed under `K_ld` with `n`; "
               "step 3 rejects before step 4"),
    InviteeNeg("V5", "ld-bad-sig", N_STREAM, _sig_flip(-1), "bundle-sig",
               "LinkDataV1 with bit 0 of the last byte of `bundle.sig` flipped (the ML-DSA part), sealed with `n`"),
    InviteeNeg("V6", "ld-bundle-expired", [("rnd", 32)] + N_STREAM,
               lambda c, r: _resigned(c, r, spk_expiry=NOW - 1), "bundle-expired",
               "`spk_expiry` := `now` − 1, the bundle re-signed under IK_sig_R with `rnd`, sealed with `n`"),
    InviteeNeg("V7", "ld-opk-absent", [("rnd", 32)] + N_STREAM,
               lambda c, r: _resigned(c, r, opk_present=0), "linkdata-decode",
               "`opk_present` := 0x00 with every other byte unchanged, re-signed with `rnd`, sealed with `n`; "
               "the PrekeyBundle decoder rejects it (§6.3)"),
    InviteeNeg("V8", "ld-wrong-key", N_STREAM, _v8, "blob-open",
               "case 4's LinkDataV1 sealed with `n` under the `K_ld` of `link_key` with bit 0 of byte 0 flipped; "
               "the invitee holds case 3's invitation"),
    InviteeNeg("V9", "ld-bad-sig-ed", N_STREAM, _sig_flip(0), "bundle-sig",
               "as V5, but bit 0 of byte 0 of `bundle.sig` flipped (the Ed25519 half: its R, still a valid point, "
               "so the decoder accepts it), sealed with `n`; HybridVerify fails on the Ed25519 component"),
]


# ---------------------------------------------------------------------------------------------
# respond-reject (R1 … R12): the responder processes `fetched`; base = case 6.


def _reseal_outer(ctx, rng, outer_value):
    outer = enc.payload("Outer", outer_value)
    init_id = rng.take(16)
    cells = hx.seal_cells(ctx.start.k_inv, ctx.record.ld_id, outer, init_id,
                          [rng.take(24) for _ in range(hx.ENVELOPE_CELLS)])
    return outer, list(cells)


def _outer_edit(ctx, rng, **edit):
    outer, cells = _reseal_outer(ctx, rng, {**ctx.env.outer_value, **edit})
    return {"outer": outer}, cells


def _inner_edit(ctx, rng, inner, extra=None):
    inner_ct = hx.seal_inner(ctx.start.k_id, ctx.record.ld_id, inner, rng.take(24))
    outer, cells = _reseal_outer(ctx, rng, {**ctx.env.outer_value, "inner_ct": inner_ct})
    return {**(extra or {}), "inner": inner, "outer": outer}, cells


def _r5(ctx, rng):
    iks = enc.raw("IKSPublic", {**ctx.i.iks_value(), "ik_dh": LOW_ORDER})
    return _inner_edit(ctx, rng, iks + ctx.env.first_msg)


def _r8(ctx, rng):
    return _inner_edit(ctx, rng, ctx.i.iks + flip(ctx.env.first_msg, -1))


def _new_first_msg(ctx, rng, content):
    """`content` encrypted from a fresh copy of I's post-init TR state (hdr_nonce), then inner and outer."""
    state = dataclasses.replace(ctx.post_init, skipped=dict(ctx.post_init.skipped))
    first_msg = tr.encrypt(state, content, rng)
    return _inner_edit(ctx, rng, ctx.i.iks + first_msg, {"content": content})


def _r9(ctx, rng):
    return _new_first_msg(ctx, rng, enc.payload("Content", handshake_content(ctx.avatar, ctx.route, caps=1)))


R13_PAYLOAD = 8


def _r13(ctx, rng):
    """A Batch (type 0x02) as first_msg: ver 1, seq 1, ts, count 1 ‖ AppMessage{msg_id, kind 1,
    expire_after 0, payload_len 8, payload} (Weisung REF-M4-1)."""
    msg = {"msg_id": rng.take(16), "kind": 1, "expire_after": 0, "payload_len": R13_PAYLOAD,
           "payload": rng.take(R13_PAYLOAD)}
    v = {"ver": enc.PROTO_VER, "type": enc.CT_BATCH, "seq": HS_SEQ, "ts": HS_TS, "body_len": 0,
         "body": {"count": 1, "messages": [msg]}}
    enc.refresh("Content", v)
    enc.encode("Content", v)                      # a valid Content: only its type is wrong for a first_msg
    return _new_first_msg(ctx, rng, enc.payload("Content", v))


def _cells(ctx, k=None, cell=None):
    cells = list(ctx.env.cells)
    if k is not None:
        cells[k] = cell
    return cells


def _reseal_chunk(ctx, rng, k, i, total):
    chunk = hx.chunks(ctx.env.outer)[k]
    pt = hx.cell_plaintext(ctx.env.init_id, i, chunk, total)
    return {}, _cells(ctx, k, hx.seal_cell(ctx.start.k_inv, ctx.record.ld_id, pt, rng.take(24)))


class ResponderNeg(NamedTuple):
    name: str
    manipulation: str
    stream: list                                  # construction draws, then R's step draws if it steps
    build: object                                 # (ctx, rng) → (derived inputs, fetched)
    rule: str                                     # the check of hx.respond that fires
    text: str
    after7: bool = False                          # R starts from its state after case 7 (else after cases 1–4)


RESPONDER_NEGATIVES = [
    ResponderNeg("R1", "opk-unknown", OUTER_RESEAL, lambda c, r: _outer_edit(c, r, opk_id=43), "prekey-ids",
                 "`opk_id` := 43 in Outer; outer re-sealed"),
    ResponderNeg("R2", "spk-unknown", OUTER_RESEAL, lambda c, r: _outer_edit(c, r, spk_id=8), "prekey-ids",
                 "`spk_id` := 8 in Outer; outer re-sealed"),
    ResponderNeg("R3", "replay", [], lambda c, r: ({}, _cells(c)), "opk-used",
                 "case 6's three cells again, to R after case 7 (OPK 42 used up); `opks_post` = []", after7=True),
    ResponderNeg("R4", "zero-ek", OUTER_RESEAL, lambda c, r: _outer_edit(c, r, ek_I=bytes(32)), "outer-decode",
                 "`ek_I` := 0x00^32 in Outer (DH2–DH4 would be zero); outer re-sealed; the Outer decoder rejects "
                 "the low-order `ek_I` first (§4.1 decoder obligation (a))"),
    ResponderNeg("R5", "low-order-ik-dh", INNER_RESEAL, _r5, "inner-decode",
                 "`IKSPublic_I.ik_dh` := e0eb…b800 (order 8) in Inner; inner and outer re-sealed"),
    ResponderNeg("R6", "tampered-chunk", [], lambda c, r: ({}, _cells(c, 1, flip(c.env.cells[1], -1))),
                 "no-complete-envelope",
                 "`cell_1` with bit 0 of its last byte flipped; chunks 0 and 2 open, no complete envelope"),
    ResponderNeg("R7", "inner-tag-flip", OUTER_RESEAL,
                 lambda c, r: _outer_edit(c, r, inner_ct=flip(c.env.inner_ct, -1)), "inner-open",
                 "bit 0 of the last byte of `inner_ct` (its tag) flipped in Outer; outer re-sealed"),
    ResponderNeg("R8", "first-msg-flip", INNER_RESEAL + STEP_DRAWS, _r8, "tr-decrypt",
                 "bit 0 of the last byte of `first_msg` (the body tag) flipped in Inner; inner and outer re-sealed. "
                 "R's decrypt takes the DH step on its working copy, then the body MAC fails"),
    ResponderNeg("R9", "caps-nonzero", [("hdr_nonce", 24)] + INNER_RESEAL + STEP_DRAWS, _r9, "content-decode",
                 "case 6's Content with `caps` := 1, encrypted from I's post-init TR state with `hdr_nonce`; inner "
                 "and outer re-sealed. R decrypts it (DH step), the Content decoder rejects `caps`"),
    ResponderNeg("R10", "ct-spk-flip", OUTER_RESEAL,
                 lambda c, r: _outer_edit(c, r, ct_spk=flip(c.env.outer_value["ct_spk"], 0)), "inner-open",
                 "bit 0 of byte 0 of `ct_spk` flipped in Outer; outer re-sealed (implicit rejection: `K_id` differs, "
                 "`inner_ct` does not open)"),
    ResponderNeg("R11", "total-not-3", [("cell_nonce_0", 24)], lambda c, r: _reseal_chunk(c, r, 0, 0, 2),
                 "no-complete-envelope", "`cell_0` re-sealed with `total` := 0x02 and `cell_nonce_0`; it opens "
                 "but does not parse and is ignored"),
    ResponderNeg("R12", "idx-dup", [("cell_nonce_1", 24)], lambda c, r: _reseal_chunk(c, r, 1, 0, 3),
                 "no-complete-envelope", "`cell_1` re-sealed with `i` := 0 and `cell_nonce_1`: two chunk-0s, no "
                 "chunk 1"),
    ResponderNeg("R13", "first-msg-not-handshake", [("msg_id", 16), ("payload", R13_PAYLOAD), ("hdr_nonce", 24)]
                 + INNER_RESEAL + STEP_DRAWS, _r13, "not-handshake",
                 "a Batch Content (type 0x02, `ver` 1, `seq` 1, `ts` 1 700 000 001, `count` 1 ‖ AppMessage{`msg_id`, "
                 "kind 1, `expire_after` 0, `payload_len` 8, `payload`}) encrypted from I's post-init TR state with "
                 "`hdr_nonce`, as in R9; inner and outer re-sealed. R decrypts it (DH step), the Handshake type check "
                 "rejects"),
]

# The negatives in case order. V9 and R13 were appended by Weisung REF-M4-1 after R12, so that no earlier
# case index (and seed) moves.
NEGATIVES = [*INVITEE_NEGATIVES[:8], *RESPONDER_NEGATIVES[:12], INVITEE_NEGATIVES[8], RESPONDER_NEGATIVES[12]]
assert [n.name for n in NEGATIVES] == [f"V{k}" for k in range(1, 9)] + [f"R{k}" for k in range(1, 13)] + ["V9", "R13"]


# ---------------------------------------------------------------------------------------------
# Rev 2.5 cases (Weisung REF-M5-2 §2, M4 review R-66) and RF-1: appended after R13, in the Weisung's order.
# Everything in this section is a proposal. R's step draws of a rejected group are listed like R8's.

STEP_DRAWS_2 = [("dh_sk_2", 32), ("kem_seed_2", 64), ("m_2", 32)]   # the second attempt's DH step (A1)
NEW_SPK_ID = SPK_ID + 1


def _a1(ctx, rng):
    """A complete group (a fresh init_id) whose first_msg body tag is flipped, then the honest group of case 6."""
    derived, rejected = _inner_edit(ctx, rng, ctx.i.iks + flip(ctx.env.first_msg, -1))
    return derived, rejected + list(ctx.env.cells), ctx.fresh_responder()


def _r14(ctx, rng):
    """[chunk 1 of X with differing bytes, the honest chunks 0, 1, 2 of X, then 0, 1, 2 of X again]."""
    chunk = flip(hx.chunks(ctx.env.outer)[1], 0)
    pt = hx.cell_plaintext(ctx.env.init_id, 1, chunk)
    c0, c1, c2 = ctx.env.cells
    differing = hx.seal_cell(ctx.start.k_inv, ctx.record.ld_id, pt, rng.take(24))
    return {}, [differing, c0, c1, c2, c0, c1, c2]


def _advanced_first_msg(ctx, rng, *, discard=0, pn=0):
    """case 6's Content encrypted from a copy of I's post-init TR state: after `discard` earlier messages on the
    chain (their cells discarded, so the header carries n = discard) or with `pn` set; inner and outer re-sealed."""
    state = dataclasses.replace(ctx.post_init, skipped=dict(ctx.post_init.skipped), pn=pn)
    for _ in range(discard):
        tr.encrypt(state, ctx.content, rng)
    first_msg = tr.encrypt(state, ctx.content, rng)
    return _inner_edit(ctx, rng, ctx.i.iks + first_msg, {"content": ctx.content})


def _r17(ctx, rng):
    return _inner_edit(ctx, rng, ctx.r.iks + ctx.env.first_msg)


UNKNOWN_KIND = 0x7F
UNKNOWN_BLOB = 16


def _r18(ctx, rng):
    blob = rng.take(UNKNOWN_BLOB)
    route = {"ver": enc.PROTO_VER, "kind": UNKNOWN_KIND, "len": UNKNOWN_BLOB, "blob": blob}
    return _new_first_msg(ctx, rng, enc.payload("Content", handshake_content(ctx.avatar, route)))


def _a2(ctx, rng):
    """R holds two SPK generations; the invitation references the older, retained one."""
    spk_dh, spk_kem = tr.DhKey.from_secret(rng.take(32)), hx.Kem1024Key.from_seed(rng.take(64))
    rpk_kem = tr.KemKey.from_seed(rng.take(64))
    old = ctx.prekeys
    prekeys = dataclasses.replace(old, spk_id=NEW_SPK_ID, spk_dh=spk_dh, spk_kem=spk_kem, rpk_kem=rpk_kem,
                                  opks=dict(old.opks),
                                  retained={SPK_ID: hx.Spk(SPK_ID, old.spk_dh, old.spk_kem, old.rpk_kem,
                                                           old.spk_expiry)})
    return {}, list(ctx.env.cells), hx.Responder(ctx.r, prekeys, ctx.record)


class ExtraPos(NamedTuple):
    name: str
    op: str
    stream: list
    build: object                                 # (ctx, rng) → (derived inputs, fetched, R's state)
    text: str


EXTRA = [
    ExtraPos("A1", "respond-later-group", INNER_RESEAL + STEP_DRAWS + STEP_DRAWS_2, _a1,
             "R, from its state after cases 1–4, on `fetched` = [the three cells of a complete group with a fresh "
             "`init_id` whose `first_msg` has bit 0 of its last byte flipped (as R8), then case 6's three cells]. "
             "The first group completes, is rejected on its working copy (its DH-step draws are the first "
             "`dh_sk`, `kem_seed`, `m`) and discarded, the OPK is kept; the second group, another `init_id`, is "
             "accepted (second step draws): outputs as `respond` (§6.5 rev 2.5)"),
    ResponderNeg("R14", "no-reform", [("cell_nonce_1", 24)], _r14, "inner-open",
                 "`fetched` = [a cell with `init_id` of case 6, `i` = 1, and chunk 1 with bit 0 of byte 0 flipped "
                 "(sealed with `cell_nonce_1`), case 6's cells 0, 1, 2, then cells 0, 1, 2 again]. The first-seen "
                 "chunk 1 wins, so the group completes with the differing chunk and is rejected (its `inner_ct` "
                 "does not open); the rejected `init_id` is discarded and the honest cells after it do not form it "
                 "again (§6.5 rev 2.5)"),
    ResponderNeg("R15", "first-msg-n", [("hdr_nonce_0", 24), ("hdr_nonce", 24)] + INNER_RESEAL + STEP_DRAWS,
                 lambda c, r: _advanced_first_msg(c, r, discard=1), "first-msg-header",
                 "case 6's Content encrypted from I's post-init TR state as its second message (one message "
                 "encrypted first with `hdr_nonce_0` and discarded), so the header carries `n` = 1, with "
                 "`hdr_nonce`; inner and outer re-sealed. R decrypts it (skipping one key, DH step), then rejects "
                 "the header (§6.5 rev 2.5)"),
    ResponderNeg("R16", "first-msg-pn", [("hdr_nonce", 24)] + INNER_RESEAL + STEP_DRAWS,
                 lambda c, r: _advanced_first_msg(c, r, pn=1), "first-msg-header",
                 "case 6's Content encrypted from I's post-init TR state with `pn` := 1 (header `n` = 0, `pn` = 1) "
                 "and `hdr_nonce`; inner and outer re-sealed. R decrypts it, then rejects the header"),
    ResponderNeg("R17", "reflection", INNER_RESEAL, _r17, "reflection",
                 "`IKSPublic_I` := `IKSPublic_R` (case 1's `iks`) in Inner, with case 6's `first_msg`; inner and "
                 "outer re-sealed. Rejected at §6.6 step 2 (rev 2.5), before any TR step"),
    ResponderNeg("R18", "no-known-route", [("route_blob", UNKNOWN_BLOB), ("hdr_nonce", 24)] + INNER_RESEAL
                 + STEP_DRAWS, _r18, "no-known-route",
                 "case 6's Handshake Content with its one route replaced by a RouteDescriptor of kind 0x7F (`ver` 1, "
                 "`len` 16, `blob` = `route_blob`), encrypted from I's post-init TR state with `hdr_nonce`; inner "
                 "and outer re-sealed. R decrypts and decodes it (an unknown kind is kept, §9.8), then rejects: no "
                 "route of a known kind (§6.5 rev 2.5; SQ-29)"),
    ExtraPos("A2", "respond-retained-spk", [("spk_dh_sk", 32), ("spk_kem_seed", 64), ("rpk_kem_seed", 64)]
             + STEP_DRAWS, _a2,
             "**RF-1.** R holds two SPK generations: a new current one, `spk_id` 8 (`spk_dh_sk`, `spk_kem_seed`, "
             "`rpk_kem_seed`), and SPK 7 of cases 1–4, retained because the invitation of case 3 references it "
             "(§6.1 rev 2.5). `fetched` = case 6's cells. R finds SPK 7 by `spk_id` and accepts: outputs as `respond`, "
             "`transcript`, `sk`, `k_id` equal case 7's"),
]
assert [e.name for e in EXTRA] == ["A1", "R14", "R15", "R16", "R17", "R18", "A2"]


# ---------------------------------------------------------------------------------------------
# The run


class Run(NamedTuple):
    cases: list
    rows: list                                    # per case: the facts the SCHEMA table shows
    ctx: Ctx


@functools.lru_cache(maxsize=1)
def run() -> Run:
    ctx, cases, rows = Ctx(), [], []
    i = 0
    for p in POSITIVES:
        i += 1
        rng = _Named(CaseStream(SUITE, i), p.stream)
        derived, outputs = p.build(ctx, rng)
        inputs = {**rng.done(), **derived}
        cases.append(Case(i, p.op, inputs, outputs, {"party": p.party}))
        rows.append({"i": i, "id": case_id(SUITE, i), "op": p.op, "party": p.party, "stream": p.stream,
                     "derived": list(derived), "outputs": list(outputs), "text": p.text})

    for neg in NEGATIVES:
        i += 1
        rng = _Named(CaseStream(SUITE, i), neg.stream)
        if isinstance(neg, InviteeNeg):
            _invitee_reject(ctx, cases, rows, i, rng, neg)
        else:
            _respond_reject(ctx, cases, rows, i, rng, neg)

    for ex in EXTRA:
        i += 1
        rng = _Named(CaseStream(SUITE, i), ex.stream)
        if isinstance(ex, ResponderNeg):
            _respond_reject(ctx, cases, rows, i, rng, ex)
        else:
            _respond_extra(ctx, cases, rows, i, rng, ex)
    return Run(cases, rows, ctx)


def _respond_extra(ctx, cases, rows, i, rng, ex):
    derived, fetched, responder = ex.build(ctx, rng)
    acc = hx.respond(responder, fetched, rng)
    _check(_opks(responder) == [], f"{ex.name}: the OPK was not deleted")
    outputs = _accepted_outputs(ctx, responder, acc)
    if ex.name == "A2":
        _check((outputs["transcript"], outputs["sk"], outputs["k_id"]) == (ctx.accepted7.transcript, ctx.accepted7.sk,
                                                                       ctx.accepted7.k_id), "A2: keys differ from case 7")
    cases.append(Case(i, ex.op, {**rng.done(), **derived, "fetched": fetched}, outputs, {"party": "R"}))
    rows.append({"i": i, "id": case_id(SUITE, i), "op": ex.op, "party": "R", "name": ex.name, "stream": ex.stream,
                 "derived": [*derived, "fetched"], "outputs": list(outputs), "text": ex.text})


def _invitee_reject(ctx, cases, rows, i, rng, neg):
    derived, uri, blob = neg.build(ctx, rng)
    try:
        inv.invitee_accept(uri, blob, NOW)
    except Reject:
        pass
    else:
        raise TableMismatch(f"{neg.name}: accepted")
    _check(inv.last_rule == neg.rule, f"{neg.name}: rejected at {inv.last_rule}, table says {neg.rule}")
    inputs = {**rng.done(), **derived}
    cases.append(Case(i, "invitee-reject", inputs, None, {"party": "I", "manipulation": neg.manipulation}))
    rows.append({"i": i, "id": case_id(SUITE, i), "op": "invitee-reject", "party": "I", "name": neg.name,
                 "manipulation": neg.manipulation, "stream": neg.stream, "derived": list(derived),
                 "rule": neg.rule, "text": neg.text})


def _respond_reject(ctx, cases, rows, i, rng, neg):
    responder = ctx.after7 if neg.after7 else ctx.fresh_responder()
    before = (_opks(responder), responder.prekeys.spk_id, responder.prekeys.spk_dh, responder.invitation)
    derived, fetched = neg.build(ctx, rng)
    try:
        hx.respond(responder, fetched, rng)
    except Reject:
        pass
    else:
        raise TableMismatch(f"{neg.name}: accepted")
    _check(hx.last_rule == neg.rule, f"{neg.name}: rejected at {hx.last_rule}, table says {neg.rule}")
    after = (_opks(responder), responder.prekeys.spk_id, responder.prekeys.spk_dh, responder.invitation)
    _check(after == before, f"{neg.name}: the rejection changed R's state")
    _check(after[0] == ([] if neg.after7 else [OPK_ID]), f"{neg.name}: opks_post {after[0]}")
    inputs = {**rng.done(), **derived, "fetched": fetched}
    cases.append(Case(i, "respond-reject", inputs, {"opks_post": after[0]},
                      {"party": "R", "manipulation": neg.manipulation, "expect": "reject"}))
    rows.append({"i": i, "id": case_id(SUITE, i), "op": "respond-reject", "party": "R", "name": neg.name,
                 "manipulation": neg.manipulation, "stream": neg.stream, "derived": [*derived, "fetched"],
                 "rule": neg.rule, "text": neg.text, "opks_post": after[0], "after7": neg.after7,
                 "steps": neg.stream[-len(STEP_DRAWS):] == STEP_DRAWS})


def hx_cases() -> list[Case]:
    return run().cases
