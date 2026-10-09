# SPDX-License-Identifier: AGPL-3.0-or-later
"""The `link` case table (SCHEMA §4.11 = SCHEMA-4.11-link.md; brief REF-M5): one client C, one relay R,
one handshake, then one link ("link A") on which every command runs in event order.

The order is the reviewer's: the positives and the command-error cases interleaved in event order
(`link-0001` … `link-0050`), X1, the RelayInfo cases, then `hs1-reject`, `hs2-reject` and
`frame-reject`. Every case draws from its own stream (SCHEMA §2, suite name "link", the case index);
every stream-derived value is listed in `inputs` in stream order (C's draws, then R's in response-frame
order), then the *derived* values.

The run checks itself while it generates (a disagreement raises TableMismatch instead of writing a file):
both sides derive the same handshake secrets and keys; every frame is 4352 B and every plaintext 4336 B
ISO-padded; every request gets exactly its D.2 number of response frames, right after its last request
frame, echoing its `cmd_seq`; both sides' counters agree after every case; `rid`/`sid` re-derive from
the keys; each row's counters, answer and reference check are the reviewer's; a repeated FETCH returns
the same cells; a command error leaves the store as it was; a rejection leaves the receiver's state as it
was and draws exactly what the row lists.
"""

import copy
import dataclasses
import functools
import hashlib
from typing import NamedTuple

from . import encodings as enc
from . import link, primitives, relay, sizes
from .cases import TableMismatch
from .errors import Reject
from .hx_cases import _Named
from .vectorfile import Case, CaseStream, append_zero, case_id, flip, prefix

SUITE = "link"

# ---------------------------------------------------------------------------------------------
# Suite constants (brief REF-M5)

NOW = 1_700_000_100
NOW_BUCKET = NOW // 3600
assert NOW_BUCKET == 472_222                      # hour buckets since epoch (§9.1)
KID = 1
VALID_UNTIL = 1_702_592_000
assert VALID_UNTIL - NOW == 2_591_900 < 30 * 86_400
DAY = 86_400
ONE_TIME = 1
EXPIRES_BUCKET = NOW_BUCKET + 7 * 24
assert EXPIRES_BUCKET == 472_390
BUDGET_QUEUES = 2                                 # reading OPEN-12
FILL_COUNT = 127
assert (relay.F, relay.F_M, relay.QUEUE_CAPACITY) == (4, 8, 128)
LOW_ORDER = enc.X25519_ORDER8[0]                  # as SCHEMA §4.4 row 16 and §4.10 R5
assert LOW_ORDER.hex() == "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"
BAD_EK = b"\xff\xff\xff"                          # as SCHEMA §4.4 row 17
FRAME_LEN = sizes.FRAME

# ---------------------------------------------------------------------------------------------
# Stream layouts (name, bytes), in stream order

RELAY_KEYS_STREAM = [("relay_sig_seed", 32), ("relay_dh_sk", 32), ("relay_kem_seed", 64), ("relay_access_key", 32)]
HS1_STREAM = [("e_c_sk", 32), ("ek_c_seed", 64), ("sk_e1", 32), ("m1", 32)]       # reading OPEN-1
HS2_STREAM = [("sk_er", 32), ("m2", 32)]                                          # reading OPEN-1
QUEUE_STREAM = [("recv_seed", 32), ("send_seed", 32)]
CELL_STREAM = [("cell", sizes.CELL)]
CELL_R = [("cell_r", sizes.CELL)]
LD_STREAM = [("ld_id", 16), ("owner_seed", 32)]
BLOB = [("blob", sizes.LINK_BLOB)]
DUMMY_BLOB = [("dummy_blob", sizes.LINK_BLOB)]


def dummies(n):
    return [(f"dummy_{k}", sizes.CELL) for k in range(n)]


# ---------------------------------------------------------------------------------------------
# Values


class QKeys(NamedTuple):
    """A queue's recipient and sender keys (Ed25519 seeds) and its derived identifiers (§9.1)."""
    recv_seed: bytes
    send_seed: bytes
    recv_pk: bytes
    send_pk: bytes
    rid: bytes
    sid: bytes

    @classmethod
    def from_seeds(cls, recv_seed: bytes, send_seed: bytes) -> "QKeys":
        recv_pk, send_pk = primitives.ed25519_public(recv_seed), primitives.ed25519_public(send_seed)
        return cls(recv_seed, send_seed, recv_pk, send_pk, relay.rid_of(recv_pk), relay.sid_of(recv_pk, send_pk))


class LD(NamedTuple):
    """A link-data entry as the client puts it (§9.4)."""
    ld_id: bytes
    owner_seed: bytes
    owner_pk: bytes
    blob: bytes


@dataclasses.dataclass
class Ctx:
    """What the cases hand on to later cases."""
    keys: link.RelayKeys = None
    info: dict = None                             # the honest RelayInfoV1 value
    rec_relayinfo: bytes = None
    rec_hello: bytes = None
    chs: link.ClientHs = None                     # C after link-0003
    hs2: link.Hs2 = None
    r: relay.Relay = None                         # R on link A
    c: link.Link = None                           # C on link A
    next_seq: int = 1
    queues: dict = dataclasses.field(default_factory=dict)        # "A", "B" → QKeys
    names: dict = dataclasses.field(default_factory=dict)         # rid/sid → "A"/"B" (for the answers)
    ld: LD = None                                 # L
    p6_token: bytes = None
    p6_frame: bytes = None
    p12_pairs: list = None
    fill_cell: bytes = None                       # link-0020's cell
    after8: tuple = None                         # deep copies of (R, C) after link-0008
    frame8: bytes = None                          # link-0008's request frame
    case9: dict = None                            # link-0009's payloads and frames
    round: dict = None                            # the last round trip's cmd_seqs and counters
    resp_counts: dict = dataclasses.field(default_factory=dict)   # case id → response frames

    def seq(self, skip: int = 0) -> int:
        """cmd_seq: 1 for the first command, then +1 per command (+1 + skip after a gap)."""
        self.next_seq += skip
        s, self.next_seq = self.next_seq, self.next_seq + 1
        return s

    @property
    def sess_id(self) -> bytes:
        return self.c.sess_id

    def token(self, cmd_seq: int, sess_id: bytes | None = None) -> bytes:
        return relay.token(self.keys.access_key, sess_id or self.sess_id, cmd_seq)

    def name(self, ident: bytes) -> str:
        return "0" if ident == relay.ZERO_RID else self.names.get(ident, ident.hex()[:8] + "…")


def _check(cond, what):
    if not cond:
        raise TableMismatch(what)


def link_post_r(r: relay.Relay) -> dict:
    """{c2r, r2c, cmd_seq}: the next frame counter in each direction and R's last recorded cmd_seq."""
    return {"c2r": r.link.recv_ctr, "r2c": r.link.send_ctr, "cmd_seq": r.last}


def store_post(r: relay.Relay) -> dict:
    queues = [{"rid": rid, "sid": q.sid, "cell_ids": [c.cell_id for c in q.cells], "next_cell_id": q.next_cell_id}
              for rid, q in sorted(r.queues.queues.items())]
    linkdata = [{"ld_id": ld_id, "one_time": e.one_time, "expires_bucket": e.expires_bucket,
                 "present": int(not e.consumed), "consumed": int(e.consumed)}
                for ld_id, e in sorted(r.linkdata.entries.items())]
    return {"queues": queues, "linkdata": linkdata}


# ---------------------------------------------------------------------------------------------
# Answers: a decoded response as the table writes it


def _cellr_tuple(ctx, v):
    return f"{{{v['present']}, {ctx.name(v['rid'])}, {v['cell_id']}}}"


def answer(ctx, values: list[dict]) -> str:
    """OK, ERR n, OK_QUEUE_NEW {rid, sid}, OK_SEND {cell_id, evicted_present, evicted_id},
    CELLR {present, rid, cell_id} …, LINKR {present, consumed}, CONT idx."""
    parts, k = [], 0
    while k < len(values):
        v = values[k]
        op = v["op"]
        if op == "CELLR":
            run = [v]
            while k + len(run) < len(values) and values[k + len(run)]["op"] == "CELLR":
                run.append(values[k + len(run)])
            k += len(run)
            items, j = [], 0
            while j < len(run):                   # a run of identical dummies is written n × {0, 0, 0}
                t = _cellr_tuple(ctx, run[j])
                n = 1
                while j + n < len(run) and run[j + n]["present"] == 0 and _cellr_tuple(ctx, run[j + n]) == t:
                    n += 1
                items.append(t if n == 1 else f"{n} × {t}")
                j += n
            parts.append("CELLR " + ", ".join(items))
            continue
        k += 1
        if op == "OK":
            parts.append("OK")
        elif op == "ERR":
            parts.append(f"ERR {v['code']}")
        elif op == "OK_QUEUE_NEW":
            parts.append(f"OK_QUEUE_NEW {{rid {ctx.name(v['rid'])}, sid {ctx.name(v['sid'])}}}")
        elif op == "OK_SEND":
            parts.append(f"OK_SEND {{{v['cell_id']}, {v['evicted_present']}, {v['evicted_id']}}}")
        elif op == "LINKR":
            parts.append(f"LINKR {{{v['present']}, {v['consumed']}}}")
        elif op == "CONT":
            parts.append(f"CONT {v['idx']}")
        else:
            raise TableMismatch(f"unexpected response {op}")
    return ", ".join(parts)


# ---------------------------------------------------------------------------------------------
# One round trip on link A


def _open_plaintext(key, counter, sess_id, frame):
    return primitives.xchacha20poly1305_open(key, link.frame_nonce(counter), link.frame_ad(sess_id), frame)


def _expected_trace(requests: list[bytes]) -> list[int]:
    """Per request frame, the D.2 number of response frames it triggers: LINK_PUT answers after its third
    frame (CONT idx 2), every other command after its only frame."""
    out = []
    for p in requests:
        if p[0] == enc.REQUEST_OPS["LINK_PUT"]:
            out.append(0)
        elif p[0] == enc.REQUEST_OPS["CONT"]:
            out.append(1 if p[5] == 2 else 0)
        elif p[0] == enc.OP_SKEY:
            out.append(relay.RESPONSE_FRAMES["SKEY"])
        else:
            out.append(relay.RESPONSE_FRAMES[relay.decode_request(p)["op"]])
    return out


def _cr(ctx, rng, requests: list[bytes], context: str, seqs: list[int]):
    """C seals `requests`, R executes them, C opens and decodes the responses. → (outputs, values)."""
    c, r = ctx.c, ctx.r
    c2r0, r2c0 = c.send_ctr, c.recv_ctr
    req_frames = [c.seal(p) for p in requests]
    trace = r.execute_trace(req_frames, rng)
    resp_frames = [f for per in trace for f in per]
    resp, values = relay.receive(c, resp_frames, context)

    # Items 2–4 of X1 and the counters, for every case.
    _check([len(t) for t in trace] == _expected_trace(requests), f"response positions {[len(t) for t in trace]}")
    _check(all(len(f) == FRAME_LEN for f in req_frames + resp_frames), "a frame is not 4352 B")
    for k, (p, f) in enumerate(zip(requests, req_frames)):
        pt = _open_plaintext(r.link.k_recv, c2r0 + k, r.link.sess_id, f)
        _check(pt == enc.iso_pad(p, sizes.FRAME_PLAINTEXT), "request plaintext")
    for k, (p, f) in enumerate(zip(resp, resp_frames)):
        pt = _open_plaintext(c.k_recv, r2c0 + k, c.sess_id, f)
        _check(pt == enc.iso_pad(p, sizes.FRAME_PLAINTEXT), "response plaintext")
    k = 0
    for p, per in zip(requests, trace):
        for _ in per:
            _check(values[k]["cmd_seq"] == int.from_bytes(p[1:5], "big"), "cmd_seq not echoed")
            k += 1
    _check((c.send_ctr, c.recv_ctr) == (r.link.recv_ctr, r.link.send_ctr), "the two sides' counters differ")
    _check(c.send_ctr == c2r0 + len(requests) and c.recv_ctr == r2c0 + len(resp_frames), "counters")

    ctx.round = {"seqs": seqs, "c2r": (c2r0, c.send_ctr - 1), "r2c": (r2c0, c.recv_ctr - 1)}
    out = {"req": requests, "req_frames": req_frames, "resp": resp, "resp_frames": resp_frames,
           "link_post": link_post_r(r), "store_post": store_post(r)}
    return out, values


def _payload(value: dict) -> bytes:
    """A request payload; honest values must decode (the M2 decoder agrees)."""
    p = enc.payload(f"Request/{value['op']}", value)
    relay.decode_request(p)
    return p


# Request values (D.2) with their D.6 signatures; the keyword arguments are the manipulations.


def _v_queue_new(ctx, s, k: QKeys, tok=None, signer=None):
    v = {"op": "QUEUE_NEW", "cmd_seq": s, "recv_pk": k.recv_pk, "send_pk": k.send_pk,
         "token": ctx.token(s) if tok is None else tok}
    v["sig"] = relay.sign(signer or k.recv_seed, "QUEUE_NEW", ctx.sess_id, v)
    return v


def _v_send(ctx, s, sid, cell, signer, sess=None):
    v = {"op": "SEND", "cmd_seq": s, "sid": sid, "cell": cell}
    v["sig"] = relay.sign(signer, "SEND", sess or ctx.sess_id, v)
    return v


def _v_fetch(ctx, s, rid, ack, signer, sess=None):
    v = {"op": "FETCH", "cmd_seq": s, "rid": rid, "ack": ack}
    v["sig"] = relay.sign(signer, "FETCH", sess or ctx.sess_id, v)
    return v


def _v_fetch_multi(ctx, s, entries):
    es = [{"rid": rid, "ack": ack, "sig": relay.sign(seed, "FETCH_MULTI", ctx.sess_id, {"rid": rid, "ack": ack,
                                                                                        "cmd_seq": s})}
          for rid, ack, seed in entries]
    return {"op": "FETCH_MULTI", "cmd_seq": s, "count": len(es), "entries": es}


def _v_queue_del(ctx, s, rid, signer):
    v = {"op": "QUEUE_DEL", "cmd_seq": s, "rid": rid}
    v["sig"] = relay.sign(signer, "QUEUE_DEL", ctx.sess_id, v)
    return v


def _link_put(ctx, s, ld: LD, tok=None, signer=None) -> tuple[dict, list[bytes]]:
    """LINK_PUT frame 1 with blob[0..4160], then CONT idx 1 and 2 with 4100 B each (D.2)."""
    v = {"op": "LINK_PUT", "cmd_seq": s, "ld_id": ld.ld_id, "one_time": ONE_TIME, "expires_bucket": EXPIRES_BUCKET,
         "owner_pk": ld.owner_pk, "token": ctx.token(s) if tok is None else tok}
    v["sig"] = relay.sign(signer or ld.owner_seed, "LINK_PUT", ctx.sess_id, {**v, "blob": ld.blob})
    first, *rest = relay.blob_parts(ld.blob)
    v["blob_part"] = first
    conts = [{"op": "CONT", "cmd_seq": s, "idx": i, "data": part} for i, part in enumerate(rest, start=1)]
    return v, [_payload(v), *map(_payload, conts)]


def _v_link_get(ctx, s, ld_id, mode, signer=None):
    v = {"op": "LINK_GET", "cmd_seq": s, "ld_id": ld_id, "mode": mode}
    v["sig"] = relay.sign(signer, "LINK_GET", ctx.sess_id, v) if mode == "owner-status" else bytes(64)
    return v


def _ping(s):
    return _payload({"op": "PING", "cmd_seq": s})


# ---------------------------------------------------------------------------------------------
# The handshake (P1 … P5)


def _relay_keys(ctx, rng):
    ctx.keys = keys = link.RelayKeys.from_secrets(rng.take(32), rng.take(32), rng.take(64), rng.take(32), KID)
    ctx.info = link.relayinfo(keys, VALID_UNTIL)
    ctx.rec_relayinfo = link.relayinfo_record(ctx.info)
    enc.decode("Record/RELAYINFO", ctx.rec_relayinfo)                 # honest: the decoder accepts it
    _check(keys.fp == primitives.sha256(b"SecMP-LINK/1 relay-fp" + keys.sig_pk), "relay_fp")
    return {}, {"relay_sig_pk": keys.sig_pk, "relay_fp": keys.fp, "relay_dh_pk": keys.dh_pk,
                "relay_kem_ek": keys.kem_ek, "akc": keys.akc, "relayinfo": enc.encode("RelayInfoV1", ctx.info),
                "rec_relayinfo": ctx.rec_relayinfo}


def _relayinfo_accept(ctx, rng):
    ctx.rec_hello = link.hello()
    link.hello_accept(ctx.rec_hello)              # R answers every HELLO with its RELAYINFO (§8.2)
    info = link.relayinfo_accept(ctx.rec_relayinfo, ctx.keys.fp, ctx.keys.access_key, NOW)
    _check(info == ctx.info, "relayinfo-accept: decoded value")
    return {}, {"rec_hello": ctx.rec_hello, "accept": True}


def _hs1(ctx, rng):
    ctx.chs = s = link.hs1(ctx.info, rng)
    _check(len(s.hs1) == sizes.HS1 and len(s.record) == sizes.HS1 + 3, "hs1 sizes")
    return {}, {"e_c": s.e_c, "ek_c": s.ek_c, "pk_e1": s.pk_e1, "ct_kem": s.ct_kem, "ss1": s.ss1, "h0": s.h0,
                "ck1": s.ck1, "mac1": s.mac1, "hs1": s.hs1, "rec_hs1": s.record}


def _hs2(ctx, rng):
    h, rlink = link.hs1_accept(ctx.keys, ctx.chs.record, rng)
    _check((h.ss1, h.h0, h.ck1) == (ctx.chs.ss1, ctx.chs.h0, ctx.chs.ck1), "hs2: ss1, h0, ck1 differ from C's")
    _check(len(h.hs2) == sizes.HS2 and len(h.record) == sizes.HS2 + 3, "hs2 sizes")
    ctx.hs2 = h
    ctx.r = relay.Relay(ctx.keys, rlink, NOW_BUCKET, BUDGET_QUEUES)
    return {}, {"ss1": h.ss1, "h0": h.h0, "ck1": h.ck1, "e_r": h.e_r, "ct_c": h.ct_c, "ss2": h.ss2, "h1": h.h1,
                "ck2": h.ck2, "mac2": h.mac2, "hs2": h.hs2, "rec_hs2": h.record, "k_c2r": h.k_c2r,
                "k_r2c": h.k_r2c, "sess_id": h.sess_id, "link_post": link_post_r(ctx.r)}


def _hs2_accept(ctx, rng):
    k, ctx.c = link.hs2_accept(ctx.chs, ctx.hs2.record)
    h = ctx.hs2
    _check((k.ss2, k.h1, k.ck2, k.k_c2r, k.k_r2c, k.sess_id) == (h.ss2, h.h1, h.ck2, h.k_c2r, h.k_r2c, h.sess_id),
           "hs2-accept: the client's keys differ from the relay's")
    _check((ctx.c.k_send, ctx.c.k_recv) == (ctx.r.link.k_recv, ctx.r.link.k_send), "direction keys")
    return {}, {"ss2": k.ss2, "h1": k.h1, "ck2": k.ck2, "k_c2r": k.k_c2r, "k_r2c": k.k_r2c, "sess_id": k.sess_id,
                "link_post": {"c2r": ctx.c.send_ctr, "r2c": ctx.c.recv_ctr, "cmd_seq": ctx.r.last}}


# ---------------------------------------------------------------------------------------------
# Positive cases on link A (P6 … P27)


def _queue_new(qname, fresh, ids):
    def build(ctx, rng):
        if fresh:
            ctx.queues[qname] = QKeys.from_seeds(rng.take(32), rng.take(32))
            k = ctx.queues[qname]
            ctx.names.update({k.rid: qname, k.sid: qname})
        k = ctx.queues[qname]
        _check(k.rid == relay.rid_of(k.recv_pk) and k.sid == relay.sid_of(k.recv_pk, k.send_pk), "rid/sid")
        s = ctx.seq()
        v = _v_queue_new(ctx, s, k)
        out, values = _cr(ctx, rng, [_payload(v)], "QUEUE_NEW", [s])
        _check((values[0]["rid"], values[0]["sid"]) == (k.rid, k.sid), "OK_QUEUE_NEW rid/sid re-derive")
        if qname == "A" and fresh:
            ctx.p6_token, ctx.p6_frame = v["token"], out["req_frames"][0]
        head = {"rid": k.rid, "sid": k.sid} if ids else {}
        return {"recv_pk": k.recv_pk, "send_pk": k.send_pk}, {**head, "token": v["token"], "sig": v["sig"], **out}, values
    return build


def _send(qname):
    def build(ctx, rng):
        k, cell, s = ctx.queues[qname], rng.take(sizes.CELL), ctx.seq()
        v = _v_send(ctx, s, k.sid, cell, k.send_seed)
        out, values = _cr(ctx, rng, [_payload(v)], "SEND", [s])
        return {}, {"sig": v["sig"], **out}, values
    return build


def _ping_row(skip=0):
    def build(ctx, rng):
        s = ctx.seq(skip)
        out, values = _cr(ctx, rng, [_ping(s)], "PING", [s])
        if s == 3:                                 # link-0008: the base of frame-reject
            ctx.after8 = (copy.deepcopy(ctx.r), copy.deepcopy(ctx.c))
            ctx.frame8 = out["req_frames"][0]
        return {}, out, values
    return build


def _fetch(qname, ack, check=None):
    def build(ctx, rng):
        k, s = ctx.queues[qname], ctx.seq()
        v = _v_fetch(ctx, s, k.rid, ack, k.recv_seed)
        out, values = _cr(ctx, rng, [_payload(v)], "FETCH", [s])
        if check:
            check(ctx, rng, values)
        return {}, {"sig": v["sig"], **out}, values
    return build


def _pairs(values):
    return [(v["cell_id"], v["cell"]) for v in values if v["present"] == 1]


def _check_p12(ctx, rng, values):
    ctx.p12_pairs = _pairs(values)
    _check(values[3]["cell"] == rng.values["dummy_0"], "P12: the dummy is dummy_0")


def _check_p13(ctx, rng, values):
    _check(_pairs(values) == ctx.p12_pairs, "P13: FETCH with the same ack returned other cells")


def _check_p21(ctx, rng, values):
    _check(all(v["cell"] == ctx.fill_cell for v in values), "P21: the cells are fill_cell")


def _fetch_multi_row(ctx, rng):
    a, b, s = ctx.queues["A"], ctx.queues["B"], ctx.seq()
    v = _v_fetch_multi(ctx, s, [(b.rid, 0, b.recv_seed), (a.rid, 2, a.recv_seed)])
    out, values = _cr(ctx, rng, [_payload(v)], "FETCH_MULTI", [s])
    sigs = {f"sig_{k}": e["sig"] for k, e in enumerate(v["entries"])}
    return {}, {**sigs, **out}, values


def _send_fill(ctx, rng):
    """`count` honest SENDs of `fill_cell` to B; frames_sha256 over req₁ ‖ resp₁ ‖ … (event order)."""
    b, cell = ctx.queues["B"], rng.take(sizes.CELL)
    ctx.fill_cell = cell
    h, first = hashlib.sha256(), None
    seqs = []
    for _ in range(FILL_COUNT):
        s = ctx.seq()
        seqs.append(s)
        out, values = _cr(ctx, rng, [_payload(_v_send(ctx, s, b.sid, cell, b.send_seed))], "SEND", [s])
        first = first or ctx.round
        h.update(out["req_frames"][0] + out["resp_frames"][0])
        _check(values[0]["evicted_present"] == 0, "send-fill: no eviction")
    ctx.round = {"seqs": seqs, "c2r": (first["c2r"][0], ctx.round["c2r"][1]), "r2c": (first["r2c"][0], ctx.round["r2c"][1])}
    return {}, {"frames_sha256": h.digest(), "resp_last": out["resp"][0], "link_post": out["link_post"],
                "store_post": out["store_post"]}, values


def _queue_del(ctx, rng):
    a, s = ctx.queues["A"], ctx.seq()
    v = _v_queue_del(ctx, s, a.rid, a.recv_seed)
    out, values = _cr(ctx, rng, [_payload(v)], "QUEUE_DEL", [s])
    return {}, {"sig": v["sig"], **out}, values


def _link_put_row(ctx, rng):
    ld_id, owner_seed = rng.take(16), rng.take(32)
    ctx.ld = ld = LD(ld_id, owner_seed, primitives.ed25519_public(owner_seed), rng.take(sizes.LINK_BLOB))
    s = ctx.seq()
    v, payloads = _link_put(ctx, s, ld)
    out, values = _cr(ctx, rng, payloads, "LINK_PUT", [s])
    return {"owner_pk": ld.owner_pk}, {"token": v["token"], "sig": v["sig"], **out}, values


def _link_get(mode, check):
    def build(ctx, rng):
        s = ctx.seq()
        v = _v_link_get(ctx, s, ctx.ld.ld_id, mode, ctx.ld.owner_seed)
        out, values = _cr(ctx, rng, [_payload(v)], "LINK_GET", [s])
        check(ctx, rng, values)
        head = {"sig": v["sig"]} if mode == "owner-status" else {}
        return {}, {**head, **out}, values
    return build


def _blob_of(values):
    return values[0]["blob_part"] + values[1]["data"] + values[2]["data"]


def _dummy_blob_check(ctx, rng, values):
    _check(_blob_of(values) == rng.values["dummy_blob"], "the LINKR blob is dummy_blob")


def _real_blob_check(ctx, rng, values):
    _check(_blob_of(values) == ctx.ld.blob, "the LINKR blob is P24's blob")


# ---------------------------------------------------------------------------------------------
# Command-error cases (E1 … E23)


def _err_queue_new(kind):
    def build(ctx, rng):
        derived = {}
        if kind == "send-pk-differs":
            b = ctx.queues["B"]
            k = QKeys.from_seeds(b.recv_seed, rng.take(32))
            derived = {"recv_pk": k.recv_pk}
        else:
            k = QKeys.from_seeds(rng.take(32), rng.take(32))
        s = ctx.seq()
        if kind == "token-flip":
            v = _v_queue_new(ctx, s, k, tok=flip(ctx.token(s), 0))
        elif kind == "token-replayed":
            v = _v_queue_new(ctx, s, k, tok=ctx.p6_token)
        elif kind == "token-other-link":
            v = _v_queue_new(ctx, s, k, tok=ctx.token(s, flip(ctx.sess_id, 0)))
        elif kind == "wrong-signer":
            v = _v_queue_new(ctx, s, k, signer=k.send_seed)
        else:                                      # queue-new-full, send-pk-differs: an honest request
            v = _v_queue_new(ctx, s, k)
        out, values = _cr(ctx, rng, [_payload(v)], "QUEUE_NEW", [s])
        return derived, out, values
    return build


def _err_send(kind):
    def build(ctx, rng):
        a, b, cell, s = ctx.queues["A"], ctx.queues["B"], rng.take(sizes.CELL), ctx.seq()
        if kind == "wrong-signer":
            v = _v_send(ctx, s, b.sid, cell, b.recv_seed)
        elif kind == "sess-id-other-link":
            v = _v_send(ctx, s, b.sid, cell, b.send_seed, sess=flip(ctx.sess_id, 0))
        else:                                      # unknown-sid: A, deleted in P23
            v = _v_send(ctx, s, a.sid, cell, a.send_seed)
        out, values = _cr(ctx, rng, [_payload(v)], "SEND", [s])
        return {}, out, values
    return build


def _err_fetch(kind):
    def build(ctx, rng):
        a, b, s = ctx.queues["A"], ctx.queues["B"], ctx.seq()
        if kind == "unknown-rid":
            v = _v_fetch(ctx, s, a.rid, 0, a.recv_seed)
        elif kind == "wrong-signer":
            v = _v_fetch(ctx, s, b.rid, 0, b.send_seed)
        elif kind == "sess-id-other-link":
            v = _v_fetch(ctx, s, b.rid, 0, b.recv_seed, sess=flip(ctx.sess_id, 0))
        else:                                      # stale-ack: ack = B's next_cell_id
            v = _v_fetch(ctx, s, b.rid, ctx.r.queues.get(b.rid).next_cell_id, b.recv_seed)
        out, values = _cr(ctx, rng, [_payload(v)], "FETCH", [s])
        _check(values[0]["cell"] == rng.values["cell_r"] and values[0]["rid"] == v["rid"], "error frame")
        return {}, out, values
    return build


def _err_fetch_multi(ctx, rng):
    a, b, s = ctx.queues["A"], ctx.queues["B"], ctx.seq()
    v = _v_fetch_multi(ctx, s, [(a.rid, 0, a.recv_seed), (b.rid, 0, b.recv_seed)])
    out, values = _cr(ctx, rng, [_payload(v)], "FETCH_MULTI", [s])
    _check(values[0]["cell"] == rng.values["cell_r"], "error frame")
    return {}, out, values


def _err_queue_del(ctx, rng):
    b, s = ctx.queues["B"], ctx.seq()
    out, values = _cr(ctx, rng, [_payload(_v_queue_del(ctx, s, b.rid, b.send_seed))], "QUEUE_DEL", [s])
    return {}, out, values


def _err_link_put(kind):
    def build(ctx, rng):
        s = ctx.seq()
        if kind == "link-put-exists":
            _, payloads = _link_put(ctx, s, ctx.ld)
        else:
            ld_id, owner_seed = rng.take(16), rng.take(32)
            signer = rng.take(32) if kind == "wrong-signer" else None
            ld = LD(ld_id, owner_seed, primitives.ed25519_public(owner_seed), rng.take(sizes.LINK_BLOB))
            tok = flip(ctx.token(s), 0) if kind == "token-flip" else None
            _, payloads = _link_put(ctx, s, ld, tok=tok, signer=signer)
        out, values = _cr(ctx, rng, payloads, "LINK_PUT", [s])
        return {}, out, values
    return build


def _err_link_get(kind):
    def build(ctx, rng):
        if kind == "consume-again":
            ld_id, mode, signer = ctx.ld.ld_id, "consume", None
        elif kind == "unknown-ld-id":
            ld_id, mode, signer = rng.take(16), "consume", None
        else:                                      # owner-wrong-signer
            ld_id, mode, signer = ctx.ld.ld_id, "owner-status", rng.take(32)
        s = ctx.seq()
        out, values = _cr(ctx, rng, [_payload(_v_link_get(ctx, s, ld_id, mode, signer))], "LINK_GET", [s])
        _dummy_blob_check(ctx, rng, values)
        return {}, out, values
    return build


def _err_skey(ctx, rng):
    s = ctx.seq()
    out, values = _cr(ctx, rng, [bytes([enc.OP_SKEY]) + s.to_bytes(4, "big")], "SKEY", [s])
    return {}, out, values


def _err_replay(ctx, rng):
    s = ctx.seq()
    out, values = _cr(ctx, rng, [_ping(s), _ping(s)], "PING", [s, s])
    return {}, out, values


# ---------------------------------------------------------------------------------------------
# The event table


class Ev(NamedTuple):
    name: str                                     # P1 …, E1 …
    op: str
    party: str
    stream: list
    build: object
    counters: str = ""                            # link A: the reviewer's "cmd_seq; c2r; r2c" (asserted)
    answer: str = ""                              # link A: the decoded response (asserted)
    manipulation: str = ""
    text: str = ""                                # the reviewer's step (P) or construction (E) column
    spec: str = ""                                # E rows: the reviewer's spec column
    note: str = ""                                # the reviewer's remark on the outputs (P) or the answer (E)
    in_note: str = ""                             # the reviewer's remark on the stream inputs
    derived_notes: dict = {}                      # … and on a derived input


def P(name, op, party, stream, build, counters="", answer="", text="", note="", in_note=""):
    return Ev(name, op, party, stream, build, counters, answer, text=text, note=note, in_note=in_note)


def E(name, op, manipulation, stream, build, counters, answer, text, spec, note="", in_note="", derived_notes=None):
    return Ev(name, op, "CR", stream, build, counters, answer, manipulation, text, spec, note, in_note,
              derived_notes or {})


HANDSHAKE = [
    P("P1", "relay-keys", "R", RELAY_KEYS_STREAM, _relay_keys,
      text="§8.2 relay identity and RelayInfoV1 (docs/03:528–535, 799)"),
    P("P2", "relayinfo-accept", "C", [], _relayinfo_accept,
      text="HELLO; the client checks RelayInfo (docs/03:535, 540–541; reading OPEN-4)"),
    P("P3", "hs1", "C", HS1_STREAM, _hs1, text="HS1 (docs/03:542, 545–548)"),
    P("P4", "hs2", "R", HS2_STREAM, _hs2, text="HS2 and the relay's keys (docs/03:543, 549–553)"),
    P("P5", "hs2-accept", "C", [], _hs2_accept, text="the client's keys; both sides byte-equal"),
]

LINK_A = [
    P("P6", "queue-new", "CR", QUEUE_STREAM, _queue_new("A", True, True), "1; 0; 0", "OK_QUEUE_NEW {rid A, sid A}",
      "**frame 1 each way** (reading OPEN-13). Queue A: `rid` = SHA-256(`\"SecMP-Q/1 rid\"` ‖ `recv_pk`)[0..16], "
      "`sid` = SHA-256(`\"SecMP-Q/1 sid\"` ‖ `recv_pk` ‖ `send_pk`)[0..16] (docs/03:577–578); token (docs/03:618); "
      "signed by the recv key (docs/03:809)"),
    P("P7", "send", "CR", CELL_STREAM, _send("A"), "2; 1; 1", "OK_SEND {1, 0, 0}",
      "**frame 2 each way**: SEND to `sid` A, signed by the send key (docs/03:811, 826)"),
    P("P8", "ping", "CR", [], _ping_row(), "3; 2; 2", "OK", "**frame 3 each way** (docs/03:817, 824; reading OPEN-13)"),
    P("P9", "queue-new", "CR", [], _queue_new("A", False, False), "4; 3; 3", "OK_QUEUE_NEW {rid A, sid A}",
      "identical QUEUE_NEW: OK_QUEUE_NEW without side effects (docs/03:595, 629)", note="P6's `rid` and `sid`",
      in_note="A's keys from P6"),
    P("P10", "send", "CR", CELL_STREAM, _send("A"), "5; 4; 4", "OK_SEND {2, 0, 0}"),
    P("P11", "send", "CR", CELL_STREAM, _send("A"), "6; 5; 5", "OK_SEND {3, 0, 0}"),
    P("P12", "fetch", "CR", dummies(1), _fetch("A", 0, _check_p12), "7; 6; 6–9",
      "CELLR {1, 0, 1}, {1, 0, 2}, {1, 0, 3}, {0, 0, 0}",
      "FETCH `ack` 0: the oldest `F` cells, ascending, then dummies (docs/03:597, 604, 827; reading OPEN-7)",
      note="the cells are P7's, P10's and P11's `cell`, the dummy `dummy_0`"),
    P("P13", "fetch", "CR", dummies(1), _fetch("A", 0, _check_p13), "8; 7; 10–13",
      "CELLR {1, 0, 1}, {1, 0, 2}, {1, 0, 3}, {0, 0, 0}",
      "**FETCH idempotence**: the same `ack` returns the same cells (docs/03:604)",
      note="the (`cell_id`, `cell`) of its three present-1 CELLRs equal P12's (asserted)"),
    P("P14", "fetch", "CR", dummies(3), _fetch("A", 2), "9; 8; 14–17", "CELLR {1, 0, 3}, 3 × {0, 0, 0}",
      "**cumulative ack**: `ack` 2 deletes `cell_id` 1 and 2 before selecting (docs/03:604)"),
    P("P15", "queue-new", "CR", QUEUE_STREAM, _queue_new("B", True, True), "10; 9; 18", "OK_QUEUE_NEW {rid B, sid B}",
      "second queue: two queues = `budget_queues`, which is not exceeded", note="queue B"),
    E("E1", "queue-new", "queue-new-full", QUEUE_STREAM, _err_queue_new("queue-new-full"), "11; 10; 19", "ERR 2",
      "an honest QUEUE_NEW of a fresh third queue while A and B exist", "docs/03:595, 625; reading OPEN-12"),
    P("P16", "send", "CR", CELL_STREAM, _send("B"), "12; 11; 20", "OK_SEND {1, 0, 0}",
      "a SEND is accepted at the budget limit (docs/03:625)", note="to B"),
    P("P17", "send", "CR", CELL_STREAM, _send("A"), "13; 12; 21", "OK_SEND {4, 0, 0}",
      "arrival order A3 < B1 < A4", note="to A"),
    P("P18", "fetch-multi", "CR", dummies(5), _fetch_multi_row, "14; 13; 22–29",
      "CELLR {1, A, 3}, {1, B, 1}, {1, A, 4}, 5 × {0, 0, 0}",
      "FETCH_MULTI: oldest-first by `arrival` across queues, not in request order (docs/03:598, 813; reading OPEN-8)",
      note="`req`: count 2, B `ack` 0, A `ack` 2; `sig_0`, `sig_1` in entry order"),
    P("P19", "send-fill", "CR", [("fill_cell", sizes.CELL)], _send_fill, "15–141; 14–140; 30–156",
      "OK_SEND {128, 0, 0}", "127 SENDs fill B to `QUEUE_CAPACITY` (docs/03:168)"),
    P("P20", "send", "CR", CELL_STREAM, _send("B"), "142; 141; 157", "OK_SEND {129, 1, 1}",
      "**eviction**: the oldest cell is removed and reported (docs/03:614, 826); `cell_id` keeps increasing "
      "(docs/03:583)", note="to B"),
    P("P21", "fetch", "CR", [], _fetch("B", 0, _check_p21), "143; 142; 158–161",
      "CELLR {1, 0, 2}, {1, 0, 3}, {1, 0, 4}, {1, 0, 5}",
      "the recipient finds the newest 128 cells (docs/03:614)", note="FETCH B `ack` 0; the cells are `fill_cell`"),
    P("P22", "ping", "CR", [], _ping_row(skip=1), "145; 143; 162", "OK",
      "`cmd_seq` gap: strictly increasing, not +1 (docs/03:589)"),
    P("P23", "queue-del", "CR", [], _queue_del, "146; 144; 163", "OK",
      "QUEUE_DEL of A (docs/03:599, 814); zeroization (docs/03:626) is outside the suite"),
    P("P24", "link-put", "CR", LD_STREAM + BLOB, _link_put_row, "147; 145–147; 164", "OK",
      "**multi-frame continuation, client → relay**: 4160 + 4100 + 4100 B, one response after the third frame "
      "(docs/03:600, 815, 818)",
      note="`sig` over … ‖ SHA-256(`blob`); `req`: LINK_PUT with `blob[0..4160]`, CONT idx 1, CONT idx 2"),
    E("E2", "link-put", "link-put-exists", [], _err_link_put("link-put-exists"), "148; 148–150; 165", "ERR 5",
      "P24's LINK_PUT again, with a new `cmd_seq`, token and signature", "docs/03:600, 818",
      note="after the third frame", in_note="L's values"),
    P("P25", "link-get", "CR", DUMMY_BLOB, _link_get("owner-status", _dummy_blob_check), "149; 151; 166–168",
      "LINKR {1, 0}, CONT 1, CONT 2",
      "**owner status, non-consuming**, and **multi-frame continuation, relay → client** (docs/03:601, 610, 816, 828; "
      "reading OPEN-11)", note="mode `owner-status`; the blob parts are `dummy_blob`"),
    P("P26", "link-get", "CR", [], _link_get("consume", _real_blob_check), "150; 152; 169–171",
      "LINKR {1, 0}, CONT 1, CONT 2",
      "**one-time consumption**, deleted atomically (docs/03:610; reading OPEN-11)",
      note="mode `consume`, `sig` 0^64; the blob parts are P24's `blob`"),
    P("P27", "link-get", "CR", DUMMY_BLOB, _link_get("owner-status", _dummy_blob_check), "151; 153; 172–174",
      "LINKR {0, 1}, CONT 1, CONT 2", "owner status reports the consumption (docs/03:213, 610)",
      note="the blob parts are `dummy_blob`"),
    E("E3", "queue-new", "token-flip", QUEUE_STREAM, _err_queue_new("token-flip"), "152; 154; 175", "ERR 1",
      "`token` := flip(token, 0), signed as sent", "docs/03:595, 618"),
    E("E4", "queue-new", "token-replayed", QUEUE_STREAM, _err_queue_new("token-replayed"), "153; 155; 176", "ERR 1",
      "`token` := P6's token (made for `cmd_seq` 1), signed as sent", "docs/03:618 (the token is bound to `cmd_seq`)"),
    E("E5", "queue-new", "token-other-link", QUEUE_STREAM, _err_queue_new("token-other-link"), "154; 156; 177",
      "ERR 1", "the token computed over `flip(sess_id, 0)`", "docs/03:618 (the token is bound to `sess_id`)"),
    E("E6", "queue-new", "send-pk-differs", [("send_seed", 32)], _err_queue_new("send-pk-differs"), "155; 157; 178",
      "ERR 4", "B's recv key with a fresh send key", "docs/03:629", derived_notes={"recv_pk": "= B's"}),
    E("E7", "queue-new", "wrong-signer", QUEUE_STREAM, _err_queue_new("wrong-signer"), "156; 158; 179", "ERR 4",
      "signed by the send key instead of the recv key", "docs/03:589, 595; reading OPEN-9"),
    E("E8", "send", "wrong-signer", CELL_STREAM, _err_send("wrong-signer"), "157; 159; 180", "ERR 4",
      "to `sid` B, signed by B's recv key", "docs/03:596"),
    E("E9", "send", "sess-id-other-link", CELL_STREAM, _err_send("sess-id-other-link"), "158; 160; 181", "ERR 4",
      "signed by B's send key over `flip(sess_id, 0)`", "docs/03:556, 589, 596"),
    E("E10", "send", "unknown-sid", CELL_STREAM, _err_send("unknown-sid"), "159; 161; 182", "ERR 3",
      "to `sid` A (deleted in P23), signed by A's send key", "docs/03:596"),
    E("E11", "fetch", "unknown-rid", CELL_R + dummies(3), _err_fetch("unknown-rid"), "160; 162; 183–186",
      "CELLR {2, A, 0}, 3 × {0, 0, 0}", "`rid` A, signed by A's recv key", "docs/03:597, 827; reading OPEN-7",
      note="the cells are `cell_r`, then `dummy_0..2`"),
    E("E12", "fetch", "wrong-signer", CELL_R + dummies(3), _err_fetch("wrong-signer"), "161; 163; 187–190",
      "CELLR {3, B, 0}, 3 × {0, 0, 0}", "`rid` B, signed by B's send key", "reading OPEN-7",
      note="the cells are `cell_r`, then `dummy_0..2`"),
    E("E13", "fetch", "sess-id-other-link", CELL_R + dummies(3), _err_fetch("sess-id-other-link"), "162; 164; 191–194",
      "CELLR {3, B, 0}, 3 × {0, 0, 0}", "signed by B's recv key over `flip(sess_id, 0)`", "reading OPEN-7",
      note="the cells are `cell_r`, then `dummy_0..2`"),
    E("E14", "fetch", "stale-ack", CELL_R + dummies(3), _err_fetch("stale-ack"), "163; 165; 195–198",
      "CELLR {4, B, 0}, 3 × {0, 0, 0}", "`rid` B, `ack` 130 = B's `next_cell_id`",
      "docs/03:585 (\"answer … with `ERR_MALFORMED`\" = `present` 4); reading OPEN-7",
      note="the cells are `cell_r`, then `dummy_0..2`; nothing deleted"),
    E("E15", "fetch-multi", "one-queue-unknown", CELL_R, _err_fetch_multi, "164; 166; 199–206",
      "CELLR {2, A, 0}, {1, B, 2}, {1, B, 3}, {1, B, 4}, {1, B, 5}, {1, B, 6}, {1, B, 7}, {1, B, 8}",
      "entries [A `ack` 0 (signed by A's recv key), B `ack` 0]", "docs/03:598; reading OPEN-8",
      note="the error frame carries `cell_r`; no dummies"),
    E("E16", "queue-del", "wrong-signer", [], _err_queue_del, "165; 167; 207", "ERR 4",
      "`rid` B, signed by B's send key", "reading OPEN-9"),
    E("E17", "link-put", "token-flip", LD_STREAM + BLOB, _err_link_put("token-flip"), "166; 168–170; 208", "ERR 1",
      "a fresh entry with `token` := flip(token, 0), signed as sent", "docs/03:600, 818",
      note="after the third frame; nothing stored"),
    E("E18", "link-put", "wrong-signer", LD_STREAM + [("signer_seed", 32)] + BLOB, _err_link_put("wrong-signer"),
      "167; 171–173; 209", "ERR 4", "`owner_pk` of `owner_seed`, signed by `signer_seed`",
      "docs/03:815, 818; reading OPEN-9", note="after the third frame; nothing stored"),
    E("E19", "link-get", "consume-again", DUMMY_BLOB, _err_link_get("consume-again"), "168; 174; 210–212",
      "LINKR {0, 1}, CONT 1, CONT 2", "consume mode on L (consumed in P26)", "docs/03:610",
      note="the blob parts are `dummy_blob`"),
    E("E20", "link-get", "unknown-ld-id", [("ld_id", 16)] + DUMMY_BLOB, _err_link_get("unknown-ld-id"),
      "169; 175; 213–215", "LINKR {0, 0}, CONT 1, CONT 2", "consume mode on an `ld_id` that was never stored",
      "docs/03:601 (\"dummy blob when absent\")", note="the blob parts are `dummy_blob`"),
    E("E21", "skey", "reserved-opcode", [], _err_skey, "170; 176; 216", "ERR 6", "`0x02 ‖ cmd_seq`", "docs/03:810",
      note="the one opcode answered rather than torn down; reading OPEN-6"),
    E("E22", "link-get", "owner-wrong-signer", [("signer_seed", 32)] + DUMMY_BLOB, _err_link_get("owner-wrong-signer"),
      "171; 177; 217–219", "LINKR {0, 0}, CONT 1, CONT 2", "owner status on L, signed by `signer_seed`",
      "docs/03:601, 606, 833; reading OPEN-10", note="the blob parts are `dummy_blob`"),
    E("E23", "ping", "cmd-seq-replayed", [], _err_replay, "172, 172; 178–179; 220–221", "OK, ERR 6",
      "PING with `cmd_seq` 172 (answered OK), then PING with `cmd_seq` 172 again", "docs/03:589; reading OPEN-5",
      note="nothing executed"),
]
assert len(HANDSHAKE) + len(LINK_A) == 50
RELAY_DRAWS = {"cell_r", "dummy_blob", *(f"dummy_{k}" for k in range(relay.F_M))}   # R's draws in a CR case

X1_GROUPS = [
    ("SEND", "success, AUTH, NOQUEUE", [7, 35, 37]),
    ("FETCH", "success, NOQUEUE, MALFORMED", [12, 38, 41]),
    ("FETCH_MULTI", "success, partial error", [19, 42]),
    ("QUEUE_NEW", "success, FULL, TOKEN, AUTH", [6, 16, 30, 33]),
    ("LINK_PUT", "success, EXISTS, TOKEN", [25, 26, 44]),
    ("LINK_GET", "owner status (present), real blob, owner status (consumed), consume again, absent, owner status "
                 "with the wrong signer", [27, 28, 29, 46, 47, 49]),
    ("PING / SKEY", "OK, ERR 6", [8, 48]),
]
X1_COUNTS = [[1, 1, 1], [4, 4, 4], [8, 8], [1, 1, 1, 1], [1, 1, 1], [3, 3, 3, 3, 3, 3], [1, 1]]


# ---------------------------------------------------------------------------------------------
# RelayInfo cases (I1 … I8): C, from link-0001


def _ri_record(ctx, **edit):
    return link.relayinfo_record(link.sign_relayinfo(ctx.keys.sig_seed, {**ctx.info, **edit}))


def _ri(build_record, pinned=None):
    def build(ctx, rng):
        rec = build_record(ctx)
        fp = ctx.keys.fp if pinned is None else pinned(ctx)
        derived = {"rec_relayinfo": rec} if pinned is None else {"relay_fp": fp, "rec_relayinfo": rec}
        return derived, (rec, fp)
    return build


class Ri(NamedTuple):
    name: str
    manipulation: str
    build: object
    rule: str                                     # "" for the accepting I8
    text: str                                     # the reviewer's construction
    check_note: str = ""                          # the reviewer's remark after the outcome
    derived_notes: dict = {}


RELAYINFO_CASES = [
    Ri("I1", "ri-sig-flip", _ri(lambda c: link.relayinfo_record({**c.info, "sig": flip(c.info["sig"], 32)})),
       "ri-sig", "flip(`sig`, 32), the low byte of S. S stays < L, so the decoder accepts and Ed25519 verification "
                 "fails"),
    Ri("I2", "ri-fp-mismatch", _ri(lambda c: c.rec_relayinfo, pinned=lambda c: flip(c.keys.fp, 0)), "ri-fp",
       "honest RelayInfo; the client pins flip(`relay_fp`, 0)", derived_notes={"relay_fp": "(pinned)"}),
    Ri("I3", "ri-expired", _ri(lambda c: _ri_record(c, valid_until=NOW - 1)), "ri-expired",
       "`valid_until` := `now` − 1, re-signed (Ed25519, no draw)"),
    Ri("I4", "ri-akc-mismatch", _ri(lambda c: _ri_record(c, akc=flip(c.info["akc"], 0))), "ri-akc",
       "`akc` := flip(`akc`, 0), re-signed"),
    Ri("I5", "ri-ver", _ri(lambda c: _ri_record(c, ver=0x02)), "ri-decode", "`ver` := 0x02, re-signed"),
    Ri("I6", "ri-dh-low-order", _ri(lambda c: _ri_record(c, relay_dh_pk=LOW_ORDER)), "ri-decode",
       "`relay_dh_pk` := the order-8 point, re-signed", "(docs/03:152 (a))"),
    Ri("I7", "relayinfo-valid-too-long", _ri(lambda c: _ri_record(c, valid_until=NOW + 61 * DAY)), "ri-validity",
       "`valid_until` := `now` + 61 days = 1 705 270 500, re-signed", "(docs/03:535; reading OPEN-4)"),
    Ri("I8", "relayinfo-valid-60d", _ri(lambda c: _ri_record(c, valid_until=NOW + 60 * DAY)), "",
       "`valid_until` := `now` + 60 days = 1 705 184 100 (`valid_until − now` = 5 184 000 s exactly), re-signed",
       ": the boundary is accepted (reading OPEN-4)"),
]
assert NOW + 61 * DAY == 1_705_270_500 and NOW + 60 * DAY == 1_705_184_100 and 60 * DAY == link.MAX_VALIDITY


# ---------------------------------------------------------------------------------------------
# hs1-reject (H1, S1 … S10): R with link-0001's keys; base = link-0003's records


def _hs1_value(ctx):
    return enc.decode("Record/HS1", ctx.chs.record)


def _hs1_edit(**edit):
    def build(ctx, rng):
        rec = enc.raw("Record/HS1", {**_hs1_value(ctx), **{k: f(ctx) for k, f in edit.items()}})
        return {"rec_hs1": rec}, rec
    return build


def _h1(ctx, rng):
    rec = flip(ctx.rec_hello, 3)
    return {"rec_hello": rec}, rec


def _s4(ctx, rng):
    other_dh_sk, other_kem_seed = rng.take(32), rng.take(64)
    other_ek, _ = primitives.ml_kem_keygen(1024, other_kem_seed)
    fake = {**ctx.info, "relay_dh_pk": primitives.x25519_public(other_dh_sk), "relay_kem_ek": other_ek}
    rec = link.hs1(fake, rng).record                # h0 binds the real relay_fp (fake keeps relay_sig_pk)
    return {"rec_hs1": rec}, rec


def _s9(ctx, rng):
    v = _hs1_value(ctx)
    rec = enc.raw("Record/HS1", {**v, "len": enc.HS1_BODY - 1, "mac1": v["mac1"][:-1]})
    _check(rec == (enc.HS1_BODY - 1).to_bytes(2, "big") + ctx.chs.record[2:-1], "S9 bytes")
    return {"rec_hs1": rec}, rec


class Hs(NamedTuple):
    name: str
    manipulation: str
    stream: list
    build: object
    rule: str
    text: str                                     # the reviewer's construction ({key} = the size of an output)
    check_note: str = ""
    derived_notes: dict = {}


HS1_REJECTS = [
    Hs("H1", "hello-magic", [], _h1, "hello-decode", "flip(`rec_hello`, 3), so the magic reads `\"RECMP\"`"),
    Hs("S1", "mac1-flip", [], _hs1_edit(mac1=lambda c: flip(c.chs.mac1, 0)), "mac1", "flip(`mac1`, 0)"),
    Hs("S2", "ct-kem-flip", [], _hs1_edit(ct_kem=lambda c: flip(c.chs.ct_kem, 0)), "mac1",
       "flip(`ct_kem`, 0). Implicit rejection makes R's `ss1` and `h0` differ, so the honest `mac1` fails"),
    Hs("S3", "kid-unknown", [], _hs1_edit(kid=lambda c: 2), "kid-unknown",
       "`kid` := 2 (R holds only `kid` 1; docs/03:528, 556)"),
    Hs("S4", "wrong-static-key", [("other_dh_sk", 32), ("other_kem_seed", 64)] + HS1_STREAM, _s4, "mac1",
       "an honest HS1 with `kid` 1, encapsulated to another static pair (`other_dh`, `other_kem`), with `mac1` from "
       "that `ss1`"),
    Hs("S5", "pk-e1-low-order", [], _hs1_edit(pk_e1=lambda c: LOW_ORDER), "hs1-decode",
       "`pk_e1` := the order-8 point", "(docs/03:152 (a))"),
    Hs("S6", "e-c-zero", [], _hs1_edit(e_c=lambda c: bytes(32)), "hs1-decode", "`e_c` := 0^32"),
    Hs("S7", "ek-c-modulus", [], _hs1_edit(ek_c=lambda c: BAD_EK + c.chs.ek_c[3:]), "hs1-decode",
       "`ek_c` bytes 0–2 := `ff ff ff`", "(docs/03:152 (c))"),
    Hs("S8", "hs1-ver", [], _hs1_edit(ver=lambda c: 0x02), "hs1-decode", "`ver` := 0x02"),
    Hs("S9", "hs1-short", [], _s9, "hs1-decode",
       "the last body byte dropped and `len` := 2853: a complete record of the wrong size"),
    Hs("S10", "hs1-replay", HS2_STREAM, None, "frame-open",
       "P3's `rec_hs1` on a new connection. R answers it as a new handshake (reading OPEN-3), with outputs "
       "`rec_hs2` {rec_hs2} and `sess_id` {sess_id} (≠ P4's). Then P6's request frame (counter 0) arrives and fails "
       "under the new `k_c2r`", derived_notes={"rec_hs1": "(= P3)", "frame": "(= P6's request frame)"}),
]


# hs2-reject (T1 … T4): C after link-0003; base = link-0004's rec_hs2


def _hs2_edit(**edit):
    def build(ctx, rng):
        v = enc.decode("Record/HS2", ctx.hs2.record)
        rec = enc.raw("Record/HS2", {**v, **{k: f(ctx) for k, f in edit.items()}})
        return {"rec_hs2": rec}, rec
    return build


HS2_REJECTS = [
    Hs("T1", "mac2-flip", [], _hs2_edit(mac2=lambda c: flip(c.hs2.mac2, 0)), "mac2", "flip(`mac2`, 0)"),
    Hs("T2", "ct-c-flip", [], _hs2_edit(ct_c=lambda c: flip(c.hs2.ct_c, 0)), "mac2",
       "flip(`ct_c`, 0). Implicit rejection makes C's `ss2` differ, so `mac2` fails"),
    Hs("T3", "e-r-low-order", [], _hs2_edit(e_r=lambda c: LOW_ORDER), "hs2-decode", "`e_r` := the order-8 point",
       "(docs/03:152 (a))"),
    Hs("T4", "hs2-ver", [], _hs2_edit(ver=lambda c: 0x02), "hs2-decode", "`ver` := 0x02"),
]


# frame-reject (F1 … F12): from link-0008; base = link-0009's payloads and frames


class Fr(NamedTuple):
    name: str
    party: str
    manipulation: str
    stream: list
    frame: object                                 # (ctx, rng) → the unit the receiver gets
    rule: str
    text: str                                     # the reviewer's construction
    check_note: str = ""


def _k(ctx):
    return ctx.hs2


FRAME_REJECTS = [
    Fr("F1", "R", "ctr-skip", [], lambda c, r: link.seal_frame(_k(c).k_c2r, 4, _k(c).sess_id, c.case9["req"]),
       "frame-open", "link-0009's request payload sealed with `c2r` = 4 (R expects 3)", "(strict +1, docs/03:566)"),
    Fr("F2", "R", "ctr-replay", [], lambda c, r: c.frame8, "frame-open",
       "link-0008's request frame again (`c2r` = 2)"),
    Fr("F3", "R", "tag-flip", [], lambda c, r: flip(c.case9["req_frame"], -1), "frame-open",
       "flip(link-0009's request frame, −1)"),
    Fr("F4", "R", "short", [], lambda c, r: prefix(c.case9["req_frame"], sizes.FRAME - 1), "frame-len",
       "prefix(link-0009's request frame, 4351)", "(docs/03:566)"),
    Fr("F5", "R", "long", [], lambda c, r: append_zero(c.case9["req_frame"]), "frame-len",
       "append-zero(link-0009's request frame)"),
    Fr("F6", "R", "reflected", [], lambda c, r: c.case9["resp_frame"], "frame-open",
       "link-0009's **response** frame (`k_r2c`, counter 3), sent to R as its `c2r` frame 3",
       "(direction keys, docs/03:553, 563)"),
    Fr("F7", "R", "ad-other-link", [],
       lambda c, r: link.seal_frame(_k(c).k_c2r, 3, flip(_k(c).sess_id, 0), c.case9["req"]), "frame-open",
       "link-0009's request payload sealed with the AD `\"SecMP-LINK/1 frame\"` ‖ flip(`sess_id`, 0)"),
    Fr("F8", "C", "resp-ctr-skip", [], lambda c, r: link.seal_frame(_k(c).k_r2c, 4, _k(c).sess_id, c.case9["resp"]),
       "frame-open", "link-0009's response payload sealed with `r2c` = 4 (C expects 3)"),
    Fr("F9", "C", "resp-tag-flip", [], lambda c, r: flip(c.case9["resp_frame"], -1), "frame-open",
       "flip(link-0009's response frame, −1)"),
    Fr("F10", "R", "cont-orphan", [("data", enc.LINK_PART_CONT)],
       lambda c, r: link.seal_frame(_k(c).k_c2r, 3, _k(c).sess_id, _payload(
           {"op": "CONT", "cmd_seq": 3, "idx": 1, "data": r.take(enc.LINK_PART_CONT)})), "cont-orphan",
       "a client CONT {idx 1, `data`} with `cmd_seq` 3, sealed honestly at `c2r` 3, with no multi-frame command "
       "pending", "(docs/03:589, 818; reading OPEN-6)"),
    Fr("F11", "R", "pt-bad-pad", [],
       lambda c, r: link.seal_plaintext(_k(c).k_c2r, 3, _k(c).sess_id, bytes([enc.REQUEST_OPS["PING"]])
                                        + (4).to_bytes(4, "big") + bytes(sizes.FRAME_PLAINTEXT - 5)), "pt-decode",
       "a PING plaintext with `cmd_seq` 4 that has 0x00 for the 0x80 marker (0x09 ‖ `cmd_seq` ‖ 0^4331), sealed "
       "honestly at `c2r` 3", "(docs/03:149, 628; reading OPEN-6)"),
    Fr("F12", "R", "pt-unknown-op", [],
       lambda c, r: link.seal_frame(_k(c).k_c2r, 3, _k(c).sess_id, b"\x0a" + (4).to_bytes(4, "big")), "pt-decode",
       "`0x0A ‖ cmd_seq 4`, honestly padded and sealed at `c2r` 3", "(docs/03:155, 628; reading OPEN-6)"),
]


# ---------------------------------------------------------------------------------------------
# The run


class Run(NamedTuple):
    cases: list
    rows: list                                    # per case: the facts the SCHEMA table shows
    ctx: Ctx


def _range(a, b):
    return f"{a}" if a == b else f"{a}–{b}"


def _counters(rnd) -> str:
    seqs = rnd["seqs"]
    if len(seqs) > 1 and len(set(seqs)) == len(seqs):
        s = _range(seqs[0], seqs[-1])
    else:
        s = ", ".join(map(str, seqs))
    return f"{s}; {_range(*rnd['c2r'])}; {_range(*rnd['r2c'])}"


def _rules() -> str:
    """The check that raised the most recent Reject (link, relay)."""
    return relay.last_rule or link.last_rule


def _reset_rules():
    relay.last_rule = link.last_rule = None


@functools.lru_cache(maxsize=1)
def run() -> Run:
    ctx, cases, rows = Ctx(), [], []
    ids = {}

    def cid(i):
        return case_id(SUITE, i)

    # Positives and command errors, in event order.
    prev = None
    for i, ev in enumerate(HANDSHAKE + LINK_A, start=1):
        rng = _Named(CaseStream(SUITE, i), ev.stream)
        before = store_post(ctx.r) if ev.manipulation else None
        result = ev.build(ctx, rng)
        derived, outputs = result[:2]
        fields = {"party": ev.party}
        if prev is not None:
            fields["from"] = cid(prev)
        row = {"i": i, "id": cid(i), "ev": ev, "stream": ev.stream, "derived": list(derived), "outputs": outputs}
        if ev.party == "CR":
            values = result[2]
            got = answer(ctx, values)
            _check(got == ev.answer, f"{ev.name}: answer {got!r}, the table says {ev.answer!r}")
            _check(_counters(ctx.round) == ev.counters,
                   f"{ev.name}: counters {_counters(ctx.round)}, the table says {ev.counters}")
            fields["cmd_seq"] = ctx.round["seqs"][0]
            if ev.op == "send-fill":
                fields["count"] = FILL_COUNT
            if ev.manipulation:
                _check(store_post(ctx.r) == before, f"{ev.name}: the command error changed the store")
            ctx.resp_counts[i] = len(outputs.get("resp_frames", ()))
            row.update(answer=got, counters=ctx.round, values=values)
            if i == 9:
                ctx.case9 = {"req": outputs["req"][0], "req_frame": outputs["req_frames"][0],
                             "resp": outputs["resp"][0], "resp_frame": outputs["resp_frames"][0]}
        if ev.manipulation:
            fields["manipulation"] = ev.manipulation
        cases.append(Case(i, ev.op, {**rng.done(), **derived}, outputs, fields))
        rows.append(row)
        ids[ev.name] = i
        prev = i
    _check(ctx.r.last == 172 and (ctx.c.send_ctr, ctx.c.recv_ctr) == (180, 222), "link A at the end")

    # X1
    i = len(cases) + 1
    groups = [[cid(n) for n in g] for _, _, g in X1_GROUPS]
    counts = [[ctx.resp_counts[n] for n in g] for _, _, g in X1_GROUPS]
    _check(counts == X1_COUNTS, f"X1: resp_counts {counts}")
    _check(all(len(set(c)) == 1 for c in counts), "X1: a group's frame counts differ")
    _Named(CaseStream(SUITE, i), []).done()
    cases.append(Case(i, "indist", {}, {"resp_counts": counts, "frame_len": FRAME_LEN},
                      {"party": "CR", "cases": groups}))
    rows.append({"i": i, "id": cid(i), "groups": groups, "counts": counts})

    # RelayInfo cases
    for ri in RELAYINFO_CASES:
        i = len(cases) + 1
        rng = _Named(CaseStream(SUITE, i), [])
        derived, (rec, fp) = ri.build(ctx, rng)
        _reset_rules()
        fields = {"party": "C", "from": cid(ids["P1"]), "manipulation": ri.manipulation}
        if ri.rule:
            try:
                link.relayinfo_accept(rec, fp, ctx.keys.access_key, NOW)
            except Reject:
                pass
            else:
                raise TableMismatch(f"{ri.name}: accepted")
            _check(link.last_rule == ri.rule, f"{ri.name}: rejected at {link.last_rule}, the table says {ri.rule}")
            cases.append(Case(i, "relayinfo-reject", {**rng.done(), **derived}, None, fields))
        else:
            link.relayinfo_accept(rec, fp, ctx.keys.access_key, NOW)
            cases.append(Case(i, "relayinfo-accept", {**rng.done(), **derived}, {"accept": True}, fields))
        rows.append({"i": i, "id": cid(i), "ev": ri, "derived": list(derived)})

    # hs1-reject: R holds only link-0001's keys; it draws nothing before mac1 verifies.
    for hs in HS1_REJECTS:
        i = len(cases) + 1
        rng = _Named(CaseStream(SUITE, i), hs.stream)
        fields = {"party": "R", "from": cid(ids["P1"]), "manipulation": hs.manipulation}
        _reset_rules()
        if hs.name == "S10":
            derived, outputs = _s10(ctx, rng)
            fields["expect"] = "reject"
        else:
            derived, rec = hs.build(ctx, rng)
            outputs = None
            try:
                (link.hello_accept(rec) if hs.name == "H1" else link.hs1_accept(ctx.keys, rec, rng))
            except Reject:
                pass
            else:
                raise TableMismatch(f"{hs.name}: accepted")
        _check(_rules() == hs.rule, f"{hs.name}: rejected at {_rules()}, the table says {hs.rule}")
        cases.append(Case(i, "hs1-reject", {**rng.done(), **derived}, outputs, fields))
        rows.append({"i": i, "id": cid(i), "ev": hs, "derived": list(derived), "outputs": outputs})

    # hs2-reject: C after link-0003.
    for hs in HS2_REJECTS:
        i = len(cases) + 1
        rng = _Named(CaseStream(SUITE, i), hs.stream)
        derived, rec = hs.build(ctx, rng)
        _reset_rules()
        try:
            link.hs2_accept(ctx.chs, rec)
        except Reject:
            pass
        else:
            raise TableMismatch(f"{hs.name}: accepted")
        _check(link.last_rule == hs.rule, f"{hs.name}: rejected at {link.last_rule}, the table says {hs.rule}")
        cases.append(Case(i, "hs2-reject", {**rng.done(), **derived}, None,
                          {"party": "C", "from": cid(ids["P3"]), "manipulation": hs.manipulation}))
        rows.append({"i": i, "id": cid(i), "ev": hs, "derived": list(derived)})

    # frame-reject: from link-0008 (R expects c2r 3, C expects r2c 3, last 3).
    r8, c8 = ctx.after8
    _check(link_post_r(r8) == {"c2r": 3, "r2c": 3, "cmd_seq": 3} and (c8.send_ctr, c8.recv_ctr) == (3, 3), "after 8")
    for fr in FRAME_REJECTS:
        i = len(cases) + 1
        rng = _Named(CaseStream(SUITE, i), fr.stream)
        frame = fr.frame(ctx, rng)
        _reset_rules()
        if fr.party == "R":
            r = copy.deepcopy(r8)
            try:
                r.execute([frame], rng)
            except Reject:
                pass
            else:
                raise TableMismatch(f"{fr.name}: accepted")
            _check(r == r8, f"{fr.name}: the rejection changed R's state")
            post = link_post_r(r)
        else:
            c = copy.deepcopy(c8)
            try:
                relay.receive(c, [frame], "QUEUE_NEW")
            except Reject:
                pass
            else:
                raise TableMismatch(f"{fr.name}: accepted")
            _check(c == c8, f"{fr.name}: the rejection changed C's state")
            post = {"c2r": c.send_ctr, "r2c": c.recv_ctr, "cmd_seq": r8.last}
        _check(_rules() == fr.rule, f"{fr.name}: rejected at {_rules()}, the table says {fr.rule}")
        _check(post == {"c2r": 3, "r2c": 3, "cmd_seq": 3}, f"{fr.name}: link_post {post}")
        cases.append(Case(i, "frame-reject", {**rng.done(), "frame": frame}, {"link_post": post},
                          {"party": fr.party, "from": cid(ids["P8"]), "manipulation": fr.manipulation,
                           "expect": "reject"}))
        rows.append({"i": i, "id": cid(i), "ev": fr, "derived": ["frame"]})

    _check(len(cases) == 86, f"{len(cases)} cases")
    return Run(cases, rows, ctx)


def _s10(ctx, rng):
    """P3's rec_hs1 replayed on a new connection: a fresh HS2 and link (reading OPEN-3); then P6's request
    frame fails under the new k_c2r."""
    h, rlink = link.hs1_accept(ctx.keys, ctx.chs.record, rng)
    _check(h.sess_id != ctx.hs2.sess_id and h.record != ctx.hs2.record, "S10: the replay gave P4's link")
    r = relay.Relay(ctx.keys, rlink, NOW_BUCKET, BUDGET_QUEUES)
    before = copy.deepcopy(r)
    _reset_rules()
    try:
        r.execute([ctx.p6_frame], rng)
    except Reject:
        pass
    else:
        raise TableMismatch("S10: P6's frame opened on the replayed link")
    _check(r == before, "S10: the rejection changed R's state")
    return {"rec_hs1": ctx.chs.record, "frame": ctx.p6_frame}, {"rec_hs2": h.record, "sess_id": h.sess_id}


def link_cases() -> list[Case]:
    return run().cases
