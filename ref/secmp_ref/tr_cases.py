# SPDX-License-Identifier: AGPL-3.0-or-later
"""The `tr` case table (SCHEMA §4.9 = SCHEMA-4.9-tr.md; brief REF-M3): the SecMP-TR transcript.

One case per event, in event order. `init` initialises both parties; `send` encrypts one message of
the transcript (m01 … m40); `recv` decrypts one; `advance` encrypts Dummy cells that are lost in
transit; `recv-reject` offers a manipulated cell that must be rejected with the state unchanged.
Every case draws from its own stream (SCHEMA §2, suite name "tr", the case index); the ratchet takes
its randomness from that stream, and every stream-derived value is listed in `inputs`.

Each case records the party's state digest before and after the event (StateDigestV1 below, a
comparison construct of this suite, not a persistence format).

The run checks itself while it generates: every `recv` returns the sender's Content, steps exactly
where the table says, and every `recv-reject` is rejected by the check the table names and leaves the
state byte-identical; no message key encrypts twice or decrypts twice, and every decryption uses the
key of its own message. A disagreement raises TableMismatch instead of writing a file.
"""

import functools
from typing import NamedTuple

from . import encodings as enc
from . import encodings_cases as ec
from . import hybridsign, identity, labels, primitives, sizes, tr
from .cases import TableMismatch
from .errors import Reject
from .vectorfile import Case, CaseStream, append_zero, case_id, drop_last, flip

SUITE = "tr"

# ---------------------------------------------------------------------------------------------
# StateDigestV1 (brief REF-M3):
#   SHA-256( "SecMP-TR/1 state-digest" ‖ sb ‖ rk ‖ dh_s.sk[32] ‖ opt(dh_r) ‖ kem_s.seed[64 = d ‖ z]
#            ‖ opt(kem_r) ‖ opt(last_ct_r) ‖ opt(ct_s) ‖ opt(ck_s) ‖ opt(ck_r) ‖ opt(hk_s) ‖ opt(hk_r)
#            ‖ opt(nhk_s) ‖ opt(nhk_r) ‖ u32be(n_s) ‖ u32be(n_r) ‖ u32be(pn) ‖ u32be(|skipped|)
#            ‖ Σ_{entries in insertion order} ( hk[32] ‖ u32be(n) ‖ mk[32] ) )
#   opt(None) = 0x00 ; opt(Some(x)) = 0x01 ‖ x ; dh_s.sk = the 32 raw bytes as drawn (before clamping).
# The label is not in spec App. A (see SQ-24); it is used here and nowhere else.

DIGEST_LABEL = b"SecMP-TR/1 state-digest"


def _opt(x):
    return b"\x00" if x is None else b"\x01" + x


def _u32(n):
    return n.to_bytes(4, "big")


def state_bytes(s: tr.RatchetState) -> bytes:
    """The digest preimage. It holds every field of the state, so equal preimages are equal states."""
    out = [DIGEST_LABEL, s.sb, s.rk, s.dh_s.sk, _opt(s.dh_r), s.kem_s.seed, _opt(s.kem_r), _opt(s.last_ct_r),
           _opt(s.ct_s), _opt(s.ck_s), _opt(s.ck_r), _opt(s.hk_s), _opt(s.hk_r), _opt(s.nhk_s), _opt(s.nhk_r),
           _u32(s.n_s), _u32(s.n_r), _u32(s.pn), _u32(len(s.skipped))]
    for (hk, n), mk in s.skipped.items():
        out += [hk, _u32(n), mk]
    return b"".join(out)


def state_digest(s: tr.RatchetState) -> bytes:
    return primitives.sha256(state_bytes(s))


# ---------------------------------------------------------------------------------------------
# The forty messages and their Content (brief REF-M3; §7.6, D.5)

TS_BASE = 1_700_000_000                           # ts = 1 700 000 000 + seq
BATCH_OVERHEAD = 1 + 16 + 1 + 4 + 2               # count ‖ msg_id ‖ kind ‖ expire_after ‖ payload_len
BATCH_MAX_L = enc.BODY_MAX - BATCH_OVERHEAD       # 1665: the largest payload of a one-cell Batch
assert BATCH_MAX_L == 1665
FRAGMENT_CHUNK = enc.BODY_MAX - enc.FRAGMENT_HEADER
assert FRAGMENT_CHUNK == 1669                     # "maximal chunks of 1669 B (1689 − 20)"
KEYCHANGE_REASSEMBLED = 1 + enc.KEYCHANGE_BODY
assert KEYCHANGE_REASSEMBLED == 5391
KEYCHANGE_TOTAL = -(-KEYCHANGE_REASSEMBLED // FRAGMENT_CHUNK)
assert KEYCHANGE_TOTAL == 4


class Msg(NamedTuple):
    sender: str                                   # "A" (initiator) or "B" (responder)
    kind: str                                     # "Batch", "Dummy", "RouteUpdate", "Fragment"
    arg: int = 0                                  # Batch: payload length L; Fragment: idx


def _messages():
    m = {}
    for nums, sender, kind, arg in [
        ((1,), "A", "Batch", 100), ((2,), "A", "Dummy", 0), ((3,), "A", "Batch", 500),
        ((4,), "B", "Batch", 100), ((5,), "B", "Batch", BATCH_MAX_L), ((6,), "B", "Dummy", 0),   # m05: SQ-22
        (range(7, 11), "A", "Batch", 64),
        (range(11, 14), "B", "Batch", 32),
        ((14, 15), "A", "Batch", 16),
        ((16, 17), "B", "Batch", 200),
        ((22,), "B", "RouteUpdate", 0), ((23,), "B", "Batch", 8),
        (range(24, 31), "A", "Batch", 8),
        ((31,), "B", "Dummy", 0), (range(32, 36), "B", "Batch", 8),
        (range(36, 39), "A", "Batch", 8),
        ((39, 40), "B", "Batch", 8),
    ]:
        for n in nums:
            m[n] = Msg(sender, kind, arg)
    for idx, n in enumerate(range(18, 22)):
        m[n] = Msg("A", "Fragment", idx)
    return dict(sorted(m.items()))


MESSAGES = _messages()
assert list(MESSAGES) == list(range(1, 41))


def msg_name(n: int) -> str:
    return f"m{n:02d}"


def other(party: str) -> str:
    return "B" if party == "A" else "A"


def describe(n: int) -> str:
    m = MESSAGES[n]
    if m.kind == "Batch":
        return f"Batch L={m.arg}"
    if m.kind == "Fragment":
        return f"Fragment idx {m.arg} of {KEYCHANGE_TOTAL} (KeyChange)"
    if m.kind == "RouteUpdate":
        return "RouteUpdate (1 RelayQueue)"
    return m.kind


# Stream-derived fields of each content kind, in stream order (name, length).
KEYCHANGE_STREAM = [("old_ik_mldsa_xi", 32), ("old_ik_ed_seed", 32), ("new_ik_mldsa_xi", 32),
                    ("new_ik_ed_seed", 32), ("new_ik_dh_sk", 32), ("rnd", 32), ("msg_id", 16)]
ROUTE_STREAM = [("relay_fp", 32), ("onion_seed", 32), ("akc", 32), ("sid", 16), ("send_seed", 32)]
ROUTE_PERIOD = 20                                 # as the encodings row rd_relayqueue (SCHEMA §4.8)


class _Recorder:
    """A case stream handed out as randomness; records every draw, in order."""

    def __init__(self, stream):
        self.stream, self.draws = stream, []

    def take(self, n):
        b = self.stream.take(n)
        self.draws.append(b)
        return b


class _Buffer:
    """Randomness from bytes already drawn from the stream, front to back."""

    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        out = self.data[self.pos: self.pos + n]
        if len(out) != n:
            raise ValueError("buffer exhausted")
        self.pos += n
        return out


def _named(draws, layout, what):
    if [len(d) for d in draws] != [n for _, n in layout]:
        raise TableMismatch(f"{what}: draws of {[len(d) for d in draws]} B, expected {[n for _, n in layout]}")
    return {name: d for (name, _), d in zip(layout, draws)}


def _content_value(seq, ctype, body, ts=None):
    v = {"ver": enc.PROTO_VER, "type": ctype, "seq": seq, "ts": TS_BASE + seq if ts is None else ts,
         "body_len": 0, "body": body}
    enc.refresh("Content", v)
    enc.encode("Content", v)                      # a valid Content (the M2 decoder agrees), else ValueError
    return v


class KeyChange(NamedTuple):
    msg_id: bytes
    reassembled: bytes                            # 0x05 ‖ KeyChange (5391 B)
    old_pk_ed: bytes
    old_pk_mldsa: bytes

    def chunk(self, idx):
        return self.reassembled[idx * FRAGMENT_CHUNK: (idx + 1) * FRAGMENT_CHUNK]


def _keychange(s) -> tuple[dict, KeyChange]:
    """§7.6 KeyChange = new IKSPublic ‖ HybridSign(old IK_sig, "SecMP-TR/1 keychange", fingerprint(new))."""
    d = {name: s.take(n) for name, n in KEYCHANGE_STREAM}
    old_pk_ed, old_pk_mldsa, old_sk_mldsa = hybridsign.keygen(d["old_ik_ed_seed"], d["old_ik_mldsa_xi"])
    new_iks = identity.iks_public_from_seeds(d["new_ik_ed_seed"], d["new_ik_mldsa_xi"], d["new_ik_dh_sk"])
    fp = identity.fingerprint(new_iks)
    sig = hybridsign.sign(d["old_ik_ed_seed"], old_sk_mldsa, labels.TR_KEYCHANGE, fp, d["rnd"])
    hybridsign.verify(old_pk_ed, old_pk_mldsa, labels.TR_KEYCHANGE, fp, sig)
    reassembled = bytes([enc.CT_KEYCHANGE]) + new_iks + sig
    enc.decode("FragmentPayload", reassembled)
    return d, KeyChange(d["msg_id"], reassembled, old_pk_ed, old_pk_mldsa)


def _content(n, s, ctx) -> tuple[dict, bytes]:
    """→ (the stream-derived fields in stream order, the unpadded encoded Content)."""
    m = MESSAGES[n]
    if m.kind == "Batch":
        msg_id, payload = s.take(16), s.take(m.arg)
        fields = {"msg_id": msg_id, "payload": payload}
        body = {"count": 1, "messages": [{"msg_id": msg_id, "kind": 1, "expire_after": 0,
                                          "payload_len": m.arg, "payload": payload}]}
        v = _content_value(n, enc.CT_BATCH, body)
    elif m.kind == "Dummy":
        fields, v = {}, _content_value(n, enc.CT_DUMMY, b"")
    elif m.kind == "RouteUpdate":
        rec = _Recorder(s)
        route = ec._route(("rq", ROUTE_PERIOD, False))(rec)     # exactly the encodings row rd_relayqueue
        fields = _named(rec.draws, ROUTE_STREAM, msg_name(n))
        v = _content_value(n, enc.CT_ROUTEUPDATE, {"count": 1, "routes": [route]})
    else:                                         # Fragment idx of the KeyChange
        if m.arg == 0:
            fields, ctx["keychange"] = _keychange(s)
        else:
            fields = {}
        kc = ctx["keychange"]
        body = {"msg_id": kc.msg_id, "idx": m.arg, "total": KEYCHANGE_TOTAL, "chunk": kc.chunk(m.arg)}
        v = _content_value(n, enc.CT_FRAGMENT, body)
    return fields, enc.payload("Content", v)


ADVANCE_CONTENT = enc.payload("Content", _content_value(0, enc.CT_DUMMY, b"", ts=0))   # reading: seq 0, ts 0


# ---------------------------------------------------------------------------------------------
# Negative events (brief REF-M3, N1 … N13). The honest cell of the base message is the base; a
# header that must be well-formed is re-sealed with the sender's header key under the cell's own
# hdr_nonce, and the body is left unchanged.


class Sent(NamedTuple):
    i: int                                        # the send case
    cell: bytes
    header: dict                                  # the HeaderV1 value the cell carries
    hk: bytes                                     # the sender's hk_s it was sealed under
    sb: bytes
    content: bytes


def _reseal(base: Sent, header=None, sb=None) -> bytes:
    hdr_nonce, _, body = tr.split(base.cell)
    data = enc.raw("HeaderV1", base.header if header is None else header)
    ad = labels.TR_HDR + (base.sb if sb is None else sb)
    return hdr_nonce + primitives.xchacha20poly1305_seal(base.hk, hdr_nonce, ad, data) + body


def _flip_ct(s, base, rx, inputs):
    return _reseal(base, {**base.header, "ct_pq": flip(base.header["ct_pq"], 0)})


def _n2(s, base, rx, inputs):
    inputs["ek_pq_seed"] = s.take(sizes.MLKEM_SEED)
    return _reseal(base, {**base.header, "ek_pq": tr.KemKey.from_seed(inputs["ek_pq_seed"]).ek})


def _n9(s, base, rx, inputs):
    if base.hk != rx.nhk_r:                       # SQ-23: the key the receiver tries as nhk_r
        raise TableMismatch("N9: m16 is not sealed under the receiver's nhk_r")
    return _reseal(base, {**base.header, "dh_pk": rx.dh_r})


def _n10(s, base, rx, inputs):
    if base.hk != rx.hk_r:
        raise TableMismatch("N10: m14 is not sealed under the receiver's hk_r")
    return _reseal(base, {**base.header, "n": rx.n_r + tr.MAX_FF + 1})


class Neg(NamedTuple):
    manipulation: str
    base: int                                     # the message whose honest cell is the base
    build: object                                 # (stream, base Sent, receiver state, inputs) → cell
    rule: str                                     # the check of the reference Decrypt that fires
    text: str


NEGATIVES = {
    "N1": Neg("bad-kem-ct", 4, _flip_ct, "body-mac",
              "m04's header re-sealed under B's hk_s with `ct_pq` bit 0 flipped; body unchanged. A steps "
              "(DHRatchet runs on the working copy, implicit-rejection KEM secret), the body MAC fails (§7.4 note (b))"),
    "N2": Neg("kem-changed-mid-chain-ek", 2, _n2, "kem-constancy",
              "m02's header re-sealed under A's hk_s with `ek_pq` := the ek of ek_pq_seed (64, stream); it opens "
              "under hk_r, the constancy check rejects"),
    "N3": Neg("kem-changed-mid-chain-ct", 2, _flip_ct, "kem-constancy", "m02's header re-sealed under A's hk_s with `ct_pq` bit 0 flipped; opens under hk_r, the "
              "constancy check rejects"),
    "N4": Neg("replay-current", 3, lambda s, b, rx, i: b.cell, "replay",
              "m03 again: opens under hk_r, `n` = 2 < n_r = 3"),
    "N5": Neg("replay-skipped", 7, lambda s, b, rx, i: b.cell, "replay",
              "m07 again, after its skipped key was consumed: opens under hk_r, `n` = 0 < n_r = 4"),
    "N6": Neg("truncated", 14, lambda s, b, rx, i: drop_last(b.cell), "cell-length",
              "m14 without its last byte (4095 B)"),
    "N7": Neg("trailing", 14, lambda s, b, rx, i: append_zero(b.cell), "cell-length",
              "m14 with one 0x00 appended (4097 B)"),
    "N8": Neg("wrong-sb", 14, lambda s, b, rx, i: _reseal(b, sb=flip(b.sb, 0)), "no-header-key",
              "m14's header re-sealed under A's hk_s with `sb` bit 0 flipped in the header AD; no key opens it"),
    "N9": Neg("step-without-new-dh", 16, _n9, "step-same-dh",
              "m16's header with `dh_pk` := A's dh_r (the old key), `pn`, `n`, `ek_pq`, `ct_pq` as m16, re-sealed "
              "under the sender's current `hk_s` (the key the receiver opens with `nhk_r`; SQ-23); opens under "
              "nhk_r, rejected before any KDF"),
    "N10": Neg("gap-over-max-ff", 14, _n10, "max-ff",
               "m14's header with `n` := n_r + 2^20 + 1 = 1048578 (B's n_r = 1), re-sealed under A's hk_s (m14's chain "
               "key = B's hk_r); rejected before any KDF"),
    "N11": Neg("flags-nonzero", 3, lambda s, b, rx, i: _reseal(b, {**b.header, "flags": 1}), "header-decode",
               "m03's header re-sealed under A's hk_s with `flags` = 0x01; opens under hk_r, HeaderV1 decoding rejects"),
    "N12": Neg("body-tag-flip", 17, lambda s, b, rx, i: flip(b.cell, -1), "body-mac",
               "m17 with bit 0 of its last byte (the body tag) flipped"),
    "N13": Neg("hdr-nonce-flip", 17, lambda s, b, rx, i: flip(b.cell, 0), "no-header-key",
               "m17 with bit 0 of byte 0 (the hdr_nonce) flipped; no key opens the header"),
}

# ---------------------------------------------------------------------------------------------
# The transcript. Within a phase the sender's `send` events come first, in send order, then the
# deliveries in delivery order; phases 5 and 9 interleave as the brief writes them. A negative event
# sits immediately before (or after) the delivery the brief names.

INIT_STREAM = [("sk", 32), ("sb", 32), ("spk_dh_sk", 32), ("rpk_kem_seed", 64)]
INIT_DRAWS = [("dh_s_sk", 32), ("kem_s_seed", 64), ("m", 32)]
STEP_DRAWS = [("dh_sk", 32), ("kem_seed", 64), ("m", 32)]


def _sends(ns):
    return [("send", n) for n in ns]


PHASES = (
    (0, "initialisation", [("init",)]),
    (1, "A→B m01 Batch L=100, m02 Dummy, m03 Batch L=500; delivered in order (B steps on m01)",
     [*_sends((1, 2, 3)), ("recv", 1, "step"), ("reject", "N2"), ("reject", "N3"), ("recv", 2),
      ("reject", "N11"), ("recv", 3), ("reject", "N4")]),
    (2, f"B→A m04 Batch L=100, m05 Batch L={BATCH_MAX_L} (SQ-22), m06 Dummy; in order (A steps on m04) — round trip 1",
     [*_sends((4, 5, 6)), ("reject", "N1"), ("recv", 4, "step"), ("recv", 5), ("recv", 6)]),
    (3, "A→B m07–m10 Batch L=64; delivered m09, m07, m10, m08 (B steps on m09)",
     [*_sends(range(7, 11)), ("recv", 9, "step"), ("recv", 7), ("recv", 10), ("recv", 8), ("reject", "N5")]),
    (4, "B→A m11–m13 Batch L=32; m11 is not delivered now; A receives m12 (a step on a non-first message of the "
        "chain, §7.4 note (d)), then m13 — round trip 2",
     [*_sends((11, 12, 13)), ("recv", 12, "step"), ("recv", 13)]),
    (5, "A→B m14 Batch L=16, delivered; advance A 10000; A→B m15 Batch L=16, delivered (B fast-forwards 10 000 "
        "positions and stores 256 keys)",
     [("send", 14), ("reject", "N6"), ("reject", "N7"), ("reject", "N8"), ("recv", 14, "step"),
      ("advance", "A", 10000), ("send", 15), ("reject", "N10"), ("recv", 15)]),
    (6, "B→A m16, m17 Batch L=200; in order (A steps on m16)",
     [*_sends((16, 17)), ("reject", "N9"), ("recv", 16, "step"), ("reject", "N12"), ("reject", "N13"), ("recv", 17)]),
    (7, "A→B m18–m21 = the four Fragments of one KeyChange; in order (B steps on m18)",
     [*_sends(range(18, 22)), ("recv", 18, "step"), ("recv", 19), ("recv", 20), ("recv", 21)]),
    (8, "B→A m22 RouteUpdate, m23 Batch L=8; in order (A steps on m22)",
     [*_sends((22, 23)), ("recv", 22, "step"), ("recv", 23)]),
    (9, "advance A 300; A→B m24–m30 Batch L=8; delivered m24 (B steps, stores 256 keys → 512), m26 (513 → the "
        "earliest-inserted entry, from the phase-5 chain, is evicted → 512), m25, m28, m27, m30, m29",
     [("advance", "A", 300), *_sends(range(24, 31)), ("recv", 24, "step"),
      *[("recv", n) for n in (26, 25, 28, 27, 30, 29)]]),
    (10, "B→A m31 Dummy, m32–m35 Batch L=8; delivered m33 (A steps, stores keys for n = 0, 1), m31, m32, m35, m34",
     [*_sends(range(31, 36)), ("recv", 33, "step"), *[("recv", n) for n in (31, 32, 35, 34)]]),
    (11, "A→B m36–m38 Batch L=8; in order (B steps on m36)",
     [*_sends(range(36, 39)), ("recv", 36, "step"), ("recv", 37), ("recv", 38)]),
    (12, "B→A m39, m40 Batch L=8; in order (A steps on m39)",
     [*_sends((39, 40)), ("recv", 39, "step"), ("recv", 40)]),
    (13, "late delivery: A receives m11 (its key is in `skipped` under the header key of the chain m11–m13; the "
         "distinct-hk loop of §7.4 step 1 finds it)",
     [("recv", 11)]),
)

EVENTS = [(phase, ev) for phase, _, evs in PHASES for ev in evs]


class Run(NamedTuple):
    cases: list
    rows: list                                    # per event: the facts the SCHEMA table shows
    enc_log: list                                 # (label, mk) for every encryption, in order
    dec_log: list                                 # (msg, mk) for every decryption, in order
    states: dict                                  # the final states of A and B
    keychange: KeyChange
    sent: dict


def _delta(before: dict, after: dict):
    return len(after.keys() - before.keys()), len(before.keys() - after.keys())


@functools.lru_cache(maxsize=1)
def run() -> Run:
    st, sent, ctx = {}, {}, {}
    enc_log, dec_log, cases, rows = [], [], [], []
    for i, (phase, ev) in enumerate(EVENTS, start=1):
        s = CaseStream(SUITE, i)
        op = "recv-reject" if ev[0] == "reject" else ev[0]
        row = {"i": i, "id": case_id(SUITE, i), "phase": phase, "op": op}

        if op == "init":
            inputs = {name: s.take(n) for name, n in INIT_STREAM}
            spk, rpk = tr.DhKey.from_secret(inputs["spk_dh_sk"]), tr.KemKey.from_seed(inputs["rpk_kem_seed"])
            rec = _Recorder(s)
            st["A"] = tr.init_initiator(inputs["sk"], inputs["sb"], spk.pk, rpk.ek, rec)
            st["B"] = tr.init_responder(inputs["sk"], inputs["sb"], spk, rpk)
            inputs.update(_named(rec.draws, INIT_DRAWS, "init"))
            cases.append(Case(i, "init", inputs, {"state_post_A": state_digest(st["A"]),
                                                  "state_post_B": state_digest(st["B"])}, {"party": "AB"}))
            row.update(party="AB")

        elif op == "send":
            n = ev[1]
            party = MESSAGES[n].sender
            state = st[party]
            pre = state_digest(state)
            fields, content = _content(n, s, ctx)
            header, hk = tr.header_value(state), state.hk_s
            rec, mks = _Recorder(s), []
            cell = tr.encrypt(state, content, rec, mks)
            inputs = {**fields, **_named(rec.draws, [("hdr_nonce", tr.HDR_NONCE)], msg_name(n)), "content": content}
            if tr.open_header(state.sb, hk, *tr.split(cell)[:2]) != header:
                raise TableMismatch(f"{msg_name(n)}: the cell does not carry its header")
            enc_log.append((msg_name(n), mks[0]))
            sent[n] = Sent(i, cell, header, hk, state.sb, content)
            cases.append(Case(i, "send", inputs, {"cell": cell, "state_pre": pre, "state_post": state_digest(state)},
                              {"party": party, "msg": msg_name(n)}))
            row.update(party=party, msg=msg_name(n), content=describe(n), pn=header["pn"], n=header["n"],
                       content_len=len(content), skipped=len(state.skipped))

        elif op == "recv":
            n = ev[1]
            party = other(MESSAGES[n].sender)
            state = st[party]
            pre, before = state_digest(state), dict(state.skipped)
            rec, mks = _Recorder(s), []
            try:
                plaintext = tr.decrypt(state, sent[n].cell, rec, mks)
            except Reject:
                raise TableMismatch(f"{msg_name(n)}: rejected at {tr.last_rule}") from None
            if bool(rec.draws) != ("step" in ev):
                raise TableMismatch(f"{msg_name(n)}: DH step {bool(rec.draws)}, table says {'step' in ev}")
            inputs = _named(rec.draws, STEP_DRAWS, msg_name(n)) if rec.draws else {}
            content = enc.payload("Content", enc.decode("Content", plaintext))
            if content != sent[n].content:
                raise TableMismatch(f"{msg_name(n)}: content differs from the sender's")
            dec_log.append((msg_name(n), mks[0]))
            inserted, removed = _delta(before, state.skipped)
            cases.append(Case(i, "recv", inputs, {"content": content, "state_pre": pre, "state_post": state_digest(state)},
                              {"party": party, "msg": msg_name(n), "from": case_id(SUITE, sent[n].i)}))
            row.update(party=party, msg=msg_name(n), frm=case_id(SUITE, sent[n].i), content=describe(n),
                       pn=sent[n].header["pn"], n=sent[n].header["n"], step="step" in ev,
                       skipped=len(state.skipped), inserted=inserted, removed=removed,
                       via=_path(before, state, sent[n]))

        elif op == "advance":
            party, count = ev[1], ev[2]
            state = st[party]
            pre, first = state_digest(state), state.n_s
            nonces = s.take(tr.HDR_NONCE * count)
            rng, mks = _Buffer(nonces), []
            for _ in range(count):
                tr.encrypt(state, ADVANCE_CONTENT, rng, mks)
            enc_log.extend(("advance", mk) for mk in mks)
            cases.append(Case(i, "advance", {"hdr_nonces": nonces}, {"state_pre": pre, "state_post": state_digest(state)},
                              {"party": party, "count": count}))
            row.update(party=party, count=count, pn=state.pn, n=f"{first}–{state.n_s - 1}", skipped=len(state.skipped))

        else:                                     # recv-reject
            name = ev[1]
            neg = NEGATIVES[name]
            base = sent[neg.base]
            party = other(MESSAGES[neg.base].sender)
            state = st[party]
            pre = state_bytes(state)
            inputs = {}
            cell = neg.build(s, base, state, inputs)
            rec = _Recorder(s)
            try:
                tr.decrypt(state, cell, rec)
            except Reject:
                pass
            else:
                raise TableMismatch(f"{name}: accepted")
            if tr.last_rule != neg.rule:
                raise TableMismatch(f"{name}: rejected at {tr.last_rule}, table says {neg.rule}")
            if state_bytes(state) != pre:
                raise TableMismatch(f"{name}: the rejection changed the state")
            if rec.draws:
                inputs.update(_named(rec.draws, STEP_DRAWS, name))
            inputs["cell"] = cell
            digest = primitives.sha256(pre)
            cases.append(Case(i, "recv-reject", inputs, {"state_pre": digest, "state_post": digest},
                              {"party": party, "msg": msg_name(neg.base), "from": case_id(SUITE, base.i),
                               "manipulation": neg.manipulation, "expect": "reject"}))
            row.update(party=party, msg=msg_name(neg.base), frm=case_id(SUITE, base.i), neg=name,
                       manipulation=neg.manipulation, rule=neg.rule, cell_len=len(cell), skipped=len(state.skipped),
                       drew=bool(rec.draws))
        rows.append(row)

    _check_message_keys(enc_log, dec_log)
    return Run(cases, rows, enc_log, dec_log, st, ctx["keychange"], sent)


def _path(before: dict, state: tr.RatchetState, sent_msg: Sent) -> str:
    """How the message was decrypted: from `skipped` (§7.4 step 1) or on a chain (step 2)."""
    key = (sent_msg.hk, sent_msg.header["n"])
    return "skipped" if key in before and key not in state.skipped else "chain"


def _check_message_keys(enc_log, dec_log):
    """No message key encrypts twice or decrypts twice, and each decryption uses its own message's key."""
    enc_mks = [mk for _, mk in enc_log]
    dec_mks = [mk for _, mk in dec_log]
    if len(set(enc_mks)) != len(enc_mks) or len(set(dec_mks)) != len(dec_mks):
        raise TableMismatch("a message key was used twice")
    own = {label: mk for label, mk in enc_log if label != "advance"}
    for label, mk in dec_log:
        if own[label] != mk:
            raise TableMismatch(f"{label}: decrypted with another message's key")


def tr_cases() -> list[Case]:
    return run().cases
