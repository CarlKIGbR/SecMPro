# SPDX-License-Identifier: AGPL-3.0-or-later
"""Byte layouts of spec Appendix D: an encoder and a decoder per structure (spec §4.1, App. B, D).

Values. A value is a dict holding a structure's wire fields in Appendix D order, under Appendix D's
names (SCHEMA §4.8 names the few fields Appendix D leaves unnamed). u8 … u64 fields are ints, except
the frame opcode `op` and the LINK_GET `mode`, which are names (SCHEMA §1: `op`/`mode` are JSON
strings); byte fields are bytes, a nested structure is a dict, a repeated field is a list. Length and
count fields, presence bytes, `ver` and type bytes are fields like any other; padding is not a field.
An optional field is in the dict iff it is on the wire.

    decode(structure, data, context=None) -> value    the uniform Reject on any defect
    encode(structure, value, context=None) -> bytes   the canonical encoding (ValueError unless valid)
    raw(structure, value) -> bytes                    fields written literally, padded, no checks
    refresh(structure, value)                         recompute every length and count field

`raw` and `refresh` exist to build negative vectors. The decoders are written by hand from App. D;
`raw` is driven by a field list per structure. `decode` re-encodes what it accepted with `raw` and
requires the input back, so the two paths check each other and every accepted encoding is canonical
(§4.1: "decode-then-encode reproduces the input byte-for-byte").

What decoding checks is the decoding contract D-1 … D-13 of SCHEMA §4.8 (SCHEMA-4.8-encodings.md),
cited below; it includes the reviewer's answers to SQ-12 … SQ-19 (ref/SPEC-QUESTIONS.md, ADR-039).
"""

import hashlib

from . import hybridkem, labels, primitives, sizes
from .errors import Reject

# ---------------------------------------------------------------------------------------------
# Constants (App. B, App. D, §4.2) — each composite size is re-derived from its layout here.

PROTO_VER = 0x01                                  # §4.1 / §4.2 PROTO_VER
PERIODS = (10, 20, 40, 80)                        # §4.2 PERIODS (tunable until M6, ADR-018)

# D.1 records
REC_HELLO, REC_RELAYINFO, REC_HS1, REC_HS2 = 0x01, 0x02, 0x03, 0x04
HELLO_MAGIC = b"SECMP"
HELLO_BODY = 1 + len(HELLO_MAGIC) + 1
RELAYINFO_BODY = 1 + sizes.RELAY_INFO
HS1_BODY = 1 + sizes.HS1
HS2_BODY = 1 + sizes.HS2
assert HELLO_BODY == 7                                                               # D.1 "(7 B)"
assert (1 + 32 + 4 + sizes.X25519_PK + sizes.MLKEM1024_EK + 32 + 8 + sizes.ED25519_SIG
        == sizes.RELAY_INFO == 1741)                                                 # D.1 / App. B
assert (1 + 4 + sizes.X25519_PK + sizes.MLKEM768_EK + sizes.X25519_PK + sizes.MLKEM1024_CT
        + sizes.HMAC_TAG == sizes.HS1 == 2853)                                       # D.1 / App. B
assert 1 + sizes.X25519_PK + sizes.MLKEM768_CT + sizes.HMAC_TAG == sizes.HS2 == 1153  # D.1 / App. B

# D.2 frame plaintext
FRAME_PLAINTEXT = sizes.FRAME_PLAINTEXT
assert FRAME_PLAINTEXT == sizes.FRAME - sizes.AEAD_TAG == 4336                       # §8.4 / App. B
REQUEST_OPS = {"QUEUE_NEW": 0x01, "SEND": 0x03, "FETCH": 0x04, "FETCH_MULTI": 0x05,
               "QUEUE_DEL": 0x06, "LINK_PUT": 0x07, "LINK_GET": 0x08, "PING": 0x09, "CONT": 0x7F}
OP_SKEY = 0x02                                    # D.2 "(reserved, v1 relay answers ERR_MALFORMED)"
LINK_GET_MODES = {"consume": 0, "owner-status": 1}  # D.2 / §9.3 "mode u8 (0 = consume, 1 = owner status)"
RESPONSE_OPS = {"OK": 0x80, "OK_QUEUE_NEW": 0x81, "OK_SEND": 0x82, "CELLR": 0x83, "LINKR": 0x84,
                "ERR": 0x8F, "CONT": 0xFF}
ERR_CODES = range(1, 8)                           # D.2 ERR: 1 TOKEN … 7 RATE
CELLR_PRESENT_MAX = 4                             # D.2 CELLR: 0 dummy, 1 cell, 2–4 errors
FETCH_MULTI_MAX = 32                              # D.2 "count u8 (1..=32)"
LINK_PART_FIRST, LINK_PART_CONT = 4160, 4100      # D.2 LINK_PUT / LINKR / CONT
CONT_IDX = (1, 2)
assert LINK_PART_FIRST + 2 * LINK_PART_CONT == sizes.LINK_BLOB == 12360              # D.2 / App. B
# Largest payloads fit in front of at least the 0x80 marker:
assert 1 + 4 + 16 + 1 + 4 + 32 + 32 + 64 + LINK_PART_FIRST < FRAME_PLAINTEXT          # LINK_PUT 4314
assert 1 + 4 + 1 + 16 + 8 + sizes.CELL < FRAME_PLAINTEXT                              # CELLR 4126
assert 1 + 4 + 1 + FETCH_MULTI_MAX * (16 + 8 + 64) < FRAME_PLAINTEXT                  # FETCH_MULTI 2822
assert sizes.CELL + 240 + sizes.AEAD_TAG == sizes.FRAME                               # §4.2 FRAME_SIZE

# D.3
ONION_LEN = 35                                    # §5.3 "decoded 56-char address"
ONION_VERSION = 0x03                              # Tor rend-spec-v3 §6 (SQ-13 answer)
ONION_CHECKSUM_LABEL = b".onion checksum"         # Tor rend-spec-v3 §6, not a SecMP label
HOST_MAX = 253                                    # SQ-14 answer: host 1..=253 bytes of 0x21..=0x7E, port ≠ 0
NAME_MAX = 64                                     # §5.4 / D.3 "name (UTF-8, ≤ 64)"
INVITATION_KINDS = (0x01,)
INVITATION_KIND_MULTI = 0x02                      # §5.2 "reserved, v1 clients MUST reject"
RELAY_REF_NO_DIRECT = 1 + 32 + ONION_LEN + 32 + 1
assert (1 + 1 + RELAY_REF_NO_DIRECT + 16 + 32 + 32 + 16 + 32 + 2 + 8
        == sizes.INVITATION_NO_DIRECT == 241)                                        # App. B
assert 1 + sizes.ED25519_PK + sizes.MLDSA65_PK + sizes.X25519_PK == sizes.IKS_PUBLIC == 2017
assert (1 + 4 + sizes.X25519_PK + sizes.MLKEM1024_EK + sizes.MLKEM768_EK + 8 + 1 + 4
        + sizes.X25519_PK + sizes.MLKEM1024_EK + sizes.HYBRID_SIG == sizes.PREKEY_BUNDLE == 7775)
PROFILE_MAX = 1 + NAME_MAX + 1 + 32
assert 1 + sizes.IKS_PUBLIC + sizes.PREKEY_BUNDLE + PROFILE_MAX + 8 < sizes.LINKDATA_PADDED  # 9899 < 12288
assert (sizes.XCHACHA_NONCE + sizes.CAEAD_COM + sizes.LINKDATA_PADDED + sizes.AEAD_TAG
        == sizes.LINK_BLOB)                                                          # §5.4 12360

# D.4
HS_TOTAL = 3                                      # D.4 "total u8 (=3)"
HS_CHUNK = 4006
INNER = sizes.IKS_PUBLIC + sizes.CELL
INNER_CT = sizes.XCHACHA_NONCE + sizes.CAEAD_COM + INNER + sizes.AEAD_TAG
HS_CELL_PLAINTEXT = 16 + 1 + 1 + HS_CHUNK
assert INNER == 6113 and INNER_CT == 6185                                            # D.4
assert (1 + sizes.X25519_PK + 4 + 4 + sizes.MLKEM1024_CT + sizes.MLKEM1024_CT + INNER_CT
        == sizes.HS_OUTER == 9362)                                                   # D.4 / App. B
assert HS_TOTAL * HS_CHUNK == sizes.HS_OUTER_PADDED == 12018                         # D.4 / App. B
assert HS_CELL_PLAINTEXT == 4024                                                     # D.4
assert (sizes.XCHACHA_NONCE + sizes.CAEAD_COM + HS_CELL_PLAINTEXT + sizes.AEAD_TAG
        == sizes.CELL)                                                               # D.4 (4096)

# D.5
CT_DUMMY, CT_HANDSHAKE, CT_BATCH, CT_FRAGMENT, CT_ROUTEUPDATE, CT_KEYCHANGE, CT_RECEIPT, CT_CONTROL = range(8)
CONTENT_HEADER = 1 + 1 + 8 + 8 + 2
BODY_MAX = sizes.BODY_LEN - CONTENT_HEADER - 1    # one byte for the 0x80 marker
assert BODY_MAX == 1689                                                              # §7.6 "body ≤ 1689 B"
assert 1 + 1 + sizes.X25519_PK + 4 + 4 + sizes.MLKEM768_EK + sizes.MLKEM768_CT == sizes.HEADER == 2314
assert sizes.HEADER + sizes.AEAD_TAG == sizes.HDR_CT == 2330                          # §4.2 HDR_CT_LEN
assert sizes.XCHACHA_NONCE + sizes.HDR_CT + sizes.BODY_LEN + sizes.HMAC_TAG == sizes.CELL  # D.5
KEYCHANGE_BODY = sizes.IKS_PUBLIC + sizes.HYBRID_SIG
assert KEYCHANGE_BODY == 5390 > BODY_MAX                                             # §7.6 "always fragmented"
APPMESSAGE_KINDS = range(1, 7)                    # §7.6: 1 text … 6 delete
RECEIPT_KINDS = (1, 2)                            # §7.6: 1 delivered, 2 read
CONTROL_CODES = (1, 2)                            # §7.6: 1 contact-removed, 2 session-reset-request
FRAGMENTS_MIN, FRAGMENTS_MAX = 2, 64             # §7.6 "total: u16 (≤ 64)"; SQ-18 answer (2): total ≥ 2
FRAGMENT_HEADER = 16 + 2 + 2
assert FRAGMENTS_MAX * (BODY_MAX - FRAGMENT_HEADER) >= 1 + 1 + 16 + 1 + 4 + 2 + 65535  # MAX_MSG_BYTES fits
ROUTE_RELAYQUEUE = 0x01                           # §9.8 kind 0x01 (v1); other kinds are ignored
FRAGMENT_INNER_TYPES = (CT_BATCH, CT_ROUTEUPDATE, CT_KEYCHANGE, CT_RECEIPT, CT_CONTROL)   # SQ-18 answer (4)

# Curve25519 / edwards25519 (§3, §3.5; SQ-11)
P25519 = 2**255 - 19
MASK255 = (1 << 255) - 1
assert P25519 == primitives.ED25519_P
X25519_ORDER8 = (bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
                 bytes.fromhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"))
# The u-coordinates of the points of order dividing 8 on the curve and its twist: 0 (order 2),
# 1 and p − 1 (order 4), and the two order-8 points. X25519 of any clamped scalar with one of these
# is all-zero (tests/test_encodings.py checks each against libsodium).
X25519_LOW_ORDER_U = frozenset({0, 1, P25519 - 1, *(int.from_bytes(b, "little") for b in X25519_ORDER8)})


def x25519_low_order(pk: bytes) -> bool:
    """RFC 7748 §5 decoding (bit 255 masked, u reduced mod p) lands on a low-order u."""
    return (int.from_bytes(pk, "little") & MASK255) % P25519 in X25519_LOW_ORDER_U


def x25519_low_order_encodings() -> list[bytes]:
    """All 14 byte strings that decode to a low-order u: the five canonical values and the
    non-canonical p ≡ 0 and p + 1 ≡ 1, each with bit 255 clear and set."""
    out = []
    for u in sorted(X25519_LOW_ORDER_U):
        for v in (u, u + P25519):
            if v <= MASK255:
                out += [v.to_bytes(32, "little"), (v | 1 << 255).to_bytes(32, "little")]
    return out


def onion_checksum(pubkey: bytes, version: int = ONION_VERSION) -> bytes:
    """Tor rend-spec-v3 §6: CHECKSUM = SHA3-256(".onion checksum" ‖ PUBKEY ‖ VERSION)[:2]."""
    return hashlib.sha3_256(ONION_CHECKSUM_LABEL + pubkey + bytes([version])).digest()[:2]


def onion_from_pubkey(pubkey: bytes) -> bytes:
    """The 35-byte decoded v3 address PUBKEY ‖ CHECKSUM ‖ VERSION."""
    return pubkey + onion_checksum(pubkey) + bytes([ONION_VERSION])


# ---------------------------------------------------------------------------------------------
# Rejection. Reject carries no detail (errors.py). For the generator's self-checks only, the check
# that raised the most recent Reject is recorded in `last_rule`.

last_rule = None


def _fail(rule):
    global last_rule
    last_rule = rule
    raise Reject()


# ---------------------------------------------------------------------------------------------
# Reading


class _Reader:
    __slots__ = ("data", "pos", "end")

    def __init__(self, data: bytes, pos: int = 0, end: int | None = None):
        self.data, self.pos = data, pos
        self.end = len(data) if end is None else end

    def take(self, n: int) -> bytes:
        if self.end - self.pos < n:
            _fail("truncated")
        out = self.data[self.pos: self.pos + n]
        self.pos += n
        return out

    def uint(self, width: int) -> int:
        return int.from_bytes(self.take(width), "big")

    def sub(self, n: int) -> "_Reader":
        """A reader over the next n bytes (a length-delimited field); this one skips them."""
        if self.end - self.pos < n:
            _fail("truncated")
        r = _Reader(self.data, self.pos, self.pos + n)
        self.pos += n
        return r

    def rest(self) -> bytes:
        return self.take(self.end - self.pos)

    def done(self):
        if self.pos != self.end:
            _fail("trailing")


def _ver(x):                                      # D-2
    if x != PROTO_VER:
        _fail("ver")
    return x


def _bool(x):                                     # D-5
    if x not in (0, 1):
        _fail("bool")
    return x


def _period(x):                                   # D-8
    if x not in PERIODS:
        _fail("range")
    return x


def _x25519(pk):                                  # D-9
    if x25519_low_order(pk):
        _fail("x25519-low-order")
    return pk


def _ed_point(enc: bytes, what: str):
    """D-10: the §3.5 encoding rules on a 32-byte point encoding (y plus the sign bit of x)."""
    y = int.from_bytes(enc, "little") & MASK255
    if y >= P25519:
        _fail(f"ed25519-{what}-noncanonical")
    if y in primitives.ED25519_SMALL_ORDER_Y:
        _fail(f"ed25519-{what}-small-order")
    if _ed_recover_x(y, enc[31] >> 7) is None:
        _fail(f"ed25519-{what}-off-curve")        # SQ-12 answer (a)


_ED_D = -121665 * pow(121666, P25519 - 2, P25519) % P25519
_ED_SQRT_M1 = pow(2, (P25519 - 1) // 4, P25519)


def _ed_recover_x(y: int, sign: int):
    """RFC 8032 §5.1.3 steps 2–4 for a canonical y; None if the encoding is not a curve point."""
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, P25519 - 2, P25519) % P25519
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P25519 + 3) // 8, P25519)
    if (x * x - x2) % P25519:
        x = x * _ED_SQRT_M1 % P25519
    if (x * x - x2) % P25519:
        return None
    return x


def _ed_key(pk):                                  # D-10
    _ed_point(pk, "key")
    return pk


def _ed_sig(sig):                                 # D-10, on sig (64 B) or the first 64 B of a HybridSig
    _ed_point(sig[:32], "sig-R")
    if int.from_bytes(sig[32:64], "little") >= primitives.ED25519_L:
        _fail("ed25519-sig-S")
    return sig


def _mlkem_ek(ek, params):                        # D-11, SQ-12 answer (b): FIPS 203 §7.2 modulus check
    if not hybridkem.ek_input_check(params, ek):
        _fail("mlkem-ek")
    return ek


def _utf8(b):                                     # D-12
    try:
        b.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _fail("utf8")
    return b


def _count(n):                                    # SQ-17 answer: count u8 (1..=255)
    if n == 0:
        _fail("range")
    return n


def _check_pad(data: bytes, pos: int):            # D-4: ISO/IEC 7816-4
    if pos >= len(data) or data[pos] != 0x80 or any(data[pos + 1:]):
        _fail("pad")


# ---------------------------------------------------------------------------------------------
# Decoders, one per structure, each reading exactly its own fields from a _Reader.

def _d_relayinfo(r):
    v = {"ver": _ver(r.uint(1))}
    v["relay_sig_pk"] = _ed_key(r.take(sizes.ED25519_PK))
    v["kid"] = r.uint(4)
    v["relay_dh_pk"] = _x25519(r.take(sizes.X25519_PK))
    v["relay_kem_ek"] = _mlkem_ek(r.take(sizes.MLKEM1024_EK), hybridkem.HYBRIDKEM_1024)
    v["akc"] = r.take(32)
    v["valid_until"] = r.uint(8)
    v["sig"] = _ed_sig(r.take(sizes.ED25519_SIG))
    return v


def _record(rtype, body_len, body):
    """D.1 Record = len: u16 ‖ body, the body starting with its type byte."""
    def dec(r):
        n = r.uint(2)
        b = r.sub(n)
        t = b.uint(1)
        if t != rtype:
            _fail("type")
        if n != body_len:
            _fail("len")
        v = {"len": n, "type": t}
        body(b, v)
        b.done()
        return v
    return dec


def _b_hello(b, v):
    v["magic"] = b.take(len(HELLO_MAGIC))
    if v["magic"] != HELLO_MAGIC:
        _fail("magic")
    v["ver"] = _ver(b.uint(1))


def _b_relayinfo(b, v):
    v["relay_info"] = _d_relayinfo(b)


def _b_hs1(b, v):
    v["ver"] = _ver(b.uint(1))
    v["kid"] = b.uint(4)
    v["e_c"] = _x25519(b.take(sizes.X25519_PK))
    v["ek_c"] = _mlkem_ek(b.take(sizes.MLKEM768_EK), hybridkem.HYBRIDKEM_768)
    v["pk_e1"] = _x25519(b.take(sizes.X25519_PK))
    v["ct_kem"] = b.take(sizes.MLKEM1024_CT)
    v["mac1"] = b.take(sizes.HMAC_TAG)


def _b_hs2(b, v):
    v["ver"] = _ver(b.uint(1))
    v["e_r"] = _x25519(b.take(sizes.X25519_PK))
    v["ct_c"] = b.take(sizes.MLKEM768_CT)
    v["mac2"] = b.take(sizes.HMAC_TAG)


# D.2 request fields (after op ‖ cmd_seq)

def _q_queue_new(r, v):
    v["recv_pk"] = _ed_key(r.take(32))
    v["send_pk"] = _ed_key(r.take(32))
    v["token"] = r.take(32)
    v["sig"] = _ed_sig(r.take(64))


def _q_send(r, v):
    v["sid"] = r.take(16)
    v["cell"] = r.take(sizes.CELL)
    v["sig"] = _ed_sig(r.take(64))


def _q_fetch(r, v):
    v["rid"] = r.take(16)
    v["ack"] = r.uint(8)
    v["sig"] = _ed_sig(r.take(64))


def _q_fetch_multi(r, v):
    count = r.uint(1)
    if not 1 <= count <= FETCH_MULTI_MAX:
        _fail("range")
    v["count"] = count
    v["entries"] = []
    for _ in range(count):
        e = {"rid": r.take(16)}
        e["ack"] = r.uint(8)
        e["sig"] = _ed_sig(r.take(64))
        v["entries"].append(e)


def _q_queue_del(r, v):
    v["rid"] = r.take(16)
    v["sig"] = _ed_sig(r.take(64))


def _q_link_put(r, v):
    v["ld_id"] = r.take(16)
    v["one_time"] = _bool(r.uint(1))
    v["expires_bucket"] = r.uint(4)
    v["owner_pk"] = _ed_key(r.take(32))
    v["token"] = r.take(32)
    v["sig"] = _ed_sig(r.take(64))
    v["blob_part"] = r.take(LINK_PART_FIRST)


def _q_link_get(r, v):
    v["ld_id"] = r.take(16)
    mode = r.uint(1)
    if mode not in LINK_GET_MODES.values():
        _fail("range")
    v["mode"] = next(name for name, code in LINK_GET_MODES.items() if code == mode)
    sig = r.take(64)
    if mode == 0 and any(sig):
        _fail("reserved")                         # D.2 "sig[64] (zeros when mode = 0)"
    if mode == 1:
        _ed_sig(sig)
    v["sig"] = sig


def _q_ping(r, v):
    pass


def _cont(r, v):
    idx = r.uint(1)
    if idx not in CONT_IDX:
        _fail("range")
    v["idx"] = idx
    v["data"] = r.take(LINK_PART_CONT)


_REQUEST_FIELDS = {0x01: _q_queue_new, 0x03: _q_send, 0x04: _q_fetch, 0x05: _q_fetch_multi,
                   0x06: _q_queue_del, 0x07: _q_link_put, 0x08: _q_link_get, 0x09: _q_ping, 0x7F: _cont}
assert set(_REQUEST_FIELDS) == set(REQUEST_OPS.values())


_REQUEST_NAMES = {code: name for name, code in REQUEST_OPS.items()}
_RESPONSE_NAMES = {code: name for name, code in RESPONSE_OPS.items()}


def _d_request(r, context):
    op, cmd_seq = r.uint(1), r.uint(4)
    if op == OP_SKEY:
        _fail("reserved")
    if op not in _REQUEST_FIELDS:
        _fail("type")
    v = {"op": _REQUEST_NAMES[op], "cmd_seq": cmd_seq}
    _REQUEST_FIELDS[op](r, v)
    return v


# D.2 response fields

def _r_ok(r, v, context):
    pass


def _r_ok_queue_new(r, v, context):
    v["rid"] = r.take(16)
    v["sid"] = r.take(16)


def _r_ok_send(r, v, context):
    v["cell_id"] = r.uint(8)
    v["evicted_present"] = _bool(r.uint(1))
    v["evicted_id"] = r.uint(8)
    if v["evicted_present"] == 0 and v["evicted_id"] != 0:
        _fail("reserved")                         # D.2 "MUST be 0 when evicted_present = 0"


def _r_cellr(r, v, context):
    if context not in ("FETCH", "FETCH_MULTI"):
        raise ValueError("a CELLR is decoded as the response to FETCH or FETCH_MULTI (context)")
    present = r.uint(1)
    if present > CELLR_PRESENT_MAX:
        _fail("range")
    v["present"] = present
    v["rid"] = r.take(16)
    v["cell_id"] = r.uint(8)
    v["cell"] = r.take(sizes.CELL)
    if present == 0 and (any(v["rid"]) or v["cell_id"]):
        _fail("reserved")                         # "0 dummy (rid and cell_id zero, cell random)"
    if present >= 2 and v["cell_id"]:
        _fail("reserved")                         # "for 2–4: rid set, cell_id zero, cell random"
    if context == "FETCH" and present == 1 and any(v["rid"]):
        _fail("reserved")                         # "For FETCH, rid is zero on present 0/1."


def _r_linkr(r, v, context):
    v["present"] = _bool(r.uint(1))
    v["consumed"] = _bool(r.uint(1))
    v["blob_part"] = r.take(LINK_PART_FIRST)


def _r_err(r, v, context):
    code = r.uint(1)
    if code not in ERR_CODES:
        _fail("type")
    v["code"] = code


def _r_cont(r, v, context):
    _cont(r, v)


_RESPONSE_FIELDS = {0x80: _r_ok, 0x81: _r_ok_queue_new, 0x82: _r_ok_send, 0x83: _r_cellr,
                    0x84: _r_linkr, 0x8F: _r_err, 0xFF: _r_cont}
assert set(_RESPONSE_FIELDS) == set(RESPONSE_OPS.values())


def _d_response(r, context):
    op, cmd_seq = r.uint(1), r.uint(4)
    if op not in _RESPONSE_FIELDS:
        _fail("type")
    v = {"op": _RESPONSE_NAMES[op], "cmd_seq": cmd_seq}
    _RESPONSE_FIELDS[op](r, v, context)
    return v


# D.3

def _d_relayref(r):
    v = {"ver": _ver(r.uint(1))}
    v["relay_fp"] = r.take(32)
    v["onion"] = r.take(ONION_LEN)
    if v["onion"][34] != ONION_VERSION or v["onion"][32:34] != onion_checksum(v["onion"][:32]):
        _fail("onion")                            # SQ-13 answer (B)
    v["akc"] = r.take(32)
    v["direct_present"] = _bool(r.uint(1))
    if v["direct_present"]:
        v["host_len"] = r.uint(2)                 # SQ-14 answer (B)
        if not 1 <= v["host_len"] <= HOST_MAX:
            _fail("host")
        v["host"] = r.take(v["host_len"])
        if not all(0x21 <= c <= 0x7E for c in v["host"]):
            _fail("host")
        v["port"] = r.uint(2)
        if v["port"] == 0:
            _fail("host")
        v["spki_sha256"] = r.take(32)
    return v


def _d_invitation(r):
    v = {"ver": _ver(r.uint(1))}
    kind = r.uint(1)
    if kind == INVITATION_KIND_MULTI:
        _fail("reserved")
    if kind not in INVITATION_KINDS:
        _fail("type")
    v["kind"] = kind
    v["relay"] = _d_relayref(r)
    v["ld_id"] = r.take(16)
    v["link_key"] = r.take(32)
    v["inviter_fp"] = r.take(32)
    v["inv_sid"] = r.take(16)
    v["inv_send_seed"] = r.take(32)
    v["inv_period_s"] = _period(r.uint(2))
    v["expires"] = r.uint(8)
    return v


def _d_profile(r):
    n = r.uint(1)
    if n > NAME_MAX:
        _fail("len")
    v = {"name_len": n, "name": _utf8(r.take(n))}
    v["avatar_present"] = _bool(r.uint(1))
    if v["avatar_present"]:
        v["avatar_sha256"] = r.take(32)
    return v


def _d_iks(r):
    v = {"ver": _ver(r.uint(1))}
    v["ik_ed25519"] = _ed_key(r.take(sizes.ED25519_PK))
    v["ik_mldsa65"] = r.take(sizes.MLDSA65_PK)
    v["ik_dh"] = _x25519(r.take(sizes.X25519_PK))
    return v


def _d_bundle(r):
    v = {"ver": _ver(r.uint(1))}
    v["spk_id"] = r.uint(4)
    v["spk_dh"] = _x25519(r.take(sizes.X25519_PK))
    v["spk_kem"] = _mlkem_ek(r.take(sizes.MLKEM1024_EK), hybridkem.HYBRIDKEM_1024)
    v["rpk_kem"] = _mlkem_ek(r.take(sizes.MLKEM768_EK), hybridkem.HYBRIDKEM_768)
    v["spk_expiry"] = r.uint(8)
    v["opk_present"] = r.uint(1)
    if v["opk_present"] != 1:
        _fail("option")                           # §6.3 "MUST be 0x01 in v1"
    v["opk_id"] = r.uint(4)
    v["opk_dh"] = _x25519(r.take(sizes.X25519_PK))
    v["opk_kem"] = _mlkem_ek(r.take(sizes.MLKEM1024_EK), hybridkem.HYBRIDKEM_1024)
    v["sig"] = r.take(sizes.HYBRID_SIG)
    _ed_sig(v["sig"])
    return v


def _d_linkdata(r):
    v = {"ver": _ver(r.uint(1))}
    v["inviter_iks"] = _d_iks(r)
    v["bundle"] = _d_bundle(r)
    v["profile"] = _d_profile(r)
    v["created"] = r.uint(8)
    return v


# D.4

def _d_outer(r):
    v = {"ver": _ver(r.uint(1))}
    v["ek_I"] = _x25519(r.take(sizes.X25519_PK))
    v["spk_id"] = r.uint(4)
    v["opk_id"] = r.uint(4)
    v["ct_spk"] = r.take(sizes.MLKEM1024_CT)
    v["ct_opk"] = r.take(sizes.MLKEM1024_CT)
    v["inner_ct"] = r.take(INNER_CT)
    return v


def _d_inner(r):
    v = {"iks": _d_iks(r)}
    v["first_msg"] = r.take(sizes.CELL)
    return v


def _d_hs_cell_plaintext(r):
    v = {"init_id": r.take(16)}
    v["i"] = r.uint(1)
    v["total"] = r.uint(1)
    if v["total"] != HS_TOTAL or v["i"] >= HS_TOTAL:
        _fail("range")
    v["chunk"] = r.take(HS_CHUNK)
    return v


# D.5

def _d_header(r):
    v = {"ver": _ver(r.uint(1))}
    v["flags"] = r.uint(1)
    if v["flags"] != 0:
        _fail("reserved")                         # §7.5 "flags MUST be zero in v1 (reserved)"
    v["dh_pk"] = _x25519(r.take(sizes.X25519_PK))
    v["pn"] = r.uint(4)
    v["n"] = r.uint(4)
    v["ek_pq"] = _mlkem_ek(r.take(sizes.MLKEM768_EK), hybridkem.HYBRIDKEM_768)
    v["ct_pq"] = r.take(sizes.MLKEM768_CT)
    return v


def _d_appmessage(r):
    v = {"msg_id": r.take(16)}
    v["kind"] = r.uint(1)
    if v["kind"] not in APPMESSAGE_KINDS:
        _fail("type")
    v["expire_after"] = r.uint(4)
    v["payload_len"] = r.uint(2)
    v["payload"] = r.take(v["payload_len"])
    return v


def _d_batch(r):
    v = {"count": _count(r.uint(1))}
    v["messages"] = [_d_appmessage(r) for _ in range(v["count"])]
    return v


def _d_fragment(r):
    v = {"msg_id": r.take(16)}
    v["idx"] = r.uint(2)
    v["total"] = r.uint(2)
    if not FRAGMENTS_MIN <= v["total"] <= FRAGMENTS_MAX or v["idx"] >= v["total"]:
        _fail("range")                            # SQ-18 answer (1), (2): idx from 0, 2 ≤ total ≤ 64
    v["chunk"] = r.rest()
    if not v["chunk"]:
        _fail("len")                              # SQ-18 answer (3)
    return v


def _d_route(r):
    v = {"ver": _ver(r.uint(1))}
    v["kind"] = r.uint(1)
    v["len"] = r.uint(2)
    b = r.sub(v["len"])
    if v["kind"] == ROUTE_RELAYQUEUE:
        v["blob"] = _d_relayqueue(b)
        b.done()
    else:
        v["blob"] = b.rest()                      # §9.8 "v1 clients MUST ignore unknown kinds"
    return v


def _d_relayqueue(r):
    v = {"relay": _d_relayref(r)}
    v["sid"] = r.take(16)
    v["send_seed"] = r.take(32)
    v["period_s"] = _period(r.uint(2))
    return v


def _d_routeupdate(r):
    v = {"count": _count(r.uint(1))}
    v["routes"] = [_d_route(r) for _ in range(v["count"])]
    return v


def _d_handshake(r):
    v = {"profile": _d_profile(r)}
    v["caps"] = r.uint(4)
    if v["caps"] != 0:
        _fail("reserved")                         # SQ-15 answer (A)
    v["route_count"] = _count(r.uint(1))
    v["routes"] = [_d_route(r) for _ in range(v["route_count"])]
    return v


def _d_keychange(r):
    v = {"iks": _d_iks(r)}
    v["sig"] = r.take(sizes.HYBRID_SIG)
    _ed_sig(v["sig"])
    return v


def _d_receipt(r):
    v = {"kind": r.uint(1)}
    if v["kind"] not in RECEIPT_KINDS:
        _fail("type")
    v["count"] = _count(r.uint(1))
    v["msg_ids"] = [r.take(16) for _ in range(v["count"])]
    return v


def _d_control(r):
    v = {"code": r.uint(1)}
    if v["code"] not in CONTROL_CODES:
        _fail("type")
    v["arg_len"] = r.uint(2)
    v["arg"] = r.take(v["arg_len"])
    return v


def _d_dummy(r):
    if r.end != r.pos:
        _fail("len")                              # §7.6 "Dummy: empty body"
    return b""


# Content.type → the body structure (§7.6); used by Content and by the reassembled FragmentPayload.
BODY_STRUCTURE = {CT_HANDSHAKE: "HandshakeBody", CT_BATCH: "BatchBody", CT_FRAGMENT: "Fragment",
                  CT_ROUTEUPDATE: "RouteUpdateBody", CT_KEYCHANGE: "KeyChangeBody",
                  CT_RECEIPT: "ReceiptBody", CT_CONTROL: "ControlBody"}
_BODY_DECODERS = {CT_DUMMY: _d_dummy, CT_HANDSHAKE: _d_handshake, CT_BATCH: _d_batch,
                  CT_FRAGMENT: _d_fragment, CT_ROUTEUPDATE: _d_routeupdate,
                  CT_KEYCHANGE: _d_keychange, CT_RECEIPT: _d_receipt, CT_CONTROL: _d_control}


def _d_content(r):
    v = {"ver": _ver(r.uint(1))}
    v["type"] = r.uint(1)
    if v["type"] not in _BODY_DECODERS:
        _fail("type")
    v["seq"] = r.uint(8)
    v["ts"] = r.uint(8)
    v["body_len"] = r.uint(2)
    if v["body_len"] > BODY_MAX:
        _fail("len")
    b = r.sub(v["body_len"])
    v["body"] = _BODY_DECODERS[v["type"]](b)
    b.done()
    return v


def _d_fragment_payload(r):
    v = {"inner_type": r.uint(1)}
    if v["inner_type"] not in FRAGMENT_INNER_TYPES:
        _fail("type")                             # SQ-18 answer (4)
    v["inner_body"] = _BODY_DECODERS[v["inner_type"]](r)
    return v


# ---------------------------------------------------------------------------------------------
# Raw writing: a field list per structure. Kinds: an int width (big-endian integer), "b" (bytes),
# ("s", S) a nested structure, ("l", S) a list of structures, "lb" a list of byte strings, "op" and
# "mode" (a u8 given by its name, or by an int for a negative row), and the polymorphic "body"
# (Content), "inner" (FragmentPayload), "blob" (RouteDescriptor). A field missing from the value is
# not written (so a negative row can remove one).

_FRAME_HEAD = [("op", "op"), ("cmd_seq", 4)]
_IKS = [("ver", 1), ("ik_ed25519", "b"), ("ik_mldsa65", "b"), ("ik_dh", "b")]
_RELAYREF = [("ver", 1), ("relay_fp", "b"), ("onion", "b"), ("akc", "b"), ("direct_present", 1),
             ("host_len", 2), ("host", "b"), ("port", 2), ("spki_sha256", "b")]

SPEC = {
    # D.1
    "RelayInfoV1": [("ver", 1), ("relay_sig_pk", "b"), ("kid", 4), ("relay_dh_pk", "b"),
                    ("relay_kem_ek", "b"), ("akc", "b"), ("valid_until", 8), ("sig", "b")],
    "Record/HELLO": [("len", 2), ("type", 1), ("magic", "b"), ("ver", 1)],
    "Record/RELAYINFO": [("len", 2), ("type", 1), ("relay_info", ("s", "RelayInfoV1"))],
    "Record/HS1": [("len", 2), ("type", 1), ("ver", 1), ("kid", 4), ("e_c", "b"), ("ek_c", "b"),
                   ("pk_e1", "b"), ("ct_kem", "b"), ("mac1", "b")],
    "Record/HS2": [("len", 2), ("type", 1), ("ver", 1), ("e_r", "b"), ("ct_c", "b"), ("mac2", "b")],
    # D.2 requests
    "Request/QUEUE_NEW": _FRAME_HEAD + [("recv_pk", "b"), ("send_pk", "b"), ("token", "b"), ("sig", "b")],
    "Request/SEND": _FRAME_HEAD + [("sid", "b"), ("cell", "b"), ("sig", "b")],
    "Request/FETCH": _FRAME_HEAD + [("rid", "b"), ("ack", 8), ("sig", "b")],
    "Request/FETCH_MULTI": _FRAME_HEAD + [("count", 1), ("entries", ("l", "FetchMultiEntry"))],
    "FetchMultiEntry": [("rid", "b"), ("ack", 8), ("sig", "b")],
    "Request/QUEUE_DEL": _FRAME_HEAD + [("rid", "b"), ("sig", "b")],
    "Request/LINK_PUT": _FRAME_HEAD + [("ld_id", "b"), ("one_time", 1), ("expires_bucket", 4),
                                       ("owner_pk", "b"), ("token", "b"), ("sig", "b"), ("blob_part", "b")],
    "Request/LINK_GET": _FRAME_HEAD + [("ld_id", "b"), ("mode", "mode"), ("sig", "b")],
    "Request/PING": _FRAME_HEAD,
    "Request/CONT": _FRAME_HEAD + [("idx", 1), ("data", "b")],
    # D.2 responses
    "Response/OK": _FRAME_HEAD,
    "Response/OK_QUEUE_NEW": _FRAME_HEAD + [("rid", "b"), ("sid", "b")],
    "Response/OK_SEND": _FRAME_HEAD + [("cell_id", 8), ("evicted_present", 1), ("evicted_id", 8)],
    "Response/CELLR": _FRAME_HEAD + [("present", 1), ("rid", "b"), ("cell_id", 8), ("cell", "b")],
    "Response/LINKR": _FRAME_HEAD + [("present", 1), ("consumed", 1), ("blob_part", "b")],
    "Response/ERR": _FRAME_HEAD + [("code", 1)],
    "Response/CONT": _FRAME_HEAD + [("idx", 1), ("data", "b")],
    # D.3
    "RelayRef": _RELAYREF,
    "InvitationV1": [("ver", 1), ("kind", 1), ("relay", ("s", "RelayRef")), ("ld_id", "b"),
                     ("link_key", "b"), ("inviter_fp", "b"), ("inv_sid", "b"), ("inv_send_seed", "b"),
                     ("inv_period_s", 2), ("expires", 8)],
    "Profile": [("name_len", 1), ("name", "b"), ("avatar_present", 1), ("avatar_sha256", "b")],
    "LinkDataV1": [("ver", 1), ("inviter_iks", ("s", "IKSPublic")), ("bundle", ("s", "PrekeyBundle")),
                   ("profile", ("s", "Profile")), ("created", 8)],
    "LinkBlob": [("N", "b"), ("COM", "b"), ("ct", "b")],
    "IKSPublic": _IKS,
    "PrekeyBundle": [("ver", 1), ("spk_id", 4), ("spk_dh", "b"), ("spk_kem", "b"), ("rpk_kem", "b"),
                     ("spk_expiry", 8), ("opk_present", 1), ("opk_id", 4), ("opk_dh", "b"),
                     ("opk_kem", "b"), ("sig", "b")],
    # D.4
    "Outer": [("ver", 1), ("ek_I", "b"), ("spk_id", 4), ("opk_id", 4), ("ct_spk", "b"),
              ("ct_opk", "b"), ("inner_ct", "b")],
    "inner_ct": [("N2", "b"), ("COM", "b"), ("ct", "b")],
    "Inner": [("iks", ("s", "IKSPublic")), ("first_msg", "b")],
    "HandshakeCell": [("N_i", "b"), ("COM", "b"), ("ct", "b")],
    "HandshakeCellPlaintext": [("init_id", "b"), ("i", 1), ("total", 1), ("chunk", "b")],
    # D.5
    "Cell": [("hdr_nonce", "b"), ("hdr_ct", "b"), ("body_ct", "b"), ("tag", "b")],
    "HeaderV1": [("ver", 1), ("flags", 1), ("dh_pk", "b"), ("pn", 4), ("n", 4), ("ek_pq", "b"),
                 ("ct_pq", "b")],
    "Content": [("ver", 1), ("type", 1), ("seq", 8), ("ts", 8), ("body_len", 2), ("body", "body")],
    "AppMessage": [("msg_id", "b"), ("kind", 1), ("expire_after", 4), ("payload_len", 2), ("payload", "b")],
    "BatchBody": [("count", 1), ("messages", ("l", "AppMessage"))],
    "Fragment": [("msg_id", "b"), ("idx", 2), ("total", 2), ("chunk", "b")],
    "FragmentPayload": [("inner_type", 1), ("inner_body", "inner")],
    "RouteDescriptor": [("ver", 1), ("kind", 1), ("len", 2), ("blob", "blob")],
    "RelayQueue": [("relay", ("s", "RelayRef")), ("sid", "b"), ("send_seed", "b"), ("period_s", 2)],
    "RouteUpdateBody": [("count", 1), ("routes", ("l", "RouteDescriptor"))],
    "HandshakeBody": [("profile", ("s", "Profile")), ("caps", 4), ("route_count", 1),
                      ("routes", ("l", "RouteDescriptor"))],
    "KeyChangeBody": [("iks", ("s", "IKSPublic")), ("sig", "b")],
    "ReceiptBody": [("kind", 1), ("count", 1), ("msg_ids", "lb")],
    "ControlBody": [("code", 1), ("arg_len", 2), ("arg", "b")],
}

PAD_TO = {"LinkDataV1": sizes.LINKDATA_PADDED, "Outer": sizes.HS_OUTER_PADDED, "Content": sizes.BODY_LEN,
          **{s: FRAME_PLAINTEXT for s in SPEC if s.startswith(("Request/", "Response/"))}}

# Fixed sizes of the structures that have one (App. B, D); padded structures have their PAD_TO.
FIXED_SIZE = {"Record/HELLO": 2 + HELLO_BODY, "Record/RELAYINFO": 2 + RELAYINFO_BODY,
              "Record/HS1": 2 + HS1_BODY, "Record/HS2": 2 + HS2_BODY, "RelayInfoV1": sizes.RELAY_INFO,
              "LinkBlob": sizes.LINK_BLOB, "IKSPublic": sizes.IKS_PUBLIC, "PrekeyBundle": sizes.PREKEY_BUNDLE,
              "inner_ct": INNER_CT, "Inner": INNER, "HandshakeCell": sizes.CELL,
              "HandshakeCellPlaintext": HS_CELL_PLAINTEXT, "Cell": sizes.CELL, "HeaderV1": sizes.HEADER,
              "KeyChangeBody": KEYCHANGE_BODY, **PAD_TO}


def _poly_structure(kind, value, x):
    if kind == "body":
        return BODY_STRUCTURE[value["type"]]
    if kind == "inner":
        return BODY_STRUCTURE[value["inner_type"]]
    return "RelayQueue"                           # "blob": a dict blob is a RelayQueue


def _write(structure, v) -> bytes:
    spec = SPEC[structure]
    unknown = set(v) - {name for name, _ in spec}
    if unknown:
        raise ValueError(f"{structure}: unknown fields {sorted(unknown)}")
    out = bytearray()
    for name, kind in spec:
        if name not in v:
            continue
        x = v[name]
        if isinstance(kind, int):
            out += x.to_bytes(kind, "big")
        elif kind in ("op", "mode"):
            out.append(x if isinstance(x, int) else _code(structure, kind, x))
        elif kind == "b":
            out += x
        elif kind == "lb":
            out += b"".join(x)
        elif isinstance(kind, tuple):
            items = [x] if kind[0] == "s" else x
            out += b"".join(_write(kind[1], e) for e in items)
        else:                                     # polymorphic: bytes as they are, a dict by its type
            out += x if isinstance(x, bytes) else _write(_poly_structure(kind, v, x), x)
    return bytes(out)


def _code(structure, kind, name):
    if kind == "mode":
        return LINK_GET_MODES[name]
    return (REQUEST_OPS if structure.startswith("Request/") else RESPONSE_OPS)[name]


def iso_pad(payload: bytes, size: int) -> bytes:
    """ISO/IEC 7816-4: payload ‖ 0x80 ‖ 0x00… to `size` (§4.1)."""
    if len(payload) >= size:
        raise ValueError(f"payload of {len(payload)} B does not fit a {size}-byte padded structure")
    return payload + b"\x80" + bytes(size - len(payload) - 1)


def payload(structure: str, value: dict) -> bytes:
    """The fields written literally (for a padded structure: without the padding)."""
    return _write(structure, value)


def raw(structure: str, value: dict) -> bytes:
    """The fields written literally and, for a padded structure, padded. No checks."""
    data = _write(structure, value)
    return iso_pad(data, PAD_TO[structure]) if structure in PAD_TO else data


# Length and count fields: (field, what it counts). refresh() recomputes them bottom-up.
_LENGTHS = {
    "Record/HELLO": [("len", "record")], "Record/RELAYINFO": [("len", "record")],
    "Record/HS1": [("len", "record")], "Record/HS2": [("len", "record")],
    "RelayRef": [("host_len", "host")], "Profile": [("name_len", "name")],
    "Content": [("body_len", "body")], "AppMessage": [("payload_len", "payload")],
    "RouteDescriptor": [("len", "blob")], "ControlBody": [("arg_len", "arg")],
    "Request/FETCH_MULTI": [("count", "entries")], "BatchBody": [("count", "messages")],
    "RouteUpdateBody": [("count", "routes")], "HandshakeBody": [("route_count", "routes")],
    "ReceiptBody": [("count", "msg_ids")],
}


def refresh(structure: str, v: dict) -> None:
    """Recompute every length and count field of v (and of the structures nested in it) from the
    content, in place."""
    spec = dict(SPEC[structure])
    for name, x in v.items():
        kind = spec[name]
        if isinstance(kind, tuple):
            for e in ([x] if kind[0] == "s" else x):
                refresh(kind[1], e)
        elif kind in ("body", "inner", "blob") and isinstance(x, dict):
            refresh(_poly_structure(kind, v, x), x)
    for field, covered in _LENGTHS.get(structure, ()):
        if field not in v:
            continue
        if covered == "record":
            v[field] = len(_write(structure, v)) - 2
        elif covered in ("body", "blob") and isinstance(v.get(covered), dict):
            v[field] = len(_write(_poly_structure(covered, v, v[covered]), v[covered]))
        else:
            v[field] = len(v.get(covered, b""))


# ---------------------------------------------------------------------------------------------
# Top-level decoding

def _whole(fn):
    """A structure decoded from exactly the input (D-1)."""
    def dec(data, context):
        r = _Reader(data)
        v = fn(r)
        r.done()
        return v
    return dec


def _padded(size, fn):
    """A padded structure: exactly `size` bytes, the fields, then ISO/IEC 7816-4 padding (D-1, D-4)."""
    def dec(data, context):
        if len(data) != size:
            _fail("size")
        r = _Reader(data)
        v = fn(r, context)
        _check_pad(data, r.pos)
        return v
    return dec


def _opaque(structure):
    """A structure of opaque fixed-size fields: only its size is checked (D-13)."""
    widths = {"LinkBlob": (24, 32, sizes.LINKDATA_PADDED + sizes.AEAD_TAG),
              "inner_ct": (24, 32, INNER + sizes.AEAD_TAG),
              "HandshakeCell": (24, 32, HS_CELL_PLAINTEXT + sizes.AEAD_TAG),
              "Cell": (sizes.XCHACHA_NONCE, sizes.HDR_CT, sizes.BODY_LEN, sizes.HMAC_TAG)}[structure]
    names = [name for name, _ in SPEC[structure]]
    assert sum(widths) == FIXED_SIZE[structure]

    def dec(data, context):
        if len(data) != FIXED_SIZE[structure]:
            _fail("size")
        r = _Reader(data)
        return {name: r.take(w) for name, w in zip(names, widths)}
    return dec


def _frame(direction, name):
    decoder = _d_request if direction == "Request" else _d_response

    def fields(r, context):
        v = decoder(r, context)
        if v["op"] != name:
            _fail("type")                         # a valid frame, but not the named one
        return v
    return _padded(FRAME_PLAINTEXT, fields)


def _no_context(fn):
    return lambda r, context: fn(r)


DECODERS = {
    "Record/HELLO": _whole(_record(REC_HELLO, HELLO_BODY, _b_hello)),
    "Record/RELAYINFO": _whole(_record(REC_RELAYINFO, RELAYINFO_BODY, _b_relayinfo)),
    "Record/HS1": _whole(_record(REC_HS1, HS1_BODY, _b_hs1)),
    "Record/HS2": _whole(_record(REC_HS2, HS2_BODY, _b_hs2)),
    "RelayInfoV1": _whole(_d_relayinfo),
    **{f"Request/{n}": _frame("Request", n) for n in REQUEST_OPS},
    **{f"Response/{n}": _frame("Response", n) for n in RESPONSE_OPS},
    "RelayRef": _whole(_d_relayref),
    "InvitationV1": _whole(_d_invitation),
    "Profile": _whole(_d_profile),
    "LinkDataV1": _padded(sizes.LINKDATA_PADDED, _no_context(_d_linkdata)),
    "LinkBlob": _opaque("LinkBlob"),
    "IKSPublic": _whole(_d_iks),
    "PrekeyBundle": _whole(_d_bundle),
    "Outer": _padded(sizes.HS_OUTER_PADDED, _no_context(_d_outer)),
    "inner_ct": _opaque("inner_ct"),
    "Inner": _whole(_d_inner),
    "HandshakeCell": _opaque("HandshakeCell"),
    "HandshakeCellPlaintext": _whole(_d_hs_cell_plaintext),
    "Cell": _opaque("Cell"),
    "HeaderV1": _whole(_d_header),
    "Content": _padded(sizes.BODY_LEN, _no_context(_d_content)),
    "AppMessage": _whole(_d_appmessage),
    "BatchBody": _whole(_d_batch),
    "Fragment": _whole(_d_fragment),
    "FragmentPayload": _whole(_d_fragment_payload),
    "RouteDescriptor": _whole(_d_route),
    "RelayQueue": _whole(_d_relayqueue),
    "RouteUpdateBody": _whole(_d_routeupdate),
    "HandshakeBody": _whole(_d_handshake),
    "KeyChangeBody": _whole(_d_keychange),
    "ReceiptBody": _whole(_d_receipt),
    "ControlBody": _whole(_d_control),
}
assert set(DECODERS) == set(SPEC) - {"FetchMultiEntry"}


def decode(structure: str, data: bytes, context: str | None = None) -> dict:
    """The value encoded by `data`, or the uniform Reject (D-1 … D-13). Total: any other exception
    is a bug."""
    data = bytes(data)
    value = DECODERS[structure](data, context)
    if raw(structure, value) != data:
        _fail("noncanonical")                     # never reached if the decoders are right
    return value


# ---------------------------------------------------------------------------------------------
# D.6 signed messages (encode only: they are computed by both sides, never parsed)

SIGNED_FIELDS = {
    "QUEUE_NEW": [("recv_pk", "b"), ("send_pk", "b"), ("token", "b")],
    "SEND": [("sid", "b"), ("cell", "b")],
    "FETCH": [("rid", "b"), ("ack", 8)],
    "FETCH_MULTI": [("rid", "b"), ("ack", 8)],    # one entry; D.2: "each sig ... ‖rid‖ack"
    "QUEUE_DEL": [("rid", "b")],
    "LINK_PUT": [("ld_id", "b"), ("one_time", 1), ("expires_bucket", 4), ("owner_pk", "b"),
                 ("token", "b"), ("blob", "sha256")],
    "LINK_GET": [("ld_id", "b"), ("mode", "mode")],
}
SIGNED = {f"Signed/{c}": c for c in SIGNED_FIELDS}


def signed_message(command: str, v: dict) -> bytes:
    """D.6: "SecMP-Q/1 " ‖ CMD_LABEL ‖ sess_id[16] ‖ cmd_seq u32 ‖ the D.2 fields except sig and
    blob parts (SHA-256(blob) for LINK_PUT). Keys of v other than these are ignored."""
    if len(v["sess_id"]) != 16:
        raise ValueError("sess_id must be 16 bytes")
    out = labels.Q_CMD[command] + v["sess_id"] + v["cmd_seq"].to_bytes(4, "big")
    for name, kind in SIGNED_FIELDS[command]:
        x = v[name]
        if kind == "sha256":
            if len(x) != sizes.LINK_BLOB:
                raise ValueError("the LINK_PUT blob is 12360 bytes")
            out += primitives.sha256(x)
        elif kind == "b":
            out += x
        elif kind == "mode":
            out += bytes([LINK_GET_MODES[x]])
        else:
            out += x.to_bytes(kind, "big")
    return out


# ---------------------------------------------------------------------------------------------

def encode(structure: str, value: dict, context: str | None = None) -> bytes:
    """The canonical encoding of a valid value; ValueError for anything decode would not return."""
    if structure in SIGNED:
        expected = {"sess_id", "cmd_seq", *(name for name, _ in SIGNED_FIELDS[SIGNED[structure]])}
        if set(value) != expected:
            raise ValueError(f"{structure}: fields {sorted(value)}, expected {sorted(expected)}")
        return signed_message(SIGNED[structure], value)
    data = raw(structure, value)
    try:
        back = decode(structure, data, context)
    except Reject:
        raise ValueError(f"{structure}: not a valid value (rule {last_rule})") from None
    if back != value:
        raise ValueError(f"{structure}: value does not survive encode → decode")
    return data
