# SPDX-License-Identifier: AGPL-3.0-or-later
"""The `encodings` case table (SCHEMA §4.8 = SCHEMA-4.8-encodings.md; briefs REF-M2, REF-M2-1) and its
builders.

Positive rows (op "encode"): inputs {structure, value[, context]}, outputs {bytes}. Each row's
recipe builds the value from the case's own stream (SCHEMA §2) in the order given by the row's
structure in SCHEMA-4.8 ("stream order"): public keys and signatures are derived from stream seeds
with the M1 primitives, ciphertexts, MACs, hashes, ids and nonces are raw stream bytes, free
integers are big-endian stream bytes, and constrained values come from the table.

Negative rows (op "decode", expect reject): inputs {structure, bytes[, context]}. A row "from row r"
draws its own stream exactly as row r's recipe does, builds the honest value, then applies
`edit` (value level), recomputes every length and count field, applies `lens` (length fields set
explicitly), writes the bytes (padded if the structure is padded) and applies `final` (byte level).

The table is the adopted SCHEMA §4.8 with the reviewer's corrections (Weisung REF-M2-1, ADR-039):
the rows the proposal withheld on SQ-12 … SQ-18 are written with their answered outcome.

Every positive is checked to round-trip and every negative to be rejected by the check the table
names; a disagreement raises TableMismatch instead of writing a file.
"""

import copy
from typing import Callable, NamedTuple

from . import encodings as enc
from . import hybridsign, identity, labels, primitives, sizes
from .cases import TableMismatch
from .errors import Reject
from .vectorfile import Case, CaseStream

SUITE = "encodings"

# ---------------------------------------------------------------------------------------------
# Stream helpers


def _u(s, width):
    """A free integer: `width` stream bytes, big-endian."""
    return int.from_bytes(s.take(width), "big")


def _or(s, width, fixed):
    """A free integer from the stream, unless the table fixes it (the maximum-value rows)."""
    return fixed if fixed is not None else _u(s, width)


U32_MAX, U64_MAX = 2**32 - 1, 2**64 - 1


def _ed(s):
    """An Ed25519 seed (32) → (seed, public key)."""
    seed = s.take(32)
    return seed, primitives.ed25519_public(seed)


def _x(s):
    """An X25519 secret (32) → the public key X25519(sk, 9)."""
    return primitives.x25519_public(s.take(32))


def _ek(s, level):
    """An ML-KEM seed d ‖ z (64) → ek from KeyGen_internal(d, z)."""
    return primitives.ml_kem_keygen(level, s.take(sizes.MLKEM_SEED))[0]


def _text(s, n):
    """Text from the stream: the lowercase hex of n stream bytes (2n ASCII bytes)."""
    return s.take(n).hex().encode("ascii")


def _sign(seed, msg, pk):
    sig = primitives.ed25519_sign(seed, msg)
    primitives.ed25519_verify(pk, msg, sig)
    return sig


# ---------------------------------------------------------------------------------------------
# Recipes (stream → value), in App. D order

def _iks_keys(s):
    ed_seed, mldsa_seed, dh_seed = s.take(32), s.take(sizes.MLDSA_SEED), s.take(32)
    pk_ed, pk_mldsa, sk_mldsa = hybridsign.keygen(ed_seed, mldsa_seed)
    v = {"ver": 1, "ik_ed25519": pk_ed, "ik_mldsa65": pk_mldsa, "ik_dh": primitives.x25519_public(dh_seed)}
    return v, (ed_seed, sk_mldsa)


def _iks(topbit=False):
    def recipe(s):
        v, _ = _iks_keys(s)
        if topbit:                                # §3 / SQ-11: accepted and kept as received
            v["ik_dh"] = v["ik_dh"][:31] + bytes([v["ik_dh"][31] | 0x80])
        return v
    return recipe


def _bundle(s, signer=None):
    v = {"ver": 1, "spk_id": _u(s, 4), "spk_dh": _x(s), "spk_kem": _ek(s, 1024), "rpk_kem": _ek(s, 768),
         "spk_expiry": _u(s, 8), "opk_present": 1, "opk_id": _u(s, 4), "opk_dh": _x(s),
         "opk_kem": _ek(s, 1024)}
    iks, (ed_seed, sk_mldsa) = signer if signer is not None else _iks_keys(s)
    rnd = s.take(32)
    msg = enc.payload("PrekeyBundle", v) + iks["ik_dh"]          # §6.3 all preceding fields ‖ ik_dh
    v["sig"] = hybridsign.sign(ed_seed, sk_mldsa, labels.HX_BUNDLE, msg, rnd)
    hybridsign.verify(iks["ik_ed25519"], iks["ik_mldsa65"], labels.HX_BUNDLE, msg, v["sig"])
    return v


def _keychange(s):
    iks, _ = _iks_keys(s)
    old_ed, old_mldsa = s.take(32), s.take(sizes.MLDSA_SEED)
    old_pk_ed, old_pk_mldsa, old_sk = hybridsign.keygen(old_ed, old_mldsa)
    rnd = s.take(32)
    fp = identity.fingerprint(enc.raw("IKSPublic", iks))
    sig = hybridsign.sign(old_ed, old_sk, labels.TR_KEYCHANGE, fp, rnd)          # §7.6
    hybridsign.verify(old_pk_ed, old_pk_mldsa, labels.TR_KEYCHANGE, fp, sig)
    return {"iks": iks, "sig": sig}


def _relayinfo(kid=None, valid_until=None):
    def recipe(s):
        seed, pk = _ed(s)
        v = {"ver": 1, "relay_sig_pk": pk, "kid": _or(s, 4, kid), "relay_dh_pk": _x(s),
             "relay_kem_ek": _ek(s, 1024), "akc": s.take(32), "valid_until": _or(s, 8, valid_until)}
        v["sig"] = _sign(seed, labels.LINK_RELAYINFO + enc.payload("RelayInfoV1", v), pk)     # §8.2
        return v
    return recipe


def _record(structure, body):
    def recipe(s):
        v = {"len": 0, **body(s)}
        enc.refresh(structure, v)
        return v
    return recipe


def _hello(s):
    return {"type": enc.REC_HELLO, "magic": enc.HELLO_MAGIC, "ver": 1}


def _rec_relayinfo(s):
    return {"type": enc.REC_RELAYINFO, "relay_info": _relayinfo()(s)}


def _hs1(s):
    return {"type": enc.REC_HS1, "ver": 1, "kid": _u(s, 4), "e_c": _x(s), "ek_c": _ek(s, 768),
            "pk_e1": _x(s), "ct_kem": s.take(sizes.MLKEM1024_CT), "mac1": s.take(32)}


def _hs2(s):
    return {"type": enc.REC_HS2, "ver": 1, "e_r": _x(s), "ct_c": s.take(sizes.MLKEM768_CT), "mac2": s.take(32)}


# D.2 requests. Signed commands: the fields in D.2 order, then sess_id (16), then the signer's
# Ed25519 seed (32) unless the signer's key is itself a field (QUEUE_NEW recv_pk, LINK_PUT owner_pk).

def _signed(command, fields, sess_id):
    return enc.signed_message(command, {**fields, "sess_id": sess_id})


def _q_queue_new(s):
    v = {"op": "QUEUE_NEW", "cmd_seq": _u(s, 4)}
    recv_seed, v["recv_pk"] = _ed(s)
    _, v["send_pk"] = _ed(s)
    v["token"] = s.take(32)
    v["sig"] = _sign(recv_seed, _signed("QUEUE_NEW", v, s.take(16)), v["recv_pk"])
    return v


def _q_send(s):
    v = {"op": "SEND", "cmd_seq": _u(s, 4), "sid": s.take(16), "cell": s.take(sizes.CELL)}
    msg = _signed("SEND", v, s.take(16))
    seed, pk = _ed(s)
    v["sig"] = _sign(seed, msg, pk)
    return v


def _q_fetch(cmd_seq=None, ack=None):
    def recipe(s):
        v = {"op": "FETCH", "cmd_seq": _or(s, 4, cmd_seq), "rid": s.take(16), "ack": _or(s, 8, ack)}
        msg = _signed("FETCH", v, s.take(16))
        seed, pk = _ed(s)
        v["sig"] = _sign(seed, msg, pk)
        return v
    return recipe


def _q_fetch_multi(count):
    def recipe(s):
        v = {"op": "FETCH_MULTI", "cmd_seq": _u(s, 4), "count": count,
             "entries": [{"rid": s.take(16), "ack": _u(s, 8)} for _ in range(count)]}
        sess_id = s.take(16)
        for e in v["entries"]:                    # one signer seed per entry, in entry order
            seed, pk = _ed(s)
            e["sig"] = _sign(seed, _signed("FETCH_MULTI", {**e, "cmd_seq": v["cmd_seq"]}, sess_id), pk)
        return v
    return recipe


def _q_queue_del(s):
    v = {"op": "QUEUE_DEL", "cmd_seq": _u(s, 4), "rid": s.take(16)}
    msg = _signed("QUEUE_DEL", v, s.take(16))
    seed, pk = _ed(s)
    v["sig"] = _sign(seed, msg, pk)
    return v


def _q_link_put(s):
    v = {"op": "LINK_PUT", "cmd_seq": _u(s, 4), "ld_id": s.take(16), "one_time": 1, "expires_bucket": _u(s, 4)}
    owner_seed, v["owner_pk"] = _ed(s)
    v["token"] = s.take(32)
    blob = s.take(sizes.LINK_BLOB)                # the whole blob; frame 1 carries its first 4160 B
    v["sig"] = _sign(owner_seed, _signed("LINK_PUT", {**v, "blob": blob}, s.take(16)), v["owner_pk"])
    v["blob_part"] = blob[: enc.LINK_PART_FIRST]
    return v


def _q_link_get(mode):
    def recipe(s):
        v = {"op": "LINK_GET", "cmd_seq": _u(s, 4), "ld_id": s.take(16), "mode": mode}
        if mode == "consume":
            v["sig"] = bytes(64)                  # D.2 "zeros when mode = 0"
        else:
            msg = _signed("LINK_GET", v, s.take(16))
            seed, pk = _ed(s)
            v["sig"] = _sign(seed, msg, pk)
        return v
    return recipe


def _q_ping(s):
    return {"op": "PING", "cmd_seq": _u(s, 4)}


def _cont(op, idx):
    return lambda s: {"op": op, "cmd_seq": _u(s, 4), "idx": idx, "data": s.take(enc.LINK_PART_CONT)}


# D.2 responses

def _r_ok(s):
    return {"op": "OK", "cmd_seq": _u(s, 4)}


def _r_ok_queue_new(s):
    return {"op": "OK_QUEUE_NEW", "cmd_seq": _u(s, 4), "rid": s.take(16), "sid": s.take(16)}


def _r_ok_send(evicted, cmd_seq=None, cell_id=None, evicted_id=None):
    def recipe(s):
        v = {"op": "OK_SEND", "cmd_seq": _or(s, 4, cmd_seq), "cell_id": _or(s, 8, cell_id),
             "evicted_present": int(evicted)}
        v["evicted_id"] = _or(s, 8, evicted_id) if evicted else 0
        return v
    return recipe


def _r_cellr(present, context):
    def recipe(s):
        v = {"op": "CELLR", "cmd_seq": _u(s, 4), "present": present}
        zero_rid = present == 0 or (context == "FETCH" and present == 1)
        v["rid"] = bytes(16) if zero_rid else s.take(16)
        v["cell_id"] = _u(s, 8) if present == 1 else 0
        v["cell"] = s.take(sizes.CELL)
        return v
    return recipe


def _r_linkr(present, consumed):
    return lambda s: {"op": "LINKR", "cmd_seq": _u(s, 4), "present": present, "consumed": consumed,
                      "blob_part": s.take(enc.LINK_PART_FIRST)}


def _r_err(code):
    return lambda s: {"op": "ERR", "cmd_seq": _u(s, 4), "code": code}


# D.3

HOST = b"relay.example.org"                       # table-fixed; valid under every reading of SQ-14
PORT = 443
UTF8_NAME = "Zoë Ångström 李雷 🙂".encode("utf-8")  # table-fixed; 1-, 2-, 3- and 4-byte UTF-8 sequences
MAX_HOST = b".".join((b"a" * 63, b"b" * 63, b"c" * 63, b"d" * 61))    # 253 B, the SQ-14 maximum
assert len(MAX_HOST) == enc.HOST_MAX


def _relayref(direct=False, host=HOST, port=PORT):
    def recipe(s):
        v = {"ver": 1, "relay_fp": s.take(32)}
        v["onion"] = enc.onion_from_pubkey(_ed(s)[1])       # onion_seed 32 → PUBKEY ‖ CHECKSUM ‖ 0x03
        v["akc"] = s.take(32)
        v["direct_present"] = int(direct)
        if direct:
            v.update(host_len=len(host), host=host, port=port, spki_sha256=s.take(32))
        return v
    return recipe


def _invitation(period, direct=False, expires=None):
    def recipe(s):
        return {"ver": 1, "kind": 0x01, "relay": _relayref(direct)(s), "ld_id": s.take(16),
                "link_key": s.take(32), "inviter_fp": s.take(32), "inv_sid": s.take(16),
                "inv_send_seed": s.take(32), "inv_period_s": period, "expires": _or(s, 8, expires)}
    return recipe


def _profile(name, avatar):
    """name: an int k → text of k stream bytes (2k ASCII bytes); bytes → the table-fixed name."""
    def recipe(s):
        n = _text(s, name) if isinstance(name, int) else name
        v = {"name_len": len(n), "name": n, "avatar_present": int(avatar)}
        if avatar:
            v["avatar_sha256"] = s.take(32)
        return v
    return recipe


def _linkdata(s):
    iks, secrets = _iks_keys(s)
    return {"ver": 1, "inviter_iks": iks, "bundle": _bundle(s, (iks, secrets)),
            "profile": _profile(8, True)(s), "created": _u(s, 8)}


def _linkblob(s):
    return {"N": s.take(24), "COM": s.take(32), "ct": s.take(sizes.LINKDATA_PADDED + sizes.AEAD_TAG)}


# D.4

def _outer(s):
    return {"ver": 1, "ek_I": _x(s), "spk_id": _u(s, 4), "opk_id": _u(s, 4),
            "ct_spk": s.take(sizes.MLKEM1024_CT), "ct_opk": s.take(sizes.MLKEM1024_CT),
            "inner_ct": s.take(enc.INNER_CT)}


def _inner_ct(s):
    return {"N2": s.take(24), "COM": s.take(32), "ct": s.take(enc.INNER + sizes.AEAD_TAG)}


def _inner(s):
    return {"iks": _iks_keys(s)[0], "first_msg": s.take(sizes.CELL)}


def _hs_cell(s):
    return {"N_i": s.take(24), "COM": s.take(32), "ct": s.take(enc.HS_CELL_PLAINTEXT + sizes.AEAD_TAG)}


def _hs_cell_plaintext(i):
    return lambda s: {"init_id": s.take(16), "i": i, "total": enc.HS_TOTAL, "chunk": s.take(enc.HS_CHUNK)}


# D.5

def _cell(s):
    return {"hdr_nonce": s.take(24), "hdr_ct": s.take(sizes.HDR_CT), "body_ct": s.take(sizes.BODY_LEN),
            "tag": s.take(32)}


def _header(pn=None, n=None):
    return lambda s: {"ver": 1, "flags": 0, "dh_pk": _x(s), "pn": _or(s, 4, pn), "n": _or(s, 4, n),
                      "ek_pq": _ek(s, 768), "ct_pq": s.take(sizes.MLKEM768_CT)}


def _content(ctype, body=None, seq=None, ts=None):
    def recipe(s):
        v = {"ver": 1, "type": ctype, "seq": _or(s, 8, seq), "ts": _or(s, 8, ts), "body_len": 0,
             "body": body(s) if body else b""}
        enc.refresh("Content", v)
        return v
    return recipe


def _appmessage(kind, text_len=None, raw_len=None, expire_after=None):
    """payload: text of text_len stream bytes, or raw_len opaque stream bytes."""
    def recipe(s):
        v = {"msg_id": s.take(16), "kind": kind, "expire_after": _or(s, 4, expire_after)}
        payload = _text(s, text_len) if text_len is not None else s.take(raw_len)
        v.update(payload_len=len(payload), payload=payload)
        return v
    return recipe


def _batch(*messages):
    return lambda s: {"count": len(messages), "messages": [_appmessage(k, n)(s) for k, n in messages]}


def _fragment(idx, total, chunk_len):
    return lambda s: {"msg_id": s.take(16), "idx": idx, "total": total, "chunk": s.take(chunk_len)}


def _fragment_payload(s):
    return {"inner_type": enc.CT_KEYCHANGE, "inner_body": _keychange(s)}


def _relayqueue(period, direct=False):
    return lambda s: {"relay": _relayref(direct)(s), "sid": s.take(16), "send_seed": s.take(32),
                      "period_s": period}


def _route(spec):
    """("rq", period, direct) → kind 0x01 RelayQueue; ("unknown", kind, n) → n opaque stream bytes."""
    def recipe(s):
        if spec[0] == "rq":
            v = {"ver": 1, "kind": enc.ROUTE_RELAYQUEUE, "len": 0, "blob": _relayqueue(spec[1], spec[2])(s)}
        else:
            v = {"ver": 1, "kind": spec[1], "len": 0, "blob": s.take(spec[2])}
        enc.refresh("RouteDescriptor", v)
        return v
    return recipe


def _routeupdate(*routes):
    return lambda s: {"count": len(routes), "routes": [_route(r)(s) for r in routes]}


def _handshake(name, avatar, *routes):
    def recipe(s):
        return {"profile": _profile(name, avatar)(s), "caps": 0, "route_count": len(routes),
                "routes": [_route(r)(s) for r in routes]}
    return recipe


def _receipt(kind, count):
    return lambda s: {"kind": kind, "count": count, "msg_ids": [s.take(16) for _ in range(count)]}


def _control(code, arg_len):
    return lambda s: {"code": code, "arg_len": arg_len, "arg": s.take(arg_len)}


# D.6: sess_id 16, cmd_seq 4, then the signed fields in D.2 order (keys derived from seeds)

def _s_queue_new(s):
    v = {"sess_id": s.take(16), "cmd_seq": _u(s, 4)}
    _, v["recv_pk"] = _ed(s)
    _, v["send_pk"] = _ed(s)
    v["token"] = s.take(32)
    return v


def _s_send(s):
    return {"sess_id": s.take(16), "cmd_seq": _u(s, 4), "sid": s.take(16), "cell": s.take(sizes.CELL)}


def _s_rid_ack(s):
    return {"sess_id": s.take(16), "cmd_seq": _u(s, 4), "rid": s.take(16), "ack": _u(s, 8)}


def _s_queue_del(s):
    return {"sess_id": s.take(16), "cmd_seq": _u(s, 4), "rid": s.take(16)}


def _s_link_put(s):
    v = {"sess_id": s.take(16), "cmd_seq": _u(s, 4), "ld_id": s.take(16), "one_time": 1,
         "expires_bucket": _u(s, 4)}
    _, v["owner_pk"] = _ed(s)
    v["token"] = s.take(32)
    v["blob"] = s.take(sizes.LINK_BLOB)
    return v


def _s_link_get(s):
    return {"sess_id": s.take(16), "cmd_seq": _u(s, 4), "ld_id": s.take(16), "mode": "owner-status"}


# ---------------------------------------------------------------------------------------------
# Positive rows

class Pos(NamedTuple):
    key: str
    structure: str
    recipe: Callable
    variant: str                  # the table-fixed values, as SCHEMA-4.8 lists them
    context: str | None = None


POSITIVES = [
    # D.1
    Pos("hello", "Record/HELLO", _record("Record/HELLO", _hello), "len 7, type 0x01, magic `SECMP`, ver 1 (no stream input)"),
    Pos("rec_relayinfo", "Record/RELAYINFO", _record("Record/RELAYINFO", _rec_relayinfo), "type 0x02; relay_info as RelayInfoV1"),
    Pos("relayinfo", "RelayInfoV1", _relayinfo(), "ver 1"),
    Pos("relayinfo_max", "RelayInfoV1", _relayinfo(U32_MAX, U64_MAX), "ver 1; kid 0xffffffff, valid_until 2^64 − 1 (maxima)"),
    Pos("hs1", "Record/HS1", _record("Record/HS1", _hs1), "type 0x03, ver 1"),
    Pos("hs2", "Record/HS2", _record("Record/HS2", _hs2), "type 0x04, ver 1"),
    # D.2 requests
    Pos("q_queue_new", "Request/QUEUE_NEW", _q_queue_new, "op `QUEUE_NEW`"),
    Pos("q_send", "Request/SEND", _q_send, "op `SEND`"),
    Pos("q_fetch", "Request/FETCH", _q_fetch(), "op `FETCH`"),
    Pos("q_fetch_max", "Request/FETCH", _q_fetch(U32_MAX, U64_MAX), "op `FETCH`; cmd_seq 0xffffffff, ack 2^64 − 1 (maxima)"),
    Pos("q_fetch_multi3", "Request/FETCH_MULTI", _q_fetch_multi(3), "op `FETCH_MULTI`, count 3"),
    Pos("q_fetch_multi32", "Request/FETCH_MULTI", _q_fetch_multi(32), "op `FETCH_MULTI`, count 32 (maximum)"),
    Pos("q_queue_del", "Request/QUEUE_DEL", _q_queue_del, "op `QUEUE_DEL`"),
    Pos("q_link_put", "Request/LINK_PUT", _q_link_put, "op `LINK_PUT`, one_time 1"),
    Pos("q_link_get0", "Request/LINK_GET", _q_link_get("consume"), "op `LINK_GET`, mode `consume` (0), sig = 0^64"),
    Pos("q_link_get1", "Request/LINK_GET", _q_link_get("owner-status"), "op `LINK_GET`, mode `owner-status` (1)"),
    Pos("q_ping", "Request/PING", _q_ping, "op `PING`"),
    Pos("q_cont", "Request/CONT", _cont("CONT", 2), "op `CONT` (0x7F), idx 2"),
    # D.2 responses
    Pos("r_ok", "Response/OK", _r_ok, "op `OK`"),
    Pos("r_ok_queue_new", "Response/OK_QUEUE_NEW", _r_ok_queue_new, "op `OK_QUEUE_NEW`"),
    Pos("r_ok_send0", "Response/OK_SEND", _r_ok_send(False), "op `OK_SEND`, evicted_present 0, evicted_id 0"),
    Pos("r_ok_send1", "Response/OK_SEND", _r_ok_send(True), "op `OK_SEND`, evicted_present 1"),
    Pos("r_ok_send_max", "Response/OK_SEND", _r_ok_send(True, U32_MAX, U64_MAX, U64_MAX),
        "op `OK_SEND`, evicted_present 1; cmd_seq 0xffffffff, cell_id = evicted_id = 2^64 − 1 (maxima)"),
    Pos("r_cellr_f1", "Response/CELLR", _r_cellr(1, "FETCH"), "op `CELLR`, present 1, rid 0 (context FETCH)", "FETCH"),
    Pos("r_cellr_f0", "Response/CELLR", _r_cellr(0, "FETCH"), "op `CELLR`, present 0 (dummy), rid 0, cell_id 0 (context FETCH)", "FETCH"),
    Pos("r_cellr_m1", "Response/CELLR", _r_cellr(1, "FETCH_MULTI"), "op `CELLR`, present 1, rid set (context FETCH_MULTI)", "FETCH_MULTI"),
    Pos("r_cellr_m3", "Response/CELLR", _r_cellr(3, "FETCH_MULTI"), "op `CELLR`, present 3 (AUTH), rid set, cell_id 0 (context FETCH_MULTI)", "FETCH_MULTI"),
    Pos("r_linkr", "Response/LINKR", _r_linkr(1, 0), "op `LINKR`, present 1, consumed 0"),
    Pos("r_err", "Response/ERR", _r_err(7), "op `ERR`, code 7 (RATE, the largest code)"),
    Pos("r_cont", "Response/CONT", _cont("CONT", 1), "op `CONT` (0xFF), idx 1"),
    # D.3
    Pos("relayref", "RelayRef", _relayref(False), "ver 1, direct_present 0"),
    Pos("relayref_direct", "RelayRef", _relayref(True), "ver 1, direct_present 1, host `relay.example.org`, port 443"),
    Pos("relayref_max", "RelayRef", _relayref(True, MAX_HOST, 0xFFFF),
        "ver 1, direct_present 1, host of 253 B (the maximum: 63 × `a`, `.`, 63 × `b`, `.`, 63 × `c`, `.`, 61 × `d`), port 65535"),
    Pos("invitation", "InvitationV1", _invitation(40), "ver 1, kind 0x01, relay without direct (241 B), inv_period_s 40"),
    Pos("invitation_direct", "InvitationV1", _invitation(10, True), "ver 1, kind 0x01, relay with direct as in the RelayRef row, inv_period_s 10"),
    Pos("invitation_max", "InvitationV1", _invitation(80, False, U64_MAX),
        "ver 1, kind 0x01, relay without direct, inv_period_s 80 (the largest period), expires 2^64 − 1 (maximum)"),
    Pos("profile_max", "Profile", _profile(32, True), "name = text of 32 stream bytes (64 B, the maximum), avatar_present 1"),
    Pos("profile_utf8", "Profile", _profile(UTF8_NAME, False), "name = `Zoë Ångström 李雷 🙂` (27 B UTF-8), avatar_present 0"),
    Pos("linkdata", "LinkDataV1", _linkdata, "ver 1; bundle signed by inviter_iks; profile: name = text of 8 stream bytes, avatar_present 1"),
    Pos("linkblob", "LinkBlob", _linkblob, "—"),
    Pos("iks", "IKSPublic", _iks(), "ver 1"),
    Pos("iks_topbit", "IKSPublic", _iks(True), "ver 1; ik_dh with bit 255 set (§3: accepted, kept as received)"),
    Pos("bundle", "PrekeyBundle", lambda s: _bundle(s), "ver 1, opk_present 1; signer IKS from the stream"),
    # D.4
    Pos("outer", "Outer", _outer, "ver 1"),
    Pos("inner_ct", "inner_ct", _inner_ct, "—"),
    Pos("inner", "Inner", _inner, "iks ver 1"),
    Pos("hs_cell", "HandshakeCell", _hs_cell, "—"),
    Pos("hs_cell_pt", "HandshakeCellPlaintext", _hs_cell_plaintext(2), "i 2, total 3"),
    # D.5
    Pos("cell", "Cell", _cell, "—"),
    Pos("header", "HeaderV1", _header(), "ver 1, flags 0"),
    Pos("header_max", "HeaderV1", _header(U32_MAX, U32_MAX), "ver 1, flags 0; pn = n = 0xffffffff (maxima)"),
    Pos("c_dummy", "Content", _content(enc.CT_DUMMY), "ver 1, type 0x00 Dummy, body_len 0"),
    Pos("c_handshake", "Content", _content(enc.CT_HANDSHAKE, _handshake(8, False, ("rq", 20, False))),
        "ver 1, type 0x01; body: profile (name = text of 8 stream bytes, avatar_present 0), caps 0, one RelayQueue route (no direct, period_s 20)"),
    Pos("c_batch", "Content", _content(enc.CT_BATCH, _batch((1, 20), (3, 12))),
        "ver 1, type 0x02; body: count 2 — kind 1 with text of 20 stream bytes, kind 3 with text of 12 stream bytes"),
    Pos("c_fragment", "Content", _content(enc.CT_FRAGMENT, _fragment(1, 3, enc.BODY_MAX - enc.FRAGMENT_HEADER)),
        "ver 1, type 0x03; body: idx 1, total 3, chunk 1669 B → body_len 1689 (the maximum; the pad is the marker alone)"),
    Pos("c_routeupdate", "Content", _content(enc.CT_ROUTEUPDATE, _routeupdate(("rq", 40, True))),
        "ver 1, type 0x04; body: count 1 — RelayQueue with direct, period_s 40"),
    Pos("c_receipt", "Content", _content(enc.CT_RECEIPT, _receipt(2, 4)), "ver 1, type 0x06; body: kind 2 (read), count 4"),
    Pos("c_control", "Content", _content(enc.CT_CONTROL, _control(2, 0)), "ver 1, type 0x07; body: code 2, arg_len 0"),
    Pos("c_dummy_max", "Content", _content(enc.CT_DUMMY, seq=U64_MAX, ts=U64_MAX),
        "ver 1, type 0x00 Dummy; seq = ts = 2^64 − 1 (maxima)"),
    Pos("appmsg", "AppMessage", _appmessage(1, 50), "kind 1 (text); payload = text of 50 stream bytes"),
    Pos("appmsg_max", "AppMessage", _appmessage(2, raw_len=0xFFFF, expire_after=U32_MAX),
        "kind 2 (attachment-inline); expire_after 0xffffffff, payload_len 65535 = MAX_MSG_BYTES (maxima); payload 65535 opaque stream bytes"),
    Pos("batch", "BatchBody", _batch((1, 30), (3, 5)), "count 2 — kind 1 with text of 30 stream bytes, kind 3 with text of 5"),
    Pos("fragment", "Fragment", _fragment(1, 2, 100), "idx 1, total 2, chunk 100 B"),
    Pos("fragment_idx0", "Fragment", _fragment(0, 2, 100), "idx 0, total 2, chunk 100 B (withheld in the proposal; SQ-18 answer (1))"),
    Pos("fragment_max", "Fragment", _fragment(63, 64, enc.BODY_MAX - enc.FRAGMENT_HEADER), "idx 63, total 64 (maxima), chunk 1669 B"),
    Pos("fragpayload", "FragmentPayload", _fragment_payload, "inner_type 0x05 (KeyChange)"),
    Pos("rd_relayqueue", "RouteDescriptor", _route(("rq", 20, False)), "ver 1, kind 0x01; RelayQueue without direct, period_s 20"),
    Pos("rd_unknown", "RouteDescriptor", _route(("unknown", 0x7E, 24)), "ver 1, kind 0x7E (unknown: ignored, kept), blob 24 stream bytes"),
    Pos("rd_unknown_max", "RouteDescriptor", _route(("unknown", 0x7E, 0xFFFF)),
        "ver 1, kind 0x7E (unknown: ignored, kept), len 65535 (maximum), blob 65535 stream bytes"),
    Pos("relayqueue", "RelayQueue", _relayqueue(80, True), "relay with direct as in the RelayRef row, period_s 80"),
    Pos("routeupdate", "RouteUpdateBody", _routeupdate(("rq", 80, False), ("rq", 10, True)),
        "count 2 — RelayQueue without direct, period_s 80; RelayQueue with direct, period_s 10"),
    Pos("handshake", "HandshakeBody", _handshake(4, True, ("rq", 10, True), ("unknown", 0x10, 40)),
        "profile (name = text of 4 stream bytes, avatar_present 1), caps 0, route_count 2 — RelayQueue with direct, period_s 10; kind 0x10 (unknown: ignored, kept) with 40 stream bytes"),
    Pos("keychange", "KeyChangeBody", _keychange, "iks ver 1; sig by a second IKS from the stream"),
    Pos("receipt", "ReceiptBody", _receipt(1, 5), "kind 1 (delivered), count 5"),
    Pos("receipt_max", "ReceiptBody", _receipt(2, 255), "kind 2 (read), count 255 (maximum)"),
    Pos("control", "ControlBody", _control(1, 0), "code 1 (contact-removed), arg_len 0"),
    Pos("control_arg", "ControlBody", _control(2, 16), "code 2 (session-reset-request), arg_len 16 (arg: 16 opaque stream bytes)"),
    Pos("control_max", "ControlBody", _control(1, 0xFFFF), "code 1, arg_len 65535 (maximum; arg: 65535 opaque stream bytes)"),
    # D.6
    Pos("s_queue_new", "Signed/QUEUE_NEW", _s_queue_new, "label `SecMP-Q/1 QUEUE_NEW`"),
    Pos("s_send", "Signed/SEND", _s_send, "label `SecMP-Q/1 SEND`"),
    Pos("s_fetch", "Signed/FETCH", _s_rid_ack, "label `SecMP-Q/1 FETCH`"),
    Pos("s_fetch_multi", "Signed/FETCH_MULTI", _s_rid_ack, "label `SecMP-Q/1 MFETCH` (one entry: rid ‖ ack)"),
    Pos("s_queue_del", "Signed/QUEUE_DEL", _s_queue_del, "label `SecMP-Q/1 QUEUE_DEL`"),
    Pos("s_link_put", "Signed/LINK_PUT", _s_link_put, "label `SecMP-Q/1 LINK_PUT`, one_time 1; SHA-256 of the 12360-byte blob"),
    Pos("s_link_get", "Signed/LINK_GET", _s_link_get, "label `SecMP-Q/1 LINK_GET`, mode `owner-status`"),
]
POS_BY_KEY = {p.key: p for p in POSITIVES}
assert len(POS_BY_KEY) == len(POSITIVES)
POS_INDEX = {p.key: i for i, p in enumerate(POSITIVES, start=1)}

# ---------------------------------------------------------------------------------------------
# Manipulations

P = enc.P25519
L = primitives.ED25519_L
_Y8 = 2707385501144840649318225287225658788936804267575313519463743609750303402022
assert primitives.ED25519_SMALL_ORDER_Y == {0, 1, P - 1, _Y8, P - _Y8}


def le32(n):
    return n.to_bytes(32, "little")


def topbit(b):
    return b[:31] + bytes([b[31] | 0x80])


# X25519 low-order values (encodings.x25519_low_order_encodings lists all 14)
X_U0, X_U1, X_PM1, X_P, X_P1 = le32(0), le32(1), le32(P - 1), le32(P), le32(P + 1)
X_O8A, X_O8B = enc.X25519_ORDER8

# Ed25519 points of order dividing 8, and non-canonical encodings (y ≥ p)
ED_IDENTITY = le32(1)                             # order 1
ED_IDENTITY_SIGNX = le32(1 | 1 << 255)            # y = 1 with the x sign bit set
ED_ORDER2 = le32(P - 1)                           # y = −1
ED_ORDER4 = le32(0)                               # y = 0, x = +√−1
ED_ORDER4_SIGNX = le32(1 << 255)                  # y = 0, x = −√−1
ED_ORDER8 = le32(_Y8)
ED_ORDER8_NEG = le32((P - _Y8) | 1 << 255)
ED_IDENTITY_NONCANON = le32(P + 1)                # y = p + 1 ≡ 1
ED_Y3_NONCANON = le32(P + 3)                      # y = p + 3 ≡ 3: a curve point, not small order
ED_Y18_NONCANON = le32(2**255 - 1)                # y = p + 18 ≡ 18: a curve point, not small order
ED_Y2_OFF_CURVE = le32(2)                         # canonical, not a curve point (SQ-12)


def s_plus_l(sig):
    """The Ed25519 S (bytes 32–63, little-endian) replaced by S + L."""
    return sig[:32] + (int.from_bytes(sig[32:64], "little") + L).to_bytes(32, "little") + sig[64:]


def set_r(point):
    return lambda sig: point + sig[32:]


def flip(k):
    return lambda b: b[:k] + bytes([b[k] ^ 0x01]) + b[k + 1:]


def set_byte(k, x):
    return lambda b: b[:k] + bytes([x]) + b[k + 1:]


def plus(n):
    return lambda x: x + n


def frozen(structure):
    """A nested value replaced by its bytes (before a type/kind change makes it unreadable)."""
    return lambda v: enc.raw(structure, v)


DEL = object()                                    # edit value: remove the field


def COEFF_GE_Q(ek):
    """An ML-KEM ek with bytes 0–2 := ff ff ff: the first packed coefficient is 0xfff ≥ q (FIPS 203 §7.2)."""
    return b"\xff\xff\xff" + ek[3:]


# A well-formed HandshakeBody for the FragmentPayload inner_type 0x01 row (SQ-18 answer (4)).
INNER_HANDSHAKE = {"profile": {"name_len": 1, "name": b"a", "avatar_present": 0}, "caps": 0, "route_count": 1,
                   "routes": [{"ver": 1, "kind": 0x10, "len": 1, "blob": b"\x01"}]}


# final (byte-level) manipulations: (payload, data) → bytes
def drop_last(p, d):
    return d[:-1]


def append_zero(p, d):
    return d + b"\x00"


def empty(p, d):
    return b""


def prefix(n):
    return lambda p, d: d[:n]


def unpadded(p, d):
    return p


def pad_marker(x):
    return lambda p, d: p + bytes([x]) + d[len(p) + 1:]


def pad_last(x):
    return lambda p, d: d[:-1] + bytes([x])


def marker_late(p, d):
    return enc.iso_pad(p + b"\x00", len(d))


def marker_early(p, d):
    return enc.iso_pad(p[:-1], len(d))


# ---------------------------------------------------------------------------------------------
# Negative rows

FAMILIES = {
    "VER": "wrong `ver`",
    "SIZE": "encoding one byte short, one byte long (fixed size), or empty",
    "TRAIL": "trailing bytes",
    "LEN": "length or count field off by one (−1, +1), zero, or maximum + 1",
    "OVF": "length, count or index at the field's maximum value (0xFF / 0xFFFF / 0xFFFFFFFF)",
    "PAD": "wrong ISO/IEC 7816-4 padding (marker value, non-zero pad byte, marker one late / one early)",
    "RSV": "reserved value or reserved zero field set",
    "TYPE": "unknown opcode, type, kind or code byte (or wrong identification constant)",
    "OPT": "Option/boolean byte not in {0, 1}, present when forbidden, absent when required",
    "X25519": "low-order X25519 public key",
    "ED25519": "non-canonical or small-order Ed25519 key or signature R; S ≥ L",
    "RANGE": "value outside its stated set or range",
    "UTF8": "invalid UTF-8",
    "NEST": "defect inside a nested structure",
    "CTX": "valid bytes decoded under the wrong request context",
    "MLKEM": "ML-KEM encapsulation key failing the FIPS 203 §7.2 modulus check (a coefficient ≥ q)",
}


class Neg(NamedTuple):
    structure: str
    row: str                      # key of the positive row whose recipe it follows
    manipulation: str             # SCHEMA-4.8 text
    family: str
    rule: str | None              # the ref decoder's check that rejects it (None: not asserted)
    edit: tuple = ()              # (path, value | fn | DEL) applied before lengths are recomputed
    lens: tuple = ()              # (path, value | fn) applied after lengths are recomputed
    final: Callable | None = None  # (payload, data) → bytes
    context: str | None = None    # overrides the row's context


def N(structure, row, manipulation, family, rule, **kw):
    return Neg(structure, row, manipulation, family, rule, **kw)


def _size3(structure, row, rules=("truncated", "trailing", "truncated")):
    return [N(structure, row, "drop-last", "SIZE", rules[0], final=drop_last),
            N(structure, row, "append-zero", "TRAIL", rules[1], final=append_zero),
            N(structure, row, "empty (0 bytes)", "SIZE", rules[2], final=empty)]


def _opaque3(structure, row):
    return [N(structure, row, "drop-last", "SIZE", "size", final=drop_last),
            N(structure, row, "append-zero", "SIZE", "size", final=append_zero),
            N(structure, row, "empty (0 bytes)", "SIZE", "size", final=empty)]


def _pad(structure, row, markers=(0x00,), early="pad"):
    rows = [N(structure, row, f"pad: marker 0x80 := 0x{m:02x}", "PAD", "pad", final=pad_marker(m)) for m in markers]
    return rows + [
        N(structure, row, "pad: last byte := 0x01", "PAD", "pad", final=pad_last(0x01)),
        N(structure, row, "pad: marker late (one 0x00 byte between the fields and the marker)", "PAD", "pad",
          final=marker_late),
        N(structure, row, "pad: marker early (the fields' last byte dropped, then padded)", "PAD", early,
          final=marker_early),
    ]


def _frame5(structure, row, early="pad", markers=()):
    return ([N(structure, row, "drop-last (4335 B)", "SIZE", "size", final=drop_last),
             N(structure, row, "append-zero (4337 B)", "SIZE", "size", final=append_zero)]
            + _pad(structure, row, markers, early))


def _x_rows(structure, row, field, points, family="X25519", path=None):
    names = {X_U0: "u = 0", X_U1: "u = 1", X_PM1: "u = p − 1", X_P: "u = p (≡ 0)", X_P1: "u = p + 1 (≡ 1)",
             X_O8A: "order-8 point e0eb7a7c…", X_O8B: "order-8 point 5f9c95bc…"}
    rows = []
    for pt in points:
        base = pt if pt in names else bytes(pt[:31]) + bytes([pt[31] & 0x7F])
        name = names[base] + (" with bit 255 set" if pt != base else "")
        rows.append(N(structure, row, f"{path or field} := {pt.hex()} ({name})", family, "x25519-low-order",
                      edit=((path or field, pt),)))
    return rows


R = "Request/"
S = "Response/"

NEGATIVES = [
    # ----- D.1 Record/HELLO
    N("Record/HELLO", "hello", "len := 6", "LEN", "len", lens=(("len", 6),)),
    N("Record/HELLO", "hello", "len := 8 (bytes unchanged)", "LEN", "truncated", lens=(("len", 8),)),
    N("Record/HELLO", "hello", "len := 0", "LEN", "truncated", lens=(("len", 0),)),
    N("Record/HELLO", "hello", "len := 0xffff", "OVF", "truncated", lens=(("len", 0xFFFF),)),
    N("Record/HELLO", "hello", "len := 8 and one 0x00 appended (len consistent, body too long)", "LEN", "len",
      lens=(("len", 8),), final=append_zero),
    N("Record/HELLO", "hello", "type := 0x00", "TYPE", "type", edit=(("type", 0x00),)),
    N("Record/HELLO", "hello", "type := 0x02 (RELAYINFO)", "TYPE", "type", edit=(("type", 0x02),)),
    N("Record/HELLO", "hello", "type := 0x05", "TYPE", "type", edit=(("type", 0x05),)),
    N("Record/HELLO", "hello", "magic := `SECMQ`", "TYPE", "magic", edit=(("magic", b"SECMQ"),)),
    N("Record/HELLO", "hello", "magic := `secmp`", "TYPE", "magic", edit=(("magic", b"secmp"),)),
    N("Record/HELLO", "hello", "ver := 0x00", "VER", "ver", edit=(("ver", 0x00),)),
    N("Record/HELLO", "hello", "ver := 0x02", "VER", "ver", edit=(("ver", 0x02),)),
    N("Record/HELLO", "hello", "ver := 0xff", "VER", "ver", edit=(("ver", 0xFF),)),
    *_size3("Record/HELLO", "hello"),
    # ----- D.1 Record/RELAYINFO
    N("Record/RELAYINFO", "rec_relayinfo", "len := 1741", "LEN", "len", lens=(("len", 1741),)),
    N("Record/RELAYINFO", "rec_relayinfo", "len := 1743 (bytes unchanged)", "LEN", "truncated", lens=(("len", 1743),)),
    N("Record/RELAYINFO", "rec_relayinfo", "len := 0", "LEN", "truncated", lens=(("len", 0),)),
    N("Record/RELAYINFO", "rec_relayinfo", "len := 0xffff", "OVF", "truncated", lens=(("len", 0xFFFF),)),
    N("Record/RELAYINFO", "rec_relayinfo", "type := 0x01 (HELLO)", "TYPE", "type", edit=(("type", 0x01),)),
    N("Record/RELAYINFO", "rec_relayinfo", "type := 0x04 (HS2)", "TYPE", "type", edit=(("type", 0x04),)),
    N("Record/RELAYINFO", "rec_relayinfo", "relay_info.sig: last byte removed (len recomputed: 1741)", "LEN", "len",
      edit=(("relay_info.sig", lambda b: b[:-1]),)),
    N("Record/RELAYINFO", "rec_relayinfo", "relay_info.ver := 0x02", "NEST", "ver", edit=(("relay_info.ver", 2),)),
    N("Record/RELAYINFO", "rec_relayinfo", f"relay_info.relay_dh_pk := {X_O8A.hex()} (order 8)", "NEST",
      "x25519-low-order", edit=(("relay_info.relay_dh_pk", X_O8A),)),
    *_size3("Record/RELAYINFO", "rec_relayinfo"),
    # ----- D.1 RelayInfoV1
    N("RelayInfoV1", "relayinfo", "ver := 0x00", "VER", "ver", edit=(("ver", 0),)),
    N("RelayInfoV1", "relayinfo", "ver := 0x02", "VER", "ver", edit=(("ver", 2),)),
    N("RelayInfoV1", "relayinfo", "relay_sig_pk := 01 00…00 (identity)", "ED25519", "ed25519-key-small-order",
      edit=(("relay_sig_pk", ED_IDENTITY),)),
    N("RelayInfoV1", "relayinfo", f"relay_sig_pk := {ED_ORDER8.hex()} (order 8)", "ED25519",
      "ed25519-key-small-order", edit=(("relay_sig_pk", ED_ORDER8),)),
    N("RelayInfoV1", "relayinfo", f"relay_sig_pk := {ED_Y3_NONCANON.hex()} (y = p + 3, non-canonical)", "ED25519",
      "ed25519-key-noncanonical", edit=(("relay_sig_pk", ED_Y3_NONCANON),)),
    *_x_rows("RelayInfoV1", "relayinfo", "relay_dh_pk", (X_U0, X_P1, topbit(X_O8B))),
    N("RelayInfoV1", "relayinfo", "sig: S := S + L", "ED25519", "ed25519-sig-S", edit=(("sig", s_plus_l),)),
    N("RelayInfoV1", "relayinfo", "sig: R := 01 00…00 (identity)", "ED25519", "ed25519-sig-R-small-order",
      edit=(("sig", set_r(ED_IDENTITY)),)),
    N("RelayInfoV1", "relayinfo", f"sig: R := {ED_Y3_NONCANON.hex()} (y = p + 3)", "ED25519",
      "ed25519-sig-R-noncanonical", edit=(("sig", set_r(ED_Y3_NONCANON)),)),
    N("RelayInfoV1", "relayinfo", f"sig: R := {ED_Y2_OFF_CURVE.hex()} (y = 2: canonical, not a curve point)", "ED25519",
      "ed25519-sig-R-off-curve", edit=(("sig", set_r(ED_Y2_OFF_CURVE)),)),
    N("RelayInfoV1", "relayinfo", "relay_kem_ek bytes 0–2 := ff ff ff (a coefficient ≥ q)", "MLKEM", "mlkem-ek",
      edit=(("relay_kem_ek", COEFF_GE_Q),)),
    *_size3("RelayInfoV1", "relayinfo"),
    # ----- D.1 Record/HS1
    N("Record/HS1", "hs1", "len := 2853", "LEN", "len", lens=(("len", 2853),)),
    N("Record/HS1", "hs1", "len := 2855 (bytes unchanged)", "LEN", "truncated", lens=(("len", 2855),)),
    N("Record/HS1", "hs1", "len := 0", "LEN", "truncated", lens=(("len", 0),)),
    N("Record/HS1", "hs1", "len := 0xffff", "OVF", "truncated", lens=(("len", 0xFFFF),)),
    N("Record/HS1", "hs1", "type := 0x04 (HS2)", "TYPE", "type", edit=(("type", 0x04),)),
    N("Record/HS1", "hs1", "type := 0xff", "TYPE", "type", edit=(("type", 0xFF),)),
    N("Record/HS1", "hs1", "ver := 0x00", "VER", "ver", edit=(("ver", 0),)),
    N("Record/HS1", "hs1", "ver := 0x02", "VER", "ver", edit=(("ver", 2),)),
    *_x_rows("Record/HS1", "hs1", "e_c", (X_U1, X_O8A)),
    *_x_rows("Record/HS1", "hs1", "pk_e1", (X_PM1, topbit(X_U0))),
    N("Record/HS1", "hs1", "mac1: last byte removed (len recomputed: 2853)", "LEN", "len",
      edit=(("mac1", lambda b: b[:-1]),)),
    N("Record/HS1", "hs1", "ek_c bytes 0–2 := ff ff ff (a coefficient ≥ q)", "MLKEM", "mlkem-ek",
      edit=(("ek_c", COEFF_GE_Q),)),
    *_size3("Record/HS1", "hs1"),
    # ----- D.1 Record/HS2
    N("Record/HS2", "hs2", "len := 1153", "LEN", "len", lens=(("len", 1153),)),
    N("Record/HS2", "hs2", "len := 1155 (bytes unchanged)", "LEN", "truncated", lens=(("len", 1155),)),
    N("Record/HS2", "hs2", "len := 0", "LEN", "truncated", lens=(("len", 0),)),
    N("Record/HS2", "hs2", "len := 0xffff", "OVF", "truncated", lens=(("len", 0xFFFF),)),
    N("Record/HS2", "hs2", "type := 0x03 (HS1)", "TYPE", "type", edit=(("type", 0x03),)),
    N("Record/HS2", "hs2", "type := 0x00", "TYPE", "type", edit=(("type", 0x00),)),
    N("Record/HS2", "hs2", "ver := 0x00", "VER", "ver", edit=(("ver", 0),)),
    N("Record/HS2", "hs2", "ver := 0xff", "VER", "ver", edit=(("ver", 0xFF),)),
    *_x_rows("Record/HS2", "hs2", "e_r", (X_U0, X_P)),
    N("Record/HS2", "hs2", "ct_c: one 0x00 byte appended (len recomputed: 1155)", "LEN", "len",
      edit=(("ct_c", lambda b: b + b"\x00"),)),
    *_size3("Record/HS2", "hs2"),

    # ----- D.2 requests
    N(R + "QUEUE_NEW", "q_queue_new", "recv_pk := 01 00…00 (identity)", "ED25519", "ed25519-key-small-order",
      edit=(("recv_pk", ED_IDENTITY),)),
    N(R + "QUEUE_NEW", "q_queue_new", f"recv_pk := {ED_Y3_NONCANON.hex()} (y = p + 3)", "ED25519",
      "ed25519-key-noncanonical", edit=(("recv_pk", ED_Y3_NONCANON),)),
    N(R + "QUEUE_NEW", "q_queue_new", "send_pk := 00…00 (y = 0, order 4)", "ED25519", "ed25519-key-small-order",
      edit=(("send_pk", ED_ORDER4),)),
    N(R + "QUEUE_NEW", "q_queue_new", f"send_pk := {ED_ORDER8_NEG.hex()} (order 8)", "ED25519",
      "ed25519-key-small-order", edit=(("send_pk", ED_ORDER8_NEG),)),
    N(R + "QUEUE_NEW", "q_queue_new", "sig: S := S + L", "ED25519", "ed25519-sig-S", edit=(("sig", s_plus_l),)),
    N(R + "QUEUE_NEW", "q_queue_new", f"sig: R := {ED_Y3_NONCANON.hex()} (y = p + 3)", "ED25519",
      "ed25519-sig-R-noncanonical", edit=(("sig", set_r(ED_Y3_NONCANON)),)),
    *_frame5(R + "QUEUE_NEW", "q_queue_new", early="ed25519-sig-S"),
    N(R + "SEND", "q_send", "sig: S := S + L", "ED25519", "ed25519-sig-S", edit=(("sig", s_plus_l),)),
    N(R + "SEND", "q_send", "sig: R := ec ff…7f (y = −1, order 2)", "ED25519", "ed25519-sig-R-small-order",
      edit=(("sig", set_r(ED_ORDER2)),)),
    *_frame5(R + "SEND", "q_send", early="ed25519-sig-S"),
    N(R + "FETCH", "q_fetch", "sig: S := S + L", "ED25519", "ed25519-sig-S", edit=(("sig", s_plus_l),)),
    N(R + "FETCH", "q_fetch", "sig: R := 00…00 (y = 0, order 4)", "ED25519", "ed25519-sig-R-small-order",
      edit=(("sig", set_r(ED_ORDER4)),)),
    *_frame5(R + "FETCH", "q_fetch", early="ed25519-sig-S"),
    N(R + "FETCH_MULTI", "q_fetch_multi3", "count := 0, entries removed", "RANGE", "range",
      edit=(("entries", []),)),
    N(R + "FETCH_MULTI", "q_fetch_multi3", "count := 0 (entries kept)", "LEN", "range", lens=(("count", 0),)),
    N(R + "FETCH_MULTI", "q_fetch_multi3", "count := 4 (3 entries)", "LEN", "ed25519-sig-R-small-order",
      lens=(("count", 4),)),
    N(R + "FETCH_MULTI", "q_fetch_multi3", "count := 2 (3 entries)", "LEN", "pad", lens=(("count", 2),)),
    N(R + "FETCH_MULTI", "q_fetch_multi3", "count := 0xff", "OVF", "range", lens=(("count", 0xFF),)),
    N(R + "FETCH_MULTI", "q_fetch_multi32", "entries[0] appended again → count 33 (maximum + 1)", "RANGE", "range",
      edit=(("entries", lambda es: es + [es[0]]),)),
    N(R + "FETCH_MULTI", "q_fetch_multi3", "entries[0].sig: S := S + L", "ED25519", "ed25519-sig-S",
      edit=(("entries.0.sig", s_plus_l),)),
    N(R + "FETCH_MULTI", "q_fetch_multi3", "entries[2].sig: R := 01 00…00 (identity)", "ED25519",
      "ed25519-sig-R-small-order", edit=(("entries.2.sig", set_r(ED_IDENTITY)),)),
    *_frame5(R + "FETCH_MULTI", "q_fetch_multi3", early="ed25519-sig-S"),
    N(R + "QUEUE_DEL", "q_queue_del", "sig: S := S + L", "ED25519", "ed25519-sig-S", edit=(("sig", s_plus_l),)),
    N(R + "QUEUE_DEL", "q_queue_del", f"sig: R := {ED_ORDER8.hex()} (order 8)", "ED25519",
      "ed25519-sig-R-small-order", edit=(("sig", set_r(ED_ORDER8)),)),
    *_frame5(R + "QUEUE_DEL", "q_queue_del", early="ed25519-sig-S"),
    N(R + "LINK_PUT", "q_link_put", "owner_pk := 01 00…00 (identity)", "ED25519", "ed25519-key-small-order",
      edit=(("owner_pk", ED_IDENTITY),)),
    N(R + "LINK_PUT", "q_link_put", f"owner_pk := {ED_Y18_NONCANON.hex()} (y = p + 18)", "ED25519",
      "ed25519-key-noncanonical", edit=(("owner_pk", ED_Y18_NONCANON),)),
    N(R + "LINK_PUT", "q_link_put", "one_time := 0x02", "OPT", "bool", edit=(("one_time", 2),)),
    N(R + "LINK_PUT", "q_link_put", "one_time := 0xff", "OPT", "bool", edit=(("one_time", 0xFF),)),
    N(R + "LINK_PUT", "q_link_put", "sig: S := S + L", "ED25519", "ed25519-sig-S", edit=(("sig", s_plus_l),)),
    N(R + "LINK_PUT", "q_link_put", f"sig: R := {ED_IDENTITY_SIGNX.hex()} (y = 1, x sign bit set)", "ED25519",
      "ed25519-sig-R-small-order", edit=(("sig", set_r(ED_IDENTITY_SIGNX)),)),
    *_frame5(R + "LINK_PUT", "q_link_put"),
    N(R + "LINK_GET", "q_link_get0", "mode := 0x02", "RANGE", "range", edit=(("mode", 2),)),
    N(R + "LINK_GET", "q_link_get0", "mode := 0xff", "RANGE", "range", edit=(("mode", 0xFF),)),
    N(R + "LINK_GET", "q_link_get0", "sig := 01 00…00 (mode 0)", "RSV", "reserved", edit=(("sig", set_byte(0, 1)),)),
    N(R + "LINK_GET", "q_link_get0", "sig: last byte := 0x01 (mode 0)", "RSV", "reserved",
      edit=(("sig", set_byte(63, 1)),)),
    N(R + "LINK_GET", "q_link_get0", "mode := `owner-status` (1) (sig all zero: absent when required)", "OPT",
      "ed25519-sig-R-small-order", edit=(("mode", "owner-status"),)),
    N(R + "LINK_GET", "q_link_get1", "mode := `consume` (0) (signature kept: present when forbidden)", "OPT",
      "reserved", edit=(("mode", "consume"),)),
    N(R + "LINK_GET", "q_link_get1", "sig: S := S + L", "ED25519", "ed25519-sig-S", edit=(("sig", s_plus_l),)),
    N(R + "LINK_GET", "q_link_get1", f"sig: R := {ED_Y3_NONCANON.hex()} (y = p + 3)", "ED25519",
      "ed25519-sig-R-noncanonical", edit=(("sig", set_r(ED_Y3_NONCANON)),)),
    N(R + "LINK_GET", "q_link_get1", f"sig: R := {ED_ORDER8.hex()} (order 8)", "ED25519",
      "ed25519-sig-R-small-order", edit=(("sig", set_r(ED_ORDER8)),)),
    *_frame5(R + "LINK_GET", "q_link_get0", early="reserved"),
    N(R + "PING", "q_ping", "op := 0x00", "TYPE", "type", edit=(("op", 0x00),)),
    N(R + "PING", "q_ping", "op := 0x02 (SKEY, reserved)", "RSV", "reserved", edit=(("op", 0x02),)),
    N(R + "PING", "q_ping", "op := 0x0a", "TYPE", "type", edit=(("op", 0x0A),)),
    N(R + "PING", "q_ping", "op := 0x7e", "TYPE", "type", edit=(("op", 0x7E),)),
    N(R + "PING", "q_ping", "op := 0x80 (a response opcode)", "TYPE", "type", edit=(("op", 0x80),)),
    N(R + "PING", "q_ping", "op := 0xff (the response CONT)", "TYPE", "type", edit=(("op", 0xFF),)),
    N(R + "PING", "q_ping", "empty (0 bytes)", "SIZE", "size", final=empty),
    *_frame5(R + "PING", "q_ping", markers=(0x00,)),
    N(R + "CONT", "q_cont", "idx := 0", "RANGE", "range", edit=(("idx", 0),)),
    N(R + "CONT", "q_cont", "idx := 3", "RANGE", "range", edit=(("idx", 3),)),
    N(R + "CONT", "q_cont", "idx := 0xff", "OVF", "range", edit=(("idx", 0xFF),)),
    *_frame5(R + "CONT", "q_cont"),

    # ----- D.2 responses
    N(S + "OK", "r_ok", "op := 0x00", "TYPE", "type", edit=(("op", 0x00),)),
    N(S + "OK", "r_ok", "op := 0x01 (a request opcode)", "TYPE", "type", edit=(("op", 0x01),)),
    N(S + "OK", "r_ok", "op := 0x7f (the request CONT)", "TYPE", "type", edit=(("op", 0x7F),)),
    N(S + "OK", "r_ok", "op := 0x85", "TYPE", "type", edit=(("op", 0x85),)),
    N(S + "OK", "r_ok", "op := 0x8e", "TYPE", "type", edit=(("op", 0x8E),)),
    N(S + "OK", "r_ok", "op := 0x90", "TYPE", "type", edit=(("op", 0x90),)),
    N(S + "OK", "r_ok", "empty (0 bytes)", "SIZE", "size", final=empty),
    *_frame5(S + "OK", "r_ok", markers=(0x00,)),
    *_frame5(S + "OK_QUEUE_NEW", "r_ok_queue_new", markers=(0x81,)),
    N(S + "OK_SEND", "r_ok_send0", "evicted_id := 1 (evicted_present 0)", "RSV", "reserved",
      edit=(("evicted_id", 1),)),
    N(S + "OK_SEND", "r_ok_send0", "evicted_present := 0x02", "OPT", "bool", edit=(("evicted_present", 2),)),
    N(S + "OK_SEND", "r_ok_send0", "evicted_present := 0xff", "OPT", "bool", edit=(("evicted_present", 0xFF),)),
    N(S + "OK_SEND", "r_ok_send1", "evicted_present := 0 (evicted_id kept: present when forbidden)", "OPT",
      "reserved", edit=(("evicted_present", 0),)),
    *_frame5(S + "OK_SEND", "r_ok_send0", early="reserved"),
    N(S + "CELLR", "r_cellr_f1", "rid := 00…01 (FETCH, present 1)", "RSV", "reserved",
      edit=(("rid", set_byte(15, 1)),)),
    N(S + "CELLR", "r_cellr_f1", "present := 5", "RANGE", "range", edit=(("present", 5),)),
    N(S + "CELLR", "r_cellr_f1", "present := 0xff", "RANGE", "range", edit=(("present", 0xFF),)),
    N(S + "CELLR", "r_cellr_f1", "present := 0 (cell_id kept)", "RSV", "reserved", edit=(("present", 0),)),
    N(S + "CELLR", "r_cellr_f0", "rid := 00…01 (present 0)", "RSV", "reserved", edit=(("rid", set_byte(15, 1)),)),
    N(S + "CELLR", "r_cellr_f0", "cell_id := 1 (present 0)", "RSV", "reserved", edit=(("cell_id", 1),)),
    N(S + "CELLR", "r_cellr_m3", "cell_id := 1 (present 3)", "RSV", "reserved", edit=(("cell_id", 1),)),
    N(S + "CELLR", "r_cellr_m1", "present := 2 (cell_id kept)", "RSV", "reserved", edit=(("present", 2),)),
    N(S + "CELLR", "r_cellr_m1", "present := 4 (cell_id kept)", "RSV", "reserved", edit=(("present", 4),)),
    N(S + "CELLR", "r_cellr_m1", "bytes unchanged, context := FETCH (rid set on present 1)", "CTX", "reserved",
      context="FETCH"),
    *_frame5(S + "CELLR", "r_cellr_f1"),
    N(S + "LINKR", "r_linkr", "present := 0x02", "OPT", "bool", edit=(("present", 2),)),
    N(S + "LINKR", "r_linkr", "consumed := 0x02", "OPT", "bool", edit=(("consumed", 2),)),
    N(S + "LINKR", "r_linkr", "consumed := 0xff", "OPT", "bool", edit=(("consumed", 0xFF),)),
    *_frame5(S + "LINKR", "r_linkr"),
    N(S + "ERR", "r_err", "code := 0", "TYPE", "type", edit=(("code", 0),)),
    N(S + "ERR", "r_err", "code := 8", "TYPE", "type", edit=(("code", 8),)),
    N(S + "ERR", "r_err", "code := 0xff", "OVF", "type", edit=(("code", 0xFF),)),
    *_frame5(S + "ERR", "r_err", early="type"),
    N(S + "CONT", "r_cont", "idx := 0", "RANGE", "range", edit=(("idx", 0),)),
    N(S + "CONT", "r_cont", "idx := 3", "RANGE", "range", edit=(("idx", 3),)),
    N(S + "CONT", "r_cont", "idx := 0xff", "OVF", "range", edit=(("idx", 0xFF),)),
    *_frame5(S + "CONT", "r_cont"),

    # ----- D.3 RelayRef
    N("RelayRef", "relayref", "ver := 0x00", "VER", "ver", edit=(("ver", 0),)),
    N("RelayRef", "relayref", "ver := 0x02", "VER", "ver", edit=(("ver", 2),)),
    N("RelayRef", "relayref", "direct_present := 0x02", "OPT", "bool", edit=(("direct_present", 2),)),
    N("RelayRef", "relayref", "direct_present := 0xff", "OPT", "bool", edit=(("direct_present", 0xFF),)),
    N("RelayRef", "relayref", "direct_present := 1 (no direct fields: absent when announced)", "OPT", "truncated",
      edit=(("direct_present", 1),)),
    N("RelayRef", "relayref_direct", "direct_present := 0 (direct fields kept: present when not announced)", "OPT",
      "trailing", edit=(("direct_present", 0),)),
    N("RelayRef", "relayref_direct", "host_len := host_len + 1", "LEN", "host", lens=(("host_len", plus(1)),)),
    N("RelayRef", "relayref_direct", "host_len := host_len − 1", "LEN", "trailing", lens=(("host_len", plus(-1)),)),
    N("RelayRef", "relayref_direct", "host_len := 0 (host kept)", "LEN", "host", lens=(("host_len", 0),)),
    N("RelayRef", "relayref_direct", "host_len := 0xffff", "OVF", "host", lens=(("host_len", 0xFFFF),)),
    N("RelayRef", "relayref", "onion[34] (VERSION) := 0x02", "TYPE", "onion", edit=(("onion", set_byte(34, 0x02)),)),
    N("RelayRef", "relayref", "onion[32] (CHECKSUM) ^= 0x01", "RANGE", "onion", edit=(("onion", flip(32)),)),
    N("RelayRef", "relayref_direct", "host := empty (host_len recomputed: 0)", "LEN", "host", edit=(("host", b""),)),
    N("RelayRef", "relayref_direct", "host := 254 × `a` (host_len recomputed: 254, maximum + 1)", "LEN", "host",
      edit=(("host", b"a" * 254),)),
    N("RelayRef", "relayref_direct", "host[5] := 0x20 (space)", "RANGE", "host", edit=(("host", set_byte(5, 0x20)),)),
    N("RelayRef", "relayref_direct", "port := 0", "RANGE", "host", edit=(("port", 0),)),
    *_size3("RelayRef", "relayref"),
    N("RelayRef", "relayref_direct", "drop-last", "SIZE", "truncated", final=drop_last),
    N("RelayRef", "relayref_direct", "append-zero", "TRAIL", "trailing", final=append_zero),
    # ----- D.3 InvitationV1
    N("InvitationV1", "invitation", "ver := 0x00", "VER", "ver", edit=(("ver", 0),)),
    N("InvitationV1", "invitation", "ver := 0x02", "VER", "ver", edit=(("ver", 2),)),
    N("InvitationV1", "invitation", "kind := 0x00", "TYPE", "type", edit=(("kind", 0),)),
    N("InvitationV1", "invitation", "kind := 0x02 (multi-use, reserved)", "RSV", "reserved", edit=(("kind", 2),)),
    N("InvitationV1", "invitation", "kind := 0x03", "TYPE", "type", edit=(("kind", 3),)),
    N("InvitationV1", "invitation", "kind := 0xff", "TYPE", "type", edit=(("kind", 0xFF),)),
    *[N("InvitationV1", "invitation", f"inv_period_s := {p}", "RANGE", "range", edit=(("inv_period_s", p),))
      for p in (0, 9, 11, 30, 160)],
    N("InvitationV1", "invitation", "inv_period_s := 0xffff", "OVF", "range", edit=(("inv_period_s", 0xFFFF),)),
    N("InvitationV1", "invitation", "relay.ver := 0x00", "NEST", "ver", edit=(("relay.ver", 0),)),
    N("InvitationV1", "invitation", "relay.direct_present := 0x02", "NEST", "bool",
      edit=(("relay.direct_present", 2),)),
    N("InvitationV1", "invitation_direct", "relay.host_len := host_len + 1", "NEST", "host",
      lens=(("relay.host_len", plus(1)),)),
    *_size3("InvitationV1", "invitation"),
    # ----- D.3 Profile
    N("Profile", "profile_max", "name := name ‖ `0` (65 B; name_len recomputed: maximum + 1)", "LEN", "len",
      edit=(("name", lambda b: b + b"0"),)),
    N("Profile", "profile_max", "name_len := 0xff", "OVF", "len", lens=(("name_len", 0xFF),)),
    N("Profile", "profile_max", "name_len := 63 (name kept)", "LEN", "bool", lens=(("name_len", 63),)),
    N("Profile", "profile_max", "name_len := 0 (name kept)", "LEN", "bool", lens=(("name_len", 0),)),
    N("Profile", "profile_max", "avatar_present := 0x02", "OPT", "bool", edit=(("avatar_present", 2),)),
    N("Profile", "profile_max", "avatar_present := 0 (avatar_sha256 kept)", "OPT", "trailing",
      edit=(("avatar_present", 0),)),
    N("Profile", "profile_utf8", "avatar_present := 1 (no avatar_sha256)", "OPT", "truncated",
      edit=(("avatar_present", 1),)),
    N("Profile", "profile_utf8", "name_len := name_len + 1", "LEN", "truncated", lens=(("name_len", plus(1)),)),
    N("Profile", "profile_utf8", "name[0] := 0xff", "UTF8", "utf8", edit=(("name", set_byte(0, 0xFF)),)),
    N("Profile", "profile_utf8", "name: last byte removed (a 4-byte sequence cut; name_len recomputed)", "UTF8",
      "utf8", edit=(("name", lambda b: b[:-1]),)),
    N("Profile", "profile_utf8", "name := c0 af (overlong `/`)", "UTF8", "utf8", edit=(("name", b"\xc0\xaf"),)),
    N("Profile", "profile_utf8", "name := ed a0 80 (UTF-16 surrogate U+D800)", "UTF8", "utf8",
      edit=(("name", b"\xed\xa0\x80"),)),
    N("Profile", "profile_utf8", "name := f4 90 80 80 (above U+10FFFF)", "UTF8", "utf8",
      edit=(("name", b"\xf4\x90\x80\x80"),)),
    *_size3("Profile", "profile_max"),
    # ----- D.3 LinkDataV1
    N("LinkDataV1", "linkdata", "ver := 0x00", "VER", "ver", edit=(("ver", 0),)),
    N("LinkDataV1", "linkdata", "inviter_iks.ik_dh := 01 00…00 (u = 1)", "NEST", "x25519-low-order",
      edit=(("inviter_iks.ik_dh", X_U1),)),
    N("LinkDataV1", "linkdata", f"inviter_iks.ik_ed25519 := {ED_ORDER8.hex()} (order 8)", "NEST",
      "ed25519-key-small-order", edit=(("inviter_iks.ik_ed25519", ED_ORDER8),)),
    N("LinkDataV1", "linkdata", "bundle.opk_present := 0", "NEST", "option", edit=(("bundle.opk_present", 0),)),
    N("LinkDataV1", "linkdata", "profile.name := name ‖ 49 × `a` (65 B; lengths recomputed)", "NEST", "len",
      edit=(("profile.name", lambda b: b + b"a" * (65 - len(b))),)),
    *_pad("LinkDataV1", "linkdata", markers=(0x00, 0x81)),
    N("LinkDataV1", "linkdata", "the unpadded fields alone", "PAD", "size", final=unpadded),
    *_opaque3("LinkDataV1", "linkdata"),
    # ----- D.3 LinkBlob
    *_opaque3("LinkBlob", "linkblob"),
    # ----- D.3 IKSPublic
    N("IKSPublic", "iks", "ver := 0x00", "VER", "ver", edit=(("ver", 0),)),
    N("IKSPublic", "iks", "ver := 0x02", "VER", "ver", edit=(("ver", 2),)),
    N("IKSPublic", "iks", "ver := 0xff", "VER", "ver", edit=(("ver", 0xFF),)),
    *_x_rows("IKSPublic", "iks", "ik_dh", enc.x25519_low_order_encodings()),
    *[N("IKSPublic", "iks", f"ik_ed25519 := {pt.hex()} ({name})", "ED25519", rule, edit=(("ik_ed25519", pt),))
      for pt, name, rule in (
          (ED_IDENTITY, "identity", "ed25519-key-small-order"),
          (ED_IDENTITY_SIGNX, "y = 1 with the x sign bit set", "ed25519-key-small-order"),
          (ED_ORDER2, "y = −1, order 2", "ed25519-key-small-order"),
          (ED_ORDER4, "y = 0, order 4", "ed25519-key-small-order"),
          (ED_ORDER4_SIGNX, "y = 0 with the x sign bit set, order 4", "ed25519-key-small-order"),
          (ED_ORDER8, "order 8", "ed25519-key-small-order"),
          (ED_ORDER8_NEG, "order 8, the other sign of x", "ed25519-key-small-order"),
          (ED_IDENTITY_NONCANON, "y = p + 1, non-canonical identity", "ed25519-key-noncanonical"),
          (ED_Y3_NONCANON, "y = p + 3, non-canonical", "ed25519-key-noncanonical"),
          (ED_Y18_NONCANON, "y = p + 18 = 2^255 − 1, non-canonical", "ed25519-key-noncanonical"))],
    N("IKSPublic", "iks", f"ik_ed25519 := {ED_Y2_OFF_CURVE.hex()} (y = 2: canonical, not a curve point)", "ED25519",
      "ed25519-key-off-curve", edit=(("ik_ed25519", ED_Y2_OFF_CURVE),)),
    *_size3("IKSPublic", "iks"),
    # ----- D.3 PrekeyBundle
    N("PrekeyBundle", "bundle", "ver := 0x00", "VER", "ver", edit=(("ver", 0),)),
    N("PrekeyBundle", "bundle", "opk_present := 0 (opk fields kept)", "OPT", "option", edit=(("opk_present", 0),)),
    N("PrekeyBundle", "bundle", "opk_present := 0, opk_id/opk_dh/opk_kem removed (6171 B: absent when required)",
      "OPT", "option", edit=(("opk_present", 0), ("opk_id", DEL), ("opk_dh", DEL), ("opk_kem", DEL))),
    N("PrekeyBundle", "bundle", "opk_present := 0x02", "OPT", "option", edit=(("opk_present", 2),)),
    *_x_rows("PrekeyBundle", "bundle", "spk_dh", (X_U0,)),
    *_x_rows("PrekeyBundle", "bundle", "opk_dh", (X_PM1, X_O8B)),
    N("PrekeyBundle", "bundle", "sig: Ed25519 S (bytes 32–63) := S + L", "ED25519", "ed25519-sig-S",
      edit=(("sig", s_plus_l),)),
    N("PrekeyBundle", "bundle", f"sig: Ed25519 R := {ED_ORDER8.hex()} (order 8)", "ED25519",
      "ed25519-sig-R-small-order", edit=(("sig", set_r(ED_ORDER8)),)),
    N("PrekeyBundle", "bundle", f"sig: Ed25519 R := {ED_Y3_NONCANON.hex()} (y = p + 3)", "ED25519",
      "ed25519-sig-R-noncanonical", edit=(("sig", set_r(ED_Y3_NONCANON)),)),
    *[N("PrekeyBundle", "bundle", f"{f} bytes 0–2 := ff ff ff (a coefficient ≥ q)", "MLKEM", "mlkem-ek",
        edit=((f, COEFF_GE_Q),)) for f in ("spk_kem", "rpk_kem", "opk_kem")],
    *_size3("PrekeyBundle", "bundle"),

    # ----- D.4
    N("Outer", "outer", "ver := 0x00", "VER", "ver", edit=(("ver", 0),)),
    N("Outer", "outer", "ver := 0x02", "VER", "ver", edit=(("ver", 2),)),
    *_x_rows("Outer", "outer", "ek_I", (X_U1, X_O8A, X_P1)),
    *_pad("Outer", "outer", markers=(0x00, 0xFF)),
    N("Outer", "outer", "the unpadded fields alone (9362 B)", "PAD", "size", final=unpadded),
    *_opaque3("Outer", "outer"),
    *_opaque3("inner_ct", "inner_ct"),
    N("Inner", "inner", "iks.ver := 0x00", "NEST", "ver", edit=(("iks.ver", 0),)),
    N("Inner", "inner", f"iks.ik_dh := {X_O8A.hex()} (order 8)", "NEST", "x25519-low-order",
      edit=(("iks.ik_dh", X_O8A),)),
    N("Inner", "inner", "iks.ik_ed25519 := 01 00…00 (identity)", "NEST", "ed25519-key-small-order",
      edit=(("iks.ik_ed25519", ED_IDENTITY),)),
    *_size3("Inner", "inner"),
    *_opaque3("HandshakeCell", "hs_cell"),
    N("HandshakeCellPlaintext", "hs_cell_pt", "i := 3", "RANGE", "range", edit=(("i", 3),)),
    N("HandshakeCellPlaintext", "hs_cell_pt", "i := 0xff", "OVF", "range", edit=(("i", 0xFF),)),
    *[N("HandshakeCellPlaintext", "hs_cell_pt", f"total := {t}", "RANGE", "range", edit=(("total", t),))
      for t in (0, 2, 4)],
    N("HandshakeCellPlaintext", "hs_cell_pt", "total := 0xff", "OVF", "range", edit=(("total", 0xFF),)),
    *_size3("HandshakeCellPlaintext", "hs_cell_pt"),

    # ----- D.5
    *_opaque3("Cell", "cell"),
    N("HeaderV1", "header", "ver := 0x00", "VER", "ver", edit=(("ver", 0),)),
    N("HeaderV1", "header", "ver := 0x02", "VER", "ver", edit=(("ver", 2),)),
    *[N("HeaderV1", "header", f"flags := 0x{f:02x}", "RSV", "reserved", edit=(("flags", f),)) for f in (0x01, 0x80, 0xFF)],
    *_x_rows("HeaderV1", "header", "dh_pk", (X_U0, X_O8B, X_P, topbit(X_U1))),
    N("HeaderV1", "header", "ek_pq bytes 0–2 := ff ff ff (a coefficient ≥ q)", "MLKEM", "mlkem-ek",
      edit=(("ek_pq", COEFF_GE_Q),)),
    *_size3("HeaderV1", "header"),
    # Content
    N("Content", "c_batch", "ver := 0x00", "VER", "ver", edit=(("ver", 0),)),
    N("Content", "c_batch", "ver := 0x02", "VER", "ver", edit=(("ver", 2),)),
    N("Content", "c_dummy", "type := 0x08", "TYPE", "type", edit=(("type", 0x08),)),
    N("Content", "c_dummy", "type := 0xff", "TYPE", "type", edit=(("type", 0xFF),)),
    N("Content", "c_dummy", "type := 0x05 (KeyChange: 5390 B never fits a body)", "TYPE", "truncated",
      edit=(("type", 0x05),)),
    N("Content", "c_dummy", "body := 00 (Dummy with a 1-byte body; body_len recomputed)", "LEN", "len",
      edit=(("body", b"\x00"),)),
    N("Content", "c_batch", "body_len := body_len + 1", "LEN", "trailing", lens=(("body_len", plus(1)),)),
    N("Content", "c_batch", "body_len := body_len − 1", "LEN", "truncated", lens=(("body_len", plus(-1)),)),
    N("Content", "c_batch", "body_len := 0 (body kept)", "LEN", "truncated", lens=(("body_len", 0),)),
    N("Content", "c_batch", "body_len := 0xffff", "OVF", "len", lens=(("body_len", 0xFFFF),)),
    N("Content", "c_fragment", "body.chunk ‖ 00 (body_len recomputed: 1690, maximum + 1; the fields fill all 1710 B, "
      "no room for the marker)", "LEN", "len", edit=(("body.chunk", lambda b: b + b"\x00"),)),
    *_pad("Content", "c_batch", markers=(0x00, 0x81)),
    *_opaque3("Content", "c_batch"),
    N("Content", "c_batch", "body.messages[0].kind := 0", "NEST", "type", edit=(("body.messages.0.kind", 0),)),
    N("Content", "c_batch", "body.messages[1].payload_len := payload_len + 1", "NEST", "truncated",
      lens=(("body.messages.1.payload_len", plus(1)),)),
    N("Content", "c_fragment", "body.total := 65", "NEST", "range", edit=(("body.total", 65),)),
    N("Content", "c_receipt", "body.kind := 3", "NEST", "type", edit=(("body.kind", 3),)),
    N("Content", "c_control", "body.code := 0", "NEST", "type", edit=(("body.code", 0),)),
    N("Content", "c_routeupdate", "body.routes[0].ver := 0x02", "NEST", "ver", edit=(("body.routes.0.ver", 2),)),
    N("Content", "c_handshake", "body.profile.avatar_present := 0x02", "NEST", "bool",
      edit=(("body.profile.avatar_present", 2),)),
    # AppMessage
    *[N("AppMessage", "appmsg", f"kind := {k}", "TYPE", "type", edit=(("kind", k),)) for k in (0, 7)],
    N("AppMessage", "appmsg", "kind := 0xff", "OVF", "type", edit=(("kind", 0xFF),)),
    N("AppMessage", "appmsg", "payload_len := payload_len + 1", "LEN", "truncated", lens=(("payload_len", plus(1)),)),
    N("AppMessage", "appmsg", "payload_len := payload_len − 1", "LEN", "trailing", lens=(("payload_len", plus(-1)),)),
    N("AppMessage", "appmsg", "payload_len := 0 (payload kept)", "LEN", "trailing", lens=(("payload_len", 0),)),
    N("AppMessage", "appmsg", "payload_len := 0xffff", "OVF", "truncated", lens=(("payload_len", 0xFFFF),)),
    *_size3("AppMessage", "appmsg"),
    # BatchBody
    N("BatchBody", "batch", "count := count + 1", "LEN", "truncated", lens=(("count", plus(1)),)),
    N("BatchBody", "batch", "count := count − 1", "LEN", "trailing", lens=(("count", plus(-1)),)),
    N("BatchBody", "batch", "count := 0 (messages kept)", "LEN", "range", lens=(("count", 0),)),
    N("BatchBody", "batch", "count := 0xff", "OVF", "truncated", lens=(("count", 0xFF),)),
    N("BatchBody", "batch", "messages[0].kind := 7", "NEST", "type", edit=(("messages.0.kind", 7),)),
    N("BatchBody", "batch", "messages[1].payload_len := payload_len + 1", "NEST", "truncated",
      lens=(("messages.1.payload_len", plus(1)),)),
    N("BatchBody", "batch", "messages := [] (count recomputed: 0)", "LEN", "range", edit=(("messages", []),)),
    *_size3("BatchBody", "batch"),
    # Fragment
    N("Fragment", "fragment", "total := 0", "RANGE", "range", edit=(("total", 0),)),
    N("Fragment", "fragment", "total := 65 (maximum + 1)", "RANGE", "range", edit=(("total", 65),)),
    N("Fragment", "fragment", "total := 0xffff", "OVF", "range", edit=(("total", 0xFFFF),)),
    N("Fragment", "fragment", "idx := 0xffff (> total)", "OVF", "range", edit=(("idx", 0xFFFF),)),
    N("Fragment", "fragment", "idx := 2 (= total)", "RANGE", "range", edit=(("idx", 2),)),
    N("Fragment", "fragment", "total := 1, idx := 0 (a second encoding of an unfragmented body)", "RANGE", "range",
      edit=(("total", 1), ("idx", 0))),
    N("Fragment", "fragment", "chunk := empty", "LEN", "len", edit=(("chunk", b""),)),
    N("Fragment", "fragment", "prefix(19) (header cut)", "SIZE", "truncated", final=prefix(19)),
    N("Fragment", "fragment", "empty (0 bytes)", "SIZE", "truncated", final=empty),
    # FragmentPayload
    N("FragmentPayload", "fragpayload", "inner_type := 0x08", "TYPE", "type",
      edit=(("inner_body", frozen("KeyChangeBody")), ("inner_type", 0x08))),
    N("FragmentPayload", "fragpayload", "inner_type := 0xff", "TYPE", "type",
      edit=(("inner_body", frozen("KeyChangeBody")), ("inner_type", 0xFF))),
    N("FragmentPayload", "fragpayload", "inner_body.iks.ik_dh := 00…00 (u = 0)", "NEST", "x25519-low-order",
      edit=(("inner_body.iks.ik_dh", X_U0),)),
    N("FragmentPayload", "fragpayload", "inner_body.sig: Ed25519 S := S + L", "NEST", "ed25519-sig-S",
      edit=(("inner_body.sig", s_plus_l),)),
    N("FragmentPayload", "fragpayload", "inner_type := 0x00, inner_body := empty (a Dummy)", "TYPE", "type",
      edit=(("inner_type", 0x00), ("inner_body", b""))),
    N("FragmentPayload", "fragpayload", "inner_type := 0x01, inner_body := HandshakeBody{profile {name `a`, "
      "avatar_present 0}, caps 0, one route: ver 1, kind 0x10, blob 01}", "TYPE", "type",
      edit=(("inner_type", 0x01), ("inner_body", INNER_HANDSHAKE))),
    N("FragmentPayload", "fragpayload", "inner_type := 0x03, inner_body := Fragment{msg_id 0^16, idx 0, total 2, "
      "chunk 8 × 01}", "TYPE", "type",
      edit=(("inner_type", 0x03), ("inner_body", {"msg_id": bytes(16), "idx": 0, "total": 2, "chunk": b"\x01" * 8}))),
    *_size3("FragmentPayload", "fragpayload"),
    # RouteDescriptor
    N("RouteDescriptor", "rd_relayqueue", "ver := 0x00", "VER", "ver", edit=(("ver", 0),)),
    N("RouteDescriptor", "rd_relayqueue", "ver := 0x02", "VER", "ver", edit=(("ver", 2),)),
    N("RouteDescriptor", "rd_unknown", "ver := 0x00 (unknown kind)", "VER", "ver", edit=(("ver", 0),)),
    N("RouteDescriptor", "rd_relayqueue", "len := len + 1", "LEN", "truncated", lens=(("len", plus(1)),)),
    N("RouteDescriptor", "rd_relayqueue", "len := len − 1", "LEN", "truncated", lens=(("len", plus(-1)),)),
    N("RouteDescriptor", "rd_relayqueue", "len := 0 (blob kept)", "LEN", "truncated", lens=(("len", 0),)),
    N("RouteDescriptor", "rd_relayqueue", "len := 0xffff", "OVF", "truncated", lens=(("len", 0xFFFF),)),
    N("RouteDescriptor", "rd_unknown", "len := len + 1 (unknown kind)", "LEN", "truncated", lens=(("len", plus(1)),)),
    N("RouteDescriptor", "rd_relayqueue", "blob ‖ 00 (len recomputed: trailing byte inside the blob)", "TRAIL",
      "trailing", edit=(("blob", lambda b: enc.raw("RelayQueue", b) + b"\x00"),)),
    N("RouteDescriptor", "rd_relayqueue", "blob.period_s removed (len recomputed)", "LEN", "truncated",
      edit=(("blob.period_s", DEL),)),
    N("RouteDescriptor", "rd_relayqueue", "blob.period_s := 30", "RANGE", "range", edit=(("blob.period_s", 30),)),
    N("RouteDescriptor", "rd_relayqueue", "blob.period_s := 0", "RANGE", "range", edit=(("blob.period_s", 0),)),
    N("RouteDescriptor", "rd_relayqueue", "blob.relay.ver := 0x02", "NEST", "ver", edit=(("blob.relay.ver", 2),)),
    *_size3("RouteDescriptor", "rd_relayqueue"),
    N("RouteDescriptor", "rd_unknown", "append-zero (unknown kind)", "TRAIL", "trailing", final=append_zero),
    # RelayQueue
    *[N("RelayQueue", "relayqueue", f"period_s := {p}", "RANGE", "range", edit=(("period_s", p),)) for p in (0, 15, 30)],
    N("RelayQueue", "relayqueue", "period_s := 0xffff", "OVF", "range", edit=(("period_s", 0xFFFF),)),
    N("RelayQueue", "relayqueue", "relay.ver := 0x00", "NEST", "ver", edit=(("relay.ver", 0),)),
    *_size3("RelayQueue", "relayqueue"),
    # RouteUpdateBody
    N("RouteUpdateBody", "routeupdate", "count := count + 1", "LEN", "truncated", lens=(("count", plus(1)),)),
    N("RouteUpdateBody", "routeupdate", "count := count − 1", "LEN", "trailing", lens=(("count", plus(-1)),)),
    N("RouteUpdateBody", "routeupdate", "count := 0 (routes kept)", "LEN", "range", lens=(("count", 0),)),
    N("RouteUpdateBody", "routeupdate", "count := 0xff", "OVF", "truncated", lens=(("count", 0xFF),)),
    N("RouteUpdateBody", "routeupdate", "routes[0].blob.period_s := 30", "NEST", "range",
      edit=(("routes.0.blob.period_s", 30),)),
    N("RouteUpdateBody", "routeupdate", "routes[1].len := len + 1", "NEST", "truncated",
      lens=(("routes.1.len", plus(1)),)),
    N("RouteUpdateBody", "routeupdate", "routes := [] (count recomputed: 0)", "LEN", "range", edit=(("routes", []),)),
    *_size3("RouteUpdateBody", "routeupdate"),
    # HandshakeBody
    N("HandshakeBody", "handshake", "route_count := route_count + 1", "LEN", "truncated",
      lens=(("route_count", plus(1)),)),
    N("HandshakeBody", "handshake", "route_count := route_count − 1", "LEN", "trailing",
      lens=(("route_count", plus(-1)),)),
    N("HandshakeBody", "handshake", "route_count := 0 (routes kept)", "LEN", "range", lens=(("route_count", 0),)),
    N("HandshakeBody", "handshake", "route_count := 0xff", "OVF", "truncated", lens=(("route_count", 0xFF),)),
    N("HandshakeBody", "handshake", "profile.name := name ‖ 57 × `a` (65 B; name_len recomputed)", "NEST", "len",
      edit=(("profile.name", lambda b: b + b"a" * (65 - len(b))),)),
    N("HandshakeBody", "handshake", "profile.avatar_present := 0xff", "NEST", "bool",
      edit=(("profile.avatar_present", 0xFF),)),
    N("HandshakeBody", "handshake", "routes[0].blob.period_s := 15", "NEST", "range",
      edit=(("routes.0.blob.period_s", 15),)),
    N("HandshakeBody", "handshake", "routes[1].ver := 0x00 (the unknown-kind route)", "NEST", "ver",
      edit=(("routes.1.ver", 0),)),
    N("HandshakeBody", "handshake", "caps := 0x00000001", "RSV", "reserved", edit=(("caps", 1),)),
    N("HandshakeBody", "handshake", "caps := 0x80000000", "RSV", "reserved", edit=(("caps", 0x80000000),)),
    N("HandshakeBody", "handshake", "routes := [] (route_count recomputed: 0)", "LEN", "range", edit=(("routes", []),)),
    *_size3("HandshakeBody", "handshake"),
    # KeyChangeBody
    N("KeyChangeBody", "keychange", "iks.ver := 0x02", "NEST", "ver", edit=(("iks.ver", 2),)),
    N("KeyChangeBody", "keychange", f"iks.ik_dh := {topbit(X_O8A).hex()} (order 8, bit 255 set)", "NEST",
      "x25519-low-order", edit=(("iks.ik_dh", topbit(X_O8A)),)),
    N("KeyChangeBody", "keychange", f"iks.ik_ed25519 := {ED_ORDER8_NEG.hex()} (order 8)", "NEST",
      "ed25519-key-small-order", edit=(("iks.ik_ed25519", ED_ORDER8_NEG),)),
    N("KeyChangeBody", "keychange", "sig: Ed25519 S := S + L", "ED25519", "ed25519-sig-S", edit=(("sig", s_plus_l),)),
    N("KeyChangeBody", "keychange", "sig: Ed25519 R := 01 00…00 (identity)", "ED25519", "ed25519-sig-R-small-order",
      edit=(("sig", set_r(ED_IDENTITY)),)),
    N("KeyChangeBody", "keychange", f"sig: Ed25519 R := {ED_Y3_NONCANON.hex()} (y = p + 3)", "ED25519",
      "ed25519-sig-R-noncanonical", edit=(("sig", set_r(ED_Y3_NONCANON)),)),
    *_size3("KeyChangeBody", "keychange"),
    # ReceiptBody
    *[N("ReceiptBody", "receipt", f"kind := {k}", "TYPE", "type", edit=(("kind", k),)) for k in (0, 3)],
    N("ReceiptBody", "receipt", "kind := 0xff", "OVF", "type", edit=(("kind", 0xFF),)),
    N("ReceiptBody", "receipt", "count := count + 1", "LEN", "truncated", lens=(("count", plus(1)),)),
    N("ReceiptBody", "receipt", "count := count − 1", "LEN", "trailing", lens=(("count", plus(-1)),)),
    N("ReceiptBody", "receipt", "count := 0 (msg_ids kept)", "LEN", "range", lens=(("count", 0),)),
    N("ReceiptBody", "receipt", "count := 0xff", "OVF", "truncated", lens=(("count", 0xFF),)),
    N("ReceiptBody", "receipt", "msg_ids := [] (count recomputed: 0)", "LEN", "range", edit=(("msg_ids", []),)),
    *_size3("ReceiptBody", "receipt"),
    # ControlBody
    *[N("ControlBody", "control", f"code := {c}", "TYPE", "type", edit=(("code", c),)) for c in (0, 3)],
    N("ControlBody", "control", "code := 0xff", "OVF", "type", edit=(("code", 0xFF),)),
    N("ControlBody", "control", "arg_len := 1 (no arg bytes)", "LEN", "truncated", lens=(("arg_len", 1),)),
    N("ControlBody", "control", "arg_len := 0xffff", "OVF", "truncated", lens=(("arg_len", 0xFFFF),)),
    N("ControlBody", "control_arg", "arg_len := arg_len − 1", "LEN", "trailing", lens=(("arg_len", plus(-1)),)),
    N("ControlBody", "control_arg", "arg_len := 0 (arg kept)", "LEN", "trailing", lens=(("arg_len", 0),)),
    *_size3("ControlBody", "control"),
]


# ---------------------------------------------------------------------------------------------
# Provenance, for SCHEMA §4.8's "Changes from the proposal": the rows the proposal withheld on
# SQ-12 … SQ-18 (written since Weisung REF-M2-1, correction 3) and the rows the Weisung added
# (correction 4, addition 2), as positive keys and (structure, start of the manipulation text).

FORMERLY_WITHHELD_POSITIVES = ["fragment_idx0"]
FORMERLY_WITHHELD = [
    ("SQ-12", "IKSPublic", "ik_ed25519 := 0200"), ("SQ-12", "RelayInfoV1", "sig: R := 0200"),
    ("SQ-12", "PrekeyBundle", "spk_kem bytes 0–2"), ("SQ-12", "HeaderV1", "ek_pq bytes 0–2"),
    ("SQ-13", "RelayRef", "onion[34]"), ("SQ-13", "RelayRef", "onion[32]"),
    ("SQ-14", "RelayRef", "host := empty"), ("SQ-14", "RelayRef", "host := 254"),
    ("SQ-14", "RelayRef", "host[5]"), ("SQ-14", "RelayRef", "port := 0"),
    ("SQ-15", "HandshakeBody", "caps := 0x00000001"), ("SQ-15", "HandshakeBody", "caps := 0x80000000"),
    ("SQ-17", "BatchBody", "messages := []"), ("SQ-17", "RouteUpdateBody", "routes := []"),
    ("SQ-17", "HandshakeBody", "routes := []"), ("SQ-17", "ReceiptBody", "msg_ids := []"),
    ("SQ-18", "Fragment", "idx := 2 (= total)"), ("SQ-18", "Fragment", "total := 1, idx := 0"),
    ("SQ-18", "Fragment", "chunk := empty"), ("SQ-18", "FragmentPayload", "inner_type := 0x03"),
    ("SQ-18", "FragmentPayload", "inner_type := 0x00"),
]
# The one formerly withheld row whose answered outcome differs from the proposal's reading.
OUTCOME_DIFFERS_FROM_PROPOSAL = [("Fragment", "total := 1, idx := 0")]

ADDED_POSITIVES = ["relayinfo_max", "q_fetch_max", "r_ok_send_max", "relayref_max", "invitation_max",
                   "header_max", "c_dummy_max", "appmsg_max", "fragment_max", "rd_unknown_max",
                   "receipt_max", "control_arg", "control_max"]
ADDED = [
    ("addition 2", "RelayInfoV1", "relay_kem_ek bytes 0–2"), ("addition 2", "Record/HS1", "ek_c bytes 0–2"),
    ("addition 2", "PrekeyBundle", "rpk_kem bytes 0–2"), ("addition 2", "PrekeyBundle", "opk_kem bytes 0–2"),
    ("correction 4", "FragmentPayload", "inner_type := 0x01"),
    ("correction 4", "Request/LINK_GET", "sig: R := "),
    ("correction 4", "ControlBody", "arg_len := arg_len − 1"), ("correction 4", "ControlBody", "arg_len := 0 (arg kept)"),
]


def rows_matching(structure, start):
    """Row numbers of the negatives of `structure` whose manipulation starts with `start`."""
    first = len(POSITIVES) + 1
    return [i for i, n in enumerate(NEGATIVES, start=first)
            if n.structure == structure and n.manipulation.startswith(start)]


# ---------------------------------------------------------------------------------------------
# Structures, and the negative families that apply to each (for the coverage check)

APPLIES = {
    "Record/HELLO": {"VER", "SIZE", "TRAIL", "LEN", "OVF", "TYPE"},
    "Record/RELAYINFO": {"SIZE", "TRAIL", "LEN", "OVF", "TYPE", "NEST"},
    "RelayInfoV1": {"VER", "SIZE", "TRAIL", "X25519", "ED25519", "MLKEM"},
    "Record/HS1": {"VER", "SIZE", "TRAIL", "LEN", "OVF", "TYPE", "X25519", "MLKEM"},
    "Record/HS2": {"VER", "SIZE", "TRAIL", "LEN", "OVF", "TYPE", "X25519"},
    R + "QUEUE_NEW": {"SIZE", "PAD", "ED25519"},
    R + "SEND": {"SIZE", "PAD", "ED25519"},
    R + "FETCH": {"SIZE", "PAD", "ED25519"},
    R + "FETCH_MULTI": {"SIZE", "PAD", "ED25519", "LEN", "OVF", "RANGE"},
    R + "QUEUE_DEL": {"SIZE", "PAD", "ED25519"},
    R + "LINK_PUT": {"SIZE", "PAD", "ED25519", "OPT"},
    R + "LINK_GET": {"SIZE", "PAD", "ED25519", "OPT", "RSV", "RANGE"},
    R + "PING": {"SIZE", "PAD", "TYPE", "RSV"},
    R + "CONT": {"SIZE", "PAD", "RANGE", "OVF"},
    S + "OK": {"SIZE", "PAD", "TYPE"},
    S + "OK_QUEUE_NEW": {"SIZE", "PAD"},
    S + "OK_SEND": {"SIZE", "PAD", "OPT", "RSV"},
    S + "CELLR": {"SIZE", "PAD", "RANGE", "RSV", "CTX"},
    S + "LINKR": {"SIZE", "PAD", "OPT"},
    S + "ERR": {"SIZE", "PAD", "TYPE", "OVF"},
    S + "CONT": {"SIZE", "PAD", "RANGE", "OVF"},
    "RelayRef": {"VER", "SIZE", "TRAIL", "LEN", "OVF", "OPT", "TYPE", "RANGE"},
    "InvitationV1": {"VER", "SIZE", "TRAIL", "TYPE", "RSV", "RANGE", "OVF", "NEST"},
    "Profile": {"SIZE", "TRAIL", "LEN", "OVF", "OPT", "UTF8"},
    "LinkDataV1": {"VER", "SIZE", "PAD", "NEST"},
    "LinkBlob": {"SIZE"},
    "IKSPublic": {"VER", "SIZE", "TRAIL", "X25519", "ED25519"},
    "PrekeyBundle": {"VER", "SIZE", "TRAIL", "OPT", "X25519", "ED25519", "MLKEM"},
    "Outer": {"VER", "SIZE", "PAD", "X25519"},
    "inner_ct": {"SIZE"},
    "Inner": {"SIZE", "TRAIL", "NEST"},
    "HandshakeCell": {"SIZE"},
    "HandshakeCellPlaintext": {"SIZE", "TRAIL", "RANGE", "OVF"},
    "Cell": {"SIZE"},
    "HeaderV1": {"VER", "SIZE", "TRAIL", "RSV", "X25519", "MLKEM"},
    "Content": {"VER", "SIZE", "PAD", "TYPE", "LEN", "OVF", "NEST"},
    "AppMessage": {"SIZE", "TRAIL", "TYPE", "LEN", "OVF"},
    "BatchBody": {"SIZE", "TRAIL", "LEN", "OVF", "NEST"},
    "Fragment": {"SIZE", "RANGE", "OVF", "LEN"},
    "FragmentPayload": {"SIZE", "TRAIL", "TYPE", "NEST"},
    "RouteDescriptor": {"VER", "SIZE", "TRAIL", "LEN", "OVF", "RANGE", "NEST"},
    "RelayQueue": {"SIZE", "TRAIL", "RANGE", "OVF", "NEST"},
    "RouteUpdateBody": {"SIZE", "TRAIL", "LEN", "OVF", "NEST"},
    "HandshakeBody": {"SIZE", "TRAIL", "LEN", "OVF", "NEST", "RSV"},
    "KeyChangeBody": {"SIZE", "TRAIL", "NEST", "ED25519"},
    "ReceiptBody": {"SIZE", "TRAIL", "TYPE", "LEN", "OVF"},
    "ControlBody": {"SIZE", "TRAIL", "TYPE", "LEN", "OVF"},
    **{s: set() for s in enc.SIGNED},             # D.6: encode only, no decoder
}
assert set(APPLIES) == set(enc.DECODERS) | set(enc.SIGNED)
assert {p.structure for p in POSITIVES} == set(APPLIES)


# ---------------------------------------------------------------------------------------------
# Building the cases

def _path_set(v, path, val):
    keys = path.split(".")
    for k in keys[:-1]:
        v = v[int(k)] if isinstance(v, list) else v[k]
    last = int(keys[-1]) if isinstance(v, list) else keys[-1]
    if val is DEL:
        del v[last]
    elif callable(val):
        v[last] = val(v[last])
    else:
        v[last] = copy.deepcopy(val)


def honest_value(key: str, i: int) -> dict:
    """Row `key`'s recipe run on case i's stream."""
    return POS_BY_KEY[key].recipe(CaseStream(SUITE, i))


def negative_bytes(neg: Neg, i: int) -> bytes:
    v = copy.deepcopy(honest_value(neg.row, i))
    for path, val in neg.edit:
        _path_set(v, path, val)
    enc.refresh(neg.structure, v)
    for path, val in neg.lens:
        _path_set(v, path, val)
    p = enc.payload(neg.structure, v)
    size = enc.PAD_TO.get(neg.structure)
    data = enc.iso_pad(p, size) if size and len(p) < size else p
    return neg.final(p, data) if neg.final else data


def context_of(neg: Neg):
    return neg.context or POS_BY_KEY[neg.row].context


def outcome(structure, data, context):
    """(accepted, rule) under the current mode."""
    try:
        enc.decode(structure, data, context)
    except Reject:
        return False, enc.last_rule
    return True, None


def _check_positive(i, pos, value, data):
    if pos.structure in enc.SIGNED:
        return
    if enc.decode(pos.structure, data, pos.context) != value:
        raise TableMismatch(f"enc row {i} ({pos.key}): decode(encode(value)) ≠ value")
    if enc.raw(pos.structure, value) != data:
        raise TableMismatch(f"enc row {i} ({pos.key}): encode(decode(bytes)) ≠ bytes")
    expected = enc.FIXED_SIZE.get(pos.structure)
    if expected is not None and len(data) != expected:
        raise TableMismatch(f"enc row {i} ({pos.key}): {len(data)} B, App. B/D says {expected}")


def check_negative(i, neg, data):
    """Rejected, by the stated rule if the table names one. → the rule that fired."""
    ctx = context_of(neg)
    accepted, rule = outcome(neg.structure, data, ctx)
    if accepted:
        raise TableMismatch(f"enc row {i} ({neg.structure}: {neg.manipulation}): accepted")
    if rule == "noncanonical" or (neg.rule is not None and rule != neg.rule):
        raise TableMismatch(f"enc row {i} ({neg.structure}: {neg.manipulation}): rejected by {rule}, "
                            f"the table says {neg.rule}")
    return rule


def encodings_cases() -> list[Case]:
    cases = []
    for i, pos in enumerate(POSITIVES, start=1):
        value = honest_value(pos.key, i)
        data = enc.encode(pos.structure, value, pos.context)
        _check_positive(i, pos, value, data)
        inputs = {"structure": pos.structure, "value": value}
        if pos.context:
            inputs["context"] = pos.context
        cases.append(Case(i, "encode", inputs, {"bytes": data}))
    for i, neg in enumerate(NEGATIVES, start=len(POSITIVES) + 1):
        data = negative_bytes(neg, i)
        check_negative(i, neg, data)
        inputs = {"structure": neg.structure, "bytes": data}
        if context_of(neg):
            inputs["context"] = context_of(neg)
        cases.append(Case(i, "decode", inputs, None))
    return cases
