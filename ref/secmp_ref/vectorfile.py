# SPDX-License-Identifier: AGPL-3.0-or-later
"""The vector-file format of SCHEMA.md rev 3 (rev 2 for the M1 files) and the per-case input randomness.

SCHEMA §1: file shape, value encodings, canonical writer, structural comparison.
SCHEMA §2: seed_i and stream_i (SQ-01, Reading A). SCHEMA §3: suite tags (SQ-02, Reading A).
SCHEMA §4 (preamble): the manipulations flip / drop-last / append-zero / prefix.
"""

import json
import re
from typing import NamedTuple

from . import labels
from .primitives import sha256, shake256

SCHEMA = 2
# SCHEMA §1 (REF-M2-1 correction 2): encodings.json is "schema": 3, for its nested `value` objects and
# arrays and the ASCII fields `structure`/`context`; the M1 files keep 2. Brief REF-M3: tr.json is
# "schema": 4, for its case-level fields (SCHEMA §4.9).
SUITE_SCHEMA = {"encodings": 3, "tr": 4}
SPEC = "SecMP/1 rev 2.2"
# Weisung REF-M2-3: encodings.json names spec rev 2.3 (ADR-039); the M1 files keep rev 2.2.
SUITE_SPEC = {"encodings": "SecMP/1 rev 2.3", "tr": "SecMP/1 rev 2.3"}
GENERATOR = "ref-python"


def schema_of(suite: str) -> int:
    return SUITE_SCHEMA.get(suite, SCHEMA)


def spec_of(suite: str) -> str:
    return SUITE_SPEC.get(suite, SPEC)

# SCHEMA §3
SUITE_TAGS = {
    "hkdf-labels": "hkdf",
    "caead": "caead",
    "msgencrypt": "msgenc",
    "hybridkem-768": "hk768",
    "hybridkem-1024": "hk1024",
    "hybridsign": "hsig",
    "fingerprint": "fp",
    "sas": "sas",
    "encodings": "enc",                      # brief REF-M2 / proposal SCHEMA-4.8-encodings.md
    "tr": "tr",                              # brief REF-M3 / proposal SCHEMA-4.9-tr.md
}

# SCHEMA §1 / SQ-04: the operation names (encode/decode: proposal SCHEMA-4.8).
POSITIVE_OPS = {"seal", "encaps", "sign", "derive", "fp", "sas", "encode"}
NEGATIVE_OPS = {"open", "decaps", "encaps-to", "verify", "decode"}

# SCHEMA §1 / SQ-03: fields that are not byte strings. Every other input/output field is a byte
# string, written as lowercase hex. `structure` and `context` name an encodings structure and the
# request a response answers (proposal SCHEMA-4.8); nested values are covered by _check_nested.
ASCII_FIELDS = {"label", "mode", "structure", "context"}
DIGIT_FIELDS = {"half_a", "half_b", "safety_number"}
INT_FIELDS = {"len"}
BOOL_FIELDS = {"verify"}

HEX_RE = re.compile(r"^([0-9a-f]{2})*$")
DIGITS_RE = re.compile(r"^[0-9]+$")


def case_seed(suite: str, i: int) -> bytes:
    """SCHEMA §2: seed_i = SHA-256(ASCII("SecMP-vectors/1") ‖ ASCII(<suite name>) ‖ u32be(i)),
    i = the case index (1, 2, …) = the number in the case id."""
    return sha256(labels.VECTORS + suite.encode("ascii") + i.to_bytes(4, "big"))


class CaseStream:
    """SCHEMA §2: stream_i = SHAKE-256(seed_i), one XOF stream per case, consumed front to back."""

    def __init__(self, suite: str, i: int):
        self._seed = case_seed(suite, i)
        self._used = 0

    def take(self, n: int) -> bytes:
        out = shake256(self._seed, self._used + n)[self._used:]
        self._used += n
        return out


class Case(NamedTuple):
    """One case before encoding. outputs None means "expect": "reject". `fields` holds case-level
    fields besides id/op/inputs/outputs (tr, SCHEMA §4.9: party, msg, from, count, manipulation, and
    `expect` for a recv-reject, which also has outputs)."""
    i: int
    op: str
    inputs: dict
    outputs: dict | None
    fields: dict | None = None


# ---------------------------------------------------------------------------------------------
# SCHEMA §4 manipulations. They apply to the honest value; the result is what the file lists.


def flip(value: bytes, k: int) -> bytes:
    """flip(field, k): XOR byte k with 0x01; negative k counts from the end (-1 = last byte)."""
    out = bytearray(value)
    out[k] ^= 0x01
    return bytes(out)


def drop_last(value: bytes) -> bytes:
    return value[:-1]


def append_zero(value: bytes) -> bytes:
    return value + b"\x00"


def prefix(value: bytes, n: int) -> bytes:
    return value[:n]


# ---------------------------------------------------------------------------------------------
# Writing


def case_id(suite: str, i: int) -> str:
    """SCHEMA §1: `<suite-tag>-<4-digit index>`, index from 0001."""
    return f"{SUITE_TAGS[suite]}-{i:04d}"


def encode_value(value):
    """SCHEMA §1: byte strings as lowercase hex; integers as JSON numbers; labels, digit strings,
    mode and op as JSON strings; booleans as JSON booleans."""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, dict):                  # encodings: a structure value (proposal SCHEMA-4.8)
        return {k: encode_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [encode_value(v) for v in value]
    raise TypeError(f"no vector encoding for {type(value).__name__}")


def canonical_json(doc) -> bytes:
    """SCHEMA §1 writer: keys sorted by code point at every level, separators (",", ":"),
    ASCII only, no trailing newline."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def suite_document(suite: str, cases: list[Case]) -> dict:
    out = []
    for case in sorted(cases, key=lambda c: c.i):
        entry = {"id": case_id(suite, case.i), "op": case.op,
                 "inputs": {k: encode_value(v) for k, v in case.inputs.items()}}
        entry.update(case.fields or {})
        if case.outputs is None:
            entry["expect"] = "reject"
        else:
            entry["outputs"] = {k: encode_value(v) for k, v in case.outputs.items()}
        out.append(entry)
    return {"schema": schema_of(suite), "suite": suite, "spec": spec_of(suite), "generator": GENERATOR,
            "cases": out}


# ---------------------------------------------------------------------------------------------
# Reading: validation and the structural comparison of SCHEMA §1


NESTED_NAME_FIELDS = {"op", "mode"}             # SCHEMA §1: `op`/`mode` are JSON strings, in `value` too


def _check_nested(value, key=None):
    """Inside an encodings structure value (SCHEMA §4.8): `op` and `mode` are ASCII names; other
    integers (booleans included) are JSON numbers, every other string is a byte string in lowercase
    hex, objects and arrays nest."""
    if isinstance(value, dict):
        for k, v in value.items():
            _check_nested(v, k)
    elif isinstance(value, list):
        for v in value:
            _check_nested(v)
    elif key in NESTED_NAME_FIELDS:
        if not (isinstance(value, str) and value and value.isascii()):
            raise ValueError(f"nested {key!r}: {value!r} is not a name")
    elif isinstance(value, bool) or not (isinstance(value, int) or
                                          (isinstance(value, str) and HEX_RE.match(value))):
        raise ValueError(f"nested value {value!r}")


def _check_field(name, value):
    if isinstance(value, (dict, list)):
        _check_nested(value)
        return
    if name in ASCII_FIELDS:
        ok = isinstance(value, str) and value.isascii()
    elif name in DIGIT_FIELDS:
        ok = isinstance(value, str) and DIGITS_RE.match(value) is not None
    elif name in INT_FIELDS:
        ok = isinstance(value, int) and not isinstance(value, bool)
    elif name in BOOL_FIELDS:
        ok = isinstance(value, bool)
    else:
        ok = isinstance(value, str) and HEX_RE.match(value) is not None
    if not ok:
        raise ValueError(f"field {name!r}: bad value {value!r}")


# SCHEMA §4.9 (tr, "schema": 4): the case-level keys per op, and the output keys.
TR_CASE_KEYS = {
    "init": ({"party"}, {"state_post_A", "state_post_B"}),
    "send": ({"party", "msg"}, {"cell", "state_pre", "state_post"}),
    "recv": ({"party", "msg", "from"}, {"content", "state_pre", "state_post"}),
    "advance": ({"party", "count"}, {"state_pre", "state_post"}),
    "recv-reject": ({"party", "msg", "from", "manipulation", "expect"}, {"state_pre", "state_post"}),
}
MSG_RE = re.compile(r"^m[0-9]{2}$")


def _validate_tr_case(case: dict, earlier_ids: set) -> None:
    op = case.get("op")
    if op not in TR_CASE_KEYS:
        raise ValueError(f"{case['id']}: op {op!r}")
    extra, outputs = TR_CASE_KEYS[op]
    if set(case) != {"id", "op", "inputs", "outputs"} | extra:
        raise ValueError(f"{case['id']}: keys {sorted(case)}")
    if set(case["outputs"]) != outputs:
        raise ValueError(f"{case['id']}: output keys {sorted(case['outputs'])}")
    if case["party"] not in (("AB",) if op == "init" else ("A", "B")):
        raise ValueError(f"{case['id']}: party {case['party']!r}")
    if "msg" in case and not (isinstance(case["msg"], str) and MSG_RE.match(case["msg"])):
        raise ValueError(f"{case['id']}: msg {case['msg']!r}")
    if "from" in case and case["from"] not in earlier_ids:
        raise ValueError(f"{case['id']}: from {case['from']!r} is not an earlier case")
    if "count" in case and (isinstance(case["count"], bool) or not isinstance(case["count"], int)
                            or case["count"] < 1):
        raise ValueError(f"{case['id']}: count {case['count']!r}")
    if "manipulation" in case and not (isinstance(case["manipulation"], str) and case["manipulation"].isascii()):
        raise ValueError(f"{case['id']}: manipulation {case['manipulation']!r}")
    if "expect" in case and case["expect"] != "reject":
        raise ValueError(f"{case['id']}: expect {case['expect']!r}")
    for name, value in [*case["inputs"].items(), *case["outputs"].items()]:
        if not (isinstance(value, str) and HEX_RE.match(value)):
            raise ValueError(f"{case['id']}: field {name!r} is not a byte string")


def validate_document(doc: dict) -> None:
    """Raises ValueError unless doc has the SCHEMA §1 shape."""
    if set(doc) != {"schema", "suite", "spec", "generator", "cases"}:
        raise ValueError(f"top-level keys {sorted(doc)}")
    if doc["suite"] not in SUITE_TAGS or doc["schema"] != schema_of(doc["suite"]):
        raise ValueError("schema or suite")
    if doc["suite"] == "tr":
        seen = set()
        for n, case in enumerate(doc["cases"], start=1):
            if case.get("id") != case_id("tr", n):
                raise ValueError(f"case {n}: id {case.get('id')!r} (ids start at 0001, no gaps, in order)")
            _validate_tr_case(case, seen)
            seen.add(case["id"])
        return
    for n, case in enumerate(doc["cases"], start=1):
        if case.get("id") != case_id(doc["suite"], n):
            raise ValueError(f"case {n}: id {case.get('id')!r} (ids start at 0001, no gaps, in order)")
        if case.get("op") not in POSITIVE_OPS | NEGATIVE_OPS:
            raise ValueError(f"{case['id']}: op {case.get('op')!r}")
        if "expect" in case:
            if set(case) != {"id", "op", "inputs", "expect"} or case["expect"] != "reject":
                raise ValueError(f"{case['id']}: reject case keys {sorted(case)}")
            fields = case["inputs"].items()
        else:
            if set(case) != {"id", "op", "inputs", "outputs"}:
                raise ValueError(f"{case['id']}: keys {sorted(case)}")
            fields = [*case["inputs"].items(), *case["outputs"].items()]
        for name, value in fields:
            _check_field(name, value)


def _json_equal(x, y) -> bool:
    # Python's == would equate true with 1 and 1 with 1.0; JSON values of different types differ.
    if type(x) is not type(y):
        return False
    if isinstance(x, dict):
        return x.keys() == y.keys() and all(_json_equal(x[k], y[k]) for k in x)
    if isinstance(x, list):
        return len(x) == len(y) and all(_json_equal(u, v) for u, v in zip(x, y))
    return x == y


def documents_equal(a: bytes, b: bytes) -> bool:
    """SCHEMA §1: parse both files, remove `generator`, compare the JSON values. No case-folding."""
    da, db = json.loads(a), json.loads(b)
    da.pop("generator", None)
    db.pop("generator", None)
    return _json_equal(da, db)
