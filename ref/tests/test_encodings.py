# SPDX-License-Identifier: AGPL-3.0-or-later
"""Suite `encodings` (spec §4.1, App. B, App. D; SCHEMA §4.8 = SCHEMA-4.8-encodings.md, with the
answers to SQ-12 … SQ-19 and the corrections of Weisung REF-M2-1)."""

import base64
import collections
import hashlib
import json
import os
import pathlib
import random

import nacl.bindings
import nacl.exceptions
import pytest

import _ed25519_model as edm
import gen_vectors
from _spec import appendix
from secmp_ref import encodings as enc
from secmp_ref import encodings_cases as ec
from secmp_ref import hybridkem, labels, primitives, sizes, vectorfile
from secmp_ref.cases import TableMismatch
from secmp_ref.errors import Reject

SCHEMA_4_8 = pathlib.Path(__file__).resolve().parent.parent.parent / "SCHEMA-4.8-encodings.md"


@pytest.fixture(scope="module")
def document():
    return gen_vectors.suite_bytes("encodings")


@pytest.fixture(scope="module")
def cases_by_id(document):
    return {c["id"]: c for c in json.loads(document)["cases"]}


# ---------------------------------------------------------------------------------------------
# Constants against the spec text


def test_appendix_b_sizes_are_the_encoded_sizes():
    """Every positive of a fixed-size structure has its App. B / D size (also asserted while
    generating); here against the literal App. B numbers."""
    b = appendix("B")
    for text in ("| `IKSPublic` | 2017 |", "| `PrekeyBundle` | 7775 |", "| `LinkDataV1` padded / blob | 12288 / 12360",
                 "| `HeaderV1` / `hdr_ct` | 2314 / 2330 |", "| Cell / `BODY_LEN` / Frame / frame plaintext | 4096 / 1710 / 4352 / 4336 |",
                 "| Handshake `Outer` / padded / cells | 9362 / 12018 / 3 × 4096 |",
                 "| `RelayInfoV1` / HS1 / HS2 | 1741 / 2853 / 1153 |", "| `InvitationV1` (no direct) | 241"):
        assert text in b
    sizes_seen = {}
    for i, pos in enumerate(ec.POSITIVES, start=1):
        if pos.structure not in enc.SIGNED:
            sizes_seen[pos.key] = len(enc.encode(pos.structure, ec.honest_value(pos.key, i), pos.context))
    assert sizes_seen["iks"] == 2017 and sizes_seen["bundle"] == 7775
    assert sizes_seen["linkdata"] == 12288 and sizes_seen["linkblob"] == 12360
    assert sizes_seen["header"] == 2314 and sizes_seen["cell"] == 4096 and sizes_seen["hs_cell"] == 4096
    assert sizes_seen["outer"] == 12018 and sizes_seen["relayinfo"] == 1741
    assert sizes_seen["hs1"] == 2 + 1 + 2853 and sizes_seen["hs2"] == 2 + 1 + 1153 and sizes_seen["hello"] == 2 + 7
    assert sizes_seen["invitation"] == 241
    assert all(sizes_seen[k] == 4336 for k in sizes_seen if k[:2] in ("q_", "r_"))
    assert sizes_seen["keychange"] == 5390 and sizes_seen["inner"] == 6113 and sizes_seen["inner_ct"] == 6185
    assert sizes_seen["hs_cell_pt"] == 4024


def test_appendix_d_quoted_constants():
    d = appendix("D")
    assert 'HELLO      = 0x01 ‖ "SECMP" ‖ ver(0x01)                                             (7 B)' in d
    assert "0x05 FETCH_MULTI  count u8 (1..=32)" in d
    assert "4160 + 4100 + 4100 = 12360" in d
    assert "total u8 (=3) ‖ chunk[4006]" in d
    assert "code u8   ; 1 TOKEN, 2 FULL, 3 NOQUEUE, 4 AUTH, 5 EXISTS, 6 MALFORMED, 7 RATE" in d
    for name, op in {**enc.REQUEST_OPS, "SKEY": enc.OP_SKEY}.items():
        assert f"0x{op:02X} {name}" in d
    for name, op in enc.RESPONSE_OPS.items():
        assert f"0x{op:02X} {name}" in d


def test_outer_payload_is_9362_bytes():
    value = ec.honest_value("outer", 1)
    assert len(enc.payload("Outer", value)) == sizes.HS_OUTER == 9362


# ---------------------------------------------------------------------------------------------
# Point checks


def test_x25519_low_order_set_against_libsodium():
    """Each of the 14 encodings gives the all-zero output for random scalars; the next values do not."""
    encs = enc.x25519_low_order_encodings()
    assert len(encs) == len(set(encs)) == 14
    for pk in encs:
        assert enc.x25519_low_order(pk)
        for _ in range(3):
            with pytest.raises(nacl.exceptions.CryptoError):      # libsodium refuses the zero output
                nacl.bindings.crypto_scalarmult(os.urandom(32), pk)
    for u in (2, 3, enc.P25519 + 2, enc.P25519 - 2, 2**255 - 1):
        pk = u.to_bytes(32, "little")
        assert not enc.x25519_low_order(pk)
        nacl.bindings.crypto_scalarmult(os.urandom(32), pk)


def test_x25519_top_bit_positive_is_accepted_as_received():
    value = ec.honest_value("iks_topbit", ec.POS_INDEX["iks_topbit"])
    assert value["ik_dh"][31] & 0x80
    data = enc.encode("IKSPublic", value)
    assert data[-32:] == value["ik_dh"]


def test_ed25519_small_order_constants_are_the_torsion_points():
    torsion = {edm.encode(pt) for pt in edm.torsion_points()}
    named = {ec.ED_IDENTITY, ec.ED_ORDER2, ec.ED_ORDER4, ec.ED_ORDER4_SIGNX, ec.ED_ORDER8, ec.ED_ORDER8_NEG}
    assert named <= torsion
    for pt in torsion:
        with pytest.raises(Reject):
            enc._ed_key(pt)


def test_ed25519_noncanonical_rows_isolate_canonicality():
    """y = p + 3 and y = p + 18 reduce to curve points that are not of small order, so only the
    canonicality rule rejects them."""
    for encoded, y in ((ec.ED_Y3_NONCANON, 3), (ec.ED_Y18_NONCANON, 18)):
        assert int.from_bytes(encoded, "little") == enc.P25519 + y
        assert edm.recover_x(y, 0) is not None and y not in primitives.ED25519_SMALL_ORDER_Y
        assert edm.decode_lenient(encoded) is not None


def test_ed25519_off_curve_constant():
    assert edm.recover_x(2, 0) is None and edm.recover_x(2, 1) is None


@pytest.mark.parametrize("address", [
    "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad",
    "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid",
    "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd",
])
def test_onion_checksum_against_published_v3_addresses(address):
    """Tor rend-spec-v3 §6 CHECKSUM = SHA3-256(".onion checksum" ‖ PUBKEY ‖ VERSION)[:2]."""
    decoded = base64.b32decode(address.upper())
    assert len(decoded) == enc.ONION_LEN and decoded[34] == enc.ONION_VERSION
    assert decoded == enc.onion_from_pubkey(decoded[:32])


# ---------------------------------------------------------------------------------------------
# D.6 signed messages


def test_signed_messages_follow_d6():
    v = {"sess_id": bytes(range(16)), "cmd_seq": 0x01020304, "rid": b"\xaa" * 16, "ack": 5}
    assert enc.signed_message("FETCH_MULTI", v) == (b"SecMP-Q/1 MFETCH" + bytes(range(16)) + bytes([1, 2, 3, 4])
                                                   + b"\xaa" * 16 + (5).to_bytes(8, "big"))
    assert enc.signed_message("FETCH", v).startswith(b"SecMP-Q/1 FETCH\x00\x01")
    blob = bytes(sizes.LINK_BLOB)
    put = {"sess_id": bytes(16), "cmd_seq": 1, "ld_id": b"\x01" * 16, "one_time": 1, "expires_bucket": 7,
           "owner_pk": b"\x02" * 32, "token": b"\x03" * 32, "blob": blob}
    assert enc.signed_message("LINK_PUT", put).endswith(hashlib.sha256(blob).digest())
    for command in enc.SIGNED_FIELDS:
        assert labels.Q_CMD[command] in labels.APPENDIX_A


def test_frame_signatures_verify_over_d6():
    """The positive QUEUE_NEW frame's sig verifies over the D.6 message with the row's sess_id
    (drawn after the fields, SCHEMA-4.8 stream order)."""
    i = ec.POS_INDEX["q_queue_new"]
    v = ec.honest_value("q_queue_new", i)
    s = vectorfile.CaseStream("encodings", i)
    s.take(4 + 32 + 32 + 32)
    sess_id = s.take(16)
    msg = enc.signed_message("QUEUE_NEW", {**v, "sess_id": sess_id})
    primitives.ed25519_verify(v["recv_pk"], msg, v["sig"])


# ---------------------------------------------------------------------------------------------
# Positives and negatives


def test_positive_round_trips(cases_by_id):
    for i, pos in enumerate(ec.POSITIVES, start=1):
        case = cases_by_id[f"enc-{i:04d}"]
        assert case["op"] == "encode" and case["inputs"]["structure"] == pos.structure
        value = ec.honest_value(pos.key, i)
        data = bytes.fromhex(case["outputs"]["bytes"])
        assert enc.encode(pos.structure, value, pos.context) == data
        if pos.structure not in enc.SIGNED:
            assert enc.decode(pos.structure, data, pos.context) == value
            assert enc.raw(pos.structure, enc.decode(pos.structure, data, pos.context)) == data


def test_negatives_are_rejected(cases_by_id):
    first = len(ec.POSITIVES) + 1
    for i, neg in enumerate(ec.NEGATIVES, start=first):
        case = cases_by_id[f"enc-{i:04d}"]
        assert case["op"] == "decode" and case["expect"] == "reject"
        data = bytes.fromhex(case["inputs"]["bytes"])
        rule = ec.check_negative(i, neg, data)
        assert rule != "noncanonical"


def test_at_least_200_negatives_and_every_family_covered():
    assert len(ec.NEGATIVES) >= 200
    covered = collections.defaultdict(set)
    for neg in ec.NEGATIVES:
        covered[neg.structure].add(neg.family)
    for structure, families in ec.APPLIES.items():
        assert families <= covered[structure], (structure, families - covered[structure])
    assert {n.family for n in ec.NEGATIVES} <= set(ec.FAMILIES)


def test_every_structure_has_a_positive():
    assert {p.structure for p in ec.POSITIVES} == set(enc.DECODERS) | set(enc.SIGNED)


# The 22 rows the proposal withheld, written with their answered outcome (REF-M2-1 correction 3):
# (structure, start of the manipulation text, the check that rejects them).
ANSWERED_REJECTS = [
    ("IKSPublic", "ik_ed25519 := 0200", "ed25519-key-off-curve"),              # SQ-12 (a)
    ("RelayInfoV1", "sig: R := 0200", "ed25519-sig-R-off-curve"),              # SQ-12 (a)
    ("PrekeyBundle", "spk_kem bytes 0–2", "mlkem-ek"),                         # SQ-12 (b)
    ("HeaderV1", "ek_pq bytes 0–2", "mlkem-ek"),                               # SQ-12 (b)
    ("RelayRef", "onion[34]", "onion"), ("RelayRef", "onion[32]", "onion"),    # SQ-13
    ("RelayRef", "host := empty", "host"), ("RelayRef", "host := 254", "host"),  # SQ-14
    ("RelayRef", "host[5]", "host"), ("RelayRef", "port := 0", "host"),
    ("HandshakeBody", "caps := 0x00000001", "reserved"),                       # SQ-15
    ("HandshakeBody", "caps := 0x80000000", "reserved"),
    ("BatchBody", "messages := []", "range"), ("RouteUpdateBody", "routes := []", "range"),  # SQ-17
    ("HandshakeBody", "routes := []", "range"), ("ReceiptBody", "msg_ids := []", "range"),
    ("Fragment", "idx := 2 (= total)", "range"), ("Fragment", "total := 1, idx := 0", "range"),  # SQ-18
    ("Fragment", "chunk := empty", "len"),
    ("FragmentPayload", "inner_type := 0x03", "type"), ("FragmentPayload", "inner_type := 0x00", "type"),
]


@pytest.mark.parametrize("structure,start,rule", ANSWERED_REJECTS)
def test_formerly_withheld_rows_are_written_as_rejects(structure, start, rule):
    first = len(ec.POSITIVES) + 1
    rows = [(i, n) for i, n in enumerate(ec.NEGATIVES, start=first)
            if n.structure == structure and n.manipulation.startswith(start)]
    assert len(rows) == 1
    i, neg = rows[0]
    assert neg.rule == rule
    assert ec.check_negative(i, neg, ec.negative_bytes(neg, i)) == rule


def test_formerly_withheld_accepted_row_is_a_positive():
    """SQ-18 answer (1): idx counts from 0, so idx 0 with total 2 is valid (correction 3)."""
    i = ec.POS_INDEX["fragment_idx0"]
    value = ec.honest_value("fragment_idx0", i)
    assert (value["idx"], value["total"]) == (0, 2)
    assert enc.decode("Fragment", enc.encode("Fragment", value)) == value


def test_rows_added_by_the_corrections():
    """Correction 4 and addition 2 of Weisung REF-M2-1."""
    def rows(structure, start):
        return [n for n in ec.NEGATIVES if n.structure == structure and n.manipulation.startswith(start)]
    assert rows("FragmentPayload", "inner_type := 0x01")[0].rule == "type"
    link_get_r = [n.rule for n in ec.NEGATIVES if n.row == "q_link_get1" and n.manipulation.startswith("sig: R")]
    assert sorted(link_get_r) == ["ed25519-sig-R-noncanonical", "ed25519-sig-R-small-order"]
    assert ec.POS_BY_KEY["control_arg"].recipe(vectorfile.CaseStream("encodings", 1))["arg_len"] == 16
    assert {n.manipulation for n in ec.NEGATIVES if n.row == "control_arg"} == {
        "arg_len := arg_len − 1", "arg_len := 0 (arg kept)"}
    ek_fields = {"RelayInfoV1": ["relay_kem_ek"], "Record/HS1": ["ek_c"],
                 "PrekeyBundle": ["spk_kem", "rpk_kem", "opk_kem"], "HeaderV1": ["ek_pq"]}
    for structure, fields in ek_fields.items():
        for f in fields:
            assert [n.rule for n in rows(structure, f"{f} bytes 0–2")] == ["mlkem-ek"]


def test_maximum_values_round_trip_exactly():
    """Correction 4: counters and lengths at their maxima, big-endian."""
    def data(key):
        i = ec.POS_INDEX[key]
        pos = ec.POS_BY_KEY[key]
        return enc.encode(pos.structure, ec.honest_value(key, i), pos.context)
    fetch = data("q_fetch_max")                     # op ‖ cmd_seq ‖ rid ‖ ack ‖ sig
    assert fetch[1:5] == b"\xff" * 4 and fetch[21:29] == b"\xff" * 8
    ok_send = data("r_ok_send_max")                 # op ‖ cmd_seq ‖ cell_id ‖ 01 ‖ evicted_id
    assert ok_send[1:22] == b"\xff" * 12 + b"\x01" + b"\xff" * 8
    header = data("header_max")                     # ver ‖ flags ‖ dh_pk ‖ pn ‖ n
    assert header[34:42] == b"\xff" * 8
    content = data("c_dummy_max")                   # ver ‖ type ‖ seq ‖ ts ‖ body_len 0 ‖ 80
    assert content[2:18] == b"\xff" * 16 and content[18:21] == b"\x00\x00\x80"
    assert data("appmsg_max")[17:23] == b"\xff" * 6 and len(data("appmsg_max")) == 23 + 0xFFFF
    assert data("control_max")[1:3] == b"\xff\xff" and data("rd_unknown_max")[2:4] == b"\xff\xff"
    assert data("receipt_max")[1] == 255 and data("fragment_max")[16:20] == bytes([0, 63, 0, 64])
    relay = ec.honest_value("relayref_max", ec.POS_INDEX["relayref_max"])
    assert (relay["host_len"], relay["port"]) == (253, 0xFFFF)
    assert data("invitation_max")[-8:] == b"\xff" * 8
    info = ec.honest_value("relayinfo_max", ec.POS_INDEX["relayinfo_max"])
    assert (info["kid"], info["valid_until"]) == (2**32 - 1, 2**64 - 1)


def test_op_and_mode_are_names(document):
    """Correction 1: `op` and `mode` are JSON strings, also inside `value`."""
    ops = set(enc.REQUEST_OPS) | set(enc.RESPONSE_OPS)
    seen = collections.Counter()
    for case in json.loads(document)["cases"]:
        assert isinstance(case["op"], str)
        value = case["inputs"].get("value", {})
        if "op" in value:
            assert value["op"] in ops and case["inputs"]["structure"].endswith("/" + value["op"])
            seen["op"] += 1
        if "mode" in value:
            assert value["mode"] in enc.LINK_GET_MODES
            seen["mode"] += 1
    assert seen["op"] == sum(p.structure.startswith(("Request/", "Response/")) for p in ec.POSITIVES)
    assert seen["mode"] == 3                        # two LINK_GET frames and Signed/LINK_GET


def test_generator_refuses_a_wrong_table_row():
    neg = ec.NEGATIVES[0]._replace(rule="ver")
    with pytest.raises(TableMismatch):
        ec.check_negative(999, neg, ec.negative_bytes(neg, 999))
    noop = ec.N("IKSPublic", "iks", "no manipulation", "VER", "ver")
    with pytest.raises(TableMismatch):
        ec.check_negative(999, noop, ec.negative_bytes(noop, 999))


def test_reject_is_uniform():
    datas = [ec.negative_bytes(n, 500 + k) for k, n in enumerate(ec.NEGATIVES[:40])]
    errors = set()
    for n, data in zip(ec.NEGATIVES[:40], datas):
        try:
            enc.decode(n.structure, data, ec.context_of(n))
        except Reject as e:
            errors.add((type(e), e.args))
    assert errors == {(Reject, ("reject",))}


# ---------------------------------------------------------------------------------------------
# Totality


def test_decoders_are_total_and_canonical():
    """Random mutations of every positive: the uniform Reject or a value whose encoding is exactly
    the input; never another exception (§4.1 "Decoders MUST be total")."""
    rng = random.Random(4096)
    for i, pos in enumerate(ec.POSITIVES, start=1):
        if pos.structure in enc.SIGNED:
            continue
        data = enc.encode(pos.structure, ec.honest_value(pos.key, i), pos.context)
        for _ in range(60):
            b = bytearray(data)
            op = rng.randrange(4)
            if op == 0:
                b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
            elif op == 1:
                del b[rng.randrange(len(b) + 1):]
            elif op == 2:
                b.insert(rng.randrange(len(b) + 1), rng.choice((0, 1, 0x80, 0xFF)))
            else:
                b[rng.randrange(min(len(b), 48))] = rng.choice((0, 1, 2, 0x80, 0xFF))
            b = bytes(b)
            try:
                v = enc.decode(pos.structure, b, pos.context)
            except Reject:
                assert enc.last_rule != "noncanonical"
                continue
            assert enc.raw(pos.structure, v) == b


def test_cellr_needs_its_context():
    i = ec.POS_INDEX["r_cellr_f1"]
    data = enc.encode("Response/CELLR", ec.honest_value("r_cellr_f1", i), "FETCH")
    with pytest.raises(ValueError):
        enc.decode("Response/CELLR", data)


def test_encoder_refuses_invalid_values():
    value = ec.honest_value("iks", 1)
    with pytest.raises(ValueError):
        enc.encode("IKSPublic", {**value, "ver": 2})
    with pytest.raises(ValueError):
        enc.encode("IKSPublic", {**value, "extra": b""})
    with pytest.raises(ValueError):
        enc.encode("Profile", {"name_len": 3, "name": b"abcd", "avatar_present": 0})


# ---------------------------------------------------------------------------------------------
# The written file and the proposal document


def test_written_file_is_current(document):
    path = gen_vectors.VECTORS_DIR / "encodings.json"
    assert path.read_bytes() == document
    doc = json.loads(document)
    vectorfile.validate_document(doc)
    assert vectorfile.canonical_json(doc) == document
    assert (doc["schema"], doc["suite"], doc["spec"]) == (3, "encodings", "SecMP/1 rev 2.3")
    assert len(doc["cases"]) == len(ec.POSITIVES) + len(ec.NEGATIVES)


def test_no_pending_readings_are_left():
    """All eight questions are answered: no check is switched by a mode any more."""
    assert not hasattr(enc, "lenient_pending")
    assert not any(n.rule and n.rule.startswith("sq") for n in ec.NEGATIVES)


def test_schema_4_8_document_is_current():
    from tools import render_schema_4_8
    assert SCHEMA_4_8.read_text(encoding="utf-8") == render_schema_4_8.render()


def test_hybridkem_ek_check_is_the_m1_one():
    """SQ-12 (b) reuses the FIPS 203 §7.2 check of the M1 hybridkem module."""
    ek = ec.honest_value("header", ec.POS_INDEX["header"])["ek_pq"]
    assert hybridkem.ek_input_check(hybridkem.HYBRIDKEM_768, ek)
    assert not hybridkem.ek_input_check(hybridkem.HYBRIDKEM_768, b"\xff\xff\xff" + ek[3:])
