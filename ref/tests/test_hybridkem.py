# SPDX-License-Identifier: AGPL-3.0-or-later
"""Suites hybridkem-768 and hybridkem-1024 (spec §3.2, SCHEMA §4.4)."""

import hashlib

import pytest
from kyber_py.ml_kem import ML_KEM_768, ML_KEM_1024

import _ed25519_model as model
from secmp_ref import cases, hybridkem, primitives
from secmp_ref.errors import Reject

PARAMS = {"768": hybridkem.HYBRIDKEM_768, "1024": hybridkem.HYBRIDKEM_1024}
KYBER = {768: ML_KEM_768, 1024: ML_KEM_1024}
SUITES = {"768": ("hybridkem-768", cases.hybridkem_768_cases), "1024": ("hybridkem-1024", cases.hybridkem_1024_cases)}

DK_SEED = bytes(range(64))
SK_DH = bytes(range(64, 96))
M = bytes(range(96, 128))
SK_E = bytes(range(128, 160))


@pytest.fixture(params=list(PARAMS), scope="module")
def params(request):
    return PARAMS[request.param]


def sha3(b):
    return hashlib.sha3_256(b).digest()


def test_params_match_spec(params):
    assert params.v == f"SecMP-HybridKEM-{params.level}/1".encode()
    assert params.ek_len == 384 * params.k + 32
    assert (params.ek_len, params.ct_len) == {768: (1184, 1088), 1024: (1568, 1568)}[params.level]


def test_combiner_is_the_spec_formula(params):
    ek_kem, dk_kem, pk_dh = hybridkem.keygen(params, DK_SEED, SK_DH)
    pk_e, ct_kem, ss = hybridkem.encaps(params, ek_kem, pk_dh, M, SK_E)
    ss_kem, ct = KYBER[params.level]._encaps_internal(ek_kem, M)
    assert ct == ct_kem
    ss_dh = primitives.x25519(SK_E, pk_dh)
    assert pk_e == primitives.x25519_public(SK_E)
    assert ss == sha3(ss_kem + ss_dh + sha3(ct_kem) + sha3(ek_kem) + pk_dh + pk_e + params.v)
    assert hybridkem.decaps(params, DK_SEED, SK_DH, pk_e, ct_kem) == ss


def test_implicit_rejection_value(params):
    """A flipped ct_kem decapsulates to K̄ = J(z ‖ c) = SHAKE-256(z ‖ c, 32) (FIPS 203 Alg. 18),
    computed here independently of kyber-py, and the combiner is applied to it."""
    ek_kem, _, pk_dh = hybridkem.keygen(params, DK_SEED, SK_DH)
    pk_e, ct_kem, ss = hybridkem.encaps(params, ek_kem, pk_dh, M, SK_E)
    bad = bytes([ct_kem[0] ^ 1]) + ct_kem[1:]
    k_bar = hashlib.shake_256(DK_SEED[32:] + bad).digest(32)
    ss_dh = primitives.x25519(SK_DH, pk_e)
    expected = sha3(k_bar + ss_dh + sha3(bad) + sha3(ek_kem) + pk_dh + pk_e + params.v)
    assert hybridkem.decaps(params, DK_SEED, SK_DH, pk_e, bad) == expected != ss


def _set_coefficient(ek, index, value):
    """Write the 12-bit coefficient `index` of ek[0:384k] (ByteEncode12 bit order)."""
    t = bytearray(ek)
    j = 3 * (index // 2)
    if index % 2 == 0:
        t[j] = value & 0xFF
        t[j + 1] = (t[j + 1] & 0xF0) | (value >> 8)
    else:
        t[j + 1] = (t[j + 1] & 0x0F) | ((value & 0x0F) << 4)
        t[j + 2] = value >> 4
    return bytes(t)


@pytest.mark.parametrize("index", [0, 1, 2, 255, 256, "last"])
@pytest.mark.parametrize("value,ok", [(3328, True), (3329, False), (4095, False)])
def test_modulus_check_agrees_with_kyber_py(params, index, value, ok):
    ek_kem, _, pk_dh = hybridkem.keygen(params, DK_SEED, SK_DH)
    n = 256 * params.k - 1 if index == "last" else index
    ek = _set_coefficient(ek_kem, n, value)
    assert hybridkem.ek_input_check(params, ek) is ok
    try:
        KYBER[params.level]._encaps_internal(ek, M)
        kyber_ok = True
    except ValueError:
        kyber_ok = False
    assert kyber_ok is ok
    if not ok:
        with pytest.raises(Reject):
            hybridkem.encaps(params, ek, pk_dh, M, SK_E)


def test_type_check(params):
    ek_kem, _, pk_dh = hybridkem.keygen(params, DK_SEED, SK_DH)
    for ek in (ek_kem[:-1], ek_kem + b"\x00", b""):
        assert not hybridkem.ek_input_check(params, ek)
        with pytest.raises(Reject):
            hybridkem.encaps(params, ek, pk_dh, M, SK_E)


def test_wrong_ciphertext_lengths_are_rejected(params):
    ek_kem, _, pk_dh = hybridkem.keygen(params, DK_SEED, SK_DH)
    pk_e, ct_kem, _ = hybridkem.encaps(params, ek_kem, pk_dh, M, SK_E)
    for ct in (ct_kem[:-1], ct_kem + b"\x00", b""):
        with pytest.raises(Reject):
            hybridkem.decaps(params, DK_SEED, SK_DH, pk_e, ct)
    for pk in (pk_e[:-1], pk_e + b"\x00"):
        with pytest.raises(Reject):
            hybridkem.decaps(params, DK_SEED, SK_DH, pk, ct_kem)


def test_x25519_constants_are_low_order():
    """Rows 14–16: u = 0 and u = 1, and the order-8 point, whose Edwards image (y = (u−1)/(u+1),
    RFC 7748 §4.1) is one of the order-8 points of tests/_ed25519_model.py."""
    u = int.from_bytes(cases.X25519_ORDER8, "little")
    p = model.P
    y = (u - 1) * pow(u + 1, p - 2, p) % p
    y8 = {int.from_bytes(model.encode(t), "little") & ((1 << 255) - 1) for t in model.torsion_points()[1::2]}
    assert y in y8
    for pk in (cases.X25519_U0, cases.X25519_U1, cases.X25519_ORDER8):
        with pytest.raises(Reject):
            primitives.x25519(SK_DH, pk)


# ---------------------------------------------------------------------------------------------
# SCHEMA §4.4 rows


@pytest.fixture(params=list(SUITES), scope="module")
def suite(request):
    name, build = SUITES[request.param]
    return name, PARAMS[request.param], {c.i: c for c in build()}


def test_table_shape(suite):
    _, params, rows = suite
    assert sorted(rows) == list(range(1, 20))
    for i in range(1, 9):
        c = rows[i]
        assert c.op == "encaps"
        assert {k: len(v) for k, v in c.inputs.items()} == {"dk_seed": 64, "sk_dh": 32, "m": 32, "sk_e": 32}
        assert {k: len(v) for k, v in c.outputs.items()} == {
            "ek_kem": params.ek_len, "pk_dh": 32, "ct_kem": params.ct_len, "pk_e": 32, "ss": 32}
    for i, _, _, _, result in cases.HYBRIDKEM_DECAPS:
        assert rows[i].op == "decaps"
        assert set(rows[i].inputs) == {"dk_seed", "sk_dh", "pk_e", "ct_kem"}
        assert (rows[i].outputs is None) == (result == "reject")
    for i, *_ in cases.HYBRIDKEM_ENCAPS_TO:
        assert rows[i].op == "encaps-to" and rows[i].outputs is None
        assert set(rows[i].inputs) == {"ek_kem", "pk_dh", "m", "sk_e"}


def test_positive_rows_round_trip(suite):
    _, params, rows = suite
    for i in range(1, 9):
        c = rows[i]
        assert hybridkem.decaps(params, c.inputs["dk_seed"], c.inputs["sk_dh"],
                                c.outputs["pk_e"], c.outputs["ct_kem"]) == c.outputs["ss"]


def test_decaps_rows(suite):
    name, params, rows = suite
    for i, row, field, _, result in cases.HYBRIDKEM_DECAPS:
        honest = cases._hybridkem_honest(name, params, i)
        c = rows[i]
        assert [k for k in c.inputs if c.inputs[k] != honest[k]] == ([] if i == 9 else [field])
        if result == "reject":
            with pytest.raises(Reject):
                hybridkem.decaps(params, **c.inputs)
        elif i == 9:
            assert c.outputs["ss"] == honest["ss"]
        else:
            assert c.outputs["ss"] != honest["ss"]
    # rows 10 and 11: the implicit-rejection secret
    for i in (10, 11):
        c = rows[i]
        ek_kem, _, pk_dh = hybridkem.keygen(params, c.inputs["dk_seed"], c.inputs["sk_dh"])
        k_bar = hashlib.shake_256(c.inputs["dk_seed"][32:] + c.inputs["ct_kem"]).digest(32)
        ss_dh = primitives.x25519(c.inputs["sk_dh"], c.inputs["pk_e"])
        assert c.outputs["ss"] == sha3(k_bar + ss_dh + sha3(c.inputs["ct_kem"]) + sha3(ek_kem)
                                       + pk_dh + c.inputs["pk_e"] + params.v)


def test_encaps_to_rows(suite):
    name, params, rows = suite
    assert rows[17].inputs["ek_kem"][:3] == b"\xff\xff\xff"
    assert len(rows[18].inputs["ek_kem"]) == params.ek_len - 1
    assert rows[19].inputs["pk_dh"] == bytes(32)
    for i, *_ in cases.HYBRIDKEM_ENCAPS_TO:
        with pytest.raises(Reject):
            hybridkem.encaps(params, **rows[i].inputs)
