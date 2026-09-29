# SPDX-License-Identifier: AGPL-3.0-or-later
"""Suites fingerprint and sas (spec §6.2, §6.7, SCHEMA §4.6, §4.7)."""

import hashlib

import pytest

from secmp_ref import cases, identity, primitives, sizes

ED_SEED, MLDSA_SEED, DH_SEED = bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96))


def test_iks_public_layout():
    iks = identity.iks_public_from_seeds(ED_SEED, MLDSA_SEED, DH_SEED)
    pk_mldsa, _ = primitives.ml_dsa_65_keygen(MLDSA_SEED)
    assert len(iks) == sizes.IKS_PUBLIC == 2017
    assert iks[0] == 0x01
    assert iks[1:33] == primitives.ed25519_public(ED_SEED)
    assert iks[33:1985] == pk_mldsa
    assert iks[1985:] == primitives.x25519_public(DH_SEED)


def test_fingerprint_is_labelled_sha256_of_the_encoding():
    iks = identity.iks_public_from_seeds(ED_SEED, MLDSA_SEED, DH_SEED)
    assert identity.fingerprint(iks) == hashlib.sha256(b"SecMP-FP/1" + iks).digest()
    with pytest.raises(ValueError):
        identity.fingerprint(iks[:-1])


def _iter_reference(fp):
    h = fp
    for _ in range(5200):
        h = hashlib.sha256(b"SecMP-SAS/1" + h + fp).digest()
    return h


def test_sas_iteration_count_and_input():
    fp = bytes(range(32))
    assert identity.sas_iter(fp) == _iter_reference(fp)
    one_less = fp
    for _ in range(5199):
        one_less = hashlib.sha256(b"SecMP-SAS/1" + one_less + fp).digest()
    assert identity.sas_iter(fp) != one_less


def test_sas_half_groups(monkeypatch):
    """Six groups from bytes 0–29 of iter(fp), big-endian, mod 100000, zero-padded to 5 digits."""
    h = bytes.fromhex("0000000001" "00000186a0" "ffffffffff" "0000000000" "0000018699" "000001869f" "abcd")
    monkeypatch.setattr(identity, "sas_iter", lambda fp: h)
    # 0xffffffffff = 1099511627775 ≡ 27775; 0x186a0 = 100000 ≡ 0
    assert identity.sas_half(bytes(32)) == "00001" "00000" "27775" "00000" "99993" "99999"


def test_safety_number_is_sorted_and_symmetric():
    a, b = bytes(range(32)), bytes(range(1, 33))
    ha, hb = identity.sas_half(a), identity.sas_half(b)
    assert len(ha) == len(hb) == 30 and ha.isdigit()
    sn = identity.safety_number(a, b)
    assert sn == identity.safety_number(b, a) == min(ha, hb) + max(ha, hb)
    assert len(sn) == sizes.SAS_DIGITS


# ---------------------------------------------------------------------------------------------
# SCHEMA §4.6 and §4.7 rows


def test_fingerprint_rows():
    rows = cases.fingerprint_cases()
    assert [c.i for c in rows] == list(range(1, 9))
    for c in rows:
        assert c.op == "fp" and {k: len(v) for k, v in c.inputs.items()} == {"ed_seed": 32, "mldsa_seed": 32, "dh_seed": 32}
        assert c.outputs["iks"] == identity.iks_public_from_seeds(**c.inputs)
        assert c.outputs["fp"] == hashlib.sha256(b"SecMP-FP/1" + c.outputs["iks"]).digest()


def test_sas_rows():
    rows = {c.i: c for c in cases.sas_cases()}
    assert sorted(rows) == list(range(1, 11))
    for c in rows.values():
        assert c.op == "sas"
        assert len(c.outputs["half_a"]) == len(c.outputs["half_b"]) == 30
        assert c.outputs["safety_number"] == "".join(sorted((c.outputs["half_a"], c.outputs["half_b"])))
    assert rows[9].inputs["fp_a"] == rows[9].inputs["fp_b"]
    assert rows[9].outputs["safety_number"] == 2 * rows[9].outputs["half_a"]
    assert (rows[10].inputs["fp_a"], rows[10].inputs["fp_b"]) == (rows[1].inputs["fp_b"], rows[1].inputs["fp_a"])
    assert rows[10].outputs["safety_number"] == rows[1].outputs["safety_number"]
    assert (rows[10].outputs["half_a"], rows[10].outputs["half_b"]) == (rows[1].outputs["half_b"], rows[1].outputs["half_a"])
