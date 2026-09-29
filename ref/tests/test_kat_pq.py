# SPDX-License-Identifier: AGPL-3.0-or-later
"""Library qualification: kyber-py (ML-KEM-768/1024) and dilithium-py (ML-DSA-65).

Official vectors: NIST ACVP (usnistgov/ACVP-Server @ 975de31e):
ML-KEM keyGen (d, z), encapsulation (ek, m), decapsulation incl. modified ciphertexts
(implicit rejection), encapsulationKeyCheck (FIPS 203 §7.2 modulus check);
ML-DSA-65 keyGen (ξ), sigGen external/pure hedged and deterministic, sigGen internal hedged,
sigVer external/pure.
"""

import pytest

from _kat import h, load
from dilithium_py.ml_dsa import ML_DSA_65
from secmp_ref import primitives, sizes
from secmp_ref.errors import Reject

KEM = load("ml_kem.json")
DSA = load("ml_dsa_65.json")


def level(case):
    return int(case["param"].removeprefix("ML-KEM-"))


def kem_id(case):
    return f"{case['param']}-tc{case['tcId']}"


@pytest.mark.parametrize("case", KEM["keygen"], ids=kem_id)
def test_ml_kem_keygen_acvp(case):
    ek, dk = primitives.ml_kem_keygen(level(case), h(case["d"]) + h(case["z"]))
    assert ek == h(case["ek"])
    assert dk == h(case["dk"])
    assert len(ek) == {768: sizes.MLKEM768_EK, 1024: sizes.MLKEM1024_EK}[level(case)]


@pytest.mark.parametrize("case", KEM["encaps"], ids=kem_id)
def test_ml_kem_encaps_acvp(case):
    ct, ss = primitives.ml_kem_encaps(level(case), h(case["ek"]), h(case["m"]))
    assert ct == h(case["c"])
    assert ss == h(case["k"])
    assert len(ct) == {768: sizes.MLKEM768_CT, 1024: sizes.MLKEM1024_CT}[level(case)]
    assert len(ss) == sizes.MLKEM_SS


@pytest.mark.parametrize("case", KEM["decaps"], ids=kem_id)
def test_ml_kem_decaps_acvp(case):
    # "modified ciphertext" cases expect the implicit-rejection key K̄, not an error.
    assert primitives.ml_kem_decaps(level(case), h(case["dk"]), h(case["c"])) == h(case["k"])


@pytest.mark.parametrize("case", KEM["ek_check"], ids=kem_id)
def test_ml_kem_encapsulation_key_check_acvp(case):
    if case["passed"]:
        primitives.ml_kem_encaps(level(case), h(case["ek"]), bytes(32))
    else:
        with pytest.raises(Reject):
            primitives.ml_kem_encaps(level(case), h(case["ek"]), bytes(32))


@pytest.mark.parametrize("lvl", [768, 1024])
def test_ml_kem_type_checks_rejected(lvl):
    ek, dk = primitives.ml_kem_keygen(lvl, bytes(64))
    ct, _ = primitives.ml_kem_encaps(lvl, ek, bytes(32))
    with pytest.raises(Reject):
        primitives.ml_kem_encaps(lvl, ek[:-1], bytes(32))
    with pytest.raises(Reject):
        primitives.ml_kem_decaps(lvl, dk, ct[:-1])
    with pytest.raises(Reject):
        primitives.ml_kem_decaps(lvl, dk, ct + b"\x00")


@pytest.mark.parametrize("case", DSA["keygen"], ids=lambda c: f"tc{c['tcId']}")
def test_ml_dsa_65_keygen_acvp(case):
    pk, sk = primitives.ml_dsa_65_keygen(h(case["seed"]))
    assert pk == h(case["pk"])
    assert sk == h(case["sk"])
    assert len(pk) == sizes.MLDSA65_PK


@pytest.mark.parametrize("case", DSA["sign_hedged_external"] + DSA["sign_deterministic_external"],
                         ids=lambda c: f"tc{c['tcId']}")
def test_ml_dsa_65_sign_external_acvp(case):
    # Deterministic cases are the same algorithm with rnd = 0^32 (FIPS 204 Alg. 2 line 5).
    sig = primitives.ml_dsa_65_sign(h(case["sk"]), h(case["message"]), h(case["context"]), h(case["rnd"]))
    assert sig == h(case["signature"])
    assert len(sig) == sizes.MLDSA65_SIG


@pytest.mark.parametrize("case", DSA["sign_hedged_internal"], ids=lambda c: f"tc{c['tcId']}")
def test_ml_dsa_65_sign_internal_acvp(case):
    # Checks that dilithium-py's Sign_internal takes rnd exactly as FIPS 204 Alg. 7 specifies.
    sig = ML_DSA_65._sign_internal(h(case["sk"]), h(case["message"]), h(case["rnd"]))
    assert sig == h(case["signature"])


@pytest.mark.parametrize("case", DSA["verify_external"], ids=lambda c: f"tc{c['tcId']}-{c['passed']}")
def test_ml_dsa_65_verify_external_acvp(case):
    args = (h(case["pk"]), h(case["message"]), h(case["signature"]), h(case["context"]))
    if case["passed"]:
        primitives.ml_dsa_65_verify(*args)
    else:
        with pytest.raises(Reject):
            primitives.ml_dsa_65_verify(*args)
