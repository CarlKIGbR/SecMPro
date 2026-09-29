# SPDX-License-Identifier: AGPL-3.0-or-later
"""Library qualification: hashlib (SHA-256, SHA3-256, SHAKE-256) and cryptography (HMAC, HKDF).

Official vectors: NIST ACVP SHA2-256 / SHA3-256 / SHAKE-256 / HMAC-SHA2-256 (AFT),
RFC 4231 §4.2–4.8, RFC 5869 Appendix A.1–A.3.
"""

import pytest

from _kat import h, load
from secmp_ref import primitives

HASHES = load("hashes.json")
HMAC = load("hmac_sha256.json")
HKDF = load("hkdf_sha256.json")


@pytest.mark.parametrize("case", HASHES["sha2-256"], ids=lambda c: f"acvp-{c['tcId']}")
def test_sha256_acvp(case):
    assert primitives.sha256(h(case["msg"])) == h(case["md"])


@pytest.mark.parametrize("case", HASHES["sha3-256"], ids=lambda c: f"acvp-{c['tcId']}")
def test_sha3_256_acvp(case):
    assert primitives.sha3_256(h(case["msg"])) == h(case["md"])


@pytest.mark.parametrize("case", HASHES["shake-256"], ids=lambda c: f"acvp-{c['tcId']}")
def test_shake256_acvp(case):
    assert primitives.shake256(h(case["msg"]), case["out_len"]) == h(case["md"])


@pytest.mark.parametrize("case", HMAC["rfc4231"], ids=lambda c: c["name"])
def test_hmac_sha256_rfc4231(case):
    mac = h(case["mac"])
    # Test Case 5 lists the output truncated to 128 bits.
    assert primitives.hmac_sha256(h(case["key"]), h(case["data"]))[: len(mac)] == mac


@pytest.mark.parametrize("case", HMAC["acvp"], ids=lambda c: f"acvp-{c['tcId']}")
def test_hmac_sha256_acvp(case):
    mac = h(case["mac"])
    # ACVP macLen may be shorter than 256 bits: compare the leading bytes.
    assert primitives.hmac_sha256(h(case["key"]), h(case["msg"]))[: len(mac)] == mac


@pytest.mark.parametrize("case", HKDF, ids=lambda c: c["name"])
def test_hkdf_rfc5869(case):
    salt, ikm, info, length = h(case["salt"]), h(case["ikm"]), h(case["info"]), case["len"]
    prk = primitives.hkdf_extract(salt, ikm)
    assert prk == h(case["prk"])
    assert primitives.hkdf_expand(prk, info, length) == h(case["okm"])
    assert primitives.hkdf(salt, ikm, info, length) == h(case["okm"])


def test_ct_equal():
    assert primitives.ct_equal(b"\x01" * 32, b"\x01" * 32)
    assert not primitives.ct_equal(b"\x01" * 32, b"\x01" * 31 + b"\x00")
    assert not primitives.ct_equal(b"\x01" * 32, b"\x01" * 31)
