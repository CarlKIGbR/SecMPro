# SPDX-License-Identifier: AGPL-3.0-or-later
"""Library qualification: PyNaCl X25519 and Ed25519.

Official vectors: RFC 7748 §5.2 (single and iterated X25519) and §6.1 (Diffie-Hellman),
RFC 8032 §7.1 (Ed25519 TEST 1, 2, 3, 1024, SHA(abc)).
"""

import pytest

from _kat import h, load
from secmp_ref import primitives
from secmp_ref.errors import Reject

X25519 = load("x25519.json")
ED25519 = load("ed25519.json")


@pytest.mark.parametrize("case", X25519["single"], ids=lambda c: c["name"])
def test_x25519_rfc7748_single(case):
    # Vector #2 has the top bit of u set, so this also checks the RFC 7748 §5 masking.
    assert primitives.x25519(h(case["scalar"]), h(case["u"])) == h(case["out"])


def test_x25519_rfc7748_iterated():
    it = X25519["iterated"]
    k = u = h(it["start"])
    for n in range(1, 1001):
        k, u = primitives.x25519(k, u), k
        if n == 1:
            assert k == h(it["after_1"])
    assert k == h(it["after_1000"])


def test_x25519_rfc7748_dh():
    dh = X25519["dh"]
    a, b = h(dh["a"]), h(dh["b"])
    assert primitives.x25519_public(a) == h(dh["pk_a"])
    assert primitives.x25519_public(b) == h(dh["pk_b"])
    assert primitives.x25519(a, h(dh["pk_b"])) == h(dh["k"])
    assert primitives.x25519(b, h(dh["pk_a"])) == h(dh["k"])


# u = 0 and u = 1 are points of order dividing the cofactor; X25519 maps them to 0 for every
# scalar (RFC 7748 §6.1 / §7), which spec §3 requires to be rejected.
@pytest.mark.parametrize("u", [bytes(32), b"\x01" + bytes(31)], ids=["u=0", "u=1"])
def test_x25519_all_zero_output_rejected(u):
    with pytest.raises(Reject):
        primitives.x25519(h(X25519["dh"]["a"]), u)


@pytest.mark.parametrize("u", [bytes(31), bytes(33)], ids=["31B", "33B"])
def test_x25519_wrong_length_public_key_rejected(u):
    with pytest.raises(Reject):
        primitives.x25519(h(X25519["dh"]["a"]), u)


@pytest.mark.parametrize("case", ED25519, ids=lambda c: c["name"])
def test_ed25519_rfc8032(case):
    seed, pk, msg, sig = h(case["secret"]), h(case["public"]), h(case["message"]), h(case["signature"])
    assert primitives.ed25519_public(seed) == pk
    assert primitives.ed25519_sign(seed, msg) == sig
    primitives.ed25519_verify(pk, msg, sig)


@pytest.mark.parametrize("case", ED25519, ids=lambda c: c["name"])
def test_ed25519_rfc8032_tampered_rejected(case):
    pk, msg, sig = h(case["public"]), h(case["message"]), h(case["signature"])
    flipped_sig = bytes([sig[0] ^ 0x01]) + sig[1:]
    with pytest.raises(Reject):
        primitives.ed25519_verify(pk, msg, flipped_sig)
    with pytest.raises(Reject):
        primitives.ed25519_verify(pk, msg + b"\x00", sig)
    with pytest.raises(Reject):
        primitives.ed25519_verify(pk, msg, sig[:-1])
