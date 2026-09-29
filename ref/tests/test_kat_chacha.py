# SPDX-License-Identifier: AGPL-3.0-or-later
"""Library qualification: cryptography ChaCha20 and PyNaCl (X)ChaCha20-Poly1305.

Official vectors: RFC 8439 §2.4.2 and A.2 #1–#3 (ChaCha20 encryption, incl. initial counter 0),
RFC 8439 §2.8.2 (AEAD_CHACHA20_POLY1305, the core that libsodium's XChaCha20-Poly1305 builds on),
draft-irtf-cfrg-xchacha-03 §A.3.1 (AEAD_XCHACHA20_POLY1305).
"""

import nacl.bindings
import pytest

from _kat import h, load
from secmp_ref import primitives
from secmp_ref.errors import Reject

CHACHA = load("chacha20.json")
XCHACHA = load("xchacha20poly1305.json")


@pytest.mark.parametrize("case", CHACHA["chacha20"], ids=lambda c: c["name"])
def test_chacha20_rfc8439(case):
    key, nonce, counter = h(case["key"]), h(case["nonce"]), case["counter"]
    assert primitives.chacha20_xor(key, nonce, counter, h(case["plaintext"])) == h(case["ciphertext"])
    assert primitives.chacha20_xor(key, nonce, counter, h(case["ciphertext"])) == h(case["plaintext"])


def test_chacha20poly1305_rfc8439_2_8_2():
    c = CHACHA["aead"]
    out = nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
        h(c["plaintext"]), h(c["aad"]), h(c["nonce"]), h(c["key"]))
    assert out == h(c["ciphertext"]) + h(c["tag"])


@pytest.mark.parametrize("case", XCHACHA, ids=lambda c: c["name"])
def test_xchacha20poly1305_draft(case):
    key, nonce, aad = h(case["key"]), h(case["nonce"]), h(case["aad"])
    sealed = h(case["ciphertext"]) + h(case["tag"])
    assert primitives.xchacha20poly1305_seal(key, nonce, aad, h(case["plaintext"])) == sealed
    assert primitives.xchacha20poly1305_open(key, nonce, aad, sealed) == h(case["plaintext"])


@pytest.mark.parametrize("case", XCHACHA, ids=lambda c: c["name"])
def test_xchacha20poly1305_tampering_rejected(case):
    key, nonce, aad = h(case["key"]), h(case["nonce"]), h(case["aad"])
    sealed = h(case["ciphertext"]) + h(case["tag"])
    for bad_key, bad_nonce, bad_aad, bad_ct in [
        (key, nonce, aad, bytes([sealed[0] ^ 1]) + sealed[1:]),   # flipped ciphertext
        (key, nonce, aad, sealed[:-1] + bytes([sealed[-1] ^ 1])),  # flipped tag
        (key, nonce, aad, sealed[:-1]),                            # truncated
        (key, nonce, aad, sealed[:15]),                            # shorter than a tag
        (key, nonce, aad + b"\x00", sealed),                       # wrong AD
        (bytes([key[0] ^ 1]) + key[1:], nonce, aad, sealed),       # wrong key
        (key, bytes([nonce[23] ^ 1]) + nonce[:23], aad, sealed),   # wrong nonce
    ]:
        with pytest.raises(Reject):
            primitives.xchacha20poly1305_open(bad_key, bad_nonce, bad_aad, bad_ct)
