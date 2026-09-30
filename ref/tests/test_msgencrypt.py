# SPDX-License-Identifier: AGPL-3.0-or-later
"""Suite msgencrypt (spec §3.3, SCHEMA §4.3)."""

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from secmp_ref import cases, msgencrypt, primitives, sizes
from secmp_ref.errors import Reject

MK = bytes(range(32))
AD = b"SecMP-TR/1 body" + bytes(range(40))
P = bytes(i % 251 for i in range(sizes.BODY_LEN))


def test_message_keys_are_the_hkdf_split():
    okm = primitives.hkdf(bytes(32), MK, b"SecMP-TR/1 msgkeys", 76)
    assert msgencrypt.message_keys(MK) == (okm[:32], okm[32:64], okm[64:76])


def test_body_is_chacha20_counter_0_then_hmac_over_ad_and_c():
    k_enc, k_mac, iv = msgencrypt.message_keys(MK)
    out = msgencrypt.msg_encrypt(MK, AD, P)
    c, tag = out[:-32], out[-32:]
    # Keystream block 0 (the RFC 8439 AEAD would start at block 1).
    zero_counter = Cipher(algorithms.ChaCha20(k_enc, bytes(4) + iv), mode=None).encryptor()
    assert c == zero_counter.update(P)
    assert tag == primitives.hmac_sha256(k_mac, AD + c)
    assert len(out) == msgencrypt.C_TAG_LEN == 1742


def test_round_trip():
    assert msgencrypt.msg_decrypt(MK, AD, msgencrypt.msg_encrypt(MK, AD, P)) == P


@pytest.mark.parametrize("n", [0, 1, 1709, 1711, 4096])
def test_plaintext_length_must_be_body_len(n):
    with pytest.raises(Reject):
        msgencrypt.msg_encrypt(MK, AD, bytes(n))


@pytest.mark.parametrize("n", [0, 32, 1741, 1743])
def test_ciphertext_length_must_be_body_len_plus_32(n):
    with pytest.raises(Reject):
        msgencrypt.msg_decrypt(MK, AD, bytes(n))


def test_mac_is_checked_before_decrypting(monkeypatch):
    out = msgencrypt.msg_encrypt(MK, AD, P)
    bad = out[:-1] + bytes([out[-1] ^ 1])
    called = []
    monkeypatch.setattr(primitives, "chacha20_xor", lambda *a: called.append(a))
    with pytest.raises(Reject):
        msgencrypt.msg_decrypt(MK, AD, bad)
    assert called == []


# ---------------------------------------------------------------------------------------------
# SCHEMA §4.3 rows


@pytest.fixture(scope="module")
def rows():
    return {c.i: c for c in cases.msgencrypt_cases()}


def test_table_shape(rows):
    assert sorted(rows) == list(range(1, 17))
    for i, ad_len in cases.MSGENC_SEAL.items():
        c = rows[i]
        assert c.op == "seal"
        assert [len(c.inputs[k]) for k in ("mk", "ad", "p")] == [32, ad_len, 1710]
        assert {k: len(v) for k, v in c.outputs.items()} == {"k_enc": 32, "k_mac": 32, "iv": 12, "c_tag": 1742}
    for i, row, field, _ in cases.MSGENC_OPEN:
        c = rows[i]
        assert c.op == "open" and c.outputs is None and set(c.inputs) == {"mk", "ad", "c_tag"}
        mk, ad, p = cases._msgenc_stream(i, row)
        honest = {"mk": mk, "ad": ad, "c_tag": msgencrypt.msg_encrypt(mk, ad, p)}
        assert [f for f in honest if honest[f] != c.inputs[f]] == [field]
    c = rows[16]
    assert c.op == "seal" and c.outputs is None
    assert [len(c.inputs[k]) for k in ("mk", "ad", "p")] == [32, 0, 1709]


def test_length_rows(rows):
    assert [len(rows[i].inputs["c_tag"]) for i in (11, 12, 15)] == [1741, 1743, 0]


def test_positive_rows(rows):
    for i in cases.MSGENC_SEAL:
        c = rows[i]
        assert msgencrypt.message_keys(c.inputs["mk"]) == (c.outputs["k_enc"], c.outputs["k_mac"], c.outputs["iv"])
        assert msgencrypt.msg_decrypt(c.inputs["mk"], c.inputs["ad"], c.outputs["c_tag"]) == c.inputs["p"]


def test_negative_rows(rows):
    for i, *_ in cases.MSGENC_OPEN:
        c = rows[i]
        with pytest.raises(Reject):
            msgencrypt.msg_decrypt(c.inputs["mk"], c.inputs["ad"], c.inputs["c_tag"])
    with pytest.raises(Reject):
        msgencrypt.msg_encrypt(rows[16].inputs["mk"], rows[16].inputs["ad"], rows[16].inputs["p"])
