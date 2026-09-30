# SPDX-License-Identifier: AGPL-3.0-or-later
"""Suite caead (spec §3.4, SCHEMA §4.2)."""

import pytest

from secmp_ref import caead, cases, primitives
from secmp_ref.errors import Reject

K = bytes(range(32))
N = bytes(range(100, 124))
AD = b"SecMP-INV/1 blob" + bytes(16)
P = b"link data " * 20


def test_seal_is_com_then_xchacha_under_the_derived_key():
    okm = primitives.hkdf_expand(K, b"SecMP-commit/1" + N, 64)
    k_enc, com = okm[:32], okm[32:]
    assert caead.seal(K, N, AD, P) == com + primitives.xchacha20poly1305_seal(k_enc, N, AD, P)


def test_round_trip_and_sizes():
    for p in (b"", b"x", P):
        out = caead.seal(K, N, AD, p)
        assert len(out) == 32 + len(p) + 16
        assert caead.open(K, N, AD, out) == p


def test_com_is_checked_before_the_aead():
    """A blob with a wrong COM but a valid AEAD part (under the right K_enc) is rejected, so COM is
    checked at all; and both failures raise the same error type."""
    blob = caead.seal(K, N, AD, P)
    wrong_com = bytes(32) + blob[32:]
    wrong_aead = blob[:32] + bytes([blob[32] ^ 1]) + blob[33:]
    for bad in (wrong_com, wrong_aead):
        with pytest.raises(Reject) as e:
            caead.open(K, N, AD, bad)
        assert type(e.value) is Reject


def test_commitment_to_key_and_nonce():
    """UtC: COM depends on (K, N), so opening under another key fails at COM already."""
    blob = caead.seal(K, N, AD, P)
    other_k = bytes(32)
    okm = primitives.hkdf_expand(other_k, b"SecMP-commit/1" + N, 64)
    assert okm[32:] != blob[:32]
    with pytest.raises(Reject):
        caead.open(other_k, N, AD, blob)


@pytest.mark.parametrize("n", [0, 16, 31, 32, 47])
def test_too_short_is_rejected(n):
    with pytest.raises(Reject):
        caead.open(K, N, AD, caead.seal(K, N, AD, b"")[:n])


def test_wrong_nonce_length():
    with pytest.raises(ValueError):
        caead.seal(K, N[:-1], AD, P)
    with pytest.raises(Reject):
        caead.open(K, N[:-1], AD, caead.seal(K, N, AD, P))


# ---------------------------------------------------------------------------------------------
# SCHEMA §4.2 rows


@pytest.fixture(scope="module")
def rows():
    return {c.i: c for c in cases.caead_cases()}


def test_table_shape(rows):
    assert sorted(rows) == list(range(1, 18))
    for i, (ad_len, p_len) in cases.CAEAD_SEAL.items():
        c = rows[i]
        assert c.op == "seal"
        assert [len(c.inputs[k]) for k in ("k", "n", "ad", "p")] == [32, 24, ad_len, p_len]
        assert len(c.outputs["com"]) == 32 and len(c.outputs["c"]) == p_len + 16
    for i, row, field, _ in cases.CAEAD_OPEN:
        c = rows[i]
        assert c.op == "open" and c.outputs is None
        assert set(c.inputs) == {"k", "n", "ad", "com", "c"}
        k, n, ad, _, com, cc = cases._caead_honest(i, row)
        honest = {"k": k, "n": n, "ad": ad, "com": com, "c": cc}
        assert [f for f in honest if honest[f] != c.inputs[f]] == [field]


def test_manipulations(rows):
    assert len(rows[12].inputs["c"]) == 16 + 16 - 1
    assert len(rows[13].inputs["c"]) == 15
    assert len(rows[17].inputs["c"]) == 16          # empty plaintext: the tag alone


def test_positive_rows_open(rows):
    for i in cases.CAEAD_SEAL:
        c = rows[i]
        assert caead.open(c.inputs["k"], c.inputs["n"], c.inputs["ad"], c.outputs["com"] + c.outputs["c"]) == c.inputs["p"]


def test_negative_rows_reject(rows):
    for i, *_ in cases.CAEAD_OPEN:
        c = rows[i]
        with pytest.raises(Reject):
            caead.open(c.inputs["k"], c.inputs["n"], c.inputs["ad"], c.inputs["com"] + c.inputs["c"])
