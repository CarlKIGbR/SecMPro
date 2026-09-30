# SPDX-License-Identifier: AGPL-3.0-or-later
"""Suite hkdf-labels (spec §3 table "KDF", Appendix A)."""

import pytest

from secmp_ref import cases, hkdf_labels, labels, primitives

SALT = bytes(range(32))
IKM = bytes(range(100, 164))

# Every place where the spec calls HKDF-SHA-256 or HKDF-Expand with a label, with its output length.
CALL_SITES = [
    ("§5.4 K_ld", labels.INV_LINKDATA, 32),
    ("§6.4 SK", labels.HX_SK, 32),
    ("§6.4 K_id", labels.HX_IDKEY, 32),
    ("§6.5 K_inv", labels.HX_INITKEY, 32),
    ("§7.2 init", labels.TR_INIT, 96),
    ("§7.2 KDF_RK", labels.TR_RK, 96),
    ("§3.3 msgkeys", labels.TR_MSGKEYS, 76),
    ("§3.4 CAEAD (Expand)", labels.COMMIT, 64),
    ("§8.3 link keys (Expand)", labels.LINK_KEYS, 80),
]


@pytest.mark.parametrize("site,label,length", CALL_SITES, ids=[c[0] for c in CALL_SITES])
def test_call_site_labels_are_appendix_a_labels(site, label, length):
    assert label in labels.APPENDIX_A
    assert len(hkdf_labels.labeled_hkdf(SALT, IKM, label, b"", length)) == length


@pytest.mark.parametrize("label", labels.APPENDIX_A, ids=lambda l: l.decode())
def test_info_is_label_followed_by_extra_info(label):
    extra = b"\x00\xffcontext"
    expected = primitives.hkdf(SALT, IKM, label + extra, 42)
    assert hkdf_labels.labeled_hkdf(SALT, IKM, label, extra, 42) == expected


def test_expand_is_expand_of_label_followed_by_extra_info():
    prk = primitives.hkdf_extract(SALT, IKM)
    nonce = bytes(range(24))
    expected = primitives.hkdf_expand(prk, b"SecMP-commit/1" + nonce, 64)
    assert hkdf_labels.labeled_hkdf_expand(prk, labels.COMMIT, nonce, 64) == expected
    # Full HKDF = Expand(Extract(salt, ikm)) with the same info.
    assert hkdf_labels.labeled_hkdf(SALT, IKM, labels.COMMIT, nonce, 64) == expected


def test_distinct_labels_give_distinct_keys():
    outputs = {hkdf_labels.labeled_hkdf(SALT, IKM, label, b"", 32) for label in labels.APPENDIX_A}
    assert len(outputs) == len(labels.APPENDIX_A)


@pytest.mark.parametrize("label", labels.APPENDIX_A, ids=lambda l: l.decode())
def test_label_is_recoverable_from_info(label):
    """Rev 2.2 Appendix A is prefix-free (SQ-07), so for info = label ‖ extra_info exactly one
    Appendix A label is a prefix of info, whatever extra_info is."""
    for extra in (b"", b"key", b"cell", b" blob", b"_MULTI", bytes(range(8))):
        info = label + extra
        assert [l for l in labels.APPENDIX_A if info.startswith(l)] == [label]


@pytest.mark.parametrize("label", [b"", b"SecMP-HX/1", b"SecMP-TR/1 msgkeys ", b"secmp-tr/1 msgkeys",
                                   b"SecMP-STORE/1 unknown",
                                   # the pre-rev-2.2 names (SQ-07)
                                   b"SecMP-INV/1", b"SecMP-HX/1 init", b"SecMP-Q/1 FETCH_MULTI"])
def test_non_appendix_a_label_is_refused(label):
    with pytest.raises(ValueError):
        hkdf_labels.labeled_hkdf(SALT, IKM, label, b"", 32)
    with pytest.raises(ValueError):
        hkdf_labels.labeled_hkdf_expand(SALT, label, b"", 32)


def test_length_bounds():
    assert len(hkdf_labels.labeled_hkdf(SALT, IKM, labels.TR_RK, b"", 1)) == 1
    assert len(hkdf_labels.labeled_hkdf(SALT, IKM, labels.TR_RK, b"", 255 * 32)) == 255 * 32
    for bad in (0, 255 * 32 + 1):
        with pytest.raises(ValueError):
            hkdf_labels.labeled_hkdf(SALT, IKM, labels.TR_RK, b"", bad)
        with pytest.raises(ValueError):
            hkdf_labels.labeled_hkdf_expand(SALT, labels.TR_RK, b"", bad)


def test_expand_prk_must_be_at_least_hashlen():
    with pytest.raises(ValueError):
        hkdf_labels.labeled_hkdf_expand(bytes(31), labels.COMMIT, b"", 64)


def test_derive_modes():
    info_extra = bytes(range(24))
    assert hkdf_labels.derive("extract-expand", SALT, IKM, labels.COMMIT, info_extra, 64) == \
        primitives.hkdf(SALT, IKM, b"SecMP-commit/1" + info_extra, 64)
    prk = IKM[:32]
    assert hkdf_labels.derive("expand", b"", prk, labels.COMMIT, info_extra, 64) == \
        primitives.hkdf_expand(prk, b"SecMP-commit/1" + info_extra, 64)
    with pytest.raises(ValueError):
        hkdf_labels.derive("expand", SALT, prk, labels.COMMIT, b"", 64)        # salt MUST be empty
    with pytest.raises(ValueError):
        hkdf_labels.derive("Expand", b"", prk, labels.COMMIT, b"", 64)


def test_schema_rows():
    rows = cases.hkdf_labels_cases()
    assert [c.i for c in rows] == list(range(1, 13))
    for c, (i, mode, label, salt_len, ikm_len, extra_len, length) in zip(rows, cases.HKDF_LABELS):
        assert c.op == "derive"
        assert (c.inputs["mode"], c.inputs["label"], c.inputs["len"]) == (mode, label.decode(), length)
        assert [len(c.inputs[k]) for k in ("salt", "ikm", "extra_info")] == [salt_len, ikm_len, extra_len]
        assert len(c.outputs["okm"]) == length
        info = label + c.inputs["extra_info"]
        if mode == "expand":
            expected = primitives.hkdf_expand(c.inputs["ikm"], info, length)
        else:
            expected = primitives.hkdf(c.inputs["salt"], c.inputs["ikm"], info, length)
        assert c.outputs["okm"] == expected
    assert [c.i for c in rows if c.inputs["mode"] == "expand"] == [8, 9]
    assert {c.inputs["label"] for c in rows}.isdisjoint(l.decode() for l in labels.APPENDIX_A
                                                        if l.startswith(b"SecMP-STORE/1"))
    # row 10: empty salt ≡ 0^32
    assert rows[9].outputs["okm"] == primitives.hkdf(bytes(32), rows[9].inputs["ikm"], labels.TR_MSGKEYS, 76)


def test_empty_salt_equals_zero_salt():
    """RFC 5869 §2.2: an absent salt is HashLen zeros; §3.3 writes salt = 0^32 explicitly."""
    a = hkdf_labels.labeled_hkdf(b"", IKM, labels.TR_MSGKEYS, b"", 76)
    b = hkdf_labels.labeled_hkdf(bytes(32), IKM, labels.TR_MSGKEYS, b"", 76)
    assert a == b
