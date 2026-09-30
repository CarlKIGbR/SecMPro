# SPDX-License-Identifier: AGPL-3.0-or-later
"""labels.py and sizes.py against the spec text (Appendix A, Appendix B, and the layouts that
define the composite sizes)."""

import re

from _spec import appendix
from secmp_ref import labels, sizes


def appendix_a_labels() -> list[bytes]:
    """Every quoted string of the Appendix A label list (the fenced block, not the Rules text
    after it, which quotes the pre-rev-2.2 names), in order."""
    block = re.search(r"^```\n(.*?)^```", appendix("A"), flags=re.S | re.M).group(1)
    return [q.encode("ascii") for q in re.findall(r'"([^"]*)"', block)]


def test_labels_match_appendix_a_literally():
    assert labels.APPENDIX_A == tuple(appendix_a_labels())


def test_appendix_a_is_prefix_free():
    """Appendix A rule (rev 2.2, ADR-035): no label is a prefix of another. Read from the spec
    file itself, so that a later spec edit that breaks the rule fails here."""
    spec_labels = appendix_a_labels()
    assert len(spec_labels) == len(set(spec_labels))
    offending = [(a, b) for a in spec_labels for b in spec_labels if a != b and b.startswith(a)]
    assert offending == []


def test_renamed_labels_are_gone():
    """The three pre-rev-2.2 names that broke prefix-freeness (SQ-07)."""
    for old in (b"SecMP-INV/1", b"SecMP-HX/1 init", b"SecMP-Q/1 FETCH_MULTI"):
        assert old not in labels.APPENDIX_A
    assert labels.Q_CMD["FETCH_MULTI"] == b"SecMP-Q/1 MFETCH"
    assert set(labels.Q_CMD.values()) <= set(labels.APPENDIX_A)


def test_hybridsign_labels():
    text = appendix("A")
    assert ('`HybridSign` accepts only `"SecMP-HX/1 bundle"` and `"SecMP-TR/1 keychange"`' in text)
    assert labels.HYBRIDSIGN_LABELS == (b"SecMP-HX/1 bundle", b"SecMP-TR/1 keychange")


def test_labels_are_distinct_ascii():
    assert len(set(labels.APPENDIX_A)) == len(labels.APPENDIX_A)
    for label in labels.APPENDIX_A:
        label.decode("ascii")


def test_sizes_match_appendix_b_rows():
    s = sizes
    rows = {
        "X25519 pk/ss · Ed25519 pk/sig":
            f"{s.X25519_PK}/{s.X25519_SS} · {s.ED25519_PK}/{s.ED25519_SIG}",
        "ML-KEM-768 ek/ct/ss · ML-KEM-1024 ek/ct/ss":
            f"{s.MLKEM768_EK}/{s.MLKEM768_CT}/{s.MLKEM_SS} · {s.MLKEM1024_EK}/{s.MLKEM1024_CT}/{s.MLKEM_SS}",
        "ML-DSA-65 pk/sig · `HybridSig`": f"{s.MLDSA65_PK}/{s.MLDSA65_SIG} · {s.HYBRID_SIG}",
        "`IKSPublic`": f"{s.IKS_PUBLIC}",
        "`PrekeyBundle`": f"{s.PREKEY_BUNDLE}",
        "`LinkDataV1` padded / blob": f"{s.LINKDATA_PADDED} / {s.LINK_BLOB} (3 frames)",
        "`HeaderV1` / `hdr_ct`": f"{s.HEADER} / {s.HDR_CT}",
        "Cell / `BODY_LEN` / Frame / frame plaintext":
            f"{s.CELL} / {s.BODY_LEN} / {s.FRAME} / {s.FRAME_PLAINTEXT}",
        "Handshake `Outer` / padded / cells": f"{s.HS_OUTER} / {s.HS_OUTER_PADDED} / {s.HS_CELLS} × {s.CELL}",
        "`RelayInfoV1` / HS1 / HS2": f"{s.RELAY_INFO} / {s.HS1} / {s.HS2}",
        "`InvitationV1` (no direct)": f"{s.INVITATION_NO_DIRECT} (≈ 322 chars base64url)",
    }
    table = {}
    for line in appendix("B").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 2 and cells[0] not in ("Object", "---"):
            table[cells[0]] = cells[1]
    assert table == rows


def test_composite_sizes_add_up():
    """Re-add the composite sizes from their layouts; a spec arithmetic error would show here."""
    s = sizes
    # §3 table / §3.5: HybridSig = Ed25519 sig ‖ ML-DSA-65 sig
    assert s.ED25519_SIG + s.MLDSA65_SIG == s.HYBRID_SIG
    # §6.2 / D.3: IKSPublic = ver ‖ ik_ed25519 ‖ ik_mldsa65 ‖ ik_dh
    assert 1 + s.ED25519_PK + s.MLDSA65_PK + s.X25519_PK == s.IKS_PUBLIC
    # §6.3 / D.3: PrekeyBundle
    assert (1 + 4 + s.X25519_PK + s.MLKEM1024_EK + s.MLKEM768_EK + 8 + 1 + 4 + s.X25519_PK
            + s.MLKEM1024_EK + s.HYBRID_SIG) == s.PREKEY_BUNDLE
    # §5.4 / D.3: blob = N ‖ COM ‖ ct(padded LinkDataV1) ‖ tag
    assert s.XCHACHA_NONCE + s.CAEAD_COM + s.LINKDATA_PADDED + s.AEAD_TAG == s.LINK_BLOB
    # §7.5 / D.5: HeaderV1, hdr_ct, Cell
    assert 1 + 1 + s.X25519_PK + 4 + 4 + s.MLKEM768_EK + s.MLKEM768_CT == s.HEADER
    assert s.HEADER + s.AEAD_TAG == s.HDR_CT
    assert s.XCHACHA_NONCE + s.HDR_CT + s.BODY_LEN + s.HMAC_TAG == s.CELL
    # §4.2: FRAME_SIZE = cell + 240 B command overhead + 16 B tag; plaintext = frame − tag
    assert s.CELL + 240 + s.AEAD_TAG == s.FRAME
    assert s.FRAME - s.AEAD_TAG == s.FRAME_PLAINTEXT
    # §6.5 / D.4: inner_ct, Outer, padded Outer, handshake cell
    inner_ct = s.XCHACHA_NONCE + s.CAEAD_COM + (s.IKS_PUBLIC + s.CELL) + s.AEAD_TAG
    assert inner_ct == 6185
    assert 1 + s.X25519_PK + 4 + 4 + s.MLKEM1024_CT + s.MLKEM1024_CT + inner_ct == s.HS_OUTER
    assert s.HS_CELLS * 4006 == s.HS_OUTER_PADDED
    assert s.XCHACHA_NONCE + s.CAEAD_COM + (16 + 1 + 1 + 4006) + s.AEAD_TAG == s.CELL
    # §8.2 / D.1: RelayInfoV1, HS1, HS2
    assert 1 + 32 + 4 + s.X25519_PK + s.MLKEM1024_EK + 32 + 8 + s.ED25519_SIG == s.RELAY_INFO
    assert 1 + 4 + s.X25519_PK + s.MLKEM768_EK + s.X25519_PK + s.MLKEM1024_CT + s.HMAC_TAG == s.HS1
    assert 1 + s.X25519_PK + s.MLKEM768_CT + s.HMAC_TAG == s.HS2
    # §5.2 / D.3: InvitationV1 without `direct` (RelayRef = ver ‖ relay_fp ‖ onion ‖ akc ‖ direct_present)
    relay_ref = 1 + 32 + 35 + 32 + 1
    assert 1 + 1 + relay_ref + 16 + 32 + 32 + 16 + 32 + 2 + 8 == s.INVITATION_NO_DIRECT
    # §4.2 SAS_DIGITS; §6.7: two halves of 6 groups × 5 digits
    assert 2 * 6 * 5 == s.SAS_DIGITS
    # §3.3: C ‖ TAG of a body; SCHEMA §4.3 c_tag (1742)
    assert s.BODY_LEN + s.HMAC_TAG == 1742
    # SCHEMA §4.3 row 7: §7.3 body AD = "SecMP-TR/1 body" ‖ sb ‖ hdr_nonce ‖ hdr_ct
    assert len(labels.TR_BODY) + s.SHA256 + s.XCHACHA_NONCE + s.HDR_CT == 2401
    # SCHEMA §4.5 row 7: PrekeyBundle fields before sig ‖ ik_dh
    assert s.PREKEY_BUNDLE - s.HYBRID_SIG + s.X25519_PK == 4434
