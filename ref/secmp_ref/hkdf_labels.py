# SPDX-License-Identifier: AGPL-3.0-or-later
"""hkdf-labels: HKDF-SHA-256 with the label discipline of spec §3 and Appendix A.

Spec §3 table, row "KDF": "HKDF-SHA-256 | Every `info` begins with a label from Appendix A."
Every HKDF call site in the spec has the shape  info = label ‖ context  (context possibly empty),
e.g. §6.4 `info = "SecMP-HX/1 sk" ‖ transcript`, §3.4 `info = "SecMP-commit/1" ‖ N`.
The vector suite (vectors/SCHEMA.md) calls the context `extra_info`.
"""

from . import labels, primitives, sizes

# RFC 5869 §2.3: L ≤ 255 · HashLen.
MAX_LEN = 255 * sizes.SHA256


def _info(label: bytes, extra_info: bytes) -> bytes:
    # §3 table: "Every info begins with a label from Appendix A".
    if label not in labels.APPENDIX_A:
        raise ValueError(f"not an Appendix A label: {label!r}")
    # Label and context are concatenated directly (‖), with no separator or length prefix.
    return label + extra_info


def _check_len(length: int) -> None:
    if not 1 <= length <= MAX_LEN:
        raise ValueError(f"HKDF output length must be in 1..{MAX_LEN}, got {length}")


def labeled_hkdf(salt: bytes, ikm: bytes, label: bytes, extra_info: bytes, length: int) -> bytes:
    """OKM = HKDF-SHA-256(salt, IKM, info = label ‖ extra_info, L = length) (RFC 5869 §2, spec §3)."""
    _check_len(length)
    return primitives.hkdf(salt, ikm, _info(label, extra_info), length)


def labeled_hkdf_expand(prk: bytes, label: bytes, extra_info: bytes, length: int) -> bytes:
    """OKM = HKDF-Expand(PRK, info = label ‖ extra_info, L = length) (RFC 5869 §2.3, spec §3).

    Used where the spec calls HKDF-Expand directly: §3.4 CAEAD, §8.3 link keys.
    """
    _check_len(length)
    # RFC 5869 §2.3: "PRK  a pseudorandom key of at least HashLen octets".
    if len(prk) < sizes.SHA256:
        raise ValueError(f"HKDF-Expand PRK must be at least {sizes.SHA256} bytes, got {len(prk)}")
    return primitives.hkdf_expand(prk, _info(label, extra_info), length)


# SCHEMA §4.1 `mode`.
EXTRACT_EXPAND = "extract-expand"
EXPAND = "expand"


def derive(mode: str, salt: bytes, ikm: bytes, label: bytes, extra_info: bytes, length: int) -> bytes:
    """SCHEMA §4.1 op "derive": "extract-expand" = HKDF(salt, IKM, info, L) with an empty salt
    meaning 0^32 (RFC 5869); "expand" = HKDF-Expand(PRK = ikm, info, L), salt MUST be empty."""
    if mode == EXTRACT_EXPAND:
        return labeled_hkdf(salt, ikm, label, extra_info, length)
    if mode == EXPAND:
        if salt:
            raise ValueError("mode expand takes no salt")
        return labeled_hkdf_expand(ikm, label, extra_info, length)
    raise ValueError(f"unknown mode {mode!r}")
