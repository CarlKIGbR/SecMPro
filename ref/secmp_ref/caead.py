# SPDX-License-Identifier: AGPL-3.0-or-later
"""CAEAD, the committing AEAD wrapper (spec §3.4).

    CAEAD.Seal(K, N (24 B), AD, P):
        (K_enc ‖ COM) = HKDF-Expand(PRK = K, info = "SecMP-commit/1" ‖ N, L = 64)
        C = XChaCha20-Poly1305.Seal(K_enc, N, AD, P)
        return COM ‖ C                                        ; COM is 32 B, C includes the 16 B tag
    CAEAD.Open(K, N, AD, COM ‖ C): recompute COM, constant-time compare, then open.

N is not part of the output; the caller transmits it (e.g. §5.4 blob = N ‖ COM ‖ ct).
"""

from . import hkdf_labels, labels, primitives, sizes
from .errors import Reject

KEY = 32


def _keys(k: bytes, n: bytes) -> tuple[bytes, bytes]:
    okm = hkdf_labels.labeled_hkdf_expand(k, labels.COMMIT, n, 2 * 32)
    return okm[:32], okm[32:]                      # K_enc, COM


def seal(k: bytes, n: bytes, ad: bytes, p: bytes) -> bytes:
    """Returns COM ‖ C."""
    primitives.require_len("CAEAD key", k, KEY)
    primitives.require_len("CAEAD nonce", n, sizes.XCHACHA_NONCE)
    k_enc, com = _keys(k, n)
    return com + primitives.xchacha20poly1305_seal(k_enc, n, ad, p)


def open(k: bytes, n: bytes, ad: bytes, com_c: bytes) -> bytes:  # noqa: A001 (spec name)
    """Returns P; raises the uniform Reject for a wrong COM and for a failed AEAD open alike."""
    primitives.require_len("CAEAD key", k, KEY)
    if len(n) != sizes.XCHACHA_NONCE or len(com_c) < sizes.CAEAD_COM + sizes.AEAD_TAG:
        raise Reject()
    k_enc, com = _keys(k, n)
    if not primitives.ct_equal(com, com_c[: sizes.CAEAD_COM]):
        raise Reject()
    return primitives.xchacha20poly1305_open(k_enc, n, ad, com_c[sizes.CAEAD_COM:])
