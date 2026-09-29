# SPDX-License-Identifier: AGPL-3.0-or-later
"""MsgEncrypt / MsgDecrypt, Encrypt-then-MAC for E2E bodies (spec §3.3).

    (K_enc ‖ K_mac ‖ IV) = HKDF-SHA-256(salt = 0^32, IKM = MK, info = "SecMP-TR/1 msgkeys", L = 32+32+12)
    C   = ChaCha20(K_enc, nonce = IV, counter = 0) XOR P
    TAG = HMAC-SHA-256(K_mac, AD ‖ C)
    return C ‖ TAG

"Decrypt: recompute TAG', compare in constant time, only then decrypt. MsgEncrypt MUST reject
|P| ≠ BODY_LEN and MsgDecrypt MUST reject |C ‖ TAG| ≠ BODY_LEN + 32, with the same uniform error
as a MAC failure. Padding is not interpreted here."
"""

from . import hkdf_labels, labels, primitives, sizes
from .errors import Reject

MK = 32
C_TAG_LEN = sizes.BODY_LEN + sizes.HMAC_TAG


def message_keys(mk: bytes) -> tuple[bytes, bytes, bytes]:
    """(K_enc, K_mac, IV) = okm[0:32], okm[32:64], okm[64:76]."""
    primitives.require_len("message key", mk, MK)
    okm = hkdf_labels.labeled_hkdf(bytes(32), mk, labels.TR_MSGKEYS, b"",
                                   sizes.CHACHA_KEY + sizes.HMAC_TAG + sizes.CHACHA_NONCE)
    return okm[:32], okm[32:64], okm[64:76]


def msg_encrypt(mk: bytes, ad: bytes, p: bytes) -> bytes:
    """Returns C ‖ TAG (BODY_LEN + 32 bytes)."""
    if len(p) != sizes.BODY_LEN:
        raise Reject()
    k_enc, k_mac, iv = message_keys(mk)
    c = primitives.chacha20_xor(k_enc, iv, 0, p)
    return c + primitives.hmac_sha256(k_mac, ad + c)


def msg_decrypt(mk: bytes, ad: bytes, c_tag: bytes) -> bytes:
    if len(c_tag) != C_TAG_LEN:
        raise Reject()
    k_enc, k_mac, iv = message_keys(mk)
    c, tag = c_tag[: sizes.BODY_LEN], c_tag[sizes.BODY_LEN:]
    if not primitives.ct_equal(primitives.hmac_sha256(k_mac, ad + c), tag):
        raise Reject()
    return primitives.chacha20_xor(k_enc, iv, 0, c)
