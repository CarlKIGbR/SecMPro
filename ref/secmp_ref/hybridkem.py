# SPDX-License-Identifier: AGPL-3.0-or-later
"""HybridKEM-768 and HybridKEM-1024 (spec §3.2).

    Encaps(pk_peer = (pk_dh, ek_kem)):
        (sk_e, pk_e)     = X25519.keygen()
        ss_dh            = X25519(sk_e, pk_dh)               ; MUST NOT be all-zero
        (ct_kem, ss_kem) = ML-KEM.Encaps(ek_kem)
        ss = SHA3-256( ss_kem ‖ ss_dh ‖ SHA3-256(ct_kem) ‖ SHA3-256(ek_kem) ‖ pk_dh ‖ pk_e ‖ V )
        return (ct = (pk_e, ct_kem), ss)

    Decaps(sk_peer = (sk_dh, dk_kem), ct = (pk_e, ct_kem)):
        ss_dh  = X25519(sk_dh, pk_e)                          ; MUST NOT be all-zero
        ss_kem = ML-KEM.Decaps(dk_kem, ct_kem)                ; implicit rejection per FIPS 203
        ss     = SHA3-256( ... as above ... )

For reproducible vectors the randomness is supplied by the caller: sk_e (32 B X25519 secret) and
m (32 B, FIPS 203 Encaps_internal). The decapsulation key is the 64-byte seed d ‖ z (§3 table,
"Decapsulation keys stored as 64-byte seeds"); ek_kem and pk_dh, which the combiner needs on the
decapsulating side too, are recomputed from the secrets.
"""

from typing import NamedTuple

from . import labels, primitives, sizes
from .errors import Reject

Q = 3329


class Params(NamedTuple):
    level: int      # ML-KEM parameter set
    k: int          # FIPS 203 module rank
    ek_len: int
    ct_len: int
    v: bytes        # the combiner label V


HYBRIDKEM_768 = Params(768, 3, sizes.MLKEM768_EK, sizes.MLKEM768_CT, labels.HYBRIDKEM_768)
HYBRIDKEM_1024 = Params(1024, 4, sizes.MLKEM1024_EK, sizes.MLKEM1024_CT, labels.HYBRIDKEM_1024)


def ek_input_check(params: Params, ek: bytes) -> bool:
    """FIPS 203 §7.2 encapsulation-key checks. Type check: |ek| = 384k + 32. Modulus check:
    ByteEncode12(ByteDecode12(ek[0:384k])) = ek[0:384k], i.e. no packed 12-bit coefficient is
    ≥ q. Every 3 bytes b0 b1 b2 pack two coefficients, little-endian bit order (Alg. 5/6)."""
    if len(ek) != 384 * params.k + 32:
        return False
    t = ek[: 384 * params.k]
    for j in range(0, len(t), 3):
        b0, b1, b2 = t[j], t[j + 1], t[j + 2]
        c0 = b0 | ((b1 & 0x0F) << 8)
        c1 = (b1 >> 4) | (b2 << 4)
        if c0 >= Q or c1 >= Q:
            return False
    return True


def keygen(params: Params, dk_seed: bytes, sk_dh: bytes) -> tuple[bytes, bytes, bytes]:
    """The recipient's hybrid key pair from its secrets → (ek_kem, dk_kem, pk_dh)."""
    ek_kem, dk_kem = primitives.ml_kem_keygen(params.level, dk_seed)
    return ek_kem, dk_kem, primitives.x25519_public(sk_dh)


def _combine(params, ss_kem, ss_dh, ct_kem, ek_kem, pk_dh, pk_e) -> bytes:
    sha3 = primitives.sha3_256
    return sha3(ss_kem + ss_dh + sha3(ct_kem) + sha3(ek_kem) + pk_dh + pk_e + params.v)


def encaps(params: Params, ek_kem: bytes, pk_dh: bytes, m: bytes, sk_e: bytes) -> tuple[bytes, bytes, bytes]:
    """→ (pk_e, ct_kem, ss). Raises Reject for a malformed ek_kem or pk_dh, or an all-zero ss_dh."""
    if not ek_input_check(params, ek_kem):
        raise Reject()
    pk_e = primitives.x25519_public(sk_e)
    ss_dh = primitives.x25519(sk_e, pk_dh)                       # rejects wrong length and all-zero
    ct_kem, ss_kem = primitives.ml_kem_encaps(params.level, ek_kem, m)
    return pk_e, ct_kem, _combine(params, ss_kem, ss_dh, ct_kem, ek_kem, pk_dh, pk_e)


def decaps(params: Params, dk_seed: bytes, sk_dh: bytes, pk_e: bytes, ct_kem: bytes) -> bytes:
    """→ ss. A well-formed but wrong ct_kem is not an error (implicit rejection, SQ-05); only a
    wrong length of ct_kem or pk_e, or an all-zero ss_dh, raises Reject."""
    ek_kem, dk_kem, pk_dh = keygen(params, dk_seed, sk_dh)
    if len(ct_kem) != params.ct_len:
        raise Reject()
    ss_dh = primitives.x25519(sk_dh, pk_e)                       # rejects wrong length and all-zero
    ss_kem = primitives.ml_kem_decaps(params.level, dk_kem, ct_kem)
    return _combine(params, ss_kem, ss_dh, ct_kem, ek_kem, pk_dh, pk_e)
