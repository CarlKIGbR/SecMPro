# SPDX-License-Identifier: AGPL-3.0-or-later
"""HybridSign / HybridVerify (spec §3.5).

    HybridSign(sk = (sk_ed, sk_mldsa), label, M):
        m = SHA-256("SecMP-HybridSign/1" ‖ label ‖ M)
        return Ed25519.Sign(sk_ed, m) ‖ ML-DSA-65.Sign(sk_mldsa, m, ctx = label)
    HybridVerify(pk, label, M, sig): both components MUST verify.

label ∈ {"SecMP-HX/1 bundle", "SecMP-TR/1 keychange"}; any other label is refused. Ed25519 is pure
RFC 8032 Ed25519 over the 32-byte m with strict verification (primitives.ed25519_verify). ML-DSA-65
is pure ML-DSA (FIPS 204 Alg. 2/3) hedged with a caller-supplied rnd; keys from KeyGen_internal(ξ).
"""

from . import labels, primitives, sizes
from .errors import Reject


def keygen(ed_seed: bytes, mldsa_seed: bytes) -> tuple[bytes, bytes, bytes]:
    """→ (pk_ed, pk_mldsa, sk_mldsa). The Ed25519 secret is its 32-byte seed."""
    pk_mldsa, sk_mldsa = primitives.ml_dsa_65_keygen(mldsa_seed)
    return primitives.ed25519_public(ed_seed), pk_mldsa, sk_mldsa


def _digest(label: bytes, msg: bytes) -> bytes:
    return primitives.sha256(labels.HYBRIDSIGN + label + msg)


def sign(ed_seed: bytes, sk_mldsa: bytes, label: bytes, msg: bytes, rnd: bytes) -> bytes:
    """→ sig = sig_ed (64) ‖ sig_mldsa (3309)."""
    if label not in labels.HYBRIDSIGN_LABELS:
        raise ValueError(f"not a HybridSign label: {label!r}")
    m = _digest(label, msg)
    return primitives.ed25519_sign(ed_seed, m) + primitives.ml_dsa_65_sign(sk_mldsa, m, label, rnd)


def verify(pk_ed: bytes, pk_mldsa: bytes, label: bytes, msg: bytes, sig: bytes) -> None:
    """Raises the uniform Reject unless the label is a HybridSign label and both components verify."""
    if (label not in labels.HYBRIDSIGN_LABELS or len(sig) != sizes.HYBRID_SIG
            or len(pk_ed) != sizes.ED25519_PK or len(pk_mldsa) != sizes.MLDSA65_PK):
        raise Reject()
    m = _digest(label, msg)
    ok = True
    for check in (lambda: primitives.ed25519_verify(pk_ed, m, sig[: sizes.ED25519_SIG]),
                  lambda: primitives.ml_dsa_65_verify(pk_mldsa, m, sig[sizes.ED25519_SIG:], label)):
        try:
            check()
        except Reject:
            ok = False
    if not ok:
        raise Reject()
