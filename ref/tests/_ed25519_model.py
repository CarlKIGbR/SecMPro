# SPDX-License-Identifier: AGPL-3.0-or-later
"""A small pure-Python model of edwards25519 (RFC 8032 §5.1), for tests only.

It builds signatures that satisfy the cofactorless equation [S]B = R + [k]A but violate exactly
one of the strict rules of spec §3.5, so that the tests can tell which rules libsodium enforces by
itself. `lenient_verify` is RFC 8032 §5.1.7 without any of those rules: y is reduced mod p, S is
not range-checked, small-order points are accepted.
"""

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1, 1, 0)


def _inv(x):
    return pow(x, P - 2, P)


def add(p1, p2):
    """RFC 8032 §5.1.4, extended coordinates."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def mul(s, point):
    q = IDENTITY
    while s > 0:
        if s & 1:
            q = add(q, point)
        point = add(point, point)
        s >>= 1
    return q


def equal(p1, p2):
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def recover_x(y, sign):
    """RFC 8032 §5.1.3 steps 2–4; None if there is no such point."""
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    return P - x if (x & 1) != sign else x


def point(x, y):
    return (x, y, 1, x * y % P)


def decode_lenient(enc: bytes):
    """y reduced mod p; x = 0 with the sign bit set is accepted as x = 0."""
    v = int.from_bytes(enc, "little")
    y, sign = (v & ((1 << 255) - 1)) % P, v >> 255
    x = recover_x(y, sign)
    if x is None and y * y % P == 1:
        x = 0
    return None if x is None else point(x, y)


def encode(pt) -> bytes:
    x, y, z, _ = pt
    zi = _inv(z)
    x, y = x * zi % P, y * zi % P
    return (y | (x & 1) << 255).to_bytes(32, "little")


B = point(recover_x(4 * _inv(5) % P, 0), 4 * _inv(5) % P)


def _h(*parts) -> int:
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def sign(seed: bytes, msg: bytes) -> tuple[bytes, bytes]:
    """RFC 8032 §5.1.6 → (A, sig)."""
    digest = hashlib.sha512(seed).digest()
    a = int.from_bytes(digest[:32], "little")
    a = (a & ((1 << 254) - 8)) | (1 << 254)
    a_enc = encode(mul(a, B))
    r = _h(digest[32:], msg) % L
    r_enc = encode(mul(r, B))
    s = (r + _h(r_enc, a_enc, msg) * a) % L
    return a_enc, r_enc + s.to_bytes(32, "little")


def lenient_verify(a_enc: bytes, msg: bytes, sig: bytes) -> bool:
    """[S]B = R + [k]A with k = SHA-512(R ‖ A ‖ M) mod L, and nothing else."""
    a, r = decode_lenient(a_enc), decode_lenient(sig[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    k = _h(sig[:32], a_enc, msg) % L
    return equal(mul(s, B), add(r, mul(k, a)))


def torsion_points():
    """The eight points of order dividing 8, from the curve itself: [L]·Q for a point Q whose
    image has order 8 generates the torsion subgroup."""
    y = 2
    while True:
        x = recover_x(y, 0)
        if x is not None:
            t = mul(L, point(x, y))
            if not equal(mul(4, t), IDENTITY):
                return [mul(i, t) for i in range(8)]
        y += 1
