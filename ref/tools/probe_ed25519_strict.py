# SPDX-License-Identifier: AGPL-3.0-or-later
"""Which of the spec §3.5 strict Ed25519 rules does libsodium enforce by itself?

    ref/.venv/bin/python ref/tools/probe_ed25519_strict.py

Each probe is a (A, M, sig) that satisfies the cofactorless equation [S]B = R + [k]A (checked with
the independent model in tests/_ed25519_model.py) and violates exactly one strict rule, so a
libsodium rejection can only come from libsodium's own check of that rule. The same probes are
asserted in tests/test_hybridsign.py.
"""

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

import _ed25519_model as model  # noqa: E402
from secmp_ref import primitives  # noqa: E402
from secmp_ref.errors import Reject  # noqa: E402

MSG = b"SecMP strict Ed25519 probe"
MASK255 = (1 << 255) - 1


def _k(r_enc, a_enc, msg):
    return model._h(r_enc, a_enc, msg)


def sig_for_small_order_a(a_enc: bytes, msg: bytes) -> bytes:
    """R = [r]B, S = r, with r chosen so that k ≡ 0 (mod 8) both before and after reduction mod L;
    then [k]A = O for every A of order dividing 8 and the equation holds."""
    for r in range(1, 1 << 16):
        r_enc = model.encode(model.mul(r, model.B))
        k = _k(r_enc, a_enc, msg)
        if k % 8 == 0 and k % model.L % 8 == 0:
            return r_enc + r.to_bytes(32, "little")
    raise RuntimeError("no r found")


def sig_for_identity_r(r_enc: bytes, msg: bytes, a: int = 0x5ec3a9) -> tuple[bytes, bytes]:
    """A = [a]B, R = an encoding of the identity, S = k·a mod L: [S]B = O + [k]A."""
    a_enc = model.encode(model.mul(a, model.B))
    return a_enc, r_enc + (_k(r_enc, a_enc, msg) % model.L * a % model.L).to_bytes(32, "little")


def probes():
    """→ list of (rule, name, A, M, sig)."""
    out = []
    seed = bytes(range(32))
    a_enc, sig = model.sign(seed, MSG)
    s = int.from_bytes(sig[32:], "little")
    out.append(("S ≥ L", "S + L (row 14)", a_enc, MSG, sig[:32] + (s + model.L).to_bytes(32, "little")))
    y8 = primitives._ED25519_Y8
    y_name = {0: "0", 1: "1", model.P - 1: "p-1", y8: "y8", model.P - y8: "p-y8"}
    for n, t in enumerate(model.torsion_points()):
        enc = model.encode(t)
        v = int.from_bytes(enc, "little")
        y = v & MASK255
        out.append(("small-order A", f"A = [{n}]T8 (y = {y_name[y]})", enc, MSG, sig_for_small_order_a(enc, MSG)))
        if y + model.P < 2**255:                                   # y ∈ {0, 1}: y + p fits
            nc = ((y + model.P) | (v >> 255) << 255).to_bytes(32, "little")
            out.append(("non-canonical A", f"A = [{n}]T8 encoded with y + p", nc, MSG,
                        sig_for_small_order_a(nc, MSG)))
        if model.recover_x(y, 1) is None and v >> 255 == 0:         # x = 0: "negative zero"
            nz = (y | 1 << 255).to_bytes(32, "little")
            out.append(("small-order A", f"A = [{n}]T8 with the x sign bit set", nz, MSG,
                        sig_for_small_order_a(nz, MSG)))
    for rule, name, r_enc in [
        ("small-order R", "R = identity", b"\x01" + bytes(31)),
        ("non-canonical R", "R = identity encoded with y = p + 1", bytes.fromhex("ee" + "ff" * 30 + "7f")),
        ("small-order R", "R = identity with the x sign bit set", b"\x01" + bytes(30) + b"\x80"),
    ]:
        a2, sig2 = sig_for_identity_r(r_enc, MSG)
        out.append((rule, name, a2, MSG, sig2))
    return out


def main():
    print(f"{'rule':16s} {'probe':44s} equation  libsodium  pre-check")
    for rule, name, a, msg, sig in probes():
        eq = model.lenient_verify(a, msg, sig)
        lib = "accepts" if primitives.libsodium_ed25519_verify(a, msg, sig) else "rejects"
        try:
            primitives.ed25519_strict_precheck(a, sig)
            pre = "passes"
        except Reject:
            pre = "rejects"
        print(f"{rule:16s} {name:44s} {'holds' if eq else 'FAILS':9s} {lib:10s} {pre}")


if __name__ == "__main__":
    main()
