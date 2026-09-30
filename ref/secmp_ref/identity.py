# SPDX-License-Identifier: AGPL-3.0-or-later
"""IKSPublic, fingerprint and safety number (spec §6.2, §6.7).

    IKSPublic { ver: u8 = 0x01, ik_ed25519: [u8;32], ik_mldsa65: [u8;1952], ik_dh: [u8;32] }     ; 2017 B
    fingerprint(iks) = SHA-256("SecMP-FP/1" ‖ encode(iks))

    iter(fp):  h = fp; repeat 5200 times: h = SHA-256("SecMP-SAS/1" ‖ h ‖ fp); return h
    half(fp):  6 groups of 5 decimal digits: for k in 0..6: int_be(iter(fp)[5k..5k+5]) mod 100000, zero-padded
    safety_number = concat(sorted_lexicographically(half(fp_A), half(fp_B)))     ; 60 digits
"""

from . import labels, primitives, sizes

VER = 0x01
SAS_ITERATIONS = 5200


def encode_iks_public(ik_ed25519: bytes, ik_mldsa65: bytes, ik_dh: bytes) -> bytes:
    primitives.require_len("ik_ed25519", ik_ed25519, sizes.ED25519_PK)
    primitives.require_len("ik_mldsa65", ik_mldsa65, sizes.MLDSA65_PK)
    primitives.require_len("ik_dh", ik_dh, sizes.X25519_PK)
    return bytes([VER]) + ik_ed25519 + ik_mldsa65 + ik_dh


def iks_public_from_seeds(ed_seed: bytes, mldsa_seed: bytes, dh_seed: bytes) -> bytes:
    """A well-formed encoded IKSPublic from the three secrets (SCHEMA §4.6, SQ-10)."""
    pk_mldsa, _ = primitives.ml_dsa_65_keygen(mldsa_seed)
    return encode_iks_public(primitives.ed25519_public(ed_seed), pk_mldsa,
                             primitives.x25519_public(dh_seed))


def fingerprint(iks: bytes) -> bytes:
    primitives.require_len("encoded IKSPublic", iks, sizes.IKS_PUBLIC)
    return primitives.sha256(labels.FP + iks)


def sas_iter(fp: bytes) -> bytes:
    primitives.require_len("fingerprint", fp, sizes.FINGERPRINT)
    h = fp
    for _ in range(SAS_ITERATIONS):
        h = primitives.sha256(labels.SAS + h + fp)
    return h


def sas_half(fp: bytes) -> str:
    """30 decimal digits: six groups taken from bytes 0–29 of iter(fp)."""
    h = sas_iter(fp)
    return "".join(f"{int.from_bytes(h[5 * k: 5 * k + 5], 'big') % 100000:05d}" for k in range(6))


def safety_number(fp_a: bytes, fp_b: bytes) -> str:
    """60 digits; symmetric in its arguments."""
    return "".join(sorted((sas_half(fp_a), sas_half(fp_b))))
