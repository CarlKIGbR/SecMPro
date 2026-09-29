# SPDX-License-Identifier: AGPL-3.0-or-later
"""Thin wrappers around the pinned primitive libraries (spec §3 table).

Only primitives live here. Every SecMP construction has its own module and is written from the
spec text. Each wrapper below is checked against official vectors in tests/test_kat_*.py.
Failures caused by untrusted input are mapped to the uniform `Reject`; wrong lengths of values
that this implementation produces itself raise ValueError.
"""

import hashlib

import nacl.bindings
import nacl.exceptions
from cryptography.hazmat.primitives import constant_time, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_768, ML_KEM_1024

from . import sizes
from .errors import Reject


def require_len(name, value, length):
    if len(value) != length:
        raise ValueError(f"{name} must be {length} bytes, got {len(value)}")


# ---------------------------------------------------------------------------------------------
# Hashes: SHA-256, SHA3-256, SHAKE-256 (hashlib)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def shake256(data: bytes, length: int) -> bytes:
    return hashlib.shake_256(data).digest(length)


# ---------------------------------------------------------------------------------------------
# HMAC-SHA-256 and HKDF-SHA-256 (cryptography)


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(message)
    return mac.finalize()


def ct_equal(a: bytes, b: bytes) -> bool:
    """Constant-time comparison (spec §3 table: "constant-time comparison")."""
    return constant_time.bytes_eq(a, b)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract (RFC 5869 §2.2)."""
    return HKDF.extract(hashes.SHA256(), salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869 §2.3); length ≤ 255 · 32."""
    return HKDFExpand(hashes.SHA256(), length, info).derive(prk)


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA-256 = Expand(Extract(salt, ikm), info, length) (RFC 5869 §2)."""
    return HKDF(hashes.SHA256(), length, salt, info).derive(ikm)


# ---------------------------------------------------------------------------------------------
# ChaCha20 (RFC 8439 §2.4) (cryptography)


def chacha20_xor(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    """ChaCha20 encryption = data XOR keystream(key, nonce, initial block counter)."""
    require_len("ChaCha20 key", key, sizes.CHACHA_KEY)
    require_len("ChaCha20 nonce", nonce, sizes.CHACHA_NONCE)
    # cryptography takes a 16-byte value: the 32-bit little-endian block counter followed by the
    # 96-bit nonce, i.e. state words 12..15 of RFC 8439 §2.3.
    full_nonce = counter.to_bytes(4, "little") + nonce
    encryptor = Cipher(algorithms.ChaCha20(key, full_nonce), mode=None).encryptor()
    return encryptor.update(data) + encryptor.finalize()


# ---------------------------------------------------------------------------------------------
# XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03) (PyNaCl / libsodium)


def xchacha20poly1305_seal(key: bytes, nonce: bytes, ad: bytes, plaintext: bytes) -> bytes:
    """Returns ciphertext ‖ 16-byte tag."""
    require_len("XChaCha20-Poly1305 key", key, 32)
    require_len("XChaCha20-Poly1305 nonce", nonce, sizes.XCHACHA_NONCE)
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, nonce, key)


def xchacha20poly1305_open(key: bytes, nonce: bytes, ad: bytes, ciphertext: bytes) -> bytes:
    require_len("XChaCha20-Poly1305 key", key, 32)
    require_len("XChaCha20-Poly1305 nonce", nonce, sizes.XCHACHA_NONCE)
    # PyNaCl raises a bare cffi ValueError (not a CryptoError) for inputs shorter than the tag.
    if len(ciphertext) < sizes.AEAD_TAG:
        raise Reject()
    try:
        return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, ad, nonce, key)
    except nacl.exceptions.CryptoError:
        raise Reject() from None


# ---------------------------------------------------------------------------------------------
# X25519 (RFC 7748) (PyNaCl / libsodium)


def x25519_public(sk: bytes) -> bytes:
    """X25519(sk, 9)."""
    require_len("X25519 secret", sk, sizes.X25519_SK)
    return nacl.bindings.crypto_scalarmult_base(sk)


def x25519(sk: bytes, pk: bytes) -> bytes:
    """X25519(sk, pk); an all-zero output is rejected (spec §3 table: "All-zero output MUST be rejected")."""
    require_len("X25519 secret", sk, sizes.X25519_SK)
    # The binding passes raw pointers to libsodium, so the length of the untrusted input must be
    # checked here.
    if len(pk) != sizes.X25519_PK:
        raise Reject()
    try:
        out = nacl.bindings.crypto_scalarmult(sk, pk)
    except nacl.exceptions.CryptoError:
        # libsodium itself refuses to return the all-zero result.
        raise Reject() from None
    if out == bytes(sizes.X25519_SS):
        raise Reject()
    return out


# ---------------------------------------------------------------------------------------------
# Ed25519 (RFC 8032 §5.1, pure Ed25519) (PyNaCl / libsodium)


def ed25519_public(seed: bytes) -> bytes:
    require_len("Ed25519 seed", seed, sizes.ED25519_SEED)
    pk, _ = nacl.bindings.crypto_sign_seed_keypair(seed)
    return pk


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    """Deterministic Ed25519 signature (RFC 8032 §5.1.6)."""
    require_len("Ed25519 seed", seed, sizes.ED25519_SEED)
    _, sk = nacl.bindings.crypto_sign_seed_keypair(seed)
    return nacl.bindings.crypto_sign(message, sk)[: sizes.ED25519_SIG]


# Spec §3.5 strict verification: "RFC 8032 §5.1.7 with the cofactorless equation [S]B = R + [k]A,
# and rejection of S ≥ L, of non-canonical encodings of A or R (y-coordinate ≥ p), and of
# small-order A or R (order dividing 8, including the identity). Implementations whose library
# does less MUST add the missing checks on the encoded bytes before verifying."
ED25519_P = 2**255 - 19
ED25519_L = 2**252 + 27742317777372353535851937790883648493
# y-coordinates of the eight points of order dividing 8: the identity (y = 1), the point of order
# 2 (y = p − 1), the two of order 4 (y = 0) and the four of order 8 (y = ±Y8, two points each).
# tests/test_hybridsign.py derives this set from the curve equation.
_ED25519_Y8 = 2707385501144840649318225287225658788936804267575313519463743609750303402022
ED25519_SMALL_ORDER_Y = frozenset({0, 1, ED25519_P - 1, _ED25519_Y8, ED25519_P - _ED25519_Y8})


def ed25519_strict_precheck(pk: bytes, sig: bytes) -> None:
    """The §3.5 rules that concern the encodings, checked on the bytes: S < L; A and R canonical
    (y < p); A and R not of small order. Raises Reject. An encoding is 255 bits of y plus the sign
    bit of x (RFC 8032 §5.1.2); every point of order dividing 8 is identified by its y alone."""
    if len(pk) != sizes.ED25519_PK or len(sig) != sizes.ED25519_SIG:
        raise Reject()
    if int.from_bytes(sig[32:], "little") >= ED25519_L:
        raise Reject()
    for point in (pk, sig[:32]):
        y = int.from_bytes(point, "little") & ((1 << 255) - 1)
        if y >= ED25519_P or y in ED25519_SMALL_ORDER_Y:
            raise Reject()


def libsodium_ed25519_verify(pk: bytes, message: bytes, sig: bytes) -> bool:
    """libsodium's crypto_sign_open alone, without the §3.5 pre-checks. Used by the tests that
    record which strict rules libsodium enforces itself; SecMP code calls ed25519_verify."""
    if len(pk) != sizes.ED25519_PK or len(sig) != sizes.ED25519_SIG:
        return False
    try:
        nacl.bindings.crypto_sign_open(sig + message, pk)
    except nacl.exceptions.CryptoError:
        return False
    return True


def ed25519_verify(pk: bytes, message: bytes, sig: bytes) -> None:
    """Strict Ed25519 verification of spec §3.5; raises Reject.

    The byte-level pre-checks implement the encoding rules; libsodium then decodes and checks the
    cofactorless equation (it recomputes R' = [S]B − [k]A and compares its canonical encoding with
    the R bytes). libsodium 1.0.20 also enforces the encoding rules itself (see
    tests/test_hybridsign.py); the pre-checks keep the rule independent of how libsodium was built
    (an ED25519_COMPAT build does not).
    """
    ed25519_strict_precheck(pk, sig)
    if not libsodium_ed25519_verify(pk, message, sig):
        raise Reject()


# ---------------------------------------------------------------------------------------------
# ML-KEM-768 / ML-KEM-1024 (FIPS 203) (kyber-py, deterministic internal algorithms)

_ML_KEM = {768: ML_KEM_768, 1024: ML_KEM_1024}


def ml_kem_keygen(level: int, seed: bytes) -> tuple[bytes, bytes]:
    """ML-KEM.KeyGen_internal(d, z) (FIPS 203 Alg. 16) from the 64-byte seed d ‖ z → (ek, dk)."""
    require_len("ML-KEM seed", seed, sizes.MLKEM_SEED)
    d, z = seed[:32], seed[32:]
    return _ML_KEM[level]._keygen_internal(d, z)


def ml_kem_encaps(level: int, ek: bytes, m: bytes) -> tuple[bytes, bytes]:
    """ML-KEM.Encaps_internal(ek, m) (FIPS 203 Alg. 17) → (ct, ss).

    kyber-py performs the FIPS 203 §7.2 input check (type check and modulus check) on ek and
    raises ValueError on failure; that becomes Reject.
    """
    require_len("ML-KEM encapsulation randomness", m, 32)
    try:
        ss, ct = _ML_KEM[level]._encaps_internal(ek, m)
    except ValueError:
        raise Reject() from None
    return ct, ss


def ml_kem_decaps(level: int, dk: bytes, ct: bytes) -> bytes:
    """ML-KEM.Decaps_internal(dk, ct) (FIPS 203 Alg. 18) with the §7.3 input checks.

    A well-formed but wrong ciphertext is NOT an error: implicit rejection returns K̄ = J(z ‖ c).
    Only failed input checks (wrong lengths, hash check) raise Reject.
    """
    try:
        return _ML_KEM[level]._decaps_internal(dk, ct)
    except ValueError:
        raise Reject() from None


# ---------------------------------------------------------------------------------------------
# ML-DSA-65 (FIPS 204) (dilithium-py, internal algorithms with a caller-supplied rnd)


def ml_dsa_65_keygen(xi: bytes) -> tuple[bytes, bytes]:
    """ML-DSA.KeyGen_internal(ξ) (FIPS 204 Alg. 6) → (pk, sk)."""
    require_len("ML-DSA seed", xi, sizes.MLDSA_SEED)
    return ML_DSA_65._keygen_internal(xi)


def _ml_dsa_message(message: bytes, ctx: bytes) -> bytes:
    """M' = IntegerToBytes(0, 1) ‖ IntegerToBytes(|ctx|, 1) ‖ ctx ‖ M (FIPS 204 Alg. 2 line 10, Alg. 3 line 5)."""
    if len(ctx) > 255:
        raise ValueError("ML-DSA context longer than 255 bytes")
    return bytes([0, len(ctx)]) + ctx + message


def ml_dsa_65_sign(sk: bytes, message: bytes, ctx: bytes, rnd: bytes) -> bytes:
    """ML-DSA.Sign(sk, M, ctx) (FIPS 204 Alg. 2, pure), hedged with the 32-byte rnd supplied by
    the caller instead of drawn from an RBG, so that vectors are reproducible.

    dilithium-py's public sign() cannot take rnd, so Alg. 2 is completed here around
    ML-DSA.Sign_internal (Alg. 7); the ACVP "external / pure / hedged" vectors check this.
    """
    require_len("ML-DSA rnd", rnd, 32)
    return ML_DSA_65._sign_internal(sk, _ml_dsa_message(message, ctx), rnd)


def ml_dsa_65_verify(pk: bytes, message: bytes, sig: bytes, ctx: bytes) -> None:
    """ML-DSA.Verify(pk, M, sig, ctx) (FIPS 204 Alg. 3, pure); raises Reject on failure."""
    if len(pk) != sizes.MLDSA65_PK or len(sig) != sizes.MLDSA65_SIG or len(ctx) > 255:
        raise Reject()
    try:
        ok = ML_DSA_65._verify_internal(pk, _ml_dsa_message(message, ctx), sig)
    except ValueError:
        raise Reject() from None
    if not ok:
        raise Reject()
