# SPDX-License-Identifier: AGPL-3.0-or-later
"""SecMP-TR, the hybrid ratchet (spec §7): state, initialisation, Encrypt and Decrypt.

The Signal Double Ratchet with header encryption, extended so that every DH ratchet step also mixes
an ML-KEM-768 shared secret into the root KDF, in the receiving and in the sending half (§7 preamble).

    (RK ‖ HK_A ‖ NHK_B) = HKDF-SHA-256(salt = 0^32, IKM = SK, info = "SecMP-TR/1 init", L = 96)
    KDF_RK(rk, ikm) = HKDF-SHA-256(salt = rk, IKM = ikm, info = "SecMP-TR/1 rk", L = 96) → (rk', ck, nhk)
    KDF_CK(ck)      = (ck' = HMAC-SHA-256(ck, 0x02), mk = HMAC-SHA-256(ck, 0x01))

Randomness comes from the caller: `rng.take(n)` returns the next n random bytes (the OS CSPRNG in a
client, the case stream in the vectors). The draws, in order:

    init_initiator   dh_s secret 32, kem_s seed 64 (d ‖ z), Encaps randomness m 32      (§7.2)
    encrypt          hdr_nonce 24                                                        (§7.3)
    decrypt          on a DH step only (DHRatchet): dh_s secret 32, kem_s seed 64, m 32  (§7.4)

Every rejection of an untrusted cell is the uniform Reject (§7.4 note (b)). Decrypt is transactional
(§7.4 note (c)): it works on a copy of the state and commits only after the body MAC has verified, so a
rejected cell leaves the state exactly as it was. The first skipped-key path mutates only after its
MAC has verified, too.
"""

import dataclasses
from typing import NamedTuple

from . import encodings as enc
from . import hkdf_labels, labels, msgencrypt, primitives, sizes
from .errors import Reject

SKIP_WINDOW = 256                                  # §4.2: skipped keys retained per receiving chain
MAX_FF = 2**20                                     # §4.2: maximum chain fast-forward per message
MAX_SKIPPED = 2 * SKIP_WINDOW                      # §4.2 / §7.4: total bound across chains
U32_MAX = 2**32 - 1
KEM = 768                                          # §3 table: ML-KEM-768 in the ratchet

HDR_NONCE = sizes.XCHACHA_NONCE
assert HDR_NONCE + sizes.HDR_CT + sizes.BODY_LEN + sizes.HMAC_TAG == sizes.CELL      # §7.5 / D.5


class DhKey(NamedTuple):
    """An X25519 key pair. `sk` is the 32-byte secret as drawn; X25519 clamps it (RFC 7748 §5)."""
    sk: bytes
    pk: bytes

    @classmethod
    def from_secret(cls, sk: bytes) -> "DhKey":
        return cls(sk, primitives.x25519_public(sk))


class KemKey(NamedTuple):
    """An ML-KEM-768 key pair from its 64-byte seed d ‖ z (§3 table: "Decapsulation keys stored as
    64-byte seeds"; KeyGen_internal(d, z))."""
    seed: bytes
    ek: bytes
    dk: bytes

    @classmethod
    def from_seed(cls, seed: bytes) -> "KemKey":
        ek, dk = primitives.ml_kem_keygen(KEM, seed)
        return cls(seed, ek, dk)


@dataclasses.dataclass
class RatchetState:
    """§7.1, field for field. `skipped` maps (hk, n) → mk; a Python dict keeps insertion order."""
    sb: bytes
    rk: bytes
    dh_s: DhKey
    dh_r: bytes | None
    kem_s: KemKey
    kem_r: bytes | None
    last_ct_r: bytes | None
    ct_s: bytes | None
    ck_s: bytes | None
    ck_r: bytes | None
    hk_s: bytes | None
    hk_r: bytes | None
    nhk_s: bytes | None
    nhk_r: bytes | None
    n_s: int
    n_r: int
    pn: int
    skipped: dict


def _copy(state: RatchetState) -> RatchetState:
    # Every other field is immutable (bytes, int, NamedTuple of bytes).
    return dataclasses.replace(state, skipped=dict(state.skipped))


def _commit(state: RatchetState, work: RatchetState) -> None:
    for f in dataclasses.fields(RatchetState):
        setattr(state, f.name, getattr(work, f.name))


# ---------------------------------------------------------------------------------------------
# Rejection. For the generator's self-checks only, the check that raised the most recent Reject
# is recorded in `last_rule` (as in encodings.py); Reject itself carries no detail.

last_rule = None


def _fail(rule):
    global last_rule
    last_rule = rule
    raise Reject()


# ---------------------------------------------------------------------------------------------
# KDFs (§7.2)


def kdf_init(sk: bytes) -> tuple[bytes, bytes, bytes]:
    """→ (RK, HK_A, NHK_B)."""
    primitives.require_len("SK", sk, 32)
    okm = hkdf_labels.labeled_hkdf(bytes(32), sk, labels.TR_INIT, b"", 96)
    return okm[:32], okm[32:64], okm[64:]


def kdf_rk(rk: bytes, ikm: bytes) -> tuple[bytes, bytes, bytes]:
    """→ (rk', ck, nhk)."""
    okm = hkdf_labels.labeled_hkdf(rk, ikm, labels.TR_RK, b"", 96)
    return okm[:32], okm[32:64], okm[64:]


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    """→ (ck', mk)."""
    return primitives.hmac_sha256(ck, b"\x02"), primitives.hmac_sha256(ck, b"\x01")


# ---------------------------------------------------------------------------------------------
# Initialisation (§7.2)


def init_initiator(sk: bytes, sb: bytes, spk_dh_r: bytes, rpk_kem_r: bytes, rng) -> RatchetState:
    """Alice role (the HX initiator, sends first). spk_dh_r / rpk_kem_r: the responder's SPK_dh and
    RPK_kem public keys from its verified bundle."""
    rk, hk_a, nhk_b = kdf_init(sk)
    dh_s = DhKey.from_secret(rng.take(32))
    kem_s = KemKey.from_seed(rng.take(sizes.MLKEM_SEED))
    ct_s, ss_pq = primitives.ml_kem_encaps(KEM, rpk_kem_r, rng.take(32))
    rk, ck_s, nhk_s = kdf_rk(rk, primitives.x25519(dh_s.sk, spk_dh_r) + ss_pq)
    return RatchetState(sb=sb, rk=rk, dh_s=dh_s, dh_r=spk_dh_r, kem_s=kem_s, kem_r=rpk_kem_r, last_ct_r=None,
                        ct_s=ct_s, ck_s=ck_s, ck_r=None, hk_s=hk_a, hk_r=None, nhk_s=nhk_s, nhk_r=nhk_b,
                        n_s=0, n_r=0, pn=0, skipped={})


def init_responder(sk: bytes, sb: bytes, spk_dh: DhKey, rpk_kem: KemKey) -> RatchetState:
    """Bob role (the HX responder): its own SPK_dh and RPK_kem key pairs. Draws nothing."""
    rk, hk_a, nhk_b = kdf_init(sk)
    return RatchetState(sb=sb, rk=rk, dh_s=spk_dh, dh_r=None, kem_s=rpk_kem, kem_r=None, last_ct_r=None,
                        ct_s=None, ck_s=None, ck_r=None, hk_s=None, hk_r=None, nhk_s=nhk_b, nhk_r=hk_a,
                        n_s=0, n_r=0, pn=0, skipped={})


# ---------------------------------------------------------------------------------------------
# Encrypt (§7.3)


def _hdr_ad(sb: bytes) -> bytes:
    return labels.TR_HDR + sb


def _body_ad(sb: bytes, hdr_nonce: bytes, hdr_ct: bytes) -> bytes:
    return labels.TR_BODY + sb + hdr_nonce + hdr_ct


def header_value(state: RatchetState) -> dict:
    """The HeaderV1 of the next message on the sending chain (§7.3, D.5); `flags` is 0 (§7.5)."""
    return {"ver": enc.PROTO_VER, "flags": 0, "dh_pk": state.dh_s.pk, "pn": state.pn, "n": state.n_s,
            "ek_pq": state.kem_s.ek, "ct_pq": state.ct_s}


def encrypt(state: RatchetState, content: bytes, rng, mk_log: list | None = None) -> bytes:
    """Encrypt the unpadded encoded Content (§7.6, D.5) into a 4096-byte cell. The caller persists
    the state before the cell leaves the process (§7.5 persist-before-send)."""
    if state.ck_s is None or state.hk_s is None:
        raise ValueError("no sending chain (the responder sends only after its first DH step)")
    if state.n_s == U32_MAX:
        raise ValueError("n_s would overflow")        # §7.3 "checked_add; abort at u32::MAX"
    ck_s, mk = kdf_ck(state.ck_s)
    header = enc.raw("HeaderV1", header_value(state))
    hdr_nonce = rng.take(HDR_NONCE)
    primitives.require_len("hdr_nonce", hdr_nonce, HDR_NONCE)
    hdr_ct = primitives.xchacha20poly1305_seal(state.hk_s, hdr_nonce, _hdr_ad(state.sb), header)
    body = msgencrypt.msg_encrypt(mk, _body_ad(state.sb, hdr_nonce, hdr_ct), enc.iso_pad(content, sizes.BODY_LEN))
    state.ck_s = ck_s
    state.n_s += 1
    if mk_log is not None:
        mk_log.append(mk)
    return hdr_nonce + hdr_ct + body


# ---------------------------------------------------------------------------------------------
# Decrypt (§7.4)


def split(cell: bytes) -> tuple[bytes, bytes, bytes]:
    """(hdr_nonce, hdr_ct, body = body_ct ‖ tag); any length other than CELL_SIZE rejects."""
    if len(cell) != sizes.CELL:
        _fail("cell-length")
    return cell[:HDR_NONCE], cell[HDR_NONCE: HDR_NONCE + sizes.HDR_CT], cell[HDR_NONCE + sizes.HDR_CT:]


def open_header(sb: bytes, hk: bytes | None, hdr_nonce: bytes, hdr_ct: bytes) -> dict | None:
    """Open() of §7.4: the decoded HeaderV1, or None when hk is absent or the AEAD does not open.
    A header that opens but does not decode (App. D, §4.1 decoder obligations, `flags` ≠ 0 by §7.5)
    rejects the cell: only the holder of hk can have sealed it."""
    if hk is None:
        return None
    try:
        data = primitives.xchacha20poly1305_open(hk, hdr_nonce, _hdr_ad(sb), hdr_ct)
    except Reject:
        return None
    try:
        return enc.decode("HeaderV1", data)
    except Reject:
        _fail("header-decode")


def _msg_decrypt(mk, ad, body):
    try:
        return msgencrypt.msg_decrypt(mk, ad, body)
    except Reject:
        _fail("body-mac")


def skip_message_keys(s: RatchetState, until: int) -> None:
    if s.ck_r is None:
        return                                    # no receiving chain yet (responder before its first step)
    if until < s.n_r:
        _fail("replay")                           # replay / stale counter
    if until - s.n_r > MAX_FF:
        _fail("max-ff")
    while s.n_r < until:
        s.ck_r, mk = kdf_ck(s.ck_r)
        if until - s.n_r <= SKIP_WINDOW:          # older positions can no longer arrive
            s.skipped[(s.hk_r, s.n_r)] = mk
        s.n_r += 1
    while len(s.skipped) > MAX_SKIPPED:           # evict the earliest-inserted entries, across chains
        del s.skipped[next(iter(s.skipped))]


def dh_ratchet(s: RatchetState, header: dict, rng) -> None:
    s.pn, s.n_s, s.n_r = s.n_s, 0, 0
    s.hk_s, s.hk_r = s.nhk_s, s.nhk_r
    s.dh_r, s.kem_r, s.last_ct_r = header["dh_pk"], header["ek_pq"], header["ct_pq"]
    ss_pq_recv = primitives.ml_kem_decaps(KEM, s.kem_s.dk, header["ct_pq"])   # ct was encapsulated to OUR kem_s
    s.rk, s.ck_r, s.nhk_r = kdf_rk(s.rk, primitives.x25519(s.dh_s.sk, s.dh_r) + ss_pq_recv)
    s.dh_s = DhKey.from_secret(rng.take(32))
    s.kem_s = KemKey.from_seed(rng.take(sizes.MLKEM_SEED))
    s.ct_s, ss_pq_send = primitives.ml_kem_encaps(KEM, s.kem_r, rng.take(32))
    s.rk, s.ck_s, s.nhk_s = kdf_rk(s.rk, primitives.x25519(s.dh_s.sk, s.dh_r) + ss_pq_send)


def decrypt(state: RatchetState, cell: bytes, rng, mk_log: list | None = None) -> bytes:
    """The padded Content (BODY_LEN bytes), or the uniform Reject with `state` unchanged."""
    hdr_nonce, hdr_ct, body = split(cell)
    body_ad = _body_ad(state.sb, hdr_nonce, hdr_ct)

    # 1. skipped keys: try every distinct hk in `skipped`, then look up (hk, header.n)
    for hk in dict.fromkeys(hk for hk, _ in state.skipped):
        header = open_header(state.sb, hk, hdr_nonce, hdr_ct)
        if header is not None:
            mk = state.skipped.get((hk, header["n"]))
            if mk is None:
                break
            plaintext = _msg_decrypt(mk, body_ad, body)
            del state.skipped[(hk, header["n"])]
            if mk_log is not None:
                mk_log.append(mk)
            return plaintext

    # 2. current / next header key, on a working copy (transactional decrypt, §7.4 note (c))
    s = _copy(state)
    step = False
    header = open_header(s.sb, s.hk_r, hdr_nonce, hdr_ct)
    if header is None:
        header = open_header(s.sb, s.nhk_r, hdr_nonce, hdr_ct)
        step = True
        if header is None:
            _fail("no-header-key")
    if step:
        if header["dh_pk"] == s.dh_r:
            _fail("step-same-dh")                 # a step must carry a new ratchet key
        skip_message_keys(s, header["pn"])        # on the old receiving chain
        dh_ratchet(s, header, rng)
    elif header["ek_pq"] != s.kem_r or header["ct_pq"] != s.last_ct_r:
        _fail("kem-constancy")                    # KEM material must be constant within a chain
    skip_message_keys(s, header["n"])
    s.ck_r, mk = kdf_ck(s.ck_r)
    if s.n_r == U32_MAX:
        _fail("counter")                          # n_r is a u32 (§7.1)
    s.n_r += 1
    plaintext = _msg_decrypt(mk, body_ad, body)
    _commit(state, s)
    if mk_log is not None:
        mk_log.append(mk)
    return plaintext
