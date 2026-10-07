# SPDX-License-Identifier: AGPL-3.0-or-later
"""SecMP-LINK (spec §8): the relay identity and RelayInfoV1 (§8.2), the hybrid NK-style handshake
(§8.3) and the fixed-size AEAD frames (§8.4).

    C → R:  HELLO { magic = "SECMP", ver }
    R → C:  RELAYINFO { RelayInfoV1 }
    C → R:  HS1 { ver, kid, e_c, ek_c, ct_stat = HybridKEM-1024.Encaps((relay_dh_pk, relay_kem_ek)), mac1 }
    R → C:  HS2 { ver, e_r, ct_c, mac2 }

    h0  = SHA-256("SecMP-LINK/1 h0" ‖ ver ‖ kid ‖ relay_fp ‖ e_c ‖ SHA-256(ek_c) ‖ pk_e1 ‖ SHA-256(ct_kem))
    ck1 = HKDF-Extract(salt = h0, IKM = ss1);  mac1 = HMAC-SHA-256(ck1, "SecMP-LINK/1 hs1")
    (ct_c, ss2) = HybridKEM-768.Encaps((e_c, ek_c)), the hybrid ciphertext being (e_r, ct_c)
    h1  = SHA-256(h0 ‖ mac1 ‖ e_r ‖ SHA-256(ct_c))
    ck2 = HKDF-Extract(salt = h1, IKM = ck1 ‖ ss2);  mac2 = HMAC-SHA-256(ck2, "SecMP-LINK/1 hs2")
    (k_c2r ‖ k_r2c ‖ sess_id) = HKDF-Expand(ck2, "SecMP-LINK/1 keys", 32 + 32 + 16)

    Frame (4352 B) = XChaCha20-Poly1305.Seal(k_dir, 0^16 ‖ counter_dir (u64 BE),
                                             "SecMP-LINK/1 frame" ‖ sess_id, pad(payload, 4336))

Randomness is drawn from the caller's `rng` (an object with take(n)) in the order of reading OPEN-1:
the client draws `e_c_sk`, `ek_c_seed`, `sk_e1`, `m1`; the relay draws `sk_er`, `m2`, and only after
`mac1` has verified (reading OPEN-2). `kid` is a u32 big-endian in `h0` as in HS1 (D.1).

Every failure on received bytes is the uniform Reject (reading OPEN-2). For the generator's self-checks
only, the check that raised it is recorded in `last_rule`; the names are those of SCHEMA §4.11's "ref
check" column.
"""

import dataclasses
from typing import NamedTuple

from . import encodings as enc
from . import hybridkem, labels, primitives, sizes
from .errors import Reject

KEYS_LEN = 32 + 32 + 16                           # §8.3: k_c2r ‖ k_r2c ‖ sess_id
SESS_ID = 16
MAX_VALIDITY = 60 * 86_400                        # §8.2 "valid_until − now ≤ 60 days"; reading OPEN-4: checked by the client
COUNTER_LIMIT = 2**64                             # §8.4 counter_dir is a u64, `checked_add`
NONCE_PREFIX = bytes(16)                          # §8.4 nonce = 0^16 ‖ u64be(counter)
assert sizes.FRAME == sizes.FRAME_PLAINTEXT + sizes.AEAD_TAG == 4352
assert len(NONCE_PREFIX) + 8 == sizes.XCHACHA_NONCE
RELAYINFO_SIGNED = sizes.RELAY_INFO - sizes.ED25519_SIG
assert RELAYINFO_SIGNED == 1677                   # "all preceding fields" of RelayInfoV1


last_rule = None


def _fail(rule):
    global last_rule
    last_rule = rule
    raise Reject()


class CounterOverflow(Exception):
    """§8.4 `checked_add (abort on overflow)`: a local abort, not a verdict on received bytes."""


# ---------------------------------------------------------------------------------------------
# §8.2 relay identity and RelayInfoV1


def relay_fp(relay_sig_pk: bytes) -> bytes:
    """relay_fp = SHA-256("SecMP-LINK/1 relay-fp" ‖ relay_sig_pk) (§8.2, §5.3)."""
    return primitives.sha256(labels.LINK_RELAY_FP + relay_sig_pk)


def akc(access_key: bytes) -> bytes:
    """akc = SHA-256("SecMP-Q/1 akc" ‖ relay_access_key) (§5.3, §9.6)."""
    return primitives.sha256(labels.Q_AKC + access_key)


class RelayKeys(NamedTuple):
    """The relay's long-term identity `relay_sig`, the static pair (`relay_dh`, `relay_kem`) of its one
    key generation `kid`, and the operator's `relay_access_key` (§8.2, §9.6). `kem_seed` is the 64-byte
    ML-KEM-1024 seed d ‖ z (§3 table: decapsulation keys are stored as seeds)."""
    sig_seed: bytes
    sig_pk: bytes
    kid: int
    dh_sk: bytes
    dh_pk: bytes
    kem_seed: bytes
    kem_ek: bytes
    access_key: bytes

    @classmethod
    def from_secrets(cls, sig_seed: bytes, dh_sk: bytes, kem_seed: bytes, access_key: bytes,
                     kid: int) -> "RelayKeys":
        kem_ek, _ = primitives.ml_kem_keygen(1024, kem_seed)
        return cls(sig_seed, primitives.ed25519_public(sig_seed), kid, dh_sk, primitives.x25519_public(dh_sk),
                   kem_seed, kem_ek, access_key)

    @property
    def fp(self) -> bytes:
        return relay_fp(self.sig_pk)

    @property
    def akc(self) -> bytes:
        return akc(self.access_key)


def relayinfo_message(info: dict) -> bytes:
    """"SecMP-LINK/1 relayinfo" ‖ all fields before `sig` (the 1677 encoded bytes)."""
    fields = enc.raw("RelayInfoV1", {k: v for k, v in info.items() if k != "sig"})
    return labels.LINK_RELAYINFO + fields


def sign_relayinfo(sig_seed: bytes, info: dict) -> dict:
    """The RelayInfoV1 value with `sig` = Ed25519(relay_sig, relayinfo_message) (deterministic, RFC 8032)."""
    unsigned = {k: v for k, v in info.items() if k != "sig"}
    return {**unsigned, "sig": primitives.ed25519_sign(sig_seed, relayinfo_message(unsigned))}


def relayinfo(keys: RelayKeys, valid_until: int) -> dict:
    """The relay's RelayInfoV1 value (§8.2, D.1)."""
    return sign_relayinfo(keys.sig_seed, {
        "ver": enc.PROTO_VER, "relay_sig_pk": keys.sig_pk, "kid": keys.kid, "relay_dh_pk": keys.dh_pk,
        "relay_kem_ek": keys.kem_ek, "akc": keys.akc, "valid_until": valid_until})


def relayinfo_record(info: dict) -> bytes:
    """RELAYINFO record: len ‖ 0x02 ‖ RelayInfoV1 (D.1), written literally (the value may be manipulated)."""
    return enc.raw("Record/RELAYINFO", {"len": enc.RELAYINFO_BODY, "type": enc.REC_RELAYINFO, "relay_info": info})


def hello() -> bytes:
    """HELLO record: len (7) ‖ 0x01 ‖ "SECMP" ‖ ver (D.1)."""
    return enc.encode("Record/HELLO", {"len": enc.HELLO_BODY, "type": enc.REC_HELLO, "magic": enc.HELLO_MAGIC,
                                       "ver": enc.PROTO_VER})


def hello_accept(record: bytes) -> None:
    """The relay's check of a HELLO record; it answers with its RELAYINFO (§8.2)."""
    try:
        enc.decode("Record/HELLO", record)
    except Reject:
        _fail("hello-decode")


def relayinfo_accept(record: bytes, pinned_fp: bytes, access_key: bytes | None, now: int) -> dict:
    """The client's processing of a RELAYINFO record (§8.2): the RelayInfoV1 decoder with the §4.1
    obligations (`relay_sig_pk`, the R and S of `sig`, `relay_dh_pk` not low-order, the `relay_kem_ek`
    modulus check), then strict Ed25519 (§3.5) of `sig`, `relay_fp` = the pinned value, `valid_until ≥
    now`, `valid_until − now ≤ 60 days` (reading OPEN-4), and `akc` if the client holds an access key.
    Returns the RelayInfoV1 value; the caller uses it for this link only and never caches it."""
    try:
        info = enc.decode("Record/RELAYINFO", record)["relay_info"]
    except Reject:
        _fail("ri-decode")
    try:
        primitives.ed25519_verify(info["relay_sig_pk"], relayinfo_message(info), info["sig"])
    except Reject:
        _fail("ri-sig")
    if not primitives.ct_equal(relay_fp(info["relay_sig_pk"]), pinned_fp):
        _fail("ri-fp")
    if info["valid_until"] < now:
        _fail("ri-expired")
    if info["valid_until"] - now > MAX_VALIDITY:
        _fail("ri-validity")
    if access_key is not None and not primitives.ct_equal(info["akc"], akc(access_key)):
        _fail("ri-akc")
    return info


# ---------------------------------------------------------------------------------------------
# §8.3 handshake


def h0(ver: int, kid: int, fp: bytes, e_c: bytes, ek_c: bytes, pk_e1: bytes, ct_kem: bytes) -> bytes:
    sha = primitives.sha256
    return sha(labels.LINK_H0 + bytes([ver]) + kid.to_bytes(4, "big") + fp + e_c + sha(ek_c) + pk_e1 + sha(ct_kem))


def _ck1_mac1(h0_: bytes, ss1: bytes) -> tuple[bytes, bytes]:
    ck1 = primitives.hkdf_extract(h0_, ss1)
    return ck1, primitives.hmac_sha256(ck1, labels.LINK_HS1)


def h1(h0_: bytes, mac1: bytes, e_r: bytes, ct_c: bytes) -> bytes:
    return primitives.sha256(h0_ + mac1 + e_r + primitives.sha256(ct_c))


def _ck2_mac2(h1_: bytes, ck1: bytes, ss2: bytes) -> tuple[bytes, bytes]:
    ck2 = primitives.hkdf_extract(h1_, ck1 + ss2)
    return ck2, primitives.hmac_sha256(ck2, labels.LINK_HS2)


def link_keys(ck2: bytes) -> tuple[bytes, bytes, bytes]:
    """(k_c2r ‖ k_r2c ‖ sess_id) = HKDF-Expand(PRK = ck2, "SecMP-LINK/1 keys", 80), split 32/32/16."""
    okm = primitives.hkdf_expand(ck2, labels.LINK_KEYS, KEYS_LEN)
    return okm[:32], okm[32:64], okm[64:]


class ClientHs(NamedTuple):
    """The client's handshake state between HS1 and HS2, and the values of HS1."""
    e_c_sk: bytes
    e_c: bytes
    ek_c_seed: bytes
    ek_c: bytes
    pk_e1: bytes
    ct_kem: bytes
    ss1: bytes
    h0: bytes
    ck1: bytes
    mac1: bytes
    hs1: bytes                                    # the HS1 body without its record header (2853 B)
    record: bytes                                 # len ‖ 0x03 ‖ hs1 (2856 B)


def hs1(info: dict, rng) -> ClientHs:
    """C → R: HS1 to the relay of the accepted RelayInfoV1 `info` (§8.3). Its `relay_fp` is computed from
    `info.relay_sig_pk`, which relayinfo_accept has matched with the pinned value."""
    fp = relay_fp(info["relay_sig_pk"])
    e_c_sk = rng.take(sizes.X25519_SK)
    e_c = primitives.x25519_public(e_c_sk)
    ek_c_seed = rng.take(sizes.MLKEM_SEED)
    ek_c, _ = primitives.ml_kem_keygen(768, ek_c_seed)
    sk_e1, m1 = rng.take(sizes.X25519_SK), rng.take(32)        # HybridKEM.Encaps: X25519.keygen, then ML-KEM.Encaps
    pk_e1, ct_kem, ss1 = hybridkem.encaps(hybridkem.HYBRIDKEM_1024, info["relay_kem_ek"], info["relay_dh_pk"],
                                          m1, sk_e1)
    h0_ = h0(enc.PROTO_VER, info["kid"], fp, e_c, ek_c, pk_e1, ct_kem)
    ck1, mac1 = _ck1_mac1(h0_, ss1)
    value = {"len": enc.HS1_BODY, "type": enc.REC_HS1, "ver": enc.PROTO_VER, "kid": info["kid"], "e_c": e_c,
             "ek_c": ek_c, "pk_e1": pk_e1, "ct_kem": ct_kem, "mac1": mac1}
    record = enc.encode("Record/HS1", value)
    return ClientHs(e_c_sk, e_c, ek_c_seed, ek_c, pk_e1, ct_kem, ss1, h0_, ck1, mac1, record[3:], record)


class Hs2(NamedTuple):
    """The relay's handshake values and the HS2 it sends."""
    ss1: bytes
    h0: bytes
    ck1: bytes
    e_r: bytes
    ct_c: bytes
    ss2: bytes
    h1: bytes
    ck2: bytes
    mac2: bytes
    hs2: bytes                                    # without the record header (1153 B)
    record: bytes                                 # len ‖ 0x04 ‖ hs2 (1156 B)
    k_c2r: bytes
    k_r2c: bytes
    sess_id: bytes


def hs1_accept(keys: RelayKeys, record: bytes, rng) -> tuple[Hs2, "Link"]:
    """R: process HS1 and answer HS2 (§8.3). The HS1 decoder carries the §4.1 obligations on `e_c`,
    `pk_e1` (not low-order) and `ek_c` (modulus check); the `kid` must be held; Decaps hashes R's own
    `relay_dh_pk` and `relay_kem_ek` into the combiner; `mac1` is compared in constant time before R
    draws anything (reading OPEN-2). There is no HS1 replay cache (reading OPEN-3)."""
    try:
        v = enc.decode("Record/HS1", record)
    except Reject:
        _fail("hs1-decode")
    if v["kid"] != keys.kid:
        _fail("kid-unknown")
    try:
        ss1 = hybridkem.decaps(hybridkem.HYBRIDKEM_1024, keys.kem_seed, keys.dh_sk, v["pk_e1"], v["ct_kem"])
    except Reject:
        _fail("ss1")                              # an all-zero X25519 output; the decoder already excludes it
    h0_ = h0(v["ver"], v["kid"], keys.fp, v["e_c"], v["ek_c"], v["pk_e1"], v["ct_kem"])
    ck1, mac1 = _ck1_mac1(h0_, ss1)
    if not primitives.ct_equal(mac1, v["mac1"]):
        _fail("mac1")
    sk_er, m2 = rng.take(sizes.X25519_SK), rng.take(32)
    e_r, ct_c, ss2 = hybridkem.encaps(hybridkem.HYBRIDKEM_768, v["ek_c"], v["e_c"], m2, sk_er)
    h1_ = h1(h0_, mac1, e_r, ct_c)
    ck2, mac2 = _ck2_mac2(h1_, ck1, ss2)
    k_c2r, k_r2c, sess_id = link_keys(ck2)
    rec = enc.encode("Record/HS2", {"len": enc.HS2_BODY, "type": enc.REC_HS2, "ver": enc.PROTO_VER, "e_r": e_r,
                                    "ct_c": ct_c, "mac2": mac2})
    hs2 = Hs2(ss1, h0_, ck1, e_r, ct_c, ss2, h1_, ck2, mac2, rec[3:], rec, k_c2r, k_r2c, sess_id)
    return hs2, Link(k_send=k_r2c, k_recv=k_c2r, sess_id=sess_id)


class ClientKeys(NamedTuple):
    ss2: bytes
    h1: bytes
    ck2: bytes
    k_c2r: bytes
    k_r2c: bytes
    sess_id: bytes


def hs2_accept(state: ClientHs, record: bytes) -> tuple[ClientKeys, "Link"]:
    """C: process HS2 (§8.3). The HS2 decoder rejects a low-order `e_r`; Decaps with the client as the
    recipient (pk_dh = e_c, ek_kem = ek_c, ciphertext (e_r, ct_c)); `mac2` compared in constant time."""
    try:
        v = enc.decode("Record/HS2", record)
    except Reject:
        _fail("hs2-decode")
    try:
        ss2 = hybridkem.decaps(hybridkem.HYBRIDKEM_768, state.ek_c_seed, state.e_c_sk, v["e_r"], v["ct_c"])
    except Reject:
        _fail("ss2")                              # an all-zero X25519 output; the decoder already excludes it
    h1_ = h1(state.h0, state.mac1, v["e_r"], v["ct_c"])
    ck2, mac2 = _ck2_mac2(h1_, state.ck1, ss2)
    if not primitives.ct_equal(mac2, v["mac2"]):
        _fail("mac2")
    k_c2r, k_r2c, sess_id = link_keys(ck2)
    return ClientKeys(ss2, h1_, ck2, k_c2r, k_r2c, sess_id), Link(k_send=k_c2r, k_recv=k_r2c, sess_id=sess_id)


# ---------------------------------------------------------------------------------------------
# §8.4 frames


def frame_nonce(counter: int) -> bytes:
    return NONCE_PREFIX + counter.to_bytes(8, "big")


def frame_ad(sess_id: bytes) -> bytes:
    return labels.LINK_FRAME + sess_id


def seal_plaintext(key: bytes, counter: int, sess_id: bytes, plaintext: bytes) -> bytes:
    """One frame from a 4336-byte plaintext, as it stands (vectors use this for malformed plaintexts)."""
    if len(plaintext) != sizes.FRAME_PLAINTEXT:
        raise ValueError("a frame plaintext is 4336 bytes")
    return primitives.xchacha20poly1305_seal(key, frame_nonce(counter), frame_ad(sess_id), plaintext)


def seal_frame(key: bytes, counter: int, sess_id: bytes, payload: bytes) -> bytes:
    """Frame (4352 B) = XChaCha20-Poly1305.Seal(key, 0^16 ‖ u64be(counter), "SecMP-LINK/1 frame" ‖ sess_id,
    pad(payload, 4336))."""
    return seal_plaintext(key, counter, sess_id, enc.iso_pad(payload, sizes.FRAME_PLAINTEXT))


def unpad(plaintext: bytes) -> bytes:
    """ISO/IEC 7816-4 (§4.1): the payload before the 0x80 marker that follows it, zeros after it."""
    end = len(plaintext.rstrip(b"\x00"))
    if end == 0 or plaintext[end - 1] != 0x80:
        _fail("pt-decode")
    return plaintext[:end - 1]


def open_frame(key: bytes, counter: int, sess_id: bytes, frame: bytes) -> bytes:
    """The payload of one received unit, or Reject. A unit that is not exactly 4352 B is rejected before
    the AEAD (the stream has no length prefix, D.1); then the AEAD under the expected counter; then the
    padding."""
    if len(frame) != sizes.FRAME:
        _fail("frame-len")
    try:
        plaintext = primitives.xchacha20poly1305_open(key, frame_nonce(counter), frame_ad(sess_id), frame)
    except Reject:
        _fail("frame-open")
    return unpad(plaintext)


def _checked_add(counter: int) -> int:
    if counter + 1 >= COUNTER_LIMIT:
        raise CounterOverflow()
    return counter + 1


@dataclasses.dataclass
class Link:
    """One side of a link: its sending and receiving keys (client: k_c2r / k_r2c; relay: k_r2c /
    k_c2r), `sess_id`, and the next counter in each direction (from 0, strict +1, §8.4)."""
    k_send: bytes
    k_recv: bytes
    sess_id: bytes
    send_ctr: int = 0
    recv_ctr: int = 0

    def seal(self, payload: bytes) -> bytes:
        frame = seal_frame(self.k_send, self.send_ctr, self.sess_id, payload)
        self.send_ctr = _checked_add(self.send_ctr)
        return frame

    def open(self, frame: bytes) -> bytes:
        """The payload of the next frame; the counter advances only when the frame opens."""
        payload = open_frame(self.k_recv, self.recv_ctr, self.sess_id, frame)
        self.recv_ctr = _checked_add(self.recv_ctr)
        return payload
