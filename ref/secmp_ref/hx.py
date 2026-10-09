# SPDX-License-Identifier: AGPL-3.0-or-later
"""SecMP-HX, the hybrid initial key agreement (spec §6): key material, the signed PrekeyBundle, the
initiator's start and handshake envelope, and the responder's processing.

    DH1 = X25519(IK_dh_I, SPK_dh_R)    DH2 = X25519(EK_I, IK_dh_R)
    DH3 = X25519(EK_I, SPK_dh_R)       DH4 = X25519(EK_I, OPK_dh_R)          every DHi non-zero
    (ct_spk, ss_spk) = ML-KEM-1024.Encaps(SPK_kem_R)    (ct_opk, ss_opk) = ML-KEM-1024.Encaps(OPK_kem_R)
    transcript = SHA-256( "SecMP-HX/1 transcript" ‖ encode(IKSPublic_R) ‖ spk_id ‖ SPK_dh_R ‖ SHA-256(SPK_kem_R)
                 ‖ SHA-256(RPK_kem_R) ‖ opk_id ‖ OPK_dh_R ‖ SHA-256(OPK_kem_R) ‖ encode(IKSPublic_I) ‖ EK_I
                 ‖ SHA-256(ct_spk) ‖ SHA-256(ct_opk) ‖ ld_id )
    SK    = HKDF-SHA-256(salt = 0^32, 0xFF^32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4 ‖ ss_spk ‖ ss_opk, "SecMP-HX/1 sk" ‖ transcript, 32)
    K_id  = HKDF-SHA-256(salt = ld_id, link_key ‖ DH3 ‖ ss_spk ‖ DH4 ‖ ss_opk, "SecMP-HX/1 idkey", 32)
    K_inv = HKDF-SHA-256(salt = ld_id, link_key, "SecMP-HX/1 initkey", 32)

    Inner    = IKSPublic_I ‖ first_msg
    inner_ct = N2 ‖ CAEAD.Seal(K_id, N2, "SecMP-HX/1 inner" ‖ ld_id, Inner)                         6185 B
    Outer    = ver ‖ EK_I ‖ spk_id ‖ opk_id ‖ ct_spk ‖ ct_opk ‖ inner_ct                            9362 B
    cell_i   = N_i ‖ CAEAD.Seal(K_inv, N_i, "SecMP-HX/1 initcell" ‖ ld_id,
                                init_id ‖ i ‖ 0x03 ‖ pad(Outer, 12018)[i·4006 .. (i+1)·4006])       4096 B

Randomness comes from the caller (`rng.take(n)`), in this order:

    sign_bundle   rnd 32 (the ML-DSA hedge of the bundle signature, §3.5)
    start         EK_I secret 32, Encaps m for SPK_kem 32, Encaps m for OPK_kem 32; then the TR
                  initiator (§7.2): dh_s secret 32, kem_s seed 64, m 32
    envelope      first_msg's hdr_nonce 24 (§7.3), N2 24, init_id 16, N_0 24, N_1 24, N_2 24
    respond       decrypt(first_msg) steps (§7.4 DHRatchet): dh_s secret 32, kem_s seed 64, m 32

Every rejection of untrusted input is the uniform Reject. The responder is transactional: nothing
changes unless the whole of §6.6 steps 1–3 succeeds, and success deletes the OPK (step 4).
"""

import dataclasses
from typing import NamedTuple

from . import caead, hkdf_labels, hybridsign, identity, labels, primitives, sizes, tr
from . import encodings as enc
from .errors import Reject

KEM = 1024                                         # §3 table: ML-KEM-1024 for prekeys
ENVELOPE_CELLS = enc.HS_TOTAL
assert ENVELOPE_CELLS == sizes.HS_CELLS == 3

# ---------------------------------------------------------------------------------------------
# Rejection. For the generator's self-checks only, the check that raised the most recent Reject is
# recorded in `last_rule` (as in tr.py and encodings.py); Reject itself carries no detail.

last_rule = None


def _fail(rule):
    global last_rule
    last_rule = rule
    raise Reject()


# ---------------------------------------------------------------------------------------------
# Key material (§6.1)


class Kem1024Key(NamedTuple):
    """An ML-KEM-1024 key pair from its 64-byte seed d ‖ z (§3 table; KeyGen_internal(d, z))."""
    seed: bytes
    ek: bytes
    dk: bytes

    @classmethod
    def from_seed(cls, seed: bytes) -> "Kem1024Key":
        ek, dk = primitives.ml_kem_keygen(KEM, seed)
        return cls(seed, ek, dk)


class Identity(NamedTuple):
    """IK_sig = Ed25519 ‖ ML-DSA-65 (KeyGen_internal(ξ)) and IK_dh = X25519 (§6.1)."""
    mldsa_xi: bytes
    ed_seed: bytes
    pk_ed: bytes
    pk_mldsa: bytes
    sk_mldsa: bytes
    dh: tr.DhKey

    @classmethod
    def from_secrets(cls, mldsa_xi: bytes, ed_seed: bytes, dh_sk: bytes) -> "Identity":
        pk_ed, pk_mldsa, sk_mldsa = hybridsign.keygen(ed_seed, mldsa_xi)
        return cls(mldsa_xi, ed_seed, pk_ed, pk_mldsa, sk_mldsa, tr.DhKey.from_secret(dh_sk))

    def iks_value(self) -> dict:
        return {"ver": enc.PROTO_VER, "ik_ed25519": self.pk_ed, "ik_mldsa65": self.pk_mldsa, "ik_dh": self.dh.pk}

    @property
    def iks(self) -> bytes:
        """The encoded IKSPublic (§6.2, 2017 B)."""
        return enc.encode("IKSPublic", self.iks_value())

    @property
    def fp(self) -> bytes:
        return identity.fingerprint(self.iks)


class Opk(NamedTuple):
    dh: tr.DhKey
    kem: Kem1024Key


class Spk(NamedTuple):
    """One SPK generation: SPK_dh, SPK_kem and the RPK_kem bundled with it (§6.1)."""
    spk_id: int
    dh: tr.DhKey
    kem: Kem1024Key
    rpk: tr.KemKey
    expiry: int


@dataclasses.dataclass
class Prekeys:
    """The responder's current signed prekeys and its unused one-time prekeys (§6.1). `rpk_kem` is
    ML-KEM-768. `retained` holds the older SPK generations that an unexpired invitation still
    references (§6.1 rev 2.5: "an SPK referenced by an unexpired invitation is retained until that
    invitation expires"), by spk_id."""
    spk_id: int
    spk_dh: tr.DhKey
    spk_kem: Kem1024Key
    rpk_kem: tr.KemKey
    spk_expiry: int
    opks: dict                                    # opk_id → Opk, the unused one-time prekeys
    retained: dict = dataclasses.field(default_factory=dict)    # spk_id → Spk

    def generation(self, spk_id: int) -> Spk | None:
        if spk_id == self.spk_id:
            return Spk(self.spk_id, self.spk_dh, self.spk_kem, self.rpk_kem, self.spk_expiry)
        return self.retained.get(spk_id)

    def bundle_value(self, opk_id: int) -> dict:
        """The PrekeyBundle fields before `sig` (§6.3, D.3); `opk_present` is 0x01 (v1)."""
        opk = self.opks[opk_id]
        return {"ver": enc.PROTO_VER, "spk_id": self.spk_id, "spk_dh": self.spk_dh.pk, "spk_kem": self.spk_kem.ek,
                "rpk_kem": self.rpk_kem.ek, "spk_expiry": self.spk_expiry, "opk_present": 1, "opk_id": opk_id,
                "opk_dh": opk.dh.pk, "opk_kem": opk.kem.ek}


# ---------------------------------------------------------------------------------------------
# PrekeyBundle (§6.3): sig = HybridSign(IK_sig, "SecMP-HX/1 bundle", all preceding fields ‖ ik_dh)


def bundle_message(bundle: dict, ik_dh: bytes) -> bytes:
    """The signed message: the encoded fields before `sig`, as they stand, then the signer's ik_dh."""
    return enc.payload("PrekeyBundle", {k: v for k, v in bundle.items() if k != "sig"}) + ik_dh


def sign_bundle(signer: Identity, bundle: dict, rng) -> dict:
    """→ the bundle with `sig`; draws the ML-DSA hedge `rnd` (32)."""
    sig = hybridsign.sign(signer.ed_seed, signer.sk_mldsa, labels.HX_BUNDLE,
                          bundle_message(bundle, signer.dh.pk), rng.take(32))
    return {**{k: v for k, v in bundle.items() if k != "sig"}, "sig": sig}


def verify_bundle(iks: dict, bundle: dict) -> None:
    """HybridVerify of bundle.sig under the IKS's IK_sig (§5.5 step 4); raises Reject."""
    hybridsign.verify(iks["ik_ed25519"], iks["ik_mldsa65"], labels.HX_BUNDLE,
                      bundle_message(bundle, iks["ik_dh"]), bundle["sig"])


# ---------------------------------------------------------------------------------------------
# Key derivation (§6.4, §6.5)


def _u32(n: int) -> bytes:
    return n.to_bytes(4, "big")


def transcript(*, iks_r: bytes, spk_id: int, spk_dh: bytes, spk_kem: bytes, rpk_kem: bytes, opk_id: int,
               opk_dh: bytes, opk_kem: bytes, iks_i: bytes, ek_i: bytes, ct_spk: bytes, ct_opk: bytes,
               ld_id: bytes) -> bytes:
    """§6.4. The ids are u32 big-endian, as in the bundle (§4.1); the IKSPublics are encoded (2017 B)."""
    h = primitives.sha256
    return h(labels.HX_TRANSCRIPT + iks_r + _u32(spk_id) + spk_dh + h(spk_kem) + h(rpk_kem)
             + _u32(opk_id) + opk_dh + h(opk_kem) + iks_i + ek_i + h(ct_spk) + h(ct_opk) + ld_id)


def derive_sk(dh1, dh2, dh3, dh4, ss_spk, ss_opk, transcript_: bytes) -> bytes:
    ikm = b"\xff" * 32 + dh1 + dh2 + dh3 + dh4 + ss_spk + ss_opk
    return hkdf_labels.labeled_hkdf(bytes(32), ikm, labels.HX_SK, transcript_, 32)


def derive_k_id(ld_id, link_key, dh3, ss_spk, dh4, ss_opk) -> bytes:
    return hkdf_labels.labeled_hkdf(ld_id, link_key + dh3 + ss_spk + dh4 + ss_opk, labels.HX_IDKEY, b"", 32)


def derive_k_inv(ld_id: bytes, link_key: bytes) -> bytes:
    return hkdf_labels.labeled_hkdf(ld_id, link_key, labels.HX_INITKEY, b"", 32)


# ---------------------------------------------------------------------------------------------
# The envelope's layers (§6.5, D.4)


def seal_inner(k_id: bytes, ld_id: bytes, inner: bytes, n2: bytes) -> bytes:
    """inner_ct = N2 ‖ CAEAD.Seal(K_id, N2, AD = "SecMP-HX/1 inner" ‖ ld_id, Inner)."""
    return n2 + caead.seal(k_id, n2, labels.HX_INNER + ld_id, inner)


def open_inner(k_id: bytes, ld_id: bytes, inner_ct: bytes) -> bytes:
    n2 = inner_ct[: sizes.XCHACHA_NONCE]
    return caead.open(k_id, n2, labels.HX_INNER + ld_id, inner_ct[sizes.XCHACHA_NONCE:])


def seal_cell(k_inv: bytes, ld_id: bytes, plaintext: bytes, n: bytes) -> bytes:
    """cell = N ‖ CAEAD.Seal(K_inv, N, AD = "SecMP-HX/1 initcell" ‖ ld_id, init_id ‖ i ‖ total ‖ chunk)."""
    return n + caead.seal(k_inv, n, labels.HX_INITCELL + ld_id, plaintext)


def cell_plaintext(init_id: bytes, i: int, chunk: bytes, total: int = enc.HS_TOTAL) -> bytes:
    return enc.raw("HandshakeCellPlaintext", {"init_id": init_id, "i": i, "total": total, "chunk": chunk})


def chunks(outer: bytes) -> list[bytes]:
    """Padded = pad(Outer, 3 × 4006) (ISO/IEC 7816-4, §4.1), cut into the three chunks."""
    padded = enc.iso_pad(outer, sizes.HS_OUTER_PADDED)
    return [padded[i * enc.HS_CHUNK: (i + 1) * enc.HS_CHUNK] for i in range(ENVELOPE_CELLS)]


def seal_cells(k_inv: bytes, ld_id: bytes, outer: bytes, init_id: bytes, nonces) -> tuple:
    return tuple(seal_cell(k_inv, ld_id, cell_plaintext(init_id, i, chunk), n)
                 for i, (chunk, n) in enumerate(zip(chunks(outer), nonces, strict=True)))


def open_cell(k_inv: bytes, ld_id: bytes, cell: bytes) -> dict | None:
    """The HandshakeCellPlaintext of a cell, or None when it does not open or does not parse
    (§6.5: such cells are ignored)."""
    if len(cell) != sizes.CELL:
        return None
    n = cell[: sizes.XCHACHA_NONCE]
    try:
        return enc.decode("HandshakeCellPlaintext",
                          caead.open(k_inv, n, labels.HX_INITCELL + ld_id, cell[sizes.XCHACHA_NONCE:]))
    except Reject:
        return None


# ---------------------------------------------------------------------------------------------
# Initiator (§6.4, §6.5; §5.5 step 6)


class Start(NamedTuple):
    ld_id: bytes
    iks_i: bytes
    spk_id: int
    opk_id: int
    ek: tr.DhKey
    dh1: bytes
    dh2: bytes
    dh3: bytes
    dh4: bytes
    ct_spk: bytes
    ss_spk: bytes
    ct_opk: bytes
    ss_opk: bytes
    transcript: bytes
    sk: bytes
    k_id: bytes
    k_inv: bytes
    state: tr.RatchetState                       # the TR initiator state (§7.2), used by envelope()


def start(me: Identity, invitation: dict, linkdata: dict, rng) -> Start:
    """The initiator's key agreement and TR initialisation. `invitation` and `linkdata` are the decoded
    values that passed §5.5 steps 1, 3 and 4 (inv.invitee_accept)."""
    ld_id, link_key = invitation["ld_id"], invitation["link_key"]
    iks_r, b = linkdata["inviter_iks"], linkdata["bundle"]
    ek = tr.DhKey.from_secret(rng.take(32))
    ct_spk, ss_spk = primitives.ml_kem_encaps(KEM, b["spk_kem"], rng.take(32))
    ct_opk, ss_opk = primitives.ml_kem_encaps(KEM, b["opk_kem"], rng.take(32))
    dh1 = primitives.x25519(me.dh.sk, b["spk_dh"])       # each rejects an all-zero output (§3, §6.4)
    dh2 = primitives.x25519(ek.sk, iks_r["ik_dh"])
    dh3 = primitives.x25519(ek.sk, b["spk_dh"])
    dh4 = primitives.x25519(ek.sk, b["opk_dh"])
    th = transcript(iks_r=enc.raw("IKSPublic", iks_r), spk_id=b["spk_id"], spk_dh=b["spk_dh"], spk_kem=b["spk_kem"],
                    rpk_kem=b["rpk_kem"], opk_id=b["opk_id"], opk_dh=b["opk_dh"], opk_kem=b["opk_kem"],
                    iks_i=me.iks, ek_i=ek.pk, ct_spk=ct_spk, ct_opk=ct_opk, ld_id=ld_id)
    sk = derive_sk(dh1, dh2, dh3, dh4, ss_spk, ss_opk, th)
    state = tr.init_initiator(sk, th, b["spk_dh"], b["rpk_kem"], rng)       # §7.2: sb = transcript
    return Start(ld_id, me.iks, b["spk_id"], b["opk_id"], ek, dh1, dh2, dh3, dh4, ct_spk, ss_spk, ct_opk, ss_opk,
                 th, sk, derive_k_id(ld_id, link_key, dh3, ss_spk, dh4, ss_opk), derive_k_inv(ld_id, link_key), state)


class Envelope(NamedTuple):
    first_msg: bytes
    inner: bytes
    inner_ct: bytes
    outer_value: dict
    outer: bytes                                  # unpadded (9362 B)
    init_id: bytes
    cells: tuple


def outer_value(s: Start, inner_ct: bytes) -> dict:
    return {"ver": enc.PROTO_VER, "ek_I": s.ek.pk, "spk_id": s.spk_id, "opk_id": s.opk_id, "ct_spk": s.ct_spk,
            "ct_opk": s.ct_opk, "inner_ct": inner_ct}


def envelope(s: Start, content: bytes, rng) -> Envelope:
    """first_msg = Encrypt(state, content) (§7.3; content: the unpadded Handshake Content), then Inner,
    inner_ct, Outer and the three cells, sealed once (§6.5: re-sent byte-identical, never re-sealed)."""
    first_msg = tr.encrypt(s.state, content, rng)
    inner = s.iks_i + first_msg
    inner_ct = seal_inner(s.k_id, s.ld_id, inner, rng.take(sizes.XCHACHA_NONCE))
    ov = outer_value(s, inner_ct)
    enc.encode("Outer", ov)                       # a valid Outer (the M2 decoder agrees), else ValueError
    outer = enc.payload("Outer", ov)
    init_id = rng.take(16)
    cells = seal_cells(s.k_inv, s.ld_id, outer, init_id, [rng.take(sizes.XCHACHA_NONCE) for _ in range(ENVELOPE_CELLS)])
    return Envelope(first_msg, inner, inner_ct, ov, outer, init_id, cells)


# ---------------------------------------------------------------------------------------------
# Responder (§6.6 steps 1–4)


@dataclasses.dataclass(frozen=True)
class InvitationRecord:
    """What the inviter persists per issued invitation (§5.2), as far as HX uses it."""
    ld_id: bytes
    link_key: bytes
    spk_id: int
    opk_id: int
    expires: int


@dataclasses.dataclass
class Responder:
    me: Identity
    prekeys: Prekeys
    invitation: InvitationRecord


class Accepted(NamedTuple):
    init_id: bytes
    transcript: bytes
    sk: bytes
    k_id: bytes
    peer_iks: bytes                               # the encoded IKSPublic_I
    content: dict                                 # the decoded Handshake Content (§7.6, D.5)
    state: tr.RatchetState                        # the TR responder state after decrypt(first_msg)


MAX_PARTIAL_GROUPS = 8                             # §6.5 rev 2.5: "at most 8 partial groups are stored"


def _complete_groups(k_inv: bytes, ld_id: bytes, fetched):
    """Trial-open every fetched cell and group the chunks by init_id (§6.5). Yields (init_id, padded
    Outer) for each group as its chunks 0, 1 and 2 have all arrived, in fetch order. A duplicate
    (init_id, i) is ignored, whether its bytes are identical or differ (first-seen wins); a group that
    has been yielded is closed: later chunks of its init_id are ignored, so it cannot re-form; at most
    MAX_PARTIAL_GROUPS partial groups are stored, the oldest evicted."""
    partial, closed = {}, set()
    for cell in fetched:
        pt = open_cell(k_inv, ld_id, cell)
        if pt is None or pt["init_id"] in closed:
            continue
        group = partial.get(pt["init_id"])
        if group is None:
            if len(partial) >= MAX_PARTIAL_GROUPS:
                del partial[next(iter(partial))]
            group = partial[pt["init_id"]] = {}
        group.setdefault(pt["i"], pt["chunk"])
        if len(group) == ENVELOPE_CELLS:
            del partial[pt["init_id"]]
            closed.add(pt["init_id"])
            yield pt["init_id"], b"".join(group[i] for i in range(ENVELOPE_CELLS))


def _x25519(sk, pk):
    try:
        return primitives.x25519(sk, pk)
    except Reject:
        _fail("dh-zero")


def respond(r: Responder, fetched, rng) -> Accepted:
    """§6.6 steps 1–4 on the cells fetched from the invitation queue. Complete groups are processed in
    the order they complete; after a rejected complete group that group is discarded, the OPK is kept
    and later groups with other init_ids are processed (§6.5 rev 2.5). If no group is accepted the
    result is the uniform Reject (the reference check of the last rejected group, or
    `no-complete-envelope`). Success deletes the OPK; a rejection changes nothing."""
    inv = r.invitation
    k_inv = derive_k_inv(inv.ld_id, inv.link_key)
    failure = None
    for init_id, padded in _complete_groups(k_inv, inv.ld_id, fetched):
        try:
            return _respond_group(r, init_id, padded, rng)
        except Reject:
            failure = last_rule
    _fail(failure or "no-complete-envelope")


def _known_route(route: dict) -> bool:
    return route["kind"] == enc.ROUTE_RELAYQUEUE      # §9.8: v1 defines kind 0x01 (SQ-29)


def _respond_group(r: Responder, init_id: bytes, padded: bytes, rng) -> Accepted:
    inv, pk = r.invitation, r.prekeys
    # 1. Outer; spk_id/opk_id must be this invitation's (the SPK may be a retained generation), the
    #    OPK unused.
    try:
        outer = enc.decode("Outer", padded)
    except Reject:
        _fail("outer-decode")
    spk = pk.generation(outer["spk_id"])
    if outer["spk_id"] != inv.spk_id or spk is None or outer["opk_id"] != inv.opk_id:
        _fail("prekey-ids")
    opk = pk.opks.get(outer["opk_id"])
    if opk is None:
        _fail("opk-used")
    # 2. K_id; inner_ct → IKSPublic_I (decodable, ik_dh not low-order, not IKSPublic_R) and first_msg.
    ek_i = outer["ek_I"]
    dh3, dh4 = _x25519(spk.dh.sk, ek_i), _x25519(opk.dh.sk, ek_i)
    ss_spk = primitives.ml_kem_decaps(KEM, spk.kem.dk, outer["ct_spk"])       # implicit rejection (§3.2)
    ss_opk = primitives.ml_kem_decaps(KEM, opk.kem.dk, outer["ct_opk"])
    k_id = derive_k_id(inv.ld_id, inv.link_key, dh3, ss_spk, dh4, ss_opk)
    try:
        inner_bytes = open_inner(k_id, inv.ld_id, outer["inner_ct"])
    except Reject:
        _fail("inner-open")
    try:
        inner = enc.decode("Inner", inner_bytes)
    except Reject:
        _fail("inner-decode")
    iks_i = inner_bytes[: sizes.IKS_PUBLIC]
    if iks_i == r.me.iks:
        _fail("reflection")                       # §6.6 step 2 (rev 2.5)
    # 3. DH1, DH2, transcript, SK; TR as responder (§7.2); decrypt first_msg; a Handshake Content.
    dh1, dh2 = _x25519(spk.dh.sk, inner["iks"]["ik_dh"]), _x25519(r.me.dh.sk, ek_i)
    th = transcript(iks_r=r.me.iks, spk_id=spk.spk_id, spk_dh=spk.dh.pk, spk_kem=spk.kem.ek,
                    rpk_kem=spk.rpk.ek, opk_id=outer["opk_id"], opk_dh=opk.dh.pk, opk_kem=opk.kem.ek,
                    iks_i=iks_i, ek_i=ek_i, ct_spk=outer["ct_spk"], ct_opk=outer["ct_opk"], ld_id=inv.ld_id)
    sk = derive_sk(dh1, dh2, dh3, dh4, ss_spk, ss_opk, th)
    state = tr.init_responder(sk, th, spk.dh, spk.rpk)
    nhk = state.nhk_r                             # the header key of the first message (before the step)
    try:
        padded_content = tr.decrypt(state, inner["first_msg"], rng)
    except Reject:
        _fail("tr-decrypt")
    hdr_nonce, hdr_ct, _ = tr.split(inner["first_msg"])
    header = tr.open_header(th, nhk, hdr_nonce, hdr_ct)
    if header["n"] != 0 or header["pn"] != 0:
        _fail("first-msg-header")                 # §6.5: n = 0 and pn = 0 (rev 2.5)
    try:
        content = enc.decode("Content", padded_content)          # caps = 0 (§7.6, D.5)
    except Reject:
        _fail("content-decode")
    if content["type"] != enc.CT_HANDSHAKE:
        _fail("not-handshake")                    # §6.5: first_msg's Content is a Handshake
    if not any(_known_route(route) for route in content["body"]["routes"]):
        _fail("no-known-route")                   # §6.5: at least one route of a known kind (rev 2.5)
    # 4. Success: the OPK is used up.
    del pk.opks[outer["opk_id"]]
    return Accepted(init_id, th, sk, k_id, iks_i, content, state)
