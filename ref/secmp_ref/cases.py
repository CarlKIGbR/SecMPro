# SPDX-License-Identifier: AGPL-3.0-or-later
"""The M1 case tables of SCHEMA.md rev 2 §4, transcribed, and the builders that turn each row into
a Case.

Stream rule (SCHEMA §2 and the §4 preamble): case i draws its stream-derived inputs from its own
stream_i, in the order of the suite's input list. A negative row "derived from row r" takes the
lengths/label of row r, consumes its own stream the way row r does, computes the honest object and
then applies the manipulation. The one exception is written into the table itself: sas row 10
reuses row 1's fingerprints, swapped.

Every builder checks itself: positive outputs are round-tripped through the opposite operation,
and every row the table marks as a reject is actually rejected by this implementation (and every
positive row is accepted). A disagreement raises TableMismatch instead of writing a file.
"""

from . import caead, hkdf_labels, hybridkem, hybridsign, identity, labels, msgencrypt, primitives, sizes
from .errors import Reject
from .vectorfile import Case, CaseStream, append_zero, drop_last, flip, prefix


class TableMismatch(AssertionError):
    """A SCHEMA §4 row and this implementation disagree."""


def _rejects(fn) -> bool:
    try:
        fn()
    except Reject:
        return True
    return False


def _require_reject(suite, i, fn):
    if not _rejects(fn):
        raise TableMismatch(f"{suite} row {i}: SCHEMA expects reject, the implementation accepts")


# ---------------------------------------------------------------------------------------------
# §4.1 hkdf-labels. inputs (stream order) salt, ikm, extra_info; table-fixed mode, label, len.

EE, EX = hkdf_labels.EXTRACT_EXPAND, hkdf_labels.EXPAND
HKDF_LABELS = [
    # i  mode  label                salt  ikm  extra_info  len     note
    (1, EE, labels.INV_LINKDATA,    16,   32,    0,     32),   # §5.4 K_ld
    (2, EE, labels.HX_SK,           32,  224,   32,     32),   # §6.4 SK (extra = transcript)
    (3, EE, labels.HX_IDKEY,        16,  160,    0,     32),   # §6.4 K_id
    (4, EE, labels.HX_INITKEY,      16,   32,    0,     32),   # §6.5 K_inv
    (5, EE, labels.TR_INIT,         32,   32,    0,     96),   # §7.2
    (6, EE, labels.TR_RK,           32,   64,    0,     96),   # §7.2 KDF_RK
    (7, EE, labels.TR_MSGKEYS,      32,   32,    0,     76),   # §3.3
    (8, EX, labels.COMMIT,           0,   32,   24,     64),   # §3.4 (PRK = K, info = label ‖ N)
    (9, EX, labels.LINK_KEYS,        0,   32,    0,     80),   # §8.3 (PRK = ck2)
    (10, EE, labels.TR_MSGKEYS,      0,   32,    0,     76),   # edge: empty salt ≡ 0^32
    (11, EE, labels.HX_SK,          32,   32,  100,   8160),   # edge: maximum L
    (12, EE, labels.TR_RK,          32,    0,    0,      1),   # edge: empty IKM, L = 1
]


def hkdf_labels_cases() -> list[Case]:
    cases = []
    for i, mode, label, salt_len, ikm_len, extra_len, length in HKDF_LABELS:
        s = CaseStream("hkdf-labels", i)
        salt, ikm, extra_info = s.take(salt_len), s.take(ikm_len), s.take(extra_len)
        okm = hkdf_labels.derive(mode, salt, ikm, label, extra_info, length)
        inputs = {"mode": mode, "salt": salt, "ikm": ikm, "extra_info": extra_info,
                  "label": label.decode("ascii"), "len": length}
        cases.append(Case(i, "derive", inputs, {"okm": okm}))
    return cases


# ---------------------------------------------------------------------------------------------
# §4.2 caead. Seal inputs (stream order) k (32), n (24), ad, p; outputs com (32), c (|p| + 16).

CAEAD_SEAL = {
    # i: (ad, p)
    1: (0, 0),
    2: (16, 1),
    3: (21, 16),
    4: (32, 255),
    5: (64, 256),
    6: (128, 1024),
    7: (256, 4006),
    8: (1024, 12288),
}
CAEAD_OPEN = [
    # i  from row  field  manipulation
    (9, 3, "c", lambda v: flip(v, 0)),
    (10, 3, "c", lambda v: flip(v, -1)),       # tag
    (11, 3, "com", lambda v: flip(v, 0)),
    (12, 3, "c", drop_last),
    (13, 3, "c", lambda v: prefix(v, 15)),     # shorter than a tag
    (14, 3, "ad", lambda v: flip(v, 0)),
    (15, 3, "n", lambda v: flip(v, 0)),
    (16, 3, "k", lambda v: flip(v, 0)),
    (17, 1, "c", lambda v: flip(v, 0)),        # empty plaintext: only the tag exists
]


def _caead_honest(i, row):
    ad_len, p_len = CAEAD_SEAL[row]
    s = CaseStream("caead", i)
    k, n, ad, p = s.take(32), s.take(sizes.XCHACHA_NONCE), s.take(ad_len), s.take(p_len)
    com_c = caead.seal(k, n, ad, p)
    return k, n, ad, p, com_c[: sizes.CAEAD_COM], com_c[sizes.CAEAD_COM:]


def caead_cases() -> list[Case]:
    cases = []
    for i in CAEAD_SEAL:
        k, n, ad, p, com, c = _caead_honest(i, i)
        if caead.open(k, n, ad, com + c) != p:
            raise TableMismatch(f"caead row {i}: open(seal(p)) ≠ p")
        cases.append(Case(i, "seal", {"k": k, "n": n, "ad": ad, "p": p}, {"com": com, "c": c}))
    for i, row, field, manipulate in CAEAD_OPEN:
        k, n, ad, _, com, c = _caead_honest(i, row)
        inputs = {"k": k, "n": n, "ad": ad, "com": com, "c": c}
        inputs[field] = manipulate(inputs[field])
        _require_reject("caead", i, lambda: caead.open(inputs["k"], inputs["n"], inputs["ad"],
                                                       inputs["com"] + inputs["c"]))
        cases.append(Case(i, "open", inputs, None))
    return cases


# ---------------------------------------------------------------------------------------------
# §4.3 msgencrypt. Seal inputs (stream order) mk (32), ad, p (BODY_LEN); outputs k_enc, k_mac,
# iv, c_tag.

MSGENC_SEAL = {
    # i: ad
    1: 0,
    2: 1,
    3: 32,
    4: 64,
    5: 128,
    6: 1024,
    7: 2401,       # the real body AD length: 15 + 32 + 24 + 2330
    8: 4096,
}
MSGENC_OPEN = [
    # i  from row  field  manipulation
    (9, 3, "c_tag", lambda v: flip(v, 0)),
    (10, 3, "c_tag", lambda v: flip(v, -1)),
    (11, 3, "c_tag", drop_last),
    (12, 3, "c_tag", append_zero),
    (13, 3, "ad", lambda v: flip(v, 0)),
    (14, 3, "mk", lambda v: flip(v, 0)),
    (15, 3, "c_tag", lambda v: b""),
]
# i = 16: from row 1, p of length 1709 on the seal side → op "seal", expect reject.
MSGENC_SHORT_P = (16, 1, sizes.BODY_LEN - 1)


def _msgenc_stream(i, row, p_len=sizes.BODY_LEN):
    s = CaseStream("msgencrypt", i)
    return s.take(msgencrypt.MK), s.take(MSGENC_SEAL[row]), s.take(p_len)


def msgencrypt_cases() -> list[Case]:
    cases = []
    for i in MSGENC_SEAL:
        mk, ad, p = _msgenc_stream(i, i)
        c_tag = msgencrypt.msg_encrypt(mk, ad, p)
        if msgencrypt.msg_decrypt(mk, ad, c_tag) != p:
            raise TableMismatch(f"msgencrypt row {i}: decrypt(encrypt(p)) ≠ p")
        k_enc, k_mac, iv = msgencrypt.message_keys(mk)
        cases.append(Case(i, "seal", {"mk": mk, "ad": ad, "p": p},
                          {"k_enc": k_enc, "k_mac": k_mac, "iv": iv, "c_tag": c_tag}))
    for i, row, field, manipulate in MSGENC_OPEN:
        mk, ad, p = _msgenc_stream(i, row)
        inputs = {"mk": mk, "ad": ad, "c_tag": msgencrypt.msg_encrypt(mk, ad, p)}
        inputs[field] = manipulate(inputs[field])
        _require_reject("msgencrypt", i,
                        lambda: msgencrypt.msg_decrypt(inputs["mk"], inputs["ad"], inputs["c_tag"]))
        cases.append(Case(i, "open", inputs, None))
    i, row, p_len = MSGENC_SHORT_P
    mk, ad, p = _msgenc_stream(i, row, p_len)
    _require_reject("msgencrypt", i, lambda: msgencrypt.msg_encrypt(mk, ad, p))
    cases.append(Case(i, "seal", {"mk": mk, "ad": ad, "p": p}, None))
    return cases


# ---------------------------------------------------------------------------------------------
# §4.4 hybridkem-768 / hybridkem-1024. Encaps inputs (stream order) dk_seed (64), sk_dh (32),
# m (32), sk_e (32); outputs ek_kem, pk_dh, ct_kem, pk_e, ss.

HYBRIDKEM_ENCAPS = range(1, 9)          # rows 1–8: eight round trips

X25519_U0 = bytes(32)
X25519_U1 = b"\x01" + bytes(31)
X25519_ORDER8 = bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")

HYBRIDKEM_DECAPS = [
    # i  from row  field     manipulation                    result
    (9, 1, "ct_kem", lambda v: v, "ss"),                  # none (honest)
    (10, 1, "ct_kem", lambda v: flip(v, 0), "ss"),        # implicit-rejection secret
    (11, 1, "ct_kem", lambda v: flip(v, -1), "ss"),       # implicit-rejection secret
    (12, 2, "pk_e", lambda v: flip(v, 0), "ss"),          # ss recomputed with the modified pk_e
    (13, 1, "ct_kem", drop_last, "reject"),
    (14, 1, "pk_e", lambda v: X25519_U0, "reject"),      # u = 0
    (15, 1, "pk_e", lambda v: X25519_U1, "reject"),      # u = 1
    (16, 1, "pk_e", lambda v: X25519_ORDER8, "reject"),  # order-8 point
]
HYBRIDKEM_ENCAPS_TO = [
    # i  from row  field     manipulation
    (17, 1, "ek_kem", lambda v: b"\xff\xff\xff" + v[3:]),   # packed coefficient ≥ q
    (18, 1, "ek_kem", drop_last),
    (19, 1, "pk_dh", lambda v: bytes(32)),
]


def _hybridkem_honest(suite, params, i):
    s = CaseStream(suite, i)
    dk_seed, sk_dh, m, sk_e = s.take(sizes.MLKEM_SEED), s.take(32), s.take(32), s.take(32)
    ek_kem, _, pk_dh = hybridkem.keygen(params, dk_seed, sk_dh)
    pk_e, ct_kem, ss = hybridkem.encaps(params, ek_kem, pk_dh, m, sk_e)
    return dict(dk_seed=dk_seed, sk_dh=sk_dh, m=m, sk_e=sk_e, ek_kem=ek_kem, pk_dh=pk_dh,
                pk_e=pk_e, ct_kem=ct_kem, ss=ss)


def _hybridkem_cases(suite, params) -> list[Case]:
    cases = []
    for i in HYBRIDKEM_ENCAPS:
        h = _hybridkem_honest(suite, params, i)
        if hybridkem.decaps(params, h["dk_seed"], h["sk_dh"], h["pk_e"], h["ct_kem"]) != h["ss"]:
            raise TableMismatch(f"{suite} row {i}: Decaps(Encaps) ≠ ss")
        cases.append(Case(i, "encaps", {k: h[k] for k in ("dk_seed", "sk_dh", "m", "sk_e")},
                          {k: h[k] for k in ("ek_kem", "pk_dh", "ct_kem", "pk_e", "ss")}))
    for i, _row, field, manipulate, result in HYBRIDKEM_DECAPS:
        h = _hybridkem_honest(suite, params, i)
        inputs = {k: h[k] for k in ("dk_seed", "sk_dh", "pk_e", "ct_kem")}
        inputs[field] = manipulate(inputs[field])
        try:
            ss = hybridkem.decaps(params, **inputs)
        except Reject:
            ss = None
        if (ss is None) != (result == "reject"):
            raise TableMismatch(f"{suite} row {i}: SCHEMA expects {result}, got {ss}")
        if ss is not None and inputs[field] != h[field] and ss == h["ss"]:
            raise TableMismatch(f"{suite} row {i}: manipulated input gave the honest ss")
        cases.append(Case(i, "decaps", inputs, None if ss is None else {"ss": ss}))
    for i, _row, field, manipulate in HYBRIDKEM_ENCAPS_TO:
        h = _hybridkem_honest(suite, params, i)
        inputs = {k: h[k] for k in ("ek_kem", "pk_dh", "m", "sk_e")}
        inputs[field] = manipulate(inputs[field])
        _require_reject(suite, i, lambda: hybridkem.encaps(params, **inputs))
        cases.append(Case(i, "encaps-to", inputs, None))
    return cases


def hybridkem_768_cases() -> list[Case]:
    return _hybridkem_cases("hybridkem-768", hybridkem.HYBRIDKEM_768)


def hybridkem_1024_cases() -> list[Case]:
    return _hybridkem_cases("hybridkem-1024", hybridkem.HYBRIDKEM_1024)


# ---------------------------------------------------------------------------------------------
# §4.5 hybridsign. Sign inputs (stream order) ed_seed (32), mldsa_seed (32), rnd (32), msg;
# table-fixed label; outputs pk_ed, pk_mldsa, sig, verify.

HYBRIDSIGN_SIGN = {
    # i: (label, msg)
    1: (labels.HX_BUNDLE, 0),
    2: (labels.TR_KEYCHANGE, 1),
    3: (labels.HX_BUNDLE, 32),
    4: (labels.TR_KEYCHANGE, 32),
    5: (labels.HX_BUNDLE, 100),
    6: (labels.TR_KEYCHANGE, 1024),
    7: (labels.HX_BUNDLE, 4434),       # PrekeyBundle fields before sig (4402) + ik_dh (32)
    8: (labels.TR_KEYCHANGE, 4096),
}


def s_plus_l(sig: bytes) -> bytes:
    """Row 14: the Ed25519 S (bytes 32–63 of sig, little-endian) replaced by S + L."""
    s = int.from_bytes(sig[32:64], "little")
    return sig[:32] + (s + primitives.ED25519_L).to_bytes(32, "little") + sig[64:]


ED25519_IDENTITY = b"\x01" + bytes(31)
ED25519_Y1_NONCANONICAL = bytes.fromhex("ee" + "ff" * 30 + "7f")      # y = p + 1

HYBRIDSIGN_VERIFY = [
    # i  from row  field   manipulation
    (9, 3, "sig", lambda v: flip(v, 0)),                    # Ed25519 R
    (10, 3, "sig", lambda v: flip(v, 64)),                  # ML-DSA part
    (11, 3, "label", lambda v: labels.TR_KEYCHANGE),        # the other HybridSign label
    (12, 3, "label", lambda v: labels.TR_RK),               # not a HybridSign label → refused
    (13, 3, "sig", drop_last),
    (14, 3, "sig", s_plus_l),                               # S + L
    (15, 3, "pk_ed", lambda v: ED25519_IDENTITY),           # the identity, small order
    (16, 3, "pk_ed", lambda v: ED25519_Y1_NONCANONICAL),    # non-canonical encoding of y = 1
    (17, 3, "msg", lambda v: flip(v, 0)),                   # msg length 32
]


def _hybridsign_honest(i, row):
    label, msg_len = HYBRIDSIGN_SIGN[row]
    s = CaseStream("hybridsign", i)
    ed_seed, mldsa_seed, rnd, msg = s.take(32), s.take(sizes.MLDSA_SEED), s.take(32), s.take(msg_len)
    pk_ed, pk_mldsa, sk_mldsa = hybridsign.keygen(ed_seed, mldsa_seed)
    sig = hybridsign.sign(ed_seed, sk_mldsa, label, msg, rnd)
    return dict(ed_seed=ed_seed, mldsa_seed=mldsa_seed, rnd=rnd, msg=msg, label=label,
                pk_ed=pk_ed, pk_mldsa=pk_mldsa, sig=sig)


def hybridsign_cases() -> list[Case]:
    cases = []
    for i in HYBRIDSIGN_SIGN:
        h = _hybridsign_honest(i, i)
        verify = not _rejects(lambda: hybridsign.verify(h["pk_ed"], h["pk_mldsa"], h["label"], h["msg"], h["sig"]))
        if not verify:
            raise TableMismatch(f"hybridsign row {i}: own signature does not verify")
        cases.append(Case(i, "sign",
                          {"ed_seed": h["ed_seed"], "mldsa_seed": h["mldsa_seed"], "rnd": h["rnd"],
                           "msg": h["msg"], "label": h["label"].decode("ascii")},
                          {"pk_ed": h["pk_ed"], "pk_mldsa": h["pk_mldsa"], "sig": h["sig"], "verify": verify}))
    for i, row, field, manipulate in HYBRIDSIGN_VERIFY:
        h = _hybridsign_honest(i, row)
        inputs = {k: h[k] for k in ("pk_ed", "pk_mldsa", "label", "msg", "sig")}
        inputs[field] = manipulate(inputs[field])
        _require_reject("hybridsign", i, lambda: hybridsign.verify(**inputs))
        inputs["label"] = inputs["label"].decode("ascii")
        cases.append(Case(i, "verify", inputs, None))
    return cases


# ---------------------------------------------------------------------------------------------
# §4.6 fingerprint. inputs (stream order) ed_seed, mldsa_seed, dh_seed (32 each); outputs iks, fp.

FINGERPRINT_ROWS = range(1, 9)


def fingerprint_cases() -> list[Case]:
    cases = []
    for i in FINGERPRINT_ROWS:
        s = CaseStream("fingerprint", i)
        ed_seed, mldsa_seed, dh_seed = s.take(32), s.take(sizes.MLDSA_SEED), s.take(32)
        iks = identity.iks_public_from_seeds(ed_seed, mldsa_seed, dh_seed)
        cases.append(Case(i, "fp", {"ed_seed": ed_seed, "mldsa_seed": mldsa_seed, "dh_seed": dh_seed},
                          {"iks": iks, "fp": identity.fingerprint(iks)}))
    return cases


# ---------------------------------------------------------------------------------------------
# §4.7 sas. inputs (stream order) fp_a, fp_b (32 each); outputs half_a, half_b, safety_number.
# Rows 1–8 from the stream; row 9: fp_b := fp_a; row 10: row 1's fp_a, fp_b swapped.

SAS_STREAM_ROWS = range(1, 9)
SAS_EQUAL = 9
SAS_SWAPPED = (10, 1)


def _sas_case(i, fp_a, fp_b) -> Case:
    half_a, half_b = identity.sas_half(fp_a), identity.sas_half(fp_b)
    return Case(i, "sas", {"fp_a": fp_a, "fp_b": fp_b},
                {"half_a": half_a, "half_b": half_b, "safety_number": identity.safety_number(fp_a, fp_b)})


def sas_cases() -> list[Case]:
    cases = []
    for i in SAS_STREAM_ROWS:
        s = CaseStream("sas", i)
        cases.append(_sas_case(i, s.take(sizes.FINGERPRINT), s.take(sizes.FINGERPRINT)))
    fp = CaseStream("sas", SAS_EQUAL).take(sizes.FINGERPRINT)
    cases.append(_sas_case(SAS_EQUAL, fp, fp))
    i, row = SAS_SWAPPED
    ref = cases[row - 1]
    swapped = _sas_case(i, ref.inputs["fp_b"], ref.inputs["fp_a"])
    if swapped.outputs["safety_number"] != ref.outputs["safety_number"]:
        raise TableMismatch(f"sas row {i}: swapping the fingerprints changed the safety number")
    cases.append(swapped)
    return cases


# ---------------------------------------------------------------------------------------------

SUITES = {
    "hkdf-labels": hkdf_labels_cases,
    "caead": caead_cases,
    "msgencrypt": msgencrypt_cases,
    "hybridkem-768": hybridkem_768_cases,
    "hybridkem-1024": hybridkem_1024_cases,
    "hybridsign": hybridsign_cases,
    "fingerprint": fingerprint_cases,
    "sas": sas_cases,
}
