# SPDX-License-Identifier: AGPL-3.0-or-later
"""Suite hybridsign (spec §3.5, SCHEMA §4.5) and the strict Ed25519 rule."""

import hashlib
import pathlib
import sys

import pytest
from dilithium_py.ml_dsa import ML_DSA_65

import _ed25519_model as model
from _kat import h, load
from secmp_ref import cases, hybridsign, labels, primitives, sizes
from secmp_ref.errors import Reject

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import probe_ed25519_strict as probe  # noqa: E402

ED_SEED = bytes(range(32))
MLDSA_SEED = bytes(range(32, 64))
RND = bytes(range(64, 96))
MSG = b"prekey bundle bytes"


@pytest.fixture(scope="module")
def keys():
    return hybridsign.keygen(ED_SEED, MLDSA_SEED)


@pytest.fixture(scope="module")
def signed(keys):
    pk_ed, pk_mldsa, sk_mldsa = keys
    return {label: hybridsign.sign(ED_SEED, sk_mldsa, label, MSG, RND) for label in labels.HYBRIDSIGN_LABELS}


# ---------------------------------------------------------------------------------------------
# The construction


def test_sign_is_ed25519_then_ml_dsa_over_the_labelled_digest(keys, signed):
    pk_ed, pk_mldsa, sk_mldsa = keys
    label = labels.HX_BUNDLE
    m = hashlib.sha256(b"SecMP-HybridSign/1" + label + MSG).digest()
    sig = signed[label]
    assert len(sig) == sizes.HYBRID_SIG == 64 + 3309
    assert sig[:64] == primitives.ed25519_sign(ED_SEED, m)
    # pure ML-DSA (SQ-08): M' = 0x00 ‖ len(ctx) ‖ ctx ‖ m, ctx = the label
    assert sig[64:] == primitives.ml_dsa_65_sign(sk_mldsa, m, label, RND)
    assert sig[64:] == ML_DSA_65._sign_internal(sk_mldsa, bytes([0, len(label)]) + label + m, RND)


def test_verify_accepts_both_labels(keys, signed):
    pk_ed, pk_mldsa, _ = keys
    for label, sig in signed.items():
        hybridsign.verify(pk_ed, pk_mldsa, label, MSG, sig)


def test_signature_is_bound_to_its_label(keys, signed):
    pk_ed, pk_mldsa, _ = keys
    with pytest.raises(Reject):
        hybridsign.verify(pk_ed, pk_mldsa, labels.TR_KEYCHANGE, MSG, signed[labels.HX_BUNDLE])


@pytest.mark.parametrize("label", [l for l in labels.APPENDIX_A if l not in labels.HYBRIDSIGN_LABELS],
                         ids=lambda l: l.decode())
def test_other_labels_are_refused(keys, signed, label):
    pk_ed, pk_mldsa, sk_mldsa = keys
    with pytest.raises(ValueError):
        hybridsign.sign(ED_SEED, sk_mldsa, label, MSG, RND)
    with pytest.raises(Reject):
        hybridsign.verify(pk_ed, pk_mldsa, label, MSG, signed[labels.HX_BUNDLE])


def test_each_half_must_verify(keys, signed):
    """Both components MUST verify: a valid half does not rescue an invalid one."""
    pk_ed, pk_mldsa, _ = keys
    sig = signed[labels.HX_BUNDLE]
    other_ed = primitives.ed25519_public(bytes(32))
    other_mldsa, _ = primitives.ml_dsa_65_keygen(bytes(32))
    with pytest.raises(Reject):
        hybridsign.verify(other_ed, pk_mldsa, labels.HX_BUNDLE, MSG, sig)
    with pytest.raises(Reject):
        hybridsign.verify(pk_ed, other_mldsa, labels.HX_BUNDLE, MSG, sig)


@pytest.mark.parametrize("n_ed,n_mldsa,n_sig", [(31, 1952, 3373), (33, 1952, 3373), (32, 1951, 3373),
                                                 (32, 1952, 3372), (32, 1952, 3374), (32, 1952, 0)])
def test_wrong_lengths_are_rejected(keys, signed, n_ed, n_mldsa, n_sig):
    pk_ed, pk_mldsa, _ = keys
    sig = signed[labels.HX_BUNDLE]
    fit = lambda v, n: (v + bytes(n))[:n]
    with pytest.raises(Reject):
        hybridsign.verify(fit(pk_ed, n_ed), fit(pk_mldsa, n_mldsa), labels.HX_BUNDLE, MSG, fit(sig, n_sig))


# ---------------------------------------------------------------------------------------------
# Strict Ed25519 (spec §3.5): which rules libsodium enforces, and the wrapper's pre-checks


def test_model_matches_rfc8032():
    for case in load("ed25519.json"):
        a_enc, sig = model.sign(h(case["secret"]), h(case["message"]))
        assert (a_enc, sig) == (h(case["public"]), h(case["signature"]))
        assert model.lenient_verify(a_enc, h(case["message"]), sig)


def test_small_order_y_set_is_derived_from_the_curve():
    torsion = model.torsion_points()
    for n, t in enumerate(torsion):
        assert model.equal(model.mul(8, t), model.IDENTITY)
        assert model.equal(t, model.IDENTITY) == (n == 0)
    ys = {int.from_bytes(model.encode(t), "little") & ((1 << 255) - 1) for t in torsion}
    assert ys == set(primitives.ED25519_SMALL_ORDER_Y)
    assert len(ys) == 5
    assert primitives.ED25519_P == model.P and primitives.ED25519_L == model.L


PROBES = probe.probes()


@pytest.mark.parametrize("rule,name,a,msg,sig", PROBES, ids=[p[1] for p in PROBES])
def test_strict_probe_isolates_one_rule(rule, name, a, msg, sig):
    """Each probe satisfies the cofactorless equation, so only the strict rule can reject it."""
    assert model.lenient_verify(a, msg, sig)


@pytest.mark.parametrize("rule,name,a,msg,sig", PROBES, ids=[p[1] for p in PROBES])
def test_libsodium_enforces_the_strict_rule_itself(rule, name, a, msg, sig):
    """Result for libsodium 1.0.20-stable (PyNaCl 1.6.2): every strict rule that can be isolated
    is enforced by crypto_sign_open itself — S < L, A and R not of small order, A and R canonical.
    (A non-canonical encoding of a point outside the torsion subgroup cannot be isolated: it needs
    a point with y < 19 and a known discrete logarithm.)"""
    assert not primitives.libsodium_ed25519_verify(a, msg, sig)


@pytest.mark.parametrize("rule,name,a,msg,sig", PROBES, ids=[p[1] for p in PROBES])
def test_precheck_enforces_the_strict_rule(rule, name, a, msg, sig):
    with pytest.raises(Reject):
        primitives.ed25519_strict_precheck(a, sig)
    with pytest.raises(Reject):
        primitives.ed25519_verify(a, msg, sig)


def test_precheck_passes_honest_signatures():
    for case in load("ed25519.json"):
        primitives.ed25519_strict_precheck(h(case["public"]), h(case["signature"]))


@pytest.mark.parametrize("y", [primitives.ED25519_P + k for k in range(2, 19)])
def test_non_canonical_large_order_encodings_are_rejected(y):
    """y ∈ [p + 2, 2^255 − 1]: not isolable (see above), but rejected by both layers."""
    enc = y.to_bytes(32, "little")
    _, sig = model.sign(bytes(32), b"m")
    with pytest.raises(Reject):
        primitives.ed25519_strict_precheck(enc, sig)
    assert not primitives.libsodium_ed25519_verify(enc, b"m", sig)
    with pytest.raises(Reject):                         # as R
        primitives.ed25519_strict_precheck(primitives.ed25519_public(bytes(32)), enc + sig[32:])


def test_s_boundary():
    """S = L − 1 passes the range check, S = L does not."""
    pk = primitives.ed25519_public(bytes(32))
    r = model.encode(model.mul(7, model.B))
    primitives.ed25519_strict_precheck(pk, r + (primitives.ED25519_L - 1).to_bytes(32, "little"))
    with pytest.raises(Reject):
        primitives.ed25519_strict_precheck(pk, r + primitives.ED25519_L.to_bytes(32, "little"))


# ---------------------------------------------------------------------------------------------
# SCHEMA §4.5 rows


def test_row_constants():
    assert cases.ED25519_IDENTITY == bytes.fromhex("01" + "00" * 31)
    assert cases.ED25519_Y1_NONCANONICAL == bytes.fromhex(
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
    assert int.from_bytes(cases.ED25519_Y1_NONCANONICAL, "little") == primitives.ED25519_P + 1
    assert primitives.ED25519_L == 2**252 + 27742317777372353535851937790883648493


@pytest.fixture(scope="module")
def suite():
    return {c.i: c for c in cases.hybridsign_cases()}


def test_table_shape(suite):
    assert sorted(suite) == list(range(1, 18))
    for i, (label, msg_len) in cases.HYBRIDSIGN_SIGN.items():
        c = suite[i]
        assert c.op == "sign" and c.inputs["label"] == label.decode()
        assert len(c.inputs["msg"]) == msg_len
        assert c.outputs["verify"] is True
        assert (len(c.outputs["pk_ed"]), len(c.outputs["pk_mldsa"]), len(c.outputs["sig"])) == (32, 1952, 3373)
    for i in range(9, 18):
        assert suite[i].op == "verify" and suite[i].outputs is None
        assert set(suite[i].inputs) == {"pk_ed", "pk_mldsa", "label", "msg", "sig"}


def test_positive_rows_verify(suite):
    for i in cases.HYBRIDSIGN_SIGN:
        c = suite[i]
        hybridsign.verify(c.outputs["pk_ed"], c.outputs["pk_mldsa"], c.inputs["label"].encode(),
                          c.inputs["msg"], c.outputs["sig"])


def test_negative_rows_are_rejected_and_differ_from_honest_in_one_field(suite):
    for i, row, field, _ in cases.HYBRIDSIGN_VERIFY:
        c = suite[i]
        inputs = dict(c.inputs, label=c.inputs["label"].encode())
        with pytest.raises(Reject):
            hybridsign.verify(**inputs)
        honest = cases._hybridsign_honest(i, row)
        differing = [k for k in inputs if inputs[k] != honest[k]]
        assert differing == [field]


def test_row14_isolates_s_range(suite):
    """Row 14 changes only S to S + L: the equation still holds, the ML-DSA half still verifies."""
    c = suite[14]
    m = hashlib.sha256(labels.HYBRIDSIGN + c.inputs["label"].encode() + c.inputs["msg"]).digest()
    assert model.lenient_verify(c.inputs["pk_ed"], m, c.inputs["sig"][:64])
    primitives.ml_dsa_65_verify(c.inputs["pk_mldsa"], m, c.inputs["sig"][64:], c.inputs["label"].encode())
