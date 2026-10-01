# SPDX-License-Identifier: AGPL-3.0-or-later
"""SecMP-TR (spec §7) and the `tr` suite (SCHEMA §4.9 proposal, brief REF-M3)."""

import collections
import copy
import hashlib
import json

import pytest

import gen_vectors
from secmp_ref import encodings as enc
from secmp_ref import hybridsign, identity, labels, primitives, sizes, tr, tr_cases, vectorfile
from secmp_ref.errors import Reject
from secmp_ref.vectorfile import Case, CaseStream
from _spec import spec_text


class Rng:
    """Deterministic randomness for the unit tests (not the vector streams)."""

    def __init__(self, tag):
        self.s = CaseStream("tr-unit-" + tag, 1)

    def take(self, n):
        return self.s.take(n)


def _pair(tag="pair"):
    rng = Rng(tag)
    sk, sb = rng.take(32), rng.take(32)
    spk, rpk = tr.DhKey.from_secret(rng.take(32)), tr.KemKey.from_seed(rng.take(64))
    a = tr.init_initiator(sk, sb, spk.pk, rpk.ek, rng)
    b = tr.init_responder(sk, sb, spk, rpk)
    return a, b, rng


def _content(seq, payload=b""):
    body = {"count": 1, "messages": [{"msg_id": bytes(16), "kind": 1, "expire_after": 0,
                                      "payload_len": len(payload), "payload": payload}]}
    v = {"ver": 1, "type": enc.CT_BATCH, "seq": seq, "ts": seq, "body_len": 0, "body": body}
    enc.refresh("Content", v)
    return enc.payload("Content", v)


def _plain(padded):
    return enc.payload("Content", enc.decode("Content", padded))


def _rejects(state, cell, rng, rule=None):
    before = tr_cases.state_bytes(state)
    with pytest.raises(Reject):
        tr.decrypt(state, cell, rng)
    assert tr_cases.state_bytes(state) == before              # transactional (§7.4 note (c))
    if rule is not None:
        assert tr.last_rule == rule


# ---------------------------------------------------------------------------------------------
# The ratchet on its own


def test_initialisation_matches_7_2():
    a, b, _ = _pair()
    rk, hk_a, nhk_b = tr.kdf_init(bytes(32))
    okm = primitives.hkdf(bytes(32), bytes(32), b"SecMP-TR/1 init", 96)
    assert (rk, hk_a, nhk_b) == (okm[:32], okm[32:64], okm[64:])
    assert a.hk_s == b.nhk_r and a.nhk_r == b.nhk_s                   # HK_A, NHK_B
    assert a.hk_r is None and b.hk_s is None and b.hk_r is None
    assert a.ck_r is None and b.ck_s is None and b.ck_r is None and b.ct_s is None
    assert a.dh_r == b.dh_s.pk and a.kem_r == b.kem_s.ek and a.last_ct_r is None
    assert (a.n_s, a.n_r, a.pn, b.n_s, b.n_r, b.pn) == (0,) * 6
    with pytest.raises(ValueError):
        tr.encrypt(b, _content(1), Rng("x"))                         # the responder has no sending chain yet


def test_kdf_ck_and_kdf_rk():
    ck = bytes(range(32))
    assert tr.kdf_ck(ck) == (primitives.hmac_sha256(ck, b"\x02"), primitives.hmac_sha256(ck, b"\x01"))
    okm = primitives.hkdf(b"\x07" * 32, b"ikm", b"SecMP-TR/1 rk", 96)
    assert tr.kdf_rk(b"\x07" * 32, b"ikm") == (okm[:32], okm[32:64], okm[64:])


def test_round_trips_and_header_fields():
    a, b, rng = _pair()
    cell = tr.encrypt(a, _content(1, b"hi"), rng)
    assert len(cell) == sizes.CELL
    header = tr.open_header(a.sb, b.nhk_r, *tr.split(cell)[:2])
    assert header == {"ver": 1, "flags": 0, "dh_pk": a.dh_s.pk, "pn": 0, "n": 0, "ek_pq": a.kem_s.ek, "ct_pq": a.ct_s}
    assert _plain(tr.decrypt(b, cell, rng)) == _content(1, b"hi")
    assert b.hk_r == a.hk_s and b.dh_r == a.dh_s.pk and b.kem_r == a.kem_s.ek and b.last_ct_r == a.ct_s
    back = tr.encrypt(b, _content(2), rng)
    assert _plain(tr.decrypt(a, back, rng)) == _content(2)
    # A's receiving half mirrors B's sending half; A's rk has also been through its own sending half
    assert a.ck_r == b.ck_s and a.hk_r == b.hk_s and a.nhk_r == b.nhk_s and a.rk != b.rk
    assert a.dh_r == b.dh_s.pk and a.kem_r == b.kem_s.ek and a.last_ct_r == b.ct_s and a.pn == 1


def test_rejections_leave_the_state_unchanged():
    a, b, rng = _pair()
    c0, c1 = tr.encrypt(a, _content(1), rng), tr.encrypt(a, _content(2), rng)
    _rejects(b, c0[:-1], rng, "cell-length")
    _rejects(b, vectorfile.flip(c0, 0), rng, "no-header-key")
    _rejects(b, vectorfile.flip(c0, -1), rng, "body-mac")           # a step message: DHRatchet ran on the copy
    tr.decrypt(b, c1, rng)                                          # m1 first: m0's key goes to skipped
    assert list(b.skipped) == [(a.hk_s, 0)]
    _rejects(b, vectorfile.flip(c0, -1), rng, "body-mac")           # skipped path: MAC first, then removal
    assert list(b.skipped) == [(a.hk_s, 0)]
    _rejects(b, c1, rng, "replay")
    tr.decrypt(b, c0, rng)
    assert b.skipped == {}
    _rejects(b, c0, rng, "replay")                                  # consumed from skipped


def test_step_must_carry_a_new_dh_key_and_constant_kem_material():
    a, b, rng = _pair()
    tr.decrypt(b, tr.encrypt(a, _content(1), rng), rng)
    hk, sb = a.hk_s, a.sb
    cell = tr.encrypt(a, _content(2), rng)
    nonce, _, body = tr.split(cell)
    header = tr.open_header(sb, hk, *tr.split(cell)[:2])
    for field, value, rule in (("ek_pq", tr.KemKey.from_seed(bytes(64)).ek, "kem-constancy"),
                               ("ct_pq", vectorfile.flip(header["ct_pq"], 5), "kem-constancy"),
                               ("flags", 1, "header-decode")):
        forged = enc.raw("HeaderV1", {**header, field: value})
        _rejects(b, nonce + primitives.xchacha20poly1305_seal(hk, nonce, labels.TR_HDR + sb, forged) + body, rng, rule)
    # B answers; a step message from B that repeats A's current dh_r is refused before any KDF
    reply = tr.encrypt(b, _content(3), rng)
    nonce, _, body = tr.split(reply)
    header = tr.open_header(b.sb, b.hk_s, *tr.split(reply)[:2])
    forged = enc.raw("HeaderV1", {**header, "dh_pk": a.dh_r})
    _rejects(a, nonce + primitives.xchacha20poly1305_seal(b.hk_s, nonce, labels.TR_HDR + sb, forged) + body, rng,
             "step-same-dh")
    tr.decrypt(a, reply, rng)


def test_skip_window_max_ff_and_eviction(monkeypatch):
    monkeypatch.setattr(tr, "SKIP_WINDOW", 3)
    monkeypatch.setattr(tr, "MAX_SKIPPED", 6)
    monkeypatch.setattr(tr, "MAX_FF", 10)
    a, b, rng = _pair("window")
    tr.decrypt(b, tr.encrypt(a, _content(0), rng), rng)
    for _ in range(10):
        tr.encrypt(a, _content(0), rng)                            # n = 1 … 10 lost
    over = copy.deepcopy(a)
    tr.encrypt(over, _content(0), rng)
    _rejects(b, tr.encrypt(over, _content(0), rng), rng, "max-ff")  # n = 12: gap 11 > MAX_FF
    tr.decrypt(b, tr.encrypt(a, _content(0), rng), rng)            # n = 11: gap 10 = MAX_FF
    assert [n for _, n in b.skipped] == [8, 9, 10]                 # only the last SKIP_WINDOW positions
    tr.decrypt(a, tr.encrypt(b, _content(0), rng), rng)            # new chains
    for _ in range(4):
        tr.encrypt(a, _content(0), rng)
    first_chain = a.pn
    tr.decrypt(b, tr.encrypt(a, _content(0), rng), rng)            # stores n = 1 … 3 of the new chain → 6
    assert len(b.skipped) == 6 and first_chain == 12
    tr.encrypt(a, _content(0), rng)
    tr.decrypt(b, tr.encrypt(a, _content(0), rng), rng)            # one more → 7 → the oldest entry goes
    assert len(b.skipped) == 6 and [n for _, n in b.skipped][:2] == [9, 10]


# ---------------------------------------------------------------------------------------------
# State digest


def test_state_digest_layout():
    a, b, _ = _pair()
    # responder at init: dh_r, kem_r, last_ct_r, ct_s, ck_s, ck_r, hk_s, hk_r absent; nhk_s, nhk_r present
    expected = (b"SecMP-TR/1 state-digest" + b.sb + b.rk + b.dh_s.sk + b"\x00" + b.kem_s.seed + b"\x00" * 7
                + b"\x01" + b.nhk_s + b"\x01" + b.nhk_r + bytes(16))
    assert tr_cases.state_bytes(b) == expected
    assert tr_cases.state_digest(b) == hashlib.sha256(expected).digest()
    b.skipped[(b"\x11" * 32, 7)] = b"\x22" * 32
    assert tr_cases.state_bytes(b).endswith(bytes([0, 0, 0, 1]) + b"\x11" * 32 + bytes([0, 0, 0, 7]) + b"\x22" * 32)


def test_digest_label_is_outside_appendix_a_and_prefix_free():
    """SQ-24: the label is not an App. A label; it neither starts with one nor starts one."""
    assert tr_cases.DIGEST_LABEL not in labels.APPENDIX_A and tr_cases.DIGEST_LABEL.isascii()
    assert "SecMP-TR/1 state-digest" not in spec_text()
    for label in labels.APPENDIX_A:
        assert not label.startswith(tr_cases.DIGEST_LABEL) and not tr_cases.DIGEST_LABEL.startswith(label)


# ---------------------------------------------------------------------------------------------
# The transcript


@pytest.fixture(scope="module")
def run():
    return tr_cases.run()


def test_event_counts_and_order(run):
    assert collections.Counter(c.op for c in run.cases) == {"init": 1, "send": 40, "recv": 40, "advance": 2,
                                                            "recv-reject": 13}
    assert [c.i for c in run.cases] == list(range(1, 97))
    sends = [c.fields["msg"] for c in run.cases if c.op == "send"]
    assert sends == [f"m{n:02d}" for n in range(1, 41)]            # send order m01–m40
    delivered = [c.fields["msg"] for c in run.cases if c.op == "recv"]
    assert sorted(delivered) == sends and delivered[-1] == "m11"
    assert [c.fields["count"] for c in run.cases if c.op == "advance"] == [10000, 300]


def test_state_digests_chain_per_party(run):
    last = {}
    for c in run.cases:
        if c.op == "init":
            last = {"A": c.outputs["state_post_A"], "B": c.outputs["state_post_B"]}
            continue
        party = c.fields["party"]
        assert c.outputs["state_pre"] == last[party], c.i
        last[party] = c.outputs["state_post"]
        if c.op == "recv-reject":
            assert c.outputs["state_post"] == c.outputs["state_pre"]
    assert last == {p: tr_cases.state_digest(run.states[p]) for p in "AB"}


def test_inputs_are_the_case_stream_in_order(run):
    derived = {"content", "cell"}
    for c in run.cases:
        drawn = b"".join(v for k, v in c.inputs.items() if k not in derived)
        assert CaseStream("tr", c.i).take(len(drawn)) == drawn, c.i
    keys = {c.i: list(c.inputs) for c in run.cases}
    assert keys[1] == ["sk", "sb", "spk_dh_sk", "rpk_kem_seed", "dh_s_sk", "kem_s_seed", "m"]
    assert keys[2] == ["msg_id", "payload", "hdr_nonce", "content"]
    assert keys[3] == ["hdr_nonce", "content"]
    assert keys[5] == ["dh_sk", "kem_seed", "m"] and keys[8] == []
    assert keys[6] == ["ek_pq_seed", "cell"] and keys[15] == ["dh_sk", "kem_seed", "m", "cell"]
    assert keys[38] == ["hdr_nonces"] and len(run.cases[37].inputs["hdr_nonces"]) == 24 * 10000


def test_recv_returns_the_senders_content_and_steps_as_the_table_says(run):
    sends = {c.fields["msg"]: c for c in run.cases if c.op == "send"}
    steps = []
    for c in run.cases:
        if c.op == "recv":
            send = sends[c.fields["msg"]]
            assert c.fields["from"] == vectorfile.case_id("tr", send.i)
            assert c.outputs["content"] == send.inputs["content"]
            assert c.fields["party"] != send.fields["party"]
            if c.inputs:
                steps.append(c.fields["msg"])
    assert steps == ["m01", "m04", "m09", "m12", "m14", "m16", "m18", "m22", "m24", "m33", "m36", "m39"]


def test_content_layouts(run):
    sends = {c.fields["msg"]: c for c in run.cases if c.op == "send"}
    for name, c in sends.items():
        v = enc.decode("Content", enc.iso_pad(c.inputs["content"], sizes.BODY_LEN))
        seq = int(name[1:])
        assert (v["ver"], v["seq"], v["ts"]) == (1, seq, 1_700_000_000 + seq)
    m05 = enc.decode("Content", enc.iso_pad(sends["m05"].inputs["content"], sizes.BODY_LEN))
    assert m05["body_len"] == enc.BODY_MAX and m05["body"]["messages"][0]["payload_len"] == 1665      # SQ-22
    assert enc.decode("Content", enc.iso_pad(sends["m02"].inputs["content"], sizes.BODY_LEN))["type"] == enc.CT_DUMMY
    route = enc.decode("Content", enc.iso_pad(sends["m22"].inputs["content"], sizes.BODY_LEN))["body"]
    assert route["count"] == 1 and route["routes"][0]["blob"]["period_s"] == 20
    assert "direct_present" in route["routes"][0]["blob"]["relay"] and route["routes"][0]["blob"]["relay"]["direct_present"] == 0


def test_keychange_fragments_reassemble_and_verify(run):
    recvs = {c.fields["msg"]: c for c in run.cases if c.op == "recv"}
    frags = [enc.decode("Content", enc.iso_pad(recvs[f"m{n}"].outputs["content"], sizes.BODY_LEN))["body"]
             for n in (18, 19, 20, 21)]
    assert [f["idx"] for f in frags] == [0, 1, 2, 3] and {f["total"] for f in frags} == {4}
    assert len({f["msg_id"] for f in frags}) == 1
    assert [len(f["chunk"]) for f in frags] == [1669, 1669, 1669, 384]
    payload = enc.decode("FragmentPayload", b"".join(f["chunk"] for f in frags))
    assert payload["inner_type"] == enc.CT_KEYCHANGE
    new_iks = enc.raw("IKSPublic", payload["inner_body"]["iks"])
    kc = run.keychange
    hybridsign.verify(kc.old_pk_ed, kc.old_pk_mldsa, labels.TR_KEYCHANGE, identity.fingerprint(new_iks),
                      payload["inner_body"]["sig"])
    first = next(c for c in run.cases if c.op == "send" and c.fields["msg"] == "m18")
    assert list(first.inputs)[:7] == ["old_ik_mldsa_xi", "old_ik_ed_seed", "new_ik_mldsa_xi", "new_ik_ed_seed",
                                      "new_ik_dh_sk", "rnd", "msg_id"]
    assert primitives.ed25519_public(first.inputs["old_ik_ed_seed"]) == kc.old_pk_ed


def test_skipped_keys_fast_forward_eviction_and_late_delivery(run):
    rows = {(r["op"], r.get("msg")): r for r in run.rows if r["op"] == "recv"}
    assert rows[("recv", "m15")]["inserted"] == 256 and rows[("recv", "m15")]["skipped"] == 256
    assert rows[("recv", "m24")]["inserted"] == 256 and rows[("recv", "m24")]["skipped"] == 512
    assert (rows[("recv", "m26")]["inserted"], rows[("recv", "m26")]["removed"], rows[("recv", "m26")]["skipped"]) == (1, 1, 512)
    assert rows[("recv", "m33")]["inserted"] == 2
    via_skipped = [m for (_, m), r in rows.items() if r["via"] == "skipped"]
    assert sorted(via_skipped) == ["m07", "m08", "m11", "m25", "m27", "m29", "m31", "m32", "m34"]
    # m11: its key was stored under the header key of B's chain m11–m13 when A stepped on m12
    m11 = run.sent[11]
    assert m11.hk not in (run.states["A"].hk_r, run.states["A"].nhk_r) and run.states["A"].skipped == {}
    # the entry evicted at m26 is the earliest-inserted one: m14's chain, position 10001 − 256
    m14 = run.sent[14]
    final_b = run.states["B"].skipped
    assert (m14.hk, 9745) not in final_b and (m14.hk, 9746) in final_b
    assert list(final_b)[0] == (m14.hk, 9746)


def test_message_keys_are_never_reused(run):
    enc_mks = [mk for _, mk in run.enc_log]
    assert len(enc_mks) == 40 + 10000 + 300 == len(set(enc_mks))
    assert len(run.dec_log) == 40 == len({mk for _, mk in run.dec_log})
    own = dict(entry for entry in run.enc_log if entry[0] != "advance")
    assert all(own[label] == mk for label, mk in run.dec_log)
    assert len(set(enc_mks) | {mk for _, mk in run.dec_log}) == 10340


def test_negative_events(run):
    rows = [r for r in run.rows if r["op"] == "recv-reject"]
    assert [r["neg"] for r in rows] == ["N2", "N3", "N11", "N4", "N1", "N5", "N6", "N7", "N8", "N10", "N9", "N12", "N13"]
    for r in rows:
        assert r["rule"] == tr_cases.NEGATIVES[r["neg"]].rule
        assert r["cell_len"] == {"N6": 4095, "N7": 4097}.get(r["neg"], 4096)
        assert r["drew"] == (r["neg"] == "N1")                     # only N1 reaches DHRatchet
    # each negative sits where the brief puts it
    order = [(r["op"], r.get("neg") or r.get("msg")) for r in run.rows]
    def at(x):
        return order.index(x)
    assert at(("recv-reject", "N2")) < at(("recv-reject", "N3")) < at(("recv", "m02")) == at(("recv-reject", "N3")) + 1
    assert at(("recv-reject", "N11")) + 1 == at(("recv", "m03")) == at(("recv-reject", "N4")) - 1
    assert at(("recv-reject", "N1")) + 1 == at(("recv", "m04"))
    assert at(("recv", "m08")) + 1 == at(("recv-reject", "N5"))
    assert at(("recv-reject", "N8")) + 1 == at(("recv", "m14")) and at(("recv-reject", "N10")) + 1 == at(("recv", "m15"))
    assert at(("recv-reject", "N9")) + 1 == at(("recv", "m16"))
    assert at(("recv-reject", "N13")) + 1 == at(("recv", "m17")) == at(("recv-reject", "N12")) + 2


def test_n10_header_and_n9_header(run):
    cases = {c.fields.get("manipulation"): c for c in run.cases if c.op == "recv-reject"}
    m14, m16 = run.sent[14], run.sent[16]
    h10 = tr.open_header(m14.sb, m14.hk, *tr.split(cases["gap-over-max-ff"].inputs["cell"])[:2])
    assert h10 == {**m14.header, "n": 1 + 2**20 + 1}
    h9 = tr.open_header(m16.sb, m16.hk, *tr.split(cases["step-without-new-dh"].inputs["cell"])[:2])
    assert h9 == {**m16.header, "dh_pk": run.sent[11].header["dh_pk"]}   # A's dh_r then: B's chain of m11–m13


# ---------------------------------------------------------------------------------------------
# The file


def test_written_file_is_current_canonical_and_valid():
    path = gen_vectors.VECTORS_DIR / "tr.json"
    data = path.read_bytes()
    assert data == gen_vectors.suite_bytes("tr")
    doc = json.loads(data)
    vectorfile.validate_document(doc)
    assert vectorfile.canonical_json(doc) == data and data.isascii() and not data.endswith(b"\n")
    assert (doc["schema"], doc["suite"], doc["spec"], doc["generator"]) == (4, "tr", "SecMP/1 rev 2.3", "ref-python")
    reject = next(c for c in doc["cases"] if c["op"] == "recv-reject")
    assert reject["expect"] == "reject" and set(reject["outputs"]) == {"state_pre", "state_post"}


def test_schema_4_9_is_rendered_from_this_table():
    from tools import render_schema_4_9
    assert render_schema_4_9.OUT.read_text(encoding="utf-8") == render_schema_4_9.render()


@pytest.mark.parametrize("mutate", [
    lambda d: d["cases"][0].update(party="A"),
    lambda d: d["cases"][1].update(party="C"),
    lambda d: d["cases"][1].pop("msg"),
    lambda d: d["cases"][1].update(msg="m1"),
    lambda d: d["cases"][2].update({"from": "tr-0009"}),
    lambda d: d["cases"][2]["outputs"].pop("content"),
    lambda d: d["cases"][3].update(count=0),
    lambda d: d["cases"][3].update(count=True),
    lambda d: d["cases"][4].update(expect="accept"),
    lambda d: d["cases"][4].pop("outputs"),
    lambda d: d["cases"][4]["inputs"].update(cell="AB"),
    lambda d: d["cases"][4].update(op="open"),
])
def test_tr_validator_rejects(mutate):
    doc = vectorfile.suite_document("tr", [
        Case(1, "init", {"sk": b"\x01"}, {"state_post_A": b"\x02", "state_post_B": b"\x03"}, {"party": "AB"}),
        Case(2, "send", {"hdr_nonce": b"\x04"}, {"cell": b"", "state_pre": b"", "state_post": b""},
             {"party": "A", "msg": "m01"}),
        Case(3, "recv", {}, {"content": b"", "state_pre": b"", "state_post": b""},
             {"party": "B", "msg": "m01", "from": "tr-0002"}),
        Case(4, "advance", {"hdr_nonces": b""}, {"state_pre": b"", "state_post": b""}, {"party": "A", "count": 3}),
        Case(5, "recv-reject", {"cell": b"\x05"}, {"state_pre": b"\x06", "state_post": b"\x06"},
             {"party": "B", "msg": "m01", "from": "tr-0002", "manipulation": "truncated", "expect": "reject"}),
    ])
    vectorfile.validate_document(doc)
    mutate(doc)
    with pytest.raises(ValueError):
        vectorfile.validate_document(doc)
