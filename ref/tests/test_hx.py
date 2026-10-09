# SPDX-License-Identifier: AGPL-3.0-or-later
"""SecMP-INV (spec §5), SecMP-HX (spec §6) and the `hx` suite (SCHEMA §4.10 proposal, brief REF-M4)."""

import base64
import collections
import dataclasses
import json

import pytest

import gen_vectors
from secmp_ref import caead, hx, hx_cases, inv, labels, primitives, sizes, tr, tr_cases, vectorfile
from secmp_ref import encodings as enc
from secmp_ref.errors import Reject
from secmp_ref.vectorfile import Case, CaseStream, flip

H = primitives.sha256


def _hkdf(salt, ikm, label, extra=b""):
    """HKDF-SHA-256 straight from the primitive, with the label written out here (not via hx/inv)."""
    return primitives.hkdf(salt, ikm, label + extra, 32)


@pytest.fixture(scope="module")
def run():
    return hx_cases.run()


@pytest.fixture(scope="module")
def doc():
    return json.loads(gen_vectors.suite_bytes("hx"))


def _cases(doc):
    return {c["id"]: c for c in doc["cases"]}


def _b(x):
    return bytes.fromhex(x)


def _copy(state):
    return dataclasses.replace(state, skipped=dict(state.skipped))


# ---------------------------------------------------------------------------------------------
# SecMP-INV on its own


def test_uri_round_trip_and_strict_decoding():
    for n in range(0, 12):
        data = bytes(range(n))
        uri = inv.uri_encode(data)
        assert "=" not in uri and inv.uri_decode(uri) == data
    good = inv.uri_encode(b"\xfb\xff\xbf\x01")                   # 4 bytes → 6 characters, "_" and "-" appear
    assert good == "secmp://i/-_-_AQ"
    for bad in [good + "==", good.replace("secmp", "SECMP"), "secmp://j/" + good[10:], good[:-1] + "R",
                good.replace("_", "/"), good.replace("-", "+"), good[:-1], good + " ", good[:10] + "=" + good[10:]]:
        with pytest.raises(Reject):
            inv.uri_decode(bad)
        assert inv.last_rule == "uri"


def test_k_ld_and_blob():
    ld_id, link_key, n = bytes(range(16)), bytes(range(32)), bytes(range(24))
    k_ld = inv.derive_k_ld(ld_id, link_key)
    assert k_ld == _hkdf(ld_id, link_key, b"SecMP-INV/1 linkdata")
    blob = inv.seal_blob(k_ld, n, ld_id, b"abc")
    assert len(blob) == sizes.LINK_BLOB == 12360 and blob[:24] == n
    assert caead.open(k_ld, n, b"SecMP-INV/1 blob" + ld_id, blob[24:]) == b"abc\x80" + bytes(12288 - 4)
    assert inv.open_blob(k_ld, ld_id, blob) == enc.iso_pad(b"abc", 12288)
    for bad in [blob[:-1], blob + b"\x00", flip(blob, 0), flip(blob, 24), flip(blob, -1)]:
        with pytest.raises(Reject):
            inv.open_blob(k_ld, ld_id, bad)
    with pytest.raises(Reject):
        inv.open_blob(k_ld, flip(ld_id, 0), blob)                 # ld_id is in the AD


# ---------------------------------------------------------------------------------------------
# The run: counts, streams, file


def test_case_counts_and_order(run):
    ops = [c.op for c in run.cases]
    assert ops == ["keys-R", "keys-I", "invite", "linkdata", "invitee-accept", "initiate", "respond",
                   "respond-garbage"] + ["invitee-reject"] * 8 + ["respond-reject"] * 12 + ["invitee-reject",
                                                                                           "respond-reject"] + [
                   "respond-later-group", "respond-reject", "respond-reject", "respond-reject", "respond-reject",
                   "respond-reject", "respond-retained-spk"]
    assert [c.i for c in run.cases] == list(range(1, 38))
    assert [r["name"] for r in run.rows[8:]] == ([f"V{k}" for k in range(1, 9)] + [f"R{k}" for k in range(1, 13)]
                                                 + ["V9", "R13"]       # appended by Weisung REF-M4-1
                                                 + ["A1", "R14", "R15", "R16", "R17", "R18", "A2"])   # REF-M5-2
    assert collections.Counter(c.op for c in run.cases)["respond-reject"] == 18


def test_inputs_are_the_case_stream_in_order(run):
    """Every stream-derived input is the next slice of the case's own stream; derived values follow."""
    for c, row in zip(run.cases, run.rows):
        s = CaseStream("hx", c.i)
        names = [name for name, _ in row["stream"]]
        assert list(c.inputs)[: len(names)] == names
        for name, size in row["stream"]:
            assert c.inputs[name] == s.take(size), (c.i, name)
        assert list(c.inputs)[len(names):] == row["derived"]


def test_written_file_is_current_canonical_and_valid():
    path = gen_vectors.VECTORS_DIR / "hx.json"
    data = path.read_bytes()
    assert data == gen_vectors.suite_bytes("hx")
    d = json.loads(data)
    vectorfile.validate_document(d)
    assert vectorfile.canonical_json(d) == data and data.isascii() and not data.endswith(b"\n")
    assert (d["schema"], d["suite"], d["spec"], d["generator"]) == (5, "hx", "SecMP/1 rev 2.6", "ref-python")


def test_schema_4_10_is_rendered_from_this_table():
    from tools import render_schema_4_10
    assert render_schema_4_10.OUT.read_text(encoding="utf-8") == render_schema_4_10.render()


# ---------------------------------------------------------------------------------------------
# The positive cases, recomputed from the file with the spec formulas


def test_keys_and_bundle(doc):
    c = _cases(doc)
    r, i = c["hx-0001"], c["hx-0002"]
    for case in (r, i):
        iks = _b(case["outputs"]["iks"])
        assert len(iks) == 2017 and _b(case["outputs"]["fp"]) == H(b"SecMP-FP/1" + iks)
        assert iks[-32:] == primitives.x25519_public(_b(case["inputs"]["ik_dh_sk"]))
        assert iks[1:33] == primitives.ed25519_public(_b(case["inputs"]["ik_ed_seed"]))
    b = enc.decode("PrekeyBundle", _b(r["outputs"]["bundle"]))
    assert (b["spk_id"], b["opk_id"], b["spk_expiry"], b["opk_present"]) == (7, 42, 1_702_592_000, 1)
    assert b["spk_dh"] == primitives.x25519_public(_b(r["inputs"]["spk_dh_sk"]))
    assert b["opk_dh"] == primitives.x25519_public(_b(r["inputs"]["opk_dh_sk"]))
    assert b["rpk_kem"] == tr.KemKey.from_seed(_b(r["inputs"]["rpk_kem_seed"])).ek
    iks_r = enc.decode("IKSPublic", _b(r["outputs"]["iks"]))
    msg = _b(r["outputs"]["bundle"])[: -sizes.HYBRID_SIG] + iks_r["ik_dh"]
    assert len(msg) == 4434                                       # SCHEMA §4.5 row 7
    from secmp_ref import hybridsign
    hybridsign.verify(iks_r["ik_ed25519"], iks_r["ik_mldsa65"], labels.HX_BUNDLE, msg, b["sig"])
    assert r["outputs"]["opks_post"] == [42]


def test_invitation_uri_and_linkdata(doc, run):
    c = _cases(doc)
    v = enc.decode("InvitationV1", _b(c["hx-0003"]["outputs"]["invitation"]))
    inputs = c["hx-0003"]["inputs"]
    assert v["relay"]["onion"][:32] == _b(inputs["onion_pubkey"]) and v["relay"]["direct_present"] == 0
    assert (v["kind"], v["inv_period_s"], v["expires"]) == (1, 20, 1_702_592_000)
    assert v["inviter_fp"] == _b(c["hx-0001"]["outputs"]["fp"])
    uri = c["hx-0003"]["outputs"]["uri"]
    assert uri.startswith("secmp://i/") and len(uri) == 10 + 322
    assert base64.urlsafe_b64decode(uri[10:] + "==") == _b(c["hx-0003"]["outputs"]["invitation"])
    ld = c["hx-0004"]
    k_ld = _hkdf(v["ld_id"], v["link_key"], b"SecMP-INV/1 linkdata")
    assert _b(ld["outputs"]["k_ld"]) == k_ld
    blob, linkdata = _b(ld["outputs"]["blob"]), _b(ld["outputs"]["linkdata"])
    assert blob[:24] == _b(ld["inputs"]["n"])
    assert caead.open(k_ld, blob[:24], b"SecMP-INV/1 blob" + v["ld_id"], blob[24:]) == enc.iso_pad(linkdata, 12288)
    lv = enc.decode("LinkDataV1", enc.iso_pad(linkdata, 12288))
    assert lv["profile"] == {"name_len": 3, "name": b"bob", "avatar_present": 0} and lv["created"] == 1_700_000_000
    acc = c["hx-0005"]
    assert acc["inputs"] == {} and acc["outputs"]["accept"] is True
    assert _b(acc["outputs"]["k_inv"]) == _hkdf(v["ld_id"], v["link_key"], b"SecMP-HX/1 initkey")


def test_initiate_recomputed_from_the_spec_formulas(doc):
    c = _cases(doc)
    v = enc.decode("InvitationV1", _b(c["hx-0003"]["outputs"]["invitation"]))
    ld_id, link_key = v["ld_id"], v["link_key"]
    iks_r, iks_i = _b(c["hx-0001"]["outputs"]["iks"]), _b(c["hx-0002"]["outputs"]["iks"])
    b = enc.decode("PrekeyBundle", _b(c["hx-0001"]["outputs"]["bundle"]))
    x, o = c["hx-0006"]["inputs"], {k: _b(val) for k, val in c["hx-0006"]["outputs"].items()}
    ek_pk = primitives.x25519_public(_b(x["ek_sk"]))
    assert o["ek_pk"] == ek_pk
    assert o["dh1"] == primitives.x25519(_b(c["hx-0002"]["inputs"]["ik_dh_sk"]), b["spk_dh"])
    assert o["dh2"] == primitives.x25519(_b(x["ek_sk"]), iks_r[-32:])
    assert o["dh3"] == primitives.x25519(_b(x["ek_sk"]), b["spk_dh"])
    assert o["dh4"] == primitives.x25519(_b(x["ek_sk"]), b["opk_dh"])
    assert (o["ct_spk"], o["ss_spk"]) == primitives.ml_kem_encaps(1024, b["spk_kem"], _b(x["m_spk"]))
    assert (o["ct_opk"], o["ss_opk"]) == primitives.ml_kem_encaps(1024, b["opk_kem"], _b(x["m_opk"]))
    th = H(b"SecMP-HX/1 transcript" + iks_r + (7).to_bytes(4, "big") + b["spk_dh"] + H(b["spk_kem"]) + H(b["rpk_kem"])
           + (42).to_bytes(4, "big") + b["opk_dh"] + H(b["opk_kem"]) + iks_i + ek_pk + H(o["ct_spk"]) + H(o["ct_opk"])
           + ld_id)
    assert o["transcript"] == th
    ikm = b"\xff" * 32 + o["dh1"] + o["dh2"] + o["dh3"] + o["dh4"] + o["ss_spk"] + o["ss_opk"]
    assert len(ikm) == 224 and o["sk"] == _hkdf(bytes(32), ikm, b"SecMP-HX/1 sk", th)
    assert o["k_id"] == _hkdf(ld_id, link_key + o["dh3"] + o["ss_spk"] + o["dh4"] + o["ss_opk"], b"SecMP-HX/1 idkey")
    assert o["k_inv"] == _hkdf(ld_id, link_key, b"SecMP-HX/1 initkey")
    # Outer, inner_ct, the cells (D.4)
    outer = o["outer"]
    assert len(outer) == 9362 and outer[:1] == b"\x01" and outer[1:33] == ek_pk
    assert outer[33:41] == (7).to_bytes(4, "big") + (42).to_bytes(4, "big")
    assert outer[41:41 + 3136] == o["ct_spk"] + o["ct_opk"] and outer[41 + 3136:] == o["inner_ct"]
    inner_ct = o["inner_ct"]
    assert inner_ct[:24] == _b(x["inner_nonce"])
    inner = caead.open(o["k_id"], inner_ct[:24], b"SecMP-HX/1 inner" + ld_id, inner_ct[24:])
    assert inner == iks_i + o["first_msg"]
    padded = b""
    for k in range(3):
        cell = o[f"cell_{k}"]
        assert len(cell) == 4096 and cell[:24] == _b(x[f"cell_nonce_{k}"])
        pt = caead.open(o["k_inv"], cell[:24], b"SecMP-HX/1 initcell" + ld_id, cell[24:])
        assert pt[:16] == _b(x["init_id"]) and pt[16:18] == bytes([k, 3]) and len(pt) == 4024
        padded += pt[18:]
    assert padded == outer + b"\x80" + bytes(12018 - 9363)
    # first_msg decrypts under a fresh TR responder from SK (§7.2), like R does
    r_in = c["hx-0001"]["inputs"]
    state = tr.init_responder(o["sk"], th, tr.DhKey.from_secret(_b(r_in["spk_dh_sk"])),
                              tr.KemKey.from_seed(_b(r_in["rpk_kem_seed"])))
    rng = CaseStream("hx-unit-first-msg", 1)
    assert tr.decrypt(state, o["first_msg"], rng) == enc.iso_pad(o["content"], sizes.BODY_LEN)


def test_handshake_content(doc):
    c = _cases(doc)
    x = c["hx-0006"]["inputs"]
    v = enc.decode("Content", enc.iso_pad(_b(c["hx-0006"]["outputs"]["content"]), sizes.BODY_LEN))
    assert (v["ver"], v["type"], v["seq"], v["ts"]) == (1, 0x01, 1, 1_700_000_001)
    body = v["body"]
    assert body["profile"] == {"name_len": 5, "name": b"alice", "avatar_present": 1,
                               "avatar_sha256": _b(x["avatar_sha256"])}
    assert body["caps"] == 0 and body["route_count"] == 1
    route = body["routes"][0]
    assert (route["ver"], route["kind"], route["blob"]["period_s"]) == (1, 0x01, 20)
    rq = route["blob"]
    assert (rq["relay"]["relay_fp"], rq["relay"]["akc"], rq["sid"], rq["send_seed"]) == tuple(
        _b(x[k]) for k in ("relay_fp", "akc", "sid", "send_seed"))
    assert rq["relay"]["onion"][:32] == primitives.ed25519_public(_b(x["onion_seed"]))
    assert rq["relay"]["direct_present"] == 0


@pytest.mark.parametrize("cid", ["hx-0007", "hx-0008"])
def test_both_sides_derive_the_same_keys(doc, cid):
    c = _cases(doc)
    i, r = c["hx-0006"]["outputs"], c[cid]["outputs"]
    assert (r["transcript"], r["sk"], r["k_id"]) == (i["transcript"], i["sk"], i["k_id"])
    assert r["peer_iks"] == c["hx-0002"]["outputs"]["iks"]
    assert r["content"] == i["content"] and r["opks_post"] == []
    body = enc.decode("Content", enc.iso_pad(_b(r["content"]), sizes.BODY_LEN))["body"]
    assert _b(r["profile"]) == enc.encode("Profile", body["profile"])
    assert [_b(x) for x in r["routes"]] == [enc.encode("RouteDescriptor", x) for x in body["routes"]]
    cells = [i["cell_0"], i["cell_1"], i["cell_2"]]
    fetched = c[cid]["inputs"]["fetched"]
    if cid == "hx-0007":
        assert fetched == cells
    else:
        g1, g2 = c[cid]["inputs"]["g1"], c[cid]["inputs"]["g2"]
        assert fetched == [g1, cells[0], g2, cells[1], cells[2]]


def test_content_round_trips(doc):
    c = _cases(doc)
    for cid in ("hx-0006", "hx-0007", "hx-0008"):
        content = _b(c[cid]["outputs"]["content"])
        assert enc.payload("Content", enc.decode("Content", enc.iso_pad(content, sizes.BODY_LEN))) == content


def test_state_digests(run, doc):
    c = _cases(doc)
    assert _b(c["hx-0006"]["outputs"]["state_post_I"]) == tr_cases.state_digest(run.ctx.start.state)
    assert _b(c["hx-0007"]["outputs"]["state_post_R"]) == tr_cases.state_digest(run.ctx.accepted7.state)
    assert c["hx-0007"]["outputs"]["state_post_R"] != c["hx-0008"]["outputs"]["state_post_R"]   # other DH step


def test_session_works_both_ways_after_case_7(run):
    """R encrypts one Dummy, I decrypts it; I encrypts one Batch, R decrypts it (test only)."""
    i_state, r_state = _copy(run.ctx.start.state), _copy(run.ctx.accepted7.state)
    rng = CaseStream("hx-unit-session", 1)
    dummy = enc.encode("Content", {"ver": 1, "type": enc.CT_DUMMY, "seq": 1, "ts": 1_700_000_200, "body_len": 0,
                                   "body": b""})[: 20]
    cell = tr.encrypt(r_state, dummy, rng)
    assert tr.decrypt(i_state, cell, rng) == enc.iso_pad(dummy, sizes.BODY_LEN)     # I steps on R's first message
    batch = {"ver": 1, "type": enc.CT_BATCH, "seq": 2, "ts": 1_700_000_300, "body_len": 0,
             "body": {"count": 1, "messages": [{"msg_id": bytes(16), "kind": 1, "expire_after": 0,
                                                "payload_len": 5, "payload": b"hello"}]}}
    enc.refresh("Content", batch)
    content = enc.payload("Content", batch)
    cell = tr.encrypt(i_state, content, rng)
    assert enc.payload("Content", enc.decode("Content", tr.decrypt(r_state, cell, rng))) == content


# ---------------------------------------------------------------------------------------------
# The rejections


def test_every_rejection_keeps_the_opk(doc, run):
    assert len(doc["cases"]) == len(run.rows) == 37
    for case, row in zip(doc["cases"][8:], run.rows[8:], strict=True):
        if row["name"] in ("A1", "A2"):
            assert "expect" not in case and case["outputs"]["opks_post"] == []
            continue
        assert case["expect"] == "reject"
        if case["op"] == "respond-reject":
            assert case["outputs"] == {"opks_post": [] if row["name"] == "R3" else [42]}
        else:
            assert "outputs" not in case


def test_invitee_rejections_are_the_named_manipulation(doc, run):
    c = _cases(doc)
    honest_inv = _b(c["hx-0003"]["outputs"]["invitation"])
    honest_ld = _b(c["hx-0004"]["outputs"]["linkdata"])
    diffs = {"inv-expired": None, "inv-kind-multi": [1], "inv-ver": [0]}
    for case in [x for x in doc["cases"] if x["op"] == "invitee-reject"]:
        m, x = case["manipulation"], case["inputs"]
        if m in diffs:
            assert x["uri"] == inv.uri_encode(_b(x["invitation"]))
            changed = [k for k in range(len(honest_inv)) if honest_inv[k] != _b(x["invitation"])[k]]
            if diffs[m] is not None:
                assert changed == diffs[m]
            else:                                                # expires is the last field (u64)
                assert changed and min(changed) >= len(honest_inv) - 8
                assert int.from_bytes(_b(x["invitation"])[-8:], "big") == 1_700_000_099
            continue
        blob = _b(x["blob"])
        assert len(blob) == 12360 and blob[:24] == _b(x["n"])
        if m == "ld-wrong-key":
            v = enc.decode("InvitationV1", honest_inv)
            k = _hkdf(v["ld_id"], flip(v["link_key"], 0), b"SecMP-INV/1 linkdata")
            assert inv.open_blob(k, v["ld_id"], blob) == enc.iso_pad(honest_ld, 12288)
            continue
        ld = _b(x["linkdata"])
        changed = [k for k in range(len(honest_ld)) if honest_ld[k] != ld[k]]
        bundle_at = 1 + 2017
        if m == "ld-fp-mismatch":
            assert changed and max(changed) < bundle_at
        elif m == "ld-bad-sig":
            assert changed == [bundle_at + 7775 - 1] and honest_ld[changed[0]] ^ ld[changed[0]] == 1
        elif m == "ld-bad-sig-ed":
            sig_at = bundle_at + 7775 - 3373
            assert changed == [sig_at] and honest_ld[sig_at] ^ ld[sig_at] == 1
            lv = enc.decode("LinkDataV1", enc.iso_pad(ld, 12288))          # R' is still a point: decodes
            iks, b = lv["inviter_iks"], lv["bundle"]
            msg = hx.bundle_message(b, iks["ik_dh"])
            m_hash = H(labels.HYBRIDSIGN + labels.HX_BUNDLE + msg)
            primitives.ml_dsa_65_verify(iks["ik_mldsa65"], m_hash, b["sig"][64:], labels.HX_BUNDLE)   # ML-DSA holds
            with pytest.raises(Reject):
                primitives.ed25519_verify(iks["ik_ed25519"], m_hash, b["sig"][:64])            # Ed25519 fails
        elif m == "ld-bundle-expired":
            expiry_at = bundle_at + 1 + 4 + 32 + 1568 + 1184
            assert int.from_bytes(ld[expiry_at: expiry_at + 8], "big") == 1_700_000_099
            assert all(expiry_at <= k < expiry_at + 8 or k >= bundle_at + 7775 - 3373 for k in changed)
        elif m == "ld-opk-absent":
            present_at = bundle_at + 1 + 4 + 32 + 1568 + 1184 + 8
            assert ld[present_at] == 0
            assert all(k == present_at or k >= bundle_at + 7775 - 3373 for k in changed)


def test_responder_rejections_are_the_named_manipulation(doc):
    c = _cases(doc)
    i = c["hx-0006"]["outputs"]
    cells = [i["cell_0"], i["cell_1"], i["cell_2"]]
    k_inv, k_id, iks_i, first_msg = _b(i["k_inv"]), _b(i["k_id"]), _b(c["hx-0002"]["outputs"]["iks"]), _b(i["first_msg"])
    ld_id = enc.decode("InvitationV1", _b(c["hx-0003"]["outputs"]["invitation"]))["ld_id"]

    def plain(cell):
        cell = _b(cell)
        try:
            return caead.open(k_inv, cell[:24], b"SecMP-HX/1 initcell" + ld_id, cell[24:])
        except Reject:
            return None

    outer = _b(i["outer"])
    for case in [x for x in doc["cases"] if x["op"] == "respond-reject" and x["id"] <= "hx-0030"]:
        m, x = case["manipulation"], case["inputs"]
        fetched = x["fetched"]
        if m == "replay":
            assert fetched == cells
        elif m == "tampered-chunk":
            assert fetched[0::2] == cells[0::2] and _b(fetched[1]) == flip(_b(cells[1]), -1)
            assert plain(fetched[1]) is None
        elif m in ("total-not-3", "idx-dup"):
            k = 0 if m == "total-not-3" else 1
            assert [f for j, f in enumerate(fetched) if j != k] == [f for j, f in enumerate(cells) if j != k]
            pt, honest = plain(fetched[k]), plain(cells[k])
            assert pt[:16] == honest[:16] and pt[18:] == honest[18:]
            assert pt[16:18] == (bytes([0, 2]) if m == "total-not-3" else bytes([0, 3]))
        else:                                                    # the outer was re-sealed
            new = _b(x["outer"])
            pts = [plain(f) for f in fetched]
            assert all(p[:16] == _b(x["init_id"]) for p in pts)
            assert b"".join(p[18:] for p in pts) == new + b"\x80" + bytes(12018 - 9363)
            changed = [k for k in range(9362) if new[k] != outer[k]]
            field = {"opk-unknown": range(37, 41), "spk-unknown": range(33, 37), "zero-ek": range(1, 33),
                     "ct-spk-flip": [41], "inner-tag-flip": [9361]}
            if m in field:
                assert changed and all(k in field[m] for k in changed)
                continue
            # the inner was re-sealed: only inner_ct differs, and it opens under K_id to `inner`
            inner, inner_ct = _b(x["inner"]), new[9362 - 6185:]
            assert min(changed) >= 9362 - 6185 and inner_ct[:24] == _b(x["inner_nonce"])
            assert caead.open(k_id, inner_ct[:24], b"SecMP-HX/1 inner" + ld_id, inner_ct[24:]) == inner
            if m == "low-order-ik-dh":
                assert inner == iks_i[:-32] + hx_cases.LOW_ORDER + first_msg
            elif m == "first-msg-flip":
                assert inner == iks_i + flip(first_msg, -1)
            elif m == "first-msg-not-handshake":                 # a Batch as first_msg (Weisung REF-M4-1)
                assert inner[:2017] == iks_i and inner[2017:2041] == _b(x["hdr_nonce"])
                v = enc.decode("Content", enc.iso_pad(_b(x["content"]), sizes.BODY_LEN))
                assert (v["ver"], v["type"], v["seq"], v["ts"]) == (1, 0x02, 1, 1_700_000_001)
                assert v["body"] == {"count": 1, "messages": [{"msg_id": _b(x["msg_id"]), "kind": 1, "expire_after": 0,
                                                              "payload_len": 8, "payload": _b(x["payload"])}]}
            else:                                                # caps-nonzero: a new first_msg, same position
                assert m == "caps-nonzero" and inner[:2017] == iks_i and inner[2017:2041] == _b(x["hdr_nonce"])
                content = _b(x["content"])
                assert content[:20] == _b(i["content"])[:20] and content[20 + 39: 20 + 43] == (1).to_bytes(4, "big")
                assert [k for k in range(len(content)) if content[k] != _b(i["content"])[k]] == [20 + 42]


def test_low_order_constant():
    assert hx_cases.LOW_ORDER in enc.x25519_low_order_encodings()
    with pytest.raises(Reject):
        primitives.x25519(bytes(range(32)), hx_cases.LOW_ORDER)


# ---------------------------------------------------------------------------------------------
# The responder on its own


def test_respond_is_transactional_and_first_complete_group_wins(run):
    ctx = run.ctx
    r = ctx.fresh_responder()
    c0, c1, c2 = ctx.env.cells
    with pytest.raises(Reject):
        hx.respond(r, [c0, c2], CaseStream("hx-unit-1", 1))
    assert hx.last_rule == "no-complete-envelope" and sorted(r.prekeys.opks) == [42]
    acc = hx.respond(r, [c2, c2, c1, c0, c0], CaseStream("hx-unit-1", 2))     # order and duplicates do not matter
    assert acc.sk == ctx.start.sk and sorted(r.prekeys.opks) == []
    with pytest.raises(Reject):
        hx.respond(r, [c0, c1, c2], CaseStream("hx-unit-1", 3))
    assert hx.last_rule == "opk-used"


def test_validator_rejects_bad_hx_documents():
    good = vectorfile.suite_document("hx", [
        Case(1, "invite", {"relay_fp": b"\x01"}, {"invitation": b"\x02", "uri": "secmp://i/AQ", "inv_sid": b"\x06",
                                                  "invq_recv_pk": b"\x07", "owner_pk": b"\x08"}, {"party": "R"}),
        Case(2, "invitee-accept", {}, {"k_ld": b"", "k_inv": b"", "accept": True}, {"party": "I"}),
        Case(3, "respond", {"fetched": [b"\x03"]}, {k: b"" for k in vectorfile._HX_RESPOND_OUT - {"routes", "opks_post"}}
             | {"routes": [b"\x04"], "opks_post": []}, {"party": "R"}),
        Case(4, "invitee-reject", {"n": b"\x05"}, None, {"party": "I", "manipulation": "inv-ver"}),
        Case(5, "respond-reject", {"fetched": []}, {"opks_post": [42]},
             {"party": "R", "manipulation": "replay", "expect": "reject"}),
    ])
    vectorfile.validate_document(good)
    for mutate in [
        lambda d: d["cases"][0].update(party="I"),
        lambda d: d["cases"][0]["outputs"].update(uri=7),
        lambda d: d["cases"][1]["outputs"].update(accept=1),
        lambda d: d["cases"][2]["inputs"].update(fetched="03"),
        lambda d: d["cases"][2]["outputs"].update(opks_post=[True]),
        lambda d: d["cases"][2]["outputs"].pop("routes"),
        lambda d: d["cases"][3].update(outputs={}),
        lambda d: d["cases"][3].pop("manipulation"),
        lambda d: d["cases"][4].pop("outputs"),
        lambda d: d["cases"][4].update(expect="accept"),
        lambda d: d["cases"][4].update(op="respond-garbage"),
        lambda d: d.update(schema=4),
    ]:
        d = json.loads(json.dumps(good))
        mutate(d)
        with pytest.raises(ValueError):
            vectorfile.validate_document(d)


# ---------------------------------------------------------------------------------------------
# Weisung REF-M5-2: derived inv_sid, the rev 2.5 cases, RF-1


def test_inv_sid_is_derived_and_the_old_draw_is_discarded(doc):
    c = _cases(doc)["hx-0003"]
    x, o = c["inputs"], c["outputs"]
    stream = CaseStream("hx", 3)
    expected = [stream.take(n) for n in (32, 32, 32, 16, 32, 16, 32, 32, 32)]
    names = ["relay_fp", "onion_pubkey", "akc", "ld_id", "link_key", "inv_sid_discarded", "inv_send_seed",
             "invq_recv_seed", "owner_seed"]
    assert set(x) == set(names) and [_b(x[n]) for n in names] == expected
    recv_pk = primitives.ed25519_public(_b(x["invq_recv_seed"]))
    send_pk = primitives.ed25519_public(_b(x["inv_send_seed"]))
    sid = H(b"SecMP-Q/1 sid" + recv_pk + send_pk)[:16]                      # §9.1
    assert _b(o["invq_recv_pk"]) == recv_pk and _b(o["owner_pk"]) == primitives.ed25519_public(_b(x["owner_seed"]))
    assert _b(o["inv_sid"]) == sid and sid != _b(x["inv_sid_discarded"])
    v = enc.decode("InvitationV1", _b(o["invitation"]))
    assert v["inv_sid"] == sid and v["inv_send_seed"] == _b(x["inv_send_seed"])


def _responder_tr_args(run):
    ctx = run.ctx
    return ctx.start.sk, ctx.start.transcript, ctx.prekeys.spk_dh, ctx.prekeys.rpk_kem


def test_rev_2_5_cases_from_the_file(doc, run):
    c = _cases(doc)
    cells = [c["hx-0006"]["outputs"][f"cell_{k}"] for k in range(3)]
    same = {k: c["hx-0007"]["outputs"][k] for k in ("transcript", "sk", "k_id", "peer_iks", "content")}
    # A1: a rejected complete group first, then case 6's honest group
    a1 = c["hx-0031"]
    assert a1["inputs"]["fetched"][3:] == cells and len(a1["inputs"]["fetched"]) == 6
    assert {k: a1["outputs"][k] for k in same} == same and a1["outputs"]["opks_post"] == []
    assert a1["outputs"]["state_post_R"] != c["hx-0007"]["outputs"]["state_post_R"]       # other DH-step draws
    k_inv, ld_id = run.ctx.start.k_inv, run.ctx.record.ld_id
    first = [hx.open_cell(k_inv, ld_id, _b(f)) for f in a1["inputs"]["fetched"][:3]]
    assert len({p["init_id"] for p in first}) == 1 and first[0]["init_id"] != run.ctx.env.init_id
    # R14: the first-seen chunk 1 differs, the group completes with it
    r14 = c["hx-0032"]["inputs"]["fetched"]
    assert r14[1:4] == cells and r14[4:] == cells and r14[0] != cells[1]
    pts = [hx.open_cell(k_inv, ld_id, _b(f)) for f in r14]
    assert len({p["init_id"] for p in pts}) == 1 and pts[0]["i"] == 1 and pts[0]["chunk"] != pts[2]["chunk"]
    # R15 / R16: the first_msg header
    for cid, (n, pn) in (("hx-0033", (1, 0)), ("hx-0034", (0, 1))):
        first_msg = _b(c[cid]["inputs"]["inner"])[2017:]
        state = tr.init_responder(*_responder_tr_args(run))
        hdr_nonce, hdr_ct, _ = tr.split(first_msg)
        header = tr.open_header(run.ctx.start.transcript, state.nhk_r, hdr_nonce, hdr_ct)
        assert (header["n"], header["pn"]) == (n, pn)
    # R17: IKSPublic_I = IKSPublic_R
    assert _b(c["hx-0035"]["inputs"]["inner"])[:2017] == _b(c["hx-0001"]["outputs"]["iks"])
    # R18: one route of kind 0x7F
    content = enc.decode("Content", enc.iso_pad(_b(c["hx-0036"]["inputs"]["content"]), sizes.BODY_LEN))
    assert [r["kind"] for r in content["body"]["routes"]] == [0x7F]
    assert content["body"]["routes"][0]["blob"] == _b(c["hx-0036"]["inputs"]["route_blob"])
    for cid in ("hx-0032", "hx-0033", "hx-0034", "hx-0035", "hx-0036"):
        assert c[cid]["expect"] == "reject" and c[cid]["outputs"] == {"opks_post": [42]}
    # A2 (RF-1): the older SPK is retained; the keys are case 7's
    a2 = c["hx-0037"]
    assert {k: a2["outputs"][k] for k in same} == same and a2["outputs"]["opks_post"] == []
    assert a2["inputs"]["fetched"] == cells


def test_respond_group_rules(run):
    ctx = run.ctx
    k_inv, ld_id = ctx.start.k_inv, ctx.record.ld_id

    def group(n):
        return list(hx.seal_cells(k_inv, ld_id, ctx.env.outer, bytes([n]) * 16,
                                  [bytes([n, k]) * 12 for k in range(3)]))

    # at most 8 partial groups: the oldest is evicted by a ninth, so its later chunks do not complete it
    g0 = group(0)
    others = [group(n)[0] for n in range(1, 9)]
    r = ctx.fresh_responder()
    with pytest.raises(Reject):
        hx.respond(r, [g0[0], *others, g0[1], g0[2]], CaseStream("hx-unit-2", 1))
    assert hx.last_rule == "no-complete-envelope" and sorted(r.prekeys.opks) == [42]
    r = ctx.fresh_responder()                      # with seven others g0 stays stored and completes: accepted
    assert hx.respond(r, [g0[0], *others[:7], g0[1], g0[2]], CaseStream("hx-unit-2", 2)).init_id == bytes(16)


def test_retained_spk_must_match_the_invitation(run):
    ctx = run.ctx
    old = ctx.prekeys
    rng = CaseStream("hx-unit-3", 1)
    new = dataclasses.replace(old, spk_id=8, spk_dh=tr.DhKey.from_secret(rng.take(32)),
                              spk_kem=hx.Kem1024Key.from_seed(rng.take(64)), rpk_kem=tr.KemKey.from_seed(rng.take(64)),
                              opks=dict(old.opks))
    retained = hx.Spk(7, old.spk_dh, old.spk_kem, old.rpk_kem, old.spk_expiry)
    gone = hx.Responder(ctx.r, new, ctx.record)       # the old generation is not retained
    with pytest.raises(Reject):
        hx.respond(gone, list(ctx.env.cells), CaseStream("hx-unit-3", 2))
    assert hx.last_rule == "prekey-ids" and sorted(new.opks) == [42]
    kept = hx.Responder(ctx.r, dataclasses.replace(new, retained={7: retained}), ctx.record)
    assert hx.respond(kept, list(ctx.env.cells), CaseStream("hx-unit-3", 3)).sk == ctx.start.sk
