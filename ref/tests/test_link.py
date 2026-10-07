# SPDX-License-Identifier: AGPL-3.0-or-later
"""SecMP-LINK (spec §8), SecMP-Q (spec §9) and the `link` suite (SCHEMA §4.11, brief REF-M5).

The vector checks recompute the file's values with the spec formulas from the primitives directly
(hashlib, HMAC, X25519, ML-KEM, XChaCha20-Poly1305), not through `link`/`relay`.
"""

import copy
import hashlib
import hmac
import json

import nacl.bindings
import pytest

import gen_vectors
from secmp_ref import encodings as enc
from secmp_ref import link, link_cases, primitives, relay, sizes, vectorfile
from secmp_ref.errors import Reject
from secmp_ref.vectorfile import Case, CaseStream, flip

H = primitives.sha256
LINK_CR = vectorfile.LINK_CR_OPS


@pytest.fixture(scope="module")
def run():
    return link_cases.run()


@pytest.fixture(scope="module")
def doc():
    return json.loads(gen_vectors.suite_bytes("link"))


def _cases(doc):
    return {c["id"]: c for c in doc["cases"]}


def _b(x):
    return bytes.fromhex(x)


def _hmac(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()


def _sha3(x):
    return hashlib.sha3_256(x).digest()


def _combiner(ss_kem, ss_dh, ct, ek, pk_dh, pk_e, v):
    """§3.2: SHA3-256(ss_kem ‖ ss_dh ‖ SHA3-256(ct_kem) ‖ SHA3-256(ek_kem) ‖ pk_dh ‖ pk_e ‖ V)."""
    return _sha3(ss_kem + ss_dh + _sha3(ct) + _sha3(ek) + pk_dh + pk_e + v)


def _hkdf_expand(prk, info, n):
    """RFC 5869 §2.3, written out."""
    out, t, k = b"", b"", 1
    while len(out) < n:
        t = _hmac(prk, t + info + bytes([k]))
        out, k = out + t, k + 1
    return out[:n]


def _seal(key, counter, sess_id, payload):
    pt = payload + b"\x80" + bytes(sizes.FRAME_PLAINTEXT - len(payload) - 1)
    nonce = bytes(16) + counter.to_bytes(8, "big")
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(pt, b"SecMP-LINK/1 frame" + sess_id, nonce, key)


class Replay:
    """A stream that hands out given values in order (to replay a case's inputs)."""

    def __init__(self, *values):
        self.values = list(values)

    def take(self, n):
        v = self.values.pop(0)
        assert len(v) == n
        return v


# ---------------------------------------------------------------------------------------------
# The file


def test_case_counts_and_order(run, doc):
    ops = [c["op"] for c in doc["cases"]]
    assert len(ops) == 86
    assert ops[:5] == ["relay-keys", "relayinfo-accept", "hs1", "hs2", "hs2-accept"]
    assert all(op in LINK_CR for op in ops[5:50]) and ops[50] == "indist"
    assert ops[51:59] == ["relayinfo-reject"] * 7 + ["relayinfo-accept"]
    assert ops[59:70] == ["hs1-reject"] * 11 and ops[70:74] == ["hs2-reject"] * 4 and ops[74:] == ["frame-reject"] * 12
    errors = [c for c in doc["cases"][:50] if "manipulation" in c]
    assert len(errors) == 23 and len(doc["cases"][:50]) - len(errors) == 27
    assert sum(c.get("expect") == "reject" for c in doc["cases"]) == 34
    assert [c["id"] for c in doc["cases"]] == [f"link-{i:04d}" for i in range(1, 87)]


def test_inputs_are_the_case_stream_in_order(run):
    for c, row in zip(run.cases, run.rows):
        layout = row.get("stream") if "stream" in row else getattr(row.get("ev"), "stream", [])
        s = CaseStream("link", c.i)
        names = [name for name, _ in layout]
        for name, size in layout:
            assert c.inputs[name] == s.take(size), (c.i, name)
        assert list(c.inputs)[:len(names)] == names


def test_written_file_is_current_canonical_and_valid():
    path = gen_vectors.VECTORS_DIR / "link.json"
    data = path.read_bytes()
    assert data == gen_vectors.suite_bytes("link")
    d = json.loads(data)
    vectorfile.validate_document(d)
    assert vectorfile.canonical_json(d) == data and data.isascii() and not data.endswith(b"\n")
    assert (d["schema"], d["suite"], d["spec"], d["generator"]) == (6, "link", "SecMP/1 rev 2.3", "ref-python")


def test_schema_4_11_is_rendered_from_this_table():
    from tools import render_schema_4_11
    assert render_schema_4_11.OUT.read_text(encoding="utf-8") == render_schema_4_11.render()


# ---------------------------------------------------------------------------------------------
# The handshake, recomputed from the spec formulas


def test_relay_keys_and_relayinfo(doc):
    c = _cases(doc)["link-0001"]
    i, o = {k: _b(v) for k, v in c["inputs"].items()}, {k: _b(v) for k, v in c["outputs"].items()}
    pk = nacl.bindings.crypto_sign_seed_keypair(i["relay_sig_seed"])[0]
    ek, _ = primitives.ml_kem_keygen(1024, i["relay_kem_seed"])
    assert o["relay_sig_pk"] == pk and o["relay_fp"] == H(b"SecMP-LINK/1 relay-fp" + pk)
    assert o["relay_dh_pk"] == nacl.bindings.crypto_scalarmult_base(i["relay_dh_sk"]) and o["relay_kem_ek"] == ek
    assert o["akc"] == H(b"SecMP-Q/1 akc" + i["relay_access_key"])
    head = (b"\x01" + pk + (1).to_bytes(4, "big") + o["relay_dh_pk"] + ek + o["akc"]
            + link_cases.VALID_UNTIL.to_bytes(8, "big"))
    assert len(head) == 1677 and o["relayinfo"][:1677] == head and len(o["relayinfo"]) == 1741
    nacl.bindings.crypto_sign_open(o["relayinfo"][1677:] + b"SecMP-LINK/1 relayinfo" + head, pk)
    assert o["rec_relayinfo"] == (1742).to_bytes(2, "big") + b"\x02" + o["relayinfo"]
    assert _cases(doc)["link-0002"]["outputs"] == {"rec_hello": "0007" + b"\x01SECMP\x01".hex(), "accept": True}


def test_handshake_recomputed_from_the_spec_formulas(doc):
    cs = _cases(doc)
    r = {k: _b(v) for k, v in cs["link-0001"]["outputs"].items()}
    i3, o3 = ({k: _b(v) for k, v in cs["link-0003"][f].items()} for f in ("inputs", "outputs"))
    e_c = nacl.bindings.crypto_scalarmult_base(i3["e_c_sk"])
    ek_c, _ = primitives.ml_kem_keygen(768, i3["ek_c_seed"])
    pk_e1 = nacl.bindings.crypto_scalarmult_base(i3["sk_e1"])
    ct_kem, ss_kem = primitives.ml_kem_encaps(1024, r["relay_kem_ek"], i3["m1"])
    ss1 = _combiner(ss_kem, nacl.bindings.crypto_scalarmult(i3["sk_e1"], r["relay_dh_pk"]), ct_kem, r["relay_kem_ek"],
                    r["relay_dh_pk"], pk_e1, b"SecMP-HybridKEM-1024/1")
    h0 = H(b"SecMP-LINK/1 h0" + b"\x01" + (1).to_bytes(4, "big") + r["relay_fp"] + e_c + H(ek_c) + pk_e1 + H(ct_kem))
    ck1 = _hmac(h0, ss1)                          # HKDF-Extract(salt, IKM) = HMAC(salt, IKM)
    mac1 = _hmac(ck1, b"SecMP-LINK/1 hs1")
    hs1 = b"\x01" + (1).to_bytes(4, "big") + e_c + ek_c + pk_e1 + ct_kem + mac1
    assert (o3["e_c"], o3["ek_c"], o3["pk_e1"], o3["ct_kem"], o3["ss1"], o3["h0"], o3["ck1"], o3["mac1"], o3["hs1"]) == \
        (e_c, ek_c, pk_e1, ct_kem, ss1, h0, ck1, mac1, hs1)
    assert len(hs1) == 2853 and o3["rec_hs1"] == (2854).to_bytes(2, "big") + b"\x03" + hs1

    i4, o4 = ({k: _b(v) for k, v in cs["link-0004"][f].items() if f == "inputs" or k != "link_post"}
              for f in ("inputs", "outputs"))
    e_r = nacl.bindings.crypto_scalarmult_base(i4["sk_er"])
    ct_c, ss_kem2 = primitives.ml_kem_encaps(768, ek_c, i4["m2"])
    ss2 = _combiner(ss_kem2, nacl.bindings.crypto_scalarmult(i4["sk_er"], e_c), ct_c, ek_c, e_c, e_r,
                    b"SecMP-HybridKEM-768/1")
    h1 = H(h0 + mac1 + e_r + H(ct_c))
    ck2 = _hmac(h1, ck1 + ss2)
    mac2 = _hmac(ck2, b"SecMP-LINK/1 hs2")
    keys = _hkdf_expand(ck2, b"SecMP-LINK/1 keys", 80)
    hs2 = b"\x01" + e_r + ct_c + mac2
    assert (o4["ss1"], o4["h0"], o4["ck1"]) == (ss1, h0, ck1)
    assert (o4["e_r"], o4["ct_c"], o4["ss2"], o4["h1"], o4["ck2"], o4["mac2"], o4["hs2"]) == \
        (e_r, ct_c, ss2, h1, ck2, mac2, hs2)
    assert (o4["k_c2r"], o4["k_r2c"], o4["sess_id"]) == (keys[:32], keys[32:64], keys[64:])
    assert len(hs2) == 1153 and o4["rec_hs2"] == (1154).to_bytes(2, "big") + b"\x04" + hs2
    o5 = cs["link-0005"]["outputs"]
    assert {k: o5[k] for k in ("ss2", "h1", "ck2", "k_c2r", "k_r2c", "sess_id")} == \
        {k: cs["link-0004"]["outputs"][k] for k in ("ss2", "h1", "ck2", "k_c2r", "k_r2c", "sess_id")}
    assert cs["link-0004"]["outputs"]["link_post"] == o5["link_post"] == {"c2r": 0, "r2c": 0, "cmd_seq": 0}


def test_the_relay_draws_nothing_before_mac1(run):
    """Reading OPEN-2: hs1_accept on a bad mac1 draws nothing (a Replay with no values would fail)."""
    ctx = run.ctx
    v = enc.decode("Record/HS1", ctx.chs.record)
    bad = enc.raw("Record/HS1", {**v, "mac1": flip(v["mac1"], 0)})
    with pytest.raises(Reject):
        link.hs1_accept(ctx.keys, bad, Replay())


# ---------------------------------------------------------------------------------------------
# Link A, recomputed


def _link_a(doc):
    return [c for c in doc["cases"][5:50] if c["op"] in LINK_CR]


def test_every_frame_is_the_spec_seal_and_the_counters_chain(doc):
    cs = _cases(doc)
    k = cs["link-0004"]["outputs"]
    k_c2r, k_r2c, sess = _b(k["k_c2r"]), _b(k["k_r2c"]), _b(k["sess_id"])
    post = {"c2r": 0, "r2c": 0, "cmd_seq": 0}
    for c in _link_a(doc):
        o = c["outputs"]
        if c["op"] == "send-fill":
            assert o["link_post"]["c2r"] - post["c2r"] == o["link_post"]["r2c"] - post["r2c"] == c["count"]
            post = o["link_post"]
            continue
        assert len(o["req"]) == len(o["req_frames"]) and len(o["resp"]) == len(o["resp_frames"])
        for n, (p, f) in enumerate(zip(o["req"], o["req_frames"])):
            assert _b(f) == _seal(k_c2r, post["c2r"] + n, sess, _b(p)), c["id"]
        for n, (p, f) in enumerate(zip(o["resp"], o["resp_frames"])):
            assert _b(f) == _seal(k_r2c, post["r2c"] + n, sess, _b(p)), c["id"]
        assert all(len(_b(f)) == 4352 for f in o["req_frames"] + o["resp_frames"])
        assert o["link_post"]["c2r"] == post["c2r"] + len(o["req"])
        assert o["link_post"]["r2c"] == post["r2c"] + len(o["resp"])
        assert _b(o["req"][0])[1:5] == c["cmd_seq"].to_bytes(4, "big")
        assert all(_b(p)[1:5] == _b(o["req"][-1])[1:5] for p in o["resp"])          # cmd_seq echoed
        post = o["link_post"]
    assert post == {"c2r": 180, "r2c": 222, "cmd_seq": 172}


def test_cmd_seq_and_counters_are_the_reviewers(doc):
    cs = _cases(doc)
    assert cs["link-0006"]["cmd_seq"] == 1 and cs["link-0008"]["outputs"]["link_post"] == {"c2r": 3, "r2c": 3,
                                                                                         "cmd_seq": 3}
    assert cs["link-0023"]["cmd_seq"] == 145 and cs["link-0022"]["cmd_seq"] == 143       # the gap
    assert cs["link-0020"]["cmd_seq"] == 15 and cs["link-0020"]["count"] == 127
    assert cs["link-0050"]["cmd_seq"] == 172 and cs["link-0050"]["outputs"]["link_post"]["cmd_seq"] == 172


def test_queue_ids_tokens_and_signatures(doc):
    cs = _cases(doc)
    access = _b(cs["link-0001"]["inputs"]["relay_access_key"])
    sess = _b(cs["link-0004"]["outputs"]["sess_id"])
    for cid in ("link-0006", "link-0015"):
        c = cs[cid]
        i, o = c["inputs"], c["outputs"]
        recv_pk = nacl.bindings.crypto_sign_seed_keypair(_b(i["recv_seed"]))[0]
        send_pk = nacl.bindings.crypto_sign_seed_keypair(_b(i["send_seed"]))[0]
        assert (_b(i["recv_pk"]), _b(i["send_pk"])) == (recv_pk, send_pk)
        assert _b(o["rid"]) == H(b"SecMP-Q/1 rid" + recv_pk)[:16]
        assert _b(o["sid"]) == H(b"SecMP-Q/1 sid" + recv_pk + send_pk)[:16]
        seq = c["cmd_seq"].to_bytes(4, "big")
        token = _hmac(access, b"SecMP-Q/1 token" + sess + seq)
        assert _b(o["token"]) == token
        msg = b"SecMP-Q/1 QUEUE_NEW" + sess + seq + recv_pk + send_pk + token
        nacl.bindings.crypto_sign_open(_b(o["sig"]) + msg, recv_pk)
        assert _b(o["req"][0]) == b"\x01" + seq + recv_pk + send_pk + token + _b(o["sig"])
        assert _b(o["resp"][0]) == b"\x81" + seq + _b(o["rid"]) + _b(o["sid"])
    # P18: two MFETCH signatures, in entry order (B ack 0, A ack 2)
    c = cs["link-0019"]
    req = _b(c["outputs"]["req"][0])
    seq = req[1:5]
    assert req[5] == 2 and len(req) == 6 + 2 * 88
    for k, (q, ack) in enumerate([("link-0015", 0), ("link-0006", 2)]):
        rid = _b(cs[q]["outputs"]["rid"])
        recv_pk = _b(cs[q]["inputs"]["recv_pk"])
        entry = req[6 + 88 * k: 6 + 88 * (k + 1)]
        assert entry[:24] == rid + ack.to_bytes(8, "big") and entry[24:] == _b(c["outputs"][f"sig_{k}"])
        nacl.bindings.crypto_sign_open(entry[24:] + b"SecMP-Q/1 MFETCH" + sess + seq + entry[:24], recv_pk)
    # P24: LINK_PUT signs SHA-256 of the whole blob; the blob is split 4160 + 4100 + 4100
    c = cs["link-0025"]
    i, o = {k: _b(v) for k, v in c["inputs"].items()}, c["outputs"]
    seq = c["cmd_seq"].to_bytes(4, "big")
    token = _hmac(access, b"SecMP-Q/1 token" + sess + seq)
    fields = i["ld_id"] + b"\x01" + (472_390).to_bytes(4, "big") + i["owner_pk"] + token
    nacl.bindings.crypto_sign_open(_b(o["sig"]) + b"SecMP-Q/1 LINK_PUT" + sess + seq + fields + H(i["blob"]),
                                   i["owner_pk"])
    assert [_b(p) for p in o["req"]] == [b"\x07" + seq + fields + _b(o["sig"]) + i["blob"][:4160],
                                         b"\x7f" + seq + b"\x01" + i["blob"][4160:8260],
                                         b"\x7f" + seq + b"\x02" + i["blob"][8260:]]


def _resp(case):
    return [_b(p) for p in case["outputs"]["resp"]]


def test_answers_carry_the_drawn_and_stored_bytes(doc):
    cs = _cases(doc)
    cells = [_b(cs[cid]["inputs"]["cell"]) for cid in ("link-0007", "link-0010", "link-0011")]
    p12, p13 = _resp(cs["link-0012"]), _resp(cs["link-0013"])
    for resp, dummy in ((p12, cs["link-0012"]["inputs"]["dummy_0"]), (p13, cs["link-0013"]["inputs"]["dummy_0"])):
        assert [(r[5], r[6:22], int.from_bytes(r[22:30], "big"), r[30:]) for r in resp] == \
            [(1, bytes(16), n + 1, cells[n]) for n in range(3)] + [(0, bytes(16), 0, _b(dummy))]
    assert [r[22:] for r in p12[:3]] == [r[22:] for r in p13[:3]]                 # FETCH idempotence
    e11 = _resp(cs["link-0038"])
    assert e11[0][5:30] == b"\x02" + _b(cs["link-0006"]["outputs"]["rid"]) + bytes(8)
    assert e11[0][30:] == _b(cs["link-0038"]["inputs"]["cell_r"])
    blob = _b(cs["link-0025"]["inputs"]["blob"])
    p26 = _resp(cs["link-0028"])
    assert p26[0][5:7] == b"\x01\x00" and p26[0][7:] + p26[1][6:] + p26[2][6:] == blob
    p25 = _resp(cs["link-0027"])
    assert p25[0][5:7] == b"\x01\x00" and p25[0][7:] + p25[1][6:] + p25[2][6:] == _b(cs["link-0027"]["inputs"]["dummy_blob"])
    assert _resp(cs["link-0029"])[0][5:7] == b"\x00\x01"
    assert _resp(cs["link-0021"]) == [b"\x82" + (142).to_bytes(4, "big") + (129).to_bytes(8, "big") + b"\x01"
                                      + (1).to_bytes(8, "big")]


def test_send_fill_summary_recomputed(doc):
    cs = _cases(doc)
    k = cs["link-0004"]["outputs"]
    k_c2r, k_r2c, sess = _b(k["k_c2r"]), _b(k["k_r2c"]), _b(k["sess_id"])
    b = cs["link-0015"]
    send_seed, sid = _b(b["inputs"]["send_seed"]), _b(b["outputs"]["sid"])
    _, sk = nacl.bindings.crypto_sign_seed_keypair(send_seed)
    c = cs["link-0020"]
    cell = _b(c["inputs"]["fill_cell"])
    h = hashlib.sha256()
    for n in range(c["count"]):
        seq = (15 + n).to_bytes(4, "big")
        sig = nacl.bindings.crypto_sign(b"SecMP-Q/1 SEND" + sess + seq + sid + cell, sk)[:64]
        resp = b"\x82" + seq + (2 + n).to_bytes(8, "big") + b"\x00" + bytes(8)
        h.update(_seal(k_c2r, 14 + n, sess, b"\x03" + seq + sid + cell + sig) + _seal(k_r2c, 30 + n, sess, resp))
    assert c["outputs"]["frames_sha256"] == h.hexdigest()
    assert _b(c["outputs"]["resp_last"]) == resp
    q = [x for x in c["outputs"]["store_post"]["queues"] if x["rid"] == b["outputs"]["rid"]][0]
    assert q["cell_ids"] == list(range(1, 129)) and q["next_cell_id"] == 129


def test_store_posts(doc):
    cs = _cases(doc)
    rid_a, rid_b = cs["link-0006"]["outputs"]["rid"], cs["link-0015"]["outputs"]["rid"]

    def queues(cid):
        return {q["rid"]: (q["cell_ids"], q["next_cell_id"]) for q in cs[cid]["outputs"]["store_post"]["queues"]}

    assert queues("link-0006") == {rid_a: ([], 1)} and queues("link-0009") == {rid_a: ([1], 2)}
    assert queues("link-0014") == {rid_a: ([3], 4)}
    assert queues("link-0018") == {rid_a: ([3, 4], 5), rid_b: ([1], 2)}
    assert queues("link-0021") == {rid_a: ([3, 4], 5), rid_b: (list(range(2, 130)), 130)}
    assert queues("link-0024") == {rid_b: (list(range(2, 130)), 130)}
    ld = cs["link-0025"]["inputs"]["ld_id"]
    assert cs["link-0025"]["outputs"]["store_post"]["linkdata"] == [
        {"ld_id": ld, "one_time": 1, "expires_bucket": 472_390, "present": 1, "consumed": 0}]
    assert cs["link-0028"]["outputs"]["store_post"]["linkdata"] == [
        {"ld_id": ld, "one_time": 1, "expires_bucket": 472_390, "present": 0, "consumed": 1}]
    for n in range(6, 51):                        # a command error changes nothing in the store
        c = cs[f"link-{n:04d}"]
        if "manipulation" in c:
            assert c["outputs"]["store_post"] == cs[c["from"]]["outputs"]["store_post"], c["id"]


def test_x1_counts_are_the_response_frames(doc):
    cs = _cases(doc)
    x = cs["link-0051"]
    assert x["outputs"]["resp_counts"] == [[len(cs[cid]["outputs"]["resp_frames"]) for cid in g] for g in x["cases"]]
    assert x["outputs"]["resp_counts"] == link_cases.X1_COUNTS and x["outputs"]["frame_len"] == 4352
    for g in x["cases"]:
        assert len({cs[cid]["op"] for cid in g} - {"skey", "ping"}) <= 1


# ---------------------------------------------------------------------------------------------
# The rejections, replayed from the file


def test_relayinfo_cases_from_the_file(doc, run):
    cs = _cases(doc)
    keys = run.ctx.keys
    for n in range(52, 60):
        c = cs[f"link-{n:04d}"]
        rec = _b(c["inputs"]["rec_relayinfo"])
        fp = _b(c["inputs"].get("relay_fp", keys.fp.hex()))
        if c["op"] == "relayinfo-accept":
            assert link.relayinfo_accept(rec, fp, keys.access_key, link_cases.NOW)["valid_until"] == \
                link_cases.NOW + link.MAX_VALIDITY
        else:
            with pytest.raises(Reject):
                link.relayinfo_accept(rec, fp, keys.access_key, link_cases.NOW)


def test_hs_rejections_from_the_file(doc, run):
    cs = _cases(doc)
    ctx = run.ctx
    for n in range(60, 70):
        c = cs[f"link-{n:04d}"]
        with pytest.raises(Reject):
            if "rec_hello" in c["inputs"]:
                link.hello_accept(_b(c["inputs"]["rec_hello"]))
            else:
                link.hs1_accept(ctx.keys, _b(c["inputs"]["rec_hs1"]), Replay())
    s10 = cs["link-0070"]
    hs2, new = link.hs1_accept(ctx.keys, _b(s10["inputs"]["rec_hs1"]),
                               Replay(_b(s10["inputs"]["sk_er"]), _b(s10["inputs"]["m2"])))
    assert hs2.record.hex() == s10["outputs"]["rec_hs2"] and hs2.sess_id.hex() == s10["outputs"]["sess_id"]
    assert s10["outputs"]["sess_id"] != cs["link-0004"]["outputs"]["sess_id"]
    assert s10["inputs"]["frame"] == cs["link-0006"]["outputs"]["req_frames"][0]
    with pytest.raises(Reject):
        new.open(_b(s10["inputs"]["frame"]))
    for n in range(71, 75):
        with pytest.raises(Reject):
            link.hs2_accept(ctx.chs, _b(cs[f"link-{n:04d}"]["inputs"]["rec_hs2"]))


def test_frame_rejections_from_the_file(doc, run):
    cs = _cases(doc)
    r8, c8 = run.ctx.after8
    for n in range(75, 87):
        c = cs[f"link-{n:04d}"]
        frame = _b(c["inputs"]["frame"])
        if c["party"] == "R":
            r = copy.deepcopy(r8)
            with pytest.raises(Reject):
                r.execute([frame], Replay())
            assert r == r8
        else:
            cl = copy.deepcopy(c8)
            with pytest.raises(Reject):
                relay.receive(cl, [frame], "QUEUE_NEW")
            assert cl == c8
        assert c["outputs"] == {"link_post": {"c2r": 3, "r2c": 3, "cmd_seq": 3}}
    assert len(_b(cs["link-0078"]["inputs"]["frame"])) == 4351 and len(_b(cs["link-0079"]["inputs"]["frame"])) == 4353
    # the base frame of F3 … F5 is link-0009's request frame, and it opens at R
    r = copy.deepcopy(r8)
    assert r.execute([_b(cs["link-0009"]["outputs"]["req_frames"][0])], Replay())


# ---------------------------------------------------------------------------------------------
# §8 units


def test_relayinfo_bounds(run):
    ctx = run.ctx
    keys = ctx.keys

    def rec(**edit):
        return link.relayinfo_record(link.sign_relayinfo(keys.sig_seed, {**ctx.info, **edit}))

    now = link_cases.NOW
    link.relayinfo_accept(rec(valid_until=now), keys.fp, keys.access_key, now)           # valid_until = now
    link.relayinfo_accept(rec(valid_until=now + link.MAX_VALIDITY), keys.fp, keys.access_key, now)
    with pytest.raises(Reject):
        link.relayinfo_accept(rec(valid_until=now + link.MAX_VALIDITY + 1), keys.fp, keys.access_key, now)
    with pytest.raises(Reject):
        link.relayinfo_accept(rec(valid_until=now - 1), keys.fp, keys.access_key, now)
    bad_akc = rec(akc=bytes(32))
    link.relayinfo_accept(bad_akc, keys.fp, None, now)                 # "akc (if it holds an access key)"
    with pytest.raises(Reject):
        link.relayinfo_accept(bad_akc, keys.fp, keys.access_key, now)


def test_frame_length_is_checked_before_the_aead(monkeypatch):
    calls = []
    monkeypatch.setattr(primitives, "xchacha20poly1305_open", lambda *a: calls.append(a))
    for n in (0, 16, 4351, 4353):
        with pytest.raises(Reject):
            link.open_frame(bytes(32), 0, bytes(16), bytes(n))
        assert link.last_rule == "frame-len"
    assert calls == []


def test_link_counters_are_strict_and_checked():
    a = link.Link(k_send=b"\x01" * 32, k_recv=b"\x02" * 32, sess_id=b"\x03" * 16)
    b = link.Link(k_send=b"\x02" * 32, k_recv=b"\x01" * 32, sess_id=b"\x03" * 16)
    f0, f1 = a.seal(b"\x09\x00\x00\x00\x01"), a.seal(b"\x09\x00\x00\x00\x02")
    with pytest.raises(Reject):
        b.open(f1)                                # skipped counter
    assert b.recv_ctr == 0 and b.open(f0) == b"\x09\x00\x00\x00\x01" and b.recv_ctr == 1
    with pytest.raises(Reject):
        b.open(f0)                                # replayed counter
    assert b.open(f1) == b"\x09\x00\x00\x00\x02"
    a.send_ctr = link.COUNTER_LIMIT - 1
    with pytest.raises(link.CounterOverflow):
        a.seal(b"\x09\x00\x00\x00\x03")


def test_unpad():
    assert link.unpad(b"ab\x80" + bytes(5)) == b"ab"
    assert link.unpad(b"\x80" + bytes(3)) == b""
    for bad in (bytes(8), b"ab\x81" + bytes(5), b"ab\x80\x01" + bytes(4), b"ab"):
        with pytest.raises(Reject):
            link.unpad(bad)


# ---------------------------------------------------------------------------------------------
# §9 units: behaviours the suite does not exercise (SQ-26 … SQ-28 and readings)


class Bed:
    """A relay on a fresh link with the suite's keys, and the matching client side."""

    def __init__(self, run, budget=None):
        ctx = run.ctx
        self.keys, self.sess = ctx.keys, b"\x5a" * 16
        k_c2r, k_r2c = b"\x11" * 32, b"\x22" * 32
        self.r = relay.Relay(self.keys, link.Link(k_r2c, k_c2r, self.sess), link_cases.NOW_BUCKET, budget)
        self.c = link.Link(k_c2r, k_r2c, self.sess)
        self.seq = 0

    def next(self):
        self.seq += 1
        return self.seq

    def send(self, payloads, context, rng=None):
        frames = [self.c.seal(p) for p in payloads]
        out = self.r.execute(frames, rng or Replay())
        return relay.receive(self.c, out, context)[1]

    def queue_new(self, recv_seed, send_seed, s=None):
        s = s or self.next()
        v = {"op": "QUEUE_NEW", "cmd_seq": s, "recv_pk": primitives.ed25519_public(recv_seed),
             "send_pk": primitives.ed25519_public(send_seed), "token": relay.token(self.keys.access_key, self.sess, s)}
        v["sig"] = relay.sign(recv_seed, "QUEUE_NEW", self.sess, v)
        return self.send([enc.payload("Request/QUEUE_NEW", v)], "QUEUE_NEW")

    def link_put(self, ld_id, owner_seed, blob, one_time=1, s=None):
        s = s or self.next()
        v = {"op": "LINK_PUT", "cmd_seq": s, "ld_id": ld_id, "one_time": one_time, "expires_bucket": 472_390,
             "owner_pk": primitives.ed25519_public(owner_seed), "token": relay.token(self.keys.access_key, self.sess, s)}
        v["sig"] = relay.sign(owner_seed, "LINK_PUT", self.sess, {**v, "blob": blob})
        parts = relay.blob_parts(blob)
        return [enc.payload("Request/LINK_PUT", {**v, "blob_part": parts[0]}),
                *(enc.payload("Request/CONT", {"op": "CONT", "cmd_seq": s, "idx": k, "data": parts[k]})
                  for k in (1, 2))]


def test_queue_del_of_an_unknown_rid_is_noqueue(run):
    bed = Bed(run)
    s = bed.next()
    v = {"op": "QUEUE_DEL", "cmd_seq": s, "rid": b"\x07" * 16}
    v["sig"] = relay.sign(b"\x01" * 32, "QUEUE_DEL", bed.sess, v)
    assert bed.send([enc.payload("Request/QUEUE_DEL", v)], "QUEUE_DEL") == [
        {"op": "ERR", "cmd_seq": s, "code": relay.ERR_NOQUEUE}]


def test_stale_cmd_seq_on_multi_frame_commands(run):
    """SQ-26 reading: one ERR 6, after the third frame for LINK_PUT; one frame for FETCH; nothing executed."""
    bed = Bed(run)
    bed.queue_new(b"\x01" * 32, b"\x02" * 32, s=5)
    put = bed.link_put(b"\x0b" * 16, b"\x03" * 32, b"\x44" * sizes.LINK_BLOB, s=5)
    frames = [bed.c.seal(p) for p in put]
    trace = bed.r.execute_trace(frames, Replay())
    assert [len(t) for t in trace] == [0, 0, 1]
    assert relay.receive(bed.c, trace[2], "LINK_PUT")[1] == [{"op": "ERR", "cmd_seq": 5, "code": 6}]
    assert bed.r.linkdata.entries == {} and bed.r.last == 5
    rid = relay.rid_of(primitives.ed25519_public(b"\x01" * 32))
    v = {"op": "FETCH", "cmd_seq": 4, "rid": rid, "ack": 0}
    v["sig"] = relay.sign(b"\x01" * 32, "FETCH", bed.sess, v)
    assert bed.send([enc.payload("Request/FETCH", v)], "FETCH") == [{"op": "ERR", "cmd_seq": 4, "code": 6}]


def test_anything_but_the_expected_cont_tears_down(run):
    """SQ-27 reading."""
    bed = Bed(run)
    put = bed.link_put(b"\x0b" * 16, b"\x03" * 32, b"\x44" * sizes.LINK_BLOB)
    other_seq = enc.payload("Request/CONT", {"op": "CONT", "cmd_seq": 9, "idx": 1, "data": bytes(4100)})
    for second in (put[2], other_seq, enc.payload("Request/PING", {"op": "PING", "cmd_seq": 2}),
                   b"\x02" + (2).to_bytes(4, "big")):
        b2 = copy.deepcopy(bed)
        before = copy.deepcopy(b2.r)
        relay.last_rule = None
        with pytest.raises(Reject):
            b2.r.execute([b2.c.seal(put[0]), b2.c.seal(second)], Replay())
        assert relay.last_rule == "cont-expected" and b2.r == before


def test_fetch_multi_with_more_errors_than_f_m(run):
    """SQ-28 reading: the first F_M error frames, in request order."""
    bed = Bed(run)
    s = bed.next()
    entries = [{"rid": bytes([k]) * 16, "ack": 0, "sig": relay.sign(b"\x01" * 32, "FETCH_MULTI", bed.sess,
                                                                     {"rid": bytes([k]) * 16, "ack": 0, "cmd_seq": s})}
               for k in range(1, 11)]
    v = {"op": "FETCH_MULTI", "cmd_seq": s, "count": 10, "entries": entries}
    rng = Replay(*[bytes([k]) * 4096 for k in range(8)])
    out = bed.send([enc.payload("Request/FETCH_MULTI", v)], "FETCH_MULTI", rng)
    assert [(x["present"], x["rid"]) for x in out] == [(2, bytes([k]) * 16) for k in range(1, 9)]


def test_link_data_markers_and_reusable_entries(run):
    bed = Bed(run)
    put = bed.link_put(b"\x0b" * 16, b"\x03" * 32, b"\x44" * sizes.LINK_BLOB)
    assert bed.send(put, "LINK_PUT")[0]["op"] == "OK"

    def get(ld_id, rng=None):
        s = bed.next()
        v = {"op": "LINK_GET", "cmd_seq": s, "ld_id": ld_id, "mode": "consume", "sig": bytes(64)}
        return bed.send([enc.payload("Request/LINK_GET", v)], "LINK_GET", rng)

    assert get(b"\x0b" * 16)[0]["present"] == 1
    again = bed.link_put(b"\x0b" * 16, b"\x03" * 32, b"\x55" * sizes.LINK_BLOB)
    assert bed.send(again, "LINK_PUT")[0] == {"op": "ERR", "cmd_seq": bed.seq, "code": relay.ERR_EXISTS}
    reusable = bed.link_put(b"\x0c" * 16, b"\x03" * 32, b"\x66" * sizes.LINK_BLOB, one_time=0)
    assert bed.send(reusable, "LINK_PUT")[0]["op"] == "OK"
    for _ in range(2):
        r = get(b"\x0c" * 16)
        assert (r[0]["present"], r[0]["consumed"]) == (1, 0) and r[0]["blob_part"] == b"\x66" * 4160


def test_budget_counts_queues_only(run):
    bed = Bed(run, budget=1)
    assert bed.queue_new(b"\x01" * 32, b"\x02" * 32)[0]["op"] == "OK_QUEUE_NEW"
    assert bed.queue_new(b"\x01" * 32, b"\x02" * 32)[0]["op"] == "OK_QUEUE_NEW"     # identical: idempotent
    assert bed.queue_new(b"\x03" * 32, b"\x04" * 32)[0] == {"op": "ERR", "cmd_seq": bed.seq, "code": relay.ERR_FULL}
    put = bed.link_put(b"\x0b" * 16, b"\x03" * 32, b"\x44" * sizes.LINK_BLOB)
    assert bed.send(put, "LINK_PUT")[0]["op"] == "OK"


# ---------------------------------------------------------------------------------------------
# The validator


def _good():
    return json.loads(gen_vectors.suite_bytes("link"))


@pytest.mark.parametrize("mutate", [
    lambda d: d["cases"][0].update({"from": "link-0001"}),                     # relay-keys has no `from`
    lambda d: d["cases"][1].pop("from"),
    lambda d: d["cases"][1].update({"from": "link-0005"}),                     # not an earlier case
    lambda d: d["cases"][5].pop("cmd_seq"),
    lambda d: d["cases"][5].update(cmd_seq=0),
    lambda d: d["cases"][5].update(party="C"),
    lambda d: d["cases"][5]["outputs"].update(req="00"),                       # not an array
    lambda d: d["cases"][5]["outputs"].update(req=[]),
    lambda d: d["cases"][5]["outputs"]["link_post"].update(c2r=-1),
    lambda d: d["cases"][5]["outputs"]["link_post"].pop("cmd_seq"),
    lambda d: d["cases"][5]["outputs"]["store_post"].update(queues=[{"rid": "00"}]),
    lambda d: d["cases"][1]["outputs"].update(accept=1),
    lambda d: d["cases"][19].pop("count"),
    lambda d: d["cases"][50].update(cases=[["link-0099"]]),
    lambda d: d["cases"][50]["outputs"].update(frame_len="4352"),
    lambda d: d["cases"][51].pop("expect"),
    lambda d: d["cases"][51].update(outputs={}),
    lambda d: d["cases"][74]["outputs"].update(extra="00"),
    lambda d: d["cases"][15].update(expect="reject"),
])
def test_validator_rejects_bad_link_documents(mutate):
    d = _good()
    vectorfile.validate_document(d)
    mutate(d)
    with pytest.raises(ValueError):
        vectorfile.validate_document(d)


def test_validator_accepts_the_shapes():
    case = Case(1, "relay-keys", {"relay_sig_seed": b"\x01"}, {"relay_fp": b"\x02"}, {"party": "R"})
    vectorfile.validate_document(vectorfile.suite_document("link", [case]))


def test_link_put_expires_bucket_range(run):
    """ADR-048 (o): now_bucket <= expires_bucket <= now_bucket + 720, else ERR 6 after the third frame, nothing
    stored. Check order: token, signature, range, ld_id."""
    now = link_cases.NOW_BUCKET
    assert relay.LINKDATA_TTL_BUCKETS == 720

    def put(expires, bad_sig=False, bad_token=False):
        bed = Bed(run)
        s = bed.next()
        tok = relay.token(bed.keys.access_key, bed.sess, s)
        v = {"op": "LINK_PUT", "cmd_seq": s, "ld_id": b"\x0b" * 16, "one_time": 1, "expires_bucket": expires,
             "owner_pk": primitives.ed25519_public(b"\x03" * 32), "token": flip(tok, 0) if bad_token else tok}
        blob = b"\x44" * sizes.LINK_BLOB
        v["sig"] = relay.sign(b"\x04" * 32 if bad_sig else b"\x03" * 32, "LINK_PUT", bed.sess, {**v, "blob": blob})
        parts = relay.blob_parts(blob)
        payloads = [enc.payload("Request/LINK_PUT", {**v, "blob_part": parts[0]}),
                    *(enc.payload("Request/CONT", {"op": "CONT", "cmd_seq": s, "idx": k, "data": parts[k]})
                      for k in (1, 2))]
        trace = bed.r.execute_trace([bed.c.seal(p) for p in payloads], Replay())
        assert [len(x) for x in trace] == [0, 0, 1]                         # one answer, after the third frame
        return relay.receive(bed.c, trace[2], "LINK_PUT")[1][0], bed

    for ok in (now, now + 720):
        resp, bed = put(ok)
        assert resp["op"] == "OK" and list(bed.r.linkdata.entries) == [b"\x0b" * 16]
    for bad in (now - 1, now + 721, 0, 2**32 - 1):
        resp, bed = put(bad)
        assert resp["code"] == relay.ERR_MALFORMED and bed.r.linkdata.entries == {}
    assert put(now - 1, bad_token=True)[0]["code"] == relay.ERR_TOKEN
    assert put(now - 1, bad_sig=True)[0]["code"] == relay.ERR_AUTH
    bed = Bed(run)                                 # the range comes before the ld_id check
    assert bed.send(bed.link_put(b"\x0b" * 16, b"\x03" * 32, b"\x44" * sizes.LINK_BLOB), "LINK_PUT")[0]["op"] == "OK"
    again = bed.send(bed.link_put(b"\x0b" * 16, b"\x03" * 32, b"\x55" * sizes.LINK_BLOB), "LINK_PUT")
    assert again[0]["code"] == relay.ERR_EXISTS
