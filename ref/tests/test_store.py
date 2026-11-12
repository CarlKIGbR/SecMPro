# SPDX-License-Identifier: AGPL-3.0-or-later
"""The `store` suite (ADR-053 items 1–8): every output of the generated table recomputed with its formula
written out here (not through secmp_ref.store), every reject rejected with the one uniform error, the
pre-KDF acceptance rule, and the four rev 2.7 labels prefix-free against labels.py."""

import json

import pytest

from secmp_ref import caead, identity, labels, primitives, store, store_cases, vectorfile
from secmp_ref.errors import Reject

DOC = json.loads(vectorfile.canonical_json(vectorfile.suite_document("store", store_cases.store_cases())))
CASES = {c["id"]: c for c in DOC["cases"]}
H = bytes.fromhex
PARAMS = (262144).to_bytes(4, "big") + (3).to_bytes(4, "big") + (4).to_bytes(4, "big")


def by_op(op):
    return [c for c in DOC["cases"] if c["op"] == op]


def test_header_and_validation():
    vectorfile.validate_document(DOC)
    assert (DOC["schema"], DOC["suite"], DOC["spec"], DOC["generator"]) == (8, "store", "SecMP/1 rev 2.7", "ref-python")
    assert [c["id"] for c in DOC["cases"]] == [f"store-{i:04d}" for i in range(1, 29)]


def test_keys_item_3_4():
    (c,) = by_op("keys")
    mk = H(c["inputs"]["mk"])
    for t in ("identity", "prekeys", "relays", "contacts", "sessions", "outbox", "messages", "invitations", "settings"):
        assert c["outputs"][f"k_{t}"] == primitives.hkdf(bytes(32), mk, f"SecMP-STORE/1 {t}".encode(), 32).hex()
    assert c["outputs"]["k_db"] == primitives.hkdf(bytes(32), mk, b"SecMP-STORE/1 db", 32).hex()


@pytest.mark.parametrize("c", by_op("wrap"), ids=lambda c: c["id"])
def test_wrap_item_1_2(c):
    i = c["inputs"]
    pw, salt, n, mk = H(i["passphrase"]), H(i["salt"]), H(i["n"]), H(i["mk"])
    kek = primitives.argon2id(pw, salt, t=3, m_kib=262144, p=4, length=32)
    ad = b"SecMP-STORE/1 wrap" + b"\x01" + salt + PARAMS
    wrap = b"\x01" + salt + PARAMS + n + caead.seal(kek, n, ad, mk)
    assert (c["outputs"]["kek"], c["outputs"]["wrap"]) == (kek.hex(), wrap.hex()) and len(wrap) == 133
    assert store.unwrap(pw, wrap) == mk


def test_passphrases_are_utf8():
    assert H(by_op("wrap")[1]["inputs"]["passphrase"]).decode("utf-8") == "Pässwört-Ω"


def test_seal_item_5_am1():
    expected = {"store-0008": 8, "store-0009": 17, "store-0010": 16, "store-0011": 24}
    keys = CASES["store-0001"]["outputs"]
    for c in by_op("seal"):
        i, o = c["inputs"], c["outputs"]
        rk = b"".join((p["int"].to_bytes(8, "big") if "int" in p else bytes([len(H(p["bytes"]))]) + H(p["bytes"]))
                      for p in i["row_key_parts"])
        ad = i["label"].encode() + bytes([len(i["column"])]) + i["column"].encode() + rk
        assert len(rk) == expected[c["id"]]
        assert i["k_t"] == keys["k_" + i["label"].split(" ")[1]]
        assert o["row_key"] == rk.hex() and o["ad"] == ad.hex()
        assert o["rec"] == (H(i["n"]) + caead.seal(H(i["k_t"]), H(i["n"]), ad, H(i["record"]))).hex()


def test_backup_item_6():
    (c,) = by_op("backup")
    i, o = c["inputs"], c["outputs"]
    salt, n1, mk, n, ident = (H(i[k]) for k in ("salt", "n_prime", "mk_bk", "n", "identity"))
    assert len(ident) == 97 and ident[0] == 1
    kek = primitives.argon2id(H(i["passphrase"]), salt, t=3, m_kib=262144, p=4, length=32)
    bwrap = n1 + caead.seal(kek, n1, b"SecMP-STORE/1 bwrap\x01" + salt + PARAMS, mk)
    body = ident + bytes(4) + bytes(2) + bytes(4)
    table = b"\x04" + b"".join(bytes([t]) + n_.to_bytes(4, "big") for t, n_ in ((1, 97), (2, 4), (3, 2), (4, 4)))
    header = b"\x01" + salt + PARAMS + bwrap + table
    k_bk = primitives.hkdf(bytes(32), mk, b"SecMP-STORE/1 backup", 32)
    file = b"SecMProbackup" + header + n + caead.seal(k_bk, n, b"SecMP-STORE/1 backup" + header, body)
    assert len(bwrap) == 104 and len(header) == 154
    assert o == {"kek_bk": kek.hex(), "bwrap": bwrap.hex(), "k_bk": k_bk.hex(), "header": header.hex(),
                 "body": body.hex(), "file": file.hex()}


def _attempt(c):
    i, op = c["inputs"], c["op"]
    if op == "wrap-reject":
        return store.unwrap(H(i["passphrase"]), H(i["wrap"]))
    if op == "backup-reject":
        return store.open_backup(H(i["passphrase"]), H(i["file"]))
    parts = [p["int"] if "int" in p else H(p["bytes"]) for p in i["row_key_parts"]]
    if "rec" not in i:
        return store.row_key(parts)
    return store.open_record(H(i["k_t"]), i["label"].encode(), i["column"], parts, H(i["rec"]))


REJECTS = [c for c in DOC["cases"] if c.get("expect") == "reject"]


def test_reject_count_and_shape():
    ops = [c["op"] for c in REJECTS]
    assert (ops.count("wrap-reject"), ops.count("seal-reject"), ops.count("backup-reject")) == (4, 5, 11)
    assert all("outputs" not in c for c in REJECTS)


@pytest.mark.parametrize("c", REJECTS, ids=lambda c: f"{c['id']}-{c['manipulation']}")
def test_every_reject_is_the_uniform_error(c):
    with pytest.raises(Reject) as e:
        _attempt(c)
    assert type(e.value) is Reject and str(e.value) == "reject"


def test_unacceptable_wraps_are_decided_before_the_kdf(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("KDF ran")
    store.kek.cache_clear()
    monkeypatch.setattr(primitives, "argon2id", boom)
    for c in REJECTS:
        if c["manipulation"] in ("ver=02", "params=65536,3,4", "drop-last") and c["op"] == "wrap-reject":
            with pytest.raises(Reject):
                _attempt(c)
    store.kek.cache_clear()


def test_ver_02_wrap_is_otherwise_valid():
    """The ver=02 wrap is honestly built: opened with its own header as AD it yields MK, so that the
    acceptance rule (not a broken tag) is what rejects it."""
    blob = H(CASES["store-0005"]["inputs"]["wrap"])
    base = CASES["store-0002"]["inputs"]
    kek = store.kek(H(base["passphrase"]), H(base["salt"]))
    assert blob[0] == 2
    assert caead.open(kek, blob[29:53], b"SecMP-STORE/1 wrap" + blob[:29], blob[53:]) == H(base["mk"])


def test_new_labels_are_prefix_free_against_labels_py():
    new = [labels.STORE_WRAP, labels.STORE_DB, labels.STORE_BACKUP, labels.STORE_BWRAP]
    assert new == [b"SecMP-STORE/1 wrap", b"SecMP-STORE/1 db", b"SecMP-STORE/1 backup", b"SecMP-STORE/1 bwrap"]
    assert all(x in labels.APPENDIX_A for x in new) and len(labels.APPENDIX_A) == 53    # ADR-053 item 7: 49 + 4
    others = [x for x in labels.APPENDIX_A if x not in new]
    for a in new:
        for b in others:
            assert not a.startswith(b) and not b.startswith(a)
        for b in new:
            assert a == b or not a.startswith(b)


def test_schema_4_12_is_rendered_from_this_table():
    from tools import render_schema_4_12
    assert render_schema_4_12.OUT.read_text(encoding="utf-8") == render_schema_4_12.render()
# ---- L7 (WEISUNG REF-M7-store3): the four backup sections are decoded (ADR-053 Appendix, Amendments 2 and 3)
B16 = CASES["store-0016"]["inputs"]
IDENT = H(B16["identity"])
IKS = identity.iks_public_from_seeds(bytes([1]) * 32, bytes([2]) * 32, bytes([3]) * 32)
ONE = (1).to_bytes(4, "big")
SETTINGS_OK = b"\x00\x01\x0eretention_days\x00\x04" + (30).to_bytes(4, "big")
def _contact(verified=b"\x01", local=b"\x03Bob", profile=b"\x04peer\x00", iks=IKS):
    return iks + verified + profile + local
def _message(direction=b"\x01", kind=b"\x01", index=0, ts=1_800_000_000_000, expire_after=0):
    return (index.to_bytes(4, "big") + direction + ts.to_bytes(8, "big") + bytes([7]) * 16 + kind
            + expire_after.to_bytes(4, "big") + b"\x00\x02hi")
RET = b"\x0eretention_days\x00\x04" + (30).to_bytes(4, "big")
def _l7_file(contacts, settings, messages):
    salt, n1, mk, n = (H(B16[k]) for k in ("salt", "n_prime", "mk_bk", "n"))
    sections = (IDENT, contacts, settings, messages)
    bwrap = store.backup_bwrap(H(B16["passphrase"]), salt, n1, mk)
    header = store.backup_header(salt, bwrap, [len(s) for s in sections])
    return b"".join(sections), store.backup_file(header, n, store.backup_key(mk), b"".join(sections))
def test_l7_full_body_is_accepted():
    body, f = _l7_file(ONE + _contact(), SETTINGS_OK, ONE + _message())
    assert store.open_backup(H(B16["passphrase"]), f) == body
L7_REJECTS = {
    "settings-key=mode": (ONE + _contact(), b"\x00\x01\x04mode\x00\x04\x00\x00\x00\x01", ONE + _message()),
    "retention_days-len=3": (ONE + _contact(), b"\x00\x01\x0eretention_days\x00\x03\x00\x00\x1e", ONE + _message()),
    "settings-trailing-byte": (ONE + _contact(), SETTINGS_OK + b"\x00", ONE + _message()),
    "view-once": (ONE + _contact(), b"\x00\x00", ONE + _message(kind=b"\x03")),
    "kind=7": (ONE + _contact(), b"\x00\x00", ONE + _message(kind=b"\x07")),
    "direction=2": (ONE + _contact(), b"\x00\x00", ONE + _message(direction=b"\x02")),
    "contacts-truncated": (ONE + _contact()[:-1], b"\x00\x00", bytes(4)),
    "verified=2": (ONE + _contact(verified=b"\x02"), b"\x00\x00", bytes(4)),
    "local-name-65": (ONE + _contact(local=b"\x41" + b"a" * 65), b"\x00\x00", bytes(4)),
    "local-name-invalid-utf8": (ONE + _contact(local=b"\x02\xff\xfe"), b"\x00\x00", bytes(4)),
    "am3-settings-key-twice": (bytes(4), b"\x00\x02" + RET + RET, bytes(4)),
    "am3-contact_index=1": (ONE + _contact(), b"\x00\x00", ONE + _message(index=1)),
    "am3-contact_index-without-contacts": (bytes(4), b"\x00\x00", ONE + _message()),
    "am3-iks-ver=02": (ONE + _contact(iks=b"\x02" + IKS[1:]), b"\x00\x00", bytes(4)),
    "am3-profile-avatar-flag=2": (ONE + _contact(profile=b"\x04peer\x02"), b"\x00\x00", bytes(4)),
    "am4-ts=2^63": (ONE + _contact(), b"\x00\x00", ONE + _message(ts=2**63)),
    "am4-ts=2^64-1": (ONE + _contact(), b"\x00\x00", ONE + _message(ts=2**64 - 1)),
    "am4-sum=2^63-expire=1": (ONE + _contact(), b"\x00\x00", ONE + _message(ts=2**63 - 1000, expire_after=1)),
    "am4-sum=2^63-expire=max": (ONE + _contact(), b"\x00\x00",
                                ONE + _message(ts=2**63 - 1000 * (2**32 - 1), expire_after=2**32 - 1)),
    "am4-sum-beyond-u64": (ONE + _contact(), b"\x00\x00", ONE + _message(ts=2**64 - 1, expire_after=2**32 - 1)),
    "am4-second-of-two-ts=2^63": (ONE + _contact(), b"\x00\x00",
                                  (2).to_bytes(4, "big") + _message() + _message(ts=2**63)),
    "am4-first-of-two-ts=2^63": (ONE + _contact(), b"\x00\x00",
                                 (2).to_bytes(4, "big") + _message(ts=2**63) + _message()),
}
@pytest.mark.parametrize("name", sorted(L7_REJECTS))
def test_l7_malformed_body_rejects(name):
    _, f = _l7_file(*L7_REJECTS[name])
    with pytest.raises(Reject) as e:
        store.open_backup(H(B16["passphrase"]), f)
    assert type(e.value) is Reject and str(e.value) == "reject"


AM4_ACCEPTED = {  # ADR-053 Amendment 4: the largest accepted value of each leg
    "ts=2^63-1": (2**63 - 1, 0),
    "sum=2^63-1-expire=1": (2**63 - 1001, 1),
    "sum=2^63-1-expire=max": (2**63 - 1 - 1000 * (2**32 - 1), 2**32 - 1),
}


@pytest.mark.parametrize("name", sorted(AM4_ACCEPTED))
def test_am4_largest_time_is_accepted(name):
    ts, expire_after = AM4_ACCEPTED[name]
    body, f = _l7_file(ONE + _contact(), b"\x00\x00", ONE + _message(ts=ts, expire_after=expire_after))
    assert store.open_backup(H(B16["passphrase"]), f) == body
