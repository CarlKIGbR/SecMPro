# SPDX-License-Identifier: AGPL-3.0-or-later
"""Vector-file format (SCHEMA.md rev 2 §1–§3), the written files, and the gate on open questions."""

import hashlib
import json

import pytest

import gen_vectors
from secmp_ref import cases, vectorfile
from secmp_ref.vectorfile import Case


def test_canonical_json_is_sorted_and_compact():
    doc = vectorfile.suite_document("hkdf-labels", [
        Case(2, "open", {"b": b"\xab", "a": 7}, None),
        Case(1, "derive", {"label": "SecMP-TR/1 rk"}, {"okm": b"\x00\xff"}),
    ])
    text = vectorfile.canonical_json(doc).decode("ascii")
    assert text == (
        '{"cases":[{"id":"hkdf-0001","inputs":{"label":"SecMP-TR/1 rk"},"op":"derive","outputs":{"okm":"00ff"}},'
        '{"expect":"reject","id":"hkdf-0002","inputs":{"a":7,"b":"ab"},"op":"open"}],'
        '"generator":"ref-python","schema":2,"spec":"SecMP/1 rev 2.2","suite":"hkdf-labels"}'
    )
    assert json.loads(text) == doc


def test_worked_example_of_schema_section_2():
    preimage = b"SecMP-vectors/1" + b"hkdf-labels" + (1).to_bytes(4, "big")
    assert preimage.hex() == "5365634d502d766563746f72732f31686b64662d6c6162656c7300000001"
    assert vectorfile.case_seed("hkdf-labels", 1).hex() == \
        "cf66f30f0fe1f5798c9c3f1e8e4034fbd3ef99ca2dcf68bf3d533caa15a33d23"
    s = vectorfile.CaseStream("hkdf-labels", 1)
    assert s.take(16).hex() == "66a224dde82f65dff9bc79b22f39a9ad"
    assert s.take(32).hex() == "30c09b030215e20d5de63ff06946dfb6aa044c903b7709cd7c9c3d80e8326007"
    row1 = cases.hkdf_labels_cases()[0]
    assert (row1.inputs["salt"].hex(), row1.inputs["ikm"].hex()) == (
        "66a224dde82f65dff9bc79b22f39a9ad", "30c09b030215e20d5de63ff06946dfb6aa044c903b7709cd7c9c3d80e8326007")


def test_case_stream_is_one_contiguous_shake_stream():
    parts = vectorfile.CaseStream("caead", 3)
    joined = parts.take(3) + parts.take(0) + parts.take(29)
    assert joined == hashlib.shake_256(vectorfile.case_seed("caead", 3)).digest(32)


def test_suite_tags():
    assert vectorfile.SUITE_TAGS == {"hkdf-labels": "hkdf", "caead": "caead", "msgencrypt": "msgenc",
                                     "hybridkem-768": "hk768", "hybridkem-1024": "hk1024",
                                     "hybridsign": "hsig", "fingerprint": "fp", "sas": "sas",
                                     "encodings": "enc", "tr": "tr", "hx": "hx"}
    assert set(vectorfile.SUITE_TAGS) == set(gen_vectors.SUITES)
    assert set(cases.SUITES) == set(gen_vectors.SUITES) - {"encodings", "tr", "hx"}


def test_manipulations():
    v = bytes([0x10, 0x20, 0x30])
    assert vectorfile.flip(v, 0) == bytes([0x11, 0x20, 0x30])
    assert vectorfile.flip(v, -1) == bytes([0x10, 0x20, 0x31])
    assert vectorfile.flip(v, 1) == bytes([0x10, 0x21, 0x30])
    assert vectorfile.drop_last(v) == v[:2]
    assert vectorfile.append_zero(v) == v + b"\x00"
    assert vectorfile.prefix(v, 2) == v[:2]


# ---------------------------------------------------------------------------------------------
# Validation and structural comparison


def _doc():
    return vectorfile.suite_document("sas", [
        Case(1, "sas", {"fp_a": b"\x01", "fp_b": b"\x02"}, {"half_a": "0123", "half_b": "9", "safety_number": "01239"}),
        Case(2, "verify", {"label": "SecMP-HX/1 bundle", "len": 3}, None),
    ])


def test_validator_accepts_a_good_document():
    vectorfile.validate_document(_doc())


def test_validator_nested_values():
    """encodings values (proposal SCHEMA-4.8): nested objects/arrays of numbers and hex strings."""
    good = {"structure": "Profile", "value": {"name": "6162", "list": [{"x": 1}, "00"]}}
    doc = vectorfile.suite_document("encodings", [Case(1, "encode", good, {"bytes": b"\x01"})])
    vectorfile.validate_document(doc)
    doc = vectorfile.suite_document("encodings", [Case(1, "encode", {"structure": "Request/LINK_GET",
                                                                     "value": {"op": "LINK_GET", "mode": "consume"}},
                                                       {"bytes": b"\x08"})])
    vectorfile.validate_document(doc)
    assert doc["schema"] == 3 and vectorfile.schema_of("sas") == 2
    for bad in ({"name": "AB"}, {"n": True}, {"l": ["xyz"]}, {"f": 1.5}, {"op": 8}, {"mode": 1}, {"op": ""}):
        doc = vectorfile.suite_document("encodings", [Case(1, "encode", good, {"bytes": b""})])
        doc["cases"][0]["inputs"]["value"] = bad
        with pytest.raises(ValueError):
            vectorfile.validate_document(doc)


@pytest.mark.parametrize("mutate", [
    lambda d: d["cases"][0]["inputs"].update(fp_a="AB"),            # uppercase hex
    lambda d: d["cases"][0]["inputs"].update(fp_a="abc"),           # odd length
    lambda d: d["cases"][0]["outputs"].update(half_a="12a"),        # not digits
    lambda d: d["cases"][1]["inputs"].update(len="3"),              # not a number
    lambda d: d["cases"][1]["inputs"].update(len=True),             # bool is not a number
    lambda d: d["cases"][1].update(id="sas-0003"),                  # gap
    lambda d: d["cases"][0].update(id="fp-0001"),                   # wrong tag
    lambda d: d["cases"][0].pop("op"),
    lambda d: d["cases"][0].update(op="decrypt"),
    lambda d: d["cases"][1].update(expect="accept"),
    lambda d: d["cases"][1].update(outputs={}),                     # both outputs and expect
    lambda d: d.update(schema=1),
])
def test_validator_rejects(mutate):
    doc = _doc()
    mutate(doc)
    with pytest.raises(ValueError):
        vectorfile.validate_document(doc)


def test_structural_comparison():
    a = vectorfile.canonical_json(_doc())
    other = _doc()
    other["generator"] = "secmp-rust"
    b = json.dumps(other, indent=2).encode()             # formatting is irrelevant
    assert vectorfile.documents_equal(a, b)
    for mutate in (lambda d: d["cases"][1]["inputs"].update(label="secmp-hx/1 bundle"),   # no case-folding
                   lambda d: d["cases"][1]["inputs"].update(len=3.0),
                   lambda d: d["cases"][0]["outputs"].update(half_b="09"),
                   lambda d: d.update(spec="SecMP/1 rev 2.1")):
        changed = _doc()
        mutate(changed)
        assert not vectorfile.documents_equal(a, json.dumps(changed).encode())


def test_structural_comparison_distinguishes_true_from_1():
    assert not vectorfile.documents_equal(b'{"v":true}', b'{"v":1}')


# ---------------------------------------------------------------------------------------------
# The written files


@pytest.mark.parametrize("suite", list(cases.SUITES))
def test_written_file_is_current_canonical_and_valid(suite):
    """vectors/<suite>.json is exactly what the code generates now."""
    path = gen_vectors.VECTORS_DIR / f"{suite}.json"
    data = path.read_bytes()
    assert data == gen_vectors.suite_bytes(suite)
    doc = json.loads(data)
    vectorfile.validate_document(doc)
    assert vectorfile.canonical_json(doc) == data
    assert not data.endswith(b"\n") and data.isascii()
    assert (doc["schema"], doc["suite"], doc["spec"], doc["generator"]) == (2, suite, "SecMP/1 rev 2.2", "ref-python")


def test_no_suite_is_blocked():
    assert gen_vectors.BLOCKED_BY == {}


def test_blocked_suite_is_not_written(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(gen_vectors, "VECTORS_DIR", tmp_path)
    monkeypatch.setitem(gen_vectors.BLOCKED_BY, "sas", ["SQ-99"])
    assert gen_vectors.main(["sas"]) == 2
    assert list(tmp_path.iterdir()) == []
    assert "SQ-99" in capsys.readouterr().err


def test_unblocked_suite_is_written(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(gen_vectors, "VECTORS_DIR", tmp_path)
    assert gen_vectors.main(["hkdf-labels"]) == 0
    data = (tmp_path / "hkdf-labels.json").read_bytes()
    assert hashlib.sha256(data).hexdigest() in capsys.readouterr().out
