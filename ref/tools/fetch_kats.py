# SPDX-License-Identifier: AGPL-3.0-or-later
"""Extract the official known-answer vectors used to qualify the primitive libraries.

Run once, with network access, from the repository root:

    ref/.venv/bin/python ref/tools/fetch_kats.py [--cache DIR]

Every source file is pinned by SHA-256 (SOURCES below); extraction refuses a file whose hash differs.
The vectors are parsed out of the official texts, never typed in by hand. The output files in
ref/tests/kat/ are committed, so the test-suite runs offline.
"""

import argparse
import hashlib
import json
import pathlib
import re
import tempfile
import urllib.request

ACVP_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"  # usnistgov/ACVP-Server master, 2026-08-12
ACVP = f"https://raw.githubusercontent.com/usnistgov/ACVP-Server/{ACVP_COMMIT}/gen-val/json-files/"

SOURCES = {
    "rfc4231": ("https://www.rfc-editor.org/rfc/rfc4231.txt",
                "72178527ce93500e730bc8eb182b857e583096d652b64ece0879c52ba1df973b"),
    "rfc5869": ("https://www.rfc-editor.org/rfc/rfc5869.txt",
                "7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c"),
    "rfc7748": ("https://www.rfc-editor.org/rfc/rfc7748.txt",
                "279ca0ecc5e92e2962e27b846986aeb74729d9dd34bd4a04a362f80dcb596ad3"),
    "rfc8032": ("https://www.rfc-editor.org/rfc/rfc8032.txt",
                "ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3"),
    "rfc8439": ("https://www.rfc-editor.org/rfc/rfc8439.txt",
                "25bef70fbf7a07ff45c2fe4cb7c6ce954eac687413d8610603268b4e4415324c"),
    "xchacha": ("https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt",
                "fa796b50265eeee383d40e82fed880267c7835e1b3d64c50c4f06162adaa1cfd"),
    "acvp-sha2-256": (ACVP + "SHA2-256-1.0/internalProjection.json",
                      "a7e0bf4f5c661f1787b343bf3ae1a809b1e62f8fb2c8a627791510d03a570a6c"),
    "acvp-sha3-256": (ACVP + "SHA3-256-2.0/internalProjection.json",
                      "dba4689436c7e440e61dc517210def3e8e09e50c0e9eff29ea66d89bdd0f2c63"),
    "acvp-shake-256": (ACVP + "SHAKE-256-FIPS202/internalProjection.json",
                       "a9348d17e009cad62a2baa70160353f5bca936a27116f60dd5811f39b91c6991"),
    "acvp-hmac-sha2-256": (ACVP + "HMAC-SHA2-256-2.0/internalProjection.json",
                           "a9d0734b93aee71bc6f30b47daab782fd96b39688afe4fbddb009e99402ec989"),
    "acvp-ml-kem-keygen": (ACVP + "ML-KEM-keyGen-FIPS203/internalProjection.json",
                           "d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b"),
    "acvp-ml-kem-encapdecap": (ACVP + "ML-KEM-encapDecap-FIPS203/internalProjection.json",
                               "a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f"),
    "acvp-ml-dsa-keygen": (ACVP + "ML-DSA-keyGen-FIPS204/internalProjection.json",
                           "e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf"),
    "acvp-ml-dsa-siggen": (ACVP + "ML-DSA-sigGen-FIPS204/internalProjection.json",
                           "72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22"),
    "acvp-ml-dsa-sigver": (ACVP + "ML-DSA-sigVer-FIPS204/internalProjection.json",
                           "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437"),
}

OUT_DIR = pathlib.Path(__file__).resolve().parent.parent / "tests" / "kat"


# ---------------------------------------------------------------------------------------------
# Fetching


def fetch(name, cache):
    url, pinned = SOURCES[name]
    path = cache / name
    if not path.exists():
        with urllib.request.urlopen(url, timeout=120) as response:
            path.write_bytes(response.read())
    data = path.read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if actual != pinned:
        raise SystemExit(f"{name}: SHA-256 {actual} does not match the pinned {pinned}")
    return data


def provenance(*names):
    return [{"name": n, "url": SOURCES[n][0], "sha256": SOURCES[n][1]} for n in names]


# ---------------------------------------------------------------------------------------------
# Text helpers for RFC / Internet-Draft plain text


def clean_lines(text):
    """Drop form feeds and page headers/footers so that values spanning a page break stay contiguous."""
    lines = []
    for line in text.replace("\f", "").splitlines():
        if re.search(r"\[Page \d+\]\s*$", line):
            continue
        if re.match(r"^(RFC \d+|Internet-Draft)\s{2,}", line):
            continue
        lines.append(line.rstrip())
    return lines


def section(lines, start, end):
    """Lines strictly between the first line equal to `start` and the next line equal to `end`."""
    i = lines.index(start)
    j = lines.index(end, i + 1)
    return lines[i + 1:j]


def find(lines, label, start=0):
    for i in range(start, len(lines)):
        if lines[i].strip() == label:
            return i
    raise KeyError(label)


def hex_after(lines, i):
    """Concatenate the plain-hex lines that follow line i (blank lines skipped, stops at other text)."""
    out = ""
    for line in lines[i + 1:]:
        s = line.strip()
        if s == "":
            continue
        if not re.fullmatch(r"[0-9a-f]+", s):
            break
        out += s
    return out


HEXDUMP = re.compile(r"^\s*(\d{3})  ((?:[0-9a-f]{2} ){0,15}[0-9a-f]{2})")


def hexdump_after(lines, i):
    """Parse an RFC 8439 hexdump ('000  4c 61 ...  Ladies') that follows line i; offsets are checked."""
    out = bytearray()
    for line in lines[i + 1:]:
        m = HEXDUMP.match(line)
        if not m:
            break
        if int(m.group(1)) != len(out):
            raise ValueError(f"hexdump offset mismatch at {line!r}")
        out += bytes.fromhex(m.group(2).replace(" ", ""))
    return out.hex()


def colon_hex(s):
    return s.strip().rstrip(".").strip("()").replace(":", "")


# ---------------------------------------------------------------------------------------------
# RFC extractors


def extract_rfc5869(text):
    lines = clean_lines(text)
    cases = []
    for n in (1, 2, 3):
        block = section(lines, f"A.{n}.  Test Case {n}", f"A.{n + 1}.  Test Case {n + 1}")
        fields, current = {}, None
        for line in block:
            m = re.match(r"^\s+(Hash|IKM|salt|info|L|PRK|OKM)\s*=\s*(.*)$", line)
            if m:
                current, value = m.group(1), m.group(2)
                fields[current] = ""
            elif current and re.match(r"^\s{6,}[0-9a-f]+", line):
                value = line
            else:
                current = None
                continue
            value = re.sub(r"\(.*?\)", "", value).strip()
            if current in ("Hash", "L"):
                fields[current] = value
            else:
                fields[current] += value.removeprefix("0x")
        assert fields["Hash"] == "SHA-256"
        cases.append({"name": f"RFC 5869 A.{n}", "ikm": fields["IKM"], "salt": fields["salt"],
                      "info": fields["info"], "len": int(fields["L"]), "prk": fields["PRK"],
                      "okm": fields["OKM"]})
    return cases


def extract_rfc4231(text):
    lines = clean_lines(text)
    cases = []
    names = [f"4.{k}.  Test Case {k - 1}" for k in range(2, 9)] + ["5.  Security Considerations"]
    for start, end in zip(names, names[1:]):
        block = section(lines, start, end)
        fields, current = {}, None
        for line in block:
            # Test Case 3 in the RFC text lacks the '=' after "Key"; accept both forms.
            m = re.match(r"^\s{3}(Key|Data|HMAC-SHA-\d{3})\s*=?\s+([0-9a-f]+)", line)
            c = re.match(r"^\s{18}([0-9a-f]+)", line)
            if m:
                current = m.group(1)
                fields[current] = m.group(2)
            elif current and c:
                fields[current] += c.group(1)
            else:
                current = None
        cases.append({"name": f"RFC 4231 {start.split('  ')[1]}", "key": fields["Key"],
                      "data": fields["Data"], "mac": fields["HMAC-SHA-256"]})
    return cases


def extract_rfc7748(text):
    lines = clean_lines(text)
    sec = section(lines, "5.2.  Test Vectors", "6.  Diffie-Hellman")
    x25519 = sec[find(sec, "X25519:"):find(sec, "X448:")]
    single = []
    i = 0
    while True:
        try:
            i = find(x25519, "Input scalar:", i)
        except KeyError:
            break
        k = hex_after(x25519, i)
        u = hex_after(x25519, find(x25519, "Input u-coordinate:", i))
        out = hex_after(x25519, find(x25519, "Output u-coordinate:", i))
        single.append({"name": f"RFC 7748 5.2 X25519 #{len(single) + 1}", "scalar": k, "u": u,
                       "out": out})
        i += 1
    iter_block = sec[find(sec, "For X25519:"):]
    start = hex_after(iter_block, 0)
    iterated = {
        "start": start,
        "after_1": hex_after(iter_block, find(iter_block, "After one iteration:")),
        "after_1000": hex_after(iter_block, find(iter_block, "After 1,000 iterations:")),
    }
    dh = section(lines, "6.1.  Curve25519", "6.2.  Curve448")
    dh_case = {
        "a": hex_after(dh, find(dh, "Alice's private key, a:")),
        "pk_a": hex_after(dh, find(dh, "Alice's public key, X25519(a, 9):")),
        "b": hex_after(dh, find(dh, "Bob's private key, b:")),
        "pk_b": hex_after(dh, find(dh, "Bob's public key, X25519(b, 9):")),
        "k": hex_after(dh, find(dh, "Their shared secret, K:")),
    }
    return {"single": single, "iterated": iterated, "dh": dh_case}


def extract_rfc8032(text):
    lines = clean_lines(text)
    sec = section(lines, "7.1.  Test Vectors for Ed25519", "7.2.  Test Vectors for Ed25519ctx")
    starts = [i for i, line in enumerate(sec) if line.strip().startswith("-----TEST")]
    cases = []
    for s, e in zip(starts, starts[1:] + [len(sec)]):
        block = sec[s:e]
        name = block[0].strip().removeprefix("-----TEST ").strip()
        m_idx = next(i for i, line in enumerate(block) if line.strip().startswith("MESSAGE (length"))
        m_len = int(re.search(r"length (\d+) byte", block[m_idx]).group(1))
        case = {
            "name": f"RFC 8032 7.1 TEST {name}",
            "secret": hex_after(block, find(block, "SECRET KEY:")),
            "public": hex_after(block, find(block, "PUBLIC KEY:")),
            "message": hex_after(block, m_idx),
            "signature": hex_after(block, find(block, "SIGNATURE:")),
        }
        assert len(case["message"]) == 2 * m_len, name
        cases.append(case)
    return cases


def extract_rfc8439(text):
    lines = clean_lines(text)
    # 2.4.2: ChaCha20 encryption example (key/nonce given inline in colon notation)
    sec = section(lines, "2.4.2.  Example and Test Vector for the ChaCha20 Cipher",
                  "2.5.  The Poly1305 Algorithm")
    joined = " ".join(line.strip() for line in sec)
    key = re.search(r"Key = ((?:[0-9a-f]{2}:\s*){31}[0-9a-f]{2})", joined).group(1)
    nonce = re.search(r"Nonce = \(((?:[0-9a-f]{2}:){11}[0-9a-f]{2})\)", joined).group(1)
    counter = int(re.search(r"Initial Counter = (\d+)", joined).group(1))
    chacha = [{
        "name": "RFC 8439 2.4.2",
        "key": colon_hex(key.replace(" ", "")),
        "nonce": colon_hex(nonce),
        "counter": counter,
        "plaintext": hexdump_after(sec, find(sec, "Plaintext Sunscreen:")),
        "ciphertext": hexdump_after(sec, find(sec, "Ciphertext Sunscreen:")),
    }]
    # A.2: ChaCha20 encryption test vectors #1..#3
    a2 = section(lines, "A.2.  ChaCha20 Encryption", "A.3.  Poly1305 Message Authentication Code")
    for n in (1, 2, 3):
        s = find(a2, f"Test Vector #{n}:")
        e = find(a2, f"Test Vector #{n + 1}:") if n < 3 else len(a2)
        block = a2[s:e]
        ctr_line = next(line for line in block if "Initial Block Counter" in line)
        chacha.append({
            "name": f"RFC 8439 A.2 #{n}",
            "key": hexdump_after(block, find(block, "Key:")),
            "nonce": hexdump_after(block, find(block, "Nonce:")),
            "counter": int(ctr_line.split("=")[1]),
            "plaintext": hexdump_after(block, find(block, "Plaintext:")),
            "ciphertext": hexdump_after(block, find(block, "Ciphertext:")),
        })
    # 2.8.2: AEAD_CHACHA20_POLY1305 example
    sec = section(lines, "2.8.2.  Example and Test Vector for AEAD_CHACHA20_POLY1305",
                  "3.  Implementation Advice")
    tag_idx = find(sec, "Tag:")
    aead = {
        "name": "RFC 8439 2.8.2",
        "plaintext": hexdump_after(sec, find(sec, "Plaintext:")),
        "aad": hexdump_after(sec, find(sec, "AAD:")),
        "key": hexdump_after(sec, find(sec, "Key:")),
        "nonce": hexdump_after(sec, find(sec, "32-bit fixed-common part:")) + hexdump_after(sec, find(sec, "IV:")),
        "ciphertext": hexdump_after(sec, find(sec, "Ciphertext:")),
        "tag": colon_hex(sec[tag_idx + 1]),
    }
    return {"chacha20": chacha, "aead": aead}


def extract_xchacha(text):
    lines = clean_lines(text)
    sec = section(lines, "A.3.1.  AEAD_XCHACHA20_POLY1305", "A.3.2.  XChaCha20")
    return [{
        "name": "draft-irtf-cfrg-xchacha-03 A.3.1",
        "plaintext": hex_after(sec, find(sec, "Plaintext:")),
        "aad": hex_after(sec, find(sec, "AAD:")),
        "key": hex_after(sec, find(sec, "Key:")),
        "nonce": hex_after(sec, find(sec, "IV:")),
        "ciphertext": hex_after(sec, find(sec, "Ciphertext:")),
        "tag": hex_after(sec, find(sec, "Tag:")),
    }]


# ---------------------------------------------------------------------------------------------
# ACVP extractors (hex is lower-cased; the selection is recorded in the output)


def low(v):
    return v.lower() if isinstance(v, str) else v


def acvp_groups(data):
    return json.loads(data)["testGroups"]


def extract_hashes(sha2, sha3, shake, limit=64):
    def byte_oriented(groups, with_out_len=False):
        cases = []
        for g in groups:
            if g.get("testType") != "AFT":
                continue
            for t in g["tests"]:
                if t["len"] % 8 or (with_out_len and t["outLen"] % 8):
                    continue
                case = {"tcId": t["tcId"], "msg": low(t["msg"])[: t["len"] // 4], "md": low(t["md"])}
                if with_out_len:
                    case["out_len"] = t["outLen"] // 8
                cases.append(case)
        return cases[:limit]

    return {
        "sha2-256": byte_oriented(acvp_groups(sha2)),
        "sha3-256": byte_oriented(acvp_groups(sha3)),
        "shake-256": byte_oriented(acvp_groups(shake), with_out_len=True),
    }


def extract_acvp_hmac(data, limit=64):
    cases = []
    for g in acvp_groups(data):
        for t in g["tests"]:
            if t["keyLen"] % 8 or t["msgLen"] % 8 or t["macLen"] % 8:
                continue
            cases.append({"tcId": t["tcId"], "key": low(t["key"]), "msg": low(t["msg"]),
                          "mac": low(t["mac"])})
    return cases[:limit]


def extract_ml_kem(keygen, encdec, per_group=10):
    out = {"keygen": [], "encaps": [], "decaps": [], "ek_check": []}
    for g in acvp_groups(keygen):
        if g["parameterSet"] in ("ML-KEM-768", "ML-KEM-1024"):
            for t in g["tests"][:per_group]:
                out["keygen"].append({"tcId": t["tcId"], "param": g["parameterSet"], "d": low(t["d"]),
                                      "z": low(t["z"]), "ek": low(t["ek"]), "dk": low(t["dk"])})
    for g in acvp_groups(encdec):
        if g["parameterSet"] not in ("ML-KEM-768", "ML-KEM-1024"):
            continue
        p, f = g["parameterSet"], g["function"]
        for t in g["tests"][:per_group]:
            if f == "encapsulation":
                out["encaps"].append({"tcId": t["tcId"], "param": p, "ek": low(t["ek"]), "m": low(t["m"]),
                                      "c": low(t["c"]), "k": low(t["k"])})
            elif f == "decapsulation":
                out["decaps"].append({"tcId": t["tcId"], "param": p, "dk": low(t["dk"]), "c": low(t["c"]),
                                      "k": low(t["k"]), "reason": t["reason"]})
            elif f == "encapsulationKeyCheck":
                out["ek_check"].append({"tcId": t["tcId"], "param": p, "ek": low(t["ek"]),
                                        "passed": t["testPassed"], "reason": t["reason"]})
    return out


def extract_ml_dsa_65(keygen, siggen, sigver):
    out = {"keygen": [], "sign_hedged_external": [], "sign_deterministic_external": [],
           "sign_hedged_internal": [], "verify_external": []}
    for g in acvp_groups(keygen):
        if g["parameterSet"] == "ML-DSA-65":
            for t in g["tests"][:10]:
                out["keygen"].append({"tcId": t["tcId"], "seed": low(t["seed"]), "pk": low(t["pk"]),
                                      "sk": low(t["sk"])})
    for g in acvp_groups(siggen):
        if g["parameterSet"] != "ML-DSA-65" or g["externalMu"]:
            continue
        external_pure = g["signatureInterface"] == "external" and g["preHash"] == "pure"
        internal = g["signatureInterface"] == "internal"
        if external_pure and not g["deterministic"]:
            key, n = "sign_hedged_external", 10
        elif external_pure and g["deterministic"]:
            key, n = "sign_deterministic_external", 4
        elif internal and not g["deterministic"]:
            key, n = "sign_hedged_internal", 4
        else:
            continue
        for t in g["tests"][:n]:
            case = {"tcId": t["tcId"], "sk": low(t["sk"]), "message": low(t["message"]),
                    "signature": low(t["signature"])}
            if "context" in t:
                case["context"] = low(t["context"])
            case["rnd"] = low(t["rnd"]) if "rnd" in t else "00" * 32
            out[key].append(case)
    for g in acvp_groups(sigver):
        if g["parameterSet"] == "ML-DSA-65" and g["signatureInterface"] == "external" and g["preHash"] == "pure":
            for t in g["tests"]:
                out["verify_external"].append({"tcId": t["tcId"], "pk": low(t["pk"]),
                                               "message": low(t["message"]), "context": low(t["context"]),
                                               "signature": low(t["signature"]), "passed": t["testPassed"],
                                               "reason": t["reason"]})
    return out


# ---------------------------------------------------------------------------------------------


def write(name, sources, cases):
    doc = {"extracted_by": "ref/tools/fetch_kats.py", "sources": provenance(*sources), "cases": cases}
    path = OUT_DIR / name
    path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(f"wrote {path.relative_to(OUT_DIR.parent.parent.parent)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cache", type=pathlib.Path,
                        default=pathlib.Path(tempfile.gettempdir()) / "secmp-ref-kat-cache")
    args = parser.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    def text(name):
        return fetch(name, args.cache).decode("utf-8")

    write("hkdf_sha256.json", ["rfc5869"], extract_rfc5869(text("rfc5869")))
    write("hmac_sha256.json", ["rfc4231", "acvp-hmac-sha2-256"],
          {"rfc4231": extract_rfc4231(text("rfc4231")),
           "acvp": extract_acvp_hmac(fetch("acvp-hmac-sha2-256", args.cache))})
    write("hashes.json", ["acvp-sha2-256", "acvp-sha3-256", "acvp-shake-256"],
          extract_hashes(fetch("acvp-sha2-256", args.cache), fetch("acvp-sha3-256", args.cache),
                         fetch("acvp-shake-256", args.cache)))
    write("x25519.json", ["rfc7748"], extract_rfc7748(text("rfc7748")))
    write("ed25519.json", ["rfc8032"], extract_rfc8032(text("rfc8032")))
    write("chacha20.json", ["rfc8439"], extract_rfc8439(text("rfc8439")))
    write("xchacha20poly1305.json", ["xchacha"], extract_xchacha(text("xchacha")))
    write("ml_kem.json", ["acvp-ml-kem-keygen", "acvp-ml-kem-encapdecap"],
          extract_ml_kem(fetch("acvp-ml-kem-keygen", args.cache), fetch("acvp-ml-kem-encapdecap", args.cache)))
    write("ml_dsa_65.json", ["acvp-ml-dsa-keygen", "acvp-ml-dsa-siggen", "acvp-ml-dsa-sigver"],
          extract_ml_dsa_65(fetch("acvp-ml-dsa-keygen", args.cache), fetch("acvp-ml-dsa-siggen", args.cache),
                            fetch("acvp-ml-dsa-sigver", args.cache)))


if __name__ == "__main__":
    main()
