# SPDX-License-Identifier: AGPL-3.0-or-later
"""Write vectors/<suite>.json in the format of SCHEMA.md rev 2.

    ref/.venv/bin/python ref/gen_vectors.py <suite> [<suite> ...]
    ref/.venv/bin/python ref/gen_vectors.py all

A suite is written only when no open question in ref/SPEC-QUESTIONS.md blocks it (BLOCKED_BY).
"""

import argparse
import hashlib
import pathlib
import sys

from secmp_ref import cases, encodings_cases, vectorfile

VECTORS_DIR = pathlib.Path(__file__).resolve().parent.parent / "vectors"

# M1 suites (SCHEMA §4.1–4.7) and M2 `encodings` (proposal SCHEMA-4.8-encodings.md).
SUITES = {**cases.SUITES, encodings_cases.SUITE: encodings_cases.encodings_cases}

# Open questions (ref/SPEC-QUESTIONS.md) that block writing a suite. An entry is removed only when
# the reviewer's answer is back and the code follows it. SQ-01 … SQ-11 are all answered. SQ-12 …
# SQ-19 (M2) block no suite: the `encodings` rows whose outcome depends on them are withheld
# (encodings_cases.WITHHELD) and every written row holds under every reading.
BLOCKED_BY: dict[str, list[str]] = {}


def suite_bytes(suite: str) -> bytes:
    doc = vectorfile.suite_document(suite, SUITES[suite]())
    vectorfile.validate_document(doc)
    return vectorfile.canonical_json(doc)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Write SecMP test-vector files.")
    parser.add_argument("suites", nargs="+", choices=[*SUITES, "all"])
    args = parser.parse_args(argv)
    suites = list(SUITES) if "all" in args.suites else args.suites
    for suite in suites:
        blocking = BLOCKED_BY.get(suite, [])
        if blocking:
            print(f"{suite}: not written, blocked by open question(s) {', '.join(blocking)} "
                  f"(ref/SPEC-QUESTIONS.md)", file=sys.stderr)
            return 2
    VECTORS_DIR.mkdir(exist_ok=True)
    for suite in suites:
        data = suite_bytes(suite)
        path = VECTORS_DIR / f"{suite}.json"
        path.write_bytes(data)
        print(f"{path.name}  sha256 {hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
