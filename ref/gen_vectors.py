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

from secmp_ref import cases, encodings_cases, hx_cases, link_cases, store_cases, tr_cases, vectorfile

VECTORS_DIR = pathlib.Path(__file__).resolve().parent.parent / "vectors"

# M1 suites (SCHEMA §4.1–4.7), M2 `encodings` (SCHEMA §4.8), M3 `tr` (SCHEMA-4.9-tr.md), M4 `hx`
# (SCHEMA-4.10-hx.md), M5 `link` (SCHEMA-4.11-link.md) and M7 `store` (SCHEMA-4.12-store.md).
SUITES = {**cases.SUITES, encodings_cases.SUITE: encodings_cases.encodings_cases, tr_cases.SUITE: tr_cases.tr_cases,
          hx_cases.SUITE: hx_cases.hx_cases, link_cases.SUITE: link_cases.link_cases,
          store_cases.SUITE: store_cases.store_cases}

# Open questions (ref/SPEC-QUESTIONS.md) that block writing a suite. An entry is removed only when
# the reviewer's answer is back and the code follows it. SQ-01 … SQ-11 are all answered. SQ-12 …
# SQ-19 (M2) block no suite: the `encodings` rows whose outcome depends on them are withheld
# (encodings_cases.WITHHELD) and every written row holds under every reading. SQ-22 … SQ-24 (M3) block
# no suite: `tr` is written with the pinned readings, and SCHEMA-4.9 names the cases each one touches.
# `hx` (M4): see SCHEMA-4.10 "Readings and questions". `link` (M5): see SCHEMA-4.11 "Readings and questions".
BLOCKED_BY: dict[str, list[str]] = {}


# Suites that `all` skips. `store` left the set with WEISUNG REF-M7-store3 (registered by WEISUNG M7-VEC1).
NOT_IN_ALL: set[str] = set()


def suite_bytes(suite: str) -> bytes:
    doc = vectorfile.suite_document(suite, SUITES[suite]())
    vectorfile.validate_document(doc)
    return vectorfile.canonical_json(doc)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Write SecMP test-vector files.")
    parser.add_argument("suites", nargs="+", choices=[*SUITES, "all"])
    parser.add_argument("--out-dir", type=pathlib.Path, default=VECTORS_DIR,
                        help="directory to write <suite>.json into (default: vectors/)")
    args = parser.parse_args(argv)
    suites = [s for s in SUITES if s not in NOT_IN_ALL] if "all" in args.suites else args.suites
    for suite in suites:
        blocking = BLOCKED_BY.get(suite, [])
        if blocking:
            print(f"{suite}: not written, blocked by open question(s) {', '.join(blocking)} "
                  f"(ref/SPEC-QUESTIONS.md)", file=sys.stderr)
            return 2
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for suite in suites:
        data = suite_bytes(suite)
        path = args.out_dir / f"{suite}.json"
        path.write_bytes(data)
        print(f"{path.name}  sha256 {hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
