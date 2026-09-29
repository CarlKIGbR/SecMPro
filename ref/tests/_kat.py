# SPDX-License-Identifier: AGPL-3.0-or-later
"""Loader for the official known-answer vectors in tests/kat/ (extracted by tools/fetch_kats.py)."""

import json
import pathlib

KAT_DIR = pathlib.Path(__file__).resolve().parent / "kat"


def load(name):
    return json.loads((KAT_DIR / name).read_text())["cases"]


def h(value):
    return bytes.fromhex(value)
