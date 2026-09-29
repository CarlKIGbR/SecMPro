# SPDX-License-Identifier: AGPL-3.0-or-later
"""Access to the normative spec text, so that tests can compare constants with it literally."""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
CANDIDATES = [REPO / "docs" / "03-protocol-spec.md", REPO / "03-protocol-spec.md"]


def spec_text() -> str:
    for path in CANDIDATES:
        if path.exists():
            return path.read_text(encoding="utf-8")
    raise FileNotFoundError(f"spec not found at any of {CANDIDATES}")


def appendix(letter: str) -> str:
    """The text of '## Appendix <letter>' up to the next '## ' heading."""
    text = spec_text()
    m = re.search(rf"^## Appendix {letter} .*?(?=^## |\Z)", text, flags=re.S | re.M)
    return m.group(0)
