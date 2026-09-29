# SPDX-License-Identifier: AGPL-3.0-or-later
"""Independent Python reference implementation of SecMP/1 (spec rev 2.2), for test vectors only.

Written from docs/03-protocol-spec.md and vectors/SCHEMA.md (rev 2) alone (ADR-026). One module per
construction (hkdf_labels, caead, msgencrypt, hybridkem, hybridsign, identity); primitives come
from pinned third-party libraries via `primitives`; `cases` holds the SCHEMA §4 case tables.
"""
