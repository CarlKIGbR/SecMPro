# SPDX-License-Identifier: AGPL-3.0-or-later
"""Independent Python reference implementation of SecMP/1 (spec rev 2.2), for test vectors only.

Written from docs/03-protocol-spec.md and vectors/SCHEMA.md alone (ADR-026). One module per
construction (hkdf_labels, caead, msgencrypt, hybridkem, hybridsign, identity, encodings, tr, inv,
hx); primitives come from pinned third-party libraries via `primitives`; `cases`, `encodings_cases`,
`tr_cases` and `hx_cases` hold the SCHEMA §4 case tables.
"""
