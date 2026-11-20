# SPDX-License-Identifier: AGPL-3.0-or-later
"""Library qualification: cryptography Argon2id with p = 4 (lanes), RFC 9106 §5.3 (ADR-053 item 1, ADR-026)."""

from secmp_ref import primitives

TAG = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"


def test_argon2id_rfc9106_5_3():
    out = primitives.argon2id(password=b"\x01" * 32, salt=b"\x02" * 16, secret=b"\x03" * 8, ad=b"\x04" * 12,
                              t=3, m_kib=32, p=4, length=32)
    assert out.hex() == TAG
