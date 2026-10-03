# SPDX-License-Identifier: AGPL-3.0-or-later
"""SecMP-INV, invitations and link data (spec §5): the URI form of InvitationV1, the link-data key
and blob, and the invitee's checks.

    URI  = "secmp://i/" ‖ base64url(encode(InvitationV1)), no padding                         (§5.2)
    K_ld = HKDF-SHA-256(salt = ld_id, IKM = link_key, info = "SecMP-INV/1 linkdata", L = 32)     (§5.4)
    blob = N (24) ‖ CAEAD.Seal(K_ld, N, AD = "SecMP-INV/1 blob" ‖ ld_id, pad(LinkDataV1, 12288))   12360 B

InvitationV1 and LinkDataV1 are encoded and decoded by `encodings` (App. D.3). The invitee's
processing here is §5.5 steps 1, 3 and 4, with a supplied `now`, and the blob opening of step 2;
fetching the blob from the relay (step 2), the reply queue (step 5) and sending the handshake
(step 6) are the caller's.
"""

import base64
import binascii
import re
from typing import NamedTuple

from . import caead, hkdf_labels, hx, identity, labels, primitives, sizes
from . import encodings as enc
from .errors import Reject

URI_PREFIX = "secmp://i/"
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")

# ---------------------------------------------------------------------------------------------
# Rejection (as in hx.py): `last_rule` names the check that raised the most recent Reject.

last_rule = None


def _fail(rule):
    global last_rule
    last_rule = rule
    raise Reject()


# ---------------------------------------------------------------------------------------------
# The URI (§5.2)


def uri_encode(invitation: bytes) -> str:
    return URI_PREFIX + base64.urlsafe_b64encode(invitation).rstrip(b"=").decode("ascii")


def uri_decode(uri: str) -> bytes:
    """The encoded invitation. Rejects anything but the exact prefix followed by canonical base64url
    without padding (RFC 4648 §5): only the URL-safe alphabet, no '=', no length ≡ 1 (mod 4), and the
    unused low bits of the last character zero (the string re-encodes to itself)."""
    if not isinstance(uri, str) or not uri.startswith(URI_PREFIX):
        _fail("uri")
    text = uri[len(URI_PREFIX):]
    if not _B64URL.match(text) or len(text) % 4 == 1:
        _fail("uri")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        _fail("uri")
    if uri_encode(data) != uri:
        _fail("uri")
    return data


# ---------------------------------------------------------------------------------------------
# Link data (§5.4)


def derive_k_ld(ld_id: bytes, link_key: bytes) -> bytes:
    return hkdf_labels.labeled_hkdf(ld_id, link_key, labels.INV_LINKDATA, b"", 32)


def _blob_ad(ld_id: bytes) -> bytes:
    return labels.INV_BLOB + ld_id


def seal_blob(k_ld: bytes, n: bytes, ld_id: bytes, linkdata: bytes) -> bytes:
    """linkdata: the unpadded encoded LinkDataV1; padded here to 12288 (ISO/IEC 7816-4)."""
    blob = n + caead.seal(k_ld, n, _blob_ad(ld_id), enc.iso_pad(linkdata, sizes.LINKDATA_PADDED))
    assert len(blob) == sizes.LINK_BLOB
    return blob


def open_blob(k_ld: bytes, ld_id: bytes, blob: bytes) -> bytes:
    """The padded LinkDataV1 (12288 B); raises Reject."""
    if len(blob) != sizes.LINK_BLOB:
        raise Reject()
    n = blob[: sizes.XCHACHA_NONCE]
    return caead.open(k_ld, n, _blob_ad(ld_id), blob[sizes.XCHACHA_NONCE:])


# ---------------------------------------------------------------------------------------------
# Invitee processing (§5.5)


class Accepted(NamedTuple):
    invitation: dict                              # the decoded InvitationV1
    linkdata: dict                                # the decoded LinkDataV1
    k_ld: bytes
    k_inv: bytes                                  # §6.5, for the handshake cells


def invitee_accept(uri: str, blob: bytes, now: int) -> Accepted:
    """§5.5 steps 1, 3 and 4 (and the opening of step 2); the uniform Reject on any failure."""
    # 1. Parse; reject if expired, wrong version/kind, malformed.
    data = uri_decode(uri)
    try:
        invitation = enc.decode("InvitationV1", data)
    except Reject:
        _fail("invitation-decode")
    if now >= invitation["expires"]:
        _fail("expired")
    # 2. (the caller fetched the blob) CAEAD.Open with K_ld; a well-formed LinkDataV1.
    k_ld = derive_k_ld(invitation["ld_id"], invitation["link_key"])
    try:
        padded = open_blob(k_ld, invitation["ld_id"], blob)
    except Reject:
        _fail("blob-open")
    try:
        linkdata = enc.decode("LinkDataV1", padded)
    except Reject:
        _fail("linkdata-decode")
    # 3. fingerprint(inviter_iks) = inviter_fp ("invitation does not match link data").
    fp = identity.fingerprint(enc.raw("IKSPublic", linkdata["inviter_iks"]))
    if not primitives.ct_equal(fp, invitation["inviter_fp"]):
        _fail("fingerprint")
    # 4. bundle.sig under inviter_iks.IK_sig; not expired; opk present (v1).
    bundle = linkdata["bundle"]
    try:
        hx.verify_bundle(linkdata["inviter_iks"], bundle)
    except Reject:
        _fail("bundle-sig")
    if bundle["spk_expiry"] <= now:
        _fail("bundle-expired")
    if bundle["opk_present"] != 1:
        _fail("opk-absent")                       # unreachable: the PrekeyBundle decoder rejects it (§6.3)
    return Accepted(invitation, linkdata, k_ld, hx.derive_k_inv(invitation["ld_id"], invitation["link_key"]))
