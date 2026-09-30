# SPDX-License-Identifier: AGPL-3.0-or-later
"""Domain-separation labels, copied literally from spec rev 2.2 Appendix A ("exhaustive").

A label is an ASCII byte string without terminator or length prefix; the spec concatenates it
directly (‖) with whatever follows. Appendix A rule: the set is prefix-free, so the label at the
start of a labelled string is unambiguous. tests/test_labels_sizes.py re-reads Appendix A from
the spec text, checks that this module matches it character for character, and checks
prefix-freeness.
"""

# Appendix A, line 1
HYBRIDKEM_768 = b"SecMP-HybridKEM-768/1"
HYBRIDKEM_1024 = b"SecMP-HybridKEM-1024/1"
HYBRIDSIGN = b"SecMP-HybridSign/1"
COMMIT = b"SecMP-commit/1"

# Appendix A, line 2
FP = b"SecMP-FP/1"
SAS = b"SecMP-SAS/1"

# Appendix A, line 3
INV_BLOB = b"SecMP-INV/1 blob"
INV_LINKDATA = b"SecMP-INV/1 linkdata"

# Appendix A, line 4
HX_TRANSCRIPT = b"SecMP-HX/1 transcript"
HX_SK = b"SecMP-HX/1 sk"
HX_IDKEY = b"SecMP-HX/1 idkey"
HX_BUNDLE = b"SecMP-HX/1 bundle"
HX_INITKEY = b"SecMP-HX/1 initkey"
HX_INITCELL = b"SecMP-HX/1 initcell"
HX_INNER = b"SecMP-HX/1 inner"

# Appendix A, line 5
TR_INIT = b"SecMP-TR/1 init"
TR_RK = b"SecMP-TR/1 rk"
TR_MSGKEYS = b"SecMP-TR/1 msgkeys"
TR_HDR = b"SecMP-TR/1 hdr"
TR_BODY = b"SecMP-TR/1 body"
TR_KEYCHANGE = b"SecMP-TR/1 keychange"

# Appendix A, line 6
LINK_RELAY_FP = b"SecMP-LINK/1 relay-fp"
LINK_RELAYINFO = b"SecMP-LINK/1 relayinfo"
LINK_H0 = b"SecMP-LINK/1 h0"
LINK_HS1 = b"SecMP-LINK/1 hs1"
LINK_HS2 = b"SecMP-LINK/1 hs2"
LINK_KEYS = b"SecMP-LINK/1 keys"
LINK_FRAME = b"SecMP-LINK/1 frame"

# Appendix A, line 7
Q_RID = b"SecMP-Q/1 rid"
Q_SID = b"SecMP-Q/1 sid"
Q_AKC = b"SecMP-Q/1 akc"
Q_TOKEN = b"SecMP-Q/1 token"

# Appendix A, line 8: command signature labels. D.6: the label is "SecMP-Q/1 " ‖ CMD_LABEL, where
# CMD_LABEL is the D.2 command name except FETCH_MULTI, whose label is MFETCH.
Q_QUEUE_NEW = b"SecMP-Q/1 QUEUE_NEW"
Q_SEND = b"SecMP-Q/1 SEND"
Q_FETCH = b"SecMP-Q/1 FETCH"
Q_MFETCH = b"SecMP-Q/1 MFETCH"
Q_QUEUE_DEL = b"SecMP-Q/1 QUEUE_DEL"
Q_LINK_PUT = b"SecMP-Q/1 LINK_PUT"
Q_LINK_GET = b"SecMP-Q/1 LINK_GET"
Q_CMD = {
    "QUEUE_NEW": Q_QUEUE_NEW,
    "SEND": Q_SEND,
    "FETCH": Q_FETCH,
    "FETCH_MULTI": Q_MFETCH,
    "QUEUE_DEL": Q_QUEUE_DEL,
    "LINK_PUT": Q_LINK_PUT,
    "LINK_GET": Q_LINK_GET,
}

# Appendix A, lines 9–10: local storage (out of scope for vectors, SCHEMA §4.1)
STORE_IDENTITY = b"SecMP-STORE/1 identity"
STORE_PREKEYS = b"SecMP-STORE/1 prekeys"
STORE_RELAYS = b"SecMP-STORE/1 relays"
STORE_CONTACTS = b"SecMP-STORE/1 contacts"
STORE_SESSIONS = b"SecMP-STORE/1 sessions"
STORE_OUTBOX = b"SecMP-STORE/1 outbox"
STORE_MESSAGES = b"SecMP-STORE/1 messages"
STORE_INVITATIONS = b"SecMP-STORE/1 invitations"
STORE_SETTINGS = b"SecMP-STORE/1 settings"

# Appendix A, line 11: "test-vector seed derivation only, vectors/SCHEMA.md"
VECTORS = b"SecMP-vectors/1"

# Every label, in Appendix A order.
APPENDIX_A = (
    HYBRIDKEM_768, HYBRIDKEM_1024, HYBRIDSIGN, COMMIT,
    FP, SAS,
    INV_BLOB, INV_LINKDATA,
    HX_TRANSCRIPT, HX_SK, HX_IDKEY, HX_BUNDLE, HX_INITKEY, HX_INITCELL, HX_INNER,
    TR_INIT, TR_RK, TR_MSGKEYS, TR_HDR, TR_BODY, TR_KEYCHANGE,
    LINK_RELAY_FP, LINK_RELAYINFO, LINK_H0, LINK_HS1, LINK_HS2, LINK_KEYS, LINK_FRAME,
    Q_RID, Q_SID, Q_AKC, Q_TOKEN,
    Q_QUEUE_NEW, Q_SEND, Q_FETCH, Q_MFETCH, Q_QUEUE_DEL, Q_LINK_PUT, Q_LINK_GET,
    STORE_IDENTITY, STORE_PREKEYS, STORE_RELAYS, STORE_CONTACTS, STORE_SESSIONS,
    STORE_OUTBOX, STORE_MESSAGES, STORE_INVITATIONS, STORE_SETTINGS,
    VECTORS,
)

# §3.5 / Appendix A: "HybridSign accepts only "SecMP-HX/1 bundle" and "SecMP-TR/1 keychange"".
HYBRIDSIGN_LABELS = (HX_BUNDLE, TR_KEYCHANGE)
