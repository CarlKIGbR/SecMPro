# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fixed sizes in bytes, from spec Appendix B (and the §3 / §4.2 tables where Appendix B is silent)."""

# Appendix B: "X25519 pk/ss · Ed25519 pk/sig | 32/32 · 32/64"
X25519_PK = 32
X25519_SS = 32
ED25519_PK = 32
ED25519_SIG = 64

# Appendix B: "ML-KEM-768 ek/ct/ss · ML-KEM-1024 ek/ct/ss | 1184/1088/32 · 1568/1568/32"
MLKEM768_EK = 1184
MLKEM768_CT = 1088
MLKEM1024_EK = 1568
MLKEM1024_CT = 1568
MLKEM_SS = 32

# Appendix B: "ML-DSA-65 pk/sig · HybridSig | 1952/3309 · 3373"
MLDSA65_PK = 1952
MLDSA65_SIG = 3309
HYBRID_SIG = 3373

# Appendix B: IKSPublic, PrekeyBundle, link data
IKS_PUBLIC = 2017
PREKEY_BUNDLE = 7775
LINKDATA_PADDED = 12288
LINK_BLOB = 12360

# Appendix B: ratchet header, cell, body, frame
HEADER = 2314
HDR_CT = 2330
CELL = 4096
BODY_LEN = 1710
FRAME = 4352
FRAME_PLAINTEXT = 4336

# Appendix B: handshake envelope, RelayInfo, link handshake, invitation
HS_OUTER = 9362
HS_OUTER_PADDED = 12018
HS_CELLS = 3
RELAY_INFO = 1741
HS1 = 2853
HS2 = 1153
INVITATION_NO_DIRECT = 241

# §3 table: "Decapsulation keys stored as 64-byte seeds" (d ‖ z); SCHEMA: ML-DSA seed ξ is 32 B
MLKEM_SEED = 64
MLDSA_SEED = 32
ED25519_SEED = 32
X25519_SK = 32

# §3 table: SHA-256 / SHA3-256 digests, HMAC-SHA-256 tags, XChaCha20-Poly1305 nonce and tag
SHA256 = 32
SHA3_256 = 32
HMAC_TAG = 32
XCHACHA_NONCE = 24
AEAD_TAG = 16

# §3.3 MsgEncrypt: K_enc ‖ K_mac ‖ IV = 32 + 32 + 12; §3.4 CAEAD: K_enc ‖ COM = 32 + 32
CHACHA_KEY = 32
CHACHA_NONCE = 12
CAEAD_COM = 32

# §6.2 fingerprint, §4.2 SAS_DIGITS
FINGERPRINT = 32
SAS_DIGITS = 60
