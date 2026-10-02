# SecMP/1 — Protocol Specification (normative)

Status: **v1 design freeze candidate, revision 2.4** (2026-10-02; rev 2.1 of 2026-09-25 after adversarial review and verification pass, see `docs/reviews/plan-review-2026-09-25.md`; rev 2.2 of 2026-09-28 answers the reference implementation's spec questions, see `docs/reviews/ref-spec-questions-M1.md` and ADR-035; rev 2.3 clarifies Appendix D for the M2 encodings — decoder obligations, the `ver` rule, `RelayRef` validity, Handshake `caps`, list minimums, Fragment rules and the §7.6 body layouts — see `docs/reviews/ref-spec-questions-M2.md` and ADR-039; rev 2.4 applies ADR-043 (a)–(k), the clarifications of the M3 and M4 reviews). Changes to this document require an ADR (see `08-decisions.md`) and a reviewer sign-off.

Changelog: **rev 2.4** (2026-10-02): ADR-043 (a)–(k). **rev 2.3** (2026-09-29, ADR-039) — §4.1 `ver` rule reworded and decoder obligations added; §5.3 `onion` validity (rend-spec-v3); §7.6 `caps`, list counts, Fragment rules, KeyChange never unfragmented, `payload`/`arg` opaque at the encoding layer; D.3 `RelayRef.direct` host and port; D.5 `caps (0)`, `count (1..=255)`, Fragment rules and the Batch, RouteUpdate, reassembled-Fragment and Dummy layouts. No byte layout changed. **rev 2.2** (2026-09-28, ADR-035) — label renames, `MFETCH`, answers SQ-01 … SQ-11. **rev 2.1** (2026-09-25) — after the adversarial plan review.
Audience: the implementer (Claude Code / Opus), the reviewer, and future auditors.

The words MUST / MUST NOT / SHOULD / MAY are used as in RFC 2119.

SecMP/1 is a family of five sub-protocols that together form the wire protocol of SecMPro v1:

| Sub-protocol | Purpose | Section |
|---|---|---|
| **SecMP-INV** | Out-of-band invitations (QR / URI) and encrypted link data | §5 |
| **SecMP-HX** | Hybrid (X25519 + ML-KEM-1024) asynchronous initial key agreement, PQXDH-shaped | §6 |
| **SecMP-TR** | Hybrid ratchet: Double Ratchet with header encryption + ML-KEM-768 at every step | §7 |
| **SecMP-LINK** | Client ↔ relay session: hybrid NK-style handshake, fixed-size AEAD frames | §8 |
| **SecMP-Q** | Anonymous capability-based queue commands executed by the relay | §9 |

Sections 1–4 define terminology, primitives, encoding rules and constants. §10 defines the constant-rate scheduler and the correlation mitigations. §11 lists required security properties and formal-model obligations. §12 covers transport neutrality for v1.1. Appendix D gives every byte layout.

---

## 1. Design goals and non-goals

### 1.1 Goals (v1)

1. **Zero trust in infrastructure.** The relay is an untrusted, dumb store. It MUST NOT be able to learn message content, message length, sender identity, the social graph, or user activity beyond what §11.3 explicitly lists as accepted leakage.
2. **No user identifiers.** No accounts, phone numbers, usernames, or global identity keys visible to the relay. A user is local state plus per-contact keys and queues.
3. **Post-quantum confidentiality everywhere SecMPro agrees a key.** Handshake, every ratchet step, and the client-relay link are hybrids of X25519 and ML-KEM (FIPS 203). (Tor's own circuit cryptography is classical and outside SecMPro's control; the PQ link layer runs inside it.)
4. **No negotiation.** Exactly one ciphersuite. No version or algorithm negotiation, hence no downgrade surface.
5. **Traffic-analysis resistance.** All relay-visible units are fixed size; clients emit them at a constant rate independent of user activity (§10).
6. **Fail closed.** Any verification failure drops the message and, where applicable, flags the session. No layer degrades silently.
7. **Transport neutrality.** Everything above SecMP-LINK works unchanged over a v1.1 peer-to-peer transport (§12).
8. **Survive relay restarts.** Queues are re-creatable with identical identifiers so that a RAM-only relay can restart without destroying sessions (§9.1).

### 1.2 Non-goals (v1)

Group messaging; multi-device; post-quantum *authentication* (authentication is classical X25519 identity DH, PQ signatures cover prekey bundles only — §6.6 and `01-threat-model.md` §3.8); voice/video; push notifications; hiding from the relay *whether* a given anonymous queue is currently being polled.

---

## 2. Terminology

| Term | Meaning |
|---|---|
| **User** | A person running one SecMPro client (one device in v1). No global identifier. |
| **Identity key set (IKS)** | `IK_sig` (Ed25519 ‖ ML-DSA-65) and `IK_dh` (X25519). Known only to contacts. |
| **Contact** | A user with whom a session exists, identified locally by the fingerprint of their IKS. |
| **Session** | The SecMP-TR state between two users plus the two queues used to reach each other. |
| **Queue** | A unidirectional, capability-authenticated, fixed-capacity mailbox on a relay. One writer (*sender*), one reader (*recipient*). |
| **Cell** | The fixed-size (4096 B) end-to-end encrypted unit stored and forwarded by the relay. Opaque to the relay. |
| **Frame** | The fixed-size (4352 B) link-layer unit between a client and a relay. |
| **Slot** | A tick of the constant-rate scheduler (§10). |
| **Relay** | The v1 server: stores cells in RAM, executes SecMP-Q commands. |
| **Link** | A SecMP-LINK session between a client and a relay over one byte stream (Tor onion stream or TLS/TCP). Identified internally by `sess_id`. |
| **Link data** | The encrypted blob an inviter stores on the relay under `ld_id`; contains keys and prekeys. |
| **Invitation** | A one-time capability created by an *inviter* that lets an *invitee* establish a session. |
| **Initiator / Responder** | In SecMP-HX the *invitee* is the initiator; the *inviter* is the responder. |

---

## 3. Cryptographic primitives (the single ciphersuite)

All primitives below are the only ones permitted in SecMP constructions. `secmp-crypto` wraps each in a typed API. (TLS, Tor and the local database use their own audited libraries; see `06-engineering-standards.md` §3.)

| Role | Primitive | Parameters / notes |
|---|---|---|
| Classical KEX | X25519 (RFC 7748) | Inputs handled exactly per RFC 7748 §5 (top bit of the u-coordinate masked, non-canonical u accepted, scalar clamped); the all-zero output MUST be rejected — this covers every low-order input. Public keys are hashed/transmitted as the received 32 bytes. |
| PQ KEM (prekeys, relay static key) | ML-KEM-1024 (FIPS 203) | ek 1568, ct 1568, ss 32. Decapsulation keys stored as 64-byte seeds. |
| PQ KEM (ratchet, link ephemeral) | ML-KEM-768 (FIPS 203) | ek 1184, ct 1088, ss 32. |
| Hybrid KEM | `HybridKEM-768`, `HybridKEM-1024` (§3.2) | X-Wing-shaped combiner with public key and ciphertext bound in. |
| Signatures | `HybridSign` = Ed25519 (strict verification, §3.5) ‖ ML-DSA-65 (pure, hedged) (§3.5) | pk 32 + 1952; sig 64 + 3309. |
| Hash | SHA-256; SHA3-256 in the KEM combiner | |
| KDF | HKDF-SHA-256 | Every `info` begins with a label from Appendix A. |
| MAC | HMAC-SHA-256 | 32-byte tags, constant-time comparison. |
| E2E body encryption | ChaCha20 (RFC 8439) + HMAC-SHA-256, Encrypt-then-MAC (§3.3) | Key-committing, deniable. |
| AEAD (headers, frames, link data, storage) | XChaCha20-Poly1305 (24-byte nonce), 16-byte tag; committing wrapper `CAEAD` where stated (§3.4) | |
| Password KDF (local only) | Argon2id, m = 256 MiB, t = 3, p = 4 | |
| Randomness | OS CSPRNG only (`getrandom`) | |

### 3.1 Why these

ML-KEM-1024 for long-lived keys and 768 for per-step keys mirrors Signal (Kyber-1024 in PQXDH, ML-KEM-768 in SPQR) and Apple PQ3. Concatenated hybrid signatures match IETF composite ML-DSA-65+Ed25519 and BSI TR-02102-1 (2026). Encrypt-then-MAC with HMAC gives key commitment (RFC 9771: ChaCha20-Poly1305 and AES-GCM are not committing) while keeping the Double Ratchet's deniability (no signatures on messages).

### 3.2 `HybridKEM`

A hybrid public key is `(pk_dh: 32 B, ek_kem)`; a hybrid ciphertext is `(pk_e: 32 B, ct_kem)`. `V` is the ASCII label `"SecMP-HybridKEM-768/1"` or `"SecMP-HybridKEM-1024/1"`.

```
Encaps(pk_peer = (pk_dh, ek_kem)):
    (sk_e, pk_e)     = X25519.keygen()
    ss_dh            = X25519(sk_e, pk_dh)               ; MUST NOT be all-zero
    (ct_kem, ss_kem) = ML-KEM.Encaps(ek_kem)
    ss = SHA3-256( ss_kem ‖ ss_dh ‖ SHA3-256(ct_kem) ‖ SHA3-256(ek_kem) ‖ pk_dh ‖ pk_e ‖ V )
    return (ct = (pk_e, ct_kem), ss)

Decaps(sk_peer = (sk_dh, dk_kem), ct = (pk_e, ct_kem)):
    ss_dh  = X25519(sk_dh, pk_e)                          ; MUST NOT be all-zero
    ss_kem = ML-KEM.Decaps(dk_kem, ct_kem)                ; implicit rejection per FIPS 203
    ss     = SHA3-256( ... as above ... )
```

The combiner binds the KEM ciphertext and encapsulation key, closing the ML-KEM "not MAL-BIND-K-CT with expanded keys" issue and the PQXDH re-encapsulation attack class. HybridKEM-1024 is used in the link handshake's static stage (§8.3); HybridKEM-768 in its ephemeral stage. The handshake (§6) and the ratchet (§7) mix raw X25519 and ML-KEM outputs directly into HKDF; there, the public keys and ciphertexts are bound through the transcript (§6.4) and through the header-in-AD rule (§7.3), which provides the same binding.

### 3.3 `MsgEncrypt` (E2E bodies)

Given a 32-byte single-use message key `MK`, associated data `AD`, plaintext `P` (already padded to the fixed body length):

```
(K_enc ‖ K_mac ‖ IV) = HKDF-SHA-256(salt = 0^32, IKM = MK, info = "SecMP-TR/1 msgkeys", L = 32+32+12)
C   = ChaCha20(K_enc, nonce = IV, counter = 0) XOR P
TAG = HMAC-SHA-256(K_mac, AD ‖ C)
return C ‖ TAG
```

Decrypt: recompute `TAG'`, compare in constant time, only then decrypt. `MsgEncrypt` MUST reject `|P| ≠ BODY_LEN` and `MsgDecrypt` MUST reject `|C ‖ TAG| ≠ BODY_LEN + 32`, with the same uniform error as a MAC failure. Padding is not interpreted here; it is verified by the `Content` decoder (§7.6, D.5). `MK` is never reused (§7), so the derived fixed `IV` is safe. A restored backup MUST NOT contain ratchet state (see `04-client-security.md` CS-3.5) precisely because this construction has no nonce.

### 3.4 `CAEAD` (committing AEAD wrapper)

```
CAEAD.Seal(K, N (24 B), AD, P):
    (K_enc ‖ COM) = HKDF-Expand(PRK = K, info = "SecMP-commit/1" ‖ N, L = 64)
    C = XChaCha20-Poly1305.Seal(K_enc, N, AD, P)
    return COM ‖ C                                        ; COM is 32 B, C includes the 16 B tag
CAEAD.Open(K, N, AD, COM ‖ C): recompute COM, constant-time compare, then open.
```

This is the UtC transform: `COM` commits to `(K, N)` with a key separate from the encryption key. `CAEAD` is used for link data (§5.4), the handshake envelope (§6.5) and local storage. Ratchet headers (§7.5) and link frames (§8.4) use plain XChaCha20-Poly1305 (keys come from an authenticated handshake; no commitment needed).

### 3.5 `HybridSign`

```
HybridSign(sk = (sk_ed, sk_mldsa), label, M):
    m = SHA-256("SecMP-HybridSign/1" ‖ label ‖ M)
    return Ed25519.Sign(sk_ed, m) ‖ ML-DSA-65.Sign(sk_mldsa, m, ctx = label)
HybridVerify(pk, label, M, sig): both components MUST verify.
```

`label` MUST be one of the two HybridSign labels (`"SecMP-HX/1 bundle"`, `"SecMP-TR/1 keychange"`); implementations MUST refuse any other label. ML-DSA-65 is used as **pure ML-DSA** (FIPS 204 Alg. 2/3: `M' = 0x00 ‖ len(ctx) ‖ ctx ‖ m`), hedged with 32 bytes of randomness; keys come from `KeyGen_internal(ξ)`. Not HashML-DSA. **Ed25519 verification is strict**, defined here rather than by any library: RFC 8032 §5.1.7 with the cofactorless equation `[S]B = R + [k]A`, and rejection of `S ≥ L`, of non-canonical encodings of `A` or `R` (y-coordinate ≥ p), and of small-order `A` or `R` (order dividing 8, including the identity). Implementations whose library does less MUST add the missing checks on the encoded bytes before verifying.

---

## 4. Encoding rules and global constants

### 4.1 Encoding

- Fixed-layout, big-endian, hand-encoded. No serde-derived wire formats, no maps, no floats, no varints.
- Variable-length fields carry a `u16` (or `u8` where stated) length prefix. **Consistency rule:** every length must be consistent with the enclosing structure, and the enclosing structure (cell, frame, blob or record) must be fully consumed; padding (where the layout says "pad") is ISO/IEC 7816-4 (`0x80` then zeros to the fixed length) and MUST be verified on decode.
- `ver: u8 = 0x01` (`PROTO_VER`). Every structure that App. D gives a `ver` field checks it on decode (reject on any other value); a structure without a `ver` field in App. D takes its version from the enclosing structure or the transport unit.
- Optional fields: `present: u8 ∈ {0x00, 0x01}` then the field iff present.
- **Decoder obligations** (rev 2.3, ADR-039). Besides widths, lengths, padding and the value rules of Appendix D, a decoder MUST check every public key and signature field on the encoded bytes, without a message: (a) every X25519 field (`relay_dh_pk`, `e_c`, `pk_e1`, `e_r`, `ik_dh`, `spk_dh`, `opk_dh`, `ek_I`, `dh_pk`) rejects a low-order value — after RFC 7748 decoding (top bit masked, u reduced mod p) u ∈ {0, 1, p − 1, the two u-coordinates of order 8} — and keeps every other value as received (§3); (b) every Ed25519 key (`relay_sig_pk`, `ik_ed25519`, `recv_pk`, `send_pk`, `owner_pk`) and the `R` of every Ed25519 signature (every D.2 `sig`, `RelayInfoV1.sig`, and the first 64 bytes of every `HybridSig`) reject under the §3.5 byte rules — y ≥ p or a point of order dividing 8 — and when they are not a curve point (RFC 8032 §5.1.3 decoding fails); the `S` of every such signature rejects when `S ≥ L`; (c) every ML-KEM encapsulation key (`relay_kem_ek`, `ek_c`, `spk_kem`, `rpk_kem`, `opk_kem`, `ek_pq`) passes the FIPS 203 §7.2 modulus check. A decoder MUST NOT run ML-DSA sigDecode (it is part of verification, FIPS 204 Alg. 8). Signatures, MACs and tags are verified at use, not at decode; the checks at use (§3, §3.5, §6.6, §7.4) remain.
- Decoders MUST be total (never panic), fuzzed, and tested with the negative vectors in `vectors/`.
- Encodings are canonical: decode-then-encode reproduces the input byte-for-byte (property-tested).
- All byte layouts are in Appendix D; a structure not listed there does not exist on the wire.

### 4.2 Constants

| Constant | Value | Rationale |
|---|---|---|
| `PROTO_VER` | `0x01` | |
| `CELL_SIZE` | 4096 B | Holds a full hybrid ratchet header (2330 B) plus 1710 B of content. |
| `FRAME_SIZE` | 4352 B | Cell + 240 B command overhead + 16 B tag. Every post-handshake frame in either direction is exactly this size; plaintext capacity 4336 B. |
| `HDR_CT_LEN` | 2330 B | Encrypted ratchet header (2314 + 16). Single length for every message (§7.5). |
| `BODY_LEN` | 1710 B | Padded content length per cell. |
| `F` (`FETCH_BATCH`) | 4 | Cells per `FETCH` response. |
| `F_M` (`FETCH_MULTI_BATCH`) | 8 | Cells per `FETCH_MULTI` response. |
| `QUEUE_CAPACITY` | 128 cells | FIFO eviction with sender notification (§9.5). |
| `SKIP_WINDOW` | 256 | Skipped message keys retained per skip call; total bound 2 × `SKIP_WINDOW` across chains (§7.4). |
| `MAX_FF` | 2^20 | Maximum chain fast-forward per received message (§7.4). |
| `CELL_TTL` | 7 days | Relay expiry (hour buckets). |
| `QUEUE_IDLE_TTL` | 30 days | |
| `LINKDATA_TTL` | 30 days | |
| `MAX_MSG_BYTES` | 65535 | Largest application message (`payload_len` is u16; fragmented, ≤ 64 fragments). |
| `PERIODS` | {10, 20, 40, 80} s | Allowed per-queue send periods, chosen by the recipient (§10.2). |
| `T_BALANCED` | 10 s | Slot period of a Balanced-mode link. |
| `T_LOWBW` | 30 s | Slot period of a Low-bandwidth link. |
| `LINK_LIFETIME` | U[6 h, 24 h] per link | Then a new link on a fresh circuit (§10.6). |
| `LINK_MAX_FRAMES` | 2^20 | Hard re-handshake bound. |
| `SAS_DIGITS` | 60 | |

`PERIODS`, `T_*`, `F`, `F_M` are tunable within the §10.1 invariant and are finalised in M6 (ADR-018).

---

## 5. SecMP-INV — Invitations and link data

### 5.1 Overview

A session is created only through an invitation exchanged out of band (QR shown in person, or a URI sent over an existing channel). The invitation lets the invitee (a) reach the inviter's relay, (b) fetch an encrypted *link data* blob with the inviter's keys and prekeys, (c) write the handshake into a one-time *invitation queue*, and (d) verify the blob came from the intended inviter (fingerprint commitment).

### 5.2 `InvitationV1`

```
InvitationV1 {
  ver:            u8 = 0x01
  kind:           u8            ; 0x01 = one-time (v1); 0x02 = multi-use (reserved, v1 clients MUST reject)
  relay:          RelayRef      ; §5.3
  ld_id:          [u8; 16]      ; random, relay-visible link-data id
  link_key:       [u8; 32]      ; random, NEVER sent to the relay
  inviter_fp:     [u8; 32]      ; fingerprint of the inviter's IKS (§6.2)
  inv_sid:        [u8; 16]      ; sender id of the invitation queue
  inv_send_seed:  [u8; 32]      ; Ed25519 seed of the invitation queue's sender key
  inv_period_s:   u16           ; ∈ PERIODS; the period at which the invitee sends on the invitation queue and the inviter polls it
  expires:        u64           ; Unix seconds; MUST be ≤ creation + 30 days
}
```

URI: `secmp://i/` + base64url (no padding) of the encoding (≈ 322 chars). QR: same string, byte mode.

The inviter persists, per issued invitation: `ld_id`, `link_key`, the link-data owner key, the invitation queue's recipient key, `spk_id`/`opk_id`, and `expires`, until the invitation is consumed or expired.

Invitations are **secrets**: anyone holding an unconsumed one can become the invitee. One-time link data is consumed on first `LINK_GET` (§9.4). The inviter's client polls the invitation queue at the queue's period like any other recv-queue; if the link data is reported consumed (via the owner status query, §9.4) and no valid handshake arrives before `expires`, the UI shows "invitation used by someone else".

### 5.3 `RelayRef`

```
RelayRef {
  ver:        u8 = 0x01
  relay_fp:   [u8; 32]      ; SHA-256("SecMP-LINK/1 relay-fp" ‖ relay_sig_pk)   (§8.2)
  onion:      [u8; 35]      ; v3 onion service identity (decoded 56-char address) — REQUIRED
  akc:        [u8; 32]      ; access-key commitment, SHA-256("SecMP-Q/1 akc" ‖ relay_access_key)   (§9.6)
  direct:     Option<{ host_len: u16, host: [u8; host_len], port: u16, spki_sha256: [u8; 32] }>
}
```

`onion` is the decoded v3 onion address `PUBKEY[32] ‖ CHECKSUM[2] ‖ VERSION[1]` as defined by Tor's rend-spec-v3 §6 (onion-address encoding), with `CHECKSUM = SHA3-256(".onion checksum" ‖ PUBKEY ‖ VERSION)[0..2]`. A decoder MUST reject `onion` unless `VERSION = 0x03` and `CHECKSUM` is valid; `PUBKEY` is not otherwise checked (rev 2.3, ADR-039). The `direct` host and port rules are in D.3.

`akc` lets a user verify that the operator handed everyone the *same* access key (a per-user key would be an identifier). A client that holds an access key for `relay_fp` and sees a different `akc` MUST refuse the relay and warn.

Clients MUST use the onion endpoint when Tor is available; `direct` is for testing and for users who knowingly accept IP exposure.

### 5.4 Link data blob

```
LinkDataV1 {
  ver:          u8 = 0x01
  inviter_iks:  IKSPublic        ; 2017 B, §6.2
  bundle:       PrekeyBundle     ; 7775 B, §6.3
  profile:      Profile          ; App. D
  created:      u64
}
K_ld = HKDF-SHA-256(salt = ld_id, IKM = link_key, info = "SecMP-INV/1 linkdata", L = 32)
blob = N (24) ‖ CAEAD.Seal(K_ld, N, AD = "SecMP-INV/1 blob" ‖ ld_id, pad(LinkDataV1, 12288))
     = 24 + 32 (COM) + 12288 + 16 = 12360 B
```

All blobs are 12360 B; `LINK_PUT`/`LINKR` carry them in three frames (App. D).

### 5.5 Invitee processing

1. Parse `InvitationV1`; reject if expired, wrong version/kind, malformed.
2. Open a link to `relay` (§8) — on a fresh isolated circuit — and `LINK_GET(ld_id)`; `CAEAD.Open` with `K_ld`.
3. `fingerprint(inviter_iks)` MUST equal `inviter_fp`, else abort ("invitation does not match link data").
4. Verify `bundle.sig` under `inviter_iks.IK_sig`; reject expired bundles; v1 REQUIRES `opk` present.
5. Take a reply queue from the local queue pool (§10.6) or create one on the invitee's relay.
6. Run SecMP-HX as initiator (§6.4–6.5) and send the three handshake cells over the invitation queue.

The invitee checks exactly steps 1, 3 and 4; the inviter-side bounds of §5.2 and §6.3 are not invitee checks (rev 2.4).

---

## 6. SecMP-HX — Hybrid initial key agreement

PQXDH (Signal, rev. 3) with: KEM fixed to ML-KEM-1024; an ML-KEM-768 *ratchet prekey* so the ratchet's first step has the same size as every other; the whole initial message sealed so the relay never sees the initiator's keys; and an inner layer keyed by ephemeral material so the initiator's identity gains forward secrecy against a later invitation leak.

### 6.1 Keys held by every user

| Key | Type | Lifetime | Use |
|---|---|---|---|
| `IK_sig` | Ed25519 ‖ ML-DSA-65 | Long-term | Signs prekey bundles and key-change announcements. Never signs messages. |
| `IK_dh` | X25519 | Long-term | Implicit authentication (X3DH-style). Certified by `IK_sig` in every bundle. |
| `SPK_dh`, `SPK_kem` | X25519, ML-KEM-1024 | New one every 7 days; **an SPK referenced by an unexpired invitation is retained until that invitation expires** | Signed prekeys. |
| `RPK_kem` | ML-KEM-768 | Same lifetime as the SPK it is bundled with | Initial ratchet KEM key (§7.2). |
| `OPK_dh[i]`, `OPK_kem[i]` | X25519, ML-KEM-1024 | Single use | One per one-time invitation. |

### 6.2 `IKSPublic` and fingerprint

```
IKSPublic { ver: u8 = 0x01, ik_ed25519: [u8;32], ik_mldsa65: [u8;1952], ik_dh: [u8;32] }     ; 2017 B
fingerprint(iks) = SHA-256("SecMP-FP/1" ‖ encode(iks))
```

### 6.3 `PrekeyBundle` (7775 B)

```
PrekeyBundle {
  ver:        u8 = 0x01
  spk_id:     u32
  spk_dh:     [u8;32]
  spk_kem:    [u8;1568]
  rpk_kem:    [u8;1184]          ; ML-KEM-768 ratchet prekey
  spk_expiry: u64                ; MUST be ≥ the expiry of every invitation referencing it
  opk_present: u8                ; MUST be 0x01 in v1
  opk_id:     u32
  opk_dh:     [u8;32]
  opk_kem:    [u8;1568]
  sig:        HybridSig          ; HybridSign(IK_sig, "SecMP-HX/1 bundle", all preceding fields ‖ ik_dh)
}
```

### 6.4 Key derivation (initiator I, responder R)

Initiator holds `IK_sig_I, IK_dh_I`; generates ephemeral `EK_I` (X25519).

```
DH1 = X25519(IK_dh_I, SPK_dh_R)
DH2 = X25519(EK_I,    IK_dh_R)
DH3 = X25519(EK_I,    SPK_dh_R)
DH4 = X25519(EK_I,    OPK_dh_R)
(ct_spk, ss_spk) = ML-KEM-1024.Encaps(SPK_kem_R)
(ct_opk, ss_opk) = ML-KEM-1024.Encaps(OPK_kem_R)
every DHi MUST be checked non-zero.

transcript = SHA-256( "SecMP-HX/1 transcript"
             ‖ encode(IKSPublic_R) ‖ spk_id ‖ SPK_dh_R ‖ SHA-256(SPK_kem_R) ‖ SHA-256(RPK_kem_R)
             ‖ opk_id ‖ OPK_dh_R ‖ SHA-256(OPK_kem_R)
             ‖ encode(IKSPublic_I) ‖ EK_I ‖ SHA-256(ct_spk) ‖ SHA-256(ct_opk) ‖ ld_id )

IKM = 0xFF^32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4 ‖ ss_spk ‖ ss_opk
SK  = HKDF-SHA-256(salt = 0^32, IKM, info = "SecMP-HX/1 sk" ‖ transcript, L = 32)
K_id = HKDF-SHA-256(salt = ld_id, IKM = link_key ‖ DH3 ‖ ss_spk ‖ DH4 ‖ ss_opk, info = "SecMP-HX/1 idkey", L = 32)
```

`SK` initialises SecMP-TR (§7.2). `transcript` is stored by both sides as the session binding `SB`. `K_id` protects the initiator's identity inside the handshake envelope (§6.5); the responder can compute it before knowing `IKSPublic_I`, and it is forward-secret once `OPK` is deleted and `EK_I` discarded.

### 6.5 Handshake envelope (initiator → responder, three cells on the invitation queue)

```
K_inv = HKDF-SHA-256(salt = ld_id, IKM = link_key, info = "SecMP-HX/1 initkey", L = 32)

Inner    = IKSPublic_I ‖ first_msg                      ; first_msg = a SecMP-TR cell (4096 B), Content type Handshake (§7.6)
inner_ct = N2 (24) ‖ CAEAD.Seal(K_id, N2, AD = "SecMP-HX/1 inner" ‖ ld_id, Inner)      ; 24 + 32 + 6113 + 16 = 6185 B
Outer    = ver ‖ EK_I ‖ spk_id ‖ opk_id ‖ ct_spk ‖ ct_opk ‖ inner_ct                 ; 1+32+4+4+1568+1568+6185 = 9362 B
Padded   = pad(Outer, 3 × 4006 = 12018)
init_id  = random 16 B
cell_i (i = 0,1,2) = N_i (24, random) ‖ CAEAD.Seal(K_inv, N_i, AD = "SecMP-HX/1 initcell" ‖ ld_id,
                                                    init_id ‖ i (u8) ‖ 0x03 ‖ Padded[i·4006 .. (i+1)·4006])
                   = 24 + 32 (COM) + (16 + 1 + 1 + 4006) + 16 (tag) = 4096 B
```

Rules: the initiator generates all three cells once, persists them, and re-sends them **byte-identical** on retry (never re-seals). It sends them at `inv_period_s` like any other cells (§10). **Until the initiator has decrypted a first message from R, every other cell it sends on the invitation queue is a dummy**; real messages stay in the outbox (a real cell sent before the handshake cells would be acked and discarded by R without the sender learning it). The responder trial-opens every cell fetched from the invitation queue with `K_inv`; cells that fail to open are ignored (they may be garbage from the relay or from an invitation thief); chunks are grouped by `init_id`, and the first `init_id` for which all three chunks open is processed. `N_i` random ⇒ no nonce reuse; `init_id`/`i`/`total` inside the ciphertext ⇒ the relay sees three uniform cells.

`reply_route` (how R reaches I) lives inside `first_msg`'s Handshake content and is therefore bound to `SK`.

### 6.6 Responder processing and authentication semantics

1. Open outer chunks with `K_inv`; parse `Outer`; `spk_id`/`opk_id` MUST be the ids recorded for this invitation's bundle; an unknown or already used `opk_id` ⇒ reject.
2. Compute `DH3`, `DH4`, `ss_spk`, `ss_opk` → `K_id`; open `inner_ct` → `IKSPublic_I` (well-formedness: decodable, `ik_dh` not low-order) and `first_msg`.
3. Compute `DH1`, `DH2`, `transcript`, `SK`; initialise TR as responder (§7.2); decrypt `first_msg`, which MUST decrypt to a Content of type 0x01 Handshake with `caps = 0`; anything else rejects the envelope. On any failure: discard everything, keep the OPK, log nothing identifying.
4. On success: delete the OPK; store the contact as **unverified** with the routes from the Handshake content; start sending to I's reply route; the first reply carries a `RouteUpdate` with a pooled queue replacing the invitation queue; **retire the invitation queue per §10.6 rules 4–5** (keep fetching it and processing its cells as TR cells of this session for U[1 h, 24 h], then `QUEUE_DEL` on a one-shot link).
5. Display the safety number (§6.7); the contact becomes *verified* only after user confirmation.

Authentication: R is authenticated to I by `DH2`/`DH3` and by the bundle signature under `IK_sig_R`, pinned via `inviter_fp`. I is authenticated to R by `DH1`. PQ confidentiality comes from `ss_spk`/`ss_opk`. PQ authentication is not provided (industry-standard choice; `01-threat-model.md` §3.8). Deniability: no party signs a message; the envelope contains no signature by I.

Replay: the OPK is single-use and mandatory, so a replayed envelope is rejected at step 1.

### 6.7 Safety number (SAS)

```
iter(fp):  h = fp; repeat 5200 times: h = SHA-256("SecMP-SAS/1" ‖ h ‖ fp); return h
half(fp):  6 groups of 5 decimal digits: for k in 0..6: int_be(iter(fp)[5k..5k+5]) mod 100000, zero-padded
safety_number = concat(sorted_lexicographically(half(fp_A), half(fp_B)))     ; 60 digits
```

Shown as 12 groups of 5, plus a QR with `"SecMP-SAS/1" ‖ fp_own ‖ fp_peer`. A contact is `verified` after a QR scan or explicit digit confirmation. A key change (§7.7) resets `verified` and blocks sending until re-verified.

---

## 7. SecMP-TR — Hybrid ratchet

SecMP-TR is the Signal Double Ratchet (specification rev. 4), **header-encryption variant, followed exactly**, with one extension: every DH ratchet step is a hybrid step that also mixes an ML-KEM-768 shared secret into the root KDF, in both the receiving and the sending half. Every message of a sending chain carries that chain's KEM material, so losing any prefix of a chain never breaks the session.

### 7.1 State

```
RatchetState {
  sb:        [u8;32]                  ; session binding = HX transcript
  rk:        [u8;32]                  ; root key
  dh_s:      X25519 keypair           ; own ratchet key
  dh_r:      Option<[u8;32]>          ; peer ratchet public key
  kem_s:     ML-KEM-768 keypair       ; own KEM key; its ek is in every header we send; peer encapsulates to it
  kem_r:     Option<[u8;1184]>        ; peer's current ek; we encapsulate to it at our sending step
  last_ct_r: Option<[u8;1088]>        ; the KEM ciphertext of the peer's current chain (must be constant within the chain)
  ct_s:      Option<[u8;1088]>        ; our current chain's ciphertext to kem_r (constant for the chain)
  ck_s, ck_r: Option<[u8;32]>
  hk_s, hk_r, nhk_s, nhk_r: Option<[u8;32]>
  n_s, n_r:  u32
  pn:        u32
  skipped:   OrderedMap<(hk: [u8;32], n: u32) → mk>   ; insertion-ordered, serialised in that order; bounded (§7.4)
}
```

### 7.2 Initialisation

```
(RK ‖ HK_A ‖ NHK_B) = HKDF-SHA-256(salt = 0^32, IKM = SK, info = "SecMP-TR/1 init", L = 96)

Initiator (Alice role, sends first):
    sb = transcript; rk = RK; dh_r = SPK_dh_R; kem_r = RPK_kem_R; last_ct_r = None
    dh_s = X25519.keygen(); kem_s = ML-KEM-768.keygen()
    (ct_s, ss_pq) = ML-KEM-768.Encaps(kem_r)
    (rk, ck_s, nhk_s) = KDF_RK(rk, X25519(dh_s, dh_r) ‖ ss_pq)
    ck_r = None; n_s = n_r = pn = 0
    hk_s = HK_A; hk_r = None; nhk_r = NHK_B

Responder (Bob role):
    sb = transcript; rk = RK; dh_s = SPK_dh_R keypair; kem_s = RPK_kem_R keypair; dh_r = None; kem_r = None; ct_s = None; last_ct_r = None
    ck_s = ck_r = None; n_s = n_r = pn = 0
    hk_s = None; nhk_s = NHK_B; hk_r = None; nhk_r = HK_A

KDF_RK(rk, ikm) = HKDF-SHA-256(salt = rk, IKM = ikm, info = "SecMP-TR/1 rk", L = 96) → (rk', ck, nhk)
KDF_CK(ck)      = (ck' = HMAC-SHA-256(ck, 0x02), mk = HMAC-SHA-256(ck, 0x01))
```

### 7.3 Encrypt

```
Encrypt(state, content):
    (ck_s, mk) = KDF_CK(ck_s)
    header = HeaderV1{ dh_pk = dh_s.pk, pn, n = n_s, ek_pq = kem_s.ek, ct_pq = ct_s }
    hdr_nonce = random 24 B
    hdr_ct = XChaCha20-Poly1305.Seal(hk_s, hdr_nonce, AD = "SecMP-TR/1 hdr" ‖ sb, encode(header))
    body = MsgEncrypt(mk, AD = "SecMP-TR/1 body" ‖ sb ‖ hdr_nonce ‖ hdr_ct, pad(content, BODY_LEN))
    n_s += 1                         ; checked_add; abort at u32::MAX
    persist(state) BEFORE returning the cell (persist-before-send)
    return Cell = hdr_nonce ‖ hdr_ct ‖ body
```

### 7.4 Decrypt

```
Decrypt(state, cell):
    (hdr_nonce, hdr_ct, body) = split(cell)
    // 1. skipped keys: try every distinct hk in `skipped` (≤ 3 in practice), then look up (hk, header.n)
    for hk in distinct_header_keys(skipped):
        if header = Open(hk, hdr_nonce, hdr_ct): if mk = skipped.remove((hk, header.n)): return MsgDecrypt(mk, AD = ... ‖ hdr_nonce ‖ hdr_ct, body); else break
    // Open() with an absent (None) key fails. Open includes decoding the header; a header that opens but does not decode rejects the cell — no further key is tried.
    // 2. current / next header key
    if header = Open(hk_r, ...):              step = false
    elif header = Open(nhk_r, ...):           step = true
    else: reject (uniform error)
    if step:
        if header.dh_pk == dh_r: reject           ; a step must carry a new ratchet key; `dh_pk == dh_r` is byte equality of the encoded 32-byte key
        skip_message_keys(header.pn)               ; on the *old* receiving chain, bounded per below
        DHRatchet(state, header)
    elif header.ek_pq != kem_r or header.ct_pq != last_ct_r: reject   ; KEM material must be constant within a chain
    skip_message_keys(header.n)
    (ck_r, mk) = KDF_CK(ck_r); n_r += 1
    plaintext = MsgDecrypt(mk, AD = ... ‖ hdr_nonce ‖ hdr_ct, body)      ; failure ⇒ reject; state changes are discarded
    persist(state); return plaintext

DHRatchet(state, header):
    pn = n_s; n_s = 0; n_r = 0
    hk_s = nhk_s; hk_r = nhk_r
    dh_r = header.dh_pk; kem_r = header.ek_pq; last_ct_r = header.ct_pq
    ss_pq_recv = ML-KEM-768.Decaps(kem_s, header.ct_pq)                 ; ct was encapsulated to OUR kem_s
    (rk, ck_r, nhk_r) = KDF_RK(rk, X25519(dh_s, dh_r) ‖ ss_pq_recv)
    dh_s = X25519.keygen(); kem_s = ML-KEM-768.keygen()
    (ct_s, ss_pq_send) = ML-KEM-768.Encaps(kem_r)
    (rk, ck_s, nhk_s) = KDF_RK(rk, X25519(dh_s, dh_r) ‖ ss_pq_send)

skip_message_keys(until):
    if ck_r is None: return                   ; no receiving chain yet (responder before its first step)
    if until < n_r: reject                    ; replay / stale counter (uniform error)
    gap = until − n_r
    if gap > MAX_FF: reject
    while n_r < until:
        (ck_r, mk) = KDF_CK(ck_r)
        if until − n_r ≤ SKIP_WINDOW: skipped.insert((hk_r, n_r), mk)    ; older positions can no longer arrive (relay capacity)
        n_r += 1
    evict earliest-inserted entries so |skipped| ≤ 2 × SKIP_WINDOW (total across chains)
```

Notes. (a) Because constant-rate dummies advance chains by ~8 640 messages/day per queue, a returning recipient may face gaps far beyond a classic `MAX_SKIP`; fast-forwarding costs 2 HMACs per position and both `pn` and `n` may skip up to `MAX_FF` in one message (≤ 2^22 HMACs, a few seconds worst case); keys are stored only for positions that can still be delivered. `MAX_FF` at `P = 10 s` corresponds to ≈ 121 days of one-sided absence; beyond that the session must be re-invited (§7.8). (b) On a step message a wrong `ct_pq` makes the MAC fail (the message key depends on it); on a non-step message of the current chain the explicit constancy check rejects it — constancy is checked on the chain and step paths; a message accepted under a skipped key derives its message key before the header is read and performs no constancy check; all authentication failures are one uniform error. (c) State mutations are applied only after the body MAC verifies (transactional decrypt). (d) Every message carries its chain's KEM material; a recipient that missed the first message of a chain performs the step on whichever message arrives first.

### 7.5 Message and cell format

```
HeaderV1 (2314 B) { ver: u8 = 0x01, flags: u8 = 0x00, dh_pk: [u8;32], pn: u32, n: u32, ek_pq: [u8;1184], ct_pq: [u8;1088] }
Cell (4096 B) = hdr_nonce (24) ‖ hdr_ct (2330) ‖ body_ct (1710) ‖ tag (32)
```

There is exactly one header length, so header decryption tries at most `|distinct hks in skipped| + 2` keys and no lengths. `flags` MUST be zero in v1 (reserved).

**Persist-before-send:** `RatchetState` MUST be durably written before a cell leaves the process; a crash after persisting loses at most one cell, the reverse order could reuse a message key. **Persist-before-ack:** a received cell is acknowledged to the relay (§9.3) only after the resulting state and message are committed.

### 7.6 Content

```
Content (padded to 1710) { ver: u8, type: u8, seq: u64, ts: u64, body_len: u16, body }     ; body ≤ 1689 B
type: 0x00 Dummy · 0x01 Handshake · 0x02 Batch · 0x03 Fragment · 0x04 RouteUpdate · 0x05 KeyChange · 0x06 Receipt · 0x07 Control
```

- `seq` is a per-session application sequence (dedup/ordering, gaps ⇒ "messages may be missing"); `ts` is the sender's clock. Both exist only inside E2E.
- **Dummy**: empty body; discarded silently after decryption; it carries `seq = 0` and `ts = 0`.
- **Handshake** (first message only): `Profile ‖ caps: u32 (= 0) ‖ routes: u8 count (1..=255) ‖ RouteDescriptor[]` — the initiator's reply route(s). `caps` MUST be 0 in v1; any other value rejects (rev 2.3).
- **Batch**: `count: u8 (1..=255) ‖ AppMessage[]`.
- **Fragment**: `msg_id [16] ‖ idx: u16 ‖ total: u16 (≤ 64) ‖ chunk`; reassembled bytes are `inner_type: u8 ‖ inner_body` and are processed as a Content of that type (so large `KeyChange`/`RouteUpdate`/`Batch` contents are fragmented like anything else). `idx` counts from 0 and `idx < total`; `2 ≤ total ≤ 64` (`total = 1` would be a second encoding of an unfragmented Content, §4.1); `chunk` is at least 1 byte; `inner_type ∈ {0x02, 0x04, 0x05, 0x06, 0x07}` (0x00, 0x01 and 0x03 reject). Chunk sizing and consistency across the fragments of one `msg_id` are reassembly rules, not encoding rules (rev 2.3). Chunk shape (rev 2.4): chunks are maximal (1669 B) with the remainder last, `total = ⌈len/1669⌉ ≥ 2` for the `len` reassembled bytes; any other chunk shape rejects (enforced from M4).
- **RouteUpdate**: `count: u8 (1..=255) ‖ RouteDescriptor[]` replacing the routes by which the peer reaches us.
- **KeyChange**: `new IKSPublic ‖ HybridSign(old IK_sig, "SecMP-TR/1 keychange", fingerprint(new))` (5390 B ⇒ always fragmented; an unfragmented Content of type 0x05 rejects).
- **Receipt**: `kind: u8 (1 = delivered, 2 = read) ‖ count: u8 (1..=255) ‖ msg_id[16]×count`.
- **Control**: `code: u8 ‖ arg_len: u16 ‖ arg` — codes: 1 contact-removed, 2 session-reset-request.

`AppMessage { msg_id [16], kind: u8 (1 text, 2 attachment-inline, 3 view-once-text, 4 reaction, 5 edit, 6 delete), expire_after: u32, payload_len: u16, payload }`. Text ≤ 16 KiB UTF-8; inline attachments ≤ `MAX_MSG_BYTES`.

At the encoding layer `AppMessage.payload` and `Control.arg` are opaque length-prefixed bytes (rev 2.3, ADR-039): their layouts, and the UTF-8 and 16 KiB checks for text, are defined by an application-layer ADR before M7. `Profile.name` is checked as UTF-8 at decode (D.3); the asymmetry is intended.

### 7.7 Key change (identity succession)

Signed by the *old* `IK_sig`; receivers verify, mark the contact unverified, block outgoing messages until re-verification. Unsigned/unverifiable changes freeze the session with a warning. No "just accept" path.

### 7.8 Session reset

Either party MAY send `Control{session-reset-request}`; the peer issues a fresh invitation out of band.

---

## 8. SecMP-LINK — Client ↔ relay session

### 8.1 Underlying transport

- **Tor mode (default):** stream to the relay's v3 onion service via embedded Arti (§12.3), one isolated circuit per link. No TLS inside Tor.
- **Direct mode:** TLS 1.3/TCP, rustls (aws-lc-rs), key exchange restricted to `X25519MLKEM768`, ALPN `secmp/1`, no tickets/resumption/0-RTT, certificate pinned by `RelayRef.direct.spki_sha256`.

Both carry identical SecMP-LINK bytes. The PQ handshake below is mandatory in both modes.

### 8.2 Relay identity and `RelayInfo`

Relay long-term identity: `relay_sig` (Ed25519); `relay_fp = SHA-256("SecMP-LINK/1 relay-fp" ‖ relay_sig_pk)`. Per key generation `kid` (u32): `relay_dh` (X25519) and `relay_kem` (ML-KEM-1024).

```
RelayInfoV1 { ver, relay_sig_pk [32], kid: u32, relay_dh_pk [32], relay_kem_ek [1568], akc [32], valid_until: u64,
              sig: Ed25519(relay_sig, "SecMP-LINK/1 relayinfo" ‖ all preceding fields) }      ; 1741 B
```

The relay sends `RelayInfo` in response to every `HELLO`. The client MUST verify `sig`, `relay_fp`, `valid_until ≥ now`, and `akc` (if it holds an access key), and MUST use the info **only for the current link and never cache it** (caching would let a relay partition clients by handing out per-client keys). Static keys SHOULD be rotated monthly with overlapping validity; `valid_until − now ≤ 60 days`.

### 8.3 Handshake (hybrid NK-style; client anonymous, relay authenticated)

```
C → R:  HELLO { magic = "SECMP", ver }                                   ; cleartext record (layout D.1)
R → C:  RELAYINFO { RelayInfoV1 }                                        ; cleartext record
C → R:  HS1 { ver, kid, e_c [32], ek_c [1184], ct_stat = HybridKEM-1024.Encaps((relay_dh_pk, relay_kem_ek)) = (pk_e1 [32], ct_kem [1568]), mac1 [32] }   ; 2853 B
R → C:  HS2 { ver, e_r [32], ct_c: ML-KEM-768 ct [1088], mac2 [32] }    ; 1153 B

h0  = SHA-256("SecMP-LINK/1 h0" ‖ ver ‖ kid ‖ relay_fp ‖ e_c ‖ SHA-256(ek_c) ‖ pk_e1 ‖ SHA-256(ct_kem))
ss1 = HybridKEM-1024 shared secret
ck1 = HKDF-Extract(salt = h0, IKM = ss1)
mac1 = HMAC-SHA-256(ck1, "SecMP-LINK/1 hs1")                             ; relay verifies before responding (key confirmation, not DoS protection)
(ct_c, ss2) = HybridKEM-768.Encaps((e_c, ek_c)) on the relay side, where the hybrid ciphertext is (e_r, ct_c)
h1  = SHA-256(h0 ‖ mac1 ‖ e_r ‖ SHA-256(ct_c))
ck2 = HKDF-Extract(salt = h1, IKM = ck1 ‖ ss2)
mac2 = HMAC-SHA-256(ck2, "SecMP-LINK/1 hs2")                             ; client verifies
(k_c2r ‖ k_r2c ‖ sess_id) = HKDF-Expand(ck2, "SecMP-LINK/1 keys", 32+32+16)
```

Properties: relay authentication (only the holder of the `kid` static keys derives `ss1`); forward secrecy both ways (`ss2` is ephemeral–ephemeral); PQ confidentiality in both stages; client anonymity (no client long-term key). `sess_id` binds command signatures to this link (§9.2). DoS protection is provided by Tor intro-DoS defence and per-connection rate limits, not by `mac1`.

### 8.4 Frames

After HS2, every message in either direction is one frame:

```
Frame (4352 B) = XChaCha20-Poly1305.Seal(k_dir, nonce = 0^16 ‖ counter_dir (u64 BE), AD = "SecMP-LINK/1 frame" ‖ sess_id, pad(payload, 4336))
```

`counter_dir` is per-direction, starts at 0, `checked_add` (abort on overflow), strict `+1` on receive. After `LINK_MAX_FRAMES` or the link's lifetime (§10.6) the client opens a new link. Multi-frame commands/responses use continuation frames (App. D); every frame is exactly 4352 B.

---

## 9. SecMP-Q — Queue commands

### 9.1 Queue model and deterministic identifiers

A queue is created by its recipient on the recipient's relay with a fresh recipient key `recv_pk` and the sender key `send_pk` (the recipient generates the sender's seed and hands it to the sender inside the invitation or a `RouteUpdate`). Identifiers are derived, not chosen:

```
rid = SHA-256("SecMP-Q/1 rid" ‖ recv_pk)[0..16]
sid = SHA-256("SecMP-Q/1 sid" ‖ recv_pk ‖ send_pk)[0..16]
```

so that after a relay restart the recipient re-issues the identical `QUEUE_NEW` and the sender's stored `sid` and capability remain valid (`ERR_NOQUEUE` ⇒ recipient recreates at a random delay U[10 s, 5 min]; sender keeps retrying at its constant rate). `QUEUE_NEW` is signed by `recv_pk`, so nobody else can create a queue with that `rid`.

Relay state per queue: `recv_pk`, `send_pk`, `cells: VecDeque<{cell_id: u64, arrival: u64, cell, expiry_bucket}>`, `next_cell_id`, `created_bucket`, `last_fetch_bucket`. `cell_id` is per-queue, monotonically increasing from 1; `arrival` is a relay-global counter used for oldest-first selection in `FETCH_MULTI`. Buckets are hours since epoch (`u32`).

**After a relay restart** (the client observed `ERR_NOQUEUE`/`present = 2` and re-created the queue): the recipient MUST reset `committed_ack` to 0 and clear its `cell_id` dedup set for that queue; a sender that observed `ERR_NOQUEUE` MUST discard its `cell_id → outbox` map for that queue. The relay MUST answer a `FETCH` whose `ack ≥ next_cell_id` with `ERR_MALFORMED` (a stale ack would otherwise delete every new cell).

### 9.2 Command authentication

Every request frame carries `cmd_seq: u32` (per link, strictly increasing; the relay rejects `≤ last`; `CONT` frames repeat the continued command's `cmd_seq` and are exempt from the increase check). Every command except `PING` and `LINK_GET` in consume mode carries `sig = Ed25519.Sign(key, "SecMP-Q/1 " ‖ CMD_NAME ‖ sess_id ‖ cmd_seq ‖ command fields)`. `QUEUE_NEW` and `LINK_PUT` additionally carry a `token` (§9.6). Per-queue keys are pseudonymous capabilities, never linked to the IKS.

### 9.3 Commands (eight in v1; opcode 0x02 `SKEY` is reserved for v1.1 mailboxes)

| Command | Key fields | Response |
|---|---|---|
| `QUEUE_NEW` | `recv_pk`, `send_pk`, `token` (signed by recv key) | `OK_QUEUE_NEW { rid, sid }` \| `ERR_TOKEN` \| `ERR_FULL` \| `OK_QUEUE_NEW` also when the identical queue already exists (idempotent) |
| `SEND` | `sid`, `cell` (signed by send key) | `OK_SEND { cell_id, evicted: Option<cell_id> }` \| `ERR_NOQUEUE` \| `ERR_AUTH` |
| `FETCH` | `rid`, `ack: u64` (signed by recv key) | exactly `F` `CELLR` frames; errors are signalled in `CELLR.present` (2 = NOQUEUE, 3 = AUTH, 4 = MALFORMED) |
| `FETCH_MULTI` | `count ≤ 32`, then per entry `rid`, `ack`, `sig` (signature label `MFETCH`, App. A) | exactly `F_M` `CELLR` frames: first one `CELLR` with `present ∈ {2,3,4}` for each listed queue in error, then cells from the remaining queues oldest-first by `arrival`, then dummies |
| `QUEUE_DEL` | `rid` (signed by recv key) | `OK` |
| `LINK_PUT` | `ld_id`, `one_time`, `expires_bucket`, `owner_pk [32]`, `token`, `blob` (3 frames) | `OK` \| `ERR_EXISTS` \| `ERR_FULL` \| `ERR_TOKEN` |
| `LINK_GET` | `ld_id`, `mode: u8 (0 = consume, 1 = owner status; owner status is signed by `owner_pk`)` | 3 `LINKR` frames `{ present, consumed, blob }` (dummy blob when absent) |
| `PING` | – | `OK` |

**FETCH semantics.** `ack` is cumulative: the relay deletes all cells with `cell_id ≤ ack` before selecting, then returns the oldest `F` remaining cells (or dummies). A repeated `FETCH` with the same `ack` returns the same cells; clients drop duplicates by `cell_id`. Unacknowledged cells remain in the queue and count toward capacity. The client sets `ack` to the highest `cell_id` whose processing (decrypt, persist, or decision to discard) is committed — **every delivered cell is acknowledged**, whether or not it decrypted, once the decision is durable. The `FETCH`/`FETCH_MULTI` frame for slot k+1 (ack, `cmd_seq`, signature) is built after response k has been committed, or at a fixed δ before tick k+1 with whatever ack is committed by then — never before response k is processed, or every slot would re-fetch the same cells and halve the drain rate.

All responses are padded to `FRAME_SIZE`; success and error frames are indistinguishable on the wire.

### 9.4 Link data

`LINK_GET` in consume mode on a `one_time` blob returns it and deletes it atomically; later consume-mode calls return `present = 0, consumed = 1`. Owner-status mode (signed by `owner_pk`, which the inviter set at `LINK_PUT`) returns `present`/`consumed` and a dummy blob without consuming. Consumption markers expire with the blob's expiry.

### 9.5 Capacity and eviction

When a `SEND` arrives at a queue holding `QUEUE_CAPACITY` cells, the relay evicts the oldest cell and reports its `cell_id` in `evicted`. The sender maps evicted ids to its outbox; an evicted *real* message is re-encrypted (new message key) and re-sent at the next slot; an evicted dummy is forgotten. Because the recipient's drain rate exceeds the sender's rate whenever the recipient is online (§10.2), eviction happens only while the recipient is offline, and the newest `QUEUE_CAPACITY` cells — which always include recently (re)sent real messages — are what the recipient finds on return. The ratchet's fast-forward (§7.4) absorbs the evicted positions.

### 9.6 Tokens

v1: `token = HMAC-SHA-256(relay_access_key, "SecMP-Q/1 token" ‖ sess_id ‖ cmd_seq)`. `relay_access_key` is a 32-byte secret the operator distributes out of band; its commitment `akc` is published in `RelayInfo` and pinned in `RelayRef` so that a per-user key is detectable. v1.x replaces this with VOPRF anonymous tokens (M13).

### 9.7 Relay obligations (normative)

1. RAM only; nothing persisted; restart loses everything by design (clients recover via §9.1 and §10.4; an inviter whose owner-status query returns `present = 0, consumed = 0` before `expires` re-issues the identical `LINK_PUT` on a one-shot link).
2. No logging of commands, ids, addresses or timing. Only aggregate counters (total queues, cells, frames/s) without per-queue dimensions, and only if enabled.
3. Expiry by `CELL_TTL`, `QUEUE_IDLE_TTL`, link-data expiry, using hour buckets.
4. Global memory budget: when exceeded, `QUEUE_NEW`/`LINK_PUT` return `ERR_FULL`; `SEND` continues to be accepted (eviction bounds memory per queue).
5. Zeroize cell buffers on delete.
6. Fixed-size responses, in order, within the link.
7. Hostile-input handling: strict parsing, consistency rule, per-link frame-rate limit, per-connection handshake-rate limit, at most one link per underlying connection.
8. Idempotent `QUEUE_NEW`: an identical request (same keys) returns `OK_QUEUE_NEW` without side effects; a request with a known `recv_pk` but different `send_pk` is `ERR_AUTH`.

### 9.8 `RouteDescriptor`

```
RouteDescriptor { ver, kind: u8, len: u16, blob }
kind 0x01 RelayQueue    { relay: RelayRef, sid [16], send_seed [32], period_s: u16 ∈ PERIODS }     ; v1
kind 0x02 OnionEndpoint { onion [35], client_auth [32], cap [32] }                                 ; v1.1
kind 0x03 Mailbox       { relay: RelayRef, sid, send_seed, period_s }                              ; v1.1
```

`period_s` is the send period the recipient asks the sender to use for this queue (§10.2). v1 clients MUST ignore unknown kinds.

---

## 10. Constant-rate scheduling (client behaviour)

### 10.1 Invariant

**The sequence, size and timing of frames a client emits MUST be a function only of (mode, configured periods, set of links, the randomised link phases/lifetimes fixed at link start), never of user activity, message availability, focus state or window visibility.** Real and dummy cells are produced by the same code path and are indistinguishable to the relay. The cell for slot k+1 — including its ratchet update and persistence — MUST be fully prepared before tick k+1; the tick only writes pre-built bytes, so persistence cost cannot shift timing.

### 10.2 Periods, modes and drain

- Every recv-queue has a **period** `P_q ∈ PERIODS`, chosen by its recipient and announced in the `RouteDescriptor`. The sender emits exactly one `SEND` per `P_q` on that queue's link. Since each queue has exactly one sender, its inbound rate is `1/P_q`.
- **Strict mode** (default): one isolated link per queue. Send-links: one `SEND` per `P_q`. Recv-links: one `FETCH` per `P_q` returning `F = 4` cells ⇒ drain 4× inbound, always sufficient.
- **Balanced mode**: one link per relay. Every `T_BALANCED` = 10 s: one `SEND` to the next send-queue, in fixed round-robin order, **whose previous `SEND` is at least `P_q` ago** (if no queue is due, the slot carries a `PING` — in every mode a sender sends to a queue at most once per `P_q`), and one `FETCH_MULTI` over all recv-queues on that relay returning `F_M = 8`. The relay learns which queues belong together (accepted). The recipient MUST choose `P_q` for its queues so that `Σ_q 1/P_q ≤ F_M / (2·T_BALANCED)` (= 0.4/s: ≤ 4 contacts at 10 s, ≤ 8 at 20 s, ≤ 16 at 40 s, ≤ 32 at 80 s); when adding contacts pushes the sum over the bound, it rotates queues with a larger period via `RouteUpdate`. Queues in rotation overlap (§10.6 rule 4) count toward the bound and toward the 32-queue `FETCH_MULTI` limit; a rotation that would exceed either MUST NOT start. Send latency in Balanced mode is up to `max(P_q, N × T_BALANCED)`.
- **Low-bandwidth mode**: as Balanced with `T_LOWBW` = 30 s (bound `Σ 1/P_q ≤ 8/60 ≈ 0.133/s`: ≤ 5 contacts at 40 s, ≤ 10 at 80 s).
- Direct (non-Tor) mode implies Balanced.

Bandwidth (frames are 4352 B; Tor adds ≈ 7 % cell overhead): **Strict**, one contact at `P = 10 s`: `SEND`+`OK_SEND` (2 frames) + `FETCH`+4×`CELLR` (5 frames) per 10 s ≈ 3.05 KB/s ≈ 263 MB/day, ≈ 282 MB/day inside Tor — per contact. **Balanced**: 11 frames per 10 s ≈ 4.8 KB/s ≈ 414 MB/day (≈ 443 MB in Tor) in total, independent of contact count. **Low-bandwidth**: 11 frames per 30 s ≈ 1.6 KB/s ≈ 138 MB/day. Final values after M6 measurements (ADR-018; cap ≈ 300 MB/day/contact in Strict).

### 10.3 Slot procedure

```
on tick(link):                      ; pre-built material only
    if link.kind == send:       write pre-built SEND frame; on response: OK_SEND{evicted: Some(id)} → outbox.requeue_if_real(id); ERR_NOQUEUE → route.mark_dead (recipient will recreate; keep sending); ERR_AUTH → alert
    if link.kind == recv:       write pre-built FETCH(ack = committed_ack); on response: for each present CELLR: dedup by cell_id; Decrypt; commit; advance committed_ack
    if link.kind == balanced:   write pre-built SEND (round-robin) and FETCH_MULTI
    prepare(next slot)          ; build next cell (outbox or dummy), run ratchet, persist — off the tick path; FETCH frames are built after the previous response is committed (§9.3)
```

Requests are pipelined: a tick emits its frame even if the previous response is outstanding (max 2 outstanding; a third ⇒ tear the link down and re-establish per §10.6 rule 1). Reconnects and Tor bootstrap are the only activity-independent irregularities.

### 10.4 Outbox and delivery semantics

- An `AppMessage` is *queued* locally, *relayed* when `OK_SEND` arrived and the cell was not later reported evicted, and *delivered* when an E2E `Receipt{delivered}` arrives (on by default for verified contacts; sent in-slot). The outbox survives restarts. Messages never relayed within 30 days are surfaced as failed.
- Relay restart: `ERR_NOQUEUE` on recv-queues ⇒ recipient re-creates identical queues (§9.1) at random delay; `ERR_NOQUEUE` on send-queues ⇒ keep sending (the recipient will recreate). No `RouteUpdate` is needed. Real messages that were in the relay at restart are lost and re-sent from the outbox if not yet receipted.

### 10.5 Things a v1 client MUST NOT do

Send typing indicators, presence, read receipts by default, link previews, or any request outside the slot schedule except the control operations listed in §10.6.

### 10.6 Correlation mitigations (normative)

Constant rate hides *what* and *how much*; the following rules blur *when* links and queues start, stop and change, which is what lets an operator statistically correlate queues of one client. They do not make correlation impossible (see `01-threat-model.md` §3.1).

1. **Link phases:** each link starts at an independent random offset U[0, 3 min] after the trigger (app start, mode change, reconnect, new contact or route) and has an independent lifetime `LINK_LIFETIME` ~ U[6 h, 24 h]; at the end it re-handshakes on a fresh circuit at a random offset. Links of one client therefore neither start nor re-key together (except at process exit, which is inherent).
2. **Control operations on fresh links:** `QUEUE_NEW`, `QUEUE_DEL`, `LINK_PUT`, `LINK_GET`(owner status) each run on their own isolated one-shot link, delayed by U[1 min, 60 min] from any related operation, except where a user is waiting: the invitee's `LINK_GET`(consume) and the inviter's `LINK_PUT` happen promptly, on one-shot links.
3. **Queue pool:** clients keep a pool of ≥ 2 pre-created recv-queues per relay (created at random times, fetched at their period like any queue so they never hit `QUEUE_IDLE_TTL`) so that accepting or creating an invitation never requires a `QUEUE_NEW` at that moment.
4. **Rotation overlap:** after a `RouteUpdate` switches a sender to a new queue, the sender sends only dummies on the old queue and **re-sends on the new queue every real message among the last `QUEUE_CAPACITY` cells it sent on the old queue** (receivers deduplicate by `msg_id`; this closes the window in which real cells stranded in the old queue could fall outside the new chain's `SKIP_WINDOW`). The recipient keeps fetching the old queue for U[1 h, 24 h] and sends `QUEUE_DEL` only after a `FETCH` of it returned no present cell.
5. **Invitation queue retirement:** the responder replaces the invitation queue with a pooled queue via `RouteUpdate`; the invitation queue is retired per rule 4.

---

## 11. Security properties and verification obligations

### 11.1 Required properties per layer

| Layer | Property | Against |
|---|---|---|
| HX | SK secrecy incl. forward secrecy (OPK, EK) and PQ confidentiality; mutual classical authentication (injective agreement on `transcript`); identity confidentiality of I against the relay and against a later invitation leak (`K_id`); transcript binding; offline deniability | Network attacker, relay, HNDL quantum |
| TR | Body confidentiality/integrity with key commitment; header confidentiality (not commitment); forward secrecy per message; post-compromise security after one hybrid step (classical and PQ); replay/reorder resistance; robustness to loss of any prefix of a chain | Network attacker, relay, HNDL |
| LINK | Relay authentication; PQ confidentiality/integrity of commands; forward secrecy; client anonymity; replay resistance | Network attacker, Tor relays, HNDL |
| Q | Capability-only access; unlinkability of `rid`/`sid`; deterministic re-creation; indistinguishability of real vs dummy cells; detectability of per-user access keys (`akc`) | Relay operator |
| Scheduler | Activity-independence of the traffic pattern; bounded correlation of link/queue lifecycle events (§10.6) | Relay operator, network observer |

### 11.2 Formal models (deliverables)

`formal/CLAIMS.md` lists every query; the reviewer fixes the query set before modelling starts (including queries expected to be *false*, e.g., KCI resistance of HX, PQ authentication — so that the models cannot be weakened to go green). Models: `formal/hx.pv`, `formal/tr.pv` (bounded, 3 steps), `formal/link.pv`; ProVerif is mandatory in CI. Tamarin for the TR+HX composition is optional (M11+).

### 11.3 Accepted leakage (shown on the UI's "what the relay can see" page)

1. Per-queue online periods (constant-rate streams start and stop with the client), blurred by §10.6.
2. Statistical correlation of queues over long observation (lifecycle events), reduced but not eliminated by §10.6; in Balanced/direct modes the grouping is explicit (and direct mode reveals the IP).
3. Control operations are visible as such, from anonymous one-shot links.
4. Queue lengths and eviction events (the relay is the store); a *contact* learns from eviction notices that the recipient was offline for more than ~`QUEUE_CAPACITY × P_q`.
5. Availability: the relay can drop, delay or reorder; gaps in `Content.seq` are surfaced.

---

## 12. Transport neutrality and v1.1 hooks

### 12.1 `QueueTransport` trait (secmp-transport)

```rust
#[async_trait]
pub trait QueueTransport: Send + Sync {
    async fn create_queue(&self, recv: &SigningKey, send_pk: &VerifyingKey, token: &Token) -> Result<(RecvCap, SendCap)>;  // idempotent
    async fn send(&self, to: &SendCap, cell: &Cell) -> Result<SendOutcome>;                 // Ok { cell_id, evicted }
    async fn fetch(&self, from: &RecvCap, ack: CellId) -> Result<Vec<(CellId, Cell)>>;      // ≤ F real cells; relay dummies already filtered
    async fn fetch_multi(&self, from: &[(&RecvCap, CellId)]) -> Result<Vec<(QueueRef, CellId, Cell)>>;
    async fn delete_queue(&self, q: &RecvCap) -> Result<()>;
    async fn put_link_data(&self, id: LdId, owner: &SigningKey, blob: &LinkBlob, one_time: bool, expires: Bucket, token: &Token) -> Result<()>;
    async fn get_link_data(&self, id: LdId, mode: LinkGetMode) -> Result<LinkGetOutcome>;
}
```

`RecvCap`/`SendCap` are opaque serialisable capabilities. v1.1 adds `OnionEndpointTransport` and `MailboxTransport` with identical cell semantics; sessions never see which transport carried a cell.

### 12.2 Envelope rules that keep v1.1 a transport swap

Nothing outside the E2E cell identifies sender, session or transport; route changes are E2E content; cells are idempotent at the application layer (`msg_id` dedup); the scheduler is per-link and transport-agnostic.

### 12.3 Tor integration (client side)

Arti 2.6.x (`arti-client` 0.46.x, features `onion-service-client`, `rustls`; **not** `hs-pow-full`, which is experimental and pulls LGPL dependencies — ADR-024), embedded in the client; Tor state directory next to the encrypted profile. One `IsolationToken` per link. No link is opened before Tor has bootstrapped unless the user explicitly chose direct mode. The relay hosts its onion service with C tor (`05-relay-ops.md`); the relay's PoW defence is **off** in v1 because clients cannot solve PoW without the experimental feature (ADR-024); intro-DoS defence and rate limits remain.

---

## Appendix A — Domain-separation labels (exhaustive)

```
"SecMP-HybridKEM-768/1"  "SecMP-HybridKEM-1024/1"  "SecMP-HybridSign/1"  "SecMP-commit/1"
"SecMP-FP/1"  "SecMP-SAS/1"
"SecMP-INV/1 blob"  "SecMP-INV/1 linkdata"
"SecMP-HX/1 transcript"  "SecMP-HX/1 sk"  "SecMP-HX/1 idkey"  "SecMP-HX/1 bundle"  "SecMP-HX/1 initkey"  "SecMP-HX/1 initcell"  "SecMP-HX/1 inner"
"SecMP-TR/1 init"  "SecMP-TR/1 rk"  "SecMP-TR/1 msgkeys"  "SecMP-TR/1 hdr"  "SecMP-TR/1 body"  "SecMP-TR/1 keychange"
"SecMP-LINK/1 relay-fp"  "SecMP-LINK/1 relayinfo"  "SecMP-LINK/1 h0"  "SecMP-LINK/1 hs1"  "SecMP-LINK/1 hs2"  "SecMP-LINK/1 keys"  "SecMP-LINK/1 frame"
"SecMP-Q/1 rid"  "SecMP-Q/1 sid"  "SecMP-Q/1 akc"  "SecMP-Q/1 token"
"SecMP-Q/1 QUEUE_NEW"  "SecMP-Q/1 SEND"  "SecMP-Q/1 FETCH"  "SecMP-Q/1 MFETCH"  "SecMP-Q/1 QUEUE_DEL"  "SecMP-Q/1 LINK_PUT"  "SecMP-Q/1 LINK_GET"
"SecMP-STORE/1 identity"  "SecMP-STORE/1 prekeys"  "SecMP-STORE/1 relays"  "SecMP-STORE/1 contacts"  "SecMP-STORE/1 sessions"
"SecMP-STORE/1 outbox"  "SecMP-STORE/1 messages"  "SecMP-STORE/1 invitations"  "SecMP-STORE/1 settings"
"SecMP-vectors/1"        (test-vector seed derivation only, vectors/SCHEMA.md)
```

Test-only labels (such as "SecMP-TR/1 state-digest", vectors/SCHEMA-4.9-tr.md) are vector constructs, not wire labels, and are not part of this set (rev 2.4).

Rules: labels are ASCII, used as raw bytes with no length prefix or terminator, and **the set is prefix-free** — no label is a prefix of another (rev 2.2 renamed `"SecMP-INV/1"` → `"SecMP-INV/1 blob"`, `"SecMP-HX/1 init"` → `"SecMP-HX/1 initcell"`, and gave `FETCH_MULTI` the label `MFETCH`; ADR-035). Both implementations carry a unit test that re-reads this list and checks prefix-freeness. `HybridSign` accepts only `"SecMP-HX/1 bundle"` and `"SecMP-TR/1 keychange"`. Any new label requires a spec change and an ADR.

## Appendix B — Sizes

| Object | Bytes |
|---|---|
| X25519 pk/ss · Ed25519 pk/sig | 32/32 · 32/64 |
| ML-KEM-768 ek/ct/ss · ML-KEM-1024 ek/ct/ss | 1184/1088/32 · 1568/1568/32 |
| ML-DSA-65 pk/sig · `HybridSig` | 1952/3309 · 3373 |
| `IKSPublic` | 2017 |
| `PrekeyBundle` | 7775 |
| `LinkDataV1` padded / blob | 12288 / 12360 (3 frames) |
| `HeaderV1` / `hdr_ct` | 2314 / 2330 |
| Cell / `BODY_LEN` / Frame / frame plaintext | 4096 / 1710 / 4352 / 4336 |
| Handshake `Outer` / padded / cells | 9362 / 12018 / 3 × 4096 |
| `RelayInfoV1` / HS1 / HS2 | 1741 / 2853 / 1153 |
| `InvitationV1` (no direct) | 241 (≈ 322 chars base64url) |

## Appendix C — Test-vector obligations

`vectors/` MUST contain vectors for: HybridKEM (both sets) — including decapsulation of a bit-flipped KEM ciphertext, which is a **positive** case whose output is the implicit-rejection-derived hybrid secret (FIPS 203 rejects implicitly; only length errors and all-zero X25519 outputs reject explicitly); HybridSign (incl. strict-Ed25519 negatives: `S ≥ L`, non-canonical `A`, small-order `A`, wrong label); MsgEncrypt and CAEAD (incl. wrong MAC/COM, truncation, wrong AD/nonce/key); SAS; fingerprints; a full HX run with fixed randomness (both sides derive identical `SK`, `transcript`, `K_id`); a TR transcript of 40 messages with two full round trips, out-of-order delivery, a dropped first-message-of-chain, and a 10 000-message gap (fast-forward); LINK handshake + first three frames each direction; canonical encodings (positive) and ≥ 200 malformed encodings (negative, incl. wrong padding) for every structure. The exact case tables live in `vectors/SCHEMA.md`, written by the reviewer. **Vectors are generated by an independent reference implementation** (`ref/`, Python, written from this document alone in a separate session — ADR-026) and cross-checked against the Rust implementation; they are frozen thereafter. External vectors: Wycheproof (X25519, Ed25519, XChaCha20-Poly1305, HKDF, HMAC, ML-KEM, ML-DSA) and NIST ACVP (ML-KEM, ML-DSA) on every target.

## Appendix D — Byte layouts (normative)

All integers big-endian. `[n]` = fixed n bytes. Structures are listed with their exact field order; nothing else is on the wire.

### D.1 Records before the link handshake (cleartext, over the byte stream)

`Record = len: u16 ‖ body`. Bodies:

```
HELLO      = 0x01 ‖ "SECMP" ‖ ver(0x01)                                             (7 B)
RELAYINFO  = 0x02 ‖ RelayInfoV1                                                     (1 + 1741)
HS1        = 0x03 ‖ ver ‖ kid u32 ‖ e_c[32] ‖ ek_c[1184] ‖ pk_e1[32] ‖ ct_kem[1568] ‖ mac1[32]   (1 + 2853)
HS2        = 0x04 ‖ ver ‖ e_r[32] ‖ ct_c[1088] ‖ mac2[32]                          (1 + 1153)
RelayInfoV1 = ver ‖ relay_sig_pk[32] ‖ kid u32 ‖ relay_dh_pk[32] ‖ relay_kem_ek[1568] ‖ akc[32] ‖ valid_until u64 ‖ sig[64]
```

After HS2 the stream carries only 4352-byte frames (no length prefix).

### D.2 Frame plaintext (4336 B, padded)

`op: u8 ‖ cmd_seq: u32 ‖ fields ‖ pad`. Request opcodes (client → relay):

```
0x01 QUEUE_NEW    recv_pk[32] ‖ send_pk[32] ‖ token[32] ‖ sig[64]           ; sig by recv key over "SecMP-Q/1 QUEUE_NEW"‖sess_id‖cmd_seq‖recv_pk‖send_pk‖token
0x02 SKEY         (reserved, v1 relay answers ERR_MALFORMED)
0x03 SEND         sid[16] ‖ cell[4096] ‖ sig[64]                             ; sig by send key over "SecMP-Q/1 SEND"‖sess_id‖cmd_seq‖sid‖cell
0x04 FETCH        rid[16] ‖ ack u64 ‖ sig[64]                                ; by recv key over "SecMP-Q/1 FETCH"‖sess_id‖cmd_seq‖rid‖ack
0x05 FETCH_MULTI  count u8 (1..=32) ‖ { rid[16] ‖ ack u64 ‖ sig[64] } × count ; each sig by that queue's recv key over "SecMP-Q/1 MFETCH"‖sess_id‖cmd_seq‖rid‖ack   (label MFETCH keeps the label set prefix-free)
0x06 QUEUE_DEL    rid[16] ‖ sig[64]                                          ; by recv key over "SecMP-Q/1 QUEUE_DEL"‖sess_id‖cmd_seq‖rid
0x07 LINK_PUT     ld_id[16] ‖ one_time u8 ‖ expires_bucket u32 ‖ owner_pk[32] ‖ token[32] ‖ sig[64] ‖ blob_part[4160]   ; frame 1 of 3; sig by owner key over "SecMP-Q/1 LINK_PUT"‖sess_id‖cmd_seq‖ld_id‖one_time‖expires_bucket‖owner_pk‖token‖SHA-256(blob)
0x08 LINK_GET     ld_id[16] ‖ mode u8 ‖ sig[64] (zeros when mode = 0)         ; mode 1 sig by owner key over "SecMP-Q/1 LINK_GET"‖sess_id‖cmd_seq‖ld_id‖mode
0x09 PING         (no fields)
0x7F CONT         idx u8 ‖ data                                              ; continuation of the previous multi-frame command with the same cmd_seq (LINK_PUT: idx 1,2 carry 4100 B each: 4160 + 4100 + 4100 = 12360); LINK_PUT receives ONE response frame after its third frame
```

Response opcodes (relay → client); `cmd_seq` echoes the request:

```
0x80 OK
0x81 OK_QUEUE_NEW rid[16] ‖ sid[16]
0x82 OK_SEND      cell_id u64 ‖ evicted_present u8 ‖ evicted_id u64          ; evicted_id is always present and MUST be 0 when evicted_present = 0
0x83 CELLR        present u8 ‖ rid[16] ‖ cell_id u64 ‖ cell[4096]     ; F or F_M frames per FETCH / FETCH_MULTI. present: 0 dummy (rid and cell_id zero, cell random), 1 cell, 2 NOQUEUE, 3 AUTH, 4 MALFORMED (for 2–4: rid set, cell_id zero, cell random). For FETCH, rid is zero on present 0/1.
0x84 LINKR        present u8 ‖ consumed u8 ‖ blob_part[4160]                              ; frame 1 of 3, then two 0xFF CONT frames with 4100 B each
0x8F ERR          code u8   ; 1 TOKEN, 2 FULL, 3 NOQUEUE, 4 AUTH, 5 EXISTS, 6 MALFORMED, 7 RATE
0xFF CONT         idx u8 ‖ data
```

Multi-frame responses (CELLR × F, LINKR + CONT) are emitted back-to-back with the same `cmd_seq`. A relay MUST answer every request with the exact number of frames the table specifies, in request order.

### D.3 Invitation, relay reference, link data

```
RelayRef     = ver ‖ relay_fp[32] ‖ onion[35] ‖ akc[32] ‖ direct_present u8 ‖ [host_len u16 ‖ host ‖ port u16 ‖ spki_sha256[32]]
InvitationV1 = ver ‖ kind u8 ‖ RelayRef ‖ ld_id[16] ‖ link_key[32] ‖ inviter_fp[32] ‖ inv_sid[16] ‖ inv_send_seed[32] ‖ inv_period_s u16 ‖ expires u64
Profile      = name_len u8 ‖ name (UTF-8, ≤ 64) ‖ avatar_present u8 ‖ [avatar_sha256[32]]
LinkDataV1   = ver ‖ IKSPublic[2017] ‖ PrekeyBundle[7775] ‖ Profile ‖ created u64        → pad to 12288
LinkBlob     = N[24] ‖ COM[32] ‖ ct[12288 + 16]                                          (12360)
IKSPublic    = ver ‖ ik_ed25519[32] ‖ ik_mldsa65[1952] ‖ ik_dh[32]
PrekeyBundle = ver ‖ spk_id u32 ‖ spk_dh[32] ‖ spk_kem[1568] ‖ rpk_kem[1184] ‖ spk_expiry u64 ‖ opk_present u8 ‖ opk_id u32 ‖ opk_dh[32] ‖ opk_kem[1568] ‖ sig[3373]
```

`RelayRef.direct` (rev 2.3, ADR-039): `host` is 1..=253 bytes (`host_len` 1..=253), each byte in 0x21..=0x7E, and `port ≠ 0`; any other value rejects. `onion` validity: §5.3.

### D.4 Handshake envelope

```
Outer        = ver ‖ ek_I[32] ‖ spk_id u32 ‖ opk_id u32 ‖ ct_spk[1568] ‖ ct_opk[1568] ‖ inner_ct[6185]    (9362) → pad to 12018
inner_ct     = N2[24] ‖ COM[32] ‖ ct( IKSPublic[2017] ‖ first_msg[4096] )[6113 + 16]
HandshakeCell_i = N_i[24] ‖ COM[32] ‖ ct( init_id[16] ‖ i u8 ‖ total u8 (=3) ‖ chunk[4006] )[4024 + 16]        (4096)
```

### D.5 Ratchet cell and content

```
Cell      = hdr_nonce[24] ‖ hdr_ct[2330] ‖ body_ct[1710] ‖ tag[32]
HeaderV1  = ver ‖ flags u8 (0) ‖ dh_pk[32] ‖ pn u32 ‖ n u32 ‖ ek_pq[1184] ‖ ct_pq[1088]         (2314)
Content   = ver ‖ type u8 ‖ seq u64 ‖ ts u64 ‖ body_len u16 ‖ body ‖ pad → 1710
AppMessage = msg_id[16] ‖ kind u8 ‖ expire_after u32 ‖ payload_len u16 ‖ payload
Fragment  = msg_id[16] ‖ idx u16 ‖ total u16 ‖ chunk
RouteDescriptor = ver ‖ kind u8 ‖ len u16 ‖ blob ;  RelayQueue blob = RelayRef ‖ sid[16] ‖ send_seed[32] ‖ period_s u16
Dummy body      = (empty)
Handshake body  = Profile ‖ caps u32 (0) ‖ route_count u8 (1..=255) ‖ RouteDescriptor[]
Batch body      = count u8 (1..=255) ‖ AppMessage[] × count
RouteUpdate body = count u8 (1..=255) ‖ RouteDescriptor[] × count
KeyChange body  = IKSPublic[2017] ‖ sig[3373]
Receipt body    = kind u8 ‖ count u8 (1..=255) ‖ msg_id[16] × count
Control body    = code u8 ‖ arg_len u16 ‖ arg
Reassembled Fragment = inner_type u8 ‖ inner_body
```

Rules added in rev 2.3 (ADR-039): `caps` MUST be 0 and any other value rejects. Fragment: `idx` counts from 0 with `idx < total`, `2 ≤ total ≤ 64`, `chunk` ≥ 1 byte; the reassembled `inner_type` ∈ {0x02, 0x04, 0x05, 0x06, 0x07} (0x00, 0x01 and 0x03 reject); chunk sizing and consistency across fragments are reassembly rules, not encoding rules. Content type 0x05 (KeyChange) never appears unfragmented: an unfragmented Content of type 0x05 rejects. `AppMessage.payload` and `Control body.arg` are opaque at the encoding layer (§7.6).

### D.6 Signatures over commands

The signed message is always `"SecMP-Q/1 " ‖ CMD_LABEL ‖ sess_id[16] ‖ cmd_seq u32 ‖ <fields in the order listed in D.2, excluding sig and excluding blob parts (use SHA-256(blob) for LINK_PUT)>`, where `CMD_LABEL` is the command name except for `FETCH_MULTI`, whose label is `MFETCH`.
