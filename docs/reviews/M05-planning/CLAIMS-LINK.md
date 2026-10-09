## LINK — SecMP-LINK + SecMP-Q command binding, sessions (`formal/link.pvl` + `formal/link/<session>.pv`, M5)

*Planner draft v2 for the reviewer, 2026-10-03 (PRUEF-M5 PR-15 applied; layout per OPEN-M5-16 A, decided). §11.2 (`docs/03:711`): the reviewer fixes this query set, including the
queries expected to be false, before modelling starts. Layout per OPEN-M5-16 (A), as ADR-046/O-18 for HX. Rows marked
**M11** are equivalence properties and are not gated in M5 (as H7 → F-M11, O-8).*

Model: one honest relay R with long-term `relay_sig` (Ed25519) and, for one key generation `kid`, static keys
`relay_dh` (X25519) and `relay_kem` (ML-KEM-1024); `relay_fp` = h("SecMP-LINK/1 relay-fp", vk(relay_sig)) is pinned by
every honest client (§8.2). Honest clients C have **no long-term key** (§8.3 "client anonymous"); each link draws fresh
`e_c` (X25519), `ek_c` (ML-KEM-768) and the HybridKEM-1024 ephemeral. The attacker is Dolev–Yao on the network (Tor
relays and the path to the relay included), may open its own links to R as an anonymous client, may replay any record
or frame, and holds every value an ordinary user holds: the shared `relay_access_key` (§9.6, distributed to all users)
and its own queue keys. R is **honest** in this model: §LINK proves what a client gets from the link layer against
third parties; what R itself learns is §11.3 accepted leakage. Flow exactly §8.3: HELLO; RELAYINFO = RelayInfoV1 signed
by `relay_sig`; HS1 = (kid, e_c, ek_c, pk_e1, ct_kem, mac1); HS2 = (e_r, ct_c, mac2); keys `(k_c2r, k_r2c, sess_id)`;
then frames per §8.4 carrying Q commands per §9.2/D.6 (signature over label ‖ sess_id ‖ cmd_seq ‖ fields; token
HMAC(access_key, label ‖ sess_id ‖ cmd_seq)). Bounds: two links per client process, counters ∈ {0, 1, 2} per direction,
at most two commands per link.
Abstractions (each a ProVerif constructor with the listed equation; nothing else is assumed):
  X25519: exp(exp(g,a),b) = exp(exp(g,b),a)                       ; low-order points, the all-zero check: tests
  ML-KEM-1024, ML-KEM-768: decaps(dk, encaps_ct(pk(dk), r)) = encaps_ss(pk(dk), r) ; implicit rejection not modelled
  hkem(ss_kem, ss_dh, ct_kem, ek, pk_dh, pk_e, V)                 ; §3.2 combiner, free one-way (SHA3-256); secret if
                                                                   ; either ss_kem or ss_dh is secret
  h(x)                                                             ; SHA-256 (h0, h1, relay_fp, inner hashes)
  extract(salt, ikm), expand(prk, info)                            ; HKDF-SHA-256, free one-way; three outputs of
                                                                   ; expand(ck2, "SecMP-LINK/1 keys") as projections
  mac(k, m)                                                        ; HMAC-SHA-256 (mac1, mac2, token), free one-way
  sign(sk, m) / verify(vk(sk), m, sign(sk, m)) = true              ; Ed25519 (RelayInfo, queue keys); strictness: tests
  aead(k, ctr, ad, m) / open(k, ctr, ad, aead(k, ctr, ad, m)) = m  ; XChaCha20-Poly1305 frame, nonce = the counter;
                                                                   ; pad is the identity; the 4352-B length is a test
Oracles (enabled per session): DHO — dh_break(exp(g,a), exp(g,b)) = exp(exp(g,a),b) for every honest X25519 pair of the
session; KEMO — kem_break(encaps_ct(ek, r)) = encaps_ss(ek, r) for the ML-KEM-1024 (static) and ML-KEM-768
(ephemeral) encapsulations; SIGO — forge(vk(sk), m) = sign(sk, m) for `relay_sig` (a quantum break of Ed25519).
Compromise (each emits an event of the same name and outputs the values on c in the phase the query states):
  RevealStatic(s, kid)  relay_dh and relay_kem secrets of kid
  RevealSig(s)          relay_sig secret
  RevealEph(s, C)       the client's e_c secret and dk_c of one link (sanity only: "ephemerals were discarded")
  RevealQKey(s, q)      one queue's signing key
Events:
  RInfo(s, kid, fp, akc)                    R signs a RelayInfo
  CStart(s, fp, kid, h0)                    C accepted RELAYINFO (§8.2 checks) and sent HS1
  RAccept(s, kid, h0, h1, sid, k1, k2)      R verified mac1 and sent HS2
  CAccept(s, fp, kid, h0, h1, sid, k1, k2)  C verified mac2
  CSend / RRecv(s, sid, ctr, m)             frame c2r sealed / opened; RSend / CRecv for r2c
  CSign(s, sid, cmd_seq, cmd, qpk)          C signs a command with queue key qpk
  RExec(s, sid, cmd_seq, cmd, qpk)          R executes a command after its signature verified

| ID | Property | Query (sketch) | Assumptions | Expected | M |
|---|---|---|---|---|---|
| L1 | Relay authentication (implicit, with key confirmation at mac2) | inj-event(CAccept(s,fp,kid,h0,h1,sid,k1,k2)) ==> inj-event(RAccept(s,kid,h0,h1,sid,k1,k2)) for fp = R's pinned fp | lClean: no oracle, no compromise; attacker opens its own links | true | M5 |
| L1a | … with the classical break | as L1 | lDH: DHO (static and ephemeral DH); `relay_kem` keeps ss1 secret | true | M5 |
| L1b | … with the PQ break | as L1 | lKEM: KEMO; `relay_dh` keeps ss1 secret | true | M5 |
| L1c | Sanity: both breaks defeat relay authentication | as L1 | lBoth: DHO and KEMO — the attacker computes ss1 from HS1 and answers its own HS2 | **false** | M5 |
| L2 | Relay authentication rests on `relay_sig` (no PQ authentication, §1.2 `docs/03:39`) | as L1 | lSig: RevealSig in phase 0 (SIGO gives the same trace): the attacker signs a RelayInfo with its own static keys under the pinned `relay_sig_pk` | **false** | M5 |
| L3 | Confidentiality of commands and responses (incl. PQ) | event(CSend(s,sid,ctr,m)) && attacker(m) ==> false, and the same for RSend, m a fresh private payload, for links whose CAccept names R's fp | lClean, lDH, lKEM (each is a separate claim line L3, L3a, L3b) | true | M5 |
| L3c | Sanity: both breaks defeat confidentiality | as L3 | lBoth | **false** | M5 |
| L4 | Frame integrity, order and replay resistance per direction | event(CStart(s,fp,kid,h0)) && inj-event(RRecv(s,sid,ctr,m)) ==> inj-event(CSend(s,sid,ctr,m)) for the link whose HS1 the honest C produced; inj-event(CRecv(s,sid,ctr,m)) ==> inj-event(RSend(s,sid,ctr,m)) | lClean, lDH, lKEM; the attacker re-delivers HS1 (OPEN-3: R answers as a new handshake) and any frame | true | M5 |
| L5 | Forward secrecy of the link keys | phase 0: honest links complete, C discards its ephemerals, R its `sk_er`; phase 1: RevealStatic, RevealSig; not attacker(m) for phase-0 payloads | lFS | true | M5 |
| L5a | FS under a later classical break (HNDL) | as L5 | lFSDH: as lFS plus DHO in phase 1 (ss2's ML-KEM-768 part stays secret) | true | M5 |
| L5b | Sanity: FS rests on discarding the client ephemerals | as L5 | lFSEph: as lFS plus RevealEph in phase 1 | **false** | M5 |
| L6 | `sess_id` binding of command signatures; one execution per command | inj-event(RExec(s,sid,cmd_seq,cmd,qpk)) ==> inj-event(CSign(s,sid,cmd_seq,cmd,qpk)) for an honest qpk (§8.3 `docs/03:560`, §9.2 `:593`) | lClean; two links of the same client; the attacker replays signed frames across links; R executes each cmd_seq at most once per link (process structure) | true | M5 |
| L6a | Sanity: the queue key is the capability | as L6 | lQKey: RevealQKey in phase 0 | **false** | M5 |
| L7 | `akc` pinning (§8.2 `:539`, §5.3 `:229`; consistency) | event(CAccept(s,fp,kid,…)) ==> akc of the accepted RelayInfo = h("SecMP-Q/1 akc", k) for the access key k the client holds | lClean, clients holding k | true | M5 |
| L8 | Reachability, one line per accept event and session | in every base file: event(CStart(s,…)); event(RAccept(s,…)) && event(CAccept(s,…)) with equal sid (the honest pair completes); event(RExec(s,…)) | — | **false** per line | M5 |
| L9 | Client anonymity (structural) | no query: C holds no long-term secret; HS1 carries only fresh values (`docs/03:560`); test C-15 | — | by construction | M5 |
| L10 | Indistinguishability of success and error responses (§9.3 `:610`) | diff-equivalence: choice[success, error] of the same command on an honest link, response frames observed by the network attacker | lClean | true (lengths are a test: V-16, Q-57) | **M11** |
| L11 | Unlinkability of a client's links at the link layer (§11.1 LINK "client anonymity", `docs/03:705`, in its equivalence form) | equivalence: (C1 opens links a, b) ≈ (C1 opens a, C2 opens b), command contents fresh | lClean; R is not the attacker (R links queues by design, §11.3 items 1–2) | true | **M11** |
| L12 | Real vs dummy cells and blobs (§11.1 Q, §10.1) | equivalence: choice[real cell, dummy] in SEND and in CELLR/LINKR | lClean | true | **M11** |
| — | Agreement of R with C (client authentication) | — | — | **not claimed**: C is anonymous (§8.3); `mac1` is key confirmation of `ss1`, not of an identity | — |

Gate rule (M5): L1, L1a, L1b, L3, L3a, L3b, L4, L5, L5a, L6 and L7 must be proved true; L1c, L2, L3c, L5b, L6a and every
L8 line must be false (ProVerif reports an attack / reachability); L9 is structural; L10–L12 are M11 and absent from
`PROVERIF_EXPECTED` until then. Every file `formal/link/<session>.pv` (lClean, lDH, lKEM, lBoth, lSig, lFS, lFSDH,
lFSEph, lQKey) is verified separately over `formal/link.pvl`, each capped at 30 minutes (a timeout fails); the expected
table is per (file, ID, query text); model sha256 pinned (ADR-046 Am. 1). A model change requires a spec reference.

### Paths the model covers / excludes

Covered: HELLO/RELAYINFO with signature, `relay_fp` pin and `akc`; HS1 with `h0` over (ver, kid, relay_fp, e_c,
h(ek_c), pk_e1, h(ct_kem)), `ck1`, `mac1` checked by R before it answers; HS2 with `h1`, `ck2`, `mac2`; key split
`(k_c2r, k_r2c, sess_id)`; frames with per-direction keys, counter nonces and AD `sess_id`; HS1 replay as a new
handshake (OPEN-3); attacker-initiated links; signed commands with `sess_id ‖ cmd_seq`; tokens.
Excluded (each with where it is tested): decoders, low-order points, the ML-KEM modulus check, strict Ed25519 byte
rules (§4.1, §3.5) — C-02…C-08, RH-05…RH-07, Q-56, FZ-01, FZ-05; record and frame lengths, padding (4352/4336, ISO) —
F-02, F-07, K-01, V-16; `valid_until` and the 60-day bound (time) — C-10; RelayInfo not cached — C-13; counter
overflow and `LINK_MAX_FRAMES` — F-08, F-09, K-03; the strict +1 counter beyond the bound of three — K-02, P-04; the
uniform rejection and teardown (OPEN-2) — C-22, RH-15, F-06, P-08; `cmd_seq` rules, CONT assembly (OPEN-5, SQ-26/27)
— Q-47…Q-51, K-04, K-05; every SecMP-Q store semantic (derived ids, idempotent QUEUE_NEW, cumulative ack, FETCH
idempotence, eviction, one-time consumption, owner status, budget, expiry, zeroization) — Q-, RL- rows, K-06, K-07,
P-07, P-10; token double-spend (none in v1, M13); timing and rate limits — CT-, RL-13/14; Tor and TLS (§8.1, M6); the
relay as attacker against the client's queues — §11.3 accepted leakage, HX/TR models; the §11.1 Q properties against the
operator — unlinkability of `rid`/`sid` (derived from fresh per-queue keys, §9.1) and detectability of per-user access
keys (`akc`) — R is honest in this model: tests Q-01, P-05 (derivation), C-11, RL-19 (`akc`); L7 proves only that the
client's check runs.

### Open modelling decisions for the reviewer (LO-n)

- **LO-1** Layout — decided: per-session files `formal/link.pvl` + `formal/link/<session>.pv` (OPEN-M5-16 A, 2026-10-03).
- **LO-2** SIGO and RevealSig give the same L2 trace; keep one session (lSig with RevealSig) unless the reviewer wants
  the quantum reading as its own line.
- **LO-3** L4 is conditioned on the HS1 of an honest client (premise `event(CStart(…))`); an attacker-run link has no
  CSend by construction. If ProVerif rejects the mixed premise, split L4 into a non-injective premise query plus an
  injective query with h0 in both events.
- **LO-4** Counters as public constants {0, 1, 2}; strictness beyond the bound is Kani/proptest (K-02, P-04).
