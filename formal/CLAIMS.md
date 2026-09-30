# formal/CLAIMS.md — query set fixed by the reviewer (ADR-026, docs/03 §11.2)

## TR — SecMP-TR, bounded 3 steps (`formal/tr.pv`, M3)

Model: two honest parties A (initiator) and B (responder) share a fresh secret SK and transcript `sb`
(HX is out of scope: `SK` is a free private name). The attacker is Dolev–Yao on the network. The run is
bounded to three DH-ratchet steps: A's first chain (step 1, messages n = 0, 1), B's reply chain (step 2,
n = 0, 1), A's second chain (step 3, n = 0, 1). Abstractions (each is a ProVerif constructor with the
listed equation; nothing else about the primitive is assumed):
  hkdf_init(SK) -> (RK, HK_A, NHK_B)                       ; §7.2, three independent outputs
  kdf_rk(rk, dh, ss) -> (rk', ck, nhk)                     ; §7.2 KDF_RK on dh ‖ ss
  kdf_ck(ck) -> (ck', mk)                                  ; §7.2 KDF_CK
  X25519: exp(exp(g,a),b) = exp(exp(g,b),a)                ; classical DH
  ML-KEM: decaps(dk, encaps_ct(pk(dk), r)) = encaps_ss(pk(dk), r)
  hseal(hk, nonce, ad, header) / hopen                     ; XChaCha20-Poly1305 for the header (§7.3)
  bseal(mk, ad, body) / bopen                              ; MsgEncrypt for the body (§3.3), ad includes hdr
  pad/unpad are identity on the modelled content.
Oracles (enabled per query): DHO — a public function dh_break(exp(g,a), exp(g,b)) = exp(exp(g,a),b);
KEMO — a public function kem_break(encaps_ct(ek, r)) = encaps_ss(ek, r). Compromise: event
Compromise(P, i) publishes P's entire RatchetState immediately after step i (i in 1..3), including the
skipped map (empty in the in-order runs used by T3/T8).
Events: Send(P, i, n, c), Recv(P, i, n, c) with the chain step i and position n.

| ID | Property | Query (sketch) | Assumptions | Expected |
|---|---|---|---|---|
| T1 | Body secrecy | not attacker(c) for every honest content c | no compromise, no oracle | true |
| T2 | Authenticity, integrity, replay (injective agreement, key commitment) | inj-event(Recv(B,i,n,c)) ==> inj-event(Send(A,i,n,c)), and symmetric | no compromise of the sender's state at or before (i,n) | true |
| T3 | Forward secrecy per message | phase 0: all sends/receives of steps 1–2; phase 1: Compromise(A,2) and Compromise(B,2); query not attacker(c) for c of steps 1–2 | in-order delivery (skipped map empty) | true |
| T4 | Post-compromise security, hybrid | Compromise(A,1) then step 2 (B's honest step) and step 3 (A's honest step); not attacker(c) for c of step 3 | no oracle | true |
| T5 | PCS with the classical break | as T4 with DHO | KEM still honest | true |
| T6 | PCS with the PQ break | as T4 with KEMO | DH still honest | true |
| T7 | Sanity: both breaks defeat PCS | as T4 with DHO and KEMO | — | **false** |
| T8 | Header confidentiality | not attacker(dh_pk_i), not attacker(ek_pq_i), not attacker(n_i) for every header of steps 1–3 (modelled as private names bound into the header) | no compromise | true |
| T9 | Header forward secrecy | Compromise(A,3) and Compromise(B,3) in phase 1; not attacker(header fields of step 1) | in-order delivery | true |
| T10 | Sanity: no healing without a step | Compromise(A,1); attacker(c) for c of step 1, n = 1 (sent after the compromise on the same chain) | — | **false** (attacker learns c) |
| T11 | KEM constancy is enforced | a message of step i whose ct_pq differs from the chain's is never accepted: event Recv(B,i,n,c) ==> the header's ct_pq equals last_ct_r of B at (i) | — | true |
| T12 | Sanity: header keys are not committing | the model must not prove that hopen succeeding implies a unique (hk) — expressed as a query that is expected to fail: hopen(hk1, …) = header && hopen(hk2, …) = header ==> hk1 = hk2 | — | **false** or unprovable (documented, not a gate) |

Gate rule: T1–T6, T8, T9, T11 must be proved true; T7 and T10 must be false (ProVerif reports an attack);
T12 is informative. A model change requires a spec reference (formal/README.md).
