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
  hseal2(hk, nonce, ad, header): a second, non-committing header-AEAD constructor used only by T12 (attacker-strengthening; declared 2026-10-01)
  bseal(mk, ad, body) / bopen                              ; MsgEncrypt for the body (§3.3), ad includes hdr
  pad/unpad are identity on the modelled content.
Oracles (enabled per query): DHO — a public function dh_break(exp(g,a), exp(g,b)) = exp(exp(g,a),b);
KEMO — a public function kem_break(encaps_ct(ek, r)) = encaps_ss(ek, r). Compromise: event
Compromise(P, i) publishes P's entire RatchetState immediately after step i (i in 1..3), including the
skipped map (empty in the in-order runs used by T3/T9).
Events: Send(P, i, n, c), Recv(P, i, n, c) with the chain step i and position n.

| ID | Property | Query (sketch) | Assumptions | Expected |
|---|---|---|---|---|
| T1 | Body secrecy | not attacker(c) for every honest content c | no compromise, no oracle | true |
| T2 | Authenticity, integrity, replay (injective agreement, key commitment) | inj-event(Recv(B,i,n,c)) ==> inj-event(Send(A,i,n,c)), and symmetric | no compromise of either party's state at or before (i,n) — a compromised receiver can impersonate its peer from its own state | true |
| T3 | Forward secrecy per message | phase 0: all sends/receives of steps 1–2; phase 1: Compromise(A,2) and Compromise(B,2); query not attacker(c) for c of steps 1–2 | in-order delivery (skipped map empty) | true |
| T4 | Post-compromise security, hybrid | Compromise(A,1) then step 2 (B's honest step) and step 3 (A's honest step); not attacker(c) for c of step 3 | no oracle | true |
| T5 | PCS with the classical break | as T4 with DHO | KEM still honest | true |
| T6 | PCS with the PQ break | as T4 with KEMO | DH still honest | true |
| T7 | Sanity: both breaks defeat PCS | as T4 with DHO and KEMO | — | **false** |
| T8 | Header confidentiality | not attacker(dh_pk_i), not attacker(ek_pq_i), not attacker(n_i) for every header of steps 1–3 (modelled as private names bound into the header) | no compromise | true |
| T9 | Header forward secrecy | Compromise(A,3) and Compromise(B,3) in phase 1; not attacker(header fields of step 1) | in-order delivery | true |
| T10 | Sanity: no healing without a step | Compromise(A,1); attacker(c) for c of step 1, n = 1 (sent after the compromise on the same chain) | — | **false** (attacker learns c) |
| T11 | KEM constancy is enforced on the chain and step paths | a message accepted under hk_r (chain) or nhk_r (step) whose (ek_pq, ct_pq) differ from B's (kem_r, last_ct_r) at (i) is never accepted: event Recv(B,i,n,c) via hk_r/nhk_r ==> header.(ek_pq, ct_pq) = B.(kem_r, last_ct_r) at (i) | messages accepted under a skipped key are out of scope: §7.4 step 1 derives their mk before the header is read and performs no constancy check (reading 4, ref-spec-questions-M3 SQ-23); the M3 model's single in-order schedule exercised only the in-scope paths; the out-of-order branch was delivered in M4 by F5 (`tr.pv` 1a., the per-slot in-order/other-first branch), and the skipped path stays excluded | true |
| T12 | Sanity: header keys are not committing | the model must not prove that hopen succeeding implies a unique (hk) — expressed as a query that is expected to fail: hopen(hk1, …) = header && hopen(hk2, …) = header ==> hk1 = hk2 | — | **false** or unprovable (documented, not a gate) |
| T13 | Reachability sanity, one query per honest session (M3 R-52, EXT-1) | for every session s: event(<name>(s, …)) | — | **false** per line (the honest run completes) |

Gate rule: T1–T6, T8, T9, T11 must be proved true; T7, T10 and every T13 line must be false (ProVerif reports an
attack / reachability); T12 is informative. A model change requires a spec reference (formal/README.md).
Errata 2026-10-01 (M3 review): T11 scoped to the chain/step paths; T2 assumption; T3/T9; hseal2 declared. The original T11 was false for the specified protocol inside the bound (late (1,1) via the skipped path, V1 reproduction).
F5 (M3 R-12, WEISUNG M4-5, 2026-10-02): "Per-slot nondeterministic in-order/other-first branch, B's step-2 send parallel to its (1,1) receive, stale reject; keep T3/T9 in-order." — in the sessions of T1, T2, T4–T8, T10 (`tr.pv` 1a.); the sessions of T3 and T9 keep the in-order schedule. F34 (EXT-1): T13.

## HX — SecMP-HX + SecMP-INV, replicated sessions (`formal/hx.pvl` + `formal/hx/<session>.pv`, M4; O-18)

Model: an honest responder R (the inviter, §2) and an honest initiator I (the invitee). R holds
IKS_R = (IK_sig_R, IK_dh_R), one signed-prekey generation (SPK_dh_R, SPK_kem_R, RPK_kem_R) (one SPK generation
(ADR-044 context)), and per issued invitation j a
fresh one-time prekey OPK_j = (OPK_dh_R[j], OPK_kem_R[j]) with opk_id_j, a fresh ld_id_j (relay-visible: public)
and a fresh link_key_j. For each invitation R signs the bundle (§6.3), sends InvitationV1_j (§5.2) to I on a
private out-of-band channel (published on c under LeakInv), and publishes the link-data blob
N ‖ CAEAD.Seal(K_ld_j, N, "SecMP-INV/1 blob" ‖ ld_id_j, LinkDataV1(IKS_R, bundle_j, Profile_R, created)) on c
(§5.4). The attacker is Dolev–Yao on the network **and is the relay**: LINK_GET one-time consumption (§9.4) and
queue delivery are not trusted; any cell may be delivered, dropped, replayed or injected. I takes an invitation,
takes a blob from c, performs §5.5 steps 1–4 (fingerprint, bundle signature, `opk_present`; the expiry checks are
not modelled: no time), then §6.4–§6.5 with a fresh EK_I, and outputs the handshake cell on c (O-14). R takes
a cell from c and performs §6.6 steps 1–3, one acceptance attempt per OPK_j (O-13): on success the OPK is used
once (step 4 "delete the OPK"), a failed attempt is silent (step 3 "keep the OPK").
`first_msg` is abstracted (O-15): (ct1, tseal(tkey(SK, ss1), (n = 0, pn = 0, rt))), rt = (Profile_I, routes_I) of
the Handshake content (§7.6); R's one reply (H6b) is tseal(tkey_r(SK, ss1), ack). The attacker may also play
either role with its own identity and keys: it may issue its own invitations to I (only in the auth files of the
sessions whose queries need the misbinding case, O-20–O-22; scenarios that query I's identity exclude this, H7) and
may send R envelopes under its own identity once it holds an invitation. I sessions
and invitations are replicated; injectivity comes from R's one acceptance attempt per OPK (O-13), not from a
single-use cell, and the store bookkeeping that realises it (delete only after success, exactly once) is proven by Kani
K4/K4b and tested (M3 R-13; O-13). One model file per session (O-18).
Abstractions (each is a ProVerif constructor with the listed equation;
nothing else about the primitive is assumed):
  X25519: exp(exp(g,a),b) = exp(exp(g,b),a)                             ; §3; low-order points and the all-zero
                                                                         ; check of §6.4 are not modelled (test)
  ML-KEM-1024 (SPK_kem, OPK_kem): decaps1024(dk, encaps_ct1024(pk1024(dk), r)) = encaps_ss1024(pk1024(dk), r)
                                                                         ; implicit rejection not modelled: a
                                                                         ; wrong ct makes decaps fail; in the
                                                                         ; protocol the wrong ss makes the K_id
                                                                         ; open fail (§6.6 step 2), the same reject
  ML-KEM-768 (RPK_kem, TR first step): as §TR
  h(x)                                                                   ; SHA-256, public one-way (inner hashes)
  fp(iks) = h("SecMP-FP/1", iks)                                         ; §6.2, public
  th(iks_R, spk_id, spk_dh, h(spk_kem), h(rpk_kem), opk_id, opk_dh, h(opk_kem), iks_I, ek_I, h(ct_spk), h(ct_opk),
     ld_id)                                                              ; §6.4 transcript, a free public
                                                                         ; constructor: agreement on th is
                                                                         ; agreement on all 13 components
  hx_sk(dh1, dh2, dh3, dh4, ss_spk, ss_opk, th) -> SK                    ; §6.4, salt 0^32 and the 0xFF^32 prefix
                                                                         ; are constants (omitted)
  hx_kid(ld_id, link_key, dh3, ss_spk, dh4, ss_opk) -> K_id              ; §6.4 (DH1, DH2 are NOT inputs)
  hx_kinv(ld_id, link_key) -> K_inv ; inv_kld(ld_id, link_key) -> K_ld   ; §6.5, §5.4
  caead_seal(k, n, ad, m) / caead_open(k, n, ad, caead_seal(k, n, ad, m)) = m
                                                                         ; CAEAD (§3.4), AD checked, committing
                                                                         ; (blob, the init cell, inner_ct); every
                                                                         ; nonce a public constant (O-16)
  one init cell                                                          ; Outer as one CAEAD cell under K_inv, AD
                                                                         ; ("SecMP-HX/1 initcell", ld_id); no
                                                                         ; chunks, no init_id (O-14, O-16); pad is
                                                                         ; the identity
  plaintext layers                                                       ; sessions with LeakInv in phase 0:
                                                                         ; LinkDataV1 and Outer as plaintext tuples
                                                                         ; (ld_id, ·), ld_id checked by I/R (O-17)
  hsign(sk, label, m) / hverify(vk(sk), label, m, hsign(sk, label, m)) = true
                                                                         ; HybridSign (§3.5) as one unforgeable
                                                                         ; signature: both halves must verify, so
                                                                         ; no oracle; signed message = bundle
                                                                         ; fields before sig ‖ ik_dh (§6.3)
  first_msg = (ct1, tseal(tkey(SK, ss1), (n = 0, pn = 0, rt))), ct1/ss1 the ML-KEM-768 encapsulation to RPK_kem_R;
  R's reply tseal(tkey_r(SK, ss1), ack); tkey, tkey_r free one-way, tseal/topen a committing AEAD     ; O-15
  IKSPublic = (vk(sig), exp(g, ik)); PrekeyBundle = the §6.3 field tuple; constant ver fields omitted.
Oracles (enabled per query, scoped per session as in `tr.pv` §4): DHO — dh_break(exp(g,a), exp(g,b)) =
exp(exp(g,a),b) for every pair of honest X25519 exponents of the session (IK_dh_I, IK_dh_R, SPK_dh_R, OPK_dh_R[j],
EK_I; the TR initiator's dh_s is not modelled, O-15); KEMO — kem_break(encaps_ct(ek, r)) = encaps_ss(ek, r) for the two
ML-KEM-1024 encapsulations (ct_spk, ct_opk) and the ML-KEM-768 encapsulation to RPK_kem_R of the TR first step.
Compromise (each emits an event of the same name and outputs the values on c, in the phase the query states):
  LeakInv(s, j)      InvitationV1_j (ld_id, link_key, inviter_fp, inv_sid, inv_send_seed, …) — phase 0 = an
                     invitation thief or a relay that holds the invitation; phase 1 = "a later invitation leak"
                     (§6 intro `docs/03:263`, §11.1 `docs/03:699`)
  RevealLT(s, P)     P's IK_sig and IK_dh secrets
  RevealSPK(s, R)    SPK_dh_R secret, SPK_kem_R and RPK_kem_R decapsulation keys (medium-term: retained while an
                     unexpired invitation references the SPK, §6.1)
  RevealOPK(s, R, j) OPK_j secrets (sanity only: "the OPK was not deleted")
  PubIKS(s, I)       IKS_I in clear on c (I's identity is known to its contacts); every session except hId* does
                     this; in hId* sessions IKS_I is never output in clear and I runs only on R's invitation.
Events:
  BundleSigned(s, iks_R, b)                         R signs bundle b (§6.3; b = spk_id, spk_dh, spk_kem, rpk_kem,
                                                    spk_expiry, opk_present, opk_id, opk_dh, opk_kem)
  InvIssued(s, iks_R, ld_id, opk_id)                R issues an invitation with that OPK (once per OPK)
  IStart(s, iks_I, iks_R, b, tr, rt, sk)            I passed §5.5 steps 1–4 and sealed the init cell (§6.5);
                                                    tr = th(…), rt = (Profile_I, routes_I) of first_msg
  RAccept(s, iks_R, iks_I, ld_id, opk_id, tr, rt, sk)  R passed §6.6 steps 1–3 (first_msg opened, O-15),
                                                    immediately before step 4 deletes the OPK
  IConfirm(s, iks_I, iks_R, tr, sk)                 I decrypted R's first TR reply (H6b)

| ID | Property | Query (sketch) | Assumptions | Expected |
|---|---|---|---|---|
| H1 | SK secrecy, classical | (i) event(IStart(s,iks_I,iks_R,b,tr,rt,sk)) && attacker(sk) ==> false, iks_R honest; (ii) event(RAccept(s,iks_R,iks_I,ld,oid,tr,rt,sk)) && attacker(sk) ==> false, iks_I honest | hClean: no oracle, no compromise; LeakInv(s, j) in phase 0 for every j (SK does not depend on link_key, so it must not rest on the invitation secret) | true |
| H2 | SK secrecy with the DH oracle (HNDL: classical broken) | (i) as H1 (i); (ii) R side for matching sessions: event(RAccept(s,…,tr,rt,sk)) && event(IStart(s,…,tr,rt,sk)) && attacker(sk) ==> false (implied by (i); stated so the R side is explicit) | hDH: DHO; KEM honest; LeakInv phase 0. True because the IKM of SK (§6.4 `docs/03:318`) contains ss_spk = ML-KEM-1024.Encaps(SPK_kem_R) (I) = Decaps(dk_SPK, ct_spk) (R) and ss_opk = ML-KEM-1024.Encaps(OPK_kem_R) = Decaps(dk_OPK, ct_opk) (`docs/03:309-310`), and R's KEM keys reach I authentically (bundle under HybridSign, IKS pinned by inviter_fp). The ML-KEM-768 encapsulation to RPK_kem_R is **not** in SK (it enters the first KDF_RK, §7.2 `docs/03:400-401`); RPK_kem_R enters only the transcript, as SHA-256(RPK_kem_R). Unmatched R-side secrecy is false: H8 | true |
| H3 | SK secrecy with the KEM oracle | as H1 (i) and (ii) (unmatched) | hKEM: KEMO; DH honest; LeakInv phase 0. True because DH2 = X25519(EK_I, IK_dh_R), DH3 = X25519(EK_I, SPK_dh_R), DH4 = X25519(EK_I, OPK_dh_R) keep SK secret, and DH1 = X25519(IK_dh_I, SPK_dh_R) keeps I authenticated, so (ii) needs no matching restriction | true |
| H4 | Sanity: both breaks defeat SK secrecy | as H1 (i) | hBoth: DHO and KEMO; LeakInv phase 0; PubIKS (without the invitation EK_I, ct_spk and ct_opk stay sealed under K_inv and H4 would come out true — the outer layer then protects SK even against both breaks; this is not claimed) | **false** (attacker opens the cells with K_inv, gets DH1–DH4 by dh_break on public pairs and ss_spk, ss_opk by kem_break — both oracles reach the derivation) |
| H5 | Injective agreement of R with I on the full transcript, SK and the reply route | inj-event(RAccept(s,iks_R,iks_I,ld,oid,tr,rt,sk)) ==> inj-event(IStart(s,iks_I,iks_R,b,tr,rt,sk)), iks_I honest, where tr = SHA-256("SecMP-HX/1 transcript" ‖ encode(IKSPublic_R) ‖ spk_id ‖ SPK_dh_R ‖ SHA-256(SPK_kem_R) ‖ SHA-256(RPK_kem_R) ‖ opk_id ‖ OPK_dh_R ‖ SHA-256(OPK_kem_R) ‖ encode(IKSPublic_I) ‖ EK_I ‖ SHA-256(ct_spk) ‖ SHA-256(ct_opk) ‖ ld_id) (§6.4 `docs/03:313-316`, 13 components) and rt = (Profile_I, routes_I) of first_msg's Handshake content (bound to SK, §6.5 `docs/03:342`). "Transcript binding" (§11.1) is the agreement on (tr, sk) | hClean and hKEM (authentication is classical: it must survive KEMO); LeakInv phase 0; PubIKS; no RevealLT(I), no RevealSPK(R) (KCI, H9); replicated invitations and I sessions, one acceptance attempt per OPK (O-13; injectivity not from process structure, M3 R-13). Not agreed because not in tr or SK: spk_expiry, opk_present, bundle sig, LinkDataV1.profile/created, every InvitationV1 field except ld_id, init_id, all nonces (accepted limitation, docs/01 RR-15) | true |
| H6 | Agreement of I with R (I → R direction) | — | — | **not claimed**: HX is one-pass; I completes (IStart) before R acts, and §6.6 `docs/03:352` gives only implicit authentication of R to I ("R is authenticated to I by DH2/DH3 and by the bundle signature under IK_sig_R, pinned via inviter_fp"); what I gets is H1 (i)/H2 (i) (only R can derive SK) and H6a. §11.1 `docs/03:699` says "mutual classical authentication (injective agreement on transcript)" (wording corrected by ADR-044 (a); R → I: H6b) |
| H6a | Bundle origin authentication | event(IStart(s,iks_I,iks_R,b,tr,rt,sk)) ==> event(BundleSigned(s',iks_R,b)) (non-injective: a signed bundle is replayable by the relay or an invitation holder) | hClean and hId (O-19: checked in these two sessions; that it holds in the others is an argument, not a check) | true |
| H6b | Key confirmation at I's first decrypted reply (ADR-044 (a)) | inj-event(IConfirm(s,iks_I,iks_R,tr,sk)) ==> inj-event(RAccept(s,iks_R,iks_I,ld,oid,tr,rt,sk)) | one R → I TR cell in the model (§6.5 `docs/03:340` "until the initiator has decrypted a first message from R"); event IConfirm; hClean | true |
| H7a | Identity confidentiality of I, network attacker / relay | not attacker(exp(g, ik_I)) and not attacker(vk(sig_I)) (I's IK_dh and IK_sig public keys) | hId: no PubIKS; I runs only on R's invitation (an inviter learns I's identity by design); invitation not leaked; no oracle | true |
| H7b | … against an invitation thief (K_inv known) | as H7a | hIdThief: as hId plus LeakInv phase 0 (the attacker opens the three cells with K_inv; K_id = HKDF(salt = ld_id, IKM = link_key ‖ DH3 ‖ ss_spk ‖ DH4 ‖ ss_opk, info = "SecMP-HX/1 idkey"), §6.4 `docs/03:320`, also needs DH3, DH4, ss_spk, ss_opk) | true |
| H7c | … against a later invitation leak (forward secrecy of K_id) | as H7a | hIdLater: phase 0 the honest run completes (RAccept; R deletes OPK_j; EK_I discarded after IStart (ADR-044 (b))); phase 1 LeakInv, RevealLT(R), RevealSPK(R) and DHO; true because K_id's truth rests on ss_opk: with DHO in phase 1 DH4 = X25519(EK_I, OPK_dh_R) is computable from public keys, while ss_opk needs OPK_j's decapsulation key, deleted after the run (`docs/03:323` "forward-secret once OPK is deleted and EK_I discarded") | true |
| H7d | Sanity: K_id falls with the OPK | as H7a | as hIdLater plus RevealOPK(s, R, j) in phase 1 | **false** |
| H8 | Expected false: PQ-only authentication of I to R | H5's correspondence | hDH: DHO, KEM honest; LeakInv phase 0; PubIKS. The attacker forges I: DH1 = dh_break(IK_dh_I, SPK_dh_R) from public keys, its own EK and its own encapsulations to SPK_kem_R/OPK_kem_R give DH2–DH4, ss_spk, ss_opk, SK and K_id; R accepts "I". The KEM shares authenticate only the decapsulator R (anyone can encapsulate to R's public keys); no KEM operation involves a secret of I, so I is authenticated by DH1 alone (§6.6 `docs/03:352` "PQ authentication is not provided", §1.2 `docs/03:39`). The forgery needs the invitation (K_inv and K_id contain link_key). Stated assumption (O-9): "assumes a leaked invitation; without it the outer layer masks the missing property — the leak is the threat" | **false** |
| H9 | Expected false: KCI — R's signed-prekey secret lets the attacker impersonate I to R | H5's correspondence | hKCI: RevealSPK(s, R) in phase 0 before the handshake (SPK_dh_R secret); LeakInv phase 0; PubIKS; no oracle. DH1 = X25519(SPK_dh_R, IK_dh_I) is computable by the holder of R's SPK secret; DH2–DH4 and both KEM shares come from the attacker's own EK and encapsulations. Stated assumption (O-9): "assumes a leaked invitation; without it the outer layer masks the missing property — the leak is the threat" | **false** |
| H9b | Boundary: R's identity keys alone give no KCI | H5's correspondence | hKCIlt: RevealLT(s, R) (IK_sig_R, IK_dh_R) in phase 0, SPK not revealed; LeakInv; PubIKS (DH1 does not involve IK_dh_R; R does not verify its own bundle) | true |
| H9c | I-side: I's identity keys do not expose I's SK | H1 (i) | hKCIi: RevealLT(s, I) in phase 0; LeakInv phase 0; iks_R honest (DH2, DH3, DH4 use EK_I) | true |
| H10 | OPK single use; replayed envelope not accepted | inj-event(RAccept(s,iks_R,iks_I,ld,oid,tr,rt,sk)) ==> inj-event(InvIssued(s,iks_R,ld,oid)) | hClean + LeakInv; the attacker re-delivers byte-identical retransmissions (§6.5 `docs/03:340`) and replays (§6.6 `docs/03:354`); one acceptance attempt per OPK (O-13): consistency of the model; the store's bookkeeping is proven by Kani K4/K4b and the tests `accept_success_deletes_exactly_that_opk`, `accept_replayed_envelope_rejects_after_success`, `prop_opk_consumed_exactly_once` | true |
| H11 | Reachability sanity, one query per accept event and session (M3 R-52) | in every base file (O-18, O-19), four lines: event(IStart(s,…)); event(BundleSigned(s,…)); event(RAccept(s,…,tr,rt,sk)) && event(IStart(s,…,tr,rt,sk)) (the honest pair completes, not merely an attacker-built envelope); event(IConfirm(s,…)); in every auth file (O-22) one line, the honest pair, so that its begin-IStart declaration is not vacuous (M4 review C-7, erratum 5) | — | **false** for every line (ProVerif reports the event reachable: the honest run completes in every file, including those with phase 1) |
| H12 | Forward secrecy of SK under a later compromise that reveals no OPK | not attacker(sk) of the phase-0 session (I and R sides as H1) | hFS: phase 0 the honest run completes (R deletes OPK_j, §6.6 step 4; EK_I discarded after IStart (ADR-044 (b))); phase 1 RevealLT(I), RevealLT(R), RevealSPK(R), LeakInv. DH1, DH2, DH3, ss_spk become computable; DH4 = X25519(EK_I, OPK_dh_R) and ss_opk need EK_I or OPK_j | true |
| H12b | Sanity: FS rests on OPK deletion | as H12 | as hFS plus RevealOPK(s, R, j) in phase 1 | **false** |
| H12c | FS under a later classical break (HNDL) | as H12 | as hFS plus DHO in phase 1 (DH4 by dh_break; ss_opk still needs OPK_j's dk) | true |

Gate rule: H1, H2, H3, H5, H6a, H6b, H7a–H7c, H9b, H9c, H10, H12 and H12c must be proved true; H4, H7d, H8, H9,
H12b and every H11 line must be false (ProVerif reports an attack / reachability); H6 is not claimed; H10 is a
query (O-13). A model change requires a spec reference (formal/README.md).
Every model file `formal/hx/<file>.pv` — the 14 session files and the five auth files `<session>-auth.pv` of hClean,
hKEM, hDH, hKCI, hKCIlt that carry H5/H8/H9/H9b (O-22) and one H11 line each — is verified separately over
`formal/hx.pvl`, each capped at 30 minutes (a timeout fails); every false verdict uses only its own session by
construction (O-18, ADR-046). The gate expects 92 `RESULT` lines: 82 in the session files, 10 in the auth files
(M4 review C-7, erratum 5: 87 before the auth files' H11 lines).

### Paths the model covers / excludes (every path of §5.5, §6.4–§6.6 named; M3 R-01/R-12 lesson)

Covered: the with-OPK handshake (the only v1 path); §5.5 step 2 blob opening under K_ld, step 3 fingerprint pin,
step 4 bundle signature and `opk_present`; §6.4 all four DH and both KEM shares, transcript, SK, K_id; §6.5 Inner,
inner_ct under K_id, Outer as one cell under K_inv (O-14); retransmission of byte-identical cells and arbitrary
replay (DY attacker); garbage and attacker cells (the attacker delivers any cell; a failed attempt is silent and
has the event traces of no attempt, O-13); §6.6 step 1 spk_id/opk_id check, step 2 K_id and inner open
(IKSPublic_I decodable), step 3 DH1/DH2, transcript, SK, first_msg under tkey(SK, ss1) (O-15; R's checks of its
content are under Excluded);
one acceptance per OPK (O-13);
the attacker as inviter (to I) and as invitee (to R) with its own identity; a bundle of another
invitation of R served under this invitation's K_ld (rejected by the opk_id check, §6.6 step 1).
Excluded (each with where it is tested instead): the no-OPK path — does not exist in v1 (§6.3 `docs/03:292`,
§5.5 `docs/03:255`; decoder test V7); time: invitation `expires` (§5.5 step 1), bundle `spk_expiry` (step 4), SPK
rotation and retention (§6.1 `docs/03:271`) — tests and prekey-store tests; one SPK generation in the model
(ADR-044 context), the retained-SPK cases are tests (`accept_with_retained_previous_spk_succeeds`,
`accept_with_rotated_out_spk_rejects_and_keeps_opk`); R-side expiry: §6.6 takes no time, expiry is enforced by the
invitation-record lifecycle (§5.2) and the client does not call accept for an expired record (ADR-044 (d)) — test
`expired_invitation_record_is_not_offered_to_accept`; low-order points and the all-zero DH check (§3, §4.1 (a), §6.4
`docs/03:311`) — decoder vectors and unit tests; padding (identity) and the decoders of Outer, Inner,
HandshakeCellPlaintext, LinkDataV1, InvitationV1, URI (M2 encodings, fuzz); chunking of Outer into the three
cells (O-14) — excluded, tested: N-26…N-32, N-66/N-67, Kani K3; CAEAD nonces and init_id (O-16) — excluded,
tested: N-29, N-30, K3; the TR layer of first_msg and of R's reply (hkdf_init, KDF_RK, KDF_CK, header/body layers,
key selection; O-15) — excluded, proved in `tr.pv` (T1–T13); the OPK store's bookkeeping (delete only after
success, exactly once; O-13) — excluded, proved by Kani K4/K4b and tested (`accept_success_deletes_exactly_that_opk`,
`accept_replayed_envelope_rejects_after_success`, `prop_opk_consumed_exactly_once`); grouping by init_id, "first complete
group wins", duplicate (init_id, i), partial-group storage (§6.5 `docs/03:340`, ADR-044 (c)) — tests
`group_duplicate_chunk_identical_ignored`, `group_duplicate_chunk_differing_first_seen_wins`,
`group_rejected_then_other_init_id_accepts`, `group_partial_store_bound_8_evicts_oldest`, Kani K3; first_msg header
n = 0 / pn = 0, Handshake `caps` = 0 (ADR-043 (g)) and at least one route of a known kind in the Handshake content
(ADR-044 (e)); the abstraction carries n = 0, pn = 0 as constants (O-15) — tests
`accept_first_msg_n_nonzero_rejects_and_keeps_opk`, `accept_first_msg_pn_nonzero_rejects_and_keeps_opk`,
`accept_handshake_caps_nonzero_rejects_and_keeps_opk`, `accept_handshake_without_known_route_rejects_and_keeps_opk`;
reflection — R rejects an envelope whose IKSPublic_I equals IKSPublic_R (§6.6 step 2 `docs/03:349`, O-11, ADR-044 (f);
`hx/responder.rs`, uniform error, OPK kept), not modelled (no honest party reflects) — test
`accept_reflected_own_iks_rejects_and_keeps_opk` (`tests/hx/accept.rs`); ML-KEM implicit
rejection (decaps fails symbolically; same reject at K_id); the skipped-key path and any TR message after first_msg
(§TR; except H6b's one reply); cells on the invitation queue after success processed as TR cells (§6.6 step 4,
§10.6 rules 4–5) — test; contact storage as unverified, SAS (§6.7) and verification — not cryptographic; the
first reply's RouteUpdate and invitation-queue retirement (§6.6 step 4) — session/scheduler (M6/M7); dummies until
the first decrypted reply (§6.5) — scheduler; LINK_GET consumption, owner status, "invitation used by someone
else" (§5.2, §9.4) — relay is the attacker, not modelled as a guarantee; offline deniability (§6.6 `docs/03:352`,
§11.1) — not a trace property: structural test "no signature by I"; HybridKEM is not used in HX (raw X25519 and
ML-KEM into HKDF, binding through the transcript, §3.2 `docs/03:104`).

### Reviewer decisions (2026-10-01)

- **O-1** H6 stays "not claimed" as a one-pass property; H6b is adopted (key confirmation at I's first decrypted TR reply,
  one R → I TR cell in the model, event IConfirm, gated true). §11.1 wording errata: ADR-044 (a).
- **O-2** The initiator MUST zeroize EK_I's secret immediately after the cells are sealed and its RatchetState is
  initialised; `start` returns no EK secret, the persisted state has none (ADR-044 (b)). Model: EK_I discarded after IStart.
- **O-3** Model one SPK generation (Excluded). Prekey store keeps SPK generations by spk_id; `accept` takes any retained,
  unexpired one the invitation references (§6.1). Vectors unchanged; SQ-28 (ref): retained-SPK positive at next freeze.
- **O-4** (ADR-044 (c)) Duplicate (init_id, i): identical ⇒ ignored, differing ⇒ later one discarded (first-seen wins);
  rejected complete group discarded, OPK kept, other init_ids processed; at most 8 partial groups, oldest evicted.
- **O-5** (ADR-044 (d)) §6.6 takes no time; expiry is enforced by the invitation-record lifecycle (§5.2): the client MUST
  NOT call `accept` for an expired record and retires its queue; `accept` has no clock parameter.
- **O-6** (ADR-044 (e)) first_msg header MUST carry n = 0 and pn = 0, seq/ts per §7.6 without further constraint; the
  Handshake content MUST contain at least one route of a known kind; otherwise R rejects (uniform error, OPK kept).
- **O-7** Single-use private OPK cell in hx.pv, re-output on failure, replicated attempts; H10 stays a query. STOP rule: no
  termination in 30 min on the gate machine ⇒ bounded model (2 × 2 × 3), report; H10 also covered by tests.
- **O-8** H7 as reachability queries (H7a–H7d as drafted); observational equivalence becomes follow-up F-M11 (security
  verification milestone).
- **O-9** Accepted; stated in the Assumptions of H8/H9: "assumes a leaked invitation; without it the outer layer masks the
  missing property — the leak is the threat".
- **O-10** Accepted as a documented limitation; the "Not agreed" list stays in H5; not in ADR-044. docs/01 residual-risk
  entry proposed to the owner (memo, default: add):
  > Profile_R/created in LinkDataV1 and spk_expiry/opk_present/sig are bound only by K_ld/the bundle signature, not by the
  > transcript; an invitation holder can substitute the inviter's Profile; binding at the next breaking spec revision (v2)
- **O-11** (ADR-044 (f)) R MUST reject an envelope whose IKSPublic_I equals IKSPublic_R (reflection), uniform error, OPK
  kept; an IKS equal to an existing contact's is client-core policy (M7), not a handshake rejection.
- **O-12** The API follows §6.4–§6.6, not the docs/07 sketch; signatures: see the M4 brief (also TEST-MATRIX-M4-v2
  Conventions).

Amendments (WEISUNG M4-5, reviewer termination diagnosis 2026-10-01; O-7 is replaced by O-13):

- **O-13 (replaces O-7).** OPK single use is modelled by R's per-invitation acceptance process making exactly one
  acceptance attempt per OPK. ProVerif's Horn-clause abstraction never consumes a channel message (a read private cell
  stays readable, probe `proverif-hx-probe-opk-cell.txt`), so a single-use cell cannot carry injectivity; a failed
  attempt is silent (§6.6 step 3: no output, OPK kept) and a later attempt on the same OPK sees the same inputs, so "up
  to k sequential attempts, stop at the first success" has the event traces of one attempt (toy models: inj true for
  k = 1 and k = 3). The store's bookkeeping — delete only after success, exactly once — is proven by Kani K4/K4b and
  tested (`accept_success_deletes_exactly_that_opk`, `accept_replayed_envelope_rejects_after_success`,
  `prop_opk_consumed_exactly_once`). H10 stays a query (one RAccept per InvIssued, injective): consistency of the
  model, not the bookkeeping proof. The bounded-replication fallback of O-7 is withdrawn.
- **O-14.** The three handshake cells are one CAEAD-sealed cell under K_inv with AD ("SecMP-HX/1 initcell", ld_id) and
  content Outer. Each real chunk is sealed under the same key with (init_id, i, total) in its AD; assembly is
  relay-visible and holds no key material; the attacker's chunk-level actions reduce to drop or replay of the envelope
  or a rejection (tests N-26…N-32, N-66/N-67, Kani K3). The `chunk_i`/`join` abstraction is withdrawn.
- **O-15.** The TR first message is abstracted: `first_msg = (ct1, tseal(tkey(SK, ss1), (n = 0, pn = 0, rt)))` with
  ct1/ss1 the ML-KEM-768 encapsulation to RPK_kem_R, `tkey`, `tkey_r` free one-way functions, `tseal`/`topen` a
  committing AEAD; R's one reply (H6b) is `tseal(tkey_r(SK, ss1), ack)`. TR's internals (hkdf_init, kdf_rk, kdf_ck,
  header/body layers, selection) are proven in tr.pv (T1–T13); hx.pv needs only that rt is bound to SK and ss1 and that
  the reply is computable only with SK. KEMO still covers ct1. The line "hkdf_init, kdf_rk, kdf_ck, hseal/hopen,
  bseal/bopen exactly as §TR (first_msg only)" is replaced by this one.
- **O-16.** All CAEAD nonces are public constants in the model and init_id is not modelled (no security role;
  uniqueness and grouping are tested: N-29, N-30, K3).
- **O-17.** In a session whose LeakInv is in phase 0, K_ld, K_inv and link_key are attacker knowledge from the start; a
  committing AEAD layer under an attacker-known key is attacker-transparent (every honest sealed value is openable,
  every value is sealable), so those sessions carry LinkDataV1 and Outer as plaintext tuples whose AD field (ld_id) is
  a tuple component that I/R check. I takes invitations only from `pinv(s)`; the auth files add the attacker as
  inviter (O-20–O-23). Sessions without a leak or
  with a phase-1 leak (hId, hIdLater, hIdLaterOPK, hFS, hFSOPK, hFSDH) keep the sealed layers and the private
  invitation channel.
- **O-18.** One model file per session: `formal/hx.pvl` (library: types, constructors, equations, events, process
  macros) and `formal/hx/<session>.pv` for each of the 14 session tags (the session's instantiation, compromise,
  oracles, phases, queries). Sessions share no private value and each claim is about its own scenario; the joint file
  adds only cross-session attacker combinations, measured superlinear. The gate runs every file separately (30-min cap
  each); every false verdict is in its own session by construction.
- **O-19.** H6a is claimed in hClean and hId (one leak-phase-0 session, one no-leak session) and checked only there;
  that it holds in the other sessions is an argument (HybridSign unforgeability + inviter_fp pinning), not a check. H11
  stays four lines per session in every base file; each auth file carries one H11 line, the honest pair (M4 review
  C-7, erratum 5).
- Query declarations inside a file are grouped by begin event — no-begin queries first, then BundleSigned, IStart,
  RAccept/IConfirm, InvIssued — ID order within a group; the expected list is per (file, ID, query text). (Order
  replaced by O-22.)

Amendments (WEISUNG M4-7, reviewer decisions O-20…O-23 on the M4-5 report, 2026-10-02):

- **O-20 (attacker as inviter only where a query needs it).** The attacker-as-inviter process for I exists only in the files whose queries need the identity-misbinding case — hClean (H5), hKEM (H5), hDH (H8), hKCI (H9), hKCIlt (H9b). In hBoth, hFS, hFSOPK, hFSDH and hKCIi, I runs only on R's invitations. Justification (rewritten 2026-10-03, M4 review R-48): every query of those files is a secrecy/forward-secrecy query over an honest session (IStart/RAccept with iks_R = R). An I session on an attacker invitation that carries the attacker's own bundle yields a SK the attacker is entitled to, which no such query covers: DH1 = X25519(IK_dh_I, SPK_dh_A) is exp(pk_I, spk_A) with its own spk_A, and DH2–DH4, ss_spk, ss_opk, K_id, K_inv follow from its own secrets and the public values in Outer. An attacker invitation that carries R's genuine bundle (R-signed bundles are replayable, the O-23 case) is **not machine-checked** in these five files — their I-side rows cover I only on R-issued invitations. The argument for it: such a session binds the attacker's ld_id and link_key into K_inv, K_id and the transcript, so R accepts its envelope under none of R's invitations (no RAccept matches it) and it stays a dangling I session; the attacker learns nothing about an honest session it does not learn when it holds R's own invitation, which the LeakInv-phase-0 files model, and no attack exists there. Measured (M4-5 report §7): hFS 0.7 s, hBoth 290 s with this change.
- **O-21 (IStart only on R's invitation).** In the five files with the attacker-as-inviter process, that process emits the event `IStartA` (same arguments) instead of `IStart`; `IStartA` appears in no query. H5/H8/H9/H9b thus read "R accepts I ⇒ I started on R's own invitation", which is the stronger statement: an envelope that I produced on an attacker invitation and that R nevertheless accepts (misbinding) would yield RAccept without IStart and come out false. The begin fact IStart is then carried only by derivations from I's run on R's invitation. (Withdrawn 2026-10-02, see "O-21 withdrawn" below.)
- **O-22 (declaration order by cost; auth files).** Query declarations are ordered: no-begin queries, then IConfirm/RAccept-begin (H6b), InvIssued-begin (H10), BundleSigned-begin (H6a), IStart-begin (H5/H8/H9/H9b) last. For the five O-20 files the IStart-begin declaration lives in a separate file `formal/hx/<session>-auth.pv` (same session, same processes incl. the attacker-as-inviter; only that declaration); the base file `<session>.pv` carries the other declarations and no attacker-as-inviter process. The gate's expected table is per (file, ID); a capped auth file never hides the base file's verdicts.
- **O-23 (fallback for the auth files, applied only if an auth file still exceeds 30 min with O-20–O-22, and then named in the report).** The attacker-as-inviter process accepts only bundles that verify under IK_sig_R (R-signed bundles, replayable by anyone who holds them): a bundle signed by the attacker's own key gives it nothing it cannot compute itself (O-20 argument), so the only capability that matters is presenting R's genuine bundle under its own ld_id/link_key — the misbinding case H5 must exclude.

Amendments (WEISUNG M4-11, reviewer decisions on the M4-7 report, 2026-10-02):

- **O-21 withdrawn (2026-10-02).** Both I processes emit `IStart`; `IStartA` is removed. Reason: R's own leaked invitation re-sent on the public channel reaches the attacker-as-inviter process; a run on it is an honest start on R's invitation and must count as `IStart`, and no sound process-level exclusion of R's invitations exists. Nothing is lost against the misbinding case: under O-23 every attacker-as-inviter run has iks_R = IKS_R and tr contains ld_id, so an envelope produced under the attacker's (ld_A, lk_A) has no IStart matching R's RAccept on ld_j.
- **O-24 (search devices, "Model devices").** The auth files carry ProVerif resolution hints that change only the search strategy, never the queries, the oracle or compromise scope or the secrecy assumptions (ProVerif stays sound: a hint can make a proof fail or a trace unavailable, never produce a wrong verdict; `[ignoreAFewTimes]` keeps attack reconstruction possible). The lines, verbatim:
  `select k: key, l: bitstring, m: bitstring; attacker(caead_seal( *k, nz, (lbl_inner, *l), *m))/5000.`
  `nounif p: bitstring, r: coins; attacker(encaps_ct1024( *p, *r)) [ignoreAFewTimes].`
  `nounif x: exponent; attacker(exp(g, x)) [ignoreAFewTimes].`
  and, in hDH-auth only (lazy DH oracle): `nounif x: bitstring; attacker(exp(g, dhsk(hDH, x))) [ignoreAFewTimes].`
  Measured effect (reviewer, 2026-10-02): H5/H8/H9/H9b from > 30 min to seconds–minutes; every false trace checked to use only its own session's events.

### Model devices

- `new e[ld, lk]` (I's names indexed by the invitation): precision devices, no change to queries, oracles or compromise.
- `set unifyDerivation = false`: precision devices, no change to queries, oracles or compromise.
- `new e[ld, lk, b]` (M4-7: I's names indexed also by the bundle I verified; accepted by the reviewer, M4-11 §0):
  precision device of the same kind, no change to queries, oracles or compromise (`formal/hx.pvl` header 7.).
- O-24 (M4-11): the search devices of the five auth files (one `select`, two `nounif … [ignoreAFewTimes]`; hDH-auth
  a third, the lazy DH oracle), verbatim under "Reviewer decisions" above: search strategy only.

Open SQ entries for HX/INV: none. SPEC-QUESTIONS.md (state "Weisung REF-M4-1": "No open questions") marks every
HX/INV-related entry answered — SQ-10 (fingerprint input), SQ-12 (decoder checks), SQ-13/14 (RelayRef), SQ-15
(caps), SQ-17 (route count 0), SQ-25 (invitee checks neither inviter bound; reading A); the "spec clarification" of
§5.5 that SQ-25's answer promised is in rev 2.4 (`docs/03:259`).

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
