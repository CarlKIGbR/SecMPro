# `formal/CLAIMS.md` §HX — final text (planning cell draft of 2026-10-01 with the reviewer's decisions of 2026-10-01 applied)

Sources: `docs/03-protocol-spec.md` rev 2.3 (cited as §n and `docs/03:line`), `docs/07-milestones.md` §M4
(`docs/07:84-95`), `ref/secmp_ref/hx.py` and `inv.py` (cited `hx.py:line`), `SPEC-QUESTIONS.md` (SQ-25, REF-M4
readings 1–15), `formal/CLAIMS.md` §TR and `formal/tr.pv` (style), `docs/reviews/M03-review.md` (R-12, R-13, R-52).
Everything below the next heading is the section text, ready to append; the items the draft marked open were decided
by the reviewer on 2026-10-01 (§11.2, `docs/03:707`; see "Reviewer decisions (2026-10-01)" at the end).

---

## HX — SecMP-HX + SecMP-INV, replicated sessions (`formal/hx.pv`, M4)

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
not modelled: no time), then §6.4–§6.5 with a fresh EK_I, and outputs the three handshake cells on c. R takes
cells from c and performs §6.6 steps 1–3; the OPK_j is read from a single-use private cell, re-output on any
failure (§6.6 step 3 "keep the OPK") and not re-output on success (step 4 "delete the OPK")
(single-use private cell; bounded fallback per STOP rule).
`first_msg` is one SecMP-TR cell: I's §7.2 initiator initialisation and §7.3 Encrypt of the Content
Handshake(Profile_I, caps = 0, routes_I) (§7.6); R's §7.2 responder initialisation and the §7.4 step path
(header opened under nhk_r = HK_A, DHRatchet, KDF_CK, body). The attacker may also play either role with its own
identity and keys: it may issue its own invitations to I (scenarios that query I's identity exclude this, H7) and
may send R envelopes under its own identity once it holds an invitation. I sessions, invitations and acceptance
attempts are replicated, so injectivity must come from the OPK bookkeeping and not from process structure (M3
R-13); if the replicated model does not terminate, the bound is 2 invitations × 2 initiator sessions × 3 acceptance
attempts per invitation (single-use private cell; bounded fallback per STOP rule).
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
                                                                         ; (blob, the three cells, inner_ct)
  chunk_i(x), i = 0,1,2 ; join(chunk_0(x), chunk_1(x), chunk_2(x)) = x   ; the 4006-byte chunks of pad(Outer,
                                                                         ; 12018) (§6.5); pad is the identity;
                                                                         ; init_id, i, total sealed with the chunk
  hsign(sk, label, m) / hverify(vk(sk), label, m, hsign(sk, label, m)) = true
                                                                         ; HybridSign (§3.5) as one unforgeable
                                                                         ; signature: both halves must verify, so
                                                                         ; no oracle; signed message = bundle
                                                                         ; fields before sig ‖ ik_dh (§6.3)
  hkdf_init, kdf_rk, kdf_ck, hseal/hopen, bseal/bopen                    ; exactly as §TR (first_msg only)
  IKSPublic = (vk(sig), exp(g, ik)); PrekeyBundle = the §6.3 field tuple; constant ver fields omitted.
Oracles (enabled per query, scoped per session as in `tr.pv` §4): DHO — dh_break(exp(g,a), exp(g,b)) =
exp(exp(g,a),b) for every pair of honest X25519 exponents of the session (IK_dh_I, IK_dh_R, SPK_dh_R, OPK_dh_R[j],
EK_I, and the TR initiator's dh_s); KEMO — kem_break(encaps_ct(ek, r)) = encaps_ss(ek, r) for the two
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
  IStart(s, iks_I, iks_R, b, tr, rt, sk)            I passed §5.5 steps 1–4 and sealed the three cells (§6.5);
                                                    tr = th(…), rt = (Profile_I, routes_I) of first_msg
  RAccept(s, iks_R, iks_I, ld_id, opk_id, tr, rt, sk)  R passed §6.6 steps 1–3 (first_msg decrypted, Content type
                                                    Handshake), immediately before step 4 deletes the OPK
  IConfirm(s, iks_I, iks_R, tr, sk)                 I decrypted R's first TR reply (H6b)

| ID | Property | Query (sketch) | Assumptions | Expected |
|---|---|---|---|---|
| H1 | SK secrecy, classical | (i) event(IStart(s,iks_I,iks_R,b,tr,rt,sk)) && attacker(sk) ==> false, iks_R honest; (ii) event(RAccept(s,iks_R,iks_I,ld,oid,tr,rt,sk)) && attacker(sk) ==> false, iks_I honest | hClean: no oracle, no compromise; LeakInv(s, j) in phase 0 for every j (SK does not depend on link_key, so it must not rest on the invitation secret) | true |
| H2 | SK secrecy with the DH oracle (HNDL: classical broken) | (i) as H1 (i); (ii) R side for matching sessions: event(RAccept(s,…,tr,rt,sk)) && event(IStart(s,…,tr,rt,sk)) && attacker(sk) ==> false (implied by (i); stated so the R side is explicit) | hDH: DHO; KEM honest; LeakInv phase 0. True because the IKM of SK (§6.4 `docs/03:318`) contains ss_spk = ML-KEM-1024.Encaps(SPK_kem_R) (I) = Decaps(dk_SPK, ct_spk) (R) and ss_opk = ML-KEM-1024.Encaps(OPK_kem_R) = Decaps(dk_OPK, ct_opk) (`docs/03:309-310`), and R's KEM keys reach I authentically (bundle under HybridSign, IKS pinned by inviter_fp). The ML-KEM-768 encapsulation to RPK_kem_R is **not** in SK (it enters the first KDF_RK, §7.2 `docs/03:400-401`); RPK_kem_R enters only the transcript, as SHA-256(RPK_kem_R). Unmatched R-side secrecy is false: H8 | true |
| H3 | SK secrecy with the KEM oracle | as H1 (i) and (ii) (unmatched) | hKEM: KEMO; DH honest; LeakInv phase 0. True because DH2 = X25519(EK_I, IK_dh_R), DH3 = X25519(EK_I, SPK_dh_R), DH4 = X25519(EK_I, OPK_dh_R) keep SK secret, and DH1 = X25519(IK_dh_I, SPK_dh_R) keeps I authenticated, so (ii) needs no matching restriction | true |
| H4 | Sanity: both breaks defeat SK secrecy | as H1 (i) | hBoth: DHO and KEMO; LeakInv phase 0; PubIKS (without the invitation EK_I, ct_spk and ct_opk stay sealed under K_inv and H4 would come out true — the outer layer then protects SK even against both breaks; this is not claimed) | **false** (attacker opens the cells with K_inv, gets DH1–DH4 by dh_break on public pairs and ss_spk, ss_opk by kem_break — both oracles reach the derivation) |
| H5 | Injective agreement of R with I on the full transcript, SK and the reply route | inj-event(RAccept(s,iks_R,iks_I,ld,oid,tr,rt,sk)) ==> inj-event(IStart(s,iks_I,iks_R,b,tr,rt,sk)), iks_I honest, where tr = SHA-256("SecMP-HX/1 transcript" ‖ encode(IKSPublic_R) ‖ spk_id ‖ SPK_dh_R ‖ SHA-256(SPK_kem_R) ‖ SHA-256(RPK_kem_R) ‖ opk_id ‖ OPK_dh_R ‖ SHA-256(OPK_kem_R) ‖ encode(IKSPublic_I) ‖ EK_I ‖ SHA-256(ct_spk) ‖ SHA-256(ct_opk) ‖ ld_id) (§6.4 `docs/03:313-316`, 13 components) and rt = (Profile_I, routes_I) of first_msg's Handshake content (bound to SK, §6.5 `docs/03:342`). "Transcript binding" (§11.1) is the agreement on (tr, sk) | hClean and hKEM (authentication is classical: it must survive KEMO); LeakInv phase 0; PubIKS; no RevealLT(I), no RevealSPK(R) (KCI, H9); replicated sessions, single-use OPK cell (injectivity not from process structure, M3 R-13). Not agreed because not in tr or SK: spk_expiry, opk_present, bundle sig, LinkDataV1.profile/created, every InvitationV1 field except ld_id, init_id, all nonces (accepted limitation, docs/01 entry proposed) | true |
| H6 | Agreement of I with R (I → R direction) | — | — | **not claimed**: HX is one-pass; I completes (IStart) before R acts, and §6.6 `docs/03:352` gives only implicit authentication of R to I ("R is authenticated to I by DH2/DH3 and by the bundle signature under IK_sig_R, pinned via inviter_fp"); what I gets is H1 (i)/H2 (i) (only R can derive SK) and H6a. §11.1 `docs/03:699` says "mutual classical authentication (injective agreement on transcript)" (wording corrected by ADR-044 (a); R → I: H6b) |
| H6a | Bundle origin authentication | event(IStart(s,iks_I,iks_R,b,tr,rt,sk)) ==> event(BundleSigned(s',iks_R,b)) (non-injective: a signed bundle is replayable by the relay or an invitation holder) | every session without RevealLT(R) before IStart | true |
| H6b | Key confirmation at I's first decrypted reply (ADR-044 (a)) | inj-event(IConfirm(s,iks_I,iks_R,tr,sk)) ==> inj-event(RAccept(s,iks_R,iks_I,ld,oid,tr,rt,sk)) | one R → I TR cell in the model (§6.5 `docs/03:340` "until the initiator has decrypted a first message from R"); event IConfirm; hClean | true |
| H7a | Identity confidentiality of I, network attacker / relay | not attacker(exp(g, ik_I)) and not attacker(vk(sig_I)) (I's IK_dh and IK_sig public keys) | hId: no PubIKS; I runs only on R's invitation (an inviter learns I's identity by design); invitation not leaked; no oracle | true |
| H7b | … against an invitation thief (K_inv known) | as H7a | hIdThief: as hId plus LeakInv phase 0 (the attacker opens the three cells with K_inv; K_id = HKDF(salt = ld_id, IKM = link_key ‖ DH3 ‖ ss_spk ‖ DH4 ‖ ss_opk, info = "SecMP-HX/1 idkey"), §6.4 `docs/03:320`, also needs DH3, DH4, ss_spk, ss_opk) | true |
| H7c | … against a later invitation leak (forward secrecy of K_id) | as H7a | hIdLater: phase 0 the honest run completes (RAccept; R deletes OPK_j; EK_I discarded after IStart (ADR-044 (b))); phase 1 LeakInv, RevealLT(R), RevealSPK(R) and DHO; true because DH4 and ss_opk need EK_I or OPK_j (`docs/03:323` "forward-secret once OPK is deleted and EK_I discarded") | true |
| H7d | Sanity: K_id falls with the OPK | as H7a | as hIdLater plus RevealOPK(s, R, j) in phase 1 | **false** |
| H8 | Expected false: PQ-only authentication of I to R | H5's correspondence | hDH: DHO, KEM honest; LeakInv phase 0; PubIKS. The attacker forges I: DH1 = dh_break(IK_dh_I, SPK_dh_R) from public keys, its own EK and its own encapsulations to SPK_kem_R/OPK_kem_R give DH2–DH4, ss_spk, ss_opk, SK and K_id; R accepts "I". The KEM shares authenticate only the decapsulator R (anyone can encapsulate to R's public keys); no KEM operation involves a secret of I, so I is authenticated by DH1 alone (§6.6 `docs/03:352` "PQ authentication is not provided", §1.2 `docs/03:39`). The forgery needs the invitation (K_inv and K_id contain link_key). Stated assumption (O-9): "assumes a leaked invitation; without it the outer layer masks the missing property — the leak is the threat" | **false** |
| H9 | Expected false: KCI — R's signed-prekey secret lets the attacker impersonate I to R | H5's correspondence | hKCI: RevealSPK(s, R) in phase 0 before the handshake (SPK_dh_R secret); LeakInv phase 0; PubIKS; no oracle. DH1 = X25519(SPK_dh_R, IK_dh_I) is computable by the holder of R's SPK secret; DH2–DH4 and both KEM shares come from the attacker's own EK and encapsulations. Stated assumption (O-9): "assumes a leaked invitation; without it the outer layer masks the missing property — the leak is the threat" | **false** |
| H9b | Boundary: R's identity keys alone give no KCI | H5's correspondence | hKCIlt: RevealLT(s, R) (IK_sig_R, IK_dh_R) in phase 0, SPK not revealed; LeakInv; PubIKS (DH1 does not involve IK_dh_R; R does not verify its own bundle) | true |
| H9c | I-side: I's identity keys do not expose I's SK | H1 (i) | hKCIi: RevealLT(s, I) in phase 0; iks_R honest (DH2, DH3, DH4 use EK_I) | true |
| H10 | OPK single use; replayed envelope not accepted | inj-event(RAccept(s,iks_R,iks_I,ld,oid,tr,rt,sk)) ==> inj-event(InvIssued(s,iks_R,ld,oid)) | hClean + LeakInv; the attacker re-delivers byte-identical retransmissions (§6.5 `docs/03:340`) and replays (§6.6 `docs/03:354`); modelled with the single-use private OPK cell, re-output on failure, replicated acceptance attempts (O-7). STOP rule for the implementer: if ProVerif does not terminate within 30 minutes on the gate machine, fall back to the bounded model (2 invitations × 2 initiator sessions × 3 attempts) and report it; H10 is then additionally covered by the tests `accept_replayed_envelope_rejects_after_success` and `prop_opk_consumed_exactly_once` (TEST-MATRIX-M4, already in the matrix) | true |
| H11 | Reachability sanity, one query per accept event and session (M3 R-52) | for every session tag s of the model: event(IStart(s,…)); event(BundleSigned(s,…)); event(RAccept(s,…,tr,rt,sk)) && event(IStart(s,…,tr,rt,sk)) (the honest pair completes, not merely an attacker-built envelope); event(IConfirm(s,…)) | — | **false** for every line (ProVerif reports the event reachable: the honest run completes in every session, including those with phase 1) |
| H12 | Forward secrecy of SK | not attacker(sk) of the phase-0 session (I and R sides as H1) | hFS: phase 0 the honest run completes (R deletes OPK_j, §6.6 step 4; EK_I discarded after IStart (ADR-044 (b))); phase 1 RevealLT(I), RevealLT(R), RevealSPK(R), LeakInv. DH1, DH2, DH3, ss_spk become computable; DH4 = X25519(EK_I, OPK_dh_R) and ss_opk need EK_I or OPK_j | true |
| H12b | Sanity: FS rests on OPK deletion | as H12 | as hFS plus RevealOPK(s, R, j) in phase 1 | **false** |
| H12c | FS under a later classical break (HNDL) | as H12 | as hFS plus DHO in phase 1 (DH4 by dh_break; ss_opk still needs OPK_j's dk) | true |

Gate rule: H1, H2, H3, H5, H6a, H6b, H7a–H7c, H9b, H9c, H10, H12 and H12c must be proved true; H4, H7d, H8, H9,
H12b and every H11 line must be false (ProVerif reports an attack / reachability); H6 is not claimed; H10 is a
query (STOP rule in its row). A model change requires a spec reference (formal/README.md).
Every false verdict must be checked to use only its own session (as `tr.pv` §3).

### Paths the model covers / excludes (every path of §5.5, §6.4–§6.6 named; M3 R-01/R-12 lesson)

Covered: the with-OPK handshake (the only v1 path); §5.5 step 2 blob opening under K_ld, step 3 fingerprint pin,
step 4 bundle signature and `opk_present`; §6.4 all four DH and both KEM shares, transcript, SK, K_id; §6.5 Inner,
inner_ct under K_id, Outer, three chunks under K_inv; retransmission of byte-identical cells and arbitrary replay
(DY attacker); garbage and attacker cells interleaved with the honest ones (the attacker delivers any cells; a
cell that does not open is discarded and R can try again); §6.6 step 1 spk_id/opk_id check and the unused-OPK
check, step 2 K_id and inner open (IKSPublic_I decodable), step 3 DH1/DH2, transcript, SK, TR responder init and
first_msg on the §7.4 step path, Content type Handshake; failure keeps the OPK, success deletes it (single-use
private cell; bounded fallback per STOP rule);
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
HandshakeCellPlaintext, LinkDataV1, InvitationV1, URI (M2 encodings, fuzz); grouping by init_id, "first complete
group wins", duplicate (init_id, i), partial-group storage (§6.5 `docs/03:340`, ADR-044 (c)) — tests
`group_duplicate_chunk_identical_ignored`, `group_duplicate_chunk_differing_first_seen_wins`,
`group_rejected_then_other_init_id_accepts`, `group_partial_store_bound_8_evicts_oldest`, Kani K3; first_msg header
n = 0 / pn = 0 and at least one route of a known kind in the Handshake content (ADR-044 (e)) — tests
`accept_first_msg_n_nonzero_rejects_and_keeps_opk`, `accept_first_msg_pn_nonzero_rejects_and_keeps_opk`,
`accept_handshake_without_known_route_rejects_and_keeps_opk`; ML-KEM implicit
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

Open SQ entries for HX/INV: none. SPEC-QUESTIONS.md (state "Weisung REF-M4-1": "No open questions") marks every
HX/INV-related entry answered — SQ-10 (fingerprint input), SQ-12 (decoder checks), SQ-13/14 (RelayRef), SQ-15
(caps), SQ-17 (route count 0), SQ-25 (invitee checks neither inviter bound; reading A) — with one pending
follow-up: SQ-25's answer promises "a spec clarification" of §5.5 that is not yet in rev 2.3.
