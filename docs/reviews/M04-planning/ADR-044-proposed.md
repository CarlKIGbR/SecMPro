## ADR-044 — Spec clarifications rev 2.5 from the M4 planning (HX/INV)

**Status:** Proposed 2026-10-01 (reviewer, M4 planning); owner ratification per mandate §0(b), default ratify 2026-10-02 ~11:00 UTC

**Context.** The M4 query set (`formal/CLAIMS.md` §HX) and test matrix (TEST-MATRIX-M4) were drawn from `docs/03` rev 2.3/2.4. They found six points that the spec states ambiguously or not at all. Each item below names its source.

Note: the SQ-25 follow-up (§5.5 clarification) is carried by ADR-043 (h); nothing new here.

**Decision.**

(a) §11.1 wording errata (`docs/03:699`): "mutual classical authentication" means: I→R injective agreement on the transcript (H5); R→I implicit (DH2/DH3 + bundle signature) plus key confirmation on the first decrypted reply (H6b).

(b) Initiator EK_I discard (§6.4, `docs/03:323`): the initiator MUST zeroize EK_I's secret immediately after the three cells are sealed and the initiator RatchetState is initialised; `Initiator::start` returns no EK secret; the persisted initiator state after `start` contains no EK_I secret.

(c) Grouping (§6.5, `docs/03:340`): a duplicate (init_id, i) with identical bytes is ignored; with differing bytes the later one is discarded (first-seen wins); after a rejected complete group that group is discarded, the OPK is kept and later groups with other init_ids are processed; at most 8 partial groups are stored, oldest evicted.

(d) Expiry at the responder (§6.6, `docs/03:346-349`, and §5.2, `docs/03:211`): §6.6 takes no time; expiry is enforced by the invitation-record lifecycle (§5.2): the client MUST NOT call `accept` for an expired record and retires its queue; `accept` has no clock parameter.

(e) first_msg constraints (§6.5, `docs/03:330`, and §9.8, `docs/03:640`): the first_msg header MUST carry n = 0 and pn = 0; R rejects otherwise (uniform error, OPK kept); seq/ts follow §7.6 without further constraint; the Handshake content MUST contain at least one route of a known kind, else R rejects (uniform error, OPK kept).

(f) Reflection (§6.6 step 2, `docs/03:347`): R MUST reject an envelope whose IKSPublic_I equals IKSPublic_R (reflection), uniform error, OPK kept; an IKS equal to an existing contact's is client-core policy (M7), not a handshake rejection.

**Alternatives.** None recorded.

**Consequences.** On ratification `docs/03` becomes rev 2.5 with these texts; (b)–(f) are enforced from M4 (tests named in the M4 test specification); vectors unchanged (`hx.json` frozen at a33cf162…).
