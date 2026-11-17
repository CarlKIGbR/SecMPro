# Hardening backlog

Items deferred under ADR-062 (build phase M8–M10). Every item is closed in the hardening phase (extension of M11, before M12) or explicitly accepted by the owner; none may be dropped silently. An item that violates a CLAUDE.md §1 invariant or a threat-model statement does not belong here — it is a blocker and is fixed in its unit.

| ID | Item | Source | Status |
|---|---|---|---|
| HB-1 | SE-178 follow-up patch v10→v14 (tests only). | SE-178 | Open |
| HB-2 | Two known surviving mutants N11 and N12: a refusal that clears the floor anchors or periods of the OTHER contact's old queues is not detected by any test. Add the test or document each in `docs/mutants-accepted.md`. | M7 mutation gate | Open |
| HB-3 | CAP2 = OPEN-M7-B-32 option (B): sender-side brake on the client's own on-demand rotations. Deferred; decide, build or accept. | OPEN-M7-B-32 | Open |
| HB-4 | The mutation gate is out of the PR path (ADR-047 Amendment 14); the full run with zero undocumented survivors is a release-gate item. | ADR-047 Am. 14, ADR-062 (6) | Open |
| HB-5 | SE-178 has not been stress-tested beyond the v12 seeds. | SE-178 | Open |
| HB-6 | The milestone reviews of M8, M9 and M10 (full directorate), deferred by ADR-062 (3). Added when each milestone's short GO is recorded. | ADR-062 | Open |
| HB-7 | While the OS randomness keeps failing, `Hub::pump` returns `Unavailable` at the first contact whose send-queue switch is refused (EXT2d-1): the routes of contacts later in index order are not processed in that pump, also those that need no draw (a first route, a Q236 skip, the cap). Fix: continue the loop and return `Unavailable` at the end. | Cross-review `37abef9..0dfdb10` X-2 | Open |
| HB-8 | `Hub::register_contact` drops the `bool` of `register_route`, so a switch refused there would drop a route silently. No current caller reaches it (every caller registers a contact without a send registration, so no draw is made). Fix: map `false` to `Err(Unavailable)`. | Cross-review `37abef9..0dfdb10` X-3 | Open |

Rules: new rows get the next HB number and name their source; a row is closed with the commit or review that closes it, or marked "Accepted (Owner, date)".
