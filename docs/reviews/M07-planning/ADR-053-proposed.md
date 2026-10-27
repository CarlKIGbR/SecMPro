### ADR-053 — Store key hierarchy: passphrase wrap, per-table keys, record sealing, SQLCipher key, backup (spec rev 2.7)

**Status.** Proposed (planner, 2026-10-27; OPEN-M7-01, reviewer decisions Q80, Q123, Q124). **OWNER class** (a crypto
composition and four new labels = spec change, `docs/03:774`; CLAUDE.md §5). **No default applies**: it takes effect
only with the owner's written "ADR-053 accepted"; until then no [O-01] row of TEST-SPEC-M7 is built. Extends ADR-020 and
ADR-027; changes no wire structure, no App. D layout, no frozen vector.

**Context.** CS-3.2 (`docs/04:53`) fixes Argon2id m = 256 MiB, t = 3, p = 4 and a random 32-B `MK_profile` wrapped by a
passphrase key; CS-3.3 (`:54`) seals secret columns "with `CAEAD` under keys derived from `MK_profile`
(`"SecMP-STORE/1 <table>"`)"; CS-3.5 (`:56`) wants the backup "with the same wrapping"; App. A (`docs/03:767-768`) has the
nine table labels. Unspecified: Argon2id salt/output, the wrap, the HKDF parameters, record nonce/AD, the SQLCipher key,
the backup format; App. A has no label for wrap, SQLCipher key or backup.

**Decision.**
1. *Passphrase key* (RFC 9106 §3.1 Argon2id, v = 0x13; §4 parameter choice): `KEK = Argon2id(P = passphrase (UTF-8 as
   entered), S = salt, p = 4, T = 32, m = 262 144 KiB, t = 3, v = 0x13, K = X = empty)`, `salt` 16 B from `OsRng`. RFC 9106
   §4 recommends a 128-bit salt and 256-bit tag; its second option is t = 3, p = 4, 64 MiB — CS-3.2 raises memory to 256 MiB.
2. *Wrap of `MK_profile`* (CAEAD, spec §3.4 `docs/03:119-128`, which names local storage as a CAEAD use): `wrap = ver(0x01)
   ‖ salt(16) ‖ params(m u32 ‖ t u32 ‖ p u32) ‖ N(24) ‖ CAEAD.Seal(KEK, N, AD = "SecMP-STORE/1 wrap" ‖ ver ‖ salt ‖ params,
   MK_profile)` = 133 B, `N` random. **Unlock accepts exactly `ver` = 0x01 with `params` = `PROFILE` (262 144, 3, 4)**; any
   other `ver`/`params`, or a wrap of another length, is the uniform unlock error, decided **before** the KDF. That check
   reads only file bytes, never the passphrase, so it adds no passphrase-dependent timing; it bounds the work a crafted
   file can demand (no attacker-chosen m). Otherwise: Argon2id once, CAEAD.Open once, every failure the same error.
3. *Table keys* (HKDF-SHA-256 with salt 0^32 as in §6.4; App. A label pattern): `K_t = HKDF-SHA-256(salt = 0^32, IKM =
   MK_profile, info = "SecMP-STORE/1 <table>", L = 32)` for the nine tables of `docs/02` §4.2.
4. *SQLCipher key* (CS-3.1): `K_db = HKDF-SHA-256(salt = 0^32, IKM = MK_profile, info = "SecMP-STORE/1 db", L = 32)` as
   the raw key (`PRAGMA key = "x'…'"`); `MK_profile` is only ever HKDF input (no key reuse across constructions).
5. *Record seal* (CAEAD §3.4): `rec = N(24) ‖ CAEAD.Seal(K_t, N, AD = "SecMP-STORE/1 <table>" ‖ col_len u8 ‖ column name
   (ASCII) ‖ row_key, record)`; `row_key` = u64 big-endian for integer keys, `len u8 ‖ bytes` for byte-string ids. A record
   moved to another table, row **or column** does not open.
6. *Backup* (CS-3.5; "same wrapping" = the same construction, not the same key): at export the user enters a **backup
   passphrase**; `file = "SecMProbackup"(13 B, plaintext magic: reveals the file type only, accepted) ‖ header ‖ N(24) ‖
   CAEAD.Seal(K_bk, N, AD = "SecMP-STORE/1 backup" ‖ header, body)`, `header = ver(0x01) ‖ salt(16) ‖ params(12) ‖ bwrap ‖
   section table`, `bwrap = N'(24) ‖ CAEAD.Seal(KEK_bk, N', AD = "SecMP-STORE/1 bwrap" ‖ ver ‖ salt ‖ params, MK_bk)`
   (KEK_bk = item 1 over the backup passphrase and this salt; `MK_bk` fresh 32 B), `K_bk = HKDF-SHA-256(salt = 0^32,
   IKM = MK_bk, info = "SecMP-STORE/1 backup", L = 32)`. Item 2's acceptance rule applies to `params`. Layouts: Appendix.
7. *Labels* (spec rev 2.7, App. A): add `"SecMP-STORE/1 wrap"`, `"SecMP-STORE/1 db"`, `"SecMP-STORE/1 backup"`,
   `"SecMP-STORE/1 bwrap"`. **Prefix-free** (`docs/03:774`): checked over the 49 App. A labels + 4 new = 53, 0 prefix
   pairs; both implementations' prefix-freeness tests re-read the list.
8. *Vectors*: `ref/` generates `vectors/store.json` from this text alone (items 1–6 + Appendix, fixed inputs; Argon2id
   also against RFC 9106 §5.3); until then the store KATs are [REF]-open (OPEN-M7-38).

**Appendix — backup layout (all integers big-endian).** `section table = count u8 (= 4) ‖ {tag u8 ‖ len u32} × 4`,
tags in this order: 1 identity, 2 contacts, 3 settings, 4 messages; `body` = the four sections concatenated, each exactly
`len` bytes. identity = `ver(0x01) ‖ ed25519_seed[32] ‖ mldsa65_seed[32] ‖ x25519_secret[32]` (the seed forms of the
proto's key types). contacts = `n u32 ‖ { IKSPublic[2017] ‖ verified u8 (0/1) ‖ Profile (D.3) ‖ local_name_len u8 ‖ local_name (UTF-8, ≤ 64; the user's own display name of the contact, `docs/02:95`) } × n`. settings = `n u16 ‖
{ key_len u8 ‖ key (ASCII) ‖ val_len u16 ‖ val } × n`. messages = `n u32 ‖ { contact_index u32 ‖ direction u8 (0 in, 1
out) ‖ ts u64 ‖ AppMessage (D.5) } × n` (no view-once, CS-3.4). Nothing else; trailing bytes reject (uniform error).

**Alternatives.** (a) `MK_profile` as SQLCipher key — key reuse; rejected. (b) Wrap without commitment — a crafted file
could open under a wrong key; CAEAD is the committing wrapper (ADR-019). (c) ADR-027 fallback — not triggered. (d) A
passphrase verifier hash — an early-exit oracle; rejected (CT-01). (e) Backup under the profile passphrase and wrap
label — profile and backup wraps would be interchangeable; rejected (Q124).

**Consequences.** `docs/03` rev 2.7: App. A + four labels, changelog line. `secmp-crypto` exposes Argon2id (ADR-055)
beside HKDF and CAEAD; `secmp-store` composes them only as written. Gated rows: ST-05…ST-07, ST-10…ST-12, ST-19, CT-01,
CT-02, CT-05, BK-*, FO-03, FZ-01, FZ-02, PR-03, IN-03. Any later parameter change is a new `ver`, never a silent change.
