# Upstream advisories for the ADR-055 C code (SQLite 3.50.4, SQLCipher 4.10.0, OpenSSL 3.6.3)

Date 2026-10-28. Source of the findings: the reviewer's web check (WEISUNG M7-A1b §6). The executor's container has no
web access (a fetch of sqlite.org was refused by the proxy on 2026-10-27), so the findings below are recorded as the
reviewer gave them, not re-read by the executor.

| Component | Version in the build (A0 §3) | Findings | Fixed in |
|---|---|---|---|
| SQLite | 3.50.4 | CVE-2026-11822, CVE-2026-11824: heap write past the end; need attacker-supplied SQL, FTS5 and DEFENSIVE off | 3.53.2 |
| SQLite | 3.50.4 | CVE-2025-70873: zipfile extension only | 3.53.0 |
| SQLCipher | 4.10.0 | defensive-mode bypass in `sqlcipher_export` (CVSS 4.0 2.1 Low, no CVE id) | 4.15.0 |
| OpenSSL | 3.6.3 | CVE-2026-63072, CVE-2026-63076, CVE-2026-18798 (Moderate: CMS, CMP, QUIC); Low incl. CVE-2026-75803 (AEAD forgery with empty ciphertext via `EVP_Cipher()`) | 3.6.4 |
| OpenSSL | 3.6.3 | CVE-2026-84782 (High, DTLS); Low incl. CVE-2026-54872 (timing, non-NIST EC) | 3.6.5 |

RustSec / OSV: no advisory for `libsqlite3-sys` 0.37.0, `rusqlite` 0.39.0, `openssl-sys` 0.9.117, `openssl-src` 300.6.1+3.6.3,
`argon2` 0.6.0, `blake2` 0.11.0 (executor: `cargo audit` of 2026-10-27, DB of 1380 advisories, `a0/gates.txt`, no finding
for the scratch lock). Newest `openssl-src` 300.x on crates.io: 300.6.1+3.6.3; newest `libsqlite3-sys`: 0.39.1.

Sources:
- https://www.sqlite.org/cves.html
- https://www.zetetic.net/blog/2026/04/28/sqlcipher-4.15.0-release/
- https://openssl-library.org/news/vulnerabilities/
- https://api.osv.dev/v1/query (per crate@version)
