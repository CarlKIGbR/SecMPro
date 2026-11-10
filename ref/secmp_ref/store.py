# SPDX-License-Identifier: AGPL-3.0-or-later
"""The local-store constructions of ADR-053 items 1–6 and Amendment 1 (spec rev 2.7, App. A).

    KEK        = Argon2id(P = passphrase, S = salt, p = 4, T = 32, m = 262144 KiB, t = 3, v = 0x13)   item 1
    wrap       = ver ‖ salt ‖ params ‖ N ‖ CAEAD.Seal(KEK, N, "SecMP-STORE/1 wrap" ‖ ver ‖ salt ‖ params, MK)   item 2
    K_t, K_db  = HKDF-SHA-256(salt 0^32, IKM MK, info "SecMP-STORE/1 <table|db>", L 32)               items 3–4
    rec        = N ‖ CAEAD.Seal(K_t, N, "SecMP-STORE/1 <table>" ‖ col_len u8 ‖ column ‖ row_key, record)   item 5, Am. 1
    backup     = "SecMProbackup" ‖ header ‖ N ‖ CAEAD.Seal(K_bk, N, "SecMP-STORE/1 backup" ‖ header, body)   item 6

Every failure on untrusted input raises the uniform Reject. Written from the ADR text alone.
"""

import functools

from . import caead, labels, primitives
from .errors import Reject

VER = 1
MAGIC = b"SecMProbackup"
PROFILE = (262_144, 3, 4)                          # (m KiB, t, p), item 2
SALT = 16
NONCE = 24
KEY = 32
ZERO_SALT = bytes(32)
WRAP_LEN = 1 + SALT + 12 + NONCE + KEY + 32 + 16    # 133
TABLES = ("identity", "prekeys", "relays", "contacts", "sessions", "outbox", "messages", "invitations", "settings")
SECTION_TAGS = (1, 2, 3, 4)                         # identity, contacts, settings, messages (Appendix)


def table_label(table: str) -> bytes:
    return b"SecMP-STORE/1 " + table.encode("ascii")


def params_bytes(params=PROFILE) -> bytes:
    m, t, p = params
    return m.to_bytes(4, "big") + t.to_bytes(4, "big") + p.to_bytes(4, "big")


# ---------------------------------------------------------------------------------------------
# Items 3–4


def table_key(mk: bytes, table: str) -> bytes:
    return primitives.hkdf(ZERO_SALT, mk, table_label(table), 32)


def db_key(mk: bytes) -> bytes:
    return primitives.hkdf(ZERO_SALT, mk, labels.STORE_DB, 32)


def backup_key(mk_bk: bytes) -> bytes:
    return primitives.hkdf(ZERO_SALT, mk_bk, labels.STORE_BACKUP, 32)


# ---------------------------------------------------------------------------------------------
# Item 1


@functools.lru_cache(maxsize=None)
def kek(passphrase: bytes, salt: bytes, params=PROFILE) -> bytes:
    m, t, p = params
    return primitives.argon2id(passphrase, salt, t=t, m_kib=m, p=p, length=32)


# ---------------------------------------------------------------------------------------------
# Item 2


def _wrap_ad(label: bytes, ver: int, salt: bytes, params) -> bytes:
    return label + bytes([ver]) + salt + params_bytes(params)


def wrap(passphrase: bytes, salt: bytes, n: bytes, mk: bytes, *, ver=VER, params=PROFILE,
         label=labels.STORE_WRAP) -> bytes:
    """Builds a wrap; ver/params/label are overridable only so that the case table can craft honest-but-
    unacceptable wraps (a wrap that is valid in every respect except the one the unlock rule rejects)."""
    sealed = caead.seal(kek(passphrase, salt, params), n, _wrap_ad(label, ver, salt, params), mk)
    return bytes([ver]) + salt + params_bytes(params) + n + sealed


def _parse_wrapped(blob: bytes, length: int, label: bytes):
    """Item 2 / item 6: the acceptance rule, decided from file bytes alone, before the KDF."""
    if len(blob) != length or blob[0] != VER or blob[1 + SALT:1 + SALT + 12] != params_bytes():
        raise Reject()
    salt = blob[1:1 + SALT]
    n = blob[1 + SALT + 12:1 + SALT + 12 + NONCE]
    return salt, n, blob[1 + SALT + 12 + NONCE:], _wrap_ad(label, VER, salt, PROFILE)


def unwrap(passphrase: bytes, blob: bytes) -> bytes:
    salt, n, sealed, ad = _parse_wrapped(blob, WRAP_LEN, labels.STORE_WRAP)
    return caead.open(kek(passphrase, salt), n, ad, sealed)


# ---------------------------------------------------------------------------------------------
# Item 5 and Amendment 1


def row_key(parts) -> bytes:
    """parts: ints (u64 big-endian; negative is not encodable) and bytes (len u8 ‖ bytes), in primary-key order."""
    out = b""
    for part in parts:
        if isinstance(part, bytes):
            if len(part) > 255:
                raise Reject()
            out += bytes([len(part)]) + part
        else:
            if part < 0 or part >= 1 << 64:
                raise Reject()
            out += part.to_bytes(8, "big")
    return out


def record_ad(label: bytes, column: str, parts) -> bytes:
    col = column.encode("ascii")
    return label + bytes([len(col)]) + col + row_key(parts)


def seal_record(k_t: bytes, n: bytes, label: bytes, column: str, parts, record: bytes) -> bytes:
    return n + caead.seal(k_t, n, record_ad(label, column, parts), record)


def open_record(k_t: bytes, label: bytes, column: str, parts, rec: bytes) -> bytes:
    if len(rec) < NONCE:
        raise Reject()
    return caead.open(k_t, rec[:NONCE], record_ad(label, column, parts), rec[NONCE:])


# ---------------------------------------------------------------------------------------------
# Item 6 and Appendix


def section_table(lengths) -> bytes:
    return bytes([len(lengths)]) + b"".join(bytes([tag]) + n.to_bytes(4, "big")
                                             for tag, n in zip(SECTION_TAGS, lengths))


def backup_bwrap(passphrase: bytes, salt: bytes, n_prime: bytes, mk_bk: bytes, *, params=PROFILE,
                 label=labels.STORE_BWRAP) -> bytes:
    sealed = caead.seal(kek(passphrase, salt, params), n_prime, _wrap_ad(label, VER, salt, params), mk_bk)
    return n_prime + sealed


def backup_header(salt: bytes, bwrap: bytes, lengths, params=PROFILE) -> bytes:
    return bytes([VER]) + salt + params_bytes(params) + bwrap + section_table(lengths)


def backup_file(header: bytes, n: bytes, k_bk: bytes, body: bytes) -> bytes:
    return MAGIC + header + n + caead.seal(k_bk, n, labels.STORE_BACKUP + header, body)


BWRAP_LEN = NONCE + KEY + 32 + 16                  # 104
HEADER_LEN = 1 + SALT + 12 + BWRAP_LEN + 1 + 5 * 4   # 154


def _check_sections(body: bytes, lengths) -> None:
    """Structural check of the four sections (Appendix). Only what this generator can produce is parsed
    fully: identity (ver 0x01 ‖ three 32-B secrets) and empty contacts/settings/messages lists."""
    if len(body) != sum(lengths):
        raise Reject()
    identity, contacts, settings, messages = (body[sum(lengths[:i]):sum(lengths[:i + 1])] for i in range(4))
    if len(identity) != 97 or identity[0] != VER:
        raise Reject()
    for section, width in ((contacts, 4), (settings, 2), (messages, 4)):
        if section != bytes(width):
            raise ValueError("generator parses only empty sections")


def open_backup(passphrase: bytes, file: bytes) -> bytes:
    """Returns the body. Item 6: the profile unlock rule applies to ver/params, before the KDF."""
    if len(file) < len(MAGIC) + HEADER_LEN + NONCE + 16 + 32 or file[:len(MAGIC)] != MAGIC:
        raise Reject()
    header = file[len(MAGIC):len(MAGIC) + HEADER_LEN]
    salt, _, _, _ = _parse_wrapped(header[:1 + SALT + 12 + BWRAP_LEN], 1 + SALT + 12 + BWRAP_LEN, labels.STORE_BWRAP)
    table = header[1 + SALT + 12 + BWRAP_LEN:]
    if table[0] != 4 or [table[1 + 5 * i] for i in range(4)] != list(SECTION_TAGS):
        raise Reject()
    lengths = [int.from_bytes(table[2 + 5 * i:6 + 5 * i], "big") for i in range(4)]
    bw = header[1 + SALT + 12:1 + SALT + 12 + BWRAP_LEN]
    mk_bk = caead.open(kek(passphrase, salt), bw[:NONCE], _wrap_ad(labels.STORE_BWRAP, VER, salt, PROFILE), bw[NONCE:])
    rest = file[len(MAGIC) + HEADER_LEN:]
    body = caead.open(backup_key(mk_bk), rest[:NONCE], labels.STORE_BACKUP + header, rest[NONCE:])
    _check_sections(body, lengths)
    return body
