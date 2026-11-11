# SPDX-License-Identifier: AGPL-3.0-or-later
"""The `store` case table (SCHEMA-4.12-store.md; Weisung REF-M7-store): the ADR-053 constructions.

Cases in file order: keys (1), wrap + rejects (2–7), seal + rejects (8–15), backup + rejects (16–19), label isolation (20), Amendment 2 and 3 rejects (21–26).
Every random-looking input of a positive case is drawn from its own stream (SCHEMA §2, suite "store",
the case index) in the order of the *_STREAM lists; derived values follow. A reject case draws nothing:
it restates the inputs of the case it manipulates (`from`) so that it is self-contained. The run checks
itself while it generates: each output is recomputed by the opening side, and each reject is rejected by it
(a disagreement raises TableMismatch instead of writing a file).
"""

from . import labels, store
from .identity import iks_public_from_seeds
from .cases import TableMismatch
from .errors import Reject
from .vectorfile import Case, CaseStream, case_id, drop_last

SUITE = "store"

PASS_1 = "correct horse battery staple".encode("utf-8")
PASS_2 = "Pässwört-Ω".encode("utf-8")
PASS_WRONG = "correct horse battery stapler".encode("utf-8")
PASS_BK = "backup-Ω 2026".encode("utf-8")
PASS_BK_WRONG = "backup-Ω 2027".encode("utf-8")
ALT_PARAMS = (65_536, 3, 4)

KEYS_STREAM = [("mk", 32)]
WRAP_STREAM = [("salt", 16), ("n", 24), ("mk", 32)]
BACKUP_STREAM = [("salt", 16), ("n_prime", 24), ("mk_bk", 32), ("n", 24), ("identity_secrets", 96)]

# (table, column, row-key parts (int | bytes), record length). Sealed columns named by the reviewer (R1).
# The byte-string part of (b) is drawn from the stream (16 B); marked by None here.
SEALS = [
    ("contacts", "routes", [7], 48),
    ("invitations", "record", [None], 33),
    ("prekeys", "secret", [1, 42], 64),
    ("sessions", "data", [3, 5, 0], 80),
]


def _draw(i, layout):
    s = CaseStream(SUITE, i)
    return {name: s.take(n) for name, n in layout}


def _wrong_ok(fn, *args):
    try:
        fn(*args)
    except Reject:
        return True
    raise TableMismatch("a reject case was accepted")


def _parts_input(parts):
    return [{"bytes": p} if isinstance(p, bytes) else {"int": p} for p in parts]


def _check(cond, what):
    if not cond:
        raise TableMismatch(what)


def store_cases() -> list[Case]:
    cases: list[Case] = []

    # keys --------------------------------------------------------------------------------------
    i = 1
    d = _draw(i, KEYS_STREAM)
    mk_keys = d["mk"]
    outs = {f"k_{t}": store.table_key(mk_keys, t) for t in store.TABLES}
    outs["k_db"] = store.db_key(mk_keys)
    _check(len(set(outs.values())) == 10, "table keys must differ")
    cases.append(Case(i, "keys", dict(d), outs))

    # wrap --------------------------------------------------------------------------------------
    wraps = {}
    for i, pw in ((2, PASS_1), (3, PASS_2)):
        d = _draw(i, WRAP_STREAM)
        w = store.wrap(pw, d["salt"], d["n"], d["mk"])
        _check(len(w) == 133 and store.unwrap(pw, w) == d["mk"], "wrap round trip")
        cases.append(Case(i, "wrap", {"passphrase": pw, **d}, {"kek": store.kek(pw, d["salt"]), "wrap": w}))
        wraps[i] = (pw, d, w)
    pw, d, w = wraps[2]
    rejects = [
        ("wrong-passphrase", PASS_WRONG, w),
        # honestly sealed under its own AD (and, for params, its own KEK): only the acceptance rule rejects them
        ("ver=02", pw, store.wrap(pw, d["salt"], d["n"], d["mk"], ver=2)),
        ("params=65536,3,4", pw, store.wrap(pw, d["salt"], d["n"], d["mk"], params=ALT_PARAMS)),
        ("drop-last", pw, drop_last(w)),
    ]
    for i, (manip, p, blob) in enumerate(rejects, start=4):
        _wrong_ok(store.unwrap, p, blob)
        cases.append(Case(i, "wrap-reject", {"passphrase": p, "wrap": blob}, None,
                          {"from": case_id(SUITE, 2), "manipulation": manip, "expect": "reject"}))

    # seal --------------------------------------------------------------------------------------
    sealed = {}
    for i, (table, column, parts, rlen) in enumerate(SEALS, start=8):
        s = CaseStream(SUITE, i)
        n = s.take(24)
        parts = [s.take(16) if p is None else p for p in parts]
        record = s.take(rlen)
        label = store.table_label(table)
        k_t = store.table_key(mk_keys, table)
        rec = store.seal_record(k_t, n, label, column, parts, record)
        _check(store.open_record(k_t, label, column, parts, rec) == record, "record round trip")
        ins = {"k_t": k_t, "label": label.decode("ascii"), "column": column, "row_key_parts": _parts_input(parts),
               "n": n, "record": record}
        cases.append(Case(i, "seal", ins, {"row_key": store.row_key(parts), "ad": store.record_ad(label, column, parts),
                                           "rec": rec}, {"from": case_id(SUITE, 1)}))
        sealed[i] = (table, column, parts, k_t, label, rec)
    _check([len(store.row_key(p[2])) for p in sealed.values()] == [8, 17, 16, 24], "row_key sizes")

    table, column, parts, k_t, label, rec = sealed[8]
    k_other = store.table_key(mk_keys, "sessions")
    attempts = [
        ("column=queues", k_t, label, "queues", parts, rec),
        ("row=8", k_t, label, column, [8], rec),
        ("table=sessions", k_other, store.table_label("sessions"), column, parts, rec),
    ]
    for i, (manip, k, lab, col, prts, r) in enumerate(attempts, start=12):
        _wrong_ok(store.open_record, k, lab, col, prts, r)
        cases.append(Case(i, "seal-reject",
                          {"k_t": k, "label": lab.decode("ascii"), "column": col,
                           "row_key_parts": _parts_input(prts), "rec": r}, None,
                          {"from": case_id(SUITE, 8), "manipulation": manip, "expect": "reject"}))
    _wrong_ok(store.row_key, [-1])
    # integer part -1 is not encodable (Am. 1): there is no AD and no record to open; the sealing side refuses
    cases.append(Case(15, "seal-reject",
                      {"k_t": k_t, "label": label.decode("ascii"), "column": column,
                       "row_key_parts": _parts_input([-1])}, None,
                      {"from": case_id(SUITE, 8), "manipulation": "row=-1 (not encodable)", "expect": "reject"}))

    # backup ------------------------------------------------------------------------------------
    d = _draw(16, BACKUP_STREAM)
    identity = bytes([1]) + d.pop("identity_secrets")
    sections = (identity, bytes(4), bytes(2), bytes(4))
    lengths = [len(x) for x in sections]
    _check(lengths == [97, 4, 2, 4], "section lengths")
    body = b"".join(sections)
    bwrap = store.backup_bwrap(PASS_BK, d["salt"], d["n_prime"], d["mk_bk"])
    k_bk = store.backup_key(d["mk_bk"])
    header = store.backup_header(d["salt"], bwrap, lengths)
    file = store.backup_file(header, d["n"], k_bk, body)
    _check(len(bwrap) == 104 and len(header) == store.HEADER_LEN == 154, "backup sizes")
    _check(store.open_backup(PASS_BK, file) == body, "backup round trip")
    cases.append(Case(16, "backup", {"passphrase": PASS_BK, **d, "identity": identity},
                      {"kek_bk": store.kek(PASS_BK, d["salt"]), "bwrap": bwrap, "k_bk": k_bk,
                       "header": header, "body": body, "file": file}))

    def crafted(params=store.PROFILE, bwrap_label=labels.STORE_BWRAP):
        bw = store.backup_bwrap(PASS_BK, d["salt"], d["n_prime"], d["mk_bk"], params=params, label=bwrap_label)
        h = store.backup_header(d["salt"], bw, lengths, params)
        return store.backup_file(h, d["n"], k_bk, body)

    rejects = [
        ("wrong-passphrase", PASS_BK_WRONG, file),
        ("params=65536,3,4", PASS_BK, crafted(params=ALT_PARAMS)),
        ("bwrap-label=wrap", PASS_BK, crafted(bwrap_label=labels.STORE_WRAP)),
    ]
    for i, (manip, p, f) in enumerate(rejects, start=17):
        _wrong_ok(store.open_backup, p, f)
        cases.append(Case(i, "backup-reject", {"passphrase": p, "file": f}, None,
                          {"from": case_id(SUITE, 16), "manipulation": manip, "expect": "reject"}))
    # Reviewer rulings R2, R3, R6 (WEISUNG REF-M7-store3), after the backup cases
    table, column, parts, k_t, label, rec = sealed[8]
    lab = store.table_label("sessions")
    _wrong_ok(store.open_record, k_t, lab, column, parts, rec)
    cases.append(Case(20, "seal-reject", {"k_t": k_t, "label": lab.decode("ascii"), "column": column,
                                          "row_key_parts": _parts_input(parts), "rec": rec}, None,
                      {"from": case_id(SUITE, 8), "manipulation": "label=sessions", "expect": "reject"}))
    iks = iks_public_from_seeds(bytes([1]) * 32, bytes([2]) * 32, bytes([3]) * 32)
    one, ret = (1).to_bytes(4, "big"), b"\x0eretention_days\x00\x04" + (30).to_bytes(4, "big")

    def contact(profile=b"\x04peer\x00"):
        return iks + b"\x01" + profile + b"\x03Bob"

    def message(index=0, kind=b"\x01"):
        return (index.to_bytes(4, "big") + b"\x01" + (1_800_000_000_000).to_bytes(8, "big") + bytes([7]) * 16
                + kind + bytes(4) + b"\x00\x02hi")

    body_rejects = [  # (i, manipulation, contacts, settings, messages); identity as in store-0016
        (21, "settings-key=mode", bytes(4), b"\x00\x01\x04mode\x00\x04\x00\x00\x00\x01", bytes(4)),
        (22, "retention_days-len=3", bytes(4), b"\x00\x01\x0eretention_days\x00\x03\x00\x00\x1e", bytes(4)),
        (23, "settings-key-twice", bytes(4), b"\x00\x02" + ret + ret, bytes(4)),
        (24, "contact_index=1", one + contact(), b"\x00\x00", one + message(index=1)),
        (25, "profile-avatar-flag=2", one + contact(b"\x04peer\x02"), b"\x00\x00", bytes(4)),
        (26, "view-once", one + contact(), b"\x00\x00", one + message(kind=b"\x03")),
    ]
    for i, manip, contacts, settings, messages in body_rejects:
        secs = (identity, contacts, settings, messages)
        f = store.backup_file(store.backup_header(d["salt"], bwrap, [len(x) for x in secs]), d["n"], k_bk, b"".join(secs))
        _wrong_ok(store.open_backup, PASS_BK, f)
        cases.append(Case(i, "backup-reject", {"passphrase": PASS_BK, "file": f}, None,
                          {"from": case_id(SUITE, 16), "manipulation": manip, "expect": "reject"}))
    return cases
