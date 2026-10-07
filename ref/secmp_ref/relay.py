# SPDX-License-Identifier: AGPL-3.0-or-later
"""SecMP-Q (spec §9): the relay's queue and link-data stores and its command executor, plus the
client's side of the command layer (tokens, D.6 signatures, response decoding).

The relay runs one link (§9.7 item 7: at most one link per connection). `Relay.execute(frames, rng)`
receives request frames and returns the response frames, in request order and with exactly the D.2
number of frames per command (§9.7 item 6, D.2). It is transactional: a LINK-level rejection (reading
OPEN-2: a frame that does not open, a plaintext that does not decode, a CONT with nothing pending —
reading OPEN-6) raises the uniform Reject and leaves the link counters, `cmd_seq` and the store as they
were. A command error is not a rejection: it is a response (ERR, or a CELLR/LINKR error frame).

Readings (SCHEMA §4.11): `cmd_seq` (OPEN-5), undecodable frames and SKEY (OPEN-6), the FETCH layout
(OPEN-7), FETCH_MULTI (OPEN-8), signature failures (OPEN-9), owner status (OPEN-10), LINKR fields and
dummies (OPEN-11), the queue budget (OPEN-12). The order of checks inside one command, which §9 leaves
open, is the order of the code below; every vector case has exactly one fault.
"""

import collections
import copy
import dataclasses

from . import encodings as enc
from . import labels, link, primitives, sizes
from .errors import Reject

# §4.2 (F and F_M are tunable until M6, ADR-018)
F = 4
F_M = 8
QUEUE_CAPACITY = 128
CELL_TTL_BUCKETS = 7 * 24                         # §4.2 CELL_TTL, in hour buckets
LINKDATA_TTL_BUCKETS = 30 * 24                    # §4.2 LINKDATA_TTL in hours = 720 (ADR-048 (o))

# D.2 ERR codes and CELLR `present` values
ERR_TOKEN, ERR_FULL, ERR_NOQUEUE, ERR_AUTH, ERR_EXISTS, ERR_MALFORMED, ERR_RATE = range(1, 8)
CELLR_DUMMY, CELLR_CELL, CELLR_NOQUEUE, CELLR_AUTH, CELLR_MALFORMED = range(5)

LINK_PART = (enc.LINK_PART_FIRST, enc.LINK_PART_CONT, enc.LINK_PART_CONT)   # 4160 + 4100 + 4100 = 12360
ZERO_RID = bytes(16)

# D.2 / §9.3: response frames per request
RESPONSE_FRAMES = {"QUEUE_NEW": 1, "SEND": 1, "FETCH": F, "FETCH_MULTI": F_M, "QUEUE_DEL": 1, "LINK_PUT": 1,
                   "LINK_GET": 3, "PING": 1, "SKEY": 1}

_REQUEST_NAMES = {code: name for name, code in enc.REQUEST_OPS.items()}
_RESPONSE_NAMES = {code: name for name, code in enc.RESPONSE_OPS.items()}

last_rule = None


def _fail(rule):
    global last_rule
    last_rule = rule
    raise Reject()


# ---------------------------------------------------------------------------------------------
# §9.1 identifiers, §9.6 tokens, D.6 signatures


def rid_of(recv_pk: bytes) -> bytes:
    """rid = SHA-256("SecMP-Q/1 rid" ‖ recv_pk)[0..16]"""
    return primitives.sha256(labels.Q_RID + recv_pk)[:16]


def sid_of(recv_pk: bytes, send_pk: bytes) -> bytes:
    """sid = SHA-256("SecMP-Q/1 sid" ‖ recv_pk ‖ send_pk)[0..16]"""
    return primitives.sha256(labels.Q_SID + recv_pk + send_pk)[:16]


def token(access_key: bytes, sess_id: bytes, cmd_seq: int) -> bytes:
    """token = HMAC-SHA-256(relay_access_key, "SecMP-Q/1 token" ‖ sess_id ‖ cmd_seq), cmd_seq a u32 BE."""
    return primitives.hmac_sha256(access_key, labels.Q_TOKEN + sess_id + cmd_seq.to_bytes(4, "big"))


def sign(seed: bytes, command: str, sess_id: bytes, fields: dict) -> bytes:
    """Ed25519.Sign(key, D.6 message); `fields` holds the command's D.2 fields (and `blob` for LINK_PUT)
    and `cmd_seq`."""
    return primitives.ed25519_sign(seed, enc.signed_message(command, {**fields, "sess_id": sess_id}))


def verify(pk: bytes, command: str, sess_id: bytes, fields: dict, sig: bytes) -> bool:
    """Strict Ed25519 (§3.5) of a D.2 `sig` over the D.6 message."""
    try:
        primitives.ed25519_verify(pk, enc.signed_message(command, {**fields, "sess_id": sess_id}), sig)
    except Reject:
        return False
    return True


# ---------------------------------------------------------------------------------------------
# D.2 payloads: generic decoding by opcode


def decode_request(payload: bytes) -> dict:
    """A request payload (unpadded) as a D.2 value; Reject unless it decodes. SKEY is not decoded here."""
    if not payload or payload[0] not in _REQUEST_NAMES:
        _fail("pt-decode")
    try:
        return enc.decode(f"Request/{_REQUEST_NAMES[payload[0]]}", enc.iso_pad(payload, sizes.FRAME_PLAINTEXT))
    except Reject:
        _fail("pt-decode")


def decode_response(payload: bytes, context: str | None = None) -> dict:
    """A response payload (unpadded) as a D.2 value; a CELLR is decoded with its request as context."""
    if not payload or payload[0] not in _RESPONSE_NAMES:
        _fail("pt-decode")
    try:
        return enc.decode(f"Response/{_RESPONSE_NAMES[payload[0]]}", enc.iso_pad(payload, sizes.FRAME_PLAINTEXT),
                          context)
    except Reject:
        _fail("pt-decode")


def response(name: str, cmd_seq: int, **fields) -> bytes:
    """The payload op ‖ cmd_seq ‖ fields of a response (D.2); cmd_seq echoes the request."""
    return enc.payload(f"Response/{name}", {"op": name, "cmd_seq": cmd_seq, **fields})


def blob_parts(blob: bytes) -> list[bytes]:
    """12360 = 4160 + 4100 + 4100 (D.2 LINK_PUT / LINKR / CONT)."""
    assert len(blob) == sizes.LINK_BLOB
    a, b = LINK_PART[0], LINK_PART[0] + LINK_PART[1]
    return [blob[:a], blob[a:b], blob[b:]]


# ---------------------------------------------------------------------------------------------
# §9.1 queue store, §9.4 link-data store


@dataclasses.dataclass
class StoredCell:
    cell_id: int
    arrival: int
    cell: bytes
    expiry_bucket: int


@dataclasses.dataclass
class Queue:
    """§9.1: recv_pk, send_pk, cells, next_cell_id, created_bucket, last_fetch_bucket."""
    recv_pk: bytes
    send_pk: bytes
    sid: bytes
    created_bucket: int
    last_fetch_bucket: int
    cells: collections.deque = dataclasses.field(default_factory=collections.deque)
    next_cell_id: int = 1

    def ack(self, ack: int) -> None:
        """FETCH semantics (§9.3): delete every cell with cell_id ≤ ack (cumulative)."""
        while self.cells and self.cells[0].cell_id <= ack:
            self.cells.popleft()


@dataclasses.dataclass
class QueueStore:
    queues: dict = dataclasses.field(default_factory=dict)     # rid → Queue
    by_sid: dict = dataclasses.field(default_factory=dict)     # sid → rid
    arrival: int = 0                                           # §9.1 relay-global counter

    def __len__(self):
        return len(self.queues)

    def get(self, rid: bytes) -> Queue | None:
        return self.queues.get(rid)

    def by_sender(self, sid: bytes) -> Queue | None:
        rid = self.by_sid.get(sid)
        return None if rid is None else self.queues[rid]

    def create(self, recv_pk: bytes, send_pk: bytes, bucket: int) -> Queue:
        rid, sid = rid_of(recv_pk), sid_of(recv_pk, send_pk)
        q = Queue(recv_pk, send_pk, sid, bucket, bucket)
        self.queues[rid], self.by_sid[sid] = q, rid
        return q

    def delete(self, rid: bytes) -> None:
        q = self.queues.pop(rid)
        del self.by_sid[q.sid]
        q.cells.clear()                           # §9.7 item 5: zeroization is outside Python's control

    def append(self, q: Queue, cell: bytes, bucket: int) -> tuple[int, int | None]:
        """§9.5: at QUEUE_CAPACITY the oldest cell is evicted; → (cell_id, evicted cell_id or None)."""
        evicted = q.cells.popleft().cell_id if len(q.cells) >= QUEUE_CAPACITY else None
        self.arrival += 1
        q.cells.append(StoredCell(q.next_cell_id, self.arrival, cell, bucket + CELL_TTL_BUCKETS))
        q.next_cell_id += 1
        return q.next_cell_id - 1, evicted


@dataclasses.dataclass
class LinkData:
    one_time: int
    expires_bucket: int
    owner_pk: bytes
    blob: bytes | None                            # None once a one-time blob is consumed (§9.4)

    @property
    def consumed(self) -> bool:
        return self.blob is None


@dataclasses.dataclass
class LinkDataStore:
    entries: dict = dataclasses.field(default_factory=dict)    # ld_id → LinkData


# ---------------------------------------------------------------------------------------------
# The relay


@dataclasses.dataclass
class Pending:
    """A LINK_PUT whose CONT frames have not all arrived (D.2: 3 frames, one response after the third)."""
    request: dict
    fresh: bool                                   # its cmd_seq was > last (reading OPEN-5)
    parts: list


@dataclasses.dataclass
class Relay:
    keys: link.RelayKeys
    link: link.Link
    now_bucket: int
    budget_queues: int | None = None              # reading OPEN-12: a QUEUE_NEW that would exceed it is ERR_FULL
    queues: QueueStore = dataclasses.field(default_factory=QueueStore)
    linkdata: LinkDataStore = dataclasses.field(default_factory=LinkDataStore)
    last: int = 0                                 # reading OPEN-5: the last recorded cmd_seq, from 0
    pending: Pending | None = None

    def execute(self, frames, rng) -> list[bytes]:
        """The response frames to `frames`, in order; transactional (see the module docstring)."""
        return [f for per in self.execute_trace(frames, rng) for f in per]

    def execute_trace(self, frames, rng) -> list[list[bytes]]:
        """As execute, but the response frames grouped by the request frame that triggered them."""
        work = copy.deepcopy(self)
        out = [work._receive(frame, rng) for frame in frames]
        self.__dict__.update(work.__dict__)
        return out

    # -- one request frame

    def _receive(self, frame: bytes, rng) -> list[bytes]:
        payload = self.link.open(frame)            # Reject: frame-len, frame-open, pt-decode
        if len(payload) < 5:
            _fail("pt-decode")
        if payload[0] == enc.OP_SKEY:
            # D.2 "(reserved, v1 relay answers ERR_MALFORMED)"; reading OPEN-6. Nothing after cmd_seq is
            # parsed: SKEY has no v1 fields.
            cmd_seq = int.from_bytes(payload[1:5], "big")
            if self.pending is not None:
                _fail("cont-expected")
            self._record(cmd_seq)
            return self._seal([self._err(cmd_seq, ERR_MALFORMED)])
        req = decode_request(payload)
        if self.pending is not None:
            return self._continue(req, rng)
        if req["op"] == "CONT":
            _fail("cont-orphan")                   # reading OPEN-6
        fresh = self._record(req["cmd_seq"])
        if req["op"] == "LINK_PUT":
            self.pending = Pending(req, fresh, [req["blob_part"]])
            return []
        if not fresh:
            return self._seal([self._err(req["cmd_seq"], ERR_MALFORMED)])   # reading OPEN-5
        return self._seal(getattr(self, "_cmd_" + req["op"].lower())(req, rng))

    def _record(self, cmd_seq: int) -> bool:
        """Reading OPEN-5: a cmd_seq > last is recorded, whatever the outcome; → whether it was."""
        if cmd_seq > self.last:
            self.last = cmd_seq
            return True
        return False

    def _continue(self, req: dict, rng) -> list[bytes]:
        p = self.pending
        if req["op"] != "CONT" or req["cmd_seq"] != p.request["cmd_seq"] or req["idx"] != len(p.parts):
            _fail("cont-expected")                 # proposal: anything but the expected CONT tears down
        p.parts.append(req["data"])
        if len(p.parts) < len(LINK_PART):
            return []
        self.pending = None
        cmd_seq = p.request["cmd_seq"]
        if not p.fresh:
            return self._seal([self._err(cmd_seq, ERR_MALFORMED)])          # after the third frame (D.2)
        return self._seal(self._cmd_link_put(p.request, b"".join(p.parts)))

    def _seal(self, payloads: list[bytes]) -> list[bytes]:
        return [self.link.seal(p) for p in payloads]

    # -- helpers

    @staticmethod
    def _err(cmd_seq: int, code: int) -> bytes:
        return response("ERR", cmd_seq, code=code)

    def _token_ok(self, req: dict) -> bool:
        expected = token(self.keys.access_key, self.link.sess_id, req["cmd_seq"])
        return primitives.ct_equal(expected, req["token"])

    def _sig_ok(self, pk: bytes, command: str, fields: dict) -> bool:
        return verify(pk, command, self.link.sess_id, fields, fields["sig"])

    def _status(self, rid: bytes, ack: int, sig: bytes, command: str, cmd_seq: int):
        """FETCH / FETCH_MULTI entry checks: → the queue, or the CELLR `present` of its error."""
        q = self.queues.get(rid)
        if q is None:
            return CELLR_NOQUEUE
        if not self._sig_ok(q.recv_pk, command, {"rid": rid, "ack": ack, "cmd_seq": cmd_seq, "sig": sig}):
            return CELLR_AUTH
        if ack >= q.next_cell_id:
            return CELLR_MALFORMED                 # §9.1 "answer … with ERR_MALFORMED"; reading OPEN-7
        return q

    @staticmethod
    def _cellr(cmd_seq, present, rid, cell_id, cell) -> bytes:
        return response("CELLR", cmd_seq, present=present, rid=rid, cell_id=cell_id, cell=cell)

    def _dummies(self, cmd_seq: int, n: int, rng) -> list[bytes]:
        return [self._cellr(cmd_seq, CELLR_DUMMY, ZERO_RID, 0, rng.take(sizes.CELL)) for _ in range(n)]

    def _linkr(self, cmd_seq: int, present: int, consumed: int, blob: bytes) -> list[bytes]:
        first, *rest = blob_parts(blob)
        return [response("LINKR", cmd_seq, present=present, consumed=consumed, blob_part=first),
                *(response("CONT", cmd_seq, idx=k, data=part) for k, part in enumerate(rest, start=1))]

    # -- §9.3 commands; each returns its response payloads

    def _cmd_queue_new(self, r, rng):
        s = r["cmd_seq"]
        if not self._token_ok(r):
            return [self._err(s, ERR_TOKEN)]
        if not self._sig_ok(r["recv_pk"], "QUEUE_NEW", r):
            return [self._err(s, ERR_AUTH)]       # reading OPEN-9
        rid = rid_of(r["recv_pk"])
        q = self.queues.get(rid)
        if q is not None:                          # §9.7 item 8
            if q.send_pk != r["send_pk"]:
                return [self._err(s, ERR_AUTH)]
            return [response("OK_QUEUE_NEW", s, rid=rid, sid=q.sid)]
        if self.budget_queues is not None and len(self.queues) >= self.budget_queues:
            return [self._err(s, ERR_FULL)]       # §9.7 item 4; reading OPEN-12
        q = self.queues.create(r["recv_pk"], r["send_pk"], self.now_bucket)
        return [response("OK_QUEUE_NEW", s, rid=rid, sid=q.sid)]

    def _cmd_send(self, r, rng):
        s = r["cmd_seq"]
        q = self.queues.by_sender(r["sid"])
        if q is None:
            return [self._err(s, ERR_NOQUEUE)]
        if not self._sig_ok(q.send_pk, "SEND", r):
            return [self._err(s, ERR_AUTH)]
        cell_id, evicted = self.queues.append(q, r["cell"], self.now_bucket)
        return [response("OK_SEND", s, cell_id=cell_id, evicted_present=int(evicted is not None),
                         evicted_id=evicted or 0)]

    def _cmd_fetch(self, r, rng):
        s = r["cmd_seq"]
        q = self._status(r["rid"], r["ack"], r["sig"], "FETCH", s)
        if isinstance(q, int):                     # reading OPEN-7: the error frame, then F − 1 dummies
            return [self._cellr(s, q, r["rid"], 0, rng.take(sizes.CELL)), *self._dummies(s, F - 1, rng)]
        q.ack(r["ack"])
        q.last_fetch_bucket = self.now_bucket
        cells = list(q.cells)[:F]                  # the oldest F, ascending by cell_id; rid zero for FETCH
        out = [self._cellr(s, CELLR_CELL, ZERO_RID, c.cell_id, c.cell) for c in cells]
        return out + self._dummies(s, F - len(out), rng)

    def _cmd_fetch_multi(self, r, rng):
        s = r["cmd_seq"]
        errors, ok = [], {}
        for e in r["entries"]:
            q = self._status(e["rid"], e["ack"], e["sig"], "FETCH_MULTI", s)
            if isinstance(q, int):
                errors.append((q, e["rid"]))
            else:
                q.ack(e["ack"])
                q.last_fetch_bucket = self.now_bucket
                ok[e["rid"]] = q
        out = [self._cellr(s, p, rid, 0, rng.take(sizes.CELL)) for p, rid in errors[:F_M]]
        pool = sorted(((c.arrival, rid, c) for rid, q in ok.items() for c in q.cells), key=lambda t: t[0])
        out += [self._cellr(s, CELLR_CELL, rid, c.cell_id, c.cell) for _, rid, c in pool[:F_M - len(out)]]
        return out + self._dummies(s, F_M - len(out), rng)

    def _cmd_queue_del(self, r, rng):
        s = r["cmd_seq"]
        q = self.queues.get(r["rid"])
        if q is None:
            return [self._err(s, ERR_NOQUEUE)]     # reading OPEN-9
        if not self._sig_ok(q.recv_pk, "QUEUE_DEL", r):
            return [self._err(s, ERR_AUTH)]
        self.queues.delete(r["rid"])
        return [response("OK", s)]

    def _cmd_link_put(self, r, blob):
        s = r["cmd_seq"]
        if not self._token_ok(r):
            return [self._err(s, ERR_TOKEN)]
        if not self._sig_ok(r["owner_pk"], "LINK_PUT", {**r, "blob": blob}):
            return [self._err(s, ERR_AUTH)]       # reading OPEN-9
        if not self.now_bucket <= r["expires_bucket"] <= self.now_bucket + LINKDATA_TTL_BUCKETS:
            return [self._err(s, ERR_MALFORMED)]  # ADR-048 (o): now_bucket ≤ expires_bucket ≤ now_bucket + 720
        if r["ld_id"] in self.linkdata.entries:
            return [self._err(s, ERR_EXISTS)]     # also on a consumption marker (proposal)
        self.linkdata.entries[r["ld_id"]] = LinkData(r["one_time"], r["expires_bucket"], r["owner_pk"], blob)
        return [response("OK", s)]

    def _cmd_link_get(self, r, rng):
        s = r["cmd_seq"]
        e = self.linkdata.entries.get(r["ld_id"])
        if r["mode"] == "consume":
            if e is not None and not e.consumed:   # reading OPEN-11: present 1, consumed 0
                blob = e.blob
                if e.one_time:
                    e.blob = None                  # §9.4: deleted atomically; the marker stays
                return self._linkr(s, 1, 0, blob)
            return self._linkr(s, 0, int(e is not None), rng.take(sizes.LINK_BLOB))
        dummy = rng.take(sizes.LINK_BLOB)
        if e is None or not self._sig_ok(e.owner_pk, "LINK_GET", r):
            return self._linkr(s, 0, 0, dummy)     # reading OPEN-10
        return self._linkr(s, int(not e.consumed), int(e.consumed), dummy)

    def _cmd_ping(self, r, rng):
        return [response("OK", r["cmd_seq"])]


# ---------------------------------------------------------------------------------------------
# The client's side of a round trip


def receive(client: link.Link, frames, context: str) -> tuple[list[bytes], list[dict]]:
    """C opens and decodes the response frames to a request of kind `context` (a CELLR with its request
    as context); → (payloads, values). Each frame echoes one request's cmd_seq."""
    payloads = [client.open(f) for f in frames]
    return payloads, [decode_response(p, context) for p in payloads]
