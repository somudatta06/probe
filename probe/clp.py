"""CLP-style lossless, seekable, TYPED columnar log store.

Each record splits into a timestamp, a logtype (body with variables -> sentinel,
deduplicated into a dictionary), and variables. Within each gzip block, variables
are stored by TYPE per logtype-slot: integer slots as zig-zag delta varints
(binary) — which a generic compressor can't reproduce from ASCII digits — and
string slots / timestamps as text. Blocks carry an offset index, so a line lookup
decodes only the block(s) it touches (seekable retention).

Lossless: decode(store) == original, byte-for-byte (proven in cli.selftest +
bench.clp_typed). Integer typing is guarded by str(int(v)) == v, so leading zeros
or signs fall back to string slots.
"""
import re
import gzip
import bisect
from collections import Counter, defaultdict

SENT = "\x00"  # variable slot inside a logtype
BLOCK_RECS = 16384  # records per block: balances ratio (bigger = better) vs seek cost

# Leading-timestamp matcher, shared by the engine (templating) and the store
# (ts column). Covers the common real-world formats so timestamps don't leak into
# templates/variables as numeric noise. Anything unmatched -> ts="" (graceful).
TS_PREFIX = re.compile(
    r"^(?:"
    r"\[[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\]"      # [Mon Dec 04 04:47:44 2005]
    r"|\[\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\]]*\]"                             # [2024-01-02T03:04:05...]
    r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"    # ISO-8601 (T or space, .|, millis)
    r"|\d{6}\s+\d{6}\b"                                                             # 081109 203615 (HDFS/Spark/Zookeeper)
    r"|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"                                 # Jun  2 10:00:00 (syslog)
    r")\s*"
)
_VAR = re.compile(
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    r"|\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
    r"|\b0x[0-9a-fA-F]+\b"
    r"|\b[0-9a-fA-F]{12,}\b"
    r"|\b\d+\b"
)
_INT = re.compile(r"^\d+$")


def encode(text):
    """text -> (timestamp, logtype, [variables]). Reversible."""
    m = TS_PREFIX.match(text)
    ts, body = (text[:m.end()], text[m.end():]) if m else ("", text)
    if SENT in body:
        return ts, SENT, [body]
    vrs = []
    lt = _VAR.sub(lambda x: (vrs.append(x.group(0)) or SENT), body)
    return ts, lt, vrs


def decode(ts, logtype, vrs):
    """(timestamp, logtype, [variables]) -> text. Exact inverse of encode()."""
    parts = logtype.split(SENT)
    out = [parts[0]]
    for i, v in enumerate(vrs):
        out.append(v)
        out.append(parts[i + 1])
    return ts + "".join(out)


# ---------------------------------------------------------------- varint helpers
def _intable(s):
    return bool(_INT.match(s)) and str(int(s)) == s


def _uvarint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def _read_uvarint(buf, i):
    shift = res = 0
    while True:
        b = buf[i]
        i += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            return res, i
        shift += 7


def _zz(n):
    return (-n * 2 - 1) if n < 0 else (n * 2)


def _unzz(z):
    return -(z + 1) // 2 if (z & 1) else z // 2


def _frame(sections):
    out = bytearray()
    for s in sections:
        out += _uvarint(len(s))
        out += s
    return bytes(out)


def _unframe(buf):
    secs, i = [], 0
    while i < len(buf):
        n, i = _read_uvarint(buf, i)
        secs.append(buf[i:i + n])
        i += n
    return secs


# ---------------------------------------------------------------- typed block codec
def _encode_block(chunk, nslots):
    """chunk: list of (ts, logtype_id, [vars]) -> gzipped typed block bytes."""
    ts_text = "\n".join(r[0] for r in chunk)
    ids = [r[1] for r in chunk]
    slotvals = defaultdict(list)
    for _, lid, vrs in chunk:
        for j, v in enumerate(vrs):
            slotvals[(lid, j)].append(v)

    flags, int_blob, str_items = bytearray(), bytearray(), []
    for lid in sorted(set(ids)):                       # canonical order (matches decode)
        for j in range(nslots[lid]):
            vals = slotvals[(lid, j)]
            is_int = len(vals) > 0 and all(_intable(v) for v in vals)
            flags.append(1 if is_int else 0)
            if is_int:
                prev = 0
                for v in vals:
                    iv = int(v)
                    int_blob += _uvarint(_zz(iv - prev))
                    prev = iv
            else:
                str_items.extend(vals)

    ids_blob = b"".join(_uvarint(x) for x in ids)
    payload = _frame([ts_text.encode("utf-8"), ids_blob, bytes(flags),
                      "\n".join(str_items).encode("utf-8"), bytes(int_blob)])
    return gzip.compress(payload, 9, mtime=0)


def _decode_block(blob, logtypes, nslots):
    ts_b, ids_b, flags, str_b, int_b = _unframe(gzip.decompress(blob))
    ts = ts_b.decode("utf-8").split("\n")
    ids, i = [], 0
    while i < len(ids_b):
        x, i = _read_uvarint(ids_b, i)
        ids.append(x)
    counts = Counter(ids)
    str_items = str_b.decode("utf-8").split("\n") if len(str_b) else []

    slotvals, fi, bi, si = {}, 0, 0, 0
    for lid in sorted(set(ids)):
        c = counts[lid]
        for j in range(nslots[lid]):
            is_int = flags[fi]
            fi += 1
            if is_int:
                vals, prev = [], 0
                for _ in range(c):
                    z, bi = _read_uvarint(int_b, bi)
                    prev += _unzz(z)
                    vals.append(str(prev))
                slotvals[(lid, j)] = vals
            else:
                slotvals[(lid, j)] = str_items[si:si + c]
                si += c

    cur, out = defaultdict(int), []
    for k, lid in enumerate(ids):
        vrs = []
        for j in range(nslots[lid]):
            vrs.append(slotvals[(lid, j)][cur[(lid, j)]])
            cur[(lid, j)] += 1
        out.append(decode(ts[k], logtypes[lid], vrs))
    return out


def write_store(path, rows, logtypes, block_recs=BLOCK_RECS):
    """rows: list of (ts, logtype_id, [vars]). Writes typed gzip blocks; returns
    the index [[first_record, byte_offset, byte_len], ...]."""
    nslots = [lt.count(SENT) for lt in logtypes]
    blocks, off = [], 0
    with open(path, "wb") as f:
        i = 0
        while i < len(rows):
            blob = _encode_block(rows[i:i + block_recs], nslots)
            f.write(blob)
            blocks.append([i, off, len(blob)])
            off += len(blob)
            i += block_recs
    return blocks


class Reader:
    """Random access into the typed block store: O(one block) per lookup."""

    def __init__(self, path, blocks, logtypes):
        self.path = path
        self.blocks = blocks
        self.logtypes = logtypes
        self.nslots = [lt.count(SENT) for lt in logtypes]
        self._firsts = [b[0] for b in blocks]
        self._cache = {}  # block index -> (first_record, [record texts])

    def _ensure(self, bi):
        if bi in self._cache:
            return
        first, off, ln = self.blocks[bi]
        with open(self.path, "rb") as f:
            f.seek(off)
            blob = f.read(ln)
        self._cache[bi] = (first, _decode_block(blob, self.logtypes, self.nslots))

    def record_text(self, rec_idx):
        bi = bisect.bisect_right(self._firsts, rec_idx) - 1
        self._ensure(bi)
        first, texts = self._cache[bi]
        return texts[rec_idx - first]
