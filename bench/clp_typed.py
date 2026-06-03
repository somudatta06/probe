"""Experiment: typed binary variable encoding vs the current gzip-columns store.

CLP's headline ratio comes from encoding variables by TYPE — integers as compact
binary (here: per-logtype-slot zig-zag delta varints) rather than ASCII text that a
generic compressor must re-discover. This measures whether that actually beats the
current store, head-to-head, on synthetic AND real LogHub logs, and proves the
typed form round-trips byte-for-byte.

Run: PYTHONPATH=. python3 -m bench.clp_typed
"""
import os
import re
import csv
import gzip
from collections import Counter, defaultdict

from probe import engine, clp, gen

csv.field_size_limit(10_000_000)
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_INT = re.compile(r"^\d+$")
SYSTEMS = ["Apache", "BGL", "HDFS", "HPC", "Hadoop", "HealthApp", "Linux", "Mac",
           "OpenSSH", "OpenStack", "Proxifier", "Spark", "Thunderbird", "Zookeeper"]


def _intable(s):
    return bool(_INT.match(s)) and str(int(s)) == s          # no leading zeros / signs


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


def _gz(data):
    return len(gzip.compress(data if isinstance(data, bytes) else data.encode("utf-8"), 9))


def measure(lines):
    enc = [clp.encode(ln) for ln in lines]
    lt_ids, logtypes, id_col, ts_col = {}, [], [], []
    for ts, lt, _ in enc:
        if lt not in lt_ids:
            lt_ids[lt] = len(logtypes)
            logtypes.append(lt)
        id_col.append(lt_ids[lt])
        ts_col.append(ts)

    nslots = [lt.count(clp.SENT) for lt in logtypes]
    slotvals = {i: [[] for _ in range(nslots[i])] for i in range(len(logtypes))}
    for (_, lt, vars), lid in zip(enc, id_col):
        for j, v in enumerate(vars):
            slotvals[lid][j].append(v)

    # --- typed encoding: int slots -> delta-varint binary; string slots -> text
    slot_is_int, int_blob, str_parts = {}, bytearray(), []
    for lid in range(len(logtypes)):
        for j in range(nslots[lid]):
            vals = slotvals[lid][j]
            is_int = len(vals) > 0 and all(_intable(v) for v in vals)
            slot_is_int[(lid, j)] = is_int
            if is_int:
                prev = 0
                for v in vals:
                    iv = int(v)
                    int_blob += _uvarint(_zz(iv - prev))
                    prev = iv
            else:
                str_parts.append("\n".join(vals))

    ts_text = "\n".join(ts_col)
    lt_text = "\n".join(logtypes)
    id_blob = b"".join(_uvarint(i) for i in id_col)
    typed = _gz(ts_text) + _gz(lt_text) + _gz(id_blob) + _gz("\x02".join(str_parts)) + _gz(bytes(int_blob))

    # --- current store: columnar TEXT (ts / ids / vars), one gzip stream + logtype dict
    var_text = "\n".join("\x01".join(v) for (_, _, v) in enc)
    cur_payload = ts_text + "\x02" + "\n".join(str(i) for i in id_col) + "\x02" + var_text
    current = _gz(cur_payload) + _gz(lt_text)

    # --- prove the typed binary form round-trips byte-for-byte
    counts = Counter(id_col)
    bi, intvals = 0, {}
    for lid in range(len(logtypes)):
        for j in range(nslots[lid]):
            if slot_is_int[(lid, j)]:
                vals, prev = [], 0
                for _ in range(counts[lid]):
                    z, bi = _read_uvarint(int_blob, bi)
                    prev += _unzz(z)
                    vals.append(str(prev))
                intvals[(lid, j)] = vals
    cur = defaultdict(int)
    recon = []
    for (ts, _, _), lid in zip(enc, id_col):
        rebuilt = []
        for j in range(nslots[lid]):
            col = intvals[(lid, j)] if slot_is_int[(lid, j)] else slotvals[lid][j]
            rebuilt.append(col[cur[(lid, j)]])
            cur[(lid, j)] += 1
        recon.append(clp.decode(ts, logtypes[lid], rebuilt))

    raw = sum(len(ln) + 1 for ln in lines)
    return {"n": len(lines), "raw": raw, "gzip": _gz("\n".join(lines)),
            "current": current, "typed": typed, "lossless": recon == lines,
            "logtypes": len(logtypes)}


def _load_real():
    lines = []
    for s in SYSTEMS:
        p = os.path.join(_REPO, ".bench", "vendor", "loghub", s, "%s_2k.log_structured.csv" % s)
        try:
            with open(p, newline="") as f:
                for row in csv.DictReader(f):
                    lines.append(row.get("Content", "") or "")
        except FileNotFoundError:
            pass
    return lines


def _row(name, m):
    print("  %-22s n=%-7d raw %6.0f KB | gzip %5.0f KB (%5.1fx) | current %5.0f KB (%5.1fx) | typed %5.0f KB (%5.1fx)  lossless=%s"
          % (name, m["n"], m["raw"] / 1024, m["gzip"] / 1024, m["raw"] / m["gzip"],
             m["current"] / 1024, m["raw"] / m["current"], m["typed"] / 1024, m["raw"] / m["typed"], m["lossless"]))


def main():
    log = os.path.join(os.path.dirname(_REPO), "clp_typed_syn.log")
    gen.generate(100000, log, kind="db_pool")
    syn = open(log).read().split("\n")
    if syn and syn[-1] == "":
        syn.pop()
    real = _load_real()

    print("=" * 120)
    print("  typed binary variable encoding vs current gzip-columns store")
    print("=" * 120)
    _row("synthetic (db_pool)", measure(syn))
    if real:
        _row("real LogHub (14 systems)", measure(real))
    print("-" * 120)
    print("  typed = int variable slots as zig-zag delta varints (binary) + string slots/ts/logtypes gzipped.")
    print("  The honest ceiling on this data is set by its entropy; CLP's ~169x is on high-cardinality")
    print("  production logs. Promote typed encoding into the store iff the 'typed' column wins here.")


if __name__ == "__main__":
    main()
