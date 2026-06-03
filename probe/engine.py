"""The single-pass incident-evidence engine.

build()        : one deterministic pass over a single log stream -> capsule + capture.
build_multi()  : merge several services' streams by timestamp -> cross-service capsule;
                 templates and trace ids span services.

Emits:
  - capsule.json : ranked first-page evidence (facts, not verdicts)
  - an immutable, content-addressed capture (raw.gz + index) for drill-down

Invariants (see cli.selftest): conservation, soundness, determinism,
redaction-at-boundary, never-lose-a-signal, bounded. No model, no network, no GPU.
"""
import os
import re
import json
import math
import hashlib
import bisect
from collections import defaultdict

from . import redact as _redact
from . import clp as _clp

# ----------------------------------------------------------------------------- masking / parsing
_MASKS = [
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "<ip>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<hex>"),
    (re.compile(r"\b[0-9a-fA-F]{12,}\b"), "<hex>"),
    (re.compile(r"\b\d+\b"), "<num>"),
]
# A line CONTINUES the previous record (vs starting a new one) only if it looks
# like a continuation: indented, or a stack-trace marker. Format-agnostic — works
# on HDFS/syslog/OpenStack/JSON, not just ISO-8601 — while keeping traces atomic.
_CONT = re.compile(r'^(?:\s|at |Caused by|\.\.\.|Traceback|File ")')
_LEVEL = re.compile(r"\b(FATAL|ERROR|WARNING|WARN|INFO|DEBUG|TRACE)\b")
_TRACE = re.compile(r"\b(?:id|trace|trace_id|request_id|req)=([A-Za-z0-9_\-]+)")
_CHANGE = re.compile(r"(?i)\b(deploy|deployed|released|rollout|config[ _]?(?:change|update)|version=)\b")
_SEV = {"FATAL": 1.0, "ERROR": 0.8, "WARNING": 0.4, "WARN": 0.4, "INFO": 0.1, "DEBUG": 0.0, "TRACE": 0.0}

DEFAULT_WEIGHTS = {"anomaly": 0.40, "severity": 0.25, "proximity": 0.20, "rarity": 0.10, "causal": 0.05}


def mask(s):
    for pat, rep in _MASKS:
        s = pat.sub(rep, s)
    return s


def render(tokens):
    return " ".join(tokens)


def _cache_dir():
    return os.environ.get("PROBE_CACHE", os.path.expanduser("~/.probe-cache"))


# ----------------------------------------------------------------------------- multiline records
def to_records(raw_lines, service=""):
    """Group physical lines into logical records (start line + its continuation
    lines: stack traces, etc.). Tags each record with its service. Never drops a line."""
    records = []
    for ln, text in enumerate(raw_lines):
        if records and _CONT.match(text):
            r = records[-1]
            r["end"] = ln
            r["lines"].append(text)
        else:
            records.append({"start": ln, "end": ln, "lines": [text]})
    for r in records:
        joined = "\n".join(r["lines"])
        first = r["lines"][0]
        body = _clp.TS_PREFIX.sub("", first)
        m = _LEVEL.search(joined)
        r["level"] = m.group(1) if m else "INFO"
        r["sev"] = _SEV.get(r["level"], 0.2)
        r["traces"] = list(dict.fromkeys(_TRACE.findall(joined)))
        r["raw"] = joined
        r["ts"] = first[: len(first) - len(body)].strip()
        r["key"] = mask(body).split()
        r["service"] = service
    return records


# ----------------------------------------------------------------------------- Drain templating
class Drain:
    def __init__(self, sim_th=0.4):
        self.sim_th = sim_th
        self.clusters = []
        # Fixed-depth route: (token_count, tok0, tok1). Routing on the first two
        # literal tokens stops wildcard-inflated similarity from over-merging
        # distinct templates (e.g. "heartbeat" being absorbed into "cache").
        self.tree = defaultdict(list)

    @staticmethod
    def _sim(a, b):
        if not a:
            return 1.0
        same = sum(1 for x, y in zip(a, b) if x == y or x == "<*>" or y == "<*>")
        return same / len(a)

    def add(self, rec, idx):
        toks = rec["key"] or [""]
        bucket = self.tree[(len(toks), toks[0], toks[1] if len(toks) > 1 else "")]
        best, best_s = None, -1.0
        for cid in bucket:
            s = self._sim(self.clusters[cid]["tok"], toks)
            if s > best_s:
                best_s, best = s, cid
        if best is not None and best_s >= self.sim_th:
            c = self.clusters[best]
            c["tok"] = [x if x == y else "<*>" for x, y in zip(c["tok"], toks)]
            c["count"] += 1
            c["recs"].append(idx)
            c["traces"].update(rec["traces"])
            c["services"].add(rec.get("service", ""))
            if rec["sev"] > c["sev"]:
                c["sev"], c["level"], c["example"], c["ex_rec"] = rec["sev"], rec["level"], rec["raw"], idx
            return best
        cid = len(self.clusters)
        self.clusters.append({
            "id": cid, "tok": list(toks), "count": 1, "recs": [idx],
            "traces": set(rec["traces"]), "services": {rec.get("service", "")},
            "level": rec["level"], "sev": rec["sev"],
            "example": rec["raw"], "ex_rec": idx, "first": idx,
        })
        bucket.append(cid)
        return cid


# ----------------------------------------------------------------------------- scoring + selection
def _score(clusters, anchor, n_rec, weights):
    err_traces = set()
    for c in clusters:
        if c["sev"] >= 0.8:
            err_traces |= c["traces"]
    tau, eps = max(1.0, 0.1 * n_rec), 1e-6
    for c in clusters:
        pre = sum(1 for i in c["recs"] if i < anchor)
        c["pre"], c["post"] = pre, c["count"] - pre
        c["first_rec"], c["last_rec"] = c["recs"][0], c["recs"][-1]
        if c["pre"] == 0 and c["post"] > 0:
            a = 1.0                                   # new after incident
        elif c["post"] == 0 and c["pre"] >= 2:
            a = 1.0                                   # recurring template went silent
        elif c["post"] == 0:
            a = 0.0                                   # lone early line: not a signal
        else:
            rp, rq = c["pre"] / max(1, anchor), c["post"] / max(1, n_rec - anchor)
            a = min(1.0, abs(math.log((rq + eps) / (rp + eps))) / 3.0)
        c["anomaly"] = a
        c["prox"] = math.exp(-abs(c["first_rec"] - anchor) / tau)
        c["rarity"] = min(1.0, (-math.log10(c["count"] / max(1, n_rec))) / 4.0)
        c["causal"] = 1.0 if (c["traces"] & err_traces) else 0.0
        c["score"] = (weights["anomaly"] * a + weights["severity"] * c["sev"]
                      + weights["proximity"] * c["prox"] + weights["rarity"] * c["rarity"]
                      + weights["causal"] * c["causal"])


def _fact(c, records, anchor):
    ex = _redact.redact(c["example"])[:600]
    r = records[c["ex_rec"]]
    svcs = sorted(s for s in c.get("services", set()) if s)
    flags = []
    if c["pre"] == 0 and c["post"] > 0:
        flags.append("new_after_incident")
    # "went silent" = an established baseline (recurred well before the incident)
    # that stopped. A short burst just before the anchor is a trigger, not silence.
    if c["post"] == 0 and c["pre"] >= 2 and c["first_rec"] < anchor * 0.5:
        flags.append("went_silent")
    if c["sev"] >= 0.8:
        flags.append("error")
    if c["prox"] >= 0.6:
        flags.append("near_incident")
    if c["causal"] > 0:
        flags.append("shares_error_trace")
    if len(svcs) > 1:
        flags.append("cross_service")
    if "\n" in c["example"]:
        flags.append("multiline")
    return {
        "fact_id": "F%d" % c["id"], "template": _redact.redact(render(c["tok"])), "example": ex,
        "template_id": c["id"], "count": c["count"], "pre": c["pre"], "post": c["post"],
        "anomaly": round(c["anomaly"], 3), "severity": c["sev"], "score": round(c["score"], 3),
        "first_line": records[c["first_rec"]]["start"] + 1,
        "last_line": records[c["last_rec"]]["start"] + 1,
        "span": [r["start"] + 1, r["end"] + 1], "level": c["level"],
        "services": svcs, "traces": sorted(c["traces"])[:5], "flags": flags,
    }


def _select(clusters, records, budget, anchor):
    chosen, used, tok = [], set(), 0

    def take(c):
        nonlocal tok
        if c["id"] in used:
            return
        f = _fact(c, records, anchor)
        used.add(c["id"])
        chosen.append(f)
        tok += max(1, len(json.dumps(f)) // 4)

    # reserved quotas (the high-signal tail is never truncated away)
    for c in sorted([c for c in clusters if c["anomaly"] >= 0.999], key=lambda c: -c["score"])[:20]:
        take(c)                                   # all new / went-silent templates
    for c in [c for c in clusters if c["sev"] >= 0.8]:
        take(c)                                   # every error/fatal template
    for c in sorted(clusters, key=lambda c: -c["count"])[:3]:
        take(c)                                   # a routine baseline sample
    for c in sorted(clusters, key=lambda c: -c["score"]):
        if tok >= budget:
            break
        take(c)                                   # fill remaining budget greedily
    chosen.sort(key=lambda f: (-f["score"], f["template_id"]))
    return chosen, tok


# ----------------------------------------------------------------------------- finalize (shared)
def _finalize(records, clusters, facts, tok, anchor, n_lines, n_rec,
              raw_bytes, h, cache_dir, services, budget_tokens, change_events):
    changes = []
    for r in records:
        if _CHANGE.search(r["raw"]):
            ch = {"line": r["start"] + 1, "text": _redact.redact(r["raw"])[:200]}
            if r.get("service"):
                ch["service"] = r["service"]
            changes.append(ch)
    if change_events:
        changes.extend(change_events)
    changes = changes[:12]

    hyps = []
    errf = sorted([f for f in facts if "error" in f["flags"]], key=lambda f: -f["score"])
    silent = [f for f in facts if "went_silent" in f["flags"]]
    if errf:
        top = errf[0]
        rests, note = [top["fact_id"]], []
        if changes:
            note.append("a change at %s" % ("line %d" % changes[0]["line"] if "line" in changes[0] else changes[0].get("source", "external")))
        if silent:
            note.append("%r went silent" % silent[0]["template"])
            rests.append(silent[0]["fact_id"])
        if len(top.get("services", [])) > 1:
            note.append("spanning services %s" % ", ".join(top["services"]))
        hyps.append({
            "candidate": "%s emerged near line %d%s" % (
                top["template"], top["first_line"],
                (" correlated with " + ", ".join(note)) if note else ""),
            "confidence": "medium" if note else "low",
            "rests_on": rests,
            "note": "candidate for the agent to verify against raw evidence, not an assertion",
        })

    capsule = {
        "schema": "probe.capsule/v0",
        "window": {"lines": n_lines, "records": n_rec,
                   "first_ts": records[0]["ts"] if records else "",
                   "last_ts": records[-1]["ts"] if records else "",
                   "services": services},
        "budget_tokens": budget_tokens,
        "evidence": facts,
        "routine": [{"template": _redact.redact(render(c["tok"])), "count": c["count"]}
                    for c in sorted(clusters, key=lambda c: -c["count"])[:3]],
        "changes": changes,
        "hypotheses": hyps,
        "index": {"capture_id": h, "tools": ["capsule", "search", "context", "trace", "verify"]},
        "stats": {"templates": len(clusters), "input_lines": n_lines, "records": n_rec,
                  "capsule_tokens": tok, "compression_x": round(n_lines / max(1, tok), 1)},
    }

    traces_index = defaultdict(list)
    for i, r in enumerate(records):
        for t in r["traces"]:
            traces_index[t].append(i)

    _write_capture(cache_dir, h, raw_bytes, records, clusters, traces_index, capsule)
    return capsule, h


# ----------------------------------------------------------------------------- build (single + multi)
def build(raw_bytes, budget_tokens=2000, weights=None, cache_dir=None, change_events=None):
    weights = weights or DEFAULT_WEIGHTS
    cache_dir = cache_dir or _cache_dir()
    h = hashlib.sha256(raw_bytes).hexdigest()[:16]

    raw_lines = raw_bytes.decode("utf-8", "replace").split("\n")
    if raw_lines and raw_lines[-1] == "":
        raw_lines.pop()
    n_lines = len(raw_lines)

    records = to_records(raw_lines)
    n_rec = len(records)
    drain = Drain()
    for i, r in enumerate(records):
        r["cid"] = drain.add(r, i)
    clusters = drain.clusters

    err_idx = [i for i, r in enumerate(records) if r["sev"] >= 0.8]
    anchor = err_idx[0] if err_idx else int(0.85 * n_rec)
    _score(clusters, anchor, n_rec, weights)
    facts, tok = _select(clusters, records, budget_tokens, anchor)

    return _finalize(records, clusters, facts, tok, anchor, n_lines, n_rec,
                     raw_bytes, h, cache_dir, [], budget_tokens, change_events)


def build_multi(sources, budget_tokens=2000, weights=None, cache_dir=None, change_events=None):
    """sources: list of (service_name, raw_bytes). Merge streams by timestamp into
    one capture; templates + trace ids span services (distributed root cause)."""
    weights = weights or DEFAULT_WEIGHTS
    cache_dir = cache_dir or _cache_dir()

    recs = []
    for svc, raw in sources:
        lines = raw.decode("utf-8", "replace").split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        recs.extend(to_records(lines, svc))
    recs.sort(key=lambda r: (r["ts"], r["service"]))     # ISO ts sorts chronologically

    merged = []
    for r in recs:
        r["start"] = len(merged)
        merged.extend(r["lines"])
        r["end"] = len(merged) - 1
    n_lines, n_rec = len(merged), len(recs)

    drain = Drain()
    for i, r in enumerate(recs):
        r["cid"] = drain.add(r, i)
    clusters = drain.clusters

    err_idx = [i for i, r in enumerate(recs) if r["sev"] >= 0.8]
    anchor = err_idx[0] if err_idx else int(0.85 * n_rec)
    _score(clusters, anchor, n_rec, weights)
    facts, tok = _select(clusters, recs, budget_tokens, anchor)

    raw_bytes = ("\n".join(merged) + "\n").encode("utf-8")
    h = hashlib.sha256(raw_bytes).hexdigest()[:16]
    services = sorted({svc for svc, _ in sources})
    return _finalize(recs, clusters, facts, tok, anchor, n_lines, n_rec,
                     raw_bytes, h, cache_dir, services, budget_tokens, change_events)


def _write_capture(cache_dir, h, raw_bytes, records, clusters, traces_index, capsule):
    d = os.path.join(cache_dir, "captures", h)
    os.makedirs(d, exist_ok=True)

    # CLP-style lossless columnar store (replaces whole-file raw.gz): per record a
    # (logtype_id, vars) pair against a deduplicated logtype dictionary, in seekable
    # gzip blocks. Drill-down decodes only the blocks it touches.
    lt_id, logtypes, rows = {}, [], []
    for r in records:
        ts, lt, vrs = _clp.encode(r["raw"])
        if lt not in lt_id:
            lt_id[lt] = len(logtypes)
            logtypes.append(lt)
        rows.append((ts, lt_id[lt], vrs))
    blocks = _clp.write_store(os.path.join(d, "store.clp"), rows, logtypes)

    meta = {
        "n_lines": capsule["window"]["lines"],
        "records": [[r["start"] + 1, r["end"] + 1, r["cid"], r["level"], r.get("service", "")] for r in records],
        "clusters": [{"id": c["id"], "template": render(c["tok"]), "count": c["count"],
                      "level": c["level"], "recs": c["recs"]} for c in clusters],
        "traces": dict(traces_index),
        "logtypes": logtypes,
        "blocks": blocks,
    }
    with open(os.path.join(d, "meta.json"), "w") as f:
        json.dump(meta, f)
    with open(os.path.join(d, "capsule.json"), "w") as f:
        json.dump(capsule, f, indent=2)


# ----------------------------------------------------------------------------- read-only drill-down
class Loader:
    def __init__(self, capture_id, cache_dir=None):
        self.dir = os.path.join(cache_dir or _cache_dir(), "captures", capture_id)
        with open(os.path.join(self.dir, "meta.json")) as f:
            self.meta = json.load(f)
        with open(os.path.join(self.dir, "capsule.json")) as f:
            self.capsule = json.load(f)
        self.reader = _clp.Reader(os.path.join(self.dir, "store.clp"),
                                  self.meta["blocks"], self.meta["logtypes"])
        self._starts = [row[0] for row in self.meta["records"]]   # record start lines (ascending)

    @staticmethod
    def _rec(row):
        return row[0], row[1], row[2], row[3], (row[4] if len(row) > 4 else "")

    def capsule_view(self):
        return self.capsule

    def _lines(self, a, b):
        """Physical lines [a,b] (1-based, inclusive) as (line_no, text), decoding
        only the records that overlap the range (seekable: O(records touched))."""
        ri = max(0, bisect.bisect_right(self._starts, a) - 1)
        out, n = [], len(self.meta["records"])
        while ri < n and self.meta["records"][ri][0] <= b:
            s = self.meta["records"][ri][0]
            for k, line in enumerate(self.reader.record_text(ri).split("\n")):
                if a <= s + k <= b:
                    out.append((s + k, line))
            ri += 1
        return out

    def _text(self, s, e):
        return _redact.redact("\n".join(t for _, t in self._lines(s, e)))[:400]

    def all_lines(self):
        """Full lossless reconstruction from the CLP store (round-trip invariant)."""
        out = []
        for ridx in range(len(self.meta["records"])):
            out.extend(self.reader.record_text(ridx).split("\n"))
        return out

    def search(self, query=None, level=None, template_id=None, limit=50, cursor=0):
        hits = []
        for ridx, row in enumerate(self.meta["records"]):
            s, e, cid, lvl, svc = self._rec(row)
            if level and lvl.upper() != level.upper():
                continue
            if template_id is not None and cid != int(template_id):
                continue
            if query and query.lower() not in self.reader.record_text(ridx).lower():
                continue
            hits.append({"line": s, "level": lvl, "service": svc, "template_id": cid, "text": self._text(s, e)})
        page = hits[cursor:cursor + limit]
        nxt = cursor + limit if cursor + limit < len(hits) else None
        return {"total": len(hits), "cursor": cursor, "next_cursor": nxt, "results": page}

    def context(self, line, before=5, after=5):
        a, b = max(1, line - before), line + after
        ls = self._lines(a, b)
        return {"from": a, "to": (ls[-1][0] if ls else a),
                "lines": [{"line": g, "text": _redact.redact(t)[:400]} for g, t in ls]}

    def trace(self, trace_id):
        idxs = self.meta["traces"].get(trace_id, [])
        out = []
        for ridx in idxs[:200]:
            s, e, cid, lvl, svc = self._rec(self.meta["records"][ridx])
            out.append({"line": s, "level": lvl, "service": svc, "text": self._text(s, e)})
        return {"trace": trace_id, "count": len(idxs), "lines": out}

    def verify(self, fact_id):
        cid = int(str(fact_id).lstrip("F"))
        c = self.meta["clusters"][cid]
        cap = next((f for f in self.capsule["evidence"] if f["fact_id"] == fact_id), None)
        samples = []
        for ridx in c["recs"][:5]:
            s, e, _, _, _ = self._rec(self.meta["records"][ridx])
            samples.append({"line": s, "text": self._text(s, e)})
        recomputed = len(c["recs"])
        return {"fact_id": fact_id, "template": c["template"], "recomputed_count": recomputed,
                "capsule_count": (cap or {}).get("count"),
                "matches": (cap or {}).get("count") == recomputed, "samples": samples}
