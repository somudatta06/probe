"""Minimal, dependency-free MCP server (stdio, newline-delimited JSON-RPC 2.0).

Exposes the capsule + read-only drill-down tools to an agent. The agent drives
retrieval: it reads the cheap capsule first, then expands / searches / verifies
against the local capture only as its hypothesis demands. No data leaves the box
beyond what the agent pulls (and that is redacted at this boundary).
"""
import os
import sys
import json

from . import engine

_TOOL_NAMES = ("capsule", "search", "context", "trace", "verify")


def _build_path(path):
    """Resolve + (optionally) confine the build path. Set PROBE_LOG_DIR to restrict
    which files an agent may ask the server to read (defense-in-depth for the MCP
    trust boundary); regular-file/size checks happen in cli._build_file."""
    rp = os.path.realpath(path)
    allowed = os.environ.get("PROBE_LOG_DIR")
    if allowed:
        ar = os.path.realpath(allowed)
        if rp != ar and not rp.startswith(ar + os.sep):
            raise ValueError("path outside PROBE_LOG_DIR: %s" % rp)
    return rp

TOOLS = [
    {"name": "build",
     "description": "Build an incident capsule from a log file path. Returns ranked evidence (facts, not verdicts) + a capture_id for drill-down.",
     "inputSchema": {"type": "object", "properties": {
         "path": {"type": "string"}, "budget_tokens": {"type": "integer"}}, "required": ["path"]}},
    {"name": "capsule",
     "description": "Return the capsule for a capture_id (the cheap first-page view).",
     "inputSchema": {"type": "object", "properties": {"capture_id": {"type": "string"}}, "required": ["capture_id"]}},
    {"name": "search",
     "description": "Search raw lines in a capture by substring/level/template_id. Bounded + paginated.",
     "inputSchema": {"type": "object", "properties": {
         "capture_id": {"type": "string"}, "query": {"type": "string"}, "level": {"type": "string"},
         "template_id": {"type": "integer"}, "limit": {"type": "integer"}, "cursor": {"type": "integer"}},
         "required": ["capture_id"]}},
    {"name": "context",
     "description": "Return raw lines surrounding a line number in a capture.",
     "inputSchema": {"type": "object", "properties": {
         "capture_id": {"type": "string"}, "line": {"type": "integer"},
         "before": {"type": "integer"}, "after": {"type": "integer"}}, "required": ["capture_id", "line"]}},
    {"name": "trace",
     "description": "Return every line sharing a trace/request id (cross-service when multi-stream).",
     "inputSchema": {"type": "object", "properties": {
         "capture_id": {"type": "string"}, "trace_id": {"type": "string"}}, "required": ["capture_id", "trace_id"]}},
    {"name": "verify",
     "description": "Re-derive a fact's count from raw evidence + return sample raw lines. Proves the capsule did not invent it.",
     "inputSchema": {"type": "object", "properties": {
         "capture_id": {"type": "string"}, "fact_id": {"type": "string"}}, "required": ["capture_id", "fact_id"]}},
]


_LOADERS = {}  # capture_id -> Loader; meta is loaded once per session, not per call


def _loader(cid):
    ld = _LOADERS.get(cid)
    if ld is None:
        if len(_LOADERS) >= 16:
            _LOADERS.pop(next(iter(_LOADERS)))   # evict oldest (capture_id is a content hash)
        ld = _LOADERS[cid] = engine.Loader(cid)
    return ld


def _call(name, a):
    if name == "build":
        from . import cli  # reuse the Rust-accelerated build path (Python fallback)
        cap, _h, _eng = cli._build_file(_build_path(a["path"]), int(a.get("budget_tokens", 2000)))
        return cap
    if name not in _TOOL_NAMES:
        raise ValueError("unknown tool: %s" % name)
    ld = _loader(a["capture_id"])
    if name == "capsule":
        return ld.capsule_view()
    if name == "search":
        return ld.search(query=a.get("query"), level=a.get("level"), template_id=a.get("template_id"),
                         limit=min(int(a.get("limit", 50)), 1000), cursor=int(a.get("cursor", 0)))
    if name == "context":
        return ld.context(int(a["line"]), min(int(a.get("before", 5)), 1000), min(int(a.get("after", 5)), 1000))
    if name == "trace":
        return ld.trace(a["trace_id"])
    return ld.verify(a["fact_id"])


def _send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def serve():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            _send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            continue
        mid, method = req.get("id"), req.get("method")
        if method == "initialize":
            _send({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "probe", "version": "0.0.1"},
                "capabilities": {"tools": {}}}})
        elif method == "tools/list":
            _send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            p = req.get("params", {}) or {}
            try:
                res = _call(p.get("name"), p.get("arguments") or {})
                _send({"jsonrpc": "2.0", "id": mid,
                       "result": {"content": [{"type": "text", "text": json.dumps(res)}]}})
            except Exception as e:  # never crash the agent's session
                _send({"jsonrpc": "2.0", "id": mid,
                       "result": {"content": [{"type": "text", "text": "error: %s" % e}], "isError": True}})
        elif mid is not None:  # request we don't handle
            _send({"jsonrpc": "2.0", "id": mid,
                   "error": {"code": -32601, "message": "method not found: %s" % method}})
        # notifications (no id) get no response


if __name__ == "__main__":
    serve()
