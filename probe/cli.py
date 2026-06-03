"""probe CLI.

  probe build  <file> [--budget N]     build a capsule + capture from a log file
  probe wrap   -- <cmd...>              run a command, capsule its stdout+stderr
  probe capsule <capture_id>           print the capsule
  probe search  <capture_id> [--query Q|--level L|--template T] [--limit N] [--cursor C]
  probe context <capture_id> <line> [--before N] [--after N]
  probe trace   <capture_id> <trace_id>
  probe verify  <capture_id> <fact_id>
  probe gen    <file> [--lines N]      write a synthetic incident log
  probe selftest                       run the invariant suite + a demo
  probe mcp                            run the stdio MCP server
"""
import os
import sys
import json
import time
import tempfile
import subprocess

from . import engine, gen, changes


def _flags(args):
    out, pos = {}, []
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("--"):
            out[a[2:]] = args[i + 1] if i + 1 < len(args) else True
            i += 2
        else:
            pos.append(a)
            i += 1
    return pos, out


def _p(obj):
    print(json.dumps(obj, indent=2))


def cmd_build(pos, fl):
    raw = open(pos[0], "rb").read()
    ce = changes.git_changes(fl["repo"]) if fl.get("repo") else None
    cap, h = engine.build(raw, budget_tokens=int(fl.get("budget", 2000)), change_events=ce)
    _p(cap)
    print("\ncapture_id: %s   (drill down: probe search %s --query ...)" % (h, h), file=sys.stderr)


def cmd_multi(pos, fl):
    sources = []
    for spec in pos:
        if "=" in spec:
            svc, path = spec.split("=", 1)
            sources.append((svc, open(path, "rb").read()))
    ce = changes.git_changes(fl["repo"]) if fl.get("repo") else None
    cap, h = engine.build_multi(sources, budget_tokens=int(fl.get("budget", 2000)), change_events=ce)
    _p(cap)
    print("\ncapture_id: %s   services=%s" % (h, cap["window"]["services"]), file=sys.stderr)


def cmd_multitest(pos, fl):
    d = os.path.join(tempfile.gettempdir(), "probe_multi")
    srcs = gen.generate_multi(40000, d, kind="db_pool")
    sources = [(svc, open(p, "rb").read()) for svc, p in srcs]
    repo = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".bench", "vendor", "codag-drain")
    ce = changes.git_changes(repo, since="20 years ago", max_n=3)
    cap, h = engine.build_multi(sources, budget_tokens=1500, change_events=ce)
    ld = engine.Loader(h)
    tr = ld.trace("abc124")
    svcs = sorted({x["service"] for x in tr["lines"] if x.get("service")})
    cause = any("psycopg2" in x["text"] for x in tr["lines"])
    symptom = any("upstream timeout" in x["text"] for x in tr["lines"])
    git_evs = [c for c in cap["changes"] if c.get("source") == "git"]
    print("=" * 64)
    print("  probe cross-service + change-provider test")
    print("=" * 64)
    print("  capsule services .......... %s" % cap["window"]["services"])
    print("  trace abc124 .............. %d lines spanning services %s" % (tr["count"], svcs))
    print("  root cause in trace ....... %s  (psycopg2, from db)" % cause)
    print("  symptom in trace .......... %s  (upstream timeout, from api)" % symptom)
    print("  git change events attached  %d  e.g. %r" % (len(git_evs), (git_evs[0]["text"][:46] if git_evs else "-")))
    xstitch = cap["window"]["services"] == ["api", "db"] and len(svcs) >= 2 and cause and symptom
    print("-" * 64)
    print("  CROSS-SERVICE STITCH: %s" % ("PASS" if xstitch else "FAIL"))
    print("  CHANGE PROVIDER (git): %s" % ("PASS" if git_evs else "FAIL"))
    sys.exit(0 if (xstitch and git_evs) else 1)


def cmd_wrap(pos, fl):
    if "--" in pos:
        pos = pos[pos.index("--") + 1:]
    elif "--" in sys.argv:
        pos = sys.argv[sys.argv.index("--") + 1:]
    proc = subprocess.run(pos, capture_output=True, text=True)
    raw = (proc.stdout + proc.stderr).encode("utf-8", "replace")
    cap, h = engine.build(raw, budget_tokens=int(fl.get("budget", 2000)))
    _p(cap)
    print("\ncapture_id: %s" % h, file=sys.stderr)


def cmd_capsule(pos, fl):
    _p(engine.Loader(pos[0]).capsule_view())


def cmd_search(pos, fl):
    ld = engine.Loader(pos[0])
    _p(ld.search(query=fl.get("query"), level=fl.get("level"),
                 template_id=fl.get("template"), limit=int(fl.get("limit", 50)),
                 cursor=int(fl.get("cursor", 0))))


def cmd_context(pos, fl):
    _p(engine.Loader(pos[0]).context(int(pos[1]), int(fl.get("before", 5)), int(fl.get("after", 5))))


def cmd_trace(pos, fl):
    _p(engine.Loader(pos[0]).trace(pos[1]))


def cmd_verify(pos, fl):
    _p(engine.Loader(pos[0]).verify(pos[1]))


def cmd_gen(pos, fl):
    n = gen.generate(int(fl.get("lines", 100000)), pos[0])
    print("wrote %d lines -> %s" % (n, pos[0]))


def cmd_selftest(pos, fl):
    n = int(fl.get("lines", 100000))
    budget = int(fl.get("budget", 2000))
    log = os.path.join(tempfile.gettempdir(), "probe_selftest.log")
    gen.generate(n, log)
    raw = open(log, "rb").read()

    t0 = time.time()
    cap, h = engine.build(raw, budget_tokens=budget)
    build_ms = (time.time() - t0) * 1000
    ld = engine.Loader(h)
    cs = json.dumps(cap)

    # rebuild for determinism check
    cap2, h2 = engine.build(raw, budget_tokens=budget)

    sum_count = sum(c["count"] for c in ld.meta["clusters"])
    cover = sum(r[1] - r[0] + 1 for r in ld.meta["records"])
    psy = next((f for f in cap["evidence"] if "psycopg2" in f["example"]), None)

    checks = []

    def chk(name, ok, detail=""):
        checks.append((name, ok, detail))

    chk("conservation", sum_count == cap["window"]["records"] and cover == cap["window"]["lines"],
        "Sigma(cluster counts)=%d records=%d ; covered lines=%d total=%d"
        % (sum_count, cap["window"]["records"], cover, cap["window"]["lines"]))
    chk("determinism", h == h2 and cap == cap2, "same bytes -> identical capsule + capture id")
    chk("redaction_boundary", gen.SECRET_MARK not in cs and gen.SECRET_MARK.encode() in raw,
        "secret present in raw, absent from capsule")
    chk("never_lose_signal", all(g in cs for g in gen.GOLD),
        "gold substrings in capsule: " + ", ".join(g for g in gen.GOLD if g in cs))
    chk("multiline_atomic", bool(psy) and "\n" in psy["example"],
        "psycopg2 fact keeps its traceback as one atomic span")
    chk("baseline_shift", any("went_silent" in f["flags"] for f in cap["evidence"]),
        "silent heartbeat surfaced")
    sound = ld.verify(psy["fact_id"]) if psy else {"matches": False}
    chk("soundness", bool(psy) and sound["matches"],
        "verify(%s) recomputes count from raw and matches capsule" % (psy["fact_id"] if psy else "?"))
    orig = raw.decode("utf-8", "replace").split("\n")
    if orig and orig[-1] == "":
        orig.pop()
    chk("clp_lossless", ld.all_lines() == orig,
        "decode(CLP store) == raw, byte-for-byte (%d lines)" % len(orig))
    chk("bounded", cap["stats"]["capsule_tokens"] <= budget * 1.5,
        "capsule_tokens=%d budget=%d" % (cap["stats"]["capsule_tokens"], budget))

    print("=" * 64)
    print("  probe selftest  (%s lines, budget %d tokens)" % (f"{n:,}", budget))
    print("=" * 64)
    for name, ok, detail in checks:
        print("  [%s] %-18s %s" % ("PASS" if ok else "FAIL", name, detail))
    allok = all(ok for _, ok, _ in checks)
    st = cap["stats"]
    print("-" * 64)
    print("  input lines ........ %s" % f"{st['input_lines']:,}")
    print("  logical records .... %s  (multiline grouped)" % f"{st['records']:,}")
    print("  templates .......... %d" % st["templates"])
    print("  capsule tokens ..... ~%d" % st["capsule_tokens"])
    print("  compression ........ %sx (lines/token)" % st["compression_x"])
    import gzip as _gz
    store_b = os.path.getsize(os.path.join(ld.dir, "store.clp")) + len(json.dumps(ld.meta["logtypes"]).encode())
    gz_b = len(_gz.compress(raw, 6))
    print("  CLP store .......... %.0f KB lossless+seekable (%.1fx) vs whole-file gzip %.0f KB (%.1fx)"
          % (store_b / 1024, len(raw) / store_b, gz_b / 1024, len(raw) / gz_b))
    print("  build time ......... %.0f ms  (no model, no GPU, 1 core)" % build_ms)
    print("  capsule cost @ Sonnet in($3/M) .. $%.5f  vs raw ~$%.2f"
          % (st["capsule_tokens"] / 1e6 * 3, st["input_lines"] * 6 / 1e6 * 3))
    print("-" * 64)
    if cap["hypotheses"]:
        print("  hypothesis (labeled, not asserted):")
        print("    -> %s  [%s]" % (cap["hypotheses"][0]["candidate"], cap["hypotheses"][0]["confidence"]))
    tr = ld.trace("abc124")
    print("  drill-down  trace(abc124) -> %d correlated lines across the cascade" % tr["count"])
    print("=" * 64)
    print("  RESULT: %s" % ("ALL INVARIANTS PASS" if allok else "FAILURES ABOVE"))
    print("=" * 64)
    sys.exit(0 if allok else 1)


def cmd_mcp(pos, fl):
    from . import mcp_server
    mcp_server.serve()


_CMDS = {
    "build": cmd_build, "wrap": cmd_wrap, "capsule": cmd_capsule, "search": cmd_search,
    "context": cmd_context, "trace": cmd_trace, "verify": cmd_verify, "gen": cmd_gen,
    "multi": cmd_multi, "multitest": cmd_multitest, "selftest": cmd_selftest, "mcp": cmd_mcp,
}


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return
    cmd = argv[0]
    if cmd not in _CMDS:
        print("unknown command: %s\n%s" % (cmd, __doc__))
        sys.exit(2)
    pos, fl = _flags(argv[1:])
    _CMDS[cmd](pos, fl)


if __name__ == "__main__":
    main()
