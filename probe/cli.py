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
import stat as _stat
import shutil
import tempfile
import subprocess

from . import engine, gen, changes, redact


def _safe_to_read(path):
    """Reject non-regular files (devices/FIFOs hang on read) and oversized files."""
    st = os.stat(path)  # FileNotFoundError if missing
    if not _stat.S_ISREG(st.st_mode):
        raise ValueError("refusing to read non-regular file (device/fifo/dir): %s" % path)
    if st.st_size > 2 * 1024 ** 3:
        raise ValueError("file too large (%d bytes, cap 2 GiB): %s" % (st.st_size, path))


def _rust_bin():
    """The probe-rs accelerator, if available (PROBE_RS_BIN or on PATH)."""
    p = os.environ.get("PROBE_RS_BIN") or shutil.which("probe-rs")
    return p if p and os.path.exists(p) else None


def _build_file(path, budget, change_events=None, engine_choice="auto"):
    """Build a capture from a file, using the Rust engine when available (and no
    change-event injection is needed), else the Python engine. Returns (capsule, id, engine)."""
    _safe_to_read(path)
    rb = _rust_bin()
    want_rust = engine_choice == "rust" or (engine_choice == "auto" and rb and not change_events)
    if engine_choice == "rust" and not rb:
        print("probe: --engine rust requested but probe-rs not found; using python", file=sys.stderr)
        want_rust = False
    if want_rust and rb:
        r = subprocess.run([rb, "build", path, "--cache", engine._cache_dir(), "--budget", str(budget)],
                           capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            try:
                cap = json.loads(r.stdout)
                return cap, cap["index"]["capture_id"], "rust"
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                print("probe: rust output invalid (%s), using python" % e, file=sys.stderr)
        else:
            print("probe: rust engine failed, using python:\n%s" % (r.stderr or "")[:200], file=sys.stderr)
    raw = open(path, "rb").read()
    cap, h = engine.build(raw, budget_tokens=budget, change_events=change_events)
    return cap, h, "python"


def _flags(args):
    out, pos = {}, []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":                                  # everything after -- is positional
            pos.extend(args[i + 1:])
            break
        if a.startswith("--"):
            if i + 1 < len(args) and not args[i + 1].startswith("--"):
                out[a[2:]] = args[i + 1]
                i += 2
            else:
                out[a[2:]] = True                      # bare flag, don't steal the next token
                i += 1
        else:
            pos.append(a)
            i += 1
    return pos, out


def _p(obj):
    print(json.dumps(obj, indent=2))


def cmd_build(pos, fl):
    ce = changes.git_changes(fl["repo"]) if fl.get("repo") else None
    cap, h, eng = _build_file(pos[0], int(fl.get("budget", 2000)), ce, fl.get("engine", "auto"))
    _p(cap)
    print("\ncapture_id: %s   engine: %s   (drill down: probe search %s --query ...)"
          % (h, eng, h), file=sys.stderr)


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
    cmdv = pos  # _flags() puts everything after `--` into pos
    if not cmdv:
        print("usage: probe wrap -- <command...>", file=sys.stderr)
        sys.exit(2)
    proc = subprocess.run(cmdv, capture_output=True, text=True)
    # mkstemp: unpredictable name, O_EXCL|O_CREAT, mode 0600 — no symlink/TOCTOU race in
    # the shared temp dir, and the wrapped output (may contain secrets) isn't world-readable.
    fd, tmp = tempfile.mkstemp(prefix="probe_wrap_", suffix=".log")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(proc.stdout + proc.stderr)
        cap, h, eng = _build_file(tmp, int(fl.get("budget", 2000)), None, fl.get("engine", "auto"))
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    _p(cap)
    print("\ncapture_id: %s   engine: %s" % (h, eng), file=sys.stderr)


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


def cmd_savings(pos, fl):
    s = engine.savings_summary(price_per_mtok=fl.get("price"))
    _p(s)
    print("\nprobe has saved an estimated $%.2f across %d captures, by sending short summaries "
          "instead of the raw logs\n(assumes a model at $%g per million tokens; set --price or "
          "PROBE_PRICE_PER_MTOK to change)."
          % (s["saved_usd"], s["captures"], s["price_per_mtok"]), file=sys.stderr)


def cmd_gen(pos, fl):
    n = gen.generate(int(fl.get("lines", 100000)), pos[0])
    print("wrote %d lines -> %s" % (n, pos[0]))


def cmd_selftest(pos, fl):
    n = int(fl.get("lines", 100000))
    budget = int(fl.get("budget", 2000))
    fd, log = tempfile.mkstemp(prefix="probe_selftest_", suffix=".log")  # unpredictable name: no symlink clobber
    os.close(fd)
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

    # --- adversarial safety checks (the heuristic wrappers that failed real-log review) ---
    _secrets = ["db_password=hunter2", "client_secret=abc123def", "access_token=zzz9tok",
                "card=4111111111111111", "ssn=123-45-6789", "X-Internal-Auth: t0knQx7",
                "Authorization: Basic dXNlcjpwYXNz"]
    _ids = ["req=550e8400-e29b-41d4-a716-446655440000", "sha=9f2c3a1b4d5e6f70819a2b3c4d5e6f7081920304"]
    red_ok = all("redacted" in redact.redact(s) for s in _secrets) and all("redacted" not in redact.redact(s) for s in _ids)
    chk("redaction_adversarial", red_ok, "%d real-format secrets redacted; UUIDs/SHAs preserved" % len(_secrets))

    many = "\n".join("2026-01-01T00:%02d:%02d ERROR svc_%d failed code=%d uniq%d"
                     % (i // 60, i % 60, i, i, i) for i in range(400)) + "\n"
    capb, _ = engine.build(many.encode(), budget_tokens=500)
    chk("bounded_worstcase", capb["stats"]["capsule_tokens"] <= 500 * 1.5,
        "%d distinct errors @budget 500 -> %d tok, truncated=%d"
        % (capb["stats"]["templates"], capb["stats"]["capsule_tokens"], capb["stats"]["truncated_templates"]))

    ctx = ld.context(100, before=999999, after=999999)
    srch = ld.search(limit=-5)
    chk("drilldown_capped", len(ctx["lines"]) <= 405 and len(srch["results"]) <= 1,
        "huge context-window -> %d lines; search limit=-5 -> %d results" % (len(ctx["lines"]), len(srch["results"])))

    t = time.time()
    redact.redact(("-----BEGIN PRIVATE KEY-----\n" * 3000) + ("x" * 60 + "\n") * 100)
    redos_ms = (time.time() - t) * 1000
    chk("redos_safe", redos_ms < 1000, "PEM-flood redaction in %.0f ms (<1000)" % redos_ms)

    # --- security boundary: traversal rejected, integrity enforced, cache locked, injection-labeled ---
    sec = []
    for bad in ["../../etc/passwd", "/etc/passwd", "ABCDEF0123456789", h + "x", "../" * 4 + "tmp"]:
        try:
            engine.Loader(bad); sec.append("traversal accepted: %r" % bad)
        except ValueError:
            pass
    _sd = tempfile.mkdtemp(prefix="probe_sec_")
    try:
        _h = engine.build(raw[:20000] + b"\nERROR sentinel boom\n", budget_tokens=300, cache_dir=_sd)[1]
        _sp = os.path.join(_sd, "captures", _h, "store.clp")
        _b = bytearray(open(_sp, "rb").read()); _b[-2] ^= 0x40; open(_sp, "wb").write(bytes(_b))
        try:
            engine.Loader(_h, cache_dir=_sd); sec.append("store tamper not detected")
        except ValueError:
            pass
    finally:
        shutil.rmtree(_sd, ignore_errors=True)
    if os.name == "posix":
        for _p in (ld.dir, os.path.join(ld.dir, "store.clp"), os.path.join(ld.dir, "meta.json")):
            if _stat.S_IMODE(os.stat(_p).st_mode) & 0o077:
                sec.append("group/other-accessible: %s" % os.path.basename(_p))
    if "_provenance" not in cap:
        sec.append("missing prompt-injection note")
    chk("security_boundary", not sec,
        "traversal rejected, store-tamper detected, cache 0700/0600, injection-labeled" if not sec else "; ".join(sec))

    cost = cap["stats"].get("cost")
    sv = engine.savings_summary()
    price_ok = bool(cost) and cost["raw_tokens"] >= cost["capsule_tokens"] and cost["saved_tokens"] >= 0 \
        and sv["captures"] >= 1 and sv["saved_usd"] >= 0
    chk("price_log", price_ok, "this build saved ~$%.4f; cache total ~$%.2f across %d captures"
        % ((cost or {}).get("saved_usd", 0), sv["saved_usd"], sv["captures"]))

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
    _c = st["cost"]
    print("  capsule cost @ $%g/M tokens .. $%.5f  vs raw ~$%.2f  (estimated saving $%.2f)"
          % (_c["price_per_mtok"], _c["capsule_tokens"] / 1e6 * _c["price_per_mtok"],
             _c["raw_tokens"] / 1e6 * _c["price_per_mtok"], _c["saved_usd"]))
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
    "context": cmd_context, "trace": cmd_trace, "verify": cmd_verify, "savings": cmd_savings,
    "gen": cmd_gen, "multi": cmd_multi, "multitest": cmd_multitest, "selftest": cmd_selftest,
    "mcp": cmd_mcp,
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
    try:
        _CMDS[cmd](pos, fl)
    except (FileNotFoundError, ValueError, OSError, KeyError, IndexError) as e:
        print("error: %s: %s" % (type(e).__name__, e), file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
