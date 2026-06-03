"""Real LogHub grouping benchmark.

Runs probe's templater over the labeled LogHub 2k samples and computes the same
metrics Codag publishes (GA / FGA / FTA / purity / line_cx), macro-averaged over
systems with a bootstrap 95% CI, then prints our numbers next to theirs.

Note: this uses the public LogHub *2k* labeled samples (logpai/loghub), not the
LogHub-2.0 3k slices Codag used, so absolute numbers differ slightly. The metric
definitions and the apples-to-apples question ("does our grouping match Drain3?")
are identical. Set LOGHUB_DIR to override the dataset root.
"""
import os
import re
import csv
import random
from collections import defaultdict, Counter

from probe import engine

# The 14 systems Codag benchmarks (loghub also ships Android/Windows; excluded for parity).
SYSTEMS = ["Apache", "BGL", "HDFS", "HPC", "Hadoop", "HealthApp", "Linux", "Mac",
           "OpenSSH", "OpenStack", "Proxifier", "Spark", "Thunderbird", "Zookeeper"]

# Codag's published "drain" arm (LogHub-2.0, docs/PUBLIC_BENCHMARKS.md).
THEIRS = {"GA": 0.770, "FGA": 0.833, "FTA": 0.297, "purity": 0.978}
THEIRS_DRAIN3 = {"GA": 0.770, "FGA": 0.833, "FTA": 0.186, "purity": 0.978}

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WILD = re.compile(r"<(?:\*|num|ip|hex|uuid)>")
csv.field_size_limit(10_000_000)


def _norm(s):
    """Collapse all wildcard kinds to <*> and squeeze whitespace for template eq."""
    return " ".join(_WILD.sub("<*>", s).split())


def _template_messages(contents):
    """Template a list of single-line messages (no multiline grouping)."""
    d = engine.Drain()
    pred = []
    for i, c in enumerate(contents):
        rec = {"key": engine.mask(c).split() or [""], "traces": [],
               "sev": 0.2, "level": "INFO", "raw": c}
        pred.append(d.add(rec, i))
    return pred, d


def _load(system, loghub_dir):
    path = os.path.join(loghub_dir, system, "%s_2k.log_structured.csv" % system)
    contents, eids, tmpls = [], [], []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            contents.append(row.get("Content", "") or "")
            eids.append(row.get("EventId", ""))
            tmpls.append(row.get("EventTemplate", "") or "")
    return contents, eids, tmpls


def _metrics(contents, eids, tmpls):
    pred, d = _template_messages(contents)
    n = len(contents)
    pred_g, orac_g = defaultdict(set), defaultdict(set)
    for i in range(n):
        pred_g[pred[i]].add(i)
        orac_g[eids[i]].add(i)
    pred_set = {c: frozenset(s) for c, s in pred_g.items()}
    orac_set = {e: frozenset(s) for e, s in orac_g.items()}
    orac_members = set(orac_set.values())
    pred_members = set(pred_set.values())

    # GA: a message is correct if its predicted member-set equals its oracle member-set.
    ga = sum(1 for i in range(n) if pred_set[pred[i]] == orac_set[eids[i]]) / n

    # FGA: F1 over groups by exact member-set match.
    p_ok = sum(1 for s in pred_set.values() if s in orac_members)
    o_ok = sum(1 for s in orac_members if s in pred_members)
    P, R = p_ok / len(pred_set), o_ok / len(orac_set)
    fga = 2 * P * R / (P + R) if P + R else 0.0

    # FTA: FGA but the rendered template must also match the oracle template.
    tmpl_of = {c: _norm(engine.render(d.clusters[c]["tok"])) for c in pred_g}
    orac_tmpl = {frozenset(s): _norm(tmpls[next(iter(s))]) for e, s in orac_g.items()}
    t_ok = sum(1 for c, s in pred_set.items()
               if s in orac_tmpl and tmpl_of[c] == orac_tmpl[s])
    Pt, Rt = t_ok / len(pred_set), t_ok / len(orac_set)
    fta = 2 * Pt * Rt / (Pt + Rt) if Pt + Rt else 0.0

    # purity: line-weighted dominant-oracle share per predicted cluster.
    purity = sum(max(Counter(eids[i] for i in s).values()) for s in pred_g.values()) / n
    return {"GA": ga, "FGA": fga, "FTA": fta, "purity": purity,
            "line_cx": n / len(pred_g), "templates": len(pred_g)}


def _boot(vals, iters=2000, seed=0):
    r = random.Random(seed)
    n = len(vals)
    means = sorted(sum(vals[r.randrange(n)] for _ in range(n)) / n for _ in range(iters))
    return means[int(0.025 * iters)], means[int(0.975 * iters)]


def main():
    loghub = os.environ.get("LOGHUB_DIR", os.path.join(_REPO, ".bench", "vendor", "loghub"))
    rows, per = [], defaultdict(list)
    for s in SYSTEMS:
        try:
            m = _metrics(*_load(s, loghub))
        except FileNotFoundError:
            print("  (skip %s: not found under %s)" % (s, loghub))
            continue
        rows.append((s, m))
        for k in ("GA", "FGA", "FTA", "purity", "line_cx"):
            per[k].append(m[k])

    if not rows:
        print("No LogHub systems found. Set LOGHUB_DIR to the structured-CSV root.")
        return

    print("=" * 78)
    print("  probe grouping on real LogHub-2k  (%d systems, oracle-labeled)" % len(rows))
    print("=" * 78)
    print("  %-12s %6s %6s %6s %7s %8s" % ("system", "GA", "FGA", "FTA", "purity", "line_cx"))
    for s, m in rows:
        print("  %-12s %6.3f %6.3f %6.3f %7.3f %7.1fx" % (s, m["GA"], m["FGA"], m["FTA"], m["purity"], m["line_cx"]))
    print("-" * 78)
    macro = {k: sum(v) / len(v) for k, v in per.items()}
    print("  %-12s %6.3f %6.3f %6.3f %7.3f %7.1fx   <- probe (macro mean)"
          % ("MACRO", macro["GA"], macro["FGA"], macro["FTA"], macro["purity"], macro["line_cx"]))
    for k in ("GA", "FGA", "FTA", "purity"):
        lo, hi = _boot(per[k])
        print("    %-6s 95%% CI [%.3f, %.3f]" % (k, lo, hi))
    print("-" * 78)
    print("  Codag 'drain'  GA %.3f  FGA %.3f  FTA %.3f  purity %.3f   (their LogHub-2.0 table)"
          % (THEIRS["GA"], THEIRS["FGA"], THEIRS["FTA"], THEIRS["purity"]))
    print("  Codag 'drain3' GA %.3f  FGA %.3f  FTA %.3f  purity %.3f"
          % (THEIRS_DRAIN3["GA"], THEIRS_DRAIN3["FGA"], THEIRS_DRAIN3["FTA"], THEIRS_DRAIN3["purity"]))
    print("=" * 78)
    print("  Read: grouping (GA/FGA/purity) is a Drain plateau — matching it is the goal,")
    print("  not beating it. probe's edge is downstream: ranked evidence + drill-down +")
    print("  baseline/trace correlation, measured in bench.diagnosis, not here.")


if __name__ == "__main__":
    main()
