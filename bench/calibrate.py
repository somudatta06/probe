"""Calibrate EvidenceScore weights by how well they RANK the true root cause.

Objective = mean reciprocal rank (MRR) of the first gold-bearing fact in the
score-ordered evidence, across the incident corpus. Higher = the real root cause
sits at the top of what the agent reads first. Coordinate ascent over the five
weights (renormalized to sum 1). This is the knob that, on real data, would be
tuned on LogHub-2.0 + the labeled incident corpus.
"""
import os
import tempfile

from probe import engine, gen

KINDS = ["db_pool", "oom", "disk_full", "cert_expiry"]
N = 20000          # large enough to overflow naive context, small enough to calibrate fast
BUDGET = 100000    # generous: we score ranking, not truncation
KEYS = ["anomaly", "severity", "proximity", "rarity", "causal"]


def _rr(cap, gold):
    for i, f in enumerate(cap["evidence"]):  # evidence is score-sorted
        if any(g in f["example"] or g in f["template"] for g in gold):
            return 1.0 / (i + 1)
    return 0.0


def _mrr(raws, weights):
    w = {k: max(0.0, v) for k, v in weights.items()}
    s = sum(w.values()) or 1.0
    w = {k: v / s for k, v in w.items()}
    tot = 0.0
    for kind, raw in raws.items():
        cap, _ = engine.build(raw, budget_tokens=BUDGET, weights=w)
        tot += _rr(cap, gen.GOLD_BY_KIND[kind])
    return tot / len(raws)


def main():
    tmp = tempfile.gettempdir()
    raws = {}
    for kind in KINDS:
        p = os.path.join(tmp, "cal_%s.log" % kind)
        gen.generate(N, p, kind=kind)
        raws[kind] = open(p, "rb").read()

    default = dict(engine.DEFAULT_WEIGHTS)
    base = _mrr(raws, default)

    best, best_mrr = dict(default), base
    step = 0.10
    for _ in range(4):                       # coordinate ascent
        improved = False
        for k in KEYS:
            for d in (step, -step):
                trial = dict(best)
                trial[k] = best[k] + d
                m = _mrr(raws, trial)
                if m > best_mrr + 1e-9:
                    best, best_mrr, improved = trial, m, True
        step /= 2
        if not improved:
            break

    s = sum(max(0.0, v) for v in best.values()) or 1.0
    best = {k: round(max(0.0, v) / s, 3) for k, v in best.items()}

    print("=" * 64)
    print("  EvidenceScore weight calibration (objective: MRR of root cause)")
    print("=" * 64)
    print("  corpus: %d archetypes x %d lines" % (len(KINDS), N))
    print("  default weights %s" % {k: round(v, 3) for k, v in engine.DEFAULT_WEIGHTS.items()})
    print("    -> MRR = %.3f" % base)
    print("  best weights    %s" % best)
    print("    -> MRR = %.3f" % best_mrr)
    print("-" * 64)
    if best_mrr <= base + 1e-9:
        print("  Defaults are already at the local optimum on this corpus (MRR %.3f)." % base)
        print("  On real data, rerun against LogHub-2.0 + the labeled incident corpus.")
    else:
        print("  Calibration improved root-cause ranking by +%.3f MRR." % (best_mrr - base))
    print("  MRR=1.000 means the true root cause is the #1 fact the agent reads.")


if __name__ == "__main__":
    main()
