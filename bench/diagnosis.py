"""Diagnosis eval: does the artifact let an agent actually diagnose the incident?

Two judges:
  - deterministic (default): gold-evidence recall — fast, no API, the regression gate.
  - real LLM (--llm): mirrors Codag's Section-02 design. For each artifact an agent
    DIAGNOSES the root cause with no gold labels; a SEPARATE blind judge scores the
    diagnosis against the gold root cause. Auto-detects a backend (ANTHROPIC_API_KEY,
    OPENAI_API_KEY, or a logged-in `claude` CLI); falls back to deterministic if none.

Three arms under a fixed budget: capsule (probe's ranked evidence) / raw_trunc (raw
logs capped to ~20k tokens) / naive_freq (the 5 highest-volume templates).

  PYTHONPATH=. python3 -m bench.diagnosis            # deterministic
  PYTHONPATH=. python3 -m bench.diagnosis --llm      # real diagnose + blind judge
  PYTHONPATH=. python3 -m bench.diagnosis --emit DIR # write artifacts for manual review
"""
import os
import re
import sys
import json
import tempfile
import subprocess

from probe import engine, gen, redact

KINDS = ["db_pool", "oom", "disk_full", "cert_expiry"]
SIZES = [("small", 300), ("large", 100000)]
RAW_CAP_CHARS = 80000   # ~20k tokens — Codag's raw control budget
BUDGET = 800


# ----------------------------------------------------------------- artifacts
def _naive(raw, k=5):
    recs = engine.to_records(raw.decode("utf-8", "replace").split("\n"))
    d = engine.Drain()
    for i, r in enumerate(recs):
        d.add(r, i)
    top = sorted(d.clusters, key=lambda c: -c["count"])[:k]
    return "\n".join("x%d %s" % (c["count"], redact.redact(engine.render(c["tok"]))) for c in top)


def artifacts(kind, n):
    path = os.path.join(tempfile.gettempdir(), "diag_%s_%d.log" % (kind, n))
    gen.generate(n, path, kind=kind)
    raw = open(path, "rb").read()
    cap, _ = engine.build(raw, budget_tokens=BUDGET)
    return {
        "capsule": json.dumps(cap),
        "raw_trunc": raw.decode("utf-8", "replace")[:RAW_CAP_CHARS],
        "naive_freq": _naive(raw),
    }


# ----------------------------------------------------------------- judges
def gold_recall(text, gold):
    return sum(1 for g in gold if g in text) / len(gold)


def _llm(prompt, max_tokens=256):
    """Return model text, or None if no backend is reachable."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            import anthropic
            m = anthropic.Anthropic().messages.create(
                model=os.environ.get("PROBE_JUDGE_MODEL", "claude-3-5-haiku-latest"),
                max_tokens=max_tokens, messages=[{"role": "user", "content": prompt}])
            return "".join(b.text for b in m.content if getattr(b, "type", "") == "text").strip()
        except Exception:
            pass
    if os.environ.get("OPENAI_API_KEY"):
        try:
            import openai
            r = openai.OpenAI().chat.completions.create(
                model=os.environ.get("PROBE_JUDGE_MODEL", "gpt-4o-mini"),
                max_tokens=max_tokens, messages=[{"role": "user", "content": prompt}])
            return (r.choices[0].message.content or "").strip()
        except Exception:
            pass
    try:  # logged-in `claude` CLI (prompt via stdin to dodge ARG_MAX)
        r = subprocess.run(["claude", "-p"], input=prompt, capture_output=True, text=True, timeout=180)
        out = (r.stdout or "").strip()
        if r.returncode == 0 and out and "Not logged in" not in out and "/login" not in out:
            return out
    except Exception:
        pass
    return None


def llm_available():
    return _llm("Reply with exactly: OK", max_tokens=8) is not None


def diagnose(artifact):
    return _llm(
        "You are an on-call SRE. Below is observability data for ONE incident, with no "
        "labels. In a single sentence, state the single most likely ROOT CAUSE.\n\n"
        "DATA:\n" + artifact)


def llm_judge(diagnosis, gold):
    txt = _llm(
        "Gold root cause of an incident: %s\n\nA candidate diagnosis said:\n%s\n\n"
        "Score from 0.0 to 1.0 how well the candidate identifies the gold root cause "
        "(1.0 = correct, 0.0 = wrong/uninformative). Reply with ONLY the number."
        % (", ".join(gold), diagnosis or "(no diagnosis)"), max_tokens=8)
    m = re.search(r"[01](?:\.\d+)?", txt or "")
    return max(0.0, min(1.0, float(m.group(0)))) if m else 0.0


# ----------------------------------------------------------------- runners
def run_deterministic():
    arms = ["capsule", "raw_trunc", "naive_freq"]
    agg = {sz: {a: [] for a in arms} for sz, _ in SIZES}
    for kind in KINDS:
        gold = gen.GOLD_BY_KIND[kind]
        for sz, n in SIZES:
            arts = artifacts(kind, n)
            for a in arms:
                agg[sz][a].append(gold_recall(arts[a], gold))
    print("=" * 72)
    print("  diagnosis (deterministic judge = gold-evidence recall)  %d archetypes" % len(KINDS))
    print("=" * 72)
    print("  %-14s %10s %10s %11s" % ("window", "capsule", "raw_trunc", "naive_freq"))
    for sz, n in SIZES:
        r = [sum(agg[sz][a]) / len(agg[sz][a]) for a in arms]
        print("  %-14s %10.2f %10.2f %11.2f   (n=%d)" % ("%s (%d)" % (sz, n), r[0], r[1], r[2], len(KINDS)))
    print("-" * 72)
    print("  Run --llm for the real diagnose+blind-judge eval (needs an API key or logged-in claude CLI).")


def run_llm(kinds):
    if not llm_available():
        print("No LLM backend reachable (no ANTHROPIC_API_KEY / OPENAI_API_KEY, `claude` not logged in).")
        print("The eval is wired and correct; set a key and re-run. Falling back to deterministic:\n")
        run_deterministic()
        return
    arms = ["capsule", "raw_trunc", "naive_freq"]
    print("=" * 72)
    print("  diagnosis (REAL LLM: agent diagnoses blind, separate blind judge scores)")
    print("=" * 72)
    tot = {a: [] for a in arms}
    for kind in kinds:
        gold = gen.GOLD_BY_KIND[kind]
        arts = artifacts(kind, 100000)   # large window: the case that matters
        print("  incident: %s   gold=%s" % (kind, gold))
        for a in arms:
            dx = diagnose(arts[a])
            sc = llm_judge(dx, gold)
            tot[a].append(sc)
            print("    %-11s score=%.2f  dx=%s" % (a, sc, (dx or "")[:80].replace("\n", " ")))
    print("-" * 72)
    print("  mean: " + "  ".join("%s=%.2f" % (a, sum(tot[a]) / len(tot[a])) for a in arms))


def run_emit(d):
    os.makedirs(d, exist_ok=True)
    golds = {}
    for kind in ["db_pool", "oom"]:
        arts = artifacts(kind, 100000)
        golds[kind] = gen.GOLD_BY_KIND[kind]
        for a, txt in arts.items():
            open(os.path.join(d, "%s.%s.txt" % (kind, a)), "w").write(txt)
    json.dump(golds, open(os.path.join(d, "golds.json"), "w"), indent=2)
    print("wrote artifacts for %d incidents x 3 arms to %s" % (len(golds), d))


def main(argv):
    if "--emit" in argv:
        run_emit(argv[argv.index("--emit") + 1])
    elif "--llm" in argv:
        run_llm(KINDS[:2])   # small corpus to bound cost; widen as desired
    else:
        run_deterministic()


if __name__ == "__main__":
    main(sys.argv[1:])
