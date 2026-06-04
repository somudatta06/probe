# probe

**Logs an agent can investigate, not just read.**

`probe` turns a log firehose into one immutable, redacted, indexed **incident
snapshot** in a single deterministic pass. The agent gets a cheap ranked
**capsule** (the first page), and can drill into the *full, retained* logs on
demand — every claim re-derives from raw. No model, no GPU, no server, nothing
leaves your box but what the agent pulls.

This is the local-first, deterministic answer to hosted log-compression services
(e.g. Codag): same "huge logs → tiny artifact" win, but **lossless underneath,
verifiable, private, and ~$0 to run** because the work happens on your machine
and the reasoning is done by the agent you already pay for.

> Reference implementation in Python (stdlib only). The hot path (templating +
> scoring) ports to Rust/Go for the shipped single binary.

---

## What it does (measured)

`bin/probe selftest --lines 1200000` on a synthetic incident (a DB-pool-exhaustion
cascade buried in routine noise, plus a planted secret and a heartbeat that goes
silent):

```
input lines ........ 1,200,000
capsule tokens ..... ~1,740
compression ........ 690x  (lines / token)
build time ......... 8.8 s   pure Python, 1 core, no GPU  (Rust port: sub-second)
capsule cost ....... $0.005  vs ~$21.60 to feed raw to a frontier model
```

The capsule the agent receives (real output, trimmed):

```
EVIDENCE (ranked by EvidenceScore):
  F12  score=0.95  x1     new,error,near_incident,shares_trace,multiline | ERROR psycopg2.OperationalError: could not connect ...
  F13  score=0.95  x2     new,error,near_incident,shares_trace           | ERROR retry <num>/<num> db_users id=abc124
  F14  score=0.95  x1     new,error,near_incident,shares_trace           | ERROR pool exhausted, queue=<num> id=abc125
  F11  score=0.80  x2     near_incident                                  | WARN  pool acquire <*>            (the trigger)
  F9   score=0.49  x169   went_silent                                    | INFO  heartbeat ok seq=<num>      (baseline shift)
CHANGES:    deploy released sha=9f2c3a1 service=db version=v2.3.1
HYPOTHESIS: psycopg2.OperationalError emerged near line 1020004, correlated with a change
            and 'heartbeat' going silent   [confidence: medium, rests_on: F12, F9]
ROUTINE collapsed: 69k lines -> 3 template counts
```

Note what it does **not** do: it never emits a `root_cause` verdict. It surfaces
ranked, provenance-stamped **facts** + clearly-labeled **hypotheses**. The agent
concludes, and can `verify` any fact against raw lines.

---

## Design in one breath

**Build once, view many.** One streaming pass does: multiline-group → Drain
templatize → count → in-window baseline → **EvidenceScore** → redact → index →
persist. The capsule and every drill-down tool are just *views* over the same
immutable artifact, so investigation costs near-zero extra build work.

**EvidenceScore** ranks each template by `0.40·anomaly + 0.25·severity +
0.20·proximity + 0.10·rarity + 0.05·causal` — anomaly (new / went-silent / rate
shift vs an in-window baseline, so it works with **no history**) and severity
dominate. Selection fills the token budget greedily **but reserves slots** for
the first/last error, every new/silent template, multiline error spans (kept
atomic), and a routine sample — so the high-signal tail is never truncated away.

### Invariants (what "robust" means here — all enforced as tests)

| Invariant | Guarantee |
|---|---|
| **conservation** | every input line is accounted for; none silently dropped |
| **soundness** | every cited line/number exists in raw and re-derives (`verify`) |
| **determinism** | same bytes → byte-identical capsule → cacheable |
| **redaction boundary** | no secret crosses local→cloud (raw on disk stays intact) |
| **never-lose-a-signal** | a parser miss routes to a scored rare pool, not the bin |
| **bounded** | RAM O(templates + budget); every tool result size-capped |

`bin/probe selftest` runs all six as property tests over a 100k-line incident.

---

## Install

```bash
./install.sh          # isolated venv, puts `probe` on your PATH (zero runtime deps)
# alternatives:  pipx install .   ·   pip install .   ·   or run ./bin/probe with no install
```

## Quickstart

```bash
probe selftest                       # run the invariant suite + demo
probe gen   /tmp/incident.log --lines 200000
probe build /tmp/incident.log        # -> capsule (stdout) + capture_id (stderr)

# drill down over the retained, indexed capture:
probe search  <capture_id> --level ERROR --limit 20
probe context <capture_id> 85004 --before 5 --after 10
probe trace   <capture_id> abc124    # all lines on a request id (cross-service when multi-stream)
probe verify  <capture_id> F12       # re-derive the fact's count from raw + sample lines

# wrap any log source your agent already runs (captures stdout + stderr):
probe wrap -- kubectl logs api -n prod --tail=200000
probe wrap -- journalctl -u api --since "1 hour ago"
probe wrap -- docker compose logs api
```

## Wire it into an agent (MCP)

Claude Code / Cursor / Codex — add to your MCP config (e.g. `.mcp.json`):

```json
{
  "mcpServers": {
    "probe": { "command": "probe", "args": ["mcp"] }
  }
}
```

If your agent can't find `probe` on its PATH, use the absolute path `install.sh` prints
(e.g. `~/.local/bin/probe`). Verified tools over JSON-RPC: `build`, `capsule`, `search`,
`context`, `trace`, `verify`.

Tools exposed: `build`, `capsule`, `search`, `context`, `trace`, `verify`.
The agent reads the cheap `capsule` first, then expands only as its hypothesis
demands — query-time, agent-driven retrieval instead of one-shot guess-the-query
compression.

---

## Why this beats a hosted one-shot compressor

| | hosted capsule (e.g. Codag) | probe |
|---|---|---|
| logs after compression | thrown away (lossy funnel) | **retained, indexed, queryable** |
| can the agent verify a claim? | no | **yes — `verify` re-derives from raw** |
| picks lines before the query | yes (query-blind) | capsule is page 1; **agent drives drill-down** |
| root-cause label | asserted by a model | **facts + labeled hypotheses; agent concludes** |
| baseline / went-silent signal | none (single window) | **in-window baseline, no history needed** |
| secrets | shipped to their SaaS, then redacted | **redacted at the boundary; raw never leaves** |
| model in the path | their fine-tuned model (a weaker bottleneck) | **none — your frontier agent reasons** |
| our cost to run (COGS) | GPU + ingest + storage, scales w/ users | **$0 — runs on the user's box** |

---

## Benchmarked on real data + ported to Rust

**Grouping — real LogHub-2k, 14 oracle-labeled systems** (`python3 -m bench.grouping`):

| metric | probe | Codag `drain` | Codag `drain3` |
|---|---:|---:|---:|
| GA | **0.783** | 0.770 | 0.770 |
| FTA | **0.434** | 0.297 | 0.186 |
| purity | 0.977 | 0.978 | 0.978 |

We match the Drain plateau on grouping (GA/purity) and beat their template
rendering (FTA) on real labeled logs. (FGA trails on Proxifier/Spark — Drain's
known-hard systems.)

**Diagnosis under a fixed budget** (`python3 -m bench.diagnosis`, gold-evidence recall):

| window | capsule | raw (trunc 20k tok) | frequency-only |
|---|---:|---:|---:|
| small (300) | 1.00 | 1.00 | 0.00 |
| large (100k) | **1.00** | 0.00 | 0.00 |

Codag's crossover, reproduced: raw wins only when it fits; at scale it truncates and
loses the cause; frequency surfaces the loud symptom; the scored capsule keeps the
root cause every time. Calibration (`bench.calibrate`) puts the true root cause as the
**#1 fact (MRR 1.000)**.

**Rust accelerator** (`rs/`, wired into the CLI): all **7 invariants** pass; it writes the *same
typed store* the Python `Loader` reads — **cross-language lossless, verified** (a Rust-built
capture decodes byte-for-byte in Python, and `search`/`verify`/MCP work on it). `probe build/wrap`
**auto-use it** when `probe-rs` is on PATH (or `PROBE_RS_BIN` is set), falling back to Python
otherwise (`--engine py|rust|auto`). **1.2M lines: 8.9 s (Python) → 2.4 s (Rust) end-to-end via
the CLI (~3.8×)**; `install.sh` builds it automatically when cargo is present.

**Cross-service + change providers** (`bin/probe multitest`): `build_multi` merges
services' streams by timestamp; `trace <id>` stitches a request across services (root
cause in `db`, symptom in `api`); `git log` / k8s events attach as capsule `changes`.

**Capture — CLP-style lossless, seekable, TYPED store** (`probe/clp.py`): logtype dictionary +
timestamp column + variables, where integer variable slots are stored as **zig-zag delta varints**
(binary) — which a generic compressor can't reproduce from ASCII digits. Byte-for-byte **lossless**
(a selftest invariant) and **seekable**: **34.4× at 100k, 114.8× at 1.2M** (vs whole-file gzip 17.5×),
and a random `context` lookup decodes **1 of 74 blocks in ~11 ms** instead of decompressing the file.
Head-to-head (`bench.clp_typed`) the typed encoding beats the text-columnar store by **+21–26%**,
losslessly; on real LogHub (28k lines) it's 13.2× vs gzip's 10.0× (synthetic inflates the ratio).

## Commands

```bash
bin/probe selftest                          # invariant suite + demo
PYTHONPATH=. python3 -m bench.grouping      # real LogHub grouping vs Codag's numbers
PYTHONPATH=. python3 -m bench.diagnosis     # capsule vs raw vs frequency-only
PYTHONPATH=. python3 -m bench.calibrate     # EvidenceScore weight search
PYTHONPATH=. python3 -m bench.clp_typed     # typed binary store vs gzip-columns (ratio + lossless)
bin/probe multitest                         # cross-service stitch + git change provider
bin/probe multi api=api.log db=db.log --repo .   # cross-service capsule + git changes
# Rust:
source ~/.cargo/env && CARGO_TARGET_DIR=/tmp/probe-rs-target \
  cargo build --release --manifest-path rs/Cargo.toml
/tmp/probe-rs-target/release/probe-rs bench --lines 1200000
```

## Remaining roadmap

- Capture is a **typed, lossless, seekable CLP-style store in both Python and Rust**
  (byte-compatible — either engine's capture is readable by the other): integer variables as
  zig-zag delta varints — **34.4× @100k, 114.8× @1.2M**, beating gzip + the text store.
  Remaining toward CLP's ~169×: delta-timestamp encoding + binary float typing, validated on
  real high-cardinality production logs (synthetic inflates the ratio; real LogHub here is 13.2×).
- `bench.diagnosis --llm` is wired for a **real blind diagnose + judge** (auto-detects
  Anthropic / OpenAI / a logged-in `claude` CLI; deterministic fallback). A frontier-model
  spot-check (N=2) scored **capsule 1.00 vs truncated-raw 0.00 vs frequency-only 0.00** at
  scale; the automated 80-incident run just needs an API key in the environment.
- Wire the gated real-time k8s event provider (`changes.k8s_changes`).

MIT-spirited; build on it.
