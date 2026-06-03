//! The single-pass incident-evidence engine (Rust port of `probe/engine.py`).
//!
//! `build()` runs one deterministic pass over a log byte stream and produces a
//! ranked first-page evidence capsule plus a content-addressed capture id.
//!
//! Field names and semantics mirror engine.py so capsules are comparable.

pub mod clp;
pub mod redact;

use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::OnceLock;

// ----------------------------------------------------------------- masking / parsing

struct Res {
    masks: Vec<(Regex, &'static str)>,
    ts_prefix: Regex,
    cont: Regex,
    level: Regex,
    trace: Regex,
    change: Regex,
}

fn res() -> &'static Res {
    static R: OnceLock<Res> = OnceLock::new();
    R.get_or_init(|| Res {
        masks: vec![
            (
                Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap(),
                "<ip>",
            ),
            (
                Regex::new(
                    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
                )
                .unwrap(),
                "<uuid>",
            ),
            (Regex::new(r"\b0x[0-9a-fA-F]+\b").unwrap(), "<hex>"),
            (Regex::new(r"\b[0-9a-fA-F]{12,}\b").unwrap(), "<hex>"),
            (Regex::new(r"\b\d+\b").unwrap(), "<num>"),
        ],
        ts_prefix: Regex::new(r"^(?:\[[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\]|\[\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\]]*\]|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\d{6}\s+\d{6}\b|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s*").unwrap(),
        cont: Regex::new(r#"^(?:\s|at |Caused by|\.\.\.|Traceback|File ")"#).unwrap(),
        level: Regex::new(r"\b(FATAL|ERROR|WARNING|WARN|INFO|DEBUG|TRACE)\b").unwrap(),
        trace: Regex::new(r"\b(?:id|trace|trace_id|request_id|req)=([A-Za-z0-9_\-]+)").unwrap(),
        change: Regex::new(
            r"(?i)\b(deploy|deployed|released|rollout|config[ _]?(?:change|update)|version=)\b",
        )
        .unwrap(),
    })
}

fn sev_for(level: &str) -> f64 {
    match level {
        "FATAL" => 1.0,
        "ERROR" => 0.8,
        "WARNING" | "WARN" => 0.4,
        "INFO" => 0.1,
        "DEBUG" | "TRACE" => 0.0,
        _ => 0.2,
    }
}

/// Apply the masking patterns in order.
pub fn mask(s: &str) -> String {
    let r = res();
    let mut out = std::borrow::Cow::Borrowed(s);
    for (pat, rep) in &r.masks {
        out = std::borrow::Cow::Owned(pat.replace_all(&out, *rep).into_owned());
    }
    out.into_owned()
}

fn render(tokens: &[String]) -> String {
    tokens.join(" ")
}

/// Python `str.split()` with no args: split on any whitespace run, drop empties.
fn py_split(s: &str) -> Vec<String> {
    s.split_whitespace().map(|t| t.to_string()).collect()
}

/// Ordered-unique (preserve first-seen order), like `list(dict.fromkeys(...))`.
fn ordered_unique(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for it in items {
        if seen.insert(it.clone()) {
            out.push(it);
        }
    }
    out
}

// ----------------------------------------------------------------- records

#[derive(Debug, Clone)]
pub struct Record {
    pub start: usize,
    pub end: usize,
    pub lines: Vec<String>,
    pub level: String,
    pub sev: f64,
    pub traces: Vec<String>,
    pub raw: String,
    pub ts: String,
    pub key: Vec<String>,
    pub cid: usize,
}

/// Group physical lines into logical records. A record starts with a timestamp
/// line; non-timestamp lines are continuations appended to the previous record.
/// Never drops a line.
pub fn to_records(raw_lines: &[String]) -> Vec<Record> {
    let r = res();
    let mut records: Vec<Record> = Vec::new();
    for (ln, text) in raw_lines.iter().enumerate() {
        if !records.is_empty() && r.cont.is_match(text) {
            let last = records.last_mut().unwrap();
            last.end = ln;
            last.lines.push(text.clone());
        } else {
            records.push(Record {
                start: ln,
                end: ln,
                lines: vec![text.clone()],
                level: String::new(),
                sev: 0.0,
                traces: Vec::new(),
                raw: String::new(),
                ts: String::new(),
                key: Vec::new(),
                cid: 0,
            });
        }
    }
    for rec in &mut records {
        let joined = rec.lines.join("\n");
        let first = &rec.lines[0];
        let body = r.ts_prefix.replace(first, "").into_owned();
        let level = match r.level.find(&joined) {
            Some(m) => m.as_str().to_string(),
            None => "INFO".to_string(),
        };
        rec.sev = sev_for(&level);
        rec.level = level;
        let traces: Vec<String> = r
            .trace
            .captures_iter(&joined)
            .map(|c| c[1].to_string())
            .collect();
        rec.traces = ordered_unique(traces);
        // ts = the stripped prefix text (first minus body).
        let prefix_len = first.len() - body.len();
        rec.ts = first[..prefix_len].trim().to_string();
        rec.key = py_split(&mask(&body));
        rec.raw = joined;
    }
    records
}

// ----------------------------------------------------------------- Drain

#[derive(Debug, Clone)]
pub struct Cluster {
    pub id: usize,
    pub tok: Vec<String>,
    pub count: usize,
    pub recs: Vec<usize>,
    pub traces: BTreeSet<String>,
    pub level: String,
    pub sev: f64,
    pub example: String,
    pub ex_rec: usize,
    pub first: usize,
    // scoring fields (filled by score())
    pub pre: usize,
    pub post: usize,
    pub first_rec: usize,
    pub last_rec: usize,
    pub anomaly: f64,
    pub prox: f64,
    pub rarity: f64,
    pub causal: f64,
    pub score: f64,
}

pub struct Drain {
    pub sim_th: f64,
    pub clusters: Vec<Cluster>,
    tree: BTreeMap<(usize, String, String), Vec<usize>>,
}

impl Drain {
    pub fn new(sim_th: f64) -> Self {
        Drain {
            sim_th,
            clusters: Vec::new(),
            tree: BTreeMap::new(),
        }
    }

    fn sim(a: &[String], b: &[String]) -> f64 {
        if a.is_empty() {
            return 1.0;
        }
        let same = a
            .iter()
            .zip(b.iter())
            .filter(|(x, y)| x == y || x.as_str() == "<*>" || y.as_str() == "<*>")
            .count();
        same as f64 / a.len() as f64
    }

    pub fn add(&mut self, rec: &Record, idx: usize) -> usize {
        // toks = rec.key or [""]
        let toks: Vec<String> = if rec.key.is_empty() {
            vec![String::new()]
        } else {
            rec.key.clone()
        };
        let key = (
            toks.len(),
            toks[0].clone(),
            if toks.len() > 1 {
                toks[1].clone()
            } else {
                String::new()
            },
        );

        // Find best candidate in this bucket. Borrow tree immutably, clone the
        // small Vec<usize> of candidate ids so no tree borrow is held across the
        // later mutation of self.clusters / self.tree.
        let bucket_ids: Vec<usize> = self.tree.get(&key).cloned().unwrap_or_default();
        let mut best: Option<usize> = None;
        let mut best_s = -1.0f64;
        for &cid in bucket_ids.iter() {
            let s = Self::sim(&self.clusters[cid].tok, &toks);
            if s > best_s {
                best_s = s;
                best = Some(cid);
            }
        }

        if let Some(bcid) = best {
            if best_s >= self.sim_th {
                let c = &mut self.clusters[bcid];
                // merge: differing positions -> "<*>"
                for (slot, y) in c.tok.iter_mut().zip(toks.iter()) {
                    if slot != y {
                        *slot = "<*>".to_string();
                    }
                }
                c.count += 1;
                c.recs.push(idx);
                for t in &rec.traces {
                    c.traces.insert(t.clone());
                }
                if rec.sev > c.sev {
                    c.sev = rec.sev;
                    c.level = rec.level.clone();
                    c.example = rec.raw.clone();
                    c.ex_rec = idx;
                }
                return bcid;
            }
        }

        let cid = self.clusters.len();
        let mut traces = BTreeSet::new();
        for t in &rec.traces {
            traces.insert(t.clone());
        }
        self.clusters.push(Cluster {
            id: cid,
            tok: toks,
            count: 1,
            recs: vec![idx],
            traces,
            level: rec.level.clone(),
            sev: rec.sev,
            example: rec.raw.clone(),
            ex_rec: idx,
            first: idx,
            pre: 0,
            post: 0,
            first_rec: idx,
            last_rec: idx,
            anomaly: 0.0,
            prox: 0.0,
            rarity: 0.0,
            causal: 0.0,
            score: 0.0,
        });
        self.tree.entry(key).or_default().push(cid);
        cid
    }
}

// ----------------------------------------------------------------- scoring

#[derive(Clone, Copy)]
pub struct Weights {
    pub anomaly: f64,
    pub severity: f64,
    pub proximity: f64,
    pub rarity: f64,
    pub causal: f64,
}

impl Default for Weights {
    fn default() -> Self {
        Weights {
            anomaly: 0.40,
            severity: 0.25,
            proximity: 0.20,
            rarity: 0.10,
            causal: 0.05,
        }
    }
}

fn score_clusters(clusters: &mut [Cluster], anchor: usize, n_rec: usize, w: &Weights) {
    let mut err_traces: BTreeSet<String> = BTreeSet::new();
    for c in clusters.iter() {
        if c.sev >= 0.8 {
            for t in &c.traces {
                err_traces.insert(t.clone());
            }
        }
    }
    let tau = (0.1 * n_rec as f64).max(1.0);
    let eps = 1e-6;
    for c in clusters.iter_mut() {
        let pre = c.recs.iter().filter(|&&i| i < anchor).count();
        c.pre = pre;
        c.post = c.count - pre;
        c.first_rec = *c.recs.first().unwrap();
        c.last_rec = *c.recs.last().unwrap();
        let a = if c.pre == 0 && c.post > 0 {
            1.0
        } else if c.post == 0 && c.pre >= 2 {
            1.0
        } else if c.post == 0 {
            0.0
        } else {
            let rp = c.pre as f64 / (anchor.max(1) as f64);
            let rq = c.post as f64 / ((n_rec - anchor).max(1) as f64);
            (((rq + eps) / (rp + eps)).ln().abs() / 3.0).min(1.0)
        };
        c.anomaly = a;
        c.prox = (-((c.first_rec as f64 - anchor as f64).abs()) / tau).exp();
        c.rarity = ((-((c.count as f64 / (n_rec.max(1) as f64)).log10())) / 4.0).min(1.0);
        c.causal = if c.traces.iter().any(|t| err_traces.contains(t)) {
            1.0
        } else {
            0.0
        };
        c.score = w.anomaly * a
            + w.severity * c.sev
            + w.proximity * c.prox
            + w.rarity * c.rarity
            + w.causal * c.causal;
    }
}

// ----------------------------------------------------------------- facts

/// Round to 3 decimal places the way Python's round() does for these values
/// (round-half-to-even). serde_json will then print the shortest repr.
fn round3(x: f64) -> f64 {
    // Match Python round(x, 3): banker's rounding.
    let scaled = x * 1000.0;
    let floor = scaled.floor();
    let diff = scaled - floor;
    let rounded = if (diff - 0.5).abs() < 1e-9 {
        // halfway: round to even
        if (floor as i64) % 2 == 0 {
            floor
        } else {
            floor + 1.0
        }
    } else {
        scaled.round()
    };
    rounded / 1000.0
}

fn build_fact(c: &Cluster, records: &[Record], anchor: usize) -> Value {
    let ex_full = redact::redact(&c.example);
    let ex: String = ex_full.chars().take(600).collect();
    let r = &records[c.ex_rec];

    let mut flags: Vec<String> = Vec::new();
    if c.pre == 0 && c.post > 0 {
        flags.push("new_after_incident".to_string());
    }
    if c.post == 0 && c.pre >= 2 && (c.first_rec as f64) < anchor as f64 * 0.5 {
        flags.push("went_silent".to_string());
    }
    if c.sev >= 0.8 {
        flags.push("error".to_string());
    }
    if c.prox >= 0.6 {
        flags.push("near_incident".to_string());
    }
    if c.causal > 0.0 {
        flags.push("shares_error_trace".to_string());
    }
    if c.example.contains('\n') {
        flags.push("multiline".to_string());
    }

    let traces_sorted: Vec<String> = {
        // c.traces is a BTreeSet (already sorted); take first 5.
        c.traces.iter().take(5).cloned().collect()
    };

    let mut m = Map::new();
    m.insert("fact_id".into(), json!(format!("F{}", c.id)));
    m.insert(
        "template".into(),
        json!(redact::redact(&render(&c.tok))),
    );
    m.insert("example".into(), json!(ex));
    m.insert("template_id".into(), json!(c.id));
    m.insert("count".into(), json!(c.count));
    m.insert("pre".into(), json!(c.pre));
    m.insert("post".into(), json!(c.post));
    m.insert("anomaly".into(), json!(round3(c.anomaly)));
    m.insert("severity".into(), json!(c.sev));
    m.insert("score".into(), json!(round3(c.score)));
    m.insert(
        "first_line".into(),
        json!(records[c.first_rec].start + 1),
    );
    m.insert("last_line".into(), json!(records[c.last_rec].start + 1));
    m.insert("span".into(), json!([r.start + 1, r.end + 1]));
    m.insert("level".into(), json!(c.level));
    m.insert("traces".into(), json!(traces_sorted));
    m.insert("flags".into(), json!(flags));
    Value::Object(m)
}

// ----------------------------------------------------------------- Python-faithful token length

/// Serialize a JSON value the way Python's `json.dumps(obj)` does by default:
/// item separator ", " and key separator ": ". Used only for the token estimate
/// (len // 4), to reproduce engine.py's budget behavior.
fn python_json(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            out.push('"');
            // serde_json's string escaping matches Python's default (ensure_ascii
            // aside). We use serde to escape the string body for correctness.
            let escaped = serde_json::to_string(s).unwrap();
            out.push_str(&escaped[1..escaped.len() - 1]);
            out.push('"');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                python_json(item, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, val)) in m.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push('"');
                let escaped = serde_json::to_string(k).unwrap();
                out.push_str(&escaped[1..escaped.len() - 1]);
                out.push_str("\": ");
                python_json(val, out);
            }
            out.push('}');
        }
    }
}

fn python_json_len(v: &Value) -> usize {
    let mut s = String::new();
    python_json(v, &mut s);
    s.chars().count()
}

// ----------------------------------------------------------------- selection

fn fact_score(f: &Value) -> f64 {
    f.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0)
}
fn fact_template_id(f: &Value) -> i64 {
    f.get("template_id").and_then(|v| v.as_i64()).unwrap_or(0)
}

fn select(
    clusters: &[Cluster],
    records: &[Record],
    budget: usize,
    anchor: usize,
) -> (Vec<Value>, usize) {
    let mut chosen: Vec<Value> = Vec::new();
    let mut used: BTreeSet<usize> = BTreeSet::new();
    let mut tok: usize = 0;

    let take = |c: &Cluster, chosen: &mut Vec<Value>, used: &mut BTreeSet<usize>, tok: &mut usize| {
        if used.contains(&c.id) {
            return;
        }
        let f = build_fact(c, records, anchor);
        used.insert(c.id);
        *tok += (python_json_len(&f) / 4).max(1);
        chosen.push(f);
    };

    // reserved: anomaly >= 0.999, sorted by -score, top 20.
    let mut anom: Vec<&Cluster> = clusters.iter().filter(|c| c.anomaly >= 0.999).collect();
    // Python sorted() is stable; sort by -score keeping original order on ties.
    anom.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
    for c in anom.into_iter().take(20) {
        take(c, &mut chosen, &mut used, &mut tok);
    }
    // every sev >= 0.8 (original cluster order).
    for c in clusters.iter().filter(|c| c.sev >= 0.8) {
        take(c, &mut chosen, &mut used, &mut tok);
    }
    // top 3 by count (stable).
    let mut by_count: Vec<&Cluster> = clusters.iter().collect();
    by_count.sort_by(|a, b| b.count.cmp(&a.count));
    for c in by_count.into_iter().take(3) {
        take(c, &mut chosen, &mut used, &mut tok);
    }
    // greedy by -score until budget.
    let mut by_score: Vec<&Cluster> = clusters.iter().collect();
    by_score.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
    for c in by_score {
        if tok >= budget {
            break;
        }
        take(c, &mut chosen, &mut used, &mut tok);
    }

    // final sort: (-score, template_id), stable.
    chosen.sort_by(|a, b| {
        match fact_score(b).partial_cmp(&fact_score(a)).unwrap() {
            std::cmp::Ordering::Equal => fact_template_id(a).cmp(&fact_template_id(b)),
            o => o,
        }
    });
    (chosen, tok)
}

// ----------------------------------------------------------------- build

pub fn build(raw_bytes: &[u8], budget_tokens: usize) -> (Value, String) {
    build_with_weights(raw_bytes, budget_tokens, &Weights::default())
}

pub fn build_with_weights(
    raw_bytes: &[u8],
    budget_tokens: usize,
    weights: &Weights,
) -> (Value, String) {
    let (capsule, h, _records, _clusters) = build_inner(raw_bytes, budget_tokens, weights);
    (capsule, h)
}

fn build_inner(
    raw_bytes: &[u8],
    budget_tokens: usize,
    weights: &Weights,
) -> (Value, String, Vec<Record>, Vec<Cluster>) {
    let r = res();
    let mut hasher = Sha256::new();
    hasher.update(raw_bytes);
    let full = hasher.finalize();
    let h: String = full.iter().map(|b| format!("{:02x}", b)).collect::<String>()[..16].to_string();

    let text = String::from_utf8_lossy(raw_bytes).into_owned();
    let mut raw_lines: Vec<String> = text.split('\n').map(|s| s.to_string()).collect();
    if raw_lines.last().map(|s| s.is_empty()).unwrap_or(false) {
        raw_lines.pop();
    }
    let n_lines = raw_lines.len();

    let mut records = to_records(&raw_lines);
    let n_rec = records.len();

    let mut drain = Drain::new(0.4);
    for i in 0..records.len() {
        let cid = drain.add(&records[i], i);
        records[i].cid = cid;
    }
    let mut clusters = drain.clusters;

    let err_idx: Option<usize> = records.iter().position(|r| r.sev >= 0.8);
    let anchor = match err_idx {
        Some(i) => i,
        None => (0.85 * n_rec as f64) as usize,
    };

    score_clusters(&mut clusters, anchor, n_rec, weights);
    let (facts, tok) = select(&clusters, &records, budget_tokens, anchor);

    // changes
    let mut changes: Vec<Value> = Vec::new();
    for rec in &records {
        if r.change.is_match(&rec.raw) {
            let txt: String = redact::redact(&rec.raw).chars().take(200).collect();
            changes.push(json!({"line": rec.start + 1, "text": txt}));
        }
    }
    changes.truncate(10);

    // hypotheses
    let mut hyps: Vec<Value> = Vec::new();
    let mut errf: Vec<&Value> = facts
        .iter()
        .filter(|f| flag_has(f, "error"))
        .collect();
    errf.sort_by(|a, b| fact_score(b).partial_cmp(&fact_score(a)).unwrap());
    let silent: Vec<&Value> = facts
        .iter()
        .filter(|f| flag_has(f, "went_silent"))
        .collect();
    if let Some(&top) = errf.first() {
        let mut rests: Vec<Value> = vec![top.get("fact_id").unwrap().clone()];
        let mut note: Vec<String> = Vec::new();
        if let Some(ch0) = changes.first() {
            note.push(format!(
                "a change at line {}",
                ch0.get("line").unwrap().as_i64().unwrap()
            ));
        }
        if let Some(&s0) = silent.first() {
            let tmpl = s0.get("template").unwrap().as_str().unwrap();
            // Python `%r` on a str -> single-quoted repr.
            note.push(format!("{} went silent", py_repr(tmpl)));
            rests.push(s0.get("fact_id").unwrap().clone());
        }
        let top_tmpl = top.get("template").unwrap().as_str().unwrap();
        let top_first_line = top.get("first_line").unwrap().as_i64().unwrap();
        let candidate = if note.is_empty() {
            format!("{} emerged near line {}", top_tmpl, top_first_line)
        } else {
            format!(
                "{} emerged near line {} correlated with {}",
                top_tmpl,
                top_first_line,
                note.join(", ")
            )
        };
        let confidence = if note.is_empty() { "low" } else { "medium" };
        hyps.push(json!({
            "candidate": candidate,
            "confidence": confidence,
            "rests_on": rests,
            "note": "candidate for the agent to verify against raw evidence, not an assertion",
        }));
    }

    // routine: top 3 by count.
    let mut by_count: Vec<&Cluster> = clusters.iter().collect();
    by_count.sort_by(|a, b| b.count.cmp(&a.count));
    let routine: Vec<Value> = by_count
        .iter()
        .take(3)
        .map(|c| json!({"template": redact::redact(&render(&c.tok)), "count": c.count}))
        .collect();

    let first_ts = records.first().map(|r| r.ts.clone()).unwrap_or_default();
    let last_ts = records.last().map(|r| r.ts.clone()).unwrap_or_default();

    let compression_x = round1(n_lines as f64 / (tok.max(1) as f64));

    let mut window = Map::new();
    window.insert("lines".into(), json!(n_lines));
    window.insert("records".into(), json!(n_rec));
    window.insert("first_ts".into(), json!(first_ts));
    window.insert("last_ts".into(), json!(last_ts));

    let mut index = Map::new();
    index.insert("capture_id".into(), json!(h));
    index.insert(
        "tools".into(),
        json!(["capsule", "search", "context", "trace", "verify"]),
    );

    let mut stats = Map::new();
    stats.insert("templates".into(), json!(clusters.len()));
    stats.insert("input_lines".into(), json!(n_lines));
    stats.insert("records".into(), json!(n_rec));
    stats.insert("capsule_tokens".into(), json!(tok));
    stats.insert("compression_x".into(), json!(compression_x));

    let mut capsule = Map::new();
    capsule.insert("schema".into(), json!("probe.capsule/v0"));
    capsule.insert("window".into(), Value::Object(window));
    capsule.insert("budget_tokens".into(), json!(budget_tokens));
    capsule.insert("evidence".into(), Value::Array(facts));
    capsule.insert("routine".into(), Value::Array(routine));
    capsule.insert("changes".into(), Value::Array(changes));
    capsule.insert("hypotheses".into(), Value::Array(hyps));
    capsule.insert("index".into(), Value::Object(index));
    capsule.insert("stats".into(), Value::Object(stats));

    (Value::Object(capsule), h, records, clusters)
}

fn flag_has(f: &Value, name: &str) -> bool {
    f.get("flags")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().any(|x| x.as_str() == Some(name)))
        .unwrap_or(false)
}

/// Python `%r` on a string: single quotes, with backslash/quote escaping.
fn py_repr(s: &str) -> String {
    // Mirror CPython repr for the common case (no embedded single+double mix
    // edge handling beyond the basics needed here).
    let has_single = s.contains('\'');
    let has_double = s.contains('"');
    let (quote, escape_quote) = if has_single && !has_double {
        ('"', '"')
    } else {
        ('\'', '\'')
    };
    let mut out = String::new();
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == escape_quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn round1(x: f64) -> f64 {
    let scaled = x * 10.0;
    let floor = scaled.floor();
    let diff = scaled - floor;
    let rounded = if (diff - 0.5).abs() < 1e-9 {
        if (floor as i64) % 2 == 0 {
            floor
        } else {
            floor + 1.0
        }
    } else {
        scaled.round()
    };
    rounded / 10.0
}

// ----------------------------------------------------------------- selftest incident generator

/// Deterministically generate a synthetic incident log with the testable
/// properties described in the spec.
pub fn generate_incident(n_lines: usize) -> String {
    let mut lines: Vec<String> = Vec::with_capacity(n_lines);
    // anchor (cascade) starts near 85%.
    let cascade_at = (0.85 * n_lines as f64) as usize;
    // Reserve a handful of cascade lines; routine fills the rest.
    let cascade_len = 8usize;
    let routine_lines = cascade_at;

    // deterministic timestamp generator (seconds since a base).
    let ts = |sec: usize| -> String {
        let base = 1_700_000_000usize + sec; // fixed base
        let h = (base / 3600) % 24;
        let m = (base / 60) % 60;
        let s = base % 60;
        // day component kept constant for determinism / shape.
        format!("2026-06-02T{:02}:{:02}:{:02}Z", h, m, s)
    };

    let mut sec = 0usize;
    // secret line near the top (line ~3).
    for i in 0..routine_lines {
        if i == 3 {
            lines.push(format!(
                "{} INFO auth token=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ5f7sVz1aBcDeFgHiJkLmNoPqRsTuVwXy req={}",
                ts(sec), 1000 + i
            ));
        } else if i % 500 == 0 {
            // heartbeat every 500 lines BEFORE the cascade only.
            lines.push(format!("{} INFO heartbeat ok seq={}", ts(sec), i));
        } else {
            // mostly routine INFO traffic with rotating shapes.
            match i % 4 {
                0 => lines.push(format!(
                    "{} INFO request served path=/api/items status=200 id=req{}",
                    ts(sec),
                    i
                )),
                1 => lines.push(format!(
                    "{} INFO cache hit key=user:{} latency_ms={}",
                    ts(sec),
                    i % 97,
                    1 + (i % 9)
                )),
                2 => lines.push(format!(
                    "{} DEBUG worker tick pool_in_use={} id=trace{}",
                    ts(sec),
                    i % 5,
                    i
                )),
                _ => lines.push(format!(
                    "{} INFO request served path=/api/users status=200 id=req{}",
                    ts(sec),
                    i
                )),
            }
        }
        sec += 1;
    }

    // The cascade near 85%.
    lines.push(format!(
        "{} WARN db pool acquire slow waited_ms=512 id=abc123",
        ts(sec)
    ));
    sec += 1;
    // ERROR with multiline traceback (continuation lines have NO timestamp).
    lines.push(format!(
        "{} ERROR psycopg2.OperationalError: could not connect to server id=abc124",
        ts(sec)
    ));
    sec += 1;
    lines.push("Traceback (most recent call last):".to_string());
    lines.push("  File \"/app/db.py\", line 88, in acquire".to_string());
    lines.push("    conn = pool.getconn()".to_string());
    lines.push("psycopg2.OperationalError: connection pool exhausted".to_string());
    // ERROR retry / pool exhausted.
    lines.push(format!(
        "{} ERROR retry failed pool exhausted attempts=3 id=abc124",
        ts(sec)
    ));
    sec += 1;
    // WARN circuit breaker / p99.
    lines.push(format!(
        "{} WARN circuit breaker open p99_ms=2300 id=abc125",
        ts(sec)
    ));
    sec += 1;

    // Pad remaining lines (if any room left) AFTER the cascade with a few
    // post-incident records, but no heartbeats (heartbeats are pre-cascade only).
    let produced = lines.len();
    if produced < n_lines {
        for j in produced..n_lines {
            lines.push(format!(
                "{} ERROR retry failed pool exhausted attempts=3 id=abc124",
                ts(sec)
            ));
            sec += 1;
            let _ = j;
        }
    } else if produced > n_lines {
        lines.truncate(n_lines);
    }
    let _ = cascade_len;

    let mut s = lines.join("\n");
    s.push('\n');
    s
}

// ----------------------------------------------------------------- capture (CLP store) + drill-down

/// Build a capsule AND persist a CLP-style capture (store.clp + meta.json +
/// capsule.json) under `<cache_dir>/captures/<id>/`. Returns (capsule, id).
pub fn build_capture(raw_bytes: &[u8], budget_tokens: usize, cache_dir: &str) -> (Value, String) {
    let (capsule, h, records, clusters) = build_inner(raw_bytes, budget_tokens, &Weights::default());
    write_capture(cache_dir, &h, &records, &clusters, &capsule);
    (capsule, h)
}

fn write_capture(cache_dir: &str, h: &str, records: &[Record], clusters: &[Cluster], capsule: &Value) {
    let dir = format!("{}/captures/{}", cache_dir, h);
    std::fs::create_dir_all(&dir).unwrap();

    // CLP-style lossless columnar store: dedup logtype dict + per-record (ts, id, vars).
    let mut lt_id: HashMap<String, usize> = HashMap::new();
    let mut logtypes: Vec<String> = Vec::new();
    let mut rows: Vec<(String, usize, Vec<String>)> = Vec::with_capacity(records.len());
    for rec in records {
        let (ts, lt, vars) = clp::encode(&rec.raw);
        let id = *lt_id.entry(lt.clone()).or_insert_with(|| {
            logtypes.push(lt.clone());
            logtypes.len() - 1
        });
        rows.push((ts, id, vars));
    }
    let blocks = clp::write_store(&format!("{}/store.clp", dir), &rows, 8192);

    let records_json: Vec<Value> = records
        .iter()
        .map(|r| json!([r.start + 1, r.end + 1, r.cid, r.level, ""]))
        .collect();
    let clusters_json: Vec<Value> = clusters
        .iter()
        .map(|c| json!({"id": c.id, "template": render(&c.tok), "count": c.count, "level": c.level, "recs": c.recs}))
        .collect();
    let mut traces: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, r) in records.iter().enumerate() {
        for t in &r.traces {
            traces.entry(t.clone()).or_default().push(i);
        }
    }
    let blocks_json: Vec<Value> = blocks.iter().map(|b| json!([b.0, b.1, b.2])).collect();

    let meta = json!({
        "n_lines": capsule["window"]["lines"],
        "records": records_json,
        "clusters": clusters_json,
        "traces": traces,
        "logtypes": logtypes,
        "blocks": blocks_json,
    });
    std::fs::write(format!("{}/meta.json", dir), serde_json::to_string(&meta).unwrap()).unwrap();
    std::fs::write(
        format!("{}/capsule.json", dir),
        serde_json::to_string_pretty(capsule).unwrap(),
    )
    .unwrap();
}

#[derive(Deserialize)]
struct ClusterMeta {
    template: String,
    recs: Vec<usize>,
}

#[derive(Deserialize)]
struct Meta {
    records: Vec<(usize, usize, usize, String, String)>,
    clusters: Vec<ClusterMeta>,
    traces: BTreeMap<String, Vec<usize>>,
    logtypes: Vec<String>,
    blocks: Vec<(usize, u64, usize)>,
}

/// Read-only drill-down over a CLP capture. Random access decodes only the
/// block(s) a lookup touches (seekable retention).
pub struct Loader {
    meta: Meta,
    capsule: Value,
    reader: clp::Reader,
    starts: Vec<usize>,
}

impl Loader {
    pub fn open(capture_id: &str, cache_dir: &str) -> Loader {
        let dir = format!("{}/captures/{}", cache_dir, capture_id);
        let meta: Meta =
            serde_json::from_str(&std::fs::read_to_string(format!("{}/meta.json", dir)).unwrap()).unwrap();
        let capsule: Value =
            serde_json::from_str(&std::fs::read_to_string(format!("{}/capsule.json", dir)).unwrap()).unwrap();
        let reader = clp::Reader::open(&format!("{}/store.clp", dir), meta.blocks.clone(), meta.logtypes.clone());
        let starts = meta.records.iter().map(|r| r.0).collect();
        Loader { meta, capsule, reader, starts }
    }

    pub fn capsule(&self) -> &Value {
        &self.capsule
    }
    pub fn blocks(&self) -> usize {
        self.meta.blocks.len()
    }
    pub fn decoded_blocks(&self) -> usize {
        self.reader.cached()
    }

    /// Full lossless reconstruction from the store (round-trip invariant).
    pub fn all_lines(&mut self) -> Vec<String> {
        let n = self.meta.records.len();
        let mut out = Vec::new();
        for i in 0..n {
            for line in self.reader.record_text(i).split('\n') {
                out.push(line.to_string());
            }
        }
        out
    }

    /// Physical lines [a,b] (1-based inclusive), decoding only overlapping records.
    pub fn lines(&mut self, a: usize, b: usize) -> Vec<(usize, String)> {
        let mut ri = self.starts.partition_point(|&x| x <= a).saturating_sub(1);
        let n = self.meta.records.len();
        let mut out = Vec::new();
        while ri < n && self.meta.records[ri].0 <= b {
            let s = self.meta.records[ri].0;
            for (k, line) in self.reader.record_text(ri).split('\n').enumerate() {
                let gl = s + k;
                if a <= gl && gl <= b {
                    out.push((gl, line.to_string()));
                }
            }
            ri += 1;
        }
        out
    }

    /// Re-derive a fact's count from the store + return sample raw lines (soundness).
    pub fn verify(&mut self, fact_id: &str) -> Value {
        let cid: usize = fact_id.trim_start_matches('F').parse().unwrap();
        let recomputed = self.meta.clusters[cid].recs.len();
        let template = self.meta.clusters[cid].template.clone();
        let cap_count = self.capsule["evidence"]
            .as_array()
            .and_then(|a| a.iter().find(|f| f["fact_id"].as_str() == Some(fact_id)))
            .and_then(|f| f["count"].as_u64());
        let recs: Vec<usize> = self.meta.clusters[cid].recs.iter().take(5).cloned().collect();
        let mut samples: Vec<Value> = Vec::new();
        for ridx in recs {
            let s = self.meta.records[ridx].0;
            let txt: String = redact::redact(&self.reader.record_text(ridx)).chars().take(400).collect();
            samples.push(json!({"line": s, "text": txt}));
        }
        json!({
            "fact_id": fact_id,
            "template": template,
            "recomputed_count": recomputed,
            "capsule_count": cap_count,
            "matches": cap_count == Some(recomputed as u64),
            "samples": samples,
        })
    }

    /// All lines sharing a trace id (single-stream here; cross-service in Python).
    pub fn trace(&mut self, trace_id: &str) -> Value {
        let idxs: Vec<usize> = self.meta.traces.get(trace_id).cloned().unwrap_or_default();
        let mut lines: Vec<Value> = Vec::new();
        for &ridx in idxs.iter().take(200) {
            let (s, lvl, svc) = {
                let r = &self.meta.records[ridx];
                (r.0, r.3.clone(), r.4.clone())
            };
            let txt: String = redact::redact(&self.reader.record_text(ridx)).chars().take(400).collect();
            lines.push(json!({"line": s, "level": lvl, "service": svc, "text": txt}));
        }
        json!({"trace": trace_id, "count": idxs.len(), "lines": lines})
    }
}
