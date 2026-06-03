//! CLP-style lossless, seekable columnar log store (Rust port of `probe/clp.py`).
//!
//! Each record splits into a timestamp column, a logtype (body with variables
//! replaced by a sentinel) deduplicated into a dictionary, and the variable
//! substrings. Records are written in independently-gzipped blocks with an offset
//! index, so a line lookup decodes only the block(s) it touches.

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::OnceLock;

const SENT: char = '\u{0}'; // variable slot
const COL: char = '\u{2}'; // column separator within a block
const VS: char = '\u{1}'; // variable separator within a record

struct CRes {
    ts: Regex,
    var: Regex,
}

fn cres() -> &'static CRes {
    static R: OnceLock<CRes> = OnceLock::new();
    R.get_or_init(|| CRes {
        ts: Regex::new(r"^(?:\[[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\]|\[\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\]]*\]|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\d{6}\s+\d{6}\b|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s*").unwrap(),
        var: Regex::new(
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b|\b0x[0-9a-fA-F]+\b|\b[0-9a-fA-F]{12,}\b|\b\d+\b",
        )
        .unwrap(),
    })
}

/// text -> (timestamp, logtype, [variables]). Reversible.
pub fn encode(text: &str) -> (String, String, Vec<String>) {
    let r = cres();
    let (ts, body): (String, &str) = match r.ts.find(text) {
        Some(m) => (text[..m.end()].to_string(), &text[m.end()..]),
        None => (String::new(), text),
    };
    if body.contains(SENT) {
        return (ts, SENT.to_string(), vec![body.to_string()]);
    }
    let mut vars = Vec::new();
    let mut lt = String::new();
    let mut last = 0usize;
    for m in r.var.find_iter(body) {
        lt.push_str(&body[last..m.start()]);
        lt.push(SENT);
        vars.push(m.as_str().to_string());
        last = m.end();
    }
    lt.push_str(&body[last..]);
    (ts, lt, vars)
}

/// (timestamp, logtype, [variables]) -> text. Exact inverse of encode().
pub fn decode(ts: &str, logtype: &str, vars: &[String]) -> String {
    let parts: Vec<&str> = logtype.split(SENT).collect();
    let mut out = String::from(ts);
    out.push_str(parts[0]);
    for (i, v) in vars.iter().enumerate() {
        out.push_str(v);
        out.push_str(parts[i + 1]);
    }
    out
}

/// Write rows (ts, logtype_id, vars) in gzip blocks. Returns [(first_record, byte_offset, byte_len)].
pub fn write_store(path: &str, rows: &[(String, usize, Vec<String>)], block_recs: usize) -> Vec<(usize, u64, usize)> {
    let mut f = File::create(path).unwrap();
    let mut blocks = Vec::new();
    let mut off: u64 = 0;
    let vs = VS.to_string();
    let mut i = 0usize;
    while i < rows.len() {
        let end = (i + block_recs).min(rows.len());
        let chunk = &rows[i..end];
        let ts_col = chunk.iter().map(|r| r.0.as_str()).collect::<Vec<_>>().join("\n");
        let id_col = chunk.iter().map(|r| r.1.to_string()).collect::<Vec<_>>().join("\n");
        let var_col = chunk.iter().map(|r| r.2.join(&vs)).collect::<Vec<_>>().join("\n");
        let payload = format!("{}{}{}{}{}", ts_col, COL, id_col, COL, var_col);
        let mut enc = GzEncoder::new(Vec::new(), Compression::new(6));
        enc.write_all(payload.as_bytes()).unwrap();
        let blob = enc.finish().unwrap();
        f.write_all(&blob).unwrap();
        blocks.push((i, off, blob.len()));
        off += blob.len() as u64;
        i = end;
    }
    blocks
}

/// Random access into the block store: O(one block) per record lookup.
pub struct Reader {
    path: String,
    blocks: Vec<(usize, u64, usize)>,
    firsts: Vec<usize>,
    logtypes: Vec<String>,
    cache: HashMap<usize, (usize, Vec<String>, Vec<String>, Vec<String>)>,
}

impl Reader {
    pub fn open(path: &str, blocks: Vec<(usize, u64, usize)>, logtypes: Vec<String>) -> Reader {
        let firsts = blocks.iter().map(|b| b.0).collect();
        Reader { path: path.to_string(), blocks, firsts, logtypes, cache: HashMap::new() }
    }

    pub fn cached(&self) -> usize {
        self.cache.len()
    }

    fn ensure(&mut self, bi: usize) {
        if self.cache.contains_key(&bi) {
            return;
        }
        let (first, off, len) = self.blocks[bi];
        let mut f = File::open(&self.path).unwrap();
        f.seek(SeekFrom::Start(off)).unwrap();
        let mut buf = vec![0u8; len];
        f.read_exact(&mut buf).unwrap();
        let mut dec = GzDecoder::new(&buf[..]);
        let mut payload = String::new();
        dec.read_to_string(&mut payload).unwrap();
        let cols: Vec<&str> = payload.split(COL).collect();
        let ts = cols[0].split('\n').map(|s| s.to_string()).collect();
        let ids = cols[1].split('\n').map(|s| s.to_string()).collect();
        let vars = cols[2].split('\n').map(|s| s.to_string()).collect();
        self.cache.insert(bi, (first, ts, ids, vars));
    }

    pub fn record_text(&mut self, idx: usize) -> String {
        let bi = self.firsts.partition_point(|&x| x <= idx) - 1;
        self.ensure(bi);
        let (first, ts, ids, vstrs) = self.cache.get(&bi).unwrap();
        let k = idx - first;
        let vstr = &vstrs[k];
        let vars: Vec<String> = if vstr.is_empty() {
            Vec::new()
        } else {
            vstr.split(VS).map(|s| s.to_string()).collect()
        };
        let lt = &self.logtypes[ids[k].parse::<usize>().unwrap()];
        decode(&ts[k], lt, &vars)
    }
}
