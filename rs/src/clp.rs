//! CLP-style lossless, seekable, TYPED columnar store (Rust port of `probe/clp.py`).
//!
//! The on-disk block format is byte-compatible with the Python store, so a capture
//! written by either engine is readable by the other's Loader. Per block:
//! gzip( frame[ ts_text, ids_varints, type_flags, str_text, int_delta_varints ] ).

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use regex::Regex;
use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::OnceLock;

pub const SENT: char = '\u{0}'; // variable slot inside a logtype

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
    out.push_str(parts.first().copied().unwrap_or(""));
    for (i, v) in vars.iter().enumerate() {
        out.push_str(v);
        out.push_str(parts.get(i + 1).copied().unwrap_or("")); // tolerate corrupt store
    }
    out
}

// ---------------------------------------------------------------- varint / zigzag / framing
fn intable(s: &str) -> bool {
    // all ASCII digits, no leading zero (unless "0"), fits i64 (else treat as string)
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if s.len() > 1 && s.as_bytes()[0] == b'0' {
        return false;
    }
    s.parse::<i64>().is_ok()
}

fn uvarint(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let b = (n & 0x7F) as u8;
        n >>= 7;
        if n != 0 {
            out.push(b | 0x80);
        } else {
            out.push(b);
            return;
        }
    }
}

fn read_uvarint(buf: &[u8], mut i: usize) -> (u64, usize) {
    let (mut shift, mut res) = (0u32, 0u64);
    loop {
        if i >= buf.len() || shift >= 64 {
            return (res, i); // truncated/garbage varint -> stop gracefully
        }
        let b = buf[i];
        i += 1;
        res |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return (res, i);
        }
        shift += 7;
    }
}

fn zz(n: i64) -> u64 {
    ((n << 1) ^ (n >> 63)) as u64
}
fn unzz(z: u64) -> i64 {
    ((z >> 1) as i64) ^ -((z & 1) as i64)
}

fn frame(sections: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in sections {
        uvarint(s.len() as u64, &mut out);
        out.extend_from_slice(s);
    }
    out
}

fn unframe(buf: &[u8]) -> Vec<Vec<u8>> {
    let mut secs = Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let (n, ni) = read_uvarint(buf, i);
        if ni > buf.len() {
            break;
        }
        let end = (ni + n as usize).min(buf.len()); // clamp a section that overruns the buffer
        secs.push(buf[ni..end].to_vec());
        i = end;
    }
    secs
}

fn gzip(payload: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::new(9));
    e.write_all(payload).unwrap();
    e.finish().unwrap()
}

fn gunzip(blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = GzDecoder::new(blob).read_to_end(&mut out); // corrupt gzip -> partial/empty, not a panic
    out
}

// ---------------------------------------------------------------- typed block codec
fn encode_block(chunk: &[(String, usize, Vec<String>)], nslots: &[usize]) -> Vec<u8> {
    let ts_text = chunk.iter().map(|r| r.0.as_str()).collect::<Vec<_>>().join("\n");
    let ids: Vec<usize> = chunk.iter().map(|r| r.1).collect();

    let mut slotvals: HashMap<(usize, usize), Vec<&str>> = HashMap::new();
    for (_, lid, vrs) in chunk {
        for (j, v) in vrs.iter().enumerate() {
            slotvals.entry((*lid, j)).or_default().push(v.as_str());
        }
    }
    let distinct: BTreeSet<usize> = ids.iter().cloned().collect();
    let (mut flags, mut int_blob, mut str_items): (Vec<u8>, Vec<u8>, Vec<&str>) =
        (Vec::new(), Vec::new(), Vec::new());
    for &lid in &distinct {
        for j in 0..nslots[lid] {
            let empty = Vec::new();
            let vals = slotvals.get(&(lid, j)).unwrap_or(&empty);
            let is_int = !vals.is_empty() && vals.iter().all(|v| intable(v));
            flags.push(if is_int { 1 } else { 0 });
            if is_int {
                let mut prev: i64 = 0;
                for v in vals {
                    let iv: i64 = v.parse().unwrap();
                    uvarint(zz(iv - prev), &mut int_blob);
                    prev = iv;
                }
            } else {
                str_items.extend(vals.iter().cloned());
            }
        }
    }
    let mut ids_blob = Vec::new();
    for &x in &ids {
        uvarint(x as u64, &mut ids_blob);
    }
    // length-prefix string values (a value may contain '\n' — '\n'-join would corrupt decode)
    let mut str_blob = Vec::new();
    for v in &str_items {
        let vb = v.as_bytes();
        uvarint(vb.len() as u64, &mut str_blob);
        str_blob.extend_from_slice(vb);
    }
    let payload = frame(&[ts_text.into_bytes(), ids_blob, flags, str_blob, int_blob]);
    gzip(&payload)
}

fn decode_block(blob: &[u8], logtypes: &[String], nslots: &[usize]) -> Vec<String> {
    let secs = unframe(&gunzip(blob));
    if secs.len() < 5 {
        return Vec::new(); // corrupt/truncated block -> no records, no panic
    }
    let ts_s = String::from_utf8_lossy(&secs[0]).into_owned();
    let ts: Vec<&str> = ts_s.split('\n').collect();
    let mut ids: Vec<usize> = Vec::new();
    let (idb, mut i) = (&secs[1], 0usize);
    while i < idb.len() {
        let (v, ni) = read_uvarint(idb, i);
        ids.push(v as usize);
        i = ni;
    }
    let flags = &secs[2];
    let mut str_items: Vec<String> = Vec::new();
    {
        let sb = &secs[3];
        let mut p = 0usize;
        while p < sb.len() {
            let (n, np) = read_uvarint(sb, p);
            let n = n as usize;
            str_items.push(String::from_utf8_lossy(&sb[np..np + n]).into_owned());
            p = np + n;
        }
    }
    let int_b = &secs[4];

    let mut counts: HashMap<usize, usize> = HashMap::new();
    for &x in &ids {
        *counts.entry(x).or_insert(0) += 1;
    }
    let distinct: BTreeSet<usize> = ids.iter().cloned().collect();
    let mut slotvals: HashMap<(usize, usize), Vec<String>> = HashMap::new();
    let (mut fi, mut bi, mut si) = (0usize, 0usize, 0usize);
    for &lid in &distinct {
        let c = counts[&lid];
        for j in 0..nslots[lid] {
            let is_int = flags[fi] == 1;
            fi += 1;
            if is_int {
                let (mut vals, mut prev) = (Vec::with_capacity(c), 0i64);
                for _ in 0..c {
                    let (z, ni) = read_uvarint(int_b, bi);
                    bi = ni;
                    prev += unzz(z);
                    vals.push(prev.to_string());
                }
                slotvals.insert((lid, j), vals);
            } else {
                slotvals.insert((lid, j), str_items[si..si + c].iter().map(|s| s.to_string()).collect());
                si += c;
            }
        }
    }
    let mut cur: HashMap<(usize, usize), usize> = HashMap::new();
    let mut out = Vec::with_capacity(ids.len());
    for (k, &lid) in ids.iter().enumerate() {
        let mut vars = Vec::with_capacity(nslots[lid]);
        for j in 0..nslots[lid] {
            let idx = cur.entry((lid, j)).or_insert(0);
            vars.push(slotvals[&(lid, j)][*idx].clone());
            *idx += 1;
        }
        out.push(decode(ts[k], &logtypes[lid], &vars));
    }
    out
}

/// Write rows (ts, logtype_id, vars) as typed gzip blocks. Returns [(first_record, byte_offset, byte_len)].
pub fn write_store(path: &str, rows: &[(String, usize, Vec<String>)], logtypes: &[String], block_recs: usize) -> Vec<(usize, u64, usize)> {
    let nslots: Vec<usize> = logtypes.iter().map(|lt| lt.matches(SENT).count()).collect();
    let mut f = File::create(path).unwrap();
    let mut blocks = Vec::new();
    let mut off: u64 = 0;
    let mut i = 0usize;
    while i < rows.len() {
        let end = (i + block_recs).min(rows.len());
        let blob = encode_block(&rows[i..end], &nslots);
        f.write_all(&blob).unwrap();
        blocks.push((i, off, blob.len()));
        off += blob.len() as u64;
        i = end;
    }
    blocks
}

/// Random access into the typed block store: decodes one block per lookup.
pub struct Reader {
    path: String,
    blocks: Vec<(usize, u64, usize)>,
    firsts: Vec<usize>,
    logtypes: Vec<String>,
    nslots: Vec<usize>,
    cache: HashMap<usize, (usize, Vec<String>)>,
}

impl Reader {
    pub fn open(path: &str, blocks: Vec<(usize, u64, usize)>, logtypes: Vec<String>) -> Reader {
        let firsts = blocks.iter().map(|b| b.0).collect();
        let nslots = logtypes.iter().map(|lt| lt.matches(SENT).count()).collect();
        Reader { path: path.to_string(), blocks, firsts, logtypes, nslots, cache: HashMap::new() }
    }

    pub fn cached(&self) -> usize {
        self.cache.len()
    }

    fn ensure(&mut self, bi: usize) {
        if self.cache.contains_key(&bi) {
            return;
        }
        let (first, off, len) = self.blocks[bi];
        // Tolerate a truncated/corrupt store: I/O errors yield an empty block, not a panic.
        let texts = (|| -> Option<Vec<String>> {
            let mut f = File::open(&self.path).ok()?;
            f.seek(SeekFrom::Start(off)).ok()?;
            let mut buf = vec![0u8; len];
            f.read_exact(&mut buf).ok()?;
            Some(decode_block(&buf, &self.logtypes, &self.nslots))
        })()
        .unwrap_or_default();
        self.cache.insert(bi, (first, texts));
    }

    pub fn record_text(&mut self, rec_idx: usize) -> String {
        let bi = self.firsts.partition_point(|&x| x <= rec_idx).saturating_sub(1);
        if bi >= self.blocks.len() {
            return String::new();
        }
        self.ensure(bi);
        match self.cache.get(&bi) {
            Some((first, texts)) => texts.get(rec_idx.saturating_sub(*first)).cloned().unwrap_or_default(),
            None => String::new(),
        }
    }
}
