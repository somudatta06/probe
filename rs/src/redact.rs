//! Deterministic redaction at the local->cloud trust boundary (port of probe/redact.py).
//!
//! Catches real-format secrets (keyword may be glued after a prefix: db_password,
//! x-api-key, client_secret), structured keys, cards (Luhn), SSN, auth headers; a
//! high-entropy backstop catches bare blobs but PRESERVES UUIDs / hex SHAs / numeric
//! ids so `trace` keeps working. The regex crate is linear-time -> no ReDoS.

use regex::{Captures, Regex};
use std::collections::HashMap;
use std::sync::OnceLock;

struct Pats {
    whole: Vec<(&'static str, Regex)>,
    cc: Regex,
    auth: Regex,
    bearer: Regex,
    kv: Regex,
    email: Regex,
    long: Regex,
}

fn pats() -> &'static Pats {
    static P: OnceLock<Pats> = OnceLock::new();
    P.get_or_init(|| Pats {
        whole: vec![
            ("private_key", Regex::new(r"-----(?:BEGIN|END)[A-Z ]*PRIVATE KEY-----").unwrap()),
            ("jwt", Regex::new(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}").unwrap()),
            ("aws_key", Regex::new(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{12,20}\b").unwrap()),
            ("gcp_key", Regex::new(r"\bAIza[0-9A-Za-z_\-]{20,}\b").unwrap()),
            ("github_token", Regex::new(r"\bgh[pousr]_[0-9A-Za-z]{20,}\b").unwrap()),
            ("slack_token", Regex::new(r"\bxox[baprs]-[0-9A-Za-z-]{8,}").unwrap()),
            ("ssn", Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap()),
        ],
        cc: Regex::new(r"\b(?:\d[ -]?){13,19}\b").unwrap(),
        auth: Regex::new(r#"(?i)([\w\-]*auth[\w\-]*\s*[:=]\s*(?:basic |bearer |digest |token )?"?)([^"\s&;,]{3,})"#).unwrap(),
        bearer: Regex::new(r"(?i)(\bbearer\s+)([A-Za-z0-9._\-]{6,})").unwrap(),
        kv: Regex::new(r#"(?i)([\w.\-]*?(?:passw(?:or)?d|pwd|secret|token|api[_\-]?key|access[_\-]?key|secret[_\-]?key|credential|passphrase)\s*[=:]\s*"?)([^"\s&;,]+)"#).unwrap(),
        email: Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap(),
        long: Regex::new(r"[A-Za-z0-9]{20,}").unwrap(),
    })
}

fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    let mut n = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        n += 1;
    }
    let nf = n as f64;
    -counts.values().map(|&v| { let p = v as f64 / nf; p * p.log2() }).sum::<f64>()
}

fn luhn(d: &str) -> bool {
    let n = d.len();
    if !(13..=19).contains(&n) {
        return false;
    }
    let (mut total, mut alt) = (0u32, false);
    for ch in d.chars().rev() {
        let mut x = ch as u32 - 48;
        if alt {
            x *= 2;
            if x > 9 {
                x -= 9;
            }
        }
        total += x;
        alt = !alt;
    }
    total % 10 == 0
}

pub fn redact(text: &str) -> String {
    if text.is_empty() {
        return text.to_string();
    }
    let p = pats();
    let mut out = text.to_string();
    for (name, pat) in &p.whole {
        out = pat.replace_all(&out, format!("<redacted:{}>", name).as_str()).into_owned();
    }
    out = p.cc.replace_all(&out, |c: &Captures| {
        let digits: String = c[0].chars().filter(|ch| ch.is_ascii_digit()).collect();
        if luhn(&digits) { "<redacted:card>".to_string() } else { c[0].to_string() }
    }).into_owned();
    out = p.auth.replace_all(&out, |c: &Captures| format!("{}<redacted:auth>", &c[1])).into_owned();
    out = p.bearer.replace_all(&out, |c: &Captures| format!("{}<redacted:bearer>", &c[1])).into_owned();
    out = p.kv.replace_all(&out, |c: &Captures| format!("{}<redacted:kv_secret>", &c[1])).into_owned();
    out = p.email.replace_all(&out, "<redacted:email>").into_owned();
    out = p.long.replace_all(&out, |c: &Captures| {
        let tok = &c[0];
        if tok.contains("<redacted")
            || tok.chars().all(|ch| ch.is_ascii_digit())
            || tok.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            tok.to_string()
        } else if entropy(tok) >= 3.6 {
            "<redacted:highentropy>".to_string()
        } else {
            tok.to_string()
        }
    }).into_owned();
    out
}

#[allow(dead_code)]
pub fn has_secret(text: &str) -> bool {
    !text.is_empty() && redact(text).contains("<redacted")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_real_format_secrets() {
        for s in [
            "db_password=hunter2", "client_secret=abc123def", "access_token=zzz9tok",
            "card=4111111111111111", "ssn=123-45-6789", "X-Internal-Auth: t0knQx7",
            "Authorization: Basic dXNlcjpwYXNz", "x-api-key=AKIAIOSFODNN7EXAMPLE",
        ] {
            assert!(redact(s).contains("<redacted"), "leaked: {}", s);
        }
    }

    #[test]
    fn preserves_trace_identifiers() {
        for s in [
            "psycopg2.OperationalError: pool exhausted",
            "request_id=550e8400-e29b-41d4-a716-446655440000",
            "commit=9f2c3a1b4d5e6f70819a2b3c4d5e6f7081920304",
            "order_id=1234567890123456",
        ] {
            assert!(!redact(s).contains("<redacted"), "over-redacted: {}", s);
        }
    }
}
