//! Deterministic redaction at the local->cloud trust boundary.
//!
//! Port of `probe/redact.py`. Raw logs stay unredacted on disk; anything that
//! crosses into the capsule is redacted. Patterns are applied in order, then a
//! backstop replaces long, dotless, high-entropy tokens.

use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

struct Patterns {
    list: Vec<(&'static str, Regex)>,
    long_token: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        list: vec![
            (
                "private_key",
                // [\s\S]*? -> `(?s).*?` in the regex crate (dot matches newline).
                Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?s).*?-----END [A-Z ]*PRIVATE KEY-----")
                    .unwrap(),
            ),
            (
                "jwt",
                Regex::new(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}").unwrap(),
            ),
            (
                "aws_key",
                Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(),
            ),
            (
                "bearer",
                Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{8,}").unwrap(),
            ),
            (
                "kv_secret",
                Regex::new(r"(?i)\b(?:pass(?:word)?|pwd|secret|token|api[_-]?key|authorization)\s*[=:]\s*\S+")
                    .unwrap(),
            ),
            (
                "email",
                Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap(),
            ),
        ],
        // Backstop: long, dotless, high-entropy tokens. Excludes ".".
        long_token: Regex::new(r"[A-Za-z0-9_\-+/=]{32,}").unwrap(),
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
    -counts
        .values()
        .map(|&v| {
            let p = v as f64 / nf;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Return text with secrets replaced by `<redacted:type>` markers.
pub fn redact(text: &str) -> String {
    if text.is_empty() {
        return text.to_string();
    }
    let p = patterns();
    let mut out = text.to_string();
    for (name, pat) in &p.list {
        out = pat
            .replace_all(&out, format!("<redacted:{}>", name).as_str())
            .into_owned();
    }
    // Entropy backstop: only replace a long dotless token if it is not already
    // part of a redaction marker and its Shannon entropy >= 4.0.
    p.long_token
        .replace_all(&out, |caps: &regex::Captures| {
            let tok = &caps[0];
            if tok.contains("<redacted") {
                tok.to_string()
            } else if entropy(tok) >= 4.0 {
                "<redacted:highentropy>".to_string()
            } else {
                tok.to_string()
            }
        })
        .into_owned()
}

#[allow(dead_code)]
pub fn has_secret(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    patterns().list.iter().any(|(_, pat)| pat.is_match(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_jwt() {
        let raw = "auth token=Bearer eyJhbGciOiJIUzI1Ni) but the jwt eyJabcdef.ghijkl.mnopqr ok";
        let r = redact(raw);
        assert!(!r.contains("eyJabcdef.ghijkl.mnopqr"));
    }

    #[test]
    fn keeps_dotted_identifiers() {
        // psycopg2.OperationalError must survive (has a dot, backstop excludes dots).
        let raw = "psycopg2.OperationalError: connection pool exhausted";
        assert_eq!(redact(raw), raw);
    }

    #[test]
    fn redacts_bearer() {
        let raw = "Authorization: Bearer abcdefghijklmnop";
        let r = redact(raw);
        assert!(r.contains("<redacted:"));
        assert!(!r.contains("abcdefghijklmnop"));
    }
}
