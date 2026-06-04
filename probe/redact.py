"""Deterministic redaction at the local->cloud trust boundary.

Raw logs stay unredacted on disk (local ground truth). Anything crossing to a
cloud agent (capsule + tool payloads) is redacted. `--trust local` skips this.

Design (hardened after adversarial review on real logs):
- secret keywords match even when GLUED after a prefix (db_password, x-api-key,
  client_secret, access_token) — the most common real form;
- structured secrets (JWT, AWS/GCP/GitHub/Slack keys, PEM, card via Luhn, SSN,
  auth headers incl. the credential after a scheme);
- a high-entropy backstop for unprefixed blobs that EXCLUDES '-', '.', '_' so
  UUIDs / dotted ids / snake_case survive, and preserves pure hex (git SHAs) and
  pure-digit ids — redaction must not destroy the trace IDs `trace` depends on;
- bounded quantifiers + no cross-line scans -> no catastrophic backtracking.
"""
import re
import math
from collections import Counter


def _entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in Counter(s).values())


def _luhn(d):
    if not (13 <= len(d) <= 19):
        return False
    total, alt = 0, False
    for ch in reversed(d):
        n = ord(ch) - 48
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


# whole-match structured secrets (all bounded; no [\s\S] cross-line scan -> no ReDoS)
_WHOLE = [
    ("private_key", re.compile(r"-----(?:BEGIN|END)[A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{12,20}\b")),
    ("gcp_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{8,}")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]
_CC = re.compile(r"\b(?:\d[ -]?){13,19}\b")
# keep the key/scheme, redact the value:
_AUTH = re.compile(r'(?i)([\w\-]*auth[\w\-]*\s*[:=]\s*(?:basic |bearer |digest |token )?"?)([^"\s&;,]{3,})')
_BEARER = re.compile(r"(?i)(\bbearer\s+)([A-Za-z0-9._\-]{6,})")
_KV = re.compile(
    r'(?i)([\w.\-]*?(?:passw(?:or)?d|pwd|secret|token|api[_\-]?key|access[_\-]?key'
    r'|secret[_\-]?key|credential|passphrase)\s*[=:]\s*"?)([^"\s&;,]+)'
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
# entropy backstop token: alphanumerics only (no -._=+/) so UUIDs, dotted ids,
# snake_case, and `word=hexid` can't glue into one token. Contextualized base64
# secrets (key=<base64>) are already caught by the kv/structured patterns above.
_LONG = re.compile(r"[A-Za-z0-9]{20,}")
_HEX = re.compile(r"[0-9a-fA-F]+\Z")


def _ent_sub(m):
    tok = m.group(0)
    if "<redacted" in tok or tok.isdigit() or _HEX.match(tok):
        return tok                                   # marker / numeric id / hex id (git sha) -> keep
    return "<redacted:highentropy>" if _entropy(tok) >= 3.6 else tok


def _cc_sub(m):
    return "<redacted:card>" if _luhn(re.sub(r"\D", "", m.group(0))) else m.group(0)


def redact(text):
    """Replace secrets with <redacted:type> markers (idempotent, ReDoS-safe)."""
    if not text:
        return text
    out = text
    for name, pat in _WHOLE:
        out = pat.sub("<redacted:%s>" % name, out)
    out = _CC.sub(_cc_sub, out)
    out = _AUTH.sub(lambda m: m.group(1) + "<redacted:auth>", out)
    out = _BEARER.sub(lambda m: m.group(1) + "<redacted:bearer>", out)
    out = _KV.sub(lambda m: m.group(1) + "<redacted:kv_secret>", out)
    out = _EMAIL.sub("<redacted:email>", out)
    out = _LONG.sub(_ent_sub, out)
    return out


def has_secret(text):
    return bool(text) and "<redacted" in redact(text)
