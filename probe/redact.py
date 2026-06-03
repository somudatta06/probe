"""Deterministic redaction at the local->cloud trust boundary.

Raw logs stay unredacted on disk (local ground truth for verification).
Anything that crosses to a cloud agent (capsule + tool payloads) is redacted.
In local-model mode (--trust local) this pass is skipped by the caller.
"""
import re
import math
from collections import Counter

_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{8,}")),
    ("kv_secret", re.compile(r"(?i)\b(?:pass(?:word)?|pwd|secret|token|api[_-]?key|authorization)\s*[=:]\s*\S+")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
]

# Backstop for unprefixed secrets: long, dotless, high-entropy tokens only.
# Excludes "." so dotted identifiers (psycopg2.OperationalError, host names,
# versions) are never mistaken for secrets. Real JWTs are caught above.
_LONG_TOKEN = re.compile(r"[A-Za-z0-9_\-+/=]{32,}")


def _entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in Counter(s).values())


def redact(text):
    """Return text with secrets replaced by <redacted:type> markers."""
    if not text:
        return text
    out = text
    for name, pat in _PATTERNS:
        out = pat.sub("<redacted:%s>" % name, out)

    def _ent_sub(m):
        tok = m.group(0)
        if "<redacted" in tok:
            return tok
        return "<redacted:highentropy>" if _entropy(tok) >= 4.0 else tok

    return _LONG_TOKEN.sub(_ent_sub, out)


def has_secret(text):
    if not text:
        return False
    for _, pat in _PATTERNS:
        if pat.search(text):
            return True
    return False
