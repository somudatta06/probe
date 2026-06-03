"""Deterministic synthetic incident-log generator.

Plants a known root-cause cascade (pool exhaustion -> psycopg2 error with a
multiline traceback -> retries -> circuit breaker) in a sea of routine noise,
plus a secret (to test redaction) and a heartbeat that goes silent after the
incident (to test baseline-shift detection). No randomness -> reproducible.
"""
import os

_ROUTINE = [
    "INFO  request id={tid} path=/v1/users 200",
    "INFO  cache hit user:{n}",
    "INFO  health probe ok 200",
    "INFO  redis ping ok 0.6ms",
    "INFO  request id={tid} path=/v1/orders 200",
    "INFO  cache miss user:{n}",
    "DEBUG gc pause 2ms",
]

SECRET_MARK = "eyJ"  # JWT prefix; must NOT survive into the capsule.


def _cascade(kind):
    """Return (events, gold) for an incident archetype. Events are
    ("add", text) timestamped lines or ("raw", text) continuation lines
    (no timestamp -> grouped into the preceding multiline record)."""
    C = {
        "db_pool": ([
            ("add", "INFO  deploy released sha=9f2c3a1 service=db version=v2.3.1"),
            ("add", "WARN  pool acquire 240ms"),
            ("add", "WARN  pool acquire 480ms"),
            ("add", "ERROR psycopg2.OperationalError: could not connect to server id=abc124"),
            ("raw", "Traceback (most recent call last):"),
            ("raw", '  File "/app/db.py", line 42, in connect'),
            ("raw", "    conn = pool.acquire(timeout=5)"),
            ("raw", "psycopg2.OperationalError: connection pool exhausted"),
            ("add", "ERROR retry 1/3 db_users id=abc124"),
            ("add", "ERROR retry 2/3 db_users id=abc124"),
            ("add", "ERROR pool exhausted, queue=18 id=abc125"),
            ("add", "WARN  circuit breaker open svc=db"),
            ("add", "WARN  p99 latency 2840ms"),
        ], ["psycopg2.OperationalError", "pool exhausted"]),
        "oom": ([
            ("add", "INFO  deploy released sha=7a1b2c3 service=worker version=v4.1.0"),
            ("add", "WARN  gc overhead 78% pause 1200ms"),
            ("add", "ERROR java.lang.OutOfMemoryError: Java heap space id=req55"),
            ("raw", "\tat com.app.Cache.load(Cache.java:88)"),
            ("raw", "\tat com.app.Handler.handle(Handler.java:42)"),
            ("raw", "Caused by: java.lang.OutOfMemoryError: Java heap space"),
            ("add", "ERROR container OOMKilled pod=worker-3 id=req55"),
            ("add", "WARN  restarting worker pod=worker-3"),
            ("add", "WARN  p99 latency 5200ms"),
        ], ["OutOfMemoryError", "OOMKilled"]),
        "disk_full": ([
            ("add", "INFO  deploy released sha=33ddee1 service=ingest version=v2.0.0"),
            ("add", "WARN  disk usage 92% mount=/data"),
            ("add", "ERROR write failed: No space left on device path=/data/seg id=req77"),
            ("raw", "Traceback (most recent call last):"),
            ("raw", '  File "/app/io.py", line 12, in flush'),
            ("raw", "OSError: [Errno 28] No space left on device"),
            ("add", "ERROR disk usage 100% mount=/data id=req77"),
            ("add", "WARN  shedding writes svc=ingest"),
            ("add", "WARN  p99 latency 3100ms"),
        ], ["No space left on device", "disk usage 100%"]),
        "cert_expiry": ([
            ("add", "INFO  deploy released sha=99ffaa2 service=gateway version=v3.3.3"),
            ("add", "WARN  cert age 89d host=api.internal"),
            ("add", "ERROR x509: certificate has expired or is not yet valid id=req91"),
            ("raw", "Traceback (most recent call last):"),
            ("raw", '  File "/app/tls.py", line 5, in handshake'),
            ("raw", "ssl.SSLCertVerificationError: certificate has expired"),
            ("add", "ERROR TLS handshake error host=api.internal id=req91"),
            ("add", "WARN  upstream unreachable svc=gateway"),
            ("add", "WARN  p99 latency 4400ms"),
        ], ["certificate has expired", "TLS handshake"]),
    }
    return C[kind]


GOLD_BY_KIND = {k: _cascade(k)[1] for k in ("db_pool", "oom", "disk_full", "cert_expiry")}
GOLD = GOLD_BY_KIND["db_pool"]  # default archetype (used by cli.selftest)


def _ts(sec):
    return "2026-05-04T%02d:%02d:%02dZ" % (14 + sec // 3600, (sec // 60) % 60, sec % 60)


def generate(n_lines, out_path, kind="db_pool"):
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    lines = []
    sec = [0]

    def add(msg):
        if len(lines) % 50 == 0:
            sec[0] += 1
        lines.append("%s %s" % (_ts(sec[0]), msg))

    anchor = max(20, int(n_lines * 0.85))

    add("INFO  pod/api-7f9 starting...")
    add("INFO  loaded config /etc/api")
    add("INFO  postgres pool size=20")
    add("INFO  auth session token=Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV1adQssw5c")

    ridx = 0
    while len(lines) < anchor:
        if len(lines) % 500 == 0:
            add("INFO  heartbeat ok seq=%d" % (len(lines) // 500))
        t = _ROUTINE[ridx % len(_ROUTINE)]
        add(t.format(tid="abc%d" % (100 + ridx % 800), n=ridx % 100))
        ridx += 1

    # change marker + root-cause cascade for this archetype (gold)
    for mode, text in _cascade(kind)[0]:
        if mode == "add":
            add(text)
        else:
            lines.append(text)

    # degraded tail: routine continues, heartbeat is now silent, sporadic 500s
    while len(lines) < n_lines:
        if ridx % 7 == 0:
            add("ERROR upstream timeout id=abc%d" % (100 + ridx % 800))
        else:
            t = _ROUTINE[ridx % len(_ROUTINE)]
            add(t.format(tid="abc%d" % (100 + ridx % 800), n=ridx % 100))
        ridx += 1

    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return len(lines)


def generate_multi(n_lines, out_dir, kind="db_pool", trace="abc124"):
    """Two services sharing a trace id: 'db' carries the root cause (the cascade),
    'api' carries the symptom (timeouts on the same request). Returns [(svc, path)].
    Cross-service stitching is demonstrated with kind='db_pool' (its cascade uses
    id=abc124)."""
    os.makedirs(out_dir, exist_ok=True)
    half = max(40, n_lines // 2)
    db = os.path.join(out_dir, "db.log")
    generate(half, db, kind=kind)

    api_lines, sec = [], [0]

    def add(msg):
        if len(api_lines) % 50 == 0:
            sec[0] += 1
        api_lines.append("%s %s" % (_ts(sec[0]), msg))

    anchor = max(20, int(half * 0.85))
    ridx = 0
    while len(api_lines) < anchor:
        add(_ROUTINE[ridx % len(_ROUTINE)].format(tid="abc%d" % (100 + ridx % 800), n=ridx % 100))
        ridx += 1
    for _ in range(8):
        add("ERROR upstream timeout id=%s waiting on db" % trace)
    while len(api_lines) < half:
        add(_ROUTINE[ridx % len(_ROUTINE)].format(tid="abc%d" % (100 + ridx % 800), n=ridx % 100))
        ridx += 1

    api = os.path.join(out_dir, "api.log")
    with open(api, "w") as f:
        f.write("\n".join(api_lines) + "\n")
    return [("api", api), ("db", db)]
