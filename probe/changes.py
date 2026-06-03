"""Change providers: 'what changed just before the incident?' — the #1 RCA
signal, and one that lives OUTSIDE the logs. These return change events that
build()/build_multi() merge into capsule.changes.

git_changes is real and runnable. k8s_changes is gated on a cluster (kubectl).
"""
import subprocess


def git_changes(repo, since="2 hours ago", max_n=10):
    """Recent commits as deploy/change events. Empty list if not a git repo."""
    try:
        out = subprocess.run(
            ["git", "-C", repo, "log", "--since", since, "--pretty=%h\t%cI\t%s", "-n", str(max_n)],
            capture_output=True, text=True, timeout=10)
    except Exception:
        return []
    evs = []
    for ln in out.stdout.splitlines():
        parts = ln.split("\t", 2)
        if len(parts) == 3:
            sha, ts, subj = parts
            evs.append({"type": "deploy", "source": "git", "ref": sha, "ts": ts, "text": subj[:160]})
    return evs


def k8s_changes(namespace="default"):
    """Deploy/scaling/restart events from a Kubernetes cluster (requires kubectl)."""
    fmt = '{range .items[*]}{.lastTimestamp}{"\\t"}{.reason}{"\\t"}{.message}{"\\n"}{end}'
    try:
        out = subprocess.run(
            ["kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp", "-o", "jsonpath=" + fmt],
            capture_output=True, text=True, timeout=10)
    except Exception:
        return []
    keep = {"ScalingReplicaSet", "Killing", "Created", "Started", "BackOff", "Unhealthy"}
    evs = []
    for ln in out.stdout.splitlines():
        parts = ln.split("\t", 2)
        if len(parts) == 3 and parts[1] in keep:
            evs.append({"type": "k8s", "source": "k8s", "ts": parts[0], "text": ("%s %s" % (parts[1], parts[2]))[:160]})
    return evs
