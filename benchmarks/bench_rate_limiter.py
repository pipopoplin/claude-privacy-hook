#!/usr/bin/env python3
"""Benchmark the rate limiter — subprocess and in-process violation counting."""

import json
import os
import subprocess
import sys
import tempfile
import time

BENCH_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BENCH_DIR)
HOOKS_DIR = os.path.join(PROJECT_ROOT, ".claude", "hooks")
sys.path.insert(0, HOOKS_DIR)

RATE_LIMITER = os.path.join(HOOKS_DIR, "rate_limiter.py")
RATE_LIMITER_CONFIG = os.path.join(HOOKS_DIR, "rate_limiter_config.json")


def _now_ts():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def _make_audit_log(n_entries, session_id="bench-session"):
    """Create a temp audit log with n_entries deny violations."""
    fd, path = tempfile.mkstemp(suffix=".log", prefix="bench_rl_")
    ts = _now_ts()
    with os.fdopen(fd, "w") as f:
        for i in range(n_entries):
            entry = {
                "timestamp": ts,
                "filter": "regex_filter",
                "rule_name": f"rule_{i % 5}",
                "action": "deny",
                "matched_patterns": [f"pattern_{i}"],
                "command_hash": f"sha256:{'a' * 64}",
                "command_preview": "test",
                "session_id": session_id,
            }
            f.write(json.dumps(entry) + "\n")
    return path


def _hook_input(session_id="bench-session"):
    return {
        "session_id": session_id,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo test"},
    }


# =====================================================================
# Subprocess benchmarks
# =====================================================================

def bench_subprocess(label, log_entries, iterations=50):
    log_path = _make_audit_log(log_entries)
    env = {**os.environ, "HOOK_AUDIT_LOG": log_path}
    stdin = json.dumps(_hook_input())

    # Warmup
    subprocess.run([sys.executable, RATE_LIMITER, RATE_LIMITER_CONFIG],
                   input=stdin, capture_output=True, text=True, env=env)

    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        subprocess.run([sys.executable, RATE_LIMITER, RATE_LIMITER_CONFIG],
                       input=stdin, capture_output=True, text=True, env=env)
        times.append((time.perf_counter() - t0) * 1000)

    os.unlink(log_path)

    times.sort()
    p50 = times[len(times) // 2]
    p95 = times[int(len(times) * 0.95)]
    mean = sum(times) / len(times)
    return label, iterations, mean, p50, p95


# =====================================================================
# In-process benchmarks
# =====================================================================

def bench_log_parsing(label, log_entries, iterations=1000):
    """Benchmark audit log reading and violation counting."""
    log_path = _make_audit_log(log_entries)

    # Read the log content once
    with open(log_path) as f:
        lines = f.readlines()

    # Warmup
    for _ in range(5):
        count = 0
        ts_cutoff = _now_ts()
        for line in lines:
            try:
                entry = json.loads(line)
                if (entry.get("session_id") == "bench-session"
                        and entry.get("action") in ("deny", "ask")
                        and entry.get("timestamp", "") >= ts_cutoff[:10]):
                    count += 1
            except json.JSONDecodeError:
                pass

    t0 = time.perf_counter()
    for _ in range(iterations):
        count = 0
        for line in lines:
            try:
                entry = json.loads(line)
                if (entry.get("session_id") == "bench-session"
                        and entry.get("action") in ("deny", "ask")):
                    count += 1
            except json.JSONDecodeError:
                pass
    elapsed = (time.perf_counter() - t0) * 1000

    os.unlink(log_path)

    per_call = elapsed / iterations
    ops = iterations / (elapsed / 1000) if elapsed > 0 else float("inf")
    return label, iterations, per_call, ops


def main():
    print("=" * 78)
    print("Rate Limiter Benchmark")
    print("=" * 78)

    # --- Subprocess ---
    print()
    print("  Subprocess (end-to-end latency)")
    print()
    print(f"  {'Scenario':<45} {'N':>5} {'Mean':>8} {'p50':>8} {'p95':>8}")
    print(f"  {'-'*45} {'---':>5} {'---':>8} {'---':>8} {'---':>8}")

    for entries in [0, 5, 10, 50, 100, 500, 1000]:
        label = f"Audit log: {entries} entries"
        name, n, mean, p50, p95 = bench_subprocess(label, entries, iterations=50)
        print(f"  {name:<45} {n:>5} {mean:>7.1f}ms {p50:>7.1f}ms {p95:>7.1f}ms")

    # --- In-process: log parsing ---
    print()
    print("  In-process (JSONL parsing + violation counting)")
    print()
    print(f"  {'Scenario':<45} {'N':>6} {'per call':>10} {'ops/sec':>12}")
    print(f"  {'-'*45} {'---':>6} {'---':>10} {'---':>12}")

    for entries in [0, 10, 50, 100, 500, 1000]:
        label = f"Parse {entries} entries"
        iters = 5000 if entries <= 100 else 1000 if entries <= 500 else 200
        name, n, per_call, ops = bench_log_parsing(label, entries, iterations=iters)
        print(f"  {name:<45} {n:>6} {per_call:>8.3f}ms {ops:>10,.0f}/s")

    print()


if __name__ == "__main__":
    main()
