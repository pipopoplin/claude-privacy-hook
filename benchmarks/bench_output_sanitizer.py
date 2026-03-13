#!/usr/bin/env python3
"""Benchmark the output sanitizer — subprocess and in-process redaction."""

import json
import os
import subprocess
import sys
import time

BENCH_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BENCH_DIR)
HOOKS_DIR = os.path.join(PROJECT_ROOT, ".claude", "hooks")
sys.path.insert(0, HOOKS_DIR)

OUTPUT_SANITIZER = os.path.join(HOOKS_DIR, "output_sanitizer.py")
SANITIZER_RULES = os.path.join(HOOKS_DIR, "output_sanitizer_rules.json")

# Representative outputs
SAFE_OUTPUT = "Compiling src/main.rs...\nFinished release [optimized]\n42 tests passed"
API_KEY_OUTPUT = "Debug: token=sk-ant-abc123def456-xyz key=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
PII_OUTPUT = "SSN: 123-45-6789, card: 4111 1111 1111 1111, email: user@example.com"
DB_OUTPUT = "postgres://admin:secret@db.prod.internal:5432/mydb connected, host: 10.0.1.55:8080"
KEY_OUTPUT = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
MIXED_OUTPUT = (
    "Debug output:\n"
    "  token=sk-ant-abc123def456-xyz\n"
    "  SSN: 123-45-6789\n"
    "  card: 4111 1111 1111 1111\n"
    "  email: admin@company.com\n"
    "  db: postgres://root:pass@10.0.0.5:5432/app\n"
    "  -----BEGIN RSA PRIVATE KEY-----\n"
    "  MIIEpA...\n"
)
LARGE_SAFE = ("line: normal build output here\n" * 500)
LARGE_MIXED = ("safe line\n" * 50 + "token=sk-ant-abc123\n") * 10


def _hook_input(stdout, stderr=""):
    return {
        "session_id": "bench",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "test"},
        "tool_result": {"stdout": stdout, "stderr": stderr},
    }


# =====================================================================
# Subprocess benchmarks
# =====================================================================

def bench_subprocess(label, hook_input, iterations=50):
    stdin = json.dumps(hook_input)
    subprocess.run([sys.executable, OUTPUT_SANITIZER, SANITIZER_RULES],
                   input=stdin, capture_output=True, text=True)

    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        subprocess.run([sys.executable, OUTPUT_SANITIZER, SANITIZER_RULES],
                       input=stdin, capture_output=True, text=True)
        times.append((time.perf_counter() - t0) * 1000)

    times.sort()
    p50 = times[len(times) // 2]
    p95 = times[int(len(times) * 0.95)]
    p99 = times[int(len(times) * 0.99)]
    mean = sum(times) / len(times)
    return label, iterations, mean, p50, p95, p99


# =====================================================================
# In-process benchmarks
# =====================================================================

def bench_inprocess(label, stdout, iterations=5000):
    from output_sanitizer import load_config, _compile_patterns, redact_text

    config = load_config(SANITIZER_RULES)
    compiled = _compile_patterns(config["rules"])

    # Warmup
    for _ in range(10):
        redact_text(stdout, compiled)

    t0 = time.perf_counter()
    for _ in range(iterations):
        redact_text(stdout, compiled)
    elapsed = (time.perf_counter() - t0) * 1000

    per_call = elapsed / iterations
    ops = iterations / (elapsed / 1000) if elapsed > 0 else float("inf")
    return label, iterations, per_call, ops


def main():
    print("=" * 78)
    print("Output Sanitizer Benchmark")
    print("=" * 78)

    # --- Subprocess ---
    print()
    print("  Subprocess (end-to-end latency)")
    print()
    print(f"  {'Scenario':<45} {'N':>5} {'Mean':>8} {'p50':>8} {'p95':>8} {'p99':>8}")
    print(f"  {'-'*45} {'---':>5} {'---':>8} {'---':>8} {'---':>8} {'---':>8}")

    sub_scenarios = [
        ("Safe output (no redaction)", SAFE_OUTPUT),
        ("API keys (2 keys)", API_KEY_OUTPUT),
        ("PII (SSN + card + email)", PII_OUTPUT),
        ("DB conn + internal IP", DB_OUTPUT),
        ("Private key block", KEY_OUTPUT),
        ("Mixed (all rule types)", MIXED_OUTPUT),
        ("Large safe (500 lines)", LARGE_SAFE),
        ("Large mixed (510 lines, 10 keys)", LARGE_MIXED),
    ]

    for label, stdout in sub_scenarios:
        name, n, mean, p50, p95, p99 = bench_subprocess(
            label, _hook_input(stdout), iterations=50)
        print(f"  {name:<45} {n:>5} {mean:>7.1f}ms {p50:>7.1f}ms {p95:>7.1f}ms {p99:>7.1f}ms")

    # --- In-process ---
    print()
    print("  In-process (redact_text only, compiled rules cached)")
    print()
    print(f"  {'Scenario':<45} {'N':>6} {'per call':>10} {'ops/sec':>12}")
    print(f"  {'-'*45} {'---':>6} {'---':>10} {'---':>12}")

    inproc = [
        ("Safe output (no match)", SAFE_OUTPUT),
        ("API keys (2 keys)", API_KEY_OUTPUT),
        ("PII (SSN + card + email)", PII_OUTPUT),
        ("DB conn + internal IP", DB_OUTPUT),
        ("Private key block", KEY_OUTPUT),
        ("Mixed (all rule types)", MIXED_OUTPUT),
        ("Large safe (500 lines)", LARGE_SAFE),
        ("Large mixed (510 lines)", LARGE_MIXED),
    ]

    for label, stdout in inproc:
        name, n, per_call, ops = bench_inprocess(label, stdout, iterations=5000)
        print(f"  {name:<45} {n:>6} {per_call:>8.3f}ms {ops:>10,.0f}/s")

    print()


if __name__ == "__main__":
    main()
