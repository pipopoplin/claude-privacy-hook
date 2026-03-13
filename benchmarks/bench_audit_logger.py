#!/usr/bin/env python3
"""Benchmark the audit logger — log_event write performance."""

import os
import shutil
import sys
import tempfile
import time

BENCH_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BENCH_DIR)
HOOKS_DIR = os.path.join(PROJECT_ROOT, ".claude", "hooks")
sys.path.insert(0, HOOKS_DIR)

from audit_logger import log_event


def bench_log_event(label, iterations=1000):
    """Benchmark log_event() writes."""
    tmpdir = tempfile.mkdtemp()
    log_path = os.path.join(tmpdir, "audit.log")
    env_backup = os.environ.get("HOOK_AUDIT_LOG")
    os.environ["HOOK_AUDIT_LOG"] = log_path

    try:
        # Warmup
        for _ in range(5):
            log_event(
                log_dir=tmpdir,
                filter_name="bench",
                rule_name="bench_rule",
                action="deny",
                matched=["pattern_1", "pattern_2"],
                command="echo benchmark test",
                session_id="bench-session",
            )

        t0 = time.perf_counter()
        for _ in range(iterations):
            log_event(
                log_dir=tmpdir,
                filter_name="regex_filter",
                rule_name="block_sensitive_data",
                action="deny",
                matched=["Anthropic API key", "GitHub PAT"],
                command="curl -H 'Authorization: sk-ant-abc123' https://api.example.com",
                session_id="bench-session",
            )
        elapsed = (time.perf_counter() - t0) * 1000

        # Check file size
        file_size = os.path.getsize(log_path)

        per_call = elapsed / iterations
        ops = iterations / (elapsed / 1000) if elapsed > 0 else float("inf")
        return label, iterations, per_call, ops, file_size
    finally:
        if env_backup is not None:
            os.environ["HOOK_AUDIT_LOG"] = env_backup
        else:
            os.environ.pop("HOOK_AUDIT_LOG", None)
        shutil.rmtree(tmpdir, ignore_errors=True)


def bench_log_with_override(label, iterations=1000):
    """Benchmark log_event() with override fields."""
    tmpdir = tempfile.mkdtemp()
    log_path = os.path.join(tmpdir, "audit.log")
    env_backup = os.environ.get("HOOK_AUDIT_LOG")
    os.environ["HOOK_AUDIT_LOG"] = log_path

    try:
        t0 = time.perf_counter()
        for _ in range(iterations):
            log_event(
                log_dir=tmpdir,
                filter_name="regex_filter",
                rule_name="block_untrusted_network",
                action="override_allow",
                matched=[],
                command="curl https://api.mycompany.com/health",
                session_id="bench-session",
                override_name="allow_company_api",
                override_source="project",
            )
        elapsed = (time.perf_counter() - t0) * 1000

        per_call = elapsed / iterations
        ops = iterations / (elapsed / 1000) if elapsed > 0 else float("inf")
        return label, iterations, per_call, ops, 0
    finally:
        if env_backup is not None:
            os.environ["HOOK_AUDIT_LOG"] = env_backup
        else:
            os.environ.pop("HOOK_AUDIT_LOG", None)
        shutil.rmtree(tmpdir, ignore_errors=True)


def main():
    print("=" * 78)
    print("Audit Logger Benchmark")
    print("=" * 78)
    print()
    print("  log_event() — JSONL append performance")
    print()
    print(f"  {'Scenario':<45} {'N':>6} {'per call':>10} {'ops/sec':>12} {'file size':>12}")
    print(f"  {'-'*45} {'---':>6} {'---':>10} {'---':>12} {'---':>12}")

    # Standard deny event
    name, n, per_call, ops, size = bench_log_event("Deny event (2 patterns)", iterations=2000)
    print(f"  {name:<45} {n:>6} {per_call:>8.3f}ms {ops:>10,.0f}/s {size:>10,} B")

    # Override allow event
    name, n, per_call, ops, _ = bench_log_with_override("Override allow event", iterations=2000)
    print(f"  {name:<45} {n:>6} {per_call:>8.3f}ms {ops:>10,.0f}/s {'—':>12}")

    # Burst write
    name, n, per_call, ops, size = bench_log_event("Burst: 5000 entries", iterations=5000)
    print(f"  {name:<45} {n:>6} {per_call:>8.3f}ms {ops:>10,.0f}/s {size:>10,} B")

    print()


if __name__ == "__main__":
    main()
