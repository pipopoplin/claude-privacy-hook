#!/usr/bin/env python3
"""Benchmark shared utilities — normalize_unicode and resolve_field."""

import os
import sys
import time

BENCH_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BENCH_DIR)
HOOKS_DIR = os.path.join(PROJECT_ROOT, ".claude", "hooks")
sys.path.insert(0, HOOKS_DIR)

from hook_utils import normalize_unicode, resolve_field


# =====================================================================
# Inputs
# =====================================================================

PLAIN_ASCII = "echo hello world"
SHORT_UNICODE = "sk-\u0430nt-abc123"  # Cyrillic 'a'
ZERO_WIDTH = "sk-ant\u200b-abc\u200c123\ufeffdef"
MIXED_HOMOGLYPHS = "\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456 normal text"
LONG_TEXT = "echo " + "hello world " * 500
LONG_UNICODE = ("\u0430bc " * 1000)

SHALLOW_DATA = {
    "tool_name": "Bash",
    "tool_input": {"command": "echo hello"},
}
DEEP_DATA = {
    "a": {"b": {"c": {"d": {"e": "deep_value"}}}},
    "tool_input": {"command": "test"},
}
MISSING_FIELD_DATA = {"tool_name": "Bash"}


def bench(label, fn, args, iterations=50000):
    """Benchmark a function call."""
    # Warmup
    for _ in range(100):
        fn(*args)

    t0 = time.perf_counter()
    for _ in range(iterations):
        fn(*args)
    elapsed = (time.perf_counter() - t0) * 1000

    per_call = elapsed / iterations
    ops = iterations / (elapsed / 1000) if elapsed > 0 else float("inf")
    return label, iterations, per_call, ops


def main():
    print("=" * 78)
    print("Hook Utils Benchmark")
    print("=" * 78)

    # --- normalize_unicode ---
    print()
    print("  normalize_unicode()")
    print()
    print(f"  {'Scenario':<45} {'N':>6} {'per call':>10} {'ops/sec':>12}")
    print(f"  {'-'*45} {'---':>6} {'---':>10} {'---':>12}")

    unicode_cases = [
        ("Plain ASCII (16 chars)", PLAIN_ASCII),
        ("Cyrillic homoglyph (short)", SHORT_UNICODE),
        ("Zero-width chars", ZERO_WIDTH),
        ("Mixed homoglyphs (8 chars)", MIXED_HOMOGLYPHS),
        ("Long ASCII (6KB)", LONG_TEXT),
        ("Long Unicode (4KB)", LONG_UNICODE),
        ("Empty string", ""),
    ]

    for label, text in unicode_cases:
        name, n, per_call, ops = bench(
            label, normalize_unicode, (text,), iterations=50000)
        print(f"  {name:<45} {n:>6} {per_call:>8.4f}ms {ops:>10,.0f}/s")

    # --- resolve_field ---
    print()
    print("  resolve_field()")
    print()
    print(f"  {'Scenario':<45} {'N':>6} {'per call':>10} {'ops/sec':>12}")
    print(f"  {'-'*45} {'---':>6} {'---':>10} {'---':>12}")

    field_cases = [
        ("Shallow: tool_input.command", SHALLOW_DATA, "tool_input.command"),
        ("Top-level: tool_name", SHALLOW_DATA, "tool_name"),
        ("Deep: a.b.c.d.e (5 levels)", DEEP_DATA, "a.b.c.d.e"),
        ("Missing field (returns '')", MISSING_FIELD_DATA, "tool_input.command"),
        ("Empty field path", SHALLOW_DATA, ""),
    ]

    for label, data, field in field_cases:
        name, n, per_call, ops = bench(
            label, resolve_field, (data, field), iterations=50000)
        print(f"  {name:<45} {n:>6} {per_call:>8.4f}ms {ops:>10,.0f}/s")

    print()


if __name__ == "__main__":
    main()
