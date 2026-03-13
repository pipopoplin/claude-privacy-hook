#!/usr/bin/env python3
"""Benchmark the override resolver — in-process check_override and load_overrides."""

import json
import os
import re
import sys
import tempfile
import time

BENCH_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BENCH_DIR)
HOOKS_DIR = os.path.join(PROJECT_ROOT, ".claude", "hooks")
sys.path.insert(0, HOOKS_DIR)

from override_resolver import check_override, load_overrides, merge_nlp_overrides


def _make_overrides(n, rule_name="block_untrusted_network"):
    """Generate n override entries."""
    overrides = []
    for i in range(n):
        overrides.append({
            "name": f"allow_endpoint_{i}",
            "rule_name": rule_name,
            "patterns": [
                {"pattern": f"https?://api{i}\\.example\\.com", "label": f"API {i}"}
            ],
            "expires": "2099-12-31",
            "_source": "project",
        })
    return overrides


def _make_rule(name="block_untrusted_network", overridable=True):
    return {"name": name, "overridable": overridable, "action": "ask"}


# =====================================================================
# In-process benchmarks
# =====================================================================

def bench_check_override(label, overrides, rule, value, iterations=10000):
    """Benchmark check_override()."""
    # Warmup
    for _ in range(10):
        check_override(overrides, rule, value)

    t0 = time.perf_counter()
    for _ in range(iterations):
        check_override(overrides, rule, value)
    elapsed = (time.perf_counter() - t0) * 1000

    per_call = elapsed / iterations
    ops = iterations / (elapsed / 1000) if elapsed > 0 else float("inf")
    return label, iterations, per_call, ops


def bench_load_overrides(label, iterations=500):
    """Benchmark load_overrides() (file I/O)."""
    # Warmup
    for _ in range(5):
        load_overrides(HOOKS_DIR)

    t0 = time.perf_counter()
    for _ in range(iterations):
        load_overrides(HOOKS_DIR)
    elapsed = (time.perf_counter() - t0) * 1000

    per_call = elapsed / iterations
    ops = iterations / (elapsed / 1000) if elapsed > 0 else float("inf")
    return label, iterations, per_call, ops


def bench_merge_nlp(label, overrides, iterations=10000):
    """Benchmark merge_nlp_overrides()."""
    for _ in range(10):
        merge_nlp_overrides(overrides)

    t0 = time.perf_counter()
    for _ in range(iterations):
        merge_nlp_overrides(overrides)
    elapsed = (time.perf_counter() - t0) * 1000

    per_call = elapsed / iterations
    ops = iterations / (elapsed / 1000) if elapsed > 0 else float("inf")
    return label, iterations, per_call, ops


def main():
    print("=" * 78)
    print("Override Resolver Benchmark")
    print("=" * 78)

    rule = _make_rule()
    non_overridable = _make_rule("block_sensitive_data", overridable=False)

    # --- check_override ---
    print()
    print("  check_override() — pattern matching")
    print()
    print(f"  {'Scenario':<50} {'N':>6} {'per call':>10} {'ops/sec':>12}")
    print(f"  {'-'*50} {'---':>6} {'---':>10} {'---':>12}")

    # Varying override count
    for n in [0, 1, 5, 10, 25, 50, 100]:
        overrides = _make_overrides(n)
        label = f"{n} overrides, no match"
        name, iters, per_call, ops = bench_check_override(
            label, overrides, rule, "curl https://other.com", iterations=10000)
        print(f"  {name:<50} {iters:>6} {per_call:>8.4f}ms {ops:>10,.0f}/s")

    print()

    # Match at various positions
    for n in [10, 50, 100]:
        overrides = _make_overrides(n)
        # First override matches
        label = f"{n} overrides, match at #1"
        name, iters, per_call, ops = bench_check_override(
            label, overrides, rule, "curl https://api0.example.com", iterations=10000)
        print(f"  {name:<50} {iters:>6} {per_call:>8.4f}ms {ops:>10,.0f}/s")

        # Last override matches
        label = f"{n} overrides, match at #{n}"
        name, iters, per_call, ops = bench_check_override(
            label, overrides, rule, f"curl https://api{n-1}.example.com", iterations=10000)
        print(f"  {name:<50} {iters:>6} {per_call:>8.4f}ms {ops:>10,.0f}/s")

    print()

    # Non-overridable (early return)
    overrides_50 = _make_overrides(50)
    label = "Non-overridable rule (early return)"
    name, iters, per_call, ops = bench_check_override(
        label, overrides_50, non_overridable, "anything", iterations=10000)
    print(f"  {name:<50} {iters:>6} {per_call:>8.4f}ms {ops:>10,.0f}/s")

    # Empty overrides
    label = "Empty overrides list"
    name, iters, per_call, ops = bench_check_override(
        label, [], rule, "anything", iterations=10000)
    print(f"  {name:<50} {iters:>6} {per_call:>8.4f}ms {ops:>10,.0f}/s")

    # --- load_overrides ---
    print()
    print("  load_overrides() — file I/O")
    print()
    print(f"  {'Scenario':<50} {'N':>6} {'per call':>10} {'ops/sec':>12}")
    print(f"  {'-'*50} {'---':>6} {'---':>10} {'---':>12}")

    name, iters, per_call, ops = bench_load_overrides(
        "Load from project config", iterations=500)
    print(f"  {name:<50} {iters:>6} {per_call:>8.3f}ms {ops:>10,.0f}/s")

    # --- merge_nlp_overrides ---
    print()
    print("  merge_nlp_overrides()")
    print()
    print(f"  {'Scenario':<50} {'N':>6} {'per call':>10} {'ops/sec':>12}")
    print(f"  {'-'*50} {'---':>6} {'---':>10} {'---':>12}")

    nlp_overrides = [
        {"_source": "user", "_nlp_overrides": {
            "disabled_entity_types": ["EMAIL", "PHONE"],
            "confidence_overrides": {"SSN": 0.95},
        }},
        {"_source": "project", "_nlp_overrides": {
            "disabled_entity_types": ["EMAIL"],
            "confidence_overrides": {"PHONE": 0.9, "SSN": 0.8},
        }},
    ]
    name, iters, per_call, ops = bench_merge_nlp(
        "Merge 2 NLP override layers", nlp_overrides, iterations=10000)
    print(f"  {name:<50} {iters:>6} {per_call:>8.4f}ms {ops:>10,.0f}/s")

    name, iters, per_call, ops = bench_merge_nlp(
        "Empty overrides", [], iterations=10000)
    print(f"  {name:<50} {iters:>6} {per_call:>8.4f}ms {ops:>10,.0f}/s")

    print()


if __name__ == "__main__":
    main()
