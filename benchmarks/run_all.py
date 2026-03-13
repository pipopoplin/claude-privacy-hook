#!/usr/bin/env python3
"""Run all benchmarks and report combined results.

Usage:
    python3 benchmarks/run_all.py          # run all benchmarks
    python3 benchmarks/run_all.py --fast   # skip slow NLP subprocess benchmarks
"""

import subprocess
import sys
import os
import time

BENCH_DIR = os.path.dirname(os.path.abspath(__file__))

SUITES = [
    ("Hook Utils", "bench_hook_utils.py", False),
    ("Regex Filter", "bench_regex_filter.py", False),
    ("Output Sanitizer", "bench_output_sanitizer.py", False),
    ("Rate Limiter", "bench_rate_limiter.py", False),
    ("Override Resolver", "bench_overrides.py", False),
    ("Audit Logger", "bench_audit_logger.py", False),
]


def main():
    fast_mode = "--fast" in sys.argv

    print()
    print("=" * 78)
    print("Claude Privacy Hook — Full Benchmark Suite")
    print("=" * 78)
    print()

    total_start = time.perf_counter()
    results = []

    for label, filename, slow in SUITES:
        if fast_mode and slow:
            print(f"  [SKIP] {label} (use --full to include)")
            results.append((label, "SKIP", 0))
            continue

        path = os.path.join(BENCH_DIR, filename)
        t0 = time.perf_counter()
        result = subprocess.run(
            [sys.executable, path],
            capture_output=False,
            text=True,
        )
        elapsed = time.perf_counter() - t0

        status = "OK" if result.returncode == 0 else "FAIL"
        results.append((label, status, elapsed))

    total_elapsed = time.perf_counter() - total_start

    print()
    print("=" * 78)
    print("Benchmark Summary")
    print("=" * 78)
    print()
    for label, status, elapsed in results:
        if status == "SKIP":
            print(f"  [SKIP] {label}")
        elif status == "OK":
            print(f"  [ OK ] {label} ({elapsed:.1f}s)")
        else:
            print(f"  [FAIL] {label} ({elapsed:.1f}s)")
    print()
    print(f"  Total time: {total_elapsed:.1f}s")
    print("=" * 78)

    sys.exit(0 if all(s in ("OK", "SKIP") for _, s, _ in results) else 1)


if __name__ == "__main__":
    main()
