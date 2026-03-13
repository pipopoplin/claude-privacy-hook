#!/usr/bin/env python3
"""Run all hook test suites and report combined results.

Usage:
    python3 tests/run_all.py              # run all suites
    python3 tests/run_all.py --fast       # skip slow service tests
"""

import subprocess
import sys
import os

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))

SUITES = [
    ("Regex Filter", "test_regex_filter.py"),
    ("NLP Filter", "test_nlp_filter.py"),
    ("Output Sanitizer", "test_output_sanitizer.py"),
    ("Rate Limiter", "test_rate_limiter.py"),
    ("Overrides", "test_overrides.py"),
    ("NLP Service", "test_nlp_service.py"),
    ("Conftest Infrastructure", "test_conftest.py"),
]


def main():
    fast_mode = "--fast" in sys.argv

    total_passed = 0
    total_failed = 0
    suite_results = []

    for label, filename in SUITES:
        if fast_mode and filename == "test_nlp_service.py":
            suite_results.append((label, "SKIP", 0, 0))
            continue

        path = os.path.join(TESTS_DIR, filename)
        result = subprocess.run(
            [sys.executable, path],
            capture_output=False,
            text=True,
        )

        if result.returncode == 0:
            suite_results.append((label, "PASS", 0, 0))
        else:
            suite_results.append((label, "FAIL", 0, 0))

    print()
    print("=" * 60)
    print("All Suites Summary")
    print("=" * 60)
    all_ok = True
    for label, status, _, _ in suite_results:
        icon = "PASS" if status == "PASS" else ("SKIP" if status == "SKIP" else "FAIL")
        print(f"  [{icon}] {label}")
        if status == "FAIL":
            all_ok = False
    print("=" * 60)

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
