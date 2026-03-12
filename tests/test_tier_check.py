#!/usr/bin/env python3
"""Tests for tier_check.py — pro feature gating logic.

Validates:
- Module presence detection (override_resolver importable or not)
- License status file reading
- is_pro_available() integration (modules + license)
- Transition mode (no license module → allow based on module presence)
- reset_cache() clears cached state
"""

import json
import os
import sys
import tempfile

# Add hooks dir and tests dir to path
_tests_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_tests_dir)
_hooks_dir = os.path.join(_project_root, ".claude", "hooks")

if _tests_dir not in sys.path:
    sys.path.insert(0, _tests_dir)
if _hooks_dir not in sys.path:
    sys.path.insert(0, _hooks_dir)

from conftest import TestRunner

import tier_check


def main():
    t = TestRunner("tier_check.py — Pro Feature Gating Tests")
    t.header()

    # --- Module presence detection ---
    t.section("Module Presence Detection")

    # override_resolver exists in .claude/hooks/ so should be found
    tier_check.reset_cache()
    t.check(
        "Pro modules detected (override_resolver exists)",
        tier_check._check_pro_modules(),
        True,
    )

    # Test with override_resolver temporarily hidden
    # Files to hide: .claude/hooks/ and pro/hooks/ locations
    pro_hooks = os.path.join(_project_root, "pro", "hooks")
    or_paths_to_hide = [
        os.path.join(_hooks_dir, "override_resolver.py"),
        os.path.join(pro_hooks, "override_resolver.py"),
    ]
    renamed = []

    try:
        for path in or_paths_to_hide:
            if os.path.exists(path):
                backup = path + ".bak_test"
                os.rename(path, backup)
                renamed.append((backup, path))
        tier_check.reset_cache()
        sys.modules.pop("override_resolver", None)
        t.check(
            "Pro modules NOT detected when override_resolver hidden",
            tier_check._check_pro_modules(),
            False,
        )
    finally:
        for backup, original in renamed:
            os.rename(backup, original)
        tier_check.reset_cache()
        sys.modules.pop("override_resolver", None)

    # Test caching: after reset and re-check
    tier_check.reset_cache()
    result1 = tier_check._check_pro_modules()
    result2 = tier_check._check_pro_modules()
    t.check("Cached result matches first check", result1, result2)

    # --- License status file ---
    t.section("License Status File")

    # Create a temporary valid status file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"status": "valid"}, f)
        valid_status_path = f.name

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"status": "expired"}, f)
        expired_status_path = f.name

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("not json")
        bad_status_path = f.name

    try:
        # Patch _get_status_path to return our test files
        original_get_status_path = tier_check._get_status_path

        tier_check._get_status_path = lambda: valid_status_path
        t.check("Valid status file → True", tier_check._is_license_valid(), True)

        tier_check._get_status_path = lambda: expired_status_path
        t.check("Expired status file → False", tier_check._is_license_valid(), False)

        tier_check._get_status_path = lambda: bad_status_path
        t.check("Malformed status file → False", tier_check._is_license_valid(), False)

        tier_check._get_status_path = lambda: "/nonexistent/path.json"
        t.check("Missing status file → False", tier_check._is_license_valid(), False)
    finally:
        tier_check._get_status_path = original_get_status_path
        os.unlink(valid_status_path)
        os.unlink(expired_status_path)
        os.unlink(bad_status_path)

    # --- is_pro_available() integration ---
    t.section("is_pro_available() Integration")

    # Transition mode: license module exists but no token file → True
    # (development/pre-license-server phase)
    tier_check.reset_cache()
    sys.modules.pop("override_resolver", None)
    t.check(
        "Transition mode: license module + no token file → True",
        tier_check.is_pro_available(),
        True,
    )

    # With valid status file and token file → True
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"status": "valid"}, f)
        tmp_status = f.name
    try:
        original_get_status = tier_check._get_status_path
        tier_check.reset_cache()
        sys.modules.pop("override_resolver", None)
        tier_check._get_status_path = lambda: tmp_status
        t.check(
            "Pro modules + valid status file → True",
            tier_check.is_pro_available(),
            True,
        )
    finally:
        tier_check._get_status_path = original_get_status
        os.unlink(tmp_status)

    # With override_resolver hidden → False regardless of license
    renamed2 = []
    try:
        for path in or_paths_to_hide:
            if os.path.exists(path):
                backup = path + ".bak_test"
                os.rename(path, backup)
                renamed2.append((backup, path))
        tier_check.reset_cache()
        sys.modules.pop("override_resolver", None)
        t.check(
            "No pro modules → False even without license check",
            tier_check.is_pro_available(),
            False,
        )
    finally:
        for backup, original in renamed2:
            os.rename(backup, original)
        tier_check.reset_cache()
        sys.modules.pop("override_resolver", None)

    # --- reset_cache() ---
    t.section("reset_cache()")

    tier_check._check_pro_modules()
    t.check(
        "Cache is populated after check",
        tier_check._pro_modules_available is not None,
        True,
    )

    tier_check.reset_cache()
    t.check(
        "Cache is None after reset",
        tier_check._pro_modules_available is None,
        True,
    )

    # --- _setup_pro_path() ---
    t.section("Pro Path Setup")

    # Verify _setup_pro_path adds pro/hooks/ to sys.path if it exists
    pro_hooks_dir = os.path.join(_project_root, "pro", "hooks")
    if os.path.isdir(pro_hooks_dir):
        # Remove from path first
        if pro_hooks_dir in sys.path:
            sys.path.remove(pro_hooks_dir)
        tier_check._setup_pro_path()
        t.check(
            "pro/hooks/ added to sys.path when dir exists",
            pro_hooks_dir in sys.path,
            True,
        )
    else:
        # pro/hooks/ doesn't exist yet, verify it doesn't crash
        tier_check._setup_pro_path()
        t.check(
            "No crash when pro/hooks/ dir missing",
            True,
            True,
        )

    return t.summary()


if __name__ == "__main__":
    sys.exit(main())
