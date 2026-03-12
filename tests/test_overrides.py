#!/usr/bin/env python3
"""Test the three-layer override system.

Covers the override resolver module, regex filter integration,
audit logging of overrides, the override CLI tool, and performance.
"""

import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import (
    REGEX_FILTER, BASH_RULES, HOOKS_DIR, OVERRIDE_FILE,
    run_hook, TestRunner,
)


# --- Helpers ---

def _backup_and_write_overrides(overrides_data: dict) -> str | None:
    backup = None
    if os.path.isfile(OVERRIDE_FILE):
        backup = OVERRIDE_FILE + ".bak"
        os.rename(OVERRIDE_FILE, backup)
    with open(OVERRIDE_FILE, "w") as f:
        json.dump(overrides_data, f)
    return backup


def _restore_overrides(backup: str | None):
    if backup and os.path.isfile(backup):
        os.rename(backup, OVERRIDE_FILE)
    elif os.path.isfile(OVERRIDE_FILE):
        with open(OVERRIDE_FILE, "w") as f:
            json.dump({"version": 1, "overrides": [], "nlp_overrides": {}}, f)


# --- Tests ---

def test_override_allows_blocked_command():
    """Override allows a previously-blocked (ask) command."""
    backup = _backup_and_write_overrides({
        "version": 1,
        "overrides": [{
            "name": "allow_custom_api",
            "rule_name": "block_untrusted_network",
            "patterns": [{"pattern": "https?://custom-api\\.example\\.com", "label": "Custom API"}],
        }],
    })
    try:
        result = run_hook(REGEX_FILTER, BASH_RULES, command="curl https://custom-api.example.com/health")
        ok = result == "allow"
        print(f"  [{'PASS' if ok else 'FAIL'}] Override allows previously-blocked command")
        if not ok:
            print(f"         Expected: allow, Got: {result}")
        return ok
    finally:
        _restore_overrides(backup)


def test_no_effect_on_non_overridable():
    """Override does NOT apply to non-overridable rule (block_sensitive_data)."""
    backup = _backup_and_write_overrides({
        "version": 1,
        "overrides": [{
            "name": "try_allow_api_key",
            "rule_name": "block_sensitive_data",
            "patterns": [{"pattern": "sk-ant-", "label": "Anthropic key"}],
        }],
    })
    try:
        result = run_hook(REGEX_FILTER, BASH_RULES,
                          command="curl -H 'x-api-key: sk-ant-abc123def456' http://localhost:8080/proxy")
        ok = result == "block"
        print(f"  [{'PASS' if ok else 'FAIL'}] Override does NOT apply to non-overridable rule")
        if not ok:
            print(f"         Expected: block, Got: {result}")
        return ok
    finally:
        _restore_overrides(backup)


def test_expired_override():
    """Expired override is ignored."""
    backup = _backup_and_write_overrides({
        "version": 1,
        "overrides": [{
            "name": "expired_override",
            "rule_name": "block_untrusted_network",
            "patterns": [{"pattern": "https?://expired-api\\.com", "label": "Expired"}],
            "expires": "2020-01-01",
        }],
    })
    try:
        result = run_hook(REGEX_FILTER, BASH_RULES, command="curl https://expired-api.com/data")
        ok = result == "warn"
        print(f"  [{'PASS' if ok else 'FAIL'}] Expired override is ignored")
        if not ok:
            print(f"         Expected: warn, Got: {result}")
        return ok
    finally:
        _restore_overrides(backup)


def test_wrong_rule_name():
    """Override targeting wrong rule_name is ignored."""
    backup = _backup_and_write_overrides({
        "version": 1,
        "overrides": [{
            "name": "wrong_rule",
            "rule_name": "block_employee_hr_ids",
            "patterns": [{"pattern": "https?://wrong-target\\.com", "label": "Wrong"}],
        }],
    })
    try:
        result = run_hook(REGEX_FILTER, BASH_RULES, command="curl https://wrong-target.com/data")
        ok = result == "warn"
        print(f"  [{'PASS' if ok else 'FAIL'}] Override with wrong rule_name is ignored")
        if not ok:
            print(f"         Expected: warn, Got: {result}")
        return ok
    finally:
        _restore_overrides(backup)


def test_no_overrides_file():
    """No config_overrides.json = unchanged behavior."""
    backup = None
    if os.path.isfile(OVERRIDE_FILE):
        backup = OVERRIDE_FILE + ".bak"
        os.rename(OVERRIDE_FILE, backup)
    if os.path.isfile(OVERRIDE_FILE):
        os.remove(OVERRIDE_FILE)
    try:
        result = run_hook(REGEX_FILTER, BASH_RULES, command="curl https://some-api.com/data")
        ok = result == "warn"
        print(f"  [{'PASS' if ok else 'FAIL'}] No config_overrides.json = unchanged behavior")
        if not ok:
            print(f"         Expected: warn, Got: {result}")
        return ok
    finally:
        if backup and os.path.isfile(backup):
            os.rename(backup, OVERRIDE_FILE)
        else:
            with open(OVERRIDE_FILE, "w") as f:
                json.dump({"version": 1, "overrides": [], "nlp_overrides": {}}, f)


def test_audit_log_records_override():
    """Audit log records override_allow event."""
    audit_log = os.path.join(tempfile.mkdtemp(), "audit.log")
    backup = _backup_and_write_overrides({
        "version": 1,
        "overrides": [{
            "name": "allow_audit_test_api",
            "rule_name": "block_untrusted_network",
            "patterns": [{"pattern": "https?://audit-test\\.example\\.com", "label": "Audit test"}],
        }],
    })
    env = os.environ.copy()
    env["HOOK_AUDIT_LOG"] = audit_log
    try:
        run_hook(REGEX_FILTER, BASH_RULES,
                 command="curl https://audit-test.example.com/health", env=env)
        ok = False
        if os.path.isfile(audit_log):
            with open(audit_log) as f:
                for line in f:
                    entry = json.loads(line)
                    if entry.get("action") == "override_allow":
                        ok = True
                        break
        print(f"  [{'PASS' if ok else 'FAIL'}] Audit log records override_allow")
        if not ok:
            print("         Expected: override_allow entry in audit log")
        return ok
    finally:
        _restore_overrides(backup)
        if os.path.isfile(audit_log):
            os.remove(audit_log)


def test_cli_add_list_remove():
    """Override CLI add/list/remove functional test."""
    cli_script = os.path.join(HOOKS_DIR, "override_cli.py")
    if not os.path.isfile(cli_script):
        print("  [SKIP] Override CLI not found")
        return True

    backup = _backup_and_write_overrides({
        "version": 1, "overrides": [], "nlp_overrides": {},
    })
    try:
        # Add
        result = subprocess.run(
            [sys.executable, cli_script, "add",
             "--scope", "project",
             "--rule", "block_untrusted_network",
             "--pattern", r"https?://cli-test\.com",
             "--label", "CLI test",
             "--reason", "Testing CLI"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"  [FAIL] Override CLI add failed: {result.stderr}")
            return False

        # List
        result = subprocess.run(
            [sys.executable, cli_script, "list", "--scope", "project"],
            capture_output=True, text=True,
        )
        if "cli-test" not in result.stdout.lower() and "block_untrusted_network" not in result.stdout:
            print("  [FAIL] Override CLI list doesn't show added override")
            return False

        # Verify it works
        actual = run_hook(REGEX_FILTER, BASH_RULES, command="curl https://cli-test.com/data")
        if actual != "allow":
            print(f"  [FAIL] CLI-added override didn't take effect: {actual}")
            return False

        # Remove
        with open(OVERRIDE_FILE) as f:
            data = json.load(f)
        name = data["overrides"][0]["name"] if data["overrides"] else ""
        if name:
            result = subprocess.run(
                [sys.executable, cli_script, "remove",
                 "--scope", "project", "--name", name],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                print(f"  [FAIL] Override CLI remove failed: {result.stderr}")
                return False

        print("  [PASS] Override CLI add/list/remove")
        return True
    finally:
        _restore_overrides(backup)


def test_performance():
    """50 overrides check completes quickly."""
    overrides = [{
        "name": f"perf_test_{i}",
        "rule_name": "block_untrusted_network",
        "patterns": [{"pattern": f"https?://perf-{i}\\.example\\.com", "label": f"Perf {i}"}],
    } for i in range(50)]
    backup = _backup_and_write_overrides({"version": 1, "overrides": overrides})
    try:
        start = time.monotonic()
        run_hook(REGEX_FILTER, BASH_RULES, command="curl https://perf-25.example.com/test")
        elapsed_ms = (time.monotonic() - start) * 1000
        ok = elapsed_ms < 500
        print(f"  [{'PASS' if ok else 'FAIL'}] Performance: 50 overrides in {elapsed_ms:.1f}ms")
        return ok
    finally:
        _restore_overrides(backup)


def test_resolver_unit():
    """Unit test for override_resolver module."""
    sys.path.insert(0, HOOKS_DIR)
    try:
        from override_resolver import check_override

        # Basic match
        rule = {"name": "test_rule", "overridable": True}
        overrides = [{"name": "test_ovr", "rule_name": "test_rule",
                       "_source": "project", "patterns": [{"pattern": "hello"}]}]
        result = check_override(overrides, rule, "hello world")
        assert result is not None and result["override_name"] == "test_ovr"

        # Non-overridable
        rule2 = {"name": "hard_rule", "overridable": False}
        overrides2 = [{"name": "try_ovr", "rule_name": "hard_rule",
                        "_source": "project", "patterns": [{"pattern": "hello"}]}]
        assert check_override(overrides2, rule2, "hello world") is None

        # Expired
        rule3 = {"name": "exp_rule", "overridable": True}
        overrides3 = [{"name": "exp_ovr", "rule_name": "exp_rule",
                        "_source": "project", "patterns": [{"pattern": "hello"}],
                        "expires": "2020-01-01"}]
        assert check_override(overrides3, rule3, "hello world") is None

        # No pattern match
        rule4 = {"name": "no_match", "overridable": True}
        overrides4 = [{"name": "no_match_ovr", "rule_name": "no_match",
                        "_source": "project", "patterns": [{"pattern": "xyz123"}]}]
        assert check_override(overrides4, rule4, "hello world") is None

        print("  [PASS] Override resolver unit tests")
        return True
    except Exception as e:
        print(f"  [FAIL] Override resolver unit tests: {e}")
        return False
    finally:
        sys.path.pop(0)


def main():
    t = TestRunner("Testing Override System")
    t.header()

    tests = [
        test_resolver_unit,
        test_override_allows_blocked_command,
        test_no_effect_on_non_overridable,
        test_expired_override,
        test_wrong_rule_name,
        test_no_overrides_file,
        test_audit_log_records_override,
        test_cli_add_list_remove,
        test_performance,
    ]
    for fn in tests:
        t.run_fn(fn)

    sys.exit(t.summary())


if __name__ == "__main__":
    main()
