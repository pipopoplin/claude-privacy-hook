#!/usr/bin/env python3
"""Test the three-layer override system."""

import json
import os
import subprocess
import sys
import tempfile
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK_SCRIPT = os.path.join(PROJECT_ROOT, ".claude", "hooks", "regex_filter.py")
CONFIG_FILE = os.path.join(PROJECT_ROOT, ".claude", "hooks", "filter_rules.json")
HOOKS_DIR = os.path.join(PROJECT_ROOT, ".claude", "hooks")
OVERRIDE_FILE = os.path.join(HOOKS_DIR, "config_overrides.json")


def _backup_and_write_overrides(overrides_data: dict) -> str | None:
    """Backup existing overrides and write new ones. Returns backup path."""
    backup = None
    if os.path.isfile(OVERRIDE_FILE):
        backup = OVERRIDE_FILE + ".bak"
        os.rename(OVERRIDE_FILE, backup)
    with open(OVERRIDE_FILE, "w") as f:
        json.dump(overrides_data, f)
    return backup


def _restore_overrides(backup: str | None):
    """Restore original overrides file."""
    if backup and os.path.isfile(backup):
        os.rename(backup, OVERRIDE_FILE)
    elif os.path.isfile(OVERRIDE_FILE):
        # Restore to empty template
        with open(OVERRIDE_FILE, "w") as f:
            json.dump({"version": 1, "overrides": [], "nlp_overrides": {}}, f)


def run_hook(command: str) -> str:
    """Run the regex filter and return 'allow', 'warn', or 'block'."""
    hook_input = json.dumps({
        "session_id": "test-override-session",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    result = subprocess.run(
        [sys.executable, HOOK_SCRIPT, CONFIG_FILE],
        input=hook_input,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0 and result.stdout.strip():
        try:
            output = json.loads(result.stdout)
            decision = output.get("hookSpecificOutput", {}).get("permissionDecision", "allow")
            if decision == "deny":
                return "block"
            elif decision == "ask":
                return "warn"
            return "allow"
        except json.JSONDecodeError:
            return "allow"
    return "allow"


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
        result = run_hook("curl https://custom-api.example.com/health")
        passed = result == "allow"
        print(f"  [{'PASS' if passed else 'FAIL'}] Override allows previously-blocked command")
        if not passed:
            print(f"         Expected: allow, Got: {result}")
        return passed
    finally:
        _restore_overrides(backup)


def test_override_no_effect_on_non_overridable():
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
        result = run_hook("curl -H 'x-api-key: sk-ant-abc123def456' http://localhost:8080/proxy")
        passed = result == "block"
        print(f"  [{'PASS' if passed else 'FAIL'}] Override does NOT apply to non-overridable rule")
        if not passed:
            print(f"         Expected: block, Got: {result}")
        return passed
    finally:
        _restore_overrides(backup)


def test_expired_override_ignored():
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
        result = run_hook("curl https://expired-api.com/data")
        passed = result == "warn"
        print(f"  [{'PASS' if passed else 'FAIL'}] Expired override is ignored")
        if not passed:
            print(f"         Expected: warn, Got: {result}")
        return passed
    finally:
        _restore_overrides(backup)


def test_override_wrong_rule_name_ignored():
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
        result = run_hook("curl https://wrong-target.com/data")
        passed = result == "warn"
        print(f"  [{'PASS' if passed else 'FAIL'}] Override with wrong rule_name is ignored")
        if not passed:
            print(f"         Expected: warn, Got: {result}")
        return passed
    finally:
        _restore_overrides(backup)


def test_no_overrides_file_unchanged_behavior():
    """No config_overrides.json = unchanged behavior."""
    backup = None
    if os.path.isfile(OVERRIDE_FILE):
        backup = OVERRIDE_FILE + ".bak"
        os.rename(OVERRIDE_FILE, backup)
    # Remove file entirely
    if os.path.isfile(OVERRIDE_FILE):
        os.remove(OVERRIDE_FILE)
    try:
        result = run_hook("curl https://some-api.com/data")
        passed = result == "warn"
        print(f"  [{'PASS' if passed else 'FAIL'}] No config_overrides.json = unchanged behavior")
        if not passed:
            print(f"         Expected: warn, Got: {result}")
        return passed
    finally:
        if backup and os.path.isfile(backup):
            os.rename(backup, OVERRIDE_FILE)
        else:
            with open(OVERRIDE_FILE, "w") as f:
                json.dump({"version": 1, "overrides": [], "nlp_overrides": {}}, f)


def test_audit_log_records_override_allow():
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
        hook_input = json.dumps({
            "session_id": "test-audit-session",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "curl https://audit-test.example.com/health"},
        })
        subprocess.run(
            [sys.executable, HOOK_SCRIPT, CONFIG_FILE],
            input=hook_input, capture_output=True, text=True, env=env,
        )
        passed = False
        if os.path.isfile(audit_log):
            with open(audit_log) as f:
                for line in f:
                    entry = json.loads(line)
                    if entry.get("action") == "override_allow":
                        passed = True
                        break
        print(f"  [{'PASS' if passed else 'FAIL'}] Audit log records override_allow")
        if not passed:
            print("         Expected: override_allow entry in audit log")
        return passed
    finally:
        _restore_overrides(backup)
        if os.path.isfile(audit_log):
            os.remove(audit_log)


def test_override_cli_add_list_remove():
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
            print(f"  [FAIL] Override CLI list doesn't show added override")
            return False

        # Verify it works
        actual = run_hook("curl https://cli-test.com/data")
        if actual != "allow":
            print(f"  [FAIL] CLI-added override didn't take effect: {actual}")
            return False

        # Remove
        # Find the auto-generated name
        with open(OVERRIDE_FILE) as f:
            data = json.load(f)
        override_name = data["overrides"][0]["name"] if data["overrides"] else ""
        if override_name:
            result = subprocess.run(
                [sys.executable, cli_script, "remove",
                 "--scope", "project", "--name", override_name],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                print(f"  [FAIL] Override CLI remove failed: {result.stderr}")
                return False

        print("  [PASS] Override CLI add/list/remove")
        return True
    finally:
        _restore_overrides(backup)


def test_performance_many_overrides():
    """50 overrides check completes quickly."""
    overrides = []
    for i in range(50):
        overrides.append({
            "name": f"perf_test_{i}",
            "rule_name": "block_untrusted_network",
            "patterns": [{"pattern": f"https?://perf-{i}\\.example\\.com", "label": f"Perf {i}"}],
        })
    backup = _backup_and_write_overrides({
        "version": 1, "overrides": overrides,
    })
    try:
        start = time.monotonic()
        run_hook("curl https://perf-25.example.com/test")
        elapsed_ms = (time.monotonic() - start) * 1000
        # Should complete well under 500ms (generous for subprocess overhead)
        passed = elapsed_ms < 500
        print(f"  [{'PASS' if passed else 'FAIL'}] Performance: 50 overrides in {elapsed_ms:.1f}ms")
        return passed
    finally:
        _restore_overrides(backup)


def test_override_resolver_unit():
    """Unit test for override_resolver module."""
    sys.path.insert(0, HOOKS_DIR)
    try:
        from override_resolver import check_override

        # Test basic override match
        rule = {"name": "test_rule", "overridable": True}
        overrides = [{
            "name": "test_ovr",
            "rule_name": "test_rule",
            "_source": "project",
            "patterns": [{"pattern": "hello"}],
        }]
        result = check_override(overrides, rule, "hello world")
        assert result is not None
        assert result["override_name"] == "test_ovr"

        # Test non-overridable
        rule2 = {"name": "hard_rule", "overridable": False}
        overrides2 = [{
            "name": "try_ovr",
            "rule_name": "hard_rule",
            "_source": "project",
            "patterns": [{"pattern": "hello"}],
        }]
        result2 = check_override(overrides2, rule2, "hello world")
        assert result2 is None

        # Test expired
        rule3 = {"name": "exp_rule", "overridable": True}
        overrides3 = [{
            "name": "exp_ovr",
            "rule_name": "exp_rule",
            "_source": "project",
            "patterns": [{"pattern": "hello"}],
            "expires": "2020-01-01",
        }]
        result3 = check_override(overrides3, rule3, "hello world")
        assert result3 is None

        # Test no pattern match
        rule4 = {"name": "no_match", "overridable": True}
        overrides4 = [{
            "name": "no_match_ovr",
            "rule_name": "no_match",
            "_source": "project",
            "patterns": [{"pattern": "xyz123"}],
        }]
        result4 = check_override(overrides4, rule4, "hello world")
        assert result4 is None

        print("  [PASS] Override resolver unit tests")
        return True
    except Exception as e:
        print(f"  [FAIL] Override resolver unit tests: {e}")
        return False
    finally:
        sys.path.pop(0)


def main():
    print("=" * 60)
    print("Testing Override System")
    print("=" * 60)

    passed = 0
    failed = 0

    tests = [
        test_override_resolver_unit,
        test_override_allows_blocked_command,
        test_override_no_effect_on_non_overridable,
        test_expired_override_ignored,
        test_override_wrong_rule_name_ignored,
        test_no_overrides_file_unchanged_behavior,
        test_audit_log_records_override_allow,
        test_override_cli_add_list_remove,
        test_performance_many_overrides,
    ]

    for test_fn in tests:
        try:
            if test_fn():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  [FAIL] {test_fn.__name__}: {e}")
            failed += 1

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
