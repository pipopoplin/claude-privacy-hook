#!/usr/bin/env python3
"""Test the rate limiter PreToolUse hook.

Verifies threshold escalation, session isolation, rolling window behavior,
and disabled-config handling.
"""

import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import RATE_LIMITER, RATE_LIMITER_CONFIG, run_hook_raw, parse_decision, TestRunner


def _write_audit_log(log_path: str, entries: list[dict]) -> None:
    """Write JSONL audit log entries."""
    with open(log_path, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


def _make_violation(session_id: str, ts: str, action: str = "deny") -> dict:
    return {
        "timestamp": ts,
        "session_id": session_id,
        "action": action,
        "filter_name": "regex_filter",
        "rule_name": "test_rule",
        "matched": ["test"],
    }


def _run_limiter(session_id: str, log_path: str, config_path: str = RATE_LIMITER_CONFIG) -> str:
    """Run the rate limiter and return 'allow', 'warn', or 'block'."""
    hook_input = {
        "session_id": session_id,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo test"},
    }
    env = os.environ.copy()
    env["HOOK_AUDIT_LOG"] = log_path
    result = run_hook_raw(RATE_LIMITER, config_path, hook_input, env=env)
    return parse_decision(result)


def test_under_threshold():
    """No violations → allow."""
    log_path = os.path.join(tempfile.mkdtemp(), "audit.log")
    _write_audit_log(log_path, [])
    try:
        result = _run_limiter("sess-1", log_path)
        ok = result == "allow"
        print(f"  [{'PASS' if ok else 'FAIL'}] Under threshold: allow")
        if not ok:
            print(f"         Expected: allow, Got: {result}")
        return ok
    finally:
        os.remove(log_path)


def test_warn_threshold():
    """5 violations → warn (ask)."""
    log_path = os.path.join(tempfile.mkdtemp(), "audit.log")
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    entries = [_make_violation("sess-warn", now) for _ in range(5)]
    _write_audit_log(log_path, entries)
    try:
        result = _run_limiter("sess-warn", log_path)
        ok = result == "warn"
        print(f"  [{'PASS' if ok else 'FAIL'}] Warn threshold (5 violations)")
        if not ok:
            print(f"         Expected: warn, Got: {result}")
        return ok
    finally:
        os.remove(log_path)


def test_block_threshold():
    """10 violations → block (deny)."""
    log_path = os.path.join(tempfile.mkdtemp(), "audit.log")
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    entries = [_make_violation("sess-block", now) for _ in range(10)]
    _write_audit_log(log_path, entries)
    try:
        result = _run_limiter("sess-block", log_path)
        ok = result == "block"
        print(f"  [{'PASS' if ok else 'FAIL'}] Block threshold (10 violations)")
        if not ok:
            print(f"         Expected: block, Got: {result}")
        return ok
    finally:
        os.remove(log_path)


def test_session_isolation():
    """Violations from other sessions don't count."""
    log_path = os.path.join(tempfile.mkdtemp(), "audit.log")
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    entries = [_make_violation("other-session", now) for _ in range(15)]
    _write_audit_log(log_path, entries)
    try:
        result = _run_limiter("my-session", log_path)
        ok = result == "allow"
        print(f"  [{'PASS' if ok else 'FAIL'}] Session isolation")
        if not ok:
            print(f"         Expected: allow, Got: {result}")
        return ok
    finally:
        os.remove(log_path)


def test_expired_violations():
    """Old violations outside the window don't count."""
    log_path = os.path.join(tempfile.mkdtemp(), "audit.log")
    # Timestamp from 10 minutes ago (window is 5 minutes)
    old_ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 600))
    entries = [_make_violation("sess-old", old_ts) for _ in range(15)]
    _write_audit_log(log_path, entries)
    try:
        result = _run_limiter("sess-old", log_path)
        ok = result == "allow"
        print(f"  [{'PASS' if ok else 'FAIL'}] Expired violations outside window")
        if not ok:
            print(f"         Expected: allow, Got: {result}")
        return ok
    finally:
        os.remove(log_path)


def test_only_deny_ask_count():
    """Only deny/ask actions count as violations (not allow, redact, override_allow)."""
    log_path = os.path.join(tempfile.mkdtemp(), "audit.log")
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    entries = [
        _make_violation("sess-mixed", now, action="allow"),
        _make_violation("sess-mixed", now, action="redact"),
        _make_violation("sess-mixed", now, action="override_allow"),
        _make_violation("sess-mixed", now, action="allow"),
    ]
    _write_audit_log(log_path, entries)
    try:
        result = _run_limiter("sess-mixed", log_path)
        ok = result == "allow"
        print(f"  [{'PASS' if ok else 'FAIL'}] Only deny/ask count as violations")
        if not ok:
            print(f"         Expected: allow, Got: {result}")
        return ok
    finally:
        os.remove(log_path)


def test_no_session_id():
    """Missing session ID → allow (cannot rate-limit)."""
    log_path = os.path.join(tempfile.mkdtemp(), "audit.log")
    _write_audit_log(log_path, [])
    hook_input = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo test"},
    }
    env = os.environ.copy()
    env["HOOK_AUDIT_LOG"] = log_path
    try:
        result = run_hook_raw(RATE_LIMITER, RATE_LIMITER_CONFIG, hook_input, env=env)
        ok = parse_decision(result) == "allow"
        print(f"  [{'PASS' if ok else 'FAIL'}] No session ID → allow")
        return ok
    finally:
        os.remove(log_path)


def test_disabled_config():
    """Disabled config → allow everything."""
    config = {"enabled": False, "window_seconds": 300,
              "thresholds": {"warn": 5, "block": 10}}
    config_path = os.path.join(tempfile.mkdtemp(), "disabled_rl.json")
    with open(config_path, "w") as f:
        json.dump(config, f)

    log_path = os.path.join(tempfile.mkdtemp(), "audit.log")
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    entries = [_make_violation("sess-dis", now) for _ in range(15)]
    _write_audit_log(log_path, entries)
    try:
        result = _run_limiter("sess-dis", log_path, config_path)
        ok = result == "allow"
        print(f"  [{'PASS' if ok else 'FAIL'}] Disabled config → allow")
        if not ok:
            print(f"         Expected: allow, Got: {result}")
        return ok
    finally:
        os.remove(log_path)
        os.remove(config_path)


def test_missing_log_file():
    """Missing audit log → allow (no violations to count)."""
    result = _run_limiter("sess-nofile", "/tmp/nonexistent_audit_log.jsonl")
    ok = result == "allow"
    print(f"  [{'PASS' if ok else 'FAIL'}] Missing audit log → allow")
    return ok


def main():
    t = TestRunner("Testing Rate Limiter Hook")
    t.header()

    tests = [
        test_under_threshold,
        test_warn_threshold,
        test_block_threshold,
        test_session_isolation,
        test_expired_violations,
        test_only_deny_ask_count,
        test_no_session_id,
        test_disabled_config,
        test_missing_log_file,
    ]
    for fn in tests:
        t.run_fn(fn)

    sys.exit(t.summary())


if __name__ == "__main__":
    main()
