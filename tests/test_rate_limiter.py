#!/usr/bin/env python3
"""Test the rate limiter PreToolUse hook.

Verifies threshold escalation, boundary values, session isolation,
rolling window behavior, action filtering, config edge cases,
malformed input handling, output format, and custom thresholds.
"""

import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import RATE_LIMITER, RATE_LIMITER_CONFIG, HOOKS_DIR, run_hook_raw, parse_decision, TestRunner


# --- Helpers ---

def _write_audit_log(log_path: str, entries: list[dict]) -> None:
    """Write JSONL audit log entries."""
    with open(log_path, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


def _make_violation(session_id: str, ts: str, action: str = "deny",
                    filter_name: str = "regex_filter",
                    rule_name: str = "test_rule") -> dict:
    return {
        "timestamp": ts,
        "session_id": session_id,
        "action": action,
        "filter_name": filter_name,
        "rule_name": rule_name,
        "matched": ["test"],
    }


def _now_ts() -> str:
    """Current time as ISO 8601 UTC string."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time()))


def _ago_ts(seconds: int) -> str:
    """Timestamp from `seconds` ago as ISO 8601 UTC string."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - seconds))


def _tmp_log() -> str:
    """Create a temp audit log path."""
    return os.path.join(tempfile.mkdtemp(), "audit.log")


def _tmp_config(config: dict) -> str:
    """Write a temp config in HOOKS_DIR and return its path."""
    fd, path = tempfile.mkstemp(suffix=".json", prefix="test_rl_", dir=HOOKS_DIR)
    with os.fdopen(fd, "w") as f:
        json.dump(config, f)
    return path


def _run_limiter(session_id: str, log_path: str,
                 config_path: str = RATE_LIMITER_CONFIG) -> str:
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


def _run_limiter_raw(hook_input: dict, log_path: str,
                     config_path: str = RATE_LIMITER_CONFIG):
    """Run the rate limiter and return raw CompletedProcess."""
    env = os.environ.copy()
    env["HOOK_AUDIT_LOG"] = log_path
    return run_hook_raw(RATE_LIMITER, config_path, hook_input, env=env)


# =====================================================================
# Tests: Threshold boundaries
# =====================================================================

def test_zero_violations(t: TestRunner):
    """0 violations → allow."""
    log_path = _tmp_log()
    _write_audit_log(log_path, [])
    try:
        t.check("0 violations → allow",
                _run_limiter("sess-0", log_path), "allow")
    finally:
        os.remove(log_path)


def test_one_violation(t: TestRunner):
    """1 violation → allow (well under warn=5)."""
    log_path = _tmp_log()
    _write_audit_log(log_path, [_make_violation("sess-1", _now_ts())])
    try:
        t.check("1 violation → allow",
                _run_limiter("sess-1", log_path), "allow")
    finally:
        os.remove(log_path)


def test_four_violations(t: TestRunner):
    """4 violations → allow (1 below warn=5)."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("sess-4", now) for _ in range(4)])
    try:
        t.check("4 violations → allow (1 below warn)",
                _run_limiter("sess-4", log_path), "allow")
    finally:
        os.remove(log_path)


def test_five_violations(t: TestRunner):
    """5 violations → warn (exactly at warn=5)."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("sess-5", now) for _ in range(5)])
    try:
        t.check("5 violations → warn (exactly at warn threshold)",
                _run_limiter("sess-5", log_path), "warn")
    finally:
        os.remove(log_path)


def test_six_violations(t: TestRunner):
    """6 violations → warn (1 above warn, still below block)."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("sess-6", now) for _ in range(6)])
    try:
        t.check("6 violations → warn (between warn and block)",
                _run_limiter("sess-6", log_path), "warn")
    finally:
        os.remove(log_path)


def test_nine_violations(t: TestRunner):
    """9 violations → warn (1 below block=10)."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("sess-9", now) for _ in range(9)])
    try:
        t.check("9 violations → warn (1 below block threshold)",
                _run_limiter("sess-9", log_path), "warn")
    finally:
        os.remove(log_path)


def test_ten_violations(t: TestRunner):
    """10 violations → block (exactly at block=10)."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("sess-10", now) for _ in range(10)])
    try:
        t.check("10 violations → block (exactly at block threshold)",
                _run_limiter("sess-10", log_path), "block")
    finally:
        os.remove(log_path)


def test_eleven_violations(t: TestRunner):
    """11 violations → block (1 above block=10)."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("sess-11", now) for _ in range(11)])
    try:
        t.check("11 violations → block (above block threshold)",
                _run_limiter("sess-11", log_path), "block")
    finally:
        os.remove(log_path)


def test_fifty_violations(t: TestRunner):
    """50 violations → block (far above threshold)."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("sess-50", now) for _ in range(50)])
    try:
        t.check("50 violations → block (far above threshold)",
                _run_limiter("sess-50", log_path), "block")
    finally:
        os.remove(log_path)


# =====================================================================
# Tests: Action filtering
# =====================================================================

def test_deny_counts(t: TestRunner):
    """deny actions count as violations."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("sess-deny", now, action="deny") for _ in range(5)])
    try:
        t.check("5 deny actions → warn",
                _run_limiter("sess-deny", log_path), "warn")
    finally:
        os.remove(log_path)


def test_ask_counts(t: TestRunner):
    """ask actions count as violations."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("sess-ask", now, action="ask") for _ in range(5)])
    try:
        t.check("5 ask actions → warn",
                _run_limiter("sess-ask", log_path), "warn")
    finally:
        os.remove(log_path)


def test_mixed_deny_ask(t: TestRunner):
    """Both deny and ask count together."""
    log_path = _tmp_log()
    now = _now_ts()
    entries = (
        [_make_violation("sess-mix", now, action="deny") for _ in range(3)]
        + [_make_violation("sess-mix", now, action="ask") for _ in range(2)]
    )
    _write_audit_log(log_path, entries)
    try:
        t.check("3 deny + 2 ask = 5 → warn",
                _run_limiter("sess-mix", log_path), "warn")
    finally:
        os.remove(log_path)


def test_allow_does_not_count(t: TestRunner):
    """allow actions are not violations."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("sess-allow", now, action="allow") for _ in range(20)])
    try:
        t.check("20 allow actions → allow (not violations)",
                _run_limiter("sess-allow", log_path), "allow")
    finally:
        os.remove(log_path)


def test_redact_does_not_count(t: TestRunner):
    """redact actions are not violations."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("sess-redact", now, action="redact") for _ in range(20)])
    try:
        t.check("20 redact actions → allow (not violations)",
                _run_limiter("sess-redact", log_path), "allow")
    finally:
        os.remove(log_path)


def test_override_allow_does_not_count(t: TestRunner):
    """override_allow actions are not violations."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("sess-ovr", now, action="override_allow") for _ in range(20)])
    try:
        t.check("20 override_allow actions → allow (not violations)",
                _run_limiter("sess-ovr", log_path), "allow")
    finally:
        os.remove(log_path)


def test_mixed_actions_only_violations_counted(t: TestRunner):
    """Mix of all action types — only deny/ask reach threshold."""
    log_path = _tmp_log()
    now = _now_ts()
    entries = [
        _make_violation("sess-full-mix", now, action="allow"),
        _make_violation("sess-full-mix", now, action="redact"),
        _make_violation("sess-full-mix", now, action="override_allow"),
        _make_violation("sess-full-mix", now, action="deny"),
        _make_violation("sess-full-mix", now, action="deny"),
        _make_violation("sess-full-mix", now, action="allow"),
        _make_violation("sess-full-mix", now, action="ask"),
        _make_violation("sess-full-mix", now, action="ask"),
        _make_violation("sess-full-mix", now, action="redact"),
        _make_violation("sess-full-mix", now, action="deny"),  # 5th violation (3 deny + 2 ask)
    ]
    _write_audit_log(log_path, entries)
    try:
        t.check("10 entries, 5 violations (3 deny + 2 ask) → warn",
                _run_limiter("sess-full-mix", log_path), "warn")
    finally:
        os.remove(log_path)


# =====================================================================
# Tests: Session isolation
# =====================================================================

def test_session_isolation_basic(t: TestRunner):
    """Violations from other sessions don't affect current session."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("other-session", now) for _ in range(15)])
    try:
        t.check("15 violations in other session → allow for my session",
                _run_limiter("my-session", log_path), "allow")
    finally:
        os.remove(log_path)


def test_session_isolation_mixed(t: TestRunner):
    """Violations split across sessions — only current session counts."""
    log_path = _tmp_log()
    now = _now_ts()
    entries = (
        [_make_violation("sess-A", now) for _ in range(4)]
        + [_make_violation("sess-B", now) for _ in range(4)]
        + [_make_violation("sess-C", now) for _ in range(4)]
    )
    _write_audit_log(log_path, entries)
    try:
        t.check("4 violations each in A, B, C → allow for A (under 5)",
                _run_limiter("sess-A", log_path), "allow")
    finally:
        os.remove(log_path)


def test_session_isolation_current_at_threshold(t: TestRunner):
    """Current session at threshold, others irrelevant."""
    log_path = _tmp_log()
    now = _now_ts()
    entries = (
        [_make_violation("target-sess", now) for _ in range(5)]
        + [_make_violation("other-sess", now) for _ in range(50)]
    )
    _write_audit_log(log_path, entries)
    try:
        t.check("5 own + 50 other → warn for own session",
                _run_limiter("target-sess", log_path), "warn")
    finally:
        os.remove(log_path)


def test_empty_session_id_in_log(t: TestRunner):
    """Log entries with empty session_id don't match any session."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("", now) for _ in range(20)])
    try:
        t.check("20 empty-session violations → allow for named session",
                _run_limiter("my-session", log_path), "allow")
    finally:
        os.remove(log_path)


# =====================================================================
# Tests: Time window
# =====================================================================

def test_all_expired(t: TestRunner):
    """All violations outside window (10 min ago, window=5 min) → allow."""
    log_path = _tmp_log()
    old_ts = _ago_ts(600)
    _write_audit_log(log_path, [_make_violation("sess-exp", old_ts) for _ in range(15)])
    try:
        t.check("15 expired violations (10 min ago) → allow",
                _run_limiter("sess-exp", log_path), "allow")
    finally:
        os.remove(log_path)


def test_mix_expired_and_fresh(t: TestRunner):
    """Mix of expired and fresh — only fresh count."""
    log_path = _tmp_log()
    old_ts = _ago_ts(600)
    now = _now_ts()
    entries = (
        [_make_violation("sess-mix-time", old_ts) for _ in range(8)]  # expired
        + [_make_violation("sess-mix-time", now) for _ in range(4)]   # fresh
    )
    _write_audit_log(log_path, entries)
    try:
        t.check("8 expired + 4 fresh = 4 effective → allow",
                _run_limiter("sess-mix-time", log_path), "allow")
    finally:
        os.remove(log_path)


def test_mix_expired_pushes_to_warn(t: TestRunner):
    """Fresh violations just at warn threshold, expired don't count."""
    log_path = _tmp_log()
    old_ts = _ago_ts(600)
    now = _now_ts()
    entries = (
        [_make_violation("sess-mix-warn", old_ts) for _ in range(10)]  # expired
        + [_make_violation("sess-mix-warn", now) for _ in range(5)]     # fresh = warn
    )
    _write_audit_log(log_path, entries)
    try:
        t.check("10 expired + 5 fresh = 5 effective → warn",
                _run_limiter("sess-mix-warn", log_path), "warn")
    finally:
        os.remove(log_path)


def test_just_inside_window(t: TestRunner):
    """Violations at 4 min ago (inside 5 min window) still count."""
    log_path = _tmp_log()
    recent_ts = _ago_ts(240)  # 4 minutes ago
    _write_audit_log(log_path, [_make_violation("sess-recent", recent_ts) for _ in range(5)])
    try:
        t.check("5 violations at 4 min ago (inside window) → warn",
                _run_limiter("sess-recent", log_path), "warn")
    finally:
        os.remove(log_path)


def test_just_outside_window(t: TestRunner):
    """Violations at 6 min ago (outside 5 min window) don't count."""
    log_path = _tmp_log()
    old_ts = _ago_ts(360)  # 6 minutes ago
    _write_audit_log(log_path, [_make_violation("sess-outside", old_ts) for _ in range(15)])
    try:
        t.check("15 violations at 6 min ago (outside window) → allow",
                _run_limiter("sess-outside", log_path), "allow")
    finally:
        os.remove(log_path)


def test_violations_across_time_window_boundary(t: TestRunner):
    """Some violations inside window, some just outside."""
    log_path = _tmp_log()
    just_outside = _ago_ts(310)  # 5 min 10 sec ago (outside)
    just_inside = _ago_ts(290)   # 4 min 50 sec ago (inside)
    entries = (
        [_make_violation("sess-boundary", just_outside) for _ in range(5)]  # outside
        + [_make_violation("sess-boundary", just_inside) for _ in range(3)]  # inside
    )
    _write_audit_log(log_path, entries)
    try:
        t.check("5 outside + 3 inside window = 3 effective → allow",
                _run_limiter("sess-boundary", log_path), "allow")
    finally:
        os.remove(log_path)


# =====================================================================
# Tests: Config edge cases
# =====================================================================

def test_disabled_config(t: TestRunner):
    """Disabled config → allow even with many violations."""
    config = {"enabled": False, "window_seconds": 300,
              "thresholds": {"warn": 5, "block": 10}}
    config_path = _tmp_config(config)
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("sess-dis", now) for _ in range(15)])
    try:
        t.check("Disabled config → allow (15 violations ignored)",
                _run_limiter("sess-dis", log_path, config_path), "allow")
    finally:
        os.remove(log_path)
        os.remove(config_path)


def test_custom_thresholds_lower(t: TestRunner):
    """Custom lower thresholds (warn=2, block=4)."""
    config = {"enabled": True, "window_seconds": 300,
              "thresholds": {"warn": 2, "block": 4}}
    config_path = _tmp_config(config)
    log_path = _tmp_log()
    now = _now_ts()

    try:
        # 1 violation → allow
        _write_audit_log(log_path, [_make_violation("sess-low", now)])
        t.check("Custom warn=2: 1 violation → allow",
                _run_limiter("sess-low", log_path, config_path), "allow")

        # 2 violations → warn
        _write_audit_log(log_path, [_make_violation("sess-low2", now) for _ in range(2)])
        t.check("Custom warn=2: 2 violations → warn",
                _run_limiter("sess-low2", log_path, config_path), "warn")

        # 3 violations → warn (between warn and block)
        _write_audit_log(log_path, [_make_violation("sess-low3", now) for _ in range(3)])
        t.check("Custom block=4: 3 violations → warn",
                _run_limiter("sess-low3", log_path, config_path), "warn")

        # 4 violations → block
        _write_audit_log(log_path, [_make_violation("sess-low4", now) for _ in range(4)])
        t.check("Custom block=4: 4 violations → block",
                _run_limiter("sess-low4", log_path, config_path), "block")
    finally:
        os.remove(log_path)
        os.remove(config_path)


def test_custom_thresholds_higher(t: TestRunner):
    """Custom higher thresholds (warn=20, block=50)."""
    config = {"enabled": True, "window_seconds": 300,
              "thresholds": {"warn": 20, "block": 50}}
    config_path = _tmp_config(config)
    log_path = _tmp_log()
    now = _now_ts()

    try:
        # 10 violations → allow (under warn=20)
        _write_audit_log(log_path, [_make_violation("sess-hi10", now) for _ in range(10)])
        t.check("Custom warn=20: 10 violations → allow",
                _run_limiter("sess-hi10", log_path, config_path), "allow")

        # 20 violations → warn
        _write_audit_log(log_path, [_make_violation("sess-hi20", now) for _ in range(20)])
        t.check("Custom warn=20: 20 violations → warn",
                _run_limiter("sess-hi20", log_path, config_path), "warn")

        # 50 violations → block
        _write_audit_log(log_path, [_make_violation("sess-hi50", now) for _ in range(50)])
        t.check("Custom block=50: 50 violations → block",
                _run_limiter("sess-hi50", log_path, config_path), "block")
    finally:
        os.remove(log_path)
        os.remove(config_path)


def test_custom_window_short(t: TestRunner):
    """Short window (60s) — recent violations count, 2-min-old don't."""
    config = {"enabled": True, "window_seconds": 60,
              "thresholds": {"warn": 5, "block": 10}}
    config_path = _tmp_config(config)
    log_path = _tmp_log()
    two_min_ago = _ago_ts(120)
    now = _now_ts()

    try:
        # 10 violations 2 min ago → allow (outside 60s window)
        _write_audit_log(log_path, [_make_violation("sess-short", two_min_ago) for _ in range(10)])
        t.check("60s window: 10 violations at 2 min ago → allow",
                _run_limiter("sess-short", log_path, config_path), "allow")

        # 5 fresh violations → warn
        _write_audit_log(log_path, [_make_violation("sess-short2", now) for _ in range(5)])
        t.check("60s window: 5 fresh violations → warn",
                _run_limiter("sess-short2", log_path, config_path), "warn")
    finally:
        os.remove(log_path)
        os.remove(config_path)


def test_custom_window_long(t: TestRunner):
    """Long window (3600s = 1 hour) — 10-min-old violations still count."""
    config = {"enabled": True, "window_seconds": 3600,
              "thresholds": {"warn": 5, "block": 10}}
    config_path = _tmp_config(config)
    log_path = _tmp_log()
    ten_min_ago = _ago_ts(600)

    try:
        _write_audit_log(log_path, [_make_violation("sess-long", ten_min_ago) for _ in range(5)])
        t.check("3600s window: 5 violations at 10 min ago → warn",
                _run_limiter("sess-long", log_path, config_path), "warn")
    finally:
        os.remove(log_path)
        os.remove(config_path)


def test_threshold_warn_equals_block(t: TestRunner):
    """When warn == block, reaching threshold immediately blocks."""
    config = {"enabled": True, "window_seconds": 300,
              "thresholds": {"warn": 5, "block": 5}}
    config_path = _tmp_config(config)
    log_path = _tmp_log()
    now = _now_ts()

    try:
        _write_audit_log(log_path, [_make_violation("sess-eq", now) for _ in range(5)])
        t.check("warn=block=5: 5 violations → block (block wins)",
                _run_limiter("sess-eq", log_path, config_path), "block")
    finally:
        os.remove(log_path)
        os.remove(config_path)


def test_threshold_one(t: TestRunner):
    """Warn at 1 violation — extremely strict."""
    config = {"enabled": True, "window_seconds": 300,
              "thresholds": {"warn": 1, "block": 2}}
    config_path = _tmp_config(config)
    log_path = _tmp_log()
    now = _now_ts()

    try:
        _write_audit_log(log_path, [_make_violation("sess-strict1", now)])
        t.check("warn=1: 1 violation → warn",
                _run_limiter("sess-strict1", log_path, config_path), "warn")

        _write_audit_log(log_path, [_make_violation("sess-strict2", now) for _ in range(2)])
        t.check("block=2: 2 violations → block",
                _run_limiter("sess-strict2", log_path, config_path), "block")
    finally:
        os.remove(log_path)
        os.remove(config_path)


# =====================================================================
# Tests: Input edge cases
# =====================================================================

def test_no_session_id(t: TestRunner):
    """Missing session_id → allow (cannot rate-limit)."""
    log_path = _tmp_log()
    _write_audit_log(log_path, [])
    hook_input = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo test"},
    }
    try:
        env = os.environ.copy()
        env["HOOK_AUDIT_LOG"] = log_path
        result = run_hook_raw(RATE_LIMITER, RATE_LIMITER_CONFIG, hook_input, env=env)
        t.check("No session_id → allow",
                parse_decision(result), "allow")
    finally:
        os.remove(log_path)


def test_empty_session_id(t: TestRunner):
    """Empty string session_id → allow."""
    log_path = _tmp_log()
    _write_audit_log(log_path, [])
    hook_input = {
        "session_id": "",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo test"},
    }
    try:
        env = os.environ.copy()
        env["HOOK_AUDIT_LOG"] = log_path
        result = run_hook_raw(RATE_LIMITER, RATE_LIMITER_CONFIG, hook_input, env=env)
        t.check("Empty session_id → allow",
                parse_decision(result), "allow")
    finally:
        os.remove(log_path)


def test_missing_log_file(t: TestRunner):
    """Nonexistent audit log → allow (no violations to count)."""
    t.check("Missing audit log → allow",
            _run_limiter("sess-nofile", "/tmp/nonexistent_audit_log_xyz.jsonl"), "allow")


def test_empty_log_file(t: TestRunner):
    """Empty audit log file → allow."""
    log_path = _tmp_log()
    _write_audit_log(log_path, [])
    try:
        t.check("Empty audit log → allow",
                _run_limiter("sess-empty", log_path), "allow")
    finally:
        os.remove(log_path)


def test_malformed_json_stdin(t: TestRunner):
    """Malformed JSON on stdin → exit 0 (allow)."""
    import subprocess
    log_path = _tmp_log()
    _write_audit_log(log_path, [])
    env = os.environ.copy()
    env["HOOK_AUDIT_LOG"] = log_path
    try:
        result = subprocess.run(
            [sys.executable, RATE_LIMITER, RATE_LIMITER_CONFIG],
            input="not valid json{{{",
            capture_output=True, text=True, env=env,
        )
        t.check("Malformed JSON stdin → exit 0",
                result.returncode, 0)
    finally:
        os.remove(log_path)


def test_missing_tool_input(t: TestRunner):
    """Missing tool_input field → still works (only session_id matters)."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("sess-no-ti", now) for _ in range(5)])
    hook_input = {
        "session_id": "sess-no-ti",
        "hook_event_name": "PreToolUse",
    }
    try:
        env = os.environ.copy()
        env["HOOK_AUDIT_LOG"] = log_path
        result = run_hook_raw(RATE_LIMITER, RATE_LIMITER_CONFIG, hook_input, env=env)
        t.check("Missing tool_input → still warns at threshold",
                parse_decision(result), "warn")
    finally:
        os.remove(log_path)


# =====================================================================
# Tests: Malformed log entries
# =====================================================================

def test_malformed_json_in_log(t: TestRunner):
    """Bad JSON lines in log are skipped, valid ones still counted."""
    log_path = _tmp_log()
    now = _now_ts()
    with open(log_path, "w") as f:
        # 3 bad lines
        f.write("not json at all\n")
        f.write("{incomplete json\n")
        f.write("\n")  # empty line
        # 5 valid violations
        for _ in range(5):
            f.write(json.dumps(_make_violation("sess-bad-json", now)) + "\n")
    try:
        t.check("3 malformed + 5 valid log entries → warn (5 counted)",
                _run_limiter("sess-bad-json", log_path), "warn")
    finally:
        os.remove(log_path)


def test_missing_timestamp_in_entry(t: TestRunner):
    """Entry without timestamp → parse_timestamp returns 0.0 (epoch), treated as expired."""
    log_path = _tmp_log()
    entries = [{"session_id": "sess-no-ts", "action": "deny"} for _ in range(10)]
    _write_audit_log(log_path, entries)
    try:
        t.check("10 entries without timestamp → allow (parsed as epoch, expired)",
                _run_limiter("sess-no-ts", log_path), "allow")
    finally:
        os.remove(log_path)


def test_bad_timestamp_format(t: TestRunner):
    """Entry with unparseable timestamp → treated as epoch (expired)."""
    log_path = _tmp_log()
    entries = [{
        "session_id": "sess-bad-ts",
        "action": "deny",
        "timestamp": "not-a-date",
    } for _ in range(10)]
    _write_audit_log(log_path, entries)
    try:
        t.check("10 entries with bad timestamp → allow (parsed as 0, expired)",
                _run_limiter("sess-bad-ts", log_path), "allow")
    finally:
        os.remove(log_path)


def test_missing_action_in_entry(t: TestRunner):
    """Entry without action field → not counted as violation."""
    log_path = _tmp_log()
    now = _now_ts()
    entries = [{"session_id": "sess-no-action", "timestamp": now} for _ in range(10)]
    _write_audit_log(log_path, entries)
    try:
        t.check("10 entries without action → allow (not counted)",
                _run_limiter("sess-no-action", log_path), "allow")
    finally:
        os.remove(log_path)


def test_missing_session_in_entry(t: TestRunner):
    """Entry without session_id → doesn't match any session."""
    log_path = _tmp_log()
    now = _now_ts()
    entries = [{"action": "deny", "timestamp": now} for _ in range(10)]
    _write_audit_log(log_path, entries)
    try:
        t.check("10 entries without session_id → allow for any session",
                _run_limiter("my-session", log_path), "allow")
    finally:
        os.remove(log_path)


def test_unknown_action_not_counted(t: TestRunner):
    """Unknown action values are not counted."""
    log_path = _tmp_log()
    now = _now_ts()
    entries = [_make_violation("sess-unk", now, action=a) for a in
               ["block", "reject", "warn", "info", "error", "unknown"]]
    _write_audit_log(log_path, entries)
    try:
        t.check("6 unknown action types → allow (none are deny/ask)",
                _run_limiter("sess-unk", log_path), "allow")
    finally:
        os.remove(log_path)


# =====================================================================
# Tests: Multiple violation sources
# =====================================================================

def test_violations_from_different_filters(t: TestRunner):
    """Violations from different filters all count."""
    log_path = _tmp_log()
    now = _now_ts()
    entries = [
        _make_violation("sess-multi", now, filter_name="regex_filter", rule_name="rule_1"),
        _make_violation("sess-multi", now, filter_name="llm_filter", rule_name="pii"),
        _make_violation("sess-multi", now, filter_name="regex_filter", rule_name="rule_2"),
        _make_violation("sess-multi", now, filter_name="rate_limiter", rule_name="threshold_ask"),
        _make_violation("sess-multi", now, filter_name="llm_filter", rule_name="injection"),
    ]
    _write_audit_log(log_path, entries)
    try:
        t.check("5 violations from mixed filters → warn",
                _run_limiter("sess-multi", log_path), "warn")
    finally:
        os.remove(log_path)


def test_violations_from_different_rules(t: TestRunner):
    """Violations from different rules in same filter all count."""
    log_path = _tmp_log()
    now = _now_ts()
    rules = ["block_sensitive_data", "block_untrusted_network", "block_prompt_injection",
             "block_shell_obfuscation", "block_path_traversal"]
    entries = [_make_violation("sess-rules", now, rule_name=r) for r in rules]
    _write_audit_log(log_path, entries)
    try:
        t.check("5 violations from different rules → warn",
                _run_limiter("sess-rules", log_path), "warn")
    finally:
        os.remove(log_path)


# =====================================================================
# Tests: Output format validation
# =====================================================================

def test_warn_output_format(t: TestRunner):
    """Warn output has correct hookSpecificOutput structure."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("sess-fmt-w", now) for _ in range(5)])
    env = os.environ.copy()
    env["HOOK_AUDIT_LOG"] = log_path
    hook_input = {
        "session_id": "sess-fmt-w",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo test"},
    }
    try:
        result = run_hook_raw(RATE_LIMITER, RATE_LIMITER_CONFIG, hook_input, env=env)
        output = json.loads(result.stdout)
        hso = output.get("hookSpecificOutput", {})
        ok = (
            hso.get("hookEventName") == "PreToolUse"
            and hso.get("permissionDecision") == "ask"
            and "5 violations" in hso.get("permissionDecisionReason", "")
        )
        print(f"  [{'PASS' if ok else 'FAIL'}] Warn output: correct format and violation count")
        if not ok:
            print(f"         Got: {hso}")
        if ok:
            t.passed += 1
        else:
            t.failed += 1
    finally:
        os.remove(log_path)


def test_block_output_format(t: TestRunner):
    """Block output has correct hookSpecificOutput structure."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("sess-fmt-b", now) for _ in range(10)])
    env = os.environ.copy()
    env["HOOK_AUDIT_LOG"] = log_path
    hook_input = {
        "session_id": "sess-fmt-b",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo test"},
    }
    try:
        result = run_hook_raw(RATE_LIMITER, RATE_LIMITER_CONFIG, hook_input, env=env)
        output = json.loads(result.stdout)
        hso = output.get("hookSpecificOutput", {})
        ok = (
            hso.get("hookEventName") == "PreToolUse"
            and hso.get("permissionDecision") == "deny"
            and "10 violations" in hso.get("permissionDecisionReason", "")
        )
        print(f"  [{'PASS' if ok else 'FAIL'}] Block output: correct format and violation count")
        if not ok:
            print(f"         Got: {hso}")
        if ok:
            t.passed += 1
        else:
            t.failed += 1
    finally:
        os.remove(log_path)


def test_custom_messages(t: TestRunner):
    """Custom warn/block messages appear in output."""
    config = {
        "enabled": True, "window_seconds": 300,
        "thresholds": {"warn": 2, "block": 4},
        "message_warn": "CUSTOM WARN MESSAGE",
        "message_block": "CUSTOM BLOCK MESSAGE",
    }
    config_path = _tmp_config(config)
    log_path = _tmp_log()
    now = _now_ts()

    try:
        # Warn message
        _write_audit_log(log_path, [_make_violation("sess-msg-w", now) for _ in range(2)])
        env = os.environ.copy()
        env["HOOK_AUDIT_LOG"] = log_path
        hook_input = {
            "session_id": "sess-msg-w",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo test"},
        }
        result = run_hook_raw(RATE_LIMITER, config_path, hook_input, env=env)
        output = json.loads(result.stdout)
        reason = output.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")
        ok_warn = "CUSTOM WARN MESSAGE" in reason
        print(f"  [{'PASS' if ok_warn else 'FAIL'}] Custom warn message in output")
        if ok_warn:
            t.passed += 1
        else:
            t.failed += 1
            print(f"         Got: {reason}")

        # Block message
        _write_audit_log(log_path, [_make_violation("sess-msg-b", now) for _ in range(4)])
        hook_input["session_id"] = "sess-msg-b"
        result = run_hook_raw(RATE_LIMITER, config_path, hook_input, env=env)
        output = json.loads(result.stdout)
        reason = output.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")
        ok_block = "CUSTOM BLOCK MESSAGE" in reason
        print(f"  [{'PASS' if ok_block else 'FAIL'}] Custom block message in output")
        if ok_block:
            t.passed += 1
        else:
            t.failed += 1
            print(f"         Got: {reason}")
    finally:
        os.remove(log_path)
        os.remove(config_path)


def test_violation_count_in_reason(t: TestRunner):
    """Exact violation count appears in the reason string."""
    log_path = _tmp_log()
    now = _now_ts()
    _write_audit_log(log_path, [_make_violation("sess-cnt", now) for _ in range(7)])
    env = os.environ.copy()
    env["HOOK_AUDIT_LOG"] = log_path
    hook_input = {
        "session_id": "sess-cnt",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo test"},
    }
    try:
        result = run_hook_raw(RATE_LIMITER, RATE_LIMITER_CONFIG, hook_input, env=env)
        output = json.loads(result.stdout)
        reason = output.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")
        ok = "7 violations" in reason
        print(f"  [{'PASS' if ok else 'FAIL'}] Reason includes '7 violations'")
        if not ok:
            print(f"         Got: {reason}")
        if ok:
            t.passed += 1
        else:
            t.failed += 1
    finally:
        os.remove(log_path)


# =====================================================================
# Tests: Large audit log
# =====================================================================

def test_large_log_file(t: TestRunner):
    """1000 entries — performance and correctness."""
    log_path = _tmp_log()
    now = _now_ts()
    old_ts = _ago_ts(600)
    entries = (
        [_make_violation("other-sess", now) for _ in range(400)]
        + [_make_violation("sess-large", old_ts) for _ in range(400)]  # expired
        + [_make_violation("sess-large", now) for _ in range(6)]       # 6 fresh
        + [_make_violation("other-sess-2", now) for _ in range(194)]
    )
    _write_audit_log(log_path, entries)
    try:
        start = time.time()
        result = _run_limiter("sess-large", log_path)
        elapsed = time.time() - start
        ok = result == "warn"
        print(f"  [{'PASS' if ok else 'FAIL'}] 1000 entries, 6 matching → warn ({elapsed:.3f}s)")
        if not ok:
            print(f"         Expected: warn, Got: {result}")
        if ok:
            t.passed += 1
        else:
            t.failed += 1
    finally:
        os.remove(log_path)


# =====================================================================
# Main
# =====================================================================

def main():
    t = TestRunner("Testing Rate Limiter Hook")
    t.header()

    t.section("Threshold boundaries")
    test_zero_violations(t)
    test_one_violation(t)
    test_four_violations(t)
    test_five_violations(t)
    test_six_violations(t)
    test_nine_violations(t)
    test_ten_violations(t)
    test_eleven_violations(t)
    test_fifty_violations(t)

    t.section("Action filtering")
    test_deny_counts(t)
    test_ask_counts(t)
    test_mixed_deny_ask(t)
    test_allow_does_not_count(t)
    test_redact_does_not_count(t)
    test_override_allow_does_not_count(t)
    test_mixed_actions_only_violations_counted(t)

    t.section("Session isolation")
    test_session_isolation_basic(t)
    test_session_isolation_mixed(t)
    test_session_isolation_current_at_threshold(t)
    test_empty_session_id_in_log(t)

    t.section("Time window")
    test_all_expired(t)
    test_mix_expired_and_fresh(t)
    test_mix_expired_pushes_to_warn(t)
    test_just_inside_window(t)
    test_just_outside_window(t)
    test_violations_across_time_window_boundary(t)

    t.section("Config edge cases")
    test_disabled_config(t)
    test_custom_thresholds_lower(t)
    test_custom_thresholds_higher(t)
    test_custom_window_short(t)
    test_custom_window_long(t)
    test_threshold_warn_equals_block(t)
    test_threshold_one(t)

    t.section("Input edge cases")
    test_no_session_id(t)
    test_empty_session_id(t)
    test_missing_log_file(t)
    test_empty_log_file(t)
    test_malformed_json_stdin(t)
    test_missing_tool_input(t)

    t.section("Malformed log entries")
    test_malformed_json_in_log(t)
    test_missing_timestamp_in_entry(t)
    test_bad_timestamp_format(t)
    test_missing_action_in_entry(t)
    test_missing_session_in_entry(t)
    test_unknown_action_not_counted(t)

    t.section("Multiple violation sources")
    test_violations_from_different_filters(t)
    test_violations_from_different_rules(t)

    t.section("Output format validation")
    test_warn_output_format(t)
    test_block_output_format(t)
    test_custom_messages(t)
    test_violation_count_in_reason(t)

    t.section("Large audit log")
    test_large_log_file(t)

    sys.exit(t.summary())


if __name__ == "__main__":
    main()
