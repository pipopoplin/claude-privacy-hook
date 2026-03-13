#!/usr/bin/env python3
"""
Claude Code Hook: Rate limiter based on audit log violations.

A PreToolUse hook that reads the audit log and escalates when too many
deny/ask events occur within a rolling time window for the current session.

Usage:
  python3 rate_limiter.py <config.json>

Config format: see .claude/hooks/rate_limiter_config.json
"""

import json
import os
import sys
import time

from hook_utils import normalize_unicode


def load_config(path: str) -> dict:
    """Load the rate limiter config."""
    with open(path) as f:
        return json.load(f)


def parse_timestamp(ts: str) -> float:
    """Parse an ISO 8601 timestamp (UTC) into epoch seconds."""
    try:
        return time.mktime(time.strptime(ts, "%Y-%m-%dT%H:%M:%S")) - time.timezone
    except (ValueError, OverflowError):
        return 0.0


def count_violations(log_path: str, session_id: str, window_seconds: int) -> int:
    """Count deny/ask actions for session_id within the rolling window."""
    if not os.path.isfile(log_path):
        return 0

    cutoff = time.time() - window_seconds
    count = 0

    try:
        with open(log_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Filter by session
                if entry.get("session_id") != session_id:
                    continue

                # Filter by action (only deny/ask count as violations)
                if entry.get("action") not in ("deny", "ask"):
                    continue

                # Filter by time window
                ts = parse_timestamp(entry.get("timestamp", ""))
                if ts < cutoff:
                    continue

                count += 1
    except OSError:
        return 0

    return count


def main():
    if len(sys.argv) < 2:
        print("Usage: rate_limiter.py <config.json>", file=sys.stderr)
        sys.exit(1)

    config_path = os.path.expandvars(sys.argv[1])
    if not os.path.isfile(config_path):
        print(f"Config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    # Add hooks dir to path so audit_logger is importable
    hooks_dir = os.path.dirname(os.path.abspath(__file__))
    if hooks_dir not in sys.path:
        sys.path.insert(0, hooks_dir)

    try:
        config = load_config(config_path)
    except Exception:
        sys.exit(0)

    if not config.get("enabled", True):
        sys.exit(0)

    try:
        hook_input = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    session_id = hook_input.get("session_id", "")
    if not session_id:
        sys.exit(0)  # Cannot rate-limit without a session ID

    # Resolve audit log path
    audit_log_name = config.get("audit_log", "audit.log")
    log_path = os.environ.get(
        "HOOK_AUDIT_LOG",
        os.path.join(hooks_dir, audit_log_name),
    )

    window_seconds = config.get("window_seconds", 300)
    thresholds = config.get("thresholds", {})
    block_threshold = thresholds.get("block", 10)
    warn_threshold = thresholds.get("warn", 5)
    cooldown_seconds = config.get("cooldown_seconds", 60)

    try:
        violation_count = count_violations(log_path, session_id, window_seconds)
    except Exception:
        sys.exit(0)  # Best-effort: allow through on errors

    # Determine escalation level
    if violation_count >= block_threshold:
        decision = "deny"
        reason = config.get("message_block", "Too many security violations.")
    elif violation_count >= warn_threshold:
        decision = "ask"
        reason = config.get("message_warn", "Multiple security violations detected.")
    else:
        sys.exit(0)  # Under threshold, allow through

    reason += f"\n({violation_count} violations in the last {window_seconds}s)"

    # Log the escalation event itself
    try:
        from audit_logger import log_event

        command = ""
        tool_input = hook_input.get("tool_input")
        if isinstance(tool_input, dict):
            command = tool_input.get("command", "")

        log_event(
            log_dir=hooks_dir,
            filter_name="rate_limiter",
            rule_name=f"threshold_{decision}",
            action=decision,
            matched=[f"violations={violation_count}"],
            command=normalize_unicode(command) if command else "",
            session_id=session_id,
        )
    except Exception:
        pass  # Audit logging must never block the filter

    hook_event = hook_input.get("hook_event_name", "PreToolUse")

    if hook_event == "PreToolUse":
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        }
    else:
        output = {
            "decision": "block" if decision == "deny" else decision,
            "reason": reason,
        }

    json.dump(output, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
