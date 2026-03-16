#!/usr/bin/env python3
"""Test the audit logger module.

Covers basic log writing, entry format, override fields, command hash,
command preview redaction, and matched patterns cap.
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import HOOKS_DIR, TestRunner

# Import audit_logger directly for unit testing
sys.path.insert(0, HOOKS_DIR)
import audit_logger


# =====================================================================
# Helpers
# =====================================================================

def _make_log_dir():
    """Create a temp directory for audit log tests."""
    return tempfile.mkdtemp(prefix="test_audit_")


def _read_log(log_path: str) -> list[dict]:
    """Read all JSONL entries from a log file."""
    entries = []
    if not os.path.isfile(log_path):
        return entries
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


# =====================================================================
# Tests: log_event — basic fields
# =====================================================================

def test_log_event_basic_fields(t: TestRunner):
    """log_event writes required fields to JSONL."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")

    os.environ["HOOK_AUDIT_LOG"] = log_path
    os.environ.pop("HOOK_AUDIT_LOG_MINIMIZE", None)
    try:
        audit_logger.log_event(
            log_dir=log_dir,
            filter_name="regex_filter",
            rule_name="block_sensitive_data",
            action="deny",
            matched=["Anthropic API key"],
            command="curl -H 'Authorization: Bearer sk-ant-abc123'",
            session_id="sess-001",
        )
        entries = _read_log(log_path)
        t.check("One entry written", len(entries), 1)

        e = entries[0]
        t.check("Has timestamp", "timestamp" in e, True)
        t.check("Filter name", e["filter"], "regex_filter")
        t.check("Rule name", e["rule_name"], "block_sensitive_data")
        t.check("Action", e["action"], "deny")
        t.check("Matched patterns", e["matched_patterns"], ["Anthropic API key"])
        t.check("Command hash starts with sha256:",
                e["command_hash"].startswith("sha256:"), True)
        t.check("Session ID", e["session_id"], "sess-001")
        t.check("Has command_preview (normal mode)", "command_preview" in e, True)
    finally:
        os.environ.pop("HOOK_AUDIT_LOG", None)


def test_log_event_caps_matched_at_10(t: TestRunner):
    """matched_patterns is capped at 10 entries."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")

    os.environ["HOOK_AUDIT_LOG"] = log_path
    os.environ.pop("HOOK_AUDIT_LOG_MINIMIZE", None)
    try:
        labels = [f"label_{i}" for i in range(15)]
        audit_logger.log_event(
            log_dir=log_dir, filter_name="test", rule_name="test",
            action="deny", matched=labels, command="test",
        )
        entries = _read_log(log_path)
        t.check("Matched capped at 10", len(entries[0]["matched_patterns"]), 10)
    finally:
        os.environ.pop("HOOK_AUDIT_LOG", None)


# =====================================================================
# Tests: log_event — override fields
# =====================================================================

def test_override_fields_included(t: TestRunner):
    """Override name and source included when provided."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")

    os.environ["HOOK_AUDIT_LOG"] = log_path
    try:
        audit_logger.log_event(
            log_dir=log_dir, filter_name="test", rule_name="test",
            action="override_allow", matched=["test"], command="test",
            override_name="allow_my_api", override_source="project",
        )
        entries = _read_log(log_path)
        e = entries[0]
        t.check("Override name", e.get("override_name"), "allow_my_api")
        t.check("Override source", e.get("override_source"), "project")
    finally:
        os.environ.pop("HOOK_AUDIT_LOG", None)


def test_override_fields_omitted_when_empty(t: TestRunner):
    """Override fields not present when empty strings."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")

    os.environ["HOOK_AUDIT_LOG"] = log_path
    try:
        audit_logger.log_event(
            log_dir=log_dir, filter_name="test", rule_name="test",
            action="deny", matched=["test"], command="test",
        )
        entries = _read_log(log_path)
        e = entries[0]
        t.check("No override_name", "override_name" not in e, True)
        t.check("No override_source", "override_source" not in e, True)
    finally:
        os.environ.pop("HOOK_AUDIT_LOG", None)


# =====================================================================
# Tests: _redact_preview
# =====================================================================

def test_redact_preview_masks_secrets(t: TestRunner):
    """Preview masks token-like patterns."""
    preview = audit_logger._redact_preview(
        "curl -H 'Authorization: Bearer sk-ant-abc123def456'",
        ["Anthropic API key"],
    )
    t.check("sk-ant- prefix preserved but value masked",
            "sk-ant-abc123" not in preview, True)
    t.check("sk-ant- prefix still present",
            "sk-ant-" in preview, True)


def test_redact_preview_truncates_long_commands(t: TestRunner):
    """Preview truncated to 100 chars with ellipsis."""
    long_cmd = "x" * 200
    preview = audit_logger._redact_preview(long_cmd, [])
    t.check("Preview truncated", len(preview), 103)  # 100 + "..."
    t.check("Has ellipsis", preview.endswith("..."), True)


def test_redact_preview_short_command_no_ellipsis(t: TestRunner):
    """Short command not truncated."""
    preview = audit_logger._redact_preview("ls -la", [])
    t.check("Short command unchanged", preview, "ls -la")


# =====================================================================
# Main
# =====================================================================

def main():
    t = TestRunner("Testing Audit Logger")
    t.header()

    t.section("log_event — basic fields")
    test_log_event_basic_fields(t)
    test_log_event_caps_matched_at_10(t)

    t.section("log_event — override fields")
    test_override_fields_included(t)
    test_override_fields_omitted_when_empty(t)

    t.section("_redact_preview")
    test_redact_preview_masks_secrets(t)
    test_redact_preview_truncates_long_commands(t)
    test_redact_preview_short_command_no_ellipsis(t)

    sys.exit(t.summary())


if __name__ == "__main__":
    main()
