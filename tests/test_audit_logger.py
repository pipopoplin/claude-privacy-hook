#!/usr/bin/env python3
"""Test the audit logger module.

Covers log rotation (_maybe_rotate), data minimization (HOOK_AUDIT_LOG_MINIMIZE),
SCF metadata fields, and redacted preview generation.
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


def _write_bytes(path: str, size: int):
    """Write a file of exactly `size` bytes."""
    with open(path, "wb") as f:
        f.write(b"x" * size)


# =====================================================================
# Tests: Log rotation (_maybe_rotate)
# =====================================================================

def test_rotation_disabled_zero_max_bytes(t: TestRunner):
    """Rotation disabled when max_bytes <= 0."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")
    _write_bytes(log_path, 100)

    env = os.environ.copy()
    env["HOOK_AUDIT_LOG_MAX_BYTES"] = "0"
    old_env = os.environ.copy()
    os.environ["HOOK_AUDIT_LOG_MAX_BYTES"] = "0"
    try:
        audit_logger._maybe_rotate(log_path)
        t.check("Rotation disabled (max_bytes=0): file unchanged",
                os.path.isfile(log_path), True)
        t.check("Rotation disabled: no .1 backup created",
                os.path.isfile(f"{log_path}.1"), False)
    finally:
        os.environ.pop("HOOK_AUDIT_LOG_MAX_BYTES", None)


def test_rotation_disabled_zero_backup_count(t: TestRunner):
    """Rotation disabled when backup_count <= 0."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")
    _write_bytes(log_path, 100)

    os.environ["HOOK_AUDIT_LOG_BACKUP_COUNT"] = "0"
    try:
        audit_logger._maybe_rotate(log_path)
        t.check("Rotation disabled (backup_count=0): file unchanged",
                os.path.isfile(log_path), True)
        t.check("Rotation disabled (backup_count=0): no .1 backup",
                os.path.isfile(f"{log_path}.1"), False)
    finally:
        os.environ.pop("HOOK_AUDIT_LOG_BACKUP_COUNT", None)


def test_rotation_file_too_small(t: TestRunner):
    """No rotation when file is smaller than max_bytes."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")
    _write_bytes(log_path, 50)

    os.environ["HOOK_AUDIT_LOG_MAX_BYTES"] = "100"
    try:
        audit_logger._maybe_rotate(log_path)
        t.check("File too small: no rotation",
                os.path.isfile(f"{log_path}.1"), False)
        t.check("File too small: original unchanged",
                os.path.getsize(log_path), 50)
    finally:
        os.environ.pop("HOOK_AUDIT_LOG_MAX_BYTES", None)


def test_rotation_file_missing(t: TestRunner):
    """No crash when log file doesn't exist."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "nonexistent.log")

    # Should not raise
    audit_logger._maybe_rotate(log_path)
    t.check("Missing file: no crash", True, True)


def test_rotation_triggers_at_threshold(t: TestRunner):
    """File rotated to .1 when at or above max_bytes."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")
    _write_bytes(log_path, 200)

    os.environ["HOOK_AUDIT_LOG_MAX_BYTES"] = "100"
    os.environ["HOOK_AUDIT_LOG_BACKUP_COUNT"] = "3"
    try:
        audit_logger._maybe_rotate(log_path)
        t.check("Rotation: .1 backup created",
                os.path.isfile(f"{log_path}.1"), True)
        t.check("Rotation: .1 has original size",
                os.path.getsize(f"{log_path}.1"), 200)
        t.check("Rotation: original removed (ready for new writes)",
                os.path.isfile(log_path), False)
    finally:
        os.environ.pop("HOOK_AUDIT_LOG_MAX_BYTES", None)
        os.environ.pop("HOOK_AUDIT_LOG_BACKUP_COUNT", None)


def test_rotation_shifts_backups(t: TestRunner):
    """Existing backups are shifted: .1 → .2, current → .1."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")
    _write_bytes(log_path, 200)
    _write_bytes(f"{log_path}.1", 150)

    os.environ["HOOK_AUDIT_LOG_MAX_BYTES"] = "100"
    os.environ["HOOK_AUDIT_LOG_BACKUP_COUNT"] = "5"
    try:
        audit_logger._maybe_rotate(log_path)
        t.check("Shift: .2 exists (was .1)",
                os.path.isfile(f"{log_path}.2"), True)
        t.check("Shift: .2 has old .1 size",
                os.path.getsize(f"{log_path}.2"), 150)
        t.check("Shift: .1 has old current size",
                os.path.getsize(f"{log_path}.1"), 200)
    finally:
        os.environ.pop("HOOK_AUDIT_LOG_MAX_BYTES", None)
        os.environ.pop("HOOK_AUDIT_LOG_BACKUP_COUNT", None)


def test_rotation_deletes_oldest(t: TestRunner):
    """Oldest backup is deleted when beyond backup_count."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")
    _write_bytes(log_path, 200)
    _write_bytes(f"{log_path}.1", 100)
    _write_bytes(f"{log_path}.2", 100)

    os.environ["HOOK_AUDIT_LOG_MAX_BYTES"] = "100"
    os.environ["HOOK_AUDIT_LOG_BACKUP_COUNT"] = "2"
    try:
        audit_logger._maybe_rotate(log_path)
        t.check("Oldest deleted: .2 exists (shifted from .1)",
                os.path.isfile(f"{log_path}.2"), True)
        t.check("Oldest deleted: .1 exists (shifted from current)",
                os.path.isfile(f"{log_path}.1"), True)
    finally:
        os.environ.pop("HOOK_AUDIT_LOG_MAX_BYTES", None)
        os.environ.pop("HOOK_AUDIT_LOG_BACKUP_COUNT", None)


def test_rotation_invalid_env_vars(t: TestRunner):
    """Invalid env var values fall back to defaults without crashing."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")
    _write_bytes(log_path, 50)

    os.environ["HOOK_AUDIT_LOG_MAX_BYTES"] = "not_a_number"
    try:
        audit_logger._maybe_rotate(log_path)
        # With defaults (10MB), 50 bytes won't trigger rotation
        t.check("Invalid env: no crash, no rotation",
                os.path.isfile(f"{log_path}.1"), False)
    finally:
        os.environ.pop("HOOK_AUDIT_LOG_MAX_BYTES", None)


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
# Tests: log_event — minimize mode (HOOK_AUDIT_LOG_MINIMIZE)
# =====================================================================

def test_minimize_omits_command_preview(t: TestRunner):
    """Minimize mode omits command_preview field."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")

    os.environ["HOOK_AUDIT_LOG"] = log_path
    os.environ["HOOK_AUDIT_LOG_MINIMIZE"] = "1"
    try:
        audit_logger.log_event(
            log_dir=log_dir, filter_name="test", rule_name="test",
            action="deny", matched=["API key: sk-ant-abc123"],
            command="curl example.com",
        )
        entries = _read_log(log_path)
        t.check("Minimize: no command_preview",
                "command_preview" not in entries[0], True)
    finally:
        os.environ.pop("HOOK_AUDIT_LOG", None)
        os.environ.pop("HOOK_AUDIT_LOG_MINIMIZE", None)


def test_minimize_strips_matched_text(t: TestRunner):
    """Minimize mode strips text after colon in labels."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")

    os.environ["HOOK_AUDIT_LOG"] = log_path
    os.environ["HOOK_AUDIT_LOG_MINIMIZE"] = "1"
    try:
        audit_logger.log_event(
            log_dir=log_dir, filter_name="test", rule_name="test",
            action="deny",
            matched=["API key: sk-ant-abc123", "Password: secret123", "no_colon_label"],
            command="test",
        )
        entries = _read_log(log_path)
        patterns = entries[0]["matched_patterns"]
        t.check("Label with colon stripped", patterns[0], "API key")
        t.check("Second label stripped", patterns[1], "Password")
        t.check("Label without colon unchanged", patterns[2], "no_colon_label")
    finally:
        os.environ.pop("HOOK_AUDIT_LOG", None)
        os.environ.pop("HOOK_AUDIT_LOG_MINIMIZE", None)


def test_minimize_off_includes_preview(t: TestRunner):
    """Non-minimize mode includes command_preview and full labels."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")

    os.environ["HOOK_AUDIT_LOG"] = log_path
    os.environ.pop("HOOK_AUDIT_LOG_MINIMIZE", None)
    try:
        audit_logger.log_event(
            log_dir=log_dir, filter_name="test", rule_name="test",
            action="deny", matched=["API key: sk-ant-abc123"],
            command="curl example.com",
        )
        entries = _read_log(log_path)
        t.check("Normal: has command_preview",
                "command_preview" in entries[0], True)
        t.check("Normal: full label preserved",
                entries[0]["matched_patterns"][0], "API key: sk-ant-abc123")
    finally:
        os.environ.pop("HOOK_AUDIT_LOG", None)


# =====================================================================
# Tests: log_event — SCF metadata
# =====================================================================

def test_scf_metadata_included(t: TestRunner):
    """SCF metadata fields added when scf dict provided."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")

    os.environ["HOOK_AUDIT_LOG"] = log_path
    os.environ.pop("HOOK_AUDIT_LOG_MINIMIZE", None)
    try:
        audit_logger.log_event(
            log_dir=log_dir, filter_name="test", rule_name="test",
            action="deny", matched=["test"], command="test",
            scf={
                "domain": "IAC",
                "controls": ["IAC-01", "IAC-06"],
                "regulations": ["GDPR Art.32"],
                "risk_level": "critical",
            },
        )
        entries = _read_log(log_path)
        e = entries[0]
        t.check("SCF domain", e.get("scf_domain"), "IAC")
        t.check("SCF controls", e.get("scf_controls"), ["IAC-01", "IAC-06"])
        t.check("SCF regulations", e.get("scf_regulations"), ["GDPR Art.32"])
        t.check("SCF risk_level", e.get("scf_risk_level"), "critical")
    finally:
        os.environ.pop("HOOK_AUDIT_LOG", None)


def test_scf_metadata_omitted_when_none(t: TestRunner):
    """SCF fields not present when scf is None."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")

    os.environ["HOOK_AUDIT_LOG"] = log_path
    try:
        audit_logger.log_event(
            log_dir=log_dir, filter_name="test", rule_name="test",
            action="deny", matched=["test"], command="test",
            scf=None,
        )
        entries = _read_log(log_path)
        e = entries[0]
        t.check("No scf_domain", "scf_domain" not in e, True)
        t.check("No scf_controls", "scf_controls" not in e, True)
        t.check("No scf_regulations", "scf_regulations" not in e, True)
        t.check("No scf_risk_level", "scf_risk_level" not in e, True)
    finally:
        os.environ.pop("HOOK_AUDIT_LOG", None)


def test_scf_partial_metadata(t: TestRunner):
    """Only non-empty SCF fields are included."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")

    os.environ["HOOK_AUDIT_LOG"] = log_path
    try:
        audit_logger.log_event(
            log_dir=log_dir, filter_name="test", rule_name="test",
            action="deny", matched=["test"], command="test",
            scf={"domain": "PRI", "controls": [], "regulations": [], "risk_level": ""},
        )
        entries = _read_log(log_path)
        e = entries[0]
        t.check("Partial SCF: domain present", e.get("scf_domain"), "PRI")
        t.check("Partial SCF: no empty controls", "scf_controls" not in e, True)
        t.check("Partial SCF: no empty risk_level", "scf_risk_level" not in e, True)
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
# Tests: log_event — rotation integration
# =====================================================================

def test_log_event_triggers_rotation(t: TestRunner):
    """log_event calls _maybe_rotate before writing."""
    log_dir = _make_log_dir()
    log_path = os.path.join(log_dir, "audit.log")
    # Write 200 bytes to trigger rotation at 100 threshold
    _write_bytes(log_path, 200)

    os.environ["HOOK_AUDIT_LOG"] = log_path
    os.environ["HOOK_AUDIT_LOG_MAX_BYTES"] = "100"
    os.environ["HOOK_AUDIT_LOG_BACKUP_COUNT"] = "3"
    try:
        audit_logger.log_event(
            log_dir=log_dir, filter_name="test", rule_name="test",
            action="deny", matched=["test"], command="test",
        )
        t.check("Rotation: .1 backup created",
                os.path.isfile(f"{log_path}.1"), True)
        t.check("Rotation: .1 has old content",
                os.path.getsize(f"{log_path}.1"), 200)
        # New entry written to fresh file
        entries = _read_log(log_path)
        t.check("New entry in fresh log", len(entries), 1)
    finally:
        os.environ.pop("HOOK_AUDIT_LOG", None)
        os.environ.pop("HOOK_AUDIT_LOG_MAX_BYTES", None)
        os.environ.pop("HOOK_AUDIT_LOG_BACKUP_COUNT", None)


# =====================================================================
# Main
# =====================================================================

def main():
    t = TestRunner("Testing Audit Logger")
    t.header()

    t.section("Log rotation — _maybe_rotate()")
    test_rotation_disabled_zero_max_bytes(t)
    test_rotation_disabled_zero_backup_count(t)
    test_rotation_file_too_small(t)
    test_rotation_file_missing(t)
    test_rotation_triggers_at_threshold(t)
    test_rotation_shifts_backups(t)
    test_rotation_deletes_oldest(t)
    test_rotation_invalid_env_vars(t)

    t.section("log_event — basic fields")
    test_log_event_basic_fields(t)
    test_log_event_caps_matched_at_10(t)

    t.section("log_event — minimize mode")
    test_minimize_omits_command_preview(t)
    test_minimize_strips_matched_text(t)
    test_minimize_off_includes_preview(t)

    t.section("log_event — SCF metadata")
    test_scf_metadata_included(t)
    test_scf_metadata_omitted_when_none(t)
    test_scf_partial_metadata(t)

    t.section("log_event — override fields")
    test_override_fields_included(t)
    test_override_fields_omitted_when_empty(t)

    t.section("_redact_preview")
    test_redact_preview_masks_secrets(t)
    test_redact_preview_truncates_long_commands(t)
    test_redact_preview_short_command_no_ellipsis(t)

    t.section("log_event — rotation integration")
    test_log_event_triggers_rotation(t)

    sys.exit(t.summary())


if __name__ == "__main__":
    main()
