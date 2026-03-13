"""Audit logger for hook filter events.

Writes JSONL entries to audit.log when commands are blocked or flagged.
Stores command hashes (not full commands) plus redacted previews.
"""

import hashlib
import json
import os
import re
import time


def _redact_preview(command: str, matched: list[str], max_length: int = 100) -> str:
    """Create a redacted preview of the command, masking matched content."""
    preview = command[:max_length]
    if len(command) > max_length:
        preview += "..."
    # Redact any obvious secrets (tokens, keys, passwords) in the preview
    preview = re.sub(
        r'(sk-ant-|sk-proj-|ghp_|gho_|xox[bpas]-|password=|secret=|passwd=)[^\s\'"]{4,}',
        r'\1***',
        preview,
    )
    return preview


def log_event(
    log_dir: str,
    filter_name: str,
    rule_name: str,
    action: str,
    matched: list[str],
    command: str,
    session_id: str = "",
    override_name: str = "",
    override_source: str = "",
) -> None:
    """Append a JSONL audit entry to audit.log.

    Args:
        log_dir: Directory where audit.log is written.
        filter_name: Which filter triggered (regex_filter, llm_filter).
        rule_name: Name of the rule or plugin that matched.
        action: The decision (deny, ask, override_allow).
        matched: List of matched pattern labels or entity descriptions.
        command: The original command (hashed, not stored in full).
        session_id: Claude Code session ID for correlation.
        override_name: Name of the override that allowed the action.
        override_source: Source layer of the override (user, project).
    """
    log_path = os.environ.get(
        "HOOK_AUDIT_LOG",
        os.path.join(log_dir, "audit.log"),
    )

    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        "filter": filter_name,
        "rule_name": rule_name,
        "action": action,
        "matched_patterns": matched[:10],  # Cap to avoid huge entries
        "command_hash": "sha256:" + hashlib.sha256(command.encode()).hexdigest(),
        "command_preview": _redact_preview(command, matched),
        "session_id": session_id,
    }

    if override_name:
        entry["override_name"] = override_name
    if override_source:
        entry["override_source"] = override_source

    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # Best-effort logging
