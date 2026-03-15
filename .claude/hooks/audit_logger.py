"""Audit logger for hook filter events.

Writes JSONL entries to audit.log when commands are blocked or flagged.
Stores command hashes (not full commands) plus redacted previews.

Rotation policy (configurable via env vars):
    HOOK_AUDIT_LOG_MAX_BYTES   — rotate when file exceeds this size (default 10 MB)
    HOOK_AUDIT_LOG_BACKUP_COUNT — number of rotated files to keep (default 5)
"""

import hashlib
import json
import os
import re
import time

# Rotation defaults
_DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
_DEFAULT_BACKUP_COUNT = 5


def _maybe_rotate(log_path: str) -> None:
    """Rotate the audit log if it exceeds the configured size limit.

    Shifts audit.log → audit.log.1 → audit.log.2 → ... and deletes
    the oldest file beyond the backup count.
    """
    try:
        max_bytes = int(os.environ.get("HOOK_AUDIT_LOG_MAX_BYTES", _DEFAULT_MAX_BYTES))
        backup_count = int(os.environ.get("HOOK_AUDIT_LOG_BACKUP_COUNT", _DEFAULT_BACKUP_COUNT))
    except (ValueError, TypeError):
        max_bytes = _DEFAULT_MAX_BYTES
        backup_count = _DEFAULT_BACKUP_COUNT

    if max_bytes <= 0 or backup_count <= 0:
        return  # Rotation disabled

    try:
        if os.path.getsize(log_path) < max_bytes:
            return
    except OSError:
        return  # File doesn't exist or can't stat

    # Shift existing backups: .5 → delete, .4 → .5, .3 → .4, ...
    for i in range(backup_count, 0, -1):
        src = f"{log_path}.{i}" if i > 1 else log_path
        dst = f"{log_path}.{i}"
        if i == backup_count:
            # Delete the oldest backup
            try:
                os.remove(f"{log_path}.{i}")
            except OSError:
                pass
        if i > 1:
            src = f"{log_path}.{i - 1}"
            try:
                os.rename(src, dst)
            except OSError:
                pass
        else:
            # Rotate current log to .1
            try:
                os.rename(log_path, f"{log_path}.1")
            except OSError:
                pass


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
    scf: dict | None = None,
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
        scf: Optional SCF metadata from matched rule (domain, controls,
            regulations, risk_level).
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

    if scf:
        if scf.get("domain"):
            entry["scf_domain"] = scf["domain"]
        if scf.get("controls"):
            entry["scf_controls"] = scf["controls"]
        if scf.get("regulations"):
            entry["scf_regulations"] = scf["regulations"]
        if scf.get("risk_level"):
            entry["scf_risk_level"] = scf["risk_level"]

    try:
        _maybe_rotate(log_path)
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # Best-effort logging
