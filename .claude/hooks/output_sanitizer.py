#!/usr/bin/env python3
"""
Claude Code Hook: PostToolUse output sanitizer.

A configurable PostToolUse hook that scans tool stdout/stderr for sensitive
data patterns (API keys, SSNs, credit cards, etc.) and redacts matches.
Rules are loaded from a JSON config file in the same format as filter_rules.json.

Usage:
  python3 output_sanitizer.py <config.json>

Config format: see .claude/hooks/output_sanitizer_rules.json
"""

import hashlib
import json
import os
import re
import sys

from hook_utils import normalize_unicode, resolve_field


# ---------------------------------------------------------------------------
# Config & field helpers
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    """Load and validate the sanitizer config."""
    with open(path) as f:
        config = json.load(f)
    if "rules" not in config:
        print(f"Config missing 'rules' key: {path}", file=sys.stderr)
        sys.exit(0)  # PostToolUse must never crash
    return config


# ---------------------------------------------------------------------------
# Rule evaluation & redaction
# ---------------------------------------------------------------------------

def _compile_patterns(rules: list[dict]) -> list[dict]:
    """Pre-compile regex patterns for all rules."""
    compiled = []
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        entries = []
        for entry in rule.get("patterns", []):
            if isinstance(entry, str):
                pattern, label = entry, entry
            elif isinstance(entry, dict):
                pattern, label = entry["pattern"], entry.get("label", entry["pattern"])
            else:
                continue
            try:
                entries.append((re.compile(pattern, re.IGNORECASE), label))
            except re.error:
                continue
        if entries:
            compiled.append({**rule, "_compiled": entries})
    return compiled


def redact_text(text: str, compiled_rules: list[dict]) -> tuple[str, list[str], dict | None]:
    """Apply all rules and redact matched content in *text*.

    Returns the redacted text, a list of matched labels, and SCF metadata
    from the first triggered rule (or None).
    """
    normalized = normalize_unicode(text)
    all_labels: list[str] = []
    first_scf: dict | None = None

    for rule in compiled_rules:
        match_mode = rule.get("match", "any")
        entries = rule["_compiled"]

        matches = []
        for regex, label in entries:
            if regex.search(normalized):
                matches.append((regex, label))

        triggered = False
        if match_mode == "any" and matches:
            triggered = True
        elif match_mode == "all" and len(matches) == len(entries):
            triggered = True

        if not triggered:
            continue

        action = rule.get("action", "redact")
        if action == "allow":
            continue

        if first_scf is None:
            first_scf = rule.get("scf")

        # Free tier: only "redact" mode (pseudonymize/hash require Pro)
        anon_mode = "redact"

        for regex, label in matches:
            all_labels.append(label)
            text = regex.sub("[REDACTED]", text)
            normalized = regex.sub("[REDACTED]", normalized)

    return text, all_labels, first_scf


def evaluate_output(
    compiled_rules: list[dict],
    hook_input: dict,
) -> tuple[dict | None, list[str], dict | None]:
    """Check both stdout and stderr, redacting sensitive content.

    Returns (updated_tool_result, matched_labels, scf_metadata) or
    (None, [], None) when nothing was detected.
    """
    tool_result = hook_input.get("tool_result", {})
    if not isinstance(tool_result, dict):
        return None, [], None

    stdout = tool_result.get("stdout", "")
    stderr = tool_result.get("stderr", "")

    all_labels: list[str] = []
    first_scf: dict | None = None
    updated = dict(tool_result)
    changed = False

    if stdout:
        redacted_stdout, labels, scf = redact_text(stdout, compiled_rules)
        if labels:
            updated["stdout"] = redacted_stdout
            all_labels.extend(labels)
            changed = True
            if first_scf is None:
                first_scf = scf

    if stderr:
        redacted_stderr, labels, scf = redact_text(stderr, compiled_rules)
        if labels:
            updated["stderr"] = redacted_stderr
            all_labels.extend(labels)
            changed = True
            if first_scf is None:
                first_scf = scf

    if changed:
        return updated, all_labels, first_scf
    return None, [], None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: output_sanitizer.py <config.json>", file=sys.stderr)
        sys.exit(0)

    config_path = os.path.expandvars(sys.argv[1])

    if not os.path.isfile(config_path):
        print(f"Config file not found: {config_path}", file=sys.stderr)
        sys.exit(0)

    # Add hooks dir to path so imports work
    hooks_dir = os.path.dirname(os.path.abspath(__file__))
    if hooks_dir not in sys.path:
        sys.path.insert(0, hooks_dir)

    try:
        config = load_config(config_path)
    except Exception:
        sys.exit(0)

    try:
        hook_input = json.load(sys.stdin)
    except (json.JSONDecodeError, Exception):
        sys.exit(0)

    compiled_rules = _compile_patterns(config["rules"])
    updated_result, matched_labels, scf_metadata = evaluate_output(compiled_rules, hook_input)

    if updated_result is None:
        # Nothing detected — pass through unchanged
        sys.exit(0)

    # Audit log (best-effort, never blocks)
    try:
        from audit_logger import log_event
        log_event(
            log_dir=hooks_dir,
            filter_name="output_sanitizer",
            rule_name="output_redaction",
            action="redact",
            matched=matched_labels,
            command=resolve_field(hook_input, "tool_input.command"),
            session_id=hook_input.get("session_id", ""),
            scf=scf_metadata,
        )
    except Exception:
        pass

    output = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolResult": updated_result,
        }
    }
    json.dump(output, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
