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

import json
import os
import re
import sys
import unicodedata


# ---------------------------------------------------------------------------
# Unicode normalization (mirrors regex_filter.py)
# ---------------------------------------------------------------------------

HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u03bf': 'o', '\u03b1': 'a', '\u03b9': 'i', '\u03ba': 'k',
    '\u03bd': 'v', '\u03c1': 'p',
    '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0397': 'H',
    '\u0399': 'I', '\u039a': 'K', '\u039c': 'M', '\u039d': 'N',
    '\u039f': 'O', '\u03a1': 'P', '\u03a4': 'T', '\u03a5': 'Y',
    '\u03a7': 'X',
}
ZERO_WIDTH_CHARS = {'\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad', '\u2060'}
_HOMOGLYPH_TRANS = str.maketrans(HOMOGLYPH_MAP)


def normalize_unicode(text: str) -> str:
    """Normalize Unicode to defeat homoglyph and zero-width bypasses."""
    text = unicodedata.normalize("NFKC", text)
    text = ''.join(c for c in text if c not in ZERO_WIDTH_CHARS)
    text = text.translate(_HOMOGLYPH_TRANS)
    return text


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


def resolve_field(data: dict, field: str) -> str:
    """Resolve a dot-separated field path from the hook input JSON."""
    parts = field.split(".")
    current = data
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return ""
    return str(current) if current is not None else ""


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


def redact_text(text: str, compiled_rules: list[dict]) -> tuple[str, list[str]]:
    """Apply all rules and redact matched content in *text*.

    Returns the redacted text and a list of matched labels.
    """
    normalized = normalize_unicode(text)
    all_labels: list[str] = []

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

        for regex, label in matches:
            all_labels.append(label)
            # Redact in both the original text and its normalized form so we
            # return a properly redacted original.
            text = regex.sub("[REDACTED]", text)
            normalized = regex.sub("[REDACTED]", normalized)

    return text, all_labels


def evaluate_output(
    compiled_rules: list[dict],
    hook_input: dict,
) -> tuple[dict | None, list[str]]:
    """Check both stdout and stderr, redacting sensitive content.

    Returns (updated_tool_result, matched_labels) or (None, []) when nothing
    was detected.
    """
    tool_result = hook_input.get("tool_result", {})
    if not isinstance(tool_result, dict):
        return None, []

    stdout = tool_result.get("stdout", "")
    stderr = tool_result.get("stderr", "")

    all_labels: list[str] = []
    updated = dict(tool_result)
    changed = False

    if stdout:
        redacted_stdout, labels = redact_text(stdout, compiled_rules)
        if labels:
            updated["stdout"] = redacted_stdout
            all_labels.extend(labels)
            changed = True

    if stderr:
        redacted_stderr, labels = redact_text(stderr, compiled_rules)
        if labels:
            updated["stderr"] = redacted_stderr
            all_labels.extend(labels)
            changed = True

    if changed:
        return updated, all_labels
    return None, []


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

    try:
        config = load_config(config_path)
    except Exception:
        sys.exit(0)

    try:
        hook_input = json.load(sys.stdin)
    except (json.JSONDecodeError, Exception):
        sys.exit(0)

    compiled_rules = _compile_patterns(config["rules"])
    updated_result, matched_labels = evaluate_output(compiled_rules, hook_input)

    if updated_result is None:
        # Nothing detected — pass through unchanged
        sys.exit(0)

    # Audit log (best-effort, never blocks)
    try:
        from audit_logger import log_event
        hooks_dir = os.path.dirname(os.path.abspath(__file__))
        log_event(
            log_dir=hooks_dir,
            filter_name="output_sanitizer",
            rule_name="output_redaction",
            action="redact",
            matched=matched_labels,
            command=resolve_field(hook_input, "tool_input.command"),
            session_id=hook_input.get("session_id", ""),
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
