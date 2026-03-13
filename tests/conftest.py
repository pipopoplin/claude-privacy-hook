#!/usr/bin/env python3
"""Shared test infrastructure for all hook test suites.

Provides path constants, subprocess helpers, and result parsing used by
every test module. Import what you need:

    from conftest import PROJECT_ROOT, HOOKS_DIR, run_hook, run_hook_raw
"""

import json
import os
import subprocess
import sys

# --- Path constants ---

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOKS_DIR = os.path.join(PROJECT_ROOT, ".claude", "hooks")

# Hook scripts
REGEX_FILTER = os.path.join(HOOKS_DIR, "regex_filter.py")
OUTPUT_SANITIZER = os.path.join(HOOKS_DIR, "output_sanitizer.py")
RATE_LIMITER = os.path.join(HOOKS_DIR, "rate_limiter.py")

# Config files
BASH_RULES = os.path.join(HOOKS_DIR, "filter_rules.json")
WRITE_RULES = os.path.join(HOOKS_DIR, "filter_rules_write.json")
READ_RULES = os.path.join(HOOKS_DIR, "filter_rules_read.json")
SANITIZER_RULES = os.path.join(HOOKS_DIR, "output_sanitizer_rules.json")
RATE_LIMITER_CONFIG = os.path.join(HOOKS_DIR, "rate_limiter_config.json")
OVERRIDE_FILE = os.path.join(HOOKS_DIR, "config_overrides.json")


# --- Subprocess helpers ---

def run_hook_raw(
    hook_script: str,
    config_file: str,
    hook_input: dict,
    env: dict | None = None,
) -> subprocess.CompletedProcess:
    """Run a hook script as a subprocess. Returns the raw CompletedProcess."""
    return subprocess.run(
        [sys.executable, hook_script, config_file],
        input=json.dumps(hook_input),
        capture_output=True,
        text=True,
        env=env,
    )


def parse_decision(result: subprocess.CompletedProcess) -> str:
    """Parse a PreToolUse hook result into 'allow', 'warn', or 'block'."""
    if result.returncode == 0 and result.stdout.strip():
        try:
            output = json.loads(result.stdout)
            decision = output.get("hookSpecificOutput", {}).get(
                "permissionDecision", "allow"
            )
            if decision == "deny":
                return "block"
            elif decision == "ask":
                return "warn"
            return "allow"
        except json.JSONDecodeError:
            return "allow"
    elif result.returncode == 2:
        return "block"
    return "allow"


def run_hook(
    hook_script: str,
    config_file: str,
    tool_name: str = "Bash",
    command: str | None = None,
    tool_input: dict | None = None,
    env: dict | None = None,
) -> str:
    """Run a PreToolUse hook and return 'allow', 'warn', or 'block'.

    For Bash tools, pass ``command``. For other tools, pass ``tool_input``
    directly (e.g. ``{"file_path": "/etc/shadow"}`` for Read).
    """
    if tool_input is None:
        tool_input = {"command": command or ""}

    hook_input = {
        "session_id": "test-session",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
    }
    result = run_hook_raw(hook_script, config_file, hook_input, env=env)
    return parse_decision(result)


def detected(result: subprocess.CompletedProcess) -> bool:
    """Return True if the hook detected something (deny or ask)."""
    if result.returncode == 0 and result.stdout.strip():
        try:
            output = json.loads(result.stdout)
            decision = output.get("hookSpecificOutput", {}).get(
                "permissionDecision", ""
            )
            return decision in ("deny", "ask")
        except json.JSONDecodeError:
            return False
    return False


# --- Test runner ---

class TestRunner:
    """Lightweight test runner with pass/fail counting and summaries."""

    def __init__(self, title: str):
        self.title = title
        self.passed = 0
        self.failed = 0

    def header(self):
        print("=" * 60)
        print(self.title)
        print("=" * 60)

    def section(self, name: str):
        print()
        print(f"  {name}")
        print()

    def check(self, description: str, actual, expected) -> bool:
        ok = actual == expected
        print(f"  [{'PASS' if ok else 'FAIL'}] {description}")
        if not ok:
            print(f"         Expected: {expected}, Got: {actual}")
        if ok:
            self.passed += 1
        else:
            self.failed += 1
        return ok

    def run_fn(self, fn) -> bool:
        """Run a test function that returns bool."""
        try:
            if fn():
                self.passed += 1
                return True
            else:
                self.failed += 1
                return False
        except Exception as e:
            print(f"  [FAIL] {fn.__name__}: {e}")
            self.failed += 1
            return False

    def summary(self) -> int:
        total = self.passed + self.failed
        print()
        print("=" * 60)
        print(f"Results: {self.passed} passed, {self.failed} failed, {total} total")
        print("=" * 60)
        return 0 if self.failed == 0 else 1
