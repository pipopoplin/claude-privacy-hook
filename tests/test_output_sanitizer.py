#!/usr/bin/env python3
"""Test the output sanitizer PostToolUse hook.

Verifies that sensitive data in command stdout/stderr is redacted and
that safe output passes through unchanged.
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import OUTPUT_SANITIZER, SANITIZER_RULES, run_hook_raw, TestRunner


def _run_sanitizer(stdout: str = "", stderr: str = "") -> dict:
    """Run the output sanitizer and return the parsed response.

    Returns {"redacted": bool, "stdout": str, "stderr": str}.
    """
    hook_input = {
        "session_id": "test-session",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "test"},
        "tool_result": {"stdout": stdout, "stderr": stderr},
    }
    result = run_hook_raw(OUTPUT_SANITIZER, SANITIZER_RULES, hook_input)

    if result.returncode == 0 and result.stdout.strip():
        try:
            output = json.loads(result.stdout)
            updated = output.get("hookSpecificOutput", {}).get("updatedToolResult", {})
            return {
                "redacted": True,
                "stdout": updated.get("stdout", stdout),
                "stderr": updated.get("stderr", stderr),
            }
        except json.JSONDecodeError:
            pass
    return {"redacted": False, "stdout": stdout, "stderr": stderr}


# --- Test cases: (description, stdout, stderr, should_redact, check_fn) ---

REDACT_CASES = [
    # API keys
    ("Redact: Anthropic API key",
     "Key: sk-ant-abc123def456-xyz", "",
     True, lambda r: "sk-ant-" not in r["stdout"]),
    ("Redact: GitHub PAT",
     "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "",
     True, lambda r: "ghp_" not in r["stdout"]),
    ("Redact: Stripe key",
     "STRIPE=sk_live_abc123def456ghi789jkl012", "",
     True, lambda r: "sk_live_" not in r["stdout"]),
    ("Redact: AWS access key",
     "aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "",
     True, lambda r: "AKIA" not in r["stdout"]),
    ("Redact: JWT token",
     "auth: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "",
     True, lambda r: "eyJhbG" not in r["stdout"]),

    # PII
    ("Redact: SSN",
     "SSN: 123-45-6789", "",
     True, lambda r: "123-45-6789" not in r["stdout"]),
    ("Redact: Visa card",
     "card: 4111 1111 1111 1111", "",
     True, lambda r: "4111" not in r["stdout"]),
    ("Redact: Mastercard",
     "card: 5500 0000 0000 0004", "",
     True, lambda r: "5500" not in r["stdout"]),
    ("Redact: email address",
     "contact: user@example.com", "",
     True, lambda r: "user@example.com" not in r["stdout"]),

    # Infrastructure
    ("Redact: private key header",
     "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQI...", "",
     True, lambda r: "BEGIN RSA PRIVATE KEY" not in r["stdout"]),
    ("Redact: DB connection string",
     "postgres://admin:secret@db.example.com:5432/mydb", "",
     True, lambda r: "admin:secret" not in r["stdout"]),
    ("Redact: internal IP",
     "Server: 10.0.1.55:8080", "",
     True, lambda r: "10.0.1.55" not in r["stdout"]),
    ("Redact: RFC1918 192.168.x",
     "host: 192.168.1.100", "",
     True, lambda r: "192.168.1.100" not in r["stdout"]),

    # Stderr redaction
    ("Redact: API key in stderr",
     "", "Error: invalid key sk-ant-abc123def456",
     True, lambda r: "sk-ant-" not in r["stderr"]),
]

PASS_THROUGH_CASES = [
    ("Pass: normal output",
     "Hello, world!", "", False),
    ("Pass: JSON output",
     '{"status": "ok", "count": 42}', "", False),
    ("Pass: build log",
     "Compiling src/main.rs...\nFinished release [optimized]", "", False),
    ("Pass: git log",
     "abc1234 Fix typo in README\ndef5678 Add feature X", "", False),
    ("Pass: empty output",
     "", "", False),
]


def main():
    t = TestRunner("Testing Output Sanitizer Hook")
    t.header()

    t.section("Redaction cases")
    for desc, stdout, stderr, should_redact, check_fn in REDACT_CASES:
        result = _run_sanitizer(stdout, stderr)
        if should_redact:
            ok = result["redacted"] and check_fn(result)
            print(f"  [{'PASS' if ok else 'FAIL'}] {desc}")
            if not ok:
                print(f"         redacted={result['redacted']}, stdout={result['stdout'][:100]}")
        else:
            ok = not result["redacted"]
            print(f"  [{'PASS' if ok else 'FAIL'}] {desc}")
        if ok:
            t.passed += 1
        else:
            t.failed += 1

    t.section("Pass-through cases")
    for desc, stdout, stderr, should_redact in PASS_THROUGH_CASES:
        result = _run_sanitizer(stdout, stderr)
        ok = not result["redacted"]
        print(f"  [{'PASS' if ok else 'FAIL'}] {desc}")
        if not ok:
            print(f"         Unexpectedly redacted: {result['stdout'][:100]}")
        if ok:
            t.passed += 1
        else:
            t.failed += 1

    sys.exit(t.summary())


if __name__ == "__main__":
    main()
