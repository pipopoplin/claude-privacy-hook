#!/usr/bin/env python3
"""Test the breach notification report generator.

Covers audit log loading, breach detection, severity calculation,
session filtering, and all three output formats (text, JSON, markdown).
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import HOOKS_DIR, TestRunner

sys.path.insert(0, HOOKS_DIR)
import breach_report


# =====================================================================
# Helpers
# =====================================================================

def _make_entry(
    action: str = "deny",
    session_id: str = "sess-001",
    timestamp: str = "2026-03-15T10:00:00",
    rule_name: str = "block_sensitive_data",
    matched_patterns: list | None = None,
    scf_domain: str = "IAC",
    scf_controls: list | None = None,
    scf_risk_level: str = "critical",
    scf_regulations: list | None = None,
) -> dict:
    """Build a synthetic audit log entry."""
    entry = {
        "timestamp": timestamp,
        "filter": "regex_filter",
        "rule_name": rule_name,
        "action": action,
        "session_id": session_id,
        "matched_patterns": matched_patterns or ["Anthropic API key"],
        "command_hash": "sha256:abc123",
    }
    if scf_domain:
        entry["scf_domain"] = scf_domain
    if scf_controls:
        entry["scf_controls"] = scf_controls
    if scf_risk_level:
        entry["scf_risk_level"] = scf_risk_level
    if scf_regulations:
        entry["scf_regulations"] = scf_regulations
    return entry


def _write_log(entries: list[dict]) -> str:
    """Write entries to a temp JSONL file, return path."""
    fd, path = tempfile.mkstemp(suffix=".log", prefix="test_breach_")
    with os.fdopen(fd, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
    return path


# =====================================================================
# Tests: load_audit_log
# =====================================================================

def test_load_nonexistent(t: TestRunner):
    """Nonexistent file returns empty list."""
    entries = breach_report.load_audit_log("/tmp/nonexistent_breach_xyz.log")
    t.check("Nonexistent file → empty list", entries, [])


def test_load_with_since(t: TestRunner):
    """Since filter works."""
    entries = [
        _make_entry(timestamp="2026-03-01T10:00:00"),
        _make_entry(timestamp="2026-03-15T10:00:00"),
    ]
    path = _write_log(entries)
    try:
        result = breach_report.load_audit_log(path, since="2026-03-10")
        t.check("Since filter: 1 entry", len(result), 1)
    finally:
        os.unlink(path)


def test_load_skips_bad_json(t: TestRunner):
    """Malformed lines skipped."""
    fd, path = tempfile.mkstemp(suffix=".log")
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(_make_entry()) + "\n")
        f.write("bad json\n")
    try:
        result = breach_report.load_audit_log(path)
        t.check("Bad JSON skipped, 1 valid entry", len(result), 1)
    finally:
        os.unlink(path)


# =====================================================================
# Tests: detect_breaches
# =====================================================================

def test_detect_breach_above_threshold(t: TestRunner):
    """Session with deny_count >= threshold is a breach candidate."""
    entries = [_make_entry(session_id="s1") for _ in range(10)]
    breaches = breach_report.detect_breaches(entries, threshold=10)
    t.check("1 breach detected", len(breaches), 1)
    t.check("Session ID", breaches[0]["session_id"], "s1")
    t.check("Deny count", breaches[0]["deny_count"], 10)


def test_detect_no_breach_below_threshold(t: TestRunner):
    """Session below threshold is not a breach."""
    entries = [_make_entry(session_id="s1") for _ in range(5)]
    breaches = breach_report.detect_breaches(entries, threshold=10)
    t.check("No breach below threshold", len(breaches), 0)


def test_detect_breach_custom_threshold(t: TestRunner):
    """Custom threshold works."""
    entries = [_make_entry(session_id="s1") for _ in range(3)]
    breaches = breach_report.detect_breaches(entries, threshold=3)
    t.check("Breach at custom threshold=3", len(breaches), 1)


def test_detect_breach_session_filter(t: TestRunner):
    """Session filter includes specific session regardless of threshold."""
    entries = [
        _make_entry(session_id="s1", action="deny"),
        _make_entry(session_id="s2", action="deny"),
    ]
    breaches = breach_report.detect_breaches(entries, threshold=100, session_filter="s1")
    t.check("Session filter: only s1", len(breaches), 1)
    t.check("Session filter: correct session", breaches[0]["session_id"], "s1")


def test_detect_breach_multiple_sessions(t: TestRunner):
    """Multiple sessions evaluated independently."""
    entries = (
        [_make_entry(session_id="s1") for _ in range(10)] +
        [_make_entry(session_id="s2") for _ in range(5)]
    )
    breaches = breach_report.detect_breaches(entries, threshold=10)
    t.check("Only s1 is a breach (10 denies)", len(breaches), 1)
    t.check("Breach session is s1", breaches[0]["session_id"], "s1")


def test_detect_breach_sorted_by_deny_count(t: TestRunner):
    """Breaches sorted by deny_count descending."""
    entries = (
        [_make_entry(session_id="s1") for _ in range(10)] +
        [_make_entry(session_id="s2") for _ in range(15)]
    )
    breaches = breach_report.detect_breaches(entries, threshold=10)
    t.check("Sorted: first has higher deny_count",
            breaches[0]["deny_count"] >= breaches[1]["deny_count"], True)


def test_detect_breach_counts_actions(t: TestRunner):
    """Deny, ask, redact counts tracked separately."""
    entries = [
        _make_entry(session_id="s1", action="deny"),
        _make_entry(session_id="s1", action="deny"),
        _make_entry(session_id="s1", action="ask"),
        _make_entry(session_id="s1", action="redact"),
    ]
    breaches = breach_report.detect_breaches(entries, threshold=2)
    b = breaches[0]
    t.check("Deny count", b["deny_count"], 2)
    t.check("Ask count", b["ask_count"], 1)
    t.check("Redact count", b["redact_count"], 1)
    t.check("Total events", b["total_events"], 4)


def test_detect_breach_collects_data_types(t: TestRunner):
    """Data types collected from matched_patterns."""
    entries = [
        _make_entry(session_id="s1", matched_patterns=["API key"]),
        _make_entry(session_id="s1", matched_patterns=["SSN"]),
        _make_entry(session_id="s1", matched_patterns=["API key"]),  # duplicate
    ]
    breaches = breach_report.detect_breaches(entries, threshold=3)
    t.check("Data types: 2 unique types", len(breaches[0]["data_types"]), 2)
    t.check("Data types: API key present", "API key" in breaches[0]["data_types"], True)
    t.check("Data types: SSN present", "SSN" in breaches[0]["data_types"], True)


def test_detect_breach_collects_scf_metadata(t: TestRunner):
    """SCF controls, domains, regulations collected."""
    entries = [
        _make_entry(session_id="s1", scf_controls=["IAC-01"], scf_domain="IAC",
                     scf_regulations=["GDPR Art.32"]),
        _make_entry(session_id="s1", scf_controls=["PRI-01"], scf_domain="PRI",
                     scf_regulations=["GDPR Art.9"]),
    ]
    breaches = breach_report.detect_breaches(entries, threshold=2)
    b = breaches[0]
    t.check("SCF controls collected", len(b["scf_controls"]), 2)
    t.check("SCF domains collected", len(b["scf_domains"]), 2)
    t.check("Regulations collected", len(b["regulations"]), 2)


def test_detect_breach_severity_critical(t: TestRunner):
    """Severity = critical when critical risk level present."""
    entries = [_make_entry(session_id="s1", scf_risk_level="critical") for _ in range(10)]
    breaches = breach_report.detect_breaches(entries, threshold=10)
    t.check("Severity = critical", breaches[0]["severity"], "critical")


def test_detect_breach_severity_high(t: TestRunner):
    """Severity = high when high but not critical."""
    entries = [_make_entry(session_id="s1", scf_risk_level="high") for _ in range(10)]
    breaches = breach_report.detect_breaches(entries, threshold=10)
    t.check("Severity = high", breaches[0]["severity"], "high")


def test_detect_breach_severity_medium(t: TestRunner):
    """Severity = medium when only medium risk."""
    entries = [_make_entry(session_id="s1", scf_risk_level="medium") for _ in range(10)]
    breaches = breach_report.detect_breaches(entries, threshold=10)
    t.check("Severity = medium", breaches[0]["severity"], "medium")


def test_detect_breach_time_window(t: TestRunner):
    """First/last seen timestamps tracked."""
    entries = [
        _make_entry(session_id="s1", timestamp="2026-03-10T08:00:00"),
        _make_entry(session_id="s1", timestamp="2026-03-15T20:00:00"),
    ]
    breaches = breach_report.detect_breaches(entries, threshold=2)
    t.check("First seen", breaches[0]["first_seen"], "2026-03-10T08:00:00")
    t.check("Last seen", breaches[0]["last_seen"], "2026-03-15T20:00:00")


def test_detect_breach_skips_no_session_id(t: TestRunner):
    """Entries without session_id are skipped."""
    entries = [_make_entry(session_id="") for _ in range(15)]
    breaches = breach_report.detect_breaches(entries, threshold=10)
    t.check("No session_id → no breach", len(breaches), 0)


# =====================================================================
# Tests: _consequences_text
# =====================================================================

def test_consequences_critical_gdpr(t: TestRunner):
    """Critical + GDPR regulations → specific text."""
    breach = {
        "risk_levels": ["critical"],
        "regulations": ["GDPR Art.32"],
    }
    text = breach_report._consequences_text(breach)
    t.check("Critical consequence text", "highly sensitive" in text.lower(), True)
    t.check("GDPR consequence text", "GDPR" in text, True)


def test_consequences_pci(t: TestRunner):
    """PCI regulation → payment card text."""
    breach = {"risk_levels": ["high"], "regulations": ["PCI-DSS Req.3"]}
    text = breach_report._consequences_text(breach)
    t.check("PCI consequence text", "Payment card" in text, True)


def test_consequences_default(t: TestRunner):
    """No special risk/regulation → default text."""
    breach = {"risk_levels": [], "regulations": []}
    text = breach_report._consequences_text(breach)
    t.check("Default consequence text", "assess data exposure risk" in text.lower(), True)


# =====================================================================
# Tests: format_text
# =====================================================================

def test_format_text_no_breaches(t: TestRunner):
    """Text format with no breaches."""
    text = breach_report.format_text([], threshold=10)
    t.check("No breaches: header present", "BREACH NOTIFICATION REPORT" in text, True)
    t.check("No breaches: message", "No sessions exceed" in text, True)


def test_format_text_with_breach(t: TestRunner):
    """Text format with one breach has all 7 sections."""
    breach = {
        "session_id": "s1",
        "severity": "critical",
        "deny_count": 15,
        "ask_count": 3,
        "redact_count": 2,
        "total_events": 20,
        "data_types": ["API key", "SSN"],
        "scf_controls": ["IAC-01"],
        "scf_domains": ["IAC"],
        "risk_levels": ["critical"],
        "regulations": ["GDPR Art.32"],
        "rules": ["block_sensitive_data"],
        "first_seen": "2026-03-10T10:00:00",
        "last_seen": "2026-03-15T10:00:00",
    }
    text = breach_report.format_text([breach], threshold=10)
    t.check("Section 1: Nature", "Nature of the breach" in text, True)
    t.check("Section 2: Categories", "Categories of personal data" in text, True)
    t.check("Section 3: Scale", "Approximate scale" in text, True)
    t.check("Section 4: Consequences", "Likely consequences" in text, True)
    t.check("Section 5: Measures", "Measures taken" in text, True)
    t.check("Section 6: Regulatory", "Regulatory context" in text, True)
    t.check("Section 7: Contact", "Contact information" in text, True)
    t.check("GDPR footer", "72 hours" in text, True)


# =====================================================================
# Tests: format_markdown
# =====================================================================

def test_format_markdown_no_breaches(t: TestRunner):
    """Markdown format with no breaches."""
    md = breach_report.format_markdown([], threshold=10)
    t.check("MD: header", "# Breach Notification Report" in md, True)
    t.check("MD: no breaches message", "No sessions exceed" in md, True)


def test_format_markdown_with_breach(t: TestRunner):
    """Markdown format has proper structure."""
    breach = {
        "session_id": "s1", "severity": "high",
        "deny_count": 12, "ask_count": 0, "redact_count": 1,
        "total_events": 13,
        "data_types": ["API key"],
        "scf_controls": ["IAC-01"], "scf_domains": ["IAC"],
        "risk_levels": ["high"], "regulations": ["GDPR Art.32"],
        "rules": ["block_sensitive_data"],
        "first_seen": "2026-03-15T10:00:00",
        "last_seen": "2026-03-15T11:00:00",
    }
    md = breach_report.format_markdown([breach], threshold=10)
    t.check("MD: has heading", "## Breach Candidate #1" in md, True)
    t.check("MD: has session code block", "`s1`" in md, True)
    t.check("MD: GDPR footer italic", "*GDPR Art.33" in md, True)


# =====================================================================
# Tests: format_json
# =====================================================================

def test_format_json_structure(t: TestRunner):
    """JSON output has required fields."""
    breach = {
        "session_id": "s1", "severity": "critical",
        "deny_count": 10, "ask_count": 0, "redact_count": 0,
        "total_events": 10,
        "data_types": ["API key"],
        "scf_controls": ["IAC-01"], "scf_domains": ["IAC"],
        "risk_levels": ["critical"], "regulations": [],
        "rules": ["block_sensitive_data"],
        "first_seen": "2026-03-15T10:00:00",
        "last_seen": "2026-03-15T11:00:00",
    }
    json_str = breach_report.format_json([breach], threshold=10)
    report = json.loads(json_str)
    t.check("JSON: has generated", "generated" in report, True)
    t.check("JSON: has threshold", report["threshold"], 10)
    t.check("JSON: has breach_candidates", report["breach_candidates"], 1)
    t.check("JSON: has breaches list", len(report["breaches"]), 1)
    t.check("JSON: breach has session_id", report["breaches"][0]["session_id"], "s1")


def test_format_json_empty(t: TestRunner):
    """JSON output with no breaches."""
    json_str = breach_report.format_json([], threshold=10)
    report = json.loads(json_str)
    t.check("JSON empty: 0 candidates", report["breach_candidates"], 0)
    t.check("JSON empty: empty breaches", report["breaches"], [])


# =====================================================================
# Main
# =====================================================================

def main():
    t = TestRunner("Testing Breach Report")
    t.header()

    t.section("load_audit_log")
    test_load_nonexistent(t)
    test_load_with_since(t)
    test_load_skips_bad_json(t)

    t.section("detect_breaches — threshold and counting")
    test_detect_breach_above_threshold(t)
    test_detect_no_breach_below_threshold(t)
    test_detect_breach_custom_threshold(t)
    test_detect_breach_session_filter(t)
    test_detect_breach_multiple_sessions(t)
    test_detect_breach_sorted_by_deny_count(t)
    test_detect_breach_counts_actions(t)
    test_detect_breach_skips_no_session_id(t)

    t.section("detect_breaches — data collection")
    test_detect_breach_collects_data_types(t)
    test_detect_breach_collects_scf_metadata(t)
    test_detect_breach_time_window(t)

    t.section("detect_breaches — severity")
    test_detect_breach_severity_critical(t)
    test_detect_breach_severity_high(t)
    test_detect_breach_severity_medium(t)

    t.section("_consequences_text")
    test_consequences_critical_gdpr(t)
    test_consequences_pci(t)
    test_consequences_default(t)

    t.section("format_text")
    test_format_text_no_breaches(t)
    test_format_text_with_breach(t)

    t.section("format_markdown")
    test_format_markdown_no_breaches(t)
    test_format_markdown_with_breach(t)

    t.section("format_json")
    test_format_json_structure(t)
    test_format_json_empty(t)

    sys.exit(t.summary())


if __name__ == "__main__":
    main()
