#!/usr/bin/env python3
"""Test the compliance evidence collector.

Covers cross-session analysis (hot rule detection), text/JSON formatting,
audit log loading, SCF control grouping, and override activity reporting.
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from conftest import HOOKS_DIR, TestRunner

sys.path.insert(0, HOOKS_DIR)
import evidence_collector


# =====================================================================
# Helpers
# =====================================================================

def _make_entry(
    rule_name: str = "block_sensitive_data",
    action: str = "deny",
    session_id: str = "sess-001",
    timestamp: str = "2026-03-15T10:00:00",
    scf_domain: str = "IAC",
    scf_controls: list | None = None,
    scf_risk_level: str = "critical",
    scf_regulations: list | None = None,
    matched_patterns: list | None = None,
    override_name: str = "",
    override_source: str = "",
) -> dict:
    """Build a synthetic audit log entry."""
    entry = {
        "timestamp": timestamp,
        "filter": "regex_filter",
        "rule_name": rule_name,
        "action": action,
        "session_id": session_id,
        "matched_patterns": matched_patterns or ["test pattern"],
        "command_hash": "sha256:abc123",
        "command_preview": "test command",
    }
    if scf_domain:
        entry["scf_domain"] = scf_domain
    if scf_controls is not None:
        entry["scf_controls"] = scf_controls
    else:
        entry["scf_controls"] = ["IAC-01"]
    if scf_risk_level:
        entry["scf_risk_level"] = scf_risk_level
    if scf_regulations is not None:
        entry["scf_regulations"] = scf_regulations
    if override_name:
        entry["override_name"] = override_name
        entry["override_source"] = override_source
    return entry


def _write_log(entries: list[dict]) -> str:
    """Write entries to a temp JSONL file, return path."""
    fd, path = tempfile.mkstemp(suffix=".log", prefix="test_evidence_")
    with os.fdopen(fd, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
    return path


# =====================================================================
# Tests: load_audit_log
# =====================================================================

def test_load_empty_file(t: TestRunner):
    """Empty log file returns empty list."""
    fd, path = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    try:
        entries = evidence_collector.load_audit_log(path)
        t.check("Empty file → empty list", entries, [])
    finally:
        os.unlink(path)


def test_load_nonexistent_file(t: TestRunner):
    """Nonexistent file returns empty list."""
    entries = evidence_collector.load_audit_log("/tmp/nonexistent_evidence_xyz.log")
    t.check("Nonexistent file → empty list", entries, [])


def test_load_with_since_filter(t: TestRunner):
    """--since filters entries before the date."""
    entries = [
        _make_entry(timestamp="2026-03-01T10:00:00"),
        _make_entry(timestamp="2026-03-10T10:00:00"),
        _make_entry(timestamp="2026-03-15T10:00:00"),
    ]
    path = _write_log(entries)
    try:
        result = evidence_collector.load_audit_log(path, since="2026-03-10")
        t.check("Since filter: 2 entries from Mar 10+", len(result), 2)
    finally:
        os.unlink(path)


def test_load_skips_malformed_json(t: TestRunner):
    """Malformed JSON lines are skipped."""
    fd, path = tempfile.mkstemp(suffix=".log")
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(_make_entry()) + "\n")
        f.write("not valid json\n")
        f.write(json.dumps(_make_entry()) + "\n")
    try:
        result = evidence_collector.load_audit_log(path)
        t.check("Malformed lines skipped, 2 valid entries", len(result), 2)
    finally:
        os.unlink(path)


# =====================================================================
# Tests: group_by_scf_control
# =====================================================================

def test_group_by_scf_single_control(t: TestRunner):
    """Single control groups correctly."""
    entries = [
        _make_entry(scf_controls=["IAC-01"]),
        _make_entry(scf_controls=["IAC-01"]),
    ]
    controls = evidence_collector.group_by_scf_control(entries)
    t.check("One control ID", "IAC-01" in controls, True)
    t.check("Two events under IAC-01", len(controls["IAC-01"]["events"]), 2)


def test_group_by_scf_multiple_controls(t: TestRunner):
    """Entry with multiple controls appears under each."""
    entries = [_make_entry(scf_controls=["IAC-01", "PRI-01"])]
    controls = evidence_collector.group_by_scf_control(entries)
    t.check("IAC-01 has 1 event", len(controls["IAC-01"]["events"]), 1)
    t.check("PRI-01 has 1 event", len(controls["PRI-01"]["events"]), 1)


def test_group_by_scf_unmapped(t: TestRunner):
    """Entries without scf_controls grouped under UNMAPPED."""
    entries = [_make_entry(scf_controls=None)]
    # Remove scf_controls key entirely
    entries[0].pop("scf_controls", None)
    controls = evidence_collector.group_by_scf_control(entries)
    t.check("UNMAPPED group exists", "UNMAPPED" in controls, True)


def test_group_tracks_actions(t: TestRunner):
    """Action counts are tracked per control."""
    entries = [
        _make_entry(action="deny", scf_controls=["IAC-01"]),
        _make_entry(action="deny", scf_controls=["IAC-01"]),
        _make_entry(action="ask", scf_controls=["IAC-01"]),
    ]
    controls = evidence_collector.group_by_scf_control(entries)
    t.check("Deny count", controls["IAC-01"]["actions"]["deny"], 2)
    t.check("Ask count", controls["IAC-01"]["actions"]["ask"], 1)


# =====================================================================
# Tests: cross_session_analysis
# =====================================================================

def test_cross_session_hot_rule(t: TestRunner):
    """Rule triggered in 3+ sessions is hot."""
    entries = [
        _make_entry(rule_name="block_sensitive_data", session_id="s1"),
        _make_entry(rule_name="block_sensitive_data", session_id="s2"),
        _make_entry(rule_name="block_sensitive_data", session_id="s3"),
    ]
    analysis = evidence_collector.cross_session_analysis(entries, session_threshold=3)
    rule = analysis["block_sensitive_data"]
    t.check("Hot rule: is_hot=True", rule["is_hot"], True)
    t.check("Hot rule: 3 sessions", len(rule["sessions"]), 3)
    t.check("Hot rule: 3 events", rule["total_events"], 3)


def test_cross_session_cold_rule(t: TestRunner):
    """Rule triggered in fewer sessions than threshold is cold."""
    entries = [
        _make_entry(rule_name="block_sensitive_data", session_id="s1"),
        _make_entry(rule_name="block_sensitive_data", session_id="s2"),
    ]
    analysis = evidence_collector.cross_session_analysis(entries, session_threshold=3)
    rule = analysis["block_sensitive_data"]
    t.check("Cold rule: is_hot=False", rule["is_hot"], False)


def test_cross_session_multiple_events_same_session(t: TestRunner):
    """Multiple events in same session count as 1 session."""
    entries = [
        _make_entry(rule_name="rule_a", session_id="s1"),
        _make_entry(rule_name="rule_a", session_id="s1"),
        _make_entry(rule_name="rule_a", session_id="s1"),
    ]
    analysis = evidence_collector.cross_session_analysis(entries, session_threshold=3)
    rule = analysis["rule_a"]
    t.check("Same session: 1 session", len(rule["sessions"]), 1)
    t.check("Same session: 3 total events", rule["total_events"], 3)
    t.check("Same session: not hot", rule["is_hot"], False)


def test_cross_session_custom_threshold(t: TestRunner):
    """Custom threshold changes hot rule detection."""
    entries = [
        _make_entry(rule_name="rule_a", session_id="s1"),
        _make_entry(rule_name="rule_a", session_id="s2"),
    ]
    analysis = evidence_collector.cross_session_analysis(entries, session_threshold=2)
    t.check("Threshold=2: 2 sessions → hot", analysis["rule_a"]["is_hot"], True)


def test_cross_session_tracks_actions(t: TestRunner):
    """Action counts tracked per rule."""
    entries = [
        _make_entry(rule_name="rule_a", action="deny", session_id="s1"),
        _make_entry(rule_name="rule_a", action="ask", session_id="s2"),
        _make_entry(rule_name="rule_a", action="deny", session_id="s3"),
    ]
    analysis = evidence_collector.cross_session_analysis(entries, session_threshold=3)
    t.check("Actions: deny=2", analysis["rule_a"]["actions"]["deny"], 2)
    t.check("Actions: ask=1", analysis["rule_a"]["actions"]["ask"], 1)


def test_cross_session_time_window(t: TestRunner):
    """First/last seen timestamps tracked."""
    entries = [
        _make_entry(rule_name="rule_a", session_id="s1", timestamp="2026-03-10T10:00:00"),
        _make_entry(rule_name="rule_a", session_id="s2", timestamp="2026-03-15T10:00:00"),
    ]
    analysis = evidence_collector.cross_session_analysis(entries, session_threshold=1)
    t.check("First seen", analysis["rule_a"]["first_seen"], "2026-03-10T10:00:00")
    t.check("Last seen", analysis["rule_a"]["last_seen"], "2026-03-15T10:00:00")


def test_cross_session_empty_entries(t: TestRunner):
    """Empty entries → empty analysis."""
    analysis = evidence_collector.cross_session_analysis([], session_threshold=3)
    t.check("Empty entries → empty analysis", analysis, {})


def test_cross_session_no_rule_name_skipped(t: TestRunner):
    """Entries without rule_name are skipped."""
    entries = [{"timestamp": "2026-03-15T10:00:00", "session_id": "s1", "action": "deny"}]
    analysis = evidence_collector.cross_session_analysis(entries, session_threshold=1)
    t.check("No rule_name → empty analysis", analysis, {})


# =====================================================================
# Tests: format_cross_session_text
# =====================================================================

def test_format_cross_session_text_hot_rules(t: TestRunner):
    """Text format includes hot rule details."""
    entries = [
        _make_entry(rule_name="rule_hot", session_id=f"s{i}",
                     timestamp=f"2026-03-{10+i:02d}T10:00:00")
        for i in range(4)
    ]
    analysis = evidence_collector.cross_session_analysis(entries, session_threshold=3)
    text = evidence_collector.format_cross_session_text(analysis)
    t.check("Text: contains HOT RULES header", "HOT RULES" in text, True)
    t.check("Text: contains rule name", "rule_hot" in text, True)
    t.check("Text: contains session count", "4" in text, True)


def test_format_cross_session_text_no_hot(t: TestRunner):
    """Text format shows message when no hot rules."""
    entries = [_make_entry(rule_name="rule_a", session_id="s1")]
    analysis = evidence_collector.cross_session_analysis(entries, session_threshold=3)
    text = evidence_collector.format_cross_session_text(analysis)
    t.check("Text: no hot rules message", "No hot rules detected" in text, True)


# =====================================================================
# Tests: format_cross_session_json
# =====================================================================

def test_format_cross_session_json_structure(t: TestRunner):
    """JSON format has correct structure."""
    entries = [
        _make_entry(rule_name="rule_a", session_id="s1"),
        _make_entry(rule_name="rule_a", session_id="s2"),
        _make_entry(rule_name="rule_a", session_id="s3"),
    ]
    analysis = evidence_collector.cross_session_analysis(entries, session_threshold=3)
    result = evidence_collector.format_cross_session_json(analysis)
    t.check("JSON: rule_a exists", "rule_a" in result, True)
    t.check("JSON: sessions is int", isinstance(result["rule_a"]["sessions"], int), True)
    t.check("JSON: sessions=3", result["rule_a"]["sessions"], 3)
    t.check("JSON: is_hot=True", result["rule_a"]["is_hot"], True)
    t.check("JSON: has actions dict", isinstance(result["rule_a"]["actions"], dict), True)


# =====================================================================
# Tests: group_overrides
# =====================================================================

def test_group_overrides_basic(t: TestRunner):
    """Override_allow events grouped by name."""
    entries = [
        _make_entry(action="override_allow", override_name="allow_my_api",
                     override_source="project", session_id="s1"),
        _make_entry(action="override_allow", override_name="allow_my_api",
                     override_source="project", session_id="s2"),
    ]
    overrides = evidence_collector.group_overrides(entries)
    t.check("Override grouped", "allow_my_api" in overrides, True)
    t.check("Override count", overrides["allow_my_api"]["count"], 2)
    t.check("Override sessions", len(overrides["allow_my_api"]["sessions"]), 2)


def test_group_overrides_ignores_non_override(t: TestRunner):
    """Non-override_allow events are ignored."""
    entries = [
        _make_entry(action="deny"),
        _make_entry(action="ask"),
    ]
    overrides = evidence_collector.group_overrides(entries)
    t.check("No overrides from deny/ask events", len(overrides), 0)


# =====================================================================
# Tests: format_text report
# =====================================================================

def test_format_text_report_header(t: TestRunner):
    """Text report has proper header."""
    entries = [_make_entry()]
    controls = evidence_collector.group_by_scf_control(entries)
    text = evidence_collector.format_text(controls, entries)
    t.check("Header: COMPLIANCE EVIDENCE REPORT", "COMPLIANCE EVIDENCE REPORT" in text, True)
    t.check("Header: Total audit events", "Total audit events: 1" in text, True)


def test_format_text_domain_filter(t: TestRunner):
    """Domain filter limits output to specified domain."""
    entries = [
        _make_entry(scf_domain="IAC", scf_controls=["IAC-01"]),
        _make_entry(scf_domain="PRI", scf_controls=["PRI-01"]),
    ]
    controls = evidence_collector.group_by_scf_control(entries)
    text = evidence_collector.format_text(controls, entries, domain_filter="IAC")
    t.check("Domain filter: IAC present", "IAC" in text, True)
    # PRI control detail should be filtered out
    t.check("Domain filter: PRI-01 not in control detail",
            "PRI-01" not in text.split("Control Detail")[1] if "Control Detail" in text else True,
            True)


# =====================================================================
# Tests: format_json report
# =====================================================================

def test_format_json_report_structure(t: TestRunner):
    """JSON report has required fields."""
    entries = [_make_entry(scf_controls=["IAC-01"])]
    controls = evidence_collector.group_by_scf_control(entries)
    json_str = evidence_collector.format_json(controls, entries)
    report = json.loads(json_str)
    t.check("JSON: has generated", "generated" in report, True)
    t.check("JSON: has total_events", report["total_events"], 1)
    t.check("JSON: has controls", "IAC-01" in report["controls"], True)
    ctrl = report["controls"]["IAC-01"]
    t.check("JSON: control has domain", ctrl["domain"], "IAC")
    t.check("JSON: control has event_count", ctrl["event_count"], 1)


# =====================================================================
# Main
# =====================================================================

def main():
    t = TestRunner("Testing Evidence Collector")
    t.header()

    t.section("load_audit_log")
    test_load_empty_file(t)
    test_load_nonexistent_file(t)
    test_load_with_since_filter(t)
    test_load_skips_malformed_json(t)

    t.section("group_by_scf_control")
    test_group_by_scf_single_control(t)
    test_group_by_scf_multiple_controls(t)
    test_group_by_scf_unmapped(t)
    test_group_tracks_actions(t)

    t.section("cross_session_analysis")
    test_cross_session_hot_rule(t)
    test_cross_session_cold_rule(t)
    test_cross_session_multiple_events_same_session(t)
    test_cross_session_custom_threshold(t)
    test_cross_session_tracks_actions(t)
    test_cross_session_time_window(t)
    test_cross_session_empty_entries(t)
    test_cross_session_no_rule_name_skipped(t)

    t.section("format_cross_session_text")
    test_format_cross_session_text_hot_rules(t)
    test_format_cross_session_text_no_hot(t)

    t.section("format_cross_session_json")
    test_format_cross_session_json_structure(t)

    t.section("group_overrides")
    test_group_overrides_basic(t)
    test_group_overrides_ignores_non_override(t)

    t.section("format_text report")
    test_format_text_report_header(t)
    test_format_text_domain_filter(t)

    t.section("format_json report")
    test_format_json_report_structure(t)

    sys.exit(t.summary())


if __name__ == "__main__":
    main()
