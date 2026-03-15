#!/usr/bin/env python3
"""Breach notification report generator for claude-privacy-hook.

Reads the audit log, identifies sessions exceeding a violation threshold,
and generates a structured breach notification report compatible with
GDPR Art.33 requirements.

Usage:
    python3 breach_report.py                             # All breach candidates
    python3 breach_report.py --session SESSION_ID        # Specific session
    python3 breach_report.py --threshold 5               # Custom threshold (default: 10)
    python3 breach_report.py --since 2026-03-01          # Date filter
    python3 breach_report.py --format json               # JSON output
    python3 breach_report.py --format markdown            # Markdown output

SCF controls: IRO-10 (incident stakeholder reporting), IRO-04.1 (breach evidence)
DPMP: P8.2 (breach notification)
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict


def load_audit_log(log_path: str, since: str | None = None) -> list[dict]:
    """Read all JSONL entries from the audit log."""
    entries = []
    if not os.path.isfile(log_path):
        return entries
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if since:
                ts = entry.get("timestamp", "")
                if ts < since:
                    continue
            entries.append(entry)
    return entries


def detect_breaches(entries: list[dict], threshold: int,
                    session_filter: str | None = None) -> list[dict]:
    """Identify sessions that exceed the violation threshold.

    A "breach candidate" is a session with deny count >= threshold,
    indicating potential data exposure attempts.
    """
    sessions = defaultdict(lambda: {
        "events": [],
        "deny_count": 0,
        "ask_count": 0,
        "redact_count": 0,
        "data_types": set(),
        "scf_controls": set(),
        "scf_domains": set(),
        "risk_levels": set(),
        "regulations": set(),
        "rules": set(),
        "first_seen": "",
        "last_seen": "",
    })

    for entry in entries:
        sid = entry.get("session_id", "")
        if not sid:
            continue
        if session_filter and sid != session_filter:
            continue

        s = sessions[sid]
        s["events"].append(entry)

        action = entry.get("action", "")
        if action == "deny":
            s["deny_count"] += 1
        elif action == "ask":
            s["ask_count"] += 1
        elif action == "redact":
            s["redact_count"] += 1

        # Collect data types from matched patterns
        for pat in entry.get("matched_patterns", []):
            s["data_types"].add(pat)

        # SCF metadata
        for ctrl in entry.get("scf_controls", []):
            s["scf_controls"].add(ctrl)
        domain = entry.get("scf_domain", "")
        if domain:
            s["scf_domains"].add(domain)
        risk = entry.get("scf_risk_level", "")
        if risk:
            s["risk_levels"].add(risk)
        for reg in entry.get("scf_regulations", []):
            s["regulations"].add(reg)
        rule = entry.get("rule_name", "")
        if rule:
            s["rules"].add(rule)

        ts = entry.get("timestamp", "")
        if ts:
            if not s["first_seen"] or ts < s["first_seen"]:
                s["first_seen"] = ts
            if ts > s["last_seen"]:
                s["last_seen"] = ts

    # Filter to breach candidates
    breaches = []
    for sid, s in sessions.items():
        if s["deny_count"] >= threshold or session_filter:
            severity = "critical" if "critical" in s["risk_levels"] else (
                "high" if "high" in s["risk_levels"] else "medium"
            )
            breaches.append({
                "session_id": sid,
                "severity": severity,
                "deny_count": s["deny_count"],
                "ask_count": s["ask_count"],
                "redact_count": s["redact_count"],
                "total_events": len(s["events"]),
                "data_types": sorted(s["data_types"]),
                "scf_controls": sorted(s["scf_controls"]),
                "scf_domains": sorted(s["scf_domains"]),
                "risk_levels": sorted(s["risk_levels"]),
                "regulations": sorted(s["regulations"]),
                "rules": sorted(s["rules"]),
                "first_seen": s["first_seen"],
                "last_seen": s["last_seen"],
            })

    breaches.sort(key=lambda b: -b["deny_count"])
    return breaches


def _consequences_text(breach: dict) -> str:
    """Describe likely consequences based on data types and risk levels."""
    parts = []
    if "critical" in breach["risk_levels"]:
        parts.append("Direct exposure of highly sensitive data (credentials, PII, financial)")
    if "high" in breach["risk_levels"]:
        parts.append("Potential exposure of sensitive infrastructure or personal data")
    if any("GDPR" in r for r in breach["regulations"]):
        parts.append("GDPR-regulated personal data may have been processed by AI agent")
    if any("PCI" in r for r in breach["regulations"]):
        parts.append("Payment card data may have been exposed")
    if not parts:
        parts.append("Security control violations detected; assess data exposure risk")
    return "; ".join(parts)


def format_text(breaches: list[dict], threshold: int) -> str:
    """Format breach report as human-readable text."""
    lines = []
    generated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    lines.append("=" * 72)
    lines.append("  BREACH NOTIFICATION REPORT")
    lines.append(f"  Generated: {generated}")
    lines.append(f"  Detection threshold: {threshold} deny events per session")
    lines.append(f"  Breach candidates found: {len(breaches)}")
    lines.append("=" * 72)

    if not breaches:
        lines.append("\n  No sessions exceed the breach threshold.")
        lines.append("=" * 72)
        return "\n".join(lines)

    for i, b in enumerate(breaches, 1):
        lines.append(f"\n  --- Breach Candidate #{i} (severity: {b['severity'].upper()}) ---")
        lines.append("")
        lines.append("  1. Nature of the breach")
        lines.append(f"     Session: {b['session_id']}")
        lines.append(f"     Period: {b['first_seen']} → {b['last_seen']}")
        lines.append(f"     Events: {b['total_events']} total ({b['deny_count']} deny, {b['ask_count']} ask, {b['redact_count']} redact)")
        lines.append("")
        lines.append("  2. Categories of personal data affected")
        for dt in b["data_types"][:20]:
            lines.append(f"     - {dt}")
        if len(b["data_types"]) > 20:
            lines.append(f"     ... and {len(b['data_types']) - 20} more")
        lines.append("")
        lines.append("  3. Approximate scale")
        lines.append(f"     {b['deny_count']} blocked data exposure attempts")
        lines.append(f"     {b['redact_count']} output redactions (data was in command output)")
        lines.append("")
        lines.append("  4. Likely consequences")
        lines.append(f"     {_consequences_text(b)}")
        lines.append("")
        lines.append("  5. Measures taken")
        lines.append(f"     - {b['deny_count']} commands blocked (deny)")
        lines.append(f"     - {b['ask_count']} commands flagged for human review (ask)")
        lines.append(f"     - {b['redact_count']} outputs redacted")
        lines.append(f"     - Rules triggered: {', '.join(b['rules'][:10])}")
        lines.append("")
        lines.append("  6. Regulatory context")
        if b["regulations"]:
            lines.append(f"     Applicable: {', '.join(b['regulations'])}")
        else:
            lines.append("     No specific regulatory mapping for triggered rules")
        lines.append(f"     SCF controls: {', '.join(b['scf_controls'][:10])}")
        lines.append(f"     SCF domains: {', '.join(b['scf_domains'])}")
        lines.append("")
        lines.append("  7. Contact information")
        lines.append("     [TODO: Add Data Protection Officer / incident response contact]")

    lines.append("")
    lines.append("  ---")
    lines.append("  GDPR Art.33 requires notification to supervisory authority within 72 hours")
    lines.append("  of becoming aware of a personal data breach.")
    lines.append("=" * 72)
    return "\n".join(lines)


def format_markdown(breaches: list[dict], threshold: int) -> str:
    """Format breach report as Markdown."""
    generated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    lines = []

    lines.append("# Breach Notification Report")
    lines.append("")
    lines.append(f"**Generated:** {generated}")
    lines.append(f"**Detection threshold:** {threshold} deny events per session")
    lines.append(f"**Breach candidates:** {len(breaches)}")
    lines.append("")

    if not breaches:
        lines.append("No sessions exceed the breach threshold.")
        return "\n".join(lines)

    for i, b in enumerate(breaches, 1):
        lines.append(f"## Breach Candidate #{i} — Severity: {b['severity'].upper()}")
        lines.append("")

        lines.append("### 1. Nature of the breach")
        lines.append(f"- **Session:** `{b['session_id']}`")
        lines.append(f"- **Period:** {b['first_seen']} → {b['last_seen']}")
        lines.append(f"- **Events:** {b['total_events']} total ({b['deny_count']} deny, {b['ask_count']} ask, {b['redact_count']} redact)")
        lines.append("")

        lines.append("### 2. Categories of personal data affected")
        for dt in b["data_types"][:20]:
            lines.append(f"- {dt}")
        lines.append("")

        lines.append("### 3. Approximate scale")
        lines.append(f"- {b['deny_count']} blocked data exposure attempts")
        lines.append(f"- {b['redact_count']} output redactions")
        lines.append("")

        lines.append("### 4. Likely consequences")
        lines.append(f"{_consequences_text(b)}")
        lines.append("")

        lines.append("### 5. Measures taken")
        lines.append(f"- {b['deny_count']} commands blocked (deny)")
        lines.append(f"- {b['ask_count']} commands flagged for review (ask)")
        lines.append(f"- {b['redact_count']} outputs redacted")
        lines.append(f"- Rules: {', '.join(b['rules'][:10])}")
        lines.append("")

        lines.append("### 6. Regulatory context")
        lines.append(f"- **Regulations:** {', '.join(b['regulations']) if b['regulations'] else 'None mapped'}")
        lines.append(f"- **SCF controls:** {', '.join(b['scf_controls'][:10])}")
        lines.append(f"- **SCF domains:** {', '.join(b['scf_domains'])}")
        lines.append("")

        lines.append("### 7. Contact information")
        lines.append("[TODO: Add Data Protection Officer / incident response contact]")
        lines.append("")
        lines.append("---")
        lines.append("")

    lines.append("*GDPR Art.33 requires notification to supervisory authority within 72 hours of becoming aware of a personal data breach.*")
    return "\n".join(lines)


def format_json(breaches: list[dict], threshold: int) -> str:
    """Format breach report as JSON."""
    report = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "threshold": threshold,
        "breach_candidates": len(breaches),
        "breaches": breaches,
    }
    return json.dumps(report, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Generate breach notification report from audit log",
    )
    parser.add_argument(
        "--format", choices=["text", "json", "markdown"], default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--log", default=None,
        help="Audit log path (default: audit.log in hooks dir)",
    )
    parser.add_argument(
        "--since", default=None,
        help="Only include events from this date (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--session", default=None,
        help="Report on a specific session ID",
    )
    parser.add_argument(
        "--threshold", type=int, default=10,
        help="Deny count threshold for breach detection (default: 10)",
    )
    args = parser.parse_args()

    hooks_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = args.log or os.environ.get(
        "HOOK_AUDIT_LOG",
        os.path.join(hooks_dir, "audit.log"),
    )

    entries = load_audit_log(log_path, since=args.since)
    if not entries:
        print("No audit events found.", file=sys.stderr)
        sys.exit(0)

    breaches = detect_breaches(entries, args.threshold, session_filter=args.session)

    if args.format == "json":
        print(format_json(breaches, args.threshold))
    elif args.format == "markdown":
        print(format_markdown(breaches, args.threshold))
    else:
        print(format_text(breaches, args.threshold))


if __name__ == "__main__":
    main()
