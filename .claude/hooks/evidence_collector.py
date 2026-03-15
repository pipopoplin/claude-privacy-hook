#!/usr/bin/env python3
"""Compliance evidence collector for claude-privacy-hook.

Reads the audit log (JSONL), groups events by SCF control ID, and generates
a compliance evidence report in text or JSON format.

Usage:
    python3 evidence_collector.py [OPTIONS]

Options:
    --format text|json     Output format (default: text)
    --log PATH             Audit log path (default: audit.log in hooks dir)
    --since YYYY-MM-DD     Only include events from this date onward
    --domain DOMAIN        Filter to a specific SCF domain (e.g., IAC, PRI)
    --controls-only        Only show SCF control summary, skip event details
    --overrides            Include override activity report
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import date, datetime


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


def group_by_scf_control(entries: list[dict]) -> dict:
    """Group audit entries by SCF control ID.

    Returns {control_id: {"domain": str, "risk_level": str,
             "regulations": list, "events": list, "actions": Counter}}.
    """
    controls: dict = {}
    for entry in entries:
        scf_controls = entry.get("scf_controls", [])
        if not scf_controls:
            # Legacy entries without SCF tags — group under "UNMAPPED"
            scf_controls = ["UNMAPPED"]

        for cid in scf_controls:
            if cid not in controls:
                controls[cid] = {
                    "domain": entry.get("scf_domain", ""),
                    "risk_level": entry.get("scf_risk_level", ""),
                    "regulations": [],
                    "events": [],
                    "actions": defaultdict(int),
                    "rules": set(),
                    "sessions": set(),
                    "first_seen": entry.get("timestamp", ""),
                    "last_seen": entry.get("timestamp", ""),
                }
            info = controls[cid]
            info["events"].append(entry)
            info["actions"][entry.get("action", "unknown")] += 1
            info["rules"].add(entry.get("rule_name", "unknown"))
            info["sessions"].add(entry.get("session_id", ""))

            regs = entry.get("scf_regulations", [])
            for r in regs:
                if r not in info["regulations"]:
                    info["regulations"].append(r)

            ts = entry.get("timestamp", "")
            if ts and (not info["first_seen"] or ts < info["first_seen"]):
                info["first_seen"] = ts
            if ts and ts > info["last_seen"]:
                info["last_seen"] = ts

    return controls


def group_overrides(entries: list[dict]) -> dict:
    """Group override_allow events by override name."""
    overrides: dict = {}
    for entry in entries:
        if entry.get("action") != "override_allow":
            continue
        name = entry.get("override_name", "unknown")
        if name not in overrides:
            overrides[name] = {
                "source": entry.get("override_source", "unknown"),
                "count": 0,
                "sessions": set(),
                "first_used": entry.get("timestamp", ""),
                "last_used": entry.get("timestamp", ""),
            }
        overrides[name]["count"] += 1
        overrides[name]["sessions"].add(entry.get("session_id", ""))
        ts = entry.get("timestamp", "")
        if ts and ts > overrides[name]["last_used"]:
            overrides[name]["last_used"] = ts
    return overrides


def format_text(
    controls: dict,
    entries: list[dict],
    overrides: dict | None = None,
    controls_only: bool = False,
    domain_filter: str | None = None,
) -> str:
    """Format the evidence report as human-readable text."""
    lines = []
    lines.append("=" * 72)
    lines.append("  COMPLIANCE EVIDENCE REPORT")
    lines.append(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}")
    lines.append(f"  Total audit events: {len(entries)}")
    lines.append(f"  SCF controls covered: {len([c for c in controls if c != 'UNMAPPED'])}")
    lines.append("=" * 72)

    # Summary by domain
    domains: dict = defaultdict(lambda: {"controls": set(), "events": 0, "deny": 0, "ask": 0, "redact": 0})
    for cid, info in controls.items():
        if cid == "UNMAPPED":
            continue
        d = info["domain"] or "UNKNOWN"
        if domain_filter and d != domain_filter:
            continue
        domains[d]["controls"].add(cid)
        domains[d]["events"] += len(info["events"])
        domains[d]["deny"] += info["actions"].get("deny", 0)
        domains[d]["ask"] += info["actions"].get("ask", 0)
        domains[d]["redact"] += info["actions"].get("redact", 0)

    lines.append("")
    lines.append("  SCF Domain Summary")
    lines.append("  " + "-" * 68)
    lines.append(f"  {'Domain':<8} {'Controls':>8} {'Events':>8} {'Deny':>8} {'Ask':>8} {'Redact':>8}")
    lines.append("  " + "-" * 68)
    for d in sorted(domains.keys()):
        info = domains[d]
        lines.append(
            f"  {d:<8} {len(info['controls']):>8} {info['events']:>8} "
            f"{info['deny']:>8} {info['ask']:>8} {info['redact']:>8}"
        )
    total_events = sum(d["events"] for d in domains.values())
    total_deny = sum(d["deny"] for d in domains.values())
    total_ask = sum(d["ask"] for d in domains.values())
    total_redact = sum(d["redact"] for d in domains.values())
    lines.append("  " + "-" * 68)
    lines.append(
        f"  {'TOTAL':<8} {sum(len(d['controls']) for d in domains.values()):>8} "
        f"{total_events:>8} {total_deny:>8} {total_ask:>8} {total_redact:>8}"
    )

    # Per-control detail
    lines.append("")
    lines.append("  Control Detail")
    lines.append("  " + "-" * 68)

    for cid in sorted(controls.keys()):
        if cid == "UNMAPPED":
            continue
        info = controls[cid]
        if domain_filter and info["domain"] != domain_filter:
            continue

        risk_icon = {"critical": "[!]", "high": "[*]", "medium": "[ ]"}.get(info["risk_level"], "   ")
        lines.append(
            f"\n  {risk_icon} {cid} ({info['domain']}) — {info['risk_level']}"
        )
        regs = ", ".join(info["regulations"]) if info["regulations"] else "none"
        lines.append(f"      Regulations: {regs}")
        lines.append(f"      Rules: {', '.join(sorted(info['rules']))}")
        lines.append(
            f"      Events: {len(info['events'])} "
            f"(deny={info['actions'].get('deny', 0)}, "
            f"ask={info['actions'].get('ask', 0)}, "
            f"redact={info['actions'].get('redact', 0)}, "
            f"override_allow={info['actions'].get('override_allow', 0)})"
        )
        lines.append(f"      Sessions: {len(info['sessions'])}")
        lines.append(f"      Period: {info['first_seen']} → {info['last_seen']}")

        if not controls_only and info["events"]:
            lines.append(f"      Evidence artifacts ({min(5, len(info['events']))} most recent):")
            for evt in info["events"][-5:]:
                lines.append(
                    f"        {evt.get('timestamp', '?')} "
                    f"{evt.get('action', '?'):<15} "
                    f"{evt.get('command_preview', '?')[:50]}"
                )

    # Unmapped events
    if "UNMAPPED" in controls:
        unmapped = controls["UNMAPPED"]
        lines.append(f"\n  UNMAPPED (no SCF tags) — {len(unmapped['events'])} events")
        lines.append(f"      Rules: {', '.join(sorted(unmapped['rules']))}")

    # Override activity
    if overrides:
        lines.append("")
        lines.append("  Override Activity")
        lines.append("  " + "-" * 68)
        if not overrides:
            lines.append("  (no override_allow events)")
        for name in sorted(overrides.keys()):
            info = overrides[name]
            lines.append(
                f"  {name}: {info['count']} uses, "
                f"source={info['source']}, "
                f"sessions={len(info['sessions'])}, "
                f"last={info['last_used']}"
            )

    lines.append("")
    lines.append("=" * 72)
    return "\n".join(lines)


def format_json(
    controls: dict,
    entries: list[dict],
    overrides: dict | None = None,
    domain_filter: str | None = None,
) -> str:
    """Format the evidence report as JSON."""
    report = {
        "generated": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_events": len(entries),
        "scf_controls_covered": len([c for c in controls if c != "UNMAPPED"]),
        "controls": {},
    }

    for cid in sorted(controls.keys()):
        if cid == "UNMAPPED":
            continue
        info = controls[cid]
        if domain_filter and info["domain"] != domain_filter:
            continue
        report["controls"][cid] = {
            "domain": info["domain"],
            "risk_level": info["risk_level"],
            "regulations": info["regulations"],
            "rules": sorted(info["rules"]),
            "event_count": len(info["events"]),
            "actions": dict(info["actions"]),
            "session_count": len(info["sessions"]),
            "first_seen": info["first_seen"],
            "last_seen": info["last_seen"],
        }

    if "UNMAPPED" in controls:
        report["unmapped_events"] = len(controls["UNMAPPED"]["events"])

    if overrides is not None:
        report["overrides"] = {
            name: {
                "source": info["source"],
                "usage_count": info["count"],
                "session_count": len(info["sessions"]),
                "last_used": info["last_used"],
            }
            for name, info in sorted(overrides.items())
        }

    return json.dumps(report, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Generate compliance evidence report from audit log",
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
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
        "--domain", default=None,
        help="Filter to a specific SCF domain (e.g., IAC, PRI)",
    )
    parser.add_argument(
        "--controls-only", action="store_true",
        help="Only show control summary, skip event details",
    )
    parser.add_argument(
        "--overrides", action="store_true",
        help="Include override activity report",
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

    controls = group_by_scf_control(entries)
    overrides = group_overrides(entries) if args.overrides else None

    if args.format == "json":
        print(format_json(controls, entries, overrides, domain_filter=args.domain))
    else:
        print(format_text(
            controls, entries, overrides,
            controls_only=args.controls_only,
            domain_filter=args.domain,
        ))


if __name__ == "__main__":
    main()
