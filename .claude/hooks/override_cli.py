#!/usr/bin/env python3
"""CLI tool for managing hook override configurations.

Usage:
  override_cli.py add --scope user|project --rule RULE_NAME --pattern REGEX --label LABEL [--expires DATE] [--reason TEXT]
  override_cli.py list [--scope user|project|all]
  override_cli.py remove --scope user|project --name OVERRIDE_NAME
  override_cli.py validate [--scope user|project|all]
  override_cli.py test --command COMMAND --rule RULE_NAME
"""

import argparse
import json
import os
import re
import sys
from datetime import date


def _get_override_path(scope: str) -> str:
    """Get the config_overrides.json path for the given scope."""
    if scope == "user":
        return os.path.join(
            os.path.expanduser("~"), ".claude", "hooks", "config_overrides.json"
        )
    else:  # project
        hooks_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(hooks_dir, "config_overrides.json")


def _load_overrides(path: str) -> dict:
    """Load override file, creating it if it doesn't exist."""
    if not os.path.isfile(path):
        return {"version": 1, "overrides": []}
    with open(path) as f:
        return json.load(f)


def _save_overrides(path: str, data: dict) -> None:
    """Save override file, creating parent directories if needed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _log_change(action: str, override_name: str, scope: str, rule_name: str = "",
                 details: str = "", risk_score: int = 0, risk_level: str = "") -> None:
    """Log an override configuration change to the audit log."""
    try:
        hooks_dir = os.path.dirname(os.path.abspath(__file__))
        from audit_logger import log_event
        log_event(
            log_dir=hooks_dir,
            filter_name="override_cli",
            rule_name=override_name,
            action=action,
            matched=[f"scope={scope}", f"rule={rule_name}", f"risk={risk_score}/{risk_level}"] if risk_score else [f"scope={scope}", f"rule={rule_name}"],
            command=details,
            override_name=override_name,
            override_source=scope,
        )
    except Exception:
        pass  # Best-effort — never block CLI on audit failure


# --- Risk scoring ---

_CLASSIFICATION_SCORES = {"restricted": 4, "confidential": 3, "internal": 2, "public": 1}
_RISK_LEVEL_SCORES = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_RISK_LABELS = [(8, "critical"), (6, "high"), (4, "medium"), (0, "low")]


def _calculate_risk_score(rule: dict, scope: str, expires: str | None) -> tuple[int, str]:
    """Calculate a risk score (1-10) for an override request.

    Factors:
        data_classification — restricted=4, confidential=3, internal=2, public=1
        scf.risk_level     — critical=4, high=3, medium=2, low=1
        scope              — project=+1 (team-wide), user=0 (personal)
        expires            — no expiry=+1, >90 days=+1, <=90 days=0

    Returns (score, level) where level is critical/high/medium/low.
    """
    score = 0

    # Data classification factor
    classification = rule.get("data_classification", "internal")
    score += _CLASSIFICATION_SCORES.get(classification, 2)

    # SCF risk level factor
    scf = rule.get("scf", {})
    risk_level = scf.get("risk_level", "medium")
    score += _RISK_LEVEL_SCORES.get(risk_level, 2)

    # Scope factor — project overrides affect the whole team
    if scope == "project":
        score += 1

    # Expiry factor — no expiry or long expiry is riskier
    if not expires:
        score += 1
    else:
        try:
            from datetime import datetime
            days = (datetime.strptime(expires, "%Y-%m-%d").date() - date.today()).days
            if days > 90:
                score += 1
        except ValueError:
            pass

    # Clamp to 1-10
    score = max(1, min(10, score))

    # Map score to label
    level = "low"
    for threshold, label in _RISK_LABELS:
        if score >= threshold:
            level = label
            break

    return score, level


def _load_rules() -> dict[str, dict]:
    """Load all rule files and return a dict of rule_name -> rule."""
    hooks_dir = os.path.dirname(os.path.abspath(__file__))
    rules = {}
    for filename in ["filter_rules.json", "filter_rules_write.json", "filter_rules_read.json"]:
        path = os.path.join(hooks_dir, filename)
        if os.path.isfile(path):
            with open(path) as f:
                data = json.load(f)
            for rule in data.get("rules", []):
                name = rule.get("name")
                if name:
                    rules[name] = rule
    return rules


def cmd_add(args: argparse.Namespace) -> int:
    """Add a new override."""
    # Check rule is in free tier
    from override_resolver import FREE_TIER_RULES
    if args.rule not in FREE_TIER_RULES:
        print(
            f"Rule '{args.rule}' is not available in the free tier.\n"
            f"Upgrade to Pro for overrides on all rules: https://claude-privacy-hook.dev/pro",
            file=sys.stderr,
        )
        return 1

    path = _get_override_path(args.scope)
    data = _load_overrides(path)

    # Generate a name from rule + label
    safe_label = re.sub(r"[^a-zA-Z0-9]+", "_", args.label).strip("_").lower()
    name = f"allow_{safe_label}" if safe_label else f"allow_{args.rule}"

    # Check for duplicate names
    existing_names = {o.get("name") for o in data["overrides"]}
    if name in existing_names:
        counter = 2
        while f"{name}_{counter}" in existing_names:
            counter += 1
        name = f"{name}_{counter}"

    override = {
        "name": name,
        "rule_name": args.rule,
        "patterns": [{"pattern": args.pattern, "label": args.label}],
    }

    if args.expires:
        override["expires"] = args.expires
    if args.reason:
        override["reason"] = args.reason

    data["overrides"].append(override)
    _save_overrides(path, data)

    # Risk scoring
    rules = _load_rules()
    rule = rules.get(args.rule, {})
    risk_score, risk_level = _calculate_risk_score(rule, args.scope, args.expires)

    print(f"Added override '{name}' to {args.scope} config: {path}")
    print(f"  Risk score: {risk_score}/10 ({risk_level})")
    if risk_score >= 8:
        print(f"  WARNING: High-risk override — consider adding an expiry date and reason.")

    # Audit trail
    details = f"add scope={args.scope} rule={args.rule} pattern={args.pattern} label={args.label}"
    if args.expires:
        details += f" expires={args.expires}"
    if args.reason:
        details += f" reason={args.reason}"
    _log_change("override_add", name, args.scope, args.rule, details, risk_score, risk_level)

    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """List overrides."""
    scopes = ["user", "project"] if args.scope == "all" else [args.scope]

    for scope in scopes:
        path = _get_override_path(scope)
        data = _load_overrides(path)
        overrides = data.get("overrides", [])

        print(f"\n{scope.upper()} overrides ({path}):")
        if not overrides:
            print("  (none)")
            continue

        for ovr in overrides:
            expires = ovr.get("expires", "never")
            expired = ""
            if expires != "never" and expires < date.today().isoformat():
                expired = " [EXPIRED]"
            patterns = ", ".join(
                p.get("label", p.get("pattern", "?")) if isinstance(p, dict) else p
                for p in ovr.get("patterns", [])
            )
            print(f"  {ovr.get('name', '?')}:")
            print(f"    rule: {ovr.get('rule_name', '?')}")
            print(f"    patterns: {patterns}")
            print(f"    expires: {expires}{expired}")
            if ovr.get("reason"):
                print(f"    reason: {ovr['reason']}")

    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    """Remove an override by name."""
    path = _get_override_path(args.scope)
    data = _load_overrides(path)

    original_len = len(data["overrides"])
    # Capture the removed override for audit
    removed = [o for o in data["overrides"] if o.get("name") == args.name]
    data["overrides"] = [o for o in data["overrides"] if o.get("name") != args.name]

    if len(data["overrides"]) == original_len:
        print(f"Override '{args.name}' not found in {args.scope} config.", file=sys.stderr)
        return 1

    _save_overrides(path, data)
    print(f"Removed override '{args.name}' from {args.scope} config.")

    # Audit trail
    rule_name = removed[0].get("rule_name", "") if removed else ""
    _log_change("override_remove", args.name, args.scope, rule_name,
                f"remove scope={args.scope} name={args.name} rule={rule_name}")

    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate overrides against current rules."""
    rules = _load_rules()
    scopes = ["user", "project"] if args.scope == "all" else [args.scope]
    errors = 0

    for scope in scopes:
        path = _get_override_path(scope)
        data = _load_overrides(path)
        overrides = data.get("overrides", [])

        print(f"\nValidating {scope.upper()} overrides ({path}):")
        if not overrides:
            print("  (no overrides to validate)")
            continue

        for ovr in overrides:
            name = ovr.get("name", "?")
            rule_name = ovr.get("rule_name", "")

            # Check rule exists
            if rule_name not in rules:
                print(f"  ERROR: '{name}' references non-existent rule '{rule_name}'")
                errors += 1
                continue

            # Check overridable
            rule = rules[rule_name]
            if not rule.get("overridable", True):
                print(f"  ERROR: '{name}' references non-overridable rule '{rule_name}'")
                errors += 1

            # Check pattern validity
            for entry in ovr.get("patterns", []):
                pattern = entry.get("pattern", "") if isinstance(entry, dict) else entry
                try:
                    re.compile(pattern)
                except re.error as e:
                    print(f"  ERROR: '{name}' has invalid regex: {e}")
                    errors += 1

            # Check expiry
            expires = ovr.get("expires")
            if expires and expires < date.today().isoformat():
                print(f"  WARNING: '{name}' is expired (expires: {expires})")

    if errors == 0:
        print("\n  All overrides valid.")
    else:
        print(f"\n  {errors} error(s) found.")
    return 1 if errors else 0


def cmd_test(args: argparse.Namespace) -> int:
    """Test if a command would be overridden by a specific rule."""
    hooks_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, hooks_dir)

    from override_resolver import load_overrides, check_override

    overrides = load_overrides(hooks_dir)
    rules = _load_rules()

    if args.rule not in rules:
        print(f"Rule '{args.rule}' not found.", file=sys.stderr)
        return 1

    rule = rules[args.rule]
    from hook_utils import normalize_unicode
    value = normalize_unicode(args.command)

    result = check_override(overrides, rule, value)

    if result:
        print(f"OVERRIDDEN by '{result['override_name']}' (source: {result['source']})")
        print(f"  Command would be ALLOWED despite triggering rule '{args.rule}'")
    else:
        if not rule.get("overridable", True):
            print(f"Rule '{args.rule}' is non-overridable — cannot be overridden.")
        else:
            print(f"NOT overridden — no matching override found for rule '{args.rule}'")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Manage hook override configurations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # add
    add_parser = subparsers.add_parser("add", help="Add an override")
    add_parser.add_argument("--scope", choices=["user", "project"], default="project")
    add_parser.add_argument("--rule", required=True, help="Rule name to override")
    add_parser.add_argument("--pattern", required=True, help="Regex pattern to match")
    add_parser.add_argument("--label", required=True, help="Human-readable label")
    add_parser.add_argument("--expires", help="Expiry date (ISO format: YYYY-MM-DD)")
    add_parser.add_argument("--reason", help="Justification for the override")

    # list
    list_parser = subparsers.add_parser("list", help="List overrides")
    list_parser.add_argument("--scope", choices=["user", "project", "all"], default="all")

    # remove
    remove_parser = subparsers.add_parser("remove", help="Remove an override")
    remove_parser.add_argument("--scope", choices=["user", "project"], required=True)
    remove_parser.add_argument("--name", required=True, help="Override name to remove")

    # validate
    validate_parser = subparsers.add_parser("validate", help="Validate overrides")
    validate_parser.add_argument("--scope", choices=["user", "project", "all"], default="all")

    # test
    test_parser = subparsers.add_parser("test", help="Test if a command would be overridden")
    test_parser.add_argument("--command", required=True, help="Command to test")
    test_parser.add_argument("--rule", required=True, help="Rule to check against")

    args = parser.parse_args()

    # Free tier: only 'list' is available. Other commands require Pro.
    PRO_COMMANDS = {"add", "remove", "validate", "test"}
    if args.subcommand in PRO_COMMANDS:
        print(f"The '{args.subcommand}' command requires Pro tier.", file=sys.stderr)
        print("Upgrade at: https://claude-privacy-hook.dev/pro", file=sys.stderr)
        sys.exit(1)

    commands = {
        "list": cmd_list,
    }

    sys.exit(commands[args.subcommand](args))


if __name__ == "__main__":
    main()
