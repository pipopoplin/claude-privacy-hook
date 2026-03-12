"""Override resolver for the three-layer override system.

Loads user and project override files, checks whether a triggered rule
should be allowed based on override patterns, expiry dates, and the
rule's overridable flag.

Override priority: user > project (first match wins).
"""

import json
import os
import re
from datetime import date


def _load_override_file(path: str, source: str) -> list[dict]:
    """Load overrides from a single JSON file, tagging each with *source*."""
    if not os.path.isfile(path):
        return []
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    overrides = data.get("overrides", [])
    nlp = data.get("nlp_overrides", {})

    result = []
    for ovr in overrides:
        ovr = dict(ovr)
        ovr["_source"] = source
        result.append(ovr)

    # Attach nlp_overrides metadata to allow merging later
    if nlp and result:
        result[0].setdefault("_nlp_overrides", {}).update(nlp)
    elif nlp:
        result.append({"_source": source, "_nlp_overrides": nlp})

    return result


def load_overrides(hooks_dir: str) -> list[dict]:
    """Load user overrides first, then project overrides. User wins."""
    overrides: list[dict] = []

    # User overrides (highest priority)
    user_path = os.path.join(
        os.path.expanduser("~"), ".claude", "hooks", "config_overrides.json"
    )
    overrides.extend(_load_override_file(user_path, source="user"))

    # Project overrides
    project_path = os.path.join(hooks_dir, "config_overrides.json")
    overrides.extend(_load_override_file(project_path, source="project"))

    return overrides


def check_override(
    overrides: list[dict], rule: dict, value: str
) -> dict | None:
    """Check if any override allows a triggered rule.

    Returns {"override_name": "...", "source": "user|project"} or None.
    Only checks overrides matching the triggered rule's name.
    Skips if rule has "overridable": false.
    Skips expired overrides.
    """
    # Non-overridable rules cannot be overridden
    if not rule.get("overridable", True):
        return None

    rule_name = rule.get("name", "")
    if not rule_name:
        return None

    today = date.today().isoformat()

    for ovr in overrides:
        # Skip internal metadata entries
        if "rule_name" not in ovr:
            continue

        if ovr["rule_name"] != rule_name:
            continue

        # Check expiry
        expires = ovr.get("expires")
        if expires and expires < today:
            continue

        # Check patterns — any match means the override applies
        patterns = ovr.get("patterns", [])
        for entry in patterns:
            if isinstance(entry, str):
                pattern = entry
            elif isinstance(entry, dict):
                pattern = entry.get("pattern", "")
            else:
                continue

            if not pattern:
                continue

            try:
                if re.search(pattern, value, re.IGNORECASE):
                    return {
                        "override_name": ovr.get("name", "unknown"),
                        "source": ovr.get("_source", "unknown"),
                    }
            except re.error:
                continue

    return None


def merge_nlp_overrides(overrides: list[dict]) -> dict:
    """Merge NLP override sections from user and project overrides.

    User settings take priority over project settings.
    Returns a dict with optional keys:
      - disabled_entity_types: list[str]
      - confidence_overrides: dict[str, float]
    """
    merged: dict = {
        "disabled_entity_types": [],
        "confidence_overrides": {},
    }

    # Process in reverse (project first, then user) so user wins
    for ovr in reversed(overrides):
        nlp = ovr.get("_nlp_overrides", {})
        if not nlp:
            continue

        disabled = nlp.get("disabled_entity_types", [])
        if disabled:
            # User additions extend; duplicates are fine (set later)
            merged["disabled_entity_types"].extend(disabled)

        confidence = nlp.get("confidence_overrides", {})
        if confidence:
            merged["confidence_overrides"].update(confidence)

    # De-duplicate
    merged["disabled_entity_types"] = list(set(merged["disabled_entity_types"]))

    return merged
