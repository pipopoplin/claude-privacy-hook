"""Override resolver for the free-tier override system.

Loads project override files (max 3), checks whether a triggered rule
should be allowed based on override patterns, expiry dates, and the
rule's overridable flag.

Free tier: project-level overrides only, capped at 3.
User-level overrides and unlimited overrides require Pro tier.
"""

import json
import os
import re
from datetime import date

# Free-tier rule whitelist — overrides are only allowed for these rules.
# Pro tier extends this set. Keep in sync with free-tier config files.
FREE_TIER_RULES = frozenset({
    # filter_rules.json (Bash) -- 6 rules
    "block_sensitive_data",
    "block_prompt_injection",
    "block_shell_obfuscation",
    "block_sensitive_file_access",
    "allow_trusted_endpoints",
    "block_untrusted_network",
    # filter_rules_write.json (Write/Edit) -- 3 rules
    "block_api_keys_in_content",
    "block_hardcoded_passwords_in_content",
    "block_api_keys_in_edit",
    # filter_rules_read.json (Read) -- 1 rule
    "block_sensitive_file_read",
    # output_sanitizer_rules.json -- 3 rules
    "redact_api_keys",
    "redact_email_addresses",
    "redact_internal_ip_addresses",
})


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

    result = []
    for ovr in overrides:
        ovr = dict(ovr)
        ovr["_source"] = source
        result.append(ovr)

    return result


def load_overrides(hooks_dir: str) -> list[dict]:
    """Load project overrides only (free tier: max 3, no user overrides)."""
    overrides: list[dict] = []

    # Free tier: project-level overrides only (user overrides require Pro)
    project_path = os.path.join(hooks_dir, "config_overrides.json")
    overrides.extend(_load_override_file(project_path, source="project"))

    # Free tier: cap at 3 overrides (unlimited requires Pro)
    overrides = overrides[:3]

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

    # Free tier: only allow overrides for free-tier rules
    # Set HOOK_SKIP_TIER_CHECK=1 for testing with synthetic rule names
    if not os.environ.get("HOOK_SKIP_TIER_CHECK") and rule_name not in FREE_TIER_RULES:
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


