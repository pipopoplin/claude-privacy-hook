#!/usr/bin/env python3
"""
Claude Code Hook: NLP-based sensitive content detection.

A plugin-based PreToolUse hook that uses NLP models to detect PII and
sensitive content in tool input. Complements the regex_filter for
catching content that pattern matching cannot.

Usage:
  python3 llm_filter.py <config.json>

Plugins (selected via config, first available wins):
  presidio   — Microsoft Presidio, ~0.4ms, known PII types
  distilbert — DistilBERT/NerGuard, ~25ms, best accuracy
  spacy      — spaCy sm + regex, ~3ms, edge/low-resource
"""

import importlib
import json
import os
import re
import sys

from hook_utils import normalize_unicode, resolve_field


def load_plugin_registry(hooks_dir: str) -> dict:
    """Load plugin registry from plugins/plugins.json."""
    registry_path = os.path.join(hooks_dir, "plugins", "plugins.json")
    if not os.path.isfile(registry_path):
        return {}
    with open(registry_path) as f:
        data = json.load(f)
    return {
        name: (info["module"], info["class"])
        for name, info in data.get("plugins", {}).items()
    }


def load_config(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def load_plugin(name: str, plugin_config: dict, registry: dict):
    """Load and configure a plugin by name. Returns None if unavailable."""
    if name not in registry:
        return None

    module_path, class_name = registry[name]
    try:
        module = importlib.import_module(module_path)
        cls = getattr(module, class_name)
        instance = cls()
        instance.configure(plugin_config.get(name, {}))
        if not instance.is_available():
            return None
        return instance
    except Exception:
        return None


def main():
    if len(sys.argv) < 2:
        print("Usage: llm_filter.py <config.json>", file=sys.stderr)
        sys.exit(1)

    config_path = os.path.expandvars(sys.argv[1])
    if not os.path.isfile(config_path):
        print(f"Config not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    # Add hooks dir to path so plugins package is importable
    hooks_dir = os.path.dirname(os.path.abspath(__file__))
    if hooks_dir not in sys.path:
        sys.path.insert(0, hooks_dir)

    config = load_config(config_path)
    registry = load_plugin_registry(hooks_dir)

    if not config.get("enabled", True):
        sys.exit(0)

    try:
        hook_input = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    field = config.get("field", "tool_input.command")
    text = resolve_field(hook_input, field)
    if not text:
        sys.exit(0)
    text = normalize_unicode(text)

    priority = config.get("plugin_priority", ["presidio", "spacy", "distilbert"])
    supplementary = config.get("supplementary_plugins", ["prompt_injection"])
    plugin_configs = config.get("plugins", {})
    min_confidence = config.get("min_confidence", 0.7)
    action = config.get("action", "deny")
    entity_types = list(config.get("entity_types") or [])

    # Load overrides (user + project)
    nlp_ovr: dict = {}
    overrides: list = []
    try:
        from override_resolver import load_overrides, merge_nlp_overrides

        overrides = load_overrides(hooks_dir)
        nlp_ovr = merge_nlp_overrides(overrides)
    except Exception:
        pass

    # Apply NLP overrides: filter disabled entity types
    if nlp_ovr.get("disabled_entity_types"):
        entity_types = [
            e for e in entity_types
            if e not in nlp_ovr["disabled_entity_types"]
        ]

    # Apply per-type confidence overrides
    confidence_overrides = nlp_ovr.get("confidence_overrides", {})

    all_findings = []
    reporting_plugin = None

    # Find first available PII plugin and run detection
    for plugin_name in priority:
        if plugin_name in supplementary:
            continue
        if not plugin_configs.get(plugin_name, {}).get("enabled", True):
            continue

        plugin = load_plugin(plugin_name, plugin_configs, registry)
        if plugin is None:
            continue

        try:
            detections = plugin.detect(text, entity_types if entity_types else None)
        except Exception as e:
            print(f"Plugin {plugin_name} error: {e}", file=sys.stderr)
            continue

        for d in detections:
            threshold = confidence_overrides.get(d.entity_type, min_confidence)
            if d.score >= threshold:
                all_findings.append(d)

        if all_findings:
            reporting_plugin = plugin
        break  # first_available: only try the first working PII plugin

    # Run supplementary plugins (e.g. prompt injection) independently
    for plugin_name in supplementary:
        if not plugin_configs.get(plugin_name, {}).get("enabled", True):
            continue

        plugin = load_plugin(plugin_name, plugin_configs, registry)
        if plugin is None:
            continue

        try:
            detections = plugin.detect(text, entity_types if entity_types else None)
        except Exception as e:
            print(f"Plugin {plugin_name} error: {e}", file=sys.stderr)
            continue

        findings = [d for d in detections if d.score >= min_confidence]
        if findings:
            all_findings.extend(findings)
            if reporting_plugin is None:
                reporting_plugin = plugin

    # Check pattern overrides: remove findings whose detected text matches
    # an override pattern targeting rule "llm_filter"
    if overrides and all_findings:
        try:
            from override_resolver import check_override

            dummy_rule = {"name": "llm_filter", "overridable": True}
            filtered = []
            overridden = []
            for finding in all_findings:
                override = check_override(overrides, dummy_rule, finding.text)
                if override:
                    overridden.append((finding, override))
                else:
                    filtered.append(finding)

            # Log overridden findings
            if overridden:
                try:
                    from audit_logger import log_event

                    command = resolve_field(hook_input, "tool_input.command")
                    for finding, override in overridden:
                        log_event(
                            log_dir=hooks_dir,
                            filter_name="llm_filter",
                            rule_name=override.get("override_name", "unknown"),
                            action="override_allow",
                            matched=[f"{finding.entity_type}: {finding.text}"],
                            command=command,
                            session_id=hook_input.get("session_id", ""),
                            override_name=override.get("override_name", ""),
                            override_source=override.get("source", ""),
                        )
                except Exception:
                    pass

            all_findings = filtered
        except Exception:
            pass

    if not all_findings:
        sys.exit(0)

    # Audit log the blocked event
    try:
        from audit_logger import log_event
        command = resolve_field(hook_input, "tool_input.command")
        log_event(
            log_dir=hooks_dir,
            filter_name="llm_filter",
            rule_name=reporting_plugin.name if reporting_plugin else "unknown",
            action=action,
            matched=[f"{d.entity_type}: {d.text}" for d in all_findings],
            command=command,
            session_id=hook_input.get("session_id", ""),
        )
    except Exception:
        pass  # Audit logging must never block the filter

    findings_text = "\n".join(
        f"  - {d.entity_type}: '{d.text}' (confidence: {d.score:.2f})"
        for d in all_findings
    )

    hook_event = hook_input.get("hook_event_name", "PreToolUse")

    if hook_event == "PreToolUse":
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny" if action == "deny" else "ask",
                "permissionDecisionReason": (
                    f"Sensitive content detected by {reporting_plugin.name} ({reporting_plugin.tier}):\n"
                    f"{findings_text}"
                ),
            }
        }
    else:
        output = {
            "decision": "block" if action == "deny" else action,
            "reason": f"Sensitive content detected by {reporting_plugin.name}:\n{findings_text}",
        }

    json.dump(output, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
