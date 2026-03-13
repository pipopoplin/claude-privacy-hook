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

For better performance, use llm_client.py which connects to a persistent
background service (llm_service.py) that keeps plugins loaded in memory.
"""

import json
import os
import sys


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

    from llm_service import load_all_plugins, load_plugin_registry, run_detection

    with open(config_path) as f:
        config = json.load(f)

    if not config.get("enabled", True):
        sys.exit(0)

    try:
        hook_input = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    registry = load_plugin_registry(hooks_dir)
    plugins = load_all_plugins(config, registry)

    result = run_detection(hook_input, config, hooks_dir, plugins)

    if result:
        json.dump(result, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
