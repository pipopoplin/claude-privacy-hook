# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Claude Code hook system with four complementary security layers:
1. **regex_filter** — fast, deterministic regex rules for credential detection, endpoint allowlisting, and sensitive file/content blocking
2. **llm_filter** — NLP-based PII detection with pluggable backends (Presidio, spaCy, DistilBERT) plus built-in supplementary plugins
3. **output_sanitizer** — PostToolUse hook that redacts sensitive data from command stdout/stderr
4. **rate_limiter** — session-based violation escalation (warn → block) with configurable thresholds

All hooks are registered in `.claude/settings.json`. The regex filter applies to Bash, Write/Edit, and Read tools. The NLP filter, rate limiter, and output sanitizer apply to Bash.

### Three-Layer Override System

Rules support a three-layer override system:
- **Managed** — IT-enforced hard deny rules (`overridable: false`), deployed to `/etc/claude-code/hooks/`
- **Project** — team-shared soft rules (`ask`) with exceptions in `.claude/hooks/config_overrides.json`
- **User** — personal developer exceptions in `~/.claude/hooks/config_overrides.json`

Override priority: user > project. Managed/non-overridable rules cannot be bypassed.

## Commands

```bash
# Run all tests
python3 tests/test_hook.py && python3 tests/test_llm_hook.py && python3 tests/test_overrides.py

# Test regex filter directly (Bash rules)
echo '{"tool_name":"Bash","tool_input":{"command":"curl https://example.com"}}' | python3 .claude/hooks/regex_filter.py .claude/hooks/filter_rules.json

# Test regex filter directly (Write rules)
echo '{"tool_name":"Write","tool_input":{"content":"password=secret123"}}' | python3 .claude/hooks/regex_filter.py .claude/hooks/filter_rules_write.json

# Test NLP filter directly
echo '{"tool_name":"Bash","tool_input":{"command":"send to john@example.com"}}' | python3 .claude/hooks/llm_filter.py .claude/hooks/llm_filter_config.json

# Install NLP plugin (pick one)
pip install spacy && python -m spacy download en_core_web_sm

# Override CLI — manage exceptions
python3 .claude/hooks/override_cli.py add --scope project --rule block_untrusted_network --pattern 'https?://api\.myco\.com' --label 'My API'
python3 .claude/hooks/override_cli.py list --scope all
python3 .claude/hooks/override_cli.py remove --scope project --name allow_my_api
python3 .claude/hooks/override_cli.py validate --scope all
python3 .claude/hooks/override_cli.py test --command "curl https://api.myco.com/health" --rule block_untrusted_network
```

## Architecture

### Hook Pipeline

`.claude/settings.json` registers 5 PreToolUse hooks and 1 PostToolUse hook:

```
Bash command → regex_filter.py (filter_rules.json, 16 rules + override check)
             → llm_filter.py (NLP + supplementary plugins + NLP overrides)
             → rate_limiter.py (violation escalation)
             → execute or block
                  ↓
             output_sanitizer.py (PostToolUse) → redact stdout/stderr

Write/Edit   → regex_filter.py (filter_rules_write.json) → execute or block
Read         → regex_filter.py (filter_rules_read.json)   → execute or block
```

### Shared Utilities

- `.claude/hooks/hook_utils.py` — Shared Unicode normalization (NFKC, homoglyphs, zero-width) and dot-path field resolution used by all hooks.

### Regex Filter

- `.claude/hooks/regex_filter.py` — General-purpose regex engine. Reads any JSON rule config, evaluates rules top-to-bottom (deny rules first, then ask), first match wins. Checks overrides before returning deny/ask.
- `.claude/hooks/filter_rules.json` — Bash rules: 16 rules with ~160 patterns. 8 rules are `deny` (non-overridable), 7 are `ask` (overridable).
- `.claude/hooks/filter_rules_write.json` — Write/Edit rules: all `deny`, non-overridable.
- `.claude/hooks/filter_rules_read.json` — Read rules: `deny`, overridable.

Rule format: `field` (dot-path into hook JSON), `action` (allow/deny/ask), `overridable` (bool), `match` (any/all), `patterns` (regex list), optional `tool_name` filter and `enabled` toggle.

### Override System

- `.claude/hooks/override_resolver.py` — Loads and checks overrides from user (`~/.claude/hooks/config_overrides.json`) and project (`.claude/hooks/config_overrides.json`). User overrides take priority.
- `.claude/hooks/config_overrides.json` — Project-level override file (empty template committed to git).
- `.claude/hooks/override_cli.py` — CLI tool for adding, listing, removing, validating, and testing overrides.
- `managed/` — Templates for IT-managed deployment of non-overridable rules.

### NLP Filter

- `.claude/hooks/llm_filter.py` — Plugin-based NLP hook with two-tier dispatch:
  - **PII plugins** — tries in priority order, uses first available: presidio, spacy, distilbert
  - **Supplementary plugins** — always run independently: prompt_injection, sensitive_categories, entropy_detector, semantic_intent
- Supports NLP overrides: disable entity types, adjust per-type confidence thresholds, pattern-based override of detected findings.
- `.claude/hooks/llm_filter_config.json` — Plugin priority, confidence thresholds, entity types, per-plugin settings.
- `.claude/hooks/plugins/plugins.json` — Plugin registry (7 plugins). Maps names to module/class paths. Add custom plugins here without touching Python code.
- `.claude/hooks/plugins/base.py` — `SensitiveContentPlugin` ABC and `DetectionResult` dataclass.
- `.claude/hooks/plugins/{presidio,distilbert,spacy}_plugin.py` — PII backend implementations.
- `.claude/hooks/plugins/{prompt_injection,sensitive_categories,entropy_detector,semantic_intent}_plugin.py` — Supplementary plugins (no external deps).

### Output Sanitizer

- `.claude/hooks/output_sanitizer.py` — PostToolUse hook that redacts sensitive data from command output.
- `.claude/hooks/output_sanitizer_rules.json` — 7 redaction rules: API keys, SSNs, credit cards, emails, private keys, DB connection strings, internal IPs.

### Rate Limiter

- `.claude/hooks/rate_limiter.py` — Counts deny/ask violations in a rolling 5-minute window per session. Escalates: warn at 5 violations, block at 10.
- `.claude/hooks/rate_limiter_config.json` — Thresholds, window size, cooldown period.

### Audit Logger

- `.claude/hooks/audit_logger.py` — JSONL audit log writer. All hooks call `audit_logger.log_event()` on block/redact/override_allow. Logs timestamp, filter name, rule, action, matched patterns, command hash (SHA256), redacted command preview, session ID. For overrides, also logs `override_name` and `override_source`. Override log path via `HOOK_AUDIT_LOG` env var.

### Adding Trusted Endpoints

Option 1: Add a pattern to `allow_trusted_endpoints` in `.claude/hooks/filter_rules.json`:
```json
{"pattern": "https?://api\\.your-company\\.com", "label": "Your API"}
```

Option 2: Use the override CLI:
```bash
python3 .claude/hooks/override_cli.py add --scope project --rule block_untrusted_network --pattern 'https?://api\.your-company\.com' --label 'Your API'
```

### Adding a Custom NLP Plugin

1. Create `.claude/hooks/plugins/my_plugin.py` extending `SensitiveContentPlugin`
2. Register in `.claude/hooks/plugins/plugins.json`
3. Add to `plugin_priority` or `supplementary_plugins` in `.claude/hooks/llm_filter_config.json`
