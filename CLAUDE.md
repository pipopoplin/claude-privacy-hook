# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Startup: SCF License Verification (MANDATORY)

At the start of every conversation, fetch https://securecontrolsframework.com/terms-conditions/ and verify the license is still **CC BY-ND 4.0**. Compare against the baseline in [`../LICENSE_REQUIREMENTS.md`](../LICENSE_REQUIREMENTS.md). If changed, STOP and alert the user before modifying any SCF-referencing files.

## Licensing

This tier is **MIT**. See [`../LICENSE_REQUIREMENTS.md`](../LICENSE_REQUIREMENTS.md) for full compatibility rules.
- No GPL/LGPL/AGPL dependencies permitted (would force copyleft)
- SCF control identifiers are uncopyrightable facts — safe to reference with attribution
- This code must NEVER import from `claude-privacy-hook-pro` (dependency direction is Pro → Free only)

## Project Overview

Claude Code hook system with three complementary security layers:
1. **regex_filter** — fast, deterministic regex rules for credential detection, endpoint allowlisting, and sensitive file/content blocking
2. **output_sanitizer** — PostToolUse hook that redacts sensitive data from command stdout/stderr
3. **rate_limiter** — session-based violation escalation (warn → block) with configurable thresholds

All hooks are registered in `.claude/settings.json` (4 PreToolUse hooks + 1 PostToolUse). The regex filter applies to Bash, Write/Edit, and Read tools. The rate limiter and output sanitizer apply to Bash.

### Two-Layer Override System

Rules support a two-layer override system:
- **Project** — team-shared soft rules (`ask`) with exceptions in `.claude/hooks/config_overrides.json`
- **User** — personal developer exceptions in `~/.claude/hooks/config_overrides.json`

Override priority: user > project. Non-overridable rules cannot be bypassed. Managed/IT deployment requires Pro license.

## Commands

```bash
# --- Installation ---
./install_linux.sh        # Linux: install
./install_mac.sh          # macOS: checks Xcode CLT + Homebrew, delegates to install_linux.sh
install_win.bat           # Windows: install

# --- Tests ---
python3 tests/run_all.py                # Run all 979 tests across 5 suites
python3 tests/test_regex_filter.py      # Regex filter: Bash + Write + Read rules (518 cases)
python3 tests/test_output_sanitizer.py  # Output sanitizer: redaction rules (179 cases)
python3 tests/test_rate_limiter.py      # Rate limiter: threshold escalation (60 cases)
python3 tests/test_overrides.py         # Override system (74 cases)
python3 tests/test_conftest.py          # Test infrastructure (148 cases)

# --- Benchmarks ---
python3 benchmarks/run_all.py                  # All benchmarks
python3 benchmarks/bench_regex_filter.py       # Regex filter (subprocess + in-process)
python3 benchmarks/bench_output_sanitizer.py   # Output sanitizer
python3 benchmarks/bench_rate_limiter.py       # Rate limiter + log parsing
python3 benchmarks/bench_overrides.py          # Override resolver
python3 benchmarks/bench_hook_utils.py         # Unicode normalization + field resolution
python3 benchmarks/bench_audit_logger.py       # Audit log write performance

# --- Compliance evidence ---
python3 .claude/hooks/evidence_collector.py                     # Full text report
python3 .claude/hooks/evidence_collector.py --format json       # JSON output
python3 .claude/hooks/evidence_collector.py --domain IAC        # Filter by SCF domain
python3 .claude/hooks/evidence_collector.py --since 2026-03-01  # Since date
python3 .claude/hooks/evidence_collector.py --overrides         # Include override activity

# --- Direct hook testing ---
echo '{"tool_name":"Bash","tool_input":{"command":"curl https://example.com"}}' | python3 .claude/hooks/regex_filter.py .claude/hooks/filter_rules.json
echo '{"tool_name":"Write","tool_input":{"content":"password=secret123"}}' | python3 .claude/hooks/regex_filter.py .claude/hooks/filter_rules_write.json

# --- Override CLI ---
python3 .claude/hooks/override_cli.py add --scope project --rule block_untrusted_network --pattern 'https?://api\.myco\.com' --label 'My API'
python3 .claude/hooks/override_cli.py list --scope all
python3 .claude/hooks/override_cli.py remove --scope project --name allow_my_api
python3 .claude/hooks/override_cli.py validate --scope all
python3 .claude/hooks/override_cli.py test --command "curl https://api.myco.com/health" --rule block_untrusted_network
```

## Architecture

### Hook Pipeline

`.claude/settings.json` registers 4 PreToolUse hooks and 1 PostToolUse hook:

```
Bash command → regex_filter.py (filter_rules.json, 18 rules + override check)
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
- `.claude/hooks/filter_rules.json` — Bash rules: 18 rules with ~180 patterns. 10 rules are `deny` (non-overridable), 7 are `ask` (overridable), 1 is `allow`.
- `.claude/hooks/filter_rules_write.json` — Write/Edit rules: all `deny`, non-overridable.
- `.claude/hooks/filter_rules_read.json` — Read rules: `deny`, overridable.

Rule format: `field` (dot-path into hook JSON), `action` (allow/deny/ask), `overridable` (bool), `match` (any/all), `patterns` (regex list), optional `tool_name` filter and `enabled` toggle.

### Override System

- `.claude/hooks/override_resolver.py` — Loads and checks overrides from user (`~/.claude/hooks/config_overrides.json`) and project (`.claude/hooks/config_overrides.json`). Uses `FREE_TIER_RULES` whitelist to restrict which rules can be overridden. User overrides take priority. Pro tier extends this whitelist.
- `.claude/hooks/config_overrides.json` — Project-level override file (empty template committed to git).
- `.claude/hooks/override_cli.py` — CLI tool for adding, listing, removing, validating, and testing overrides.

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

## Pro Tier

NLP-based PII detection (Presidio, spaCy, DistilBERT), managed/IT-enforced overrides, custom NLP plugins, and enhanced audit logging are available via `claude-privacy-hook-pro` (Pro tier).
