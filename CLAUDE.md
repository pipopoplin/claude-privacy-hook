# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Startup: SCF License Verification (MANDATORY)

At the start of every conversation, fetch https://securecontrolsframework.com/terms-conditions/ and verify the license is still **CC BY-ND 4.0**. Compare against the baseline in [`../LICENSE_REQUIREMENTS.md`](../LICENSE_REQUIREMENTS.md). If changed, STOP and alert the user before modifying any SCF-referencing files.

## Licensing

This tier is **MIT**. See [`../LICENSE_REQUIREMENTS.md`](../LICENSE_REQUIREMENTS.md) for full compatibility rules.
- No GPL/LGPL/AGPL dependencies permitted (would force copyleft)
- SCF control identifiers are uncopyrightable facts — safe to reference with attribution
- NEVER copy SCF control descriptions verbatim into docs or configs — reference IDs/codes only
- This code must NEVER import from `claude-privacy-hook-pro` (dependency direction is Pro → Free only)

## Project Overview

Claude Code hook system with three complementary security layers:
1. **regex_filter** — fast, deterministic regex rules for credential detection, endpoint allowlisting, and sensitive file/content blocking
2. **output_sanitizer** — PostToolUse hook that redacts sensitive data from command stdout/stderr
3. **rate_limiter** — session-based violation escalation (warn → block) with fixed thresholds (warn at 5, block at 10)

All hooks are registered in `.claude/settings.json` (4 PreToolUse hooks + 1 PostToolUse). The regex filter applies to Bash, Write/Edit, and Read tools. The rate limiter and output sanitizer apply to Bash.

### Override System

Project-level only (max 3 overrides) via `.claude/hooks/config_overrides.json`. Non-overridable rules cannot be bypassed. Pro tier adds: user-level overrides (`~/.claude/hooks/config_overrides.json`), managed/IT deployment, and unlimited overrides.

## Commands

```bash
# --- Installation ---
./install_linux.sh        # Linux: install
./install_mac.sh          # macOS: checks Xcode CLT + Homebrew, delegates to install_linux.sh
install_win.bat           # Windows: install

# --- Tests ---
python3 tests/run_all.py                # Run all ~835 tests across 7 suites
python3 tests/test_regex_filter.py      # Regex filter: Bash + Write + Read rules (518 cases)
python3 tests/test_output_sanitizer.py  # Output sanitizer: redaction (186 cases)
python3 tests/test_rate_limiter.py      # Rate limiter: threshold escalation (60 cases)
python3 tests/test_overrides.py         # Override system + risk scoring (94 cases)
python3 tests/test_conftest.py          # Test infrastructure (148 cases)
python3 tests/test_audit_logger.py      # Audit logger (55 cases)
python3 tests/test_config_validation.py # Config validation: SCF tags, classification (109 cases)

# --- Benchmarks ---
python3 benchmarks/run_all.py                  # All benchmarks
python3 benchmarks/bench_regex_filter.py       # Regex filter (subprocess + in-process)
python3 benchmarks/bench_output_sanitizer.py   # Output sanitizer
python3 benchmarks/bench_rate_limiter.py       # Rate limiter + log parsing
python3 benchmarks/bench_overrides.py          # Override resolver
python3 benchmarks/bench_hook_utils.py         # Unicode normalization + field resolution
python3 benchmarks/bench_audit_logger.py       # Audit log write performance

# --- Pro tier: Compliance evidence (evidence_collector.py) ---
# python3 .claude/hooks/evidence_collector.py                     # Full text report
# python3 .claude/hooks/evidence_collector.py --format json       # JSON output
# python3 .claude/hooks/evidence_collector.py --domain IAC        # Filter by SCF domain
# python3 .claude/hooks/evidence_collector.py --since 2026-03-01  # Since date
# python3 .claude/hooks/evidence_collector.py --overrides         # Include override activity
# python3 .claude/hooks/evidence_collector.py --cross-session     # Cross-session hot rule analysis

# --- Pro tier: Breach notification (breach_report.py) ---
# python3 .claude/hooks/breach_report.py                          # Breach candidates (text)
# python3 .claude/hooks/breach_report.py --format markdown        # Markdown report
# python3 .claude/hooks/breach_report.py --format json            # JSON report
# python3 .claude/hooks/breach_report.py --threshold 5            # Custom threshold
# python3 .claude/hooks/breach_report.py --session SESSION_ID     # Specific session

# --- Direct hook testing ---
echo '{"tool_name":"Bash","tool_input":{"command":"curl https://example.com"}}' | python3 .claude/hooks/regex_filter.py .claude/hooks/filter_rules.json
echo '{"tool_name":"Write","tool_input":{"content":"password=secret123"}}' | python3 .claude/hooks/regex_filter.py .claude/hooks/filter_rules_write.json

# --- Override CLI ---
python3 .claude/hooks/override_cli.py list --scope all
# Pro tier: add, remove, validate, test subcommands require Pro license
# python3 .claude/hooks/override_cli.py add --scope project --rule block_untrusted_network --pattern 'https?://api\.myco\.com' --label 'My API'
# python3 .claude/hooks/override_cli.py remove --scope project --name allow_my_api
# python3 .claude/hooks/override_cli.py validate --scope all
# python3 .claude/hooks/override_cli.py test --command "curl https://api.myco.com/health" --rule block_untrusted_network
```

## Architecture

### Hook Pipeline

`.claude/settings.json` registers 4 PreToolUse hooks and 1 PostToolUse hook:

```
Bash command → regex_filter.py (filter_rules.json, 6 rules, ~80 patterns + override check)
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
- `.claude/hooks/filter_rules.json` — Bash rules: 6 rules with ~80 patterns (block_sensitive_data, block_prompt_injection, block_shell_obfuscation, block_sensitive_file_access, allow_trusted_endpoints, block_untrusted_network).
- `.claude/hooks/filter_rules_write.json` — Write/Edit rules: 3 rules (block_api_keys_in_content, block_hardcoded_passwords_in_content, block_api_keys_in_edit), all `deny`, non-overridable.
- `.claude/hooks/filter_rules_read.json` — Read rules: `deny`, overridable.

Rule format: `field` (dot-path into hook JSON), `action` (allow/deny/ask), `overridable` (bool), `match` (any/all), `patterns` (regex list), `data_classification` (restricted/confidential/internal/public), `scf` (domain, controls, regulations, risk_level), optional `tool_name` filter and `enabled` toggle.

### Override System

- `.claude/hooks/override_resolver.py` — Loads and checks project-level overrides from `.claude/hooks/config_overrides.json` (max 3). Uses `FREE_TIER_RULES` whitelist to restrict which rules can be overridden. Pro tier adds user-level overrides, managed/IT layer, and unlimited overrides.
- `.claude/hooks/config_overrides.json` — Project-level override file (empty template committed to git).
- `.claude/hooks/override_cli.py` — Free tier supports `list` command only. Pro tier unlocks add, remove, validate, and test subcommands with risk scoring.

### Output Sanitizer

- `.claude/hooks/output_sanitizer.py` — PostToolUse hook that redacts sensitive data from command output. Free tier supports `redact` mode only (`[REDACTED]`). Pro tier adds `pseudonymize` (`[PII-{hash}]`) and `hash` (`sha256:{full}`) modes.
- `.claude/hooks/output_sanitizer_rules.json` — 3 redaction rules: API keys, email addresses, internal IP addresses. Pro tier adds SSNs, credit cards, private keys, DB connection strings.

### Rate Limiter

- `.claude/hooks/rate_limiter.py` — Counts deny/ask violations in a rolling 5-minute window per session. Fixed thresholds: warn at 5 violations, block at 10 (config values ignored in free tier). Pro tier adds configurable thresholds, window size, and cooldown period.

### Audit Logger

- `.claude/hooks/audit_logger.py` — JSONL audit log writer. All hooks call `audit_logger.log_event()` on block/redact/override_allow. Logs timestamp, filter name, rule, action, matched patterns, command hash (SHA256), redacted command preview, session ID. For overrides, also logs `override_name` and `override_source`. Pro tier adds: custom log path (`HOOK_AUDIT_LOG` env var), log rotation (`HOOK_AUDIT_LOG_MAX_BYTES`, `HOOK_AUDIT_LOG_BACKUP_COUNT`), data minimization (`HOOK_AUDIT_LOG_MINIMIZE=1`), and SCF metadata (domain, controls, regulations, risk_level).

### Evidence Collector (Pro tier)

- `evidence_collector.py` — Moved to Pro tier. Reads audit log, groups events by SCF control, generates compliance evidence reports (text or JSON). Supports `--cross-session` for hot rule detection across sessions, `--overrides` for override activity, `--domain` filter, `--since` date filter.

### Breach Report (Pro tier)

- `breach_report.py` — Moved to Pro tier. Identifies sessions exceeding a deny threshold (default 10) as breach candidates. Generates GDPR Art.33-compliant reports with 7 required sections. Outputs text, JSON, or markdown. Supports `--session`, `--threshold`, `--since`, `--format`.

### Adding Trusted Endpoints

Option 1: Add a pattern to `allow_trusted_endpoints` in `.claude/hooks/filter_rules.json`:
```json
{"pattern": "https?://api\\.your-company\\.com", "label": "Your API"}
```

Option 2 (Pro tier): Use the override CLI:
```bash
# Pro tier: add subcommand requires Pro license
python3 .claude/hooks/override_cli.py add --scope project --rule block_untrusted_network --pattern 'https?://api\.your-company\.com' --label 'Your API'
```

## Pro Tier

NLP-based PII detection (Presidio, spaCy, DistilBERT), managed/IT-enforced overrides, custom NLP plugins, SIEM integration (Splunk, Datadog, Elasticsearch, CEF/LEEF syslog), compliance dashboards, and SBOM generation are available via `claude-privacy-hook-pro` (Pro tier).
