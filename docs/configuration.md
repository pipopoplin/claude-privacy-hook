# Configuration

## Installation

See the main [README](../README.md#installation) for full installation instructions. Quick summary:

```bash
# Linux / macOS
./install.sh              # Install (zero dependencies, Python stdlib only)

# Windows
install.bat               # Install

# macOS
./install_mac.sh          # macOS wrapper (checks Xcode CLT + Homebrew)
```

The install scripts set up the hook system. All hooks (regex filter, output sanitizer, rate limiter) use only Python stdlib — no external dependencies required.

---

## Allow a Trusted Endpoint

Add a pattern to the `allow_trusted_endpoints` rule in `.claude/hooks/filter_rules.json`:

```json
{"pattern": "https?://api\\.your-company\\.com", "label": "Your API"}
```

Or use the override CLI:

```bash
python3 .claude/hooks/override_cli.py add --scope project \
  --rule block_untrusted_network --pattern 'https?://api\.your-company\.com' --label 'Your API'
```

## Disable a Hook

To disable a specific regex rule, add `"enabled": false` to the rule in `filter_rules.json`.

To disable an entire hook, remove its entry from `.claude/settings.json`.

## Rule Format Reference

Each rule in the JSON config files follows this structure:

| Field | Description |
|-------|-------------|
| `field` | Dot-path into hook JSON (e.g. `tool_input.command`) |
| `action` | `allow`, `deny`, or `ask` |
| `overridable` | `true` or `false` — whether overrides can bypass this rule |
| `match` | `any` (one pattern suffices) or `all` (all must match) |
| `patterns` | Array of regex patterns |
| `tool_name` | Optional — restrict rule to a specific tool |
| `enabled` | Optional — set `false` to disable a rule |
| `description` | Human-readable rule description |

Rules are evaluated top-to-bottom. `deny` rules are ordered before `ask` rules. First match wins.

## Configuration Files

| File | Description |
|------|-------------|
| `filter_rules.json` | Bash rules (16 rules, ~160 patterns) |
| `filter_rules_write.json` | Write/Edit rules (8 rules) |
| `filter_rules_read.json` | Read rules (1 rule) |
| `output_sanitizer_rules.json` | Output redaction rules (7 rules) |
| `rate_limiter_config.json` | Rate limiter thresholds and window |
| `config_overrides.json` | Project-level override exceptions |

## Override System

The two-layer override system allows exceptions without editing rule files.

### Override File Format (`config_overrides.json`)

```json
{
  "version": 1,
  "overrides": [
    {
      "name": "allow_company_api",
      "description": "Internal API for development",
      "rule_name": "block_untrusted_network",
      "patterns": [
        {"pattern": "https?://api\\.ourcompany\\.com", "label": "Company API"}
      ],
      "expires": "2026-12-31",
      "added_by": "jane@company.com",
      "reason": "Required for integration testing"
    }
  ]
}
```

### Override Entry Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique identifier for the override |
| `rule_name` | Yes | Must match a rule name from filter_rules*.json |
| `patterns` | Yes | Same format as rule patterns (regex + label) |
| `description` | No | Human-readable description |
| `expires` | No | ISO date string — override ignored after this date |
| `added_by` | No | Audit metadata — who added it |
| `reason` | No | Justification for the override |

### Override Locations

| Layer | File Path | Priority |
|-------|-----------|----------|
| User | `~/.claude/hooks/config_overrides.json` | Highest |
| Project | `.claude/hooks/config_overrides.json` | Lower |

### Override CLI

```bash
# Add an override
python3 .claude/hooks/override_cli.py add --scope user|project \
  --rule RULE_NAME --pattern 'REGEX' --label 'Label' \
  [--expires 2026-12-31] [--reason "Justification"]

# List overrides
python3 .claude/hooks/override_cli.py list [--scope user|project|all]

# Remove an override
python3 .claude/hooks/override_cli.py remove --scope user|project --name NAME

# Validate overrides against current rules
python3 .claude/hooks/override_cli.py validate [--scope user|project|all]

# Test if a command would be overridden
python3 .claude/hooks/override_cli.py test --command "COMMAND" --rule RULE_NAME
```

### Managed Deployment

For IT-managed non-overridable rules, see [`managed/README.md`](../managed/README.md).

## Output Sanitizer Rules

Edit `.claude/hooks/output_sanitizer_rules.json` to customize what gets redacted from command output. Uses the same rule format as the regex filter.

## Rate Limiter Settings

Edit `.claude/hooks/rate_limiter_config.json`:

| Setting | Default | Description |
|---------|---------|-------------|
| `warn_threshold` | 5 | Number of violations before warning |
| `block_threshold` | 10 | Number of violations before blocking |
| `window_seconds` | 300 | Rolling window size (5 minutes) |
| `cooldown_seconds` | 60 | Cooldown period after block |

> NLP configuration (PII detection sensitivity, plugin settings, entity type selection) is available in [claude-privacy-hook-pro](https://github.com/anthropics/claude-privacy-hook-pro).
