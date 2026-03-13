# Configuration

## Installation

See the main [README](../README.md#installation) for full installation instructions. Quick summary:

```bash
# Linux / macOS
./install.sh              # Full install (all NLP plugins)
./install.sh --core       # Core only (zero dependencies)
./install.sh --spacy      # Recommended: core + spaCy

# Windows
install.bat               # Full install
install.bat --core        # Core only

# Activate the virtual environment
source claude_privacy_hook_env/bin/activate   # Linux/macOS
claude_privacy_hook_env\Scripts\activate.bat  # Windows
```

The install scripts create a `claude_privacy_hook_env` virtual environment. Core hooks (regex filter, output sanitizer, rate limiter) use only Python stdlib. NLP plugins are optional.

| Plugin | Package | Use case |
|--------|---------|----------|
| spaCy | `spacy` + `en_core_web_sm` | Recommended default, lightweight NER (~3ms) |
| Presidio | `presidio-analyzer` | Known PII types, fastest (~0.4ms) |
| DistilBERT | `transformers` + `torch` | Best accuracy NER (~25ms, large download) |

---

## Allow a Trusted Endpoint

Add a pattern to the `allow_trusted_endpoints` rule in `.claude/hooks/filter_rules.json`:

```json
{"pattern": "https?://api\\.your-company\\.com", "label": "Your API"}
```

## Adjust NLP Sensitivity

Edit `.claude/hooks/llm_filter_config.json`:

```json
{
  "min_confidence": 0.7,
  "action": "deny",
  "entity_types": ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD", "IP_ADDRESS",
                   "PROMPT_INJECTION", "MEDICAL_DATA", "BIOMETRIC_DATA", "PROTECTED_CATEGORY",
                   "HIGH_ENTROPY_SECRET", "SUSPICIOUS_INTENT"]
}
```

- `min_confidence` — lower catches more, higher reduces false positives (default: 0.7)
- `action` — `"deny"` blocks, `"ask"` prompts user for approval
- `entity_types` — which entity types to detect
- `plugin_priority` — PII plugin preference order (first available wins)
- `supplementary_plugins` — plugins that always run independently (default: `["prompt_injection", "sensitive_categories", "entropy_detector", "semantic_intent"]`)

## Disable a Hook

Set `"enabled": false` in `llm_filter_config.json` to disable the NLP hook, or remove its entry from `.claude/settings.json`.

To disable a specific regex rule, add `"enabled": false` to the rule in `filter_rules.json`.

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

## Override System

The three-layer override system allows exceptions without editing rule files.

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
  ],
  "nlp_overrides": {
    "disabled_entity_types": ["EMAIL_ADDRESS"],
    "confidence_overrides": {
      "PHONE_NUMBER": 0.95
    }
  }
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

### NLP Override Fields

| Field | Description |
|-------|-------------|
| `disabled_entity_types` | List of entity types to skip (e.g. `["EMAIL_ADDRESS"]`) |
| `confidence_overrides` | Per-type confidence thresholds (e.g. `{"PHONE_NUMBER": 0.95}`) |

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
