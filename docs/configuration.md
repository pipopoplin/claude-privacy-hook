# Configuration

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
| `match` | `any` (one pattern suffices) or `all` (all must match) |
| `patterns` | Array of regex patterns |
| `tool_name` | Optional — restrict rule to a specific tool |
| `enabled` | Optional — set `false` to disable a rule |
| `description` | Human-readable rule description |

Rules are evaluated top-to-bottom. First match wins.

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
