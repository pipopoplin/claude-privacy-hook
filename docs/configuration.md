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

Or use the override CLI (Pro tier):

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
| `patterns` | Array of regex patterns with `pattern` and `label` |
| `data_classification` | Data sensitivity: `restricted`, `confidential`, `internal`, or `public` |
| `scf` | SCF metadata object (see below) |
| `tool_name` | Optional — restrict rule to a specific tool |
| `enabled` | Optional — set `false` to disable a rule |
| `description` | Human-readable rule description |

### SCF Metadata (`scf` object)

Every rule includes SCF compliance metadata. In Pro tier, this metadata is used by the audit logger, evidence collector, and risk scoring:

| Field | Description | Example |
|-------|-------------|---------|
| `domain` | SCF domain code | `"IAC"`, `"PRI"`, `"NET"` |
| `controls` | List of SCF control IDs | `["IAC-01", "IAC-06"]` |
| `regulations` | Applicable regulations | `["GDPR Art.32", "PCI-DSS Req.3"]` |
| `risk_level` | Risk criticality | `"critical"`, `"high"`, `"medium"`, `"low"` |

### Data Classification Levels

| Level | Description | Examples |
|-------|-------------|---------|
| `restricted` | Highest sensitivity — legally regulated | SSNs, credit cards, private keys, passwords |
| `confidential` | Business-sensitive | API keys, employee IDs, customer IDs |
| `internal` | Infrastructure details | Internal IPs, base64 payloads, shell obfuscation |
| `public` | Non-sensitive | Trusted endpoint allowlist |

Rules are evaluated top-to-bottom. `deny` rules are ordered before `ask` rules. First match wins.

## Configuration Files

| File | Description |
|------|-------------|
| `filter_rules.json` | Bash rules (6 rules, ~80 patterns). Pro extends to 18 rules, ~180 patterns. |
| `filter_rules_write.json` | Write/Edit rules (3 rules). Pro extends to 8 rules. |
| `filter_rules_read.json` | Read rules (1 rule) |
| `output_sanitizer_rules.json` | Output redaction rules (3 rules, redact only). Pro extends to 7 rules with 3 anonymization modes. |
| `rate_limiter_config.json` | Rate limiter thresholds and window |
| `config_overrides.json` | Project-level override exceptions |

## Override System

Project-level only (max 3 overrides). The `list` CLI command is available in free tier. User-level overrides, unlimited overrides, and full CLI (add/remove/validate/test) require Pro.

### Override File Format (`config_overrides.json` — max 3 overrides, project-level only)

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

| Layer | File Path | Tier |
|-------|-----------|------|
| Project | `.claude/hooks/config_overrides.json` | Free (max 3) |
| User | `~/.claude/hooks/config_overrides.json` | Pro only |

### Override CLI

```bash
# List overrides (free tier)
python3 .claude/hooks/override_cli.py list [--scope project]

# Pro tier: Add an override
python3 .claude/hooks/override_cli.py add --scope user|project \
  --rule RULE_NAME --pattern 'REGEX' --label 'Label' \
  [--expires 2026-12-31] [--reason "Justification"]

# Pro tier: Remove an override
python3 .claude/hooks/override_cli.py remove --scope user|project --name NAME

# Pro tier: Validate overrides against current rules
python3 .claude/hooks/override_cli.py validate [--scope user|project|all]

# Pro tier: Test if a command would be overridden
python3 .claude/hooks/override_cli.py test --command "COMMAND" --rule RULE_NAME
```

### Managed Deployment

Managed deployment (IT-enforced non-overridable rules) is available in [claude-privacy-hook-pro](https://github.com/anthropics/claude-privacy-hook-pro).

## Output Sanitizer Rules

Edit `.claude/hooks/output_sanitizer_rules.json` to customize what gets redacted from command output. Uses the same rule format as the regex filter. Free tier supports `redact` mode only (`[REDACTED]`).

| Mode | Output Format | Tier |
|------|---------------|------|
| `redact` (default) | `[REDACTED]` | Free |
| `pseudonymize` | `[PII-{8-char-hash}]` | **Pro only** — enables correlation without exposing PII |
| `hash` | `sha256:{64-char-hash}` | **Pro only** — forensic integrity, irreversible full hash |

## Audit Logger Settings

Free tier: basic JSONL logging to `{hooks_dir}/audit.log`. No configuration required.

Log rotation (`HOOK_AUDIT_LOG_MAX_BYTES`, `HOOK_AUDIT_LOG_BACKUP_COUNT`), data minimization (`HOOK_AUDIT_LOG_MINIMIZE`), custom log paths (`HOOK_AUDIT_LOG`), and SCF metadata in log entries require Pro.

## Risk Scoring

**Pro tier only.** The override CLI calculates a risk score (1-10) when adding overrides, based on four factors:

| Factor | Values |
|--------|--------|
| `data_classification` | restricted=4, confidential=3, internal=2, public=1 |
| `scf.risk_level` | critical=4, high=3, medium=2, low=1 |
| Scope | project=+1 (team-wide), user=+0 |
| Expiry | no expiry=+1, >90 days=+1, ≤90 days=+0 |

Score ≥ 8 triggers a warning. All override add/remove actions are logged to the audit trail.

## Rate Limiter Settings

Free tier uses fixed thresholds (not configurable):

| Setting | Value | Description |
|---------|-------|-------------|
| `warn_threshold` | 5 | Number of violations before warning |
| `block_threshold` | 10 | Number of violations before blocking |
| `window_seconds` | 300 | Rolling window size (5 minutes) |

Configurable thresholds and cooldown settings require Pro.

> NLP configuration (PII detection sensitivity, plugin settings, entity type selection) is available in [claude-privacy-hook-pro](https://github.com/anthropics/claude-privacy-hook-pro).
