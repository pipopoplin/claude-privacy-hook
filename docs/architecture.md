# Architecture

This system implements a Security, Compliance & Resilience Management System (SCRMS) through a three-layer hook pipeline. Filter configs are **living control sets** — declarative JSON policies updated without code changes. The override system provides **change management** for controlled exceptions. The audit log produces **evidence of control effectiveness** for compliance reporting.

## Hook Pipeline

Hooks fire at different stages depending on the tool. All hooks log blocked/redacted events to `audit.log` via the audit logger.

```
Bash command → regex_filter.py (filter_rules.json, 18 rules, <1ms)
             → rate_limiter.py (violation escalation, <1ms)
             → execute or block
                  ↓
             output_sanitizer.py (PostToolUse, 7 redaction rules) → redact stdout/stderr

Write/Edit   → regex_filter.py (filter_rules_write.json, 8 rules) → execute or block
Read         → regex_filter.py (filter_rules_read.json, 1 rule)   → execute or block
```

## Data Flow — Privacy Perspective

Personal data can enter the hook pipeline at three points. At each point, controls detect, block, or redact before the data can leave the system boundary.

```
                          SYSTEM BOUNDARY (developer machine)
                         ┌─────────────────────────────────────┐
                         │                                     │
  PD enters via          │  ┌─────────────┐                   │
  command input  ───────►│  │ normalize   │  Unicode NFKC,    │
  (Bash tool)            │  │ (hook_utils)│  homoglyph map,   │
                         │  └──────┬──────┘  zero-width strip │
                         │         ▼                           │
                         │  ┌─────────────┐   Match? ──► DENY │  PD blocked
                         │  │ regex_filter│          ──► ASK  │  (never leaves)
                         │  │ (18 rules)  │                   │
                         │  └──────┬──────┘   No match        │
                         │         ▼                    ▼      │
  PD enters via          │  ┌─────────────┐   ┌──────────┐   │
  file content  ────────►│  │ write filter│   │ execute  │   │
  (Write/Edit tool)      │  │ (8 rules)   │   │ command  │   │
                         │  └─────────────┘   └────┬─────┘   │
                         │                         ▼          │
  PD enters via          │                  ┌─────────────┐   │
  command output ◄───────│──────────────────│  output     │   │
  (stdout/stderr)        │                  │  sanitizer  │   │
                         │                  │  (7 rules)  │   │
                         │                  └──────┬──────┘   │
                         │                         ▼          │
                         │  PD replaced with [REDACTED] or    │
                         │  [PII-token] (pseudonymize mode)   │
                         │                                     │
                         │  ┌─────────────┐                   │
                         │  │ audit_logger│  Stores ONLY:     │
                         │  │ (JSONL)     │  - SHA-256 hash   │
                         │  └─────────────┘  - pattern labels │
                         │                   - SCF metadata   │
                         │    (NO raw PD in audit log)        │
                         └─────────────────────────────────────┘
```

**Key privacy guarantees:**
- PD detected at input is blocked before execution — it never reaches the network or filesystem
- PD detected in output is redacted before the developer sees it
- The audit log stores command hashes and label names only — never raw personal data
- With `HOOK_AUDIT_LOG_MINIMIZE=1`, even command previews are omitted

## Regex Filter (Layer 1)

Fast, deterministic regex engine with Unicode normalization (NFKC), homoglyph detection (Cyrillic/Greek), and zero-width character stripping. Reads any JSON rule config, evaluates rules top-to-bottom — first match wins.

All deny rules are placed before the allow rule to ensure sensitive data is blocked even when sent to trusted endpoints.

**File:** `.claude/hooks/regex_filter.py`

### Bash Rules (`filter_rules.json` — 18 rules, ~180 patterns, living control set)

| Rule | Action | What it catches |
|------|--------|----------------|
| `block_sensitive_data` | DENY | API keys (`sk-ant-*`, `sk-*`), AWS creds, GitHub/GitLab tokens, Stripe, Google, SendGrid, Twilio, JWT, npm, PyPI, Hugging Face, DigitalOcean, Vault tokens, private keys, hardcoded passwords |
| `block_employee_hr_ids` | DENY | Employee IDs (`EMP-12345`), HR numbers, staff IDs, payroll IDs |
| `block_iban_bank_accounts` | DENY | IBAN numbers, routing numbers, SWIFT/BIC codes, sort codes, bank account numbers |
| `block_passport_licence` | DENY | Passport numbers, driver licence numbers, national IDs |
| `block_base64_payloads` | DENY | `base64` CLI, `b64encode()`, `atob()`/`btoa()`, long base64 strings (80+ chars) |
| `block_prompt_injection` | DENY | "ignore previous instructions", role reassignment, jailbreak phrases, XML tag injection |
| `block_shell_obfuscation` | DENY | `eval`, hex/octal escapes, `/dev/tcp`, `/dev/udp`, `IFS=`, `source <(...)`, exec fd redirection |
| `block_path_traversal` | DENY | 3+ levels `../`, 2+ levels to sensitive files, URL-encoded `%2e%2e`, double-encoded variants |
| `block_sensitive_file_access` | DENY | `/etc/shadow`, `.ssh/id_*`, `.env`, `.aws/credentials`, `.kube/config`, shell history files |
| `block_database_connection_strings` | DENY | `postgres://user:pass@host`, `DATABASE_URL=`, JDBC, ADO.NET, ODBC connection strings |
| `block_dns_exfiltration` | DENY | `dig`/`nslookup`/`host` with `$()`, backticks, pipes, TXT queries, `+short` |
| `block_pipe_chain_exfiltration` | DENY | Multi-stage pipes to network tools, file-read-to-curl, reverse shells, `mkfifo`, `mail`/`sendmail` |
| `block_internal_network_addresses` | DENY | RFC1918 (10.x, 172.16-31.x, 192.168.x), link-local, cloud metadata endpoints, .internal/.corp/.lan suffixes |
| `block_customer_contract_ids` | DENY | Customer IDs (`CUST-*`), invoices (`INV-*`), orders (`ORD-*`), contracts, accounts, POs, tenant/subscription IDs |
| `allow_trusted_endpoints` | ALLOW | localhost, package registries (PyPI, npm, crates.io), VCS hosts (GitHub, GitLab, Bitbucket) |
| `block_untrusted_network` | DENY | curl, wget, ssh, Python requests/httpx, JS fetch/axios, Anthropic/OpenAI SDK calls, netcat, etc. |

### Write/Edit Rules (`filter_rules_write.json`)

Blocks sensitive data in file content: API keys, credentials, PII patterns, private keys, passwords, DB connection strings, SSNs, credit cards, internal IPs.

### Read Rules (`filter_rules_read.json`)

Blocks access to sensitive file paths: `/etc/passwd`, `.ssh`, `.env`, `.aws`, `.kube`, shell history, etc.

## Output Sanitizer (PostToolUse)

Runs after command execution and sanitizes sensitive data from stdout/stderr using 7 pattern rules: API keys, SSNs, credit cards, emails, private keys, DB connection strings, internal IPs.

Three anonymization modes are available per rule via the `anonymization_mode` field:

| Mode | Output | Use case |
|------|--------|----------|
| `redact` (default) | `[REDACTED]` | Maximum privacy — no trace of original value |
| `pseudonymize` | `[PII-{8-char-hash}]` | Same input = same token, enables correlation without exposing PII |
| `hash` | `sha256:{full-64-char-hash}` | Irreversible, full hash for forensic integrity verification |

**File:** `.claude/hooks/output_sanitizer.py`

## Rate Limiter

Counts deny/ask violations in a rolling 5-minute window per session. Escalates: warn at 5 violations, block at 10.

**File:** `.claude/hooks/rate_limiter.py`

## Audit Logger (Evidence of Control Effectiveness)

JSONL audit log writer providing evidence of control effectiveness. All hooks call `audit_logger.log_event()` on block/redact. Logs: timestamp, filter name, rule, action, matched patterns, command hash (SHA256), redacted command preview, session ID, SCF control metadata (domain, controls, regulations, risk_level).

### Log Rotation

Automatic size-based rotation prevents unbounded disk growth:

| Env Var | Default | Description |
|---------|---------|-------------|
| `HOOK_AUDIT_LOG_MAX_BYTES` | 10 MB | Rotate when file exceeds this size |
| `HOOK_AUDIT_LOG_BACKUP_COUNT` | 5 | Number of rotated backups to keep |

Rotation shifts `audit.log` → `audit.log.1` → `audit.log.2` → ... and deletes the oldest beyond the backup count. Set either to `0` to disable rotation.

### Data Minimization

Set `HOOK_AUDIT_LOG_MINIMIZE=1` to enable DPMP P3.2 / DCH-18.2 compliant minimization:
- Omits `command_preview` field entirely (no command text in log)
- Strips matched text from labels — `"API key: sk-ant-abc..."` becomes `"API key"`
- Retains `command_hash` for correlation without storing any PII

### Evidence Collector

Use `evidence_collector.py` to generate compliance reports grouped by SCF control. Supports `--cross-session` for situational awareness (detects "hot rules" triggered across 3+ sessions), `--overrides` for override activity, `--domain` and `--since` filters.

### Breach Report

`breach_report.py` identifies sessions exceeding a deny threshold (default 10) as breach candidates and generates GDPR Art.33-compliant reports with 7 required sections: nature, data categories, scale, consequences, measures taken, regulatory context, and contact information. Outputs text, JSON, or markdown.

Override log path via `HOOK_AUDIT_LOG` env var.

**File:** `.claude/hooks/audit_logger.py`

## Hook Utilities

Shared Unicode normalization (NFKC, homoglyphs, zero-width character stripping) and dot-path field resolution used by all hooks.

**File:** `.claude/hooks/hook_utils.py`

## Override System (Change Management)

Two-layer change management system allowing controlled exceptions without editing rule files. User overrides (`~/.claude/hooks/config_overrides.json`) take priority over project overrides (`.claude/hooks/config_overrides.json`). Non-overridable rules cannot be bypassed. Overrides support expiry dates and are logged to the audit trail.

**Files:** `.claude/hooks/override_resolver.py`, `.claude/hooks/override_cli.py`, `.claude/hooks/config_overrides.json`

## Project Structure

```
claude-privacy-hook/
├── install.sh                  # Linux installer
├── install_mac.sh              # macOS installer (wraps install.sh)
├── install.bat                 # Windows installer
├── .claude/
│   ├── settings.json           # Hook registrations
│   └── hooks/
│       ├── regex_filter.py     # Layer 1: regex engine
│       ├── output_sanitizer.py # Post-hook: output redaction
│       ├── rate_limiter.py     # Meta: violation escalation
│       ├── audit_logger.py     # Meta: JSONL audit logging
│       ├── hook_utils.py       # Shared: Unicode normalization, field resolution
│       ├── override_resolver.py# Override loading and checking
│       ├── override_cli.py     # Override management CLI
│       ├── filter_rules.json   # Living control set: Bash (18 rules, ~180 patterns)
│       ├── filter_rules_write.json  # Living control set: Write/Edit
│       ├── filter_rules_read.json   # Living control set: Read
│       ├── output_sanitizer_rules.json # Living control set: output redaction
│       ├── rate_limiter_config.json # Rate limiter config
│       ├── evidence_collector.py    # SCF compliance evidence reporting + cross-session analysis
│       ├── breach_report.py        # GDPR Art.33 breach notification generator
│       └── config_overrides.json    # Change management: project-level overrides
├── tests/                      # 9 test suites, 1,390 cases
├── benchmarks/                 # Benchmark suites
└── docs/                       # Documentation
```

> NLP-based PII detection, custom plugins, and enhanced features are available in [claude-privacy-hook-pro](https://github.com/anthropics/claude-privacy-hook-pro).

For visual diagrams of the hook pipeline, see [Hook System — Diagrams](sequence-diagram.md).
