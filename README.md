# claude-privacy-hook

Security hooks for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that intercept Bash commands before execution and block credential leaks, untrusted network calls, PII exposure, prompt injection, and sensitive file access.

Multi-layer defense with PreToolUse and PostToolUse hooks:

| Hook | What it catches | Latency | Dependencies |
|------|----------------|---------|--------------|
| **regex_filter** (Bash) | API keys, vendor tokens, untrusted endpoints, employee IDs, IBANs, passports, base64, prompt injection, shell obfuscation, path traversal, sensitive files, DB connections, DNS exfiltration, pipe chains, internal IPs, customer IDs | <1ms | None |
| **regex_filter** (Write/Edit) | Sensitive data in file content (API keys, credentials, PII patterns) | <1ms | None |
| **regex_filter** (Read) | Access to sensitive file paths (.env, .ssh, .aws, etc.) | <1ms | None |
| **llm_filter** | PII (names, emails, SSNs, credit cards, phone numbers, IP addresses) | 3-25ms | One NLP plugin |
| **llm_filter** (supplementary) | Prompt injection, medical/biometric/protected data, high-entropy secrets, suspicious intent | ~1ms each | None (built-in) |
| **output_sanitizer** | Redacts sensitive data from command stdout/stderr (PostToolUse) | <1ms | None |
| **rate_limiter** | Escalates when too many violations occur in a session window | <1ms | None |

## Installation

### Prerequisites

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI installed
- Python 3.10+

### 1. Clone the repository

```bash
git clone https://github.com/pipopoplin/claude-privacy-hook.git
cd claude-privacy-hook
```

### 2. Copy hooks into your project

Copy the `.claude/` directory into any project where you want the hooks active:

```bash
cp -r .claude /path/to/your/project/
```

Or use this repo directly as your project.

### 3. Install an NLP plugin (optional, for PII detection)

The regex filter and prompt injection plugin work with zero dependencies. For NLP-based PII detection, install one backend:

```bash
# spaCy — recommended, lightweight, ~3ms
pip install spacy
python -m spacy download en_core_web_sm

# Microsoft Presidio — fastest, ~0.4ms, known PII types
pip install presidio-analyzer

# DistilBERT — best accuracy, ~25ms
pip install transformers torch
```

Or install from the requirements file (spaCy by default):

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 4. Verify installation

```bash
python3 test_hook.py        # Regex filter tests (126 cases, always works)
python3 test_llm_hook.py    # NLP filter tests (39 cases, supplementary plugins always work, PII needs a plugin)
```

### 5. Restart Claude Code

Hooks are loaded at session startup. Restart Claude Code or run `/hooks` to review the active hooks.

## How It Works

Hooks fire at different stages depending on the tool. All hooks log blocked/redacted events to `audit.log` via the audit logger.

```
Bash command → regex_filter.py (filter_rules.json, 16 rules, <1ms)
             → llm_filter.py (PII + 4 supplementary plugins, 3-25ms)
             → rate_limiter.py (violation escalation, <1ms)
             → execute or block
                  ↓
             output_sanitizer.py (PostToolUse, 7 redaction rules) → redact stdout/stderr

Write/Edit   → regex_filter.py (filter_rules_write.json, 8 rules) → execute or block
Read         → regex_filter.py (filter_rules_read.json, 1 rule)   → execute or block
```

### Regex filter (layer 1)

Evaluates rules from `.claude/hooks/filter_rules.json` top-to-bottom. First match wins. All deny rules are placed before the allow rule to ensure sensitive data is blocked even when sent to trusted endpoints.

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

### NLP filter (layer 2)

Detects PII that regex can't catch — real names, email addresses, phone numbers, SSNs, credit card numbers embedded in commands.

Uses a two-tier plugin dispatch:

1. **PII plugins** — tries plugins in priority order, uses the first available:

| Plugin | Tier | Latency | Best for |
|--------|------|---------|----------|
| presidio | SubMillisecond | ~0.4ms | Production, known PII types |
| spacy | EdgeDevice | ~3ms | Low resource, good default |
| distilbert | HighAccuracy | ~25ms | Maximum detection accuracy |

2. **Supplementary plugins** — always run independently, regardless of which PII plugin is active:

| Plugin | Tier | Latency | Best for |
|--------|------|---------|----------|
| prompt_injection | EdgeDevice | ~1ms | Jailbreak / injection detection (no external deps) |
| sensitive_categories | EdgeDevice | ~1ms | Medical, biometric, and GDPR Art.9 protected categories (no external deps) |
| entropy_detector | EdgeDevice | ~1ms | High-entropy secret detection for unknown token formats (no external deps) |
| semantic_intent | EdgeDevice | ~1ms | Verb+target heuristic classification for suspicious command intent (no external deps) |

The supplementary plugin architecture ensures all these detectors fire on every command, even if no PII plugin is installed.

## Configuration

### Allow a trusted endpoint

Add a pattern to the `allow_trusted_endpoints` rule in `.claude/hooks/filter_rules.json`:

```json
{"pattern": "https?://api\\.your-company\\.com", "label": "Your API"}
```

### Adjust NLP sensitivity

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

### Disable a hook

Set `"enabled": false` in `llm_filter_config.json` to disable the NLP hook, or remove its entry from `.claude/settings.json`.

To disable a specific regex rule, add `"enabled": false` to the rule in `filter_rules.json`.

### Add a custom NLP plugin

1. Create `.claude/hooks/plugins/my_plugin.py`:

```python
from .base import DetectionResult, SensitiveContentPlugin

class MyPlugin(SensitiveContentPlugin):
    name = "my_plugin"
    tier = "Custom"

    def is_available(self) -> bool:
        try:
            import my_library
            return True
        except ImportError:
            return False

    def detect(self, text, entity_types=None):
        # Return list of DetectionResult
        return []
```

2. Register in `.claude/hooks/plugins/plugins.json`:

```json
{
  "my_plugin": {
    "module": "plugins.my_plugin",
    "class": "MyPlugin",
    "tier": "Custom",
    "latency": "~5ms",
    "description": "My custom detector",
    "install": "pip install my-library"
  }
}
```

3. Add to `llm_filter_config.json`:

```json
{
  "plugin_priority": ["my_plugin", "presidio", "spacy"],
  "plugins": {
    "my_plugin": {
      "enabled": true
    }
  }
}
```

To make a plugin supplementary (always runs alongside the primary PII plugin), add it to `supplementary_plugins` instead of `plugin_priority`.

## Project Structure

```
.claude/
  settings.json                       # Hook registration (PreToolUse + PostToolUse, multi-tool matchers)
  hooks/
    regex_filter.py                   # Layer 1: regex rule engine + Unicode normalization
    filter_rules.json                 # Bash regex rules (16 rules, ~160 patterns)
    filter_rules_write.json           # Write/Edit tool rules (sensitive data in file content)
    filter_rules_read.json            # Read tool rules (sensitive file path access)
    llm_filter.py                     # Layer 2: NLP plugin dispatcher (PII + supplementary)
    llm_filter_config.json            # NLP plugin config (priority, thresholds, supplementary)
    output_sanitizer.py               # PostToolUse: redacts sensitive data from command output
    output_sanitizer_rules.json       # Output sanitizer rules (API keys, SSNs, cards, etc.)
    rate_limiter.py                   # PreToolUse: escalates on repeated session violations
    rate_limiter_config.json          # Rate limiter config (thresholds, window, cooldown)
    audit_logger.py                   # JSONL audit logger for blocked events
    plugins/
      plugins.json                    # Plugin registry (7 plugins)
      base.py                         # SensitiveContentPlugin ABC + DetectionResult
      presidio_plugin.py              # Microsoft Presidio backend
      spacy_plugin.py                 # spaCy + regex backend
      distilbert_plugin.py            # DistilBERT NER backend
      prompt_injection_plugin.py      # Prompt injection / jailbreak detection (no deps)
      sensitive_categories_plugin.py  # Medical, biometric, protected category detection (no deps)
      entropy_detector_plugin.py      # High-entropy secret detection (no deps)
      semantic_intent_plugin.py       # Verb+target suspicious intent scoring (no deps)
    audit.log                         # JSONL audit log (generated at runtime)
docs/
  sequence-diagram.md                 # Mermaid diagrams rendered in Markdown
  sequence-diagram.mmd                # Full pipeline sequence diagram (Mermaid source)
  sequence-diagram.svg                # Full pipeline sequence diagram (rendered)
  decision-flow.mmd                   # Decision flowchart (Mermaid source)
  decision-flow.svg                   # Decision flowchart (rendered)
main.py                               # Entry point (placeholder)
test_hook.py                          # Regex filter tests (126 cases)
test_llm_hook.py                      # NLP filter tests (39+ cases)
requirements.txt                      # Python dependencies (spaCy default)
CLAUDE.md                             # Claude Code project guidance
LICENSE                               # Business Source License 1.1
```

## Diagrams

### Decision Flow

![Decision flow](docs/decision-flow.svg)

### Sequence Diagram

![Sequence diagram](docs/sequence-diagram.svg)

## 📊 SCF-Mapped Security & Privacy Filter Table

Full coverage map across Phase 1, Phase 2, and Phase 3.

| # | Filter | Layer | Scope | SCF Domain | SCF Control | Regulation | Value |
|---|--------|-------|-------|------------|-------------|------------|-------|
| 1 | Anthropic / OpenAI API keys | L1 regex | 🔐 | IAC | IAC-01 | — | 🔴 Critical |
| 2 | AWS / GCP / Azure credentials | L1 regex | 🔐 | IAC | IAC-01 | — | 🔴 Critical |
| 3 | GitHub / GitLab tokens | L1 regex | 🔐 | IAC | IAC-09 | — | 🔴 Critical |
| 4 | Private keys / PEM certs | L1 regex | 🔐 | CRY | CRY-03 | — | 🔴 Critical |
| 5 | Slack / webhook tokens | L1 regex | 🔐 | IAC | IAC-09 | — | 🔴 Critical |
| 6 | Hardcoded passwords | L1 regex | 🔐 | IAC | IAC-01 | — | 🔴 Critical |
| 7 | Untrusted network calls | L1 regex | 🔐 | NET | NET-13 | — | 🔴 Critical |
| 8 | Trusted endpoint allowlist | L1 regex | 🔐 | NET | NET-13 | — | 🔴 Critical |
| 9 | Person names (NER) | L2 NLP | 🛡️ | PRI | PRI-01 | GDPR Art.4 | 🔴 Critical |
| 10 | Email addresses | L2 NLP | 🛡️ | PRI | PRI-01 | GDPR Art.4 | 🔴 Critical |
| 11 | SSN / National ID | L2 NLP | 🛡️ | PRI | PRI-03 | GDPR Art.9 | 🔴 Critical |
| 12 | Credit card numbers | L2 NLP | 🛡️ | DAT | DAT-02 | PCI-DSS Req.3 | 🔴 Critical |
| 13 | Phone numbers | L2 NLP | 🛡️ | PRI | PRI-01 | GDPR Art.4 | 🔴 Critical |
| 14 | IP addresses | L2 NLP | 🛡️ | PRI | PRI-01 | GDPR Art.4 | 🔴 Critical |
| 15 | ORG / GPE / NORP entities | L2 NLP | 🛡️ | PRI | PRI-02 | GDPR Art.4 | 🟠 High |
| 16 | Expanded vendor credentials | L1 regex | 🔐 | IAC | IAC-01 | — | 🔴 Critical |
| 17 | Employee ID / HR numbers | L1 regex | 🛡️ | HRS | HRS-01 | GDPR Art.88 | 🔴 Critical |
| 18 | Medical / health data | L2 NLP | 🛡️ | PRI | PRI-03 | GDPR Art.9 / HIPAA | 🔴 Critical |
| 19 | IBAN / bank account numbers | L1 regex | 🛡️ | DAT | DAT-02 | PSD2 / GDPR Art.4 | 🔴 Critical |
| 20 | Passport / driver licence | L1 regex | 🛡️ | PRI | PRI-03 | GDPR Art.9 | 🔴 Critical |
| 21 | Base64-encoded payloads | L1 regex | 🔐 | TVM | TVM-07 | — | 🔴 Critical |
| 22 | Prompt injection phrases | L1/L2 | 🔐 | TVM | TVM-10 | OWASP LLM01 | 🔴 Critical |
| 23 | Sensitive file access | L1 regex | 🔐🛡️ | END | END-04 | GDPR Art.32 | 🔴 Critical |
| 24 | DNS exfiltration | L1 regex | 🔐 | NET | NET-14 | — | 🟠 High |
| 25 | Path traversal | L1 regex | 🔐 | TVM | TVM-10 | OWASP A05 | 🟠 High |
| 26 | Database connection strings | L1 regex | 🔐🛡️ | DCH | DCH-05 | GDPR Art.32 | 🔴 Critical |
| 27 | Internal hostnames / IPs | L1 regex | 🛡️ | NET | NET-01 | GDPR Art.32 | 🟠 High |
| 28 | Customer / contract IDs | L1 regex | 🛡️ | PRI | PRI-02 | GDPR Art.4 | 🟠 High |
| 29 | Biometric data references | L2 NLP | 🛡️ | PRI | PRI-03 | GDPR Art.9 | 🟠 High |
| 30 | Ethnic / religious / political | L2 NLP | 🛡️ | PRI | PRI-03 | GDPR Art.9 | 🟠 High |
| 31 | Unicode / homoglyph bypass | L1 | 🔐 | TVM | TVM-07 | — | 🟠 High |
| 32 | High-entropy secret detection | L2 NLP | 🔐 | IAC | IAC-01 | — | 🟠 High |
| 33 | Shell obfuscation / eval | L1 regex | 🔐 | OPS | OPS-05 | — | 🟠 High |
| 34 | Pipe-chain exfiltration | L1 regex | 🔐 | NET | NET-13 | — | 🟠 High |
| 35 | Output sanitization | Post-hook | 🛡️ | DAT | DAT-05 | GDPR Art.32 | 🟡 Medium |
| 36 | ask / human oversight | Meta | ⚖️ | GOV | GOV-04 | GDPR Art.22 | 🟡 Medium |
| 37 | Audit log of blocked events | Meta | ⚖️ | IRO | IRO-01 | GDPR Art.5(2) | 🟠 High |
| 38 | Rate limiting / anomaly | Meta | 🔐 | OPS | OPS-08 | — | 🟡 Medium |
| 39 | Non-Bash tool coverage | Config | 🔐🛡️ | OPS | OPS-05 | GDPR Art.32 | 🟡 Medium |
| 40 | Semantic intent scoring | L2 NLP | 🔐🛡️ | TVM | TVM-10 | OWASP LLM01 | 🟡 Medium |

All 40 filters are implemented.

### Glossary

#### Column Definitions

| Column | Description |
|--------|-------------|
| **#** | Filter identifier |
| **Filter** | Name of the security or privacy filter |
| **Layer** | Processing layer — see *Layers* below |
| **Scope** | Protection category — see *Scope Icons* below |
| **SCF Domain** | Secure Controls Framework domain code |
| **SCF Control** | Specific SCF control identifier |
| **Regulation** | Applicable regulatory standard (GDPR, PCI-DSS, HIPAA, etc.) |
| **Value** | Risk criticality rating |

#### Layers

| Layer | Description |
|-------|-------------|
| **L1 regex** | Layer 1 — fast, deterministic regex-based filtering (<1ms) |
| **L1/L2** | Hybrid filter spanning both regex and NLP layers |
| **L2 NLP** | Layer 2 — NLP-based detection using pluggable backends (3-25ms) |
| **Post-hook** | Runs after command execution to sanitize output |
| **Meta** | Infrastructure-level controls (logging, rate limiting, oversight) |
| **Config** | Configuration-level controls (hook registration, tool coverage) |

#### Scope Icons

| Icon | Meaning |
|------|---------|
| 🔐 | Security — credential protection, network security, attack prevention |
| 🛡️ | Privacy — PII and sensitive data protection |
| 🔐🛡️ | Both security and privacy |
| ⚖️ | Governance — compliance, oversight, and audit controls |

#### Value / Risk Ratings

| Icon | Level | Description |
|------|-------|-------------|
| 🔴 Critical | Critical | Must-have — direct credential or PII exposure risk |
| 🟠 High | High | Important — indirect exposure, evasion, or infrastructure risk |
| 🟡 Medium | Medium | Recommended — defense-in-depth and operational controls |

#### SCF Domains

| Code | Domain |
|------|--------|
| **IAC** | Identification & Access Control |
| **CRY** | Cryptographic Protections |
| **NET** | Network Security |
| **PRI** | Privacy |
| **DAT** | Data Protection |
| **TVM** | Threat & Vulnerability Management |
| **HRS** | Human Resources Security |
| **END** | Endpoint Security |
| **DCH** | Data Classification & Handling |
| **OPS** | Operations Security |
| **GOV** | Governance |
| **IRO** | Incident Response & Operations |

#### Regulations

| Abbreviation | Full Name |
|--------------|-----------|
| **GDPR Art.4** | General Data Protection Regulation — definitions of personal data |
| **GDPR Art.9** | GDPR — special categories of personal data (health, biometric, ethnic, etc.) |
| **GDPR Art.22** | GDPR — automated decision-making and human oversight |
| **GDPR Art.32** | GDPR — security of processing |
| **GDPR Art.5(2)** | GDPR — accountability principle |
| **GDPR Art.88** | GDPR — processing in the employment context |
| **PCI-DSS Req.3** | Payment Card Industry Data Security Standard — protect stored cardholder data |
| **HIPAA** | Health Insurance Portability and Accountability Act |
| **PSD2** | Payment Services Directive 2 (EU banking regulation) |
| **OWASP LLM01** | OWASP Top 10 for LLMs — prompt injection |
| **OWASP A05** | OWASP Top 10 — security misconfiguration (path traversal) |

## License

[Business Source License 1.1](LICENSE)

Free for non-production use (evaluation, testing, development, personal projects, academic research). Production use requires a commercial license — contact the Licensor.

On the Change Date (4 years after each version's release), that version converts to [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

NLP plugin dependencies (spaCy, Presidio, transformers, PyTorch) use permissive licenses (MIT/Apache 2.0/BSD).

