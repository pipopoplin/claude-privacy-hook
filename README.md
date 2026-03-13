# claude-privacy-hook

Security hooks for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that protect your data before it ever leaves your machine.

## The Problem

AI coding assistants are powerful — but they can accidentally leak API keys, send personal data to untrusted servers, or expose credentials hidden in your codebase. A single unguarded command is all it takes.

## The Solution

**claude-privacy-hook** intercepts every tool action Claude Code takes — commands, file reads, file writes — and blocks anything that could expose sensitive data. It works silently in the background with zero configuration needed.

### What it catches

- **Credentials** — API keys, cloud tokens (AWS, GCP, Azure), private keys, database passwords, vendor secrets (Stripe, GitHub, Slack, etc.)
- **Personal data (PII)** — names, email addresses, phone numbers, SSNs, credit card numbers, passport and driver licence numbers
- **Financial data** — IBANs, bank accounts, routing numbers, customer/invoice/order IDs
- **Employee data** — employee IDs, HR numbers, payroll references
- **Attack attempts** — prompt injection, shell obfuscation, path traversal, DNS exfiltration, pipe-chain data theft
- **Network leaks** — blocks calls to untrusted servers while allowing safe ones (GitHub, npm, PyPI, localhost)
- **Sensitive files** — prevents reading `.env`, `.ssh`, `.aws/credentials`, `/etc/shadow`, and similar
- **Output leaks** — redacts any sensitive data that appears in command output after execution

### Why use it

- **Zero trust by default** — every action is checked, not just the ones you think of
- **No workflow disruption** — trusted tools and endpoints are pre-approved; you only get blocked when something is genuinely risky
- **Defense in depth** — four independent layers so no single bypass compromises everything
- **Compliance-ready** — maps to 40 security controls across GDPR, HIPAA, PCI-DSS, and OWASP standards
- **Fully auditable** — every blocked action is logged with timestamps, patterns matched, and command hashes
- **No cloud dependency** — everything runs locally on your machine, nothing phones home

## How It Works

Four independent security layers run on every action:

| Layer | What it does | Speed |
|-------|-------------|-------|
| **Regex filter** | Pattern-matches 160+ known credential formats, attack signatures, and sensitive data | <1ms |
| **NLP filter** | Detects PII that patterns can't catch (real names, contextual data) using AI models | ~5ms (service), 3-25ms (cold) |
| **Rate limiter** | Escalates when too many suspicious actions happen in a session | <1ms |
| **Output sanitizer** | Redacts sensitive data from command results after execution | <1ms |

```
Bash command → Regex filter (16 rules) → NLP filter (7 plugins) → Rate limiter → Execute
                                                                                    ↓
                                                                          Output sanitizer → Result

Write/Edit   → Regex filter (content rules) → Execute
Read         → Regex filter (path rules)    → Execute
```

All blocked events are written to an audit log for review and compliance.

## Installation

### Prerequisites

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI installed
- Python 3.10+ (3.11+ recommended for best regex performance)

### Quick Install (recommended)

The installation scripts create a `claude_privacy_hook_env` virtual environment and install all dependencies:

```bash
git clone https://github.com/pipopoplin/claude-privacy-hook.git
cd claude-privacy-hook

# Linux
chmod +x install.sh
./install.sh              # All NLP plugins (spaCy + Presidio + DistilBERT)
./install.sh --core       # Core hooks only (no NLP plugins, zero dependencies)
./install.sh --spacy      # Core + spaCy only (recommended, lightweight)

# macOS
chmod +x install_mac.sh
./install_mac.sh          # Checks Xcode CLT + Homebrew Python, then installs

# Windows
install.bat               # All NLP plugins
install.bat --core        # Core hooks only
```

Flags can be combined: `./install.sh --spacy --presidio`

| Flag | What it installs | Download size |
|------|-----------------|--------------|
| `--core` | Core hooks only (stdlib) | None |
| `--spacy` | spaCy + `en_core_web_sm` model | ~50 MB |
| `--presidio` | Microsoft Presidio analyzer | ~30 MB |
| `--distilbert` | Transformers + PyTorch | ~2.8 GB |
| _(no flags)_ | All of the above | ~3 GB |

The scripts automatically:
1. Find Python 3.10+ on your system
2. Create the `claude_privacy_hook_env` virtual environment
3. Install selected NLP plugins
4. Verify all components
5. Run smoke tests on the hook pipeline

After installation, activate the environment:

```bash
# Linux / macOS
source claude_privacy_hook_env/bin/activate

# Windows
claude_privacy_hook_env\Scripts\activate.bat
```

### Manual Install

If you prefer to manage your own environment:

```bash
git clone https://github.com/pipopoplin/claude-privacy-hook.git
cd claude-privacy-hook

python3 -m venv claude_privacy_hook_env
source claude_privacy_hook_env/bin/activate  # Linux/macOS
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### Copy Hooks Into Your Project

Copy the `.claude/` directory into any project where you want the hooks active:

```bash
cp -r .claude /path/to/your/project/
```

Or use this repo directly as your project.

### Verify Installation

```bash
python3 tests/run_all.py                # Run all 1312 tests across 7 suites
python3 tests/test_regex_filter.py      # Regex filter: Bash + Write + Read (518 cases)
python3 tests/test_nlp_filter.py        # NLP filter: PII + plugins (272 cases)
python3 tests/test_output_sanitizer.py  # Output sanitizer (179 cases)
python3 tests/test_rate_limiter.py      # Rate limiter (60 cases)
python3 tests/test_overrides.py         # Override system (81 cases)
python3 tests/test_nlp_service.py       # NLP persistent service (42 cases)
python3 tests/test_conftest.py          # Test infrastructure (160 cases)
```

### Run Benchmarks (optional)

```bash
python3 benchmarks/run_all.py          # All benchmarks (~2 min)
python3 benchmarks/run_all.py --fast   # Skip slow NLP subprocess benchmarks
```

### Restart Claude Code

Hooks are loaded at session startup. Restart Claude Code or run `/hooks` to review the active hooks.

## Configuration

The hooks work out of the box. For customization:

- **Allow a trusted endpoint** — add a URL pattern to `allow_trusted_endpoints` in `.claude/hooks/filter_rules.json`, or use the override CLI
- **Adjust NLP sensitivity** — change `min_confidence` in `.claude/hooks/llm_filter_config.json` (lower = catches more, higher = fewer false positives)
- **Disable a hook** — set `"enabled": false` in the config, or remove the hook entry from `.claude/settings.json`

See the full [Configuration guide](docs/configuration.md) for all options.

## Override System

Rules use a three-layer override system so teams can add exceptions without editing rule files:

| Layer | Scope | File | Can Override? |
|-------|-------|------|---------------|
| **Managed** | IT-enforced | `/etc/claude-code/hooks/managed_rules.json` | Cannot be overridden |
| **Project** | Team-shared | `.claude/hooks/config_overrides.json` | Overrides `ask` rules only |
| **User** | Personal | `~/.claude/hooks/config_overrides.json` | Overrides `ask` rules only |

8 rules are hard `deny` (credentials, injection, exfiltration) — these cannot be overridden. 7 rules are soft `ask` (untrusted networks, internal IPs, employee IDs, etc.) — these can be overridden with the CLI:

```bash
# Allow a specific API endpoint
python3 .claude/hooks/override_cli.py add --scope project \
  --rule block_untrusted_network \
  --pattern 'https?://api\.mycompany\.com' \
  --label 'Company API' \
  --reason 'Required for integration testing'

# List all overrides
python3 .claude/hooks/override_cli.py list

# Validate overrides against current rules
python3 .claude/hooks/override_cli.py validate

# Test if a command would be overridden
python3 .claude/hooks/override_cli.py test \
  --command "curl https://api.mycompany.com/health" \
  --rule block_untrusted_network

# Remove an override
python3 .claude/hooks/override_cli.py remove --scope project --name allow_company_api
```

For IT-managed deployment, see [`managed/README.md`](managed/README.md).

## Compliance Coverage

All 40 filters are implemented across the four security layers.

| # | Filter | Layer | Scope | SCF Domain | SCF Control | Regulation | Value | Free |
|---|--------|-------|-------|------------|-------------|------------|-------|:----:|
| 1 | Anthropic / OpenAI API keys | L1 regex | 🔐 | IAC | IAC-01 | — | 🔴 Critical |  f  |
| 2 | AWS / GCP / Azure credentials | L1 regex | 🔐 | IAC | IAC-01 | — | 🔴 Critical |  f  |
| 3 | GitHub / GitLab tokens | L1 regex | 🔐 | IAC | IAC-09 | — | 🔴 Critical |  f  |
| 4 | Private keys / PEM certs | L1 regex | 🔐 | CRY | CRY-03 | — | 🔴 Critical |  f  |
| 5 | Slack / webhook tokens | L1 regex | 🔐 | IAC | IAC-09 | — | 🔴 Critical |  f  |
| 6 | Hardcoded passwords | L1 regex | 🔐 | IAC | IAC-01 | — | 🔴 Critical |  f  |
| 7 | Untrusted network calls | L1 regex | 🔐 | NET | NET-13 | — | 🔴 Critical |   |
| 8 | Trusted endpoint allowlist | L1 regex | 🔐 | NET | NET-13 | — | 🔴 Critical |   |
| 9 | Person names (NER) | L2 NLP | 🛡️ | PRI | PRI-01 | GDPR Art.4 | 🔴 Critical |   |
| 10 | Email addresses | L2 NLP | 🛡️ | PRI | PRI-01 | GDPR Art.4 | 🔴 Critical |   |
| 11 | SSN / National ID | L2 NLP | 🛡️ | PRI | PRI-03 | GDPR Art.9 | 🔴 Critical |  f  |
| 12 | Credit card numbers | L2 NLP | 🛡️ | DAT | DAT-02 | PCI-DSS Req.3 | 🔴 Critical |  f  |
| 13 | Phone numbers | L2 NLP | 🛡️ | PRI | PRI-01 | GDPR Art.4 | 🔴 Critical |   |
| 14 | IP addresses | L2 NLP | 🛡️ | PRI | PRI-01 | GDPR Art.4 | 🔴 Critical |   |
| 15 | ORG / GPE / NORP entities | L2 NLP | 🛡️ | PRI | PRI-02 | GDPR Art.4 | 🟠 High |   |
| 16 | Expanded vendor credentials | L1 regex | 🔐 | IAC | IAC-01 | — | 🔴 Critical |   |
| 17 | Employee ID / HR numbers | L1 regex | 🛡️ | HRS | HRS-01 | GDPR Art.88 | 🔴 Critical |   |
| 18 | Medical / health data | L2 NLP | 🛡️ | PRI | PRI-03 | GDPR Art.9 / HIPAA | 🔴 Critical |   |
| 19 | IBAN / bank account numbers | L1 regex | 🛡️ | DAT | DAT-02 | PSD2 / GDPR Art.4 | 🔴 Critical |  f  |
| 20 | Passport / driver licence | L1 regex | 🛡️ | PRI | PRI-03 | GDPR Art.9 | 🔴 Critical |   |
| 21 | Base64-encoded payloads | L1 regex | 🔐 | TVM | TVM-07 | — | 🔴 Critical |   |
| 22 | Prompt injection phrases | L1/L2 | 🔐 | TVM | TVM-10 | OWASP LLM01 | 🔴 Critical |   |
| 23 | Sensitive file access | L1 regex | 🔐🛡️ | END | END-04 | GDPR Art.32 | 🔴 Critical |   |
| 24 | DNS exfiltration | L1 regex | 🔐 | NET | NET-14 | — | 🟠 High |   |
| 25 | Path traversal | L1 regex | 🔐 | TVM | TVM-10 | OWASP A05 | 🟠 High |   |
| 26 | Database connection strings | L1 regex | 🔐🛡️ | DCH | DCH-05 | GDPR Art.32 | 🔴 Critical |   |
| 27 | Internal hostnames / IPs | L1 regex | 🛡️ | NET | NET-01 | GDPR Art.32 | 🟠 High |   |
| 28 | Customer / contract IDs | L1 regex | 🛡️ | PRI | PRI-02 | GDPR Art.4 | 🟠 High |   |
| 29 | Biometric data references | L2 NLP | 🛡️ | PRI | PRI-03 | GDPR Art.9 | 🟠 High |   |
| 30 | Ethnic / religious / political | L2 NLP | 🛡️ | PRI | PRI-03 | GDPR Art.9 | 🟠 High |   |
| 31 | Unicode / homoglyph bypass | L1 | 🔐 | TVM | TVM-07 | — | 🟠 High |   |
| 32 | High-entropy secret detection | L2 NLP | 🔐 | IAC | IAC-01 | — | 🟠 High |   |
| 33 | Shell obfuscation / eval | L1 regex | 🔐 | OPS | OPS-05 | — | 🟠 High |   |
| 34 | Pipe-chain exfiltration | L1 regex | 🔐 | NET | NET-13 | — | 🟠 High |   |
| 35 | Output sanitization | Post-hook | 🛡️ | DAT | DAT-05 | GDPR Art.32 | 🟡 Medium |   |
| 36 | ask / human oversight | Meta | ⚖️ | GOV | GOV-04 | GDPR Art.22 | 🟡 Medium |   |
| 37 | Audit log of blocked events | Meta | ⚖️ | IRO | IRO-01 | GDPR Art.5(2) | 🟠 High |   |
| 38 | Rate limiting / anomaly | Meta | 🔐 | OPS | OPS-08 | — | 🟡 Medium |   |
| 39 | Non-Bash tool coverage | Config | 🔐🛡️ | OPS | OPS-05 | GDPR Art.32 | 🟡 Medium |   |
| 40 | Semantic intent scoring | L2 NLP | 🔐🛡️ | TVM | TVM-10 | OWASP LLM01 | 🟡 Medium |   |

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

## Performance

Every hook is benchmarked at two levels: **subprocess** (real-world latency including Python startup) and **in-process** (pure function cost).

### Full pipeline — Bash command (heaviest path)

| Stage | Subprocess (p50) | In-process | Notes |
|-------|----------------:|----------:|-------|
| Regex filter | 24ms | 0.07ms | 16 rules, ~160 patterns |
| NLP filter (service) | 31ms | 1.4ms | Persistent service + spaCy |
| Rate limiter | 20ms | 0.06ms | ~50 audit log entries |
| Output sanitizer | 20ms | 0.02ms | 7 redaction rules |
| **Total** | **~95ms** | **~1.6ms** | Subprocess dominated by Python startup |

Write/Edit and Read paths only run the regex filter (~20ms subprocess, <0.01ms in-process).

### Component highlights

| Component | In-process speed | Notes |
|-----------|----------------:|-------|
| `normalize_unicode()` | 1.2M ops/s | Plain ASCII; 5K ops/s for 6KB text |
| `resolve_field()` | 6.9M ops/s | Dot-path field resolution |
| `evaluate_rules()` | 14K–155K ops/s | Varies by rule set (Bash slowest, Read fastest) |
| `redact_text()` | 52K ops/s | Typical output; 280/s for 500-line output |
| `check_override()` | 67K ops/s | 50 overrides, no match |
| `log_event()` | 128K ops/s | JSONL append |
| Supplementary plugins | 100K–4.6M ops/s | Pure Python, no external deps |
| spaCy plugin | 560 ops/s | NER model inference |

The ~17ms subprocess overhead per hook is Python interpreter startup. The persistent NLP service (`llm_client.py`) reduces cold NLP invocations from ~730ms to ~31ms by keeping spaCy loaded.

See the full [Benchmark guide](benchmarks/README.md) for methodology, all scenarios, and how to run.

## Documentation

| Document | Audience | Description |
|----------|----------|-------------|
| [Architecture](docs/architecture.md) | Developers, contributors | Hook pipeline internals, layer details, project structure |
| [Configuration](docs/configuration.md) | Developers | Rule format, all configuration options, tuning guide |
| [Plugins](docs/plugins.md) | Plugin developers | Plugin API, writing and registering custom plugins |
| [Testing](docs/testing.md) | Contributors | Test suites, running tests, adding test cases |
| [Benchmarks](benchmarks/README.md) | Contributors, performance | Latency and throughput for every hook component |
| [Diagrams](docs/sequence-diagram.md) | All | Visual pipeline sequence and decision flow diagrams |

## License

[Business Source License 1.1](LICENSE)

Free for non-production use (evaluation, testing, personal projects, academic research). Production use requires a commercial license — contact the Licensor.

On the Change Date (4 years after each version's release), that version converts to [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

NLP plugin dependencies (spaCy, Presidio, transformers, PyTorch) use permissive licenses (MIT/Apache 2.0/BSD).
