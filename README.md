# claude-privacy-hook

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

Security hooks for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that protect your data before it ever leaves your machine.

---

## The Problem

AI coding assistants are powerful — but they can accidentally leak API keys, send personal data to untrusted servers, or expose credentials hidden in your codebase. A single unguarded command is all it takes.

## The Solution

**claude-privacy-hook** intercepts every tool action Claude Code takes — commands, file reads, file writes — and blocks anything that could expose sensitive data. It implements a Security, Compliance & Resilience Management System (SCRMS) with living control sets, change management, and evidence of control effectiveness — all running silently in the background with zero configuration needed.

### What it catches

- **Credentials** — API keys, cloud tokens (AWS, GCP, Azure), private keys, database passwords, vendor secrets (Stripe, GitHub, Slack, etc.)
- **Personal data (PII)** — names, email addresses, phone numbers, SSNs, credit card numbers, passport and driver licence numbers
- **Financial data** — IBANs, bank accounts, routing numbers, customer/invoice/order IDs
- **Employee data** — employee IDs, HR numbers, payroll references
- **Attack attempts** — prompt injection, shell obfuscation, path traversal, DNS exfiltration, pipe-chain data theft
- **Network leaks** — blocks calls to untrusted servers while allowing safe ones (GitHub, npm, PyPI, localhost)
- **Sensitive files** — prevents reading `.env`, `.ssh`, `.aws/credentials`, `/etc/shadow`, and similar
- **Output leaks** — redacts any sensitive data that appears in command output after execution

---

## How It Works

Three independent security layers run on every action — total latency under 1ms in-process:

| Layer | What it does |
|-------|-------------|
| **Regex filter** | Living control set — pattern-matches 80+ known credential formats, attack signatures, and sensitive data (6 rules) |
| **Rate limiter** | Escalates when too many suspicious actions happen in a session (fixed thresholds) |
| **Output sanitizer** | Redacts sensitive data from command results after execution (3 rules). Pseudonymize and hash modes available in Pro. |

All blocked events are written to an audit log — evidence of control effectiveness for review and compliance. Log rotation, data minimization, SCF metadata, and breach detection are available in Pro.

---

## Quick Start

### Prerequisites

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI installed
- Python 3.10+ (3.11+ recommended)

### Install

```bash
git clone https://github.com/pipopoplin/claude-privacy-hook.git
cd claude-privacy-hook
./install.sh              # Linux
./install_mac.sh          # macOS
install.bat               # Windows
```

Zero dependencies — Python stdlib only. The installer runs smoke tests automatically.

### Add to your project

```bash
cp -r .claude /path/to/your/project/
```

Restart Claude Code or run `/hooks` to activate.

---

## Why use it

| Concern | How it helps |
|---------|-------------|
| **Zero trust** | Every action is checked, not just the ones you think of |
| **No workflow disruption** | Trusted tools and endpoints are pre-approved |
| **Defense in depth** | Three independent layers — no single bypass compromises everything |
| **Compliance-ready** | Maps to 27+ security controls. Pro extends to [111 controls](docs/compliance.md) across 23 SCF domains, GDPR, EU AI Act, DORA, NIS2, SOC 2, and more |
| **Fully auditable** | Every blocked action logged with timestamps, patterns, and command hashes |
| **Breach detection** | Automatic breach candidate identification with GDPR Art.33-compliant report generation (Pro) |
| **Privacy by design** | Redact-only output sanitization. Audit log minimization, pseudonymization/hashing, and configurable rotation available in Pro |
| **No cloud dependency** | Everything runs locally, nothing phones home |

---

## Compliance Coverage

27+ security controls in the free tier. Pro extends to 111 controls across 23 SCF domains — [full matrix →](docs/compliance.md)

| Regulation / Framework | What's covered | Controls |
|------------------------|---------------|----------|
| **SCF** | 23 domains: IAC, CRY, NET, PRI, DCH, THR, GOV, IRO, MON, AAT, CHG, CFG, SEA, SAI, TDA, and more | 111 |
| **GDPR** | Personal data (Art.4), special categories (Art.9), security (Art.32), accountability (Art.5), breach notification (Art.33), transfers (Art.44) | 28 |
| **EU AI Act** | Risk management (Art.9), human oversight (Art.14), record-keeping (Art.12), transparency (Art.52), incident reporting (Art.73) | 12 |
| **ISO 42001** | AI management system (§4), risk assessment (§6), change management, data quality (§A.7), verification (§A.6) | 8 |
| **DORA** | ICT governance (Art.5), security (Art.9), monitoring (Art.10), incident response (Art.14/17) | 6 |
| **NIS2** | Risk management (Art.21), incident handling, supply chain (Art.21.2d), cryptography, network security | 6 |
| **SOC 2** | CC1-CC9, P1-P8, A1, C1 — governance, access, operations, change management, privacy, availability | 4 |
| **PCI-DSS** | Credit card detection and redaction (Req.3) | 2 |
| **HIPAA** | Medical and health data detection | 1 |
| **OWASP** | Prompt injection (LLM01), path traversal (A05) | 3 |

All filters are rated by risk criticality (Critical / High / Medium) and tagged by scope (Security, Privacy, Governance).

---

## Configuration

Works out of the box. To customize:

- **Allow a trusted endpoint** — add a URL pattern to `filter_rules.json`, or use the [override CLI](docs/configuration.md#override-cli)
- **Disable a rule** — set `"enabled": false` in the rule config

Teams can add exceptions with the [override system](docs/configuration.md#override-system) (project-level, max 3, `list` only). Full override CLI (add/remove/validate/test) and user-level overrides require Pro.

See the full [Configuration guide](docs/configuration.md).

---

## Free vs Pro

| Feature | Free (MIT) | Pro (BSL 1.1) |
|---------|-----------|---------------|
| Regex-based PII detection (6 rules, ~80 patterns) | ✅ | ✅ 18 rules, ~180 patterns |
| Write/Edit content filtering (3 rules) | ✅ | ✅ 8 rules |
| Read path protection | ✅ | ✅ |
| Output sanitizer (3 rules, redact only) | ✅ | ✅ 7 rules, 3 anonymization modes |
| Rate limiter (fixed thresholds: warn=5, block=10, 300s window) | ✅ | ✅ Configurable thresholds |
| Basic audit logging (JSONL) | ✅ | ✅ Enhanced (SCF metadata, SIEM) |
| Project-level overrides (max 3, `list` only) | ✅ | ✅ User + project, unlimited, full CLI |
| Audit log rotation and data minimization | — | ✅ |
| Breach notification reports (GDPR Art.33) | — | ✅ |
| Evidence collector (SCF compliance reports) | — | ✅ |
| Cross-session situational awareness | — | ✅ |
| Risk scoring for override requests | — | ✅ |
| Override CLI add/remove/validate/test | — | ✅ |
| NLP-based PII detection (spaCy, Presidio, DistilBERT) | — | ✅ |
| SIEM integration (Splunk, Datadog, Elasticsearch, CEF/LEEF) | — | ✅ |
| Compliance dashboard (HTML, Grafana, Prometheus, Kibana) | — | ✅ |
| SBOM generation (CycloneDX 1.5) | — | ✅ |
| 7 pluggable detection backends | — | ✅ |
| Managed/IT deployment overrides | — | ✅ |
| Cross-module integrity validation | — | ✅ |

### Upgrade to Pro

NLP-powered PII detection alongside regex rules for comprehensive coverage.

> [claude-privacy-hook-pro](https://github.com/your-org/claude-privacy-hook-pro) — Pro tier

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](../docs/architecture.md) | Hook pipeline internals, layer details, project structure |
| [Configuration](docs/configuration.md) | Rule format, override system, all options |
| [Compliance](docs/compliance.md) | 27+ free tier controls, 111 in Pro — SCF, GDPR, EU AI Act, DORA, NIS2, SOC 2 |
| [Performance](docs/performance.md) | Latency and throughput benchmarks for every component |
| [Testing](docs/testing.md) | ~714 tests across 7 suites, how to run and add tests |
| [Diagrams](../docs/sequence-diagram.md) | Visual pipeline sequence and decision flow |
| [Plugins](docs/plugins.md) | Plugin system (Pro tier) |
| [Benchmarks](benchmarks/README.md) | Full benchmark methodology and results |

---

## License

[MIT License](LICENSE)

Copyright (c) 2026 Shahead. Free and open source.
