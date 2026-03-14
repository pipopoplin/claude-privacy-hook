# claude-privacy-hook

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

Security hooks for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that protect your data before it ever leaves your machine.

---

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

---

## How It Works

Three independent security layers run on every action — total latency under 1ms in-process:

| Layer | What it does |
|-------|-------------|
| **Regex filter** | Pattern-matches 180+ known credential formats, attack signatures, and sensitive data (18 rules) |
| **Rate limiter** | Escalates when too many suspicious actions happen in a session |
| **Output sanitizer** | Redacts sensitive data from command results after execution |

All blocked events are written to an audit log for review and compliance.

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
| **Compliance-ready** | Maps to [40 security controls](docs/compliance.md) across GDPR, HIPAA, PCI-DSS, and OWASP |
| **Fully auditable** | Every blocked action logged with timestamps, patterns, and command hashes |
| **No cloud dependency** | Everything runs locally, nothing phones home |

---

## Compliance Coverage

40 security controls mapped to industry regulations — [full matrix →](docs/compliance.md)

| Regulation | What's covered | Controls |
|------------|---------------|----------|
| **GDPR** | Personal data (Art.4), special categories (Art.9), employment data (Art.88), security of processing (Art.32), accountability (Art.5), automated decisions (Art.22) | 18 |
| **PCI-DSS** | Credit card detection and redaction (Req.3) | 2 |
| **HIPAA** | Medical and health data detection | 1 |
| **PSD2** | IBAN and bank account protection | 1 |
| **OWASP** | Prompt injection (LLM01), path traversal (A05) | 3 |
| **SCF** | Identification & access, cryptography, network security, privacy, data protection, threat management, endpoint, operations, governance, incident response | 40 |

All filters are rated by risk criticality (Critical / High / Medium) and tagged by scope (Security, Privacy, Governance).

---

## Configuration

Works out of the box. To customize:

- **Allow a trusted endpoint** — add a URL pattern to `filter_rules.json`, or use the [override CLI](docs/configuration.md#override-cli)
- **Disable a rule** — set `"enabled": false` in the rule config

Teams can add exceptions with the [two-layer override system](docs/configuration.md#override-system) — no need to edit rule files.

See the full [Configuration guide](docs/configuration.md).

---

## Free vs Pro

| Feature | Free (MIT) | Pro (BSL 1.1) |
|---------|-----------|---------------|
| Regex-based PII detection (18 rules, ~180 patterns) | ✅ | ✅ |
| Write/Edit content filtering | ✅ | ✅ |
| Read path protection | ✅ | ✅ |
| Output sanitizer (7 redaction rules) | ✅ | ✅ |
| Rate limiter (violation escalation) | ✅ | ✅ |
| Audit logging | ✅ | ✅ Enhanced (SIEM) |
| User & project overrides | ✅ Free rules | ✅ All rules |
| NLP-based PII detection (spaCy, Presidio, DistilBERT) | — | ✅ |
| 7 pluggable detection backends | — | ✅ |
| Managed/IT deployment overrides | — | ✅ |
| Cross-module integrity validation | — | ✅ |
| Fleet/central config management | — | Roadmap |

### Upgrade to Pro

NLP-powered PII detection alongside regex rules for comprehensive coverage.

> [claude-privacy-hook-pro](https://github.com/your-org/claude-privacy-hook-pro) — Pro tier

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | Hook pipeline internals, layer details, project structure |
| [Configuration](docs/configuration.md) | Rule format, override system, all options |
| [Compliance](docs/compliance.md) | 40 security controls mapped to GDPR, HIPAA, PCI-DSS, OWASP |
| [Performance](docs/performance.md) | Latency and throughput benchmarks for every component |
| [Testing](docs/testing.md) | 979 tests across 5 suites, how to run and add tests |
| [Diagrams](docs/sequence-diagram.md) | Visual pipeline sequence and decision flow |
| [Plugins](docs/plugins.md) | Plugin system (Pro tier) |
| [Benchmarks](benchmarks/README.md) | Full benchmark methodology and results |

---

## License

[MIT License](LICENSE)

Copyright (c) 2026 Shahead. Free and open source.
