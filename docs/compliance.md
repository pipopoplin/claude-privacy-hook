# Compliance Coverage

All 40 filters are implemented across the three security layers.

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
| 11 | SSN / National ID | L1 regex | 🛡️ | PRI | PRI-03 | GDPR Art.9 | 🔴 Critical |  f  |
| 12 | Credit card numbers | L1 regex | 🛡️ | DAT | DAT-02 | PCI-DSS Req.3 | 🔴 Critical |  f  |
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

The **Free** column marks filters included in the free (MIT) tier. Filters without a mark require [claude-privacy-hook-pro](https://github.com/your-org/claude-privacy-hook-pro).

---

## Glossary

### Column Definitions

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

### Layers

| Layer | Description |
|-------|-------------|
| **L1 regex** | Layer 1 — fast, deterministic regex-based filtering (<1ms) |
| **L1/L2** | Hybrid filter spanning both regex and NLP layers |
| **L2 NLP** | Layer 2 — NLP-based detection using pluggable backends (3-25ms) |
| **Post-hook** | Runs after command execution to sanitize output |
| **Meta** | Infrastructure-level controls (logging, rate limiting, oversight) |
| **Config** | Configuration-level controls (hook registration, tool coverage) |

### Scope Icons

| Icon | Meaning |
|------|---------|
| 🔐 | Security — credential protection, network security, attack prevention |
| 🛡️ | Privacy — PII and sensitive data protection |
| 🔐🛡️ | Both security and privacy |
| ⚖️ | Governance — compliance, oversight, and audit controls |

### Value / Risk Ratings

| Icon | Level | Description |
|------|-------|-------------|
| 🔴 Critical | Critical | Must-have — direct credential or PII exposure risk |
| 🟠 High | High | Important — indirect exposure, evasion, or infrastructure risk |
| 🟡 Medium | Medium | Recommended — defense-in-depth and operational controls |

### SCF Domains

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

### Regulations

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
