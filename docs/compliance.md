# Compliance Coverage

55 controls are mapped across the three security layers, covering 20 SCF domains.

## Filter Controls (40 filters)

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

## Architectural Controls (15 controls)

Existing features that satisfy SCF controls beyond the filter matrix above.

| # | Feature | Component | Scope | SCF Domain | SCF Control | Description | Free |
|---|---------|-----------|-------|------------|-------------|-------------|:----:|
| 41 | Unicode normalization (NFKC) | hook_utils.py | 🔐 | TVM | TVM-07 | Input validation — normalizes Unicode before pattern matching | f |
| 42 | Homoglyph detection (Cyrillic/Greek) | hook_utils.py | 🔐 | TVM | TVM-07 | Detects confusable character substitution attacks | f |
| 43 | Zero-width character stripping | hook_utils.py | 🔐 | TVM | TVM-07 | Removes invisible characters used to evade filters | f |
| 44 | Two-layer override system | override_resolver.py | ⚖️ | CHG | CHG-02 | Change control — user vs project override governance | f |
| 45 | Override expiry dates | override_resolver.py | ⚖️ | CFG | CFG-02 | Configuration enforcement — time-limited exceptions | f |
| 46 | Override validation CLI | override_cli.py | ⚖️ | CFG | CFG-04 | Configuration verification — validates override integrity | f |
| 47 | Data-driven test suite (979 cases) | tests/ | 🔐🛡️ | SLC | SLC-10 | Security testing — validates all filter behaviors | f |
| 48 | Benchmark suite | benchmarks/ | 🔐 | SEA | SEA-03 | Performance engineering — ensures filters meet latency SLAs | f |
| 49 | Graceful degradation (Pro → Free) | install_pro.sh | 🔐🛡️ | BCD | BCD-04 | Contingency operations — falls back to free tier if Pro unavailable | |
| 50 | Deny/ask/allow access model | regex_filter.py | 🔐 | IAC | IAC-20 | Access enforcement — graduated control for AI agent actions | f |
| 51 | Two-layer separation (user/project) | override_resolver.py | ⚖️ | IAC | IAC-21 | Separation of duties — distinct authority levels for overrides | f |
| 52 | JSON rule configs as policies | filter_rules*.json | ⚖️ | GOV | GOV-02 | Machine-readable security policies in declarative format | f |
| 53 | Defense-in-depth pipeline | settings.json | 🔐 | SEA | SEA-01 | Secure architecture — 3-layer hook pipeline design | f |
| 54 | License token machine binding | token.py (Pro) | 🔐 | IAC | IAC-15 | Device identification — binds license to hardware | |
| 55 | Cross-module integrity hashing | S2 (Pro) | 🔐 | SEA | SEA-15 | Tamper detection — verifies module integrity at runtime | |

---

## Cross-Framework Mappings

### NIST CSF 2.0

| NIST CSF 2.0 Function | claude-privacy-hook Mapping |
|---|---|
| **GOVERN (GV)** | GOV: "ask" human oversight, audit logging, override governance, managed layer (Pro) |
| **IDENTIFY (ID)** | AST: filter_rules*.json define protected assets; compliance.md classifies data types |
| **PROTECT (PR)** | IAC+CRY+NET+PRI+DAT+DCH+END: 30+ filters across all protection categories |
| **DETECT (DE)** | TVM+OPS+MON: regex matching, NLP detection (Pro), rate limiter anomaly detection |
| **RESPOND (RS)** | IRO: audit log, deny/ask actions, rate limiter escalation, graceful degradation |
| **RECOVER (RC)** | BCD: Pro → Free degradation, override rollback, settings.json backup |

### SOC 2 Trust Service Criteria

| TSC Category | claude-privacy-hook Mapping |
|---|---|
| **CC6 — Logical & Physical Access** | IAC filters (credentials, tokens, keys), override access control, license auth (Pro) |
| **CC7 — System Operations** | OPS filters (shell obfuscation, rate limiting), audit logging, continuous monitoring |
| **CC8 — Change Management** | Override CLI (add/remove/validate), managed overrides (Pro), settings.json versioning |
| **P1 — Privacy — Notice** | "ask" action provides notice before allowing risky operations |
| **P3 — Privacy — Collection** | PRI filters prevent unauthorized PII collection by AI agent |
| **P4 — Privacy — Use** | Output sanitizer prevents PII from being used in responses |
| **P6 — Privacy — Disposal** | Audit log rotation (planned) |
| **A1 — Availability** | Graceful degradation, rate limiting (prevents resource exhaustion) |
| **C1 — Confidentiality** | All credential and PII filters enforce confidentiality |

### ISO 27001 Annex A (selected controls)

| ISO 27001 Control | claude-privacy-hook Mapping |
|---|---|
| **A.5.1 — Information Security Policies** | filter_rules*.json = machine-readable security policies |
| **A.8.2 — Privileged Access Rights** | Deny/ask/allow model enforces least-privilege for AI agent actions |
| **A.8.3 — Information Access Restriction** | Override system restricts which rules can be relaxed, and by whom |
| **A.8.9 — Configuration Management** | Override expiry, validation CLI, two-layer config system |
| **A.8.11 — Data Masking** | Output sanitizer redacts PII and credentials from command output |
| **A.8.12 — Data Leakage Prevention** | All credential, PII, and exfiltration filters form a DLP layer |
| **A.8.16 — Monitoring Activities** | Audit logger + rate limiter provide continuous monitoring |
| **A.8.25 — Secure Development Lifecycle** | 979-case test suite, benchmarks, data-driven security testing |

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
| **CHG** | Change Management |
| **CFG** | Configuration Management |
| **SLC** | Software Development Lifecycle |
| **SEA** | Secure Engineering & Architecture |
| **BCD** | Business Continuity & Disaster Recovery |
| **AST** | Asset Management |
| **MON** | Continuous Monitoring |
| **RSK** | Risk Management |

### Regulations & Frameworks

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
| **NIST CSF 2.0** | NIST Cybersecurity Framework 2.0 — Govern, Identify, Protect, Detect, Respond, Recover |
| **SOC 2** | Service Organization Control 2 — Trust Service Criteria (CC, P, A, C) |
| **ISO 27001** | International standard for information security management (Annex A controls) |
