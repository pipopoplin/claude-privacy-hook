# Compliance Coverage — Free Tier (MIT)

This document covers the **free tier** of claude-privacy-hook. 13 filter rules and 10 architectural controls are included. Full 111-control coverage including NLP-based PII detection, compliance reporting, SCF metadata, breach notification, and GDPR/SOC2/DORA/NIS2 evidence collection is available in [Pro tier](https://claude-privacy-hook.dev/pro).

## Business Context & Privacy Objectives

**What this tool does:** claude-privacy-hook is a technical control layer that intercepts every action an AI coding assistant (Claude Code) takes — commands, file reads, file writes — and blocks or redacts anything that could expose personal or sensitive data.

**Why personal data is processed:** AI coding assistants operate on developer workstations where source code, configuration files, and command output routinely contain personal data (API keys, credentials, PII, financial data, employee identifiers). Without intervention, the AI agent may inadvertently transmit this data to untrusted endpoints, write it to files, or expose it in command output.

**Privacy objective:** Prevent personal data from leaving the developer's machine through AI agent actions. All detection and enforcement runs locally — nothing is transmitted externally. The audit log stores only SHA-256 command hashes and pattern labels, never raw personal data.

**Role:** This tool is a **technical control** (data processor safeguard), not a data controller. It does not collect, store, or transmit personal data. It detects and blocks the AI agent from doing so.

**Data subjects:** Developers using Claude Code, and any individuals whose personal data appears in the developer's working environment (employees, customers, end users).

## Personal Data Categories

The following taxonomy maps personal data categories detected by this tool to their sensitivity level, applicable GDPR article, protecting filters, and handling action.

| Category | Examples | Sensitivity | GDPR | Filters | Action |
|----------|----------|-------------|------|---------|--------|
| **Identity credentials** | API keys, tokens, passwords, private keys | Restricted | Art.32 | #1-6 | Block |
| **Government identifiers** | SSN, passport, driver licence, national ID | Restricted | Art.9 | Pro: #11, #20 | Pro only |
| **Financial data** | Credit cards, IBAN, bank accounts, routing numbers | Restricted | Art.4 / PCI-DSS | Pro: #12, #19 | Pro only |
| **Contact information** | Names, emails, phone numbers, IP addresses | Confidential | Art.4 | Free: #35 (email/IP redaction); Pro: #9, #10, #13, #14 | Redact (Free) / Block (Pro) |
| **Employment data** | Employee IDs, HR numbers, payroll references | Confidential | Art.88 | Pro: #17 | Pro only |
| **Special categories** | Medical/health, biometric, ethnic, religious, political | Confidential | Art.9 | Pro: #18, #29, #30 | Pro only (L2 NLP) |
| **Business identifiers** | Customer IDs, invoices, orders, contracts, tenant IDs | Confidential | Art.4 | Pro: #28 | Pro only |
| **Infrastructure secrets** | DB connection strings, internal IPs, cloud metadata | Restricted | Art.32 | Pro: #26, #27 | Pro only |
| **Cryptographic material** | Private keys, PEM certificates, key files | Restricted | Art.32 | #4 (Bash detection), #35 (output redaction) | Block / Redact |
| **Organizational entities** | Company names, locations, political groups | Internal | Art.4 | Pro: #15 | Pro only (L2 NLP) |

**Handling actions:** Block = command denied. Ask = human approval required. Redact = sensitive data replaced in output. L2 NLP = requires Pro tier NLP detection. "Pro only" = detection available in [Pro tier](https://claude-privacy-hook.dev/pro).

## Data Subject Empowerment

Developers are the primary data subjects in this system — their commands contain their credentials, PII, and sensitive data. The following features give developers direct control:

| Feature | Empowerment |
|---|---|
| **"ask" action** (2 rules) | Developer explicitly approves or denies each flagged action |
| **Override CLI `add`** | Pro only — developer creates permanent exceptions for their workflow |
| **Override expiry** | Pro only — time-limited consent with automatic revocation |
| **Override CLI `list`** | Developer reviews all active exceptions (transparency) |
| **Override CLI `remove`** | Pro only — developer revokes any exception at any time |
| **`HOOK_AUDIT_LOG_MINIMIZE=1`** | Pro only — developer minimizes their own PD stored in audit logs |

## Detection Quality Assurance

PII detection accuracy is validated through a structured quality program:

| Quality measure | Method | Coverage |
|---|---|---|
| **True positive rate** | ~835 data-driven test cases verify known PII patterns are detected | All 13 rules |
| **False positive rate** | Test cases include non-PII inputs that must NOT trigger (safe commands, trusted endpoints) | Regex + sanitizer cases |
| **Pattern coverage** | ~80 regex patterns across 6 Bash rules, 3 Write rules, 1 Read rule, 3 output rules | Core PD categories |
| **Confidence scoring** | Pro only — NLP plugins return 0.0-1.0 confidence per detection; configurable `min_confidence` threshold (default 0.7) | Pro: 7 NLP plugins |
| **Performance quality** | Benchmark suite validates <1ms in-process latency SLAs | All hooks |
| **Regression testing** | All tests run on every code change; `run_all.py` executes all 7 suites | ~835 cases, 0 failures |

Quality metrics for NLP confidence distribution, entity type accuracy, and plugin breakdown are available in Pro via `evidence_collector_pro.py --nlp-only`.

## Review Cadence

Controls, rules, and compliance documentation are reviewed on the following schedule:

| Review type | Frequency | Trigger | What's reviewed | Tool |
|---|---|---|---|---|
| **Scheduled review** | Quarterly | Calendar | All filter rules, override activity, compliance coverage, DPMP gaps | Manual review of compliance.md |
| **Evidence review** | Monthly | Pro: `evidence_collector.py` run | SCF control coverage, event trends, domain summary, hot rules | Pro: `evidence_collector.py --cross-session` |
| **Incident-triggered** | Ad hoc | Pro: `breach_report.py` finding or rate limiter block escalation | Affected rules, root cause, coverage gaps, remediation | Pro: `breach_report.py --format markdown` |
| **License review** | Every session | CLAUDE.md startup check | SCF CC BY-ND 4.0 terms unchanged; MIT/BSL 1.1 compatibility | Automated (CLAUDE.md mandate) |
| **Override review** | On expiry | Override expiry date reached | Expired overrides removed or renewed with justification and risk score | Pro: `override_cli.py validate --scope all` |
| **Dependency review** | On release | Pro: `generate_sbom.py` run | License compatibility (no GPL), known vulnerabilities, transitive deps | Pro: `generate_sbom.py` -> CycloneDX SBOM |

**Out-of-cycle review triggers:** Any of the following warrant immediate review outside the scheduled cadence:
- Breach candidate detected by `breach_report.py` (deny count exceeds threshold) (Pro)
- SCF license terms change detected at startup (CLAUDE.md mandate)
- New regulation or framework version published (e.g., GDPR amendment, new EU AI Act guidance)
- Override risk score >= 8 (critical) — logged with warning at creation time (Pro)

## Filter Controls (40 filters)

Relationship types follow NIST IR 8477 Set Theory Relationship Mapping (STRM). Strength is rated 1-10 based on how directly our implementation addresses the SCF control objective.

| # | Filter | Layer | Scope | SCF Domain | SCF Control | STRM | Str | Regulation | Value | Free Tier | Pro Tier |
|---|--------|-------|-------|------------|-------------|------|:---:|------------|-------|:----------:|:--------:|
| 1 | Anthropic / OpenAI API keys | L1 regex | 🔐 | IAC | IAC-01 | Subset Of | 9 | — | 🔴 Critical | x | x |
| 2 | AWS / GCP / Azure credentials | L1 regex | 🔐 | IAC | IAC-01 | Subset Of | 9 | — | 🔴 Critical | x | x |
| 3 | GitHub / GitLab tokens | L1 regex | 🔐 | IAC | IAC-01 | Subset Of | 9 | — | 🔴 Critical | x | x |
| 4 | Private keys / PEM certs | L1 regex | 🔐 | CRY | CRY-03 | Intersects With | 7 | — | 🔴 Critical | x | x |
| 5 | Slack / webhook tokens | L1 regex | 🔐 | IAC | IAC-01 | Subset Of | 9 | — | 🔴 Critical | x | x |
| 6 | Hardcoded passwords | L1 regex | 🔐 | IAC | IAC-01 | Subset Of | 9 | — | 🔴 Critical | x | x |
| 7 | Untrusted network calls | L1 regex | 🔐 | NET | NET-01 | Subset Of | 8 | — | 🔴 Critical | x | x |
| 8 | Trusted endpoint allowlist | L1 regex | 🔐 | NET | NET-01 | Subset Of | 8 | — | 🔴 Critical | x | x |
| 9 | Person names (NER) | L2 NLP | 🛡️ | PRI | PRI-01 | Subset Of | 8 | GDPR Art.4 | 🔴 Critical | | x |
| 10 | Email addresses | L2 NLP | 🛡️ | PRI | PRI-01 | Subset Of | 8 | GDPR Art.4 | 🔴 Critical | | x |
| 11 | SSN / National ID | L1 regex | 🛡️ | PRI | PRI-01 | Subset Of | 9 | GDPR Art.9 | 🔴 Critical | | x |
| 12 | Credit card numbers | L1 regex | 🛡️ | DCH | DCH-02 | Intersects With | 7 | PCI-DSS Req.3 | 🔴 Critical | | x |
| 13 | Phone numbers | L2 NLP | 🛡️ | PRI | PRI-01 | Subset Of | 8 | GDPR Art.4 | 🔴 Critical | | x |
| 14 | IP addresses | L2 NLP | 🛡️ | PRI | PRI-01 | Subset Of | 8 | GDPR Art.4 | 🔴 Critical | | x |
| 15 | ORG / GPE / NORP entities | L2 NLP | 🛡️ | PRI | PRI-02 | Intersects With | 6 | GDPR Art.4 | 🟠 High | | x |
| 16 | Expanded vendor credentials | L1 regex | 🔐 | IAC | IAC-01 | Subset Of | 9 | — | 🔴 Critical | | x |
| 17 | Employee ID / HR numbers | L1 regex | 🛡️ | HRS | HRS-01 | Intersects With | 6 | GDPR Art.88 | 🔴 Critical | | x |
| 18 | Medical / health data | L2 NLP | 🛡️ | PRI | PRI-03 | Intersects With | 7 | GDPR Art.9 / HIPAA | 🔴 Critical | | x |
| 19 | IBAN / bank account numbers | L1 regex | 🛡️ | DCH | DCH-02 | Intersects With | 7 | PSD2 / GDPR Art.4 | 🔴 Critical | | x |
| 20 | Passport / driver licence | L1 regex | 🛡️ | PRI | PRI-03 | Intersects With | 7 | GDPR Art.9 | 🔴 Critical | | x |
| 21 | Base64-encoded payloads | L1 regex | 🔐 | THR | THR-07 | Intersects With | 7 | — | 🔴 Critical | | x |
| 22 | Prompt injection phrases | L1/L2 | 🔐 | THR | THR-10 | Intersects With | 7 | OWASP LLM01 | 🔴 Critical | x | x |
| 23 | Sensitive file access | L1 regex | 🔐🛡️ | IAC | IAC-20 | Intersects With | 7 | GDPR Art.32 | 🔴 Critical | x | x |
| 24 | DNS exfiltration | L1 regex | 🔐 | NET | NET-01 | Subset Of | 7 | — | 🟠 High | | x |
| 25 | Path traversal | L1 regex | 🔐 | THR | THR-10 | Intersects With | 6 | OWASP A05 | 🟠 High | | x |
| 26 | Database connection strings | L1 regex | 🔐🛡️ | DCH | DCH-05 | Intersects With | 7 | GDPR Art.32 | 🔴 Critical | | x |
| 27 | Internal hostnames / IPs | L1 regex | 🛡️ | NET | NET-01 | Subset Of | 7 | GDPR Art.32 | 🟠 High | | x |
| 28 | Customer / contract IDs | L1 regex | 🛡️ | PRI | PRI-02 | Intersects With | 6 | GDPR Art.4 | 🟠 High | | x |
| 29 | Biometric data references | L2 NLP | 🛡️ | PRI | PRI-03 | Intersects With | 7 | GDPR Art.9 | 🟠 High | | x |
| 30 | Ethnic / religious / political | L2 NLP | 🛡️ | PRI | PRI-03 | Intersects With | 7 | GDPR Art.9 | 🟠 High | | x |
| 31 | Unicode / homoglyph bypass | L1 | 🔐 | THR | THR-07 | Intersects With | 8 | — | 🟠 High | x | x |
| 32 | High-entropy secret detection | L2 NLP | 🔐 | IAC | IAC-01 | Intersects With | 6 | — | 🟠 High | | x |
| 33 | Shell obfuscation / eval | L1 regex | 🔐 | OPS | OPS-05 | Intersects With | 7 | — | 🟠 High | x | x |
| 34 | Pipe-chain exfiltration | L1 regex | 🔐 | NET | NET-01 | Subset Of | 7 | — | 🟠 High | | x |
| 35 | Output sanitization | Post-hook | 🛡️ | DCH | DCH-05 | Intersects With | 7 | GDPR Art.32 | 🟡 Medium | x | x |
| 36 | ask / human oversight | Meta | ⚖️ | GOV | GOV-04 | Intersects With | 6 | GDPR Art.22 | 🟡 Medium | x | x |
| 37 | Audit log of blocked events | Meta | ⚖️ | IRO | IRO-01 | Subset Of | 8 | GDPR Art.5(2) | 🟠 High | x | x |
| 38 | Rate limiting / anomaly | Meta | 🔐 | MON | MON-16 | Intersects With | 6 | — | 🟡 Medium | x | x |
| 39 | Non-Bash tool coverage | Config | 🔐🛡️ | OPS | OPS-05 | Intersects With | 7 | GDPR Art.32 | 🟡 Medium | x | x |
| 40 | Semantic intent scoring | L2 NLP | 🔐🛡️ | THR | THR-10 | Intersects With | 6 | OWASP LLM01 | 🟡 Medium | | x |

The **Free Tier** column marks filters included in the basic (MIT) tier. The **Pro Tier** column marks filters included in [claude-privacy-hook-pro](https://claude-privacy-hook.dev/pro). All 40 filters are available in Pro; Free tier includes 17 core filters.

## Architectural Controls (16 controls)

Existing features that satisfy SCF controls beyond the filter matrix above.

| # | Feature | Component | Scope | SCF Domain | SCF Control | STRM | Str | Description | Free Tier | Pro Tier |
|---|---------|-----------|-------|------------|-------------|------|:---:|-------------|:----------:|:--------:|
| 41 | Unicode normalization (NFKC) | hook_utils.py | 🔐 | THR | THR-07 | Intersects With | 8 | Input validation — normalizes Unicode before pattern matching | x | x |
| 42 | Homoglyph detection (Cyrillic/Greek) | hook_utils.py | 🔐 | THR | THR-07 | Intersects With | 8 | Detects confusable character substitution attacks | x | x |
| 43 | Zero-width character stripping | hook_utils.py | 🔐 | THR | THR-07 | Intersects With | 8 | Removes invisible characters used to evade filters | x | x |
| 44 | Two-layer override system | override_resolver.py | ⚖️ | CHG | CHG-02 | Intersects With | 6 | Change control — user vs project override governance | | x |
| 45 | Override expiry dates | override_resolver.py | ⚖️ | CFG | CFG-02 | Intersects With | 6 | Configuration enforcement — time-limited exceptions | | x |
| 46 | Override validation CLI | override_cli.py | ⚖️ | CFG | CFG-04 | Intersects With | 7 | Configuration verification — validates override integrity | | x |
| 47 | Data-driven test suite (~835 cases) | tests/ | 🔐🛡️ | TDA | TDA-10 | Intersects With | 7 | Security testing — validates all filter behaviors | x | x |
| 48 | Benchmark suite | benchmarks/ | 🔐 | SEA | SEA-03 | Intersects With | 5 | Performance engineering — ensures filters meet latency SLAs | x | x |
| 49 | Graceful degradation (Pro -> Basic) | install_pro.sh | 🔐🛡️ | BCD | BCD-04 | Intersects With | 6 | Contingency operations — falls back to Free Tier if Pro unavailable | | x |
| 50 | Deny/ask/allow access model | regex_filter.py | 🔐 | IAC | IAC-20 | Intersects With | 7 | Access enforcement — graduated control for AI agent actions | x | x |
| 51 | Two-layer separation (user/project) | override_resolver.py | ⚖️ | IAC | IAC-21 | Intersects With | 6 | Separation of duties — distinct authority levels for overrides | | x |
| 52 | JSON rule configs as policies | filter_rules*.json | ⚖️ | GOV | GOV-02 | Intersects With | 6 | Machine-readable security policies in declarative format | x | x |
| 53 | Defense-in-depth pipeline | settings.json | 🔐 | SEA | SEA-01 | Subset Of | 8 | Secure architecture — 3-layer hook pipeline design | x | x |
| 54 | License token machine binding | token.py (Pro) | 🔐 | IAC | IAC-15 | Intersects With | 5 | Device identification — binds license to hardware | | x |
| 55 | Cross-module integrity hashing | S2 (Pro) | 🔐 | SEA | SEA-15 | Intersects With | 7 | Tamper detection — verifies module integrity at runtime | | x |
| 111 | Software assurance program | integrity/, generate_sbom.py, tests/ | 🔐 | SAI | SAI-03 | Intersects With | 6 | Software assurance — integrity validation, SBOM generation, comprehensive test suite. Future: compiled binary distribution strengthens to Subset Of | | x |

## EU AI Act Controls — AAT Domain (12 controls)

Mappings to the SCF Artificial Intelligence & Autonomous Technology (AAT) domain, verified against the STRM EU AI Act crosswalk (scf-strm-emea-eu-ai-act). Our tool functions as an AI governance layer for Claude Code, making these controls directly applicable.

| # | Feature | Component | Scope | SCF Domain | SCF Control | STRM | Str | EU AI Act | Description | Free Tier | Pro Tier |
|---|---------|-----------|-------|------------|-------------|------|:---:|-----------|-------------|:----------:|:--------:|
| 56 | Regex input validation | regex_filter.py | 🔐🛡️ | AAT | AAT-10 | Subset Of | 8 | Art.9 | AI TEVV — validates all AI agent input before execution | x | x |
| 57 | Output sanitizer redaction | output_sanitizer.py | 🛡️ | AAT | AAT-23 | Intersects With | 6 | Art.52 | AI output marking — redacts sensitive data from AI agent output | x | x |
| 58 | ask / human approval model | regex_filter.py | ⚖️ | AAT | AAT-22.1 | Equal | 10 | Art.14 | AI human oversight — human approval before risky AI actions | x | x |
| 59 | Audit log of AI actions | audit_logger.py | ⚖️ | AAT | AAT-16.8 | Intersects With | 7 | Art.12 | AI event logging — JSONL log of all blocked/redacted AI actions | x | x |
| 60 | Rate limiter anomaly detection | rate_limiter.py | 🔐 | AAT | AAT-16 | Intersects With | 7 | Art.9 | AI production monitoring — detects anomalous violation patterns | x | x |
| 61 | Prompt injection detection | filter_rules.json | 🔐 | AAT | AAT-17 | Intersects With | 8 | Art.5 | AI harm prevention — blocks jailbreak/injection attacks | x | x |
| 62 | Defense-in-depth pipeline | settings.json | 🔐 | AAT | AAT-02.3 | Intersects With | 7 | Art.9 | Adequate AI protections — 3-layer security pipeline | x | x |
| 63 | ~835-case test suite | tests/ | 🔐🛡️ | AAT | AAT-10.5 | Intersects With | 7 | Art.9 | AI TEVV security assessment — comprehensive control testing | x | x |
| 64 | Graceful degradation Pro->Basic | llm_client.py | 🔐 | AAT | AAT-15.2 | Intersects With | 6 | Art.7 | AI deactivation — safe degradation when Pro unavailable | | x |
| 65 | Incident reporting via audit log | audit_logger.py | ⚖️ | AAT | AAT-16.9 | Intersects With | 6 | Art.73 | AI serious incident reporting — structured incident data | x | x |
| 66 | Filter rules as AI risk controls | filter_rules*.json | ⚖️ | AAT | AAT-09 | Intersects With | 6 | Art.9 | AI risk profiling — declarative JSON configs define AI risk boundaries | x | x |
| 67 | Override governance for AI actions | override_resolver.py | ⚖️ | AAT | AAT-22.2 | Equal | 10 | Art.14 | AI oversight measures — project-level override system for AI exceptions | x | x |

## GDPR Controls — STRM-Verified (7 controls)

Additional GDPR mappings verified against the STRM EU GDPR crosswalk (scf-strm-emea-eu-gdpr). These cover GDPR articles not addressed by the filter table above.

| # | Feature | Component | Scope | SCF Domain | SCF Control | STRM | Str | Regulation | Description | Free Tier | Pro Tier |
|---|---------|-----------|-------|------------|-------------|------|:---:|------------|-------------|:----------:|:--------:|
| 68 | PII filter pipeline security | regex_filter.py | 🛡️ | PRI | PRI-01.6 | Intersects With | 8 | GDPR Art.25/32 | Security of personal data — PII filters enforce data protection by design and by default | x | x |
| 69 | Breach evidence capture | audit_logger.py, breach_report.py | ⚖️ | IRO | IRO-04.1 | Subset Of | 8 | GDPR Art.33 | Data breach support — audit log captures structured breach evidence | | x |
| 70 | Compliance demonstration | audit_logger.py, compliance.md | ⚖️ | CPL | CPL-01.3 | Intersects With | 7 | GDPR Art.5(2) | Accountability — audit log demonstrates data protection control effectiveness | x | x |
| 71 | PII usage restriction enforcement | filter_rules.json | 🛡️ | PRI | PRI-05.4 | Subset Of | 8 | GDPR Art.6 | Usage restrictions — filters block PII transmission to untrusted endpoints | x | x |
| 72 | Cross-border data transfer blocking | filter_rules.json | 🛡️ | DCH | DCH-25 | Intersects With | 6 | GDPR Art.44 | Transfer controls — network filters block sensitive data to untrusted endpoints | x | x |
| 73 | Cryptographic material protection | filter_rules.json | 🔐 | CRY | CRY-01 | Subset Of | 9 | GDPR Art.32 | Cryptographic controls — blocks private keys, certificates, and crypto exposure | x | x |
| 74 | AI data processing documentation | audit_logger.py | ⚖️ | PRI | PRI-14 | Intersects With | 7 | GDPR Art.30 | Processing records — documents AI agent data processing with hashes and timestamps | x | x |

## ISO 42001 Controls — AI Management System (8 controls)

Additional mappings to ISO 42001:2023 (AI Management Systems), verified against the STRM ISO 42001 crosswalk (scf-strm-general-iso-42001-2023). These controls cover AI governance, risk management, data quality, and assurance requirements.

| # | Feature | Component | Scope | SCF Domain | SCF Control | STRM | Str | ISO 42001 | Description | Free Tier | Pro Tier |
|---|---------|-----------|-------|------------|-------------|------|:---:|-----------|-------------|:----------:|:--------:|
| 75 | AI governance program alignment | compliance.md, filter_rules*.json | ⚖️ | AAT | AAT-01 | Intersects With | 7 | §4.1/4.4 | AI management system — hook system provides the technical control layer of an AIMS | x | x |
| 76 | AI risk management decisions | override_resolver.py, override_cli.py | ⚖️ | AAT | AAT-07 | Intersects With | 6 | §6.1 | AI risk decisions — override system allows risk-based exception decisions with expiry | x | x |
| 77 | AI incident & error reporting | audit_logger.py | ⚖️ | AAT | AAT-11.4 | Intersects With | 7 | §A.8.3 | AI incident reporting — audit log captures errors and blocked actions for review | x | x |
| 78 | AI data source integrity | hook_utils.py | 🔐 | AAT | AAT-12.2 | Intersects With | 5 | §A.6.1.3 | Data source integrity — Unicode normalization ensures input integrity before processing | x | x |
| 79 | AI post-deployment monitoring | rate_limiter.py, audit_logger.py | 🔐 | AAT | AAT-10.13 | Intersects With | 6 | §A.9.4 | Post-deployment monitoring — rate limiter and audit log track AI behavior in production | x | x |
| 80 | Change management for AI controls | override_cli.py | ⚖️ | CHG | CHG-01 | Subset Of | 8 | §6.3 | Change management program — override CLI provides structured change process | x | x |
| 81 | Data quality for AI input | hook_utils.py, regex_filter.py | 🔐 | DCH | DCH-22 | Intersects With | 6 | §A.7 | Data quality — input normalization and validation ensures quality for AI processing | x | x |
| 82 | Information assurance operations | tests/, benchmarks/ | 🔐 | IAO | IAO-01 | Subset Of | 9 | §A.6.2.5 | Information assurance — ~835 tests + benchmarks verify AI control effectiveness | x | x |

## DORA & NIS2 Controls — EU Resilience (6 controls)

Additional mappings for EU Digital Operational Resilience Act (DORA, Regulation 2022/2554) and NIS2 Directive (2022/2555), verified against STRM crosswalks. Relevant for EU financial sector and critical infrastructure deployments.

| # | Feature | Component | Scope | SCF Domain | SCF Control | STRM | Str | Regulation | Description | Free Tier | Pro Tier |
|---|---------|-----------|-------|------------|-------------|------|:---:|------------|-------------|:----------:|:--------:|
| 83 | ICT incident classification | rate_limiter.py, audit_logger.py | ⚖️ | IRO | IRO-02 | Intersects With | 6 | DORA Art.17 / NIS2 Art.23 | Incident handling — rate limiter classifies violations by severity | x | x |
| 84 | Continuous monitoring program | rate_limiter.py, audit_logger.py | 🔐 | MON | MON-01 | Intersects With | 7 | DORA Art.10 | Continuous monitoring — real-time audit logging and rolling-window violation tracking | x | x |
| 85 | ICT operations security | regex_filter.py, output_sanitizer.py | 🔐 | OPS | OPS-01 | Intersects With | 7 | DORA Art.9 | Operations security — hook pipeline enforces controls on all AI agent operations | x | x |
| 86 | Vulnerability detection | regex_filter.py | 🔐 | VPM | VPM-01 | Intersects With | 6 | DORA Art.9 / NIS2 Art.21 | Vulnerability management — detects credential exposure, injection attempts | x | x |
| 87 | Incident root cause analysis support | audit_logger.py | ⚖️ | IRO | IRO-13 | Intersects With | 6 | NIS2 Art.23 | Root cause analysis — structured audit logs enable post-incident forensics | x | x |
| 88 | Supply chain risk controls | filter_rules.json | 🔐 | TPM | TPM-03 | Intersects With | 5 | NIS2 Art.21(2d) | Supply chain security — network filters block untrusted endpoints | x | x |

## SOC 2 Controls — STRM-Verified (4 controls)

Additional SOC 2 Trust Service Criteria mappings verified against the STRM AICPA TSC crosswalk (scf-strm-general-aicpa-tsc-2017). Covers Common Criteria and Privacy criteria not addressed by the control tables above.

| # | Feature | Component | Scope | SCF Domain | SCF Control | STRM | Str | Regulation | Description | Free Tier | Pro Tier |
|---|---------|-----------|-------|------------|-------------|------|:---:|------------|-------------|:----------:|:--------:|
| 89 | Security controls oversight | tests/, compliance.md | ⚖️ | CPL | CPL-02 | Intersects With | 7 | SOC 2 CC4 | Controls oversight — test suite + compliance doc provide independent control verification | x | x |
| 90 | Security performance metrics | benchmarks/, audit_logger.py | ⚖️ | GOV | GOV-05 | Intersects With | 6 | SOC 2 CC4/CC5 | Measures of performance — benchmarks track latency SLAs; audit log tracks violation rates | x | x |
| 91 | PII collection restriction | filter_rules.json, filter_rules_write.json | 🛡️ | PRI | PRI-04 | Intersects With | 7 | SOC 2 P3 | Restrict collection — blocks AI agent from collecting PII beyond identified purpose | x | x |
| 92 | Governance program documentation | CLAUDE.md, compliance.md | ⚖️ | GOV | GOV-01 | Intersects With | 6 | SOC 2 CC1 | Governance program — CLAUDE.md + compliance.md document security governance | x | x |

## DPMP Controls — Data Privacy Principles (5 controls)

Additional mappings to the SCF Data Privacy Management Principles (86 principles across 11 domains), verified against the STRM DPMP crosswalk (scf-strm-data-privacy-management-principles). Fills gaps in Transparency, Data Lifecycle, and Risk Management principles.

| # | Feature | Component | Scope | SCF Domain | SCF Control | STRM | Str | Regulation | Description | Free Tier | Pro Tier |
|---|---------|-----------|-------|------------|-------------|------|:---:|------------|-------------|:----------:|:--------:|
| 93 | Privacy purpose specification | compliance.md, filter_rules.json | 🛡️ | PRI | PRI-02.1 | Intersects With | 5 | DPMP P4 | Purpose specification — documents what data each filter protects and why | x | x |
| 94 | Data protection enforcement | regex_filter.py, output_sanitizer.py | 🛡️ | DCH | DCH-01 | Intersects With | 7 | DPMP P5 | Data protection — enforces protection across input, processing, and output lifecycle | x | x |
| 95 | De-identification via redaction | output_sanitizer.py | 🛡️ | DCH | DCH-23 | Intersects With | 7 | DPMP P5.10 | De-identification — replaces PII with [REDACTED] tokens in command output | x | x |
| 96 | Privacy risk assessment | override_resolver.py, filter_rules.json | ⚖️ | RSK | RSK-04 | Intersects With | 6 | DPMP P9 | Risk assessment — filter rules define risk boundaries; overrides allow exceptions | x | x |
| 97 | Data protection impact assessment | compliance.md | ⚖️ | RSK | RSK-10 | Intersects With | 5 | DPMP P9.5 | DPIA — compliance.md documents controls and their regulatory impact | x | x |

## Evidence & Reporting Controls (3 controls)

New capabilities from Phase 3 — evidence collection and compliance reporting. These are available in Pro tier only.

| # | Feature | Component | Scope | SCF Domain | SCF Control | STRM | Str | Regulation | Description | Free Tier | Pro Tier |
|---|---------|-----------|-------|------------|-------------|------|:---:|------------|-------------|:----------:|:--------:|
| 98 | SCF evidence collector | evidence_collector.py | ⚖️ | CPL | CPL-01.3 | Intersects With | 8 | GDPR Art.5(2) / SOC 2 CC4 | Compliance evidence — groups audit events by SCF control with domain/regulation detail | | x |
| 99 | SCF-tagged audit log entries | audit_logger.py | ⚖️ | MON | MON-03 | Intersects With | 7 | DORA Art.12 / NIS2 Art.23 | Event log content — audit entries include scf_domain, scf_controls, scf_regulations | | x |
| 100 | Compliance summary report | evidence_collector.py | ⚖️ | GOV | GOV-05 | Intersects With | 6 | SOC 2 CC4/CC5 | Measures of performance — generates domain-level and control-level compliance metrics | | x |

## Additional SCF Controls — Deep Audit (10 controls)

Additional controls identified through line-by-line review of all filter capabilities against the full SCF taxonomy (1,433 controls across 77 STRM files). Each maps a tool capability to an SCF control not previously covered.

| # | Feature | Component | Scope | SCF Domain | SCF Control | STRM | Str | Regulation | Description | Free Tier | Pro Tier |
|---|---------|-----------|-------|------------|-------------|------|:---:|------------|-------------|:----------:|:--------:|
| 101 | Output data masking | output_sanitizer.py | 🛡️ | DCH | DCH-17 | Intersects With | 7 | GDPR Art.32 | Data masking — replaces sensitive data with [REDACTED] tokens in output | x | x |
| 102 | Cryptographic key exposure prevention | filter_rules.json, filter_rules_write.json | 🔐 | CRY | CRY-09 | Intersects With | 6 | GDPR Art.32 | Key management — blocks private key, PEM cert, and crypto material exposure | x | x |
| 103 | Data flow access control list | filter_rules.json | 🔐 | NET | NET-04 | Intersects With | 7 | — | Data flow ACL — trusted endpoint allowlist + untrusted network block | x | x |
| 104 | Behavioral indicators of compromise | rate_limiter.py | 🔐 | IRO | IRO-03 | Intersects With | 6 | — | IOC detection — rate limiter identifies patterns of repeated violations | x | x |
| 105 | Pattern-based threat intelligence | filter_rules.json | 🔐 | THR | THR-01 | Intersects With | 6 | — | Threat intelligence — ~80 regex patterns form curated threat signatures (180+ in Pro) | x | x |
| 106 | Network intrusion prevention | filter_rules.json | 🔐 | NET | NET-08 | Intersects With | 6 | DORA Art.9 | Network IPS — exfiltration and pipe-chain filters block network attacks | | x |
| 107 | Audit event log retention | audit_logger.py | ⚖️ | MON | MON-10 | Intersects With | 5 | DORA Art.12 | Log retention — append-only JSONL persistence of all security events (no rotation in free tier) | x | x |
| 108 | Insider threat evasion detection | filter_rules.json | 🔐 | THR | THR-04 | Intersects With | 5 | — | Insider threats — detects shell obfuscation, eval tricks, filter evasion | x | x |
| 109 | Command vulnerability scanning | regex_filter.py | 🔐 | VPM | VPM-06 | Intersects With | 6 | NIS2 Art.21 | Vulnerability scanning — scans AI agent commands for attack patterns | x | x |
| 110 | Secure coding enforcement | filter_rules_write.json | 🔐 | TDA | TDA-08 | Intersects With | 5 | — | Secure coding — blocks credentials and secrets in source file writes | x | x |

---

## Cross-Framework Mappings

> **Note:** Cross-framework mappings below reflect full (Pro) coverage. Free tier covers a subset — see the filter and architectural control tables above for free tier scope.

### NIST CSF 2.0

| NIST CSF 2.0 Function | claude-privacy-hook Mapping |
|---|---|
| **GOVERN (GV)** | GOV: "ask" human oversight, audit logging, override governance (Pro: managed layer) |
| **IDENTIFY (ID)** | AST: filter_rules*.json define protected assets; compliance.md classifies data types |
| **PROTECT (PR)** | IAC+CRY+NET: Free tier covers 17 filters across credential, network, and file protection categories. Pro adds PRI+DCH with 30+ filters |
| **DETECT (DE)** | THR+OPS+MON: regex matching, rate limiter anomaly detection. Pro adds NLP detection (THR+VPM) |
| **RESPOND (RS)** | IRO: audit log, deny/ask actions, rate limiter escalation. Pro adds breach reporting and graceful degradation |
| **RECOVER (RC)** | Pro: BCD — Pro -> Basic degradation, override rollback, settings.json backup |

### EU AI Act (Regulation 2024/1689)

| EU AI Act Article | claude-privacy-hook Mapping |
|---|---|
| **Art.5 — Prohibited Practices** | AAT-17: Prompt injection detection blocks manipulative/deceptive AI use |
| **Art.9 — Risk Management** | AAT-10, AAT-02.3, AAT-09, AAT-10.5, AAT-16: Input validation, defense-in-depth, risk profiling, security testing, production monitoring |
| **Art.12 — Record-Keeping** | AAT-16.8: Audit logger produces structured JSONL records of all AI agent actions |
| **Art.14 — Human Oversight** | AAT-22.1, AAT-22.2: "ask" model requires human approval; override governance provides oversight measures |
| **Art.52 — Transparency** | AAT-23: Output sanitizer marks/redacts AI-generated content containing sensitive data |
| **Art.73 — Incident Reporting** | AAT-16.9: Audit log provides structured data for serious incident reporting |

### ISO 42001:2023 (AI Management Systems)

| ISO 42001 Clause | claude-privacy-hook Mapping |
|---|---|
| **§4.1/4.4 — Context & AIMS** | AAT-01: Hook system provides the technical control layer of an AI Management System |
| **§6.1 — Risk assessment** | AAT-07, AAT-09: Override system enables risk-based decisions; filter rules define risk profiles |
| **§6.3 — Change management** | CHG-01, CHG-02: Override CLI provides structured change control for AI security rules |
| **§7 — Data management** | DCH-22, AAT-12.2: Input normalization ensures data quality and integrity |
| **§8.1 — Operational planning** | AAT-02.3: Defense-in-depth pipeline implements operational AI controls |
| **§9.1/9.2 — Monitoring & audit** | AAT-10, AAT-10.13, IAO-01: Tests, benchmarks, and production monitoring verify controls |
| **§A.6.2.5 — Verification** | IAO-01: ~835-case test suite + benchmarks provide information assurance |
| **§A.8.3 — Incident reporting** | AAT-11.4, AAT-16.8, AAT-16.9: Audit log captures AI incidents and errors |
| **§A.9.4 — Post-deployment** | AAT-10.13, AAT-16: Rate limiter and audit log monitor AI behavior in production |

### GDPR (Regulation 2016/679)

| GDPR Article | claude-privacy-hook Mapping |
|---|---|
| **Art.4 — Definitions (personal data)** | PRI-01, PRI-02: Free tier detects credentials and redacts emails/IPs in output. Pro adds full PII detection for all Art.4 categories |
| **Art.5(2) — Accountability** | CPL-01.3, IRO-01: Audit log demonstrates control effectiveness; compliance.md documents controls |
| **Art.6 — Lawful processing** | PRI-05.4: Filters block unauthorized PII processing by AI agent |
| **Art.9 — Special categories** | Pro: PRI-01, PRI-03 — detects health, biometric, ethnic, religious, political data via NLP |
| **Art.22 — Automated decisions** | GOV-04, AAT-22.1: "ask" model ensures human oversight of AI decisions |
| **Art.25 — Data protection by design** | PRI-01.6: Filter pipeline enforces privacy by design |
| **Art.30 — Records of processing** | PRI-14: Audit log documents AI agent data processing activities |
| **Art.32 — Security of processing** | PRI-01.6, CRY-01, IAC-20, NET-01: Security stack (crypto, access, network). Pro adds DCH-05 |
| **Art.33 — Breach notification** | Pro: IRO-04.1 — breach_report.py captures structured breach evidence for notification |
| **Art.44 — Transfer to third countries** | DCH-25: Network filters block sensitive data to untrusted endpoints |
| **Art.88 — Employment context** | Pro: HRS-01 — Employee ID/HR number detection filters |

### DORA (Regulation 2022/2554 — Digital Operational Resilience)

| DORA Article | claude-privacy-hook Mapping |
|---|---|
| **Art.5 — ICT governance** | GOV-04: Assigned security responsibilities; override governance structure |
| **Art.9 — ICT security** | SEA-01, SEA-03, OPS-01: Defense-in-depth, operations security. Pro adds CFG-02, VPM-01 |
| **Art.9.4 — Access controls** | IAC-01: Identity management. Pro adds IAC-21, CHG-01, CHG-02 |
| **Art.10 — Monitoring** | MON-01, MON-16: Continuous monitoring via audit log; anomaly detection via rate limiter |
| **Art.11 — Continuity** | Pro: BCD-04 — graceful degradation Pro -> Basic; contingency testing |
| **Art.14 — Incident response** | IRO-01, IRO-02: Incident response operations; severity classification via rate limiter |
| **Art.17 — Incident classification** | IRO-02: Rate limiter classifies violations by threshold (warn/block) |

### NIS2 (Directive 2022/2555 — Network & Information Security)

| NIS2 Article | claude-privacy-hook Mapping |
|---|---|
| **Art.21.1 — Risk management measures** | GOV-02, SEA-01: Published security policies; secure engineering principles |
| **Art.21.2(a) — Risk analysis** | RSK via filter rules: Declarative risk-based rule configs define acceptable risk boundaries |
| **Art.21.2(b) — Incident handling** | IRO-01, IRO-02, IRO-13: Incident response, classification, root cause analysis via audit log |
| **Art.21.2(d) — Supply chain** | TPM-03: Network filters block untrusted third-party endpoints |
| **Art.21.2(e) — Network security** | NET-01: Network security controls (endpoint allowlisting) |
| **Art.21.2(h) — Cryptography** | CRY-01: Detects and blocks private key / certificate exposure |
| **Art.21.2(i) — HR & access** | IAC-01: Identity and access management. Pro adds HRS-01 |
| **Art.21.5 — Technical measures** | SEA-01: Secure engineering. Pro adds CFG-02 |
| **Art.23 — Incident notification** | IRO-13: Structured audit logs support incident notification and root cause analysis |

### SCF Data Privacy Management Principles (DPMP)

| DPMP Principle | Coverage | claude-privacy-hook Mapping |
|---|:---:|---|
| **P1 — Data Privacy by Design** | ✓ 20% | PRI-01, GOV-01: Privacy program, governance, business context. Pro adds DCH-02, GOV-08 for full 36% |
| **P2 — Data Subject Participation** | ✓ 25% | PRI-03: "ask" model = real-time consent (2 rules). Pro adds override system with expiry, managed consent, consent records for full 50% |
| **P3 — Limited Collection & Use** | ✓ 20% | PRI-04: Filters restrict PII collection. Pro adds DCH-18.2, HOOK_AUDIT_LOG_MINIMIZE for full 38% |
| **P4 — Transparency** | ✓ 33% | PRI-02.1: compliance.md documents purpose per filter; PD categories taxonomy; data flow diagram |
| **P5 — Data Lifecycle Management** | ✓ 30% | DCH-01, DCH-23, PRI-14: Data protection, de-identification, processing records. Pro adds DCH-09.3 (log rotation), DCH-18 for full 45% |
| **P6 — Data Subject Rights** | — n/a | Organizational responsibility — this tool is a technical control, not a data controller (see rationale below) |
| **P7 — Cybersecurity by Design** | ✓ 15% | CRY-01, IAO-01: Crypto protection, information assurance. Pro adds HRS-01 for full 21% |
| **P8 — Incident Response** | ✓ 40% | IRO-01, IRO-02: Incident response, incident handling. Pro adds IRO-10, breach_report.py for full 80% |
| **P9 — Risk Management** | ✓ 25% | RSK-04, RSK-10: Risk assessment via filter rules; DPIA via compliance.md. Pro adds RSK-06.1, risk scoring, SBOM for full 40% |
| **P10 — Third-Party Management** | ✓ 15% | TPM-03: Network filters block untrusted endpoints; trusted endpoint allowlist. Pro adds SAI-03, SBOM for full 33% |
| **P11 — Business Environment** | ✓ 33% | CPL-02, GOV-02, GOV-08: Controls oversight, published governance documentation, business context documented |

#### DPMP Sub-Principles Not Applicable

The following DPMP sub-principles are outside the scope of this tool. They require organizational processes, legal determinations, or physical infrastructure that a developer-facing technical control cannot provide. They are listed here so auditors see intentional, reasoned exclusion rather than oversight.

| Category | Sub-principles | Rationale |
|---|---|---|
| **Database registration** | P1.3 | We do not operate or manage databases — we intercept AI agent actions |
| **Training** | P1.6 | We are a technical control, not a training platform. The "ask" action provides real-time education but is not a substitute for formal privacy training |
| **Privacy communications** | P1.8-1.10 | Privacy notices to data subjects are an organizational responsibility. Our compliance.md and README document our approach but do not constitute notices to end users |
| **Legal basis** | P3.1 | Authority to collect personal data is a legal/organizational determination outside our scope |
| **Lifecycle operations** | P5.3, P5.4, P5.6, P5.7, P5.9 | Specific lifecycle operations (archival procedures, disposal verification, cross-border transfer restrictions, data migration) require organizational processes beyond a hook pipeline |
| **Data subject rights** | P6.* (all 7) | Access, rectification, erasure, portability, restriction, objection, and automated decision rights require a data controller relationship. This tool is a technical safeguard within a processor, not a controller |
| **Physical/infrastructure** | P7.1, P7.3-P7.8, P7.10, P7.12 | Physical security, HR vetting, cloud infrastructure, embedded systems, and environmental controls are infrastructure-level concerns outside a CLI tool's scope |
| **Business operations** | P11.2-P11.* | Regulatory engagement, business strategy, and market-specific privacy operations are organizational responsibilities |
| **Multi-factor authentication** | IAC-06 | No login surface exists — hooks fire automatically via Claude Code's hook system. Pro license uses JWT with machine binding (IAC-15) but MFA requires an interactive authentication flow we do not have |

### SOC 2 Trust Service Criteria (STRM-verified)

| TSC Category | SCF Controls (verified) | claude-privacy-hook Mapping |
|---|---|---|
| **CC1 — Control Environment** | GOV-01, GOV-02, GOV-04, PRI-01, AAT-01 | Governance documentation, assigned responsibilities, privacy program, AI governance. Pro adds HRS-01 |
| **CC2 — Communication & Information** | GOV-02, IRO-01, IRO-02, DCH-22, PRI-01/02/14 | Published policies, incident response, data classification, privacy notices. Pro adds CHG-01/02, DCH-02 |
| **CC3 — Risk Assessment** | SEA-01, THR-10, TPM-03 | Threat analysis, supply chain risk. Pro adds CHG-01/02, HRS-01, VPM-01 |
| **CC4 — Monitoring Activities** | IAO-01, CPL-02, GOV-05 | ~835-case test suite, controls oversight, performance metrics via benchmarks |
| **CC5 — Control Activities** | GOV-02, GOV-04, SEA-01 | Published policies, assigned roles, secure engineering. Pro adds IAC-21 |
| **CC6 — Logical & Physical Access** | IAC-01, IAC-20, CRY-01/03, NET-01, PRI-01.6 | Identity management, access enforcement, crypto, network controls. Pro adds IAC-15, IAC-21, DCH-02, CFG-02 |
| **CC7 — System Operations** | IRO-01, IRO-02, MON-01, MON-16 | Incident response, continuous monitoring, anomaly detection. Pro adds IRO-04.1, IRO-13, BCD-04, CFG-02 |
| **CC8 — Change Management** | CHG-01, SEA-01, PRI-01 | Override CLI, configuration change control. Pro adds CHG-02, CFG-02, VPM-01 |
| **CC9 — Risk Mitigation** | TPM-03 | Supply chain risk controls. Pro adds VPM-01 |
| **P1 — Notice** | GOV-02, PRI-01, PRI-02 | "ask" action provides notice; published privacy policies and data privacy notices |
| **P2 — Choice & Consent** | PRI-03 | "ask" model obtains consent. Pro adds override system for user choice |
| **P3 — Collection** | PRI-03, PRI-04 | Filters restrict PII collection by AI agent to identified purposes |
| **P4 — Use, Retention, Disposal** | PRI-05.4, PRI-01.6 | Usage restrictions; output sanitizer prevents PII in responses |
| **P6 — Disclosure** | Pro: IRO-04.1 | Audit log captures breach disclosure evidence (Pro: breach_report.py) |
| **P8 — Quality** | PRI-14 | Audit log documents data processing activities |
| **A1 — Availability** | IRO-01, IRO-02 | Incident handling. Pro adds BCD-04 for graceful degradation |
| **C1 — Confidentiality** | CRY-01 | All credential and PII filters enforce confidentiality. Pro adds DCH-02 |

### ISO 27001 Annex A (selected controls)

| ISO 27001 Control | claude-privacy-hook Mapping |
|---|---|
| **A.5.1 — Information Security Policies** | filter_rules*.json = machine-readable security policies |
| **A.8.2 — Privileged Access Rights** | Deny/ask/allow model enforces least-privilege for AI agent actions |
| **A.8.3 — Information Access Restriction** | Override system restricts which rules can be relaxed (Pro: two-layer with user/project separation) |
| **A.8.9 — Configuration Management** | Pro: Override expiry, validation CLI, two-layer config system |
| **A.8.11 — Data Masking** | Output sanitizer redacts PII and credentials from command output |
| **A.8.12 — Data Leakage Prevention** | Credential and exfiltration filters form a DLP layer. Pro adds PII and infrastructure filters |
| **A.8.16 — Monitoring Activities** | Audit logger + rate limiter provide continuous monitoring |
| **A.8.25 — Secure Development Lifecycle** | ~835-case test suite, benchmarks, data-driven security testing |

### OWASP ASVS 4.0 (Application Security Verification Standard)

| ASVS Category | claude-privacy-hook Mapping |
|---|---|
| **V2 — Authentication** | IAC-01: Credential detection blocks leaked auth tokens. Pro adds IAC-15 (JWT with machine binding) |
| **V3 — Session Management** | Session-scoped rate limiting; audit log tracks session IDs for correlation |
| **V4 — Access Control** | IAC-20: Deny/ask/allow model enforces least-privilege. Pro adds IAC-21 (two-layer override separation) |
| **V5 — Validation, Sanitization, Encoding** | THR-07: Unicode normalization (NFKC), homoglyph detection, zero-width stripping before all pattern matching |
| **V7 — Error Handling & Logging** | IRO-01: All hooks log structured JSONL entries; hooks never crash (exit 0 on error). Pro adds MON-03 (SCF-tagged entries) |
| **V8 — Data Protection** | CRY-01, PRI-01: Credential detection, output redaction, cryptographic material protection. Pro adds DCH-02, DCH-05 |
| **V9 — Communication** | NET-01: Network allowlisting, untrusted endpoint blocking. Pro adds DNS/pipe exfiltration prevention |
| **V10 — Malicious Code** | THR-10, OPS-05: Prompt injection detection, shell obfuscation blocking. Pro adds path traversal prevention |
| **V12 — Files & Resources** | IAC-20: Sensitive file access blocking (.env, .ssh, .aws, .kube, shell history) |
| **V13 — API & Web Service** | NET-01: HTTP library call detection (requests, fetch, axios, AI SDKs); trusted endpoint allowlisting |
| **V14 — Configuration** | GOV-02: JSON rule configs as machine-readable security policies. Pro adds CFG-02, CFG-04 (override validation) |

### SCF Evidence Request List (ERL) Mapping

The following table maps SCF evidence types to the specific tools and audit log fields that produce them. Use this when responding to auditor evidence requests.

| Evidence type | SCF expectation | Our tool / field | How to extract |
|---|---|---|---|
| **Policy documentation** | Written security policies | `filter_rules*.json`, `compliance.md` | Rule configs ARE machine-readable policies |
| **Control effectiveness** | Proof controls are working | `audit.log` -> `action`, `rule_name` | Pro: `evidence_collector.py --format json` |
| **Incident records** | Structured incident data | `audit.log` -> deny/block events | Pro: `breach_report.py --format json` |
| **Change records** | Log of configuration changes | `audit.log` -> `override_add`, `override_remove` events | `grep override_add audit.log` |
| **Risk assessment** | Risk evaluation records | `audit.log` -> risk score on override_add | Pro: `override_cli.py validate --scope all` |
| **Access control records** | Who accessed what, when | `audit.log` -> `session_id`, `command_hash`, `timestamp` | Pro: `evidence_collector.py --cross-session` |
| **Monitoring evidence** | Continuous monitoring proof | `audit.log` -> event timeline + rate limiter escalations | Pro: `compliance_dashboard.py --format prometheus` |
| **Training / awareness** | Staff awareness evidence | "ask" action forces real-time review; compliance.md documents controls | Override audit trail shows developer engagement |
| **Third-party oversight** | Supply chain controls | TPM-03 network filter events | Pro: `generate_sbom.py` + `evidence_collector.py --domain TPM` |
| **Data classification** | Data inventory by sensitivity | `data_classification` field on all 13 rules; PD categories table | `compliance.md` §Personal Data Categories |
| **Privacy controls** | PII protection evidence | `audit.log` -> deny events for credential/PII rules | Pro: `evidence_collector_pro.py --nlp-only` (NLP confidence scores) |
| **Compliance reporting** | Periodic compliance status | Basic: audit log review | Pro: `compliance_dashboard.py --format html` |

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
| **STRM** | NIST IR 8477 Set Theory Relationship Mapping type — see *STRM Types* below |
| **Str** | Relationship strength (1-10) — how directly our implementation addresses the control objective |
| **Regulation** | Applicable regulatory standard (GDPR, PCI-DSS, HIPAA, etc.) |
| **Value** | Risk criticality rating |

### Layers

| Layer | Description |
|-------|-------------|
| **L1 regex** | Layer 1 — fast, deterministic regex-based filtering (<1ms) |
| **L1/L2** | Hybrid filter spanning both regex and NLP layers |
| **L2 NLP** | Layer 2 — NLP-based detection using pluggable backends (3-25ms) (Pro only) |
| **Post-hook** | Runs after command execution to sanitize output |
| **Meta** | Infrastructure-level controls (logging, rate limiting, oversight) |
| **Config** | Configuration-level controls (hook registration, tool coverage) |

### STRM Relationship Types (NIST IR 8477)

| Type | Meaning | Our Usage |
|------|---------|-----------|
| **Subset Of** | Our feature is fully contained within the SCF control objective | Strong match — our implementation directly satisfies a portion of the control |
| **Intersects With** | Our feature partially overlaps with the SCF control objective | Moderate match — our implementation addresses some but not all aspects |
| **Equal** | Our feature is equivalent to the SCF control objective | Exact match — our implementation fully satisfies the control |

Strength ratings (1-10): 1 = nominal, 5 = moderate, 8 = strong, 10 = direct/equal.

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

Codes follow the official [Secure Controls Framework](https://securecontrolsframework.com) taxonomy (33 domains).

| Code | Domain |
|------|--------|
| **AAT** | Artificial Intelligence & Autonomous Technology |
| **AST** | Asset Management |
| **BCD** | Business Continuity & Disaster Recovery |
| **CFG** | Configuration Management |
| **CHG** | Change Management |
| **CPL** | Compliance |
| **CRY** | Cryptographic Protections |
| **DCH** | Data Classification & Handling |
| **GOV** | Cybersecurity & Data Privacy Governance |
| **HRS** | Human Resources Security |
| **IAC** | Identification & Authentication |
| **IAO** | Information Assurance |
| **IRO** | Incident Response |
| **MON** | Continuous Monitoring |
| **NET** | Network Security |
| **OPS** | Security Operations |
| **PRI** | Data Privacy |
| **RSK** | Risk Management |
| **SAI** | Software Assurance & Integrity |
| **SEA** | Secure Engineering & Architecture |
| **TDA** | Technology Development & Acquisition |
| **THR** | Threat Management |
| **TPM** | Third-Party Management |
| **VPM** | Vulnerability & Patch Management |

### Regulations & Frameworks

| Abbreviation | Full Name |
|--------------|-----------|
| **GDPR Art.4** | General Data Protection Regulation — definitions of personal data |
| **GDPR Art.9** | GDPR — special categories of personal data (health, biometric, ethnic, etc.) |
| **GDPR Art.22** | GDPR — automated decision-making and human oversight |
| **GDPR Art.25** | GDPR — data protection by design and by default |
| **GDPR Art.30** | GDPR — records of processing activities |
| **GDPR Art.32** | GDPR — security of processing |
| **GDPR Art.33** | GDPR — notification of personal data breach to supervisory authority |
| **GDPR Art.44** | GDPR — general principle for transfers to third countries |
| **GDPR Art.5(2)** | GDPR — accountability principle |
| **GDPR Art.6** | GDPR — lawfulness of processing (legitimate basis) |
| **GDPR Art.88** | GDPR — processing in the employment context |
| **PCI-DSS Req.3** | Payment Card Industry Data Security Standard — protect stored cardholder data |
| **HIPAA** | Health Insurance Portability and Accountability Act |
| **PSD2** | Payment Services Directive 2 (EU banking regulation) |
| **OWASP LLM01** | OWASP Top 10 for LLMs — prompt injection |
| **OWASP A05** | OWASP Top 10 — security misconfiguration (path traversal) |
| **OWASP ASVS 4.0** | Application Security Verification Standard — 14 categories, ~280 requirements for application security |
| **NIST CSF 2.0** | NIST Cybersecurity Framework 2.0 — Govern, Identify, Protect, Detect, Respond, Recover |
| **SOC 2** | Service Organization Control 2 — Trust Service Criteria (CC, P, A, C) |
| **DORA** | EU Digital Operational Resilience Act (Regulation 2022/2554) — ICT risk for financial sector |
| **DPMP** | SCF Data Privacy Management Principles — 86 principles across 11 domains |
| **EU AI Act** | EU Regulation on Artificial Intelligence — risk-based framework for AI systems (Art.5-73) |
| **NIS2** | EU Network & Information Security Directive (2022/2555) — critical infrastructure cybersecurity |
| **ISO 27001** | International standard for information security management (Annex A controls) |
| **ISO 42001** | International standard for Artificial Intelligence Management Systems (AIMS) |

---

*SCF control identifiers referenced from the [Secure Controls Framework](https://securecontrolsframework.com), CC BY-ND 4.0.*
