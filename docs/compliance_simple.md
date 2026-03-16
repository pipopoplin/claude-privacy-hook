# Simplified Compliance Report — claude-privacy-hook Free Tier (MIT)

## At a Glance

| Metric | Free Tier | Pro Tier |
|--------|:---------:|:--------:|
| Filter rules | 13 | 40 |
| Architectural controls | 10 | 16 |
| Regex patterns | ~80 | 215+ |
| NLP detection plugins | 0 | 7 |
| Test cases | ~835 | 1,500+ |
| SCF domains covered | 12 | 24 |
| Frameworks mapped | 10 | 10 (full coverage) |

---

## What the Free Tier Protects

**Blocks (deny — cannot be bypassed):**
- API keys & tokens (Anthropic, OpenAI, AWS, GitHub, GitLab, Slack, Stripe, Google, SendGrid, Twilio, npm, PyPI, HuggingFace, DigitalOcean, Vault — 31 patterns)
- Private keys (RSA, EC, DSA, OPENSSH PEM headers)
- Hardcoded passwords and secrets
- Prompt injection & jailbreak attempts (13 patterns)
- Shell obfuscation (eval, hex/octal escapes, /dev/tcp, IFS manipulation)

**Asks (human approval required):**
- Sensitive file access (.env, .ssh, .aws, .kube, /etc/shadow, shell history)
- Network calls to untrusted endpoints (curl, wget, ssh, requests, fetch)

**Allows (trusted endpoints):**
- localhost, PyPI, npm, RubyGems, crates.io, GitHub, GitLab, Bitbucket

**Redacts in output:**
- API keys/tokens (20 patterns)
- Email addresses
- Internal IP addresses (RFC1918, IPv6 ULA/link-local)

**Write/Edit blocks:**
- API keys in file content (22 patterns)
- Hardcoded passwords in file content

---

## What Requires Pro Tier

| Category | Examples | Why Pro |
|----------|----------|---------|
| Government IDs | SSN, passport, driver licence, national ID | Regulated PII (GDPR Art.9) |
| Financial data | Credit cards, IBAN, bank accounts, SWIFT/BIC | PCI-DSS / PSD2 compliance |
| Employment data | Employee IDs, HR numbers, payroll | GDPR Art.88 |
| Medical/health | MRN, patient IDs, NPI, genetic data | HIPAA / GDPR Art.9 |
| Biometric data | Fingerprints, facial recognition, iris scans | GDPR Art.9 |
| Business IDs | Customer, invoice, order, contract IDs | Enterprise data governance |
| Infrastructure | DB connection strings, internal IPs, cloud metadata | DevOps/platform security |
| Exfiltration | DNS exfil, pipe chains, base64 encoding, path traversal | Advanced attack prevention |
| NLP detection | Named entities, phone numbers, semantic intent, entropy | AI-powered PII detection |

---

## Compliance Framework Coverage

### Fully addressed in Free Tier

| Framework | What's Covered |
|-----------|----------------|
| **EU AI Act** | Art.5 (prompt injection), Art.9 (input validation, testing, monitoring), Art.12 (audit logging), Art.14 (human oversight via ask rules) |
| **GDPR** | Art.25/32 (privacy by design — filter pipeline), Art.6 (usage restrictions), Art.30 (processing records via audit log), Art.44 (transfer controls) |
| **ISO 42001** | §4.1/4.4 (AI management system), §6.1 (risk decisions), §A.7 (data quality), §A.6.2.5 (information assurance — 835 tests), §A.8.3 (incident reporting), §A.9.4 (post-deployment monitoring) |
| **DORA** | Art.9 (operations security), Art.10 (continuous monitoring), Art.17 (incident classification) |
| **NIS2** | Art.21 (vulnerability detection), Art.23 (root cause analysis via audit log) |
| **SOC 2** | CC1 (governance docs), CC4 (controls oversight via tests), CC4/CC5 (performance metrics), P3 (PII collection restriction) |
| **OWASP** | LLM01 (prompt injection), ASVS V5 (input validation), V7 (error handling/logging) |

### Requires Pro for full coverage

| Framework | What's Missing in Free |
|-----------|----------------------|
| **GDPR** | Art.9 (special category detection — SSN, health, biometric), Art.33 (breach notification reports) |
| **PCI-DSS** | Req.3 (cardholder data protection — credit card detection) |
| **HIPAA** | PHI detection (medical records, NPI, DEA numbers) |
| **SOC 2** | Full evidence collection, SCF-tagged audit entries, compliance dashboards |
| **DORA** | Art.12 (SCF-tagged log content), Art.9 (network intrusion prevention — pipe/DNS exfil) |

---

## SCF Domain Coverage (Free Tier)

| Domain | Code | Free Tier Controls | What's Covered |
|--------|------|--------------------|----------------|
| Identification & Authentication | IAC | 5 | API keys, tokens, credentials, access enforcement, sensitive file gating |
| Network Security | NET | 3 | Trusted endpoint allowlist, untrusted network blocking, data flow ACL |
| Threat Management | THR | 4 | Prompt injection, shell obfuscation, Unicode/homoglyph bypass, threat patterns |
| Cryptographic Protections | CRY | 2 | Private key detection (Bash + output), crypto exposure prevention |
| Operations Security | OPS | 2 | Shell obfuscation blocking, Write/Read tool coverage |
| Data Classification & Handling | DCH | 2 | Output data masking, data protection enforcement |
| Incident Response | IRO | 2 | Audit log of blocked events, behavioral IOC via rate limiter |
| Governance | GOV | 3 | Human oversight (ask), JSON policies, governance documentation |
| Continuous Monitoring | MON | 2 | Rate limiting, audit log retention |
| Privacy | PRI | 2 | Purpose specification, PII usage restriction |
| Risk Management | RSK | 2 | Risk assessment via rules, DPIA via compliance.md |
| Technology Development | TDA | 2 | Test suite (835 cases), secure coding enforcement |

---

## Audit & Evidence

| Capability | Free | Pro |
|------------|:----:|:---:|
| JSONL audit log | Yes | Yes |
| Command SHA-256 hashing | Yes | Yes |
| Redacted command preview | Yes | Yes |
| Session ID correlation | Yes | Yes |
| Override event tracking | Yes | Yes |
| SCF metadata in entries | — | Yes |
| Log rotation (10 MB + 5 backups) | — | Yes |
| Data minimization mode | — | Yes |
| Evidence collector (SCF grouping) | — | Yes |
| Breach notification (GDPR Art.33) | — | Yes |
| SIEM integration (CEF/LEEF/Splunk/Datadog) | — | Yes |
| Compliance dashboards (HTML/Grafana/Prometheus) | — | Yes |

---

## Override System

| Capability | Free | Pro |
|------------|:----:|:---:|
| Project-level overrides | Yes (max 3) | Unlimited |
| User-level overrides | — | Yes |
| Managed/IT overrides | — | Yes |
| CLI `list` | Yes | Yes |
| CLI `add` / `remove` / `validate` / `test` | — | Yes |
| Override expiry dates | — | Yes |
| Risk scoring | — | Yes |

---

## Testing & Quality

- **7 test suites**, ~835 test cases, 0 failures
- Regex filter (298 cases), Output sanitizer (111), Rate limiter (45), Overrides (50), Conftest infrastructure (148), Audit logger (19), Config validation (43)
- Benchmark suite validates <1ms in-process latency for all hooks
- Zero external dependencies (Python 3.10+ stdlib only)

---

*SCF control identifiers referenced from the [Secure Controls Framework](https://securecontrolsframework.com), CC BY-ND 4.0. Full 111-control compliance coverage available in [Pro tier](https://claude-privacy-hook.dev/pro).*
