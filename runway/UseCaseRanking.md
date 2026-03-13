# Use Case Ranking

25 use cases ranked by value, mapped to hooks, plugins, and regulations.

## Tier 1 — Critical Value (prevents direct breach/liability)

| Rank | Use Case | Hook | Plugin | Regulation | Audience |
|:----:|----------|------|--------|------------|----------|
| 1 | Prevent credential leakage (API keys, cloud tokens, private keys, DB passwords, 30+ formats) | regex_filter (Bash + Write + Edit) | — | SOC 2, ISO 27001 | All |
| 2 | Block PII exfiltration (names, emails, phones, SSNs, credit cards in commands) | llm_filter + regex_filter (Write) | presidio / spacy / distilbert | GDPR Art.4, HIPAA, PCI-DSS Req.3 | All handling customer data |
| 3 | Prevent data exfiltration to untrusted servers (curl, wget, ssh, requests, fetch, axios) | regex_filter (Bash) | — | — | All |
| 4 | Block prompt injection & jailbreak attacks (role reassignment, DAN, XML injection) | regex_filter (Bash) + llm_filter | prompt_injection | OWASP LLM01 | All |

## Tier 2 — High Value (prevents indirect exposure/compliance gaps)

| Rank | Use Case | Hook | Plugin | Regulation | Audience |
|:----:|----------|------|--------|------------|----------|
| 5 | Protect financial & banking data (IBAN, routing numbers, SWIFT/BIC, credit cards) | regex_filter (Bash + Write) | — | PSD2, PCI-DSS | Fintech, banking |
| 6 | Block sensitive file access (.env, .ssh, .aws/credentials, /etc/shadow, kube, Docker) | regex_filter (Bash + Read) | — | GDPR Art.32 | All |
| 7 | Enterprise-wide IT policy enforcement (managed layer, non-overridable hard deny) | regex_filter (managed) | — | SOC 2, ISO 27001 | IT / security teams |
| 8 | Full audit trail (JSONL: timestamp, rule, action, SHA-256 hash, session, overrides) | audit_logger (all hooks) | — | GDPR Art.5(2), SOC 2 | Regulated industries |
| 9 | Block shell obfuscation & evasion (eval, hex/octal escapes, /dev/tcp, IFS, process substitution) | regex_filter (Bash) | — | — | Enterprise |
| 10 | Block DNS exfiltration & pipe-chain data theft (dig, nslookup, reverse shells, mkfifo, mail) | regex_filter (Bash) | — | — | Security teams |

## Tier 3 — High-Medium Value (operational protection & flexibility)

| Rank | Use Case | Hook | Plugin | Regulation | Audience |
|:----:|----------|------|--------|------------|----------|
| 11 | Protect employee & HR data (EMP-IDs, HR numbers, payroll, personnel identifiers) | regex_filter (Bash) | — | GDPR Art.88 | HR tech, enterprise |
| 12 | Protect customer & business identifiers (CUST-, INV-, ORD-, tenant, subscription IDs) | regex_filter (Bash) | — | GDPR Art.4 | SaaS, e-commerce |
| 13 | Block internal network exposure (RFC1918, cloud metadata 169.254.169.254, .corp/.internal DNS) | regex_filter (Bash + Write) | — | GDPR Art.32 | Enterprise, cloud |
| 14 | Output sanitization — redact secrets/PII from command stdout/stderr (7 redaction rules) | output_sanitizer | — | GDPR Art.32 | All |
| 15 | Flexible override system (managed/project/user layers, CLI tool, expiry dates, audit metadata) | override_resolver + override_cli | — | — | Dev teams |
| 16 | Government ID protection (passport numbers, driver licence, national IDs) | regex_filter (Bash) | — | GDPR Art.9 | Identity / travel tech |
| 17 | High-entropy secret detection (unknown token formats, random strings >4.0 bits/char entropy) | llm_filter | entropy_detector | — | Security teams |
| 18 | Medical, biometric & protected category detection (GDPR Art.9 special categories) | llm_filter | sensitive_categories | GDPR Art.9, HIPAA | Healthcare, biotech |
| 19 | Semantic intent classification (suspicious verb+target combinations, exfiltration intent) | llm_filter | semantic_intent | OWASP LLM01 | Security teams |
| 20 | Rate-limited violation escalation (warn at 5 violations, block at 10, 5-min rolling window) | rate_limiter | — | — | Enterprise |

## Tier 4 — Medium Value (defense-in-depth & advanced detection)

| Rank | Use Case | Hook | Plugin | Regulation | Audience |
|:----:|----------|------|--------|------------|----------|
| 21 | Base64 payload detection (encoded credential/data exfiltration, CLI/Python/JS variants) | regex_filter (Bash) | — | — | Security teams |
| 22 | Unicode/homoglyph bypass prevention (Cyrillic/Greek lookalikes, zero-width char stripping) | hook_utils (all hooks) | — | — | All (automatic) |
| 23 | Zero-dependency core (stdlib only, works in airgapped/CI/Docker with no internet) | regex_filter, output_sanitizer, rate_limiter | prompt_injection, sensitive_categories, entropy_detector, semantic_intent | — | Airgapped, CI/CD |
| 24 | Path traversal prevention (../../../, URL-encoded %2e, double-encoded, UTF-8 overlong) | regex_filter (Bash) | — | OWASP A05 | All |
| 25 | Pluggable NLP architecture (custom detectors via plugin ABC + JSON registry, no code changes) | llm_filter | all (extensible) | — | Orgs with custom needs |

## Summary by Audience

| Audience | Top Ranks |
|----------|-----------|
| Solo developer | 1, 3, 6, 14 |
| Startup team | 1, 2, 3, 5, 6, 14, 15 |
| Enterprise | 1–3, 5–9, 11–15, 20 |
| Regulated industry | All above + 8, 16, 18 |
| Security team | All above + 4, 9, 10, 17, 19, 22, 24 |
| Airgapped / CI | 1, 3, 6, 14, 23 |

## Hook & Plugin Coverage Matrix

| Component | Type | Use Cases Covered | Dependency |
|-----------|------|-------------------|------------|
| regex_filter.py | PreToolUse hook | 1, 3, 5, 6, 9, 10, 11, 12, 13, 16, 21, 24 | stdlib only |
| filter_rules.json | Config (Bash, 16 rules) | 1, 3–6, 9–13, 16, 21, 24 | — |
| filter_rules_write.json | Config (Write/Edit, 8 rules) | 1, 5, 13 | — |
| filter_rules_read.json | Config (Read, 1 rule) | 6 | — |
| llm_filter.py | PreToolUse hook | 2, 4, 17, 18, 19 | NLP plugin(s) |
| llm_client.py + llm_service.py | Persistent NLP service | 2, 4, 17, 18, 19 | NLP plugin(s) |
| output_sanitizer.py | PostToolUse hook | 14 | stdlib only |
| rate_limiter.py | PreToolUse hook | 20 | stdlib only |
| audit_logger.py | Meta (all hooks) | 8 | stdlib only |
| override_resolver.py + override_cli.py | Override system | 15 | stdlib only |
| hook_utils.py | Shared utility | 22 | stdlib only |
| managed/ templates | IT deployment | 7 | stdlib only |
| presidio_plugin.py | PII plugin | 2 | presidio-analyzer |
| spacy_plugin.py | PII plugin | 2 | spacy + en_core_web_sm |
| distilbert_plugin.py | PII plugin | 2 | transformers + torch |
| prompt_injection_plugin.py | Supplementary plugin | 4 | stdlib only |
| sensitive_categories_plugin.py | Supplementary plugin | 18 | stdlib only |
| entropy_detector_plugin.py | Supplementary plugin | 17 | stdlib only |
| semantic_intent_plugin.py | Supplementary plugin | 19 | stdlib only |

## Regulation Coverage

| Regulation | Use Cases | Description |
|------------|-----------|-------------|
| GDPR Art.4 | 2, 12 | Personal data definitions |
| GDPR Art.5(2) | 8 | Accountability principle |
| GDPR Art.9 | 16, 18 | Special category data (health, biometric, ethnic) |
| GDPR Art.32 | 6, 13, 14 | Security of processing |
| GDPR Art.88 | 11 | Processing in employment context |
| PCI-DSS Req.3 | 2 | Protect stored cardholder data |
| PSD2 | 5 | EU payment services (banking data) |
| HIPAA | 2, 18 | Health data protection |
| SOC 2 | 1, 7, 8 | Service organization controls |
| ISO 27001 | 1, 7 | Information security management |
| OWASP LLM01 | 4, 19 | Prompt injection |
| OWASP A05 | 24 | Security misconfiguration (path traversal) |
