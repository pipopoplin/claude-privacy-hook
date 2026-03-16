# Plugin System

> **Pro feature** — NLP plugins are available exclusively in [claude-privacy-hook-pro](https://github.com/anthropics/claude-privacy-hook-pro) (Pro tier, BSL 1.1).

## What's in Pro

The pro tier adds 7 pluggable NLP detection backends:

| Plugin | What it detects | Latency |
|--------|-----------------|---------|
| **Presidio** | Known PII types (names, emails, phones, SSNs, credit cards) | ~0.4ms |
| **spaCy** | Named entities via NER model | ~3ms |
| **DistilBERT** | High-accuracy NER via transformer | ~25ms |
| **Prompt injection** | Jailbreak phrases, role reassignment, instruction override | ~1ms |
| **Sensitive categories** | Medical, biometric, GDPR Art.9 protected data | ~1ms |
| **Entropy detector** | High-entropy strings (unknown secret formats) | ~1ms |
| **Semantic intent** | Suspicious command intent (exfiltrate, steal, dump) | ~1ms |

Pro also includes a custom plugin API for writing your own detection backends.

## Free Tier

The free tier provides regex-based detection with 6 Bash rules, 3 Write rules, and 3 output sanitizer rules (~80 patterns total) — no plugins or external dependencies needed. See [architecture.md](../../docs/architecture.md) for details on the regex filter, output sanitizer, and rate limiter.
