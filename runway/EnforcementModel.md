# Licensing Enforcement Model

## Two Tiers: Free and Pro

| Tier | Scope | Who Controls | Config Location | Account Required |
|------|-------|-------------|-----------------|:----------------:|
| Free | Repo / User | Developer | `.claude/hooks/` or `~/.claude/hooks/` | No |
| Pro | Repo / User / Computer | Developer or IT admin | Same + `/etc/claude-code/` | Yes (login + token) |

The upsell question: **"Do you need governance?"**
- No → Free (all detection + protection features)
- Yes → Pro (adds governance: overrides, managed rules, central audit, compliance)

## What Free Gets: All Detection & Protection

Every security feature that detects threats and protects data is free.

| Feature | Free | Pro |
|---------|:----:|:---:|
| **Detection** | | |
| Regex filter (16 Bash rules, ~160 patterns) | x | x |
| Write/Edit content rules (8 rules) | x | x |
| Read path rules | x | x |
| Output sanitizer (7 redaction rules) | x | x |
| NLP PII detection (names, emails, phones) | x | x |
| Supplementary plugins (prompt injection, sensitive categories, entropy, semantic intent) | x | x |
| Persistent NLP service | x | x |
| Custom NLP plugins | x | x |
| Rate limiter | x | x |
| Unicode/homoglyph normalization | x | x |
| **Governance** (Pro only) | | |
| Override CLI (add/remove/list/validate/test) | — | x |
| Project-level shared overrides | — | x |
| User-level overrides (~/.claude/hooks/config_overrides.json) | — | x |
| Computer-scoped managed rules (/etc/claude-code/) | — | x |
| Non-overridable managed rules (overridable: false enforcement) | — | x |
| Central audit log (per computer) | — | x |
| Audit log with override tracking (override_name, override_source) | — | x |
| Compliance report templates (SOC 2, GDPR, HIPAA) | — | x |
| SIEM/alerting integration (Splunk, Datadog, Elastic) | — | x |
| Fleet deployment templates (Ansible/MDM/Chef) | — | x |

## The Paywall Logic

Free tier has **all 25 use cases for detection and blocking**. It catches credentials, PII, injections, exfiltration — everything.

Pro tier adds **governance**: the ability to manage exceptions, enforce policy across machines, audit what happened, and prove compliance.

| Free user experience | Pro upgrade trigger |
|---------------------|-------------------|
| Gets blocked by a rule | Can't add an exception without editing JSON |
| Edits filter_rules.json directly | Works for 1 person, breaks for a team |
| Has a local audit.log | Auditor asks for compliance-mapped report |
| Rules are the same on every machine | IT needs to enforce non-overridable policy |
| All detection works | Needs to manage, coordinate, prove |

## Conversion Triggers

| Moment | What happens |
|--------|-------------|
| "I want to allow our company API for the whole team" | Need override CLI → Pro |
| "How do we enforce this on every dev machine?" | Need managed layer → Pro |
| "Auditor wants AI controls mapped to SOC 2" | Need compliance reporting → Pro |
| "I need to see what's being blocked across the team" | Need central audit → Pro |
| "We need non-overridable rules that devs can't bypass" | Need managed rules → Pro |

## Enforcement: Two Repos

```
Public repo:  claude-privacy-hook           (Apache 2.0 / MIT)
              ├── regex_filter.py
              ├── llm_filter.py
              ├── llm_client.py + llm_service.py
              ├── output_sanitizer.py
              ├── rate_limiter.py
              ├── audit_logger.py (basic — local JSONL only)
              ├── hook_utils.py
              ├── plugins/*
              └── filter_rules*.json

Private repo: claude-privacy-hook-pro       (BSL 1.1)
              ├── override_resolver.py
              ├── override_cli.py
              ├── config_overrides.json
              ├── managed/ (IT deployment templates)
              ├── audit_logger_pro.py (central + SIEM + compliance)
              ├── fleet/ (Ansible/MDM/Chef templates)
              └── license/ (token management, heartbeat)
```

## Enforcement: Session-Based Token

See [TokenManagement.md](TokenManagement.md) for full details.

| Property | Value |
|----------|-------|
| Token validity | 3 hours |
| Heartbeat interval | 10 min |
| Max offline grace | 3 hours |
| Max sharing exposure | 3 hours |
| Time to detect device switch | ≤10 min |

Pro hooks check the license status file before running governance features. If token is invalid/expired/missing, governance features are skipped — detection still works (free tier).

## Non-Technical Enforcement

| Mechanism | How it works |
|-----------|-------------|
| License audit clause | BSL 1.1 includes this — can request proof of compliance |
| Procurement process | Companies needing governance are already in a procurement workflow |
| Support as value | Paying customers get help with override config, managed deployment, compliance mapping |
| Update access | Pro repo is private. No license = no updates for governance features. |

## Piracy Risk Assessment

| User type | Will they pirate? | Does it matter? |
|-----------|------------------|-----------------|
| Solo dev | No — free tier has everything they need | N/A |
| Startup (5 devs) | Might try, hit wall needing support for managed deployment | Low risk |
| Mid-size (50 devs) | Won't risk it — need governance, need support | No — they'll buy Pro |
| Large org (500+ devs) | Absolutely not — audit risk, vendor liability | No — they'll buy Pro |

Key insight: **Detection is free. Governance costs money.** The people who need governance are exactly the people who go through procurement.

## Recommendation

1. **Two repos** — clean separation, free code is truly open, includes all detection
2. **Session-based licensing** — login → token → 10-min heartbeat → 3h validity
3. **License server** — lightweight, stores sessions, handles auth + renewal
4. **Private PyPI or GitHub Packages** — no public download for pro
5. **BSL 1.1** on pro repo — legal backstop
6. **Graceful degradation** — governance falls back silently, detection always works
