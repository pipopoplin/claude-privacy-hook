# Enforcement Activity Diagrams

Mermaid diagrams in `diagrams/` directory. Render with any Mermaid-compatible viewer (GitHub, VS Code extension, mermaid.live).

## Diagrams

| File | What it shows |
|------|---------------|
| [installation-flow.mmd](diagrams/installation-flow.mmd) | Free vs pro package install paths, license key validation, scope placement |
| [runtime-enforcement.mmd](diagrams/runtime-enforcement.mmd) | Full decision tree from hook trigger through free/team/enterprise paths |
| [license-validation.mmd](diagrams/license-validation.mmd) | Key sources, signature check, expiry, scope matching, fallback to free |
| [audit-trail.mmd](diagrams/audit-trail.mmd) | Local vs central vs fleet logging, SIEM forwarding by tier |
| [override-enforcement.mmd](diagrams/override-enforcement.mmd) | How overrides work (or don't) per tier |

## Runtime Summary

```
FREE (Repo/User scope)
├── regex_filter.py        ← all 16 rules, full pattern coverage
├── output_sanitizer.py    ← 7 redaction rules on stdout/stderr
├── rate_limiter.py        ← warn at 5, block at 10
├── audit_logger.py        ← local JSONL file
└── hook_utils.py          ← Unicode normalization (automatic)

TEAM (Computer scope) = FREE +
├── llm_filter.py          ← NLP PII detection
├── llm_client.py          ← persistent NLP service connection
├── plugins/*              ← all 7 plugins (3 PII + 4 supplementary)
├── override_resolver.py   ← team-shared exception management
├── override_cli.py        ← add/remove/list/validate/test overrides
├── managed/               ← IT-enforced non-overridable rules
├── license.key            ← at /etc/claude-code/
└── central audit log      ← at /var/log/claude-code/

ENTERPRISE (Fleet scope) = TEAM +
├── fleet templates        ← Ansible/MDM/Chef deployment
├── audit aggregation      ← collect logs from all machines
├── SIEM integration       ← forward to Splunk/Datadog/Elastic
├── compliance reports     ← SOC 2 / GDPR / HIPAA templates
└── priority support       ← SLA, dedicated channel
```
