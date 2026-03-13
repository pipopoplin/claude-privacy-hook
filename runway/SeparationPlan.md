# Free / Pro Code Separation Plan

## Guiding Principle

**Core credential protection is free. Compliance costs money.**

The 9 highest-impact filters — credential detection, credit card numbers, IP addresses, and prompt injection — ship in the free public repo (MIT). The remaining 31 filters (network security, PII detection, compliance-grade controls, governance, and infrastructure) live in a private pro repo (BSL 1.1). Pro features degrade gracefully to free tier when no valid license token exists.

**Why this split?** Solo developers get genuine protection against the most damaging AI-coding mistakes — leaked API keys, exposed credit card numbers, and prompt injection attacks. Teams and organizations that need full network security, regulatory compliance (GDPR, HIPAA, PCI-DSS), and governance pay for the filters that address those requirements. The paywall sits at the compliance boundary: **"Protection is free. Compliance costs money."**

---

## Filter Split: Free vs Pro

### Free Tier — 9 filters (MIT)

The highest-impact credential and data protection filters. No account needed.

| # | Filter | Layer | Scope | SCF Domain | SCF Control | Regulation | Value |
|---|--------|-------|-------|------------|-------------|------------|-------|
| 1 | Anthropic / OpenAI API keys | L1 regex | :lock: | IAC | IAC-01 | — | :red_circle: Critical |
| 2 | AWS / GCP / Azure credentials | L1 regex | :lock: | IAC | IAC-01 | — | :red_circle: Critical |
| 3 | GitHub / GitLab tokens | L1 regex | :lock: | IAC | IAC-09 | — | :red_circle: Critical |
| 4 | Private keys / PEM certs | L1 regex | :lock: | CRY | CRY-03 | — | :red_circle: Critical |
| 5 | Slack / webhook tokens | L1 regex | :lock: | IAC | IAC-09 | — | :red_circle: Critical |
| 6 | Hardcoded passwords | L1 regex | :lock: | IAC | IAC-01 | — | :red_circle: Critical |
| 12 | Credit card numbers | L2 NLP | :shield: | DAT | DAT-02 | PCI-DSS Req.3 | :red_circle: Critical |
| 14 | IP addresses | L2 NLP | :shield: | PRI | PRI-01 | GDPR Art.4 | :red_circle: Critical |
| 22 | Prompt injection phrases | L1/L2 | :lock: | TVM | TVM-10 | OWASP LLM01 | :red_circle: Critical |

**Free tier value proposition:** Stops the most damaging AI-coding mistakes — leaked API keys, cloud credentials, private keys, passwords, exposed credit card numbers, IP address leaks, and prompt injection attacks. Works out of the box with zero configuration.

**Note:** Filters #12, #14, and #22 have regulation mappings but are included in the free tier due to their exceptionally high impact-to-hook ratio — every developer benefits from credit card, IP address, and prompt injection protection regardless of compliance requirements.

### Pro Tier — 31 additional filters (BSL 1.1)

Pro includes all 9 free filters plus 31 additional filters covering network security, full PII detection, compliance controls, and governance infrastructure.

| # | Filter | Layer | Scope | SCF Domain | SCF Control | Regulation | Value |
|---|--------|-------|-------|------------|-------------|------------|-------|
| 7 | Untrusted network calls | L1 regex | :lock: | NET | NET-13 | — | :red_circle: Critical |
| 8 | Trusted endpoint allowlist | L1 regex | :lock: | NET | NET-13 | — | :red_circle: Critical |
| 9 | Person names (NER) | L2 NLP | :shield: | PRI | PRI-01 | GDPR Art.4 | :red_circle: Critical |
| 10 | Email addresses | L2 NLP | :shield: | PRI | PRI-01 | GDPR Art.4 | :red_circle: Critical |
| 11 | SSN / National ID | L2 NLP | :shield: | PRI | PRI-03 | GDPR Art.9 | :red_circle: Critical |
| 13 | Phone numbers | L2 NLP | :shield: | PRI | PRI-01 | GDPR Art.4 | :red_circle: Critical |
| 15 | ORG / GPE / NORP entities | L2 NLP | :shield: | PRI | PRI-02 | GDPR Art.4 | :orange_circle: High |
| 16 | Expanded vendor credentials | L1 regex | :lock: | IAC | IAC-01 | — | :red_circle: Critical |
| 17 | Employee ID / HR numbers | L1 regex | :shield: | HRS | HRS-01 | GDPR Art.88 | :red_circle: Critical |
| 18 | Medical / health data | L2 NLP | :shield: | PRI | PRI-03 | GDPR Art.9 / HIPAA | :red_circle: Critical |
| 19 | IBAN / bank account numbers | L1 regex | :shield: | DAT | DAT-02 | PSD2 / GDPR Art.4 | :red_circle: Critical |
| 20 | Passport / driver licence | L1 regex | :shield: | PRI | PRI-03 | GDPR Art.9 | :red_circle: Critical |
| 21 | Base64-encoded payloads | L1 regex | :lock: | TVM | TVM-07 | — | :red_circle: Critical |
| 23 | Sensitive file access | L1 regex | :lock::shield: | END | END-04 | GDPR Art.32 | :red_circle: Critical |
| 24 | DNS exfiltration | L1 regex | :lock: | NET | NET-14 | — | :orange_circle: High |
| 25 | Path traversal | L1 regex | :lock: | TVM | TVM-10 | OWASP A05 | :orange_circle: High |
| 26 | Database connection strings | L1 regex | :lock::shield: | DCH | DCH-05 | GDPR Art.32 | :red_circle: Critical |
| 27 | Internal hostnames / IPs | L1 regex | :shield: | NET | NET-01 | GDPR Art.32 | :orange_circle: High |
| 28 | Customer / contract IDs | L1 regex | :shield: | PRI | PRI-02 | GDPR Art.4 | :orange_circle: High |
| 29 | Biometric data references | L2 NLP | :shield: | PRI | PRI-03 | GDPR Art.9 | :orange_circle: High |
| 30 | Ethnic / religious / political | L2 NLP | :shield: | PRI | PRI-03 | GDPR Art.9 | :orange_circle: High |
| 31 | Unicode / homoglyph bypass | L1 | :lock: | TVM | TVM-07 | — | :orange_circle: High |
| 32 | High-entropy secret detection | L2 NLP | :lock: | IAC | IAC-01 | — | :orange_circle: High |
| 33 | Shell obfuscation / eval | L1 regex | :lock: | OPS | OPS-05 | — | :orange_circle: High |
| 34 | Pipe-chain exfiltration | L1 regex | :lock: | NET | NET-13 | — | :orange_circle: High |
| 35 | Output sanitization | Post-hook | :shield: | DAT | DAT-05 | GDPR Art.32 | :yellow_circle: Medium |
| 36 | ask / human oversight | Meta | :balance_scale: | GOV | GOV-04 | GDPR Art.22 | :yellow_circle: Medium |
| 37 | Audit log of blocked events | Meta | :balance_scale: | IRO | IRO-01 | GDPR Art.5(2) | :orange_circle: High |
| 38 | Rate limiting / anomaly | Meta | :lock: | OPS | OPS-08 | — | :yellow_circle: Medium |
| 39 | Non-Bash tool coverage | Config | :lock::shield: | OPS | OPS-05 | GDPR Art.32 | :yellow_circle: Medium |
| 40 | Semantic intent scoring | L2 NLP | :lock::shield: | TVM | TVM-10 | OWASP LLM01 | :yellow_circle: Medium |

### Conversion Wall

The free tier catches leaked API keys, credit card numbers, IP addresses, and prompt injection — the highest-impact protections every developer needs. The moment a team needs network security, full PII detection, obfuscation defense, compliance controls, or governance, they hit the paywall.

**Upgrade trigger:** "Your hooks blocked a credential leak and a credit card number. Want network security, full PII detection, and compliance controls for GDPR/HIPAA/PCI-DSS?"

---

## Tier Boundary by Component

| Component | Free | Pro | Current File(s) |
|-----------|:----:|:---:|----------------|
| Regex filter engine | x | x | `regex_filter.py` |
| Free Bash rules (6 credential filters: #1-6) | x | x | `filter_rules.json` (subset) |
| Pro Bash rules (network, obfuscation, compliance regex) | — | x | `filter_rules.json` (subset) → `filter_rules_pro.json` |
| Write/Edit content rules (credential patterns) | x | x | `filter_rules_write.json` (subset) |
| Write/Edit content rules (PII/compliance patterns) | — | x | `filter_rules_write.json` (subset) → `filter_rules_write_pro.json` |
| Read path rules (sensitive files, GDPR Art.32) | — | x | `filter_rules_read.json` |
| NLP free subset (credit cards #12, IP addresses #14) | x | x | `llm_client.py` → free NLP config |
| NLP full PII detection (all other NLP plugins) | — | x | `llm_filter.py`, `llm_client.py`, `llm_service.py`, `plugins/*` |
| Persistent NLP service | x | x | `llm_service.py`, `llm_client.py` |
| NLP plugin framework | x | x | `plugins/base.py`, `plugins/plugins.json` |
| Prompt injection detection (#22) | x | x | `plugins/prompt_injection_plugin.py` |
| Custom NLP plugins (Presidio, spaCy, DistilBERT, etc.) | — | x | `plugins/*` (most plugins) |
| High-entropy secret detection (plugin) | — | x | `plugins/entropy_detector_plugin.py` |
| Rate limiter (#38) | — | x | `rate_limiter.py` |
| Unicode/homoglyph normalization | x | x | `hook_utils.py` |
| Audit logger (local JSONL, free events) | x | x | `audit_logger.py` |
| Output sanitizer (credential redaction) | x | x | `output_sanitizer.py` (subset) |
| Output sanitizer (PII/compliance redaction) | — | x | `output_sanitizer_rules.json` (subset) → `output_sanitizer_rules_pro.json` |
| Override CLI | — | x | `override_cli.py` |
| Override resolver | — | x | `override_resolver.py` |
| Managed rules (IT-enforced) | — | x | `managed/` |
| Central audit + override tracking | — | x | `audit_logger_pro.py` (new) |
| Compliance reports (SOC 2, GDPR, HIPAA) | — | x | new |
| SIEM integration (Splunk, Datadog, Elastic) | — | x | new |
| Fleet deployment (Ansible/MDM/Chef) | — | x | new |
| License management (login, heartbeat, status) | — | x | new |

---

## Phase 1: Split Rule Configurations by Regulation

The key implementation challenge: free and pro filters currently live in the same rule files. This phase separates them.

### 1.1 — Split `filter_rules.json` into free and pro

**Current:** Single file with all 16+ Bash rules.

**New:** Two files:
- `filter_rules.json` — Free rules only (6 credential filters). Filters #1-6.
- `filter_rules_pro.json` — Pro rules (network, obfuscation, compliance regex). Filters #7, 8, 16, 17, 19, 20, 21, 23, 24, 25, 26, 27, 28, 31, 33, 34.

**Split criteria:** Only the 6 core credential detection filters (#1-6) stay free. All other regex rules — including network (#7, 8, 24, 34), obfuscation (#21, 31, 33), and compliance (#17, 19, 20, 23, 25, 26, 27, 28) — move to pro.

### 1.2 — Split `filter_rules_write.json` into free and pro

**Current:** Write/Edit rules for credential and PII patterns.

**New:**
- `filter_rules_write.json` — Free write rules (credential patterns only)
- `filter_rules_write_pro.json` — Pro write rules (PII, compliance patterns)

### 1.3 — Split `output_sanitizer_rules.json` into free and pro

**Current:** 7 redaction rules covering API keys, SSNs, credit cards, emails, etc.

**New:**
- `output_sanitizer_rules.json` — Free rules: API key redaction, private key redaction, credit card redaction (matching free filter #12)
- `output_sanitizer_rules_pro.json` — Pro rules: SSN, email, internal IP, DB connection string redaction (regulation-mapped: GDPR, PCI-DSS)

### 1.4 — Create `tier_check.py` (shared module)

A single function that all hooks call to determine if pro features are available.

**File:** `.claude/hooks/tier_check.py`

```python
import json, os

_PRO_AVAILABLE = None
_STATUS_PATH = f"/tmp/claude-hook-license-{os.getuid()}.json"

def is_pro_available():
    """Check if pro rule files exist AND license is valid."""
    global _PRO_AVAILABLE
    if _PRO_AVAILABLE is None:
        hooks_dir = os.path.dirname(os.path.abspath(__file__))
        pro_rules = os.path.join(hooks_dir, "filter_rules_pro.json")
        _PRO_AVAILABLE = os.path.isfile(pro_rules)
    if not _PRO_AVAILABLE:
        return False
    return _is_license_valid()

def _is_license_valid():
    """Read the license status file. No network call, no crypto."""
    try:
        with open(_STATUS_PATH) as f:
            status = json.load(f)
        return status.get("status") == "valid"
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return False
```

### 1.5 — Modify `regex_filter.py`: load pro rules conditionally

**New behavior:**
```python
from tier_check import is_pro_available

# Always load free rules
config = load_json(rules_file)  # filter_rules.json (free)

# Conditionally merge pro rules
if is_pro_available():
    pro_rules_file = rules_file.replace(".json", "_pro.json")
    if os.path.isfile(pro_rules_file):
        pro_config = load_json(pro_rules_file)
        config["rules"].extend(pro_config.get("rules", []))
```

**What changes:**
- Free tier: only free regex rules fire (credentials, network, obfuscation)
- Pro tier: free + pro regex rules fire (adds PII regex, compliance patterns)
- Same engine, same evaluation — just different rule sets loaded

### 1.6 — Gate NLP filter: free subset vs full pro

The NLP pipeline is **partially free**. Three free filters require NLP detection:
- **#12 Credit card numbers** (L2 NLP, PCI-DSS Req.3)
- **#14 IP addresses** (L2 NLP, GDPR Art.4)
- **#22 Prompt injection phrases** (L1/L2, OWASP LLM01)

The remaining NLP entity types (person names, SSNs, phone numbers, email, medical data, biometric references, etc.) are pro-only.

**Implementation:** The NLP pipeline runs in both tiers, but with different entity type configurations.

**Free NLP config (`llm_filter_config_free.json`):**
```json
{
  "enabled_entity_types": ["CREDIT_CARD", "IP_ADDRESS"],
  "plugin_priority": ["prompt_injection"],
  "supplementary_plugins": ["prompt_injection"]
}
```

**Modification to `llm_client.py`:**
```python
from tier_check import is_pro_available

def main():
    if is_pro_available():
        config_file = "llm_filter_config.json"       # Full NLP (all entity types + plugins)
    else:
        config_file = "llm_filter_config_free.json"   # Free NLP (credit cards, IPs, prompt injection only)
    # ... existing NLP detection logic with selected config ...
```

**What this means:**
- Free tier: NLP service runs with a minimal config — detects only credit cards, IP addresses, and prompt injection
- Pro tier: NLP service runs with full config — detects all PII entity types, all plugins
- The NLP service infrastructure (`llm_service.py`, `llm_client.py`, `plugins/base.py`) ships in the free repo
- Pro adds the full plugin set (Presidio, spaCy, DistilBERT, sensitive categories, semantic intent) and the complete entity type configuration

### 1.7 — Modify `output_sanitizer.py`: load pro rules conditionally

Same pattern as regex_filter — load free rules always, merge pro rules when licensed.

### 1.8 — Gate override system as pro

Override system (`override_resolver.py`, `override_cli.py`) remains pro-only. Same gating as the original plan — overrides are a governance feature.

---

## Phase 2: Separate Audit Logger (Free vs Pro)

### 2.1 — Keep `audit_logger.py` as free (local JSONL only)

The current `audit_logger.py` stays in the free repo unchanged. It writes local JSONL for free-tier filter events only.

**Free `log_event()` signature:**
```python
def log_event(log_dir, filter_name, rule_name, action, matched, command, session_id=""):
```

### 2.2 — Create `audit_logger_pro.py` (pro repo, new)

Extends `audit_logger.py` with:
- Override tracking fields (`override_name`, `override_source`)
- Compliance-mapped event metadata (regulation, SCF control)
- Central log forwarding (write to `/var/log/claude-code/` or configurable path)
- SIEM integration hooks (Splunk HEC, Datadog, Elastic)
- Compliance report generation (SOC 2, GDPR, HIPAA templates)

**Integration:** Pro hooks import `audit_logger_pro` instead of `audit_logger`. If pro module is missing, falls back to free `audit_logger`.

```python
try:
    from audit_logger_pro import log_event
except ImportError:
    from audit_logger import log_event
```

### 2.3 — Pro audit log includes regulation context

Pro audit events include which regulation triggered the block:
```json
{
  "filter": "llm_filter",
  "rule": "person_name_detection",
  "action": "deny",
  "regulation": "GDPR Art.4",
  "scf_control": "PRI-01",
  "matched": ["John Smith"],
  "timestamp": "2026-03-13T10:00:00Z"
}
```

This metadata feeds directly into compliance reports — the core pro value.

---

## Phase 3: Isolate Pro Code in Separate Directory (Pre-Split)

Before splitting into two repos, move all pro-destined code into a dedicated `pro/` directory within the current repo.

### 3.1 — New directory structure

```
claude-privacy-hook/
├── .claude/
│   └── hooks/                     ← FREE (stays in public repo)
│       ├── regex_filter.py        ← Engine (shared), loads free rules
│       ├── output_sanitizer.py    ← Engine (shared), loads free rules
│       ├── llm_client.py          ← NLP client (shared, loads free or pro config)
│       ├── llm_service.py         ← Persistent NLP service (shared)
│       ├── llm_filter.py          ← NLP filter entry point (shared)
│       ├── llm_filter_config_free.json ← Free NLP config (credit cards, IPs, prompt injection)
│       ├── audit_logger.py        ← Free audit (local JSONL)
│       ├── hook_utils.py
│       ├── tier_check.py
│       ├── filter_rules.json      ← Free Bash rules (#1-6 credentials only)
│       ├── filter_rules_write.json ← Free write rules (credentials only)
│       ├── output_sanitizer_rules.json ← Free redaction (API keys, private keys, credit cards)
│       └── plugins/               ← FREE (prompt injection + base framework)
│           ├── base.py
│           ├── plugins.json       ← Free plugin registry (prompt_injection only)
│           └── prompt_injection_plugin.py
│
├── pro/                            ← PRO (moves to private repo)
│   ├── hooks/
│   │   ├── filter_rules_pro.json  ← Pro Bash rules (#7-8, 16-28, 31, 33, 34)
│   │   ├── filter_rules_write_pro.json ← Pro write rules (PII patterns)
│   │   ├── filter_rules_read.json ← Read path rules (GDPR Art.32)
│   │   ├── output_sanitizer_rules_pro.json ← Pro redaction (SSN, email, internal IP, DB strings)
│   │   ├── llm_filter_config.json ← Full NLP configuration (all entity types + plugins)
│   │   ├── rate_limiter.py        ← Rate limiter (#38, pro)
│   │   ├── rate_limiter_config.json
│   │   ├── override_resolver.py
│   │   ├── override_cli.py
│   │   ├── config_overrides.json
│   │   └── audit_logger_pro.py    (new)
│   ├── plugins/                    ← PRO NLP plugins
│   │   ├── plugins.json           ← Full plugin registry (all 7 plugins)
│   │   ├── presidio_plugin.py
│   │   ├── distilbert_plugin.py
│   │   ├── spacy_plugin.py
│   │   ├── entropy_detector_plugin.py
│   │   ├── sensitive_categories_plugin.py
│   │   └── semantic_intent_plugin.py
│   ├── managed/
│   │   ├── README.md
│   │   ├── managed_rules.json
│   │   └── managed_settings.json
│   ├── license/                    (new)
│   │   ├── __init__.py
│   │   ├── token.py
│   │   ├── heartbeat.py
│   │   ├── cli.py
│   │   └── config.py
│   ├── fleet/                      (new)
│   │   └── (Ansible/MDM/Chef templates)
│   ├── compliance/                 (new)
│   │   └── (SOC 2/GDPR/HIPAA report templates)
│   ├── tests/
│   │   ├── test_overrides.py
│   │   ├── test_nlp_filter_pro.py ← Pro NLP entity type tests
│   │   ├── test_nlp_service.py    ← NLP service tests (pro config)
│   │   ├── test_rate_limiter.py   ← Rate limiter tests (pro)
│   │   ├── test_license.py         (new)
│   │   └── test_pro_enforcement.py (new)
│   ├── install_pro.sh              (new)
│   ├── requirements_pro.txt        (new — spaCy, Presidio, transformers, torch)
│   └── README.md                   (new)
│
├── tests/                          ← FREE tests (stays in public repo)
│   ├── conftest.py
│   ├── test_regex_filter.py       ← Tests free rules only (#1-6)
│   ├── test_output_sanitizer.py   ← Tests free redaction only
│   ├── test_nlp_filter_free.py    ← Tests free NLP (credit cards, IPs, prompt injection)
│   ├── test_conftest.py
│   ├── test_tier_check.py          (new)
│   └── test_free_without_pro.py    (new)
│
├── benchmarks/                     ← FREE benchmarks
├── docs/                           ← FREE docs
├── install_linux.sh               ← Free install (lightweight NLP for CC/IP/injection)
├── install_mac.sh
├── install_win.bat
├── requirements.txt               ← Free deps (minimal NLP for credit card/IP detection)
├── LICENSE                         ← MIT (after split)
└── README.md
```

### 3.2 — File moves (within current repo)

| From | To | Notes |
|------|----|-------|
| `.claude/hooks/llm_filter_config.json` | `pro/hooks/llm_filter_config.json` | Full NLP config is pro (free gets `llm_filter_config_free.json`) |
| `.claude/hooks/plugins/presidio_plugin.py` | `pro/plugins/presidio_plugin.py` | Presidio NLP plugin is pro |
| `.claude/hooks/plugins/distilbert_plugin.py` | `pro/plugins/distilbert_plugin.py` | DistilBERT NLP plugin is pro |
| `.claude/hooks/plugins/spacy_plugin.py` | `pro/plugins/spacy_plugin.py` | spaCy NLP plugin is pro |
| `.claude/hooks/plugins/entropy_detector_plugin.py` | `pro/plugins/entropy_detector_plugin.py` | Entropy detector is pro (#32) |
| `.claude/hooks/plugins/sensitive_categories_plugin.py` | `pro/plugins/sensitive_categories_plugin.py` | Sensitive categories is pro |
| `.claude/hooks/plugins/semantic_intent_plugin.py` | `pro/plugins/semantic_intent_plugin.py` | Semantic intent is pro (#40) |
| `.claude/hooks/rate_limiter.py` | `pro/hooks/rate_limiter.py` | Rate limiter is pro (#38) |
| `.claude/hooks/rate_limiter_config.json` | `pro/hooks/rate_limiter_config.json` | Rate limiter config is pro |
| `.claude/hooks/override_resolver.py` | `pro/hooks/override_resolver.py` | Governance is pro |
| `.claude/hooks/override_cli.py` | `pro/hooks/override_cli.py` | Governance is pro |
| `.claude/hooks/config_overrides.json` | `pro/hooks/config_overrides.json` | Template file |
| `.claude/hooks/filter_rules_read.json` | `pro/hooks/filter_rules_read.json` | Read rules are GDPR Art.32 |
| `managed/` | `pro/managed/` | Entire directory |
| `tests/test_overrides.py` | `pro/tests/test_overrides.py` | Override tests |
| `tests/test_nlp_filter.py` | `pro/tests/test_nlp_filter_pro.py` | Pro NLP entity type tests |
| `tests/test_nlp_service.py` | `pro/tests/test_nlp_service.py` | NLP service tests (pro config) |
| `tests/test_rate_limiter.py` | `pro/tests/test_rate_limiter.py` | Rate limiter tests |

**Files that STAY in free repo** (changed from original plan):

| File | Reason |
|------|--------|
| `.claude/hooks/llm_client.py` | NLP client needed for free tier (credit cards, IPs, prompt injection) |
| `.claude/hooks/llm_service.py` | Persistent NLP service needed for free tier |
| `.claude/hooks/llm_filter.py` | NLP filter entry point needed for free tier |
| `.claude/hooks/plugins/base.py` | Plugin framework needed for free tier |
| `.claude/hooks/plugins/prompt_injection_plugin.py` | Free filter #22 |
| `.claude/hooks/plugins/plugins.json` | Free plugin registry (prompt_injection only) |

### 3.3 — Import path handling

After moving pro files to `pro/`, the free hooks can no longer import them directly. The `tier_check.py` handles path resolution.

**`tier_check.py` update:**
```python
import os, sys

def _get_pro_hooks_dir():
    """Return the pro hooks directory path."""
    hooks_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(hooks_dir))
    pro_hooks = os.path.join(project_root, "pro", "hooks")
    if os.path.isdir(pro_hooks) and pro_hooks not in sys.path:
        sys.path.insert(0, pro_hooks)
    return pro_hooks
```

In the **development** (monorepo) phase, pro modules live at `pro/hooks/` relative to the project root. In the **production** (split-repo) phase, the pro install script copies compiled modules into `.claude/hooks/` where they're directly importable.

### 3.4 — Pro install copies modules + rules into `.claude/hooks/`

When a pro user runs `install_pro.sh`, it:
1. Authenticates with the license server
2. Copies compiled pro modules from `pro/hooks/` into `.claude/hooks/`
3. Copies pro rule files (`filter_rules_pro.json`, `filter_rules_write_pro.json`, `filter_rules_read.json`, `output_sanitizer_rules_pro.json`)
4. Copies NLP plugins from `pro/plugins/` into `.claude/hooks/plugins/`
5. Generates `pro_manifest.json` with signed file hashes
6. Updates `settings.json` to register NLP hooks (pro adds `llm_client.py` and `output_sanitizer.py` pro rules)
7. Installs pro Python dependencies (spaCy, Presidio, transformers, torch)

### 3.5 — `.gitignore` updates

Add to the **free repo** `.gitignore` (after split):
```
# Pro modules (installed by pro installer, not tracked in free repo)
.claude/hooks/llm_filter_config.json
.claude/hooks/rate_limiter*
.claude/hooks/override_resolver*
.claude/hooks/override_cli*
.claude/hooks/audit_logger_pro*
.claude/hooks/config_overrides.json
.claude/hooks/filter_rules_pro.json
.claude/hooks/filter_rules_write_pro.json
.claude/hooks/filter_rules_read.json
.claude/hooks/output_sanitizer_rules_pro.json
.claude/hooks/pro_manifest.json
.claude/hooks/plugins/presidio*
.claude/hooks/plugins/distilbert*
.claude/hooks/plugins/spacy*
.claude/hooks/plugins/entropy_detector*
.claude/hooks/plugins/sensitive_categories*
.claude/hooks/plugins/semantic_intent*
.claude/hooks/license/
pro/
```

### 3.6 — Update `settings.json` for free vs pro tier

**Free tier `settings.json`:**
```json
{
  "hooks": {
    "PreToolUse": [
      {"command": "python3 .claude/hooks/regex_filter.py .claude/hooks/filter_rules.json"},
      {"command": "python3 .claude/hooks/llm_client.py .claude/hooks/llm_filter_config_free.json"}
    ],
    "PostToolUse": [
      {"command": "python3 .claude/hooks/output_sanitizer.py .claude/hooks/output_sanitizer_rules.json"}
    ]
  }
}
```

**Pro tier `settings.json`** (after pro install):
```json
{
  "hooks": {
    "PreToolUse": [
      {"command": "python3 .claude/hooks/regex_filter.py .claude/hooks/filter_rules.json"},
      {"command": "python3 .claude/hooks/llm_client.py .claude/hooks/llm_filter_config.json"},
      {"command": "python3 .claude/hooks/rate_limiter.py .claude/hooks/rate_limiter_config.json"}
    ],
    "PostToolUse": [
      {"command": "python3 .claude/hooks/output_sanitizer.py .claude/hooks/output_sanitizer_rules.json"}
    ]
  }
}
```

**Key differences:**
- Free tier: NLP client points to `llm_filter_config_free.json` (credit cards, IPs, prompt injection only). No rate limiter.
- Pro tier: NLP client points to full `llm_filter_config.json` (all entity types + plugins). Rate limiter added.
- The regex_filter.py auto-discovers `*_pro.json` rule files when pro is available.

---

## Phase 4: License Token Integration

### 4.1 — Add heartbeat to `llm_service.py` (pro)

The persistent NLP service runs as a background daemon. The license heartbeat thread runs alongside the existing idle timer.

**New thread in `llm_service.py`:**
```python
def _heartbeat_loop(self):
    """Every 10 min: POST /auth/heartbeat, update status file."""
    while self._running:
        try:
            from license.heartbeat import renew_token
            renew_token()
        except Exception:
            pass
        time.sleep(600)  # 10 minutes
```

**What this means:**
- If token expires: `is_pro_available()` returns False → regex_filter stops loading pro rules, NLP service stops accepting requests
- NLP service shuts down gracefully (no license = no pro detection needed)

### 4.2 — Create `license/` module (pro repo)

| File | Purpose |
|------|---------|
| `license/__init__.py` | Package init |
| `license/token.py` | Token parsing, signature verification (offline) |
| `license/heartbeat.py` | `renew_token()` — POST to license server, write status file |
| `license/cli.py` | `login`, `logout`, `status` commands |
| `license/config.py` | License server URL, token paths, timeouts |

**Token validation (offline, < 0.1ms):**
```python
def is_license_valid():
    status = read_json(STATUS_PATH)
    return status.get("status") == "valid"
```

### 4.3 — CLI entry point

**New:** `claude-privacy-hook` CLI (pro repo)

```bash
claude-privacy-hook login       # Authenticate, get token
claude-privacy-hook logout      # Destroy session
claude-privacy-hook status      # Show license info
claude-privacy-hook install-pro # Copy pro modules into .claude/hooks/
```

---

## Phase 5: Install Script Updates

### 5.1 — Free install (public repo)

`install_linux.sh` / `install_mac.sh` / `install_win.bat` are **simplified**. They install only the minimal NLP dependencies needed for the 3 free NLP filters (credit cards, IP addresses, prompt injection). No heavy ML packages (spaCy models, Presidio, transformers, torch).

**Free `requirements.txt`:**
```
# Minimal NLP for free tier (credit card, IP, prompt injection detection)
# Exact deps TBD — may use lightweight regex-based detection for CC/IP
# and the built-in prompt_injection_plugin (no external deps)
```

The free tier runs regex (#1-6) + minimal NLP (#12, #14, #22). No rate limiter. No full ML pipeline.

### 5.2 — Pro install (private repo)

New `install_pro.sh` in the pro repo:

1. Verify free repo is already installed (check for `.claude/hooks/regex_filter.py`)
2. Authenticate with license server (`claude-privacy-hook login`)
3. Install pro Python dependencies (`requirements_pro.txt`: spaCy, Presidio, transformers, torch)
4. Copy pro modules + rule files into `.claude/hooks/`
5. Copy NLP plugins into `.claude/hooks/plugins/`
6. Update `settings.json` to register NLP hooks
7. Create `config_overrides.json` template
8. Optionally install managed rules to `/etc/claude-code/` (requires sudo)
9. Start heartbeat (auto-starts with NLP service)

**Pro `requirements_pro.txt`:**
```
spacy>=3.5
presidio-analyzer>=2.2
presidio-anonymizer>=2.2
transformers>=4.30
torch>=2.0
```

### 5.3 — Uninstall pro

`claude-privacy-hook uninstall-pro`:
1. Remove pro modules, rule files, and plugins from `.claude/hooks/`
2. Restore `settings.json` to free-tier hooks only
3. Remove license token files
4. Keep free detection hooks intact (free tier continues working)
5. Optionally uninstall pro Python dependencies

---

## Phase 6: Test Suite Separation

### 6.1 — Tests that stay in free repo

| Suite | File | Tests | Reason |
|-------|------|-------|--------|
| Regex Filter | `test_regex_filter.py` | Free rules only | Tests 6 credential filters (#1-6) |
| Output Sanitizer | `test_output_sanitizer.py` | Free rules only | Tests API key, private key, credit card redaction |
| NLP Filter (Free) | `test_nlp_filter_free.py` (new) | Free NLP only | Tests credit card, IP address, prompt injection detection |
| Conftest Infrastructure | `test_conftest.py` | All | Shared test helpers |

**Modification needed:** Strip network, obfuscation, and compliance test cases from free test files. Keep only tests for the 9 free filters. Create new `test_nlp_filter_free.py` for free NLP subset.

### 6.2 — Tests that move to pro repo

| Suite | File | Reason |
|-------|------|--------|
| NLP Filter (Pro) | `test_nlp_filter_pro.py` | Pro NLP entity types (names, SSN, email, medical, etc.) |
| NLP Service (Pro) | `test_nlp_service.py` | NLP service with full pro config |
| Rate Limiter | `test_rate_limiter.py` | Rate limiter is pro (#38) |
| Overrides | `test_overrides.py` | Override system is pro |
| Pro Regex Rules | `test_regex_filter_pro.py` (new) | Tests network, obfuscation, compliance regex rules |
| Pro Output Sanitizer | `test_output_sanitizer_pro.py` (new) | Tests SSN, email, internal IP, DB string redaction |

### 6.3 — New tests needed

| Suite | What it tests |
|-------|---------------|
| `test_tier_check.py` | `is_pro_available()` with/without pro rule files, with/without valid license |
| `test_free_without_pro.py` | Full free pipeline works when pro files are absent (no ImportError, no crash) |
| `test_graceful_degradation.py` | Pro features degrade to free when token expires mid-session |
| `test_license.py` (pro repo) | Token parsing, heartbeat, login/logout, status file |
| `test_pro_rules_loading.py` | Pro rule files correctly merge into free rule engine |

---

## Phase 7: Documentation & License Updates

### 7.1 — Free repo (public, MIT)

- Update `LICENSE` from BSL 1.1 to MIT
- Update `README.md`: free vs pro comparison table showing filter split by regulation
- Update `CLAUDE.md`: reflect free-only filters and lightweight install
- Remove NLP-related documentation from free repo
- Add "Upgrade to Pro for compliance" section

### 7.2 — Pro repo (private, BSL 1.1)

- `LICENSE`: BSL 1.1 (already drafted)
- `README.md`: installation on top of free, compliance features, regulation mapping table
- `CLAUDE.md`: pro-specific commands, NLP pipeline, override system
- Compliance documentation: which regulations each filter addresses
- Override system docs (currently in `docs/configuration.md`) move to pro repo

---

## Implementation Order

| Step | What | Dependencies | Estimated Scope |
|------|------|-------------|----------------|
| | **Phase A — Split rule files by regulation** | | |
| 1 | Create `tier_check.py` with pro rule file detection | None | 1 new file (~40 lines) |
| 2 | Split `filter_rules.json` → free (#1-6 credentials) + `filter_rules_pro.json` (31 pro rules) | None | 2 JSON files |
| 3 | Split `filter_rules_write.json` → free + `filter_rules_write_pro.json` | None | 2 JSON files |
| 4 | Split `output_sanitizer_rules.json` → free + `output_sanitizer_rules_pro.json` | None | 2 JSON files |
| 5 | Modify `regex_filter.py` to auto-load `*_pro.json` when pro available | Step 1 | ~20 lines changed |
| 6 | Modify `output_sanitizer.py` to auto-load pro rules when available | Step 1 | ~15 lines changed |
| 7 | Create `llm_filter_config_free.json`, modify `llm_client.py` to select free/pro config | Step 1 | 1 new JSON + ~10 lines |
| 8 | Gate override system behind `is_pro_available()` | Step 1 | ~15 lines changed |
| 9 | Strip pro-only fields from free `audit_logger.py` | None | ~5 lines changed |
| 10 | Write `test_tier_check.py` + `test_free_without_pro.py` + `test_nlp_filter_free.py` | Steps 1-9 | 3 new test files |
| 11 | Run full test suite — verify free tier works standalone with 9 filters | Steps 1-10 | Validation only |
| | **Phase B — Isolate pro code into `pro/` directory** | | |
| 12 | Create `pro/` directory structure | Step 11 | Dirs only |
| 13 | Move pro NLP plugins + full config to `pro/` (keep NLP infra + prompt_injection in free) | Step 12 | File moves |
| 14 | Move override system to `pro/` | Step 12 | File moves |
| 15 | Move pro rule files to `pro/` | Step 12 | File moves |
| 16 | Move `filter_rules_read.json` to `pro/` | Step 12 | File move |
| 17 | Move `managed/` to `pro/` | Step 12 | Dir move |
| 18 | Move pro tests to `pro/tests/` | Step 12 | File moves |
| 19 | Update `tier_check.py` to find pro modules in `pro/` | Steps 13-17 | ~10 lines |
| 20 | Update `requirements.txt` to minimal NLP deps (CC/IP/injection only) | Step 13 | Reduce lines |
| 21 | Run full test suite — verify both tiers work from new locations | Step 20 | Validation only |
| | **Phase C — Build tamper resistance** | | |
| 22 | Generate Ed25519 keypair, embed public key | None | Key management |
| 23 | Create `pro/license/` module (token verification, heartbeat, CLI) | Step 22 | New package (~4 files) |
| 24 | Add `_enforce_license()` self-enforcement to pro modules | Steps 13-14, 23 | All pro .py files |
| 25 | Build pro manifest generation + verification | Step 22 | Build script + tier_check update |
| 26 | Set up Cython compilation for critical pro modules | Steps 13-14 | CI/build config |
| | **Phase D — Pro infrastructure** | | |
| 27 | Create `pro/hooks/audit_logger_pro.py` with regulation metadata | Step 12 | 1 new file |
| 28 | Add heartbeat thread to `llm_service.py` | Step 23 | ~20 lines |
| 29 | Create pro install script (`pro/install_pro.sh`) | Steps 12-26 | 1 new file |
| 30 | Simplify free install scripts (remove NLP deps) | Step 20 | Update 3 files |
| 31 | Write pro-specific tests (self-enforcement, token, manifest) | Steps 23-25 | New test files |
| | **Phase E — Finalize** | | |
| 32 | Update licenses (MIT for free, BSL 1.1 for pro) | Step 11 | 2 files |
| 33 | Update documentation (both tiers) | Steps 1-31 | Multiple files |
| 34 | Split `pro/` into separate private repo | Step 33 | `git filter-branch` or fresh repo |

**Phase A** (steps 1-11): Split rules by tier. Free tier works standalone with 9 highest-impact filters (including minimal NLP for credit cards, IPs, and prompt injection). Safe to do in the current repo.

**Phase B** (steps 12-21): Move pro code into `pro/` directory. Establishes the physical boundary. Full NLP plugin set, rate limiter, network rules, compliance rules, and governance features all move to pro. NLP infrastructure stays in free for the 3 free NLP filters.

**Phase C** (steps 22-26): Add cryptographic enforcement. Pro modules self-verify, tokens can't be forged, compiled modules resist reverse engineering.

**Phase D** (steps 27-31): Build new pro infrastructure (enhanced audit with regulation metadata, heartbeat, installer).

**Phase E** (steps 32-34): Final split. The `pro/` directory becomes the `claude-privacy-hook-pro` private repo.

---

## Key Difference from Original Plan

| Aspect | Original Plan | New Plan |
|--------|--------------|----------|
| **Guiding principle** | "Detection is free. Governance costs money." | "Protection is free. Compliance costs money." |
| **Free tier filters** | All 25 detection filters | 9 highest-impact filters |
| **Pro tier filters** | Governance only (overrides, managed, fleet) | 31 filters (network, PII, compliance, governance) |
| **NLP pipeline** | Free (all plugins) | Partially free (credit cards, IPs, prompt injection) — full pipeline is pro |
| **Free install size** | Large (spaCy, Presidio, torch) | Small (minimal NLP for CC/IP/injection) |
| **Free install time** | Minutes (downloading ML models) | Seconds (lightweight NLP) |
| **Conversion trigger** | Team needs override management | Developer needs network security or compliance coverage |
| **Revenue per filter** | $0 (all free) | ~$0.16/filter/user/month at $5/user |

**Advantages of the new split:**
1. **Focused free tier** — 9 highest-impact filters that every developer benefits from
2. **Clearer value proposition** — "free catches your leaked keys and credit cards, pro adds network security and compliance"
3. **Natural upgrade path** — first network allowlist need or compliance audit triggers upgrade
4. **More revenue surface** — 31 filters behind paywall vs just governance features
5. **Lighter free repo** — minimal NLP dependencies (only for credit card/IP/injection detection)

---

## Tamper Resistance: Preventing Free-to-Pro Bypass

### Threat Model

An attacker with local file access to the free installation attempts to gain pro features without a valid license. Attack vectors:

| Attack | Effort | What they'd get |
|--------|--------|-----------------|
| Modify `tier_check.py` to return `True` | Trivial | Nothing — no pro rule files or NLP code to load |
| Write fake `filter_rules_pro.json` | Low | Homebrew regex rules — not real compliance coverage |
| Write fake NLP plugins | Very High | Must reimplement Presidio/spaCy/DistilBERT pipeline |
| Create fake license status file | Trivial | Nothing — pro modules verify tokens independently |
| Modify `regex_filter.py` to skip tier checks | Medium | Can hardcode rules, but must maintain fork |
| Obtain pro code, drop into `.claude/hooks/` | Medium | Blocked by pro-side cryptographic enforcement |

### Defense Layers

#### Layer 1: Code Absence (primary defense)

Pro code does not exist in the free repo. Period.

After the repo split, the full NLP plugin set (Presidio, spaCy, DistilBERT, entropy detector, sensitive categories, semantic intent), pro rule files (`*_pro.json`), the full NLP config (`llm_filter_config.json`), rate limiter, `override_resolver.py`, `override_cli.py`, `audit_logger_pro.py`, `managed/`, `license/`, and `fleet/` are exclusively in the private `claude-privacy-hook-pro` repository.

The free repo retains the NLP infrastructure (`llm_service.py`, `llm_client.py`, `llm_filter.py`, `plugins/base.py`) and one plugin (`prompt_injection_plugin.py`) plus a minimal config (`llm_filter_config_free.json`) — but the full PII detection capability requires the pro plugins and config that do not exist in the free repo.

This is the strongest defense: **you cannot unlock code that does not exist.**

The full NLP pipeline is particularly hard to replicate — it requires specific plugin implementations (Presidio, spaCy, DistilBERT), model configurations, confidence thresholds, and entity type mappings that took significant effort to build and tune.

#### Layer 2: Pro-Side Self-Enforcement (cryptographic defense)

Pro modules do NOT rely on `tier_check.py` for enforcement. Each pro module verifies the license token independently at load time using cryptographic signatures.

**`tier_check.py` (free repo) is a convenience hint, not the gate.** It tells free hooks "don't bother trying to load pro rule files." The real enforcement lives inside the pro code itself.

```python
# llm_service.py (PRO REPO — self-enforcing)
from license.token import verify_token

_VERIFIED = False

def _enforce_license():
    global _VERIFIED
    if _VERIFIED:
        return True
    if not verify_token():
        return False
    _VERIFIED = True
    return True

def run_detection(text, config, hooks_dir):
    if not _enforce_license():
        return {"decision": "allow"}  # Silent fallback — no detection without valid license
    # ... actual NLP detection logic ...
```

#### Layer 3: Cryptographic Token Verification

The license token is a signed payload that can only be issued by the license server.

**Token structure:**
```
header.payload.signature
```

- **Payload**: JSON with `user_id`, `tier`, `machine_id`, `expires_at`, `session_id`
- **Signature**: Ed25519 signature of the payload using the server's private key
- **Verification**: Pro modules use the embedded public key to verify the signature offline

#### Layer 4: Module Integrity Manifest (drop-in defense)

Prevents using tampered pro files even if obtained legitimately.

Pro install creates `.claude/hooks/pro_manifest.json` with SHA256 hashes and Ed25519 signature of all pro files. `tier_check.py` verifies the manifest before reporting pro as available.

#### Layer 5: Compiled Distribution (reverse-engineering barrier)

Pro modules are distributed as compiled bytecode (Cython `.so`/`.pyd`). Critical modules (`llm_service.py`, `license/token.py`, NLP plugins) are compiled to C extensions.

### Combined Defense: Attack Scenarios

| Attack | Layer 1 | Layer 2 | Layer 3 | Layer 4 | Layer 5 | Result |
|--------|:-------:|:-------:|:-------:|:-------:|:-------:|--------|
| Edit `tier_check.py` → `return True` | Code absent | — | — | — | — | No pro code to import |
| Write fake NLP plugins | — | Self-enforce | No valid token | Manifest fails | — | Rejected |
| Create fake status file | Code absent | Self-enforce | Sig invalid | — | — | Rejected |
| Obtain real pro code, drop in | — | Self-enforce | Token expired | Manifest stale | Compiled | Rejected |
| Obtain pro + forge token | — | Self-enforce | Can't forge Ed25519 | — | — | Rejected |
| Decompile `.so`, patch out checks | — | — | — | Hash mismatch | High effort | Very hard |
| Full reverse-engineer from scratch | — | — | — | — | — | Legal violation (BSL 1.1) |

### Free-Repo-Side Enforcement Points

In addition to pro-side self-enforcement, the free repo code must actively prevent casual bypass:

#### 1. `llm_service.py` plugin loading — hardcoded free allowlist

```python
FREE_PLUGINS = {"prompt_injection"}  # Only free plugin

def load_plugin(name, plugin_configs, registry):
    if name not in FREE_PLUGINS:
        from tier_check import is_pro_available
        if not is_pro_available():
            return None  # Silently skip pro plugins in free tier
    # ... existing loading logic ...
```

Without this, a user can drop any plugin file into `plugins/`, register it in `plugins.json`, and it loads — no license required.

#### 2. `regex_filter.py` pro rule loading — manifest verification

```python
from tier_check import is_pro_available
if is_pro_available():
    pro_path = config_path.replace(".json", "_pro.json")
    if os.path.isfile(pro_path):
        if _verify_pro_manifest(hooks_dir, pro_path):
            pro_config = load_config(pro_path)
            config["rules"].extend(pro_config["rules"])
```

Manifest verification prevents casual drop-in of homebrew `filter_rules_pro.json`. Without it, any user can create a pro rule file and `tier_check` bypass gives them all pro regex patterns.

#### 3. Accept that regex patterns are NOT protectable

The pro value for regex rules is **maintenance** (keeping 400+ patterns current with new credential formats), not **secrecy**. A determined user can always append rules to the free `filter_rules.json` directly — `evaluate_rules()` iterates whatever is in the JSON with no rule-name validation. Attempting to prevent this adds complexity with no real security gain.

### What We Explicitly Do NOT Defend Against

- **User with valid license modifying their own pro code** — they paid, it's their prerogative
- **Nation-state level reverse engineering** — not our threat model
- **Someone writing their own NLP PII pipeline from scratch** — this is legal (clean-room), and the effort justifies buying a license
- **User manually appending regex patterns to free `filter_rules.json`** — regex patterns are not the pro value; maintenance is

---

## Risk Mitigations

| Risk | Mitigation |
|------|------------|
| Breaking free tier when removing pro code | Steps 1-11 build the gating layer first, test suite validates |
| Free tier feels crippled | Free tier has 9 highest-impact filters (6 credential types + credit cards + IPs + prompt injection). Genuinely useful for every developer. |
| Performance regression from `is_pro_available()` | Single file existence check (cached) + single file read (< 0.1ms) |
| Pro rule files accidentally committed to free repo | `.gitignore` in free repo excludes all `*_pro.json`, NLP files, override files, license files |
| Free users confused by "pro feature unavailable" | No messages shown. Free tier is silent — hooks just skip pro logic. No upsell in CLI output. |
| Free install breaks without full NLP deps | Free install includes only minimal NLP for credit card/IP/injection detection. `requirements.txt` has minimal deps. |
| Token file permissions | Status file at `/tmp/` with UID-specific name. Token file at `~/.claude/hooks/` with 600 permissions. |
| NLP service crash during heartbeat | Heartbeat is a separate thread with full exception handling. Service crash → auto-restart on next hook call. |
| Free code altered to bypass tier checks | Layer 1 (code absence) + Layer 2 (pro self-enforcement) + Layer 3 (crypto tokens) |
| Pro code obtained without license | Layer 2 (self-enforcement) + Layer 3 (Ed25519 signature) + Layer 4 (manifest) |
| Pro code reverse-engineered | Layer 5 (Cython compilation) + BSL 1.1 legal enforcement |
