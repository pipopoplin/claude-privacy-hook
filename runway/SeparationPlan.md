# Separation Plan — Free & Paid Tier Code Split

## Context & Decisions

All decisions referenced here are documented in [TODO.md](TODO.md) §15.

| Decision | Value |
|----------|-------|
| **Pricing** | Free (MIT, no account) + Paid ($5/month per seat, BSL 1.1) |
| **Repos** | `claude-privacy-hook` (free, public) + `claude-privacy-hook-pro` (paid, private) |
| **Free scope** | L1 regex only (9 filters), output sanitizer, rate limiter, audit logger, overrides for free features |
| **Paid scope** | All NLP features (primary paywall), managed layer, team/fleet overrides, enhanced audit |
| **Distribution** | Pro shipped as compiled binaries (.so/.pyd) only, never source |
| **Runtime** | Everything local. Server only for token issuance + heartbeat |
| **Self-validation** | S2 cross-module validation (compiled binaries hash each other) |
| **Degradation** | Pro always degrades to free tier on failure — never hard-blocks |
| **Future tiers** | Architecture must support adding tiers without structural changes |

---

## 1. Architectural Principle

```
Pro AUGMENTS Free. Free NEVER depends on Pro.

┌──────────────────────────────────────────────────┐
│  claude-privacy-hook (MIT, public)               │
│                                                  │
│  regex_filter ─── filter_rules.json (18 rules)   │
│  regex_filter ─── filter_rules_write.json        │
│  regex_filter ─── filter_rules_read.json         │
│  output_sanitizer ── output_sanitizer_rules.json │
│  rate_limiter ──── rate_limiter_config.json      │
│  audit_logger                                    │
│  hook_utils                                      │
│  override_resolver + override_cli (free scope)   │
│  config_overrides.json                           │
│                                                  │
│  settings.json (free hooks only)                 │
└────────────────────┬─────────────────────────────┘
                     │ Pro imports from Free
                     │ (hook_utils, audit_logger)
┌────────────────────▼─────────────────────────────┐
│  claude-privacy-hook-pro (BSL 1.1, private)      │
│                                                  │
│  llm_client ─── llm_filter ─── llm_service       │
│  llm_filter_config.json                          │
│  plugins/ (spacy, presidio, distilbert,          │
│    prompt_injection, sensitive_categories,        │
│    entropy_detector, semantic_intent)             │
│  filter_rules_pro.json (additional paid rules)   │
│  output_sanitizer_rules_pro.json                 │
│  audit_logger_pro (enhanced: SIEM, override log) │
│  override_resolver_pro + override_cli_pro        │
│    (team/fleet/managed overrides)                │
│  managed/ (IT deployment templates)              │
│  license/ (token, cli, heartbeat, config)        │
│  integrity/ (cross-module S2 validation)         │
│  install_pro.sh                                  │
│  generate_manifest.py                            │
│                                                  │
│  Compiled to .so/.pyd — source never shipped     │
└──────────────────────────────────────────────────┘
```

**Dependency direction is one-way:** Pro → Free. Never Free → Pro.

This means:
- Free repo works standalone. No pro code, no stubs, no imports from pro.
- Pro repo requires the free repo to be installed first.
- Pro adds its hooks alongside free hooks in settings.json.

---

## 2. File Inventory — What Goes Where

### 2.1 Free Repo (claude-privacy-hook)

These files **stay** in the free repo. No changes unless noted.

#### Core Hooks (keep as-is)
```
.claude/hooks/regex_filter.py              ← unchanged
.claude/hooks/filter_rules.json            ← 18 rules (incl. new SSN + credit card)
.claude/hooks/filter_rules_write.json      ← unchanged
.claude/hooks/filter_rules_read.json       ← unchanged
.claude/hooks/output_sanitizer.py          ← unchanged
.claude/hooks/output_sanitizer_rules.json  ← unchanged
.claude/hooks/rate_limiter.py              ← unchanged
.claude/hooks/rate_limiter_config.json     ← unchanged
.claude/hooks/audit_logger.py              ← unchanged
.claude/hooks/hook_utils.py                ← unchanged
.claude/hooks/config_overrides.json        ← unchanged (template)
```

#### Override System (MODIFY — scope to free features)
```
.claude/hooks/override_resolver.py         ← MODIFY: scope overrides to free-tier rules only
.claude/hooks/override_cli.py              ← MODIFY: scope CLI to free-tier rules only
```

Changes needed:
- `override_resolver.py`: Add a `FREE_TIER_RULES` set listing the rule names from free-tier
  configs. Reject overrides for rules not in the set. This is a whitelist, not a blacklist —
  future tiers add to the whitelist, they don't modify the free code.
- `override_cli.py`: Validate `--rule` against `FREE_TIER_RULES`. Show upgrade message if
  user tries to override a paid rule.

#### Settings (MODIFY — remove NLP hooks)
```
.claude/settings.json                      ← MODIFY: remove llm_client hook entry
```

Free settings.json should register:
1. PreToolUse: Bash → regex_filter (filter_rules.json)
2. PreToolUse: Bash → rate_limiter
3. PreToolUse: Write|Edit → regex_filter (filter_rules_write.json)
4. PreToolUse: Read → regex_filter (filter_rules_read.json)
5. PostToolUse: Bash → output_sanitizer

The llm_client/NLP hook entry is **removed** from free settings.json.

#### Files to REMOVE from Free Repo
```
.claude/hooks/llm_client.py               → MOVE to pro
.claude/hooks/llm_filter.py               → MOVE to pro
.claude/hooks/llm_service.py              → MOVE to pro
.claude/hooks/llm_filter_config.json      → MOVE to pro
.claude/hooks/plugins/                    → MOVE entire directory to pro
  base.py
  spacy_plugin.py
  presidio_plugin.py
  distilbert_plugin.py
  prompt_injection_plugin.py
  sensitive_categories_plugin.py
  entropy_detector_plugin.py
  semantic_intent_plugin.py
  plugins.json
  __init__.py
managed/                                  → MOVE to pro (IT deployment is paid feature)
  managed_rules.json
  managed_settings.json
  README.md
```

#### Tests (MODIFY — remove NLP test suites)
```
tests/test_regex_filter.py                ← keep (free)
tests/test_output_sanitizer.py            ← keep (free)
tests/test_rate_limiter.py                ← keep (free)
tests/test_overrides.py                   ← keep, MODIFY to test free-scope only
tests/test_conftest.py                    ← keep (infrastructure)
tests/conftest.py                         ← keep (infrastructure)
tests/run_all.py                          ← MODIFY: remove NLP test references

tests/test_nlp_filter.py                  → MOVE to pro
tests/test_nlp_service.py                 → MOVE to pro
```

#### Benchmarks (MODIFY — remove NLP benchmarks)
```
benchmarks/bench_regex_filter.py          ← keep
benchmarks/bench_output_sanitizer.py      ← keep
benchmarks/bench_rate_limiter.py          ← keep
benchmarks/bench_overrides.py             ← keep
benchmarks/bench_hook_utils.py            ← keep
benchmarks/bench_audit_logger.py          ← keep
benchmarks/run_all.py                     ← MODIFY: remove NLP benchmark references

benchmarks/bench_nlp_filter.py            → MOVE to pro
```

#### Install Scripts (MODIFY — core only)
```
install_linux.sh                          ← MODIFY: remove NLP dependencies (spaCy, etc.)
install_mac.sh                            ← MODIFY: remove NLP dependencies
install_win.bat                           ← MODIFY: remove NLP dependencies
requirements.txt                          ← MODIFY: remove NLP packages
```

Free requirements.txt should be empty or near-empty (stdlib only).
No spaCy, no presidio, no transformers, no torch.

#### Docs (MODIFY — reflect free tier)
```
docs/architecture.md                      ← MODIFY: describe free tier only, reference pro
docs/configuration.md                     ← MODIFY: free-tier config only
docs/plugins.md                           → MOVE to pro (plugins are paid)
docs/testing.md                           ← MODIFY: free tests only
docs/sequence-diagram.md                  ← MODIFY: free pipeline only
README.md                                 ← MODIFY: free/paid comparison table, upgrade CTA
CLAUDE.md                                 ← MODIFY: free tier architecture
LICENSE                                   ← REPLACE with MIT license
```

#### Runway (keep — planning docs)
```
runway/TODO.md                            ← keep
runway/SeparationPlan.md                  ← this file
```

### 2.2 Pro Repo (claude-privacy-hook-pro)

Everything below lives in the pro repo. Source code is compiled to .so/.pyd before distribution.

#### Directory Structure
```
claude-privacy-hook-pro/
├── hooks/
│   ├── llm_client.py                  ← thin client, talks to llm_service
│   ├── llm_filter.py                  ← standalone NLP hook (fallback)
│   ├── llm_service.py                 ← persistent TCP NLP service
│   ├── llm_filter_config.json         ← plugin config, thresholds
│   ├── filter_rules_pro.json          ← additional paid Bash rules
│   ├── filter_rules_write_pro.json    ← additional paid Write/Edit rules
│   ├── output_sanitizer_rules_pro.json ← additional paid redaction rules
│   ├── override_resolver_pro.py       ← team/fleet/managed override support
│   ├── override_cli_pro.py            ← pro override CLI (all scopes)
│   ├── audit_logger_pro.py            ← enhanced audit (override tracking, SIEM stubs)
│   ├── rate_limiter_pro.py            ← pro rate limiter (with license check)
│   ├── config_overrides.json          ← template for pro overrides
│   └── plugins/
│       ├── __init__.py
│       ├── base.py                    ← plugin ABC + DetectionResult
│       ├── spacy_plugin.py
│       ├── presidio_plugin.py
│       ├── distilbert_plugin.py
│       ├── prompt_injection_plugin.py
│       ├── sensitive_categories_plugin.py
│       ├── entropy_detector_plugin.py
│       ├── semantic_intent_plugin.py
│       └── plugins.json
├── license/
│   ├── __init__.py
│   ├── token.py                       ← Ed25519 token verification
│   ├── config.py                      ← server URL, paths, timeouts
│   ├── cli.py                         ← login, logout, status commands
│   └── heartbeat.py                   ← 10min renewal + integrity report
├── integrity/
│   ├── __init__.py
│   ├── validator.py                   ← S2 cross-module hashing logic
│   ├── module_map.json                ← which modules validate which
│   └── reporter.py                    ← build integrity report for heartbeat
├── managed/
│   ├── README.md
│   ├── managed_rules.json             ← 8 hard-deny IT rules
│   └── managed_settings.json          ← /etc/claude-code/hooks/ template
├── tests/
│   ├── test_nlp_filter.py
│   ├── test_nlp_service.py
│   ├── test_overrides.py              ← pro override tests
│   ├── test_rate_limiter.py           ← pro rate limiter tests
│   ├── test_license.py                ← token, heartbeat, CLI tests
│   ├── test_integrity.py              ← S2 cross-module validation tests
│   └── run_pro_tests.py
├── benchmarks/
│   └── bench_nlp_filter.py
├── install_pro.sh                     ← installs pro alongside free
├── generate_manifest.py               ← builds signed release manifest
├── requirements_pro.txt               ← spaCy, presidio, transformers, torch
├── LICENSE                            ← BSL 1.1
├── README.md                          ← pro documentation
└── CLAUDE.md                          ← pro-specific Claude Code guidance
```

---

## 3. Integration Point — How Pro Augments Free

### 3.1 Installation Flow

```
1. User has claude-privacy-hook (free) installed and working
2. User subscribes ($5/mo) → receives download token
3. Runs: install_pro.sh --hooks-dir /path/to/.claude/hooks
4. install_pro.sh:
   a. Verifies free tier is installed (checks for regex_filter.py)
   b. Downloads/copies compiled .so/.pyd binaries into .claude/hooks/pro/
   c. Installs NLP dependencies (spaCy, etc.) into existing venv
   d. Patches .claude/settings.json to add NLP hook entry (insert after regex_filter)
   e. Prompts: python3 -m pro.license.cli login
5. User logs in → token saved to ~/.claude/hooks/license_token
6. Pro hooks are now active alongside free hooks
```

### 3.2 settings.json — Combined (after pro install)

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/regex_filter.py \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/filter_rules.json",
            "timeout": 10
          }
        ]
      },
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/pro/llm_client.py \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/pro/llm_filter_config.json",
            "timeout": 30
          }
        ]
      },
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/rate_limiter.py \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/rate_limiter_config.json",
            "timeout": 5
          }
        ]
      },
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/regex_filter.py \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/filter_rules_write.json",
            "timeout": 10
          }
        ]
      },
      {
        "matcher": "Read",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/regex_filter.py \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/filter_rules_read.json",
            "timeout": 10
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/output_sanitizer.py \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/output_sanitizer_rules.json",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

Key: Pro hooks live under `.claude/hooks/pro/` subdirectory. Clean namespace separation.

### 3.3 Import Dependencies

Pro modules may import from free:
```python
# Pro modules can use these free-tier utilities:
from audit_logger import log_event          # shared audit logging
from hook_utils import normalize_unicode, resolve_field  # shared utilities
```

Pro modules must NEVER be imported by free modules. The free repo has zero knowledge of pro.

### 3.4 Override System Integration

| Scope | Free | Pro |
|-------|------|-----|
| **User overrides** (`~/.claude/hooks/config_overrides.json`) | Free rules only | All rules |
| **Project overrides** (`.claude/hooks/config_overrides.json`) | Free rules only | All rules |
| **Managed overrides** (`/etc/claude-code/hooks/`) | N/A | Pro only |
| **Fleet overrides** (central config server) | N/A | Pro only (future) |

Implementation:
- Free `override_resolver.py` has a `FREE_TIER_RULES` whitelist. Only processes overrides
  matching those rules.
- Pro `override_resolver_pro.py` extends free resolver. Removes the whitelist restriction.
  Adds managed + fleet override sources.

---

## 4. Tier Abstraction — Future Extensibility

Design the tier system so additional tiers (e.g., Team, Enterprise) are a **config change**, not a structural change.

### 4.1 Tier Definition

```python
# license/tiers.py (pro repo)
TIERS = {
    "free":       {"level": 0, "features": ["regex", "output_sanitizer", "rate_limiter", "audit_basic", "override_free"]},
    "paid":       {"level": 1, "features": ["regex", "output_sanitizer", "rate_limiter", "audit_basic", "override_free",
                                             "nlp", "plugins", "override_all", "managed", "audit_enhanced"]},
    # Future tiers — uncomment when ready:
    # "team":     {"level": 2, "features": [..., "fleet_overrides", "central_audit", "siem"]},
    # "enterprise": {"level": 3, "features": [..., "custom_plugins", "air_gap", "on_prem_server"]},
}
```

### 4.2 Feature Gating

```python
# license/gate.py (pro repo)
def has_feature(feature: str) -> bool:
    """Check if current license tier includes the given feature."""
    tier = get_current_tier()  # reads token → extracts tier field
    return feature in TIERS.get(tier, TIERS["free"])["features"]
```

Pro modules call `has_feature("nlp")` before executing. This pattern means:
- Adding a new tier = add entry to `TIERS` dict + new token tier value on server
- Adding a new feature = add to relevant tier feature lists
- No structural code changes needed

### 4.3 Token Tier Field

```json
{
  "user_id": "usr_abc123",
  "tier": "paid",
  "org": "org_xyz",
  "machine_id": "hmac:...",
  "session_id": "sess_...",
  "expires_at": "2026-03-13T17:00:00Z",
  "features": ["nlp", "plugins", "override_all", "managed", "audit_enhanced"],
  "signature": "ed25519:..."
}
```

The `features` array in the token allows the server to grant fine-grained access
without changing client code. Future tiers just get different feature arrays.

---

## 5. Graceful Degradation

Pro must **never** break the developer's workflow. Every failure mode degrades to free tier.

| Scenario | Behavior |
|----------|----------|
| No token file | NLP hooks skip silently, free hooks run normally |
| Token expired (offline >3h) | NLP hooks skip, log "Pro license expired — running in free mode" |
| Token signature invalid | NLP hooks skip, log warning, heartbeat reports anomaly |
| Pro binary missing/corrupted | Hook exits 0 (allow), free hooks still protect |
| NLP service crash | llm_client falls back to direct llm_filter; if that fails, exits 0 |
| License server unreachable | Token valid until 3h expiry, then degrade |

Implementation: every pro hook entry point wraps execution in:
```python
try:
    if not verify_license():
        sys.exit(0)  # allow — degrade to free tier
    # ... pro logic ...
except Exception:
    sys.exit(0)  # allow — never block on pro failure
```

---

## 6. Upgrade Messaging

When a free-tier user encounters something that pro would catch, show a helpful message.

### 6.1 Where to Show Upgrade Messages

The free repo itself does NOT show upgrade messages (it has no knowledge of pro).
Instead, the upgrade messaging comes from the **pro installer's one-time setup** or
from a lightweight **upgrade_hint.py** script that pro installs into the free hooks directory.

Option: Pro installer places a `upgrade_hint.py` in `.claude/hooks/` that:
- Registers as a low-priority PostToolUse hook
- On each Bash command, checks if the command contained patterns that NLP would catch
  (person names, medical data, etc.) using simple heuristics
- If detected, appends a one-line hint: "Pro tip: NLP filter would catch PII like names
  and medical data. See: upgrade-url"
- Rate-limited: max 1 hint per session

This keeps the free repo clean while still driving conversion after pro trial expires.

---

## 7. Execution Order — Step by Step

### Phase 1: Prepare Free Repo

```
Step 1.1  Create feature branch: feature/free-tier-separation
Step 1.2  Remove NLP files from free repo:
          - Delete: llm_client.py, llm_filter.py, llm_service.py, llm_filter_config.json
          - Delete: plugins/ directory entirely
          - Delete: managed/ directory
Step 1.3  Update .claude/settings.json: remove NLP hook entry
Step 1.4  Update override_resolver.py: add FREE_TIER_RULES whitelist
Step 1.5  Update override_cli.py: validate against FREE_TIER_RULES
Step 1.6  Update requirements.txt: remove NLP packages
Step 1.7  Update install scripts: remove NLP install steps, add --core-only mode
Step 1.8  Update tests/run_all.py: remove NLP test references
Step 1.9  Move test_nlp_filter.py, test_nlp_service.py to archive (or delete)
Step 1.10 Move benchmarks/bench_nlp_filter.py to archive (or delete)
Step 1.11 Update README.md: free/paid comparison table, link to pro
Step 1.12 Update CLAUDE.md: free tier architecture only
Step 1.13 Replace LICENSE with MIT license text
Step 1.14 Run free-tier tests: verify 518 regex + output + rate limiter + override tests pass
Step 1.15 Update docs/: architecture, configuration, testing (remove NLP references)
```

### Phase 2: Build Pro Repo

```
Step 2.1  Create clean branch in claude-privacy-hook-pro: feature/pro-tier-v1
Step 2.2  Set up directory structure (hooks/, license/, integrity/, managed/, etc.)
Step 2.3  Copy NLP files from free repo (pre-separation snapshot):
          - llm_client.py, llm_filter.py, llm_service.py, llm_filter_config.json
          - plugins/ directory
Step 2.4  Create pro-specific rule configs:
          - filter_rules_pro.json (additional paid Bash rules)
          - filter_rules_write_pro.json (additional paid Write rules)
          - output_sanitizer_rules_pro.json (additional paid redaction rules)
Step 2.5  Create override_resolver_pro.py (extends free, removes whitelist, adds managed)
Step 2.6  Create override_cli_pro.py (all scopes, license enforcement)
Step 2.7  Create audit_logger_pro.py (enhanced: override tracking, SIEM stubs)
Step 2.8  Implement license/ module:
          - token.py (Ed25519 verification)
          - config.py (server URL, paths)
          - cli.py (login, logout, status)
          - heartbeat.py (10min renewal + integrity report)
Step 2.9  Implement integrity/ module:
          - validator.py (S2 cross-module hashing)
          - module_map.json
          - reporter.py (build integrity report)
Step 2.10 Implement tier abstraction (license/tiers.py, license/gate.py)
Step 2.11 Create install_pro.sh (installs alongside free, patches settings.json)
Step 2.12 Create generate_manifest.py (signed release manifest)
Step 2.13 Set up pro tests (NLP, overrides, rate limiter, license, integrity)
Step 2.14 Set up pro benchmarks
Step 2.15 Create requirements_pro.txt (spaCy, presidio, transformers, etc.)
Step 2.16 Write pro README.md and CLAUDE.md
Step 2.17 Verify BSL 1.1 LICENSE is in place
Step 2.18 Run full pro test suite
```

### Phase 3: Compilation & Distribution

```
Step 3.1  Choose compilation tool (Cython vs Nuitka) — benchmark both
Step 3.2  Create build script: compile all .py in hooks/, license/, integrity/ → .so/.pyd
Step 3.3  Set up CI/CD for multi-platform builds (Linux x86_64, macOS arm64, Windows x86_64)
Step 3.4  Create release manifest (generate_manifest.py) for each build
Step 3.5  Set up distribution channel (private PyPI or direct download)
Step 3.6  Test compiled binaries end-to-end on each platform
Step 3.7  Verify cross-module S2 validation works with compiled binaries
```

### Phase 4: Integration Testing

```
Step 4.1  Fresh machine: install free only → verify all free tests pass
Step 4.2  Same machine: install pro alongside free → verify combined pipeline works
Step 4.3  Revoke token → verify graceful degradation (NLP skips, free continues)
Step 4.4  Expire token (offline >3h) → verify degradation
Step 4.5  Remove pro files → verify free tier continues working
Step 4.6  Test upgrade path: free → pro (install_pro.sh modifies settings.json correctly)
Step 4.7  Test downgrade path: pro → free (uninstall pro, revert settings.json)
Step 4.8  Test cross-module validation: tamper with one binary → verify heartbeat reports mismatch
```

---

## 8. Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| Free repo accidentally includes NLP imports | Pro features leaked for free | CI check: grep for NLP imports in free repo, fail build if found |
| Pro settings.json patch breaks free hooks | User locked out | install_pro.sh backs up settings.json before patching; rollback on failure |
| Compiled binary incompatible across Python versions | Pro broken on update | Pin Python version in pro; build for 3.11 and 3.12 |
| Override whitelist too restrictive | Free users frustrated | Whitelist matches ALL free-tier rule names; test coverage required |
| Future tier breaks existing tier | Paid users disrupted | Tier level is additive (higher level = superset of lower); never remove features |
| Token contains future-tier features client doesn't know | Silent failure | Client ignores unknown features; `has_feature()` returns False for unknown |

---

## 9. Validation Checklist

Before declaring separation complete:

- [ ] Free repo has zero NLP imports (automated CI check)
- [ ] Free repo has zero references to `license/`, `integrity/`, `managed/`
- [ ] Free repo `settings.json` has no NLP hook entries
- [ ] Free repo tests pass standalone (no pro dependencies)
- [ ] Free repo installs and works on a clean machine with no NLP packages
- [ ] Pro repo compiles to .so/.pyd on Linux, macOS, Windows
- [ ] Pro repo installs alongside free without breaking free hooks
- [ ] Pro hooks degrade gracefully on every failure mode (table in §5)
- [ ] Cross-module S2 validation reports correct hashes on heartbeat
- [ ] Override whitelist covers exactly the 18 free-tier rules + output sanitizer + rate limiter
- [ ] MIT license in free repo, BSL 1.1 in pro repo
- [ ] README.md in free repo has clear free/paid comparison and upgrade path
