# Licensing & Monetization — TODO
# Status: [ ] = open, [x] = done, [~] = in progress

---

## Remaining: Planning

[x] Define pricing tiers
    - Free: $0, open source, 9 highest-impact filters, no account needed
    - Pro: $5/user/month or $49/user/year (2 months free), all 40 filters (31 additional) + governance, requires login
[x] Define trial period: 14 days (full Pro features, no payment required, token expires after 14 days)
[x] Define support tiers
    - Free + Pro: community support via GitHub Issues on the public repo
    - Paid support: custom engagements booked by contacting the Licensor directly
[x] How to handle community contributions to paid features? (must be evaluated and approved by the Licensor)
[ ] Legal review of dual-license compatibility (MIT + BSL 1.1)
[ ] What analytics/telemetry (if any) to measure conversion?
[ ] Validate customer profiles with real user interviews or feedback

## Remaining: Implementation

### Phase A — Split rule files by tier
[ ] Create `tier_check.py` with pro rule file detection
[ ] Split `filter_rules.json` → free (#1-6 credentials + #22 prompt injection = 2 rules) + `filter_rules_pro.json` (14 pro rules)
    - CRITICAL: `block_sensitive_data` must be split at PATTERN level (17 free patterns, ~14 pro patterns)
    - Pro `allow_trusted_endpoints` MUST come before `block_untrusted_network` (first match wins)
[ ] Split `filter_rules_write.json` → free (5 rules, trimmed patterns) + `filter_rules_write_pro.json` (5 rules)
    - `block_api_keys_in_content` and `block_api_keys_in_edit` need pattern-level split (same as block_sensitive_data)
    - `block_api_keys_in_edit` mixes SSN + CC + IP patterns — must decompose
[ ] Split `output_sanitizer_rules.json` → free (3 rules: API keys trimmed, credit cards, private keys) + pro (5 rules)
    - `redact_api_keys` needs pattern-level split matching block_sensitive_data split
[ ] Move `filter_rules_read.json` entirely to pro (#23 GDPR Art.32)
[ ] Modify `regex_filter.py` to auto-load `*_pro.json` with manifest verification when pro is available
[ ] Modify `output_sanitizer.py` to auto-load pro rules when available
[ ] Create `llm_filter_config_free.json` (prompt injection only, entity_types: ["PROMPT_INJECTION"])
[ ] Shrink free `plugins/plugins.json` to prompt_injection only
[ ] Add FREE_PLUGINS allowlist to `llm_service.py` plugin loading (block non-free plugins without license)
[ ] Update free `settings.json`: remove rate_limiter + Read hooks, change NLP config to free
[ ] Update free `requirements.txt`: remove all NLP deps (stdlib only)
[ ] Write `test_tier_check.py` + `test_free_without_pro.py` + `test_nlp_filter_free.py`
[ ] Run full test suite — verify free tier works standalone with 9 filters

### Phase B — Isolate pro code into `pro/` directory
[ ] Create `pro/` directory structure (hooks/, plugins/, managed/, tests/, license/, fleet/, compliance/)
[ ] Move pro NLP plugins to `pro/` (presidio, distilbert, spacy, entropy_detector, sensitive_categories, semantic_intent)
[ ] Move full NLP config to `pro/` (llm_filter_config.json → pro/hooks/)
[ ] Move rate limiter to `pro/` (rate_limiter.py, rate_limiter_config.json)
[ ] Move override system to `pro/` (override_resolver, override_cli, config_overrides)
[ ] Move pro rule files to `pro/` (filter_rules_pro, filter_rules_write_pro, filter_rules_read, output_sanitizer_rules_pro)
[ ] Move `managed/` to `pro/managed/`
[ ] Move pro tests to `pro/tests/` (test_nlp_filter_pro, test_nlp_service, test_rate_limiter, test_overrides)
[ ] Keep NLP infra in free: llm_client.py, llm_service.py, llm_filter.py, plugins/base.py, prompt_injection_plugin.py
[ ] Update `tier_check.py` to find pro modules in `pro/`
[ ] Update `requirements.txt` to minimal NLP deps (credit card/IP/injection detection only)
[ ] Run full test suite — verify both tiers work from new locations

### Phase C — Build tamper resistance
[ ] Generate Ed25519 keypair, embed public key in `tier_check.py` + pro code
[ ] Create `pro/license/` module (token verification, heartbeat, CLI)
[ ] Add `_enforce_license()` self-enforcement to every pro module
[ ] Build pro manifest generation + verification in `tier_check.py`
[ ] Set up Cython compilation for critical pro modules (llm_service, license/token, NLP plugins)

### Phase D — Pro infrastructure
[ ] Create `pro/hooks/audit_logger_pro.py` with regulation metadata in events
[ ] Add heartbeat thread to `llm_service.py`
[ ] Create pro install script (`pro/install_pro.sh`)
[ ] Simplify free install scripts (minimal NLP deps for CC/IP/injection, faster install)
[ ] Write pro-specific tests (self-enforcement, token, manifest, pro rule loading)

### Phase E — Finalize
[ ] Draft MIT license text for free repo
[ ] Draft BSL 1.1 license text for pro repo
[ ] Update version string from v0.0.1-alpha
[ ] Set up free tier as public open-source repo
[ ] Set up paid tier distribution (private repo, license server, or package registry)
[ ] Set up payment processing (Stripe, Paddle, or LemonSqueezy)
[ ] Create subscription management portal
[ ] Build license server (login, heartbeat, logout, status endpoints)
[ ] Update README.md with free vs paid comparison table (filter split by regulation)
[ ] Create LICENSING.md explaining both tiers
[ ] Update CLAUDE.md to reflect free/paid split
[ ] Update settings.json to reflect free vs paid hooks
[ ] Update .gitignore for paid-tier artifacts
[ ] Create landing page content (value proposition per profile)
[ ] Write upgrade path documentation (free -> paid migration)
[ ] Create blog post: "Why we open-sourced our core security hooks"
[ ] Create sales collateral for enterprise outreach
[ ] Build compliance report templates (SOC 2, GDPR, HIPAA) for pro tier
[ ] Build SIEM integration (Splunk, Datadog, Elastic) for pro tier
[ ] Build fleet deployment templates (Ansible/MDM/Chef) for pro tier
[ ] Split `pro/` into separate private repo

---

## Completed

### 1. Customer Profiles — [CustomerProfiles.md](CustomerProfiles.md)
[x] Define customer profiles (6 profiles identified)
    - Profile 1: Solo Developer / Freelancer (free tier, viral loop)
    - Profile 2: Tech Lead / Small Team (2-15 devs, $50-200/mo)
    - Profile 3: Engineering Manager / Platform Team (15-100 devs, $500-2,000/mo)
    - Profile 4: CISO / Security Team (100-5,000+ devs, $2,000-10,000+/mo)
    - Profile 5: Regulated Industry Developer (compliance-driven budget)
    - Profile 6: Airgapped / High-Security Environment (high budget, slow procurement)
[x] Map conversion funnel (solo dev -> team -> org -> enterprise)

### 2. Use Case Ranking — [UseCaseRanking.md](UseCaseRanking.md)
[x] Identify all 25 use cases (expanded to 40 filters in compliance table)
[x] Rank by value (Tier 1-4)
[x] Map use cases to hooks, plugins, and regulations

### 3. Free vs Paid Feature Split — [SeparationPlan.md](SeparationPlan.md)
[x] ~~Define tiers: Free (all detection, no account) and Pro (adds governance, requires login)~~ **SUPERSEDED**
[x] ~~Define free tier: all detection — regex, NLP, plugins, output sanitizer, rate limiter, audit log~~ **SUPERSEDED**
[x] ~~Define pro tier: governance — overrides, managed rules, central audit, compliance, SIEM, fleet~~ **SUPERSEDED**
[x] ~~Identify conversion wall: "Detection is free. Governance costs money."~~ **SUPERSEDED**
[x] ~~Define tiers: Free (16 non-regulation filters) and Pro (24 regulation-mapped filters + governance)~~ **SUPERSEDED**
[x] ~~Define free tier: credential detection, network exfiltration, obfuscation — no regulatory mapping~~ **SUPERSEDED**
[x] ~~Define pro tier: PII/NLP detection (GDPR), health data (HIPAA), cardholder data (PCI-DSS), injection (OWASP) + governance~~ **SUPERSEDED**
[x] **FINAL** Define tiers: Free (9 highest-impact filters) and Pro (all 40 filters = 9 free + 31 additional + governance)
[x] **FINAL** Define free tier: 6 credential filters (#1-6) + credit cards (#12) + IP addresses (#14) + prompt injection (#22)
[x] **FINAL** Define pro tier: network security, full PII/NLP, compliance controls, rate limiter, governance + all free filters
[x] **FINAL** Identify conversion wall: "Protection is free. Compliance costs money."
[x] **FINAL** Ensure free tier is genuinely useful (9 highest-impact filters, includes minimal NLP for CC/IP/injection)
[x] **FINAL** Map all 40 filters to free/pro by Score×Hook analysis + manual override

### 4. Licensing Structure — see also [EnforcementModel.md](EnforcementModel.md)
[x] Choose license for free tier: MIT
[x] Choose license for paid tier: BSL 1.1
[x] Decide: two repos — free (public, MIT) + pro (private, BSL 1.1)
[x] Decide repo structure: two repos (claude-privacy-hook + claude-privacy-hook-pro)
[x] Check dependency license compatibility — all compatible (spaCy=MIT, Presidio=MIT, transformers=Apache 2.0, PyTorch=BSD)
[x] Decide: BSL 1.1 stays for paid tier
[x] **FINAL** Full NLP deps (spaCy, Presidio, transformers, torch) move to pro `requirements_pro.txt`. Free keeps minimal NLP deps for CC/IP/injection.

### 5. Enforcement Activity Diagrams — [EnforcementActivityDiagram.md](EnforcementActivityDiagram.md)
[x] Installation flow (free vs pro package, license key validation)
[x] Runtime enforcement flow (free path vs team path vs enterprise path)
[x] License validation flow (key decode, signature, expiry, scope check)
[x] Audit trail enforcement by tier (local vs central vs fleet + SIEM)
[x] Override enforcement by tier (free=edit JSON, team/enterprise=CLI + shared config)

### 6. Token Management — [TokenManagement.md](TokenManagement.md)
[x] Define token properties (3h validity, 10min heartbeat)
[x] Define login flow (authenticate → session → signed token)
[x] Define token contents (user, tier, org, machine_id, session_id, expiry, signature)
[x] Define heartbeat lifecycle (NLP service runs check every 10 min)
[x] Define license status file (shared between heartbeat and hooks)
[x] Define device switch behavior (stale session, token expires ≤3h)
[x] Define graceful degradation (pro → free tier fallback, never hard-fail)
[x] Define multi-seat model (N seats per org, reject on overflow)
[x] Define CLI commands (login, status, logout)
[x] Define license server endpoints (login, heartbeat, logout, status)
[x] Add license check mechanism: session-based token

### 7. Resolved Open Questions
[x] ~~Should the NLP plugins be the primary paywall? — No. All detection is free.~~ **SUPERSEDED**
[x] ~~Should the NLP plugins be the primary paywall? — Yes. NLP detects regulation-mapped PII (GDPR/HIPAA/PCI-DSS). NLP is pro.~~ **SUPERSEDED**
[x] **FINAL** Should the NLP plugins be the primary paywall? — Partially. Full NLP plugin set is pro. Minimal NLP (credit cards, IPs, prompt injection) is free.
[x] Should override system be free for personal use, paid for team use? — Paid for all. It's governance.
[x] Should managed layer be a separate enterprise add-on? — No enterprise tier. Managed is in Pro.
[x] How to prevent paid features from being trivially extracted? — Two repos. Paid code never published. NLP pipeline is hard to replicate.

### 8. Current License Status
[x] Current license: Business Source License 1.1 (BSL 1.1)
[x] Licensor: Shahead
[x] Licensed Work: claude-privacy-hook v0.0.1-alpha
[x] Change Date: 2030-03-10 (converts to Apache 2.0)
