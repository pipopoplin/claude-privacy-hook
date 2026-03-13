# Licensing & Monetization — TODO
# Status: [ ] = open, [x] = done, [~] = in progress

## 1. Customer Profiles — [CustomerProfiles.md](CustomerProfiles.md)
[x] Define customer profiles (6 profiles identified)
    - Profile 1: Solo Developer / Freelancer (free tier, viral loop)
    - Profile 2: Tech Lead / Small Team (2-15 devs, $50-200/mo)
    - Profile 3: Engineering Manager / Platform Team (15-100 devs, $500-2,000/mo)
    - Profile 4: CISO / Security Team (100-5,000+ devs, $2,000-10,000+/mo)
    - Profile 5: Regulated Industry Developer (compliance-driven budget)
    - Profile 6: Airgapped / High-Security Environment (high budget, slow procurement)
[x] Map conversion funnel (solo dev -> team -> org -> enterprise)
[ ] Validate profiles with real user interviews or feedback

## 2. Use Case Ranking — [UseCaseRanking.md](UseCaseRanking.md)
[x] Identify all 25 use cases
[x] Rank by value (Tier 1-4)
[x] Map use cases to hooks, plugins, and regulations
[~] Decide which use cases belong in free vs paid tier (draft in EnforcementModel.md)

## 3. Free vs Paid Feature Split — [EnforcementModel.md](EnforcementModel.md)
[x] Define tier-scope mapping (Free=Repo/User, Team=Computer, Enterprise=Fleet)
[x] Define free tier (regex_filter, output_sanitizer, rate_limiter, audit_logger, hook_utils)
[x] Define paid tier (NLP filter, plugins, overrides, managed layer, compliance reporting)
[x] Identify the "hook" — free regex catches 80%, NLP paywall at "missed a real name"
[x] Identify conversion walls (overrides at team boundary, managed at org boundary)
[x] Ensure free tier is genuinely useful (all 16 regex rules, output redaction, rate limiting)

## 4. Licensing Structure — see also [EnforcementModel.md](EnforcementModel.md)
[x] Choose license for free tier: MIT (open source, builds trust)
[x] Choose license for paid tier: BSL 1.1
[x] Decide: dual-repo (claude-privacy-hook MIT + claude-privacy-hook-pro BSL 1.1)
[x] Define pricing tiers
    - Free: open source, no account needed
    - Paid: $5/month per seat (requires login + token)
[ ] Draft license text for both tiers
[ ] Legal review of dual-license compatibility
[ ] Check dependency license compatibility (spaCy=MIT, Presidio=MIT, transformers=Apache 2.0)

## 5. Enforcement Activity Diagrams — [EnforcementActivityDiagram.md](EnforcementActivityDiagram.md)
[x] Installation flow (free vs pro package, license key validation)
[x] Runtime enforcement flow (free path vs team path vs enterprise path)
[x] License validation flow (key decode, signature, expiry, scope check)
[x] Audit trail enforcement by tier (local vs central vs fleet + SIEM)
[x] Override enforcement by tier (free=edit JSON, team/enterprise=CLI + shared config)

## 6. Token Management — [TokenManagement.md](TokenManagement.md)
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

## 7. Repository & Distribution — see also [EnforcementModel.md](EnforcementModel.md)
[x] Repo structure decided: dual-repo
    - claude-privacy-hook (MIT) — free tier, public open-source
    - claude-privacy-hook-pro (BSL 1.1) — paid tier
[x] Set up free tier as public open-source repo
[x] Set up paid tier distribution (separate repo, BSL 1.1)
[ ] Update .gitignore for any paid-tier artifacts
[ ] Update install scripts to handle free vs paid installation

## 8. Code Changes
[ ] Separate free and paid code paths
[ ] Add license check mechanism for paid features (if mono-repo)
[ ] Ensure free tier works standalone without paid components
[ ] Add graceful degradation (paid feature unavailable -> clear upgrade message)
[ ] Update settings.json to reflect free vs paid hooks

## 9. Documentation & Marketing
[ ] Update README.md with free vs paid comparison table
[ ] Create LICENSING.md explaining both tiers
[ ] Update CLAUDE.md to reflect free/paid split
[ ] Create landing page content (value proposition per profile)
[ ] Write upgrade path documentation (free -> paid migration)
[ ] Create blog post: "Why we open-sourced our core security hooks"

## 10. Business Operations
[ ] Set up payment processing (Stripe, Paddle, or LemonSqueezy)
[ ] Create subscription management portal
[ ] Define trial period (14 days? 30 days?)
[ ] Set up license key generation and validation
[ ] Define support tiers (community vs paid support)
[ ] Create sales collateral for enterprise outreach

## 11. Current License Status
[x] Current license: Business Source License 1.1 (BSL 1.1)
[x] Licensor: Shahead
[x] Licensed Work: claude-privacy-hook v0.0.1-alpha
[x] Change Date: 2030-03-10 (converts to Apache 2.0)
[ ] Update version string from v0.0.1-alpha
[x] BSL 1.1 confirmed for paid tier (claude-privacy-hook-pro)

## 12. Code Protection Strategy

### Layer 1: Distribution Protection — DECIDED
[x] A3: Compiled distribution (Cython/Nuitka → .so/.pyd binaries)
    - Pro repo source code is never distributed
    - Users receive compiled binaries only
    - Platform-specific builds required (Linux, macOS, Windows)
    [ ] Choose compilation tool (Cython vs Nuitka)
    [ ] Set up CI/CD pipeline for multi-platform builds
    [ ] Define distribution channel (private PyPI, direct download, or installer)

### Layer 2 + 3: Runtime Protection & Self-Validation — DECIDED
    Core principle: EVERYTHING runs locally. Server is only for token issuance.
    Software validates its own integrity and reports status back to server.
[x] Choose self-validation strategy: S2 (cross-module validation) for launch
    [ ] Implement cross-module hashing in compiled binaries
    [ ] Define module dependency map (which modules validate which)
    [ ] Implement heartbeat integrity report (POST to server)
    [ ] Implement server-side manifest comparison + response actions
    [ ] Define version upgrade strategy (atomic module updates)
[ ] S3 (runtime behavior attestation) — BACKLOG, future enhancement

### Layer 4: Legal Protection — ALL THREE
[ ] D1: BSL 1.1 — already in place for pro repo
    [ ] Draft final BSL 1.1 license text for pro tier
    [ ] Legal review of BSL 1.1 + MIT dual-license compatibility
[ ] D2: Terms of Service
    [ ] Draft ToS prohibiting redistribution, reverse engineering, token sharing
    [ ] Account-level ToS acceptance on signup/login
    [ ] Legal review of ToS
[ ] D3: Audit trail for leak tracing
    [ ] Token embeds user_id + org_id in every audit log entry
    [ ] If leaked compiled code surfaces, token trace identifies source
    [ ] Define leak response procedure

## 13. Runtime Protection & Self-Validation (Layer 2+3)

### Core Architecture
    - Both free and paid tiers run 100% locally on the user's machine
    - Server contact is ONLY for: (1) login → get token, (2) heartbeat → renew token + report
    - No user code ever leaves the machine
    - Token valid 3h, hardware-bound (machine_id)

### Self-Validation Concept
    The compiled pro binaries validate their own integrity at runtime and report
    status back to the server on heartbeat. This merges runtime protection (Layer 2)
    and tamper detection (Layer 3) into one unified flow.

    Flow:
    1. User logs in → server issues Ed25519-signed token (3h, machine-bound)
    2. On each pro hook invocation:
       a. Module reads token from ~/.claude/hooks/license_token
       b. Verifies Ed25519 signature + expiry + machine_id locally (no server call)
       c. If valid → pro features execute
       d. If invalid/missing/expired → degrade to free tier (never hard-fail)
    3. Background heartbeat (every 10min):
       a. Pro binaries compute their own integrity hashes (SHA-256)
       b. Heartbeat POST sends: token, machine_id, version, integrity_report
       c. Server compares hashes against known-good manifest for that version
       d. Server responds with: renewed token (or revocation)
    4. If heartbeat fails (offline):
       a. Grace period: token stays valid until 3h expiry
       b. After expiry without renewal: degrade to free tier

### Self-Validation Options — choose depth:

### Option S1: Binary self-hash (lightweight)
    Each .so module hashes itself at startup, stores in memory.
    On heartbeat, all hashes sent to server.
    Server checks against release manifest.

    Integrity report:
    {
      "version": "1.2.0",
      "modules": {
        "llm_filter_pro.so": "sha256:a1b2c3...",
        "override_resolver_pro.so": "sha256:d4e5f6...",
        "audit_logger_pro.so": "sha256:g7h8i9..."
      },
      "machine_id": "hmac:...",
      "timestamp": "2026-03-13T14:00:00Z"
    }

    + Simple, fast (~1ms total for all modules)
    + Detects file replacement / patching of compiled binaries
    - Module hashing itself can be patched out (attacker replaces binary + fakes hash)
    - Only checks at heartbeat intervals (10min gap)

### Option S2: Cross-module validation (strong)
    Each .so module hashes OTHER modules, not just itself.
    Module A hashes B and C, module B hashes A and C, etc.
    No single module can be replaced without others detecting it.

    Integrity report:
    {
      "version": "1.2.0",
      "reporters": {
        "llm_filter_pro.so": {
          "self": "sha256:a1b2c3...",
          "observed": {
            "override_resolver_pro.so": "sha256:d4e5f6...",
            "audit_logger_pro.so": "sha256:g7h8i9..."
          }
        },
        "override_resolver_pro.so": {
          "self": "sha256:d4e5f6...",
          "observed": {
            "llm_filter_pro.so": "sha256:a1b2c3...",
            "audit_logger_pro.so": "sha256:g7h8i9..."
          }
        }
      },
      "machine_id": "hmac:...",
      "timestamp": "2026-03-13T14:00:00Z"
    }

    + Strong: must replace ALL modules simultaneously to avoid detection
    + Cross-validation creates a web of trust between compiled binaries
    + Server can detect inconsistencies (A says B is X, but B says B is Y)
    - More complex to implement and maintain
    - All modules must know paths to all other modules
    - Version upgrades must update all modules atomically

### Option S3: Runtime behavior attestation (strongest)
    Beyond file hashes — modules report runtime behavior signatures.
    e.g., "I processed 47 requests, blocked 3, detected 12 PII entities"
    Server builds a behavioral profile per installation.
    Anomalies (e.g., 0 blocks ever, or detection counts don't match usage)
    suggest the module is stubbed out or bypassed.

    Integrity report:
    {
      "version": "1.2.0",
      "module_hashes": { ... },
      "behavior": {
        "requests_processed": 47,
        "detections": {"PII": 12, "credentials": 3, "prompt_injection": 0},
        "blocks": 3,
        "degradations": 0,
        "avg_latency_ms": 4.2
      },
      "machine_id": "hmac:...",
      "timestamp": "2026-03-13T14:00:00Z"
    }

    + Detects logical bypasses (binary replaced with no-op that returns "clean")
    + Server can flag statistically impossible behavior (never blocks anything)
    + Valuable analytics data (real-world detection rates per customer)
    + Can feed into conversion messaging ("Pro caught 342 PII leaks this month")
    - Most complex to implement
    - Privacy consideration: behavioral data sent to server (anonymized, no code content)
    - Needs baseline model to distinguish "quiet repo" from "bypassed module"
    - False positives possible (low-activity user flagged as tampered)

### Server-side response actions (all options):
    On heartbeat response, server can:
    - RENEW: issue fresh 3h token (normal case)
    - WARN: token renewed but integrity mismatch flagged (soft alert)
    - REVOKE: refuse renewal, token expires in ≤3h, degrade to free tier
    - SUSPEND: immediate revocation + account flag (severe tampering)

### Decision:
    S2 (cross-module validation) for launch — cross-module trust, much harder to defeat
    S3 (runtime behavior attestation) — BACKLOG, future enhancement

## 15. Open Questions

### Decisions made
    - Pricing: Free + Paid ($5/month per seat)
    - Repos: dual-repo (claude-privacy-hook MIT + claude-privacy-hook-pro BSL 1.1)
    - Free tier: all L1 regex only (9 filters incl. #11 SSN + #12 Credit cards via regex)
    - Paid tier: all NLP features (primary paywall)
    - Distribution: compiled binaries (Cython/Nuitka), no source shipped
    - Runtime: S2 cross-module validation, local execution, server for tokens only
    - Legal: BSL 1.1 + ToS + audit trail
    - Old docs (EnforcementModel, TokenManagement, etc.) are obsolete — new strategy from scratch

### Blocking — must resolve before code separation
[x] SeparationPlan.md — COMPLETE. 4-phase plan with 9 sections covering architecture,
    file inventory, integration, tier extensibility, degradation, execution steps, and validation.
[x] Override system scope — RESOLVED:
    Free tier: overrides for free-tier features only (9 L1 regex filters, output sanitizer, rate limiter)
    Paid tier: overrides for all features (NLP filters, managed layer, team/fleet overrides)

### Open — important but not blocking
[x] NLP plugins are the primary paywall — all NLP features are paid tier
    (#11 SSN + #12 Credit cards covered by L1 regex in free tier, no NLP needed)
[ ] How to handle community contributions to paid features?
[ ] Managed layer: include in paid tier or treat as separate add-on at higher price?
[ ] What analytics/telemetry (if any) to measure conversion?

### Backlog
[ ] S3: Runtime behavior attestation (future enhancement to self-validation)
