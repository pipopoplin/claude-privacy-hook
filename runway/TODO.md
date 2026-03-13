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
[ ] Choose license for free tier (Apache 2.0 or MIT — open source, builds trust)
[ ] Choose license for paid tier (BSL 1.1 or proprietary)
[~] Decide: dual-repo vs mono-repo with gated features (recommendation: hybrid in EnforcementModel.md)
[~] Define pricing tiers
    - Free: open source, no account needed
    - Team: per-seat, monthly or annual (requires login + token)
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
[ ] Decide repo structure
    - Option A: Single repo, paid features behind license key
    - Option B: Two repos (claude-privacy-hook-community + claude-privacy-hook-pro)
    - Option C: Single repo, paid features in separate package/directory
[ ] Set up free tier as public open-source repo
[ ] Set up paid tier distribution (private repo, license server, or package registry)
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
[ ] Decide if BSL 1.1 stays for paid tier or switches to proprietary

## 12. Open Questions

### Blocking — must resolve before code separation
[ ] Free-tier NLP conflict: Filters #11 (SSN) and #12 (Credit cards) are marked free but are L2 NLP.
    Free tier is defined as regex_filter only (§3). Options:
    - (a) Add regex fallback patterns for SSN/credit card to free tier (no NLP dependency)
    - (b) Include limited NLP path for those two filters in free tier
    - (c) Move #11 and #12 out of free tier (only 7 free filters remain)
[ ] Repo structure decision (§7): mono-repo with gated features vs dual-repo vs hybrid?
    Blocks all code separation work.
[ ] Referenced docs removed: EnforcementModel.md, TokenManagement.md, CustomerProfiles.md,
    UseCaseRanking.md, EnforcementActivityDiagram.md were in Archive.zip (now deleted).
    - Are the decisions in those docs still valid, or do they need to be re-documented?
    - §5 and §6 are marked [x] done — should they stay done or reopen?
[ ] SeparationPlan.md is empty — needs a code separation plan before §8 can start.

### Open — important but not blocking
[ ] Should the NLP plugins be the primary paywall? (strongest conversion trigger)
[ ] Should override system be free for personal use, paid for team use?
[ ] How to handle community contributions to paid features?
[ ] Should managed layer be a separate enterprise add-on?
[ ] What analytics/telemetry (if any) to measure conversion?
[ ] How to prevent paid features from being trivially extracted from mono-repo?
