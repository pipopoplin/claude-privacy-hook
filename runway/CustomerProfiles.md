# Customer Profiles

6 customer profiles with conversion triggers and funnel mapping.

## Profile 1: Solo Developer / Freelancer

| Attribute | Detail |
|-----------|--------|
| **Who** | Individual dev using Claude Code on client projects or personal work |
| **Team size** | 1 |
| **Budget** | $0–20/month, pays from own pocket |
| **Primary pain** | "I accidentally committed an API key last year and had to rotate everything" |
| **Secondary pain** | Works with client codebases containing real credentials, PII in databases |
| **Trust barrier** | High — won't install something they can't read the source of |
| **What hooks them** | Credential protection + sensitive file blocking — solves an immediate, personal fear |
| **What makes them pay** | Nothing. They're the trust-builder. They star the repo, write blog posts, recommend to their team lead. They're the marketing engine. |
| **Conversion path** | Gets hired at a company → recommends tool → company buys paid tier |
| **Top use cases** | #1 (credentials), #3 (network), #6 (sensitive files), #14 (output sanitization) |

## Profile 2: Tech Lead / Small Team

| Attribute | Detail |
|-----------|--------|
| **Who** | Lead engineer at a startup or small product team adopting Claude Code |
| **Team size** | 2–15 |
| **Budget** | $50–200/month, can expense it |
| **Primary pain** | "I can't control what Claude does on my team's machines. Someone will leak our staging DB password." |
| **Secondary pain** | Needs shared rules (project-level config), needs to allow internal APIs without editing rule files |
| **Trust barrier** | Medium — needs to see the core works before pitching to manager |
| **What hooks them** | Installs free tier personally → sees it catch real issues → realizes they need team-wide config |
| **What makes them pay** | Override system (team exceptions), project-level config, shared rules across repos |
| **Conversion trigger** | First time a team member gets blocked trying to curl the company API and asks "how do I allow this for everyone?" |
| **Top use cases** | #1, #2 (PII), #3, #5 (financial), #6, #14, #15 (overrides) |

## Profile 3: Engineering Manager / Platform Team

| Attribute | Detail |
|-----------|--------|
| **Who** | Manages 15–100 devs, responsible for developer tooling and security posture |
| **Team size** | 15–100 |
| **Budget** | $500–2,000/month, has tooling budget |
| **Primary pain** | "We're rolling out Claude Code to the org but security team won't approve it without guardrails" |
| **Secondary pain** | Needs audit evidence, central policy, can't rely on each dev configuring hooks correctly |
| **Trust barrier** | Low for open-source core — actually required ("we need to audit the code") |
| **What hooks them** | Free tier unblocks Claude Code adoption. Without it, security team says no. |
| **What makes them pay** | Managed layer (IT-enforced rules), audit dashboard/reporting, NLP detection, central deployment |
| **Conversion trigger** | Security review asks "how do you prove no credentials leak through the AI tool?" and the audit log isn't enough without managed enforcement |
| **Top use cases** | #1–3, #5–9, #11–15, #20 (rate limiter) |

## Profile 4: CISO / Security Team

| Attribute | Detail |
|-----------|--------|
| **Who** | Security leadership at mid-to-large company (100+ devs) |
| **Team size** | 100–5,000+ |
| **Budget** | $2,000–10,000+/month, enterprise procurement |
| **Primary pain** | "AI tools are a data loss vector and we have zero visibility" |
| **Secondary pain** | Compliance audits (SOC 2, GDPR, HIPAA) need documented AI controls |
| **Trust barrier** | Lowest — they expect commercial support. Open-source core is a checkbox for vendor evaluation. |
| **What hooks them** | They discover the tool because their devs already use the free tier |
| **What makes them pay** | Managed deployment, compliance reporting, SLA/support, enterprise SSO for override management, custom plugin development |
| **Conversion trigger** | Compliance audit or board-level AI governance requirement |
| **Top use cases** | All Tier 1–2, plus #8 (audit), #7 (managed), #20 (rate limiter) |

## Profile 5: Regulated Industry Developer

| Attribute | Detail |
|-----------|--------|
| **Who** | Dev at healthcare, fintech, government, or legal tech company |
| **Team size** | Any |
| **Budget** | Determined by compliance requirements (not optional) |
| **Primary pain** | "We handle patient/financial/citizen data and literally cannot risk PII in an AI tool" |
| **Secondary pain** | Needs specific detectors (medical terms, IBAN, government IDs) + audit proof |
| **Trust barrier** | Medium — needs open source core + vendor accountability for paid features |
| **What hooks them** | Free regex layer catches credentials. They immediately realize they also need NLP for unstructured PII. |
| **What makes them pay** | NLP plugins (medical/financial PII detection), compliance mapping documentation, audit log with compliance-ready formatting |
| **Conversion trigger** | First time the regex filter misses a real name or phone number in a command, and they realize regex can't catch natural language PII |
| **Top use cases** | All above + #8, #16 (government IDs), #18 (medical/biometric) |

## Profile 6: Airgapped / High-Security Environment

| Attribute | Detail |
|-----------|--------|
| **Who** | Defense contractors, classified environments, critical infrastructure |
| **Team size** | Any |
| **Budget** | High, but procurement is slow |
| **Primary pain** | "Nothing leaves our network. Period." |
| **Secondary pain** | Can't install packages from the internet, needs zero-dependency solution |
| **Trust barrier** | Requires source code audit — open-source core is mandatory |
| **What hooks them** | Zero-dep core runs with stdlib only — the only solution that works in their environment |
| **What makes them pay** | Custom plugin development, on-premise support, managed deployment templates |
| **Conversion trigger** | They need the managed layer to enforce policy across classified workstations |
| **Top use cases** | #1, #3, #6, #14, #23 (zero-dep core) |

## Conversion Funnel

```
                        AWARENESS
                            |
            Solo dev finds repo (blog, GitHub, HN, word of mouth)
                            |
                        ADOPTION
                            |
            Installs free tier, open source builds trust
            Sees it catch real credentials — "this actually works"
                            |
                      TEAM SPREAD
                            |
            Recommends to team → Tech Lead installs for team
            Team hits override/shared config wall
                            |
                     FIRST PURCHASE
                            |
            Tech Lead buys Team tier ($50-200/mo)
            Override system, project config, NLP plugins
                            |
                    ORG-WIDE ROLLOUT
                            |
            Eng Manager standardizes across 15-100 devs
            Needs managed layer, audit reporting
            Buys Org tier ($500-2,000/mo)
                            |
                     ENTERPRISE DEAL
                            |
            CISO needs compliance proof, central governance
            Security audit triggers enterprise procurement
            Enterprise tier ($2,000-10,000+/mo)
            SLA, support, custom plugins, compliance reporting
```

### Funnel Economics

| Stage | Profile | Pays? | Value to Business |
|-------|---------|-------|-------------------|
| Awareness → Adoption | Profile 1 (Solo dev) | No | Viral loop — stars, blogs, recommendations |
| Team spread → First purchase | Profile 2 (Tech Lead) | $50–200/mo | First revenue, proves product-market fit |
| Org rollout | Profile 3 (Eng Manager) | $500–2,000/mo | Scalable revenue, multi-seat |
| Enterprise deal | Profile 4 (CISO) | $2,000–10,000+/mo | High-value contracts, annual commitments |
| Compliance-driven | Profile 5 (Regulated) | Varies | Non-optional spend, low churn |
| High-security | Profile 6 (Airgapped) | Custom | Long sales cycle, high contract value |

### Key Insight

Profile 1 (solo dev) never pays but is essential — they're the viral loop. Every paying customer (Profiles 2–6) discovers the tool because a solo dev on their team was already using it.

The free tier must be:
- **Genuinely useful** — not crippled, solves real problems
- **Open source** — builds the trust that drives adoption
- **Limited at the team boundary** — individual use is free, team/org use hits the paywall naturally
