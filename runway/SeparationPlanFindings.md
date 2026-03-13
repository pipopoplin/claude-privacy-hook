# Separation Plan — Findings & Open Questions

Log of issues, decisions, and surprises encountered during implementation.

## Format
- **[Fn]** = Finding (observation)
- **[Q]** = Open question (needs decision)
- **[D]** = Decision made during implementation

---

## [F1] Free repo is on branch `feat/mirror` (not `main`)
We have uncommitted changes from TODO.md, SeparationPlan.md, and filter_rules.json (SSN/CC rules).
Creating feature branch `feature/free-tier-separation` from current state.

## [F2] `merge_nlp_overrides()` removed from free override_resolver.py
This function was used by the NLP filter to merge disabled entity types and confidence
overrides. Since NLP is gone from free tier, it's removed. Pro must reimplement this
in `override_resolver_pro.py`.

## [D1] FREE_TIER_RULES is a frozenset of all rule names across free-tier configs
37 rule names total (18 Bash + 8 Write + 1 Read + 7 output sanitizer + 3 rate limiter meta).
Pro's `override_resolver_pro.py` will extend or remove this whitelist.

## [F3] Pro repo had staged deletions on `feature/reworked-pro`
Created clean `feature/pro-tier-v1` branch from main, restored all files, then
began copying NLP files from free repo.

## [F4] Override tests use synthetic rule names (`mw_rule`, `src_rule`, etc.)
These aren't in FREE_TIER_RULES whitelist, causing test failures.
**[D2]** Added `HOOK_SKIP_TIER_CHECK=1` env var escape hatch for testing.
Tests set this var to bypass the whitelist. Production code never sets it.
Pro can also use this var or extend FREE_TIER_RULES.

## [F5] `_load_override_file` was loading `nlp_overrides` section
Removed NLP override loading from free tier. Pro must handle this in its own resolver.

## [F6] Pro token.py already has `get_token_payload()`, not `read_token_payload()`
Updated gate.py to use the existing function name.

## [F7] Conftest tests had 160 cases, now 148 — 12 NLP-related checks removed
(5 file existence, 4 JSON validity, 3 LLM hook script checks)

## [F8] Override tests had 81 cases, now 74 — 5 NLP merge tests + 2 section lines removed

## [F9] test_overrides.py needed `HOOK_SKIP_TIER_CHECK=1` at module level
The in-process tests (not subprocess) were failing because `check_override()` rejects
synthetic rule names not in `FREE_TIER_RULES`. Added `os.environ["HOOK_SKIP_TIER_CHECK"] = "1"`
at the top of `test_overrides.py` (after imports). This is separate from the subprocess env
that was already handled.

## [D3] gate.py fixed: `read_token_payload()` → `get_token_payload()`
Also added `None` check since `get_token_payload()` returns `None` on failure (not a dict).

## [F10] Pro rule configs created with medical/biometric/genetic patterns
Pro adds 4 Bash rules, 3 Write rules, 3 output sanitizer rules — all focused on
healthcare/biometric data categories that complement free-tier financial/credential patterns.

## [Q1] Should `HOOK_SKIP_TIER_CHECK` be documented or kept internal?
Currently used to allow override tests with synthetic rule names.
Pro could use a different mechanism (extend FREE_TIER_RULES).

