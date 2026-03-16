# Tests

Test suites for all security hook layers, compliance tools, and shared test infrastructure.

## Quick Start

```bash
# Run everything (1,390 tests across 9 suites)
python3 tests/run_all.py
```

## Test Suites

| Suite | File | Cases | What it tests |
|-------|------|-------|---------------|
| **Regex Filter** | `test_regex_filter.py` | 518 | Pattern matching for Bash, Write/Edit, and Read rules |
| **Output Sanitizer** | `test_output_sanitizer.py` | 186 | Redaction rules + anonymization modes (pseudonymize, hash, redact) |
| **Rate Limiter** | `test_rate_limiter.py` | 60 | Threshold boundaries, session isolation, time window, config edge cases |
| **Overrides** | `test_overrides.py` | 94 | Resolver, integration, CLI, performance, risk scoring, audit trail |
| **Conftest Infrastructure** | `test_conftest.py` | 148 | Path constants, helpers, TestRunner, integration round-trips |
| **Audit Logger** | `test_audit_logger.py` | 55 | Log rotation, data minimization, SCF metadata, override fields |
| **Evidence Collector** | `test_evidence_collector.py` | 47 | SCF grouping, cross-session analysis, formatting, overrides |
| **Breach Report** | `test_breach_report.py` | 55 | Breach detection, severity, session filter, 3 output formats |
| **Config Validation** | `test_config_validation.py` | 109 | SCF tags, data_classification, rule counts, ordering |

## Shared Infrastructure

`conftest.py` provides shared helpers used by all suites:

- **Path constants** — `PROJECT_ROOT`, `HOOKS_DIR`, all hook script and config paths
- **`run_hook()`** — run any PreToolUse hook and get back `"allow"`, `"warn"`, or `"block"`
- **`run_hook_raw()`** — run a hook and get the raw `subprocess.CompletedProcess`
- **`parse_decision()`** — parse hook output into `"allow"` / `"warn"` / `"block"`
- **`detected()`** — boolean: did the hook detect something?
- **`TestRunner`** — lightweight runner with `check()`, `run_fn()`, section headers, and summary

## Suite Details

### test_regex_filter.py

Tests the regex filter (`regex_filter.py`) against all three rule sets with extensive edge-value coverage:

**Bash rules** (`filter_rules.json`) — 332 cases:
- Allow: no-network commands, trusted endpoints (localhost, GitHub, PyPI, npm, GitLab, rubygems, crates.io, bitbucket, pkg.go.dev)
- Warn (ask): untrusted network endpoints (curl, wget, httpie, httpx, axios, urllib, aiohttp, fetch, rsync, telnet, socat, nmap, AI SDKs), employee IDs, IBANs, sensitive files, DB connections (postgres, mysql, mongodb, redis, JDBC, AMQP, ADO.NET, DSN, Data Source, cockroachdb, couchdb, mariadb), internal IPs (IPv4, IPv6 ULA/link-local, .local/.lan/.corp/.internal/.intranet/.private suffixes), customer/contract IDs
- Block (deny): API keys (Anthropic, OpenAI, AWS, GitHub PAT/OAuth, Slack, Stripe live/test/restricted, Google API/OAuth/client ID/client secret, SendGrid, Twilio SID/key, GitLab PAT/runner/OAuth, Discord, Telegram, npm, PyPI, Hugging Face, DigitalOcean, Heroku, Vault, JWT), private keys (RSA, EC, DSA, OPENSSH, generic), hardcoded passwords, prompt injection (ignore instructions, role reassignment, pretend, DAN mode, do anything now, sudo/admin mode, new instructions, no restrictions, jailbreak, XML tag injection, system prompt override, forget/bypass/override instructions), shell obfuscation (eval with string/variable/network tool, hex/octal escapes, /dev/tcp, /dev/udp, exec FD, source stdin/process substitution, IFS, consecutive hex), path traversal (3+ levels, sensitive file, /etc/, URL-encoded, double-encoded, mixed ..%2f, UTF-8 overlong, Windows backslash), DNS exfiltration (dig/nslookup/host with subst/backtick, pipe to DNS, dig +short, dig TXT, resolvectl), pipe-chain exfiltration (file read to network, reverse shell, mkfifo, compress-and-pipe, redirect to /dev/tcp+udp, encrypt-and-pipe, mail/sendmail, socat), base64 (CLI tool, pipe, Python encode/decode, JS atob/btoa, Node Buffer.from, long strings, echo-pipe patterns), passport/licence numbers (passport number/value/num/no, driver licence/license, DL, national ID), Unicode/homoglyph bypass (Cyrillic, zero-width)
- Edge values: boundary-length keys, minimum/maximum digit counts, false positives for below-minimum lengths, non-matching prefixes

**Write/Edit rules** (`filter_rules_write.json`) — 89 cases:
- Block: API keys (Anthropic, OpenAI, GitHub PAT/OAuth, Slack, Stripe live/restricted, Google API/OAuth/client secret, SendGrid, Twilio, GitLab, npm, PyPI, HuggingFace, DigitalOcean, JWT, Telegram), private keys (RSA, EC, DSA, OPENSSH, generic), passwords (password/passwd/secret, Vault token, Heroku key, boundary 4-char minimum), DB URIs (postgres, mysql, mongodb, redis, JDBC, ADO.NET, AMQP, Data Source), SSNs (raw, assignment, social_security_number), credit cards (Visa, Mastercard, Amex, Discover, assignment patterns), internal IPs (10.x, 172.16.x, 192.168.x)
- Allow: normal code, config, JSON, HTML, SQL, imports, safe edits, below-minimum passwords

**Read rules** (`filter_rules_read.json`) — 63 cases:
- Block: system auth (/etc/passwd, /etc/shadow, /etc/sudoers), SSH (id_rsa, id_ecdsa, id_dsa, config, authorized_keys, known_hosts, host keys), .env variants (.env, .env.production, .env.local, .env.staging, .env.development), cloud credentials (AWS, GCloud, Azure, Terraform), Kubernetes (kube config, PKI), history files (bash, zsh, python, mysql, psql), credential dotfiles (.netrc, .pgpass, .my.cnf), package manager auth (.npmrc, .pypirc), Docker, GPG, wallet.dat, Rails (master.key, credentials.yml.enc), Vault token
- Allow: normal source files, README, /etc/hostname, /etc/hosts, /etc/os-release, /etc/resolv.conf, config files, .gitignore, Dockerfile, .envrc, .env_template, public keys

### test_output_sanitizer.py

Tests the PostToolUse output sanitizer (`output_sanitizer.py`) with edge-value coverage for all 7 rules:

- **API key redaction** (31) — Anthropic, OpenAI, GitHub, Slack, Stripe, Google, SendGrid, Twilio, JWT, GitLab, npm, PyPI, Hugging Face, DigitalOcean, AWS, boundary-length edges
- **SSN redaction** (10) — standard, assignment, spaces, quoted, boundary, false positives
- **Credit card redaction** (19) — Visa, Mastercard, Amex, Discover, various formats, false positives
- **Email redaction** (12) — standard, subdomain, special chars, false positives
- **Private key redaction** (11) — RSA/EC/DSA/OPENSSH headers/footers, false positives
- **DB connection string redaction** (25) — All URI schemes, env vars, JDBC, ADO.NET, false positives
- **Internal IP redaction** (23) — RFC1918, link-local, IPv6, false positives
- **Stderr redaction** (7) — All rule types in stderr, combined stdout+stderr
- **Pass-through** (17) — Safe output preserved unchanged
- **Redaction quality** (3) — Markers, surrounding text, multi-rule
- **Config edge cases** (10) — Disabled, allow, match=all, empty, invalid regex, string patterns
- **Input edge cases** (6) — Missing/bad tool_result, malformed JSON, missing config
- **Audit logging** (2) — Redaction logged, safe output not logged
- **Unicode / case insensitivity** (3) — Case-insensitive, homoglyph normalization
- **Anonymization modes** (7) — Pseudonymize (`[PII-{hash}]`), hash (`sha256:{full}`), default redact (`[REDACTED]`), deterministic tokens, full SHA-256, unknown mode fallback, per-rule config

### test_rate_limiter.py

Tests the rate limiter (`rate_limiter.py`):

- **Threshold boundaries** (9): 0, 1, 4 (below warn), 5 (at warn), 6, 9 (below block), 10 (at block), 11, 50 violations
- **Action filtering** (7): deny counts, ask counts, mixed deny+ask, allow/redact/override_allow don't count, mixed actions
- **Session isolation** (4): other session ignored, multi-session split, current at threshold, empty session_id in log
- **Time window** (6): all expired, mix expired+fresh, fresh at threshold, 4min (inside), 6min (outside), boundary straddling
- **Config edge cases** (10): disabled, custom lower thresholds (warn=2/block=4), higher thresholds (warn=20/block=50), short window (60s), long window (3600s), warn=block, warn=1/block=2
- **Input edge cases** (6): no session_id, empty session_id, missing log, empty log, malformed JSON stdin, missing tool_input
- **Malformed log entries** (6): bad JSON lines, missing timestamp, bad timestamp, missing action, missing session_id, unknown actions
- **Multiple sources** (2): different filters, different rules
- **Output format** (5): warn format, block format, custom messages (warn+block), violation count in reason
- **Large audit log** (1): 1000 entries performance

### test_overrides.py

Tests the two-layer override system:

- **Resolver unit tests** (28) — basic match, non-overridable rule, expired/future/today expiry, wrong rule_name, case insensitive, full regex, multiple patterns (any match), first-wins ordering, source preservation (user/project), empty overrides/rule, missing overridable defaults True, invalid regex skipped, string patterns, empty pattern, no patterns key, metadata entries skipped
- **Integration allows** (6) — override for each overridable rule: untrusted network, internal IP, employee ID, DB connection, customer ID, IBAN
- **Non-overridable rules** (5) — block_sensitive_data, block_prompt_injection, block_shell_obfuscation, block_path_traversal, block_dns_exfiltration stay blocked with override
- **Edge cases** (12) — expired/future expiry, wrong rule_name, missing/empty/malformed override file, multiple overrides (network+IP), partial pattern match, selective URL matching
- **Audit logging** (4) — override_allow recorded with override_name and override_source, non-overridden commands have no override_allow
- **CLI tool** (17) — add/list/remove cycle, add with --expires, duplicate name auto-increment, remove nonexistent, validate (valid/invalid-rule/non-overridable/invalid-regex/expired-warning), test (overridden/not-overridden/non-overridable)
- **Performance** (2) — 50 overrides match and no-match complete under 500ms
- **Risk scoring** (13) — restricted+critical→10, public+low→2, default values, project scope +1, no expiry +1, long expiry +1, clamping 1-10, invalid expiry, level thresholds (critical/high/medium/low)
- **CLI risk scoring and audit trail** (4) — add shows risk score, high-risk warning, add logs override_add, remove logs override_remove

### test_conftest.py

Tests the shared test infrastructure (`conftest.py`):

- **Path constants** (42) — PROJECT_ROOT/HOOKS_DIR exist, 6 hook scripts exist and are .py under HOOKS_DIR, 7 config files exist and are valid JSON
- **parse_decision()** (21) — deny→block, ask→warn, allow→allow, exit code 2→block, exit 0 empty→allow, exit 1/127/255→allow (fail-open), invalid/partial JSON→allow, missing/empty hookSpecificOutput→allow, unknown decisions→allow, non-dict hookSpecificOutput→AttributeError
- **detected()** (12) — deny/ask→True, allow/empty/whitespace/error-code/invalid-JSON/missing-decision/unknown-values→False
- **run_hook_raw()** (9) — safe command exit 0, sensitive command→block, returns CompletedProcess with stdout/stderr/returncode, custom env passthrough, empty hook_input graceful
- **run_hook()** (14) — Bash safe→allow, API key→block, default tool_name, Read /etc/shadow→block, Read safe→allow, Write password→block, Write safe→allow, None/empty command→allow, tool_input overrides command, return type always str in valid set
- **TestRunner init** (5) — title stored, counters start at 0, empty/long titles
- **TestRunner check()** (18) — pass/fail counting, return values, multiple passes/fails, type comparisons (int vs str, None, list, dict, empty list, bool vs int)
- **TestRunner run_fn()** (11) — True/False/exception/None/0/string/"" returns, pass/fail counting
- **TestRunner summary()** (5) — all pass→0, has fails→1, zero tests→0, all fail→1, 100+1→1
- **TestRunner header/section()** (4) — no-crash, empty name, special characters
- **Integration round-trip** (9) — safe/blocked/warned through raw→parse→detected, run_hook agrees
- **Edge cases** (10) — long command (6KB), newlines, unicode, null bytes, whitespace, JSON chars, extra fields, trailing newline, leading whitespace, double JSON

## Adding Test Cases

Each suite uses a data-driven pattern — add cases to the appropriate list:

```python
# Regex filter (test_regex_filter.py)
BASH_CASES = [
    ("Description", "command string", "allow|warn|block"),
    ...
]

WRITE_CASES = [
    ("Description", "Write|Edit", "content", "allow|block"),
    ...
]

READ_CASES = [
    ("Description", "/path/to/file", "allow|block"),
    ...
]
```

For standalone tests (overrides, rate limiter, audit logger, etc.), add a new `test_*()` function and register it in `main()`.

### test_audit_logger.py

Tests the audit logger module directly (unit tests, not subprocess):

- **Log rotation** (8) — disabled (zero max_bytes, zero backup_count), file too small, missing file, triggers at threshold, shifts backups (.1→.2), deletes oldest, invalid env vars
- **Basic fields** (2) — required fields present, matched_patterns capped at 10
- **Minimize mode** (3) — command_preview omitted, label text stripped, normal mode includes preview
- **SCF metadata** (3) — full metadata included, omitted when None, partial (only non-empty fields)
- **Override fields** (2) — included when provided, omitted when empty
- **Redact preview** (3) — secrets masked, long commands truncated, short commands unchanged
- **Rotation integration** (1) — log_event triggers rotation before writing

### test_evidence_collector.py

Tests the compliance evidence collector:

- **load_audit_log** (4) — empty file, nonexistent file, since filter, malformed JSON skipped
- **group_by_scf_control** (4) — single control, multiple controls per entry, unmapped entries, action counts
- **cross_session_analysis** (8) — hot rule (3+ sessions), cold rule, same-session dedup, custom threshold, action tracking, time window, empty entries, missing rule_name
- **format_cross_session_text** (2) — hot rules table, no hot rules message
- **format_cross_session_json** (1) — correct structure with sessions/actions/is_hot
- **group_overrides** (2) — override_allow grouped, non-override events ignored
- **format_text/json report** (3) — report header, domain filter, JSON structure

### test_breach_report.py

Tests the breach notification report generator:

- **load_audit_log** (3) — nonexistent file, since filter, bad JSON skipped
- **detect_breaches — threshold** (8) — above/below threshold, custom threshold, session filter, multiple sessions, sorting, action counts, no session_id
- **detect_breaches — data** (3) — data types collection, SCF metadata, time window
- **detect_breaches — severity** (3) — critical, high, medium based on risk_levels
- **_consequences_text** (3) — critical+GDPR, PCI, default
- **format_text** (2) — no breaches, 7-section report with GDPR footer
- **format_markdown** (2) — no breaches, heading structure with code blocks
- **format_json** (2) — full structure, empty report

### test_config_validation.py

Validates JSON config file metadata:

- **data_classification** (4 groups) — all Bash (18), Write (8), Read (1), and Sanitizer (7) rules have valid classification
- **SCF metadata** (4 groups) — all rules have scf.domain and scf.risk_level
- **SCF controls** (1) — all Bash rules have non-empty scf.controls list
- **Rule counts** (4) — Bash=18, Write=8, Read=1, Sanitizer=7
- **Rule ordering** (1) — no deny rules after allow in Bash rules

## Dependencies

All tests work with Python 3.10+ only (no extra dependencies required).

> NLP filter tests (PII detection, NLP service) are available in [claude-privacy-hook-pro](https://github.com/anthropics/claude-privacy-hook-pro).
