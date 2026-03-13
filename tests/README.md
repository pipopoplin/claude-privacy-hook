# Tests

Test suites for all three security hook layers plus the override system and shared test infrastructure.

## Quick Start

```bash
# Run everything (979 tests)
python3 tests/run_all.py
```

## Test Suites

| Suite | File | Cases | What it tests |
|-------|------|-------|---------------|
| **Regex Filter** | `test_regex_filter.py` | 518 | Pattern matching for Bash, Write/Edit, and Read rules |
| **Output Sanitizer** | `test_output_sanitizer.py` | 179 | API keys (20 patterns), SSNs, credit cards, emails, private keys, DB connections, internal IPs, stderr, config/input edge cases, audit logging, Unicode |
| **Rate Limiter** | `test_rate_limiter.py` | 60 | Threshold boundaries, action filtering, session isolation, time window, config variants, malformed input, output format |
| **Overrides** | `test_overrides.py` | 74 | Resolver unit tests, integration allows, non-overridable rules, edge cases, audit logging, CLI tool, performance |
| **Conftest Infrastructure** | `test_conftest.py` | 148 | Path constants, parse_decision, detected, run_hook_raw, run_hook, TestRunner, integration round-trips, edge cases |

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

- **API key redaction** (31) — Anthropic (standard, mid-output), OpenAI (sk-proj-, sk- 20-char), GitHub (PAT, OAuth), Slack (xoxb/xoxa/xoxp), Stripe (live/test/restricted rk_live/rk_test), Google (API AIza 35-char, OAuth ya29.), SendGrid, Twilio (SK/AC 32-hex), JWT (standard, Bearer header), GitLab PAT, npm, PyPI (60+ chars), Hugging Face, DigitalOcean, AWS (access key assignment, secret key, AKIA standalone), boundary-length edge (20 chars exact, 19 below min), two keys in one line
- **SSN redaction** (10) — standard NNN-NN-NNNN, assignment (= and :), with spaces, mid-text, quoted, boundary zeros, all nines, FP date format, FP version string
- **Credit card redaction** (19) — Visa (spaces/dashes/none, 4000 prefix, boundary 4999), Mastercard (5100/5200/5300/5400/5500, spaces/dashes/none), Amex (34xx/37xx, spaces/dashes/none), Discover (6011/65xx, none), FP non-matching prefix, FP 15-digit
- **Email redaction** (12) — standard, subdomain, dots/plus/percent/hyphen/underscore in local, numbers, short TLD, two emails, FP shell `${array[@]}`, FP git ref `HEAD@{1}`
- **Private key redaction** (11) — RSA/EC/DSA/OPENSSH/generic headers, RSA/EC/generic footers, full block, FP public key, FP certificate
- **DB connection string redaction** (25) — URI with credentials (postgres/postgresql/mysql/mariadb/mongodb/mongodb+srv/redis/amqp/rabbitmq/cockroachdb/couchdb/mssql), env var assignments (DATABASE_URL/MONGO_URI/MONGODB_URI/REDIS_URL/AMQP_URL), ADO.NET, ODBC, JDBC (mysql/postgresql/sqlserver/oracle), Data Source, FP plain URL, FP db name
- **Internal IP redaction** (23) — RFC1918 Class A (10.0.0.1, :8080, max 255, mid-range), Class B (172.16 lower, 172.31 upper, 172.20 mid), Class C (192.168.0/1/255), link-local (169.254.0.1, AWS metadata), IPv6 ULA (fd00/fdab), IPv6 link-local (fe80::), two IPs in one line, FP public (8.8.8.8, 1.1.1.1), FP out-of-range (172.32, 172.15, 11.x), FP localhost
- **Stderr redaction** (7) — API key, SSN, email, internal IP, DB URI, private key in stderr; both stdout+stderr simultaneously
- **Pass-through** (17) — normal text, JSON, build log, git log, empty, npm output, test results, file listing, public IP, version numbers, hex colors, MAC address, URL without credentials, SQL without secrets, Docker digest, safe stderr, large output (500 lines)
- **Redaction quality** (3) — [REDACTED] marker present, surrounding text preserved, multiple rules all redact in single output
- **Config edge cases** (10) — disabled rule, action=allow, match=all (partial/full), empty rules, invalid regex skipped, string patterns, missing rules key, no patterns key
- **Input edge cases** (6) — missing tool_result, non-dict tool_result, empty stdout+stderr, malformed JSON, no config arg, nonexistent config
- **Audit logging** (2) — redaction event recorded, no log for safe output
- **Unicode / case insensitivity** (3) — case-insensitive matching (upper/lower), Unicode homoglyph normalization

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

For standalone tests (overrides, rate limiter), add a new `test_*()` function that returns `bool` and register it in the `tests` list in `main()`.

## Dependencies

All tests work with Python 3.10+ only (no extra dependencies required).

> NLP filter tests (PII detection, NLP service) are available in [claude-privacy-hook-pro](https://github.com/anthropics/claude-privacy-hook-pro).
